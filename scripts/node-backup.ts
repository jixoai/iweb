// 用户原始需求（2026-08-14）：升级前必须备份持久卷、Kernel 路由状态与未来控制数据库，并在失败时关闭、保留上一个可恢复备份。
// 正交意图：label/destination 校验；固定权限；staging 归档；归档成员预检；事务化 restore。
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statfsSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export type NodeBackupKind = "iweb-node-backup";

export interface NodeBackupSource {
	readonly label: string;
	readonly path: string;
	readonly destination: string;
}

export interface NodeBackupSourceRecord {
	readonly label: string;
	readonly destination: string;
	readonly fileCount: number;
	readonly bytes: number;
	readonly sha256: string;
}

export interface NodeBackupManifest {
	readonly version: 1;
	readonly kind: NodeBackupKind;
	readonly backupId: string;
	readonly createdAt: string;
	readonly archive: { readonly name: string; readonly bytes: number; readonly sha256: string };
	readonly sources: readonly NodeBackupSourceRecord[];
	readonly complete: true;
}

export interface NodeBackupLatestPointer {
	readonly backupId: string;
	readonly createdAt: string;
}

export interface PreflightOutcome {
	readonly ok: boolean;
	readonly errors: readonly string[];
}

export interface RestoreReport {
	readonly backupId: string;
	readonly restoredAt: string;
	readonly destinations: readonly string[];
	readonly verified: readonly NodeBackupSourceRecord[];
}

export interface BackupStat {
	readonly isDirectory: boolean;
	readonly isFile: boolean;
	readonly isSymbolicLink: boolean;
	readonly size: number;
}

export interface BackupFile {
	readonly absolutePath: string;
	readonly relativePath: string;
	readonly size: number;
}

export interface ArchiveMember {
	readonly path: string;
	readonly type: "file" | "directory" | "symbolic-link" | "hard-link" | "other";
}

export interface BackupIO {
	exists(path: string): boolean;
	stat(path: string): BackupStat;
	readdir(path: string): string[];
	readFile(path: string): Buffer;
	writeFile(path: string, data: Buffer | string): void;
	mkdir(path: string): void;
	rm(path: string): void;
	rename(from: string, to: string): void;
	chmod(path: string, mode: number): void;
	copyTree(source: string, dest: string): void;
	archive(sourceDir: string, outputFile: string): Promise<void>;
	extract(archiveFile: string, targetDir: string): Promise<void>;
	listArchiveMembers(archiveFile: string): ArchiveMember[];
	freeBytes(path: string): number;
	effectiveUserId(): number;
	sha256File(path: string): string;
}

export class NodeBackupError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.name = "NodeBackupError";
		this.code = code;
	}
}

export const ARCHIVE_NAME = "backup.tar.gz";
export const MANIFEST_NAME = "manifest.json";
export const LATEST_NAME = "latest.json";
const MINIMUM_FREE_MARGIN_BYTES = 1024 * 1024;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const BACKUP_ID_PATTERN = /^backup-[A-Za-z0-9._-]+$/;
const SOURCE_LABEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function boundedMessage(message: string): string {
	return message.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 240);
}

function fail(code: string, message: string): never {
	throw new NodeBackupError(code, boundedMessage(message));
}

function isWithin(child: string, parent: string): boolean {
	const normalizedChild = resolve(child);
	const normalizedParent = resolve(parent);
	return normalizedChild === normalizedParent || normalizedChild.startsWith(normalizedParent + "/");
}

function statOrNull(io: BackupIO, path: string): BackupStat | null {
	try {
		return io.stat(path);
	} catch {
		return null;
	}
}

function isRealDirectory(io: BackupIO, path: string): boolean {
	const stat = statOrNull(io, path);
	return stat?.isDirectory === true && stat.isSymbolicLink === false;
}

function isSymlink(io: BackupIO, path: string): boolean {
	return statOrNull(io, path)?.isSymbolicLink === true;
}

function listFiles(io: BackupIO, root: string): BackupFile[] {
	const result: BackupFile[] = [];
	const walk = (current: string, prefix: string): void => {
		for (const name of io.readdir(current).sort()) {
			const absolutePath = join(current, name);
			const relativePath = prefix ? prefix + "/" + name : name;
			const stat = io.stat(absolutePath);
			if (stat.isSymbolicLink) fail("SYMLINK_NOT_ALLOWED", "backup does not follow symbolic links: " + relativePath);
			if (stat.isDirectory) walk(absolutePath, relativePath);
			else if (stat.isFile) result.push({ absolutePath, relativePath, size: stat.size });
		}
	};
	walk(root, "");
	return result;
}

function treeDigest(io: BackupIO, files: BackupFile[]): string {
	const hash = createHash("sha256");
	for (const file of [...files].sort((left, right) => left.relativePath.localeCompare(right.relativePath))) {
		const content = io.readFile(file.absolutePath);
		hash.update(file.relativePath);
		hash.update("\0");
		hash.update(String(content.length));
		hash.update("\0");
		hash.update(content);
	}
	return hash.digest("hex");
}

function treeBytes(files: readonly BackupFile[]): number {
	return files.reduce((total, file) => total + file.size, 0);
}

function writeAtomic(io: BackupIO, path: string, content: string, mode: number): void {
	io.mkdir(dirname(path));
	const temporary = path + "." + process.pid + "." + Date.now() + ".tmp";
	io.writeFile(temporary, content);
	io.chmod(temporary, mode);
	io.rename(temporary, path);
}

// --- source label / destination validation (shared by CLI, manifest, and implementation) ---

export function validateSourceLabel(label: unknown): { readonly ok: boolean; readonly error?: string } {
	if (typeof label !== "string" || !SOURCE_LABEL_PATTERN.test(label)) {
		return { ok: false, error: "source label must be a single safe identifier without traversal or separators" };
	}
	return { ok: true };
}

export function validateDestination(destination: unknown): { readonly ok: boolean; readonly error?: string } {
	if (typeof destination !== "string" || !destination.startsWith("/") || destination.length > 512) {
		return { ok: false, error: "restore destination must be an absolute path" };
	}
	if (destination.includes("\0") || /[\u0000-\u001f]/.test(destination)) {
		return { ok: false, error: "restore destination contains control characters" };
	}
	const segments = destination.split("/").filter((segment) => segment.length > 0);
	if (segments.some((segment) => segment === ".." || segment === ".")) {
		return { ok: false, error: "restore destination must not contain traversal segments" };
	}
	return { ok: true };
}

export function validateSources(sources: readonly NodeBackupSource[]): { readonly ok: boolean; readonly errors: readonly string[] } {
	const errors: string[] = [];
	const seenLabels = new Set<string>();
	const seenDestinations = new Set<string>();
	for (const source of sources) {
		const label = validateSourceLabel(source.label);
		if (!label.ok) errors.push("source label is invalid: " + boundedMessage(source.label));
		else if (seenLabels.has(source.label)) errors.push("duplicate source label: " + source.label);
		else seenLabels.add(source.label);
		const destination = validateDestination(source.destination);
		if (!destination.ok) errors.push(destination.error + ": " + boundedMessage(source.destination));
		else if (seenDestinations.has(source.destination)) errors.push("duplicate restore destination: " + source.destination);
		else seenDestinations.add(source.destination);
	}
	return { ok: errors.length === 0, errors };
}

export function validateArchiveMembers(members: readonly ArchiveMember[]): void {
	for (const member of members) {
		if (member.type !== "file" && member.type !== "directory") {
			fail("UNSAFE_ARCHIVE_MEMBER", "archive contains a non-file entry");
		}
		let stripped = member.path.startsWith("./") ? member.path.slice(2) : member.path;
		stripped = stripped.replace(/\/+$/, "");
		if (stripped === "") continue;
		if (stripped.startsWith("/")) fail("UNSAFE_ARCHIVE_MEMBER", "archive member has an absolute path");
		if (stripped.split("/").some((segment) => segment === ".." || segment === "." || segment === "")) fail("UNSAFE_ARCHIVE_MEMBER", "archive member escapes the staging root");
		if (/[\u0000-\u001f]/.test(stripped)) fail("UNSAFE_ARCHIVE_MEMBER", "archive member contains control characters");
	}
}

// --- preflight ---

export function preflightNodeBackup(io: BackupIO, options: { readonly sources: readonly NodeBackupSource[]; readonly outputDirectory: string; readonly requireRoot?: boolean }): PreflightOutcome {
	const errors: string[] = [];
	const requireRoot = options.requireRoot ?? true;
	if (requireRoot && io.effectiveUserId() !== 0) errors.push("node backup requires root privileges");

	const labelCheck = validateSources(options.sources);
	errors.push(...labelCheck.errors);

	for (const source of options.sources) {
		if (isSymlink(io, source.path)) {
			errors.push("source path must not be a symbolic link: " + source.label);
			continue;
		}
		if (!isRealDirectory(io, source.path)) {
			errors.push("source directory is missing: " + source.label);
			continue;
		}
		if (isWithin(source.path, options.outputDirectory) || isWithin(options.outputDirectory, source.path)) {
			errors.push("output directory must not overlap source: " + source.label);
		}
	}

	if (!isRealDirectory(io, options.outputDirectory)) {
		errors.push("output directory is missing");
	} else {
		let totalBytes = 0;
		for (const source of options.sources) {
			try {
				totalBytes += treeBytes(listFiles(io, source.path));
			} catch {
				// The missing-directory error above already covers an unreadable source.
			}
		}
		if (io.freeBytes(options.outputDirectory) < totalBytes + MINIMUM_FREE_MARGIN_BYTES) {
			errors.push("insufficient free space for backup");
		}
		for (const name of io.readdir(options.outputDirectory)) {
			if (!name.startsWith("backup-")) continue;
			const candidate = join(options.outputDirectory, name);
			if (!isRealDirectory(io, candidate)) continue;
			if (!io.exists(join(candidate, MANIFEST_NAME))) {
				errors.push("incomplete backup already present: " + name);
			}
		}
	}

	return { ok: errors.length === 0, errors };
}

// --- manifest ---

export function validateBackupManifest(value: unknown): NodeBackupManifest {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail("INVALID_MANIFEST", "backup manifest must be an object");
	const record = value as Record<string, unknown>;
	if (record.version !== 1) fail("INVALID_MANIFEST", "backup manifest has an unsupported version");
	if (record.kind !== "iweb-node-backup") fail("INVALID_MANIFEST", "backup manifest has an unsupported kind");
	if (typeof record.backupId !== "string" || !BACKUP_ID_PATTERN.test(record.backupId)) fail("INVALID_MANIFEST", "backup manifest has an invalid backup identifier");
	if (typeof record.createdAt !== "string" || Number.isNaN(Date.parse(record.createdAt))) fail("INVALID_MANIFEST", "backup manifest has an invalid creation timestamp");
	if (record.complete !== true) fail("INVALID_MANIFEST", "backup manifest is not marked complete");

	const archive = record.archive;
	if (!archive || typeof archive !== "object" || Array.isArray(archive)) fail("INVALID_MANIFEST", "backup manifest has no archive record");
	const archiveRecord = archive as Record<string, unknown>;
	if (typeof archiveRecord.name !== "string" || archiveRecord.name.includes("/") || archiveRecord.name.includes("..")) fail("INVALID_MANIFEST", "backup manifest has an invalid archive name");
	if (!Number.isSafeInteger(archiveRecord.bytes) || (archiveRecord.bytes as number) < 0) fail("INVALID_MANIFEST", "backup manifest has an invalid archive size");
	if (typeof archiveRecord.sha256 !== "string" || !SHA256_PATTERN.test(archiveRecord.sha256)) fail("INVALID_MANIFEST", "backup manifest has an invalid archive digest");

	const sources = record.sources;
	if (!Array.isArray(sources) || sources.length === 0) fail("INVALID_MANIFEST", "backup manifest has no source records");
	const normalizedSources: NodeBackupSourceRecord[] = sources.map((source, index) => {
		if (!source || typeof source !== "object" || Array.isArray(source)) fail("INVALID_MANIFEST", "backup manifest source " + index + " is invalid");
		const item = source as Record<string, unknown>;
		const labelCheck = validateSourceLabel(item.label);
		if (!labelCheck.ok) fail("INVALID_MANIFEST", "backup manifest source " + index + " has an invalid label");
		const destinationCheck = validateDestination(item.destination);
		if (!destinationCheck.ok) fail("INVALID_MANIFEST", "backup manifest source " + index + " has an invalid destination");
		if (!Number.isSafeInteger(item.fileCount) || (item.fileCount as number) < 0) fail("INVALID_MANIFEST", "backup manifest source " + index + " has an invalid file count");
		if (!Number.isSafeInteger(item.bytes) || (item.bytes as number) < 0) fail("INVALID_MANIFEST", "backup manifest source " + index + " has an invalid byte count");
		if (typeof item.sha256 !== "string" || !SHA256_PATTERN.test(item.sha256)) fail("INVALID_MANIFEST", "backup manifest source " + index + " has an invalid digest");
		return {
			label: item.label as string,
			destination: item.destination as string,
			fileCount: item.fileCount as number,
			bytes: item.bytes as number,
			sha256: item.sha256 as string,
		};
	});
	return {
		version: 1,
		kind: "iweb-node-backup",
		backupId: record.backupId as string,
		createdAt: record.createdAt as string,
		archive: {
			name: archiveRecord.name as string,
			bytes: archiveRecord.bytes as number,
			sha256: archiveRecord.sha256 as string,
		},
		sources: normalizedSources,
		complete: true,
	};
}

export function readBackupManifest(io: BackupIO, manifestPath: string): NodeBackupManifest {
	let raw: Buffer;
	try {
		raw = io.readFile(manifestPath);
	} catch {
		fail("BACKUP_NOT_FOUND", "backup manifest is missing");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw.toString("utf8"));
	} catch {
		fail("INVALID_MANIFEST", "backup manifest is not valid JSON");
	}
	return validateBackupManifest(parsed);
}

// --- create backup ---

export async function createNodeBackup(options: {
	readonly io?: BackupIO;
	readonly sources: readonly NodeBackupSource[];
	readonly outputDirectory: string;
	readonly requireRoot?: boolean;
	readonly backupId?: string;
	readonly now?: Date;
}): Promise<NodeBackupManifest> {
	const io = options.io ?? defaultBackupIO;
	const backupId = options.backupId ?? "backup-" + Date.now();
	if (!BACKUP_ID_PATTERN.test(backupId)) fail("INVALID_BACKUP_ID", "backup identifier is invalid");
	const preflight = preflightNodeBackup(io, { sources: options.sources, outputDirectory: options.outputDirectory, requireRoot: options.requireRoot });
	if (!preflight.ok) fail("PRECONDITION_FAILED", preflight.errors.join("; "));

	const backupDirectory = join(options.outputDirectory, backupId);
	if (io.exists(backupDirectory)) fail("BACKUP_EXISTS", "backup already exists: " + backupId);
	io.mkdir(backupDirectory);
	io.chmod(backupDirectory, 0o700);
	const stageDirectory = join(backupDirectory, ".stage");
	io.mkdir(stageDirectory);
	io.chmod(stageDirectory, 0o700);

	// 1. Snapshot the live sources into a consistent staging tree first.
	try {
		for (const source of options.sources) {
			io.copyTree(source.path, join(stageDirectory, source.label));
		}
	} catch (error) {
		io.rm(backupDirectory);
		fail("SNAPSHOT_FAILED", error instanceof Error ? error.message : "snapshot failed");
	}

	// 2. Compute source records from staging, so digest always matches the archived bytes.
	let sourceRecords: NodeBackupSourceRecord[];
	try {
		sourceRecords = options.sources.map((source) => {
			const stagedPath = join(stageDirectory, source.label);
			const files = listFiles(io, stagedPath);
			return {
				label: source.label,
				destination: source.destination,
				fileCount: files.length,
				bytes: treeBytes(files),
				sha256: treeDigest(io, files),
			};
		});
	} catch (error) {
		io.rm(backupDirectory);
		fail("SNAPSHOT_FAILED", error instanceof Error ? error.message : "snapshot verification failed");
	}

	// 3. Archive staging.
	try {
		await io.archive(stageDirectory, join(backupDirectory, ARCHIVE_NAME));
	} catch (error) {
		io.rm(backupDirectory);
		fail("ARCHIVE_FAILED", error instanceof Error ? error.message : "archive failed");
	} finally {
		io.rm(stageDirectory);
	}

	const archivePath = join(backupDirectory, ARCHIVE_NAME);
	io.chmod(archivePath, 0o600);
	const archiveBytes = io.stat(archivePath).size;
	const archiveSha256 = io.sha256File(archivePath);
	const manifest: NodeBackupManifest = {
		version: 1,
		kind: "iweb-node-backup",
		backupId,
		createdAt: (options.now ?? new Date()).toISOString(),
		archive: { name: ARCHIVE_NAME, bytes: archiveBytes, sha256: archiveSha256 },
		sources: sourceRecords,
		complete: true,
	};
	writeAtomic(io, join(backupDirectory, MANIFEST_NAME), JSON.stringify(manifest, null, 2) + "\n", 0o600);
	const pointer: NodeBackupLatestPointer = { backupId, createdAt: manifest.createdAt };
	writeAtomic(io, join(options.outputDirectory, LATEST_NAME), JSON.stringify(pointer, null, 2) + "\n", 0o600);
	return manifest;
}

// --- restore ---

interface RestoreSwap {
	readonly stagedPath: string;
	readonly destination: string;
	readonly previousPath: string;
	readonly hadExisting: boolean;
	previousMoved: boolean;
	stagedMoved: boolean;
}

function rollbackRestore(io: BackupIO, swaps: readonly RestoreSwap[]): void {
	const failures: string[] = [];
	for (const swap of [...swaps].reverse()) {
		try {
			if (swap.stagedMoved && (io.exists(swap.destination) || statOrNull(io, swap.destination) !== null)) {
				io.rm(swap.destination);
			}
			if (swap.previousMoved && (io.exists(swap.previousPath) || statOrNull(io, swap.previousPath) !== null)) {
				io.rename(swap.previousPath, swap.destination);
			}
		} catch {
			failures.push(swap.destination);
		}
	}
	if (failures.length > 0) fail("ROLLBACK_FAILED", "restore rollback failed for " + failures.length + " destination(s)");
}

function replaceDirectories(io: BackupIO, entries: readonly { readonly stagedPath: string; readonly destination: string }[]): void {
	const transactionId = process.pid + "-" + randomBytes(6).toString("hex");
	const swaps: RestoreSwap[] = entries.map((entry) => ({
		...entry,
		previousPath: entry.destination + ".restore-old-" + transactionId,
		hadExisting: io.exists(entry.destination) || statOrNull(io, entry.destination) !== null,
		previousMoved: false,
		stagedMoved: false,
	}));
	try {
		for (const swap of swaps) {
			io.mkdir(dirname(swap.destination));
			if (swap.hadExisting) {
				io.rename(swap.destination, swap.previousPath);
				swap.previousMoved = true;
			}
		}
		for (const swap of swaps) {
			io.rename(swap.stagedPath, swap.destination);
			swap.stagedMoved = true;
		}
	} catch (error) {
		rollbackRestore(io, swaps);
		throw error;
	}
	for (const swap of swaps) {
		if (swap.previousMoved && (io.exists(swap.previousPath) || statOrNull(io, swap.previousPath) !== null)) io.rm(swap.previousPath);
	}
}

export async function restoreNodeBackup(options: {
	readonly io?: BackupIO;
	readonly backupDirectory: string;
	readonly requireRoot?: boolean;
}): Promise<RestoreReport> {
	const io = options.io ?? defaultBackupIO;
	if ((options.requireRoot ?? true) && io.effectiveUserId() !== 0) fail("NOT_ROOT", "node restore requires root privileges");
	const manifest = readBackupManifest(io, join(options.backupDirectory, MANIFEST_NAME));
	const archivePath = join(options.backupDirectory, manifest.archive.name);
	if (!io.exists(archivePath)) fail("BACKUP_NOT_FOUND", "backup archive is missing");
	const actualArchiveDigest = io.sha256File(archivePath);
	if (actualArchiveDigest !== manifest.archive.sha256) fail("DIGEST_MISMATCH", "backup archive digest does not match the manifest");

	// 1. Validate every archive member before extraction.
	const members = io.listArchiveMembers(archivePath);
	validateArchiveMembers(members);

	// 2. Extract into a same-filesystem staging root (sibling of the first destination).
	const stagingRoot = join(dirname(manifest.sources[0].destination), ".iweb-restore-" + process.pid + "-" + randomBytes(6).toString("hex"));
	io.mkdir(stagingRoot);
	io.chmod(stagingRoot, 0o700);
	try {
		try {
			await io.extract(archivePath, stagingRoot);
		} catch (error) {
			fail("EXTRACT_FAILED", error instanceof Error ? error.message : "extract failed");
		}

		// 3. Verify every staged tree against the manifest before touching the live target.
		const verified: NodeBackupSourceRecord[] = [];
		for (const source of manifest.sources) {
			const stagedPath = join(stagingRoot, source.label);
			if (!isRealDirectory(io, stagedPath)) fail("DIGEST_MISMATCH", "restored source is missing: " + source.label);
			const files = listFiles(io, stagedPath);
			const digest = treeDigest(io, files);
			if (digest !== source.sha256 || files.length !== source.fileCount || treeBytes(files) !== source.bytes) {
				fail("DIGEST_MISMATCH", "restored source does not match the manifest: " + source.label);
			}
			verified.push({ label: source.label, destination: source.destination, fileCount: files.length, bytes: treeBytes(files), sha256: digest });
		}

		// 4. Commit all destinations as one transaction; any failed rename restores all prior trees.
		replaceDirectories(io, manifest.sources.map((source) => ({ stagedPath: join(stagingRoot, source.label), destination: source.destination })));

		return { backupId: manifest.backupId, restoredAt: new Date().toISOString(), destinations: manifest.sources.map((source) => source.destination), verified };
	} finally {
		io.rm(stagingRoot);
	}
}

// --- previous-image orchestration ---

// --- helpers ---

export function sha256Text(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex");
}

export function countRoutes(routesJsonText: string): number {
	const parsed: unknown = JSON.parse(routesJsonText);
	if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { routes?: unknown }).routes)) {
		throw new Error("route state is invalid");
	}
	return (parsed as { routes: unknown[] }).routes.length;
}

// --- default IO (root-owned host) ---

export const defaultBackupIO: BackupIO = {
	exists: (path) => existsSync(path),
	stat: (path) => {
		const value = lstatSync(path);
		return { isDirectory: value.isDirectory(), isFile: value.isFile(), isSymbolicLink: value.isSymbolicLink(), size: value.size };
	},
	readdir: (path) => readdirSync(path),
	readFile: (path) => readFileSync(path),
	writeFile: (path, data) => writeFileSync(path, data),
	mkdir: (path) => mkdirSync(path, { recursive: true }),
	rm: (path) => rmSync(path, { recursive: true, force: true }),
	rename: (from, to) => renameSync(from, to),
	chmod: (path, mode) => chmodSync(path, mode),
	copyTree: (source, dest) => {
		execFileSync("cp", ["-a", source, dest], { stdio: "pipe" });
	},
	archive: async (sourceDir, outputFile) => {
		execFileSync("tar", ["-czf", outputFile, "-C", sourceDir, "."], { stdio: "pipe" });
	},
	extract: async (archiveFile, targetDir) => {
		execFileSync("tar", ["-xzf", archiveFile, "-C", targetDir], { stdio: "pipe" });
	},
	listArchiveMembers: (archiveFile) => {
		const names = execFileSync("tar", ["-tzf", archiveFile], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024 })
			.split("\n").map((line) => line.replace(/\r$/, "")).filter((line) => line.length > 0);
		const verbose = execFileSync("tar", ["-tvzf", archiveFile], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024 })
			.split("\n").map((line) => line.replace(/\r$/, "")).filter((line) => line.length > 0);
		if (names.length !== verbose.length) fail("UNSAFE_ARCHIVE_MEMBER", "archive listing is inconsistent");
		return names.map((path, index) => {
			const marker = verbose[index]?.[0];
			const type: ArchiveMember["type"] = marker === "-" ? "file" : marker === "d" ? "directory" : marker === "l" ? "symbolic-link" : marker === "h" ? "hard-link" : "other";
			return { path, type };
		});
	},
	freeBytes: (path) => {
		try {
			const statFs = statfsSync(path);
			return statFs.bavail * statFs.bsize;
		} catch {
			return 0;
		}
	},
	effectiveUserId: () => process.geteuid?.() ?? -1,
	sha256File: (path) => createHash("sha256").update(readFileSync(path)).digest("hex"),
};
