// 用户原始需求（2026-08-14）：desired state 必须落盘，supervisor 重启后仍能重建 limits/version 映射；reconcile 不得从可变容器 label 重建权威。
// 正交意图：原子写（tmp+rename）、0600；secrets 与可检查记录物理分离；quarantine 日志持久。
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { type ManifestEgress } from "../contracts/manifest.ts";
import { createQuarantineJournal, validateApplicationId, validateBucketName, validateObjectCredentialRecord, validateStorageSecret, validateTimestamp, type QuarantineJournal } from "../contracts/persisted-records.ts";
import { validateNormalizedPolicy, validateVersionIdentity, type VersionIdentity } from "../contracts/records.ts";

// Durability contract (2.28): a state replacement is durable at the FILE level
// (write → fsync → atomic rename). The parent-directory fsync that follows the
// rename makes the rename itself crash-safe; the only tolerated failure is the
// platform reporting the operation unsupported (EINVAL/ENOSYS/EPERM on
// filesystems without directory fsync). Any OTHER directory-fsync error (EIO,
// EDQUOT, ...) is an infrastructure failure and THROWS: silently swallowing it
// would narrow the durability contract without saying so.
const DIRECTORY_FSYNC_UNSUPPORTED = new Set(["EINVAL", "ENOSYS", "EPERM"]);

export function syncDirectoryOrFail(directory: string): void {
	let dirFd: number | undefined;
	try {
		dirFd = openSync(directory, "r");
		fsyncSync(dirFd);
	} catch (error) {
		const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
		if (!DIRECTORY_FSYNC_UNSUPPORTED.has(code)) throw error;
	} finally {
		if (dirFd !== undefined) {
			try { closeSync(dirFd); } catch { /* closing an fd never carries durability meaning */ }
		}
	}
}

export interface DesiredSandboxRecord {
	readonly sandboxId: string;
	readonly packageDigest: string;
	readonly versionIdentity: VersionIdentity;
	readonly policy: NormalizedPolicy;
	readonly createdAt: string;
	/** Supervisor-allocated deterministic subnet index (0..1023): pins the
	 * gateway (.2) and app (.3) addresses of this sandbox's internal network. */
	readonly subnetIndex: number;
}

export interface DesiredStateFile {
	readonly version: 1;
	readonly records: Record<string, DesiredSandboxRecord>;
}

export interface QuarantineRecord {
	readonly sandboxId: string;
	readonly quarantinedAt: string;
	/** Origin of the entry: "reconcile", "desired-record", "desired-state"
	 * (file-level corruption), or "gateway-secret". */
	readonly kind?: string;
	/** Human-readable rejection reason; set for malformed-record entries. */
	readonly reason?: string;
}

export interface QuarantineFile {
	readonly version: 1;
	readonly entries: readonly QuarantineRecord[];
}

export interface GatewayObjectCredential {
	readonly endpoint: string;
	readonly region: string;
	readonly accessKeyId: string;
	readonly secretAccessKey: string;
}

// Secret material lives only in the per-sandbox secrets file that is mounted
// into the gateway container. It never enters desired-state.json or argv.
export interface GatewaySecret {
	readonly version: 1;
	readonly sandboxId: string;
	readonly versionId: string;
	readonly generation: number;
	readonly bucket: string;
	readonly object: GatewayObjectCredential;
	readonly egress: ManifestEgress;
	// Boot-required topology fields: the gateway entrypoint validates the mounted
	// config with parseGatewayConfig, which rejects a secret missing either one.
	// ingressTarget is the celld listener inside the pod; socketDirectory is the
	// mounted gateway socket directory. The env override in gateway-main.ts wins
	// for socketDirectory, but the field must still parse.
	readonly ingressTarget: string;
	readonly socketDirectory: string;
	// Optional application persistent-data plane (2.27): when all three are
	// present the gateway runs the capability-verified data proxy scoped to
	// this application's stable namespace. They are gateway-only secrets.
	readonly applicationId?: string;
	readonly storageSecret?: string;
	readonly data?: GatewayObjectCredential;
}

export interface StateStoreIO {
	readFile(path: string): string | null;
	writeFileAtomic(path: string, content: string): void;
	deleteFile(path: string): void;
	ensureDirectory(path: string): void;
}

export const systemStateStoreIO: StateStoreIO = {
	readFile: (path) => {
		try {
			return readFileSync(path, "utf8");
		} catch (error) {
			// ENOENT is a legitimate "not created yet"; a permission or I/O
			// failure is an infrastructure error that must never masquerade as
			// an absent state file (2.37/2.47).
			const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
			if (code !== "ENOENT") throw error;
			return null;
		}
	},
	writeFileAtomic: (path, content) => {
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		const temporary = path + ".tmp";
		const fd = openSync(temporary, "w", 0o600);
		try {
			writeFileSync(fd, content);
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
		renameSync(temporary, path);
		syncDirectoryOrFail(dirname(path));
	},
	deleteFile: (path) => {
		try {
			rmSync(path, { force: true });
		} catch {
			// deleting a missing file is already the desired end state
		}
	},
	ensureDirectory: (path) => {
		mkdirSync(path, { recursive: true, mode: 0o700 });
	},
};

// Runtime-validate a persisted gateway secret field-by-field. Persisted JSON is
// never trusted via a type assertion: any unknown or malformed field rejects the
// whole record so the gateway cannot start from a tampered secret file. Every
// NESTED credential object (.object and .data) goes through the shared
// persisted-records authority — unknown fields, endpoints, and credential
// strings included — never a shallow typeof-string check (2.28/2.37).
export function validateGatewaySecret(parsed: Record<string, unknown>, sandboxId: string): GatewaySecret | null {
	// unknown top-level fields reject outright (allowlist)
	const known = new Set(["version", "sandboxId", "versionId", "generation", "bucket", "object", "egress", "ingressTarget", "socketDirectory", "applicationId", "storageSecret", "data"]);
	for (const key of Object.keys(parsed)) if (!known.has(key)) return null;
	if (parsed.version !== 1 || typeof parsed.sandboxId !== "string" || parsed.sandboxId !== sandboxId) return null;
	if (typeof parsed.versionId !== "string" || parsed.versionId.length === 0 || parsed.versionId.length > 200) return null;
	if (typeof parsed.generation !== "number" || !Number.isSafeInteger(parsed.generation) || parsed.generation < 1) return null;
	if (!validateBucketName(parsed.bucket).ok) return null;
	// nested .object: full shared-authority validation
	const object = validateObjectCredentialRecord(parsed.object);
	if (!object.ok) return null;
	if (!isRecord(parsed.egress)) return null;
	if (parsed.egress.default !== "deny" || !Array.isArray(parsed.egress.allow)) return null;
	for (const key of Object.keys(parsed.egress)) if (key !== "default" && key !== "allow") return null;
	const allow: ManifestEgress["allow"] = [];
	for (const entry of parsed.egress.allow) {
		if (!isRecord(entry)) return null;
		if (typeof entry.host !== "string" || entry.host.length === 0 || entry.host.length > 253 || /[\u0000-\u001f]/.test(entry.host)) return null;
		if (typeof entry.port !== "number" || !Number.isSafeInteger(entry.port) || entry.port < 1 || entry.port > 65535) return null;
		for (const key of Object.keys(entry)) if (key !== "host" && key !== "port") return null;
		allow.push({ host: entry.host, port: entry.port });
	}
	if (typeof parsed.ingressTarget !== "string" || parsed.ingressTarget.length === 0 || !/^[^\s:]+:[0-9]{1,5}$/.test(parsed.ingressTarget)) return null;
	if (typeof parsed.socketDirectory !== "string" || !parsed.socketDirectory.startsWith("/")) return null;
	const secret: GatewaySecret = {
		version: 1,
		sandboxId,
		versionId: parsed.versionId,
		generation: parsed.generation,
		bucket: parsed.bucket,
		object: object.value,
		egress: { default: "deny", allow },
		ingressTarget: parsed.ingressTarget,
		socketDirectory: parsed.socketDirectory,
	};
	// The optional data-plane triple is all-or-nothing and each field carries its
	// own authority: applicationId shape, 64-hex storageSecret, and a FULLY
	// validated nested data credential (a shallow string check here previously
	// let a malformed endpoint or smuggled field reach the gateway).
	const hasAppId = parsed.applicationId !== undefined;
	const hasStorageSecret = parsed.storageSecret !== undefined;
	const hasData = parsed.data !== undefined;
	if (hasAppId || hasStorageSecret || hasData) {
		if (!hasAppId || !hasStorageSecret || !hasData) return null;
		if (!validateApplicationId(parsed.applicationId)) return null;
		if (!validateStorageSecret(parsed.storageSecret)) return null;
		const data = validateObjectCredentialRecord(parsed.data);
		if (!data.ok) return null;
		secret.applicationId = parsed.applicationId;
		secret.storageSecret = parsed.storageSecret;
		secret.data = data.value;
	}
	return secret;
}

// Runtime-validate a persisted desired-sandbox record field by field; any
// malformed or unknown record is dropped (treated as not desired) instead of
// being trusted through a type assertion.
function isOpaqueSandboxId(value: unknown): value is string {
	return typeof value === "string" && value.startsWith("sbx-") && value.length >= 8 && value.length <= 128;
}
type DesiredRecordValidation =
	| { readonly ok: true; readonly record: DesiredSandboxRecord }
	| { readonly ok: false; readonly reason: string };

// Field-by-field persisted desired-record validation. policy and version
// identity reuse the admission-time authority in contracts/records.ts, so a
// persisted record can never be accepted looser than admission accepted it;
// unknown fields reject so a tampered record cannot smuggle extra state into
// reconcile. A rejected record is reported with its reason, not dropped.
function validateDesiredRecord(parsed: Record<string, unknown>): DesiredRecordValidation {
	const known = new Set(["sandboxId", "packageDigest", "versionIdentity", "policy", "createdAt", "subnetIndex"]);
	for (const key of Object.keys(parsed)) if (!known.has(key)) return { ok: false, reason: "unknown field " + key };
	if (!isOpaqueSandboxId(parsed.sandboxId)) return { ok: false, reason: "sandboxId is not an opaque sandbox id" };
	if (typeof parsed.packageDigest !== "string" || !/^[a-f0-9]{64}$/.test(parsed.packageDigest)) return { ok: false, reason: "packageDigest is not a sha-256 digest" };
	const identity = validateVersionIdentity(parsed.versionIdentity);
	if (!identity.ok) return { ok: false, reason: "versionIdentity: " + identity.errors.map((e) => e.message).join("; ") };
	const policy = validateNormalizedPolicy(parsed.policy);
	if (!policy.ok) return { ok: false, reason: "policy: " + policy.errors.map((e) => e.message).join("; ") };
	if (!validateTimestamp(parsed.createdAt)) return { ok: false, reason: "createdAt is not a timestamp" };
	if (typeof parsed.subnetIndex !== "number" || !Number.isSafeInteger(parsed.subnetIndex) || parsed.subnetIndex < 0 || parsed.subnetIndex > 1023) return { ok: false, reason: "subnetIndex is out of range" };
	return { ok: true, record: { sandboxId: parsed.sandboxId, packageDigest: parsed.packageDigest, versionIdentity: identity.value, policy: policy.value, createdAt: parsed.createdAt, subnetIndex: parsed.subnetIndex } };
}

export function validateDesiredStateFile(parsed: Record<string, unknown>, journal?: QuarantineJournal): DesiredStateFile {
	const at = new Date().toISOString();
	// Top-level corruption is never silently an empty state: version, shape,
	// and unknown top-level fields all reject into the durable journal (2.37).
	for (const key of Object.keys(parsed)) {
		if (key !== "version" && key !== "records") {
			journal?.append("desired-state", "desired-state", "desired-state.json has unknown top-level field " + key, at);
			return { version: 1, records: {} };
		}
	}
	if (parsed.version !== 1 || !isRecord(parsed.records)) {
		journal?.append("desired-state", "desired-state", "desired-state.json top level is malformed (version/records)", at);
		return { version: 1, records: {} };
	}
	const records: Record<string, DesiredSandboxRecord> = {};
	for (const [sandboxId, raw] of Object.entries(parsed.records)) {
		if (!isRecord(raw)) {
			journal?.append("desired-record", sandboxId, "record is not a JSON object", new Date().toISOString());
			continue;
		}
		const result = validateDesiredRecord(raw);
		if (!result.ok) {
			journal?.append("desired-record", sandboxId, result.reason, new Date().toISOString());
			continue;
		}
		if (result.record.sandboxId !== sandboxId) {
			journal?.append("desired-record", sandboxId, "record key does not match its sandboxId field", new Date().toISOString());
			continue;
		}
		records[sandboxId] = result.record;
	}
	return { version: 1, records };
}

// The quarantine file is itself a persisted security record (2.37): strict
// top-level shape, strict per-entry validation, and NO silent entry dropping.
// A present-but-corrupt quarantine file is an explicit failure
// (QUARANTINE_FILE_CORRUPT) — swallowing it would silently forget the exact
// rejection history the durability contract exists to preserve.
export function validateQuarantineFile(parsed: Record<string, unknown>): QuarantineFile {
	if (parsed.version !== 1 || !Array.isArray(parsed.entries)) {
		throw new Error("QUARANTINE_FILE_CORRUPT: quarantine.json top level is malformed (version/entries)");
	}
	for (const key of Object.keys(parsed)) {
		if (key !== "version" && key !== "entries") throw new Error("QUARANTINE_FILE_CORRUPT: quarantine.json has unknown top-level field " + key);
	}
	const entries: QuarantineRecord[] = [];
	for (const entry of parsed.entries) {
		if (!isRecord(entry)) throw new Error("QUARANTINE_FILE_CORRUPT: quarantine entry is not a JSON object");
		const valid = (isOpaqueSandboxId(entry.sandboxId) || entry.sandboxId === "desired-state") && typeof entry.quarantinedAt === "string" && entry.quarantinedAt.length > 0;
		if (!valid) throw new Error("QUARANTINE_FILE_CORRUPT: quarantine entry has an invalid sandboxId/quarantinedAt");
		for (const key of Object.keys(entry)) if (key !== "sandboxId" && key !== "quarantinedAt" && key !== "kind" && key !== "reason") throw new Error("QUARANTINE_FILE_CORRUPT: quarantine entry has unknown field " + key);
		if (entry.kind !== undefined && (typeof entry.kind !== "string" || entry.kind.length === 0 || entry.kind.length > 64)) throw new Error("QUARANTINE_FILE_CORRUPT: quarantine entry kind is malformed");
		if (entry.reason !== undefined && (typeof entry.reason !== "string" || entry.reason.length === 0 || entry.reason.length > 512)) throw new Error("QUARANTINE_FILE_CORRUPT: quarantine entry reason is malformed");
		const record: QuarantineRecord = { sandboxId: entry.sandboxId, quarantinedAt: entry.quarantinedAt };
		if (typeof entry.kind === "string") record.kind = entry.kind;
		if (typeof entry.reason === "string") record.reason = entry.reason;
		entries.push(record);
	}
	return { version: 1, entries };
}

export class JsonStateStore {
	private readonly io: StateStoreIO;
	private readonly stateDirectory: string;

	constructor(io: StateStoreIO, stateDirectory: string) {
		this.io = io;
		this.stateDirectory = stateDirectory;
	}

	private desiredPath(): string {
		return join(this.stateDirectory, "desired-state.json");
	}

	private quarantinePath(): string {
		return join(this.stateDirectory, "quarantine.json");
	}

	secretPath(sandboxId: string): string {
		return join(this.stateDirectory, "secrets", sandboxId + ".json");
	}

	readDesired(): DesiredStateFile {
		const text = this.io.readFile(this.desiredPath());
		if (text === null) return { version: 1, records: {} };
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			// a corrupt desired-state file is an explicit quarantine event; an
			// implicit empty state would silently forget every desired sandbox
			this.appendQuarantineRecords([{ kind: "desired-state", key: "desired-state", reason: "desired-state.json is not parseable JSON", at: new Date().toISOString() }]);
			return { version: 1, records: {} };
		}
		if (!isRecord(parsed)) {
			this.appendQuarantineRecords([{ kind: "desired-state", key: "desired-state", reason: "desired-state.json is not a JSON object", at: new Date().toISOString() }]);
			return { version: 1, records: {} };
		}
		const journal = createQuarantineJournal();
		const file = validateDesiredStateFile(parsed, journal);
		this.appendQuarantineRecords(journal.entries());
		return file;
	}

	writeDesired(file: DesiredStateFile): void {
		this.io.ensureDirectory(this.stateDirectory);
		this.io.writeFileAtomic(this.desiredPath(), JSON.stringify(file, null, 2) + "\n");
	}

	readQuarantine(): QuarantineFile {
		const text = this.io.readFile(this.quarantinePath());
		if (text === null) return { version: 1, entries: [] };
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			// ENOENT is the only legitimate "no journal yet" (mapped above); a
			// present-but-unparseable journal is an explicit corruption failure.
			throw new Error("QUARANTINE_FILE_CORRUPT: quarantine.json is not parseable JSON");
		}
		if (!isRecord(parsed)) throw new Error("QUARANTINE_FILE_CORRUPT: quarantine.json is not a JSON object");
		return validateQuarantineFile(parsed);
	}

	appendQuarantine(sandboxId: string, quarantinedAt: string): QuarantineFile {
		const current = this.readQuarantine();
		const file: QuarantineFile = { version: 1, entries: [...current.entries, { sandboxId, quarantinedAt }] };
		this.io.ensureDirectory(this.stateDirectory);
		this.io.writeFileAtomic(this.quarantinePath(), JSON.stringify(file, null, 2) + "\n");
		return file;
	}

	// Durably append validation-rejection entries (kind/reason/at) drained from
	// a quarantine journal. A no-op for an empty journal.
	appendQuarantineRecords(entries: readonly { readonly kind: string; readonly key: string; readonly reason: string; readonly at: string }[]): void {
		if (entries.length === 0) return;
		const current = this.readQuarantine();
		const file: QuarantineFile = {
			version: 1,
			entries: [...current.entries, ...entries.map((entry) => ({ sandboxId: entry.key, quarantinedAt: entry.at, kind: entry.kind, reason: entry.reason }))],
		};
		this.io.ensureDirectory(this.stateDirectory);
		this.io.writeFileAtomic(this.quarantinePath(), JSON.stringify(file, null, 2) + "\n");
	}

	readSecret(sandboxId: string): GatewaySecret | null {
		const text = this.io.readFile(this.secretPath(sandboxId));
		if (text === null) return null;
		let reason = "secret file is not parseable JSON";
		try {
			const parsed: unknown = JSON.parse(text);
			if (isRecord(parsed)) {
				const secret = validateGatewaySecret(parsed, sandboxId);
				if (secret !== null) return secret;
				reason = "secret failed field validation";
			} else {
				reason = "secret file is not a JSON object";
			}
		} catch {
			// reason already set; fall through to the quarantine trail
		}
		// the gateway can never start from a malformed secret, and the
		// rejection must not be silent: append the reason to the durable journal
		this.appendQuarantineRecords([{ kind: "gateway-secret", key: sandboxId, reason, at: new Date().toISOString() }]);
		return null;
	}

	writeSecret(secret: GatewaySecret): void {
		this.io.ensureDirectory(join(this.stateDirectory, "secrets"));
		this.io.writeFileAtomic(this.secretPath(secret.sandboxId), JSON.stringify(secret, null, 2) + "\n");
	}

	deleteSecret(sandboxId: string): void {
		this.io.deleteFile(this.secretPath(sandboxId));
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
