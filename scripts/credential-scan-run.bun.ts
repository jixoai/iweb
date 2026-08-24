// 用户原始需求（2026-08-14）：12.3 的凭据扫描执行器：只报类别与消毒后的位置，绝不输出 secret 值；secret 从调用方提供的文件读取（默认不读任何真实凭据）。
// 正交意图：fail closed——路径缺失/不可读、声明的 kind 零覆盖、零输入、模式命中都判失败并退出非零；绝不静默跳过。
import { createHash } from "node:crypto";
import { readFileSync, statSync, readdirSync } from "node:fs";
import { join, isAbsolute, relative } from "node:path";
import { scanForCredentialPatterns, scanForSecrets, type ScanLocationKind } from "../packages/contracts/credential-scan.ts";

const MAX_FILE_BYTES = 16 * 1024 * 1024;

interface CliOptions {
	secretsFile?: string;
	locations: { kind: ScanLocationKind; label: string }[];
}

function parseArguments(argv: string[]): CliOptions {
	const locations: { kind: ScanLocationKind; label: string }[] = [];
	let secretsFile: string | undefined;
	for (let index = 2; index < argv.length; index += 1) {
		const argument = argv[index];
		if (argument === "--secrets-file") {
			secretsFile = argv[index + 1];
			index += 1;
			continue;
		}
		const separator = argument.indexOf(":");
		if (separator <= 0) throw new Error("location must be kind:path, got: " + argument);
		const kind = argument.slice(0, separator);
		const validKinds: ScanLocationKind[] = ["package", "sandbox-fs", "env-projection", "object-store", "admin-assets", "log", "monitor-frame", "test-output", "image-layer"];
		if (!validKinds.includes(kind as ScanLocationKind)) throw new Error("unknown location kind: " + kind);
		locations.push({ kind: kind as ScanLocationKind, label: argument.slice(separator + 1) });
	}
	if (locations.length === 0) throw new Error("at least one kind:path location is required");
	return { secretsFile, locations };
}

function digest(label: string): string {
	return createHash("sha256").update(label).digest("hex").slice(0, 12);
}

function collectFiles(root: string): { files: string[]; skipped: { label: string; reason: string }[] } {
	const files: string[] = [];
	const skipped: { label: string; reason: string }[] = [];
	const walk = (directory: string): void => {
		let names: string[];
		try {
			names = readdirSync(directory);
		} catch (error) {
			skipped.push({ label: directory, reason: ((error as NodeJS.ErrnoException).code ?? "READ_ERROR") + ":unreadable-directory" });
			return;
		}
		for (const name of names) {
			const full = join(directory, name);
			let stats;
			try { stats = statSync(full); } catch (error) {
				skipped.push({ label: full, reason: ((error as NodeJS.ErrnoException).code ?? "READ_ERROR") + ":unstatable" });
				continue;
			}
			if (stats.isDirectory()) { walk(full); continue; }
			if (!stats.isFile()) continue;
			// the caller's own secrets file is excluded (never a self-finding)
			if (secretsFileAbsolute !== null && full === secretsFileAbsolute) continue;
			// a file above the size ceiling is an uncovered surface, not a silent skip
			if (stats.size > MAX_FILE_BYTES) skipped.push({ label: full, reason: "OVER_SIZE_CEILING" });
			else files.push(full);
		}
	};
	const absolute = isAbsolute(root) ? root : join(process.cwd(), root);
	walk(absolute);
	return { files, skipped };
}

const options = parseArguments(process.argv);
// The caller's own secrets file obviously contains the secrets; scanning it
// would be a guaranteed self-finding, so it is excluded from every location.
const secretsFileAbsolute = options.secretsFile ? (isAbsolute(options.secretsFile) ? options.secretsFile : join(process.cwd(), options.secretsFile)) : null;
const secrets: { value: string; category: string }[] = [];
if (options.secretsFile) {
	const text = readFileSync(options.secretsFile, "utf8");
	for (const line of text.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (trimmed === "" || trimmed.startsWith("#")) continue;
		secrets.push({ value: trimmed, category: "caller-provided" });
	}
}

const failures: { label: string; reason: string }[] = [];
const locations: { kind: ScanLocationKind; label: string; content: string }[] = [];
const kindCounts = new Map<ScanLocationKind, number>();
for (const kind of ["package", "sandbox-fs", "env-projection", "object-store", "admin-assets", "log", "monitor-frame", "test-output", "image-layer"] as ScanLocationKind[]) kindCounts.set(kind, 0);

for (const entry of options.locations) {
	let stats;
	try {
		stats = statSync(entry.label);
	} catch (error) {
		// a declared location that cannot be stat'ed is a failure, never a skip
		failures.push({ label: entry.kind + ":" + digest(entry.label), reason: ((error as NodeJS.ErrnoException).code ?? "READ_ERROR") + ":location-missing-or-unreadable" });
		continue;
	}
	try {
		if (stats.isDirectory()) {
			const collected = collectFiles(entry.label);
			for (const skip of collected.skipped) failures.push({ label: entry.kind + ":" + digest(skip.label), reason: skip.reason });
			if (collected.files.length === 0) {
				failures.push({ label: entry.kind + ":" + digest(entry.label), reason: "EMPTY_LOCATION:no-scannable-files" });
				continue;
			}
			for (const file of collected.files) {
				locations.push({ kind: entry.kind, label: relative(process.cwd(), file), content: readFileSync(file, "utf8") });
				kindCounts.set(entry.kind, (kindCounts.get(entry.kind) ?? 0) + 1);
			}
			continue;
		}
		if (secretsFileAbsolute !== null && (isAbsolute(entry.label) ? entry.label : join(process.cwd(), entry.label)) === secretsFileAbsolute) {
			failures.push({ label: entry.kind + ":" + digest(entry.label), reason: "SECRETS_FILE_DECLARED:excluded-from-scan" });
			continue;
		}
		locations.push({ kind: entry.kind, label: relative(process.cwd(), entry.label), content: readFileSync(entry.label, "utf8") });
		kindCounts.set(entry.kind, (kindCounts.get(entry.kind) ?? 0) + 1);
	} catch (error) {
		failures.push({ label: entry.kind + ":" + digest(entry.label), reason: ((error as NodeJS.ErrnoException).code ?? "READ_ERROR") + ":read-failed" });
	}
}

// every DECLARED kind must have contributed at least one scanned location
for (const entry of options.locations) {
	if ((kindCounts.get(entry.kind) ?? 0) === 0) failures.push({ label: entry.kind + ":declared", reason: "UNCOVERED_KIND:zero-locations-scanned" });
}
// zero input is never a clean run
if (locations.length === 0) failures.push({ label: "input", reason: "ZERO_INPUT:no-locations-scanned" });

const needle = scanForSecrets({ secrets, locations });
const pattern = scanForCredentialPatterns(locations);
const findings = [...needle.findings, ...pattern.findings].sort((a, b) => (a.location + a.category < b.location + b.category ? -1 : 1));
const clean = needle.clean && pattern.clean && failures.length === 0;

const report = {
	run: "credential-scan",
	ranAt: new Date().toISOString(),
	secretsProvided: secrets.length,
	locationsScanned: locations.length,
	kindsCovered: Object.fromEntries([...kindCounts.entries()].filter(([, count]) => count > 0)),
	failures,
	patternFindings: pattern.findings,
	clean,
	findings,
};
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
if (!clean) process.exitCode = 1;