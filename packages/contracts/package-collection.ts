// 用户原始需求（2026-08-14）：把 owner workspace 的包内容收敛为 content-addressed 不可变快照，不执行任何包内代码。
// 正交意图：canonical path/duplicate/stat/symlink/TOCTOU 校验；manifest 运行时校验；canonical 序列化；稳定摘要。
import { createHash } from "node:crypto";
import {
	failure,
	isRecord,
	issue,
	ok,
	type ValidationIssue,
	type ValidationResult,
} from "./validation.ts";
import { type ApplicationManifest } from "./manifest.ts";

export const MAX_PACKAGE_FILES = 10_000;
export const MAX_PACKAGE_BYTES = 512 * 1024 * 1024;
export const MAX_PACKAGE_FILE_BYTES = 64 * 1024 * 1024;

export interface PackageFileEntry {
	readonly path: string;
	readonly size: number;
	readonly kind: "file";
	readonly mtimeNs?: number;
}

export interface PackageStat {
	readonly kind: "regular" | "symlink" | "other" | "missing";
	readonly size: number;
	readonly mtimeNs: number;
}

export interface PackageSnapshot {
	readonly digest: string;
	readonly fileCount: number;
	readonly bytes: number;
	readonly files: readonly PackageFileEntry[];
}

export interface CollectPackageOptions {
	readonly manifest: ApplicationManifest;
	readonly files: readonly PackageFileEntry[];
	readonly readContent: (path: string) => Buffer;
	readonly statFile: (path: string) => PackageStat | null;
	readonly manifestText?: string;
}

function safePackagePath(value: string): boolean {
	if (!value || value.length > 512) return false;
	if (value.startsWith("/")) return false;
	const segments = value.split("/");
	if (segments.some((segment) => segment === "..")) return false;
	if (/[\u0000-\u001f]/.test(value)) return false;
	return true;
}

// Collapse repeated slashes and remove "." segments. ".." is rejected earlier
// as unsafe and is intentionally left untouched here.
function normalizePath(value: string): string {
	return value
		.split("/")
		.filter((segment) => segment !== "" && segment !== ".")
		.join("/");
}

function filePath(path: string): string {
	return "/files/" + path.slice(0, 40);
}

// Content-addressed snapshot of the admitted package. Only reads declared file
// content and metadata; never executes package-provided scripts or plugins.
export function collectPackage(options: CollectPackageOptions): ValidationResult<PackageSnapshot> {
	const errors: ValidationIssue[] = [];

	if (options.files.length > MAX_PACKAGE_FILES) {
		errors.push(issue("PACKAGE_TOO_MANY_FILES", "/files", "package exceeds the maximum file count"));
	}
	let totalBytes = 0;
	const seenPaths = new Set<string>();
	for (const file of options.files) {
		if (!safePackagePath(file.path)) errors.push(issue("INVALID_PATH", filePath(file.path), "package file path is unsafe"));
		const normalized = normalizePath(file.path);
		if (seenPaths.has(normalized)) {
			errors.push(issue("PACKAGE_DUPLICATE_PATH", filePath(file.path), "package file path duplicates another file after normalization"));
		}
		seenPaths.add(normalized);
		if (file.kind !== "file") errors.push(issue("INVALID_FILE_KIND", filePath(file.path), "package file kind must be file"));
		if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_PACKAGE_FILE_BYTES) {
			errors.push(issue("INVALID_SIZE", filePath(file.path), "package file size is out of bounds"));
		}
		totalBytes += file.size;
	}
	if (totalBytes > MAX_PACKAGE_BYTES) errors.push(issue("PACKAGE_TOO_LARGE", "/files", "package exceeds the maximum total size"));

	const statFile = options.statFile;
	if (typeof statFile !== "function") {
		errors.push(issue("PACKAGE_STAT_FAILED", "/statFile", "statFile callback is required to verify package metadata"));
	}

	// Deterministic UTF-8 byte order (NOT localeCompare): the digest is a
	// cross-implementation contract — the Rust Kernel must reproduce the
	// ordering byte-for-byte, and ICU collation weights punctuation/accented
	// characters differently from byte order (e.g. "ab" vs "a-b").
	const canonical = [...options.files].sort((left, right) => Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")));
	const digested: { path: string; content: Buffer }[] = [];
	for (const file of canonical) {
		let before: PackageStat | null = null;
		if (typeof statFile === "function") {
			before = statFile(file.path);
			if (before === null) {
				errors.push(issue("PACKAGE_STAT_FAILED", filePath(file.path), "package file could not be stat'ed"));
				continue;
			}
			if (before.kind === "symlink") {
				errors.push(issue("PACKAGE_SYMLINK", filePath(file.path), "package file is a symlink"));
				continue;
			}
			if (before.kind === "missing") {
				errors.push(issue("PACKAGE_MISSING", filePath(file.path), "package file is missing"));
				continue;
			}
			if (before.kind !== "regular") {
				errors.push(issue("PACKAGE_NON_REGULAR", filePath(file.path), "package file is not a regular file"));
				continue;
			}
			if (before.size !== file.size) {
				errors.push(issue("SIZE_MISMATCH", filePath(file.path), "package file stat size does not match the declared size"));
				continue;
			}
		}
		let content: Buffer;
		try {
			content = options.readContent(file.path);
		} catch {
			errors.push(issue("PACKAGE_READ_FAILED", filePath(file.path), "package file could not be read"));
			continue;
		}
		if (content.length !== file.size) {
			errors.push(issue("SIZE_MISMATCH", filePath(file.path), "package file size does not match its content"));
			continue;
		}
		if (typeof statFile === "function" && before !== null) {
			const after = statFile(file.path);
			if (after === null || after.kind !== "regular" || after.size !== before.size || after.mtimeNs !== before.mtimeNs) {
				errors.push(issue("PACKAGE_TOCTOU_CHANGED", filePath(file.path), "package file changed while being collected"));
				continue;
			}
		}
		digested.push({ path: file.path, content });
	}

	// Runtime validation of the manifest against the collected snapshot. The
	// Kernel owns iweb.json; this module only verifies the declared shape.
	const entrypoint = options.manifest.runtime.entrypoint;
	const assetsRoot = options.manifest.assets.root;
	const normalizedFiles = options.files.map((file) => normalizePath(file.path));
	if (!normalizedFiles.includes(entrypoint)) {
		errors.push(issue("MANIFEST_ENTRYPOINT_MISSING", "/runtime/entrypoint", "declared entrypoint is not present in the collected files"));
	}
	if (!entrypoint.startsWith(assetsRoot + "/")) {
		errors.push(issue("MANIFEST_ENTRYPOINT_OUTSIDE_ASSETS", "/runtime/entrypoint", "declared entrypoint is not under the declared assets root"));
	}
	if (!normalizedFiles.some((path) => path.startsWith(assetsRoot + "/"))) {
		errors.push(issue("MANIFEST_ASSETS_ROOT_MISSING", "/assets/root", "no collected file exists under the declared assets root"));
	}

	// The optional manifest text must parse to exactly the collected manifest
	// and must itself be written in canonical form, so the persisted digest is
	// reproducible from the raw iweb.json file without re-canonicalization.
	if (options.manifestText !== undefined) {
		let parsed: unknown = null;
		let parseFailed = false;
		try {
			parsed = JSON.parse(options.manifestText);
		} catch {
			parseFailed = true;
		}
		if (parseFailed) {
			errors.push(issue("MANIFEST_INVALID_TEXT", "/manifestText", "manifest text is not valid JSON"));
		} else {
			const canonicalText = canonicalSerializeManifest(options.manifest);
			if (options.manifestText !== canonicalText || canonicalSerialize(parsed) !== canonicalText) {
				errors.push(issue("MANIFEST_NOT_CANONICAL", "/manifestText", "manifest text is not the canonical serialization of the collected manifest"));
			}
		}
	}

	if (errors.length) return failure(errors);
	return ok({ digest: packageFilesDigest(digested), fileCount: canonical.length, bytes: totalBytes, files: canonical });
}

function canonicalKeySorter(_key: string, value: unknown): unknown {
	if (Array.isArray(value)) return value.map((item) => canonicalKeySorter("", item));
	if (isRecord(value)) {
		const result: Record<string, unknown> = {};
		for (const key of Object.keys(value).sort()) result[key] = canonicalKeySorter(key, value[key]);
		return result;
	}
	return value;
}

function canonicalSerialize(value: unknown): string {
	return JSON.stringify(value, canonicalKeySorter, 2);
}

// Fixed recursive key order (alphabetical; nested objects and arrays
// preserved) so equivalent manifest objects serialize identically regardless
// of property insertion order. Used by collectPackage and versionDigest.
export function canonicalSerializeManifest(manifest: ApplicationManifest): string {
	return canonicalSerialize(manifest);
}

export function versionDigest(packageDigest: string, manifest: ApplicationManifest): string {
	const hash = createHash("sha256");
	hash.update("package:" + packageDigest);
	hash.update("\0");
	hash.update("manifest:" + canonicalSerializeManifest(manifest));
	return hash.digest("hex");
}

// The single digest authority for a canonical package: sha256 over each file's
// (path \0 decimal-length \0 content) in sorted path order. collectPackage and
// every snapshot verification path must route through this so an admitted digest
// is reproducible from the restored bytes alone.
export function packageFilesDigest(files: readonly { readonly path: string; readonly content: Buffer }[]): string {
	// Same byte-order rule as collectPackage — one ordering authority for the
	// digest contract (see the comment above).
	const canonical = [...files].sort((left, right) => Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")));
	const hash = createHash("sha256");
	for (const file of canonical) {
		hash.update(file.path);
		hash.update("\0");
		hash.update(String(file.content.length));
		hash.update("\0");
		hash.update(file.content);
	}
	return hash.digest("hex");
}
