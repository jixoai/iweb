// 用户原始需求（2026-08-14）：沙箱只能从 supervisor 物化并校验过的不可变快照运行；缺失、残缺、过期或摘要不符即 fail closed，绝不创建 pod。
// 正交意图：2.33 生产物化——把 Kernel 存入 MinIO 的 canonical snapshot 取到 supervisor 拥有的只读 bind-mount 目录，用单一摘要权威重算并比对；可注入 executor 供单测。
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

export type MaterializeExec = (command: string, args: readonly string[], options?: { readonly input?: Buffer; readonly binary?: boolean }) => string | Buffer;

const defaultExec: MaterializeExec = (command, args, options) =>
	execFileSync(command, [...args], { encoding: options?.binary === true ? null : "utf8", stdio: ["pipe", "pipe", "pipe"], input: options?.input });

export class MaterializationFailure extends Error {
	readonly kind: "missing" | "partial" | "digest-mismatch" | "infrastructure";
	constructor(kind: MaterializationFailure["kind"], message: string) {
		super(message);
		this.name = "MaterializationFailure";
		this.kind = kind;
	}
}

export interface SnapshotMaterializerOptions {
	readonly alias?: string;
	readonly exec?: MaterializeExec;
	readonly maxFiles?: number;
	readonly maxBytes?: number;
}

function isSafeRelativePath(value: string): boolean {
	if (!value || value.length > 512 || value.startsWith("/")) return false;
	return value.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..");
}

// Materializes the canonical snapshot stored under
// <alias>/packages/<digest>/ into the supervisor-owned target directory and
// verifies it against the single digest authority before the runtime mounts it.
// Layout (written by kernel/package-store.js): manifest.json, files.json (the
// stable path index), files/<path> per indexed file.
export function createSnapshotMaterializer(stateDirectory: string, options: SnapshotMaterializerOptions = {}) {
	const alias = options.alias ?? "local/iweb-system";
	const exec = options.exec ?? defaultExec;
	const maxFiles = options.maxFiles ?? 10_000;
	const maxBytes = options.maxBytes ?? 512 * 1024 * 1024;

	return async function materialize(packageDigest: string, targetDirectory: string): Promise<void> {
		const sourcePrefix = alias + "/packages/" + packageDigest;
		let indexText: string;
		try {
			indexText = exec("mc", ["cat", sourcePrefix + "/files.json"]);
		} catch {
			throw new MaterializationFailure("missing", "snapshot index is absent; refusing to create the sandbox");
		}
		let paths: string[];
		try {
			const parsed = JSON.parse(indexText) as { files?: unknown };
			if (!parsed || !Array.isArray(parsed.files)) throw new Error("bad index");
			paths = parsed.files.map(String);
		} catch {
			throw new MaterializationFailure("partial", "snapshot index is malformed; refusing to create the sandbox");
		}
		if (paths.length === 0 || paths.length > maxFiles) throw new MaterializationFailure("partial", "snapshot index is empty or exceeds the file ceiling");
		if (!paths.every(isSafeRelativePath)) throw new MaterializationFailure("partial", "snapshot index contains an unsafe path");

		mkdirSync(targetDirectory, { recursive: true, mode: 0o755 });
		// the index rides along so verifyMaterializedSnapshot can re-check the tree
		// later (restart reconciliation) without re-downloading.
		writeFileSync(join(targetDirectory, "files.json"), indexText, { mode: 0o644 });
		const restored: { path: string; content: Buffer }[] = [];
		let total = 0;
		for (const path of paths) {
			let content: Buffer;
			try {
				content = Buffer.from(exec("mc", ["cat", sourcePrefix + "/files/" + path], { binary: true }) as Buffer);
			} catch {
				throw new MaterializationFailure("partial", "indexed snapshot file is missing: " + path);
			}
			const bytes = content;
			total += bytes.byteLength;
			if (total > maxBytes) throw new MaterializationFailure("partial", "snapshot exceeds the size ceiling");
			const destination = join(targetDirectory, path);
			mkdirSync(join(destination, ".."), { recursive: true });
			writeFileSync(destination, bytes, { mode: 0o644 });
			restored.push({ path, content: bytes });
		}
		const actual = packageFilesDigest(restored);
		if (actual !== packageDigest) {
			throw new MaterializationFailure("digest-mismatch", "materialized snapshot content does not match its digest");
		}
	};
}

// Verifies an already-materialized directory still matches the digest without
// re-downloading (used on prepare of an existing sandbox / restart reconciliation).
export function verifyMaterializedSnapshot(packageDigest: string, targetDirectory: string): boolean {
	try {
		const indexText = readFileSync(join(targetDirectory, "files.json"), "utf8");
		// the materialized tree carries only the indexed files (files.json itself is metadata)
		const parsed = JSON.parse(indexText) as { files?: string[] };
		if (!parsed || !Array.isArray(parsed.files) || parsed.files.length === 0) return false;
		const restored: { path: string; content: Buffer }[] = [];
		for (const path of parsed.files) {
			if (!isSafeRelativePath(path)) return false;
			const entry = statSync(join(targetDirectory, path));
			if (!entry.isFile()) return false;
			restored.push({ path, content: readFileSync(join(targetDirectory, path)) });
		}
		return packageFilesDigest(restored) === packageDigest;
	} catch {
		return false;
	}
}

export function _internal() {
	return { isSafeRelativePath, readdirSync };
}
