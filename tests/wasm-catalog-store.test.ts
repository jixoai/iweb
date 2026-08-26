// 用户原始需求（2026-08-26，add-wasm-runtime 任务 7.7 + 4.2）：wasm catalog store 的正/负向量——
//   固定路径布局（revisions/index/release-receipts/delete-audit）、启动重建（index 缺失/损坏重建、
//   分歧/坏 digest fail-closed）、revision CAS 与受保护 entry 禁删、CVE revoke 不删除且阻断、
//   release→GC 全链（保留期/引用保护/审计先行/审计缺失 fail-closed）、幂等重放（append/release/gc）。
// 正交意图：负例断言稳定错误码；「零写入」以全目录字节快照为准；恢复语义以重开 store（新实例）为准。
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	CATALOG_DELETE_AUDIT_STORE_MISMATCH,
	CATALOG_HISTORY_LAST_PRESENT,
	CATALOG_HISTORY_RECORD_MISSING,
	CATALOG_RELEASE_RECEIPT_MISSING,
	CATALOG_RELEASE_RECEIPT_STORE_MISMATCH,
	systemWasmCatalogStoreIO,
	WasmCatalogStore,
	WASM_CATALOG_STORE_ALREADY_INITIALIZED,
	WASM_CATALOG_STORE_CORRUPT,
	WASM_CATALOG_STORE_DIVERGENT,
	WASM_CATALOG_STORE_UNINITIALIZED,
	WasmCatalogStoreError,
	type WasmCatalogStoreIO,
	type WasmCatalogStoreOutcome,
} from "../supervisor/wasm-catalog-store.ts";
import {
	CATALOG_RELEASE_RETENTION_SECONDS,
	CATALOG_REVISION_CONFLICT,
	catalogHistoryRevisionFilePath,
	exampleRuntimeBindingForCatalogEntry,
	exampleRuntimeCatalogV1,
	exampleWasmRollbackRecordV1,
	rollbackRecordReference,
	sealCatalogHistoryRecordV1,
	sealRuntimeCatalogV1,
	validateCatalogDeleteAuditV1,
	validateCatalogHistoryIndexV1,
	validateCatalogHistoryRecordV1,
	validateCatalogReleaseReceiptV1,
	WASM_CATALOG_ENTRY_PROTECTED,
	WASM_RUNTIME_BINDING_RELEASED,
	WASM_RUNTIME_BINDING_REVOKED,
	type RuntimeCatalogV1,
	type WasmCatalogEntryReferenceV1,
} from "../packages/contracts/wasm-catalog.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";

const FIXED_NOW = "2026-08-26T00:00:00.000Z";
const RELEASE_ID = "018f1e2c-3d4b-7a5e-9f01-23456789aaaa";
const OTHER_RELEASE_ID = "018f1e2c-3d4b-7a5e-9f01-23456789aaba";
const OWNER_COMMAND_ID = "018f1e2c-3d4b-7a5e-9f01-23456789bbbb";
const DELETE_ID = "018f1e2c-3d4b-7a5e-9f01-23456789cccc";
const OTHER_DELETE_ID = "018f1e2c-3d4b-7a5e-9f01-23456789ccdc";
const REVOCATION = { cve: "CVE-2026-4242", reasonCode: "wasmd-wasm-bypass", revokedAt: "2026-08-26T00:00:00Z" } as const;
const DRAINED_AT = "2026-08-26T00:00:00Z";
const RELEASED_AT = "2026-08-26T00:01:00Z";
const DELETED_AFTER_RETENTION = "2027-08-27T00:00:00Z";

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-catalog-store-"));
}

function newStore(directory: string, io: WasmCatalogStoreIO = systemWasmCatalogStoreIO): WasmCatalogStore {
	return new WasmCatalogStore(io, directory, { now: () => FIXED_NOW });
}

function bootstrapped(directory: string): { readonly store: WasmCatalogStore; readonly catalog: RuntimeCatalogV1 } {
	const store = newStore(directory);
	const example = exampleRuntimeCatalogV1();
	const outcome = store.bootstrap({ schemaVersion: 1, revision: example.revision, entries: example.entries });
	if (!outcome.ok) throw new Error("fixture error: bootstrap failed: " + outcome.code);
	return { store, catalog: outcome.value.catalog };
}

function revisionPath(directory: string, revision: number, catalogHash: string): string {
	return join(directory, "revisions", revision + "-" + catalogHash + ".json");
}

function indexPath(directory: string): string {
	return join(directory, "catalog-history-index-v1.json");
}

function receiptPath(directory: string, releaseId: string): string {
	return join(directory, "release-receipts", releaseId + ".json");
}

function auditPath(directory: string, deleteId: string): string {
	return join(directory, "delete-audit", deleteId + ".json");
}

function snapshotTree(root: string): Map<string, string> {
	const files = new Map<string, string>();
	if (!existsSync(root)) return files;
	const walk = (directory: string, prefix: string): void => {
		const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) => (left.name < right.name ? -1 : 1));
		for (const entry of entries) {
			if (entry.isDirectory()) walk(join(directory, entry.name), prefix + entry.name + "/");
			else if (entry.isFile()) files.set(prefix + entry.name, readFileSync(join(directory, entry.name), "utf8"));
		}
	};
	walk(root, "");
	return files;
}

function expectSnapshotsEqual(left: Map<string, string>, right: Map<string, string>): void {
	expect([...left.keys()].sort()).toEqual([...right.keys()].sort());
	for (const [path, content] of left) expect(right.get(path)).toBe(content);
}

function expectFailure<T>(outcome: WasmCatalogStoreOutcome<T>): string {
	expect(outcome.ok).toBe(false);
	if (outcome.ok) throw new Error("expected failure");
	return outcome.code;
}

function expectStoreErrorCode(action: () => unknown, code: string): void {
	let caught: unknown = null;
	try {
		action();
	} catch (error) {
		caught = error;
	}
	expect(caught).toBeInstanceOf(WasmCatalogStoreError);
	if (caught instanceof WasmCatalogStoreError) expect(caught.code).toBe(code);
}

function writeJcs(path: string, value: unknown): void {
	writeFileSync(path, Buffer.from(jcsCanonicalBytes(value)).toString("utf8"));
}

function readJson(path: string): unknown {
	return JSON.parse(readFileSync(path, "utf8"));
}

function nextPayload(catalog: RuntimeCatalogV1, revision?: number): unknown {
	return { schemaVersion: 1, revision: revision ?? catalog.revision + 1, entries: catalog.entries };
}

function releaseInput(entryKey: string, references: readonly WasmCatalogEntryReferenceV1[] = [], releaseId: string = RELEASE_ID, releasedAt: string = RELEASED_AT): {
	readonly entryKey: string;
	readonly references: readonly WasmCatalogEntryReferenceV1[];
	readonly releaseId: string;
	readonly ownerCommandId: string;
	readonly drainedAt: string;
	readonly releasedAt: string;
} {
	return { entryKey, references, releaseId, ownerCommandId: OWNER_COMMAND_ID, drainedAt: DRAINED_AT, releasedAt };
}

function gcInput(releaseId: string = RELEASE_ID, deleteId: string = DELETE_ID, references: readonly WasmCatalogEntryReferenceV1[] = [], deletedAt: string = DELETED_AFTER_RETENTION): {
	readonly releaseId: string;
	readonly deleteId: string;
	readonly ownerCommandId: string;
	readonly deletedAt: string;
	readonly reason: string;
	readonly references: readonly WasmCatalogEntryReferenceV1[];
} {
	return { releaseId, deleteId, ownerCommandId: OWNER_COMMAND_ID, deletedAt, reason: "owner-approved cleanup after retention", references };
}

// delete-audit 写入被破坏的 IO：审计对象无法在盘上证明 → gc 必须在删除 revision 文件前中止。
function corruptingAuditIO(): WasmCatalogStoreIO {
	return {
		...systemWasmCatalogStoreIO,
		writeFileAtomic: (path, content) => {
			if (path.includes("/delete-audit/")) {
				systemWasmCatalogStoreIO.writeFileAtomic(path, "garbage{");
				return;
			}
			systemWasmCatalogStoreIO.writeFileAtomic(path, content);
		},
	};
}

// ---------------------------------------------------------------------------
// 固定布局与启动重建
// ---------------------------------------------------------------------------

describe("wasm catalog store fixed layout and recovery", () => {
	test("bootstrap writes revision + index at the spec-fixed layout and reopens deterministically", () => {
		const directory = tempDirectory();
		const { catalog } = bootstrapped(directory);

		expect(existsSync(revisionPath(directory, catalog.revision, catalog.catalogHash))).toBe(true);
		const record = validateCatalogHistoryRecordV1(readJson(revisionPath(directory, catalog.revision, catalog.catalogHash)));
		expect(record.ok).toBe(true);
		// 落盘字节是 JCS（读回 raw bytes 必须等于 JCS(parse)）。
		expect(readFileSync(revisionPath(directory, catalog.revision, catalog.catalogHash), "utf8")).toBe(Buffer.from(jcsCanonicalBytes(readJson(revisionPath(directory, catalog.revision, catalog.catalogHash)))).toString("utf8"));

		const index = validateCatalogHistoryIndexV1(readJson(indexPath(directory)));
		expect(index.ok).toBe(true);
		if (index.ok) {
			expect(index.value.currentRevision).toBe(catalog.revision);
			expect(index.value.currentHash).toBe(catalog.catalogHash);
			// index 的 path 字段恒为 spec 公式路径（/data/kernel/...），与物理 root 无关。
			expect(index.value.revisions[0]?.path).toBe(catalogHistoryRevisionFilePath(catalog.revision, catalog.catalogHash));
		}

		const reopened = newStore(directory);
		expect(reopened.current()).toEqual(catalog);
		expect(reopened.readIndex()?.currentRevision).toBe(catalog.revision);
	});

	test("an uninitialized store has no current revision and fails closed on append before bootstrap", () => {
		const directory = tempDirectory();
		const store = newStore(directory);
		expect(store.current()).toBeNull();
		expect(store.readIndex()).toBeNull();
		const example = exampleRuntimeCatalogV1();
		expect(expectFailure(store.append({ revision: example.revision, catalogHash: example.catalogHash }, nextPayload(example)))).toBe(WASM_CATALOG_STORE_UNINITIALIZED);
		expect(expectFailure(store.revoke({ revision: example.revision, catalogHash: example.catalogHash }, "iweb-wasmd-amd64", REVOCATION))).toBe(WASM_CATALOG_STORE_UNINITIALIZED);
		expect(expectFailure(store.release(releaseInput("legacy-wasmd-amd64")))).toBe(WASM_CATALOG_STORE_UNINITIALIZED);

		const boot = store.bootstrap(nextPayload(example, example.revision));
		expect(boot.ok).toBe(true);
		expect(expectFailure(store.bootstrap(nextPayload(example, example.revision)))).toBe(WASM_CATALOG_STORE_ALREADY_INITIALIZED);
	});

	test("a corrupt or missing index is rebuilt from intact history files (gate stays closed until the hash is proven)", () => {
		for (const corruption of ["overwrite-garbage", "delete-index"] as const) {
			const directory = tempDirectory();
			const { store, catalog } = bootstrapped(directory);
			const appended = store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, nextPayload(catalog));
			expect(appended.ok).toBe(true);
			if (corruption === "overwrite-garbage") writeFileSync(indexPath(directory), "not json {{{");
			else rmSync(indexPath(directory));

			// 启动恢复（open）负责重建并落盘；读路径只读不写。
			const reopened = newStore(directory);
			expect(reopened.current()?.revision).toBe(catalog.revision + 1);
			expect(reopened.open()?.revision).toBe(catalog.revision + 1);
			const rebuilt = validateCatalogHistoryIndexV1(readJson(indexPath(directory)));
			expect(rebuilt.ok).toBe(true);
			if (rebuilt.ok) expect(rebuilt.value.currentRevision).toBe(catalog.revision + 1);
		}
	});

	test("a tampered record digest, non-canonical bytes, or an unexpected object fails closed", () => {
		const directory = tempDirectory();
		const { catalog } = bootstrapped(directory);
		const path = revisionPath(directory, catalog.revision, catalog.catalogHash);

		const tampered = readJson(path) as { storedAt: string };
		tampered.storedAt = "2027-01-01T00:00:00Z";
		writeJcs(path, tampered);
		expectStoreErrorCode(() => newStore(directory).current(), WASM_CATALOG_STORE_CORRUPT);

		writeFileSync(path, JSON.stringify(readJson(path), null, 2));
		expectStoreErrorCode(() => newStore(directory).current(), WASM_CATALOG_STORE_CORRUPT);

		writeJcs(path, readJson(path));
		writeFileSync(join(directory, "revisions", "notes.txt"), "stray");
		expectStoreErrorCode(() => newStore(directory).current(), WASM_CATALOG_STORE_CORRUPT);
	});

	test("duplicate revisions or a valid index disagreeing with files fail closed; owner rebuildIndex repairs", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const indexBeforeAppend = readFileSync(indexPath(directory), "utf8");
		const appended = store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, nextPayload(catalog));
		expect(appended.ok).toBe(true);
		if (!appended.ok) throw new Error("fixture error");

		// 同 revision 两份不同 hash 的历史文件 → 分歧。
		const alternative = sealRuntimeCatalogV1({ schemaVersion: 1, revision: catalog.revision + 1, entries: catalog.entries.slice(0, 2) });
		expect(alternative.ok).toBe(true);
		if (alternative.ok) {
			const alternativeRecord = sealCatalogHistoryRecordV1({ schemaVersion: 1, runtimeKind: "wasm", revision: alternative.value.revision, catalogHash: alternative.value.catalogHash, catalog: alternative.value, storedAt: FIXED_NOW });
			expect(alternativeRecord.ok).toBe(true);
			if (alternativeRecord.ok) writeJcs(revisionPath(directory, alternative.value.revision, alternative.value.catalogHash), alternativeRecord.value);
		}
		expectStoreErrorCode(() => newStore(directory).current(), WASM_CATALOG_STORE_DIVERGENT);
		rmSync(revisionPath(directory, alternative.ok ? alternative.value.revision : 0, alternative.ok ? alternative.value.catalogHash : ""));

		// 有效但过期的 index（append 前快照）与文件分歧 → fail-closed；owner 显式 rebuildIndex 修复。
		writeFileSync(indexPath(directory), indexBeforeAppend);
		expectStoreErrorCode(() => newStore(directory).current(), WASM_CATALOG_STORE_DIVERGENT);
		const repaired = newStore(directory).rebuildIndex();
		expect(repaired.ok).toBe(true);
		if (repaired.ok) expect(repaired.value.currentRevision).toBe(catalog.revision + 1);
		expect(newStore(directory).current()?.revision).toBe(catalog.revision + 1);
	});

	test("an index claiming revisions whose files vanished fails closed", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		expect(store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, nextPayload(catalog)).ok).toBe(true);
		rmSync(revisionPath(directory, catalog.revision, catalog.catalogHash));
		expectStoreErrorCode(() => newStore(directory).current(), WASM_CATALOG_STORE_DIVERGENT);

		const emptied = tempDirectory();
		const { catalog: sole } = bootstrapped(emptied);
		rmSync(revisionPath(emptied, sole.revision, sole.catalogHash));
		expectStoreErrorCode(() => newStore(emptied).current(), WASM_CATALOG_STORE_DIVERGENT);
	});
});

// ---------------------------------------------------------------------------
// owner append：CAS、幂等重放、受保护 entry 禁删
// ---------------------------------------------------------------------------

describe("owner append CAS and protected entries", () => {
	test("appends revision + 1 with history preserved and the index current pointer advanced", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const outcome = store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, nextPayload(catalog));
		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("fixture error");
		expect(outcome.value.catalog.revision).toBe(catalog.revision + 1);
		expect(existsSync(revisionPath(directory, catalog.revision, catalog.catalogHash))).toBe(true);
		expect(existsSync(revisionPath(directory, catalog.revision + 1, outcome.value.catalog.catalogHash))).toBe(true);
		expect(newStore(directory).readIndex()?.currentRevision).toBe(catalog.revision + 1);
	});

	test("two racing appends from the same expected pair: one wins, the other conflicts with zero writes", () => {
		const directory = tempDirectory();
		const { catalog } = bootstrapped(directory);
		const winner = newStore(directory);
		const loser = newStore(directory);
		const pin = { revision: catalog.revision, catalogHash: catalog.catalogHash };
		expect(winner.append(pin, nextPayload(catalog)).ok).toBe(true);
		const before = snapshotTree(directory);
		expect(expectFailure(loser.append(pin, nextPayload(catalog)))).toBe(CATALOG_REVISION_CONFLICT);
		expectSnapshotsEqual(before, snapshotTree(directory));

		// 期望 revision 不是 current+1 同样冲突。
		expect(expectFailure(winner.append({ revision: catalog.revision + 2, catalogHash: catalog.catalogHash }, nextPayload(catalog, catalog.revision + 3)))).toBe(CATALOG_REVISION_CONFLICT);
		expectSnapshotsEqual(before, snapshotTree(directory));
	});

	test("a byte-identical re-append from the same pin conflicts with zero writes (idempotency lives on releaseId/deleteId keys)", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const pin = { revision: catalog.revision, catalogHash: catalog.catalogHash };
		expect(store.append(pin, nextPayload(catalog)).ok).toBe(true);
		const before = snapshotTree(directory);
		// spec 场景：同一 expected pin 的第二次 append 一律冲突，不因字节相同而静默重放。
		expect(expectFailure(store.append(pin, nextPayload(catalog)))).toBe(CATALOG_REVISION_CONFLICT);
		expectSnapshotsEqual(before, snapshotTree(directory));
		// 同一 slot 上不同 next 内容同样冲突。
		expect(expectFailure(store.append(pin, nextPayload(catalog, catalog.revision + 2)))).toBe(CATALOG_REVISION_CONFLICT);
	});

	test("a referenced entry must not be deleted from a subsequent revision (zero writes)", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const binding = exampleRuntimeBindingForCatalogEntry(catalog, "iweb-wasmd-amd64");
		const references: readonly WasmCatalogEntryReferenceV1[] = [
			{ kind: "active-version", runtimeBinding: binding },
			rollbackRecordReference(exampleWasmRollbackRecordV1(binding)),
		];
		const withoutProtected = { schemaVersion: 1, revision: catalog.revision + 1, entries: catalog.entries.filter((entry) => entry.entryKey !== "iweb-wasmd-amd64") };
		const before = snapshotTree(directory);
		expect(expectFailure(store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, withoutProtected, references))).toBe(WASM_CATALOG_ENTRY_PROTECTED);
		expectSnapshotsEqual(before, snapshotTree(directory));
		// 引用解除后同一删除可通过。
		expect(store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, withoutProtected, []).ok).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// CVE revoke：追加 revoked revision、不删除、阻断新操作
// ---------------------------------------------------------------------------

describe("CVE revoke lifecycle", () => {
	test("revoke appends a revoked revision without deleting the entry; repeats fail closed with zero writes", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const pin = { revision: catalog.revision, catalogHash: catalog.catalogHash };
		const revoked = store.revoke(pin, "iweb-wasmd-amd64", REVOCATION);
		expect(revoked.ok).toBe(true);
		if (!revoked.ok) throw new Error("fixture error");
		expect(revoked.value.catalog.revision).toBe(catalog.revision + 1);
		const entry = revoked.value.catalog.entries.find((candidate) => candidate.entryKey === "iweb-wasmd-amd64");
		expect(entry).toBeDefined();
		if (entry !== undefined && entry.status === "revoked") expect(entry.revocation).toEqual(REVOCATION);
		// 历史 revision 保留 replay：旧文件不删。
		expect(existsSync(revisionPath(directory, catalog.revision, catalog.catalogHash))).toBe(true);

		const before = snapshotTree(directory);
		// 重复 revoke（同字段或不同字段）一律 fail-closed；revoke 没有幂等重放键。
		expect(expectFailure(store.revoke(pin, "iweb-wasmd-amd64", REVOCATION))).toBe("WASM_CATALOG_ENTRY_ALREADY_REVOKED");
		expectSnapshotsEqual(before, snapshotTree(directory));
		expect(expectFailure(store.revoke(pin, "iweb-wasmd-amd64", { ...REVOCATION, cve: "CVE-2026-9999" }))).toBe("WASM_CATALOG_ENTRY_ALREADY_REVOKED");
		expect(expectFailure(store.revoke(pin, "missing-entry", REVOCATION))).toBe("WASM_CATALOG_ENTRY_NOT_FOUND");
	});

	test("revocation blocks new prepare/activation/rollback through the store fence", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		expect(store.revoke({ revision: catalog.revision, catalogHash: catalog.catalogHash }, "iweb-wasmd-amd64", REVOCATION).ok).toBe(true);
		const current = store.current();
		if (current === null) throw new Error("fixture error");
		const revokedBinding = exampleRuntimeBindingForCatalogEntry(current, "iweb-wasmd-amd64");
		const rejected = store.checkBindingUsable(revokedBinding, "linux/amd64");
		expect(rejected.ok).toBe(false);
		if (!rejected.ok) expect(rejected.errors.some((entry) => entry.code === WASM_RUNTIME_BINDING_REVOKED)).toBe(true);
		const activeBinding = exampleRuntimeBindingForCatalogEntry(current, "iweb-wasmd-arm64");
		expect(store.checkBindingUsable(activeBinding, "linux/arm64").ok).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// release receipt / GC 全链
// ---------------------------------------------------------------------------

describe("release and garbage collection", () => {
	test("release is blocked while a rollback reference remains, then writes a one-year retention receipt", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const legacyBinding = exampleRuntimeBindingForCatalogEntry(catalog, "legacy-wasmd-amd64");
		const before = snapshotTree(directory);
		expect(expectFailure(store.release(releaseInput("legacy-wasmd-amd64", [rollbackRecordReference(exampleWasmRollbackRecordV1(legacyBinding))])))).toBe(WASM_CATALOG_ENTRY_PROTECTED);
		expectSnapshotsEqual(before, snapshotTree(directory));
		expect(expectFailure(store.release(releaseInput("missing-entry")))).toBe("WASM_CATALOG_ENTRY_NOT_FOUND");

		const released = store.release(releaseInput("legacy-wasmd-amd64"));
		expect(released.ok).toBe(true);
		if (!released.ok) throw new Error("fixture error");
		expect(released.value.protectedReferenceCount).toBe(0);
		expect(Date.parse(released.value.releaseRetentionUntil)).toBe(Date.parse(RELEASED_AT) + CATALOG_RELEASE_RETENTION_SECONDS * 1000);
		expect(validateCatalogReleaseReceiptV1(readJson(receiptPath(directory, RELEASE_ID))).ok).toBe(true);
		// index 的 retention 快照随 receipt 刷新。
		expect(newStore(directory).readIndex()?.revisions.find((entry) => entry.revision === catalog.revision)?.releaseRetentionUntil).toBe(released.value.releaseRetentionUntil);

		// 幂等重放 / 同 releaseId 不同请求 → fail-closed。
		const replay = store.release(releaseInput("legacy-wasmd-amd64"));
		expect(replay.ok).toBe(true);
		if (replay.ok) expect(replay.value).toEqual(released.value);
		expect(expectFailure(store.release(releaseInput("legacy-wasmd-amd64", [], RELEASE_ID, "2026-08-26T00:09:00Z")))).toBe(CATALOG_RELEASE_RECEIPT_STORE_MISMATCH);
	});

	test("gc before retention or with a protected reference fails closed, preserves the file, and records the reference", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const legacyBinding = exampleRuntimeBindingForCatalogEntry(catalog, "legacy-wasmd-amd64");
		expect(store.release(releaseInput("legacy-wasmd-amd64")).ok).toBe(true);
		expect(store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, nextPayload(catalog)).ok).toBe(true);
		const revisionFile = revisionPath(directory, catalog.revision, catalog.catalogHash);

		expect(expectFailure(store.gc(gcInput(RELEASE_ID, DELETE_ID, [], "2026-09-01T00:00:00Z")))).toBe("CATALOG_RELEASE_RETENTION_ACTIVE");
		expect(existsSync(revisionFile)).toBe(true);
		expect(existsSync(auditPath(directory, DELETE_ID))).toBe(false);

		const protectedRefs: readonly WasmCatalogEntryReferenceV1[] = [{ kind: "active-version", runtimeBinding: legacyBinding }];
		expect(expectFailure(store.gc(gcInput(RELEASE_ID, DELETE_ID, protectedRefs)))).toBe(WASM_CATALOG_ENTRY_PROTECTED);
		expect(existsSync(revisionFile)).toBe(true);
		// spec 场景：删除 CAS 失败后，下一次 index 记录受保护引用。
		expect(newStore(directory).readIndex()?.revisions.find((entry) => entry.revision === catalog.revision)?.protectedReferenceCount).toBe(1);

		expect(expectFailure(store.gc(gcInput(OTHER_RELEASE_ID, DELETE_ID)))).toBe(CATALOG_RELEASE_RECEIPT_MISSING);
	});

	test("gc writes the audit first, removes the revision file, and marks the index entry deleted", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		expect(store.release(releaseInput("legacy-wasmd-amd64")).ok).toBe(true);
		const appended = store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, nextPayload(catalog));
		expect(appended.ok).toBe(true);
		if (!appended.ok) throw new Error("fixture error");
		const revisionFile = revisionPath(directory, catalog.revision, catalog.catalogHash);

		const collected = store.gc(gcInput());
		expect(collected.ok).toBe(true);
		if (!collected.ok) throw new Error("fixture error");
		expect(existsSync(revisionFile)).toBe(false);
		const audit = validateCatalogDeleteAuditV1(readJson(auditPath(directory, DELETE_ID)));
		expect(audit.ok).toBe(true);
		if (audit.ok) expect(audit.value).toEqual(collected.value.audit);
		const index = newStore(directory).readIndex();
		expect(index?.currentRevision).toBe(catalog.revision + 1);
		const deletedEntry = index?.revisions.find((entry) => entry.revision === catalog.revision);
		expect(deletedEntry?.status).toBe("deleted");
		expect(deletedEntry?.deletedAt).toBe(DELETED_AFTER_RETENTION);
		expect(deletedEntry?.path).toBe(catalogHistoryRevisionFilePath(catalog.revision, catalog.catalogHash));

		// 完成态重放幂等；不同 deleteId 对同一 release → 历史文件已收集，fail-closed；
		// 同 deleteId 但请求字段不同 → 审计不匹配，fail-closed。
		const replay = store.gc(gcInput());
		expect(replay.ok).toBe(true);
		if (replay.ok) expect(replay.value.audit).toEqual(collected.value.audit);
		expect(expectFailure(store.gc(gcInput(RELEASE_ID, OTHER_DELETE_ID)))).toBe(CATALOG_HISTORY_RECORD_MISSING);
		expect(expectFailure(store.gc(gcInput(RELEASE_ID, DELETE_ID, [], "2027-08-26T00:01:00.000Z")))).toBe(CATALOG_DELETE_AUDIT_STORE_MISMATCH);
	});

	test("a sabotaged audit write aborts gc and preserves the revision file", () => {
		const directory = tempDirectory();
		const plain = bootstrapped(directory);
		expect(plain.store.release(releaseInput("legacy-wasmd-amd64")).ok).toBe(true);
		expect(plain.store.append({ revision: plain.catalog.revision, catalogHash: plain.catalog.catalogHash }, nextPayload(plain.catalog)).ok).toBe(true);
		const indexBefore = readFileSync(indexPath(directory), "utf8");
		const revisionFile = revisionPath(directory, plain.catalog.revision, plain.catalog.catalogHash);

		const sabotaged = newStore(directory, corruptingAuditIO());
		expectStoreErrorCode(() => sabotaged.gc(gcInput()), WASM_CATALOG_STORE_CORRUPT);
		expect(existsSync(revisionFile)).toBe(true);
		expect(readFileSync(indexPath(directory), "utf8")).toBe(indexBefore);
	});

	test("gc refusing to remove the last present revision and audit-missing fail-closed at recovery", () => {
		const lastDirectory = tempDirectory();
		const { store, catalog } = bootstrapped(lastDirectory);
		expect(store.release(releaseInput("legacy-wasmd-amd64")).ok).toBe(true);
		expect(expectFailure(store.gc(gcInput()))).toBe(CATALOG_HISTORY_LAST_PRESENT);
		expect(existsSync(revisionPath(lastDirectory, catalog.revision, catalog.catalogHash))).toBe(true);

		const directory = tempDirectory();
		const seeded = bootstrapped(directory);
		expect(seeded.store.release(releaseInput("legacy-wasmd-amd64")).ok).toBe(true);
		expect(seeded.store.append({ revision: seeded.catalog.revision, catalogHash: seeded.catalog.catalogHash }, nextPayload(seeded.catalog)).ok).toBe(true);
		expect(seeded.store.gc(gcInput()).ok).toBe(true);
		// 审计对象被移除后，恢复必须 fail-closed（receipt 所指 revision 的文件与审计皆无）。
		rmSync(auditPath(directory, DELETE_ID));
		expectStoreErrorCode(() => newStore(directory).current(), WASM_CATALOG_STORE_DIVERGENT);
	});

	test("a released binding stays non-reactivatable and auditable after collection", () => {
		const directory = tempDirectory();
		const { store, catalog } = bootstrapped(directory);
		const legacyBinding = exampleRuntimeBindingForCatalogEntry(catalog, "legacy-wasmd-amd64");
		const released = store.release(releaseInput("legacy-wasmd-amd64"));
		expect(released.ok).toBe(true);
		const rejected = store.checkBindingUsable(legacyBinding, "linux/amd64");
		expect(rejected.ok).toBe(false);
		if (!rejected.ok) expect(rejected.errors.some((entry) => entry.code === WASM_RUNTIME_BINDING_RELEASED)).toBe(true);

		expect(store.append({ revision: catalog.revision, catalogHash: catalog.catalogHash }, nextPayload(catalog)).ok).toBe(true);
		expect(store.gc(gcInput()).ok).toBe(true);
		// 历史 binding 仍可审计：receipt 与 delete audit 都保留。
		const reopened = newStore(directory);
		expect(reopened.receipts().length).toBe(1);
		expect(reopened.audits().length).toBe(1);
		const stillRejected = reopened.checkBindingUsable(legacyBinding, "linux/amd64");
		expect(stillRejected.ok).toBe(false);
		if (!stillRejected.ok) expect(stillRejected.errors.some((entry) => entry.code === WASM_RUNTIME_BINDING_RELEASED)).toBe(true);
	});
});
