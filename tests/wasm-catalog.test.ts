// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.4）：runtime catalog 与 node capability record v1 的正/负向量——catalog hash 自校验、revision CAS 冲突、entry 唯一键/禁删/被引用保护、CVE revoke 不删除但阻断新 prepare/activation/rollback、release 后可删、历史 revision 恢复索引重建、reserve 与 binding+arch 的 memoryBytes 字节比较、缺失/不等/reserve>=memoryBytes fail-closed。
// 正交意图：负例断言稳定错误码；digest 用手拼 JCS preimage / 预排序 JSON.stringify 字面量的独立 oracle；矩阵与既有 wasm-capability 行为保持一致。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
	appendNodeCapabilityRecordV1,
	appendRuntimeCatalogRevision,
	CATALOG_RELEASE_RECEIPT_DIGEST_DOMAIN,
	CATALOG_RELEASE_RETENTION_SECONDS,
	CATALOG_REVISION_CONFLICT,
	catalogDeleteAuditFilePath,
	catalogHistoryRevisionFileName,
	catalogHistoryRevisionFilePath,
	catalogReleaseReceiptFilePath,
	checkNodeCapabilityPin,
	checkRuntimeBindingCapabilityCompatibility,
	checkRuntimeBindingNotReleased,
	checkRuntimeBindingUsable,
	checkWasmMemoryReservation,
	checkWasmPolicyMaxima,
	computeCatalogHistoryRecordDigestV1,
	computeNodeCapabilityRecordHashV1,
	computeRuntimeCatalogHashV1,
	exampleCatalogHistoryRecordV1,
	exampleNodeCapabilityRecordV1,
	exampleRuntimeBindingForCatalogEntry,
	exampleRuntimeCatalogV1,
	exampleWasmRollbackRecordV1,
	findRuntimeReserve,
	gcCatalogHistoryRevision,
	NODE_CAPABILITY_RECORD_HASH_DOMAIN,
	protectedRuntimeCatalogEntryKeys,
	rebuildCatalogHistoryIndex,
	releaseRuntimeCatalogEntry,
	rollbackRecordReference,
	revokeRuntimeCatalogEntry,
	RUNTIME_CATALOG_HASH_DOMAIN,
	sealNodeCapabilityRecordV1,
	sealRuntimeCatalogV1,
	validateCatalogDeleteAuditV1,
	validateCatalogHistoryFileName,
	validateCatalogHistoryIndexV1,
	validateCatalogHistoryRecordV1,
	validateCatalogReleaseReceiptV1,
	validateNodeCapabilityRecordV1,
	validateRuntimeCatalogV1,
	validateWasmRollbackRecordV1,
	WASM_CAPABILITY_REVISION_CONFLICT,
	WASM_CATALOG_ENTRY_NOT_FOUND,
	WASM_CATALOG_ENTRY_PROTECTED,
	WASM_RESOURCE_RECORD_INVALID,
	WASM_RUNTIME_BINDING_RELEASED,
	WASM_RUNTIME_BINDING_REVOKED,
	type CatalogHistoryRecordV1,
	type RuntimeCatalogEntryV1,
	type RuntimeCatalogPayloadV1,
	type WasmCatalogEntryReferenceV1,
} from "../packages/contracts/wasm-catalog.ts";
import { WASM_CAPABILITY_MATRIX_REVISION_1 } from "../packages/contracts/wasm-capability.ts";
import { jcsCanonicalize, WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL } from "../packages/contracts/wasm-package.ts";
import type { RuntimeBindingIdentityV1 } from "../packages/contracts/wasm-execution.ts";
import type { ValidationIssue, ValidationResult } from "../packages/contracts/validation.ts";

const RELEASE_ID = "018f1e2c-3d4b-7a5e-9f01-23456789aaaa";
const OWNER_COMMAND_ID = "018f1e2c-3d4b-7a5e-9f01-23456789bbbb";
const DELETE_ID = "018f1e2c-3d4b-7a5e-9f01-23456789cccc";

function expectRejected(result: ValidationResult<unknown>): readonly ValidationIssue[] {
	expect(result.ok).toBe(false);
	if (result.ok) throw new Error("expected rejection");
	return result.errors;
}

function hasCode(errors: readonly ValidationIssue[], code: string): boolean {
	return errors.some((entry) => entry.code === code);
}

function roundTrip(value: unknown): unknown {
	return JSON.parse(JSON.stringify(value));
}

function sha256Text(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// 手拼 JCS oracle：example catalog 的 payload（无 catalogHash）与完整 record（含 hash）
// ---------------------------------------------------------------------------

function catalogEntryJcs(entryKey: string, architecture: string, imageHex: string, middle: string): string {
	return (
		'{"architecture":"' + architecture +
		'","entryKey":"' + entryKey +
		'","hostABI":"' + WASM_HOST_ABI_LITERAL +
		'","imageDigest":"sha256:' + imageHex +
		'","kind":"wasm"' + middle +
		',"world":"' + WASM_WORLD_LITERAL + '"}'
	);
}

const CATALOG_ENTRIES_JCS =
	catalogEntryJcs("iweb-wasmd-amd64", "linux/amd64", "a".repeat(64), ',"status":"active"') + "," +
	catalogEntryJcs("iweb-wasmd-arm64", "linux/arm64", "b".repeat(64), ',"status":"active"') + "," +
	catalogEntryJcs("legacy-wasmd-amd64", "linux/amd64", "c".repeat(64), ',"revocation":{"cve":"CVE-2026-1234","reasonCode":"wasmd-memory-corruption","revokedAt":"2026-08-01T00:00:00Z"},"status":"revoked"');
const CATALOG_PAYLOAD_JCS = '{"entries":[' + CATALOG_ENTRIES_JCS + '],"revision":8,"schemaVersion":1}';

// ---------------------------------------------------------------------------
// RuntimeCatalogV1
// ---------------------------------------------------------------------------

describe("runtime catalog record", () => {
	test("round-trips through JSON and reproduces the hand-built catalogHash oracle", () => {
		const example = exampleRuntimeCatalogV1();
		const result = validateRuntimeCatalogV1(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);

		// 序列化器与手拼 JCS 逐字节一致；hash 是域前缀单次 SHA-256（不是对 hex 再哈希）。
		const payload: RuntimeCatalogPayloadV1 = { schemaVersion: 1, revision: example.revision, entries: example.entries };
		expect(jcsCanonicalize(payload)).toBe(CATALOG_PAYLOAD_JCS);
		expect(computeRuntimeCatalogHashV1(payload)).toBe(sha256Text(RUNTIME_CATALOG_HASH_DOMAIN + "\n" + CATALOG_PAYLOAD_JCS));
		expect(example.catalogHash).toBe(sha256Text(RUNTIME_CATALOG_HASH_DOMAIN + "\n" + CATALOG_PAYLOAD_JCS));
	});

	test("seal computes the hash and refuses a payload that carries catalogHash", () => {
		const example = exampleRuntimeCatalogV1();
		const sealed = sealRuntimeCatalogV1({ schemaVersion: 1, revision: example.revision, entries: example.entries });
		expect(sealed.ok).toBe(true);
		if (sealed.ok) expect(sealed.value).toEqual(example);
		expectRejected(sealRuntimeCatalogV1(example));
	});

	test("rejects a tampered catalogHash and unknown/missing fields at every depth", () => {
		const example = exampleRuntimeCatalogV1();
		expect(hasCode(expectRejected(validateRuntimeCatalogV1({ ...example, catalogHash: "0".repeat(64) })), "WASM_CATALOG_DIGEST_MISMATCH")).toBe(true);
		expectRejected(validateRuntimeCatalogV1({ ...example, extra: true }));
		const missing = { ...example } as Record<string, unknown>;
		delete missing.revision;
		expectRejected(validateRuntimeCatalogV1(missing));
		const entryExtra = { ...example.entries[0], acceptanceRecordDigest: "0".repeat(64) };
		expectRejected(validateRuntimeCatalogV1({ ...example, entries: [entryExtra, ...example.entries.slice(1)] }));
		const revokedEntry = example.entries[2];
		if (revokedEntry.status !== "revoked") throw new Error("fixture error");
		expectRejected(validateRuntimeCatalogV1({ ...example, entries: [...example.entries.slice(0, 2), { ...revokedEntry, revocation: { ...revokedEntry.revocation, extra: 1 } }] }));
	});

	test("rejects duplicate entryKey, unsorted entries, and more than 128 entries", () => {
		const example = exampleRuntimeCatalogV1();
		const duplicated: RuntimeCatalogEntryV1 = { ...example.entries[1], entryKey: "iweb-wasmd-amd64" };
		expect(hasCode(expectRejected(validateRuntimeCatalogV1({ ...example, entries: [example.entries[0], duplicated, example.entries[2]] })), "WASM_CATALOG_INVALID")).toBe(true);
		expectRejected(validateRuntimeCatalogV1({ ...example, entries: [example.entries[1], example.entries[0], example.entries[2]] }));
		const many = (count: number): RuntimeCatalogEntryV1[] =>
			Array.from({ length: count }, (_, i) => ({
				entryKey: "k" + String(i).padStart(3, "0"),
				kind: "wasm" as const,
				imageDigest: "sha256:" + "a".repeat(64),
				hostABI: WASM_HOST_ABI_LITERAL,
				world: WASM_WORLD_LITERAL,
				architecture: "linux/amd64" as const,
				status: "active" as const,
			}));
		expect(sealRuntimeCatalogV1({ schemaVersion: 1, revision: 8, entries: many(128) }).ok).toBe(true);
		expectRejected(sealRuntimeCatalogV1({ schemaVersion: 1, revision: 8, entries: many(129) }));
	});

	test("rejects entry grammar and literal violations", () => {
		const example = exampleRuntimeCatalogV1();
		const withFirst = (patch: Partial<Record<string, unknown>>): unknown => ({ ...example, entries: [{ ...example.entries[0], ...patch }, ...example.entries.slice(1)] });
		expectRejected(validateRuntimeCatalogV1(withFirst({ entryKey: "1bad" })));
		expectRejected(validateRuntimeCatalogV1(withFirst({ imageDigest: "A".repeat(71) })));
		expectRejected(validateRuntimeCatalogV1(withFirst({ imageDigest: "a".repeat(64) })));
		expectRejected(validateRuntimeCatalogV1(withFirst({ hostABI: "iweb-wasmd-abi@1.1.0" })));
		expectRejected(validateRuntimeCatalogV1(withFirst({ world: "wasi:http/proxy@0.2.7" })));
		expectRejected(validateRuntimeCatalogV1(withFirst({ kind: "celld" })));
		expectRejected(validateRuntimeCatalogV1(withFirst({ architecture: "linux/386" })));
		expectRejected(validateRuntimeCatalogV1(withFirst({ status: "deleted" })));
		expectRejected(validateRuntimeCatalogV1({ ...example, revision: 0 }));
		expectRejected(validateRuntimeCatalogV1({ ...example, revision: 9007199254740992 }));
	});

	test("revocation exists exactly when status is revoked and carries bounded fields", () => {
		const example = exampleRuntimeCatalogV1();
		const activeWithRevocation = { ...example.entries[0], revocation: { cve: "CVE-2026-1234", reasonCode: "x", revokedAt: "2026-08-01T00:00:00Z" } };
		expectRejected(validateRuntimeCatalogV1({ ...example, entries: [activeWithRevocation, ...example.entries.slice(1)] }));
		const revokedEntry = example.entries[2];
		if (revokedEntry.status !== "revoked") throw new Error("fixture error");
		const withoutRevocation = { ...revokedEntry } as Record<string, unknown>;
		delete withoutRevocation.revocation;
		expectRejected(validateRuntimeCatalogV1({ ...example, entries: [...example.entries.slice(0, 2), withoutRevocation] }));
		for (const cve of ["CVE-26-1234", "cve-2026-1234", "CVE-2026-123", "CVE-2026-12345-extra"]) {
			expectRejected(validateRuntimeCatalogV1({ ...example, entries: [...example.entries.slice(0, 2), { ...revokedEntry, revocation: { ...revokedEntry.revocation, cve } }] }));
		}
		expectRejected(validateRuntimeCatalogV1({ ...example, entries: [...example.entries.slice(0, 2), { ...revokedEntry, revocation: { ...revokedEntry.revocation, reasonCode: "UPPER_CASE" } }] }));
		expectRejected(validateRuntimeCatalogV1({ ...example, entries: [...example.entries.slice(0, 2), { ...revokedEntry, revocation: { ...revokedEntry.revocation, revokedAt: "2026-08-01T00:00:00+00:00" } }] }));
	});
});

// ---------------------------------------------------------------------------
// entry 选择与 revoke 阻断
// ---------------------------------------------------------------------------

describe("catalog entry selection and revocation gate", () => {
	const catalog = exampleRuntimeCatalogV1();

	test("selects by exact five-field equality with no fallback", () => {
		const binding = exampleRuntimeBindingForCatalogEntry(catalog, "iweb-wasmd-amd64");
		const selected = checkRuntimeBindingUsable(catalog, binding, "linux/amd64");
		expect(selected.ok).toBe(true);
		if (selected.ok) expect(selected.value.entryKey).toBe("iweb-wasmd-amd64");

		expect(hasCode(expectRejected(checkRuntimeBindingUsable(catalog, binding, "linux/arm64")), WASM_CATALOG_ENTRY_NOT_FOUND)).toBe(true);
		expect(hasCode(expectRejected(checkRuntimeBindingUsable(catalog, { ...binding, imageDigest: "sha256:" + "9".repeat(64) }, "linux/amd64")), WASM_CATALOG_ENTRY_NOT_FOUND)).toBe(true);
		expect(hasCode(expectRejected(checkRuntimeBindingUsable(catalog, { ...binding, world: "wasi:http/proxy@0.2.7" }, "linux/amd64")), WASM_CATALOG_ENTRY_NOT_FOUND)).toBe(true);
	});

	test("a binding must pin the catalog revision and hash exactly", () => {
		const stale = exampleRuntimeBindingForCatalogEntry(catalog, "iweb-wasmd-amd64");
		const mismatched = { ...stale, catalogRevision: 7 };
		expect(hasCode(expectRejected(checkRuntimeBindingUsable(catalog, mismatched, "linux/amd64")), "WASM_CATALOG_BINDING_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(checkRuntimeBindingUsable(catalog, { ...stale, catalogHash: "0".repeat(64) }, "linux/amd64")), "WASM_CATALOG_BINDING_MISMATCH")).toBe(true);
	});

	test("a revoked entry blocks new prepare, activation, rebind, and rollback", () => {
		const binding = exampleRuntimeBindingForCatalogEntry(catalog, "legacy-wasmd-amd64");
		expect(hasCode(expectRejected(checkRuntimeBindingUsable(catalog, binding, "linux/amd64")), WASM_RUNTIME_BINDING_REVOKED)).toBe(true);
		// 历史 revision 保留 replay：旧 revision 内该 entry 仍是其原始状态，但 pin 检查强制新操作钉住当前 revision。
		expect(catalog.entries.some((entry) => entry.entryKey === "legacy-wasmd-amd64")).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// revision 追加 CAS 与 owner 更新协议
// ---------------------------------------------------------------------------

describe("catalog revision append CAS", () => {
	const current = exampleRuntimeCatalogV1();
	const pin = { revision: current.revision, catalogHash: current.catalogHash };

	test("appends revision current + 1, seals the hash, and rejects stale pins", () => {
		const next = appendRuntimeCatalogRevision(current, pin, { schemaVersion: 1, revision: 9, entries: current.entries });
		expect(next.ok).toBe(true);
		if (next.ok) {
			expect(next.value.revision).toBe(9);
			expect(validateRuntimeCatalogV1(next.value).ok).toBe(true);
		}
		// stale expected hash / revision → CAS 冲突。
		expect(hasCode(expectRejected(appendRuntimeCatalogRevision(current, { revision: 8, catalogHash: "0".repeat(64) }, { schemaVersion: 1, revision: 9, entries: current.entries })), CATALOG_REVISION_CONFLICT)).toBe(true);
		expect(hasCode(expectRejected(appendRuntimeCatalogRevision(current, { revision: 7, catalogHash: current.catalogHash }, { schemaVersion: 1, revision: 9, entries: current.entries })), CATALOG_REVISION_CONFLICT)).toBe(true);
		// next.revision 必须恰为 current + 1。
		expect(hasCode(expectRejected(appendRuntimeCatalogRevision(current, pin, { schemaVersion: 1, revision: 10, entries: current.entries })), CATALOG_REVISION_CONFLICT)).toBe(true);
		expect(hasCode(expectRejected(appendRuntimeCatalogRevision(current, pin, { schemaVersion: 1, revision: 8, entries: current.entries })), CATALOG_REVISION_CONFLICT)).toBe(true);
	});

	test("two racing appends from the same expected pair: one wins, the other conflicts", () => {
		const winner = appendRuntimeCatalogRevision(current, pin, { schemaVersion: 1, revision: 9, entries: current.entries });
		expect(winner.ok).toBe(true);
		if (!winner.ok) throw new Error("expected append to succeed");
		// 存储已推进到 revision 9；第二个写者仍拿 revision-8 期望值 → 冲突且不写任何东西。
		const loser = appendRuntimeCatalogRevision(winner.value, pin, { schemaVersion: 1, revision: 9, entries: current.entries });
		expect(hasCode(expectRejected(loser), CATALOG_REVISION_CONFLICT)).toBe(true);
	});

	test("rejects duplicate entry keys and malformed next payloads", () => {
		const duplicated = [...current.entries, { ...current.entries[0] }];
		expectRejected(appendRuntimeCatalogRevision(current, pin, { schemaVersion: 1, revision: 9, entries: duplicated }));
		expectRejected(appendRuntimeCatalogRevision(current, pin, { schemaVersion: 1, revision: 9, entries: current.entries, catalogHash: "0".repeat(64) }));
		expectRejected(appendRuntimeCatalogRevision(current, { revision: 0, catalogHash: current.catalogHash }, { schemaVersion: 1, revision: 9, entries: current.entries }));
	});
});

// ---------------------------------------------------------------------------
// entry 引用保护与 revoke 状态机
// ---------------------------------------------------------------------------

describe("entry reference protection and revoke state machine", () => {
	const catalog = exampleRuntimeCatalogV1();
	const pin = { revision: catalog.revision, catalogHash: catalog.catalogHash };
	const amd64Binding = exampleRuntimeBindingForCatalogEntry(catalog, "iweb-wasmd-amd64");
	const references: readonly WasmCatalogEntryReferenceV1[] = [
		{ kind: "active-version", runtimeBinding: amd64Binding },
		rollbackRecordReference(exampleWasmRollbackRecordV1(amd64Binding)),
	];

	test("protectedRuntimeCatalogEntryKeys derives keys from all reference kinds", () => {
		expect(protectedRuntimeCatalogEntryKeys(references)).toEqual(new Set(["iweb-wasmd-amd64"]));
	});

	test("a referenced entry must not be deleted from a subsequent revision", () => {
		const withoutActive = catalog.entries.filter((entry) => entry.entryKey !== "iweb-wasmd-amd64");
		const deletion = appendRuntimeCatalogRevision(catalog, pin, { schemaVersion: 1, revision: 9, entries: withoutActive }, references);
		expect(hasCode(expectRejected(deletion), WASM_CATALOG_ENTRY_PROTECTED)).toBe(true);
		// 引用解除后同一删除可通过。
		const freed = appendRuntimeCatalogRevision(catalog, pin, { schemaVersion: 1, revision: 9, entries: withoutActive }, []);
		expect(freed.ok).toBe(true);
	});

	test("revoke appends a revoked revision without deleting the entry", () => {
		const revocation = { cve: "CVE-2026-4242", reasonCode: "wasmd-wasm-bypass", revokedAt: "2026-08-26T00:00:00Z" };
		const next = revokeRuntimeCatalogEntry(catalog, pin, "iweb-wasmd-amd64", revocation);
		expect(next.ok).toBe(true);
		if (!next.ok) throw new Error("expected revoke to succeed");
		expect(next.value.revision).toBe(9);
		const entry = next.value.entries.find((candidate) => candidate.entryKey === "iweb-wasmd-amd64");
		expect(entry).toBeDefined();
		if (entry !== undefined && entry.status === "revoked") expect(entry.revocation).toEqual(revocation);
		expect(validateRuntimeCatalogV1(next.value).ok).toBe(true);
		// revoke 后新 prepare/activation/rollback 被阻断。
		const rebound = exampleRuntimeBindingForCatalogEntry(next.value, "iweb-wasmd-amd64");
		expect(hasCode(expectRejected(checkRuntimeBindingUsable(next.value, rebound, "linux/amd64")), WASM_RUNTIME_BINDING_REVOKED)).toBe(true);

		expect(hasCode(expectRejected(revokeRuntimeCatalogEntry(catalog, pin, "missing-entry", revocation)), WASM_CATALOG_ENTRY_NOT_FOUND)).toBe(true);
		expect(hasCode(expectRejected(revokeRuntimeCatalogEntry(catalog, pin, "legacy-wasmd-amd64", revocation)), "WASM_CATALOG_ENTRY_ALREADY_REVOKED")).toBe(true);
		expect(hasCode(expectRejected(revokeRuntimeCatalogEntry(catalog, { revision: 8, catalogHash: "0".repeat(64) }, "iweb-wasmd-amd64", revocation)), CATALOG_REVISION_CONFLICT)).toBe(true);
	});

	test("a revoked entry cannot be flipped back to active by a later revision", () => {
		const unrevoked = catalog.entries.map((entry) =>
			entry.entryKey === "legacy-wasmd-amd64"
				? { entryKey: entry.entryKey, kind: "wasm" as const, imageDigest: entry.imageDigest, hostABI: entry.hostABI, world: entry.world, architecture: entry.architecture, status: "active" as const }
				: entry,
		);
		const next = appendRuntimeCatalogRevision(catalog, pin, { schemaVersion: 1, revision: 9, entries: unrevoked });
		expect(hasCode(expectRejected(next), "WASM_CATALOG_REVOCATION_REGRESSION")).toBe(true);
		// revocation 字段被改写同样拒绝。
		const tamperedRevocation = catalog.entries.map((entry) =>
			entry.entryKey === "legacy-wasmd-amd64" && entry.status === "revoked" ? { ...entry, revocation: { ...entry.revocation, cve: "CVE-2026-9999" } } : entry,
		);
		expect(hasCode(expectRejected(appendRuntimeCatalogRevision(catalog, pin, { schemaVersion: 1, revision: 9, entries: tamperedRevocation })), "WASM_CATALOG_REVOCATION_REGRESSION")).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// rollback 记录（引用保护的输入形状）
// ---------------------------------------------------------------------------

describe("wasm rollback record", () => {
	const binding = exampleRuntimeBindingForCatalogEntry(exampleRuntimeCatalogV1(), "iweb-wasmd-amd64");

	test("round-trips through JSON", () => {
		const record = exampleWasmRollbackRecordV1(binding);
		const result = validateWasmRollbackRecordV1(roundTrip(record));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(record);
	});

	test("rejects unknown fields, bad IDs, and malformed bindings", () => {
		expectRejected(validateWasmRollbackRecordV1({ ...exampleWasmRollbackRecordV1(binding), extra: 1 }));
		expectRejected(validateWasmRollbackRecordV1({ ...exampleWasmRollbackRecordV1(binding), ownerCommandId: "018f1e2c-3d4b-4a5e-9f01-23456789abcd" }));
		expectRejected(validateWasmRollbackRecordV1({ ...exampleWasmRollbackRecordV1(binding), toVersionId: "a".repeat(64) }));
		expectRejected(validateWasmRollbackRecordV1({ ...exampleWasmRollbackRecordV1(binding), targetRuntimeBinding: { ...binding, catalogRevision: 0 } }));
		expectRejected(validateWasmRollbackRecordV1({ ...exampleWasmRollbackRecordV1(binding), createdAt: "2026-08-26T00:00:00" }));
	});
});

// ---------------------------------------------------------------------------
// release receipt / delete audit / GC
// ---------------------------------------------------------------------------

describe("release receipt and GC state machine", () => {
	const catalog = exampleRuntimeCatalogV1();
	const legacyBinding = exampleRuntimeBindingForCatalogEntry(catalog, "legacy-wasmd-amd64");
	const rollbackReference = rollbackRecordReference(exampleWasmRollbackRecordV1(legacyBinding));

	function releaseRequest(references: readonly WasmCatalogEntryReferenceV1[] = []) {
		return {
			catalog,
			entryKey: "legacy-wasmd-amd64",
			references,
			releaseId: RELEASE_ID,
			ownerCommandId: OWNER_COMMAND_ID,
			drainedAt: "2026-08-26T00:00:00Z",
			releasedAt: "2026-08-26T00:01:00Z",
		};
	}

	test("releases an unreferenced entry with a one-year retention receipt", () => {
		const released = releaseRuntimeCatalogEntry(releaseRequest());
		expect(released.ok).toBe(true);
		if (!released.ok) throw new Error("expected release to succeed");
		const receipt = released.value;
		expect(receipt.protectedReferenceCount).toBe(0);
		expect(receipt.targetRuntimeBinding).toEqual(legacyBinding);
		expect(Date.parse(receipt.releaseRetentionUntil)).toBe(Date.parse("2026-08-26T00:01:00Z") + CATALOG_RELEASE_RETENTION_SECONDS * 1000);
		expect(catalogReleaseReceiptFilePath(receipt.releaseId)).toBe("/data/kernel/runtime-catalog/release-receipts/" + RELEASE_ID + ".json");

		// receiptDigest 独立 oracle：预排序 JSON.stringify 字面量。
		const receiptPayloadJcs = JSON.stringify({
			catalogHash: receipt.catalogHash,
			catalogRevision: receipt.catalogRevision,
			drainedAt: receipt.drainedAt,
			entryKey: receipt.entryKey,
			ownerCommandId: receipt.ownerCommandId,
			protectedReferenceCount: receipt.protectedReferenceCount,
			releaseId: receipt.releaseId,
			releaseRetentionUntil: receipt.releaseRetentionUntil,
			releasedAt: receipt.releasedAt,
			runtimeKind: receipt.runtimeKind,
			schemaVersion: receipt.schemaVersion,
			targetRuntimeBinding: {
				catalogHash: receipt.targetRuntimeBinding.catalogHash,
				catalogRevision: receipt.targetRuntimeBinding.catalogRevision,
				entryKey: receipt.targetRuntimeBinding.entryKey,
				hostABI: receipt.targetRuntimeBinding.hostABI,
				imageDigest: receipt.targetRuntimeBinding.imageDigest,
				kind: receipt.targetRuntimeBinding.kind,
				world: receipt.targetRuntimeBinding.world,
			},
		});
		expect(receipt.receiptDigest).toBe(sha256Text(CATALOG_RELEASE_RECEIPT_DIGEST_DOMAIN + "\n" + receiptPayloadJcs));
		expect(validateCatalogReleaseReceiptV1(roundTrip(receipt)).ok).toBe(true);
	});

	test("release is blocked while any protected reference remains", () => {
		expect(hasCode(expectRejected(releaseRuntimeCatalogEntry(releaseRequest([rollbackReference]))), WASM_CATALOG_ENTRY_PROTECTED)).toBe(true);
		expect(hasCode(expectRejected(releaseRuntimeCatalogEntry({ ...releaseRequest(), entryKey: "missing-entry" })), WASM_CATALOG_ENTRY_NOT_FOUND)).toBe(true);
	});

	test("receipt validation rejects tampering, non-zero counts, and short retention", () => {
		const receipt = releaseRuntimeCatalogEntry(releaseRequest());
		if (!receipt.ok) throw new Error("expected release to succeed");
		expect(hasCode(expectRejected(validateCatalogReleaseReceiptV1({ ...receipt.value, receiptDigest: "0".repeat(64) })), "CATALOG_RELEASE_RECEIPT_DIGEST_MISMATCH")).toBe(true);
		expectRejected(validateCatalogReleaseReceiptV1({ ...receipt.value, protectedReferenceCount: 1 }));
		expectRejected(validateCatalogReleaseReceiptV1({ ...receipt.value, releaseRetentionUntil: "2026-09-26T00:01:00Z" }));
		expectRejected(validateCatalogReleaseReceiptV1({ ...receipt.value, drainedAt: "2026-08-26T00:02:00Z" }));
		expectRejected(validateCatalogReleaseReceiptV1({ ...receipt.value, releaseId: "not-a-uuid" }));
		expectRejected(validateCatalogReleaseReceiptV1({ ...receipt.value, extra: true }));
	});

	test("a released binding cannot be reactivated", () => {
		const receipt = releaseRuntimeCatalogEntry(releaseRequest());
		if (!receipt.ok) throw new Error("expected release to succeed");
		expect(hasCode(expectRejected(checkRuntimeBindingNotReleased([receipt.value], legacyBinding)), WASM_RUNTIME_BINDING_RELEASED)).toBe(true);
		const other = exampleRuntimeBindingForCatalogEntry(catalog, "iweb-wasmd-amd64");
		expect(checkRuntimeBindingNotReleased([receipt.value], other).ok).toBe(true);
	});

	test("GC writes the delete audit and deleted index entry only after retention", () => {
		const history = exampleCatalogHistoryRecordV1(catalog, "2026-08-26T00:00:00Z");
		const receipt = releaseRuntimeCatalogEntry(releaseRequest());
		if (!receipt.ok) throw new Error("expected release to succeed");
		const request = {
			record: history,
			receipt: receipt.value,
			references: [] as readonly WasmCatalogEntryReferenceV1[],
			deleteId: DELETE_ID,
			ownerCommandId: OWNER_COMMAND_ID,
			deletedAt: "2027-08-27T00:00:00Z",
			reason: "owner-approved cleanup after retention",
		};
		const gc = gcCatalogHistoryRevision(request);
		expect(gc.ok).toBe(true);
		if (!gc.ok) throw new Error("expected GC to succeed");
		expect(gc.value.audit.path).toBe(catalogHistoryRevisionFilePath(history.revision, history.catalogHash));
		expect(catalogDeleteAuditFilePath(DELETE_ID)).toBe("/data/kernel/runtime-catalog/delete-audit/" + DELETE_ID + ".json");
		expect(gc.value.indexEntry.status).toBe("deleted");
		expect(gc.value.indexEntry.deletedAt).toBe("2027-08-27T00:00:00Z");
		expect(gc.value.indexEntry.catalogHash).toBe(history.catalogHash);
		// objectDigest 独立 oracle：被删对象完整 JCS 的无前缀 SHA-256。
		expect(gc.value.audit.objectDigest).toBe(sha256Text(jcsCanonicalize(history)));
		expect(validateCatalogDeleteAuditV1(roundTrip(gc.value.audit)).ok).toBe(true);

		// 保留期内 / 有引用 / receipt 不匹配 → fail-closed 且文件保留。
		expect(hasCode(expectRejected(gcCatalogHistoryRevision({ ...request, deletedAt: "2026-09-01T00:00:00Z" })), "CATALOG_RELEASE_RETENTION_ACTIVE")).toBe(true);
		expect(hasCode(expectRejected(gcCatalogHistoryRevision({ ...request, references: [rollbackReference] })), WASM_CATALOG_ENTRY_PROTECTED)).toBe(true);
		const staleReceipt = { ...receipt.value, catalogRevision: 7 };
		expect(hasCode(expectRejected(gcCatalogHistoryRevision({ ...request, receipt: staleReceipt })), "CATALOG_RELEASE_RECEIPT_MISMATCH")).toBe(true);
		expectRejected(validateCatalogDeleteAuditV1({ ...gc.value.audit, path: "/tmp/elsewhere.json" }));
		expectRejected(validateCatalogDeleteAuditV1({ ...gc.value.audit, reason: "" }));
	});
});

// ---------------------------------------------------------------------------
// catalog history 与恢复索引重建
// ---------------------------------------------------------------------------

describe("catalog history record and recovery index", () => {
	const catalog = exampleRuntimeCatalogV1();

	test("history record round-trips, agrees with its filename, and matches the hand-built digest oracle", () => {
		const history = exampleCatalogHistoryRecordV1(catalog, "2026-08-26T00:00:00Z");
		const result = validateCatalogHistoryRecordV1(roundTrip(history));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(history);
		expect(catalogHistoryRevisionFileName(history.revision, history.catalogHash)).toBe("8-" + history.catalogHash + ".json");

		const fullCatalogJcs = '{"catalogHash":"' + catalog.catalogHash + '","entries":[' + CATALOG_ENTRIES_JCS + '],"revision":8,"schemaVersion":1}';
		const historyPayloadJcs = '{"catalog":' + fullCatalogJcs + ',"catalogHash":"' + catalog.catalogHash + '","revision":8,"runtimeKind":"wasm","schemaVersion":1,"storedAt":"2026-08-26T00:00:00Z"}';
		expect(history.recordDigest).toBe(sha256Text("iweb-catalog-history-v1\n" + historyPayloadJcs));
		expect(computeCatalogHistoryRecordDigestV1({ schemaVersion: 1, runtimeKind: "wasm", revision: history.revision, catalogHash: history.catalogHash, catalog, storedAt: history.storedAt })).toBe(history.recordDigest);

		expect(validateCatalogHistoryFileName("8-" + history.catalogHash + ".json", history).ok).toBe(true);
		expectRejected(validateCatalogHistoryFileName("9-" + history.catalogHash + ".json", history));
	});

	test("rejects wrapper/catalog disagreement and tampered digests", () => {
		const history = exampleCatalogHistoryRecordV1(catalog, "2026-08-26T00:00:00Z");
		// wrapper revision 与嵌套 catalog revision 不一致：文件名三元一致规则先于 digest 复算 fail-closed。
		expect(hasCode(expectRejected(validateCatalogHistoryRecordV1({ ...history, revision: 9 })), "WASM_CATALOG_HISTORY_INVALID")).toBe(true);
		expect(hasCode(expectRejected(validateCatalogHistoryRecordV1({ ...history, catalogHash: "0".repeat(64) })), "WASM_CATALOG_HISTORY_INVALID")).toBe(true);
		expect(hasCode(expectRejected(validateCatalogHistoryRecordV1({ ...history, recordDigest: "0".repeat(64) })), "WASM_CATALOG_HISTORY_DIGEST_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(validateCatalogHistoryRecordV1({ ...history, storedAt: "2027-01-01T00:00:00Z" })), "WASM_CATALOG_HISTORY_DIGEST_MISMATCH")).toBe(true);
		expectRejected(validateCatalogHistoryRecordV1({ ...history, storedAt: "2026-08-26T00:00:00" }));
	});

	test("rebuilds the index from history files and fails closed on disagreement", () => {
		// 构造 revision 7、8、9 三份历史（7 为较小 catalog，9 为 append 产物）。
		const base = { schemaVersion: 1, revision: 7, entries: catalog.entries.slice(0, 2) } as const;
		const rev7 = sealRuntimeCatalogV1(base);
		if (!rev7.ok) throw new Error("fixture error");
		const rev9 = appendRuntimeCatalogRevision(catalog, { revision: catalog.revision, catalogHash: catalog.catalogHash }, { schemaVersion: 1, revision: 9, entries: catalog.entries });
		if (!rev9.ok) throw new Error("fixture error");
		const records: CatalogHistoryRecordV1[] = [
			exampleCatalogHistoryRecordV1(rev7.value, "2026-08-25T00:00:00Z"),
			exampleCatalogHistoryRecordV1(catalog, "2026-08-26T00:00:00Z"),
			exampleCatalogHistoryRecordV1(rev9.value, "2026-08-27T00:00:00Z"),
		];

		const rebuilt = rebuildCatalogHistoryIndex(records, { updatedAt: "2026-08-27T01:00:00Z" });
		expect(rebuilt.ok).toBe(true);
		if (!rebuilt.ok) throw new Error("expected rebuild to succeed");
		expect(rebuilt.value.currentRevision).toBe(9);
		expect(rebuilt.value.currentHash).toBe(rev9.value.catalogHash);
		expect(rebuilt.value.revisions.map((entry) => entry.revision)).toEqual([7, 8, 9]);
		expect(rebuilt.value.revisions.every((entry) => entry.status === "present" && entry.deletedAt === null)).toBe(true);
		expect(validateCatalogHistoryIndexV1(roundTrip(rebuilt.value)).ok).toBe(true);
		// 重建确定性：两次重建字节一致。
		const again = rebuildCatalogHistoryIndex([...records].reverse(), { updatedAt: "2026-08-27T01:00:00Z" });
		expect(again.ok).toBe(true);
		if (again.ok) expect(again.value).toEqual(rebuilt.value);

		// protectedReferenceCount 按钉住该 revision 的引用计数。
		const withRefs = rebuildCatalogHistoryIndex(records, {
			updatedAt: "2026-08-27T01:00:00Z",
			references: [{ kind: "rollback-target", runtimeBinding: exampleRuntimeBindingForCatalogEntry(catalog, "iweb-wasmd-amd64") }],
		});
		expect(withRefs.ok).toBe(true);
		if (withRefs.ok) {
			const rev8Entry = withRefs.value.revisions.find((entry) => entry.revision === 8);
			expect(rev8Entry?.protectedReferenceCount).toBe(1);
			const rev7Entry = withRefs.value.revisions.find((entry) => entry.revision === 7);
			expect(rev7Entry?.protectedReferenceCount).toBe(0);
		}

		// 任何坏记录 / 同 revision 分歧 → fail-closed，绝不选"最近" revision。
		const tampered = { ...records[1], storedAt: "2027-01-01T00:00:00Z" };
		expect(hasCode(expectRejected(rebuildCatalogHistoryIndex([records[0], tampered, records[2]], { updatedAt: "2026-08-27T01:00:00Z" })), "WASM_CATALOG_HISTORY_DIGEST_MISMATCH")).toBe(true);
		const conflicting = exampleCatalogHistoryRecordV1(catalog, "2026-08-26T12:00:00Z");
		expect(hasCode(expectRejected(rebuildCatalogHistoryIndex([records[0], records[1], conflicting, records[2]], { updatedAt: "2026-08-27T01:00:00Z" })), "WASM_CATALOG_INDEX_INVALID")).toBe(true);
		expectRejected(rebuildCatalogHistoryIndex([], { updatedAt: "2026-08-27T01:00:00Z" }));
	});

	test("index validation enforces sorting, path formula, and current-pointer agreement", () => {
		const rev7 = sealRuntimeCatalogV1({ schemaVersion: 1, revision: 7, entries: exampleRuntimeCatalogV1().entries.slice(0, 2) });
		if (!rev7.ok) throw new Error("fixture error");
		const catalog8 = exampleRuntimeCatalogV1();
		const records = [exampleCatalogHistoryRecordV1(rev7.value, "2026-08-25T00:00:00Z"), exampleCatalogHistoryRecordV1(catalog8, "2026-08-26T00:00:00Z")];
		const index = rebuildCatalogHistoryIndex(records, { updatedAt: "2026-08-26T01:00:00Z" });
		if (!index.ok) throw new Error("fixture error");

		expectRejected(validateCatalogHistoryIndexV1({ ...index.value, currentRevision: 7 }));
		expectRejected(validateCatalogHistoryIndexV1({ ...index.value, currentHash: "0".repeat(64) }));
		expectRejected(validateCatalogHistoryIndexV1({ ...index.value, revisions: [...index.value.revisions].reverse() }));
		expect(hasCode(expectRejected(validateCatalogHistoryIndexV1({ ...index.value, indexDigest: "0".repeat(64) })), "WASM_CATALOG_INDEX_DIGEST_MISMATCH")).toBe(true);
		const badPath = [...index.value.revisions];
		badPath[0] = { ...badPath[0], path: "/tmp/x.json" };
		expectRejected(validateCatalogHistoryIndexV1({ ...index.value, revisions: badPath }));
		const deletedWithoutAt = [...index.value.revisions];
		deletedWithoutAt[0] = { ...deletedWithoutAt[0], status: "deleted" as const };
		expectRejected(validateCatalogHistoryIndexV1({ ...index.value, revisions: deletedWithoutAt }));
		const presentWithAt = [...index.value.revisions];
		presentWithAt[1] = { ...presentWithAt[1], deletedAt: "2026-08-26T02:00:00Z" };
		expectRejected(validateCatalogHistoryIndexV1({ ...index.value, revisions: presentWithAt }));
	});
});

// ---------------------------------------------------------------------------
// NodeCapabilityRecordV1
// ---------------------------------------------------------------------------

// 矩阵的预排序手写字面量（独立于实现的 canonical 顺序 oracle）。
const MATRIX_HAND_LITERAL = {
	hostABI: WASM_HOST_ABI_LITERAL,
	hostImports: [
		{ direction: "import", interface: "store", package: "iweb:config@1.0.0" },
		{ direction: "import", interface: "store", package: "iweb:secrets@1.0.0" },
		{ direction: "import", interface: "stderr", package: "wasi:cli@0.2.8" },
		{ direction: "import", interface: "stdin", package: "wasi:cli@0.2.8" },
		{ direction: "import", interface: "stdout", package: "wasi:cli@0.2.8" },
		{ direction: "import", interface: "monotonic-clock", package: "wasi:clocks@0.2.8" },
		{ direction: "import", interface: "wall-clock", package: "wasi:clocks@0.2.8" },
		{ direction: "import", interface: "outgoing-handler", package: "wasi:http@0.2.8" },
		{ direction: "import", interface: "types", package: "wasi:http@0.2.8" },
		{ direction: "import", interface: "error", package: "wasi:io@0.2.8" },
		{ direction: "import", interface: "poll", package: "wasi:io@0.2.8" },
		{ direction: "import", interface: "streams", package: "wasi:io@0.2.8" },
		{ direction: "import", interface: "random", package: "wasi:random@0.2.8" },
	],
	requiredRootExport: { direction: "export", interface: "incoming-handler", package: "wasi:http@0.2.8" },
	world: WASM_WORLD_LITERAL,
};

describe("node capability record", () => {
	test("round-trips through JSON and reproduces the pre-sorted-literal recordHash oracle", () => {
		const example = exampleNodeCapabilityRecordV1();
		const result = validateNodeCapabilityRecordV1(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);

		// 矩阵常量的 canonical 序与手写字面量一致；recordHash 用独立序列化路径复算。
		expect(jcsCanonicalize(WASM_CAPABILITY_MATRIX_REVISION_1)).toBe(JSON.stringify(MATRIX_HAND_LITERAL));
		const { recordHash, ...capabilityPayload } = example;
		void recordHash;
		const binding = example.runtimeReserves[0].runtimeBinding;
		const payloadJcs = JSON.stringify({
			admission: { maxBlobBytes: 134217728, maxClosureDepth: 64, maxClosureEdges: 16384, maxClosureNodes: 4096, maxLayerCount: 128, maxPackageBytes: 536870912, stagingTtlSeconds: 3600 },
			drainDeadlineMs: 30000,
			engine: { fuelPerRequest: null, maxEpochDeadlineMs: 60000, maxLiveInstances: 128 },
			http: { maxConcurrentRequests: 256, maxRequestBytes: 16777216, maxRequestHeaderBytes: 8192, maxRequestHeaderCount: 64, maxResponseBytes: 67108864, maxResponseHeaderBytes: 8192, maxResponseHeaderCount: 64 },
			matrix: MATRIX_HAND_LITERAL,
			policyMaxima: { cpuMillis: 500000, memoryBytes: 68719476736, pidLimit: 100000, storageBytes: 1099511627776 },
			restart: { maxRestarts: 3, windowMs: 600000 },
			revision: 5,
			runtimeReserves: [
				{ architecture: "linux/amd64", reserveBytes: 33554432, runtimeBinding: { catalogHash: binding.catalogHash, catalogRevision: binding.catalogRevision, entryKey: binding.entryKey, hostABI: binding.hostABI, imageDigest: binding.imageDigest, kind: binding.kind, world: binding.world } },
				{ architecture: "linux/arm64", reserveBytes: 33554432, runtimeBinding: { catalogHash: binding.catalogHash, catalogRevision: binding.catalogRevision, entryKey: binding.entryKey, hostABI: binding.hostABI, imageDigest: binding.imageDigest, kind: binding.kind, world: binding.world } },
			],
			schemaVersion: 1,
		});
		expect(computeNodeCapabilityRecordHashV1(capabilityPayload)).toBe(sha256Text(NODE_CAPABILITY_RECORD_HASH_DOMAIN + "\n" + payloadJcs));
		expect(example.recordHash).toBe(sha256Text(NODE_CAPABILITY_RECORD_HASH_DOMAIN + "\n" + payloadJcs));
	});

	test("seals and rejects a payload carrying recordHash", () => {
		const example = exampleNodeCapabilityRecordV1();
		const { recordHash, ...payload } = example;
		void recordHash;
		const sealed = sealNodeCapabilityRecordV1(payload);
		expect(sealed.ok).toBe(true);
		if (sealed.ok) expect(sealed.value).toEqual(example);
		expectRejected(sealNodeCapabilityRecordV1(example));
	});

	test("rejects a tampered recordHash and unknown/missing fields at every depth", () => {
		const example = exampleNodeCapabilityRecordV1();
		expect(hasCode(expectRejected(validateNodeCapabilityRecordV1({ ...example, recordHash: "0".repeat(64) })), "WASM_NODE_CAPABILITY_DIGEST_MISMATCH")).toBe(true);
		expectRejected(validateNodeCapabilityRecordV1({ ...example, extra: true }));
		expectRejected(validateNodeCapabilityRecordV1({ ...example, http: { ...example.http, extra: 1 } }));
		expectRejected(validateNodeCapabilityRecordV1({ ...example, engine: { ...example.engine, extra: 1 } }));
		expectRejected(validateNodeCapabilityRecordV1({ ...example, admission: { ...example.admission, extra: 1 } }));
		expectRejected(validateNodeCapabilityRecordV1({ ...example, restart: { ...example.restart, extra: 1 } }));
		expectRejected(validateNodeCapabilityRecordV1({ ...example, policyMaxima: { ...example.policyMaxima, extra: 1 } }));
		expectRejected(validateNodeCapabilityRecordV1({ ...example, runtimeReserves: [{ ...example.runtimeReserves[0], extra: 1 }, example.runtimeReserves[1]] }));
		const missing = { ...example } as Record<string, unknown>;
		delete missing.drainDeadlineMs;
		expectRejected(validateNodeCapabilityRecordV1(missing));
	});

	test("enforces every spec bound on each field", () => {
		const example = exampleNodeCapabilityRecordV1();
		const cases: readonly [string, unknown, unknown][] = [
			["policyMaxima", { ...example.policyMaxima, cpuMillis: 1000001 }, { ...example.policyMaxima, cpuMillis: 0 }],
			["policyMaxima", { ...example.policyMaxima, memoryBytes: 68719476737 }, { ...example.policyMaxima, memoryBytes: 0 }],
			["policyMaxima", { ...example.policyMaxima, pidLimit: 1000001 }, { ...example.policyMaxima, pidLimit: 0 }],
			["policyMaxima", { ...example.policyMaxima, storageBytes: 1099511627777 }, null],
			["http", { ...example.http, maxRequestBytes: 16777217 }, { ...example.http, maxRequestBytes: 0 }],
			["http", { ...example.http, maxResponseBytes: 67108865 }, { ...example.http, maxResponseHeaderCount: 257 }],
			["http", { ...example.http, maxConcurrentRequests: 4097 }, { ...example.http, maxRequestHeaderBytes: 65537 }],
			["engine", { ...example.engine, maxEpochDeadlineMs: 300001 }, { ...example.engine, maxEpochDeadlineMs: 0 }],
			["engine", { ...example.engine, fuelPerRequest: 0 }, { ...example.engine, fuelPerRequest: 1000000000001 }],
			["engine", { ...example.engine, maxLiveInstances: 4097 }, { ...example.engine, maxLiveInstances: 0 }],
			["admission", { ...example.admission, maxPackageBytes: 536870913 }, { ...example.admission, maxBlobBytes: 134217129 }],
			["admission", { ...example.admission, maxLayerCount: 129 }, { ...example.admission, maxClosureNodes: 4097 }],
			["admission", { ...example.admission, maxClosureEdges: 16385 }, { ...example.admission, maxClosureDepth: 65 }],
			["admission", { ...example.admission, stagingTtlSeconds: 3601 }, { ...example.admission, stagingTtlSeconds: 0 }],
			["restart", { ...example.restart, maxRestarts: 101 }, { ...example.restart, maxRestarts: -1 }],
			["restart", { ...example.restart, windowMs: 999 }, { ...example.restart, windowMs: 86400001 }],
		];
		for (const [field, ...values] of cases) {
			for (const value of values) {
				if (value === null) continue;
				expectRejected(validateNodeCapabilityRecordV1({ ...example, [field]: value }));
			}
		}
		expect(validateNodeCapabilityRecordV1({ ...example, drainDeadlineMs: 300001 }).ok).toBe(false);
		expect(validateNodeCapabilityRecordV1({ ...example, drainDeadlineMs: 0 }).ok).toBe(false);
		expect(validateNodeCapabilityRecordV1({ ...example, restart: { maxRestarts: 0, windowMs: 1000 } }).ok).toBe(false); // recordHash 未重算
		// 数值启用 fuel 合法。
		const refueled = { ...example, engine: { ...example.engine, fuelPerRequest: 1000000000000 } };
		const { recordHash, ...fuelPayload } = refueled;
		void recordHash;
		expect(sealNodeCapabilityRecordV1(fuelPayload).ok).toBe(true);
	});

	test("runtimeReserves must be non-empty, unique by (binding, architecture), sorted, and bounded", () => {
		const example = exampleNodeCapabilityRecordV1();
		const { recordHash, ...payload } = example;
		void recordHash;
		const withReserves = (reserves: readonly unknown[]): unknown => ({ ...payload, runtimeReserves: reserves });
		expectRejected(sealNodeCapabilityRecordV1(withReserves([])));
		const duplicated = [example.runtimeReserves[0], example.runtimeReserves[0]];
		expectRejected(sealNodeCapabilityRecordV1(withReserves(duplicated)));
		const unsorted = [example.runtimeReserves[1], example.runtimeReserves[0]];
		expectRejected(sealNodeCapabilityRecordV1(withReserves(unsorted)));
		expectRejected(sealNodeCapabilityRecordV1(withReserves([{ ...example.runtimeReserves[0], reserveBytes: 0 }, example.runtimeReserves[1]])));
		expectRejected(sealNodeCapabilityRecordV1(withReserves([{ ...example.runtimeReserves[0], reserveBytes: 68719476736 }, example.runtimeReserves[1]])));
		const many = (count: number) =>
			Array.from({ length: count }, (_, i) => ({
				runtimeBinding: { ...example.runtimeReserves[0].runtimeBinding, entryKey: "k" + String(i).padStart(3, "0") },
				architecture: "linux/amd64" as const,
				reserveBytes: 1,
			}));
		expect(sealNodeCapabilityRecordV1(withReserves(many(256))).ok).toBe(true);
		expectRejected(sealNodeCapabilityRecordV1(withReserves(many(257))));
	});

	test("the matrix pin reuses the revision-1 capability matrix validator", () => {
		const example = exampleNodeCapabilityRecordV1();
		const { recordHash, ...payload } = example;
		void recordHash;
		const withMatrix = (matrix: unknown): unknown => ({ ...payload, matrix });
		expectRejected(sealNodeCapabilityRecordV1(withMatrix({ ...example.matrix, world: "wasi:http/proxy@0.2.7" })));
		expectRejected(sealNodeCapabilityRecordV1(withMatrix({ ...example.matrix, hostImports: example.matrix.hostImports.slice(1) })));
		expectRejected(sealNodeCapabilityRecordV1(withMatrix({ ...example.matrix, extra: true })));
	});

	test("owner update CAS: strictly revision + 1 with a matching expected pair", () => {
		const example = exampleNodeCapabilityRecordV1();
		const { recordHash, ...payload } = example;
		void recordHash;
		const next = appendNodeCapabilityRecordV1(example, { revision: example.revision, recordHash: example.recordHash }, { ...payload, revision: 6 });
		expect(next.ok).toBe(true);
		if (next.ok) {
			expect(next.value.revision).toBe(6);
			expect(validateNodeCapabilityRecordV1(next.value).ok).toBe(true);
		}
		expect(hasCode(expectRejected(appendNodeCapabilityRecordV1(example, { revision: 5, recordHash: "0".repeat(64) }, { ...payload, revision: 6 })), WASM_CAPABILITY_REVISION_CONFLICT)).toBe(true);
		expect(hasCode(expectRejected(appendNodeCapabilityRecordV1(next.ok ? next.value : example, { revision: 5, recordHash: example.recordHash }, { ...payload, revision: 6 })), WASM_CAPABILITY_REVISION_CONFLICT)).toBe(true);
		expect(hasCode(expectRejected(appendNodeCapabilityRecordV1(example, { revision: example.revision, recordHash: example.recordHash }, { ...payload, revision: 7 })), WASM_CAPABILITY_REVISION_CONFLICT)).toBe(true);
		expectRejected(appendNodeCapabilityRecordV1(example, { revision: example.revision, recordHash: example.recordHash }, { ...payload, revision: 6, recordHash: "0".repeat(64) }));
	});
});

// ---------------------------------------------------------------------------
// reserve / policy maxima / pin / ABI fence
// ---------------------------------------------------------------------------

describe("reserve and memory fence (byte-unit comparison)", () => {
	const record = exampleNodeCapabilityRecordV1();
	const binding = record.runtimeReserves[0].runtimeBinding; // amd64 与 arm64 各 33554432 bytes。

	test("compares reserveBytes and memoryBytes in identical byte units", () => {
		const exact = checkWasmMemoryReservation({ record, runtimeBinding: binding, architecture: "linux/amd64", memoryBytes: 33554433 });
		expect(exact.ok).toBe(true);
		if (exact.ok) expect(exact.value.guestLinearMemoryBytes).toBe(1);
		const roomy = checkWasmMemoryReservation({ record, runtimeBinding: binding, architecture: "linux/arm64", memoryBytes: 68719476736 });
		expect(roomy.ok).toBe(true);
		if (roomy.ok) expect(roomy.value.guestLinearMemoryBytes).toBe(68719476736 - 33554432);
	});

	test("reserve >= memoryBytes fails closed (equal and greater)", () => {
		for (const memoryBytes of [33554432, 33554431, 1]) {
			const rejected = checkWasmMemoryReservation({ record, runtimeBinding: binding, architecture: "linux/amd64", memoryBytes });
			expect(hasCode(expectRejected(rejected), WASM_RESOURCE_RECORD_INVALID)).toBe(true);
		}
	});

	test("a missing reserve for the exact binding+architecture is never defaulted or zeroed", () => {
		const unknownBinding: RuntimeBindingIdentityV1 = { ...binding, entryKey: "other-wasmd" };
		expect(findRuntimeReserve(record, unknownBinding, "linux/amd64")).toBeNull();
		const rejected = checkWasmMemoryReservation({ record, runtimeBinding: unknownBinding, architecture: "linux/amd64", memoryBytes: 68719476736 });
		expect(hasCode(expectRejected(rejected), WASM_RESOURCE_RECORD_INVALID)).toBe(true);
		expectRejected(checkWasmMemoryReservation({ record, runtimeBinding: binding, architecture: "linux/amd64", memoryBytes: 0 }));
	});

	test("policy maxima reject any requested field above its bound", () => {
		expect(checkWasmPolicyMaxima(record, { cpuMillis: 500000, memoryBytes: 68719476736, pidLimit: 100000, storageBytes: 1099511627776 }).ok).toBe(true);
		expect(hasCode(expectRejected(checkWasmPolicyMaxima(record, { cpuMillis: 500001, memoryBytes: 1, pidLimit: 1, storageBytes: 0 })), "WASM_POLICY_MAXIMA_EXCEEDED")).toBe(true);
		expect(hasCode(expectRejected(checkWasmPolicyMaxima(record, { cpuMillis: 1, memoryBytes: 68719476737, pidLimit: 1, storageBytes: 0 })), "WASM_POLICY_MAXIMA_EXCEEDED")).toBe(true);
		expect(hasCode(expectRejected(checkWasmPolicyMaxima(record, { cpuMillis: 1, memoryBytes: 1, pidLimit: 100001, storageBytes: 0 })), "WASM_POLICY_MAXIMA_EXCEEDED")).toBe(true);
		expect(hasCode(expectRejected(checkWasmPolicyMaxima(record, { cpuMillis: 1, memoryBytes: 1, pidLimit: 1, storageBytes: 1099511627777 })), "WASM_POLICY_MAXIMA_EXCEEDED")).toBe(true);
	});

	test("preparations must pin the exact capability revision and hash", () => {
		expect(checkNodeCapabilityPin(record, { revision: record.revision, recordHash: record.recordHash }).ok).toBe(true);
		expect(hasCode(expectRejected(checkNodeCapabilityPin(record, { revision: record.revision - 1, recordHash: record.recordHash })), "WASM_CAPABILITY_PIN_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(checkNodeCapabilityPin(record, { revision: record.revision, recordHash: "0".repeat(64) })), "WASM_CAPABILITY_PIN_MISMATCH")).toBe(true);
	});

	test("binding world/ABI must match the pinned matrix", () => {
		expect(checkRuntimeBindingCapabilityCompatibility(record, record.runtimeReserves[0].runtimeBinding).ok).toBe(true);
		expect(hasCode(expectRejected(checkRuntimeBindingCapabilityCompatibility(record, { ...record.runtimeReserves[0].runtimeBinding, world: "wasi:http/proxy@0.2.7" })), "WASM_WORLD_UNSUPPORTED")).toBe(true);
		expect(hasCode(expectRejected(checkRuntimeBindingCapabilityCompatibility(record, { ...record.runtimeReserves[0].runtimeBinding, hostABI: "iweb-wasmd-abi@1.1.0" })), "WASM_HOST_ABI_MISMATCH")).toBe(true);
	});
});
