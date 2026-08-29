// 用户原始需求（2026-08-27，add-wasm-host-services 契约层 schema+向量先行）：`iweb:kv@1.0.0` 的 WIT 文本、
// grammar、CAS/tombstone、共享配额写前拒绝、cursor 绑定/过期与 mutation/快照 wire 必须与规范逐字一致并 fail-closed。
// 正交意图：WIT 文本↔spec 逐字一致性（剥注释比对 + 结构断言）；key/value grammar 与 base64url canonical；
// 单 key CAS 冲突与复活阻断；quota aggregate 原子拒绝；cursor scope/expiry；有界分页；marker/快照精确键集。
import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import {
	IWEB_KV_CURSOR_EXPIRED_ERROR_CASE,
	IWEB_KV_CURSOR_SCOPE_ALLOWED_ERROR_CASES,
	IWEB_KV_CURSOR_SCOPE_ERROR_CASE,
	IWEB_KV_KEY_PATTERN,
	IWEB_KV_LIST_LIMIT_MAX,
	IWEB_KV_VALUE_MAX_BYTES,
	IWEB_KV_VERSION_MAX,
	IWEB_KV_WIRE_ERROR_BY_CASE,
	IWEB_KV_WIT_DIRECTION_ERROR_CODE,
	IWEB_KV_WIT_ERROR_CASES,
	IWEB_KV_WIT_PACKAGE,
	applyIwebKvCas,
	checkIwebKvCursor,
	checkIwebKvWriteQuota,
	compareIwebKvKeys,
	decodeIwebKvValueWire,
	iwebKvConservativeReservedDeltaBytes,
	iwebKvListLimitCeiling,
	iwebKvTombstoneRetentionFloorMs,
	iwebKvWitDirectionErrorCode,
	isIwebKvTombstoneCollectable,
	isValidIwebKvKey,
	isValidIwebKvListLimit,
	isValidIwebKvPrefix,
	isValidIwebKvValueBytes,
	isValidIwebKvValueWire,
	planIwebKvListPage,
	validateIwebKvMutationMarker,
	validateIwebKvSnapshot,
} from "../packages/contracts/wasm-host-kv.ts";

const repoRoot = join(import.meta.dir, "..");
// 规范文本解析顺序：主 specs/（归档同步后）→ 归档 change 目录 → 活跃 change 目录
//（2026-08-29 add-wasm-host-services 已归档；归档目录是 sync 前的唯一权威文本）。
const specCandidates = [
	join(repoRoot, "openspec/specs/wasm-host-kv/spec.md"),
	join(repoRoot, "openspec/changes/archive/2026-08-29-add-wasm-host-services/specs/wasm-host-kv/spec.md"),
	join(repoRoot, "openspec/changes/add-wasm-host-services/specs/wasm-host-kv/spec.md"),
];
const specPath = specCandidates.find((candidate) => existsSync(candidate));
if (specPath === undefined) throw new Error("wasm-host-kv spec text not found in specs/ or the archived change");
const specText = readFileSync(specPath, "utf8");

function extractWitBlocks(text: string): string[] {
	const blocks: string[] = [];
	// OpenSpec delta spec 使用 ~~~wit tilde fence；归档主 spec 可能用 ```wit。两种都识别。
	for (const fence of ["~~~", "```"]) {
		const pattern = new RegExp(fence + "wit\\r?\\n([\\s\\S]*?)" + fence, "g");
		let match: RegExpExecArray | null;
		while ((match = pattern.exec(text)) !== null) blocks.push(match[1]);
	}
	return blocks;
}

// 逐字一致性口径：剥掉 `//` 行注释与行尾空白、去掉空行后必须与 spec 的 wit 代码块完全相等。
function normalizeWitText(text: string): string {
	return text
		.split(/\r?\n/)
		.map((line) => {
			const commentStart = line.indexOf("//");
			return (commentStart >= 0 ? line.slice(0, commentStart) : line).replace(/\s+$/, "");
		})
		.filter((line) => line.length > 0)
		.join("\n");
}

function specKvWitBlock(): string {
	const blocks = extractWitBlocks(specText).filter((block) => normalizeWitText(block).includes("package iweb:kv@1.0.0;"));
	expect(blocks.length).toBe(1);
	return blocks[0]!;
}

describe("iweb:kv WIT package", () => {
	test("iweb-kv.wit is byte-identical to the spec block and only imports store", () => {
		const fileText = readFileSync(join(repoRoot, "packages/contracts/wit/iweb-kv.wit"), "utf8");
		const normalized = normalizeWitText(fileText);
		expect(normalized).toBe(normalizeWitText(specKvWitBlock()));
		expect(normalized).toContain("package iweb:kv@1.0.0;");
		expect(normalized).toContain("interface store {");
		expect(normalized).toContain("type key = string;");
		expect(normalized).toContain("type value = list<u8>;");
		expect(normalized).toContain("type version = u64;");
		expect(normalized).toContain("record item { key: key, value: value, version: version }");
		expect(normalized).toContain("record page { items: list<item>, next-cursor: option<string> }");
		expect(normalized).toMatch(
			/variant error \{\s*invalid-key,\s*not-found,\s*conflict,\s*quota-exceeded,\s*limit-exceeded,\s*cursor-expired,\s*unavailable,\s*internal,\s*\}/,
		);
		expect(normalized).toContain("get: func(key: key) -> result<item, error>;");
		expect(normalized).toContain("set: func(key: key, value: value, expected: option<version>) -> result<version, error>;");
		expect(normalized).toContain("delete: func(key: key, expected: option<version>) -> result<version, error>;");
		expect(normalized).toContain("list: func(prefix: string, cursor: option<string>, limit: u32) -> result<page, error>;");
		expect(normalized).toContain("world kv { import store; }");
		expect(normalized).not.toMatch(/^\s*export\s/m);
	});

	test("WIT identity constants and direction vector are import-only", () => {
		expect(IWEB_KV_WIT_PACKAGE).toBe("iweb:kv@1.0.0");
		expect(iwebKvWitDirectionErrorCode({ package: "iweb:kv@1.0.0", interface: "store", direction: "export" })).toBe(IWEB_KV_WIT_DIRECTION_ERROR_CODE);
		expect(iwebKvWitDirectionErrorCode({ package: "iweb:kv@1.0.0", interface: "store", direction: "import" })).toBeNull();
		expect(iwebKvWitDirectionErrorCode({ package: "iweb:kv@1.0.0", interface: "other", direction: "export" })).toBeNull();
		expect(iwebKvWitDirectionErrorCode({ package: "iweb:sql@1.0.0", interface: "store", direction: "export" })).toBeNull();
	});

	test("WIT error cases form the exact closed set in spec order", () => {
		expect([...IWEB_KV_WIT_ERROR_CASES]).toEqual([
			"invalid-key",
			"not-found",
			"conflict",
			"quota-exceeded",
			"limit-exceeded",
			"cursor-expired",
			"unavailable",
			"internal",
		]);
		for (const caseName of IWEB_KV_WIT_ERROR_CASES) {
			expect(IWEB_KV_WIRE_ERROR_BY_CASE[caseName]).toBe("IWEB_KV_" + caseName.toUpperCase().replaceAll("-", "_"));
		}
	});
});

describe("iweb kv key and value grammar", () => {
	test("accepts the lower-case ASCII grammar within 128 bytes", () => {
		for (const key of ["a", "z", "abc", "a1", "a-b", "a_b", "a.b", "a-b_c.d-e", "a".repeat(128)]) {
			expect(isValidIwebKvKey(key)).toBe(true);
		}
		expect(IWEB_KV_KEY_PATTERN.test("a".repeat(128))).toBe(true);
	});

	test("rejects empty, uppercase, digit-first, separator, non-ASCII and over-length keys", () => {
		for (const key of ["", "A", "Abc", "1a", "-a", "_a", ".a", "a b", "a/b", "a:b", "a\0b", "a\nb", "é", "a".repeat(129), "aBc"]) {
			expect(isValidIwebKvKey(key)).toBe(false);
		}
	});

	test("prefix is a non-empty key-grammar string", () => {
		expect(isValidIwebKvPrefix("b")).toBe(true);
		expect(isValidIwebKvPrefix("")).toBe(false);
		expect(isValidIwebKvPrefix("B")).toBe(false);
	});

	test("raw value bound is 0..65536 bytes", () => {
		expect(isValidIwebKvValueBytes(new Uint8Array(0))).toBe(true);
		expect(isValidIwebKvValueBytes(new Uint8Array(IWEB_KV_VALUE_MAX_BYTES))).toBe(true);
		expect(isValidIwebKvValueBytes(new Uint8Array(IWEB_KV_VALUE_MAX_BYTES + 1))).toBe(false);
	});

	test("value wire is canonical unpadded base64url only", () => {
		expect(decodeIwebKvValueWire("")).toEqual(new Uint8Array(0));
		expect(decodeIwebKvValueWire("aGVsbG8")).toEqual(new Uint8Array(Buffer.from("hello", "utf8")));
		expect(isValidIwebKvValueWire(Buffer.alloc(IWEB_KV_VALUE_MAX_BYTES, 1).toString("base64url"))).toBe(true);
		// padding、非 url 字母、mod4==1、alternate encoding（非零尾位 round-trip 不等）一律拒绝。
		expect(isValidIwebKvValueWire("aGVsbA")).toBe(true); // "hell" 的 canonical unpadded 形态
		expect(isValidIwebKvValueWire("aGVsbG8=")).toBe(false);
		expect(isValidIwebKvValueWire("aGVsbG8+")).toBe(false);
		expect(isValidIwebKvValueWire("aGVsbG8/")).toBe(false);
		expect(isValidIwebKvValueWire("A")).toBe(false);
		expect(isValidIwebKvValueWire("aGVsbG9")).toBe(false); // 与 "aGVsbG8" 解码同字节但尾位非零：非 canonical
		expect(isValidIwebKvValueWire("aGVsbG")).toBe(false); // 与 "aGVsbA" 解码同字节但尾位非零：非 canonical
		expect(isValidIwebKvValueWire(Buffer.alloc(IWEB_KV_VALUE_MAX_BYTES + 1, 1).toString("base64url"))).toBe(false);
		expect(decodeIwebKvValueWire(42 as unknown as string)).toBeNull();
	});

	test("keys compare by raw UTF-8 bytes", () => {
		expect(compareIwebKvKeys("a1", "a2")).toBeLessThan(0);
		expect(compareIwebKvKeys("b", "a1")).toBeGreaterThan(0);
		expect(compareIwebKvKeys("same", "same")).toBe(0);
	});
});

describe("single-key linearized CAS", () => {
	test("unconditional set creates an absent key; expected version on an absent key conflicts", () => {
		expect(applyIwebKvCas({ current: null, expected: null, nextVersion: 1 })).toEqual({ status: "committed", version: 1 });
		expect(applyIwebKvCas({ current: null, expected: 1, nextVersion: 1 })).toEqual({ status: "conflict" });
	});

	test("expected version commits only when equal; mismatch conflicts", () => {
		expect(applyIwebKvCas({ current: { version: 4 }, expected: 4, nextVersion: 5 })).toEqual({ status: "committed", version: 5 });
		expect(applyIwebKvCas({ current: { version: 4 }, expected: 3, nextVersion: 5 })).toEqual({ status: "conflict" });
		expect(applyIwebKvCas({ current: { version: 4 }, expected: null, nextVersion: 5 })).toEqual({ status: "committed", version: 5 });
	});

	test("two racing conditional writes: exactly one commits, the loser conflicts without change", () => {
		// 宿主对同一 key 串行化：A 先提交 v2，B 在 A 之后求值，current 已是 v2。
		const a = applyIwebKvCas({ current: { version: 1 }, expected: 1, nextVersion: 2 });
		const b = applyIwebKvCas({ current: { version: 2 }, expected: 1, nextVersion: 3 });
		expect(a).toEqual({ status: "committed", version: 2 });
		expect(b).toEqual({ status: "conflict" });
	});

	test("delete tombstone blocks stale resurrection but not unconditional recreation", () => {
		// k 曾为 v1，delete 提交 tombstone v2。
		const tombstone = applyIwebKvCas({ current: { version: 1 }, expected: 1, nextVersion: 2 });
		expect(tombstone).toEqual({ status: "committed", version: 2 });
		// stale writer 携带旧 expected=1：与 tombstone 版本 mismatch -> conflict，key 保持不存在。
		expect(applyIwebKvCas({ current: { version: 2 }, expected: 1, nextVersion: 3 })).toEqual({ status: "conflict" });
		// 无条件重建合法。
		expect(applyIwebKvCas({ current: { version: 2 }, expected: null, nextVersion: 3 })).toEqual({ status: "committed", version: 3 });
	});

	test("version allocation is strictly increasing, never wraps, and exhaustion is unavailable", () => {
		expect(applyIwebKvCas({ current: { version: 5 }, expected: 5, nextVersion: 5 })).toEqual({ status: "unavailable" });
		expect(applyIwebKvCas({ current: { version: 5 }, expected: null, nextVersion: 4 })).toEqual({ status: "unavailable" });
		expect(applyIwebKvCas({ current: { version: IWEB_KV_VERSION_MAX }, expected: null, nextVersion: IWEB_KV_VERSION_MAX })).toEqual({ status: "unavailable" });
		// 计数器/输入损坏 fail-closed：0、负数、非整数、超上界一律 unavailable，绝不提交。
		expect(applyIwebKvCas({ current: { version: 0 }, expected: null, nextVersion: 1 })).toEqual({ status: "unavailable" });
		expect(applyIwebKvCas({ current: { version: 1 }, expected: 1.5, nextVersion: 2 })).toEqual({ status: "unavailable" });
		expect(applyIwebKvCas({ current: { version: 1 }, expected: null, nextVersion: Number.MAX_SAFE_INTEGER + 1 })).toEqual({ status: "unavailable" });
	});
});

describe("shared quota ledger checks", () => {
	test("allows exactly the aggregate envelope and rejects one byte above it atomically", () => {
		expect(checkIwebKvWriteQuota({ committedBytes: 100, outstandingReservedBytes: 20, reservedDeltaBytes: 30, aggregateEnvelopeBytes: 150 })).toEqual({
			status: "allowed",
			projectedBytes: 150,
		});
		expect(checkIwebKvWriteQuota({ committedBytes: 100, outstandingReservedBytes: 20, reservedDeltaBytes: 30, aggregateEnvelopeBytes: 149 })).toEqual({
			status: "quota-exceeded",
		});
	});

	test("the kv service cap binds independently of the shared envelope", () => {
		const base = { committedBytes: 10, outstandingReservedBytes: 0, reservedDeltaBytes: 50, aggregateEnvelopeBytes: 1000 };
		expect(checkIwebKvWriteQuota({ ...base, kvCommittedBytes: 10, kvOutstandingReservedBytes: 0, kvServiceCapBytes: 60 })).toEqual({
			status: "allowed",
			projectedBytes: 60,
		});
		expect(checkIwebKvWriteQuota({ ...base, kvCommittedBytes: 10, kvOutstandingReservedBytes: 0, kvServiceCapBytes: 59 })).toEqual({ status: "quota-exceeded" });
	});

	test("unprovable inputs are rejected before any write: negatives, non-integers, partial cap triples", () => {
		expect(checkIwebKvWriteQuota({ committedBytes: -1, outstandingReservedBytes: 0, reservedDeltaBytes: 1, aggregateEnvelopeBytes: 10 })).toEqual({ status: "quota-exceeded" });
		expect(checkIwebKvWriteQuota({ committedBytes: 1.5, outstandingReservedBytes: 0, reservedDeltaBytes: 1, aggregateEnvelopeBytes: 10 })).toEqual({ status: "quota-exceeded" });
		expect(
			checkIwebKvWriteQuota({ committedBytes: 1, outstandingReservedBytes: 0, reservedDeltaBytes: 1, aggregateEnvelopeBytes: 10, kvCommittedBytes: 1 }),
		).toEqual({ status: "quota-exceeded" });
		expect(
			checkIwebKvWriteQuota({ committedBytes: 1, outstandingReservedBytes: 0, reservedDeltaBytes: 1, aggregateEnvelopeBytes: 10, kvServiceCapBytes: 5 }),
		).toEqual({ status: "quota-exceeded" });
	});

	test("conservative reserved delta is key+value+overhead and fails closed when not finite", () => {
		expect(iwebKvConservativeReservedDeltaBytes({ keyBytes: 10, valueBytes: 100, entryOverheadBytes: 64 })).toBe(174);
		expect(iwebKvConservativeReservedDeltaBytes({ keyBytes: 10, valueBytes: 0, entryOverheadBytes: 64 })).toBe(74); // delete：tombstone 记账由 overhead 覆盖
		expect(iwebKvConservativeReservedDeltaBytes({ keyBytes: -1, valueBytes: 0, entryOverheadBytes: 64 })).toBeNull();
		expect(iwebKvConservativeReservedDeltaBytes({ keyBytes: 0, valueBytes: Number.MAX_SAFE_INTEGER, entryOverheadBytes: 1 })).toBeNull();
	});
});

describe("kv list cursor scope and expiry", () => {
	const cursor = {
		applicationId: "notes",
		hostServicePolicyDigest: "ab".repeat(32),
		prefix: "b",
		snapshotToken: "snap-1",
		lastKey: "b2",
		expiresAtMs: 1_000,
	};
	const context = {
		applicationId: "notes",
		hostServicePolicyDigest: "ab".repeat(32),
		prefix: "b",
		snapshotToken: "snap-1",
		snapshotAlive: true,
		nowMs: 500,
	};

	test("accepts a same-scope unexpired cursor", () => {
		expect(checkIwebKvCursor({ cursor, ...context })).toEqual({ status: "valid" });
	});

	test("cross application, policy, prefix or snapshot is a stable scope rejection before scanning", () => {
		expect(checkIwebKvCursor({ cursor, ...context, applicationId: "beta" })).toEqual({ status: "invalid-scope" });
		expect(checkIwebKvCursor({ cursor, ...context, hostServicePolicyDigest: "cd".repeat(32) })).toEqual({ status: "invalid-scope" });
		expect(checkIwebKvCursor({ cursor, ...context, prefix: "a" })).toEqual({ status: "invalid-scope" });
		expect(checkIwebKvCursor({ cursor, ...context, snapshotToken: "snap-2" })).toEqual({ status: "invalid-scope" });
		// 伪造 cursor（grammar 外 lastKey、坏 digest）同样稳定拒绝，不泄露匹配 key/计数。
		expect(checkIwebKvCursor({ cursor: { ...cursor, lastKey: "BAD" }, ...context })).toEqual({ status: "invalid-scope" });
		expect(checkIwebKvCursor({ cursor: { ...cursor, hostServicePolicyDigest: "zz" }, ...context })).toEqual({ status: "invalid-scope" });
	});

	test("expired token or reclaimed snapshot returns cursor-expired, never a restart at the beginning", () => {
		expect(checkIwebKvCursor({ cursor, ...context, nowMs: 1_000 })).toEqual({ status: "expired" }); // 边界含等号
		expect(checkIwebKvCursor({ cursor, ...context, nowMs: 2_000 })).toEqual({ status: "expired" });
		expect(checkIwebKvCursor({ cursor, ...context, snapshotAlive: false })).toEqual({ status: "expired" });
	});

	test("scope rejection maps into the spec-allowed stable error set, fixed to invalid-key", () => {
		expect(IWEB_KV_CURSOR_SCOPE_ALLOWED_ERROR_CASES).toContain(IWEB_KV_CURSOR_SCOPE_ERROR_CASE);
		expect(IWEB_KV_CURSOR_SCOPE_ERROR_CASE).toBe("invalid-key");
		expect(IWEB_KV_CURSOR_EXPIRED_ERROR_CASE).toBe("cursor-expired");
	});
});

describe("bounded list paging", () => {
	const entry = (key: string, sizeBytes: number): { key: string; value: Uint8Array } => ({ key, value: new Uint8Array(sizeBytes) });

	test("limit ceiling is min(256, profile max) and profile 0 rejects everything", () => {
		expect(IWEB_KV_LIST_LIMIT_MAX).toBe(256);
		expect(iwebKvListLimitCeiling(300)).toBe(256);
		expect(iwebKvListLimitCeiling(10)).toBe(10);
		expect(iwebKvListLimitCeiling(0)).toBe(0);
		expect(isValidIwebKvListLimit(1, 10)).toBe(true);
		expect(isValidIwebKvListLimit(10, 10)).toBe(true);
		expect(isValidIwebKvListLimit(11, 10)).toBe(false);
		expect(isValidIwebKvListLimit(0, 10)).toBe(false);
		expect(isValidIwebKvListLimit(1, 0)).toBe(false);
	});

	test("pages by prefix and raw key order, continues with next-cursor only when more matches exist", () => {
		const entries = [entry("b3", 1), entry("a1", 1), entry("b1", 1), entry("b2", 1), entry("c1", 1)];
		const first = planIwebKvListPage({ entries, prefix: "b", afterKey: null, limit: 2, profileMaxListItems: 256, maxListBytes: 1024 });
		expect(first.status).toBe("ok");
		if (first.status === "ok") {
			expect(first.items.map((item) => item.key)).toEqual(["b1", "b2"]);
			expect(first.nextLastKey).toBe("b2");
		}
		const second = planIwebKvListPage({ entries, prefix: "b", afterKey: "b2", limit: 2, profileMaxListItems: 256, maxListBytes: 1024 });
		expect(second.status).toBe("ok");
		if (second.status === "ok") {
			expect(second.items.map((item) => item.key)).toEqual(["b3"]);
			expect(second.nextLastKey).toBeNull(); // 没有更多可见匹配
		}
	});

	test("tombstoned keys are never enumerated", () => {
		const entries = [entry("b1", 1), entry("b2", 1), entry("b3", 1)];
		const page = planIwebKvListPage({ entries, tombstoneKeys: ["b2"], prefix: "b", afterKey: null, limit: 10, profileMaxListItems: 256, maxListBytes: 1024 });
		expect(page.status).toBe("ok");
		if (page.status === "ok") {
			expect(page.items.map((item) => item.key)).toEqual(["b1", "b3"]);
			expect(page.nextLastKey).toBeNull();
		}
	});

	test("page hits the byte cap: prior bounded page plus continuation cursor, no unbounded allocation", () => {
		// 每个 item = key(2) + value(3) = 5 字节；cap=5 -> 每页一条。
		const entries = [entry("b1", 3), entry("b2", 3)];
		const first = planIwebKvListPage({ entries, prefix: "b", afterKey: null, limit: 10, profileMaxListItems: 256, maxListBytes: 5 });
		expect(first.status).toBe("ok");
		if (first.status === "ok") {
			expect(first.items.map((item) => item.key)).toEqual(["b1"]);
			expect(first.nextLastKey).toBe("b1");
		}
		const second = planIwebKvListPage({ entries, prefix: "b", afterKey: "b1", limit: 10, profileMaxListItems: 256, maxListBytes: 5 });
		expect(second.status).toBe("ok");
		if (second.status === "ok") {
			expect(second.items.map((item) => item.key)).toEqual(["b2"]);
			expect(second.nextLastKey).toBeNull();
		}
	});

	test("a first item alone exceeding maxListBytes is limit-exceeded instead of an empty cursor loop", () => {
		const entries = [entry("b1", 3)];
		expect(planIwebKvListPage({ entries, prefix: "b", afterKey: null, limit: 10, profileMaxListItems: 256, maxListBytes: 4 })).toEqual({ status: "limit-exceeded" });
	});

	test("malformed paging inputs fail closed", () => {
		const entries = [entry("b1", 1)];
		expect(planIwebKvListPage({ entries, prefix: "", afterKey: null, limit: 1, profileMaxListItems: 256, maxListBytes: 10 })).toEqual({ status: "limit-exceeded" });
		expect(planIwebKvListPage({ entries, prefix: "b", afterKey: "BAD", limit: 1, profileMaxListItems: 256, maxListBytes: 10 })).toEqual({ status: "limit-exceeded" });
		expect(planIwebKvListPage({ entries, prefix: "b", afterKey: null, limit: 0, profileMaxListItems: 256, maxListBytes: 10 })).toEqual({ status: "limit-exceeded" });
		expect(planIwebKvListPage({ entries, prefix: "b", afterKey: null, limit: 11, profileMaxListItems: 10, maxListBytes: 10 })).toEqual({ status: "limit-exceeded" });
		expect(planIwebKvListPage({ entries, prefix: "b", afterKey: null, limit: 1, profileMaxListItems: 0, maxListBytes: 10 })).toEqual({ status: "limit-exceeded" });
		expect(planIwebKvListPage({ entries, prefix: "b", afterKey: null, limit: 1, profileMaxListItems: 256, maxListBytes: 0 })).toEqual({ status: "limit-exceeded" });
		// 后端损坏：同 key 双条目 / 越界条目拒绝枚举，绝不静默过滤。
		expect(planIwebKvListPage({ entries: [entry("b1", 1), entry("b1", 1)], prefix: "b", afterKey: null, limit: 5, profileMaxListItems: 256, maxListBytes: 100 })).toEqual({ status: "limit-exceeded" });
		expect(planIwebKvListPage({ entries: [{ key: "B1", value: new Uint8Array(1) }], prefix: "b", afterKey: null, limit: 5, profileMaxListItems: 256, maxListBytes: 100 })).toEqual({ status: "limit-exceeded" });
		expect(
			planIwebKvListPage({ entries: [{ key: "b1", value: new Uint8Array(IWEB_KV_VALUE_MAX_BYTES + 1) }], prefix: "b", afterKey: null, limit: 5, profileMaxListItems: 256, maxListBytes: 100000 }),
		).toEqual({ status: "limit-exceeded" });
	});
});

describe("tombstone retention window", () => {
	test("floor is cursor TTL plus replay TTL; invalid TTLs retain forever", () => {
		expect(iwebKvTombstoneRetentionFloorMs(1_000, 500)).toBe(1_500);
		expect(iwebKvTombstoneRetentionFloorMs(-1, 500)).toBeNull();
		expect(iwebKvTombstoneRetentionFloorMs(1.5, 500)).toBeNull();
	});

	test("collects only after the floor and only with a no-active-reference proof", () => {
		const base = { deletedAtMs: 0, maxCursorTtlMs: 1_000, hostCallReplayTtlMs: 500 };
		expect(isIwebKvTombstoneCollectable({ ...base, nowMs: 1_499, noActiveReferenceProof: true })).toBe(false);
		expect(isIwebKvTombstoneCollectable({ ...base, nowMs: 1_500, noActiveReferenceProof: true })).toBe(true);
		expect(isIwebKvTombstoneCollectable({ ...base, nowMs: 9_999, noActiveReferenceProof: false })).toBe(false); // 证明不可得 -> 保留并计配额
		expect(isIwebKvTombstoneCollectable({ ...base, nowMs: 9_999, maxCursorTtlMs: -1, noActiveReferenceProof: true })).toBe(false);
		expect(isIwebKvTombstoneCollectable({ ...base, deletedAtMs: 5_000, nowMs: 4_999, noActiveReferenceProof: true })).toBe(false); // 时钟回拨 -> 保留
	});
});

describe("kv mutation marker wire", () => {
	const validMarker = {
		schemaVersion: 1,
		method: "set" as const,
		key: "cache.key",
		expectedVersion: 3,
		assignedVersion: 4,
		operationId: "018f1e2d-6f3a-7b8c-9d0e-1a2b3c4d5e6f",
		reservationId: "018f1e2d-6f3a-7b8c-9d0e-1a2b3c4d5e70",
		reservationProofDigest: "ab".repeat(32),
	};

	test("accepts a complete set marker and a null-expected delete marker", () => {
		expect(validateIwebKvMutationMarker(validMarker).ok).toBe(true);
		expect(validateIwebKvMutationMarker({ ...validMarker, method: "delete", expectedVersion: null, assignedVersion: 1 }).ok).toBe(true);
	});

	test("rejects unknown fields, wrong schema, bad method/key/ids/digest and non-increasing versions", () => {
		const cases: unknown[] = [
			{ ...validMarker, extra: true },
			{ ...validMarker, schemaVersion: 2 },
			{ ...validMarker, method: "get" },
			{ ...validMarker, method: "list" },
			{ ...validMarker, key: "BAD" },
			{ ...validMarker, expectedVersion: 0 },
			{ ...validMarker, expectedVersion: 1.5 },
			{ ...validMarker, assignedVersion: 3 }, // assignedVersion <= expectedVersion
			{ ...validMarker, assignedVersion: 0 },
			{ ...validMarker, operationId: "not-a-uuid" },
			{ ...validMarker, operationId: "018f1e2d-6f3a-6b8c-9d0e-1a2b3c4d5e6f" }, // version nibble 不是 7
			{ ...validMarker, reservationId: "018f1e2d-6f3a-7b8c-0d0e-1a2b3c4d5e6f" }, // variant 位不是 10xx
			{ ...validMarker, reservationProofDigest: "AB".repeat(32) },
			{ ...validMarker, reservationProofDigest: "ab".repeat(31) },
			"not-an-object",
			null,
		];
		for (const input of cases) {
			const result = validateIwebKvMutationMarker(input);
			expect(result.ok).toBe(false);
		}
		const unknownField = validateIwebKvMutationMarker({ ...validMarker, extra: true });
		expect(unknownField.ok).toBe(false);
		if (!unknownField.ok) expect(unknownField.errors.some((entry) => entry.code === "UNKNOWN_FIELD" && entry.path === "/extra")).toBe(true);
	});
});

describe("kv snapshot wire", () => {
	const validSnapshot = {
		schemaVersion: 1,
		keys: ["api-key", "cache.key", "db_password"],
		values: { "api-key": "djE", "cache.key": "", db_password: Buffer.alloc(4, 7).toString("base64url") },
		versions: { "api-key": 1, "cache.key": 9, db_password: IWEB_KV_VERSION_MAX },
	};

	test("accepts a complete snapshot with byte-equal keys/values/versions sets", () => {
		const result = validateIwebKvSnapshot(validSnapshot);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.keys).toEqual(["api-key", "cache.key", "db_password"]);
			expect(result.value.values["cache.key"]).toBe(""); // 空值合法（0..65536 字节）
		}
	});

	test("rejects a missing or extra key in values or versions", () => {
		const missingValue = validateIwebKvSnapshot({ ...validSnapshot, values: { "api-key": "djE", "cache.key": "" } });
		expect(missingValue.ok).toBe(false);
		if (!missingValue.ok) expect(missingValue.errors.some((entry) => entry.code === "KEYS_VALUES_MISMATCH")).toBe(true);

		const extraVersion = validateIwebKvSnapshot({ ...validSnapshot, versions: { ...validSnapshot.versions, ghost: 1 } });
		expect(extraVersion.ok).toBe(false);
		if (!extraVersion.ok) expect(extraVersion.errors.some((entry) => entry.code === "KEYS_VALUES_MISMATCH")).toBe(true);

		const parsed = JSON.parse('{"schemaVersion":1,"keys":["api-key"],"values":{"api-key":"djE","__proto__":"e30"},"versions":{"api-key":1,"__proto__":2}}');
		const hostile = validateIwebKvSnapshot(parsed);
		expect(hostile.ok).toBe(false);
		if (!hostile.ok) expect(hostile.errors.some((entry) => entry.code === "KEYS_VALUES_MISMATCH")).toBe(true);
	});

	test("rejects unsorted, duplicate, malformed keys; bad versions; non-canonical values; unknown fields", () => {
		const unsorted = validateIwebKvSnapshot({
			schemaVersion: 1,
			keys: ["db_password", "api-key"],
			values: { "api-key": "djE", db_password: "dg" },
			versions: { "api-key": 1, db_password: 2 },
		});
		expect(unsorted.ok).toBe(false);

		const duplicate = validateIwebKvSnapshot({
			schemaVersion: 1,
			keys: ["api-key", "api-key"],
			values: { "api-key": "djE" },
			versions: { "api-key": 1 },
		});
		expect(duplicate.ok).toBe(false);

		const badKey = validateIwebKvSnapshot({ schemaVersion: 1, keys: ["API"], values: { API: "djE" }, versions: { API: 1 } });
		expect(badKey.ok).toBe(false);

		const badVersion = validateIwebKvSnapshot({ ...validSnapshot, versions: { "api-key": 0, "cache.key": 9, db_password: 2 } });
		expect(badVersion.ok).toBe(false);
		const nonIntegerVersion = validateIwebKvSnapshot({ ...validSnapshot, versions: { "api-key": 1.5, "cache.key": 9, db_password: 2 } });
		expect(nonIntegerVersion.ok).toBe(false);

		const paddedValue = validateIwebKvSnapshot({ ...validSnapshot, values: { ...validSnapshot.values, "cache.key": "djE=" } });
		expect(paddedValue.ok).toBe(false);
		const overLongValue = validateIwebKvSnapshot({
			...validSnapshot,
			values: { ...validSnapshot.values, "cache.key": Buffer.alloc(IWEB_KV_VALUE_MAX_BYTES + 1, 1).toString("base64url") },
		});
		expect(overLongValue.ok).toBe(false);

		const unknownField = validateIwebKvSnapshot({ ...validSnapshot, extra: 1 });
		expect(unknownField.ok).toBe(false);
		if (!unknownField.ok) expect(unknownField.errors.some((entry) => entry.code === "UNKNOWN_FIELD" && entry.path === "/extra")).toBe(true);

		const wrongSchema = validateIwebKvSnapshot({ ...validSnapshot, schemaVersion: 2 });
		expect(wrongSchema.ok).toBe(false);
		const arrayKeys = validateIwebKvSnapshot({ ...validSnapshot, keys: "api-key" });
		expect(arrayKeys.ok).toBe(false);
	});
});
