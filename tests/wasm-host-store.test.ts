// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.3 契约先行）：`iweb:secrets@1.0.0` / `iweb:config@1.0.0`
// 的 WIT 文本与 owner mutation wire 必须与规范逐字一致；keys/values 键集不等、未知字段、越界一律 fail-closed。
// 正交意图：WIT 文本↔spec 逐字一致性（剥注释字符串比对 + 最小结构断言）；key/value grammar；mutation wire 正/负例。
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	IWEB_CONFIG_WIRE_ERROR_BY_CASE,
	IWEB_SECRET_WIRE_ERROR_BY_CASE,
	IWEB_STORE_KEY_PATTERN,
	IWEB_STORE_WIT_ERROR_CASES,
	isValidIwebStoreKey,
	isValidIwebStoreValue,
	validateIwebConfigAllowlistMutation,
	validateIwebSecretAllowlistMutation,
} from "../packages/contracts/wasm-host-store.ts";

const repoRoot = join(import.meta.dir, "..");
// 归档后规范权威在主 spec（WIT 块随 archive 同步）；变更目录已移入 archive。
const specText = readFileSync(join(repoRoot, "openspec/specs/wasm-application-runtime/spec.md"), "utf8");

function extractWitBlocks(text: string): string[] {
	const blocks: string[] = [];
	const pattern = /```wit\r?\n([\s\S]*?)```/g;
	let match: RegExpExecArray | null;
	while ((match = pattern.exec(text)) !== null) blocks.push(match[1]);
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

function extractWorldBlock(normalized: string, worldName: string): string {
	const start = normalized.indexOf("world " + worldName + " {");
	expect(start).toBeGreaterThanOrEqual(0);
	const end = normalized.indexOf("}", start);
	return normalized.slice(start, end + 1);
}

describe("iweb host store WIT packages", () => {
	const blocks = extractWitBlocks(specText);

	test("spec declares exactly the two iweb WIT blocks", () => {
		expect(blocks.length).toBe(2);
	});

	test("iweb-secrets.wit is byte-identical to the spec block and only imports store", () => {
		const fileText = readFileSync(join(repoRoot, "packages/contracts/wit/iweb-secrets.wit"), "utf8");
		const normalized = normalizeWitText(fileText);
		expect(normalized).toBe(normalizeWitText(blocks[0]));
		expect(normalized).toContain("package iweb:secrets@1.0.0;");
		expect(normalized).toMatch(/variant error \{\s*not-assigned,\s*denied,\s*snapshot-expired,\s*revision-stale,\s*internal,\s*\}/);
		expect(normalized).toContain("get: func(key: key) -> result<string, error>;");
		const world = extractWorldBlock(normalized, "secrets");
		expect(world).toContain("import store;");
		expect(normalized).not.toMatch(/^\s*export\s/m);
	});

	test("iweb-config.wit is byte-identical to the spec block and only imports store", () => {
		const fileText = readFileSync(join(repoRoot, "packages/contracts/wit/iweb-config.wit"), "utf8");
		const normalized = normalizeWitText(fileText);
		expect(normalized).toBe(normalizeWitText(blocks[1]));
		expect(normalized).toContain("package iweb:config@1.0.0;");
		expect(normalized).toMatch(/variant error \{\s*not-assigned,\s*denied,\s*snapshot-expired,\s*revision-stale,\s*internal,\s*\}/);
		expect(normalized).toContain("get: func(key: key) -> result<string, error>;");
		const world = extractWorldBlock(normalized, "config");
		expect(world).toContain("import store;");
		expect(normalized).not.toMatch(/^\s*export\s/m);
	});
});

describe("iweb store key and value grammar", () => {
	test("accepts the lower-case ASCII grammar within 128 bytes", () => {
		for (const key of ["a", "z", "abc", "a1", "a-b", "a_b", "a.b", "a-b_c.d-e", "a".repeat(128)]) {
			expect(isValidIwebStoreKey(key)).toBe(true);
		}
	});

	test("rejects empty, uppercase, digit-first, separator, non-ASCII and over-length keys", () => {
		for (const key of ["", "A", "Abc", "1a", "-a", "_a", ".a", "a b", "a/b", "a:b", "a\0b", "a\nb", "é", "a".repeat(129), "aBc"]) {
			expect(isValidIwebStoreKey(key)).toBe(false);
		}
		expect(IWEB_STORE_KEY_PATTERN.test("a".repeat(128))).toBe(true);
		expect(IWEB_STORE_KEY_PATTERN.test("a".repeat(129))).toBe(false);
	});

	test("value bound is 65536 UTF-8 bytes including multi-byte characters", () => {
		expect(isValidIwebStoreValue("a".repeat(65536))).toBe(true);
		expect(isValidIwebStoreValue("a".repeat(65537))).toBe(false);
		expect(isValidIwebStoreValue("é".repeat(32768))).toBe(true);
		expect(isValidIwebStoreValue("é".repeat(32769))).toBe(false);
		expect(isValidIwebStoreValue("")).toBe(true);
	});
});

describe("iweb store wire error tables", () => {
	test("WIT variant cases map onto the exact closed wire code sets", () => {
		expect([...IWEB_STORE_WIT_ERROR_CASES]).toEqual(["not-assigned", "denied", "snapshot-expired", "revision-stale", "internal"]);
		expect(IWEB_SECRET_WIRE_ERROR_BY_CASE["not-assigned"]).toBe("IWEB_SECRET_NOT_ASSIGNED");
		expect(IWEB_SECRET_WIRE_ERROR_BY_CASE["denied"]).toBe("IWEB_SECRET_DENIED");
		expect(IWEB_SECRET_WIRE_ERROR_BY_CASE["snapshot-expired"]).toBe("IWEB_SECRET_SNAPSHOT_EXPIRED");
		expect(IWEB_SECRET_WIRE_ERROR_BY_CASE["revision-stale"]).toBe("IWEB_SECRET_REVISION_STALE");
		expect(IWEB_SECRET_WIRE_ERROR_BY_CASE["internal"]).toBe("IWEB_SECRET_INTERNAL");
		expect(IWEB_CONFIG_WIRE_ERROR_BY_CASE["not-assigned"]).toBe("IWEB_CONFIG_NOT_ASSIGNED");
		expect(IWEB_CONFIG_WIRE_ERROR_BY_CASE["denied"]).toBe("IWEB_CONFIG_DENIED");
		expect(IWEB_CONFIG_WIRE_ERROR_BY_CASE["snapshot-expired"]).toBe("IWEB_CONFIG_SNAPSHOT_EXPIRED");
		expect(IWEB_CONFIG_WIRE_ERROR_BY_CASE["revision-stale"]).toBe("IWEB_CONFIG_REVISION_STALE");
		expect(IWEB_CONFIG_WIRE_ERROR_BY_CASE["internal"]).toBe("IWEB_CONFIG_INTERNAL");
	});
});

describe("secret allowlist owner mutation wire", () => {
	test("accepts a complete replacement with byte-equal keys/values sets", () => {
		const result = validateIwebSecretAllowlistMutation({
			schemaVersion: 1,
			expectedSecretRevision: 7,
			keys: ["api-token", "cache.key", "db_password"],
			values: { "api-token": "v1", "cache.key": "v2", db_password: "" },
		});
		expect(result.ok).toBe(true);
	});

	test("accepts the empty no-assignment replacement at revision 0", () => {
		const result = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 0, keys: [], values: {} });
		expect(result.ok).toBe(true);
	});

	test("rejects a missing values entry for a declared key", () => {
		const result = validateIwebSecretAllowlistMutation({
			schemaVersion: 1,
			expectedSecretRevision: 1,
			keys: ["alpha", "beta"],
			values: { alpha: "v" },
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((entry) => entry.code === "KEYS_VALUES_MISMATCH")).toBe(true);
	});

	test("rejects an extra values key outside keys, including a JSON prototype-like key", () => {
		const extra = validateIwebSecretAllowlistMutation({
			schemaVersion: 1,
			expectedSecretRevision: 1,
			keys: ["alpha"],
			values: { alpha: "v", beta: "w" },
		});
		expect(extra.ok).toBe(false);
		if (!extra.ok) expect(extra.errors.some((entry) => entry.code === "KEYS_VALUES_MISMATCH")).toBe(true);

		const parsed = JSON.parse('{"schemaVersion":1,"expectedSecretRevision":1,"keys":["alpha"],"values":{"alpha":"v","__proto__":"x"}}');
		const hostile = validateIwebSecretAllowlistMutation(parsed);
		expect(hostile.ok).toBe(false);
		if (!hostile.ok) expect(hostile.errors.some((entry) => entry.code === "KEYS_VALUES_MISMATCH")).toBe(true);
	});

	test("rejects duplicate, unsorted, malformed, over-count keys and non-string or over-long values", () => {
		const duplicate = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys: ["alpha", "alpha"], values: { alpha: "v" } });
		expect(duplicate.ok).toBe(false);
		const unsorted = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys: ["beta", "alpha"], values: { alpha: "v", beta: "w" } });
		expect(unsorted.ok).toBe(false);
		const malformed = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys: ["Alpha"], values: { Alpha: "v" } });
		expect(malformed.ok).toBe(false);
		const keys = Array.from({ length: 257 }, (_, index) => "key-" + index).sort();
		const values = Object.fromEntries(keys.map((key) => [key, "v"]));
		const overCount = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys, values });
		expect(overCount.ok).toBe(false);
		const numeric = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys: ["alpha"], values: { alpha: 7 } });
		expect(numeric.ok).toBe(false);
		const overLong = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys: ["alpha"], values: { alpha: "a".repeat(65537) } });
		expect(overLong.ok).toBe(false);
	});

	test("rejects unknown fields, wrong schemaVersion, bad revision field and non-object values", () => {
		const unknownField = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys: [], values: {}, extra: true });
		expect(unknownField.ok).toBe(false);
		if (!unknownField.ok) expect(unknownField.errors.some((entry) => entry.code === "UNKNOWN_FIELD" && entry.path === "/extra")).toBe(true);
		const wrongSchema = validateIwebSecretAllowlistMutation({ schemaVersion: 2, expectedSecretRevision: 1, keys: [], values: {} });
		expect(wrongSchema.ok).toBe(false);
		const badRevision = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: -1, keys: [], values: {} });
		expect(badRevision.ok).toBe(false);
		const arrayValues = validateIwebSecretAllowlistMutation({ schemaVersion: 1, expectedSecretRevision: 1, keys: [], values: [] });
		expect(arrayValues.ok).toBe(false);
	});
});

describe("config allowlist owner mutation wire", () => {
	test("accepts a complete replacement and rejects an empty key set", () => {
		const result = validateIwebConfigAllowlistMutation({
			schemaVersion: 1,
			expectedConfigRevision: 3,
			keys: ["endpoint", "feature-x"],
			values: { endpoint: "https://internal", "feature-x": "on" },
		});
		expect(result.ok).toBe(true);

		const empty = validateIwebConfigAllowlistMutation({ schemaVersion: 1, expectedConfigRevision: 0, keys: [], values: {} });
		expect(empty.ok).toBe(false);
	});

	test("bounded key counts: 256 accepted, 257 rejected", () => {
		const keys = Array.from({ length: 256 }, (_, index) => "key-" + index).sort();
		const values = Object.fromEntries(keys.map((key) => [key, "v"]));
		const atLimit = validateIwebConfigAllowlistMutation({ schemaVersion: 1, expectedConfigRevision: 1, keys, values });
		expect(atLimit.ok).toBe(true);
		const overLimitKeys = Array.from({ length: 257 }, (_, index) => "key-" + index).sort();
		const overLimitValues = Object.fromEntries(overLimitKeys.map((key) => [key, "v"]));
		const over = validateIwebConfigAllowlistMutation({ schemaVersion: 1, expectedConfigRevision: 1, keys: overLimitKeys, values: overLimitValues });
		expect(over.ok).toBe(false);
	});

	test("all shape rejections carry the spec wire code IWEB_CONFIG_WIRE_INVALID", () => {
		const cases: unknown[] = [
			{ schemaVersion: 1, expectedConfigRevision: 1, keys: ["a"], values: { b: "v" } },
			{ schemaVersion: 1, expectedConfigRevision: 1, keys: ["a", "a"], values: { a: "v" } },
			{ schemaVersion: 1, expectedConfigRevision: 1, keys: ["b", "a"], values: { a: "v", b: "w" } },
			{ schemaVersion: 1, expectedConfigRevision: 1, keys: ["a"], values: { a: 3 } },
			{ schemaVersion: 1, expectedConfigRevision: 1, keys: ["A"], values: { A: "v" } },
			{ schemaVersion: 1, expectedConfigRevision: 1, keys: ["a"], values: { a: "v" }, unknown: 1 },
			"not-an-object",
		];
		for (const input of cases) {
			const result = validateIwebConfigAllowlistMutation(input);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.errors.every((entry) => entry.code === "IWEB_CONFIG_WIRE_INVALID")).toBe(true);
		}
	});
});
