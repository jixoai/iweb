// 用户原始需求（2026-08-27，add-wasm-host-services 契约层先行）：`iweb:sql@1.0.0` 的 WIT 文本、minimal-sqlite-v1
// 语句静态校验（单语句/参数占位/denylist/WITH 越界）、参数/结果/行/字节配额与错误映射必须与规范一致；歧义一律 fail-closed。
// 正交意图：WIT 文本↔spec 逐字一致性（剥注释字符串比对）；语句校验正/负例；SQLite 参数序号语义；execute preflight 与
// result wire 的形状/配额界；WIT case ↔ wire/host-call 错误码表。
// 归档后规范权威在主 spec（WIT 块随 archive 同步）；当前以变更目录 spec 为准。
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	IWEB_SQL_DML_STATEMENT_KINDS,
	IWEB_SQL_HOST_CALL_ERROR_BY_CASE,
	IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS,
	IWEB_SQL_STORE_INTERFACE,
	IWEB_SQL_WIRE_ERROR_BY_CASE,
	IWEB_SQL_WIT_ERROR_CASES,
	IWEB_SQL_WIT_PACKAGE,
	IWEB_SQL_WIT_WORLD,
	iwebSqlResultBytes,
	iwebSqlValueWireBytes,
	iwebSqlWitDirectionErrorCode,
	iwebSqlWitVersionErrorCode,
	parseIwebSqlParameter,
	validateIwebSqlExecuteRequest,
	validateIwebSqlResultWire,
	validateIwebSqlStatement,
	type IwebSqlLimits,
} from "../packages/contracts/wasm-host-sql.ts";

const repoRoot = join(import.meta.dir, "..");
const specText = readFileSync(join(repoRoot, "openspec/changes/add-wasm-host-services/specs/wasm-host-sql/spec.md"), "utf8");

function extractWitBlocks(text: string): string[] {
	const blocks: string[] = [];
	const pattern = /~~~wit\r?\n([\s\S]*?)~~~/g;
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

function expectInvalidSql(statement: string, code: string, limits: IwebSqlLimits = IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS): void {
	const result = validateIwebSqlStatement(statement, limits);
	expect(result.ok).toBe(false);
	if (!result.ok) {
		expect(result.error.case).toBe("invalid-sql");
		expect(result.error.code).toBe(code);
	}
}

describe("iweb:sql WIT package", () => {
	const blocks = extractWitBlocks(specText);

	test("spec declares exactly the one iweb:sql WIT block", () => {
		expect(blocks.length).toBe(1);
	});

	test("iweb-sql.wit is byte-identical to the spec block and only imports store", () => {
		const fileText = readFileSync(join(repoRoot, "packages/contracts/wit/iweb-sql.wit"), "utf8");
		const normalized = normalizeWitText(fileText);
		expect(normalized).toBe(normalizeWitText(blocks[0]));
		expect(normalized).toContain("package " + IWEB_SQL_WIT_PACKAGE + ";");
		expect(normalized).toContain("variant value { null, integer(s64), real(f64), text(string), blob(list<u8>) }");
		expect(normalized).toContain("record query-result { rows: list<row>, affected: u64, last-insert-id: option<u64> }");
		expect(normalized).toMatch(/variant error \{\s*invalid-sql,\s*invalid-parameter,\s*constraint,\s*busy,\s*quota-exceeded,\s*limit-exceeded,\s*unavailable,\s*internal,\s*\}/);
		expect(normalized).toContain("execute: func(statement: string, parameters: list<parameter>) -> result<query-result, error>;");
		const worldIndex = normalized.indexOf("world " + IWEB_SQL_WIT_WORLD + " {");
		expect(worldIndex).toBeGreaterThanOrEqual(0);
		expect(normalized.slice(worldIndex, normalized.indexOf("}", worldIndex) + 1)).toContain("import " + IWEB_SQL_STORE_INTERFACE + ";");
		expect(normalized).not.toMatch(/^\s*export\s/m);
	});

	test("WIT identity constants and direction/version law", () => {
		expect(IWEB_SQL_WIT_PACKAGE).toBe("iweb:sql@1.0.0");
		expect(iwebSqlWitDirectionErrorCode({ package: IWEB_SQL_WIT_PACKAGE, interface: "store", direction: "export" })).toBe("IWEB_SQL_WIT_DIRECTION_INVALID");
		expect(iwebSqlWitDirectionErrorCode({ package: IWEB_SQL_WIT_PACKAGE, interface: "store", direction: "import" })).toBe(null);
		expect(iwebSqlWitDirectionErrorCode({ package: "iweb:kv@1.0.0", interface: "store", direction: "export" })).toBe(null);
		expect(iwebSqlWitVersionErrorCode("iweb:sql@1.0.0")).toBe(null);
		expect(iwebSqlWitVersionErrorCode("iweb:sql@1.0.1")).toBe("IWEB_SQL_WIT_VERSION_INVALID");
		expect(iwebSqlWitVersionErrorCode("iweb:sql@2.0.0")).toBe("IWEB_SQL_WIT_VERSION_INVALID");
		expect(iwebSqlWitVersionErrorCode("iweb:kv@1.0.0")).toBe(null);
	});
});

describe("iweb:sql error case tables", () => {
	test("WIT variant cases map onto the exact closed wire code sets", () => {
		expect([...IWEB_SQL_WIT_ERROR_CASES]).toEqual(["invalid-sql", "invalid-parameter", "constraint", "busy", "quota-exceeded", "limit-exceeded", "unavailable", "internal"]);
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE["invalid-sql"]).toBe("IWEB_SQL_INVALID_SQL");
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE["invalid-parameter"]).toBe("IWEB_SQL_INVALID_PARAMETER");
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE.constraint).toBe("IWEB_SQL_CONSTRAINT");
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE.busy).toBe("IWEB_SQL_BUSY");
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE["quota-exceeded"]).toBe("IWEB_SQL_QUOTA_EXCEEDED");
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE["limit-exceeded"]).toBe("IWEB_SQL_LIMIT_EXCEEDED");
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE.unavailable).toBe("IWEB_SQL_UNAVAILABLE");
		expect(IWEB_SQL_WIRE_ERROR_BY_CASE.internal).toBe("IWEB_SQL_INTERNAL");
	});

	test("host-call frame projection uses the design closed set", () => {
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE["invalid-sql"]).toBe("INVALID_ARGUMENT");
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE["invalid-parameter"]).toBe("INVALID_ARGUMENT");
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE.constraint).toBe("CONFLICT");
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE.busy).toBe("BUSY");
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE["quota-exceeded"]).toBe("QUOTA_EXCEEDED");
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE["limit-exceeded"]).toBe("LIMIT_EXCEEDED");
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE.unavailable).toBe("UNAVAILABLE");
		expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE.internal).toBe("INTERNAL");
	});

	test("errors never echo SQL text, parameters or paths", () => {
		const result = validateIwebSqlStatement("SELECT load_extension('marker-secret-payload') FROM 'path-marker'", IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(JSON.stringify(result.error)).not.toContain("marker-secret-payload");
			expect(JSON.stringify(result.error)).not.toContain("path-marker");
		}
	});
});

describe("minimal-sqlite-v1 statement validator: accepted DML", () => {
	test("accepts ordinary SELECT/INSERT/UPDATE/DELETE with positional placeholders", () => {
		const cases: readonly [string, "select" | "insert" | "update" | "delete", number][] = [
			["SELECT 1", "select", 0],
			["select * from t where id = ?", "select", 1],
			["INSERT INTO t (a, b) VALUES (?, ?)", "insert", 2],
			["UPDATE t SET a = ? WHERE b = ?2", "update", 2],
			["DELETE FROM t WHERE id = ?", "delete", 1],
			["sElEcT name FROM users WHERE id = ?", "select", 1],
		];
		for (const [statement, kind, parameterCount] of cases) {
			const result = validateIwebSqlStatement(statement, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value.kind).toBe(kind);
				expect(result.value.parameterCount).toBe(parameterCount);
			}
		}
		expect([...IWEB_SQL_DML_STATEMENT_KINDS]).toEqual(["select", "insert", "update", "delete"]);
	});

	test("follows the SQLite placeholder numbering semantics", () => {
		// 裸 `?` 取「已分配最大序号 + 1」；`?NNN` 显式分配；计数即最大序号。
		const cases: readonly [string, number][] = [
			["SELECT ?", 1],
			["SELECT ?2", 2],
			["SELECT ?, ?2", 2],
			["SELECT ?4, (?)", 5],
			["SELECT ?2, ?1", 2],
			["UPDATE t SET a = ?, b = ?, c = ?3 WHERE d = ?", 4],
		];
		for (const [statement, parameterCount] of cases) {
			const result = validateIwebSqlStatement(statement, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
			expect(result.ok).toBe(true);
			if (result.ok) expect(result.value.parameterCount).toBe(parameterCount);
		}
	});

	test("accepts one trailing semicolon, comments, string literals and quoted identifiers", () => {
		for (const statement of [
			"SELECT 1;",
			"SELECT 1; -- trailing comment",
			"SELECT /* leading */ 1 -- done",
			"SELECT /* outer /* nested */ still comment */ 1",
			"SELECT 'a;b'",
			"SELECT 'it''s ok' FROM t",
			"SELECT 'attach' WHERE x = 'pragma and load_extension'",
			'SELECT "pragma", `detach`, [attach] FROM t',
			'SELECT "load_extension" FROM t',
			"INSERT INTO t VALUES (x'0a0b', ?)",
			"INSERT INTO t VALUES (x'', ?)",
			"SELECT 0xFF + 1.5e-3 + .5",
			"SELECT 1e10",
			"SELECT \"café\" FROM t",
			"SELECT t.* FROM t WHERE (a IS NOT NULL AND b IN (?, ?)) OR c LIKE ?",
		]) {
			const result = validateIwebSqlStatement(statement, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
			expect(result.ok).toBe(true);
		}
	});
});

describe("minimal-sqlite-v1 statement validator: rejected statements", () => {
	test("rejects multiple statements and semicolon scripts before execution", () => {
		expectInvalidSql("SELECT 1; SELECT 2", "IWEB_SQL_MULTIPLE_STATEMENTS");
		expectInvalidSql("SELECT 1;;", "IWEB_SQL_MULTIPLE_STATEMENTS");
		expectInvalidSql("; SELECT 1", "IWEB_SQL_MULTIPLE_STATEMENTS");
		expectInvalidSql("INSERT INTO t(a) VALUES (?); DROP TABLE t", "IWEB_SQL_MULTIPLE_STATEMENTS");
		expectInvalidSql("DELETE FROM t; -- not really\nSELECT 1", "IWEB_SQL_MULTIPLE_STATEMENTS");
	});

	test("rejects empty or comment-only statements", () => {
		expectInvalidSql("", "IWEB_SQL_EMPTY_STATEMENT");
		expectInvalidSql("   \t\n", "IWEB_SQL_EMPTY_STATEMENT");
		expectInvalidSql("-- only a comment", "IWEB_SQL_EMPTY_STATEMENT");
		expectInvalidSql("/* only a block comment */", "IWEB_SQL_EMPTY_STATEMENT");
		expectInvalidSql(";", "IWEB_SQL_EMPTY_STATEMENT");
	});

	test("rejects statement kinds outside the dialect, including the pending DDL subset", () => {
		for (const statement of [
			"ATTACH DATABASE '/tmp/x.db' AS x",
			"DETACH DATABASE x",
			"PRAGMA journal_mode = WAL",
			"PRAGMA user_version",
			"CREATE TABLE t (a INTEGER)",
			"CREATE INDEX i ON t(a)",
			"DROP TABLE t",
			"ALTER TABLE t ADD COLUMN c INTEGER",
			"CREATE VIRTUAL TABLE v USING fts5(a)",
			"BEGIN",
			"COMMIT",
			"ROLLBACK",
			"VACUUM",
			"ANALYZE",
			"EXPLAIN SELECT 1",
			"REINDEX t",
		]) {
			expectInvalidSql(statement, "IWEB_SQL_STATEMENT_KIND_DENIED");
		}
	});

	test("rejects WITH/CTE as outside ordinary DML (WITH 越界)", () => {
		expectInvalidSql("WITH x AS (SELECT 1) SELECT * FROM x", "IWEB_SQL_WITH_DENIED");
		expectInvalidSql("WITH RECURSIVE c(n) AS (VALUES (1)) SELECT n FROM c", "IWEB_SQL_WITH_DENIED");
		expectInvalidSql("WITH x AS (SELECT 1) DELETE FROM t", "IWEB_SQL_WITH_DENIED");
	});

	test("rejects attach/detach/pragma keywords in any unquoted position", () => {
		expectInvalidSql("SELECT * FROM t WHERE attach = 1", "IWEB_SQL_KEYWORD_DENIED");
		expectInvalidSql("SELECT detach FROM t", "IWEB_SQL_KEYWORD_DENIED");
		expectInvalidSql("SELECT * FROM t CROSS JOIN pragma", "IWEB_SQL_KEYWORD_DENIED");
	});

	test("rejects extension loading, file path and pragma table functions in call position", () => {
		expectInvalidSql("SELECT load_extension('evil')", "IWEB_SQL_EXTENSION_FUNCTION_DENIED");
		expectInvalidSql("SELECT LOAD_EXTENSION /* spacing */ ('evil')", "IWEB_SQL_EXTENSION_FUNCTION_DENIED");
		expectInvalidSql("SELECT fts3_tokenizer('simple')", "IWEB_SQL_EXTENSION_FUNCTION_DENIED");
		expectInvalidSql("SELECT readfile('/etc/passwd')", "IWEB_SQL_FILE_FUNCTION_DENIED");
		expectInvalidSql("SELECT writefile('/tmp/x', x'00')", "IWEB_SQL_FILE_FUNCTION_DENIED");
		expectInvalidSql("SELECT edit('x')", "IWEB_SQL_FILE_FUNCTION_DENIED");
		expectInvalidSql("SELECT * FROM pragma_database_list()", "IWEB_SQL_PRAGMA_FUNCTION_DENIED");
		expectInvalidSql("SELECT * FROM t JOIN pragma_table_info('t')", "IWEB_SQL_PRAGMA_FUNCTION_DENIED");
		// 非调用位置的同名列名不触发函数 denylist（引号标识符同理由 tokenizer 豁免）。
		const column = validateIwebSqlStatement("SELECT readfile FROM t", IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(column.ok).toBe(true);
	});

	test("rejects named placeholders and malformed placeholder indexes", () => {
		expectInvalidSql("SELECT :name", "IWEB_SQL_NAMED_PLACEHOLDER_DENIED");
		expectInvalidSql("SELECT @name", "IWEB_SQL_NAMED_PLACEHOLDER_DENIED");
		expectInvalidSql("SELECT $name", "IWEB_SQL_NAMED_PLACEHOLDER_DENIED");
		expectInvalidSql("SELECT ?0", "IWEB_SQL_PLACEHOLDER_INDEX_INVALID");
		expectInvalidSql("SELECT ?12ab", "IWEB_SQL_PLACEHOLDER_INDEX_INVALID");
		expectInvalidSql("SELECT ?1234567", "IWEB_SQL_PLACEHOLDER_INDEX_INVALID");
	});

	test("rejects malformed literals, comments and out-of-grammar tokens", () => {
		expectInvalidSql("SELECT 'unterminated", "IWEB_SQL_LITERAL_UNTERMINATED");
		expectInvalidSql('SELECT "unterminated', "IWEB_SQL_LITERAL_UNTERMINATED");
		expectInvalidSql("SELECT `unterminated", "IWEB_SQL_LITERAL_UNTERMINATED");
		expectInvalidSql("SELECT [unterminated", "IWEB_SQL_LITERAL_UNTERMINATED");
		expectInvalidSql("SELECT /* unterminated", "IWEB_SQL_COMMENT_UNTERMINATED");
		expectInvalidSql("SELECT x'4'", "IWEB_SQL_BLOB_LITERAL_INVALID");
		expectInvalidSql("SELECT x'gg'", "IWEB_SQL_BLOB_LITERAL_INVALID");
		expectInvalidSql("SELECT café FROM t", "IWEB_SQL_TOKEN_INVALID");
		expectInvalidSql("SELECT #", "IWEB_SQL_TOKEN_INVALID");
		expectInvalidSql("SELECT 123abc", "IWEB_SQL_TOKEN_INVALID");
		expectInvalidSql("SELECT 1.5e", "IWEB_SQL_TOKEN_INVALID");
		expectInvalidSql("SELECT 'a\0b'", "IWEB_SQL_TOKEN_INVALID");
	});
});

describe("minimal-sqlite-v1 statement and parameter limits", () => {
	const tinyLimits: IwebSqlLimits = { ...IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS, statementMaxBytes: 16, maxParameters: 2, parameterMaxBytes: 8 };

	test("statement byte bound is inclusive at the limit", () => {
		expect(validateIwebSqlStatement("SELECT 123456789", tinyLimits).ok).toBe(true);
		const over = validateIwebSqlStatement("SELECT 1234567890", tinyLimits);
		expect(over.ok).toBe(false);
		if (!over.ok) {
			expect(over.error.case).toBe("limit-exceeded");
			expect(over.error.code).toBe("IWEB_SQL_STATEMENT_BYTES_EXCEEDED");
		}
	});

	test("default profile statement byte bound at exactly 8192", () => {
		const atLimit = "SELECT '" + "a".repeat(8192 - 9) + "'";
		expect(IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS.statementMaxBytes).toBe(8192);
		expect(validateIwebSqlStatement(atLimit, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS).ok).toBe(true);
		const over = validateIwebSqlStatement(atLimit + "a", IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(over.ok).toBe(false);
		if (!over.ok) {
			expect(over.error.case).toBe("limit-exceeded");
			expect(over.error.code).toBe("IWEB_SQL_STATEMENT_BYTES_EXCEEDED");
		}
	});

	test("statement placeholder count above maxParameters is limit-exceeded", () => {
		const result = validateIwebSqlStatement("SELECT ?300", IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.case).toBe("limit-exceeded");
			expect(result.error.code).toBe("IWEB_SQL_PARAMETER_COUNT_EXCEEDED");
		}
	});

	test("execute preflight enforces parameter count/byte maxima and count match", () => {
		const ok = validateIwebSqlExecuteRequest("SELECT ? WHERE a = ?", [{ value: { kind: "integer", value: 1 } }, { value: { kind: "null" } }], IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(ok.ok).toBe(true);
		if (ok.ok) {
			expect(ok.value.kind).toBe("select");
			expect(ok.value.parameterCount).toBe(2);
			expect(ok.value.parameterValues.length).toBe(2);
			expect(ok.value.parameterBytes).toBe(8);
		}

		const overCount = validateIwebSqlExecuteRequest("SELECT ?", [{ value: { kind: "null" } }, { value: { kind: "null" } }, { value: { kind: "null" } }], tinyLimits);
		expect(overCount.ok).toBe(false);
		if (!overCount.ok) {
			expect(overCount.error.case).toBe("limit-exceeded");
			expect(overCount.error.code).toBe("IWEB_SQL_PARAMETER_COUNT_EXCEEDED");
		}

		const overBytes = validateIwebSqlExecuteRequest("SELECT ?", [{ value: { kind: "text", value: "123456789" } }], tinyLimits);
		expect(overBytes.ok).toBe(false);
		if (!overBytes.ok) {
			expect(overBytes.error.case).toBe("limit-exceeded");
			expect(overBytes.error.code).toBe("IWEB_SQL_PARAMETER_BYTES_EXCEEDED");
		}
		const atByteBound = validateIwebSqlExecuteRequest("SELECT ?", [{ value: { kind: "text", value: "12345678" } }], tinyLimits);
		expect(atByteBound.ok).toBe(true);

		const mismatchShort = validateIwebSqlExecuteRequest("SELECT ?", [], IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(mismatchShort.ok).toBe(false);
		if (!mismatchShort.ok) {
			expect(mismatchShort.error.case).toBe("invalid-parameter");
			expect(mismatchShort.error.code).toBe("IWEB_SQL_PARAMETER_COUNT_MISMATCH");
		}
		const mismatchLong = validateIwebSqlExecuteRequest("SELECT ?4, (?)", [{ value: { kind: "null" } }, { value: { kind: "null" } }], IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(mismatchLong.ok).toBe(false);
		if (!mismatchLong.ok) expect(mismatchLong.error.code).toBe("IWEB_SQL_PARAMETER_COUNT_MISMATCH");
		const explicitMatch = validateIwebSqlExecuteRequest("SELECT ?4, (?)", [
			{ value: { kind: "null" } },
			{ value: { kind: "null" } },
			{ value: { kind: "null" } },
			{ value: { kind: "null" } },
			{ value: { kind: "null" } },
		], IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(explicitMatch.ok).toBe(true);
	});

	test("execute preflight rejects non-string statements and non-array parameters", () => {
		const badStatement = validateIwebSqlExecuteRequest(42, [], IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(badStatement.ok).toBe(false);
		if (!badStatement.ok) {
			expect(badStatement.error.case).toBe("invalid-parameter");
			expect(badStatement.error.code).toBe("IWEB_SQL_STATEMENT_TYPE_INVALID");
		}
		const badParameters = validateIwebSqlExecuteRequest("SELECT 1", { value: { kind: "null" } }, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(badParameters.ok).toBe(false);
		if (!badParameters.ok) expect(badParameters.error.code).toBe("IWEB_SQL_PARAMETERS_TYPE_INVALID");
	});
});

describe("iweb:sql value wire", () => {
	test("accepts the five WIT value kinds", () => {
		for (const value of [{ kind: "null" }, { kind: "integer", value: 42 }, { kind: "integer", value: -9007199254740991 }, { kind: "real", value: -1.5 }, { kind: "text", value: "héllo 𝒜" }, { kind: "blob", value: new Uint8Array([1, 2, 3]) }]) {
			const result = parseIwebSqlParameter({ value });
			expect(result.ok).toBe(true);
		}
	});

	test("rejects out-of-domain values fail-closed", () => {
		const badValues: unknown[] = [
			5,
			null,
			"null",
			{ kind: "json", value: { a: 1 } },
			{ kind: "integer", value: 1.5 },
			{ kind: "integer", value: 9007199254740992 },
			{ kind: "integer" },
			{ kind: "real", value: Number.NaN },
			{ kind: "real", value: Number.POSITIVE_INFINITY },
			{ kind: "text", value: "\ud800" },
			{ kind: "text", value: "ok", extra: 1 },
			{ kind: "blob", value: [1, 2, 3] },
			{ kind: "blob", value: "0102" },
			{ kind: "null", value: 1 },
		];
		for (const value of badValues) {
			const result = parseIwebSqlParameter({ value });
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.case).toBe("invalid-parameter");
				expect(result.error.code).toBe("IWEB_SQL_PARAMETER_VALUE_INVALID");
			}
		}
	});

	test("parameter record must carry exactly the value field", () => {
		expect(parseIwebSqlParameter({ value: { kind: "null" }, extra: true }).ok).toBe(false);
		expect(parseIwebSqlParameter({}).ok).toBe(false);
		expect(parseIwebSqlParameter("x").ok).toBe(false);
		const failure = parseIwebSqlParameter([1]);
		expect(failure.ok).toBe(false);
		if (!failure.ok) expect(failure.error.code).toBe("IWEB_SQL_PARAMETER_TYPE_INVALID");
	});

	test("wire byte accounting is deterministic", () => {
		expect(iwebSqlValueWireBytes({ kind: "null" })).toBe(0);
		expect(iwebSqlValueWireBytes({ kind: "integer", value: 1 })).toBe(8);
		expect(iwebSqlValueWireBytes({ kind: "real", value: 1.5 })).toBe(8);
		expect(iwebSqlValueWireBytes({ kind: "text", value: "é" })).toBe(2);
		expect(iwebSqlValueWireBytes({ kind: "text", value: "𝒜" })).toBe(4);
		expect(iwebSqlValueWireBytes({ kind: "blob", value: new Uint8Array(3) })).toBe(3);
		expect(iwebSqlResultBytes([{ columns: [{ name: "a", value: { kind: "integer", value: 1 } }] }])).toBe(9);
		expect(iwebSqlResultBytes([
			{ columns: [{ name: "bc", value: { kind: "text", value: "xyz" } }] },
			{ columns: [] },
		])).toBe(5);
	});
});

describe("iweb:sql result wire limits", () => {
	const tinyLimits: IwebSqlLimits = { ...IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS, maxRows: 2, resultMaxBytes: 16, maxAffectedRows: 2 };
	const row = { columns: [{ name: "a", value: { kind: "integer", value: 1 } }] };

	test("accepts a complete result and never a truncated success", () => {
		const result = validateIwebSqlResultWire({ rows: [row], affected: 1, lastInsertId: 7 }, tinyLimits);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.rows.length).toBe(1);
			expect(result.value.affected).toBe(1);
			expect(result.value.lastInsertId).toBe(7);
		}
		const nullId = validateIwebSqlResultWire({ rows: [], affected: 0, lastInsertId: null }, tinyLimits);
		expect(nullId.ok).toBe(true);
	});

	test("row and byte bounds are inclusive at the limit, exceeded beyond", () => {
		expect(validateIwebSqlResultWire({ rows: [row, row], affected: 0, lastInsertId: null }, tinyLimits).ok).toBe(false); // 18 > 16 bytes
		const byteOver = validateIwebSqlResultWire({ rows: [row, row], affected: 0, lastInsertId: null }, { ...tinyLimits, resultMaxBytes: 18 });
		expect(byteOver.ok).toBe(true);
		const rowsOver = validateIwebSqlResultWire({ rows: [row, row, row], affected: 0, lastInsertId: null }, { ...tinyLimits, resultMaxBytes: 1024 });
		expect(rowsOver.ok).toBe(false);
		if (!rowsOver.ok) {
			expect(rowsOver.error.case).toBe("limit-exceeded");
			expect(rowsOver.error.code).toBe("IWEB_SQL_RESULT_ROWS_EXCEEDED");
		}
		const bytesOver = validateIwebSqlResultWire({ rows: [row], affected: 0, lastInsertId: null }, { ...tinyLimits, maxRows: 5, resultMaxBytes: 8 });
		expect(bytesOver.ok).toBe(false);
		if (!bytesOver.ok) {
			expect(bytesOver.error.case).toBe("limit-exceeded");
			expect(bytesOver.error.code).toBe("IWEB_SQL_RESULT_BYTES_EXCEEDED");
		}
	});

	test("affected bound is inclusive at the limit", () => {
		expect(validateIwebSqlResultWire({ rows: [], affected: 2, lastInsertId: null }, tinyLimits).ok).toBe(true);
		const over = validateIwebSqlResultWire({ rows: [], affected: 3, lastInsertId: null }, tinyLimits);
		expect(over.ok).toBe(false);
		if (!over.ok) {
			expect(over.error.case).toBe("limit-exceeded");
			expect(over.error.code).toBe("IWEB_SQL_AFFECTED_ROWS_EXCEEDED");
		}
	});

	test("default profile row bound at exactly 1000", () => {
		const rows = Array.from({ length: 1000 }, () => row);
		expect(IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS.maxRows).toBe(1000);
		expect(validateIwebSqlResultWire({ rows, affected: 0, lastInsertId: null }, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS).ok).toBe(true);
		const over = validateIwebSqlResultWire({ rows: [...rows, row], affected: 0, lastInsertId: null }, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		expect(over.ok).toBe(false);
		if (!over.ok) expect(over.error.code).toBe("IWEB_SQL_RESULT_ROWS_EXCEEDED");
	});

	test("malformed host-produced result wires fail as internal", () => {
		const badResults: unknown[] = [
			"not-an-object",
			{ rows: "x", affected: 0, lastInsertId: null },
			{ rows: [], affected: -1, lastInsertId: null },
			{ rows: [], affected: 1.5, lastInsertId: null },
			{ rows: [], affected: 0, lastInsertId: -1 },
			{ rows: [], affected: 0, lastInsertId: 1.5 },
			{ rows: [], affected: 0, lastInsertId: null, extra: true },
			{ rows: [{ columns: [{ name: "", value: { kind: "null" } }] }], affected: 0, lastInsertId: null },
			{ rows: [{ columns: [{ name: "a".repeat(257), value: { kind: "null" } }] }], affected: 0, lastInsertId: null },
			{ rows: [{ columns: [{ name: "a", value: { kind: "real", value: Number.NaN } }] }], affected: 0, lastInsertId: null },
			{ rows: [{ columns: [] , extra: 1 }], affected: 0, lastInsertId: null },
			{ rows: [{ value: { kind: "null" } }], affected: 0, lastInsertId: null },
		];
		for (const input of badResults) {
			const result = validateIwebSqlResultWire(input, IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.case).toBe("internal");
				expect(result.error.code).toBe("IWEB_SQL_RESULT_WIRE_INVALID");
			}
		}
	});
});
