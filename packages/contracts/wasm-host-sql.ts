// 用户原始需求（2026-08-27，add-wasm-host-services 契约层先行）：`iweb:sql@1.0.0` 的 WIT 身份、minimal-sqlite-v1
// 语句静态校验、结果/行/字节配额纯函数与错误码映射必须与规范一致（owner 终裁 S1=minimal-sqlite-v1；S2=单调用隐式事务、
// 无跨调用事务句柄；宿主绝不从分号文本推断批处理）。
// 正交意图：WIT 包/方向/版本身份法；单语句+参数占位+denylist 的方言静态校验器；语句/参数/行/字节/affected 配额纯函数；
// WIT error case ↔ wire/host-call 错误码映射；execute 请求与 result wire 的 fail-closed 校验。
// 规范权威：openspec/changes/add-wasm-host-services/specs/wasm-host-sql/spec.md（WIT 块 +「SQL dialect and transaction
// boundary are pinned」「SQL resources and results are bounded」）与 design.md §6/「Owner Decisions Ratified」。
// WIT 文本权威：./wit/iweb-sql.wit（tests/wasm-host-sql.test.ts 断言与 spec 逐字一致）。
// fail-closed 裁决（歧义上报，未获 owner 冻结前一律收紧）：
// - 有界 DDL 子集是任务 1.2 的 owner 未决项：语句类型白名单当前仅 select/insert/update/delete，CREATE/ALTER/DROP 一律 invalid-sql；
// - WITH/CTE（含 WITH RECURSIVE）不属于 minimal-sqlite-v1 的 ordinary DML，按越界拒绝（WITH 越界）；
// - 「positional parameter binding」收窄为 `?` / `?NNN`：`:name` / `@name` / `$name` 命名占位一律 invalid-sql；
// - 未加引号的 attach/detach/pragma 词元任意位置拒绝（含只读 PRAGMA 与 `pragma_*()` 表函数）；
//   load_extension/fts3_tokenizer/readfile/writefile/edit 仅在调用位置（后随 `(`）拒绝；字符串字面量与引号标识符豁免；
// - 虚拟表模块注册面（csv/zipfile 等）是 wasmd 后端编译期职责，静态 denylist 不逐模块枚举；
// - s64 integer 的 TS 投影只接受 safe integer；real 必须有限；text 拒绝 lone surrogate（WIT string 是 Unicode 标量序列）；
// - IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS 是契约测试占位默认，非 owner 冻结值：真实上限由 HostServicePolicyV2 显式注入，
//   本文件所有纯函数一律显式接收 limits，绝不内置读取该常量。
// 配额预留（quota ledger reserve/finalize）、隐式事务提交、锁等待与并发上限的运行时执行是 wasmd provider 数据面职责，
// 不在本契约纯函数内。
import { boundedText, isRecord } from "./validation.ts";
import { iwebUtf8ByteLength } from "./wasm-host-store.ts";

// ---------------------------------------------------------------------------
// WIT 包/接口身份与方向/版本法（import store 是唯一合法方向）
// ---------------------------------------------------------------------------

export const IWEB_SQL_WIT_PACKAGE = "iweb:sql@1.0.0";
export const IWEB_SQL_WIT_WORLD = "sql";
export const IWEB_SQL_STORE_INTERFACE = "store";

export type IwebSqlWitDirectionErrorCode = "IWEB_SQL_WIT_DIRECTION_INVALID";

// world/component 只能 import store；export store 一律在 OCI 物化前拒绝（spec 方向向量为 normative）。
export function iwebSqlWitDirectionErrorCode(id: { readonly package: string; readonly interface: string; readonly direction: string }): IwebSqlWitDirectionErrorCode | null {
	if (id.direction !== "export" || id.interface !== IWEB_SQL_STORE_INTERFACE) return null;
	if (id.package === IWEB_SQL_WIT_PACKAGE) return "IWEB_SQL_WIT_DIRECTION_INVALID";
	return null;
}

// 版本钉死：iweb:sql 命名空间只认 1.0.0；iweb:sql@1.0.1 之类在 admission 物化前拒绝（spec「SQL import is substituted」）。
export type IwebSqlWitVersionErrorCode = "IWEB_SQL_WIT_VERSION_INVALID";

export function iwebSqlWitVersionErrorCode(packageName: string): IwebSqlWitVersionErrorCode | null {
	if (packageName === IWEB_SQL_WIT_PACKAGE || !packageName.startsWith("iweb:sql@")) return null;
	return "IWEB_SQL_WIT_VERSION_INVALID";
}

// ---------------------------------------------------------------------------
// WIT 调用错误 variant ↔ wire/host-call 错误码（closed set，不回显 SQL 文本/参数/路径/凭证）
// ---------------------------------------------------------------------------

export const IWEB_SQL_WIT_ERROR_CASES = ["invalid-sql", "invalid-parameter", "constraint", "busy", "quota-exceeded", "limit-exceeded", "unavailable", "internal"] as const;
export type IwebSqlErrorCase = (typeof IWEB_SQL_WIT_ERROR_CASES)[number];

export const IWEB_SQL_WIRE_ERROR_BY_CASE: Readonly<Record<IwebSqlErrorCase, string>> = {
	"invalid-sql": "IWEB_SQL_INVALID_SQL",
	"invalid-parameter": "IWEB_SQL_INVALID_PARAMETER",
	constraint: "IWEB_SQL_CONSTRAINT",
	busy: "IWEB_SQL_BUSY",
	"quota-exceeded": "IWEB_SQL_QUOTA_EXCEEDED",
	"limit-exceeded": "IWEB_SQL_LIMIT_EXCEEDED",
	unavailable: "IWEB_SQL_UNAVAILABLE",
	internal: "IWEB_SQL_INTERNAL",
};

// host-call frame 的 HostCallErrorV2 closed set 投影（design.md §5）；ATTACH/路径类静态拒绝经 invalid-sql → INVALID_ARGUMENT，
// 与 spec「APP_ISOLATION/INVALID_ARGUMENT without revealing whether the target exists」一致。
export type IwebSqlHostCallErrorCode = "INVALID_ARGUMENT" | "CONFLICT" | "QUOTA_EXCEEDED" | "LIMIT_EXCEEDED" | "BUSY" | "UNAVAILABLE" | "INTERNAL";

export const IWEB_SQL_HOST_CALL_ERROR_BY_CASE: Readonly<Record<IwebSqlErrorCase, IwebSqlHostCallErrorCode>> = {
	"invalid-sql": "INVALID_ARGUMENT",
	"invalid-parameter": "INVALID_ARGUMENT",
	constraint: "CONFLICT",
	busy: "BUSY",
	"quota-exceeded": "QUOTA_EXCEEDED",
	"limit-exceeded": "LIMIT_EXCEEDED",
	unavailable: "UNAVAILABLE",
	internal: "INTERNAL",
};

export interface IwebSqlWireError {
	readonly case: IwebSqlErrorCase;
	readonly code: string;
	readonly message: string;
}

export type IwebSqlCheck<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: IwebSqlWireError };

function sqlError(errorCase: IwebSqlErrorCase, code: string, message: string): IwebSqlWireError {
	return { case: errorCase, code, message: boundedText(message) };
}

// ---------------------------------------------------------------------------
// profile 上限形状（执行时间/锁等待/并发由 provider 运行时强制；其余由本文件纯函数强制）
// ---------------------------------------------------------------------------

export interface IwebSqlLimits {
	readonly statementMaxBytes: number;
	readonly maxParameters: number;
	readonly parameterMaxBytes: number;
	readonly maxRows: number;
	readonly resultMaxBytes: number;
	readonly maxAffectedRows: number;
	readonly executionMaxMs: number;
	readonly lockWaitMaxMs: number;
	readonly maxConcurrentCalls: number;
}

// 占位默认（非 owner 冻结值，任务 1.2/3.1 冻结前仅供契约测试）：真实上限以 HostServicePolicyV2 为准。
export const IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS: IwebSqlLimits = {
	statementMaxBytes: 8192,
	maxParameters: 128,
	parameterMaxBytes: 65536,
	maxRows: 1000,
	resultMaxBytes: 262144,
	maxAffectedRows: 4096,
	executionMaxMs: 5000,
	lockWaitMaxMs: 2000,
	maxConcurrentCalls: 2,
};

// ---------------------------------------------------------------------------
// WIT value/parameter/column/row/result 的 TS 投影与 fail-closed 校验
// ---------------------------------------------------------------------------

export const IWEB_SQL_VALUE_KINDS = ["null", "integer", "real", "text", "blob"] as const;
export type IwebSqlValueKind = (typeof IWEB_SQL_VALUE_KINDS)[number];

export type IwebSqlValue =
	| { readonly kind: "null" }
	| { readonly kind: "integer"; readonly value: number }
	| { readonly kind: "real"; readonly value: number }
	| { readonly kind: "text"; readonly value: string }
	| { readonly kind: "blob"; readonly value: Uint8Array };

export interface IwebSqlParameter {
	readonly value: IwebSqlValue;
}

export interface IwebSqlColumn {
	readonly name: string;
	readonly value: IwebSqlValue;
}

export interface IwebSqlRow {
	readonly columns: readonly IwebSqlColumn[];
}

export interface IwebSqlResultWire {
	readonly rows: readonly IwebSqlRow[];
	readonly affected: number;
	readonly lastInsertId: number | null;
}

export const IWEB_SQL_COLUMN_NAME_MAX_BYTES = 256;

function hasLoneSurrogate(text: string): boolean {
	for (let index = 0; index < text.length; index++) {
		const code = text.charCodeAt(index);
		if (code >= 0xd800 && code <= 0xdbff) {
			const low = index + 1 < text.length ? text.charCodeAt(index + 1) : 0;
			if (low >= 0xdc00 && low <= 0xdfff) {
				index++;
				continue;
			}
			return true;
		}
		if (code >= 0xdc00 && code <= 0xdfff) return true;
	}
	return false;
}

// 值域只收 WIT 列出的五种；JSON 对象、宿主句柄、number[] blob、NaN/Inf real、越 s64-safe 的 integer 一律 invalid-parameter。
export function parseIwebSqlValue(input: unknown): IwebSqlCheck<IwebSqlValue> {
	if (!isRecord(input)) {
		return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "value must be a kind-discriminated record") };
	}
	const fieldCount = Object.keys(input).length;
	if (input.kind === "null") {
		if (fieldCount !== 1) return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "null value carries no extra fields") };
		return { ok: true, value: { kind: "null" } };
	}
	if (input.kind === "integer" || input.kind === "real") {
		const value = input.value;
		if (fieldCount !== 2 || typeof value !== "number") {
			return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "numeric value must carry exactly one finite number") };
		}
		if (input.kind === "integer" && !Number.isSafeInteger(value)) {
			return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "integer must be a safe integer within the s64 projection") };
		}
		if (input.kind === "real" && !Number.isFinite(value)) {
			return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "real must be finite") };
		}
		return { ok: true, value: input.kind === "integer" ? { kind: "integer", value } : { kind: "real", value } };
	}
	if (input.kind === "text") {
		const value = input.value;
		if (fieldCount !== 2 || typeof value !== "string" || hasLoneSurrogate(value)) {
			return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "text must be a string of Unicode scalar values") };
		}
		return { ok: true, value: { kind: "text", value } };
	}
	if (input.kind === "blob") {
		const value = input.value;
		if (fieldCount !== 2 || !(value instanceof Uint8Array)) {
			return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "blob must be a Uint8Array of bytes") };
		}
		return { ok: true, value: { kind: "blob", value } };
	}
	return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_VALUE_INVALID", "kind must be one of null, integer, real, text, blob") };
}

// WIT `record parameter { value: value }`：恰好一个 value 字段，禁止未知字段。
export function parseIwebSqlParameter(input: unknown): IwebSqlCheck<IwebSqlValue> {
	if (!isRecord(input)) {
		return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_TYPE_INVALID", "parameter must be a record with exactly one value field") };
	}
	const keys = Object.keys(input);
	if (keys.length !== 1 || keys[0] !== "value") {
		return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_TYPE_INVALID", "parameter must carry only the value field") };
	}
	return parseIwebSqlValue(input.value);
}

// ---------------------------------------------------------------------------
// wire 字节核算：null=0，integer/real=8（s64/f64 定宽），text=UTF-8 字节，blob=字节数；列名按 UTF-8 计入。
// ---------------------------------------------------------------------------

export function iwebSqlValueWireBytes(value: IwebSqlValue): number {
	switch (value.kind) {
		case "null":
			return 0;
		case "integer":
		case "real":
			return 8;
		case "text":
			return iwebUtf8ByteLength(value.value);
		case "blob":
			return value.value.byteLength;
	}
}

export function iwebSqlResultBytes(rows: readonly IwebSqlRow[]): number {
	let total = 0;
	for (const row of rows) {
		for (const column of row.columns) {
			total += iwebUtf8ByteLength(column.name) + iwebSqlValueWireBytes(column.value);
		}
	}
	return total;
}

// ---------------------------------------------------------------------------
// minimal-sqlite-v1 词法层：字符串/注释/引号标识符感知的单语句扫描
// ---------------------------------------------------------------------------

type IwebSqlTokenKind = "word" | "quoted-identifier" | "string" | "blob" | "number" | "placeholder" | "punct" | "semicolon";

interface IwebSqlToken {
	readonly kind: IwebSqlTokenKind;
	readonly text: string;
	readonly placeholderIndex: number | null;
}

type IwebSqlTokenizeOutcome = { readonly ok: true; readonly tokens: IwebSqlToken[] } | { readonly ok: false; readonly error: IwebSqlWireError };

const SQL_ASCII_WHITESPACE = " \t\n\r\f\v";
const SQL_PUNCT_CHARS = "(),.*+-/%=<>!~&|^";
const SQL_WORD_PATTERN = /[A-Za-z_][A-Za-z0-9_]*/y;
const SQL_NUMBER_PATTERN = /(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)/y;
const SQL_PLACEHOLDER_DIGITS = /[0-9]{1,6}/y;
const SQL_HEX_PATTERN = /^[0-9A-Fa-f]*$/;
const SQL_DIGIT = /[0-9]/;
const SQL_IDENT_START = /[A-Za-z_]/;
const SQL_IDENT_CHAR = /[A-Za-z0-9_]/;

function tokenizeIwebSqlStatement(statement: string): IwebSqlTokenizeOutcome {
	const tokens: IwebSqlToken[] = [];
	const fail = (code: string, message: string): IwebSqlTokenizeOutcome => ({ ok: false, error: sqlError("invalid-sql", code, message) });
	// NUL 字节在 SQLite 词法中非法（包括字符串字面量内部），fail-closed 先拒。
	if (statement.includes("\0")) return fail("IWEB_SQL_TOKEN_INVALID", "statement contains a NUL byte");
	let index = 0;

	while (index < statement.length) {
		const ch = statement[index];
		if (SQL_ASCII_WHITESPACE.includes(ch)) {
			index++;
			continue;
		}
		if (ch === "-" && index + 1 < statement.length && statement[index + 1] === "-") {
			const newline = statement.indexOf("\n", index);
			index = newline === -1 ? statement.length : newline + 1;
			continue;
		}
		if (ch === "/" && index + 1 < statement.length && statement[index + 1] === "*") {
			let depth = 1;
			let cursor = index + 2;
			while (cursor < statement.length && depth > 0) {
				if (statement[cursor] === "/" && cursor + 1 < statement.length && statement[cursor + 1] === "*") {
					depth++;
					cursor += 2;
				} else if (statement[cursor] === "*" && cursor + 1 < statement.length && statement[cursor + 1] === "/") {
					depth--;
					cursor += 2;
				} else {
					cursor++;
				}
			}
			if (depth > 0) return fail("IWEB_SQL_COMMENT_UNTERMINATED", "block comment is not terminated");
			index = cursor;
			continue;
		}
		if (ch === "'") {
			let cursor = index + 1;
			for (;;) {
				const close = statement.indexOf("'", cursor);
				if (close === -1) return fail("IWEB_SQL_LITERAL_UNTERMINATED", "string literal is not terminated");
				if (close + 1 < statement.length && statement[close + 1] === "'") {
					cursor = close + 2;
					continue;
				}
				tokens.push({ kind: "string", text: statement.slice(index, close + 1), placeholderIndex: null });
				index = close + 1;
				break;
			}
			continue;
		}
		if ((ch === "x" || ch === "X") && index + 1 < statement.length && statement[index + 1] === "'") {
			const close = statement.indexOf("'", index + 2);
			if (close === -1) return fail("IWEB_SQL_LITERAL_UNTERMINATED", "blob literal is not terminated");
			const hex = statement.slice(index + 2, close);
			if (hex.length % 2 !== 0 || !SQL_HEX_PATTERN.test(hex)) {
				return fail("IWEB_SQL_BLOB_LITERAL_INVALID", "blob literal must contain an even number of hex digits");
			}
			tokens.push({ kind: "blob", text: statement.slice(index, close + 1), placeholderIndex: null });
			index = close + 1;
			continue;
		}
		if (ch === '"' || ch === "`") {
			let cursor = index + 1;
			for (;;) {
				const close = statement.indexOf(ch, cursor);
				if (close === -1) return fail("IWEB_SQL_LITERAL_UNTERMINATED", "quoted identifier is not terminated");
				if (close + 1 < statement.length && statement[close + 1] === ch) {
					cursor = close + 2;
					continue;
				}
				tokens.push({ kind: "quoted-identifier", text: statement.slice(index, close + 1), placeholderIndex: null });
				index = close + 1;
				break;
			}
			continue;
		}
		if (ch === "[") {
			const close = statement.indexOf("]", index + 1);
			if (close === -1) return fail("IWEB_SQL_LITERAL_UNTERMINATED", "bracket identifier is not terminated");
			tokens.push({ kind: "quoted-identifier", text: statement.slice(index, close + 1), placeholderIndex: null });
			index = close + 1;
			continue;
		}
		if (ch === "?") {
			SQL_PLACEHOLDER_DIGITS.lastIndex = index + 1;
			const digits = SQL_PLACEHOLDER_DIGITS.exec(statement);
			const digitText = digits === null ? "" : digits[0];
			if (digitText.length > 0) {
				const explicit = Number.parseInt(digitText, 10);
				const after = index + 1 + digitText.length;
				if (explicit < 1 || (after < statement.length && SQL_IDENT_CHAR.test(statement[after]))) {
					return fail("IWEB_SQL_PLACEHOLDER_INDEX_INVALID", "explicit parameter index must be 1..999999 digits and stand alone");
				}
				tokens.push({ kind: "placeholder", text: statement.slice(index, after), placeholderIndex: explicit });
				index = after;
				continue;
			}
			tokens.push({ kind: "placeholder", text: "?", placeholderIndex: null });
			index++;
			continue;
		}
		if (ch === ":" || ch === "@" || ch === "$") {
			return fail("IWEB_SQL_NAMED_PLACEHOLDER_DENIED", "minimal-sqlite-v1 accepts only ? and ?NNN positional placeholders");
		}
		if (ch === ";") {
			tokens.push({ kind: "semicolon", text: ";", placeholderIndex: null });
			index++;
			continue;
		}
		if (SQL_DIGIT.test(ch) || (ch === "." && index + 1 < statement.length && SQL_DIGIT.test(statement[index + 1]))) {
			SQL_NUMBER_PATTERN.lastIndex = index;
			const match = SQL_NUMBER_PATTERN.exec(statement);
			const raw = match === null ? "" : match[0];
			if (raw.length === 0) return fail("IWEB_SQL_TOKEN_INVALID", "numeric literal is malformed");
			const end = index + raw.length;
			if (end < statement.length && SQL_IDENT_START.test(statement[end])) {
				return fail("IWEB_SQL_TOKEN_INVALID", "numeric literal is followed by an identifier character");
			}
			tokens.push({ kind: "number", text: raw, placeholderIndex: null });
			index = end;
			continue;
		}
		SQL_WORD_PATTERN.lastIndex = index;
		const word = SQL_WORD_PATTERN.exec(statement);
		if (word !== null && word[0].length > 0) {
			tokens.push({ kind: "word", text: word[0], placeholderIndex: null });
			index += word[0].length;
			continue;
		}
		if (SQL_PUNCT_CHARS.includes(ch)) {
			tokens.push({ kind: "punct", text: ch, placeholderIndex: null });
			index++;
			continue;
		}
		return fail("IWEB_SQL_TOKEN_INVALID", "statement contains a character outside the minimal-sqlite-v1 lexical grammar");
	}
	return { ok: true, tokens };
}

// ---------------------------------------------------------------------------
// minimal-sqlite-v1 语句静态校验：单语句 + DML 白名单 + denylist + 参数计数
// ---------------------------------------------------------------------------

export const IWEB_SQL_DML_STATEMENT_KINDS = ["select", "insert", "update", "delete"] as const;
export type IwebSqlStatementKind = (typeof IWEB_SQL_DML_STATEMENT_KINDS)[number];

const SQL_STATEMENT_KEYWORD_DENYLIST: ReadonlySet<string> = new Set(["attach", "detach", "pragma"]);
const SQL_EXTENSION_FUNCTION_DENYLIST: ReadonlySet<string> = new Set(["load_extension", "fts3_tokenizer"]);
const SQL_FILE_FUNCTION_DENYLIST: ReadonlySet<string> = new Set(["readfile", "writefile", "edit"]);

function countStatementParameters(tokens: readonly IwebSqlToken[]): number {
	// SQLite 语义：裸 `?` 取「当前已分配最大序号 + 1」，`?NNN` 显式分配 NNN；参数计数即最大序号。
	let largest = 0;
	for (const token of tokens) {
		if (token.kind !== "placeholder") continue;
		largest = token.placeholderIndex === null ? largest + 1 : Math.max(largest, token.placeholderIndex);
	}
	return largest;
}

export interface IwebSqlStatementAnalysis {
	readonly kind: IwebSqlStatementKind;
	readonly parameterCount: number;
}

function analyzeIwebSqlTokens(tokens: readonly IwebSqlToken[], limits: IwebSqlLimits): IwebSqlCheck<IwebSqlStatementAnalysis> {
	const fail = (errorCase: IwebSqlErrorCase, code: string, message: string): IwebSqlCheck<IwebSqlStatementAnalysis> => ({ ok: false, error: sqlError(errorCase, code, message) });

	// 单语句：首个分号必须是最后一个 token（其后只能是被 tokenizer 跳过的注释/空白），剥去这一个尾分号。
	const firstSemicolon = tokens.findIndex((token) => token.kind === "semicolon");
	let body = tokens;
	if (firstSemicolon !== -1) {
		if (firstSemicolon !== tokens.length - 1) {
			return fail("invalid-sql", "IWEB_SQL_MULTIPLE_STATEMENTS", "exactly one statement per call; semicolon-separated scripts are rejected");
		}
		body = tokens.slice(0, -1);
	}
	if (body.length === 0) {
		return fail("invalid-sql", "IWEB_SQL_EMPTY_STATEMENT", "statement must contain one SQL statement");
	}
	const first = body[0];
	if (first.kind !== "word") {
		return fail("invalid-sql", "IWEB_SQL_STATEMENT_KIND_DENIED", "statement must begin with an ordinary DML keyword");
	}
	const leading = first.text.toLowerCase();
	if (leading === "with") {
		return fail("invalid-sql", "IWEB_SQL_WITH_DENIED", "WITH/CTE statements are outside the minimal-sqlite-v1 dialect");
	}
	const kind = (IWEB_SQL_DML_STATEMENT_KINDS as readonly string[]).includes(leading) ? (leading as IwebSqlStatementKind) : null;
	if (kind === null) {
		return fail("invalid-sql", "IWEB_SQL_STATEMENT_KIND_DENIED", "only ordinary select, insert, update and delete are accepted; the bounded DDL subset awaits the owner freeze");
	}

	for (let position = 0; position < body.length; position++) {
		const token = body[position];
		if (token.kind !== "word") continue;
		const word = token.text.toLowerCase();
		if (SQL_STATEMENT_KEYWORD_DENYLIST.has(word)) {
			return fail("invalid-sql", "IWEB_SQL_KEYWORD_DENIED", "attach, detach and pragma keywords are denied in every position");
		}
		const next = body[position + 1];
		const inCallPosition = next !== undefined && next.kind === "punct" && next.text === "(";
		if (!inCallPosition) continue;
		if (SQL_EXTENSION_FUNCTION_DENYLIST.has(word)) {
			return fail("invalid-sql", "IWEB_SQL_EXTENSION_FUNCTION_DENIED", "extension loading functions are denied");
		}
		if (SQL_FILE_FUNCTION_DENYLIST.has(word)) {
			return fail("invalid-sql", "IWEB_SQL_FILE_FUNCTION_DENIED", "arbitrary file path functions are denied");
		}
		if (word.startsWith("pragma_")) {
			return fail("invalid-sql", "IWEB_SQL_PRAGMA_FUNCTION_DENIED", "pragma table functions are denied");
		}
	}

	const parameterCount = countStatementParameters(body);
	if (parameterCount > limits.maxParameters) {
		return fail("limit-exceeded", "IWEB_SQL_PARAMETER_COUNT_EXCEEDED", "statement parameter count exceeds the profile maximum");
	}
	return { ok: true, value: { kind, parameterCount } };
}

export function validateIwebSqlStatement(statement: string, limits: IwebSqlLimits): IwebSqlCheck<IwebSqlStatementAnalysis> {
	const statementBytes = iwebUtf8ByteLength(statement);
	if (statementBytes === 0) {
		return { ok: false, error: sqlError("invalid-sql", "IWEB_SQL_EMPTY_STATEMENT", "statement must contain one SQL statement") };
	}
	if (statementBytes > limits.statementMaxBytes) {
		return { ok: false, error: sqlError("limit-exceeded", "IWEB_SQL_STATEMENT_BYTES_EXCEEDED", "statement exceeds the profile statement byte maximum") };
	}
	const outcome = tokenizeIwebSqlStatement(statement);
	if (!outcome.ok) return { ok: false, error: outcome.error };
	return analyzeIwebSqlTokens(outcome.tokens, limits);
}

// ---------------------------------------------------------------------------
// execute 请求 preflight：语句 + 参数形状 + 参数上限 + 计数匹配（全部在任何后端执行前）
// ---------------------------------------------------------------------------

export interface IwebSqlExecuteAnalysis extends IwebSqlStatementAnalysis {
	readonly parameterValues: readonly IwebSqlValue[];
	readonly parameterBytes: number;
}

export function validateIwebSqlExecuteRequest(statement: unknown, parameters: unknown, limits: IwebSqlLimits): IwebSqlCheck<IwebSqlExecuteAnalysis> {
	if (typeof statement !== "string") {
		return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_STATEMENT_TYPE_INVALID", "statement must be a string") };
	}
	const analysis = validateIwebSqlStatement(statement, limits);
	if (!analysis.ok) return analysis;

	if (!Array.isArray(parameters)) {
		return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETERS_TYPE_INVALID", "parameters must be an array") };
	}
	if (parameters.length > limits.maxParameters) {
		return { ok: false, error: sqlError("limit-exceeded", "IWEB_SQL_PARAMETER_COUNT_EXCEEDED", "bound parameter count exceeds the profile maximum") };
	}
	const values: IwebSqlValue[] = [];
	let parameterBytes = 0;
	for (const entry of parameters) {
		const parsed = parseIwebSqlParameter(entry);
		if (!parsed.ok) return parsed;
		values.push(parsed.value);
		parameterBytes += iwebSqlValueWireBytes(parsed.value);
		if (parameterBytes > limits.parameterMaxBytes) {
			return { ok: false, error: sqlError("limit-exceeded", "IWEB_SQL_PARAMETER_BYTES_EXCEEDED", "bound parameter bytes exceed the profile maximum") };
		}
	}
	if (values.length !== analysis.value.parameterCount) {
		return { ok: false, error: sqlError("invalid-parameter", "IWEB_SQL_PARAMETER_COUNT_MISMATCH", "bound parameter count must equal the statement placeholder count") };
	}
	return { ok: true, value: { ...analysis.value, parameterValues: values, parameterBytes } };
}

// ---------------------------------------------------------------------------
// result wire 校验：完整行集才允许送检（截断数据必须丢弃，绝不包装成截断成功）；
// 形状违规是宿主自产出错误 → case internal；行/字节/affected 超限 → limit-exceeded。
// ---------------------------------------------------------------------------

function resultWireInvalid(message: string): IwebSqlWireError {
	return sqlError("internal", "IWEB_SQL_RESULT_WIRE_INVALID", message);
}

export function validateIwebSqlResultWire(input: unknown, limits: IwebSqlLimits): IwebSqlCheck<IwebSqlResultWire> {
	if (!isRecord(input)) {
		return { ok: false, error: resultWireInvalid("result must be a record") };
	}
	for (const field of Object.keys(input)) {
		if (field !== "rows" && field !== "affected" && field !== "lastInsertId") {
			return { ok: false, error: resultWireInvalid("result carries an unknown field") };
		}
	}
	if (!Array.isArray(input.rows)) {
		return { ok: false, error: resultWireInvalid("rows must be an array") };
	}
	if (input.rows.length > limits.maxRows) {
		return { ok: false, error: sqlError("limit-exceeded", "IWEB_SQL_RESULT_ROWS_EXCEEDED", "result rows exceed the profile maximum") };
	}
	const rows: IwebSqlRow[] = [];
	let resultBytes = 0;
	for (const rowInput of input.rows) {
		if (!isRecord(rowInput) || Object.keys(rowInput).length !== 1 || rowInput.columns === undefined) {
			return { ok: false, error: resultWireInvalid("each row must carry only the columns field") };
		}
		if (!Array.isArray(rowInput.columns)) {
			return { ok: false, error: resultWireInvalid("row columns must be an array") };
		}
		const columns: IwebSqlColumn[] = [];
		for (const columnInput of rowInput.columns) {
			if (!isRecord(columnInput) || Object.keys(columnInput).length !== 2 || columnInput.name === undefined || columnInput.value === undefined) {
				return { ok: false, error: resultWireInvalid("each column must carry exactly name and value") };
			}
			const name = columnInput.name;
			if (typeof name !== "string" || name.length === 0 || hasLoneSurrogate(name) || iwebUtf8ByteLength(name) > IWEB_SQL_COLUMN_NAME_MAX_BYTES) {
				return { ok: false, error: resultWireInvalid("column name must be a non-empty bounded Unicode string") };
			}
			const value = parseIwebSqlValue(columnInput.value);
			if (!value.ok) {
				return { ok: false, error: resultWireInvalid("column value is not a valid SQL value") };
			}
			columns.push({ name, value: value.value });
			resultBytes += iwebUtf8ByteLength(name) + iwebSqlValueWireBytes(value.value);
			if (resultBytes > limits.resultMaxBytes) {
				return { ok: false, error: sqlError("limit-exceeded", "IWEB_SQL_RESULT_BYTES_EXCEEDED", "result bytes exceed the profile maximum") };
			}
		}
		rows.push({ columns });
	}
	const affected = input.affected;
	if (typeof affected !== "number" || !Number.isSafeInteger(affected) || affected < 0) {
		return { ok: false, error: resultWireInvalid("affected must be a non-negative safe integer") };
	}
	if (affected > limits.maxAffectedRows) {
		return { ok: false, error: sqlError("limit-exceeded", "IWEB_SQL_AFFECTED_ROWS_EXCEEDED", "affected rows exceed the profile maximum") };
	}
	const lastInsertId = input.lastInsertId;
	if (lastInsertId !== null && (typeof lastInsertId !== "number" || !Number.isSafeInteger(lastInsertId) || lastInsertId < 0)) {
		return { ok: false, error: resultWireInvalid("lastInsertId must be null or a non-negative safe integer") };
	}
	return { ok: true, value: { rows, affected, lastInsertId } };
}
