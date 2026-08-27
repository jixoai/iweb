// 用户原始需求（2026-08-27，add-wasm-host-services 契约层 schema+向量先行）：`iweb:kv@1.0.0` 的 WIT 身份、key/value grammar、
// mutation/快照 wire、共享配额写前判定与 cursor/tombstone 语义必须先于实现落地为可测纯契约
// （owner 已裁决 K1=包含有界 list、K2=单 key 线性化 CAS+tombstone、Q1=共享 storageBytes aggregate；L1/S1/H1 属其它批次）。
// 正交意图：WIT 包身份与方向法；key/value grammar 与 bound；单 key CAS/version 线性化语义；quota aggregate 写前原子拒绝；
// cursor 绑定/过期与有界分页；tombstone 保留窗口；mutation marker 与快照 wire 的 keys/values 精确键集 fail-closed 校验。
// 规范权威：openspec/changes/add-wasm-host-services/specs/wasm-host-kv/spec.md（配额两阶段契约见同 change design.md「Decisions 4/6」）。
// WIT 文本权威：./wit/iweb-kv.wit（tests/wasm-host-kv.test.ts 断言与 spec 代码块逐字一致）。
// 范围外：host-call frame/HostServicePolicyV2/IdentityV2（H1 批次）、SQL/logging（S1/L1 批次）、SQLite/ledger 实现（supervisor/wasmd）。
// fail-closed 裁决（spec 未逐字规定处，均已注释标注并在子代理报告中上报）：
//   1) 版本 wire 上界取 Number.MAX_SAFE_INTEGER（JCS 数为 IEEE double 的安全 u64 子集），达到即 unavailable，绝不回绕；
//   2) list 首个候选 item 单独超过 maxListBytes 时返回 limit-exceeded，杜绝「空页+游标」死循环；
//   3) 跨 scope cursor 固定映射 invalid-key（spec 允许 invalid-key/limit-exceeded 稳定集，不做运行时选择）。
import { Buffer } from "node:buffer";
import { failure, isRecord, issue, ok, SHA256_PATTERN, type ValidationIssue, type ValidationResult } from "./validation.ts";
import { WASM_UUIDV7_PATTERN } from "./wasm-execution.ts";

// ---------------------------------------------------------------------------
// key/value grammar 与 bound（spec「KV operations have bounded single-key linearization」）
// ---------------------------------------------------------------------------

export const IWEB_KV_KEY_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
export const IWEB_KV_KEY_MAX_BYTES = 128;
export const IWEB_KV_VALUE_MAX_BYTES = 65536;

// grammar 限定为小写 ASCII：字符数即 UTF-8 字节数（1..128），天然排除 slash、whitespace、
// colon、NUL、非规范化 UTF-8 与大小写变体（"a second encoding" 不存在）。
export function isValidIwebKvKey(key: string): boolean {
	return typeof key === "string" && IWEB_KV_KEY_PATTERN.test(key);
}

// value 是 WIT list<u8>：raw bytes 0..65536（先于任何分配校验）。
export function isValidIwebKvValueBytes(value: Uint8Array): boolean {
	return value instanceof Uint8Array && value.byteLength <= IWEB_KV_VALUE_MAX_BYTES;
}

// wire（JSON 投影）中的 value 是 unpadded、canonical 的 base64url 字符串：
// 禁止 padding、非 url 字母表、长度 mod 4 == 1 与 alternate encoding（round-trip 必须逐字相等）。
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export function decodeIwebKvValueWire(value: string): Uint8Array | null {
	if (typeof value !== "string") return null;
	if (value.length === 0) return new Uint8Array(0);
	if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return null;
	const bytes = Buffer.from(value, "base64url");
	if (bytes.toString("base64url") !== value) return null; // canonical 检查：同一字节串只有一种合法编码
	return new Uint8Array(bytes);
}

export function isValidIwebKvValueWire(value: string): boolean {
	const bytes = decodeIwebKvValueWire(value);
	return bytes !== null && bytes.byteLength <= IWEB_KV_VALUE_MAX_BYTES;
}

// list 的 prefix：非空且完整落在 key grammar 内（spec「a non-empty prefix within the key grammar」）。
export function isValidIwebKvPrefix(prefix: string): boolean {
	return isValidIwebKvKey(prefix);
}

// 结果按 raw UTF-8 key 字节排序；ASCII grammar 下与 code-unit 序一致，仍以字节比较为准（与仓库既有 sort 口径相同）。
export function compareIwebKvKeys(left: string, right: string): number {
	return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

// ---------------------------------------------------------------------------
// WIT 包/接口身份与方向法（import store 是唯一合法方向）
// ---------------------------------------------------------------------------

export const IWEB_KV_WIT_PACKAGE = "iweb:kv@1.0.0";
export const IWEB_KV_WIT_WORLD = "kv";
export const IWEB_KV_STORE_INTERFACE = "store";
export const IWEB_KV_WIT_DIRECTION_ERROR_CODE = "IWEB_KV_WIT_DIRECTION_INVALID";

// world/component 只能 import store；export store 一律在 OCI 物化前拒绝（spec「KV import direction or revision is wrong」）。
export function iwebKvWitDirectionErrorCode(id: { readonly package: string; readonly interface: string; readonly direction: string }): string | null {
	if (id.direction !== "export" || id.interface !== IWEB_KV_STORE_INTERFACE) return null;
	if (id.package === IWEB_KV_WIT_PACKAGE) return IWEB_KV_WIT_DIRECTION_ERROR_CODE;
	return null;
}

// ---------------------------------------------------------------------------
// WIT 调用错误 variant ↔ wire 错误码（closed set，不回显 key/value/payload）
// ---------------------------------------------------------------------------

export const IWEB_KV_WIT_ERROR_CASES = [
	"invalid-key",
	"not-found",
	"conflict",
	"quota-exceeded",
	"limit-exceeded",
	"cursor-expired",
	"unavailable",
	"internal",
] as const;
export type IwebKvWitErrorCase = (typeof IWEB_KV_WIT_ERROR_CASES)[number];

export const IWEB_KV_WIRE_ERROR_BY_CASE: Readonly<Record<IwebKvWitErrorCase, string>> = {
	"invalid-key": "IWEB_KV_INVALID_KEY",
	"not-found": "IWEB_KV_NOT_FOUND",
	conflict: "IWEB_KV_CONFLICT",
	"quota-exceeded": "IWEB_KV_QUOTA_EXCEEDED",
	"limit-exceeded": "IWEB_KV_LIMIT_EXCEEDED",
	"cursor-expired": "IWEB_KV_CURSOR_EXPIRED",
	unavailable: "IWEB_KV_UNAVAILABLE",
	internal: "IWEB_KV_INTERNAL",
};

// 跨 scope cursor 的稳定错误集：spec 允许 invalid-key/limit-exceeded；契约固定取 invalid-key（裁决 3），
// 两种都不泄露匹配 key 或计数；过期/快照被回收固定为 cursor-expired。
export const IWEB_KV_CURSOR_SCOPE_ALLOWED_ERROR_CASES = ["invalid-key", "limit-exceeded"] as const;
export const IWEB_KV_CURSOR_SCOPE_ERROR_CASE = "invalid-key" as const;
export const IWEB_KV_CURSOR_EXPIRED_ERROR_CASE = "cursor-expired" as const;

// ---------------------------------------------------------------------------
// 单 key 线性化 CAS + version 分配（K2）
// ---------------------------------------------------------------------------

// u64 wire 安全子集上界：JCS/JSON 数是 IEEE double，契约层以 2^53-1 封顶（裁决 1）；
// 达到上界即 exhausted -> unavailable（spec「Version counters never wrap; exhaustion returns unavailable」）。
export const IWEB_KV_VERSION_MAX = Number.MAX_SAFE_INTEGER;

function isIwebKvVersion(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= IWEB_KV_VERSION_MAX;
}

export type IwebKvCasDecision =
	| { readonly status: "committed"; readonly version: number }
	| { readonly status: "conflict" }
	| { readonly status: "unavailable" };

// 单 key CAS 线性化决策（宿主已对同一 key 串行化后调用）：
//   expected === null            -> 无条件 mutation（key 不存在也可创建）；
//   expected === current.version -> 提交；
//   其他（含 key 不存在但 expected 非 null）-> conflict。
// tombstone 与值共享同一条 CAS 线：delete 提交更高版本的 tombstone 后，任何携带旧 expected 的
// stale writer 必然 mismatch -> conflict（「Delete prevents stale resurrection」）；
// expected === null 的重新创建合法（tombstone 只阻断 stale writer，不阻断无条件写）。
// 计数器损坏/耗尽/非严格递增 -> unavailable（fail-closed，绝不回绕提交）。
export function applyIwebKvCas(input: {
	readonly current: { readonly version: number } | null;
	readonly expected: number | null;
	readonly nextVersion: number;
}): IwebKvCasDecision {
	if (input.current !== null && !isIwebKvVersion(input.current.version)) return { status: "unavailable" };
	if (input.expected !== null && !isIwebKvVersion(input.expected)) return { status: "unavailable" };
	if (!isIwebKvVersion(input.nextVersion)) return { status: "unavailable" };

	if (input.current === null) {
		if (input.expected !== null) return { status: "conflict" }; // 期待已存在版本，但 key 从未存在
	} else if (input.expected !== null && input.expected !== input.current.version) {
		return { status: "conflict" };
	}

	const currentVersion = input.current === null ? 0 : input.current.version;
	if (currentVersion === IWEB_KV_VERSION_MAX) return { status: "unavailable" }; // exhaustion
	if (input.nextVersion <= currentVersion) return { status: "unavailable" }; // 必须严格更大（含回绕）
	return { status: "committed", version: input.nextVersion };
}

// ---------------------------------------------------------------------------
// 共享配额 ledger 写前判定（Q1：KV+SQL 共用 resources.storageBytes aggregate）
// ---------------------------------------------------------------------------

export type IwebKvQuotaDecision =
	| { readonly status: "allowed"; readonly projectedBytes: number }
	| { readonly status: "quota-exceeded" };

function isNonNegativeSafeInteger(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

// spec/design 的原子写前不等式：committedBytes + outstandingReservedBytes + delta <= aggregateEnvelope，
// 且（提供 KV service cap 三元组时）kvCommittedBytes + kvOutstandingReservedBytes + delta <= kvServiceCapBytes。
// 任何输入不可证明（非负 safe integer 缺一即坏、cap 三元组不齐）-> quota-exceeded：
// 「an over-limit or unprovable reservation changes no key, tombstone, SQL data or controlRevision」。
export function checkIwebKvWriteQuota(input: {
	readonly committedBytes: number;
	readonly outstandingReservedBytes: number;
	readonly reservedDeltaBytes: number;
	readonly aggregateEnvelopeBytes: number;
	readonly kvCommittedBytes?: number;
	readonly kvOutstandingReservedBytes?: number;
	readonly kvServiceCapBytes?: number;
}): IwebKvQuotaDecision {
	const serviceCapPresent =
		input.kvCommittedBytes !== undefined || input.kvOutstandingReservedBytes !== undefined || input.kvServiceCapBytes !== undefined;
	if (
		!isNonNegativeSafeInteger(input.committedBytes) ||
		!isNonNegativeSafeInteger(input.outstandingReservedBytes) ||
		!isNonNegativeSafeInteger(input.reservedDeltaBytes) ||
		!isNonNegativeSafeInteger(input.aggregateEnvelopeBytes)
	) {
		return { status: "quota-exceeded" };
	}
	if (
		serviceCapPresent &&
		(input.kvCommittedBytes === undefined ||
			input.kvOutstandingReservedBytes === undefined ||
			input.kvServiceCapBytes === undefined ||
			!isNonNegativeSafeInteger(input.kvCommittedBytes) ||
			!isNonNegativeSafeInteger(input.kvOutstandingReservedBytes) ||
			!isNonNegativeSafeInteger(input.kvServiceCapBytes))
	) {
		return { status: "quota-exceeded" };
	}

	const projected = input.committedBytes + input.outstandingReservedBytes + input.reservedDeltaBytes;
	if (projected > input.aggregateEnvelopeBytes) return { status: "quota-exceeded" };
	if (serviceCapPresent) {
		const serviceProjected = input.kvCommittedBytes! + input.kvOutstandingReservedBytes! + input.reservedDeltaBytes;
		if (serviceProjected > input.kvServiceCapBytes!) return { status: "quota-exceeded" };
	}
	return { status: "allowed", projectedBytes: projected };
}

// reservedDeltaBytes 的保守上界公式（在触碰任何后端之前计算）：
// delta = keyBytes + valueBytes + entryOverheadBytes，entryOverheadBytes 是 profile 派生的每条目记账上界
// （必须覆盖版本/元数据/tombstone 字段与 marker 记账；delete 传 valueBytes=0，tombstone 记账由 overhead 覆盖）。
// 结果不是有限 safe integer -> null：宿主必须写前拒绝（quota-exceeded），不得猜测更小的界。
export function iwebKvConservativeReservedDeltaBytes(input: {
	readonly keyBytes: number;
	readonly valueBytes: number;
	readonly entryOverheadBytes: number;
}): number | null {
	if (!isNonNegativeSafeInteger(input.keyBytes) || !isNonNegativeSafeInteger(input.valueBytes) || !isNonNegativeSafeInteger(input.entryOverheadBytes)) {
		return null;
	}
	const delta = input.keyBytes + input.valueBytes + input.entryOverheadBytes;
	return Number.isSafeInteger(delta) ? delta : null;
}

// ---------------------------------------------------------------------------
// cursor 绑定/过期（K1：bounded, scoped and expiring）
// ---------------------------------------------------------------------------

// cursor 是宿主签发的 opaque token；其被认证 payload 恰好绑定以下字段（spec 逐字列表），
// 不含任何 caller 可选的 path 或 namespace。
export interface IwebKvCursorBindingV1 {
	readonly applicationId: string;
	readonly hostServicePolicyDigest: string;
	readonly prefix: string;
	readonly snapshotToken: string;
	readonly lastKey: string;
	readonly expiresAtMs: number;
}

export type IwebKvCursorDecision =
	| { readonly status: "valid" }
	| { readonly status: "invalid-scope" }
	| { readonly status: "expired" };

// 校验顺序固定：先 scope（app/policy/prefix/snapshotToken 之一不符、或 cursor 自身形态伪造 -> invalid-scope，
// 稳定映射 invalid-key，先于任何扫描、不泄露匹配 key/计数），后 expiry（token 过期或快照被回收 -> cursor-expired，
// 绝不从开头重启）。nowMs >= expiresAtMs 即过期（边界含等号，fail-closed）。
export function checkIwebKvCursor(input: {
	readonly cursor: IwebKvCursorBindingV1;
	readonly applicationId: string;
	readonly hostServicePolicyDigest: string;
	readonly prefix: string;
	readonly snapshotToken: string;
	readonly snapshotAlive: boolean;
	readonly nowMs: number;
}): IwebKvCursorDecision {
	const cursor = input.cursor;
	const cursorWellFormed =
		typeof cursor === "object" &&
		cursor !== null &&
		typeof cursor.applicationId === "string" &&
		SHA256_PATTERN.test(cursor.hostServicePolicyDigest) &&
		isValidIwebKvPrefix(cursor.prefix) &&
		typeof cursor.snapshotToken === "string" &&
		cursor.snapshotToken.length > 0 &&
		isValidIwebKvKey(cursor.lastKey) &&
		Number.isSafeInteger(cursor.expiresAtMs);
	if (!cursorWellFormed) return { status: "invalid-scope" };
	if (
		cursor.applicationId !== input.applicationId ||
		cursor.hostServicePolicyDigest !== input.hostServicePolicyDigest ||
		cursor.prefix !== input.prefix ||
		cursor.snapshotToken !== input.snapshotToken
	) {
		return { status: "invalid-scope" };
	}
	if (!input.snapshotAlive || input.nowMs >= cursor.expiresAtMs) return { status: "expired" };
	return { status: "valid" };
}

// ---------------------------------------------------------------------------
// 有界 list 分页（K1：limit 1..min(256, profile.maxListItems)，结果 bounded by profile.maxListBytes）
// ---------------------------------------------------------------------------

export const IWEB_KV_LIST_LIMIT_MAX = 256;

// limit 天花板：min(256, profile.maxListItems)；profile 非法（<1 或非 safe integer）-> 0（一切 limit 拒绝，fail-closed）。
export function iwebKvListLimitCeiling(profileMaxListItems: number): number {
	if (!Number.isSafeInteger(profileMaxListItems) || profileMaxListItems < 1) return 0;
	return Math.min(IWEB_KV_LIST_LIMIT_MAX, profileMaxListItems);
}

export function isValidIwebKvListLimit(limit: number, profileMaxListItems: number): boolean {
	if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit < 1) return false;
	const ceiling = iwebKvListLimitCeiling(profileMaxListItems);
	return ceiling >= 1 && limit <= ceiling;
}

export interface IwebKvListEntry {
	readonly key: string;
	readonly value: Uint8Array;
}

export type IwebKvListPagePlan =
	| { readonly status: "ok"; readonly items: readonly IwebKvListEntry[]; readonly nextLastKey: string | null }
	| { readonly status: "limit-exceeded" };

// 单页规划（纯函数）：
//   - tombstoneKeys 遮蔽的 key 永不枚举（「Tombstones are skipped」）；
//   - 只保留 prefix 匹配（非空 key grammar 内）且 raw UTF-8 字节序 > afterKey 的可见条目；
//   - 条目数 <= limit（调用方已校验 limit <= min(256, profile)），页字节（Σ key+value 字节）<= maxListBytes，
//     宿主可为守字节返回少于 limit 条；
//   - 首个候选 item 单独超过 maxListBytes -> limit-exceeded（裁决 2：杜绝空页+游标死循环）；
//   - nextLastKey 仅在还存在更多可见匹配时非空。
// 输入畸形（prefix/afterKey 越界 grammar、条目 key/value 越界、重复 key、参数非法）-> limit-exceeded
//（fail-closed：后端损坏宁可拒绝枚举，绝不静默过滤后继续）。
export function planIwebKvListPage(input: {
	readonly entries: readonly IwebKvListEntry[];
	readonly tombstoneKeys?: readonly string[];
	readonly prefix: string;
	readonly afterKey: string | null;
	readonly limit: number;
	readonly profileMaxListItems: number;
	readonly maxListBytes: number;
}): IwebKvListPagePlan {
	if (!isValidIwebKvPrefix(input.prefix)) return { status: "limit-exceeded" };
	if (input.afterKey !== null && !isValidIwebKvKey(input.afterKey)) return { status: "limit-exceeded" };
	if (!Number.isSafeInteger(input.maxListBytes) || input.maxListBytes < 1) return { status: "limit-exceeded" };
	const ceiling = iwebKvListLimitCeiling(input.profileMaxListItems);
	if (ceiling < 1 || input.limit < 1 || input.limit > ceiling) return { status: "limit-exceeded" };

	const tombstones = new Set<string>();
	for (const key of input.tombstoneKeys ?? []) {
		if (!isValidIwebKvKey(key)) return { status: "limit-exceeded" };
		tombstones.add(key);
	}

	const visible: { key: string; keyBytes: number; value: Uint8Array; valueBytes: number }[] = [];
	for (const entry of input.entries) {
		if (!isValidIwebKvKey(entry.key) || !isValidIwebKvValueBytes(entry.value)) return { status: "limit-exceeded" }; // 后端损坏
		if (tombstones.has(entry.key)) continue;
		if (!entry.key.startsWith(input.prefix)) continue;
		visible.push({ key: entry.key, keyBytes: Buffer.byteLength(entry.key, "utf8"), value: entry.value, valueBytes: entry.value.byteLength });
	}
	visible.sort((left, right) => compareIwebKvKeys(left.key, right.key));
	for (let i = 1; i < visible.length; i++) {
		if (visible[i - 1]!.key === visible[i]!.key) return { status: "limit-exceeded" }; // 后端损坏：同 key 双条目
	}

	const afterKey = input.afterKey;
	const candidates = visible.filter((entry) => (afterKey === null ? true : compareIwebKvKeys(entry.key, afterKey) > 0));

	const items: IwebKvListEntry[] = [];
	let pageBytes = 0;
	for (const entry of candidates) {
		if (items.length >= input.limit) break;
		const entryBytes = entry.keyBytes + entry.valueBytes;
		if (pageBytes + entryBytes > input.maxListBytes) {
			if (items.length === 0) return { status: "limit-exceeded" }; // 裁决 2
			break; // 「Page hits the byte cap」：返回先前有界页 + 续游标
		}
		items.push({ key: entry.key, value: entry.value });
		pageBytes += entryBytes;
	}

	// next-cursor 仅当还有更多可见匹配（未被 limit/bytes 纳入的剩余条目存在）。
	const hasMore = candidates.length > items.length && items.length > 0;
	const nextLastKey = hasMore ? items[items.length - 1]!.key : null;
	return { status: "ok", items, nextLastKey };
}

// ---------------------------------------------------------------------------
// tombstone 保留窗口（「retained for at least the maximum cursor TTL plus the host-call replay TTL」）
// ---------------------------------------------------------------------------

// 保留下限 = 最大 cursor TTL + host-call replay TTL；非法 TTL -> null（无限保留，fail-closed）。
export function iwebKvTombstoneRetentionFloorMs(maxCursorTtlMs: number, hostCallReplayTtlMs: number): number | null {
	if (!isNonNegativeSafeInteger(maxCursorTtlMs) || !isNonNegativeSafeInteger(hostCallReplayTtlMs)) return null;
	const floor = maxCursorTtlMs + hostCallReplayTtlMs;
	return Number.isSafeInteger(floor) ? floor : null;
}

// GC 仅当（1）宿主能证明没有活跃 cursor/replay 可引用该版本（noActiveReferenceProof），
// 且（2）now - deletedAt >= 最大 cursor TTL + replay TTL。证明不可得或时钟回拨 -> 保留并计入配额。
export function isIwebKvTombstoneCollectable(input: {
	readonly deletedAtMs: number;
	readonly nowMs: number;
	readonly maxCursorTtlMs: number;
	readonly hostCallReplayTtlMs: number;
	readonly noActiveReferenceProof: boolean;
}): boolean {
	if (!input.noActiveReferenceProof) return false;
	if (!isNonNegativeSafeInteger(input.deletedAtMs) || !isNonNegativeSafeInteger(input.nowMs)) return false;
	const floor = iwebKvTombstoneRetentionFloorMs(input.maxCursorTtlMs, input.hostCallReplayTtlMs);
	if (floor === null) return false;
	return input.nowMs - input.deletedAtMs >= floor;
}

// ---------------------------------------------------------------------------
// mutation marker wire（后端幂等 marker 的 JSON 投影；spec「The backend marker includes the
// operationId, reservationId and reservation proof」，重放返回原始 version）
// ---------------------------------------------------------------------------

export interface IwebKvMutationMarkerV1 {
	readonly schemaVersion: 1;
	readonly method: "set" | "delete";
	readonly key: string;
	readonly expectedVersion: number | null;
	readonly assignedVersion: number;
	readonly operationId: string;
	readonly reservationId: string;
	readonly reservationProofDigest: string;
}

const IWEB_KV_MARKER_FIELDS = ["schemaVersion", "method", "key", "expectedVersion", "assignedVersion", "operationId", "reservationId", "reservationProofDigest"] as const;

export function validateIwebKvMutationMarker(input: unknown): ValidationResult<IwebKvMutationMarkerV1> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "kv mutation marker must be an object")]);
	const errors: ValidationIssue[] = [];

	for (const field of Object.keys(input)) {
		if (!(IWEB_KV_MARKER_FIELDS as readonly string[]).includes(field)) {
			errors.push(issue("UNKNOWN_FIELD", "/" + field, "unknown field is not allowed"));
		}
	}
	if (input.schemaVersion !== 1) {
		errors.push(issue("INVALID_SCHEMA_VERSION", "/schemaVersion", "schemaVersion must be the literal 1"));
	}
	if (input.method !== "set" && input.method !== "delete") {
		errors.push(issue("INVALID_METHOD", "/method", "method must be set or delete"));
	}
	if (typeof input.key !== "string" || !isValidIwebKvKey(input.key)) {
		errors.push(issue("INVALID_KEY", "/key", "key must match ^[a-z][a-z0-9._-]{0,127}$"));
	}
	if (input.expectedVersion !== null && !isIwebKvVersion(input.expectedVersion)) {
		errors.push(issue("INVALID_NUMBER", "/expectedVersion", "expectedVersion must be null or a version in 1.." + IWEB_KV_VERSION_MAX));
	}
	if (!isIwebKvVersion(input.assignedVersion)) {
		errors.push(issue("INVALID_NUMBER", "/assignedVersion", "assignedVersion must be a version in 1.." + IWEB_KV_VERSION_MAX));
	} else if (isIwebKvVersion(input.expectedVersion) && input.assignedVersion <= input.expectedVersion) {
		// marker 记录的是已提交事实：成功提交的版本必须严格大于其 CAS 期待值（无条件写与 expectedVersion:null 一致时只查 >=1）。
		errors.push(issue("VERSION_NOT_INCREASING", "/assignedVersion", "assignedVersion must be strictly greater than expectedVersion"));
	}
	if (typeof input.operationId !== "string" || !WASM_UUIDV7_PATTERN.test(input.operationId)) {
		errors.push(issue("INVALID_IDENTIFIER", "/operationId", "operationId must be a lower-case UUIDv7"));
	}
	if (typeof input.reservationId !== "string" || !WASM_UUIDV7_PATTERN.test(input.reservationId)) {
		errors.push(issue("INVALID_IDENTIFIER", "/reservationId", "reservationId must be a lower-case UUIDv7"));
	}
	if (typeof input.reservationProofDigest !== "string" || !SHA256_PATTERN.test(input.reservationProofDigest)) {
		errors.push(issue("INVALID_DIGEST", "/reservationProofDigest", "reservationProofDigest must be a 64-character lowercase hex digest"));
	}

	if (errors.length) return failure(errors);
	return ok({
		schemaVersion: 1,
		method: input.method as "set" | "delete",
		key: input.key as string,
		expectedVersion: input.expectedVersion as number | null,
		assignedVersion: input.assignedVersion as number,
		operationId: input.operationId as string,
		reservationId: input.reservationId as string,
		reservationProofDigest: input.reservationProofDigest as string,
	});
}

// ---------------------------------------------------------------------------
// 快照 wire（备份/恢复 quiesce 快照与契约向量的规范化形态；keys/values/versions 精确键集）
// ---------------------------------------------------------------------------

export interface IwebKvSnapshotV1 {
	readonly schemaVersion: 1;
	readonly keys: readonly string[];
	readonly values: Readonly<Record<string, string>>;
	readonly versions: Readonly<Record<string, number>>;
}

const IWEB_KV_SNAPSHOT_FIELDS = ["schemaVersion", "keys", "values", "versions"] as const;

export function validateIwebKvSnapshot(input: unknown): ValidationResult<IwebKvSnapshotV1> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "kv snapshot must be an object")]);
	const errors: ValidationIssue[] = [];

	for (const field of Object.keys(input)) {
		if (!(IWEB_KV_SNAPSHOT_FIELDS as readonly string[]).includes(field)) {
			errors.push(issue("UNKNOWN_FIELD", "/" + field, "unknown field is not allowed"));
		}
	}
	if (input.schemaVersion !== 1) {
		errors.push(issue("INVALID_SCHEMA_VERSION", "/schemaVersion", "schemaVersion must be the literal 1"));
	}

	const keys: string[] = [];
	let keysValid = true;
	if (!Array.isArray(input.keys)) {
		errors.push(issue("TYPE_ARRAY", "/keys", "keys must be an array"));
		keysValid = false;
	} else {
		for (let i = 0; i < input.keys.length; i++) {
			const key = input.keys[i];
			if (typeof key !== "string" || !isValidIwebKvKey(key)) {
				errors.push(issue("INVALID_KEY", "/keys/" + i, "key must match ^[a-z][a-z0-9._-]{0,127}$"));
				keysValid = false;
				continue;
			}
			keys.push(key);
		}
		if (keysValid) {
			for (let i = 1; i < keys.length; i++) {
				// ASCII grammar 下 code-unit 序即 raw UTF-8 bytewise 序。
				if (keys[i - 1] === keys[i]) errors.push(issue("DUPLICATE_KEY", "/keys", "keys must be unique"));
				else if (compareIwebKvKeys(keys[i - 1]!, keys[i]!) > 0) errors.push(issue("UNSORTED_KEYS", "/keys", "keys must be sorted in UTF-8 byte order"));
			}
		}
	}

	// values：key -> canonical unpadded base64url（解码后 0..65536 字节）。
	let valuesKeys: readonly string[] | null = null;
	if (!isRecord(input.values)) {
		errors.push(issue("TYPE_OBJECT", "/values", "values must be an object"));
	} else {
		valuesKeys = Object.keys(input.values);
		for (const key of valuesKeys) {
			const value = input.values[key];
			if (typeof value !== "string" || !isValidIwebKvValueWire(value)) {
				errors.push(issue("INVALID_VALUE", "/values/" + key, "value must be canonical unpadded base64url decoding to at most 65536 bytes"));
			}
		}
	}

	// versions：key -> [1, IWEB_KV_VERSION_MAX]。
	let versionsKeys: readonly string[] | null = null;
	if (!isRecord(input.versions)) {
		errors.push(issue("TYPE_OBJECT", "/versions", "versions must be an object"));
	} else {
		versionsKeys = Object.keys(input.versions);
		for (const key of versionsKeys) {
			if (!isIwebKvVersion(input.versions[key])) {
				errors.push(issue("INVALID_NUMBER", "/versions/" + key, "version must be an integer in 1.." + IWEB_KV_VERSION_MAX));
			}
		}
	}

	if (keysValid) {
		// keys/values/versions 三向键集 byte-for-byte 相等：无 missing、无 extra、无 prototype-like key
		//（grammar 决定 __proto__/constructor 之类不可能出现在 keys 内，extra 检查即兜底）。
		const keySet = new Set(keys);
		for (const key of valuesKeys ?? []) {
			if (!keySet.has(key)) errors.push(issue("KEYS_VALUES_MISMATCH", "/values/" + key, "values key is not present in keys"));
		}
		for (const key of versionsKeys ?? []) {
			if (!keySet.has(key)) errors.push(issue("KEYS_VALUES_MISMATCH", "/versions/" + key, "versions key is not present in keys"));
		}
		for (const key of keys) {
			if (valuesKeys === null || !valuesKeys.includes(key)) {
				errors.push(issue("KEYS_VALUES_MISMATCH", "/values/" + key, "keys entry is missing from values"));
			}
			if (versionsKeys === null || !versionsKeys.includes(key)) {
				errors.push(issue("KEYS_VALUES_MISMATCH", "/versions/" + key, "keys entry is missing from versions"));
			}
		}
	}

	if (errors.length) return failure(errors);
	return ok({ schemaVersion: 1, keys, values: input.values as Record<string, string>, versions: input.versions as Record<string, number> });
}
