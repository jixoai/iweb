// 用户原始需求（2026-08-27，add-wasm-host-services Kernel 数据面权威批次）：HostServicePolicyV2、
// Capability record revision 2 增量形状与三服务（kv/sql/logging）policy/profile 上限数值需要唯一权威来源，
// SQL 契约的占位 limits（IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS）在此获得权威锚点；hash domain 逐字对齐 design.md
// 「Decisions 1」（digestV2 = SHA-256(ASCII(domain) || 0x00 || payloadBytes)，绝不二次 hash 十六进制文本）。
// 正交意图：（1）digestV2 原语与 16 个 V2 domain 常量表；（2）HostServicePolicyPayloadV2/V2 精确键集校验与 policyDigest；
// （3）三服务 limits/maxima 权威数值与 profile/consistency/durability/retention closed set；
// （4）Capability matrix/record revision 2 增量（三个新 import + hostServiceMaxima + iweb-wasm-capability-record-v2 hash）；
// （5）HostServiceIdentityV2 形状、versionDigest（iweb-wasm-host-identity-v2）与 guestMemoryBytes reserve 公式。
// 规范权威：openspec/changes/add-wasm-host-services/design.md「Decisions 1/2/3」与
// specs/wasm-application-runtime/spec.md「Host-service V2 identity is exact and immutable」「Resource, directory...」。
// 复用约束：JCS/sha256Hex/文法一律复用 wasm-package.ts；rev-1 矩阵复用 wasm-capability.ts；SQL limits 形状复用
// wasm-host-sql.ts（type-only）；本文件不建第二套编码实现。
// fail-closed 裁决（spec 未逐字规定处，均已注释标注并在子代理报告中上报）：
//   1) hostServices 成员的 profile/consistency/durability/retention 内层字面量：design 只固定五键形状
//      {profile,limits,consistency,durability,retention}，未列举内层值域；本文件按已批准的 K1/K2/S1/S2/L1
//      提出唯一字面量（见各 closed set），owner 冻结（任务 1.1-1.4/3.1）前不允许第二取值；
//   2) kv/logging 的 limits 键集与数值上限（maxListBytes/cursorTtlMs/entryOverheadBytes、ring 容量上限）：
//      logging 直接采用 wasm-host-logging.ts 已冻结的 *_CEILING；kv 的 maxListItems 上限采用 IWEB_KV_LIST_LIMIT_MAX=256，
//      其余为契约层提案值；
//   3) 节点 maxima（WASM_HOST_SERVICE_NODE_MAXIMA）是「capability record 内 maxima 字段的硬天花板」：
//      record maxima <= 本表，selected profile limits <= record maxima；
//   4) 全 null hostServices 的 policy 拒绝（无任一新 import 的版本是 V1 版本，不构造 V2 policy）；
//   5) capability record revision 2 的完整合并 record（rev-1 NodeCapabilityRecordV1 的 runtimes 等包裹字段）
//      属任务 3.1 批次；本文件只定义增量形状（matrixRevision/hostAbi/hostImports/hostServiceMaxima）与
//      iweb-wasm-capability-record-v2 hash 权威，不改 wasm-catalog.ts。
import { failure, isRecord, issue, ok, rejectUnknownFields, type ValidationIssue, type ValidationResult } from "./validation.ts";
import { IWEB_KV_LIST_LIMIT_MAX } from "./wasm-host-kv.ts";
import { IWEB_LOG_EVENT_MAX_BYTES_CEILING, IWEB_LOG_RING_MAX_BYTES_CEILING, IWEB_LOG_RING_MAX_EVENTS_CEILING } from "./wasm-host-logging.ts";
import { IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS, type IwebSqlLimits } from "./wasm-host-sql.ts";
import {
	jcsCanonicalBytes,
	sha256Hex,
	WASM_APPLICATION_ID_PATTERN,
	WASM_SHA256_HEX_PATTERN,
	WASM_U53_MAX,
	WASM_VERSION_ID_PATTERN,
	WASM_WORLD_LITERAL,
	type WasmImportCapability,
} from "./wasm-package.ts";
import { WASM_CAPABILITY_MATRIX_REVISION_1, sortWasmCapabilityIds, type WasmCapabilityId } from "./wasm-capability.ts";

// ---------------------------------------------------------------------------
// digestV2 原语与 V2 hash domain 常量表（design.md「Decisions 1」逐字）
// ---------------------------------------------------------------------------

/** design.md 列出的全部 V2 hash domain（ASCII literal，不带换行）；domain 混用即 fail-closed。 */
export const WASM_DIGEST_V2_DOMAINS = [
	"iweb-wasm-host-policy-v2",
	"iweb-wasm-host-identity-v2",
	"iweb-wasm-capability-record-v2",
	"iweb-wasm-acceptance-record-v3",
	"iweb-wasm-admission-proof-v2",
	"iweb-wasm-catalog-binding-v2",
	"iweb-wasm-control-state-v2",
	"iweb-wasm-execution-command-v2",
	"iweb-wasm-execution-ack-v2",
	"iweb-wasm-readiness-v2",
	"iweb-wasm-metrics-v2",
	"iweb-wasm-activation-v2",
	"iweb-wasm-route-event-v2",
	"iweb-wasm-rollback-v2",
	"iweb-wasm-host-call-v2",
	"iweb-wasm-quota-reservation-v2",
] as const;
export type WasmDigestV2Domain = (typeof WASM_DIGEST_V2_DOMAINS)[number];

export const WASM_HOST_POLICY_DIGEST_DOMAIN = "iweb-wasm-host-policy-v2" as const;
export const WASM_HOST_IDENTITY_DIGEST_DOMAIN = "iweb-wasm-host-identity-v2" as const;
export const WASM_CAPABILITY_RECORD_HASH_DOMAIN_V2 = "iweb-wasm-capability-record-v2" as const;
export const WASM_QUOTA_RESERVATION_DIGEST_DOMAIN = "iweb-wasm-quota-reservation-v2" as const;

// digestV2(domain,payloadBytes) = SHA-256(ASCII(domain) || 0x00 || payloadBytes)：
// domain 必须是上表中的精确 ASCII literal（防 domain 混用/拼错）；payload 是原始 JCS 字节，
// 绝不传入 hex 文本二次摘要。分隔符是 0x00（V2），与 V1 系 "\n" 域摘要互不兼容、互不解释。
export function digestV2(domain: WasmDigestV2Domain, payloadBytes: Uint8Array): string {
	const domainBytes = new TextEncoder().encode(domain);
	const framed = new Uint8Array(domainBytes.length + 1 + payloadBytes.byteLength);
	framed.set(domainBytes, 0);
	framed[domainBytes.length] = 0x00;
	framed.set(payloadBytes, domainBytes.length + 1);
	// 复用 wasm-package.ts 的 sha256Hex（同一 node:crypto 单次 SHA-256 hex 权威）。
	return sha256Hex(framed);
}

// ---------------------------------------------------------------------------
// V2 字面量（schemaVersion/matrixRevision/hostAbi/目录与 durability profile）
// ---------------------------------------------------------------------------

export const WASM_HOST_SERVICE_SCHEMA_VERSION = 2;
export const WASM_CAPABILITY_MATRIX_REVISION_2 = 2;
/** V2（service-enabled）host ABI；V1 保持 iweb-wasmd-abi@1.0.0，二者不可互相解释。 */
export const WASM_HOST_ABI_LITERAL_V2 = "iweb-wasmd-abi@1.1.0" as const;
export const WASM_HOST_DATA_DIRECTORY_PROFILE = "per-app-sqlite-v1" as const;
export const WASM_HOST_DURABILITY_PROFILE = "sqlite-full-fsync-v1" as const;

// ---------------------------------------------------------------------------
// 三服务 limits 形状与权威数值（SQL 占位 limits 的权威锚点）
// ---------------------------------------------------------------------------

export type WasmHostServiceKind = "kv" | "sql" | "logging";

export interface IwebKvServiceLimits {
	/** 单页 item 数上限（调用侧另受 min(256, maxListItems) 约束；spec「KV list cursors are bounded」）。 */
	readonly maxListItems: number;
	/** 单页（Σ key+value 字节）上限。 */
	readonly maxListBytes: number;
	/** cursor TTL（毫秒）。 */
	readonly cursorTtlMs: number;
	/** 每条目（版本/元数据/tombstone/marker）记账上界（保守 reservedDeltaBytes 公式的 entryOverheadBytes）。 */
	readonly entryOverheadBytes: number;
}

export interface IwebLoggingServiceLimits {
	readonly maxEventBytes: number;
	readonly ringMaxEvents: number;
	readonly ringMaxBytes: number;
}

export interface WasmHostServiceLimits {
	readonly kv: IwebKvServiceLimits;
	readonly sql: IwebSqlLimits;
	readonly logging: IwebLoggingServiceLimits;
}

/** 节点 maxima：capability record 内 hostServiceMaxima 每字段的硬天花板（裁决 3）。 */
export const WASM_HOST_SERVICE_NODE_MAXIMA: WasmHostServiceLimits = {
	kv: {
		maxListItems: IWEB_KV_LIST_LIMIT_MAX,
		maxListBytes: 1048576,
		cursorTtlMs: 600000,
		entryOverheadBytes: 4096,
	},
	sql: {
		statementMaxBytes: 65536,
		maxParameters: 256,
		parameterMaxBytes: 262144,
		maxRows: 4096,
		resultMaxBytes: 1048576,
		maxAffectedRows: 16384,
		executionMaxMs: 30000,
		lockWaitMaxMs: 10000,
		maxConcurrentCalls: 8,
	},
	logging: {
		maxEventBytes: IWEB_LOG_EVENT_MAX_BYTES_CEILING,
		ringMaxEvents: IWEB_LOG_RING_MAX_EVENTS_CEILING,
		ringMaxBytes: IWEB_LOG_RING_MAX_BYTES_CEILING,
	},
};

/**
 * 默认 profile limits（契约层权威锚点）：sql 与 IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS 同值——
 * 该占位常量的权威来源即本对象；真实发布 profile 由 owner 冻结的 HostServicePolicyV2 显式携带。
 */
export const WASM_HOST_SERVICE_PROFILE_DEFAULTS: WasmHostServiceLimits = {
	kv: {
		maxListItems: 64,
		maxListBytes: 65536,
		cursorTtlMs: 60000,
		entryOverheadBytes: 256,
	},
	sql: IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS,
	logging: {
		maxEventBytes: 8192,
		ringMaxEvents: 256,
		ringMaxBytes: 262144,
	},
};

const KV_LIMIT_FIELDS = ["maxListItems", "maxListBytes", "cursorTtlMs", "entryOverheadBytes"] as const;
const SQL_LIMIT_FIELDS = [
	"statementMaxBytes",
	"maxParameters",
	"parameterMaxBytes",
	"maxRows",
	"resultMaxBytes",
	"maxAffectedRows",
	"executionMaxMs",
	"lockWaitMaxMs",
	"maxConcurrentCalls",
] as const;
const LOGGING_LIMIT_FIELDS = ["maxEventBytes", "ringMaxEvents", "ringMaxBytes"] as const;

const LIMIT_FIELDS_BY_KIND: Readonly<Record<WasmHostServiceKind, readonly string[]>> = {
	kv: KV_LIMIT_FIELDS,
	sql: SQL_LIMIT_FIELDS,
	logging: LOGGING_LIMIT_FIELDS,
};

function limitValueCeiling(kind: WasmHostServiceKind, field: string): number | null {
	const maxima: Record<WasmHostServiceKind, Record<string, number>> = {
		kv: WASM_HOST_SERVICE_NODE_MAXIMA.kv as unknown as Record<string, number>,
		sql: WASM_HOST_SERVICE_NODE_MAXIMA.sql as unknown as Record<string, number>,
		logging: WASM_HOST_SERVICE_NODE_MAXIMA.logging as unknown as Record<string, number>,
	};
	const ceiling = maxima[kind][field];
	return typeof ceiling === "number" ? ceiling : null;
}

export type WasmHostServiceLimitsCheck =
	| { readonly ok: true; readonly kind: WasmHostServiceKind }
	| { readonly ok: false; readonly errors: readonly ValidationIssue[] };

/** 单服务 limits 校验：精确键集、每字段 1..节点 maxima（缺一不可证 -> 拒绝，fail-closed）。 */
export function validateWasmHostServiceLimits(kind: WasmHostServiceKind, input: unknown, path = ""): WasmHostServiceLimitsCheck {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) {
		return { ok: false, errors: [issue("WASM_HOST_POLICY_INVALID", path, kind + " limits must be an object with the exact limit keys")] };
	}
	rejectUnknownFields(input, path, LIMIT_FIELDS_BY_KIND[kind], errors);
	for (const field of LIMIT_FIELDS_BY_KIND[kind]) {
		if (!Object.prototype.hasOwnProperty.call(input, field)) {
			errors.push(issue("WASM_HOST_POLICY_INVALID", path + "/" + field, field + " is required"));
			continue;
		}
		const value = input[field];
		const ceiling = limitValueCeiling(kind, field);
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || ceiling === null || value > ceiling) {
			errors.push(issue("WASM_HOST_POLICY_INVALID", path + "/" + field, field + " must be an integer between 1 and the node maximum" + (ceiling === null ? "" : " " + ceiling)));
		}
	}
	if (errors.length) return { ok: false, errors };
	return { ok: true, kind };
}

// ---------------------------------------------------------------------------
// hostServices 成员 closed set（裁决 1：design 未列举内层值域，按 K1/K2/S1/S2/L1 提案唯一字面量）
// ---------------------------------------------------------------------------

export const WASM_KV_SERVICE_PROFILES = ["bounded-cas-list-v1"] as const;
export const WASM_KV_CONSISTENCY_LITERALS = ["single-key-linearizable-cas-v1"] as const;
export const WASM_SQL_SERVICE_PROFILES = ["minimal-sqlite-v1"] as const;
export const WASM_SQL_CONSISTENCY_LITERALS = ["implicit-transaction-per-call-v1"] as const;
export const WASM_LOGGING_SERVICE_PROFILES = ["bounded-memory-ring-v1"] as const;
export const WASM_LOGGING_CONSISTENCY_LITERALS = ["append-only-drop-on-full-v1"] as const;
export const WASM_KV_DURABILITY_LITERALS = [WASM_HOST_DURABILITY_PROFILE] as const;
export const WASM_SQL_DURABILITY_LITERALS = [WASM_HOST_DURABILITY_PROFILE] as const;
export const WASM_LOGGING_DURABILITY_LITERALS = ["no-durable-claim-v1"] as const;
export const WASM_KV_RETENTION_LITERALS = ["tombstone-window-v1"] as const;
export const WASM_SQL_RETENTION_LITERALS = ["retained-until-application-deletion-v1"] as const;
export const WASM_LOGGING_RETENTION_LITERALS = ["runtime-lifecycle-only-v1"] as const;

export interface IwebKvServiceMemberV2 {
	readonly profile: (typeof WASM_KV_SERVICE_PROFILES)[number];
	readonly limits: IwebKvServiceLimits;
	readonly consistency: (typeof WASM_KV_CONSISTENCY_LITERALS)[number];
	readonly durability: (typeof WASM_KV_DURABILITY_LITERALS)[number];
	readonly retention: (typeof WASM_KV_RETENTION_LITERALS)[number];
}

export interface IwebSqlServiceMemberV2 {
	readonly profile: (typeof WASM_SQL_SERVICE_PROFILES)[number];
	readonly limits: IwebSqlLimits;
	readonly consistency: (typeof WASM_SQL_CONSISTENCY_LITERALS)[number];
	readonly durability: (typeof WASM_SQL_DURABILITY_LITERALS)[number];
	readonly retention: (typeof WASM_SQL_RETENTION_LITERALS)[number];
}

export interface IwebLoggingServiceMemberV2 {
	readonly profile: (typeof WASM_LOGGING_SERVICE_PROFILES)[number];
	readonly limits: IwebLoggingServiceLimits;
	readonly consistency: (typeof WASM_LOGGING_CONSISTENCY_LITERALS)[number];
	readonly durability: (typeof WASM_LOGGING_DURABILITY_LITERALS)[number];
	readonly retention: (typeof WASM_LOGGING_RETENTION_LITERALS)[number];
}

export interface WasmHostServicesV2 {
	readonly kv: IwebKvServiceMemberV2 | null;
	readonly sql: IwebSqlServiceMemberV2 | null;
	readonly logging: IwebLoggingServiceMemberV2 | null;
}

interface ServiceLiteralSet {
	readonly profiles: readonly string[];
	readonly consistency: readonly string[];
	readonly durability: readonly string[];
	readonly retention: readonly string[];
}

const SERVICE_LITERAL_SETS: Readonly<Record<WasmHostServiceKind, ServiceLiteralSet>> = {
	kv: {
		profiles: WASM_KV_SERVICE_PROFILES,
		consistency: WASM_KV_CONSISTENCY_LITERALS,
		durability: WASM_KV_DURABILITY_LITERALS,
		retention: WASM_KV_RETENTION_LITERALS,
	},
	sql: {
		profiles: WASM_SQL_SERVICE_PROFILES,
		consistency: WASM_SQL_CONSISTENCY_LITERALS,
		durability: WASM_SQL_DURABILITY_LITERALS,
		retention: WASM_SQL_RETENTION_LITERALS,
	},
	logging: {
		profiles: WASM_LOGGING_SERVICE_PROFILES,
		consistency: WASM_LOGGING_CONSISTENCY_LITERALS,
		durability: WASM_LOGGING_DURABILITY_LITERALS,
		retention: WASM_LOGGING_RETENTION_LITERALS,
	},
};

// 成员恰有 {profile,limits,consistency,durability,retention} 五键（design 逐字），字面量取自 closed set。
function validateServiceMember(kind: WasmHostServiceKind, input: unknown, path: string, errors: ValidationIssue[]): void {
	if (!isRecord(input)) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", path, kind + " service member must be an object"));
		return;
	}
	rejectUnknownFields(input, path, ["profile", "limits", "consistency", "durability", "retention"], errors);
	const literals = SERVICE_LITERAL_SETS[kind];
	if (typeof input.profile !== "string" || !literals.profiles.includes(input.profile)) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", path + "/profile", kind + " profile must be one of " + literals.profiles.join(", ")));
	}
	if (typeof input.consistency !== "string" || !literals.consistency.includes(input.consistency)) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", path + "/consistency", kind + " consistency must be one of " + literals.consistency.join(", ")));
	}
	if (typeof input.durability !== "string" || !literals.durability.includes(input.durability)) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", path + "/durability", kind + " durability must be one of " + literals.durability.join(", ")));
	}
	if (typeof input.retention !== "string" || !literals.retention.includes(input.retention)) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", path + "/retention", kind + " retention must be one of " + literals.retention.join(", ")));
	}
	const limits = validateWasmHostServiceLimits(kind, input.limits, path + "/limits");
	if (!limits.ok) errors.push(...limits.errors);
}

function validateHostServices(input: unknown, path: string, errors: ValidationIssue[]): WasmHostServicesV2 | null {
	if (!isRecord(input)) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", path, "hostServices must be an object with exactly kv, sql, logging"));
		return null;
	}
	rejectUnknownFields(input, path, ["kv", "sql", "logging"], errors);
	const members: {
		kv: IwebKvServiceMemberV2 | null;
		sql: IwebSqlServiceMemberV2 | null;
		logging: IwebLoggingServiceMemberV2 | null;
	} = {
		kv: null,
		sql: null,
		logging: null,
	};
	let enabled = 0;
	for (const kind of ["kv", "sql", "logging"] as const) {
		const member = input[kind];
		if (member === null) continue;
		enabled++;
		validateServiceMember(kind, member, path + "/" + kind, errors);
		if (
			isRecord(member) &&
			typeof member.profile === "string" &&
			SERVICE_LITERAL_SETS[kind].profiles.includes(member.profile) &&
			isRecord(member.limits) &&
			validateWasmHostServiceLimits(kind, member.limits).ok &&
			typeof member.consistency === "string" &&
			SERVICE_LITERAL_SETS[kind].consistency.includes(member.consistency) &&
			typeof member.durability === "string" &&
			SERVICE_LITERAL_SETS[kind].durability.includes(member.durability) &&
			typeof member.retention === "string" &&
			SERVICE_LITERAL_SETS[kind].retention.includes(member.retention)
		) {
			// union-key 直写会被 TS 视作各目标类型的交集（null）；按 kind 显式分派。
			if (kind === "kv") {
				members.kv = member as unknown as IwebKvServiceMemberV2;
			} else if (kind === "sql") {
				members.sql = member as unknown as IwebSqlServiceMemberV2;
			} else {
				members.logging = member as unknown as IwebLoggingServiceMemberV2;
			}
		}
	}
	// 裁决 4：全 null 的 policy 拒绝——没有任何新 import 的版本是 V1 版本，不构造 V2 policy。
	if (enabled === 0) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", path, "at least one of kv, sql, logging must be non-null; a no-service version stays V1"));
	}
	return errors.length ? null : members;
}

// ---------------------------------------------------------------------------
// HostServicePolicyPayloadV2 / HostServicePolicyV2（policyDigest = digestV2(policy domain, JCS(payload))）
// ---------------------------------------------------------------------------

export interface WasmHostServicePolicyPayloadV2 {
	readonly schemaVersion: typeof WASM_HOST_SERVICE_SCHEMA_VERSION;
	readonly matrixRevision: typeof WASM_CAPABILITY_MATRIX_REVISION_2;
	readonly hostAbi: typeof WASM_HOST_ABI_LITERAL_V2;
	readonly hostServices: WasmHostServicesV2;
	readonly storageBytes: number;
	readonly reserveBytes: number;
	readonly dataDirectoryProfile: typeof WASM_HOST_DATA_DIRECTORY_PROFILE;
	readonly durabilityProfile: typeof WASM_HOST_DURABILITY_PROFILE;
}

export interface WasmHostServicePolicyV2 extends WasmHostServicePolicyPayloadV2 {
	readonly policyDigest: string;
}

const POLICY_PAYLOAD_FIELDS = [
	"schemaVersion",
	"matrixRevision",
	"hostAbi",
	"hostServices",
	"storageBytes",
	"reserveBytes",
	"dataDirectoryProfile",
	"durabilityProfile",
] as const;
const POLICY_FIELDS = [...POLICY_PAYLOAD_FIELDS, "policyDigest"] as const;

function validatePolicyPayload(input: unknown): ValidationResult<WasmHostServicePolicyPayloadV2> {
	if (!isRecord(input)) return failure([issue("WASM_HOST_POLICY_INVALID", "", "host service policy must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", POLICY_PAYLOAD_FIELDS, errors);
	if (input.schemaVersion !== WASM_HOST_SERVICE_SCHEMA_VERSION) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", "/schemaVersion", "schemaVersion must be the literal " + WASM_HOST_SERVICE_SCHEMA_VERSION));
	}
	if (input.matrixRevision !== WASM_CAPABILITY_MATRIX_REVISION_2) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", "/matrixRevision", "matrixRevision must be the literal " + WASM_CAPABILITY_MATRIX_REVISION_2));
	}
	if (input.hostAbi !== WASM_HOST_ABI_LITERAL_V2) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", "/hostAbi", "hostAbi must be exactly " + WASM_HOST_ABI_LITERAL_V2));
	}
	const hostServices = validateHostServices(input.hostServices, "/hostServices", errors);
	for (const field of ["storageBytes", "reserveBytes"] as const) {
		const value = input[field];
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > WASM_U53_MAX) {
			errors.push(issue("WASM_HOST_POLICY_INVALID", "/" + field, field + " must be an integer between 1 and " + WASM_U53_MAX));
		}
	}
	if (input.dataDirectoryProfile !== WASM_HOST_DATA_DIRECTORY_PROFILE) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", "/dataDirectoryProfile", "dataDirectoryProfile must be exactly " + WASM_HOST_DATA_DIRECTORY_PROFILE));
	}
	if (input.durabilityProfile !== WASM_HOST_DURABILITY_PROFILE) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", "/durabilityProfile", "durabilityProfile must be exactly " + WASM_HOST_DURABILITY_PROFILE));
	}
	if (errors.length || hostServices === null) {
		return failure(errors.length ? errors : [issue("WASM_HOST_POLICY_INVALID", "/hostServices", "hostServices is invalid")]);
	}
	return ok({
		schemaVersion: WASM_HOST_SERVICE_SCHEMA_VERSION,
		matrixRevision: WASM_CAPABILITY_MATRIX_REVISION_2,
		hostAbi: WASM_HOST_ABI_LITERAL_V2,
		hostServices,
		storageBytes: input.storageBytes as number,
		reserveBytes: input.reserveBytes as number,
		dataDirectoryProfile: WASM_HOST_DATA_DIRECTORY_PROFILE,
		durabilityProfile: WASM_HOST_DURABILITY_PROFILE,
	});
}

/** policyDigest = digestV2("iweb-wasm-host-policy-v2", JCS(payload))；payload 必须已通过结构校验。 */
export function computeWasmHostServicePolicyDigestV2(payload: WasmHostServicePolicyPayloadV2): ValidationResult<string> {
	try {
		return ok(digestV2(WASM_HOST_POLICY_DIGEST_DOMAIN, jcsCanonicalBytes(payload as unknown)));
	} catch {
		return failure([issue("WASM_HOST_POLICY_INVALID", "", "payload is outside the canonical JSON domain")]);
	}
}

export function sealWasmHostServicePolicyV2(input: unknown): ValidationResult<WasmHostServicePolicyV2> {
	const payload = validatePolicyPayload(input);
	if (!payload.ok) return payload;
	const digest = computeWasmHostServicePolicyDigestV2(payload.value);
	if (!digest.ok) return digest;
	return ok({ ...payload.value, policyDigest: digest.value });
}

export function validateWasmHostServicePolicyV2(input: unknown): ValidationResult<WasmHostServicePolicyV2> {
	if (!isRecord(input)) return failure([issue("WASM_HOST_POLICY_INVALID", "", "host service policy must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", POLICY_FIELDS, errors);
	if (typeof input.policyDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.policyDigest)) {
		errors.push(issue("WASM_HOST_POLICY_INVALID", "/policyDigest", "policyDigest must be a 64-character lower-case hex digest"));
	}
	if (errors.length) return failure(errors);
	const sealed = sealWasmHostServicePolicyV2({
		schemaVersion: input.schemaVersion,
		matrixRevision: input.matrixRevision,
		hostAbi: input.hostAbi,
		hostServices: input.hostServices,
		storageBytes: input.storageBytes,
		reserveBytes: input.reserveBytes,
		dataDirectoryProfile: input.dataDirectoryProfile,
		durabilityProfile: input.durabilityProfile,
	});
	if (!sealed.ok) return sealed;
	if (sealed.value.policyDigest !== input.policyDigest) {
		return failure([issue("WASM_HOST_POLICY_DIGEST_MISMATCH", "/policyDigest", 'policyDigest must equal digestV2("iweb-wasm-host-policy-v2", JCS(payload))')]);
	}
	return sealed;
}

// ---------------------------------------------------------------------------
// guestMemoryBytes reserve 公式（design「Decisions 3」：1 <= reserveBytes < memoryBytes，fail-closed）
// ---------------------------------------------------------------------------

export type WasmGuestMemoryReserveCheck =
	| { readonly ok: true; readonly guestMemoryBytes: number }
	| { readonly ok: false; readonly code: "WASM_GUEST_MEMORY_RESERVE_INVALID"; readonly message: string };

export function checkWasmGuestMemoryReserve(memoryBytes: number, reserveBytes: number): WasmGuestMemoryReserveCheck {
	if (typeof memoryBytes !== "number" || !Number.isSafeInteger(memoryBytes) || memoryBytes < 2 || memoryBytes > WASM_U53_MAX) {
		return { ok: false, code: "WASM_GUEST_MEMORY_RESERVE_INVALID", message: "memoryBytes must be an integer between 2 and " + WASM_U53_MAX };
	}
	if (typeof reserveBytes !== "number" || !Number.isSafeInteger(reserveBytes) || reserveBytes < 1 || reserveBytes >= memoryBytes) {
		return { ok: false, code: "WASM_GUEST_MEMORY_RESERVE_INVALID", message: "reserveBytes must be an integer with 1 <= reserveBytes < memoryBytes; no zero/default substitution" };
	}
	return { ok: true, guestMemoryBytes: memoryBytes - reserveBytes };
}

// ---------------------------------------------------------------------------
// Capability matrix revision 2（rev-1 精确并集 + 三个新 import；bytewise 排序）
// ---------------------------------------------------------------------------

export const WASM_KV_HOST_IMPORT: WasmImportCapability = { package: "iweb:kv@1.0.0", interface: "store", direction: "import" };
export const WASM_SQL_HOST_IMPORT: WasmImportCapability = { package: "iweb:sql@1.0.0", interface: "store", direction: "import" };
export const WASM_LOGGING_HOST_IMPORT: WasmImportCapability = { package: "iweb:logging@1.0.0", interface: "logger", direction: "import" };

/** revision-2 host import 矩阵 = rev-1 完整条目 ∪ 三个新服务 import，按 (package,interface,direction) 字节序排序。 */
export const WASM_CAPABILITY_MATRIX_REVISION_2_HOST_IMPORTS: readonly WasmImportCapability[] = sortWasmCapabilityIds([
	...WASM_CAPABILITY_MATRIX_REVISION_1.hostImports,
	WASM_KV_HOST_IMPORT,
	WASM_SQL_HOST_IMPORT,
	WASM_LOGGING_HOST_IMPORT,
]);

export interface WasmCapabilityMatrixV2 {
	readonly schemaVersion: typeof WASM_HOST_SERVICE_SCHEMA_VERSION;
	readonly matrixRevision: typeof WASM_CAPABILITY_MATRIX_REVISION_2;
	readonly world: typeof WASM_WORLD_LITERAL;
	readonly hostABI: typeof WASM_HOST_ABI_LITERAL_V2;
	readonly requiredRootExport: WasmCapabilityId;
	readonly hostImports: readonly WasmImportCapability[];
}

export const WASM_CAPABILITY_MATRIX_V2: WasmCapabilityMatrixV2 = {
	schemaVersion: WASM_HOST_SERVICE_SCHEMA_VERSION,
	matrixRevision: WASM_CAPABILITY_MATRIX_REVISION_2,
	world: WASM_WORLD_LITERAL,
	hostABI: WASM_HOST_ABI_LITERAL_V2,
	requiredRootExport: WASM_CAPABILITY_MATRIX_REVISION_1.requiredRootExport,
	hostImports: WASM_CAPABILITY_MATRIX_REVISION_2_HOST_IMPORTS,
};

const MATRIX_V2_CODE = "WASM_CAPABILITY_MATRIX_V2_INVALID";

function wasmCapabilityKeyOf(id: WasmCapabilityId): string {
	return id.direction + ":" + id.package + "/" + id.interface;
}

export function validateWasmCapabilityMatrixV2(input: unknown): ValidationResult<WasmCapabilityMatrixV2> {
	if (!isRecord(input)) return failure([issue(MATRIX_V2_CODE, "", "capability matrix v2 must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["schemaVersion", "matrixRevision", "world", "hostABI", "requiredRootExport", "hostImports"], errors);
	if (input.schemaVersion !== WASM_HOST_SERVICE_SCHEMA_VERSION) {
		errors.push(issue(MATRIX_V2_CODE, "/schemaVersion", "schemaVersion must be the literal " + WASM_HOST_SERVICE_SCHEMA_VERSION));
	}
	if (input.matrixRevision !== WASM_CAPABILITY_MATRIX_REVISION_2) {
		errors.push(issue(MATRIX_V2_CODE, "/matrixRevision", "matrixRevision must be the literal " + WASM_CAPABILITY_MATRIX_REVISION_2));
	}
	if (input.world !== WASM_CAPABILITY_MATRIX_V2.world) {
		errors.push(issue(MATRIX_V2_CODE, "/world", "world must remain exactly " + WASM_CAPABILITY_MATRIX_V2.world));
	}
	if (input.hostABI !== WASM_HOST_ABI_LITERAL_V2) {
		errors.push(issue(MATRIX_V2_CODE, "/hostABI", "hostABI must be exactly " + WASM_HOST_ABI_LITERAL_V2));
	}
	const rootExport = input.requiredRootExport;
	if (
		!isRecord(rootExport) ||
		rootExport.package !== WASM_CAPABILITY_MATRIX_V2.requiredRootExport.package ||
		rootExport.interface !== WASM_CAPABILITY_MATRIX_V2.requiredRootExport.interface ||
		rootExport.direction !== WASM_CAPABILITY_MATRIX_V2.requiredRootExport.direction
	) {
		errors.push(issue(MATRIX_V2_CODE, "/requiredRootExport", "requiredRootExport must remain exactly wasi:http@0.2.8/incoming-handler export"));
	}
	if (!Array.isArray(input.hostImports)) {
		errors.push(issue(MATRIX_V2_CODE, "/hostImports", "hostImports must be an array"));
	} else {
		const expected = WASM_CAPABILITY_MATRIX_V2.hostImports;
		const expectedKeys = new Set(expected.map(wasmCapabilityKeyOf));
		const seen = new Set<string>();
		let sorted = true;
		let previous: WasmCapabilityId | null = null;
		for (let index = 0; index < input.hostImports.length; index++) {
			const entry = input.hostImports[index];
			if (!isRecord(entry)) {
				errors.push(issue(MATRIX_V2_CODE, "/hostImports/" + index, "host import must be an object"));
				continue;
			}
			const candidate: WasmCapabilityId = {
				package: entry.package as string,
				interface: entry.interface as string,
				direction: entry.direction as WasmCapabilityId["direction"],
			};
			const key = wasmCapabilityKeyOf(candidate);
			if (seen.has(key)) errors.push(issue(MATRIX_V2_CODE, "/hostImports/" + index, "duplicate host import is rejected"));
			seen.add(key);
			if (!expectedKeys.has(key)) {
				errors.push(issue(MATRIX_V2_CODE, "/hostImports/" + index, "host import is not part of the revision-2 matrix"));
			}
			if (previous !== null && compareCapabilityIds(previous, candidate) > 0) sorted = false;
			previous = candidate;
		}
		if (!sorted) errors.push(issue(MATRIX_V2_CODE, "/hostImports", "hostImports must be sorted by (package, interface, direction) in UTF-8 byte order"));
		if (input.hostImports.length !== expected.length) {
			errors.push(issue(MATRIX_V2_CODE, "/hostImports", "revision-2 matrix has exactly " + expected.length + " host imports"));
		}
		for (const allowed of expected) {
			if (!seen.has(wasmCapabilityKeyOf(allowed))) {
				errors.push(issue(MATRIX_V2_CODE, "/hostImports", "revision-2 host import " + wasmCapabilityKeyOf(allowed) + " is missing"));
			}
		}
	}
	if (errors.length) return failure(errors);
	return ok(WASM_CAPABILITY_MATRIX_V2);
}

function compareCapabilityIds(left: WasmCapabilityId, right: WasmCapabilityId): number {
	if (left.package !== right.package) return left.package < right.package ? -1 : 1;
	if (left.interface !== right.interface) return left.interface < right.interface ? -1 : 1;
	if (left.direction !== right.direction) return left.direction < right.direction ? -1 : 1;
	return 0;
}

// ---------------------------------------------------------------------------
// Capability record revision 2 增量形状 + iweb-wasm-capability-record-v2 hash
// ---------------------------------------------------------------------------

export interface WasmHostServiceCapabilityIncrementPayloadV2 {
	readonly schemaVersion: typeof WASM_HOST_SERVICE_SCHEMA_VERSION;
	readonly matrixRevision: typeof WASM_CAPABILITY_MATRIX_REVISION_2;
	readonly hostAbi: typeof WASM_HOST_ABI_LITERAL_V2;
	readonly world: typeof WASM_WORLD_LITERAL;
	readonly hostImports: readonly WasmImportCapability[];
	readonly hostServiceMaxima: WasmHostServiceLimits;
}

export interface WasmHostServiceCapabilityIncrementV2 extends WasmHostServiceCapabilityIncrementPayloadV2 {
	readonly recordHash: string;
}

const CAPABILITY_INCREMENT_FIELDS = [
	"schemaVersion",
	"matrixRevision",
	"hostAbi",
	"world",
	"hostImports",
	"hostServiceMaxima",
] as const;

function validateHostServiceMaxima(input: unknown, errors: ValidationIssue[]): WasmHostServiceLimits | null {
	if (!isRecord(input)) {
		errors.push(issue("WASM_CAPABILITY_RECORD_V2_INVALID", "/hostServiceMaxima", "hostServiceMaxima must be an object with exactly kv, sql, logging"));
		return null;
	}
	rejectUnknownFields(input, "/hostServiceMaxima", ["kv", "sql", "logging"], errors);
	const out: WasmHostServiceLimits = {
		kv: input.kv as IwebKvServiceLimits,
		sql: input.sql as IwebSqlLimits,
		logging: input.logging as IwebLoggingServiceLimits,
	};
	for (const kind of ["kv", "sql", "logging"] as const) {
		// maxima 每字段 1..硬天花板（= WASM_HOST_SERVICE_NODE_MAXIMA，裁决 3）。
		const check = validateWasmHostServiceLimits(kind, input[kind], "/hostServiceMaxima/" + kind);
		if (!check.ok) errors.push(...check.errors);
	}
	return errors.length ? null : out;
}

/** recordHash = digestV2("iweb-wasm-capability-record-v2", JCS(increment without recordHash))。 */
export function computeWasmCapabilityRecordHashV2(payload: WasmHostServiceCapabilityIncrementPayloadV2): ValidationResult<string> {
	try {
		return ok(digestV2(WASM_CAPABILITY_RECORD_HASH_DOMAIN_V2, jcsCanonicalBytes(payload as unknown)));
	} catch {
		return failure([issue("WASM_CAPABILITY_RECORD_V2_INVALID", "", "payload is outside the canonical JSON domain")]);
	}
}

export function sealWasmHostServiceCapabilityIncrementV2(input: unknown): ValidationResult<WasmHostServiceCapabilityIncrementV2> {
	const payload = validateCapabilityIncrementPayload(input);
	if (!payload.ok) return payload;
	const hash = computeWasmCapabilityRecordHashV2(payload.value);
	if (!hash.ok) return hash;
	return ok({ ...payload.value, recordHash: hash.value });
}

function validateCapabilityIncrementPayload(input: unknown): ValidationResult<WasmHostServiceCapabilityIncrementPayloadV2> {
	if (!isRecord(input)) return failure([issue("WASM_CAPABILITY_RECORD_V2_INVALID", "", "capability record increment must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", CAPABILITY_INCREMENT_FIELDS, errors);
	if (input.schemaVersion !== WASM_HOST_SERVICE_SCHEMA_VERSION) {
		errors.push(issue("WASM_CAPABILITY_RECORD_V2_INVALID", "/schemaVersion", "schemaVersion must be the literal " + WASM_HOST_SERVICE_SCHEMA_VERSION));
	}
	if (input.matrixRevision !== WASM_CAPABILITY_MATRIX_REVISION_2) {
		errors.push(issue("WASM_CAPABILITY_RECORD_V2_INVALID", "/matrixRevision", "matrixRevision must be the literal " + WASM_CAPABILITY_MATRIX_REVISION_2));
	}
	if (input.hostAbi !== WASM_HOST_ABI_LITERAL_V2) {
		errors.push(issue("WASM_CAPABILITY_RECORD_V2_INVALID", "/hostAbi", "hostAbi must be exactly " + WASM_HOST_ABI_LITERAL_V2));
	}
	if (input.world !== WASM_CAPABILITY_MATRIX_V2.world) {
		errors.push(issue("WASM_CAPABILITY_RECORD_V2_INVALID", "/world", "world must remain exactly " + WASM_CAPABILITY_MATRIX_V2.world));
	}
	const matrix = validateWasmCapabilityMatrixV2({
		schemaVersion: input.schemaVersion,
		matrixRevision: input.matrixRevision,
		world: input.world,
		hostABI: input.hostAbi,
		requiredRootExport: WASM_CAPABILITY_MATRIX_V2.requiredRootExport,
		hostImports: input.hostImports,
	});
	if (!matrix.ok) {
		errors.push(...matrix.errors);
		return failure(errors);
	}
	const maxima = validateHostServiceMaxima(input.hostServiceMaxima, errors);
	if (errors.length || maxima === null) {
		return failure(errors.length ? errors : [issue("WASM_CAPABILITY_RECORD_V2_INVALID", "", "capability record increment is invalid")]);
	}
	return ok({
		schemaVersion: WASM_HOST_SERVICE_SCHEMA_VERSION,
		matrixRevision: WASM_CAPABILITY_MATRIX_REVISION_2,
		hostAbi: WASM_HOST_ABI_LITERAL_V2,
		world: WASM_CAPABILITY_MATRIX_V2.world,
		hostImports: matrix.value.hostImports,
		hostServiceMaxima: maxima,
	});
}

export function validateWasmHostServiceCapabilityIncrementV2(input: unknown): ValidationResult<WasmHostServiceCapabilityIncrementV2> {
	if (!isRecord(input)) return failure([issue("WASM_CAPABILITY_RECORD_V2_INVALID", "", "capability record increment must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", [...CAPABILITY_INCREMENT_FIELDS, "recordHash"], errors);
	if (typeof input.recordHash !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.recordHash)) {
		errors.push(issue("WASM_CAPABILITY_RECORD_V2_INVALID", "/recordHash", "recordHash must be a 64-character lower-case hex digest"));
	}
	if (errors.length) return failure(errors);
	const sealed = sealWasmHostServiceCapabilityIncrementV2({
		schemaVersion: input.schemaVersion,
		matrixRevision: input.matrixRevision,
		hostAbi: input.hostAbi,
		world: input.world,
		hostImports: input.hostImports,
		hostServiceMaxima: input.hostServiceMaxima,
	});
	if (!sealed.ok) return sealed;
	if (sealed.value.recordHash !== input.recordHash) {
		return failure([issue("WASM_CAPABILITY_RECORD_V2_HASH_MISMATCH", "/recordHash", 'recordHash must equal digestV2("iweb-wasm-capability-record-v2", JCS(increment with recordHash omitted))')]);
	}
	return sealed;
}

// ---------------------------------------------------------------------------
// HostServiceIdentityV2（11 个精确字段）与 versionDigest / versionId 投影
// ---------------------------------------------------------------------------

export interface WasmHostServiceIdentityV2 {
	readonly schemaVersion: typeof WASM_HOST_SERVICE_SCHEMA_VERSION;
	readonly applicationId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	readonly versionDigest: string;
	readonly matrixRevision: typeof WASM_CAPABILITY_MATRIX_REVISION_2;
	readonly hostAbi: typeof WASM_HOST_ABI_LITERAL_V2;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly catalogRevision: number;
	readonly catalogHash: string;
	readonly hostServicePolicyDigest: string;
}

const IDENTITY_FIELDS = [
	"schemaVersion",
	"applicationId",
	"versionId",
	"packageDigest",
	"versionDigest",
	"matrixRevision",
	"hostAbi",
	"capabilityRecordRevision",
	"capabilityRecordHash",
	"catalogRevision",
	"catalogHash",
	"hostServicePolicyDigest",
] as const;

export function validateWasmHostServiceIdentityV2(input: unknown): ValidationResult<WasmHostServiceIdentityV2> {
	if (!isRecord(input)) return failure([issue("WASM_HOST_IDENTITY_INVALID", "", "host service identity must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", IDENTITY_FIELDS, errors);
	if (input.schemaVersion !== WASM_HOST_SERVICE_SCHEMA_VERSION) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/schemaVersion", "schemaVersion must be the literal " + WASM_HOST_SERVICE_SCHEMA_VERSION));
	}
	if (typeof input.applicationId !== "string" || !WASM_APPLICATION_ID_PATTERN.test(input.applicationId)) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/applicationId", "applicationId must match the application id grammar"));
	}
	if (typeof input.versionId !== "string" || !WASM_VERSION_ID_PATTERN.test(input.versionId)) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/versionId", "versionId must be <64-hex>-<positive-sequence>"));
	}
	for (const field of ["packageDigest", "versionDigest", "capabilityRecordHash", "catalogHash", "hostServicePolicyDigest"] as const) {
		if (typeof input[field] !== "string" || !WASM_SHA256_HEX_PATTERN.test(input[field])) {
			errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/" + field, field + " must be a 64-character lower-case hex digest"));
		}
	}
	if (input.matrixRevision !== WASM_CAPABILITY_MATRIX_REVISION_2) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/matrixRevision", "matrixRevision must be the literal " + WASM_CAPABILITY_MATRIX_REVISION_2));
	}
	if (input.hostAbi !== WASM_HOST_ABI_LITERAL_V2) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/hostAbi", "hostAbi must be exactly " + WASM_HOST_ABI_LITERAL_V2));
	}
	for (const field of ["capabilityRecordRevision", "catalogRevision"] as const) {
		const value = input[field];
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > WASM_U53_MAX) {
			errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/" + field, field + " must be an integer between 1 and " + WASM_U53_MAX));
		}
	}
	if (errors.length) return failure(errors);
	if (typeof input.versionId === "string" && typeof input.versionDigest === "string" && !input.versionId.startsWith(input.versionDigest + "-")) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/versionId", "versionId must start with versionDigest + \"-\""));
		return failure(errors);
	}
	return ok({
		schemaVersion: WASM_HOST_SERVICE_SCHEMA_VERSION,
		applicationId: input.applicationId as string,
		versionId: input.versionId as string,
		packageDigest: input.packageDigest as string,
		versionDigest: input.versionDigest as string,
		matrixRevision: WASM_CAPABILITY_MATRIX_REVISION_2,
		hostAbi: WASM_HOST_ABI_LITERAL_V2,
		capabilityRecordRevision: input.capabilityRecordRevision as number,
		capabilityRecordHash: input.capabilityRecordHash as string,
		catalogRevision: input.catalogRevision as number,
		catalogHash: input.catalogHash as string,
		hostServicePolicyDigest: input.hostServicePolicyDigest as string,
	});
}

export interface WasmHostServiceVersionDigestInputV2 {
	readonly packageDigest: string;
	/** 完整 V1 normalized policy 对象（嵌入 digest 输入；必须落在 canonical JSON 域内）。 */
	readonly normalizedPolicy: unknown;
	readonly hostServicePolicyDigest: string;
}

/**
 * versionDigest = digestV2("iweb-wasm-host-identity-v2",
 *   JCS({schemaVersion:2, packageDigest, normalizedPolicy, hostServicePolicyDigest, matrixRevision:2, hostAbi}))。
 */
export function computeWasmHostServiceVersionDigestV2(input: WasmHostServiceVersionDigestInputV2): ValidationResult<string> {
	const errors: ValidationIssue[] = [];
	if (typeof input.packageDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.packageDigest)) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/packageDigest", "packageDigest must be a 64-character lower-case hex digest"));
	}
	if (typeof input.hostServicePolicyDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.hostServicePolicyDigest)) {
		errors.push(issue("WASM_HOST_IDENTITY_INVALID", "/hostServicePolicyDigest", "hostServicePolicyDigest must be a 64-character lower-case hex digest"));
	}
	if (errors.length) return failure(errors);
	try {
		const wrapper = {
			schemaVersion: WASM_HOST_SERVICE_SCHEMA_VERSION,
			packageDigest: input.packageDigest,
			normalizedPolicy: input.normalizedPolicy,
			hostServicePolicyDigest: input.hostServicePolicyDigest,
			matrixRevision: WASM_CAPABILITY_MATRIX_REVISION_2,
			hostAbi: WASM_HOST_ABI_LITERAL_V2,
		};
		return ok(digestV2(WASM_HOST_IDENTITY_DIGEST_DOMAIN, jcsCanonicalBytes(wrapper)));
	} catch {
		return failure([issue("WASM_HOST_IDENTITY_INVALID", "/normalizedPolicy", "normalizedPolicy is outside the canonical JSON domain")]);
	}
}

/** V2 versionId = <versionDigest>-<positive-sequence>；sequence 是 1..10^15-1 内的正十进制（WASM_VERSION_ID_PATTERN）。 */
export function formatWasmVersionIdV2(versionDigest: string, sequence: number): string | null {
	if (typeof versionDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(versionDigest)) return null;
	if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1 || sequence > 999999999999999) return null;
	const versionId = versionDigest + "-" + sequence;
	return WASM_VERSION_ID_PATTERN.test(versionId) ? versionId : null;
}
