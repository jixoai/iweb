// 用户原始需求（2026-08-27，add-wasm-host-services 契约先行）：`iweb:logging@1.0.0` 的 WIT 身份、结构化事件校验、
// 有界环纯函数、redaction 边界与 owner 授权外部转发面必须先于实现落入 contracts。
// owner L1 终裁（2026-08-27）：内存有界环 + monitor 投影 + owner 授权外部转发（drain/stream 或配置化 syslog/JSON-lines，默认关）；
// 节点不做持久层；redaction 先于大小计算；dropped 显式计数且不是 audit 确认；与 Kernel audit/stdio 隔离。
// 正交意图：（1）WIT 身份/方向法与错误 wire；（2）事件 grammar/界校验 + redaction 边界纯函数；
// （3）per-app 有界环纯函数（容量/dropped 计数/单调 eventId/重置语义）；（4）owner 授权 drain 与 monitor 投影形状；
// （5）外部转发配置 wire（默认关 fail-closed）+ audit/stdio 隔离的 sink 法。
// 规范权威：openspec/changes/add-wasm-host-services/specs/wasm-host-logging/spec.md；
// WIT 文本权威：./wit/iweb-logging.wit（tests/wasm-host-logging.test.ts 断言与 spec 的 wit 代码块逐字一致）。
// 契约层裁决（spec 留白处的 fail-closed 选择，均已报告）：
//  - 满容量按 spec「Buffer is full」场景取 drop-on-full：不驱逐本应用事件、更不可能触碰他应用事件；
//  - disabled level 映射 invalid-event（非容量条件）；长度/数量/事件总字节越界映射 limit-exceeded；
//  - dropped 事件不消耗 eventId；被保留事件的 eventId 在一个生命周期内连续且单调；reset 开启新生命周期，无跨重启持久化声明；
//  - 字节计量是确定性 canonical 口径（含宿主元数据），不是 wire 编码承诺；maxEventBytes/环容量默认值待 V2 capability record 固定（任务 2.1/3.1）。
import { failure, isRecord, issue, OPAQUE_ID_PATTERN, ok, rejectUnknownFields, type ValidationIssue, type ValidationResult } from "./validation.ts";
import { iwebUtf8ByteLength } from "./wasm-host-store.ts";
import { WASM_U53_MAX, WASM_VERSION_ID_PATTERN } from "./wasm-package.ts";

// ---------------------------------------------------------------------------
// WIT 包/接口身份与方向法（import logger 是唯一合法方向）
// ---------------------------------------------------------------------------

export const IWEB_LOGGING_WIT_PACKAGE = "iweb:logging@1.0.0";
export const IWEB_LOGGING_WIT_WORLD = "logging";
export const IWEB_LOGGING_INTERFACE = "logger";
// 未知 patch（如 iweb:logging@1.0.1）或任何非精确包名都在物化前拒绝，绝不降级解释。
export const IWEB_LOGGING_SUPPORTED_WIT_PACKAGES = [IWEB_LOGGING_WIT_PACKAGE] as const;

export type IwebLoggingWitAdmissionErrorCode = "IWEB_LOG_WIT_DIRECTION_INVALID" | "IWEB_LOG_WIT_PACKAGE_INVALID";

// 只裁决 logger 接口身份：export 一律方向非法；非精确包名（含未知 patch）一律包非法。
export function iwebLoggingWitAdmissionErrorCode(id: { readonly package: string; readonly interface: string; readonly direction: string }): IwebLoggingWitAdmissionErrorCode | null {
	if (id.interface !== IWEB_LOGGING_INTERFACE) return null;
	if (!(IWEB_LOGGING_SUPPORTED_WIT_PACKAGES as readonly string[]).includes(id.package)) return "IWEB_LOG_WIT_PACKAGE_INVALID";
	if (id.direction === "export") return "IWEB_LOG_WIT_DIRECTION_INVALID";
	return null;
}

// ---------------------------------------------------------------------------
// WIT 调用错误 variant ↔ wire 错误码（closed set，不回显日志正文）
// ---------------------------------------------------------------------------

export const IWEB_LOG_LEVELS = ["trace", "debug", "info", "warn", "error"] as const;
export type IwebLogLevel = (typeof IWEB_LOG_LEVELS)[number];

export const IWEB_LOG_OUTCOME_CASES = ["accepted", "dropped"] as const;
export type IwebLoggingOutcome = (typeof IWEB_LOG_OUTCOME_CASES)[number];

export const IWEB_LOG_WIT_ERROR_CASES = ["invalid-event", "limit-exceeded", "unavailable", "internal"] as const;
export type IwebLoggingWitErrorCase = (typeof IWEB_LOG_WIT_ERROR_CASES)[number];

export const IWEB_LOG_WIRE_ERROR_BY_CASE: Readonly<Record<IwebLoggingWitErrorCase, string>> = {
	"invalid-event": "IWEB_LOG_INVALID_EVENT",
	"limit-exceeded": "IWEB_LOG_LIMIT_EXCEEDED",
	unavailable: "IWEB_LOG_UNAVAILABLE",
	internal: "IWEB_LOG_INTERNAL",
};

// 传输层追加码（不在 WIT variant 内）：宿主上下文与环属主不一致是隔离违约，属 internal 域故障而非组件可重试错误。
export const IWEB_LOG_TRANSPORT_ERROR_CODES = ["IWEB_LOG_APP_ISOLATION"] as const;

export type IwebLoggingWireErrorCode = "IWEB_LOG_INVALID_EVENT" | "IWEB_LOG_LIMIT_EXCEEDED" | "IWEB_LOG_UNAVAILABLE" | "IWEB_LOG_INTERNAL" | "IWEB_LOG_APP_ISOLATION";

// ---------------------------------------------------------------------------
// 事件 grammar 与界（spec：message 0..4096；fields ≤32 唯一小写 key；value 0..1024，均 UTF-8 字节）
// ---------------------------------------------------------------------------

export const IWEB_LOG_MESSAGE_MAX_BYTES = 4096;
export const IWEB_LOG_FIELD_KEY_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
export const IWEB_LOG_FIELD_KEY_MAX_BYTES = 64;
export const IWEB_LOG_FIELD_VALUE_MAX_BYTES = 1024;
export const IWEB_LOG_FIELDS_MAX = 32;

// per-event 上限（含宿主元数据的 canonical 计量）与环容量：默认值供 profile 引用，权威 pin 在 V2 capability record。
export const IWEB_LOG_EVENT_MAX_BYTES_DEFAULT = 8192;
export const IWEB_LOG_EVENT_MAX_BYTES_CEILING = 65536;
export const IWEB_LOG_RING_MAX_EVENTS_DEFAULT = 256;
export const IWEB_LOG_RING_MAX_BYTES_DEFAULT = 262144;
export const IWEB_LOG_RING_MAX_EVENTS_CEILING = 100000;
export const IWEB_LOG_RING_MAX_BYTES_CEILING = 16777216;

// WIT string 必须是 well-formed Unicode：lone surrogate 无法编码为合法 UTF-8，一律 invalid-event。
export function isWellFormedIwebLoggingText(value: string): boolean {
	let pendingHighSurrogate = false;
	for (let index = 0; index < value.length; index++) {
		const codeUnit = value.charCodeAt(index);
		if (pendingHighSurrogate) {
			if (codeUnit < 0xdc00 || codeUnit > 0xdfff) return false;
			pendingHighSurrogate = false;
		} else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
			pendingHighSurrogate = true;
		} else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
			return false;
		}
	}
	return !pendingHighSurrogate;
}

export interface IwebLoggingFieldV1 {
	readonly key: string;
	readonly value: string;
}

export interface IwebLoggingEventV1 {
	readonly level: IwebLogLevel;
	readonly message: string;
	readonly fields: readonly IwebLoggingFieldV1[];
}

export interface IwebLoggingEventValidationOptions {
	// profile 可禁用部分 level；被禁 level 的事件按 invalid-event 拒绝（契约层裁决：非容量条件）。
	readonly enabledLevels?: readonly IwebLogLevel[];
}

// 越界类 issue code → WIT limit-exceeded；其余（结构/grammar/UTF-8/level）→ invalid-event。
const IWEB_LOG_LIMIT_ISSUE_CODES = new Set(["MESSAGE_TOO_LONG", "VALUE_TOO_LONG", "TOO_MANY_FIELDS", "EVENT_TOO_LARGE"]);

export function iwebLoggingWireErrorFromIssues(issues: readonly ValidationIssue[]): "IWEB_LOG_INVALID_EVENT" | "IWEB_LOG_LIMIT_EXCEEDED" {
	return issues.some((entry) => IWEB_LOG_LIMIT_ISSUE_CODES.has(entry.code)) ? "IWEB_LOG_LIMIT_EXCEEDED" : "IWEB_LOG_INVALID_EVENT";
}

// 事件只接受 level/message/fields 三个 caller 字段：caller timestamp、identity、owner credential、
// request body 或 host handle（任何未知字段）都在校验层拒绝，绝不进入宿主绑定。
export function validateIwebLoggingEvent(input: unknown, options: IwebLoggingEventValidationOptions = {}): ValidationResult<IwebLoggingEventV1> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "event must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["level", "message", "fields"], errors);

	let level: IwebLogLevel | null = null;
	if (typeof input.level !== "string" || !(IWEB_LOG_LEVELS as readonly string[]).includes(input.level)) {
		errors.push(issue("INVALID_LEVEL", "/level", "level must be one of trace|debug|info|warn|error"));
	} else {
		// includes 检查后无窄化：用受检 cast 固定为闭集成员。
		const candidate = input.level as IwebLogLevel;
		if (options.enabledLevels !== undefined && !options.enabledLevels.includes(candidate)) {
			errors.push(issue("LEVEL_DISABLED", "/level", "level is not enabled by the pinned profile"));
		} else {
			level = candidate;
		}
	}

	let message: string | null = null;
	if (typeof input.message !== "string") {
		errors.push(issue("TYPE_STRING", "/message", "message must be a string"));
	} else if (!isWellFormedIwebLoggingText(input.message)) {
		errors.push(issue("UTF8_INVALID", "/message", "message must be well-formed UTF-8"));
	} else if (iwebUtf8ByteLength(input.message) > IWEB_LOG_MESSAGE_MAX_BYTES) {
		errors.push(issue("MESSAGE_TOO_LONG", "/message", "message must be at most " + IWEB_LOG_MESSAGE_MAX_BYTES + " UTF-8 bytes"));
	} else {
		message = input.message;
	}

	const fields: IwebLoggingFieldV1[] = [];
	if (!Array.isArray(input.fields)) {
		errors.push(issue("TYPE_ARRAY", "/fields", "fields must be an array"));
	} else {
		if (input.fields.length > IWEB_LOG_FIELDS_MAX) {
			errors.push(issue("TOO_MANY_FIELDS", "/fields", "fields must contain at most " + IWEB_LOG_FIELDS_MAX + " entries"));
		}
		const seenKeys = new Set<string>();
		for (let index = 0; index < input.fields.length; index++) {
			const entry = input.fields[index];
			if (!isRecord(entry)) {
				errors.push(issue("TYPE_OBJECT", "/fields/" + index, "field must be an object"));
				continue;
			}
			rejectUnknownFields(entry, "/fields/" + index, ["key", "value"], errors);
			if (typeof entry.key !== "string" || !IWEB_LOG_FIELD_KEY_PATTERN.test(entry.key)) {
				errors.push(issue("INVALID_KEY", "/fields/" + index + "/key", "key must match ^[a-z][a-z0-9._-]{0,63}$"));
				continue;
			}
			if (seenKeys.has(entry.key)) {
				errors.push(issue("DUPLICATE_KEY", "/fields/" + index + "/key", "field keys must be unique"));
				continue;
			}
			seenKeys.add(entry.key);
			if (typeof entry.value !== "string") {
				errors.push(issue("TYPE_STRING", "/fields/" + index + "/value", "field value must be a string"));
				continue;
			}
			if (!isWellFormedIwebLoggingText(entry.value)) {
				errors.push(issue("UTF8_INVALID", "/fields/" + index + "/value", "field value must be well-formed UTF-8"));
				continue;
			}
			if (iwebUtf8ByteLength(entry.value) > IWEB_LOG_FIELD_VALUE_MAX_BYTES) {
				errors.push(issue("VALUE_TOO_LONG", "/fields/" + index + "/value", "field value must be at most " + IWEB_LOG_FIELD_VALUE_MAX_BYTES + " UTF-8 bytes"));
				continue;
			}
			fields.push({ key: entry.key, value: entry.value });
		}
	}

	if (errors.length) return failure(errors);
	return ok({ level: level as IwebLogLevel, message: message as string, fields });
}

// ---------------------------------------------------------------------------
// redaction 边界（先于大小计算、保留、monitor 投影与转发；原值绝不被保留）
// ---------------------------------------------------------------------------

// design.md §6 固定的 reserved 敏感字段 key 闭集；spec 允许「拒绝或替换为 [REDACTED]」，
// 本契约固定为「仅替换值」：key 进入诊断、值变成 [REDACTED]，原字符串不进入任何返回值。
export const IWEB_LOG_RESERVED_FIELD_KEYS = [
	"authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"api-key",
	"token",
	"secret",
	"password",
	"credential",
	"request-body",
	"sql",
	"kv",
	"config",
	"owner-key",
] as const;

export type IwebLoggingReservedFieldKey = (typeof IWEB_LOG_RESERVED_FIELD_KEYS)[number];
export const IWEB_LOG_REDACTED_VALUE = "[REDACTED]";

export function isReservedIwebLoggingFieldKey(key: string): key is IwebLoggingReservedFieldKey {
	return (IWEB_LOG_RESERVED_FIELD_KEYS as readonly string[]).includes(key);
}

// 纯函数：只替换 reserved key 的值，其余字段原样返回；返回数组不引用被替换的原始值字符串。
export function redactIwebLoggingFields(fields: readonly IwebLoggingFieldV1[]): IwebLoggingFieldV1[] {
	return fields.map((field) => (isReservedIwebLoggingFieldKey(field.key) ? { key: field.key, value: IWEB_LOG_REDACTED_VALUE } : { key: field.key, value: field.value }));
}

// ---------------------------------------------------------------------------
// 宿主元数据与被保留的诊断记录（字段闭集，无 audit 别名字段）
// ---------------------------------------------------------------------------

// UTC 强制 Z 后缀，不接受偏移量；时间戳、身份、代次全部由宿主注入，绝不来自 caller。
export const IWEB_LOG_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

export interface IwebLoggingHostContextV1 {
	readonly applicationId: string;
	readonly versionId: string;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
	readonly timestampUtc: string;
}

export function validateIwebLoggingHostContext(input: unknown): ValidationResult<IwebLoggingHostContextV1> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "host context must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["applicationId", "versionId", "preparationGeneration", "executionGeneration", "timestampUtc"], errors);
	if (typeof input.applicationId !== "string" || !OPAQUE_ID_PATTERN.test(input.applicationId)) {
		errors.push(issue("INVALID_IDENTIFIER", "/applicationId", "applicationId must be a lowercase opaque identifier"));
	}
	if (typeof input.versionId !== "string" || !WASM_VERSION_ID_PATTERN.test(input.versionId)) {
		errors.push(issue("INVALID_VERSION_ID", "/versionId", "versionId must be a wasm version identifier"));
	}
	for (const field of ["preparationGeneration", "executionGeneration"] as const) {
		const value = input[field];
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > WASM_U53_MAX) {
			errors.push(issue("INVALID_NUMBER", "/" + field, field + " must be an integer between 0 and " + WASM_U53_MAX));
		}
	}
	if (typeof input.timestampUtc !== "string" || !IWEB_LOG_TIMESTAMP_PATTERN.test(input.timestampUtc)) {
		errors.push(issue("INVALID_TIMESTAMP", "/timestampUtc", "timestampUtc must be an ISO-8601 UTC instant with a Z suffix"));
	}
	if (errors.length) return failure(errors);
	return ok({
		applicationId: input.applicationId as string,
		versionId: input.versionId as string,
		preparationGeneration: input.preparationGeneration as number,
		executionGeneration: input.executionGeneration as number,
		timestampUtc: input.timestampUtc as string,
	});
}

// spec「Logging is separate from audit and stdio」：被保留记录的字段闭集。
// 恰好是宿主注入的身份/时间戳 + caller 的 level/message/validated fields + 单调 eventId；
// 不存在 actor/action/authorization 等 Kernel audit 别名字段。
export const IWEB_LOG_RETAINED_RECORD_FIELDS = [
	"eventId",
	"timestampUtc",
	"applicationId",
	"versionId",
	"preparationGeneration",
	"executionGeneration",
	"level",
	"message",
	"fields",
] as const;

export interface IwebLoggingRetainedRecordV1 {
	readonly eventId: number;
	readonly timestampUtc: string;
	readonly applicationId: string;
	readonly versionId: string;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
	readonly level: IwebLogLevel;
	readonly message: string;
	readonly fields: readonly IwebLoggingFieldV1[];
}

// ---------------------------------------------------------------------------
// canonical 字节计量（redaction 先于计算）
// ---------------------------------------------------------------------------

function iwebLoggingDigitCount(value: number): number {
	return String(value).length;
}

// 确定性 canonical 口径（非 wire 编码承诺）：时间戳 + 身份 + 代次 + eventId 位数 + level + message +
// 每字段 key + 已 redact 的 value。内部先做 redaction，保证「redaction 先于大小计算」在结构上不可绕过。
export function measureIwebLoggingEventBytes(event: IwebLoggingEventV1, hostContext: IwebLoggingHostContextV1, eventId: number): number {
	const redactedFields = redactIwebLoggingFields(event.fields);
	let total =
		iwebUtf8ByteLength(hostContext.timestampUtc) +
		iwebUtf8ByteLength(hostContext.applicationId) +
		iwebUtf8ByteLength(hostContext.versionId) +
		iwebLoggingDigitCount(hostContext.preparationGeneration) +
		iwebLoggingDigitCount(hostContext.executionGeneration) +
		iwebLoggingDigitCount(eventId) +
		iwebUtf8ByteLength(event.level) +
		iwebUtf8ByteLength(event.message);
	for (const field of redactedFields) {
		total += iwebUtf8ByteLength(field.key) + iwebUtf8ByteLength(field.value);
	}
	return total;
}

// ---------------------------------------------------------------------------
// per-app 有界环（drop-on-full；dropped 计数；eventId 单调；reset 新生命周期）
// ---------------------------------------------------------------------------

export interface IwebLoggingRingCapacityV1 {
	readonly maxEvents: number;
	readonly maxBytes: number;
}

export function validateIwebLoggingRingCapacity(input: unknown): ValidationResult<IwebLoggingRingCapacityV1> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "ring capacity must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["maxEvents", "maxBytes"], errors);
	if (typeof input.maxEvents !== "number" || !Number.isSafeInteger(input.maxEvents) || input.maxEvents < 1 || input.maxEvents > IWEB_LOG_RING_MAX_EVENTS_CEILING) {
		errors.push(issue("INVALID_NUMBER", "/maxEvents", "maxEvents must be an integer between 1 and " + IWEB_LOG_RING_MAX_EVENTS_CEILING));
	}
	if (typeof input.maxBytes !== "number" || !Number.isSafeInteger(input.maxBytes) || input.maxBytes < 1 || input.maxBytes > IWEB_LOG_RING_MAX_BYTES_CEILING) {
		errors.push(issue("INVALID_NUMBER", "/maxBytes", "maxBytes must be an integer between 1 and " + IWEB_LOG_RING_MAX_BYTES_CEILING));
	}
	if (errors.length) return failure(errors);
	return ok({ maxEvents: input.maxEvents as number, maxBytes: input.maxBytes as number });
}

export interface IwebLoggingRingStateV1 {
	readonly applicationId: string;
	readonly capacity: IwebLoggingRingCapacityV1;
	readonly events: readonly IwebLoggingRetainedRecordV1[];
	readonly retainedBytes: number;
	readonly droppedCount: number;
	readonly nextEventId: number;
}

export function createIwebLoggingRing(applicationId: string, capacity: IwebLoggingRingCapacityV1): ValidationResult<IwebLoggingRingStateV1> {
	if (typeof applicationId !== "string" || !OPAQUE_ID_PATTERN.test(applicationId)) {
		return failure([issue("INVALID_IDENTIFIER", "/applicationId", "applicationId must be a lowercase opaque identifier")]);
	}
	const capacityResult = validateIwebLoggingRingCapacity(capacity);
	if (!capacityResult.ok) return capacityResult;
	return ok({ applicationId, capacity: capacityResult.value, events: [], retainedBytes: 0, droppedCount: 0, nextEventId: 1 });
}

// 重置语义：supervisor/wasmd 重启或执行代次替换后开启新生命周期——事件、dropped 计数与 eventId
// 全部归零重新开始。默认 profile 不做任何跨重启持久化声明（spec「Runtime restarts under default profile」）。
export function resetIwebLoggingRing(ring: IwebLoggingRingStateV1): IwebLoggingRingStateV1 {
	return { applicationId: ring.applicationId, capacity: ring.capacity, events: [], retainedBytes: 0, droppedCount: 0, nextEventId: 1 };
}

export interface IwebLoggingWriteOptionsV1 extends IwebLoggingEventValidationOptions {
	readonly maxEventBytes?: number;
}

export type IwebLoggingWriteResultV1 =
	| { readonly ok: true; readonly outcome: "accepted"; readonly ring: IwebLoggingRingStateV1; readonly record: IwebLoggingRetainedRecordV1 }
	// dropped：事件未被保留，不是 audit 确认；请求不被阻塞、不重试，环内既有事件不被驱逐。
	| { readonly ok: true; readonly outcome: "dropped"; readonly ring: IwebLoggingRingStateV1 }
	| { readonly ok: false; readonly code: IwebLoggingWireErrorCode; readonly issues: readonly ValidationIssue[] };

// WIT write 的纯函数投影：校验 → redact →（含宿主元数据的）大小计量 → per-event 上限 → 环准入。
// 纯不可变：输入 ring 不被修改；dropped 只递增计数并立即返回。
export function writeIwebLoggingEvent(
	ring: IwebLoggingRingStateV1,
	hostContext: unknown,
	input: unknown,
	options: IwebLoggingWriteOptionsV1 = {},
): IwebLoggingWriteResultV1 {
	const host = validateIwebLoggingHostContext(hostContext);
	if (!host.ok) {
		// 宿主元数据由宿主注入，畸形容器/时间戳是宿主侧 internal 故障，不是组件错误。
		return { ok: false, code: "IWEB_LOG_INTERNAL", issues: host.errors };
	}
	if (host.value.applicationId !== ring.applicationId) {
		return { ok: false, code: "IWEB_LOG_APP_ISOLATION", issues: [issue("IWEB_LOG_APP_ISOLATION", "/applicationId", "host context does not own this application ring")] };
	}

	const maxEventBytes = options.maxEventBytes ?? IWEB_LOG_EVENT_MAX_BYTES_DEFAULT;
	if (typeof maxEventBytes !== "number" || !Number.isSafeInteger(maxEventBytes) || maxEventBytes < 1 || maxEventBytes > IWEB_LOG_EVENT_MAX_BYTES_CEILING) {
		return { ok: false, code: "IWEB_LOG_INTERNAL", issues: [issue("INVALID_NUMBER", "/maxEventBytes", "maxEventBytes must be an integer between 1 and " + IWEB_LOG_EVENT_MAX_BYTES_CEILING)] };
	}

	const event = validateIwebLoggingEvent(input, options);
	if (!event.ok) return { ok: false, code: iwebLoggingWireErrorFromIssues(event.errors), issues: event.errors };

	const eventId = ring.nextEventId;
	const eventBytes = measureIwebLoggingEventBytes(event.value, host.value, eventId);
	if (eventBytes > maxEventBytes) {
		return { ok: false, code: "IWEB_LOG_LIMIT_EXCEEDED", issues: [issue("EVENT_TOO_LARGE", "", "encoded event including host metadata exceeds the pinned maxEventBytes")] };
	}

	if (ring.events.length >= ring.capacity.maxEvents || ring.retainedBytes + eventBytes > ring.capacity.maxBytes) {
		return { ok: true, outcome: "dropped", ring: { ...ring, droppedCount: ring.droppedCount + 1 } };
	}

	const record: IwebLoggingRetainedRecordV1 = {
		eventId,
		timestampUtc: host.value.timestampUtc,
		applicationId: host.value.applicationId,
		versionId: host.value.versionId,
		preparationGeneration: host.value.preparationGeneration,
		executionGeneration: host.value.executionGeneration,
		level: event.value.level,
		message: event.value.message,
		fields: redactIwebLoggingFields(event.value.fields),
	};
	return {
		ok: true,
		outcome: "accepted",
		ring: { ...ring, events: [...ring.events, record], retainedBytes: ring.retainedBytes + eventBytes, nextEventId: eventId + 1 },
		record,
	};
}

// ---------------------------------------------------------------------------
// owner 授权 drain/stream 与 monitor 投影（只暴露本应用 bounded 记录）
// ---------------------------------------------------------------------------

export const IWEB_LOG_DRAIN_MAX_EVENTS_LIMIT = 1000;

export interface IwebLoggingDrainRequestV1 {
	readonly schemaVersion: 1;
	readonly applicationId: string;
	// stream = 携带游标的重复 drain；游标是上一响应的 lastEventId。
	readonly afterEventId: number;
	readonly maxEvents: number;
}

export function validateIwebLoggingDrainRequest(input: unknown): ValidationResult<IwebLoggingDrainRequestV1> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "drain request must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["schemaVersion", "applicationId", "afterEventId", "maxEvents"], errors);
	if (input.schemaVersion !== 1) {
		errors.push(issue("INVALID_SCHEMA_VERSION", "/schemaVersion", "schemaVersion must be the literal 1"));
	}
	if (typeof input.applicationId !== "string" || !OPAQUE_ID_PATTERN.test(input.applicationId)) {
		errors.push(issue("INVALID_IDENTIFIER", "/applicationId", "applicationId must be a lowercase opaque identifier"));
	}
	if (typeof input.afterEventId !== "number" || !Number.isSafeInteger(input.afterEventId) || input.afterEventId < 0) {
		errors.push(issue("INVALID_NUMBER", "/afterEventId", "afterEventId must be a non-negative safe integer"));
	}
	if (typeof input.maxEvents !== "number" || !Number.isSafeInteger(input.maxEvents) || input.maxEvents < 1 || input.maxEvents > IWEB_LOG_DRAIN_MAX_EVENTS_LIMIT) {
		errors.push(issue("INVALID_NUMBER", "/maxEvents", "maxEvents must be an integer between 1 and " + IWEB_LOG_DRAIN_MAX_EVENTS_LIMIT));
	}
	if (errors.length) return failure(errors);
	return ok({ schemaVersion: 1, applicationId: input.applicationId as string, afterEventId: input.afterEventId as number, maxEvents: input.maxEvents as number });
}

export interface IwebLoggingDrainResponseV1 {
	readonly schemaVersion: 1;
	readonly applicationId: string;
	readonly events: readonly IwebLoggingRetainedRecordV1[];
	readonly droppedCount: number;
	readonly hasMore: boolean;
	readonly lastEventId: number;
}

export type IwebLoggingDrainResult = { readonly ok: true; readonly response: IwebLoggingDrainResponseV1 } | { readonly ok: false; readonly code: IwebLoggingWireErrorCode; readonly issues: readonly ValidationIssue[] };

// drain 只返回请求应用自己的 bounded 保留记录；applicationId 与环属主不一致是隔离违约（fail-closed）。
export function drainIwebLoggingRing(ring: IwebLoggingRingStateV1, request: unknown): IwebLoggingDrainResult {
	const parsed = validateIwebLoggingDrainRequest(request);
	if (!parsed.ok) return { ok: false, code: iwebLoggingWireErrorFromIssues(parsed.errors), issues: parsed.errors };
	if (parsed.value.applicationId !== ring.applicationId) {
		return { ok: false, code: "IWEB_LOG_APP_ISOLATION", issues: [issue("IWEB_LOG_APP_ISOLATION", "/applicationId", "drain request does not own this application ring")] };
	}
	const eligible = ring.events.filter((record) => record.eventId > parsed.value.afterEventId);
	const selected = eligible.slice(0, parsed.value.maxEvents);
	return {
		ok: true,
		response: {
			schemaVersion: 1,
			applicationId: ring.applicationId,
			events: selected,
			droppedCount: ring.droppedCount,
			hasMore: selected.length < eligible.length,
			lastEventId: ring.nextEventId - 1,
		},
	};
}

// monitor 投影（用量面）：只有计数与水位，没有任何日志正文。droppedCount 是显式测量值，
// 不是缺失 cgroup/重启状态的替身（「unavailable 不做零替换」法由宿主侧可用性语义承担）。
export interface IwebLoggingMonitorSummaryV1 {
	readonly applicationId: string;
	readonly retainedEvents: number;
	readonly retainedBytes: number;
	readonly droppedCount: number;
	readonly lastEventId: number;
	readonly capacity: IwebLoggingRingCapacityV1;
}

export function projectIwebLoggingMonitorSummary(ring: IwebLoggingRingStateV1): IwebLoggingMonitorSummaryV1 {
	return {
		applicationId: ring.applicationId,
		retainedEvents: ring.events.length,
		retainedBytes: ring.retainedBytes,
		droppedCount: ring.droppedCount,
		lastEventId: ring.nextEventId - 1,
		capacity: ring.capacity,
	};
}

// ---------------------------------------------------------------------------
// owner 授权外部转发配置 wire（默认关、fail-closed）
// ---------------------------------------------------------------------------

export const IWEB_LOG_FORWARDING_FORMATS = ["json-lines", "syslog"] as const;
export type IwebLoggingForwardingFormat = (typeof IWEB_LOG_FORWARDING_FORMATS)[number];

// 端点 grammar：`host:port`。host 是 DNS 名称或 IPv4 literal（允许 loopback）；无 scheme、无 userinfo、
// 无 path、无 query、无 IPv6/括号（fail-closed 拒绝而非改写）；port 是 1..65535。
const IWEB_LOG_FORWARDING_HOST_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*|\d{1,3}(?:\.\d{1,3}){3})$/;

export function isValidIwebLoggingForwardingEndpoint(endpoint: string): boolean {
	const separator = endpoint.lastIndexOf(":");
	if (separator < 0) return false;
	const host = endpoint.slice(0, separator);
	const port = endpoint.slice(separator + 1);
	if (!/^\d{1,5}$/.test(port)) return false;
	const portNumber = Number(port);
	if (portNumber < 1 || portNumber > 65535) return false;
	if (host.length < 1 || host.length > 253 || host === "localhost") return false;
	if (!IWEB_LOG_FORWARDING_HOST_PATTERN.test(host)) return false;
	if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
		for (const octet of host.split(".")) {
			if (Number(octet) > 255) return false;
		}
	}
	return true;
}

export interface IwebLoggingForwardingConfigV1 {
	readonly schemaVersion: 1;
	// 默认关：无 owner 显式开启时，节点不向任何外部端点发送日志（fail-closed，无环境/路径回退）。
	readonly enabled: boolean;
	readonly format: IwebLoggingForwardingFormat | null;
	readonly endpoint: string | null;
}

export const IWEB_LOG_FORWARDING_DEFAULT: IwebLoggingForwardingConfigV1 = Object.freeze({ schemaVersion: 1, enabled: false, format: null, endpoint: null });

// null/undefined 视为缺省关闭；对象形状必须精确：enabled:false 时不得携带 format/endpoint；
// enabled:true 时必须携带合法 format 与 endpoint。未知字段、错误 schemaVersion、畸形端点一律拒绝。
export function validateIwebLoggingForwardingConfig(input: unknown): ValidationResult<IwebLoggingForwardingConfigV1> {
	if (input === null || input === undefined) return ok(IWEB_LOG_FORWARDING_DEFAULT);
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "forwarding config must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["schemaVersion", "enabled", "format", "endpoint"], errors);
	if (input.schemaVersion !== 1) {
		errors.push(issue("INVALID_SCHEMA_VERSION", "/schemaVersion", "schemaVersion must be the literal 1"));
	}
	if (typeof input.enabled !== "boolean") {
		errors.push(issue("TYPE_BOOLEAN", "/enabled", "enabled must be a boolean"));
	}
	if (errors.length) return failure(errors);

	if (!input.enabled) {
		const leftovers: ValidationIssue[] = [];
		if (input.format !== undefined && input.format !== null) leftovers.push(issue("FORBIDDEN_WHEN_DISABLED", "/format", "format must be null when forwarding is disabled"));
		if (input.endpoint !== undefined && input.endpoint !== null) leftovers.push(issue("FORBIDDEN_WHEN_DISABLED", "/endpoint", "endpoint must be null when forwarding is disabled"));
		if (leftovers.length) return failure(leftovers);
		return ok({ schemaVersion: 1, enabled: false, format: null, endpoint: null });
	}

	if (typeof input.format !== "string" || !(IWEB_LOG_FORWARDING_FORMATS as readonly string[]).includes(input.format)) {
		errors.push(issue("INVALID_FORMAT", "/format", "format must be one of " + IWEB_LOG_FORWARDING_FORMATS.join("|")));
	}
	if (typeof input.endpoint !== "string" || !isValidIwebLoggingForwardingEndpoint(input.endpoint)) {
		errors.push(issue("INVALID_ENDPOINT", "/endpoint", "endpoint must be host:port with a DNS or IPv4 host and a 1..65535 port"));
	}
	if (errors.length) return failure(errors);
	return ok({ schemaVersion: 1, enabled: true, format: input.format as IwebLoggingForwardingFormat, endpoint: input.endpoint as string });
}

// 后端故障的合法 wire 码闭集：backend 失败返回 unavailable/internal，绝不回退到 stdout/stderr/audit/无界本地文件。
export const IWEB_LOG_FORWARDING_FAILURE_WIRE_CODES = ["IWEB_LOG_UNAVAILABLE", "IWEB_LOG_INTERNAL"] as const;

// ---------------------------------------------------------------------------
// sink 法：audit/stdio 隔离的闭集判定
// ---------------------------------------------------------------------------

export const IWEB_LOG_ALLOWED_SINKS = ["memory-ring", "monitor-projection", "owner-forwarding"] as const;
// kernel-audit/stdout/stderr 永远不是 iweb:logging 的别名、回退或合并目标；无界文件与隐式 RustFS 持久化同禁。
export const IWEB_LOG_FORBIDDEN_SINKS = ["kernel-audit", "stdout", "stderr", "unbounded-file", "implicit-rustfs"] as const;

export function iwebLoggingSinkErrorCode(sink: string): "IWEB_LOG_SINK_FORBIDDEN" | null {
	return (IWEB_LOG_FORBIDDEN_SINKS as readonly string[]).includes(sink) ? "IWEB_LOG_SINK_FORBIDDEN" : null;
}
