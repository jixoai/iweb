// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：logging 的 owner 面——
//   drain/stream 端点（经 supervisor server 既有授权/token 面）、monitor summary 投影
//   （复用 wasm-health 的 executionMetrics 采样模式）、转发配置的宿主装载（默认关 fail-closed）。
// 终审缺口修正（2026-08-28，双台账统一）：环的唯一权威是 wasmd 进程内的 per-app ring
//   （kernel-rs/wasmd host_services/logging.rs LoggingRing）；supervisor 不再维护任何本地环台账。
//   本文件把 owner 面改为「拉取式投影」：drain/summary 先做与权威无关的 wire/隔离校验，
//   然后向注入的 WasmLoggingProjectionSource 拉取 wasmd 的投影（drain response / monitor
//   summary wire），对权威答案做闭集 + 文法 + redaction 边界 + 分页不变量复验后才回给 owner。
//   权威不可达/未接线 → 显式 503 WASM_LOG_AUTHORITY_UNAVAILABLE；权威答案畸形 → 显式 503
//   WASM_LOG_AUTHORITY_WIRE_INVALID（fail-closed，绝不部分返回）；绝不从本地空环合成 404/200。
// 形态取舍（报告项）：任务给了两种统一形态——(a) supervisor 经 /v1/host-logging/drain/
//   <applicationId> 从 wasmd 拉取事件投影；(b) supervisor 侧维护与 wasmd 一致的投影缓存。
//   本层选 (a) 的无缓存拉取式：缓存形态要求 supervisor 复刻 wasmd 的生命周期重置/drop 计量/
//   eventId 连续性，天然存在再分叉为第二权威的风险，且 L1 profile 明确「不做跨重启持久化
//   声明」——缓存会让事件存活超过 wasmd 生命周期，违反 spec 的当前生命周期限定。拉取式让
//   wasmd 保持唯一权威、supervisor 无状态；代价是权威进程不可达时诊断面 503（诚实暴露，
//   不是缺陷）。wasmd 侧 HTTP 端点（Rust 5.x/6.x）落地后注入 fetch 版 source 即可，HTTP
//   语义与本文件不变。
// 正交意图：
//   1. 宿主装载 owner 授权外部转发配置 wire（IWEB_WASM_LOG_FORWARDING_FILE；缺省=默认关闭；
//      文件必须严格 JSON + JCS 规范字节 + validateIwebLoggingForwardingConfig 全过，否则 fail-closed）；
//   2. 权威投影的消费面复验（retained record / drain response / monitor summary 三层 wire
//      校验全部在本文件；闭集键、事件文法、redaction 边界、单调 eventId、游标与分页不变量）；
//   3. owner 面 HTTP 语义（drain/stream + summary）：与 execution-rpc 同款 framing 纪律
//      （方法/路径/大小/content-type/JSON/未知路由），错误码稳定，未配置 503、未知应用 404、
//      隔离违约 403、权威不可用 503，绝不部分解析、绝不下降为 celld 通道。
// 规范权威：openspec/changes/add-wasm-host-services/specs/wasm-host-logging/spec.md
//   「Logging retention and durability are profile-bound」（L1：bounded memory ring + monitor
//   投影 + owner 授权外部转发，默认关；「retain accepted events only in a bounded
//   per-application in-memory ring ... for the current runtime lifecycle」）。
// 接线边界（本文件刻意不做的部分）：
//   - wasmd 内嵌 provider（Rust 任务 5.x/6.x）尚未在其 ingress 上暴露 drain/summary HTTP
//     端点（Rust DrainResponse/MonitorSummary 也无 serde wire）；因此本仓库尚无生产 source
//     实现。source 是类型化 seam：测试注入内存权威，wasmd 端点落地后注入 HTTP client。
//   - 转发 worker（向外部端点发送日志）不在本批：本批只做配置装载与暴露（默认关）；
//   - 不挂任何未授权路由：所有端点都在 supervisor 私有 socket 的既有 requestAuthorization
//     （relay 进程期凭据）之下，没有第二个无认证入口（spec「no second unauthenticated entrance」）。
import {
	createIwebLoggingRing,
	drainIwebLoggingRing,
	IWEB_LOG_FORWARDING_DEFAULT,
	redactIwebLoggingFields,
	validateIwebLoggingDrainRequest,
	validateIwebLoggingEvent,
	validateIwebLoggingForwardingConfig,
	writeIwebLoggingEvent,
	type IwebLoggingDrainRequestV1,
	type IwebLoggingDrainResponseV1,
	type IwebLoggingForwardingConfigV1,
	type IwebLoggingHostContextV1,
	type IwebLoggingMonitorSummaryV1,
	type IwebLoggingRetainedRecordV1,
	type IwebLoggingRingCapacityV1,
	type IwebLoggingRingStateV1,
} from "../packages/contracts/wasm-host-logging.ts";
import { jcsCanonicalBytes, parseStrictJson } from "../packages/contracts/wasm-package.ts";
import { OPAQUE_ID_PATTERN, type ValidationIssue } from "../packages/contracts/validation.ts";
import {
	DEFAULT_MAX_REQUEST_BYTES,
	isJsonContentType,
} from "../packages/contracts/protocol-server.ts";
import { systemWasmServeIO, type WasmServeIO } from "./wasm-serve.ts";

// ---------------------------------------------------------------------------
// 稳定错误码与路径（owner 可见；沿用 wasm 系命名风格）
// ---------------------------------------------------------------------------

export const WASM_LOG_FACE_NOT_CONFIGURED = "WASM_LOG_FACE_NOT_CONFIGURED";
export const WASM_LOG_APPLICATION_UNKNOWN = "WASM_LOG_APPLICATION_UNKNOWN";
export const WASM_LOG_DRAIN_REQUEST_INVALID = "WASM_LOG_DRAIN_REQUEST_INVALID";
export const WASM_LOG_FORWARDING_CONFIG_INVALID = "WASM_LOG_FORWARDING_CONFIG_INVALID";
/** 权威（wasmd ring 投影源）未接线或不可达：显式 unavailable，绝不用本地台账顶替。 */
export const WASM_LOG_AUTHORITY_UNAVAILABLE = "WASM_LOG_AUTHORITY_UNAVAILABLE";
/** 权威答案未通过消费面复验（畸形/隔离/redaction 违约）：fail-closed 整体拒绝，绝不部分返回。 */
export const WASM_LOG_AUTHORITY_WIRE_INVALID = "WASM_LOG_AUTHORITY_WIRE_INVALID";

export const WASM_HOST_LOGGING_DRAIN_PATH = "/v1/host-logging/drain";
export const WASM_HOST_LOGGING_SUMMARY_PATH = "/v1/host-logging/summary";

// applicationId 文法与契约 drain wire 同源（小写字母数字与连字符，<=63 ASCII 字节）；
// 路径段先于权威查询判定（非法即 404，不进入 source）。
const APPLICATION_ID_PATH_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

export class WasmLoggingServeError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.name = "WasmLoggingServeError";
		this.code = code;
	}
}

// ---------------------------------------------------------------------------
// 转发配置的宿主装载（默认关、fail-closed）
// ---------------------------------------------------------------------------

export const IWEB_WASM_LOG_FORWARDING_FILE_ENV = "IWEB_WASM_LOG_FORWARDING_FILE";

/**
 * 宿主装载 owner 授权外部转发配置：
 * - 环境变量未设置/空白 → IWEB_LOG_FORWARDING_DEFAULT（enabled:false，无 format/endpoint）；
 * - 设置 → 必须是绝对路径；文件必须严格 JSON、字节与 JCS(parse) 一致、且通过
 *   validateIwebLoggingForwardingConfig（enabled:false 不得携带 format/endpoint；enabled:true
 *   必须携带合法 format 与 host:port endpoint）。任一不过 → fail-closed 抛出
 *   WASM_LOG_FORWARDING_CONFIG_INVALID（supervisor 启动失败），绝不带病降级为「关」以外的任何状态。
 */
export function loadIwebLoggingForwardingConfig(
	io: WasmServeIO,
	environment: Readonly<Record<string, string | undefined>>,
): IwebLoggingForwardingConfigV1 {
	const configured = environment[IWEB_WASM_LOG_FORWARDING_FILE_ENV]?.trim();
	if (configured === undefined || configured.length === 0) return IWEB_LOG_FORWARDING_DEFAULT;
	if (!configured.startsWith("/")) {
		throw new WasmLoggingServeError(
			WASM_LOG_FORWARDING_CONFIG_INVALID,
			IWEB_WASM_LOG_FORWARDING_FILE_ENV + " must be an absolute path when set",
		);
	}
	const text = io.readFile(configured);
	if (text === null) {
		throw new WasmLoggingServeError(
			WASM_LOG_FORWARDING_CONFIG_INVALID,
			"the logging forwarding config file is missing: " + configured,
		);
	}
	const parsed = parseStrictJson(text);
	if (!parsed.ok) {
		throw new WasmLoggingServeError(
			WASM_LOG_FORWARDING_CONFIG_INVALID,
			"the logging forwarding config file is not strict JSON: " + configured,
		);
	}
	if (Buffer.from(jcsCanonicalBytes(parsed.value)).toString("utf8") !== text) {
		throw new WasmLoggingServeError(
			WASM_LOG_FORWARDING_CONFIG_INVALID,
			"the logging forwarding config file bytes are not canonical JCS: " + configured,
		);
	}
	const validated = validateIwebLoggingForwardingConfig(parsed.value);
	if (!validated.ok) {
		const first = validated.errors[0];
		throw new WasmLoggingServeError(
			WASM_LOG_FORWARDING_CONFIG_INVALID,
			"the logging forwarding config failed validation at " +
				(first ? first.path : "") +
				": " +
				(first ? first.message : "unknown issue"),
		);
	}
	return validated.value;
}

// ---------------------------------------------------------------------------
// 权威投影源：wasmd 进程内 ring 的唯一读取面（双台账统一后的 seam）
// ---------------------------------------------------------------------------

/**
 * 权威对一次投影查询的答案：
 * - ok:true value —— 权威返回的投影 wire（由消费面复验后才能透出）；
 * - ok:false reason:"unknown-application" —— 权威证明该应用无环（→ 404）；
 * - ok:false reason:"unavailable" —— 权威不可达/未接线/暂不可证明（→ 503，绝不合成数据）。
 */
export type WasmLoggingProjectionOutcome<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly reason: "unknown-application" | "unavailable" };

/**
 * wasmd ring 投影源（唯一权威读取面）。生产实现拨 wasmd ingress 的 owner-drain 端点
 * （Rust 5.x/6.x 接线）；本层只依赖该 port 的类型与语义，不猜 wire、不缓存、不自建台账。
 */
export interface WasmLoggingProjectionSource {
	drain(
		applicationId: string,
		request: IwebLoggingDrainRequestV1,
	): Promise<WasmLoggingProjectionOutcome<IwebLoggingDrainResponseV1>>;
	monitorSummary(
		applicationId: string,
	): Promise<WasmLoggingProjectionOutcome<IwebLoggingMonitorSummaryV1>>;
}

// ---------------------------------------------------------------------------
// 权威投影的消费面复验（闭集 + 文法 + redaction 边界 + 分页/游标不变量）
// ---------------------------------------------------------------------------

const WIRE_CODE = WASM_LOG_AUTHORITY_WIRE_INVALID;
const RETAINED_RECORD_KEYS = [
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

function wireIssue(path: string, message: string): ValidationIssue {
	return { code: WIRE_CODE, path, message };
}

function isRecordShape(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireWireU53(value: unknown, path: string, issues: ValidationIssue[], minimum = 0): number | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > Number.MAX_SAFE_INTEGER) {
		issues.push(wireIssue(path, "must be a u53 safe integer >= " + minimum));
		return null;
	}
	return value;
}

/**
 * retained record 消费面复验：精确键集 + 宿主元数据文法 + caller 三字段走契约事件校验
 * （level 闭集、message/fields 界、唯一 key）+ redaction 边界（reserved key 的值必须已是
 * [REDACTED]——任何残留原值都说明权威侧 redaction 被绕过，整体拒绝）。
 */
export function validateIwebLoggingRetainedRecordWireV1(
	input: unknown,
	issues: ValidationIssue[],
	path: string,
): IwebLoggingRetainedRecordV1 | null {
	if (!isRecordShape(input)) {
		issues.push(wireIssue(path, "retained record must be an object"));
		return null;
	}
	for (const key of Object.keys(input)) {
		if (!(RETAINED_RECORD_KEYS as readonly string[]).includes(key)) {
			issues.push(wireIssue(path + "/" + key, "unknown field is not allowed in a retained record"));
		}
	}
	for (const key of RETAINED_RECORD_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) {
			issues.push(wireIssue(path + "/" + key, "required field is missing in a retained record"));
		}
	}
	const eventId = requireWireU53(input.eventId, path + "/eventId", issues, 1);
	if (typeof input.timestampUtc !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(input.timestampUtc)) {
		issues.push(wireIssue(path + "/timestampUtc", "timestampUtc must be an ISO-8601 UTC instant with a Z suffix"));
	}
	if (typeof input.applicationId !== "string" || !OPAQUE_ID_PATTERN.test(input.applicationId)) {
		issues.push(wireIssue(path + "/applicationId", "applicationId must be a lowercase opaque identifier"));
	}
	const versionIdOk = typeof input.versionId === "string";
	if (!versionIdOk) issues.push(wireIssue(path + "/versionId", "versionId must be a string"));
	const preparation = requireWireU53(input.preparationGeneration, path + "/preparationGeneration", issues);
	const execution = requireWireU53(input.executionGeneration, path + "/executionGeneration", issues);
	const event = validateIwebLoggingEvent(
		typeof input.level === "string" && typeof input.message === "string" && Array.isArray(input.fields)
			? { level: input.level, message: input.message, fields: input.fields }
			: null,
	);
	if (!event.ok) {
		for (const error of event.errors) issues.push(wireIssue(path + error.path, error.message));
	}
	if (
		issues.length ||
		eventId === null ||
		typeof input.timestampUtc !== "string" ||
		typeof input.applicationId !== "string" ||
		typeof input.versionId !== "string" ||
		preparation === null ||
		execution === null ||
		!event.ok
	) {
		return null;
	}
	const record: IwebLoggingRetainedRecordV1 = {
		eventId,
		timestampUtc: input.timestampUtc,
		applicationId: input.applicationId,
		versionId: input.versionId,
		preparationGeneration: preparation,
		executionGeneration: execution,
		level: event.value.level,
		message: event.value.message,
		fields: event.value.fields,
	};
	// redaction 边界：权威侧必须在保留前完成 redaction；reserved key 携带任何非 [REDACTED]
	// 值都是边界违约（原值泄漏），整份投影拒绝。
	const redacted = redactIwebLoggingFields(record.fields);
	if (JSON.stringify(redacted) !== JSON.stringify(record.fields)) {
		issues.push(wireIssue(path + "/fields", "a reserved field key carries an unredacted value; the redaction boundary was violated"));
		return null;
	}
	return record;
}

/**
 * drain response 消费面复验：精确键集 + applicationId 归属 + eventId 严格单调递增 +
 * 游标不变量（每个 eventId 都必须 > 请求 afterEventId）+ 分页不变量（条数 <= 请求
 * maxEvents）+ lastEventId 不早于最后一条事件。任何违约整份拒绝（绝不部分透出）。
 */
export function validateIwebLoggingDrainResponseWireV1(
	input: unknown,
	request: IwebLoggingDrainRequestV1,
): { readonly ok: true; readonly response: IwebLoggingDrainResponseV1 } | { readonly ok: false; readonly issues: readonly ValidationIssue[] } {
	const issues: ValidationIssue[] = [];
	if (!isRecordShape(input)) {
		return { ok: false, issues: [wireIssue("", "drain response must be an object")] };
	}
	for (const key of Object.keys(input)) {
		if (key !== "schemaVersion" && key !== "applicationId" && key !== "events" && key !== "droppedCount" && key !== "hasMore" && key !== "lastEventId") {
			issues.push(wireIssue("/" + key, "unknown field is not allowed in a drain response"));
		}
	}
	for (const key of ["schemaVersion", "applicationId", "events", "droppedCount", "hasMore", "lastEventId"] as const) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) {
			issues.push(wireIssue("/" + key, "required field is missing in a drain response"));
		}
	}
	if (input.schemaVersion !== 1) issues.push(wireIssue("/schemaVersion", "schemaVersion must be the literal 1"));
	if (input.applicationId !== request.applicationId) {
		issues.push(wireIssue("/applicationId", "the drain response belongs to another application"));
	}
	const droppedCount = requireWireU53(input.droppedCount, "/droppedCount", issues);
	const lastEventId = requireWireU53(input.lastEventId, "/lastEventId", issues);
	if (typeof input.hasMore !== "boolean") issues.push(wireIssue("/hasMore", "hasMore must be a boolean"));
	if (!Array.isArray(input.events)) {
		issues.push(wireIssue("/events", "events must be an array"));
		return { ok: false, issues };
	}
	if (input.events.length > request.maxEvents) {
		issues.push(wireIssue("/events", "the authority returned more events than the request maximum"));
	}
	const events: IwebLoggingRetainedRecordV1[] = [];
	let previousEventId = 0;
	for (let index = 0; index < input.events.length; index += 1) {
		const record = validateIwebLoggingRetainedRecordWireV1(input.events[index], issues, "/events/" + index);
		if (record === null) continue;
		if (record.applicationId !== request.applicationId) {
			issues.push(wireIssue("/events/" + index + "/applicationId", "a retained record belongs to another application"));
			continue;
		}
		if (record.eventId <= previousEventId) {
			issues.push(wireIssue("/events/" + index + "/eventId", "retained event ids must strictly increase within one drain response"));
			continue;
		}
		if (record.eventId <= request.afterEventId) {
			issues.push(wireIssue("/events/" + index + "/eventId", "the authority returned an event at or before the request cursor"));
			continue;
		}
		previousEventId = record.eventId;
		events.push(record);
	}
	if (lastEventId !== null && events.length > 0 && lastEventId < events[events.length - 1]!.eventId) {
		issues.push(wireIssue("/lastEventId", "lastEventId must not precede the last returned event"));
	}
	if (issues.length || droppedCount === null || lastEventId === null) return { ok: false, issues };
	return {
		ok: true,
		response: { schemaVersion: 1, applicationId: request.applicationId, events, droppedCount, hasMore: input.hasMore as boolean, lastEventId },
	};
}

/** monitor summary 消费面复验：精确键集 + 归属 + 计数/水位 u53；无日志正文字段可出现。 */
export function validateIwebLoggingMonitorSummaryWireV1(
	input: unknown,
	applicationId: string,
): { readonly ok: true; readonly summary: IwebLoggingMonitorSummaryV1 } | { readonly ok: false; readonly issues: readonly ValidationIssue[] } {
	const issues: ValidationIssue[] = [];
	if (!isRecordShape(input)) {
		return { ok: false, issues: [wireIssue("", "monitor summary must be an object")] };
	}
	for (const key of Object.keys(input)) {
		if (key !== "applicationId" && key !== "retainedEvents" && key !== "retainedBytes" && key !== "droppedCount" && key !== "lastEventId" && key !== "capacity") {
			issues.push(wireIssue("/" + key, "unknown field is not allowed in a monitor summary"));
		}
	}
	for (const key of ["applicationId", "retainedEvents", "retainedBytes", "droppedCount", "lastEventId", "capacity"] as const) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) {
			issues.push(wireIssue("/" + key, "required field is missing in a monitor summary"));
		}
	}
	if (input.applicationId !== applicationId) {
		issues.push(wireIssue("/applicationId", "the monitor summary belongs to another application"));
	}
	const retainedEvents = requireWireU53(input.retainedEvents, "/retainedEvents", issues);
	const retainedBytes = requireWireU53(input.retainedBytes, "/retainedBytes", issues);
	const droppedCount = requireWireU53(input.droppedCount, "/droppedCount", issues);
	const lastEventId = requireWireU53(input.lastEventId, "/lastEventId", issues);
	const capacity = isRecordShape(input.capacity) ? input.capacity : null;
	if (capacity === null) {
		issues.push(wireIssue("/capacity", "capacity must be an object"));
	} else {
		for (const key of Object.keys(capacity)) {
			if (key !== "maxEvents" && key !== "maxBytes") issues.push(wireIssue("/capacity/" + key, "unknown field is not allowed in ring capacity"));
		}
		if (typeof capacity.maxEvents !== "number" || typeof capacity.maxBytes !== "number") {
			issues.push(wireIssue("/capacity", "maxEvents and maxBytes must be present numbers"));
		}
	}
	if (issues.length || retainedEvents === null || retainedBytes === null || droppedCount === null || lastEventId === null || capacity === null) {
		return { ok: false, issues };
	}
	return {
		ok: true,
		summary: {
			applicationId,
			retainedEvents,
			retainedBytes,
			droppedCount,
			lastEventId,
			capacity: { maxEvents: capacity.maxEvents as number, maxBytes: capacity.maxBytes as number },
		},
	};
}

// ---------------------------------------------------------------------------
// owner 面 HTTP 语义（drain/stream + summary；wasm-health executionMetrics 同款接线模式）
// ---------------------------------------------------------------------------

export interface WasmLoggingDrainHttpRequest {
	readonly method: string;
	readonly path: string;
	readonly contentType: string | null;
	readonly body: Buffer;
}

export interface WasmLoggingHttpFaceResult {
	readonly status: number;
	readonly body: string;
}

export interface WasmLoggingOwnerFace {
	/** owner 授权 drain/stream（stream = 携带游标 afterEventId 的重复 drain）；从权威拉取。 */
	drain(applicationId: string, body: unknown): Promise<WasmLoggingHttpFaceResult>;
	/** monitor summary 投影（仅计数/水位；从权威拉取；未知应用 404、不可用 503）。 */
	summary(applicationId: string): Promise<WasmLoggingHttpFaceResult>;
	/** 已装载的转发配置（默认关；装载失败在装配期 fail-closed）。 */
	readonly forwardingConfig: IwebLoggingForwardingConfigV1;
}

function faceJson(status: number, body: object): WasmLoggingHttpFaceResult {
	return { status, body: JSON.stringify(body) + "\n" };
}

function faceError(status: number, code: string, message: string): WasmLoggingHttpFaceResult {
	return faceJson(status, { ok: false, code, message });
}

/**
 * 从权威投影源装配 owner 面（main.ts 与测试共用；source 为注入的 seam，null = 权威未接线）。
 * supervisor 自身不持有任何环状态：两次 drain 之间只有权威知道事件。
 */
export function createWasmLoggingOwnerFace(
	source: WasmLoggingProjectionSource | null,
	forwardingConfig: IwebLoggingForwardingConfigV1,
): WasmLoggingOwnerFace {
	return {
		forwardingConfig,
		drain: async (applicationId, body) => {
			// 路径 applicationId 与 wire applicationId 必须一致：不一致即跨应用隔离违约（403），
			// 与权威侧的环属主判定构成双重防线（本检查不依赖权威可达性）。
			const parsed = validateIwebLoggingDrainRequest(body);
			if (!parsed.ok) {
				return faceError(
					400,
					WASM_LOG_DRAIN_REQUEST_INVALID,
					"the logging drain request failed wire validation",
				);
			}
			if (parsed.value.applicationId !== applicationId) {
				return faceError(
					403,
					"IWEB_LOG_APP_ISOLATION",
					"the drain request names a different application than the drain target",
				);
			}
			if (source === null) {
				return faceError(
					503,
					WASM_LOG_AUTHORITY_UNAVAILABLE,
					"the wasmd logging ring authority is not wired into this supervisor build; no local ledger may substitute for it",
				);
			}
			const outcome = await source.drain(applicationId, parsed.value);
			if (!outcome.ok) {
				if (outcome.reason === "unknown-application") {
					return faceError(
						404,
						WASM_LOG_APPLICATION_UNKNOWN,
						"the logging authority reports no ring for this application",
					);
				}
				return faceError(
					503,
					WASM_LOG_AUTHORITY_UNAVAILABLE,
					"the wasmd logging ring authority is unavailable; no events may be synthesized",
				);
			}
			const verified = validateIwebLoggingDrainResponseWireV1(outcome.value, parsed.value);
			if (!verified.ok) {
				return faceError(
					503,
					WASM_LOG_AUTHORITY_WIRE_INVALID,
					"the logging authority projection failed consumption-side verification; nothing is partially returned",
				);
			}
			const response: IwebLoggingDrainResponseV1 = verified.response;
			return faceJson(200, { ok: true, ...response });
		},
		summary: async (applicationId) => {
			if (source === null) {
				return faceError(
					503,
					WASM_LOG_AUTHORITY_UNAVAILABLE,
					"the wasmd logging ring authority is not wired into this supervisor build; no local ledger may substitute for it",
				);
			}
			const outcome = await source.monitorSummary(applicationId);
			if (!outcome.ok) {
				if (outcome.reason === "unknown-application") {
					return faceError(
						404,
						WASM_LOG_APPLICATION_UNKNOWN,
						"the logging authority reports no ring for this application",
					);
				}
				return faceError(
					503,
					WASM_LOG_AUTHORITY_UNAVAILABLE,
					"the wasmd logging ring authority is unavailable; no counts may be synthesized",
				);
			}
			const verified = validateIwebLoggingMonitorSummaryWireV1(outcome.value, applicationId);
			if (!verified.ok) {
				return faceError(
					503,
					WASM_LOG_AUTHORITY_WIRE_INVALID,
					"the logging monitor summary failed consumption-side verification",
				);
			}
			return faceJson(200, verified.summary);
		},
	};
}

/**
 * drain/stream 的 HTTP-only 封装（与 handleExecutionRpcHttp 同款 framing 纪律的适用子集）：
 * 方法/路径 → body 上限 → content type → JSON → face。drain 语义含游标即 stream；
 * 不引入第二个传输（无 WebSocket、无 snapshot FD、无 celld envelope 解析）。
 */
export async function handleWasmLoggingDrainHttp(
	face: WasmLoggingOwnerFace,
	request: WasmLoggingDrainHttpRequest,
	options: { readonly maxRequestBytes?: number } = {},
): Promise<WasmLoggingHttpFaceResult> {
	if (request.method !== "POST" || !request.path.startsWith(WASM_HOST_LOGGING_DRAIN_PATH + "/")) {
		return faceError(404, "UNKNOWN_ROUTE", "unknown supervisor route");
	}
	const applicationId = request.path.slice(WASM_HOST_LOGGING_DRAIN_PATH.length + 1);
	if (!APPLICATION_ID_PATH_PATTERN.test(applicationId)) {
		return faceError(404, WASM_LOG_APPLICATION_UNKNOWN, "unknown logging drain target");
	}
	const maximumBytes = options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
	if (request.body.byteLength > maximumBytes) {
		return faceError(413, "BODY_TOO_LARGE", "logging drain request is too large");
	}
	if (!isJsonContentType(request.contentType)) {
		return faceError(415, "UNSUPPORTED_CONTENT_TYPE", "logging drain expects application/json");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(request.body.toString("utf8"));
	} catch {
		return faceError(400, "INVALID_JSON", "logging drain body must be JSON");
	}
	return face.drain(applicationId, parsed);
}

/** summary 的 HTTP-only 封装（只读 GET；未知应用 404 / 权威不可用 503，绝不合成零值）。 */
export async function handleWasmLoggingSummaryHttp(
	face: WasmLoggingOwnerFace,
	method: string,
	path: string,
): Promise<WasmLoggingHttpFaceResult> {
	if (method !== "GET" || !path.startsWith(WASM_HOST_LOGGING_SUMMARY_PATH + "/")) {
		return faceError(404, "UNKNOWN_ROUTE", "unknown supervisor route");
	}
	const applicationId = path.slice(WASM_HOST_LOGGING_SUMMARY_PATH.length + 1);
	if (!APPLICATION_ID_PATH_PATTERN.test(applicationId)) {
		return faceError(404, WASM_LOG_APPLICATION_UNKNOWN, "unknown logging summary target");
	}
	return face.summary(applicationId);
}

// ---------------------------------------------------------------------------
// 测试/后续接线共用的内存权威实现（以契约纯函数模拟 wasmd ring 的 owner-drain 语义）
// ---------------------------------------------------------------------------

/**
 * 以契约 ring 纯函数承载的内存权威（测试用 wasmd 替身；也可作为 5.x 前的过渡 source）。
 * 事件只经 writeIwebLoggingEvent 进入（宿主上下文注入身份，跨应用违约由契约拒绝），
 * drain/monitorSummary 的答案形状与 wasmd Rust LoggingRing::drain/monitor_summary 对位。
 * 生命周期：reset 开启新 lifecycle（与 wasmd 进程重启对齐；无跨重启持久化声明）。
 */
export class InMemoryWasmLoggingAuthority implements WasmLoggingProjectionSource {
	private readonly rings = new Map<string, IwebLoggingRingStateV1>();

	ensure(applicationId: string, capacity: IwebLoggingRingCapacityV1): IwebLoggingRingStateV1 {
		const existing = this.rings.get(applicationId);
		if (
			existing !== undefined &&
			existing.capacity.maxEvents === capacity.maxEvents &&
			existing.capacity.maxBytes === capacity.maxBytes
		) {
			return existing;
		}
		const created = createIwebLoggingRing(applicationId, capacity);
		if (!created.ok) {
			throw new WasmLoggingServeError(
				"WASM_LOG_RING_CAPACITY_INVALID",
				"the logging ring capacity for " + applicationId + " failed contract validation",
			);
		}
		this.rings.set(applicationId, created.value);
		return created.value;
	}

	find(applicationId: string): IwebLoggingRingStateV1 | null {
		return this.rings.get(applicationId) ?? null;
	}

	write(
		applicationId: string,
		hostContext: IwebLoggingHostContextV1,
		event: unknown,
		options: { readonly maxEventBytes?: number } = {},
	): ReturnType<typeof writeIwebLoggingEvent> {
		const ring = this.rings.get(applicationId);
		if (ring === undefined) {
			return {
				ok: false,
				code: "IWEB_LOG_APP_ISOLATION",
				issues: [
					{
						code: "IWEB_LOG_APP_ISOLATION",
						path: "/applicationId",
						message: "no ring exists for this application",
					},
				],
			};
		}
		const result = writeIwebLoggingEvent(ring, hostContext, event, options);
		if (result.ok) this.rings.set(applicationId, result.ring);
		return result;
	}

	reset(applicationId: string): void {
		const ring = this.rings.get(applicationId);
		if (ring !== undefined) {
			const next = createIwebLoggingRing(applicationId, ring.capacity);
			if (next.ok) this.rings.set(applicationId, next.value);
		}
	}

	async drain(
		applicationId: string,
		request: IwebLoggingDrainRequestV1,
	): Promise<WasmLoggingProjectionOutcome<IwebLoggingDrainResponseV1>> {
		const ring = this.rings.get(applicationId);
		if (ring === undefined) return { ok: false, reason: "unknown-application" };
		const drained = drainIwebLoggingRing(ring, request);
		if (!drained.ok) return { ok: false, reason: "unavailable" };
		return { ok: true, value: drained.response };
	}

	async monitorSummary(applicationId: string): Promise<WasmLoggingProjectionOutcome<IwebLoggingMonitorSummaryV1>> {
		const ring = this.rings.get(applicationId);
		if (ring === undefined) return { ok: false, reason: "unknown-application" };
		return {
			ok: true,
			value: {
				applicationId: ring.applicationId,
				retainedEvents: ring.events.length,
				retainedBytes: ring.retainedBytes,
				droppedCount: ring.droppedCount,
				lastEventId: ring.nextEventId - 1,
				capacity: ring.capacity,
			},
		};
	}
}

// ---------------------------------------------------------------------------
// 装配：宿主装载转发配置 + 权威投影源 + owner 面（供 main.ts 与测试注入 IO）
// ---------------------------------------------------------------------------

export interface AssembleWasmLoggingOwnerFaceInput {
	readonly environment: Readonly<Record<string, string | undefined>>;
	readonly io?: WasmServeIO;
	/**
	 * 权威投影源（wasmd ring 的读取面）。缺省 null：面已装配、framing/隔离校验照常，
	 * 但 drain/summary 对一切应用显式 503 WASM_LOG_AUTHORITY_UNAVAILABLE——wasmd 侧
	 * owner-drain 端点接线前的诚实形态，绝不用 supervisor 本地台账顶替权威。
	 */
	readonly source?: WasmLoggingProjectionSource | null;
}

export type WasmLoggingOwnerServices = {
	readonly enabled: true;
	readonly face: WasmLoggingOwnerFace;
	readonly source: WasmLoggingProjectionSource | null;
	readonly forwardingConfig: IwebLoggingForwardingConfigV1;
};

/**
 * 装配 logging owner 面。不设环境开关：该面是已认证 supervisor socket 上的 owner 只读诊断面
 * （bounded 计数 + 本应用 drain），无外部副作用、无秘密。转发配置装载默认关、无效
 * fail-closed（装配失败 = 启动失败）。权威源未注入时端点显式 unavailable（见上）。
 */
export function assembleWasmLoggingOwnerFace(
	input: AssembleWasmLoggingOwnerFaceInput,
): WasmLoggingOwnerServices {
	const forwardingConfig = loadIwebLoggingForwardingConfig(
		input.io ?? systemWasmServeIO,
		input.environment,
	);
	const source = input.source ?? null;
	return {
		enabled: true,
		face: createWasmLoggingOwnerFace(source, forwardingConfig),
		source,
		forwardingConfig,
	};
}
