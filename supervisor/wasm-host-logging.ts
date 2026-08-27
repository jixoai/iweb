// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：logging 的 owner 面——
//   drain/stream 端点（经 supervisor server 既有授权/token 面）、monitor summary 投影
//   （复用 wasm-health 的 executionMetrics 采样模式）、转发配置的宿主装载（默认关 fail-closed）。
// 正交意图：
//   1. 宿主装载 owner 授权外部转发配置 wire（IWEB_WASM_LOG_FORWARDING_FILE；缺省=默认关闭；
//      文件必须严格 JSON + JCS 规范字节 + validateIwebLoggingForwardingConfig 全过，否则 fail-closed）；
//   2. per-app 有界环的宿主侧台账（WasmLoggingRingStore）：写入/drain/summary 全部走
//      packages/contracts/wasm-host-logging.ts 纯函数，跨应用隔离违约由契约层 IWEB_LOG_APP_ISOLATION 拒绝；
//   3. owner 面 HTTP 语义（drain/stream + summary）：与 execution-rpc 同款 framing 纪律
//      （方法/路径/大小/content-type/JSON/未知路由），错误码稳定，未配置 503、未知应用 404、
//      隔离违约 403，绝不部分解析、绝不下降为 celld 通道。
// 规范权威：openspec/changes/add-wasm-host-services/specs/wasm-host-logging/spec.md
//   「Logging retention and durability are profile-bound」（L1：bounded memory ring + monitor 投影 +
//   owner 授权外部转发，默认关）与 design.md「Owner Decisions Ratified」L1 行。
// 接线边界（本文件刻意不做的部分）：
//   - 环的权威数据源是 wasmd 内嵌 provider（任务 5.x）；本层提供过渡期 supervisor 侧台账与
//     类型化 seam（face.drain/face.summary），provider 批次落地后替换 store 实现即可，HTTP 语义不变；
//   - 转发 worker（向外部端点发送日志）不在本批：本批只做配置装载与暴露（默认关）；
//   - 不挂任何未授权路由：所有端点都在 supervisor 私有 socket 的既有 requestAuthorization
//     （relay 进程期凭据）之下，没有第二个无认证入口（spec「no second unauthenticated entrance」）。
import {
	createIwebLoggingRing,
	drainIwebLoggingRing,
	IWEB_LOG_FORWARDING_DEFAULT,
	projectIwebLoggingMonitorSummary,
	validateIwebLoggingDrainRequest,
	validateIwebLoggingForwardingConfig,
	writeIwebLoggingEvent,
	type IwebLoggingDrainResponseV1,
	type IwebLoggingForwardingConfigV1,
	type IwebLoggingHostContextV1,
	type IwebLoggingMonitorSummaryV1,
	type IwebLoggingRingCapacityV1,
	type IwebLoggingRingStateV1,
} from "../packages/contracts/wasm-host-logging.ts";
import { jcsCanonicalBytes, parseStrictJson } from "../packages/contracts/wasm-package.ts";
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
export const WASM_LOG_RING_CAPACITY_INVALID = "WASM_LOG_RING_CAPACITY_INVALID";

export const WASM_HOST_LOGGING_DRAIN_PATH = "/v1/host-logging/drain";
export const WASM_HOST_LOGGING_SUMMARY_PATH = "/v1/host-logging/summary";

// applicationId 文法与契约 drain wire 同源（小写字母数字与连字符，<=63 ASCII 字节）；
// 路径段先于台账查找判定（非法即 404，不进入环查找）。
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
			"the logging forwarding config bytes are not canonical JCS: " + configured,
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
// per-app 有界环台账（过渡期宿主侧 seam；写入/drain/summary 全走契约纯函数）
// ---------------------------------------------------------------------------

/**
 * supervisor 侧 per-app 环台账。生产权威数据源是 wasmd 内嵌 provider（任务 5.x）；在 provider
 * 接线前，本台账以契约纯函数承载 owner 面语义：写入即校验/redact/计量（writeIwebLoggingEvent），
 * drain 只返回请求应用自己的 bounded 保留记录（drainIwebLoggingRing），summary 只有计数与水位
 * （projectIwebLoggingMonitorSummary，无日志正文）。重启语义由调用方显式 reset（无跨重启持久化声明）。
 */
export class WasmLoggingRingStore {
	private readonly rings = new Map<string, IwebLoggingRingStateV1>();

	/** 创建（或以新容量重建）一个应用的环；容量非法是宿主配置错误，fail-closed 抛出。 */
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
				WASM_LOG_RING_CAPACITY_INVALID,
				"the logging ring capacity for " + applicationId + " failed contract validation",
			);
		}
		this.rings.set(applicationId, created.value);
		return created.value;
	}

	find(applicationId: string): IwebLoggingRingStateV1 | null {
		return this.rings.get(applicationId) ?? null;
	}

	/**
	 * 写入一个事件（宿主注入身份；宿主上下文 applicationId 与环属主不一致 →
	 * IWEB_LOG_APP_ISOLATION，契约层隔离违约）。dropped/invalid 不改变已保留事件。
	 */
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

	/** 运行时生命周期重置（supervisor/wasmd 重启或执行代次替换后；无持久化声明）。 */
	reset(applicationId: string): void {
		const ring = this.rings.get(applicationId);
		if (ring !== undefined) {
			const next = createIwebLoggingRing(applicationId, ring.capacity);
			if (next.ok) this.rings.set(applicationId, next.value);
		}
	}

	/** monitor 投影：只有计数与水位，没有任何日志正文；未知应用返回 null（不合成零值）。 */
	summary(applicationId: string): IwebLoggingMonitorSummaryV1 | null {
		const ring = this.rings.get(applicationId);
		return ring === undefined ? null : projectIwebLoggingMonitorSummary(ring);
	}
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
	/** owner 授权 drain/stream（stream = 携带游标 afterEventId 的重复 drain）。 */
	drain(applicationId: string, body: unknown): WasmLoggingHttpFaceResult;
	/** monitor summary 投影（仅计数/水位；未知应用 null）。 */
	summary(applicationId: string): IwebLoggingMonitorSummaryV1 | null;
	/** 已装载的转发配置（默认关；装载失败在装配期 fail-closed）。 */
	readonly forwardingConfig: IwebLoggingForwardingConfigV1;
}

function faceJson(status: number, body: object): WasmLoggingHttpFaceResult {
	return { status, body: JSON.stringify(body) + "\n" };
}

function faceError(status: number, code: string, message: string): WasmLoggingHttpFaceResult {
	return faceJson(status, { ok: false, code, message });
}

/** 从台账装配 owner 面（main.ts 与测试共用；store 为注入的 seam）。 */
export function createWasmLoggingOwnerFace(
	store: WasmLoggingRingStore,
	forwardingConfig: IwebLoggingForwardingConfigV1,
): WasmLoggingOwnerFace {
	return {
		forwardingConfig,
		drain: (applicationId, body) => {
			// 路径 applicationId 与 wire applicationId 必须一致：不一致即跨应用隔离违约（403），
			// 与契约 drainIwebLoggingRing 的环属主判定构成双重防线。
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
			const ring = store.find(applicationId);
			if (ring === null) {
				return faceError(
					404,
					WASM_LOG_APPLICATION_UNKNOWN,
					"no logging ring exists for this application",
				);
			}
			const drained = drainIwebLoggingRing(ring, body);
			if (!drained.ok) {
				// 隔离违约（环属主不一致）→ 403；其余 wire 级失败 → 400。
				return drained.code === "IWEB_LOG_APP_ISOLATION"
					? faceError(403, drained.code, "the drain request does not own this application ring")
					: faceError(400, drained.code, "the logging drain request was rejected");
			}
			const response: IwebLoggingDrainResponseV1 = drained.response;
			return faceJson(200, { ok: true, ...response });
		},
		summary: (applicationId) => store.summary(applicationId),
	};
}

/**
 * drain/stream 的 HTTP-only 封装（与 handleExecutionRpcHttp 同款 framing 纪律的适用子集）：
 * 方法/路径 → body 上限 → content type → JSON → face。drain 语义含游标即 stream；
 * 不引入第二个传输（无 WebSocket、无 snapshot FD、无 celld envelope 解析）。
 */
export function handleWasmLoggingDrainHttp(
	face: WasmLoggingOwnerFace,
	request: WasmLoggingDrainHttpRequest,
	options: { readonly maxRequestBytes?: number } = {},
): WasmLoggingHttpFaceResult {
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

/** summary 的 HTTP-only 封装（只读 GET；未知应用 404，绝不合成零值载荷）。 */
export function handleWasmLoggingSummaryHttp(
	face: WasmLoggingOwnerFace,
	method: string,
	path: string,
): WasmLoggingHttpFaceResult {
	if (method !== "GET" || !path.startsWith(WASM_HOST_LOGGING_SUMMARY_PATH + "/")) {
		return faceError(404, "UNKNOWN_ROUTE", "unknown supervisor route");
	}
	const applicationId = path.slice(WASM_HOST_LOGGING_SUMMARY_PATH.length + 1);
	if (!APPLICATION_ID_PATH_PATTERN.test(applicationId)) {
		return faceError(404, WASM_LOG_APPLICATION_UNKNOWN, "unknown logging summary target");
	}
	const summary = face.summary(applicationId);
	if (summary === null) {
		return faceError(
			404,
			WASM_LOG_APPLICATION_UNKNOWN,
			"no logging ring exists for this application",
		);
	}
	return faceJson(200, summary);
}

// ---------------------------------------------------------------------------
// 装配：宿主装载转发配置 + 台账 + owner 面（供 main.ts 与测试注入 IO）
// ---------------------------------------------------------------------------

export interface AssembleWasmLoggingOwnerFaceInput {
	readonly environment: Readonly<Record<string, string | undefined>>;
	readonly io?: WasmServeIO;
	readonly store?: WasmLoggingRingStore;
}

export type WasmLoggingOwnerServices =
	| { readonly enabled: false }
	| {
			readonly enabled: true;
			readonly face: WasmLoggingOwnerFace;
			readonly store: WasmLoggingRingStore;
			readonly forwardingConfig: IwebLoggingForwardingConfigV1;
		};

/**
 * 装配 logging owner 面。不设环境开关：该面是已认证 supervisor socket 上的 owner 只读诊断面
 * （bounded 计数 + 本应用 drain），无外部副作用、无秘密；真正的写入源（wasmd provider）落地前
 * 台账为空，端点对未知应用一律 404。转发配置装载默认关、无效 fail-closed（装配失败 = 启动失败）。
 */
export function assembleWasmLoggingOwnerFace(
	input: AssembleWasmLoggingOwnerFaceInput,
): WasmLoggingOwnerServices {
	const forwardingConfig = loadIwebLoggingForwardingConfig(
		input.io ?? systemWasmServeIO,
		input.environment,
	);
	const store = input.store ?? new WasmLoggingRingStore();
	return {
		enabled: true,
		face: createWasmLoggingOwnerFace(store, forwardingConfig),
		store,
		forwardingConfig,
	};
}
