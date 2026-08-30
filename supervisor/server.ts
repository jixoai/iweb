// 用户原始需求（2026-08-14）：沙箱 supervisor 必须是无公网监听、无 owner key 的独立受信任服务。
// 正交意图：仅绑定 Unix socket；暴露版本化健康检查与窄 RPC；限制请求规模；关闭时清理 socket。
// 轮次注记（2026-08-26，add-wasm-runtime 1.0）：同 socket 增加 /v1/execution-rpc（wasm 专用，与
//   celld /v1/rpc 双向文法互斥）；SO_PEERCRED 双端凭据属 7.1 的 Linux 实测任务。
// 轮次注记（2026-08-26，add-wasm-runtime 4.1）：同 socket 增加 GET /v1/execution-metrics/<sandboxId>
//   （wasm engine metrics v1 只读采样）。
// 轮次注记（2026-08-28，add-wasm-host-services supervisor 接线层）：同 socket 增加 logging owner 面——
//   POST /v1/host-logging/drain/<applicationId>（owner 授权 drain/stream，游标即 stream）与
//   GET /v1/host-logging/summary/<applicationId>（monitor summary 投影，仅计数/水位，无日志正文）。
//   两端点复用本 socket 既有 requestAuthorization（relay 进程期凭据），不引入第二个认证面。
// 轮次注记（2026-08-30，two-tier-runtime-trust）：celld adapter 永久退役；/v1/rpc 不再有
//   celld 执行语义，恒拒 CELLD_PROTOCOL_MISMATCH（spec 负向量 "Celld RPC envelope is sent
//   to the wasm endpoint" 的对面：任何 celld 形状请求都无副作用、无降级解析）。
import { chmodSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { CELLD_PROTOCOL_MISMATCH } from "../packages/contracts/protocol.ts";
import { DEFAULT_MAX_REQUEST_BYTES, SUPERVISOR_RPC_PATH } from "../packages/contracts/protocol-server.ts";
import { EXECUTION_RPC_NOT_CONFIGURED, EXECUTION_RPC_PATH, handleExecutionRpcHttp, type ExecutionRpcHandler } from "./wasm-control.ts";
import {
	handleWasmLoggingDrainHttp,
	handleWasmLoggingSummaryHttp,
	WASM_HOST_LOGGING_DRAIN_PATH,
	WASM_HOST_LOGGING_SUMMARY_PATH,
	WASM_LOG_FACE_NOT_CONFIGURED,
	type WasmLoggingOwnerFace,
} from "./wasm-host-logging.ts";
import type { ServiceEngineMetricsV2, WasmEngineMetricsV1 } from "../packages/contracts/wasm-health.ts";
import type { SupervisorRequestAuthorization } from "./socket-auth.ts";

export interface SupervisorServerOptions {
	readonly socketPath: string;
	// wasm execution 通道；未配置时 /v1/execution-rpc fail-closed（503），绝不
	// 降级到任何默认执行器（celld /v1/rpc 已恒拒，无 fallback 可言）。
	readonly executionRpc?: ExecutionRpcHandler;
	// wasm engine metrics v1 采样通道（4.1）；未配置时 /v1/execution-metrics/* 同样
	// fail-closed（503）。返回 null = 未知 sandbox（404），绝不合成载荷。
	readonly executionMetrics?: (sandboxId: string) => WasmEngineMetricsV1 | ServiceEngineMetricsV2 | null;
	// logging owner 面（add-wasm-host-services；终审缺口修正后为权威拉取式投影）：
	// drain/stream + monitor summary 都向注入的 wasmd ring 权威投影源拉取；未配置 face 时
	// 两端点 fail-closed（503）。权威未接线/不可达 503、权威证明未知应用 404、权威答案
	// 畸形 503——supervisor 不持有本地环台账，绝不合成事件或零值。
	readonly loggingFace?: WasmLoggingOwnerFace;
	/**
	 * The native relay has already checked public-socket SO_PEERCRED. Node still
	 * requires its process-lifetime relay credential before buffering a request;
	 * this prevents the private upstream listener from becoming a second, open
	 * execution entrypoint.
	 */
	readonly requestAuthorization?: SupervisorRequestAuthorization;
}

export interface RunningSupervisorServer {
	readonly server: Server;
	close(): Promise<void>;
}

// Absolute memory backstop for buffered request bodies. The protocol enforces its
// own smaller DEFAULT_MAX_REQUEST_BYTES limit and returns a clean 413; this cap
// only protects the supervisor process from an unbounded buffered read.
const maximumBufferedRequestBytes = 1024 * 1024;

function json(status: number, body: object): string {
	return JSON.stringify(body) + "\n";
}

async function route(executionRpc: ExecutionRpcHandler | undefined, executionMetrics: ((sandboxId: string) => WasmEngineMetricsV1 | ServiceEngineMetricsV2 | null) | undefined, loggingFace: WasmLoggingOwnerFace | undefined, method: string | undefined, url: string | undefined, contentType: string | null, body: Buffer): Promise<{ readonly status: number; readonly body: string }> {
	let pathname = "/";
	try {
		pathname = new URL(url ?? "/", "http://supervisor.invalid").pathname;
	} catch {
		return { status: 400, body: json(400, { version: 1, ok: false, code: "INVALID_TARGET", message: "invalid supervisor request target" }) };
	}
	if (method === "GET" && pathname === "/v1/health") {
		return { status: 200, body: json(200, { version: 1, service: "iweb-sandbox-supervisor", ready: true }) };
	}
	// celld /v1/rpc（two-tier-runtime-trust）：celld 执行语义永久退役，本端点对一切请求
	// 恒拒 CELLD_PROTOCOL_MISMATCH——无 adapter、无解析、无副作用（负向量语义保留：
	// celld envelope 与 execution envelope 双向互斥，任何一方都不得在对方路径被降级
	// 解析）。响应形状沿用既有 errorResult 格式。
	if (method === "POST" && pathname === SUPERVISOR_RPC_PATH) {
		return { status: 400, body: json(400, { version: 1, ok: false, code: CELLD_PROTOCOL_MISMATCH, message: "the celld supervisor rpc endpoint is permanently removed; celld runtime admission no longer exists" }) };
	}
	// wasm execution 通道：仅接受 iweb-execution-rpc-v1 envelope；celld version/operation
	// envelope 由 handleExecutionRpcHttp 以 EXECUTION_PROTOCOL_MISMATCH 拒绝（双向互斥，
	// /v1/rpc 侧的守卫在 contracts/protocol-server.ts）。
	// 7.1 SupervisorSocketAuthV1：公开 socket 的 SO_PEERCRED、固定路径与 inode/mode
	// 复查由原生 relay 在到达此私有 upstream 前完成；本层仅接受 relay 的进程期凭据。
	if (method === "POST" && pathname === EXECUTION_RPC_PATH) {
		if (!executionRpc) {
			return { status: 503, body: json(503, { ok: false, code: EXECUTION_RPC_NOT_CONFIGURED, message: "the wasm execution rpc handler is not configured" }) };
		}
		return handleExecutionRpcHttp(executionRpc, { method: method ?? "", path: pathname, contentType, body });
	}
	// wasm engine metrics v1（4.1）：只读 GET 采样，路径固定 /v1/execution-metrics/<sandboxId>。
	// sandboxId 文法先于采样器判定（非法即 404，不进入 fence 查找）；与 celld /v1/rpc 的
	// metrics 操作无共享 parser（互斥法：celld envelope 在 /v1/rpc，本路径只出 wasm wire）。
	if (method === "GET" && pathname.startsWith(EXECUTION_METRICS_PATH + "/")) {
		const sandboxId = pathname.slice(EXECUTION_METRICS_PATH.length + 1);
		if (!SANDBOX_ID_PATTERN.test(sandboxId)) {
			return { status: 404, body: json(404, { ok: false, code: EXECUTION_SANDBOX_UNKNOWN, message: "unknown sandbox metrics target" }) };
		}
		if (!executionMetrics) {
			return { status: 503, body: json(503, { ok: false, code: EXECUTION_METRICS_NOT_CONFIGURED, message: "the wasm engine metrics sampler is not configured" }) };
		}
		const payload = executionMetrics(sandboxId);
		if (payload === null) {
			return { status: 404, body: json(404, { ok: false, code: "EXECUTION_SANDBOX_UNKNOWN", message: "unknown sandbox metrics target" }) };
		}
		return { status: 200, body: JSON.stringify(payload) + "\n" };
	}
	// logging owner 面（add-wasm-host-services）：POST drain/stream（路径段 applicationId 与
	// wire applicationId 一致才进入环属主判定；跨应用隔离违约 403）与 GET summary（仅计数/水位）。
	// 未配置 face 时 fail-closed（503），与 execution-rpc/metrics 通道同款纪律。
	if (method === "POST" && pathname.startsWith(WASM_HOST_LOGGING_DRAIN_PATH + "/")) {
		if (!loggingFace) {
			return { status: 503, body: json(503, { ok: false, code: WASM_LOG_FACE_NOT_CONFIGURED, message: "the wasm logging owner face is not configured" }) };
		}
		const result = await handleWasmLoggingDrainHttp(loggingFace, { method: method ?? "", path: pathname, contentType, body });
		return { status: result.status, body: result.body };
	}
	if (method === "GET" && pathname.startsWith(WASM_HOST_LOGGING_SUMMARY_PATH + "/")) {
		if (!loggingFace) {
			return { status: 503, body: json(503, { ok: false, code: WASM_LOG_FACE_NOT_CONFIGURED, message: "the wasm logging owner face is not configured" }) };
		}
		const result = await handleWasmLoggingSummaryHttp(loggingFace, method ?? "", pathname);
		return { status: result.status, body: result.body };
	}
	return { status: 404, body: json(404, { version: 1, ok: false, code: "UNKNOWN_ROUTE", message: "unknown supervisor route" }) };
}

export const EXECUTION_METRICS_PATH = "/v1/execution-metrics";
export const EXECUTION_METRICS_NOT_CONFIGURED = "EXECUTION_METRICS_NOT_CONFIGURED";
export const EXECUTION_SANDBOX_UNKNOWN = "EXECUTION_SANDBOX_UNKNOWN";
const SANDBOX_ID_PATTERN = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export async function startSupervisorServer(options: SupervisorServerOptions): Promise<RunningSupervisorServer> {
	rmSync(options.socketPath, { force: true });
	const server = createServer((request, response) => {
		if (options.requestAuthorization !== undefined && !options.requestAuthorization(request.headers)) {
			// No body listener is registered on this branch, so an unauthorised
			// direct upstream caller cannot reach framing, routing, or a journal.
			request.pause();
			response.writeHead(401, { "content-type": "application/json; charset=utf-8", connection: "close" });
			response.end(json(401, { version: 1, ok: false, code: "SUPERVISOR_UPSTREAM_UNAUTHORIZED", message: "unauthorized supervisor upstream" }));
			return;
		}
		const chunks: Buffer[] = [];
		let received = 0;
		let overflowed = false;
		request.on("data", (chunk: Buffer) => {
			if (overflowed) return;
			received += chunk.byteLength;
			if (received > maximumBufferedRequestBytes) {
				overflowed = true;
				chunks.length = 0;
				// Respond a stable JSON 413 and stop consuming. Do not destroy the
				// socket before the response is flushed, or the client sees ECONNRESET.
				if (!response.headersSent) {
					response.writeHead(413, { "content-type": "application/json; charset=utf-8", connection: "close" });
					response.end(json(413, { version: 1, ok: false, code: "BODY_TOO_LARGE", message: "supervisor request is too large" }));
				}
				request.pause();
				return;
			}
			chunks.push(chunk);
		});
		request.on("end", () => {
			if (overflowed) return;
			route(options.executionRpc, options.executionMetrics, options.loggingFace, request.method, request.url, request.headers["content-type"] ?? null, Buffer.concat(chunks))
				.then((result) => {
					response.writeHead(result.status, { "content-type": "application/json; charset=utf-8" });
					response.end(result.body);
				})
				.catch(() => {
					if (!response.headersSent) response.writeHead(500, { "content-type": "application/json; charset=utf-8" });
					response.end(json(500, { version: 1, ok: false, code: "INTERNAL", message: "supervisor internal error" }));
				});
		});
		request.on("error", () => {
			// The oversized body is answered in the data handler; an aborted client is a no-op.
		});
	});

	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(options.socketPath, () => {
			try {
				chmodSync(options.socketPath, 0o600);
				resolve();
			} catch (error) {
				reject(error);
			}
		});
	});

	return {
		server,
		close: async () => {
			await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
			rmSync(options.socketPath, { force: true });
		}
	};
}

export { DEFAULT_MAX_REQUEST_BYTES };
