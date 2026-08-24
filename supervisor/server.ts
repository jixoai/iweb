// 用户原始需求（2026-08-14）：沙箱 supervisor 必须是无公网监听、无 owner key 的独立受信任服务。
// 正交意图：仅绑定 Unix socket；暴露版本化健康检查与窄 RPC；限制请求规模；关闭时清理 socket；adapter 未配置时安全关闭。
import { chmodSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import {
	DEFAULT_MAX_REQUEST_BYTES,
	handleSupervisorRpc,
	SUPERVISOR_RPC_PATH,
	type SupervisorAdapter,
} from "../contracts/protocol-server.ts";

export interface SupervisorServerOptions {
	readonly socketPath: string;
	readonly adapter?: SupervisorAdapter;
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

async function route(adapter: SupervisorAdapter | undefined, method: string | undefined, url: string | undefined, contentType: string | null, body: Buffer): Promise<{ readonly status: number; readonly body: string }> {
	let pathname = "/";
	try {
		pathname = new URL(url ?? "/", "http://supervisor.invalid").pathname;
	} catch {
		return { status: 400, body: json(400, { version: 1, ok: false, code: "INVALID_TARGET", message: "invalid supervisor request target" }) };
	}
	if (method === "GET" && pathname === "/v1/health") {
		return { status: 200, body: json(200, { version: 1, service: "iweb-sandbox-supervisor", ready: true }) };
	}
	if (method === "POST" && pathname === SUPERVISOR_RPC_PATH) {
		if (!adapter) {
			return { status: 503, body: json(503, { version: 1, ok: false, code: "ADAPTER_NOT_CONFIGURED", message: "supervisor adapter is not configured" }) };
		}
		return handleSupervisorRpc(adapter, { method: method ?? "", path: pathname, contentType, body });
	}
	return { status: 404, body: json(404, { version: 1, ok: false, code: "UNKNOWN_ROUTE", message: "unknown supervisor route" }) };
}

export async function startSupervisorServer(options: SupervisorServerOptions): Promise<RunningSupervisorServer> {
	rmSync(options.socketPath, { force: true });
	const server = createServer((request, response) => {
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
			route(options.adapter, request.method, request.url, request.headers["content-type"] ?? null, Buffer.concat(chunks))
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
		server.listen(options.socketPath, resolve);
	});
	chmodSync(options.socketPath, 0o600);

	return {
		server,
		close: async () => {
			await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
			rmSync(options.socketPath, { force: true });
		}
	};
}

export { DEFAULT_MAX_REQUEST_BYTES };

