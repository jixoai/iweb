// 用户原始需求（2026-08-14）：supervisor RPC 必须经 0600 Unix socket 端到端工作，拒绝请求不触发 adapter。
// 正交意图：socket round-trip；adapter 未配置时安全关闭；拒绝请求零 adapter 调用。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startSupervisorServer } from "../supervisor/server.ts";
import type { SupervisorAdapter } from "../contracts/protocol-server.ts";
import { deriveSandboxId } from "../contracts/protocol.ts";

const digestA = "a".repeat(64);
const digestB = "b".repeat(64);
const resources = { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 };

function validPrepare(): Record<string, unknown> {
	return {
		version: 1,
		operation: "prepare",
		sandboxId: deriveSandboxId("app-a", digestB, 7),
		versionIdentity: { applicationId: "app-a", digest: digestB, sequence: 7 },
		packageDigest: digestA,
		policy: { resources, egress: { default: "deny", allow: [] } },
		object: { endpoint: "http://127.0.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTESTEXAMPLE", secretAccessKey: "SECRETTESTEXAMPLE123" },
	};
}

function spyAdapter(): { adapter: SupervisorAdapter; calls: string[] } {
	const calls: string[] = [];
	const adapter: SupervisorAdapter = {
		prepare: async (request) => { calls.push("prepare"); return { version: 1, operation: "prepare", status: "prepared", sandboxId: request.sandboxId }; },
		start: async (request) => { calls.push("start"); return { version: 1, operation: "start", status: "started", sandboxId: request.sandboxId }; },
		stop: async (request) => { calls.push("stop"); return { version: 1, operation: "stop", status: "stopped", sandboxId: request.sandboxId }; },
		inspect: async (request) => { calls.push("inspect"); return { version: 1, operation: "inspect", sandboxId: request.sandboxId, state: "ready" }; },
		metrics: async (request) => { calls.push("metrics"); return { version: 1, operation: "metrics", sandboxId: request.sandboxId, sample: { versionId: request.versionId, sampledAt: "2026-08-14T00:00:00.000Z", cpuMillis: { available: true, value: 1 }, memoryBytes: { available: true, value: 2 }, pidCount: { available: true, value: 3 }, terminated: { available: true, value: 0 }, limits: resources } }; },
		delete: async (request) => { calls.push("delete"); return { version: 1, operation: "delete", status: "deleted", sandboxId: request.sandboxId }; },
	};
	return { adapter, calls };
}

function post(socketPath: string, body: unknown, contentType = "application/json"): Promise<{ status: number; body: string }> {
	const payload = typeof body === "string" ? body : JSON.stringify(body);
	return new Promise((resolve, reject) => {
		const value = request(
			{ socketPath, method: "POST", path: "/v1/rpc", headers: { "content-type": contentType, "content-length": Buffer.byteLength(payload) } },
			(response) => {
				let data = "";
				response.setEncoding("utf8");
				response.on("data", (chunk) => (data += chunk));
				response.on("end", () => resolve({ status: response.statusCode ?? 0, body: data }));
			},
		);
		value.once("error", reject);
		value.write(payload);
		value.end();
	});
}

// Production Kernel rpc client (kernel/supervisor-rpc.js): every response is
// shape-validated and identity-correlated with the request before the caller
// sees it (2.28). These tests run the client against a real unix-socket server.
describe("Kernel rpc client validates and correlates supervisor responses", () => {
	const rpcClient = require("../kernel/supervisor-rpc.js");

	function serve(socketPath: string, handler: (body: Record<string, unknown>) => unknown): Promise<Server> {
		const server = createServer((incoming, outgoing) => {
			let data = "";
			incoming.setEncoding("utf8");
			incoming.on("data", (chunk: string) => (data += chunk));
			incoming.on("end", () => {
				const payload = handler(JSON.parse(data));
				const text = JSON.stringify(payload);
				outgoing.writeHead(payload === null ? 500 : 200, { "content-type": "application/json" });
				outgoing.end(text);
			});
		});
		return new Promise((resolve, reject) => {
			server.once("error", reject);
			server.listen(socketPath, () => resolve(server));
		});
	}

	async function withServer(handler: (body: Record<string, unknown>) => unknown, run: (socketPath: string) => Promise<void>): Promise<void> {
		const directory = mkdtempSync(join(tmpdir(), "iweb-rpcc-"));
		const socketPath = join(directory, "supervisor.sock");
		const server = await serve(socketPath, handler);
		try {
			await run(socketPath);
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	}

	test("accepts a validated, correlated inspect response", async () => {
		const sandboxId = deriveSandboxId("app-a", digestB, 7);
		await withServer(() => ({ version: 1, operation: "inspect", sandboxId, state: "ready" }), async (socketPath) => {
			const response = await rpcClient.inspect(socketPath, sandboxId);
			expect(response.state).toBe("ready");
			expect(response.sandboxId).toBe(sandboxId);
		});
	});

	test("rejects a response with smuggled unknown fields", async () => {
		const sandboxId = deriveSandboxId("app-a", digestB, 7);
		await withServer(() => ({ version: 1, operation: "inspect", sandboxId, state: "ready", diagnostic: "leak" }), async (socketPath) => {
			let code = "";
			try { await rpcClient.inspect(socketPath, sandboxId); } catch (error) { code = (error as { code?: string }).code ?? ""; }
			expect(code).toBe("SUPERVISOR_INVALID_RESPONSE");
		});
	});

	test("rejects a response whose sandbox identity does not match the request", async () => {
		const requested = deriveSandboxId("app-a", digestB, 7);
		const other = deriveSandboxId("app-a", digestB, 8);
		await withServer(() => ({ version: 1, operation: "inspect", sandboxId: other, state: "ready" }), async (socketPath) => {
			let code = "";
			try { await rpcClient.inspect(socketPath, requested); } catch (error) { code = (error as { code?: string }).code ?? ""; }
			expect(code).toBe("SUPERVISOR_INVALID_RESPONSE");
		});
	});

	test("rejects a metrics sample whose version identity does not match the request", async () => {
		const sandboxId = deriveSandboxId("app-a", digestB, 7);
		const sample = (versionId: string) => ({ versionId, sampledAt: "2026-08-14T00:00:00.000Z", cpuMillis: { available: true, value: 1 }, memoryBytes: { available: true, value: 2 }, pidCount: { available: true, value: 3 }, terminated: { available: true, value: 0 }, limits: resources });
		await withServer((body) => ({ version: 1, operation: "metrics", sandboxId: body.sandboxId, sample: sample("someone-elses-version") }), async (socketPath) => {
			let code = "";
			try { await rpcClient.metrics(socketPath, sandboxId, "expected-version"); } catch (error) { code = (error as { code?: string }).code ?? ""; }
			expect(code).toBe("SUPERVISOR_INVALID_RESPONSE");
		});
	});
});

describe("sandbox supervisor RPC over Unix socket", () => {
	test("round-trips a valid prepare request and rejects hostile input before the adapter", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-rpc-"));
		const socketPath = join(directory, "supervisor.sock");
		const { adapter, calls } = spyAdapter();
		const running = await startSupervisorServer({ socketPath, adapter });
		try {
			const okResponse = await post(socketPath, validPrepare());
			expect(okResponse.status).toBe(200);
			expect(JSON.parse(okResponse.body).operation).toBe("prepare");
			expect(calls).toEqual(["prepare"]);

			const hostile = await post(socketPath, { ...validPrepare(), socket: "/run/docker.sock" });
			expect(hostile.status).toBe(400);
			expect(calls).toEqual(["prepare"]);
		} finally {
			await running.close();
		}
	});

	test("fails closed with 503 when no adapter is configured", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-rpc-"));
		const socketPath = join(directory, "supervisor.sock");
		const running = await startSupervisorServer({ socketPath });
		try {
			const response = await post(socketPath, validPrepare());
			expect(response.status).toBe(503);
			expect(JSON.parse(response.body).code).toBe("ADAPTER_NOT_CONFIGURED");
		} finally {
			await running.close();
		}
	});
});



function postRaw(socketPath: string, rawBody: string, contentType = "application/json"): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const value = request(
			{ socketPath, method: "POST", path: "/v1/rpc", headers: { "content-type": contentType, "content-length": Buffer.byteLength(rawBody) } },
			(response) => {
				let data = "";
				response.setEncoding("utf8");
				response.on("data", (chunk) => (data += chunk));
				response.on("end", () => resolve({ status: response.statusCode ?? 0, body: data }));
			},
		);
		value.once("error", reject);
		value.write(rawBody);
		value.end();
	});
}

describe("sandbox supervisor oversized request handling", () => {
	test("returns a JSON 413 for a body over the 64 KiB protocol limit", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-rpc-"));
		const socketPath = join(directory, "supervisor.sock");
		const { adapter } = spyAdapter();
		const running = await startSupervisorServer({ socketPath, adapter });
		try {
			const response = await postRaw(socketPath, "x".repeat(70 * 1024));
			expect(response.status).toBe(413);
			expect(JSON.parse(response.body).code).toBe("BODY_TOO_LARGE");
		} finally {
			await running.close();
		}
	});

	test("returns a JSON 413 (not ECONNRESET) for a body over the 1 MiB stream backstop", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-rpc-"));
		const socketPath = join(directory, "supervisor.sock");
		const { adapter } = spyAdapter();
		const running = await startSupervisorServer({ socketPath, adapter });
		try {
			const response = await postRaw(socketPath, "x".repeat(1100 * 1024));
			expect(response.status).toBe(413);
			expect(JSON.parse(response.body).code).toBe("BODY_TOO_LARGE");
		} finally {
			await running.close();
		}
	});
});
