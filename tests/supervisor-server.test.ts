// 用户原始需求（2026-08-14）：supervisor 只能通过私有 Unix socket 提供有界服务。
// 正交意图：验证 socket 权限；验证健康协议；验证未知路由；验证关闭清理。
import { describe, expect, test } from "bun:test";
import { mkdtempSync, statSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startSupervisorServer } from "../supervisor/server.ts";
import {
	createRelayRequestAuthorization,
	fixedSupervisorInternalSocketPath,
	RELAY_AUTHORIZATION_HEADER,
	requireFixedSupervisorSocketPath,
	SUPERVISOR_INTERNAL_SOCKET_PATH,
	SUPERVISOR_SOCKET_PATH,
} from "../supervisor/socket-auth.ts";
import supervisorClient from "../kernel/supervisor-client.js";

const { supervisorHealth } = supervisorClient;

function socketRequest(socketPath: string, path: string, headers: Readonly<Record<string, string>> = {}): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const value = request({ socketPath, method: "GET", path, headers }, (response) => {
			let body = "";
			response.setEncoding("utf8");
			response.on("data", (chunk) => body += chunk);
			response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
		});
		value.once("error", reject);
		value.end();
	});
}

describe("sandbox supervisor server", () => {
	test("binds a private Unix socket and exposes only versioned health", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-supervisor-"));
		const socketPath = join(directory, "supervisor.sock");
		const running = await startSupervisorServer({ socketPath });
		try {
			expect(statSync(socketPath).mode & 0o777).toBe(0o600);
			const health = await socketRequest(socketPath, "/v1/health");
			expect(health.status).toBe(200);
			expect(JSON.parse(health.body)).toEqual({ version: 1, service: "iweb-sandbox-supervisor", ready: true });
			const unknown = await socketRequest(socketPath, "/v1/unknown");
			expect(unknown.status).toBe(404);
			expect(await supervisorHealth(socketPath)).toEqual({ configured: true, available: true, version: 1 });
		} finally {
			await running.close();
		}
		expect(() => statSync(socketPath)).toThrow();
	});

	test("rejects every /v1/rpc request as the permanent CELLD_PROTOCOL_MISMATCH negative vector", async () => {
		// two-tier-runtime-trust：celld 执行语义退役后 /v1/rpc 恒拒——celld envelope、
		// execution envelope、raw snapshot magic 一律无副作用拒绝（无 adapter 可触达）。
		const directory = mkdtempSync(join(tmpdir(), "iweb-supervisor-rpc-"));
		const socketPath = join(directory, "supervisor.sock");
		const running = await startSupervisorServer({ socketPath });
		try {
			const post = (path: string, body: string): Promise<{ status: number; body: string }> =>
				new Promise((resolve, reject) => {
					const value = request({ socketPath, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) } }, (response) => {
						let data = "";
						response.setEncoding("utf8");
						response.on("data", (chunk: string) => (data += chunk));
						response.on("end", () => resolve({ status: response.statusCode ?? 0, body: data }));
					});
					value.once("error", reject);
					value.write(body);
					value.end();
				});
			for (const body of [
				JSON.stringify({ version: 1, operation: "inspect", sandboxId: "sbx-a" }),
				JSON.stringify({ protocol: "iweb-execution-rpc-v1", requestId: "018f1e2c-3d4b-7c6d-8e9f-001122334455", body: { kind: "query", commandId: "018f1e2c-3d4b-7c6d-8e9f-001122334456" } }),
				Buffer.from("4957454246443100", "hex").toString("latin1") + "rest",
			]) {
				const result = await post("/v1/rpc", body);
				expect(result.status).toBe(400);
				expect(JSON.parse(result.body).code).toBe("CELLD_PROTOCOL_MISMATCH");
			}
		} finally {
			await running.close();
		}
	});

	test("reports an absent or unreachable supervisor without exposing connection details", async () => {
		expect(await supervisorHealth("")).toEqual({ configured: false, available: false, version: null });
		expect(await supervisorHealth("/tmp/iweb-supervisor-does-not-exist.sock")).toEqual({ configured: true, available: false, version: null });
	});

	test("fixed socket authorization rejects redirected paths and Node accepts only relay-authenticated upstream requests", async () => {
		expect(requireFixedSupervisorSocketPath(undefined)).toBe(SUPERVISOR_SOCKET_PATH);
		expect(requireFixedSupervisorSocketPath(SUPERVISOR_SOCKET_PATH)).toBe(SUPERVISOR_SOCKET_PATH);
		expect(() => requireFixedSupervisorSocketPath("/tmp/redirected-supervisor.sock")).toThrow();
		expect(() => requireFixedSupervisorSocketPath("")).toThrow();
		expect(() => requireFixedSupervisorSocketPath(" ")).toThrow();
		expect(fixedSupervisorInternalSocketPath()).toBe(SUPERVISOR_INTERNAL_SOCKET_PATH);

		const token = "a".repeat(64);
		const authorize = createRelayRequestAuthorization(token);
		expect(authorize({ [RELAY_AUTHORIZATION_HEADER]: token })).toBe(true);
		expect(authorize({})).toBe(false);
		expect(authorize({ [RELAY_AUTHORIZATION_HEADER]: "b".repeat(64) })).toBe(false);
		expect(() => createRelayRequestAuthorization("not-a-token")).toThrow();

		const directory = mkdtempSync(join(tmpdir(), "iweb-supervisor-private-"));
		const socketPath = join(directory, "supervisor-internal.sock");
		const running = await startSupervisorServer({ socketPath, requestAuthorization: authorize });
		try {
			const direct = await socketRequest(socketPath, "/v1/health");
			expect(direct.status).toBe(401);
			const proxied = await socketRequest(socketPath, "/v1/health", { [RELAY_AUTHORIZATION_HEADER]: token });
			expect(proxied.status).toBe(200);
		} finally {
			await running.close();
		}
	});
});
