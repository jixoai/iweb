// 用户原始需求（2026-08-14）：supervisor 只能通过私有 Unix socket 提供有界服务。
// 正交意图：验证 socket 权限；验证健康协议；验证未知路由；验证关闭清理。
import { describe, expect, test } from "bun:test";
import { mkdtempSync, statSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startSupervisorServer } from "../supervisor/server.ts";
import {
	createFixedSupervisorConnectionAuthorization,
	requireFixedSupervisorSocketPath,
	SUPERVISOR_SOCKET_PATH,
} from "../supervisor/socket-auth.ts";
import supervisorClient from "../kernel/supervisor-client.js";

const { supervisorHealth } = supervisorClient;

function socketRequest(socketPath: string, path: string): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const value = request({ socketPath, method: "GET", path }, (response) => {
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

	test("reports an absent or unreachable supervisor without exposing connection details", async () => {
		expect(await supervisorHealth("")).toEqual({ configured: false, available: false, version: null });
		expect(await supervisorHealth("/tmp/iweb-supervisor-does-not-exist.sock")).toEqual({ configured: true, available: false, version: null });
	});

	test("fixed socket authorization rejects redirected paths and invalid listener inode facts", () => {
		expect(requireFixedSupervisorSocketPath(undefined)).toBe(SUPERVISOR_SOCKET_PATH);
		expect(requireFixedSupervisorSocketPath(SUPERVISOR_SOCKET_PATH)).toBe(SUPERVISOR_SOCKET_PATH);
		expect(() => requireFixedSupervisorSocketPath("/tmp/redirected-supervisor.sock")).toThrow();

		const valid = createFixedSupervisorConnectionAuthorization({
			socketPath: "/tmp/test-supervisor.sock",
			canonicalPath: "/tmp/test-supervisor.sock",
			expectedUid: 501,
			expectedGid: 20,
			lstat: () => ({ isSocket: () => true, mode: 0o140600, uid: 501, gid: 20 }),
		});
		expect(valid({ destroyed: false })).toBe(true);
		expect(valid({ destroyed: true })).toBe(false);

		const wrongOwner = createFixedSupervisorConnectionAuthorization({
			socketPath: "/tmp/test-supervisor.sock",
			canonicalPath: "/tmp/test-supervisor.sock",
			expectedUid: 501,
			expectedGid: 20,
			lstat: () => ({ isSocket: () => true, mode: 0o140600, uid: 502, gid: 20 }),
		});
		expect(wrongOwner({ destroyed: false })).toBe(false);

		const wrongMode = createFixedSupervisorConnectionAuthorization({
			socketPath: "/tmp/test-supervisor.sock",
			canonicalPath: "/tmp/test-supervisor.sock",
			expectedUid: 501,
			expectedGid: 20,
			lstat: () => ({ isSocket: () => true, mode: 0o140660, uid: 501, gid: 20 }),
		});
		expect(wrongMode({ destroyed: false })).toBe(false);
	});
});
