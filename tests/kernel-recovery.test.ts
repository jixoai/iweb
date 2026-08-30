// 用户原始需求（2026-08-13）：api.<base> 是独立于任何应用的永久恢复入口；Admin/MCP/所有沙箱停止时仍可控制。
// 正交意图：7.6 本地可验证部分——真实 Kernel HTTP 子进程（真实 http server + 真实 durable control DB 文件），
// supervisor 不存在（全部沙箱停止）：恢复只依赖 durable 状态；真实节点停机/重启仍属 operator 验收。
import { describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE_HOST = "kernelrecovery.test";
const TOKEN = "recovery-test-token-000";
const PORT = 7070;

async function waitHealthy(timeoutMs: number): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const response = await fetch(`http://127.0.0.1:${PORT}/health`);
			if (response.ok) return;
		} catch {
			// not listening yet
		}
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
	throw new Error("kernel subprocess did not become healthy in time");
}

function seededDirectory(): string {
	const directory = mkdtempSync(join(tmpdir(), "iweb-kernel-recovery-"));
	// two-tier-runtime-trust：celld 控制状态不存在；路由种子即持久真相。
	// The supervisor socket points nowhere (absent-supervisor half).
	const routes = { version: 1, routes: [
		{ hostId: "admin", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
		{ hostId: "admin.app", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
		{ hostId: "mcp", target: { kind: "celld-app", appName: "mcp" }, system: true, enabled: true },
		{ hostId: "mcp.app", target: { kind: "celld-app", appName: "mcp" }, system: true, enabled: true },
	] };
	writeFileSync(join(directory, "routes.json"), JSON.stringify(routes, null, 2) + "\n");
	return directory;
}

async function api(path: string, init: RequestInit = {}): Promise<{ status: number; body: any }> {
	const headers = new Headers(init.headers);
	headers.set("host", `api.${BASE_HOST}`);
	const response = await fetch(`http://127.0.0.1:${PORT}${path}`, { ...init, headers });
	const body = await response.json().catch(() => ({}));
	return { status: response.status, body };
}

describe("api.<base> independent recovery (7.6 contributor half)", () => {
	test("with the supervisor absent, Kernel still serves durable state and bounded recovery from api.<base>", async () => {
		const directory = seededDirectory();
		// rust-kernel-rustfs-storage §3.3：同一黑盒套件驱动任一 Kernel 实现。
		// KERNEL_TEST_COMMAND 例："<repo>/kernel-rs/target/debug/iweb-kernel"（argv 整体 split）。
		const command = (process.env.KERNEL_TEST_COMMAND ?? `${join(import.meta.dir, "..", "kernel-rs", "target", "debug", "iweb-kernel")}`).split(" ");
		const child = spawn(command[0], command.slice(1), {
			env: {
				...process.env,
				IWEB_BASE_HOST: BASE_HOST,
				IWEB_API_TOKEN: TOKEN,
				IWEB_ROUTES_FILE: join(directory, "routes.json"),
				IWEB_RECOVERY_WORKER: "recovery-worker",
				IWEB_ADMIN_CELLD_BUCKET: "iweb-cells-admin",
				IWEB_CELLD_ENDPOINT: "http://127.0.0.1:9000",
				IWEB_CELLD_REGION: "us-east-1",
				IWEB_SANDBOX_SOCKET: join(directory, "supervisor.sock"),
				IWEB_CONTROL_SECRETS_FILE: join(directory, "control-secrets.json"),
				IWEB_SANDBOX_GATEWAY_DIR: join(directory, "gw"),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stderr = "";
		child.stderr.on("data", (chunk) => { stderr += String(chunk); });
		try {
			await waitHealthy(15_000);
			// removed celld admission paths answer a stable terminal error, auth first
			const anonymous = await api("/v1/applications", { method: "POST" });
			expect(anonymous.status).toBe(401);
			// CORS（2026-08-21 真浏览器登录暴露的 Rust 移植缺口，纳入共享黑盒契约）：
			// Admin 从 admin.<base>/<base>/admin.app.<base> 跨域调 api.<base>——合法来源回显，
			// 其余不发 CORS 头；preflight（带 access-control-request-* 的 OPTIONS）免鉴权 204。
			const preflight = await fetch(`http://127.0.0.1:${PORT}/v1/status`, {
				method: "OPTIONS",
				headers: {
					host: `api.${BASE_HOST}`,
					origin: `https://admin.${BASE_HOST}`,
					"access-control-request-method": "GET",
					"access-control-request-headers": "authorization",
				},
			});
			expect(preflight.status).toBe(204);
			expect(preflight.headers.get("access-control-allow-origin")).toBe(`https://admin.${BASE_HOST}`);
			const corsAllowed = await fetch(`http://127.0.0.1:${PORT}/v1/status`, {
				headers: { host: `api.${BASE_HOST}`, origin: `https://admin.${BASE_HOST}` },
			});
			expect(corsAllowed.status).toBe(401);
			expect(corsAllowed.headers.get("access-control-allow-origin")).toBe(`https://admin.${BASE_HOST}`);
			const corsDenied = await fetch(`http://127.0.0.1:${PORT}/v1/status`, {
				headers: { host: `api.${BASE_HOST}`, origin: "https://evil.example" },
			});
			expect(corsDenied.status).toBe(401);
			expect(corsDenied.headers.get("access-control-allow-origin")).toBeNull();
			// the control plane stays available from durable state alone
			const status = await api("/v1/status", { headers: { authorization: `Bearer ${TOKEN}` } });
			expect(status.status).toBe(200);
			expect(status.body.baseHost).toBe(BASE_HOST);
			expect(status.body.sandboxSupervisor.available).toBe(false);
			// 路由派生 fleet 投影（admin/mcp 去重各一）；无采样 = unavailable。
			const adminProjection = status.body.applications.find((app: { id: string }) => app.id === "admin");
			expect(adminProjection.runtimeKind).toBe("celld");
			expect(adminProjection.lifecycle).toBe("unavailable");
			expect(status.body.applications).toHaveLength(2);
			expect(status.body.watchdog.intervalMs).toBeGreaterThan(0);
			// celld admission is a removed terminal contract, not a gate that can open
			const gated = await api("/v1/applications", { headers: { authorization: `Bearer ${TOKEN}` } });
			expect(gated.status).toBe(410);
			expect(gated.body.error).toBe("CELLD_ADMISSION_REMOVED");
			// the process is still alive and serving
			const after = await api("/v1/status", { headers: { authorization: `Bearer ${TOKEN}` } });
			expect(after.status).toBe(200);
		} finally {
			child.kill("SIGTERM");
			await new Promise((resolve) => child.once("exit", resolve));
			rmSync(directory, { recursive: true, force: true });
			if (stderr && !/startup sandbox reconciliation unavailable/.test(stderr)) {
				console.error("kernel subprocess stderr:", stderr.slice(0, 500));
			}
		}
	}, 30_000);

	// rust-kernel-rustfs-storage §4 平价面：路由 CRUD 与 monitor 票据对两种实现同契约。
	test("routes CRUD and monitor ticket obey the same contract on any kernel", async () => {
		const directory = seededDirectory();
		// 路由/工作区持久化在 JS kernel 经 mc 子进程、在 Rust kernel 走本地文件——
		// 黑盒中立：提供一个 no-op mc shim（无对象存储时两侧行为一致）。
		const shimDir = join(directory, "bin");
		mkdirSync(shimDir, { recursive: true });
		writeFileSync(join(shimDir, "mc"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
		const command = (process.env.KERNEL_TEST_COMMAND ?? `${join(import.meta.dir, "..", "kernel-rs", "target", "debug", "iweb-kernel")}`).split(" ");
		const child = spawn(command[0], command.slice(1), {
			env: {
				...process.env,
				PATH: `${shimDir}:${process.env.PATH ?? ""}`,
				IWEB_BASE_HOST: BASE_HOST,
				IWEB_API_TOKEN: TOKEN,
				IWEB_ROUTES_FILE: join(directory, "routes.json"),
				IWEB_RECOVERY_WORKER: "recovery-worker",
				IWEB_ADMIN_CELLD_BUCKET: "iweb-cells-admin",
				IWEB_CELLD_ENDPOINT: "http://127.0.0.1:9000",
				IWEB_CELLD_REGION: "us-east-1",
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		try {
			await waitHealthy(15_000);
			// 匿名一律 401
			const anonymous = await api("/v1/routes");
			expect(anonymous.status).toBe(401);
			const auth = { authorization: `Bearer ${TOKEN}` };
			// two-tier-runtime-trust 9.9：用户路由只指向已准入的 wasm 应用——
			// 未准入应用名（notes 是 celld fleet）创建被 409 拒绝；ns 校验仍先行。
			const notAdmitted = await api("/v1/routes", { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ hostId: "blog.app", appName: "notes" }) });
			expect(notAdmitted.status).toBe(409);
			expect(notAdmitted.body.error).toBe("WASM_APPLICATION_NOT_ADMITTED");
			const badNamespace = await api("/v1/routes", { method: "POST", headers: auth, body: JSON.stringify({ hostId: "blog", appName: "notes" }) });
			expect(badNamespace.status).toBe(400);
			const listed = await api("/v1/routes", { headers: auth });
			expect(listed.status).toBe(200);
			// system 保护
			const systemProtected = await api("/v1/routes/admin", { method: "DELETE", headers: auth });
			expect(systemProtected.status).toBe(409);
			// monitor 票据：签发形状 + 复用拒绝
			const session = await api("/v1/monitor/session", { method: "POST", headers: auth });
			expect(session.status).toBe(201);
			expect(typeof session.body.ticket).toBe("string");
			expect(session.body.ticket.length >= 20).toBe(true);
		} finally {
			child.kill("SIGTERM");
			await new Promise((resolve) => child.once("exit", resolve));
			rmSync(directory, { recursive: true, force: true });
		}
	}, 30_000);
});
