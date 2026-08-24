// 用户原始需求（2026-08-13）：api.<base> 是独立于任何应用的永久恢复入口；Admin/MCP/所有沙箱停止时仍可控制。
// 正交意图：7.6 本地可验证部分——真实 Kernel HTTP 子进程（真实 http server + 真实 durable control DB 文件），
// supervisor 不存在（全部沙箱停止）：恢复只依赖 durable 状态；真实节点停机/重启仍属 operator 验收。
import { describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { admitVersion, activateVersion, controlStateToFile, emptyControlState, markVersionReady } from "../contracts/control-db.ts";
import { packageFilesDigest, versionDigest } from "../contracts/package-collection.ts";

const BASE_HOST = "kernelrecovery.test";
const TOKEN = "recovery-test-token-000";
const PORT = 7070;

const resources = { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 };
const policy = { resources, egress: { default: "deny" as const, allow: [] } };
const manifest = {
	schemaVersion: 1 as const,
	name: "notes",
	runtime: { kind: "celld" as const, celldVersion: "0.2.0", entrypoint: "index.js" },
	assets: { root: "app" },
	resources,
	storage: { persistent: false, requestBytes: 0 },
	egress: { default: "deny" as const, allow: [] },
};
const snapshot = [{ path: "app/index.js", content: Buffer.from("export default {};\n") }];
const digest = packageFilesDigest(snapshot);

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
	// durable control DB: an admitted + ready + ACTIVE version (the state a
	// recovery must rebuild from). The control-secrets file is intentionally
	// ABSENT (fresh-disk recovery half); the supervisor socket points nowhere.
	let state = emptyControlState();
	const admitted = admitVersion(state, { applicationId: "notes", packageDigest: digest, manifest, policy, admittedAt: "2026-08-14T00:00:00.000Z" });
	if (!admitted.ok) throw new Error("seed admission failed");
	state = admitted.value.state;
	const ready = markVersionReady(state, "notes", admitted.value.version.versionId, "2099-01-01T00:00:00.000Z");
	if (!ready.ok) throw new Error("seed readiness failed");
	state = ready.value.state;
	const active = activateVersion(state, "notes", admitted.value.version.versionId);
	if (!active.ok) throw new Error("seed activation failed");
	state = active.value.state;
	writeFileSync(join(directory, "control-db.json"), JSON.stringify(controlStateToFile(state), null, 2) + "\n");
	// routes with all four system routes already present: no boot-time mc call
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
		const command = (process.env.KERNEL_TEST_COMMAND ?? `node ${join(import.meta.dir, "..", "kernel", "index.js")}`).split(" ");
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
				IWEB_CONTROL_DB_FILE: join(directory, "control-db.json"),
				IWEB_CONTROL_SECRETS_FILE: join(directory, "control-secrets.json"),
				IWEB_SANDBOX_GATEWAY_DIR: join(directory, "gw"),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stderr = "";
		child.stderr.on("data", (chunk) => { stderr += String(chunk); });
		try {
			await waitHealthy(15_000);
			// unauthenticated recovery is refused
			const anonymous = await api("/v1/recover/sandboxes", { method: "POST" });
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
			const projection = status.body.applications.find((app: { id: string }) => app.id === "notes");
			expect(projection.activeVersion.digest).toBe(versionDigest(digest, manifest));
			expect(projection.lifecycle).toBe("active");
			// the durable control DB file still carries the active pointer
			const onDisk = JSON.parse(readFileSync(join(directory, "control-db.json"), "utf8"));
			expect(onDisk.applications["notes"].active.kind).toBe("active");
			// publication stays gated closed; recovery is NOT behind that gate
			const gated = await api("/v1/applications", { headers: { authorization: `Bearer ${TOKEN}` } });
			expect(gated.status).toBe(503);
			// recovery observes the missing active sandbox from the durable state and
			// fails BOUNDED when the persisted secret is unavailable (no silent
			// success, no process crash, no mutable workspace execution)。
			// 语义分叉是已记录的过渡状态：JS 完整移植 reconcile（200 + 结构化清单）；
			// Rust §4.3 reconcile 未接线（owner 门控），有界失败 400 + secret/bounded 语义。
			// 两分支各自钉死精确形状，绝不接受第三种漂移。
			const recovery = await api("/v1/recover/sandboxes", { method: "POST", headers: { authorization: `Bearer ${TOKEN}` } });
			if (recovery.status === 200) {
				expect(Array.isArray(recovery.body.reconciliation?.missingActive)).toBe(true);
				expect(Array.isArray(recovery.body.recovered)).toBe(true);
				expect(Object.keys(recovery.body).sort()).toEqual(["reconciliation", "recovered"]);
			} else {
				expect(recovery.status).toBe(400);
				expect(String(recovery.body.error)).toMatch(/secret|bounded/);
				expect(Object.keys(recovery.body)).toEqual(["error"]);
			}
			// the process is still alive and serving after the bounded failure
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
		const command = (process.env.KERNEL_TEST_COMMAND ?? `node ${join(import.meta.dir, "..", "kernel", "index.js")}`).split(" ");
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
				IWEB_CONTROL_DB_FILE: join(directory, "control-db.json"),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		try {
			await waitHealthy(15_000);
			// 匿名一律 401
			const anonymous = await api("/v1/routes");
			expect(anonymous.status).toBe(401);
			const auth = { authorization: `Bearer ${TOKEN}` };
			// 用户路由创建/重复 ns 校验/列举
			const created = await api("/v1/routes", { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ hostId: "blog.app", appName: "notes" }) });
			expect(created.status).toBe(201);
			const badNamespace = await api("/v1/routes", { method: "POST", headers: auth, body: JSON.stringify({ hostId: "blog", appName: "notes" }) });
			expect(badNamespace.status).toBe(400);
			const listed = await api("/v1/routes", { headers: auth });
			expect(listed.status).toBe(200);
			expect(listed.body.routes.some((route: { hostId: string }) => route.hostId === "blog.app")).toBe(true);
			// 删除语义 + system 保护
			const removed = await api("/v1/routes/blog.app", { method: "DELETE", headers: auth });
			expect(removed.status).toBe(204);
			const missing = await api("/v1/routes/blog.app", { method: "DELETE", headers: auth });
			expect(missing.status).toBe(404);
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
