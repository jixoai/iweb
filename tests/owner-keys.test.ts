// owner-key-management：多把可吊销 owner key 的黑盒契约（Rust 内核）。
// JS 参考内核冻结不实现本能力（对位 recover 端点先例），套件仅驱动 Rust。
import { describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE_HOST = "ownerkeys.test";
const BOOTSTRAP = "bootstrap-owner-token-000";
const PORT = 7070;

function seededDirectory(): string {
	const directory = mkdtempSync(join(tmpdir(), "iweb-owner-keys-"));
	const routes = { version: 1, routes: [
		{ hostId: "admin", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
	] };
	writeFileSync(join(directory, "routes.json"), `${JSON.stringify(routes)}\n`);
	return directory;
}

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

function bearer(token: string): { authorization: string } {
	return { authorization: `Bearer ${token}` };
}

// JS 冻结参考内核不实现 owner keys（spec 允许的过渡分叉）——仅 Rust 驱动。
const command = (process.env.KERNEL_TEST_COMMAND ?? "").split(" ").filter(Boolean);
const isRustKernel = command.length > 0 && !command[0].endsWith("node");

describe.skipIf(!isRustKernel)("owner keys (rust kernel only)", () => {
	test("lifecycle: create → use → audit attribution → ban → 401, bootstrap immutable", async () => {
		const directory = seededDirectory();
		const child = spawn(command[0], command.slice(1), {
			env: {
				...process.env,
				IWEB_BASE_HOST: BASE_HOST,
				IWEB_API_TOKEN: BOOTSTRAP,
				IWEB_HTTP_PORT: "38080",
				IWEB_ROUTES_FILE: join(directory, "routes.json"),
				IWEB_KEYS_FILE: join(directory, "keys.json"),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stderr = "";
		child.stderr.on("data", (chunk) => { stderr += String(chunk); });
		const api = (path: string, init: RequestInit = {}) =>
			fetch(`http://127.0.0.1:${PORT}${path}`, { ...init, headers: { host: `api.${BASE_HOST}`, ...(init.headers ?? {}) } });
		try {
			await waitHealthy(15_000);

			// bootstrap 依然可鉴权。
			expect((await api("/v1/status", { headers: bearer(BOOTSTRAP) })).status).toBe(200);

			// 未鉴权与错误 token 统一 401。
			expect((await api("/v1/status")).status).toBe(401);
			expect((await api("/v1/status", { headers: bearer("iwb_00000000_wrong") })).status).toBe(401);
			expect((await api("/v1/status", { headers: bearer("iwb_00000000_" + "A".repeat(43)) })).status).toBe(401);

			// 创建：非法输入拒绝且不留记录。
			expect((await api("/v1/keys", { method: "POST", headers: { ...bearer(BOOTSTRAP), "content-type": "application/json" }, body: JSON.stringify({ label: "", surplus: 1 }) })).status).toBe(400);
			expect((await api("/v1/keys", { method: "POST", headers: { ...bearer(BOOTSTRAP), "content-type": "application/json" }, body: JSON.stringify({ label: "ok", expiresAt: 123 }) })).status).toBe(400);
			expect((await api("/v1/keys", { method: "POST", headers: { ...bearer(BOOTSTRAP), "content-type": "application/json" }, body: JSON.stringify({ label: "ok", expiresAt: "2020-01-01T00:00:00.000Z" }) })).status).toBe(400);

			// 创建成功：token 只出现一次。
			const createResponse = await api("/v1/keys", { method: "POST", headers: { ...bearer(BOOTSTRAP), "content-type": "application/json" }, body: JSON.stringify({ label: "agent-a" }) });
			expect(createResponse.status).toBe(201);
			const created = await createResponse.json();
			expect(created.token).toMatch(/^iwb_[0-9a-f]{8}_[A-Za-z0-9_-]{42,44}$/);
			const keyId = created.key.keyId;
			expect(created.key).not.toHaveProperty("secretHash");
			expect(created.key).not.toHaveProperty("token");

			// delegated key 可用且列表含 bootstrap 合成条目（元数据无 secret）。
			expect((await api("/v1/status", { headers: bearer(created.token) })).status).toBe(200);
			const listResponse = await api("/v1/keys", { headers: bearer(created.token) });
			expect(listResponse.status).toBe(200);
			const list = await listResponse.json();
			const bootstrap = list.keys.find((key: { keyId: string }) => key.keyId === "bootstrap");
			const delegated = list.keys.find((key: { keyId: string }) => key.keyId === keyId);
			expect(bootstrap.revocable).toBe(false);
			expect(delegated.status).toBe("active");
			expect(delegated.revocable).toBe(true);
			expect(JSON.stringify(list)).not.toContain("secretHash");
			// token 明文绝不回读。
			expect(JSON.stringify(list)).not.toContain(created.token);

			// 审计归因：delegated key 的请求带 keyId；bootstrap 的请求归 bootstrap。
			expect((await api("/v1/routes", { headers: bearer(created.token) })).status).toBe(200);
			const auditResponse = await api("/v1/audit?keyId=" + keyId, { headers: bearer(BOOTSTRAP) });
			expect(auditResponse.status).toBe(200);
			const audit = await auditResponse.json();
			expect(audit.events.length).toBeGreaterThanOrEqual(1);
			expect(audit.events.every((event: { keyId?: string }) => event.keyId === keyId)).toBe(true);
			expect(JSON.stringify(audit)).not.toContain(created.token);
			// lifecycle 事件归因操作者（bootstrap 签发）。
			const allAudit = await (await api("/v1/audit?limit=200", { headers: bearer(BOOTSTRAP) })).json();
			const createEvent = allAudit.events.find((event: { action: string }) => event.action === "key.create");
			expect(createEvent.keyId).toBe("bootstrap");

			// 吊销：幂等、立即生效；bootstrap 不可吊销（409）。
			expect((await api(`/v1/keys/${keyId}`, { method: "DELETE", headers: bearer(BOOTSTRAP) })).status).toBe(204);
			expect((await api("/v1/status", { headers: bearer(created.token) })).status).toBe(401);
			expect((await api(`/v1/keys/${keyId}`, { method: "DELETE", headers: bearer(BOOTSTRAP) })).status).toBe(204);
			expect((await api("/v1/keys/bootstrap", { method: "DELETE", headers: bearer(BOOTSTRAP) })).status).toBe(409);
			expect((await api("/v1/status", { headers: bearer(BOOTSTRAP) })).status).toBe(200);

			// 吊销后列表状态与未知 key。
			const bannedList = await (await api("/v1/keys", { headers: bearer(BOOTSTRAP) })).json();
			expect(bannedList.keys.find((key: { keyId: string }) => key.keyId === keyId).status).toBe("banned");
			expect((await api("/v1/keys/ffffffff", { method: "DELETE", headers: bearer(BOOTSTRAP) })).status).toBe(404);
		} finally {
			child.kill("SIGTERM");
			await new Promise((resolve) => child.once("exit", resolve));
			rmSync(directory, { recursive: true, force: true });
			if (stderr.includes("panicked")) throw new Error(`kernel panicked:\n${stderr}`);
		}
	}, 30_000);
});
