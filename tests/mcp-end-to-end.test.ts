// 任务 4.3（owner-key-management）：MCP 端到端 fixture——用真实 Rust Kernel 子进程 +
// 真实 MCP Worker fetch 处理器，以 delegated key 调用 MCP 工具，断言 Kernel 审计事件
// 带有匹配的 keyId 且不含任何 bearer 材料（spec：A delegated MCP request is audited）。
// 正交覆盖：ban 后下一 JSON-RPC 请求 401（MCP has no long-lived authorization exemption）。
import { describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fetch as workerFetch } from "../apps/workers/mcp/src/index.ts";

const BASE_HOST = "mcpe2e.test";
const BOOTSTRAP = "bootstrap-owner-token-000";
const PORT = 7070;

function seededDirectory(): string {
	const directory = mkdtempSync(join(tmpdir(), "iweb-mcp-e2e-"));
	const routes = { version: 1, routes: [
		{ hostId: "admin", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
		{ hostId: "mcp", target: { kind: "celld-app", appName: "mcp" }, system: true, enabled: true },
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

async function api(path: string, init: RequestInit = {}): Promise<Response> {
	return fetch(`http://127.0.0.1:${PORT}${path}`, { ...init, headers: { host: `api.${BASE_HOST}`, ...(init.headers ?? {}) } });
}

function rpc(method: string, params: Record<string, unknown> | undefined, token: string): Promise<Response> {
	return workerFetch(
		new Request("https://mcp." + BASE_HOST + "/mcp", {
			method: "POST",
			headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
			body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, ...(params === undefined ? {} : { params }) }),
		}),
		{ IWEB_KERNEL_ORIGIN: `http://127.0.0.1:${PORT}` },
	);
}

const command = (process.env.KERNEL_TEST_COMMAND ?? "").split(" ").filter(Boolean);
const isRustKernel = command.length > 0 && !command[0].endsWith("node");

describe.skipIf(!isRustKernel)("MCP delegated-key end-to-end attribution (4.3, rust kernel only)", () => {
	test("a delegated tools/call is audited under its keyId with no bearer material; ban rejects the next request", async () => {
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
		try {
			await waitHealthy(15_000);

			// bootstrap 签发一把 delegated key（一次性明文只在本地变量中）。
			const createResponse = await api("/v1/keys", { method: "POST", headers: { authorization: `Bearer ${BOOTSTRAP}`, "content-type": "application/json" }, body: JSON.stringify({ label: "mcp-e2e-agent" }) });
			expect(createResponse.status).toBe(201);
			const created = (await createResponse.json()) as { token: string; key: { keyId: string } };
			const delegated = created.token;
			const keyId = created.key.keyId;

			// MCP initialize 与 tools/call 都以该 delegated key 工作。
			const init = await rpc("initialize", { protocolVersion: "2025-11-25" }, delegated);
			expect(init.status).toBe(200);
			expect(((await init.json()) as { result?: { serverInfo?: { name: string } } }).result?.serverInfo?.name).toBe("iweb-mcp");

			const call = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, delegated);
			expect(call.status).toBe(200);
			const callBody = (await call.json()) as { result?: { result?: { routes?: { hostId: string }[] } } };
			const hostIds = (callBody.result?.result?.routes ?? []).map((route) => route.hostId);
			expect(hostIds).toContain("mcp");
			expect(JSON.stringify(callBody)).not.toContain(delegated);

			// Kernel 审计归因：该 key 的请求（preflight /v1/status 与工具 /v1/routes）
			// 都记录为对应 keyId，无 bearer 材料。
			const auditResponse = await api(`/v1/audit?keyId=${keyId}&limit=200`, { headers: { authorization: `Bearer ${BOOTSTRAP}` } });
			expect(auditResponse.status).toBe(200);
			const audit = (await auditResponse.json()) as { events: { keyId: string | null; action: string; method: string; path: string; status: number }[]; dropped: number };
			expect(audit.events.length).toBeGreaterThanOrEqual(2);
			expect(audit.events.every((event) => event.keyId === keyId)).toBe(true);
			const routesEvent = audit.events.find((event) => event.path === "/v1/routes" && event.method === "GET");
			expect(routesEvent).toBeDefined();
			expect(routesEvent?.status).toBe(200);
			expect(audit.events.some((event) => event.path === "/v1/status" && event.method === "GET")).toBe(true);
			const auditText = JSON.stringify(audit);
			expect(auditText).not.toContain(delegated);
			expect(auditText).not.toContain("Bearer");
			expect(auditText).not.toContain("authorization");

			// ban：下一 JSON-RPC 请求（这里 tools/call）立即 401，不返回能力也不调工具。
			const ban = await api(`/v1/keys/${keyId}`, { method: "DELETE", headers: { authorization: `Bearer ${BOOTSTRAP}` } });
			expect(ban.status).toBe(204);
			const rejected = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, delegated);
			expect(rejected.status).toBe(401);
			const rejectedInit = await rpc("initialize", { protocolVersion: "2025-11-25" }, delegated);
			expect(rejectedInit.status).toBe(401);

			// 拒绝事件进入审计（banned key 鉴权失败 → 未归属 keyId null 的 401 事件）。
			const afterBan = (await (await api("/v1/audit?limit=50", { headers: { authorization: `Bearer ${BOOTSTRAP}` } })).json()) as { events: { keyId: string | null; status: number; path: string }[] };
			expect(afterBan.events.some((event) => event.status === 401 && event.keyId === null && event.path === "/v1/status")).toBe(true);
			expect(JSON.stringify(afterBan)).not.toContain(delegated);
		} finally {
			child.kill("SIGTERM");
			await new Promise((resolve) => child.once("exit", resolve));
			rmSync(directory, { recursive: true, force: true });
			if (stderr.includes("panicked")) throw new Error(`kernel panicked:\n${stderr}`);
		}
	}, 30_000);

	// 6.3 直连 WS 冒烟：delegated key 票据 → 首帧快照 → ban 立即关闭；票据只在
	// 升级 query 中一次性出现，不进审计/子协议（spec：Ban closes a delegated
	// monitor stream；owner key 绝不进入 monitor URL/fragment/subprotocol）。
	test("monitor WS smoke: delegated ticket connects, ban closes the stream", async () => {
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
		try {
			await waitHealthy(15_000);
			const createResponse = await api("/v1/keys", { method: "POST", headers: { authorization: `Bearer ${BOOTSTRAP}`, "content-type": "application/json" }, body: JSON.stringify({ label: "ws-smoke-agent" }) });
			expect(createResponse.status).toBe(201);
			const created = (await createResponse.json()) as { token: string; key: { keyId: string } };
			const delegated = created.token;
			const keyId = created.key.keyId;

			const ticketResponse = await api("/v1/monitor/session", { method: "POST", headers: { authorization: `Bearer ${delegated}` } });
			expect(ticketResponse.status).toBe(201);
			const ticket = ((await ticketResponse.json()) as { ticket: string }).ticket;
			expect(ticket).not.toContain(delegated);

			const socket = new WebSocket(`ws://127.0.0.1:${PORT}/v1/monitor?ticket=${encodeURIComponent(ticket)}`);
			const firstFrame = await new Promise<string>((resolve, reject) => {
				const fail = setTimeout(() => reject(new Error("monitor WS first frame did not arrive")), 10_000);
				socket.addEventListener("message", (event: MessageEvent) => {
					clearTimeout(fail);
					resolve(String(event.data));
				});
				socket.addEventListener("error", () => { clearTimeout(fail); reject(new Error("monitor WS connection failed")); });
			});
			const frame = JSON.parse(firstFrame) as { type: string; node?: unknown };
			expect(frame.type).toBe("snapshot");
			expect(firstFrame).not.toContain(delegated);
			expect(firstFrame).not.toContain(ticket);

			// ban 该 key：长连接立即被关闭（policy revocation close）。
			const closed = new Promise<void>((resolve) => socket.addEventListener("close", () => resolve()));
			const ban = await api(`/v1/keys/${keyId}`, { method: "DELETE", headers: { authorization: `Bearer ${BOOTSTRAP}` } });
			expect(ban.status).toBe(204);
			await Promise.race([closed, new Promise((_, reject) => setTimeout(() => reject(new Error("monitor WS was not closed after ban")), 10_000))]);

			// 审计：票据与 bearer 都不在事件里；建立事件（WS GET 只带票据、无 bearer）
			// 未归属 keyId=101；ban 关闭事件按连接主体归因该 keyId=1005。
			const audit = (await (await api("/v1/audit?limit=200", { headers: { authorization: `Bearer ${BOOTSTRAP}` } })).json()) as { events: { keyId: string | null; action: string; path: string; status: number }[] };
			const auditText = JSON.stringify(audit);
			expect(auditText).not.toContain(ticket);
			expect(auditText).not.toContain(delegated);
			expect(audit.events.some((event) => event.keyId === null && event.path === "/v1/monitor" && event.status === 101)).toBe(true);
			expect(audit.events.some((event) => event.keyId === keyId && event.path === "/v1/monitor" && event.status === 1005)).toBe(true);
		} finally {
			child.kill("SIGTERM");
			await new Promise((resolve) => child.once("exit", resolve));
			rmSync(directory, { recursive: true, force: true });
			if (stderr.includes("panicked")) throw new Error(`kernel panicked:\n${stderr}`);
		}
	}, 30_000);
});
