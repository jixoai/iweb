// 任务 4.1/4.2（owner-key-management）：MCP Worker 逐 JSON-RPC 请求鉴权契约 +
// 转发证明。spec：每个请求（initialize、tools/list、到达服务器的 notifications、
// tools/call）都必须先完成 owner 鉴权；Worker 精确转发当前请求的 Authorization，
// 不接受 actor/key-id 覆盖，不存储凭证，ban 后透出 Kernel 401；不在 Worker 内
// 实现 JS 授权副本（唯一权威是 Kernel /v1/status preflight + 逐请求转发）。
import { describe, expect, test } from "bun:test";
import { fetch as workerFetch } from "../apps/workers/mcp/src/index.ts";

const BOOTSTRAP = "bootstrap-owner-token-000";
const DELEGATED = "iwb_0abc45de_" + "c3RyZWFrLXBhcnQtdGVzdC1zZWNyZXQtdmFsdWU".slice(0, 43);
const KERNEL_ORIGIN = "http://127.0.0.1:7070";

interface RecordedCall {
	path: string;
	method: string;
	authorization: string | null;
	headerNames: string[];
}

/** Kernel 替身：只接受 allowed 集合内的 Bearer；记录出站头供精确断言。 */
function stubKernel(allowed: Set<string>) {
	const calls: RecordedCall[] = [];
	const original = globalThis.fetch;
	globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
		const headers = new Headers(init?.headers);
		calls.push({
			path: url.slice(KERNEL_ORIGIN.length),
			method: init?.method ?? "GET",
			authorization: headers.get("authorization"),
			headerNames: [...headers.keys()].sort(),
		});
		const bearer = headers.get("authorization") ?? "";
		const accepted = allowed.has(bearer.replace(/^Bearer /, ""));
		const status = accepted ? 200 : 401;
		if (url.endsWith("/v1/routes")) return new Response(JSON.stringify({ routes: accepted ? [] : [], ...(accepted ? {} : { error: "missing or invalid API token" }) }), { status, headers: { "content-type": "application/json" } });
		return new Response(JSON.stringify(accepted ? { ok: true } : { error: "missing or invalid API token" }), { status, headers: { "content-type": "application/json" } });
	}) as typeof fetch;
	return {
		calls,
		restore: () => {
			globalThis.fetch = original;
		},
		allow: (key: string) => allowed.add(key),
		deny: (key: string) => allowed.delete(key),
	};
}

function rpc(method: string, params: Record<string, unknown> | undefined, headers: Record<string, string>): Promise<Response> {
	return workerFetch(
		new Request("https://mcp.base.test/mcp", {
			method: "POST",
			headers: { "content-type": "application/json", ...headers },
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...(params === undefined ? {} : { params }) }),
		}),
		{ IWEB_KERNEL_ORIGIN: KERNEL_ORIGIN },
	);
}

const METHODS: { method: string; params?: Record<string, unknown> }[] = [
	{ method: "initialize", params: { protocolVersion: "2025-11-25" } },
	{ method: "tools/list" },
	{ method: "notifications/initialized" },
	{ method: "tools/call", params: { name: "iweb_domain_list", arguments: {} } },
];

describe("4.1 MCP authenticates every JSON-RPC request (initialize/tools/notifications/call)", () => {
	test("a request without a key is rejected 401 before any capability or tool invocation", async () => {
		const kernel = stubKernel(new Set([BOOTSTRAP]));
		try {
			for (const { method, params } of METHODS) {
				const response = await rpc(method, params, {});
				expect(response.status, method + " must 401").toBe(401);
				expect(response.headers.get("www-authenticate")).toBe("Bearer");
				const body = await response.text();
				expect(body).not.toContain("serverInfo");
				expect(body).not.toContain("iweb_");
			}
			// 缺失 Bearer 前缀在 Worker 侧短路：连 preflight 都不打到 Kernel。
			expect(kernel.calls).toHaveLength(0);
		} finally {
			kernel.restore();
		}
	});

	test("every authenticated method first proves the bearer against the Kernel preflight", async () => {
		const kernel = stubKernel(new Set([BOOTSTRAP, DELEGATED]));
		try {
			// bootstrap 与 delegated key 都能 initialize 并拿到能力元数据。
			for (const key of [BOOTSTRAP, DELEGATED]) {
				const init = await rpc("initialize", { protocolVersion: "2025-11-25" }, { authorization: `Bearer ${key}` });
				expect(init.status, key.slice(0, 12) + " initialize").toBe(200);
				const body = (await init.json()) as { result?: { serverInfo?: { name: string }; capabilities?: Record<string, unknown> } };
				expect(body.result?.serverInfo?.name).toBe("iweb-mcp");
				expect(body.result?.capabilities).toHaveProperty("tools");
			}
			const list = await rpc("tools/list", undefined, { authorization: `Bearer ${BOOTSTRAP}` });
			expect(list.status).toBe(200);
			expect(((await list.json()) as { result?: { tools?: unknown[] } }).result?.tools?.length).toBeGreaterThan(0);
			const notification = await rpc("notifications/initialized", undefined, { authorization: `Bearer ${DELEGATED}` });
			expect(notification.status).toBe(202);
			const call = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: `Bearer ${DELEGATED}` });
			expect(call.status).toBe(200);
			expect(((await call.json()) as { result?: { result?: unknown } }).result).toHaveProperty("result");
			// 每个请求都以 /v1/status preflight 开头（initialize 也一样）：
			// 2×initialize + tools/list + notification + tools/call = 5 次 preflight。
			const preflights = kernel.calls.filter((entry) => entry.path === "/v1/status");
			expect(preflights.length).toBe(5);
			expect(kernel.calls.map((entry) => entry.path)).toEqual([
				"/v1/status", "/v1/status", "/v1/status", "/v1/status", "/v1/status", "/v1/routes",
			]);
		} finally {
			kernel.restore();
		}
	});

	test("an invalid bearer surfaces the Kernel 401 for every method without invoking tools", async () => {
		const kernel = stubKernel(new Set());
		try {
			for (const { method, params } of METHODS) {
				const response = await rpc(method, params, { authorization: `Bearer ${DELEGATED}` });
				expect(response.status, method + " must surface the kernel 401").toBe(401);
			}
			// 只有 preflight 被尝试；工具路径从未被调用。
			expect(kernel.calls.map((entry) => entry.path)).toEqual(["/v1/status", "/v1/status", "/v1/status", "/v1/status"]);
		} finally {
			kernel.restore();
		}
	});

	test("after a ban the next request of every kind is 401 and no tool runs", async () => {
		const kernel = stubKernel(new Set([DELEGATED]));
		try {
			const before = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: `Bearer ${DELEGATED}` });
			expect(before.status).toBe(200);
			kernel.deny(DELEGATED);
			const callsBeforeBan = kernel.calls.length;
			for (const { method, params } of METHODS) {
				const response = await rpc(method, params, { authorization: `Bearer ${DELEGATED}` });
				expect(response.status, method + " after ban must be 401").toBe(401);
			}
			// ban 之后只有 preflight 尝试，工具路径从未再次被调用。
			expect(kernel.calls.slice(callsBeforeBan).map((entry) => entry.path)).toEqual(["/v1/status", "/v1/status", "/v1/status", "/v1/status"]);
		} finally {
			kernel.restore();
		}
	});
});

describe("4.2 the Worker forwards the exact credential and adds no authority of its own", () => {
	test("forwards the exact current Authorization header byte-for-byte on every kernel call", async () => {
		// 值含大小写、'-'、'_'——任何改写/重建都会破坏字节相等。
		const exoticSecret = "Tk9ULUVOQU5DRUQtWlp1NUk2d1BWX0EtbWNTZWNyZXQ".slice(0, 43);
		const exotic = `Bearer iweb_0Ff1a2b3_${exoticSecret}`;
		const kernel = stubKernel(new Set());
		try {
			// stub 尚未放行该 key：401 恰好证明 Kernel 侧看到的是原值本身。
			const probe = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: exotic });
			expect(probe.status).toBe(401);
			expect(kernel.calls[0]?.authorization).toBe(exotic);
			// 放行这个精确值后，工具调用链上（preflight + 工具 GET）同样是原值。
			kernel.allow(exotic.slice("Bearer ".length));
			const call = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: exotic });
			expect(call.status).toBe(200);
			expect(kernel.calls.map((entry) => entry.authorization)).toEqual([exotic, exotic, exotic]);
		} finally {
			kernel.restore();
		}
	});

	test("does not accept caller-controlled actor/key-id overrides", async () => {
		const kernel = stubKernel(new Set([DELEGATED]));
		try {
			const response = await rpc(
				"tools/call",
				{ name: "iweb_domain_list", arguments: {} },
				{
					authorization: `Bearer ${DELEGATED}`,
					"x-iweb-actor": "bootstrap",
					"x-iweb-key-id": "00000000",
					"x-actor-id": "bootstrap",
					"actor": "bootstrap",
				},
			);
			expect(response.status).toBe(200);
			for (const entry of kernel.calls) {
				// 出站头只有 authorization（+ 工具 POST 的 content-type）——任何覆盖头都不透传。
				expect(entry.headerNames.filter((name) => name.startsWith("x-") || name === "actor")).toEqual([]);
				expect(entry.authorization).toBe(`Bearer ${DELEGATED}`);
			}
		} finally {
			kernel.restore();
		}
	});

	test("stores no credential: each request forwards only its own key and responses never echo one", async () => {
		const keyA = "iweb_aa000000_" + "A".repeat(43);
		const keyB = "iweb_bb000000_" + "B".repeat(43);
		const kernel = stubKernel(new Set([keyA, keyB]));
		try {
			const first = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: `Bearer ${keyA}` });
			const firstText = await first.text();
			expect(first.status).toBe(200);
			expect(firstText).not.toContain(keyA);
			expect(firstText).not.toContain("Bearer ");
			const second = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: `Bearer ${keyB}` });
			const secondText = await second.text();
			expect(second.status).toBe(200);
			expect(secondText).not.toContain(keyA);
			expect(secondText).not.toContain(keyB);
			expect(secondText).not.toContain("Bearer ");
			// B 请求的两次 kernel 调用都只携带 B 的凭证（无跨请求状态）。
			const callsForB = kernel.calls.slice(-2);
			expect(callsForB.map((entry) => entry.authorization)).toEqual([`Bearer ${keyB}`, `Bearer ${keyB}`]);
		} finally {
			kernel.restore();
		}
	});

	test("a ban racing an authorized tool call fails boundedly with the Kernel 401 text", async () => {
		// preflight 已过（ban 之前），随后 Kernel 对工具操作返回 401：调用有界失败，
		// 绝不伪造成功，也绝不回显凭证。spec：Ban races an MCP tool call。
		const original = globalThis.fetch;
		const calls: string[] = [];
		let banned = false;
		try {
			globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
				const path = url.slice(KERNEL_ORIGIN.length);
				calls.push(path);
				if (path === "/v1/status") {
					// preflight 通过后 key 立刻被 ban：下一个 kernel 调用起全部 401。
					return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
				}
				const status = banned ? 401 : 200;
				return new Response(JSON.stringify(banned ? { error: "missing or invalid API token" } : { routes: [] }), { status, headers: { "content-type": "application/json" } });
			}) as typeof fetch;
			const authorized = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: `Bearer ${DELEGATED}` });
			const authorizedBody = (await authorized.json()) as { result?: { isError?: boolean } };
			expect(authorizedBody.result?.isError).toBeUndefined();
			banned = true;
			const response = await rpc("tools/call", { name: "iweb_domain_list", arguments: {} }, { authorization: `Bearer ${DELEGATED}` });
			expect(response.status).toBe(200); // JSON-RPC 层
			const body = (await response.json()) as { result?: { isError?: boolean; content?: { text?: string }[] } };
			expect(body.result?.isError).toBe(true);
			expect(body.result?.content?.[0]?.text).toContain("missing or invalid API token");
			expect(JSON.stringify(body)).not.toContain(DELEGATED);
			expect(calls).toEqual(["/v1/status", "/v1/routes", "/v1/status", "/v1/routes"]);
		} finally {
			globalThis.fetch = original;
		}
	});
});
