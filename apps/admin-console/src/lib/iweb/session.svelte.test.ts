// 用户原始需求（2026-08-23 / 任务 5.2，owner-key-management）：Admin 登录接受任意有效
// owner key（bootstrap 或委托 key），401 清除过期会话，且保持 不入 URL / 不入
// localStorage / 不进构建产物 的边界。正交意图：happy-dom 真组件级会话行为 +
// 源级边界断言（sessionStorage-only）。
import { describe, expect, test } from "vitest";
import source from "./session.svelte.ts?raw";
import pageSource from "../../routes/+page.svelte?raw";
import { ApiSession } from "./session.svelte";
import { KernelApiError } from "$lib/iweb/api";

const DELEGATED = "iwb_0abc45de_" + "A".repeat(43);
const OPAQUE_BOOTSTRAP = "opaque-bootstrap-owner-key";

// 与组件测试同约定（application-resource-table.svelte.test.ts）：无 DOM 的运行器
// （纯 bun test 发现）下显式跳过 DOM 行为断言，而不是失败测试电池。
const domAvailable = typeof window !== "undefined" && typeof window.sessionStorage !== "undefined";

function freshSession(): ApiSession {
	window.sessionStorage.clear();
	window.localStorage.clear();
	return new ApiSession();
}

describe.skipIf(!domAvailable)("Admin session accepts any valid owner key (5.2)", () => {
	test("a delegated-format key and an opaque bootstrap key both create a tab session", () => {
		for (const key of [DELEGATED, OPAQUE_BOOTSTRAP]) {
			const session = freshSession();
			session.login(key);
			expect(session.authenticated, "any owner key authenticates the tab").toBe(true);
			expect(session.ownerKey).toBe(key);
			// 只进 tab-scoped sessionStorage——localStorage/URL 永不承载。
			expect(window.sessionStorage.getItem("iweb-admin-owner-key")).toBe(key);
			expect(JSON.stringify(window.localStorage)).not.toContain(key);
			expect(window.location.search).not.toContain(key);
			expect(window.location.hash).not.toContain(key);
		}
	});

	test("logout clears the tab session; initialize restores it from sessionStorage only", () => {
		const session = freshSession();
		session.login(DELEGATED);
		session.logout();
		expect(session.authenticated).toBe(false);
		expect(window.sessionStorage.getItem("iweb-admin-owner-key")).toBeNull();

		session.login(OPAQUE_BOOTSTRAP);
		const reopened = new ApiSession();
		reopened.initialize();
		expect(reopened.authenticated).toBe(true);
		expect(reopened.ownerKey).toBe(OPAQUE_BOOTSTRAP);
	});

	test("a Kernel 401 rejects the client call and the stale session is cleared by logout", async () => {
		// 页面契约（+page.svelte showConnectionError / KeyManager onauthfailure）：
		// 任何 KernelApiError 401 都触发 logout——这里验证 session 与 client 的联合
		// 行为：401 可识别（KernelApiError.status）且 logout 后会话确实被清除。
		const session = freshSession();
		session.login(DELEGATED);
		const originalFetch = globalThis.fetch;
		globalThis.fetch = (async () => new Response(JSON.stringify({ error: "missing or invalid API token" }), { status: 401, headers: { "content-type": "application/json" } })) as typeof fetch;
		try {
			const failure = await session.client().status().catch((error: unknown) => error);
			expect(failure).toBeInstanceOf(KernelApiError);
			expect((failure as KernelApiError).status).toBe(401);
			// 过期/被吊销 key：清 session，不再无限重试受保护请求。
			session.logout();
			expect(session.authenticated).toBe(false);
			expect(window.sessionStorage.getItem("iweb-admin-owner-key")).toBeNull();
			// 空 key 的 client 直接本地拒绝（不发请求）。
			const rejected = await session.client().status().catch((error: unknown) => error);
			expect((rejected as KernelApiError).status).toBe(401);
			expect((rejected as KernelApiError).message).toContain("登录");
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});

describe("session boundary: no URL, no durable storage, no build secret (5.2)", () => {
	test("the session module only ever touches tab-scoped sessionStorage", () => {
		expect(source).toContain("window.sessionStorage");
		// 禁止任何 localStorage API 调用（注释提及不算使用）；读取 location.href 推导
		// API 域名合法，禁止的是把 key 写入 URL（assign/replace/对 search/hash 赋值）。
		expect(source).not.toMatch(/window\.localStorage|globalThis\.localStorage/);
		expect(source).not.toMatch(/location\.(assign|replace)|location\.(search|hash)\s*=/);
		expect(source).not.toContain("IWEB_API_TOKEN");
	});

	test("the login page keeps the key out of URLs and routes 401 to logout", () => {
		// 登录不要求 bootstrap 专属格式（文案与行为都不再假设单一 token）。
		expect(pageSource).toContain("任意有效 owner key");
		// 401 → logout（清会话回登录视图）而不是无限重试。
		expect(pageSource).toContain("error.status === 401");
		expect(pageSource).toContain("logout(false)");
		// Keys 视图的 401 也走同一失效路径。
		expect(pageSource).toContain("onauthfailure={() => logout(false)}");
		expect(pageSource).not.toMatch(/window\.localStorage|globalThis\.localStorage/);
	});
});
