// 用户原始需求（2026-08-13）：Admin 原生资产 handler 必须覆盖根域、路径别名、GET/HEAD 与缓存语义。
// 正交意图：模拟 celld binding；验证资源透传；验证 HTML base 适配与失败边界。
import { describe, expect, test } from "bun:test";
import { fetch as fetchAdmin } from "../apps/workers/admin/src/index.ts";

const files = new Map<string, { body: string; contentType: string; cacheControl: string }>([
	["/index.html", { body: "<!doctype html><html><head><title>Admin</title></head><body></body></html>", contentType: "text/html; charset=utf-8", cacheControl: "no-cache" }],
	["/_app/immutable/entry/app.js", { body: "export const admin = true;", contentType: "application/javascript", cacheControl: "public, max-age=31536000, immutable" }]
]);

const env = {
	ADMIN_ASSETS: {
		async fetch(request: Request): Promise<Response> {
			const file = files.get(new URL(request.url).pathname);
			if (!file) return new Response("not found", { status: 404 });
			return new Response(request.method === "HEAD" ? null : file.body, {
				headers: { "content-type": file.contentType, "cache-control": file.cacheControl, etag: '"fixture"' }
			});
		}
	}
};

describe("Admin native asset handler", () => {
	test("serves direct-host root HTML without changing its relative base", async () => {
		const response = await fetchAdmin(new Request("http://admin.app.iweb.test/"), env);
		expect(response.status).toBe(200);
		expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
		expect(await response.text()).not.toContain("<base");
	});

	test("injects the mounted base only for path-alias HTML", async () => {
		const response = await fetchAdmin(new Request("http://admin.app.iweb.test/", { headers: { "x-iweb-app-base": "/admin/app/" } }), env);
		expect(response.headers.get("cache-control")).toBe("no-cache");
		expect(await response.text()).toContain('<base href="/admin/app/">');
	});

	test("preserves immutable asset MIME and cache headers", async () => {
		const response = await fetchAdmin(new Request("http://admin.app.iweb.test/_app/immutable/entry/app.js"), env);
		expect(response.headers.get("content-type")).toBe("application/javascript");
		expect(response.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
		expect(await response.text()).toContain("admin = true");
	});

	test("preserves HEAD semantics through the binding", async () => {
		const response = await fetchAdmin(new Request("http://admin.app.iweb.test/_app/immutable/entry/app.js", { method: "HEAD" }), env);
		expect(response.status).toBe(200);
		expect(response.headers.get("etag")).toBe('"fixture"');
		expect(await response.text()).toBe("");
	});

	test("falls back to the Admin document for client-side paths", async () => {
		const response = await fetchAdmin(new Request("http://admin.app.iweb.test/workspace"), env);
		expect(response.status).toBe(200);
		expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
	});

	test("rejects methods that cannot read static resources", async () => {
		const response = await fetchAdmin(new Request("http://admin.app.iweb.test/", { method: "POST" }), env);
		expect(response.status).toBe(405);
		expect(response.headers.get("allow")).toBe("GET, HEAD");
	});
});
