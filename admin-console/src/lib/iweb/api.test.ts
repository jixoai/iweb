// 用户原始需求（2026-08-12）：Admin 对外域名应从当前 admin 域名安全推导 API 域名。
// 正交意图：验证 admin 与 admin.app 两种入口；固定路由公开链接；避免为客户端注入部署期 token。
import { describe, expect, it } from "vitest";
import { apiOriginFromAdminOrigin, publicOrigin } from "$lib/iweb/api";

describe("apiOriginFromAdminOrigin", () => {
	it("maps the normal admin host to the reserved API host", () => {
		expect(apiOriginFromAdminOrigin(new URL("https://admin.family.iweb.xin"))).toBe(
			"https://api.family.iweb.xin"
		);
	});

	it("maps the replaceable admin application host to the reserved API host", () => {
		expect(apiOriginFromAdminOrigin(new URL("https://admin.app.test.iweb.localhost:19010"))).toBe(
			"https://api.test.iweb.localhost:19010"
		);
	});

	it("forms app hosts from the route registry without losing an explicit port", () => {
		expect(publicOrigin("test.iweb.localhost", "notes.app", "https:", "19010")).toBe(
			"https://notes.app.test.iweb.localhost:19010"
		);
	});
});
