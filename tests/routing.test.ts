// 用户原始需求（2026-08-14）：public-object gateway 无 listing、拒绝 traversal；route 处置策略（2.25）。
// two-tier-runtime-trust（2026-08-29）：celld 控制状态解析（resolveRoute/resolveActiveSandboxId/readyState）
// 已随 control-db 删除；路由解析权威在 Rust kernel routes.rs（路由注册表派生），此处只保留纯策略负向量。
import { describe, expect, test } from "bun:test";
import { routeAction } from "../packages/contracts/routing.ts";
import { normalizePublicObjectPath, resolvePublicObject } from "../packages/contracts/public-objects.ts";

describe("public-object gateway", () => {
	const set = { objects: new Set(["index.html"]), prefixes: ["assets"] };
	test("serves explicit objects and prefixes only", () => {
		expect(resolvePublicObject(set, "index.html")).toBe("index.html");
		expect(resolvePublicObject(set, "/assets/app.css")).toBe("assets/app.css");
		expect(resolvePublicObject(set, "secret.txt")).toBeNull();
		expect(resolvePublicObject(set, "../etc/passwd")).toBeNull();
		expect(resolvePublicObject(set, "")).toBeNull();
	});
	test("normalizes traversal and control characters", () => {
		expect(normalizePublicObjectPath("../x")).toBeNull();
		expect(normalizePublicObjectPath("a/./b")).toBeNull();
		expect(normalizePublicObjectPath("a\u0000b")).toBeNull();
		expect(normalizePublicObjectPath("/a/b/")).toBe("a/b");
	});
});

describe("route disposition policy (2.25)", () => {
	test("system routes stay on the trusted Dispatcher; user routes need a ready active sandbox or are unavailable (502)", () => {
		expect(routeAction({ system: true }, null)).toEqual({ kind: "system" });
		expect(routeAction({ system: true }, "sbx-1")).toEqual({ kind: "system" });
		expect(routeAction({ system: false }, "sbx-1")).toEqual({ kind: "sandbox", sandboxId: "sbx-1" });
		expect(routeAction({ system: false }, null)).toEqual({ kind: "unavailable" });
		expect(routeAction(null, null)).toEqual({ kind: "unavailable" });
	});
});
