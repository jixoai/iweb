// 用户原始需求（2026-08-14）：public-object gateway 只放行显式白名单对象/前缀；路径遍历、空段、控制字符、未声明对象一律拒绝。
// 正交意图：8.3 契约测试。
import { describe, expect, test } from "bun:test";
import { normalizePublicObjectPath, parsePublicObjectSet, resolvePublicObject } from "../packages/contracts/public-objects.ts";

const set = { objects: new Set(["index.html", "favicon.svg"]), prefixes: ["assets", "app/static"] };

describe("public object gateway", () => {
	test("the root path resolves to the whitelisted index document only", () => {
		// "/" maps to index.html when it is whitelisted (8.4 public-root compatibility)
		expect(resolvePublicObject(set, "/")).toBe("index.html");
		expect(resolvePublicObject(set, "//")).toBe("index.html");
		// an empty request target stays rejected
		expect(resolvePublicObject(set, "")).toBeNull();
		// without index.html in the whitelist the root is not public
		const noIndex = { objects: new Set(["favicon.svg"]), prefixes: [] };
		expect(resolvePublicObject(noIndex, "/")).toBeNull();
	});

	test("resolves explicit objects and prefixes", () => {
		expect(resolvePublicObject(set, "/index.html")).toBe("index.html");
		expect(resolvePublicObject(set, "favicon.svg")).toBe("favicon.svg");
		expect(resolvePublicObject(set, "/assets/app.css")).toBe("assets/app.css");
		expect(resolvePublicObject(set, "/app/static/logo.png")).toBe("app/static/logo.png");
		expect(resolvePublicObject(set, "/assets")).toBe("assets");
	});

	test("parses the operator whitelist with prefixes and rejects unsafe entries", () => {
		const parsed = parsePublicObjectSet("index.html,assets/,favicon.svg,/etc/passwd,../secret,,");
		expect(parsed.objects.has("index.html")).toBe(true);
		expect(parsed.objects.has("favicon.svg")).toBe(true);
		// leading slashes normalize to a workspace-relative key; traversal never does
		expect(parsed.objects.has("etc/passwd")).toBe(true);
		expect(parsed.objects.has("../secret")).toBe(false);
		expect(parsed.prefixes).toContain("assets");
		expect(resolvePublicObject(parsed, "/assets/app.css")).toBe("assets/app.css");
		expect(parsePublicObjectSet(undefined).objects.has("index.html")).toBe(true);
	});

	test("rejects undeclared objects, listings, and traversal", () => {
		expect(resolvePublicObject(set, "/secret.env")).toBeNull();
		expect(resolvePublicObject(set, "/assets/../secret.env")).toBeNull();
		expect(resolvePublicObject(set, "/assetsx/app.css")).toBeNull();
		// "/" now serves the whitelisted index document (8.4 public-root compatibility);
		// the root test without index.html in the whitelist lives in the root-mapping test above.
		expect(resolvePublicObject(set, "/")).toBe("index.html");
		expect(resolvePublicObject(set, "/notes/iweb.json")).toBeNull();
		expect(normalizePublicObjectPath("/a/../b")).toBeNull();
		expect(normalizePublicObjectPath("/a//b")).toBeNull();
		expect(normalizePublicObjectPath("/a/./b")).toBeNull();
		expect(normalizePublicObjectPath("/a\u0000b")).toBeNull();
		expect(normalizePublicObjectPath("//")).toBeNull();
	});
});
