// 用户原始需求（2026-08-14）：route 只解析 ready active version；无 active 返回 null（502）；public-object gateway 无 listing、拒绝 traversal。
// 正交意图：8.1/8.2/8.3/8.5。
import { describe, expect, test } from "bun:test";
import { resolveActiveSandboxId, resolveRoute, routeAction, type RouteRecord } from "../contracts/routing.ts";
import { normalizePublicObjectPath, resolvePublicObject } from "../contracts/public-objects.ts";
import { activateVersion, admitVersion, emptyControlState } from "../contracts/control-db.ts";
import { exampleManifest } from "../contracts/manifest.ts";

const policy = { resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 }, egress: { default: "deny" as const, allow: [] } };

function readyState() {
	const admitted = admitVersion(emptyControlState(), { applicationId: "notes", packageDigest: "a".repeat(64), manifest: exampleManifest(), policy, admittedAt: "2026-08-14T00:00:00.000Z" });
	if (!admitted.ok) throw new Error("admit failed");
	const app = admitted.value.state.applications["notes"];
	const readyApp = { ...app, versions: app.versions.map((version) => ({ ...version, lifecycle: "ready" as const })) };
	const activated = activateVersion({ applications: { notes: readyApp } }, "notes", admitted.value.version.versionId);
	if (!activated.ok) throw new Error("activate failed");
	return { state: activated.value.state, versionId: admitted.value.version.versionId };
}

describe("route resolution", () => {
	test("resolves an enabled route only when a ready active version exists", () => {
		const { state } = readyState();
		const route: RouteRecord = { hostId: "notes.app", appName: "notes", enabled: true };
		const resolved = resolveRoute(state, route, null);
		expect(resolved?.sandboxId).toBe(resolveActiveSandboxId(state, "notes"));
		expect(resolveRoute(emptyControlState(), route, null)).toBeNull();
		expect(resolveRoute(state, { ...route, enabled: false }, null)).toBeNull();
	});

	test("preserves the path alias base path for the same active version", () => {
		const { state } = readyState();
		const hostname = resolveRoute(state, { hostId: "notes.app", appName: "notes", enabled: true }, null);
		const alias = resolveRoute(state, { hostId: "notes.app", appName: "notes", enabled: true }, "/notes/app/");
		expect(alias?.appBasePath).toBe("/notes/app/");
		expect(alias?.sandboxId).toBe(hostname?.sandboxId);
	});
});

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

