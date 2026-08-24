// 用户原始需求（2026-08-14）：版本化 iweb.json 必须接受正向包、拒绝所有危险字段类别，且验证错误有界、不回显 hostile payload。
// 正交意图：unknown field、绝对路径、..、shell command、arbitrary image、无界资源、默认拒绝 egress。
import { describe, expect, test } from "bun:test";
import { exampleManifest, validateApplicationManifest } from "../contracts/manifest.ts";

function manifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return { ...(exampleManifest() as unknown as Record<string, unknown>), ...overrides };
}

describe("application manifest schema", () => {
	test("accepts a valid versioned manifest and round-trips its normalized value", () => {
		const result = validateApplicationManifest(exampleManifest());
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.name).toBe("notes");
			expect(result.value.runtime.entrypoint).toBe("index.js");
			expect(result.value.egress.default).toBe("deny");
		}
	});

	test("rejects an unknown top-level field", () => {
		const result = validateApplicationManifest(manifest({ image: "alpine:latest" }));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((issue) => issue.code === "UNKNOWN_FIELD" && issue.path === "/image")).toBe(true);
	});

	test("rejects an arbitrary image or non-celld runtime kind", () => {
		const unknown = validateApplicationManifest(manifest({ runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint: "index.js", image: "alpine" } }));
		expect(unknown.ok).toBe(false);
		if (!unknown.ok) expect(unknown.errors.some((issue) => issue.code === "UNKNOWN_FIELD")).toBe(true);
		const wrongKind = validateApplicationManifest(manifest({ runtime: { kind: "docker", celldVersion: "0.2.0", entrypoint: "index.js" } }));
		expect(wrongKind.ok).toBe(false);
		if (!wrongKind.ok) expect(wrongKind.errors.some((issue) => issue.code === "INVALID_RUNTIME")).toBe(true);
	});

	test("rejects absolute and traversal entrypoints", () => {
		for (const entrypoint of ["/etc/passwd", "../index.js", "app/../../index.js", "a/./b.js"]) {
			const result = validateApplicationManifest(manifest({ runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint } }));
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.errors.some((issue) => issue.code === "INVALID_PATH" || issue.code === "INVALID_ENTRYPOINT")).toBe(true);
		}
	});

	test("rejects shell command and script-looking entrypoints", () => {
		for (const entrypoint of ["$(rm -rf /).js", "index.js; id", "index.js && id", "a b.js", "run.sh"]) {
			const result = validateApplicationManifest(manifest({ runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint } }));
			expect(result.ok).toBe(false);
		}
	});

	test("rejects unbounded or non-finite resources", () => {
		for (const resources of [
			{ cpuMillis: Infinity, memoryBytes: 1024, pidLimit: 10, storageBytes: 1024 },
			{ cpuMillis: -1, memoryBytes: 1024, pidLimit: 10, storageBytes: 1024 },
			{ cpuMillis: 1.5, memoryBytes: 1024, pidLimit: 10, storageBytes: 1024 },
			{ cpuMillis: 10, memoryBytes: 1024, pidLimit: 10, storageBytes: Number.MAX_SAFE_INTEGER },
		]) {
			const result = validateApplicationManifest(manifest({ resources }));
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.errors.some((issue) => issue.code === "INVALID_NUMBER")).toBe(true);
		}
	});

	test("requires deny-by-default egress", () => {
		const result = validateApplicationManifest(manifest({ egress: { default: "allow", allow: [] } }));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((issue) => issue.code === "INVALID_EGRESS_DEFAULT")).toBe(true);
	});

	test("rejects egress rules that are IP literals or invalid ports", () => {
		const ip = validateApplicationManifest(manifest({ egress: { default: "deny", allow: [{ host: "10.0.0.1", port: 443 }] } }));
		expect(ip.ok).toBe(false);
		if (!ip.ok) expect(ip.errors.some((issue) => issue.code === "INVALID_HOST")).toBe(true);
		const port = validateApplicationManifest(manifest({ egress: { default: "deny", allow: [{ host: "api.example.com", port: 70000 }] } }));
		expect(port.ok).toBe(false);
		if (!port.ok) expect(port.errors.some((issue) => issue.code === "INVALID_NUMBER")).toBe(true);
	});

	test("keeps validation errors bounded and free of hostile values", () => {
		const secret = "IWEB_API_TOKEN_leak_me_abcdef";
		const hostile = manifest({ name: secret, runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint: secret } });
		const result = validateApplicationManifest(hostile);
		expect(result.ok).toBe(false);
		const serialized = JSON.stringify(result);
		expect(serialized).not.toContain(secret);
		expect(serialized.length).toBeLessThan(4000);
	});
});

