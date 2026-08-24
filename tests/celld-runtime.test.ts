// 用户原始需求（2026-08-14）：每 version 独立 node identity 与 bucket；固定平台参数（无 celld 命令）；有界就绪探测只接受 200+身份匹配；generic 502。
// 正交意图：6.2/6.3/6.4 与 2.16 健康契约。
import { describe, expect, test } from "bun:test";
import { buildSandboxSpec, versionBucketName } from "../supervisor/sandbox-spec.ts";
import { parseHealthPayload, probeReadiness, readinessUrl, unavailableResponse } from "../supervisor/readiness.ts";
import { validateApplicationManifest } from "../contracts/manifest.ts";

const digest = "a".repeat(64);
const options = {
	runtimeImage: "ghcr.io/denoland/celld@sha256:" + "c".repeat(64),
	gatewayImage: "localhost/iweb-sandbox-gateway@sha256:" + "d".repeat(64),
	stateDirectory: "/var/lib/iweb-sandbox",
	gatewayRuntimeDirectory: "/run/iweb-sandbox/gw",
	region: "us-east-1",
};
const policy = { resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 }, egress: { default: "deny" as const, allow: [] } };
const identity = { applicationId: "app-a", digest, sequence: 2 };
const versionId = digest + "-2";

describe("celld runtime adapter", () => {
	test("assigns a unique bucket and node identity per sandbox", () => {
		expect(versionBucketName("sbx-a")).toBe("iweb-app-sbx-a");
		const specA = buildSandboxSpec({ sandboxId: "sbx-a", versionIdentity: identity, packageDigest: digest, policy }, options);
		const specB = buildSandboxSpec({ sandboxId: "sbx-b", versionIdentity: identity, packageDigest: digest, policy }, options);
		expect(specA.environment).toContain("CELLD_NODE=sbx-a");
		expect(specB.environment).toContain("CELLD_NODE=sbx-b");
		expect(specA.command.join(" ")).toContain("s3://iweb-app-sbx-a");
		expect(specB.command.join(" ")).toContain("s3://iweb-app-sbx-b");
	});

	test("uses fixed platform arguments, never package-provided commands or shells", () => {
		const spec = buildSandboxSpec({ sandboxId: "sbx-a", versionIdentity: identity, packageDigest: digest, policy }, options);
		expect(spec.command).not.toContain("celld");
		expect(spec.command).not.toContain("/bin/sh");
		expect(spec.command).not.toContain("-c");
		// entrypoint is validated to be a .js module by the manifest schema
		const manifest = validateApplicationManifest({ schemaVersion: 1, name: "notes", runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint: "run.sh" }, assets: { root: "app" }, resources: policy.resources, storage: { persistent: false, requestBytes: 0 }, egress: { default: "deny", allow: [] } });
		expect(manifest.ok).toBe(false);
	});
});

describe("readiness health contract", () => {
	const healthBody = (version: string, generation: number) => JSON.stringify({ version: 1, ok: true, versionId: version, generation });
	const fetchWith = (status: number, body: string) => async () => ({ status, body });
	const sleepNone = async () => undefined;

	test("only an exact 200 with matching identity activates a version", async () => {
		const ready = await probeReadiness({ fetch: fetchWith(200, healthBody(versionId, 2)), baseUrl: "http://sandbox", versionId, generation: 2, maxAttempts: 3, attemptTimeoutMs: 1000, intervalMs: 0, sleep: sleepNone });
		expect(ready).toMatchObject({ ready: true, attempts: 1, lastStatus: 200 });
	});

	test("authorization failures, missing routes, and throttling never count as ready", async () => {
		for (const status of [401, 403, 404, 429, 500, 502, 503]) {
			const result = await probeReadiness({ fetch: fetchWith(status, "{}"), baseUrl: "http://sandbox", versionId, maxAttempts: 2, attemptTimeoutMs: 1000, intervalMs: 0, sleep: sleepNone });
			expect(result.ready).toBe(false);
			expect(result.lastStatus).toBe(status);
		}
	});

	test("a 200 with a stale or wrong identity is a mismatch, never readiness", async () => {
		const stale = await probeReadiness({ fetch: fetchWith(200, healthBody(digest + "-9", 2)), baseUrl: "http://sandbox", versionId, generation: 2, maxAttempts: 2, attemptTimeoutMs: 1000, intervalMs: 0, sleep: sleepNone });
		expect(stale.ready).toBe(false);
		expect(stale.mismatch).toBe(true);
		const wrongGeneration = await probeReadiness({ fetch: fetchWith(200, healthBody(versionId, 7)), baseUrl: "http://sandbox", versionId, generation: 2, maxAttempts: 2, attemptTimeoutMs: 1000, intervalMs: 0, sleep: sleepNone });
		expect(wrongGeneration.ready).toBe(false);
		expect(wrongGeneration.mismatch).toBe(true);
	});

	test("an explicit 409 identity conflict is recorded as a mismatch", async () => {
		const conflict = await probeReadiness({ fetch: fetchWith(409, JSON.stringify({ ok: false, code: "version-mismatch" })), baseUrl: "http://sandbox", versionId, maxAttempts: 2, attemptTimeoutMs: 1000, intervalMs: 0, sleep: sleepNone });
		expect(conflict.ready).toBe(false);
		expect(conflict.mismatch).toBe(true);
	});

	test("hangs are cut by the per-attempt deadline and bounded attempts", async () => {
		const hanging = await probeReadiness({
			fetch: async (_url, options) => {
				await new Promise<void>((resolve) => options.signal.addEventListener("abort", () => resolve()));
				const aborted = new Error("aborted");
				(aborted as { name?: string }).name = "AbortError";
				throw aborted;
			},
			baseUrl: "http://sandbox",
			versionId,
			maxAttempts: 2,
			attemptTimeoutMs: 100,
			intervalMs: 0,
			sleep: sleepNone,
		});
		expect(hanging.ready).toBe(false);
		expect(hanging.attempts).toBe(2);
		expect(hanging.timedOut).toBe(true);
	});

	test("network errors exhaust attempts without readiness", async () => {
		const failing = await probeReadiness({ fetch: async () => { throw new Error("boom"); }, baseUrl: "http://sandbox", versionId, maxAttempts: 3, attemptTimeoutMs: 1000, intervalMs: 0, sleep: sleepNone });
		expect(failing.ready).toBe(false);
		expect(failing.attempts).toBe(3);
	});

	test("readiness URL carries the candidate identity and generation", () => {
		expect(readinessUrl("http://sandbox", versionId, 2)).toBe("http://sandbox/iweb-health?versionId=" + encodeURIComponent(versionId) + "&generation=2");
		expect(parseHealthPayload(healthBody(versionId, 2))?.versionId).toBe(versionId);
		expect(parseHealthPayload("not json")).toBeNull();
	});

	test("generic failure shaping never exposes diagnostics", () => {
		expect(unavailableResponse().status).toBe(502);
		expect(unavailableResponse().body).not.toContain("boom");
		expect(unavailableResponse().body).toContain("application unavailable");
	});
});
