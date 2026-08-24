// 用户原始需求（2026-08-14）：Kernel 的 CommonJS 契约桥必须与 TS 权威实现行为一致；bundle 由 scripts/build-kernel-contracts.bun.ts 生成。
// 正交意图：2.21 的桥一致性证据；用 node require 验证导出面与关键行为。
import { describe, expect, test } from "bun:test";
import { createRequire } from "node:module";
import { deriveSandboxId } from "../packages/contracts/protocol.ts";
import { versionLabel } from "../packages/contracts/records.ts";
import { admitVersion, emptyControlState } from "../packages/contracts/control-db.ts";

const nodeRequire = createRequire(import.meta.url);
const bundle = nodeRequire("../kernel/contracts-bundle.cjs") as Record<string, unknown>;

describe("kernel contracts bundle", () => {
	test("exposes the production consumer surface", () => {
		for (const name of [
			"ControlStore", "activateVersion", "admitVersion", "collectPackage", "deriveSandboxId",
			"emptyControlState", "emptyControlStateFile", "markVersionReady", "removeVersion",
			"rollbackVersion", "setVersionLifecycle", "validateControlStateFile", "validateSupervisorResponse",
			"versionLabel", "versionDigest", "probeReadiness", "readinessUrl", "resolveActiveSandboxId",
			"resolveRoute", "resolvePublicObject", "normalizePublicObjectPath", "systemControlStoreIO",
		]) {
			expect(bundle[name]).toBeDefined();
		}
	});

	test("matches the TypeScript authority for identity and admission", () => {
		const digest = "a".repeat(64);
		const applicationId = "notes";
		expect(bundle.deriveSandboxId(applicationId, digest, 3)).toBe(deriveSandboxId(applicationId, digest, 3));
		expect(bundle.versionLabel({ applicationId, digest, sequence: 3 })).toBe(versionLabel({ applicationId, digest, sequence: 3 }));
		const manifest = { schemaVersion: 1 as const, name: "notes", runtime: { kind: "celld" as const, celldVersion: "0.2.0", entrypoint: "index.js" }, assets: { root: "app" }, resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 }, storage: { persistent: false, requestBytes: 0 }, egress: { default: "deny" as const, allow: [] } };
		const policy = { resources: manifest.resources, egress: manifest.egress };
		const fromBundle = (bundle.admitVersion as typeof admitVersion)(bundle.emptyControlState(), { applicationId, packageDigest: digest, manifest, policy, admittedAt: "2026-08-14T00:00:00.000Z" });
		const fromTs = admitVersion(emptyControlState(), { applicationId, packageDigest: digest, manifest, policy, admittedAt: "2026-08-14T00:00:00.000Z" });
		expect(fromBundle.ok).toBe(true);
		expect(fromTs.ok).toBe(true);
		if (fromBundle.ok && fromTs.ok) {
			expect(fromBundle.value.version.versionId).toBe(fromTs.value.version.versionId);
			expect(fromBundle.value.version.packageDigest).toBe(fromTs.value.version.packageDigest);
		}
	});

	test("control state file validation agrees across the bridge", () => {
		const digest = "b".repeat(64);
		const manifest = { schemaVersion: 1 as const, name: "notes", runtime: { kind: "celld" as const, celldVersion: "0.2.0", entrypoint: "index.js" }, assets: { root: "app" }, resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 }, storage: { persistent: false, requestBytes: 0 }, egress: { default: "deny" as const, allow: [] } };
		const policy = { resources: manifest.resources, egress: manifest.egress };
		const admitted = admitVersion(emptyControlState(), { applicationId: "notes", packageDigest: digest, manifest, policy, admittedAt: "2026-08-14T00:00:00.000Z" });
		if (!admitted.ok) throw new Error("admission failed");
		const file = (bundle.emptyControlStateFile as () => { applications: Record<string, unknown> })();
		file.applications = admitted.value.state.applications;
		const validated = (bundle.validateControlStateFile as (input: unknown) => unknown)(JSON.parse(JSON.stringify(file)));
		expect(validated).not.toBeNull();
		const broken = { version: 1, applications: { x: { applicationId: "y" } } };
		expect((bundle.validateControlStateFile as (input: unknown) => unknown)(broken)).toBeNull();
	});
});
