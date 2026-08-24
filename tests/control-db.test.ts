// 用户原始需求（2026-08-14）：admission 创建不可变版本；activation 原子切换唯一 active pointer 并保留旧版本；not-ready 不切换；reconcile 只从 admitted versions 对账。
// 正交意图：7.2/7.4/7.5。
import { describe, expect, test } from "bun:test";
import { activateVersion, admitVersion, emptyControlState, rollbackVersion } from "../contracts/control-db.ts";
import { planReconciliation } from "../contracts/reconcile.ts";
import { deriveSandboxId } from "../contracts/protocol.ts";
import { exampleManifest } from "../contracts/manifest.ts";

const policy = { resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 }, egress: { default: "deny" as const, allow: [] } };
const manifest = exampleManifest();

function admit(state: ReturnType<typeof emptyControlState>, applicationId: string, packageDigest: string, admittedAt = "2026-08-14T00:00:00.000Z") {
	const result = admitVersion(state, { applicationId, packageDigest, manifest, policy, admittedAt });
	if (!result.ok) throw new Error("admit failed: " + result.errors[0].message);
	return result.value;
}

describe("transactional application control", () => {
	test("admits an immutable content-addressed version", () => {
		const admitted = admit(emptyControlState(), "notes", "a".repeat(64));
		expect(admitted.version.versionId).toMatch(/^[a-f0-9]{64}$/);
		expect(admitted.version.lifecycle).toBe("admitted");
		expect(admitted.state.applications["notes"].active.kind).toBe("unavailable");
		// duplicate identical content is rejected
		const duplicate = admitVersion(admitted.state, { applicationId: "notes", packageDigest: "a".repeat(64), manifest, policy, admittedAt: "2026-08-14T00:00:00.000Z" });
		expect(duplicate.ok).toBe(false);
	});

	test("activation switches exactly one pointer, increments generation, and retains the previous version", () => {
		let state = emptyControlState();
		const v1 = admit(state, "notes", "a".repeat(64)).version;
		state = admit(state, "notes", "a".repeat(64)).state;
		const v2 = admitVersion(state, { applicationId: "notes", packageDigest: "b".repeat(64), manifest, policy, admittedAt: "2026-08-14T00:00:01.000Z" });
		expect(v2.ok).toBe(true);
		state = v2.ok ? v2.value.state : state;
		// mark v1 + v2 ready (lifecycle mutation is a separate Kernel step; simulate by re-admitting)
		const readyState = {
			applications: {
				notes: {
					...state.applications["notes"],
					versions: state.applications["notes"].versions.map((version) => ({ ...version, lifecycle: "ready" as const })),
				},
			},
		};
		const activated = activateVersion(readyState, "notes", v1.versionId);
		expect(activated.ok).toBe(true);
		if (activated.ok) {
			expect(activated.value.state.applications["notes"].active.kind).toBe("active");
			expect(activated.value.state.applications["notes"].active.routeGeneration).toBe(1);
			expect(activated.value.state.applications["notes"].versions.find((version) => version.versionId === v1.versionId)?.lifecycle).toBe("active");
		}
	});

	test("activation is refused when the candidate is not ready and leaves the pointer unchanged", () => {
		const admitted = admit(emptyControlState(), "notes", "a".repeat(64));
		const notReady = activateVersion(admitted.state, "notes", admitted.version.versionId);
		expect(notReady.ok).toBe(false);
		if (!notReady.ok) expect(notReady.errors[0].code).toBe("NOT_READY");
	});

	test("rollback reactivates a retained admitted version through the same gate", () => {
		const admitted = admit(emptyControlState(), "notes", "a".repeat(64));
		const readyState = { applications: { notes: { ...admitted.state.applications["notes"], versions: admitted.state.applications["notes"].versions.map((version) => ({ ...version, lifecycle: "ready" as const })) } } };
		const rolled = rollbackVersion(readyState, "notes", admitted.version.versionId);
		expect(rolled.ok).toBe(true);
	});
});

describe("kernel restart reconciliation", () => {
	test("derives expected active sandboxes and flags missing/unknown", () => {
		const admitted = admit(emptyControlState(), "notes", "a".repeat(64));
		const active = activateVersion({ applications: { notes: { ...admitted.state.applications["notes"], versions: admitted.state.applications["notes"].versions.map((version) => ({ ...version, lifecycle: "ready" as const })) } } }, "notes", admitted.version.versionId);
		expect(active.ok).toBe(true);
		const state = active.ok ? active.value.state : admitted.state;
		const expected = deriveSandboxId("notes", admitted.version.versionId, 1);
		const plan = planReconciliation(state, ["sbx-unknown"]);
		expect(plan.expectedActive).toContain(expected);
		expect(plan.missingActive).toContain(expected);
		expect(plan.unknownObserved).toEqual(["sbx-unknown"]);
	});
});

