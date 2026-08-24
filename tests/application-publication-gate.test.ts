// 用户原始需求（2026-08-13）：任意应用发布必须同时满足显式启用和独立沙箱验收证明。
// 正交意图：验证默认关闭；验证单条件不足；验证双条件开启；验证守卫拒绝。
import { describe, expect, test } from "bun:test";
import gateModule from "../kernel/application-publication-gate.js";

const { evaluateApplicationPublicationGate, requireApplicationPublication } = gateModule;
const acceptedRecord = JSON.stringify({ version: 1, gate: "application-sandbox", result: "passed", evidenceDigest: "a".repeat(64) });

describe("application publication gate", () => {
	test("is disabled by default when neither condition exists", () => {
		const gate = evaluateApplicationPublicationGate({ environment: {}, readText: () => { throw new Error("missing"); } });
		expect(gate.enabled).toBe(false);
		expect(gate.reasons).toEqual(["publication-not-requested", "sandbox-acceptance-missing"]);
	});

	test("does not trust an environment switch without acceptance evidence", () => {
		const gate = evaluateApplicationPublicationGate({ environment: { IWEB_APPLICATION_PUBLICATION_ENABLED: "1" }, readText: () => "{}" });
		expect(gate.enabled).toBe(false);
		expect(gate.requested).toBe(true);
		expect(gate.accepted).toBe(false);
	});

	test("does not allow environment configuration to redirect acceptance evidence", () => {
		let requestedPath = "";
		const gate = evaluateApplicationPublicationGate({
			environment: { IWEB_APPLICATION_PUBLICATION_ENABLED: "1", IWEB_SANDBOX_ACCEPTANCE_FILE: "/tmp/forged.json" },
			readText: (path: string) => {
				requestedPath = path;
				return acceptedRecord;
			}
		});
		expect(requestedPath).toBe("/opt/iweb/release/sandbox-acceptance.json");
		expect(gate.enabled).toBe(true);
	});

	test("does not enable publication from evidence alone", () => {
		const gate = evaluateApplicationPublicationGate({ environment: {}, readText: () => acceptedRecord });
		expect(gate.enabled).toBe(false);
		expect(gate.accepted).toBe(true);
	});

	test("enables only when explicit configuration and valid evidence agree", () => {
		const gate = evaluateApplicationPublicationGate({ environment: { IWEB_APPLICATION_PUBLICATION_ENABLED: "1" }, readText: () => acceptedRecord });
		expect(gate).toMatchObject({ enabled: true, requested: true, accepted: true, reasons: [] });
		expect(() => requireApplicationPublication(gate)).not.toThrow();
	});

	test("throws a stable error before a disabled publication path can run", () => {
		const gate = evaluateApplicationPublicationGate({ environment: {}, readText: () => acceptedRecord });
		expect(() => requireApplicationPublication(gate)).toThrow("application publication is disabled");
	});
});
