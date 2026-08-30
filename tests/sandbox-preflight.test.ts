// 用户原始需求（2026-08-13；two-tier-runtime-trust 2026-08-30 容器内化修订）：supervisor
//   preflight 必须自动化验证且在任何缺失项上失败关闭——检查面是节点容器内前提（socket
//   目录属主、relay 二进制、RustFS 回环、Unix socket 绑定），宿主机沙箱原语已随 OCI
//   沙箱机器退役。
// 正交意图：验证通过报告；验证单项缺失失败关闭；验证权限失败；验证诊断有界。
import { describe, expect, test } from "bun:test";
import { runSandboxPreflight, type PreflightProbe } from "../supervisor/preflight.ts";

const RELAY_BIN = "/usr/local/bin/iweb-snapshot-fd-relay";

function probe(overrides: Partial<PreflightProbe> = {}): PreflightProbe {
	return {
		platform: () => "linux",
		effectiveUserId: () => 20001,
		pathOwner: () => ({ uid: 20001, mode: 0o40700 }),
		fileExists: () => true,
		executableFile: () => true,
		bindUnixSocket: async () => undefined,
		connectTcp: async () => undefined,
		...overrides
	};
}

function options() {
	return { stateDirectory: "/data/kernel/wasm-supervisor", runtimeDirectory: "/run/iweb-sandbox", relayBinaryPath: RELAY_BIN };
}

describe("wasm supervisor in-container preflight", () => {
	test("passes only when every in-container prerequisite is available", async () => {
		const report = await runSandboxPreflight(options(), probe());
		expect(report.ready).toBe(true);
		expect(report.version).toBe(2);
		expect(report.checks.map((check) => check.code)).toEqual(["linux", "state-ownership", "runtime-ownership", "relay-binary", "rustfs-loopback", "unix-socket"]);
		expect(report.checks.every((check) => check.passed)).toBe(true);
	});

	test("fails closed on a non-Linux host", async () => {
		const report = await runSandboxPreflight(options(), probe({ platform: () => "darwin" }));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "linux")?.passed).toBe(false);
	});

	test("fails when the relay binary is missing or not executable", async () => {
		const missing = await runSandboxPreflight(options(), probe({ fileExists: (path) => path !== RELAY_BIN }));
		expect(missing.ready).toBe(false);
		expect(missing.checks.find((check) => check.code === "relay-binary")?.passed).toBe(false);
		const notExecutable = await runSandboxPreflight(options(), probe({ executableFile: () => false }));
		expect(notExecutable.ready).toBe(false);
		expect(notExecutable.checks.find((check) => check.code === "relay-binary")?.passed).toBe(false);
	});

	test("fails when the in-container RustFS loopback listener is unreachable", async () => {
		const report = await runSandboxPreflight(options(), probe({ connectTcp: async () => { throw new Error("connection refused"); } }));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "rustfs-loopback")?.passed).toBe(false);
	});

	test("rejects directories owned by another user or writable by a group", async () => {
		const report = await runSandboxPreflight(options(), probe({
			pathOwner: (path) => path === "/data/kernel/wasm-supervisor" ? { uid: 0, mode: 0o40700 } : { uid: 20001, mode: 0o40720 }
		}));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "state-ownership")?.passed).toBe(false);
		expect(report.checks.find((check) => check.code === "runtime-ownership")?.passed).toBe(false);
	});

	test("fails when the supervisor runtime directory cannot host a Unix socket", async () => {
		const report = await runSandboxPreflight(options(), probe({
			bindUnixSocket: async () => { throw new Error("permission denied"); }
		}));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "unix-socket")?.passed).toBe(false);
	});

	test("keeps failure diagnostics bounded and single-line", async () => {
		const report = await runSandboxPreflight(options(), probe({ platform: () => `darwin\n${"x".repeat(400)}` }));
		const detail = report.checks.find((check) => check.code === "linux")?.detail ?? "";
		expect(detail.length).toBeLessThanOrEqual(160);
		expect(detail).not.toContain("\n");
	});
});
