// 用户原始需求（2026-08-13）：沙箱 preflight 必须自动化验证且在任何缺失项上失败关闭。
// 正交意图：验证通过报告；验证隔离原语失败；验证权限失败；验证诊断有界。
import { describe, expect, test } from "bun:test";
import { runSandboxPreflight, type PreflightProbe } from "../supervisor/preflight.ts";

function probe(overrides: Partial<PreflightProbe> = {}): PreflightProbe {
	return {
		platform: () => "linux",
		effectiveUserId: () => 1000,
		readText: (path) => {
			if (path.endsWith("cgroup.controllers")) return "cpuset cpu io memory pids";
			if (path.endsWith("max_user_namespaces")) return "4096";
			if (path.endsWith("unprivileged_userns_clone")) return "1";
			if (path.endsWith("seccomp.json")) return JSON.stringify({ archMap: [{ architecture: "SCMP_ARCH_X86_64" }], syscalls: [{ names: ["read", "write"], action: "SCMP_ACT_ALLOW" }] });
			throw new Error("unexpected path");
		},
		pathOwner: () => ({ uid: 1000, mode: 0o40700 }),
		rootlessPodmanInfo: () => ({ host: { security: { rootless: true } } }),
		subordinateIdRanges: () => ({ uidRanges: 1, gidRanges: 1 }),
		bindUnixSocket: async () => undefined,
		...overrides
	};
}

describe("sandbox host preflight", () => {
	test("passes only when every mandatory isolation primitive is available", async () => {
		const report = await runSandboxPreflight({ stateDirectory: "/state", runtimeDirectory: "/run", seccompProfilePath: "/usr/local/libexec/iweb-sandbox/seccomp.json" }, probe());
		expect(report.ready).toBe(true);
		expect(report.checks).toHaveLength(9);
		expect(report.checks.every((check) => check.passed)).toBe(true);
	});

	test("fails when the restrictive seccomp profile is missing or invalid", async () => {
		const missing = await runSandboxPreflight({ stateDirectory: "/state", runtimeDirectory: "/run", seccompProfilePath: "/usr/local/libexec/iweb-sandbox/seccomp.json" }, probe({
			readText: (path) => {
				if (path.endsWith("cgroup.controllers")) return "cpuset cpu io memory pids";
				if (path.endsWith("max_user_namespaces")) return "4096";
				if (path.endsWith("unprivileged_userns_clone")) return "1";
				throw new Error("missing");
			}
		}));
		expect(missing.ready).toBe(false);
		expect(missing.checks.find((check) => check.code === "seccomp-profile")?.passed).toBe(false);
	});

	test("fails when the dedicated supervisor user lacks subordinate IDs", async () => {
		const report = await runSandboxPreflight({ stateDirectory: "/state", runtimeDirectory: "/run", seccompProfilePath: "/usr/local/libexec/iweb-sandbox/seccomp.json" }, probe({
			subordinateIdRanges: () => ({ uidRanges: 0, gidRanges: 0 })
		}));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "subordinate-ids")?.passed).toBe(false);
	});

	test("fails closed when cgroup controllers or rootless OCI are unavailable", async () => {
		const report = await runSandboxPreflight({ stateDirectory: "/state", runtimeDirectory: "/run", seccompProfilePath: "/usr/local/libexec/iweb-sandbox/seccomp.json" }, probe({
			readText: (path) => path.endsWith("cgroup.controllers") ? "cpu memory" : "4096",
			rootlessPodmanInfo: () => ({ host: { security: { rootless: false } } })
		}));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "cgroup-v2")?.detail).toContain("pids");
		expect(report.checks.find((check) => check.code === "rootless-oci")?.passed).toBe(false);
	});

	test("rejects directories owned by another user or writable by a group", async () => {
		const report = await runSandboxPreflight({ stateDirectory: "/state", runtimeDirectory: "/run", seccompProfilePath: "/usr/local/libexec/iweb-sandbox/seccomp.json" }, probe({
			pathOwner: (path) => path === "/state" ? { uid: 0, mode: 0o40700 } : { uid: 1000, mode: 0o40720 }
		}));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "state-ownership")?.passed).toBe(false);
		expect(report.checks.find((check) => check.code === "runtime-ownership")?.passed).toBe(false);
	});

	test("fails when the supervisor runtime directory cannot host a Unix socket", async () => {
		const report = await runSandboxPreflight({ stateDirectory: "/state", runtimeDirectory: "/run", seccompProfilePath: "/usr/local/libexec/iweb-sandbox/seccomp.json" }, probe({
			bindUnixSocket: async () => { throw new Error("permission denied"); }
		}));
		expect(report.ready).toBe(false);
		expect(report.checks.find((check) => check.code === "unix-socket")?.passed).toBe(false);
	});

	test("keeps failure diagnostics bounded and single-line", async () => {
		const report = await runSandboxPreflight({ stateDirectory: "/state", runtimeDirectory: "/run", seccompProfilePath: "/usr/local/libexec/iweb-sandbox/seccomp.json" }, probe({ platform: () => `darwin\n${"x".repeat(400)}` }));
		const detail = report.checks.find((check) => check.code === "linux")?.detail ?? "";
		expect(detail.length).toBeLessThanOrEqual(160);
		expect(detail).not.toContain("\n");
	});
});
