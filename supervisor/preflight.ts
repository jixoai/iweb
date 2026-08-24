// 用户原始需求（2026-08-13）：不可信应用只能在宿主能够强制执行完整隔离时运行。
// 正交意图：探测 cgroup v2；探测 rootless OCI；验证 Unix socket；验证目录所有权；输出有界诊断。
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type PreflightCheckCode =
	| "linux"
	| "cgroup-v2"
	| "user-namespaces"
	| "subordinate-ids"
	| "rootless-oci"
	| "seccomp-profile"
	| "state-ownership"
	| "runtime-ownership"
	| "unix-socket";

export interface PreflightCheck {
	readonly code: PreflightCheckCode;
	readonly passed: boolean;
	readonly detail: string;
}

export interface PreflightReport {
	readonly version: 1;
	readonly ready: boolean;
	readonly checks: readonly PreflightCheck[];
}

export interface PreflightOptions {
	readonly stateDirectory: string;
	readonly runtimeDirectory: string;
	readonly seccompProfilePath: string;
}

interface RootlessPodmanInfo {
	readonly host?: {
		readonly security?: {
			readonly rootless?: boolean;
		};
	};
}

export interface PreflightProbe {
	platform(): string;
	effectiveUserId(): number;
	readText(path: string): string;
	pathOwner(path: string): { readonly uid: number; readonly mode: number };
	rootlessPodmanInfo(): RootlessPodmanInfo;
	subordinateIdRanges(userName: string): { readonly uidRanges: number; readonly gidRanges: number };
	bindUnixSocket(directory: string): Promise<void>;
}

const requiredControllers = ["cpu", "memory", "pids"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedDetail(value: string): string {
	return value.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 160);
}

function passed(code: PreflightCheckCode, detail: string): PreflightCheck {
	return { code, passed: true, detail: boundedDetail(detail) };
}

function failed(code: PreflightCheckCode, detail: string): PreflightCheck {
	return { code, passed: false, detail: boundedDetail(detail) };
}

function parsePositiveInteger(value: string): number | null {
	const parsed = Number.parseInt(value.trim(), 10);
	return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function directoryOwnershipCheck(probe: PreflightProbe, code: "state-ownership" | "runtime-ownership", directory: string): PreflightCheck {
	try {
		const owner = probe.pathOwner(directory);
		if (owner.uid !== probe.effectiveUserId()) return failed(code, "directory is not owned by the supervisor user");
		if ((owner.mode & 0o022) !== 0) return failed(code, "directory is writable by group or other users");
		return passed(code, "directory ownership and write permissions are restricted");
	} catch {
		return failed(code, "directory is missing or cannot be inspected");
	}
}

export async function runSandboxPreflight(options: PreflightOptions, probe: PreflightProbe = systemPreflightProbe): Promise<PreflightReport> {
	const checks: PreflightCheck[] = [];

	if (probe.platform() === "linux") checks.push(passed("linux", "Linux host detected"));
	else checks.push(failed("linux", "sandbox supervisor requires a Linux host"));

	try {
		const controllers = new Set(probe.readText("/sys/fs/cgroup/cgroup.controllers").trim().split(/\s+/).filter(Boolean));
		const missing = requiredControllers.filter((controller) => !controllers.has(controller));
		checks.push(missing.length === 0 ? passed("cgroup-v2", "required cpu, memory, and pids controllers are available") : failed("cgroup-v2", `missing required controllers: ${missing.join(", ")}`));
	} catch {
		checks.push(failed("cgroup-v2", "cgroup v2 controller information is unavailable"));
	}

	try {
		const maximum = parsePositiveInteger(probe.readText("/proc/sys/user/max_user_namespaces"));
		let unprivilegedAllowed = true;
		try {
			unprivilegedAllowed = probe.readText("/proc/sys/kernel/unprivileged_userns_clone").trim() !== "0";
		} catch {
			// This sysctl is absent on kernels that do not expose a separate toggle.
		}
		checks.push(maximum !== null && unprivilegedAllowed ? passed("user-namespaces", "unprivileged user namespaces are available") : failed("user-namespaces", "unprivileged user namespaces are disabled"));
	} catch {
		checks.push(failed("user-namespaces", "user namespace limits are unavailable"));
	}

	try {
		const ranges = probe.subordinateIdRanges("iweb-sandbox");
		checks.push(ranges.uidRanges > 0 && ranges.gidRanges > 0 ? passed("subordinate-ids", "supervisor user has subordinate UID and GID ranges") : failed("subordinate-ids", "supervisor user requires subordinate UID and GID ranges"));
	} catch {
		checks.push(failed("subordinate-ids", "subordinate ID configuration cannot be inspected"));
	}

	try {
		const info = probe.rootlessPodmanInfo();
		checks.push(info.host?.security?.rootless === true ? passed("rootless-oci", "rootless Podman is operational") : failed("rootless-oci", "OCI runtime did not report rootless operation"));
	} catch {
		checks.push(failed("rootless-oci", "rootless Podman is unavailable or unhealthy"));
	}

	try {
		const profile = JSON.parse(probe.readText(options.seccompProfilePath));
		const hasArchitecture = isRecord(profile) && Array.isArray(profile.archMap) && profile.archMap.length > 0;
		const hasAllowlist = isRecord(profile) && Array.isArray(profile.syscalls) && profile.syscalls.length > 0;
		checks.push(hasArchitecture && hasAllowlist ? passed("seccomp-profile", "the restrictive seccomp profile is installed and parseable") : failed("seccomp-profile", "the installed seccomp profile is invalid"));
	} catch {
		checks.push(failed("seccomp-profile", "the restrictive seccomp profile is not installed with the supervisor package"));
	}

	checks.push(directoryOwnershipCheck(probe, "state-ownership", options.stateDirectory));
	checks.push(directoryOwnershipCheck(probe, "runtime-ownership", options.runtimeDirectory));

	try {
		await probe.bindUnixSocket(options.runtimeDirectory);
		checks.push(passed("unix-socket", "permission-restricted local Unix sockets are available"));
	} catch {
		checks.push(failed("unix-socket", "cannot bind a Unix socket in the supervisor runtime directory"));
	}

	return { version: 1, ready: checks.every((check) => check.passed), checks };
}

export const systemPreflightProbe: PreflightProbe = {
	platform: () => process.platform,
	effectiveUserId: () => process.geteuid?.() ?? -1,
	readText: (path) => readFileSync(path, "utf8"),
	pathOwner: (path) => {
		const value = statSync(path);
		if (!value.isDirectory()) throw new Error("not a directory");
		return { uid: value.uid, mode: value.mode };
	},
	// The podman probe retries on transient store-lock contention: a service
	// restart (or concurrent reconciliation) holds the rootless store lock for
	// a moment, and `podman info` fails with EACCES/lock errors that say nothing
	// about the host's actual rootless capability. Capability verdicts must
	// reflect the host, not a scheduling race.
	rootlessPodmanInfo: (() => {
		const probeOnce = (): string => execFileSync("podman", ["info", "--format", "json"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 10_000 });
		return (): RootlessPodmanInfo => {
			let lastError: unknown;
			for (let attempt = 0; attempt < 3; attempt++) {
				try {
					return JSON.parse(probeOnce()) as RootlessPodmanInfo;
				} catch (error) {
					lastError = error;
					if (attempt < 2) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
				}
			}
			throw lastError;
		};
	})(),
	subordinateIdRanges: (userName) => {
		const countRanges = (path: string): number => readFileSync(path, "utf8").split(/\r?\n/).filter((line) => line.split(":", 1)[0] === userName).length;
		return { uidRanges: countRanges("/etc/subuid"), gidRanges: countRanges("/etc/subgid") };
	},
	bindUnixSocket: async (directory) => {
		const scratch = mkdtempSync(join(directory || tmpdir(), ".iweb-preflight-"));
		const socketPath = join(scratch, "supervisor.sock");
		const server = createServer();
		try {
			await new Promise<void>((resolve, reject) => {
				server.once("error", reject);
				server.listen(socketPath, () => resolve());
			});
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
			rmSync(scratch, { recursive: true, force: true });
		}
	}
};
