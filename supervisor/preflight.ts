// 用户原始需求（2026-08-13；two-tier-runtime-trust 2026-08-30 容器内化修订）：supervisor
//   以专用非 root 服务用户运行在节点容器内；启动前证明的是**容器内**前提——socket 目录
//   属主、relay 二进制在位、RustFS 回环可达、Unix socket 可绑定。宿主机沙箱前提
//   （podman、subuid/subgid、cgroup 控制器、seccomp profile、宿主用户 getpwnam）随
//   OCI 沙箱机器整体退役：wasm 边界由 Wasmtime 引擎结构强制，supervisor 不再依赖
//   任何宿主机 systemd/Podman/cgroup 配置。
// 正交意图：输出有界诊断；每项检查独立可观测；probe 可注入（测试桩）。
import { accessSync, constants as fsConstants, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { createServer, connect as connectNet } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type PreflightCheckCode =
	| "linux"
	| "state-ownership"
	| "runtime-ownership"
	| "relay-binary"
	| "rustfs-loopback"
	| "unix-socket";

export interface PreflightCheck {
	readonly code: PreflightCheckCode;
	readonly passed: boolean;
	readonly detail: string;
}

export interface PreflightReport {
	readonly version: 2;
	readonly ready: boolean;
	readonly checks: readonly PreflightCheck[];
}

export interface PreflightOptions {
	readonly stateDirectory: string;
	readonly runtimeDirectory: string;
	/** snapshot-fd relay 二进制的容器内路径（IWEB_SANDBOX_WASM_RELAY_BIN 覆盖；缺省 /usr/local/bin/iweb-snapshot-fd-relay）。 */
	readonly relayBinaryPath: string;
}

export interface PreflightProbe {
	platform(): string;
	effectiveUserId(): number;
	pathOwner(path: string): { readonly uid: number; readonly mode: number };
	fileExists(path: string): boolean;
	executableFile(path: string): boolean;
	bindUnixSocket(directory: string): Promise<void>;
	/** TCP 连接探活（带超时；RustFS 回环监听存在的证明）。 */
	connectTcp(host: string, port: number, timeoutMs: number): Promise<void>;
}

// 节点模型固定值：RustFS 只在容器内回环 127.0.0.1:9000 监听（AGENTS.md 节点拓扑）。
export const RUSTFS_LOOPBACK_HOST = "127.0.0.1";
export const RUSTFS_LOOPBACK_PORT = 9000;

function boundedDetail(value: string): string {
	return value.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 160);
}

function passed(code: PreflightCheckCode, detail: string): PreflightCheck {
	return { code, passed: true, detail: boundedDetail(detail) };
}

function failed(code: PreflightCheckCode, detail: string): PreflightCheck {
	return { code, passed: false, detail: boundedDetail(detail) };
}

function directoryOwnershipCheck(probe: PreflightProbe, code: "state-ownership" | "runtime-ownership", directory: string): PreflightCheck {
	try {
		const owner = probe.pathOwner(directory);
		if (owner.uid !== probe.effectiveUserId()) return failed(code, "directory is not owned by the supervisor service user");
		if ((owner.mode & 0o022) !== 0) return failed(code, "directory is writable by group or other users");
		return passed(code, "directory ownership and write permissions are restricted");
	} catch {
		return failed(code, "directory is missing or cannot be inspected");
	}
}

export async function runSandboxPreflight(options: PreflightOptions, probe: PreflightProbe = systemPreflightProbe): Promise<PreflightReport> {
	const checks: PreflightCheck[] = [];

	if (probe.platform() === "linux") checks.push(passed("linux", "node container host detected"));
	else checks.push(failed("linux", "the wasm supervisor requires the node container's Linux host"));

	checks.push(directoryOwnershipCheck(probe, "state-ownership", options.stateDirectory));
	checks.push(directoryOwnershipCheck(probe, "runtime-ownership", options.runtimeDirectory));

	// 容器内原生执行前置：relay 二进制必须在位且可执行——公开 socket 的 SO_PEERCRED
	// 校验与 FD 3/4 注入都由它承担，缺失即拒绝启动（不回退到无凭据校验的 Node listener）。
	if (probe.fileExists(options.relayBinaryPath)) {
		checks.push(probe.executableFile(options.relayBinaryPath) ? passed("relay-binary", "the native snapshot-fd relay binary is installed and executable") : failed("relay-binary", "the native snapshot-fd relay binary is not executable"));
	} else {
		checks.push(failed("relay-binary", "the native snapshot-fd relay binary is missing at " + options.relayBinaryPath));
	}

	try {
		await probe.connectTcp(RUSTFS_LOOPBACK_HOST, RUSTFS_LOOPBACK_PORT, 2_000);
		checks.push(passed("rustfs-loopback", "the in-container RustFS loopback listener is reachable"));
	} catch {
		checks.push(failed("rustfs-loopback", "the in-container RustFS loopback listener is unreachable"));
	}

	try {
		await probe.bindUnixSocket(options.runtimeDirectory);
		checks.push(passed("unix-socket", "permission-restricted local Unix sockets are available"));
	} catch {
		checks.push(failed("unix-socket", "cannot bind a Unix socket in the supervisor runtime directory"));
	}

	return { version: 2, ready: checks.every((check) => check.passed), checks };
}

export const systemPreflightProbe: PreflightProbe = {
	platform: () => process.platform,
	effectiveUserId: () => process.geteuid?.() ?? -1,
	pathOwner: (path) => {
		const value = statSync(path);
		if (!value.isDirectory()) throw new Error("not a directory");
		return { uid: value.uid, mode: value.mode };
	},
	fileExists: (path) => existsSync(path),
	executableFile: (path) => {
		try {
			accessSync(path, fsConstants.X_OK);
			return true;
		} catch {
			return false;
		}
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
	},
	connectTcp: (host, port, timeoutMs) =>
		new Promise<void>((resolve, reject) => {
			const socket = connectNet(port, host);
			const finish = (error: Error | null): void => {
				socket.destroy();
				if (error === null) resolve();
				else reject(error);
			};
			socket.setTimeout(timeoutMs, () => finish(new Error("connection timed out")));
			socket.once("error", (error) => finish(error));
			socket.once("connect", () => finish(null));
		}),
};
