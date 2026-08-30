// 用户原始需求（2026-08-27，add-wasm-runtime 7.1）：公开 execution HTTP socket 必须由原生
// relay 承担 SO_PEERCRED；Node 只监听 relay 私有 upstream，且该 upstream 仍要求 relay
// 进程启动时生成的通道凭据。
// 轮次注记（2026-08-30，two-tier-runtime-trust R2 9.2/9.8）：relay 的注入型 exec 目标是
//   wasmd 二进制本体（--exec <绝对路径>，去 /bin/sh launcher）；readiness 从「socket 文件
//   存在」升级为「relay 进程存活（supervisor 持有的 child pid kill -0）且两枚 socket 的
//   inode 相对启动前已翻新」——残留 socket 文件（上次崩溃遗留）不再冒充就绪。
// 正交意图：固定公开/私有 socket 路径；relay 生命周期；生产参数与测试 IO 接缝。

import { spawn as spawnChildProcess } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { SNAPSHOT_FD_SOCKET_PATH } from "./snapshot-fd.ts";
import { SnapshotFdRelayClient } from "./snapshot-fd-relay-client.ts";
import { SUPERVISOR_INTERNAL_SOCKET_PATH, SUPERVISOR_SOCKET_PATH } from "./socket-auth.ts";
import { DEFAULT_WASMD_BINARY_PATH, IWEB_SANDBOX_WASM_BIN_ENV } from "./wasm-spawn.ts";

// 部署注记（two-tier-runtime-trust：容器内拓扑）：节点 entrypoint 在 supervisor 启动前创建
// `/run/iweb-sandbox`（iweb-sandbox:iweb-sandbox，0700）；supervisor.sock（Kernel 侧
// relay 前置）与 supervisor-internal.sock（Node upstream）都在该目录绑定。
// `/data/kernel/wasm`（Kernel 投影）以只读目录对 supervisor 可见；snapshot-fd.sock 是
// 独立的 raw SCM_RIGHTS 传输。relay 二进制由节点镜像构建（/usr/local/bin/）。
export const SUPERVISOR_SOCKET_RELAY_BINARY = "/usr/local/bin/iweb-snapshot-fd-relay";
export const SUPERVISOR_SOCKET_RELAY_MISSING = "SUPERVISOR_SOCKET_RELAY_MISSING";
export const SUPERVISOR_SOCKET_RELAY_TIMEOUT = "SUPERVISOR_SOCKET_RELAY_TIMEOUT";
/** relay 进程在 readiness 窗口内退出（绑定未完成；区别于超时）。 */
export const SUPERVISOR_SOCKET_RELAY_EXITED = "SUPERVISOR_SOCKET_RELAY_EXITED";

const RELAY_CONTROL_BIND_ATTEMPTS = 100;
const RELAY_CONTROL_BIND_INTERVAL_MS = 50;

export interface SupervisorSocketRelayChild {
	on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
	kill(signal?: NodeJS.Signals | number): void;
	/** 进程存活探测（kill(pid,0) 口径；readiness 与启动期崩溃判定共用）。 */
	alive(): boolean;
}

export interface SupervisorSocketRelayIO {
	exists(path: string): boolean;
	/** socket 文件的 inode（不存在返回 null；readiness 的「翻新」判定输入）。 */
	statInode(path: string): number | null;
	sleep(ms: number): Promise<void>;
	spawnRelayProcess(binary: string, args: readonly string[]): SupervisorSocketRelayChild;
}

export const systemSupervisorSocketRelayIO: SupervisorSocketRelayIO = {
	exists: (path) => existsSync(path),
	statInode: (path) => {
		try {
			return statSync(path).ino;
		} catch {
			return null;
		}
	},
	sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
	spawnRelayProcess: (binary, args) => {
		const child = spawnChildProcess(binary, [...args], { stdio: ["ignore", "ignore", "inherit"] });
		return {
			on: (event, listener) => child.on(event, listener),
			kill: (signal) => child.kill(signal),
			alive: () => {
				if (typeof child.pid !== "number") return false;
				try {
					process.kill(child.pid, 0);
					return true;
				} catch {
					return false;
				}
			},
		};
	},
};

export class SupervisorSocketRelayError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.name = "SupervisorSocketRelayError";
		this.code = code;
	}
}

export interface StartSupervisorSocketRelayInput {
	readonly environment: Readonly<Record<string, string | undefined>>;
	readonly runtimeDirectory: string;
	readonly publicSocketPath: string;
	readonly upstreamSocketPath: string;
	/** Opaque 32-byte random hex. It is passed only to the child and Node. */
	readonly upstreamAuthorization: string;
	readonly io?: SupervisorSocketRelayIO;
}

export interface RunningSupervisorSocketRelay {
	readonly child: SupervisorSocketRelayChild;
	readonly client: SnapshotFdRelayClient;
	readonly controlSocketPath: string;
	stop(): void;
}

function absolutePath(value: string | undefined, fallback: string, name: string): string {
	const normalized = (value ?? fallback).trim();
	if (normalized.length === 0 || !normalized.startsWith("/")) throw new SupervisorSocketRelayError(SUPERVISOR_SOCKET_RELAY_MISSING, name + " must be a non-empty absolute path");
	return normalized;
}

function isRelayAuthorization(value: string): boolean {
	return /^[0-9a-f]{64}$/.test(value);
}

/**
 * Start the only public execution socket owner. There is intentionally no
 * Node fallback: a missing relay leaves the supervisor unavailable rather than
 * exposing a socket whose peer credentials cannot be checked.
 */
export async function startSupervisorSocketRelay(input: StartSupervisorSocketRelayInput): Promise<RunningSupervisorSocketRelay> {
	if (input.publicSocketPath !== SUPERVISOR_SOCKET_PATH || input.upstreamSocketPath !== SUPERVISOR_INTERNAL_SOCKET_PATH) {
		throw new SupervisorSocketRelayError(SUPERVISOR_SOCKET_RELAY_MISSING, "the execution relay requires the fixed public and private socket literals");
	}
	if (!isRelayAuthorization(input.upstreamAuthorization)) {
		throw new SupervisorSocketRelayError(SUPERVISOR_SOCKET_RELAY_MISSING, "the execution relay requires a process-local 32-byte authorization value");
	}
	const io = input.io ?? systemSupervisorSocketRelayIO;
	const binary = absolutePath(input.environment.IWEB_SANDBOX_WASM_RELAY_BIN, SUPERVISOR_SOCKET_RELAY_BINARY, "IWEB_SANDBOX_WASM_RELAY_BIN");
	if (!io.exists(binary)) {
		throw new SupervisorSocketRelayError(SUPERVISOR_SOCKET_RELAY_MISSING, "the native execution relay binary is missing; refusing to expose an unauthenticated supervisor socket");
	}
	// 直执行目标（9.2）：relay 以 --exec <wasmd 绝对路径> 直 execv（spawn payload 的
	// argv[0] 与之同值；wasm-spawn.ts 的 wasmdDirectExecArgv 单一来源）。
	const wasmdBinary = absolutePath(input.environment[IWEB_SANDBOX_WASM_BIN_ENV], DEFAULT_WASMD_BINARY_PATH, IWEB_SANDBOX_WASM_BIN_ENV);
	if (!io.exists(wasmdBinary)) {
		throw new SupervisorSocketRelayError(SUPERVISOR_SOCKET_RELAY_MISSING, "the pinned wasmd binary is missing at " + wasmdBinary + "; the execution relay refuses to start without its direct exec target");
	}
	const controlSocketPath = join(input.runtimeDirectory, "snapshot-fd-relay.sock");
	// readiness 翻新基线（9.8）：启动前已存在的 socket 文件 inode（上次崩溃的残留）。
	// 就绪要求 inode 变化——残留文件不再冒充新 relay 的绑定。
	const staleControlInode = io.statInode(controlSocketPath);
	const stalePublicInode = io.statInode(input.publicSocketPath);
	const child = io.spawnRelayProcess(binary, [
		"--fd-socket", SNAPSHOT_FD_SOCKET_PATH,
		"--control-socket", controlSocketPath,
		"--kernel-peer-uid", "0",
		"--kernel-peer-gid", "0",
		"--exec", wasmdBinary,
		"--execution-socket", input.publicSocketPath,
		"--execution-upstream", input.upstreamSocketPath,
		"--execution-upstream-token", input.upstreamAuthorization,
	]);
	child.on("exit", (code, signal) => {
		process.stderr.write("iweb sandbox supervisor: native execution relay exited (code=" + String(code) + " signal=" + String(signal) + "); supervisor socket is unavailable until restart\n");
	});
	for (let attempt = 0; attempt < RELAY_CONTROL_BIND_ATTEMPTS; attempt += 1) {
		// 进程口径 readiness：先证明 relay 活着（kill -0），再看 socket inode 翻新。
		if (!child.alive()) {
			child.kill("SIGKILL");
			throw new SupervisorSocketRelayError(SUPERVISOR_SOCKET_RELAY_EXITED, "the native execution relay exited before binding both fixed sockets");
		}
		const controlInode = io.statInode(controlSocketPath);
		const publicInode = io.statInode(input.publicSocketPath);
		const controlFresh = controlInode !== null && controlInode !== staleControlInode;
		const publicFresh = publicInode !== null && publicInode !== stalePublicInode;
		if (controlFresh && publicFresh) {
			return {
				child,
				client: new SnapshotFdRelayClient({ controlSocketPath }),
				controlSocketPath,
				stop: () => child.kill("SIGTERM"),
			};
		}
		await io.sleep(RELAY_CONTROL_BIND_INTERVAL_MS);
	}
	child.kill("SIGTERM");
	throw new SupervisorSocketRelayError(SUPERVISOR_SOCKET_RELAY_TIMEOUT, "the native execution relay did not bind both fixed sockets in time");
}
