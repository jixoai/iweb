// 用户原始需求（2026-08-27，add-wasm-runtime 7.1）：公开 execution HTTP socket 必须由原生
// relay 承担 SO_PEERCRED；Node 只监听 relay 私有 upstream，且该 upstream 仍要求 relay
// 进程启动时生成的通道凭据。
// 正交意图：固定公开/私有 socket 路径；relay 生命周期；生产参数与测试 IO 接缝。

import { spawn as spawnChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { SNAPSHOT_FD_SOCKET_PATH } from "./snapshot-fd.ts";
import { SnapshotFdRelayClient } from "./snapshot-fd-relay-client.ts";
import { SUPERVISOR_INTERNAL_SOCKET_PATH, SUPERVISOR_SOCKET_PATH } from "./socket-auth.ts";

// 部署注记（two-tier-runtime-trust：容器内拓扑）：节点 entrypoint 在 supervisor 启动前创建
// `/run/iweb-sandbox`（iweb-sandbox:iweb-sandbox，0700）；supervisor.sock（Kernel 侧
// relay 前置）与 supervisor-internal.sock（Node upstream）都在该目录绑定。
// `/data/kernel/wasm`（Kernel 投影）以只读目录对 supervisor 可见；snapshot-fd.sock 是
// 独立的 raw SCM_RIGHTS 传输。relay 二进制由节点镜像构建（/usr/local/bin/）。
export const SUPERVISOR_SOCKET_RELAY_BINARY = "/usr/local/bin/iweb-snapshot-fd-relay";
export const SUPERVISOR_SOCKET_RELAY_MISSING = "SUPERVISOR_SOCKET_RELAY_MISSING";
export const SUPERVISOR_SOCKET_RELAY_TIMEOUT = "SUPERVISOR_SOCKET_RELAY_TIMEOUT";

const RELAY_CONTROL_BIND_ATTEMPTS = 100;
const RELAY_CONTROL_BIND_INTERVAL_MS = 50;

export interface SupervisorSocketRelayChild {
	on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
	kill(signal?: NodeJS.Signals | number): void;
}

export interface SupervisorSocketRelayIO {
	exists(path: string): boolean;
	sleep(ms: number): Promise<void>;
	spawnRelayProcess(binary: string, args: readonly string[]): SupervisorSocketRelayChild;
}

export const systemSupervisorSocketRelayIO: SupervisorSocketRelayIO = {
	exists: (path) => existsSync(path),
	sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
	spawnRelayProcess: (binary, args) => spawnChildProcess(binary, [...args], { stdio: ["ignore", "ignore", "inherit"] }),
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
	const controlSocketPath = join(input.runtimeDirectory, "snapshot-fd-relay.sock");
	// relay 的注入型 exec 目标（two-tier-runtime-trust：原 --podman 的进程口径形态）：
	// supervisor 的 spawn 请求携带 ["-c", <launcher>]，relay 以 FD 3/4 注入后 exec /bin/sh
	// 执行 launcher（wasm-runtime.ts / wasm-spawn.ts 单一来源）。relay 控制 wire 的
	// flag 名保留 --podman（kernel-rs/snapshot-fd-relay 的既有契约，不改 relay）。
	const child = io.spawnRelayProcess(binary, [
		"--fd-socket", SNAPSHOT_FD_SOCKET_PATH,
		"--control-socket", controlSocketPath,
		"--kernel-peer-uid", "0",
		"--kernel-peer-gid", "0",
		"--podman", "/bin/sh",
		"--execution-socket", input.publicSocketPath,
		"--execution-upstream", input.upstreamSocketPath,
		"--execution-upstream-token", input.upstreamAuthorization,
	]);
	child.on("exit", (code, signal) => {
		process.stderr.write("iweb sandbox supervisor: native execution relay exited (code=" + String(code) + " signal=" + String(signal) + "); supervisor socket is unavailable until restart\n");
	});
	for (let attempt = 0; attempt < RELAY_CONTROL_BIND_ATTEMPTS; attempt += 1) {
		if (io.exists(controlSocketPath) && io.exists(input.publicSocketPath)) {
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
