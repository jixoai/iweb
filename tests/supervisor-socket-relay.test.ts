// 用户原始需求（2026-08-27，add-wasm-runtime 7.1；2026-08-30 two-tier-runtime-trust R2
//   9.2/9.8 修订）：原生 relay 是唯一公开 execution socket 监听者；Node upstream 没有
//   relay token 时不得成为第二入口。relay 直执行 wasmd（--exec 目标），readiness 验
//   进程存活 + socket inode 翻新（残留 socket 文件不冒充就绪）。
// 正交意图：固定 relay 参数（--exec 指向 pinned wasmd）；缺 relay/wasmd/错误路径拒绝；
// 不打印进程通道凭据。

import { describe, expect, test } from "bun:test";
import {
	startSupervisorSocketRelay,
	SUPERVISOR_SOCKET_RELAY_BINARY,
	SUPERVISOR_SOCKET_RELAY_EXITED,
	SUPERVISOR_SOCKET_RELAY_MISSING,
	SUPERVISOR_SOCKET_RELAY_TIMEOUT,
	SupervisorSocketRelayError,
	type SupervisorSocketRelayChild,
	type SupervisorSocketRelayIO,
} from "../supervisor/socket-relay.ts";
import { SUPERVISOR_INTERNAL_SOCKET_PATH, SUPERVISOR_SOCKET_PATH } from "../supervisor/socket-auth.ts";
import { DEFAULT_WASMD_BINARY_PATH } from "../supervisor/wasm-spawn.ts";

class RelayChild implements SupervisorSocketRelayChild {
	readonly kills: string[] = [];
	aliveNow = true;
	on(_event: "exit", _listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown {
		return this;
	}
	kill(signal?: NodeJS.Signals | number): void {
		this.kills.push(String(signal ?? "SIGTERM"));
	}
	alive(): boolean {
		return this.aliveNow;
	}
}

class RelayIO implements SupervisorSocketRelayIO {
	readonly files = new Set<string>([SUPERVISOR_SOCKET_RELAY_BINARY, DEFAULT_WASMD_BINARY_PATH]);
	readonly inodes = new Map<string, number>();
	readonly starts: { readonly binary: string; readonly args: readonly string[] }[] = [];
	readonly child = new RelayChild();
	private nextInode = 100;
	/** bindSimulation：spawn 时对哪些 socket 赋新 inode（缺省两个都 bind）。 */
	bindControl = true;
	bindPublic = true;

	exists(path: string): boolean {
		return this.files.has(path);
	}

	statInode(path: string): number | null {
		return this.inodes.get(path) ?? null;
	}

	async sleep(): Promise<void> {}

	spawnRelayProcess(binary: string, args: readonly string[]): SupervisorSocketRelayChild {
		this.starts.push({ binary, args: [...args] });
		const control = args.indexOf("--control-socket");
		const execution = args.indexOf("--execution-socket");
		if (control >= 0 && this.bindControl) this.inodes.set(args[control + 1] ?? "", this.nextInode++);
		if (execution >= 0 && this.bindPublic) this.inodes.set(args[execution + 1] ?? "", this.nextInode++);
		return this.child;
	}
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
	return promise.then(
		() => null,
		(error: unknown) => error,
	);
}

describe("supervisor native execution socket relay", () => {
	test("owns the fixed public socket, direct-executes wasmd, and proves readiness by fresh inodes", async () => {
		const io = new RelayIO();
		const running = await startSupervisorSocketRelay({
			environment: {},
			runtimeDirectory: "/run/iweb-sandbox",
			publicSocketPath: SUPERVISOR_SOCKET_PATH,
			upstreamSocketPath: SUPERVISOR_INTERNAL_SOCKET_PATH,
			upstreamAuthorization: "a".repeat(64),
			io,
		});
		expect(io.starts).toHaveLength(1);
		const args = io.starts[0]?.args ?? [];
		expect(io.starts[0]?.binary).toBe(SUPERVISOR_SOCKET_RELAY_BINARY);
		expect(io.starts[0]?.binary).toBe("/usr/local/bin/iweb-snapshot-fd-relay");
		expect(args).toContain("--execution-socket");
		expect(args).toContain(SUPERVISOR_SOCKET_PATH);
		expect(args).toContain("--execution-upstream");
		expect(args).toContain(SUPERVISOR_INTERNAL_SOCKET_PATH);
		expect(args).toContain("--kernel-peer-uid");
		expect(args[args.indexOf("--kernel-peer-uid") + 1]).toBe("0");
		expect(args[args.indexOf("--kernel-peer-gid") + 1]).toBe("0");
		// R2 9.2 直执行：relay 的 exec 目标是 wasmd 二进制本体（无 /bin/sh launcher）。
		expect(args).not.toContain("--podman");
		expect(args[args.indexOf("--exec") + 1]).toBe(DEFAULT_WASMD_BINARY_PATH);
		expect(args[args.indexOf("--exec") + 1]).toBe("/opt/iweb/wasmd/iweb-wasmd");
		running.stop();
		expect(io.child.kills).toEqual(["SIGTERM"]);
	});

	test("a missing pinned wasmd binary refuses to start the relay", async () => {
		const io = new RelayIO();
		io.files.delete(DEFAULT_WASMD_BINARY_PATH);
		const missing = await failure(startSupervisorSocketRelay({
			environment: {}, runtimeDirectory: "/run/iweb-sandbox", publicSocketPath: SUPERVISOR_SOCKET_PATH,
			upstreamSocketPath: SUPERVISOR_INTERNAL_SOCKET_PATH, upstreamAuthorization: "a".repeat(64), io,
		}));
		expect(missing).toBeInstanceOf(SupervisorSocketRelayError);
		expect((missing as SupervisorSocketRelayError).code).toBe(SUPERVISOR_SOCKET_RELAY_MISSING);
	});

	test("a stale socket file never fakes readiness: the inode must turn over", async () => {
		const io = new RelayIO();
		// 启动前残留（上次崩溃遗留）：inode 已存在；新 relay 只 bind 了 control——
		// public 的 inode 不翻新 → 超时拒绝，绝不把残留文件当作就绪。
		io.inodes.set(SUPERVISOR_SOCKET_PATH, 7);
		io.bindPublic = false;
		const stale = await failure(startSupervisorSocketRelay({
			environment: {}, runtimeDirectory: "/run/iweb-sandbox", publicSocketPath: SUPERVISOR_SOCKET_PATH,
			upstreamSocketPath: SUPERVISOR_INTERNAL_SOCKET_PATH, upstreamAuthorization: "a".repeat(64), io,
		}));
		expect(stale).toBeInstanceOf(SupervisorSocketRelayError);
		expect((stale as SupervisorSocketRelayError).code).toBe(SUPERVISOR_SOCKET_RELAY_TIMEOUT);
		expect(io.child.kills).toContain("SIGTERM");
	});

	test("a relay that dies before binding fails fast with the exited code", async () => {
		const io = new RelayIO();
		io.child.aliveNow = false;
		const exited = await failure(startSupervisorSocketRelay({
			environment: {}, runtimeDirectory: "/run/iweb-sandbox", publicSocketPath: SUPERVISOR_SOCKET_PATH,
			upstreamSocketPath: SUPERVISOR_INTERNAL_SOCKET_PATH, upstreamAuthorization: "a".repeat(64), io,
		}));
		expect(exited).toBeInstanceOf(SupervisorSocketRelayError);
		expect((exited as SupervisorSocketRelayError).code).toBe(SUPERVISOR_SOCKET_RELAY_EXITED);
	});

	test("refuses an alternate public path, malformed channel value, or missing native relay", async () => {
		const io = new RelayIO();
		const alternate = await failure(startSupervisorSocketRelay({
			environment: {}, runtimeDirectory: "/run/iweb-sandbox", publicSocketPath: "/tmp/redirected.sock",
			upstreamSocketPath: SUPERVISOR_INTERNAL_SOCKET_PATH, upstreamAuthorization: "a".repeat(64), io,
		}));
		expect(alternate).toBeInstanceOf(SupervisorSocketRelayError);
		expect((alternate as SupervisorSocketRelayError).code).toBe(SUPERVISOR_SOCKET_RELAY_MISSING);

		const malformed = await failure(startSupervisorSocketRelay({
			environment: {}, runtimeDirectory: "/run/iweb-sandbox", publicSocketPath: SUPERVISOR_SOCKET_PATH,
			upstreamSocketPath: SUPERVISOR_INTERNAL_SOCKET_PATH, upstreamAuthorization: "bad", io,
		}));
		expect(malformed).toBeInstanceOf(SupervisorSocketRelayError);

		const missingIO = new RelayIO();
		missingIO.files.delete(SUPERVISOR_SOCKET_RELAY_BINARY);
		const missing = await failure(startSupervisorSocketRelay({
			environment: {}, runtimeDirectory: "/run/iweb-sandbox", publicSocketPath: SUPERVISOR_SOCKET_PATH,
			upstreamSocketPath: SUPERVISOR_INTERNAL_SOCKET_PATH, upstreamAuthorization: "a".repeat(64), io: missingIO,
		}));
		expect((missing as SupervisorSocketRelayError).code).toBe(SUPERVISOR_SOCKET_RELAY_MISSING);
	});
});
