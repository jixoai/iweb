// 用户原始需求（2026-08-27，add-wasm-runtime 7.1）：原生 relay 是唯一公开 execution
// socket 监听者；Node upstream 没有 relay token 时不得成为第二入口。
// 正交意图：固定 relay 参数；缺 relay/错误路径拒绝；不打印进程通道凭据。

import { describe, expect, test } from "bun:test";
import {
	startSupervisorSocketRelay,
	SUPERVISOR_SOCKET_RELAY_BINARY,
	SUPERVISOR_SOCKET_RELAY_MISSING,
	SupervisorSocketRelayError,
	type SupervisorSocketRelayChild,
	type SupervisorSocketRelayIO,
} from "../supervisor/socket-relay.ts";
import { SUPERVISOR_INTERNAL_SOCKET_PATH, SUPERVISOR_SOCKET_PATH } from "../supervisor/socket-auth.ts";

class RelayChild implements SupervisorSocketRelayChild {
	readonly kills: string[] = [];
	on(_event: "exit", _listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown {
		return this;
	}
	kill(signal?: NodeJS.Signals | number): void {
		this.kills.push(String(signal ?? "SIGTERM"));
	}
}

class RelayIO implements SupervisorSocketRelayIO {
	readonly files = new Set<string>([SUPERVISOR_SOCKET_RELAY_BINARY]);
	readonly starts: { readonly binary: string; readonly args: readonly string[] }[] = [];
	readonly child = new RelayChild();

	exists(path: string): boolean {
		return this.files.has(path);
	}

	async sleep(): Promise<void> {}

	spawnRelayProcess(binary: string, args: readonly string[]): SupervisorSocketRelayChild {
		this.starts.push({ binary, args: [...args] });
		const control = args.indexOf("--control-socket");
		const execution = args.indexOf("--execution-socket");
		if (control >= 0) this.files.add(args[control + 1] ?? "");
		if (execution >= 0) this.files.add(args[execution + 1] ?? "");
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
	test("owns the fixed public socket and passes only fixed Kernel peer credentials", async () => {
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
		// two-tier-runtime-trust：relay 的注入型 exec 目标是 /bin/sh（FD 3/4 注入后执行
		// supervisor 组装的 wasmd launcher；relay flag 名沿用 --podman——kernel-rs 契约）。
		expect(args[args.indexOf("--podman") + 1]).toBe("/bin/sh");
		running.stop();
		expect(io.child.kills).toEqual(["SIGTERM"]);
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
