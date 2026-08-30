// 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2；two-tier-runtime-trust
//   2026-08-30 去 Podman 修订）：supervisor executor 的真实副作用端口——wasm execution
//   以受管子进程运行在节点容器内。FD 承载的启动由原生 relay（kernel-rs/snapshot-fd-relay）
//   的注入型 exec 代持：relay 是唯一持有快照描述符的半边（Node/Bun 无 SCM_RIGHTS 接收
//   能力），其 fork 路径把 FD 3（secret）/FD 4（config，存在时）映射进子进程 fd 表、
//   清 FD_CLOEXEC、关闭其余继承描述符——spec ADDED "Snapshot FD content is bound across
//   Kernel, supervisor, and wasmd" 的 direct-process 形态。
// 正交意图：
//   1. spawnExecution：relay.spawn(commandId, ["-c", launcher])——launcher 由
//      wasm-spawn.ts 的 buildWasmdLauncherScript 单一来源组装（argv@2 + pidfile），
//      relay exec /bin/sh 执行它；sh 立即退出使 waitpid 收敛（relay 控制 socket 是
//      串行单线程，长驻进程会占死 lookup/discard 通道），wasmd 以后台作业持有 FD 3/4；
//   2. stopExecution：SIGTERM → 预算内轮询退出 → 超时 SIGKILL → 等待退出（drain 语义
//      与 forced_kill_at 语义由上层 executor 复用，本端口只报 stopped/forced-kill）；
//   3. removeSandbox / isRunning：pidfile 为进程地址权威；僵尸进程（已退出未被 reap）
//      不算 running；
//   4. 一切基础设施错误以 RuntimeFailure 分类抛出（executor 将确定性拒绝回 journal，
//      意外错误保持 received-incomplete 由 replay 恢复）。
import { readFileSync, rmSync } from "node:fs";
import { buildWasmdLauncherScript, wasmdPidFilePath, type WasmSandboxSpawnSpec } from "./wasm-spawn.ts";
import { SnapshotFdRelayClient, SnapshotFdRelayError } from "./snapshot-fd-relay-client.ts";

export const WASM_SPAWN_RELAY_UNAVAILABLE = "WASM_SPAWN_RELAY_UNAVAILABLE";
export const WASM_EXECUTION_SPAWN_FAILED = "WASM_EXECUTION_SPAWN_FAILED";
export const WASM_PROCESS_LOST = "WASM_PROCESS_LOST";

export type RuntimeFailureKind = "not-found" | "conflict" | "infrastructure";

/** 确定性副作用失败（executor 以 rejected ack 终结；同命令 replay 返回存档结果）。 */
export class RuntimeFailure extends Error {
	readonly kind: RuntimeFailureKind;
	constructor(kind: RuntimeFailureKind, message: string) {
		super(message);
		this.name = "RuntimeFailure";
		this.kind = kind;
	}
}

function infrastructure(message: string): RuntimeFailure {
	return new RuntimeFailure("infrastructure", message);
}

export interface WasmStopOutcome {
	readonly result: "stopped" | "forced-kill";
}

/**
 * wasm 执行链的真实副作用端口（executor 的唯一副作用出口；测试以桩实现注入）。
 * 语义约定：
 * - spawnExecution：经 relay 的 FD 3/4 注入启动 wasmd 子进程；启动失败（relay 不可达、
 *   exec 非零退出、pidfile 未落或进程立即死亡）是确定性失败。
 * - stopExecution：SIGTERM → deadline 语义由调用方传入（毫秒预算）→ 超时 SIGKILL；
 *   返回是否被强杀。
 * - removeSandbox / isRunning：stop 命令与崩溃检测的清理/观测（pidfile 口径）。
 */
export interface WasmSandboxRuntime {
	spawnExecution(commandId: string, spec: WasmSandboxSpawnSpec): Promise<void>;
	stopExecution(sandboxId: string, budgetMs: number): Promise<WasmStopOutcome>;
	removeSandbox(sandboxId: string): Promise<void>;
	isRunning(sandboxId: string): Promise<boolean>;
}

/** 进程生命周期 IO（测试可注入；生产为文件系统 + POSIX 信号）。 */
export interface WasmProcessRuntimeIO {
	readFile(path: string): string | null;
	sleep(ms: number): Promise<void>;
	kill(pid: number, signal: NodeJS.Signals): boolean;
	/** 进程存活且非僵尸（kill(pid,0) 成功且 /proc/<pid>/stat 非 Z；/proc 不可读时只凭信号）。 */
	isAlive(pid: number): boolean;
	deleteFile(path: string): void;
}

export const systemWasmProcessRuntimeIO: WasmProcessRuntimeIO = {
	readFile: (path) => {
		try {
			return readFileSync(path, "utf8");
		} catch {
			return null;
		}
	},
	sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
	kill: (pid, signal) => {
		try {
			process.kill(pid, signal);
			return true;
		} catch {
			return false;
		}
	},
	isAlive: (pid) => {
		try {
			process.kill(pid, 0);
		} catch {
			return false;
		}
		// 僵尸进程已退出、只等 reap：不把它当作运行中的 execution（PID 1 收尸前的窗口）。
		try {
			const stat = readFileSync("/proc/" + pid + "/stat", "utf8");
			const closed = stat.lastIndexOf(")");
			const state = stat.slice(closed + 2, closed + 3);
			if (state === "Z" || state === "X" || state === "x") return false;
		} catch {
			// /proc 不可读（非 Linux 宿主）：信号探测已是可得的事实上限。
		}
		return true;
	},
	deleteFile: (path) => {
		try {
			// pidfile 不是安全记录：缺失即目标态，删除失败不升级为基础设施错误。
			rmSync(path, { force: true });
		} catch {
			/* already absent */
		}
	},
};

export interface ProcessWasmRuntimeOptions {
	/** 代持 FD 的原生 relay 控制客户端（wasmd 子进程 FD 3/4 注入的唯一来源）。 */
	readonly relay: Pick<SnapshotFdRelayClient, "spawn">;
	readonly io?: WasmProcessRuntimeIO;
	/** launcher 写 pidfile 后的进程活性确认窗口（毫秒；缺省 250）。 */
	readonly settleMs?: number;
	/** pidfile 落盘等待上限（毫秒；缺省 5000）。 */
	readonly pidfileTimeoutMs?: number;
	/** SIGKILL 后等待退出的上限（毫秒；缺省 10000）。 */
	readonly killGraceMs?: number;
	/** 退出轮询间隔（毫秒；缺省 50）。 */
	readonly pollIntervalMs?: number;
}

// pidfile 内容：launcher 写入的十进制 pid（可带换行）。
function readPid(io: WasmProcessRuntimeIO, pidFile: string): number | null {
	const text = io.readFile(pidFile);
	if (text === null) return null;
	const pid = Number.parseInt(text.trim(), 10);
	return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
}

export function createProcessWasmSandboxRuntime(options: ProcessWasmRuntimeOptions & { pidDirectory: string }): WasmSandboxRuntime {
	const relay = options.relay;
	const io = options.io ?? systemWasmProcessRuntimeIO;
	const settleMs = options.settleMs ?? 250;
	const pidfileTimeoutMs = options.pidfileTimeoutMs ?? 5_000;
	const killGraceMs = options.killGraceMs ?? 10_000;
	const pollIntervalMs = options.pollIntervalMs ?? 50;

	const pidOf = (sandboxId: string): number | null => readPid(io, wasmdPidFilePath(options.pidDirectory, sandboxId));

	const waitExited = async (pid: number, budgetMs: number): Promise<boolean> => {
		const deadline = Date.now() + Math.max(0, budgetMs);
		if (!io.isAlive(pid)) return true;
		while (Date.now() < deadline) {
			await io.sleep(pollIntervalMs);
			if (!io.isAlive(pid)) return true;
		}
		return !io.isAlive(pid);
	};

	return {
		spawnExecution: async (commandId, spec) => {
			// FD 3/4 注入 + launcher exec：argv 单一来源是 wasm-spawn.ts（argv@2 + pidfile）。
			const script = buildWasmdLauncherScript(spec);
			let spawn: Awaited<ReturnType<SnapshotFdRelayClient["spawn"]>>;
			try {
				spawn = await relay.spawn(commandId, ["-c", script]);
			} catch (error) {
				if (error instanceof SnapshotFdRelayError) throw new RuntimeFailure("infrastructure", WASM_SPAWN_RELAY_UNAVAILABLE + ": " + error.message);
				throw error;
			}
			if (!spawn.ok) throw new RuntimeFailure("infrastructure", WASM_SPAWN_RELAY_UNAVAILABLE + ": " + spawn.code + ": " + spawn.message);
			if (spawn.exitCode !== 0) throw new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": the wasmd launcher exited with " + spawn.exitCode);
			// relay 的响应在 launcher（sh）退出后返回，pidfile 已写；短暂兜底轮询覆盖
			// 文件系统可见性窗口。
			const pidDeadline = Date.now() + pidfileTimeoutMs;
			let pid = pidOf(spec.sandboxId);
			while (pid === null && Date.now() < pidDeadline) {
				await io.sleep(pollIntervalMs);
				pid = pidOf(spec.sandboxId);
			}
			if (pid === null) {
				throw new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": the wasmd launcher wrote no pidfile at " + spec.pidFilePath);
			}
			// 活性确认：二进制缺失/argv 拒绝/绑定失败会在毫秒级死亡——窗口内死亡按启动
			// 失败终结（之后的死亡由 isRunning/stop 崩溃路径观测，语义与容器时代一致）。
			await io.sleep(settleMs);
			if (!io.isAlive(pid)) {
				io.deleteFile(spec.pidFilePath);
				throw new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": the wasmd process died immediately after launch (pid " + pid + ")");
			}
		},

		stopExecution: async (sandboxId, budgetMs) => {
			const pid = pidOf(sandboxId);
			if (pid === null) return { result: "stopped" };
			if (!io.isAlive(pid)) {
				io.deleteFile(wasmdPidFilePath(options.pidDirectory, sandboxId));
				return { result: "stopped" };
			}
			io.kill(pid, "SIGTERM");
			if (await waitExited(pid, budgetMs)) return { result: "stopped" };
			// 优雅窗口耗尽：强杀并复核退出。
			io.kill(pid, "SIGKILL");
			if (await waitExited(pid, killGraceMs)) return { result: "forced-kill" };
			throw infrastructure(WASM_PROCESS_LOST + ": the wasmd process survived a forced kill (pid " + pid + ")");
		},

		removeSandbox: async (sandboxId) => {
			const pid = pidOf(sandboxId);
			if (pid !== null && io.isAlive(pid)) {
				io.kill(pid, "SIGKILL");
				await waitExited(pid, killGraceMs);
			}
			io.deleteFile(wasmdPidFilePath(options.pidDirectory, sandboxId));
		},

		isRunning: async (sandboxId) => {
			const pid = pidOf(sandboxId);
			return pid !== null && io.isAlive(pid);
		},
	};
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. relay 仍是 FD 3/4 的唯一持有者与注入者：Node/Bun 无法接收 SCM_RIGHTS，描述符无法
//    进入 Node 进程——「supervisor spawns wasmd」按部署对象成立（relay 是 supervisor 的
//    组成半边，spec 的 SupervisorSocketAuthV1 部署对象同口径）。若后续 kernel-rs 批次
//    为 relay 提供非阻塞直exec，本层只换 launcher 形态，fence 语义不动。
// 2. settle 窗口（缺省 250ms）后的进程死亡不算启动失败：与容器时代的「run 成功后崩溃」
//    同语义，由 isRunning/Kernel 崩溃检测接管；把窗口拉长只会让 start 命令时序依赖
//    wasmd 的启动速度（fail-open 方向，不做）。
// 3. stopExecution 对无 pidfile/已退出进程返回 stopped（幂等目标态）；SIGKILL 后仍存活
//    是基础设施错误（WASM_PROCESS_LOST），上层以 rejected ack 终结、不伪造 receipt。
