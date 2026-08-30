// 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2；two-tier-runtime-trust
//   2026-08-30 去 Podman 修订 + R2 9.2 直执行修订）：supervisor executor 的真实副作用
//   端口——wasm execution 以受管子进程运行在节点容器内。FD 承载的启动由原生 relay
//   （kernel-rs/snapshot-fd-relay）的注入型 exec 代持：relay 是唯一持有快照描述符的
//   半边（Node/Bun 无 SCM_RIGHTS 接收能力），其 fork 路径把 FD 3（secret）/FD 4
//   （config，存在时）映射进子进程 fd 表、清 FD_CLOEXEC、关闭其余继承描述符并直
//   execv wasmd——spec ADDED "Snapshot FD content is bound across Kernel, supervisor,
//   and wasmd" 的 direct-process 形态。R2 起 wasmd 是 relay 的直接子进程（无 /bin/sh
//   launcher、无后台化）：spawn 回执携带 pid，pidfile 由本模块记录
//   （/run/iweb-sandbox/wasmd-<applicationId>.pid，Kernel 看门狗的寻址约定）。
// 正交意图：
//   1. spawnExecution：relay.spawn(commandId, wasmdDirectExecArgv(spec))——完整 argv
//      单一来源是 wasm-spawn.ts；supervisor 以回执 pid 写 pidfile 并做短窗活性确认；
//   2. stopExecution：SIGTERM → 预算内轮询退出 → 超时 SIGKILL → 等待退出（drain 语义
//      与 forced_kill_at 语义由上层 executor 复用，本端口只报 stopped/forced-kill）；
//      进程地址是 supervisor 内存内的 sandboxId → pid 映射（同一应用的新 execution 启动
//      会覆写 per-app pidfile，stop 绝不能经 pidfile 寻址——那是看门狗的只读投影）；
//   3. removeSandbox / isRunning：映射口径；僵尸进程（已退出未被 reap）不算 running；
//      pidfile 删除以内容匹配自卫（新 execution 已覆写时不误删）；
//   4. 一切基础设施错误以 RuntimeFailure 分类抛出（executor 将确定性拒绝回 journal，
//      意外错误保持 received-incomplete 由 replay 恢复）。
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { wasmdDirectExecArgv, type WasmSandboxSpawnSpec } from "./wasm-spawn.ts";
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
 * - spawnExecution：经 relay 的 FD 3/4 注入直执行 wasmd 子进程；启动失败（relay 不可达、
 *   relay 拒绝、pidfile 写入失败或进程立即死亡）是确定性失败。
 * - stopExecution：SIGTERM → deadline 语义由调用方传入（毫秒预算）→ 超时 SIGKILL；
 *   返回是否被强杀。
 * - removeSandbox / isRunning：stop 命令与崩溃检测的清理/观测（supervisor 内存映射口径）。
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
	/** pidfile 写入（relay 回报 pid 的落盘；目录缺失时创建 0700，文件 0600）。失败抛错。 */
	writeFile(path: string, contents: string): void;
	sleep(ms: number): Promise<void>;
	kill(pid: number, signal: NodeJS.Signals): boolean;
	/** 进程存活且非僵尸（kill(pid,0) 成功且 /proc/<pid>/stat 非 Z；/proc 不可读时只凭信号）。 */
	isAlive(pid: number): boolean;
	/** 读 /proc/<pid>/stat 的 starttime（字段 22）；进程不存在或不可读返回 null。 */
	readStartTicks(pid: number): number | null;
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
	writeFile: (path, contents) => {
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		writeFileSync(path, contents, { mode: 0o600 });
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
	readStartTicks: (pid) => {
		try {
			const stat = readFileSync("/proc/" + pid + "/stat", "utf8");
			const close = stat.lastIndexOf(")");
			if (close < 0) return null;
			const fields = stat.slice(close + 2).split(" ");
			const ticks = Number.parseInt(fields[20] ?? "", 10);
			return Number.isFinite(ticks) ? ticks : null;
		} catch {
			return null;
		}
	},
	isAlive: (pid) => {
		try {
			process.kill(pid, 0);
		} catch {
			return false;
		}
		// 僵尸进程已退出、只等 reap：不把它当作运行中的 execution（relay 收尸前的窗口）。
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
	/** pidfile 写入后的进程活性确认窗口（毫秒；缺省 250）。 */
	readonly settleMs?: number;
	/** SIGKILL 后等待退出的上限（毫秒；缺省 10000）。 */
	readonly killGraceMs?: number;
	/** 退出轮询间隔（毫秒；缺省 50）。 */
	readonly pollIntervalMs?: number;
}

/** supervisor 内存内的进程地址（sandboxId → relay 回报的 pid + 该 execution 的 pidfile）。 */
interface TrackedExecution {
	readonly pid: number;
	readonly pidFilePath: string;
	/** /proc/<pid>/stat starttime（字段 22）：信号前的 PID 复用栅栏（Codex 二轮阻塞 3）。 */
	readonly startTicks: number | null;
}

export function createProcessWasmSandboxRuntime(options: ProcessWasmRuntimeOptions): WasmSandboxRuntime {
	const relay = options.relay;
	const io = options.io ?? systemWasmProcessRuntimeIO;
	const settleMs = options.settleMs ?? 250;
	const killGraceMs = options.killGraceMs ?? 10_000;
	const pollIntervalMs = options.pollIntervalMs ?? 50;

	// sandboxId → 进程地址。pidfile（wasmd-<applicationId>.pid）是 Kernel 看门狗的只读
	// 投影：同一应用的 drain+新 start 并发时后写者覆写文件，本映射保证 stop/remove/isRunning
	// 恒以本 execution 自己的 pid 寻址。supervisor 崩溃即失映射，但 entrypoint 重启路径先
	// 清理 relay/wasmd 孤儿（9.8），不存在需要经 pidfile 找回的存量进程。
	const executions = new Map<string, TrackedExecution>();

	const waitExited = async (pid: number, budgetMs: number): Promise<boolean> => {
		const deadline = Date.now() + Math.max(0, budgetMs);
		if (!io.isAlive(pid)) return true;
		while (Date.now() < deadline) {
			await io.sleep(pollIntervalMs);
			if (!io.isAlive(pid)) return true;
		}
		return !io.isAlive(pid);
	};

	// 自卫删除：仅当 pidfile 内容仍是本 execution 的 pid（未被同应用新 execution 覆写）。
	const deletePidfileIfOwns = (tracked: TrackedExecution): void => {
		const text = io.readFile(tracked.pidFilePath);
		if (text !== null && text.trim() === String(tracked.pid)) io.deleteFile(tracked.pidFilePath);
	};

	// PID 复用栅栏：信号/活性判定前复核 /proc starttime。Linux（生产）上 spawn 时即
	// 记录 startTicks，此后读数不一致 = pid 已被复用，按「本 execution 已消亡」处理，
	// 绝不向复用者发信号。无 /proc 的平台（macOS 开发机）spawn 时得 null——栅栏不可
	// 用，退回 isAlive 语义（生产 Linux 恒有 /proc，栅栏恒生效）。
	const stillOwnsPid = (tracked: TrackedExecution): boolean => {
		if (!io.isAlive(tracked.pid)) return false;
		if (tracked.startTicks === null) return true;
		return io.readStartTicks(tracked.pid) === tracked.startTicks;
	};

	return {
		spawnExecution: async (commandId, spec) => {
			// FD 3/4 注入 + 直执行：完整 argv 单一来源是 wasm-spawn.ts（argv@2 + 二进制路径）。
			let spawn: Awaited<ReturnType<SnapshotFdRelayClient["spawn"]>>;
			try {
				spawn = await relay.spawn(commandId, wasmdDirectExecArgv(spec));
			} catch (error) {
				if (error instanceof SnapshotFdRelayError) throw new RuntimeFailure("infrastructure", WASM_SPAWN_RELAY_UNAVAILABLE + ": " + error.message);
				throw error;
			}
			if (!spawn.ok) throw new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": the relay refused the direct exec: " + spawn.code + ": " + spawn.message);
			// pidfile：relay 回报 pid 的落盘（Kernel 看门狗按 wasmd-<applicationId>.pid 寻址）。
			try {
				io.writeFile(spec.pidFilePath, String(spawn.pid) + "\n");
			} catch (error) {
				throw new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": the supervisor could not record the pidfile at " + spec.pidFilePath + ": " + (error instanceof Error ? error.message : String(error)));
			}
			// 活性确认：二进制缺失/argv 拒绝/绑定失败会在毫秒级死亡——窗口内死亡按启动
			// 失败终结（之后的死亡由 isRunning/stop 崩溃路径观测，语义与容器时代一致）。
			await io.sleep(settleMs);
			if (!io.isAlive(spawn.pid)) {
				io.deleteFile(spec.pidFilePath);
				throw new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": the wasmd process died immediately after launch (pid " + spawn.pid + ")");
			}
			executions.set(spec.sandboxId, { pid: spawn.pid, pidFilePath: spec.pidFilePath, startTicks: io.readStartTicks(spawn.pid) });
		},

		stopExecution: async (sandboxId, budgetMs) => {
			const tracked = executions.get(sandboxId);
			if (tracked === undefined) return { result: "stopped" };
			if (!stillOwnsPid(tracked)) {
				executions.delete(sandboxId);
				deletePidfileIfOwns(tracked);
				return { result: "stopped" };
			}
			io.kill(tracked.pid, "SIGTERM");
			if (await waitExited(tracked.pid, budgetMs)) {
				executions.delete(sandboxId);
				deletePidfileIfOwns(tracked);
				return { result: "stopped" };
			}
			// 优雅窗口耗尽：强杀并复核退出（强杀前再次复核 PID 身份）。
			if (!stillOwnsPid(tracked)) {
				executions.delete(sandboxId);
				deletePidfileIfOwns(tracked);
				return { result: "stopped" };
			}
			io.kill(tracked.pid, "SIGKILL");
			if (await waitExited(tracked.pid, killGraceMs)) {
				executions.delete(sandboxId);
				deletePidfileIfOwns(tracked);
				return { result: "forced-kill" };
			}
			throw infrastructure(WASM_PROCESS_LOST + ": the wasmd process survived a forced kill (pid " + tracked.pid + ")");
		},

		removeSandbox: async (sandboxId) => {
			const tracked = executions.get(sandboxId);
			if (tracked !== undefined) {
				if (stillOwnsPid(tracked)) {
					io.kill(tracked.pid, "SIGKILL");
					await waitExited(tracked.pid, killGraceMs);
				}
				executions.delete(sandboxId);
				deletePidfileIfOwns(tracked);
			}
		},

		isRunning: async (sandboxId) => {
			const tracked = executions.get(sandboxId);
			return tracked !== undefined && stillOwnsPid(tracked);
		},
	};
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. relay 仍是 FD 3/4 的唯一持有者与注入者：Node/Bun 无法接收 SCM_RIGHTS，描述符无法
//    进入 Node 进程——「supervisor spawns wasmd」按部署对象成立（relay 是 supervisor 的
//    组成半边，spec 的 SupervisorSocketAuthV1 部署对象同口径）。
// 2. settle 窗口（缺省 250ms）后的进程死亡不算启动失败：与容器时代的「run 成功后崩溃」
//    同语义，由 isRunning/Kernel 崩溃检测接管；把窗口拉长只会让 start 命令时序依赖
//    wasmd 的启动速度（fail-open 方向，不做）。
// 3. stopExecution 对无映射/已退出进程返回 stopped（幂等目标态）；SIGKILL 后仍存活
//    是基础设施错误（WASM_PROCESS_LOST），上层以 rejected ack 终结、不伪造 receipt。
// 4. wasmd 子进程的收尸责任在 relay（直接父进程）；本端口的僵尸判定（/proc state Z）
//    只用于把「已退出未收尸」如实报告为非运行。
