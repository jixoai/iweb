// 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2）：supervisor executor 的真实
//   副作用端口——wasm 沙箱经 Podman 真实创建/启动/停止/清理；FD 承载的 spawn 由原生
//   relay（kernel-rs/snapshot-fd-relay）代持注入（--preserve-fds 的 FD 3/4 唯一进入路径）。
// 规范权威：spec "Wasmd has a fixed command and host-mediated network contract"（Supervisor
//   alone generates every argv element...）与 "Snapshot FD content is bound across Kernel,
//   supervisor, Podman, and wasmd"（三进程 FD 契约）。
// 正交意图：
//   1. 复用 runtime.ts 的 RuntimeExecutor 抽象与错误分类惯例（不修改 celld 侧
//      PodmanRuntime/OciRuntime——wasm 的 spec 类型与 FD 语义独立成端口，避免共用签名漂移）；
//   2. spawn 采用 `podman run -d <create argv 去掉 create>`：--preserve-fds 只在进程启动
//      的调用上生效（create+start 分离无法传递 FD；Linux 实机复核归 5.x，argv 组装仍是
//      wasm-spawn.ts 的 buildWasmdAppContainerCreateArgs 单一来源）；
//   3. drain 语义：先优雅停（podman stop -t <剩余秒>，超时由 podman SIGKILL）→ 探测仍在
//      运行即 forced-kill（podman kill）——上层以返回值区分 drained/forced-kill receipt；
//   4. 一切基础设施错误以 RuntimeFailure 分类抛出（executor 将确定性拒绝回 journal，
//      意外错误保持 received-incomplete 由 replay 恢复）。
import { appContainerName, buildNetworkCreateArgs, buildNetworkRemoveArgs } from "./sandbox-spec.ts";
import { buildWasmdAppContainerCreateArgs, type WasmSandboxSpawnSpec } from "./wasm-spawn.ts";
import { RuntimeFailure, type RuntimeExecutor } from "./runtime.ts";
import { SnapshotFdRelayClient, SnapshotFdRelayError } from "./snapshot-fd-relay-client.ts";

export const WASM_SPAWN_RELAY_UNAVAILABLE = "WASM_SPAWN_RELAY_UNAVAILABLE";
export const WASM_EXECUTION_SPAWN_FAILED = "WASM_EXECUTION_SPAWN_FAILED";

// 与 runtime.ts 同款错误文本分类（私有正则的本地对位；不改共享文件）。
const NO_SUCH_RESOURCE_PATTERN = /no such (pod|container|network)|not found|does not exist|unrecognized/i;
const ALREADY_EXISTS_PATTERN = /already exists/i;

export interface WasmStopOutcome {
	readonly result: "stopped" | "forced-kill";
}

/**
 * wasm 执行链的真实副作用端口（executor 的唯一副作用出口；测试以桩实现注入）。
 * 语义约定：
 * - ensureNetwork：prepare 的幂等前置（internal 网已存在且同名即成功）。
 * - spawnExecution：以 relay 代持的 FD 3/4 执行 `podman run -d`；非零退出是确定性失败。
 * - stopExecution：优雅停 → deadline 语义由调用方传入（毫秒预算）；返回是否被强杀。
 * - removeSandbox / isRunning：stop 命令与崩溃检测的清理/观测。
 */
export interface WasmSandboxRuntime {
	ensureNetwork(spec: WasmSandboxSpawnSpec): Promise<void>;
	spawnExecution(commandId: string, spec: WasmSandboxSpawnSpec): Promise<void>;
	stopExecution(sandboxId: string, budgetMs: number): Promise<WasmStopOutcome>;
	removeSandbox(sandboxId: string): Promise<void>;
	isRunning(sandboxId: string): Promise<boolean>;
}

export interface PodmanWasmRuntimeOptions {
	/** podman 调用执行器（复用 runtime.ts 抽象；生产为 execFileSync("podman", ...)）。 */
	readonly exec: RuntimeExecutor;
	/** 代持 FD 的原生 relay 控制客户端（spawn 的 FD 3/4 注入唯一来源；消费面仅 spawn——
	 * codex-final P0-2 放宽为结构端口，wasm-serve 装配与测试桩均可注入）。 */
	readonly relay: Pick<SnapshotFdRelayClient, "spawn">;
}

interface ExecFailure {
	readonly stdout: string;
	readonly stderr: string;
}

function wrapExecFailure(error: unknown): ExecFailure {
	const candidate = error as { readonly stdout?: unknown; readonly stderr?: unknown };
	return { stdout: typeof candidate.stdout === "string" ? candidate.stdout : "", stderr: typeof candidate.stderr === "string" ? candidate.stderr : "" };
}

function infrastructure(message: string): RuntimeFailure {
	return new RuntimeFailure("infrastructure", message);
}

export function createPodmanWasmSandboxRuntime(options: PodmanWasmRuntimeOptions): WasmSandboxRuntime {
	const exec = options.exec;
	const relay = options.relay;

	const run = (args: readonly string[]): string => exec(args);
	const runIgnoringMissing = (args: readonly string[], infrastructureMessage: string): void => {
		try {
			exec(args);
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (!NO_SUCH_RESOURCE_PATTERN.test(failure.stderr)) throw infrastructure(infrastructureMessage + ": " + failure.stderr.trim());
		}
	};

	return {
		ensureNetwork: async (spec) => {
			// wasm app 只挂 internal 网（网关容器接线属 5.x）；已存在即幂等成功。
			try {
				run(buildNetworkCreateArgs(spec.sandboxId, true, spec.subnetIndex));
			} catch (error) {
				const failure = wrapExecFailure(error);
				if (!ALREADY_EXISTS_PATTERN.test(failure.stderr)) throw infrastructure("podman network create failed for the wasm sandbox: " + failure.stderr.trim());
			}
		},

		spawnExecution: async (commandId, spec) => {
			// --preserve-fds 只在启动进程的调用上有效：create argv（wasm-spawn.ts 单一来源）
			// 的 "create" 头替换为 run -d，其余逐字节保留（FD 3/4 由 relay 注入）。
			const createArgs = buildWasmdAppContainerCreateArgs(spec);
			if (createArgs[0] !== "create") throw infrastructure("the wasm spawn argv does not start with create");
			const runArgs = ["run", "-d", ...createArgs.slice(1)];
			let spawn: Awaited<ReturnType<SnapshotFdRelayClient["spawn"]>>;
			try {
				spawn = await relay.spawn(commandId, runArgs);
			} catch (error) {
				if (error instanceof SnapshotFdRelayError) throw new RuntimeFailure("infrastructure", WASM_SPAWN_RELAY_UNAVAILABLE + ": " + error.message);
				throw error;
			}
			if (!spawn.ok) throw new RuntimeFailure("infrastructure", WASM_SPAWN_RELAY_UNAVAILABLE + ": " + spawn.code + ": " + spawn.message);
			if (spawn.exitCode !== 0) throw new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": podman exited with " + spawn.exitCode);
		},

		stopExecution: async (sandboxId, budgetMs) => {
			const seconds = Math.max(0, Math.ceil(budgetMs / 1000));
			runIgnoringMissing(["stop", "-t", String(seconds), appContainerName(sandboxId)], "podman stop failed for the wasm sandbox");
			const running = await inspectWasmContainerRunning(exec, sandboxId);
			if (!running) return { result: "stopped" };
			// stop 后仍在运行（异常路径）：显式强杀并复核。
			runIgnoringMissing(["kill", appContainerName(sandboxId)], "podman kill failed for the wasm sandbox");
			const afterKill = await inspectWasmContainerRunning(exec, sandboxId);
			if (afterKill) throw infrastructure("the wasm sandbox container survived a forced kill");
			return { result: "forced-kill" };
		},

		removeSandbox: async (sandboxId) => {
			runIgnoringMissing(["rm", "-f", appContainerName(sandboxId)], "podman rm failed for the wasm sandbox");
			runIgnoringMissing(buildNetworkRemoveArgs(sandboxId), "podman network rm failed for the wasm sandbox");
		},

		isRunning: async (sandboxId) => inspectWasmContainerRunning(exec, sandboxId),
	};
}

// inspect 语义的本地对位（runtime.ts inspectContainer 为私有；不改共享文件）。
function inspectWasmContainerRunning(exec: RuntimeExecutor, sandboxId: string): Promise<boolean> {
	return new Promise<boolean>((resolve, reject) => {
		try {
			const raw = exec(["inspect", "--format", "{{.State.Running}}", appContainerName(sandboxId)]);
			resolve(raw.trim() === "true");
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (NO_SUCH_RESOURCE_PATTERN.test(failure.stderr)) {
				resolve(false);
				return;
			}
			reject(infrastructure("podman inspect failed for the wasm sandbox"));
		}
	});
}
