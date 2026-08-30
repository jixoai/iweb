// 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2；two-tier-runtime-trust
//   2026-08-30 去 Podman 修订）：supervisor executor 真实副作用段的集成测试——prepare 的
//   spec 解析/监听索引注记、start 经 relay handoff 复核 + FD 注入 launcher 启动、drain
//   优雅停/强杀时序、stop 清理、readiness 探测采纳与 epoch 计数入口；失败路径全部
//   fail-closed 回 journal（rejected ack 或 received-incomplete）。
// 正交意图：executor 侧以 runtime/relay 桩验证调用序列与失败回滚；runtime 端口侧以
//   真实子进程（伪 wasmd 脚本 + /bin/sh launcher）验证进程口径契约（pidfile、SIGTERM→
//   预算→SIGKILL、立即死亡检测）。判定语义复用 contracts/snapshot-fd 纯函数，不在测试
//   里造第二套比对。
import { describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import {
	createExecutionRpcHandler,
	WasmExecutionJournalStore,
	type ExecutionRpcHandler,
} from "../supervisor/wasm-control.ts";
import {
	createWasmSupervisorExecutor,
	probeWasmExecutionReadiness,
	sampleWasmEngineMetrics,
	WASM_EXECUTION_POLICY_UNAVAILABLE,
	WASM_SPAWN_UNCONFIGURED,
	WasmRetirementLedger,
	type WasmAcceptedExecutionRecord,
	type WasmSupervisorExecutor,
} from "../supervisor/wasm-executor.ts";
import {
	createProcessWasmSandboxRuntime,
	RuntimeFailure,
	WASM_EXECUTION_SPAWN_FAILED,
	WASM_SPAWN_RELAY_UNAVAILABLE,
	type WasmProcessRuntimeIO,
	type WasmSandboxRuntime,
	type WasmStopOutcome,
} from "../supervisor/wasm-runtime.ts";
import {
	SnapshotFdRelayError,
	type SnapshotFdRelayClient,
	type SnapshotFdRelayHandoffView,
	type SnapshotFdRelayLookup,
} from "../supervisor/snapshot-fd-relay-client.ts";
import { systemStateStoreIO } from "../supervisor/wasm-shared.ts";
import { computeSnapshotFdDigest, validateConfiguredSnapshotSocketPath } from "../supervisor/snapshot-fd.ts";
import { buildWasmdLauncherScript, type WasmSandboxSpawnSpec } from "../supervisor/wasm-spawn.ts";
import {
	computeExecutionCommandDigest,
	exampleExecutionCommand,
	exampleNormalizedWasmManifestV1,
	type ExecutionCommand,
	type RuntimeBindingIdentityV1,
} from "../packages/contracts/wasm-execution.ts";
import { WASM_HOST_ABI_LITERAL } from "../packages/contracts/wasm-package.ts";
import { sealWasmHostServicePolicyV2, WASM_EMPTY_HOST_SERVICE_POLICY_V2, WASM_HOST_POLICY_DIGEST_MISMATCH, type WasmHostServicePolicyV2 } from "../packages/contracts/wasm-host-policy.ts";
import { buildWasmSandboxSpec } from "../supervisor/wasm-spawn.ts";

const REQUEST_ID = "018f1e2c-3d4b-7c6d-8e9f-001122334455";
const FIXED_NOW = "2026-08-26T00:00:00.000Z";

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-spawn-"));
}

let commandCounter = 0;

function uuidOf(counter: number): string {
	const sequence = counter.toString(16).padStart(3, "0").slice(-3);
	return "018f1e2c-3d4b-7" + sequence + "-9e01-00112233445" + (counter % 16).toString(16);
}

// 快照字节 → 命令/视图共享的 valuesDigest（域前缀单次 SHA-256；与 snapshot-fd.ts 同源）。
const SECRET_FD_BYTES = Buffer.from('{"applicationId":"vector","values":{}}', "utf8");
const SECRET_VALUES_DIGEST = computeSnapshotFdDigest("secret", SECRET_FD_BYTES);
const CONFIG_FD_BYTES = Buffer.from('{"applicationId":"vector","config":{}}', "utf8");
const CONFIG_VALUES_DIGEST = computeSnapshotFdDigest("config", CONFIG_FD_BYTES);

// logging-only 的 sealed policy（契约要求至少一个服务成员；reserveBytes 1 <
// example manifest memoryBytes 2，满足 design §3 资源门）。
const MINIMAL_POLICY_PAYLOAD = {
	schemaVersion: 2,
	matrixRevision: 2,
	hostAbi: "iweb-wasmd-abi@1.1.0",
	hostServices: {
		kv: null,
		sql: null,
		logging: {
			profile: "bounded-memory-ring-v1",
			limits: { maxEventBytes: 256, ringMaxEvents: 8, ringMaxBytes: 2048 },
			consistency: "append-only-drop-on-full-v1",
			durability: "no-durable-claim-v1",
			retention: "runtime-lifecycle-only-v1",
		},
	},
	storageBytes: 4,
	reserveBytes: 1,
	dataDirectoryProfile: "per-app-sqlite-v1",
	durabilityProfile: "sqlite-full-fsync-v1",
} as const;
const MINIMAL_POLICY = sealWasmHostServicePolicyV2(MINIMAL_POLICY_PAYLOAD);
if (!MINIMAL_POLICY.ok) throw new Error("fixture error: minimal policy must seal");

/** hostServicePolicySource 桩（wasm-serve 文件来源的测试替身；manifest = 契约 example）。 */
function stubHostServicePolicySource(): (input: { applicationId: string; versionId: string; packageDigest: string; capabilityRecordHash: string }) => Promise<{ policy: WasmHostServicePolicyV2; normalizedPolicy: ReturnType<typeof exampleNormalizedWasmManifestV1> }> | null {
	return async () => ({ policy: MINIMAL_POLICY.value, normalizedPolicy: exampleNormalizedWasmManifestV1() });
}

/**
 * policyless 来源桩（wasm-serve 文件来源 policyless 半边的测试替身）：无 policy 文件的
 * 准入行按 V1 versionDigest 绑定解析为零值策略（policyDigest ""；simplify 复审 P0）。
 */
function policylessHostServicePolicySource(): (input: { applicationId: string; versionId: string; packageDigest: string; capabilityRecordHash: string }) => Promise<{ policy: WasmHostServicePolicyV2; normalizedPolicy: ReturnType<typeof exampleNormalizedWasmManifestV1> }> {
	return async () => ({ policy: WASM_EMPTY_HOST_SERVICE_POLICY_V2, normalizedPolicy: exampleNormalizedWasmManifestV1() });
}

/** admission 事实形 binding（retiring 记录的持久面；ABI 1.0.0）。 */
function factBindingOf(source: ExecutionCommand): RuntimeBindingIdentityV1 {
	return { ...source.runtimeBinding, hostABI: WASM_HOST_ABI_LITERAL };
}

// 契约 example 的浅层副本（纯数据 fixture；逐次展开避免用例间共享可变引用）。
function exampleBaseCommand(): ExecutionCommand {
	const example = exampleExecutionCommand();
	return { ...example, identity: { ...example.identity }, runtimeBinding: { ...example.runtimeBinding } };
}

function command(overrides: Partial<ExecutionCommand> = {}): ExecutionCommand {
	commandCounter += 1;
	return {
		...exampleBaseCommand(),
		commandId: uuidOf(commandCounter),
		expectedJournalRevision: 0,
		secretValuesDigest: SECRET_VALUES_DIGEST,
		secretSnapshotRef: "5".repeat(64),
		hostServicePolicyDigest: MINIMAL_POLICY.value.policyDigest,
		// 默认 secret-only（configRevision 0 ⇔ ref/digest null 的契约耦合）；config 场景显式覆盖。
		configRevision: 0,
		configSnapshotRef: null,
		configValuesDigest: null,
		...overrides,
	};
}

function handoffView(command: ExecutionCommand, kind: "secret" | "config", fdBytes: Buffer, valuesDigest: string): SnapshotFdRelayHandoffView {
	return {
		commandId: command.commandId,
		kind,
		commandDigest: computeExecutionCommandDigest(command),
		ref: kind === "secret" ? command.secretSnapshotRef : command.configSnapshotRef ?? "7".repeat(64),
		applicationId: "vector",
		versionId: command.identity.versionId,
		preparationGeneration: command.identity.preparationGeneration,
		revision: kind === "secret" ? command.secretRevision : command.configRevision,
		valuesDigest,
		fdDigest: valuesDigest,
		expiresAt: "2100-01-01T00:00:00Z",
		fdBytesBase64: fdBytes.toString("base64"),
		descriptorRegularFile: true,
		descriptorReadOnly: true,
	};
}

// --- 桩：relay 客户端与 runtime 端口（调用序列记录 + 可配置失败） ---------------------------

class RelayStub implements Pick<SnapshotFdRelayClient, "lookup" | "spawn" | "discard"> {
	readonly lookups: string[] = [];
	readonly spawns: { readonly commandId: string; readonly argv: readonly string[] }[] = [];
	readonly discards: string[] = [];
	handoffs = new Map<string, SnapshotFdRelayLookup>();
	spawnExitCode = 0;
	spawnThrows: Error | null = null;
	lookupThrows: SnapshotFdRelayError | null = null;

	async lookup(commandId: string): Promise<SnapshotFdRelayLookup> {
		this.lookups.push(commandId);
		if (this.lookupThrows !== null) throw this.lookupThrows;
		return this.handoffs.get(commandId) ?? { secret: null, config: null };
	}

	async spawn(commandId: string, argv: readonly string[]): Promise<{ ok: true; exitCode: number } | { ok: false; code: string; message: string }> {
		this.spawns.push({ commandId, argv: [...argv] });
		if (this.spawnThrows !== null) throw this.spawnThrows;
		if (this.spawnExitCode !== 0) return { ok: true, exitCode: this.spawnExitCode };
		return { ok: true, exitCode: 0 };
	}

	async discard(commandId: string): Promise<number> {
		this.discards.push(commandId);
		return 1;
	}
}

class RuntimeStub implements WasmSandboxRuntime {
	readonly specs: WasmSandboxSpawnSpec[] = [];
	readonly spawnCalls: { readonly commandId: string; readonly spec: WasmSandboxSpawnSpec }[] = [];
	readonly stopCalls: { readonly sandboxId: string; readonly budgetMs: number }[] = [];
	readonly removes: string[] = [];
	readonly runningChecks: string[] = [];
	running = true;
	spawnFailure: Error | null = null;
	stopOutcome: WasmStopOutcome = { result: "stopped" };
	stopFailure: Error | null = null;
	removeFailure: Error | null = null;

	async spawnExecution(commandId: string, spec: WasmSandboxSpawnSpec): Promise<void> {
		if (this.spawnFailure !== null) throw this.spawnFailure;
		this.spawnCalls.push({ commandId, spec });
	}

	async stopExecution(sandboxId: string, budgetMs: number): Promise<WasmStopOutcome> {
		if (this.stopFailure !== null) throw this.stopFailure;
		this.stopCalls.push({ sandboxId, budgetMs });
		return this.stopOutcome;
	}

	async removeSandbox(sandboxId: string): Promise<void> {
		if (this.removeFailure !== null) throw this.removeFailure;
		this.removes.push(sandboxId);
	}

	async isRunning(sandboxId: string): Promise<boolean> {
		this.runningChecks.push(sandboxId);
		return this.running;
	}
}

const SPAWN_OPTIONS = {
	stateDirectory: "/data/kernel/wasm-supervisor-test",
	wasmdBinaryPath: "/opt/iweb/wasmd/iweb-wasmd",
	gatewayAddress: "127.0.0.1:8081",
	capabilityRecordHostPath: "/data/kernel/wasm/node-capability.json",
	architecture: "linux/arm64" as const,
	pidDirectory: "/run/iweb-sandbox/wasmd",
};

interface World {
	readonly directory: string;
	readonly journal: WasmExecutionJournalStore;
	readonly executor: WasmSupervisorExecutor;
	readonly runtime: RuntimeStub;
	readonly relay: RelayStub;
	readonly handler: ExecutionRpcHandler;
	deliver(body: Parameters<ExecutionRpcHandler["handle"]>[0]["body"]): Promise<
		| { readonly ok: true; readonly result?: string; readonly failureCode?: string | null }
		| { readonly ok: false; readonly status: number; readonly code: string }
	>;
}

function world(options: { readonly policy?: boolean | "policyless"; readonly spawnOptions?: boolean; readonly now?: () => string } = {}): World {
	const directory = tempDirectory();
	const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
	const runtime = new RuntimeStub();
	const relay = new RelayStub();
	const executor = createWasmSupervisorExecutor({
		journal,
		runtime,
		relay,
		hostServicePolicySource:
			options.policy === false ? undefined : options.policy === "policyless" ? policylessHostServicePolicySource() : (stubHostServicePolicySource() ?? undefined),
		spawnOptions: options.spawnOptions === false ? undefined : SPAWN_OPTIONS,
		now: options.now ?? (() => FIXED_NOW),
	});
	const handler = createExecutionRpcHandler({ journal, executor, now: options.now ?? (() => FIXED_NOW) });
	const deliver = async (body: Parameters<ExecutionRpcHandler["handle"]>[0]["body"]) => {
		const result = await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body });
		if (!result.ok) return { ok: false as const, status: result.status, code: result.code };
		if (result.body.kind === "acknowledgement") {
			const ack = result.body.acknowledgement;
				return { ok: true as const, result: ack.result, failureCode: ack.failureCode, drainReceipt: null };
		}
		return { ok: true as const };
	};
	return { directory, journal, executor, runtime, relay, handler, deliver };
}

async function preparedStarted(worldRef: World, overrides: Partial<ExecutionCommand> = {}): Promise<ExecutionCommand> {
	const prepare = command({ operation: "prepare", identity: { sandboxId: "sbx-vector", versionId: exampleBaseCommand().identity.versionId, preparationGeneration: 1, executionGeneration: 1 }, ...overrides });
	await worldRef.deliver({ kind: "command", command: prepare });
	const start = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 2, ...overrides });
	worldRef.relay.handoffs.set(start.commandId, { secret: handoffView(start, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST), config: null });
	await worldRef.deliver({ kind: "command", command: start });
	return start;
}

describe("wasm executor real side effects: prepare (process-era)", () => {
	test("prepare resolves the policy, allocates a listen index, and records it without spawning", async () => {
		const worldRef = world();
		const outcome = await worldRef.deliver({ kind: "command", command: command({ operation: "prepare" }) });
		expect(outcome.ok).toBe(true);
		if (outcome.ok) expect(outcome.result).toBe("applied");
		// 进程口径：prepare 无进程副作用——只解析/校验 spawn spec 并注记监听索引。
		expect(worldRef.runtime.spawnCalls).toHaveLength(0);
		const record = worldRef.executor.fence.current("sbx-vector");
		expect(record?.listenIndex).toBe(0);
		expect(record?.substate).toBe("prepared");
	});

	test("two sandboxes get distinct deterministic listen indexes", async () => {
		const worldRef = world();
		await worldRef.deliver({ kind: "command", command: command({ operation: "prepare", identity: { ...exampleBaseCommand().identity, sandboxId: "sbx-alpha" } }) });
		await worldRef.deliver({ kind: "command", command: command({ operation: "prepare", identity: { ...exampleBaseCommand().identity, sandboxId: "sbx-beta" }, expectedJournalRevision: 2 }) });
		const alpha = worldRef.executor.fence.current("sbx-alpha");
		const beta = worldRef.executor.fence.current("sbx-beta");
		expect([alpha?.listenIndex, beta?.listenIndex]).toEqual([0, 1]);
	});

	test("missing policy source and missing spawn options fail closed with named codes", async () => {
		const noPolicy = world({ policy: false });
		const rejectedPolicy = await noPolicy.deliver({ kind: "command", command: command({ operation: "prepare" }) });
		expect(rejectedPolicy.ok && rejectedPolicy.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
		const noOptions = world({ spawnOptions: false });
		const rejectedOptions = await noOptions.deliver({ kind: "command", command: command({ operation: "prepare" }) });
		expect(rejectedOptions.ok && rejectedOptions.failureCode).toBe(WASM_SPAWN_UNCONFIGURED);
	});

	test("a spawn spec assembly rejection is recorded as a rejected acknowledgement", async () => {
		const worldRef = world();
		// 命令 pin 与来源策略不一致 → prepare 以 MISMATCH 终结（回 journal 终态）。
		const prepare = command({ operation: "prepare", hostServicePolicyDigest: "f".repeat(64) });
		const outcome = await worldRef.deliver({ kind: "command", command: prepare });
		expect(outcome.ok && outcome.failureCode).toBe(WASM_HOST_POLICY_DIGEST_MISMATCH);
		const found = worldRef.journal.find(prepare.commandId);
		expect(found.completed?.acknowledgement.result).toBe("rejected");
	});
});

describe("wasm executor empty policy pin: zero-value policy closes the spawn chain (simplify P0)", () => {
	test("prepare/start with an empty policyDigest pin spawn through the zero-value policy", async () => {
		const worldRef = world({ policy: "policyless" });
		const start = await preparedStarted(worldRef, { hostServicePolicyDigest: "" });
		expect(worldRef.runtime.spawnCalls).toHaveLength(1);
		expect(worldRef.runtime.spawnCalls[0]?.commandId).toBe(start.commandId);
		const argv = worldRef.runtime.spawnCalls[0]?.spec.argv;
		expect(argv).toHaveLength(11);
		const context = JSON.parse(argv[10] ?? "{}") as { hostServicePolicy: { policyDigest: string; hostServices: Record<string, null> } };
		expect(context.hostServicePolicy.policyDigest).toBe("");
		expect(context.hostServicePolicy.hostServices).toEqual({ kv: null, sql: null, logging: null });
	});

	test("an empty pin against a sealed policy resolution is a digest mismatch (fail-closed)", async () => {
		// 默认来源解析出 sealed MINIMAL_POLICY：空串 pin 与磁盘/来源事实不一致 → MISMATCH，
		// 绝不给空串 pin 携带 sealed 策略字节。
		const worldRef = world();
		const rejected = await worldRef.deliver({ kind: "command", command: command({ operation: "prepare", hostServicePolicyDigest: "" }) });
		expect(rejected.ok && rejected.failureCode).toBe(WASM_HOST_POLICY_DIGEST_MISMATCH);
		expect(worldRef.runtime.spawnCalls).toHaveLength(0);
	});

	test("without any policy source the empty pin still fails closed (manifest proof missing)", async () => {
		const worldRef = world({ policy: false });
		const rejected = await worldRef.deliver({ kind: "command", command: command({ operation: "prepare", hostServicePolicyDigest: "" }) });
		expect(rejected.ok && rejected.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
	});
});

describe("wasm executor real side effects: start via relay FD handoff", () => {
	test("start correlates both handoffs and spawns through the runtime port", async () => {
		const worldRef = world();
		const start = await preparedStarted(worldRef);
		expect(worldRef.relay.lookups).toEqual([start.commandId]);
		expect(worldRef.runtime.spawnCalls).toHaveLength(1);
		expect(worldRef.runtime.spawnCalls[0]?.commandId).toBe(start.commandId);
		const spec = worldRef.runtime.spawnCalls[0]?.spec;
		// spawn spec 携带进程口径字段：本地二进制路径 + pidfile + 回环监听。
		expect(spec?.wasmdBinaryPath).toBe(SPAWN_OPTIONS.wasmdBinaryPath);
		expect(spec?.pidFilePath).toBe(SPAWN_OPTIONS.pidDirectory + "/sbx-vector.pid");
		expect(spec?.listenAddress).toBe("127.200.0.3:8787");
		const record = worldRef.executor.fence.current("sbx-vector");
		expect(record?.substate).toBe("running");
		expect(record?.spawnCommandId).toBe(start.commandId);
		expect(record?.listenIndex).toBe(0);
		expect(record?.readiness).toBe("unprobed");
	});

	test("a config handoff is required exactly when configRevision is non-zero", async () => {
		const worldRef = world();
		// config 三元组耦合是 fence 字段：prepare 与 start 携带同一 config 快照绑定。
		const configFields = { configRevision: 2, configSnapshotRef: "7".repeat(64), configValuesDigest: CONFIG_VALUES_DIGEST } as const;
		const prepare = command({ operation: "prepare", identity: { ...exampleBaseCommand().identity, preparationGeneration: 1, executionGeneration: 1 }, ...configFields });
		await worldRef.deliver({ kind: "command", command: prepare });
		const start = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 2, ...configFields });
		// secret 命中但 config 缺失 → SNAPSHOT_HANDOFF_MISSING（fail-closed，不 spawn）。
		worldRef.relay.handoffs.set(start.commandId, { secret: handoffView(start, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST), config: null });
		const missing = await worldRef.deliver({ kind: "command", command: start });
		expect(missing.ok && missing.failureCode).toBe("SNAPSHOT_HANDOFF_MISSING");
		expect(worldRef.runtime.spawnCalls).toHaveLength(0);
		// secret + config 均命中 → spawn。
		const retry = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 4, ...configFields });
		worldRef.relay.handoffs.set(retry.commandId, { secret: handoffView(retry, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST), config: handoffView(retry, "config", CONFIG_FD_BYTES, CONFIG_VALUES_DIGEST) });
		const ok = await worldRef.deliver({ kind: "command", command: retry });
		expect(ok.ok && ok.result).toBe("applied");
		expect(worldRef.runtime.spawnCalls).toHaveLength(1);
	});

	test("a handoff whose bytes do not match the values digest is rejected", async () => {
		const worldRef = world();
		const prepare = command({ operation: "prepare" });
		await worldRef.deliver({ kind: "command", command: prepare });
		const start = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 2 });
		const forged = handoffView(start, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST);
		const mismatched = { ...forged, fdBytesBase64: Buffer.from("other-bytes").toString("base64") };
		worldRef.relay.handoffs.set(start.commandId, { secret: mismatched, config: null });
		const outcome = await worldRef.deliver({ kind: "command", command: start });
		expect(outcome.ok && outcome.failureCode).toBe("SNAPSHOT_VALUES_DIGEST_MISMATCH");
		expect(worldRef.runtime.spawnCalls).toHaveLength(0);
	});

	test("a handoff naming another command digest is a conflict", async () => {
		const worldRef = world();
		const prepare = command({ operation: "prepare" });
		await worldRef.deliver({ kind: "command", command: prepare });
		const start = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 2 });
		const foreign = { ...handoffView(start, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST), commandId: uuidOf(991), commandDigest: "0".repeat(64) };
		worldRef.relay.handoffs.set(start.commandId, { secret: foreign, config: null });
		const outcome = await worldRef.deliver({ kind: "command", command: start });
		expect(outcome.ok && outcome.failureCode).toBe("SNAPSHOT_HANDOFF_ID_CONFLICT");
	});

	test("relay transport failure and a failed launcher exit are deterministic rejections", async () => {
		const worldRef = world();
		const prepare = command({ operation: "prepare" });
		await worldRef.deliver({ kind: "command", command: prepare });
		const startA = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 2 });
		worldRef.relay.lookupThrows = new SnapshotFdRelayError("SNAPSHOT_SPAWN_FAILED", "control socket unreachable");
		const transport = await worldRef.deliver({ kind: "command", command: startA });
		expect(transport.ok && transport.failureCode).toBe(WASM_SPAWN_RELAY_UNAVAILABLE);
		worldRef.relay.lookupThrows = null;
		const startB = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 4 });
		worldRef.relay.handoffs.set(startB.commandId, { secret: handoffView(startB, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST), config: null });
		worldRef.runtime.spawnFailure = new RuntimeFailure("infrastructure", WASM_EXECUTION_SPAWN_FAILED + ": the wasmd launcher exited with 7");
		const exited = await worldRef.deliver({ kind: "command", command: startB });
		expect(exited.ok && exited.failureCode).toBe(WASM_EXECUTION_SPAWN_FAILED);
		expect(worldRef.journal.find(startB.commandId)?.completed?.acknowledgement.failureCode).toBe(WASM_EXECUTION_SPAWN_FAILED);
	});

	test("an optional readiness probe records adoption without flipping the command result", async () => {
		const directory = tempDirectory();
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
		const runtime = new RuntimeStub();
		const relay = new RelayStub();
		const healthOf = (cmd: ExecutionCommand) => ({
			schemaVersion: 2 as const,
			ok: true,
			sandboxId: cmd.identity.sandboxId,
			versionId: cmd.identity.versionId,
			packageDigest: cmd.packageDigest,
			runtimeBinding: cmd.runtimeBinding,
			hostServicePolicyDigest: cmd.hostServicePolicyDigest,
			capabilityRecordRevision: cmd.capabilityRecordRevision,
			capabilityRecordHash: cmd.capabilityRecordHash,
			secretRevision: cmd.secretRevision,
			secretValuesDigest: cmd.secretValuesDigest,
			configRevision: cmd.configRevision,
			configSnapshotRef: cmd.configSnapshotRef,
			configValuesDigest: cmd.configValuesDigest,
			preparationGeneration: cmd.identity.preparationGeneration,
			executionGeneration: cmd.identity.executionGeneration,
		});
		let startCommand: ExecutionCommand | null = null;
		const executor = createWasmSupervisorExecutor({
			journal,
			runtime,
			relay,
			hostServicePolicySource: stubHostServicePolicySource() ?? undefined,
			spawnOptions: SPAWN_OPTIONS,
			now: () => FIXED_NOW,
			readinessProbe: {
				fetch: async () => {
					if (startCommand === null) throw new Error("no start command captured");
					return { status: 200, body: JSON.stringify(healthOf(startCommand)) };
				},
				maxAttempts: 1,
				intervalMs: 0,
			},
		});
		const handler = createExecutionRpcHandler({ journal, executor, now: () => FIXED_NOW });
		const prepare = command({ operation: "prepare" });
		await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: prepare } });
		startCommand = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 2 });
		relay.handoffs.set(startCommand.commandId, { secret: handoffView(startCommand, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST), config: null });
		const outcome = await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: startCommand } });
		expect(outcome.ok).toBe(true);
		const record = executor.fence.current("sbx-vector");
		expect(record?.readiness).toBe("adopted");
		// stale 信号（旧 execution generation）→ stale 采纳注记。
		const staleProbe = await probeWasmExecutionReadiness(executor.fence, "sbx-vector", "http://127.0.0.1:1", {
			fetch: async () => ({ status: 200, body: JSON.stringify({ ...healthOf(startCommand), executionGeneration: 2 }) }),
			maxAttempts: 1,
			intervalMs: 0,
		});
		expect(staleProbe).toBe("stale");
	});
});

describe("wasm executor real side effects: drain and stop", () => {
	test("graceful stop within the deadline yields a drained receipt and keeps retiring", async () => {
		const worldRef = world();
		const start = await preparedStarted(worldRef);
		const drain = command({ operation: "drain", identity: start.identity, expectedJournalRevision: 4 });
		// Kernel route-CAS 对面的 retiring 台账（wasm-executor WasmRetirementLedger）。
		// deadline 在固定时钟之后：优雅停预算为正。
		const retirements = new WasmRetirementLedger();
		expect(retirements.record({
			drainCommandId: drain.commandId,
			applicationId: "vector",
			execution: drain.identity,
			packageDigest: drain.packageDigest,
			runtimeBinding: factBindingOf(drain),
			routeGeneration: 3,
			deadlineAtEpochMillis: Date.parse(FIXED_NOW) + 5_000,
			flipAtEpochMillis: Date.parse(FIXED_NOW),
			retired: false,
			acceptedReceiptDigest: null,
		}).ok).toBe(true);
		// 以带台账的执行器重组通道（同一 journal）。
		const drainedExecutor = createWasmSupervisorExecutor({
			journal: new WasmExecutionJournalStore(systemStateStoreIO, worldRef.directory),
			runtime: worldRef.runtime,
			relay: worldRef.relay,
			hostServicePolicySource: stubHostServicePolicySource() ?? undefined,
			spawnOptions: SPAWN_OPTIONS,
			retirements,
			now: () => FIXED_NOW,
		});
		const drainedHandler = createExecutionRpcHandler({ journal: new WasmExecutionJournalStore(systemStateStoreIO, worldRef.directory), executor: drainedExecutor, now: () => FIXED_NOW });
		const result = await drainedHandler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: drain } });
		expect(result.ok).toBe(true);
		if (result.ok && result.body.kind === "acknowledgement") {
			expect(result.body.acknowledgement.result).toBe("applied");
			expect(result.body.acknowledgement.drainReceiptDigest).not.toBeNull();
		}
		// 停止调用序列：恰一次，预算 = deadline - now（5s）。
		expect(worldRef.runtime.stopCalls).toHaveLength(1);
		expect(worldRef.runtime.stopCalls[0]?.sandboxId).toBe("sbx-vector");
		expect(worldRef.runtime.stopCalls[0]?.budgetMs).toBe(5_000);
		// 释放触发 spawn 的代持 FD。
		expect(worldRef.relay.discards).toEqual([start.commandId]);
		expect(drainedExecutor.fence.current("sbx-vector")?.substate).toBe("retiring");
	});

	test("a forced kill after the graceful window yields a forced-kill receipt", async () => {
		const worldRef = world();
		const start = await preparedStarted(worldRef);
		worldRef.runtime.stopOutcome = { result: "forced-kill" };
		const retirements = new WasmRetirementLedger();
		const drain = command({ operation: "drain", identity: start.identity, expectedJournalRevision: 4 });
		expect(retirements.record({
			drainCommandId: drain.commandId,
			applicationId: "vector",
			execution: drain.identity,
			packageDigest: drain.packageDigest,
			runtimeBinding: factBindingOf(drain),
			routeGeneration: 3,
			// deadline 已过（固定时钟）：预算 0 → 立即强杀是合法路径（forcedKillAt >= deadline）。
			deadlineAtEpochMillis: Date.parse(FIXED_NOW) - 1_000,
			flipAtEpochMillis: Date.parse(FIXED_NOW) - 2_000,
			retired: false,
			acceptedReceiptDigest: null,
		}).ok).toBe(true);
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, worldRef.directory);
		const drainedExecutor = createWasmSupervisorExecutor({
			journal,
			runtime: worldRef.runtime,
			relay: worldRef.relay,
			hostServicePolicySource: stubHostServicePolicySource() ?? undefined,
			spawnOptions: SPAWN_OPTIONS,
			retirements,
			now: () => FIXED_NOW,
		});
		const drainedHandler = createExecutionRpcHandler({ journal, executor: drainedExecutor, now: () => FIXED_NOW });
		const result = await drainedHandler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: drain } });
		expect(result.ok).toBe(true);
		if (result.ok && result.body.kind === "acknowledgement") {
			expect(result.body.acknowledgement.result).toBe("applied");
		}
		expect(drainedExecutor.fence.current("sbx-vector")?.substate).toBe("stopped");
		// forced-kill receipt 草稿经 journal ack 采纳（drainReceiptDigest 非空即 receipt 校验通过）。
		const completed = journal.find(drain.commandId)?.completed;
		expect(completed?.acknowledgement.drainReceiptDigest).not.toBeNull();
	});

	test("stop removes the sandbox and releases the held descriptors", async () => {
		const worldRef = world();
		const start = await preparedStarted(worldRef);
		const stop = command({ operation: "stop", identity: start.identity, expectedJournalRevision: 4 });
		const outcome = await worldRef.deliver({ kind: "command", command: stop });
		expect(outcome.ok && outcome.result).toBe("applied");
		expect(worldRef.runtime.removes).toEqual(["sbx-vector"]);
		expect(worldRef.relay.discards).toEqual([start.commandId]);
		expect(worldRef.executor.fence.current("sbx-vector")?.substate).toBe("stopped");
	});

	test("epoch timeout events feed the engine metrics counter source", async () => {
		const worldRef = world();
		const start = await preparedStarted(worldRef);
		const stop = command({ operation: "stop", identity: start.identity, expectedJournalRevision: 4 });
		await worldRef.deliver({ kind: "command", command: stop });
		const identity = start.identity;
		expect(worldRef.executor.noteEpochTimeout(identity)?.epochTimeoutsCumulative).toBe(1);
		expect(worldRef.executor.noteEpochTimeout(identity)?.epochTimeoutsCumulative).toBe(2);
		// stopped 状态的可证明零/计数经由 executorInternalEngineCounterSource 进入 metrics wire。
		const sample = sampleWasmEngineMetrics(worldRef.executor.fence, "sbx-vector", { now: () => FIXED_NOW });
		expect(sample?.availability).toBe("available");
		expect(sample?.engine?.epochTimeoutsCumulative).toBe(2);
		expect(sample?.engine?.instancesLiveInstant).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// 进程口径 runtime 端口：伪 wasmd 脚本 + relay 执行桩（真实子进程、真实信号、真实 pidfile）
// ---------------------------------------------------------------------------

/** relay spawn 桩：同步执行 launcher（/bin/sh -c <script>；FD 注入由真实 relay 的 rust 测试覆盖）。 */
class ExecutingRelayStub implements Pick<SnapshotFdRelayClient, "spawn"> {
	readonly scripts: string[] = [];
	spawnExitCode = 0;
	async spawn(commandId: string, argv: readonly string[]): Promise<{ ok: true; exitCode: number } | { ok: false; code: string; message: string }> {
		void commandId;
		if (argv[0] !== "-c" || typeof argv[1] !== "string") return { ok: false, code: "SNAPSHOT_SPAWN_FAILED", message: "unexpected argv shape" };
		this.scripts.push(argv[1]);
		if (this.spawnExitCode !== 0) return { ok: true, exitCode: this.spawnExitCode };
		// stdio ignore：后台作业继承描述符，spawnSync 的 pipe 会等全部持有者关闭
		// （长驻伪 wasmd 会把同步调用挂死）——真实 relay 的注入型 exec 无此耦合。
		const result = spawnSync("/bin/sh", ["-c", argv[1]], { encoding: "utf8", stdio: ["ignore", "ignore", "ignore"] });
		return { ok: true, exitCode: result.status ?? 1 };
	}
}

/** 伪 wasmd：可执行脚本（忽略 argv；长驻——真实子进程/信号/pidfile 的载体）。 */
function fakeWasmd(directory: string): string {
	const path = join(directory, "fake-wasmd");
	writeFileSync(path, "#!/bin/sh\nexec sleep 300\n", { mode: 0o755 });
	chmodSync(path, 0o755);
	return path;
}

function specFixture(wasmdBinaryPath: string, pidDirectory: string): WasmSandboxSpawnSpec {
	const cmd = command({ operation: "start" });
	const built = buildWasmSandboxSpec({ command: cmd, policy: exampleNormalizedWasmManifestV1(), hostServicePolicy: MINIMAL_POLICY.value }, { ...SPAWN_OPTIONS, wasmdBinaryPath, pidDirectory, listenIndex: 0 });
	if (!built.ok) throw new Error("fixture spec failed to build");
	return built.value;
}

describe("process wasm runtime port: launcher, pidfile, and signal lifecycle", () => {
	test("spawnExecution runs the launcher and proves the process alive via the pidfile", async () => {
		const directory = tempDirectory();
		const pidDirectory = join(directory, "pids");
		const relay = new ExecutingRelayStub();
		const runtime = createProcessWasmSandboxRuntime({ relay, pidDirectory, settleMs: 50, pollIntervalMs: 10 });
		const spec = specFixture(fakeWasmd(directory), pidDirectory);
		try {
			await runtime.spawnExecution(spec.sandboxId + "-cmd", spec);
			// launcher 恰好一次，载荷是 sh -c 形态的 buildWasmdLauncherScript 产物。
			expect(relay.scripts).toHaveLength(1);
			expect(relay.scripts[0]).toBe(buildWasmdLauncherScript(spec));
			// pidfile 存在且进程活着（真实子进程）。
			expect(await runtime.isRunning("sbx-vector")).toBe(true);
		} finally {
			await runtime.removeSandbox("sbx-vector");
		}
		expect(await runtime.isRunning("sbx-vector")).toBe(false);
	});

	test("stopExecution maps the graceful budget to SIGTERM and reports stopped", async () => {
		const directory = tempDirectory();
		const pidDirectory = join(directory, "pids");
		const relay = new ExecutingRelayStub();
		const runtime = createProcessWasmSandboxRuntime({ relay, pidDirectory, settleMs: 50, pollIntervalMs: 10 });
		const spec = specFixture(fakeWasmd(directory), pidDirectory);
		await runtime.spawnExecution("cmd-graceful", spec);
		expect(await runtime.isRunning("sbx-vector")).toBe(true);
		const outcome = await runtime.stopExecution("sbx-vector", 2_000);
		expect(outcome.result).toBe("stopped");
		expect(await runtime.isRunning("sbx-vector")).toBe(false);
	});

	test("a process surviving SIGTERM past the budget is force-killed and reported", async () => {
		// 信号序列的确定性契约：SIGTERM 后预算窗口内仍存活 → SIGKILL → forced-kill。
		// （以 IO 桩固定「TERM 无效」——真实孤儿后台作业在 macOS 上无视 trap 被 TERM
		// 杀死，平台语义不可移植；真实信号路径由 resident/graceful 用例覆盖。）
		const signals: string[] = [];
		const relay = new ExecutingRelayStub();
		let killCount = 0;
		const io: WasmProcessRuntimeIO = {
			readFile: () => "424242\n",
			sleep: async () => {},
			kill: (_pid, signal) => {
				signals.push(String(signal));
				killCount += 1;
				// SIGKILL（第二次信号）后才放行 isAlive=false。
				return true;
			},
			isAlive: () => killCount < 2,
			deleteFile: () => {},
		};
		const runtime = createProcessWasmSandboxRuntime({ relay, pidDirectory: "/tmp/iweb-wasm-pids-unused", io, settleMs: 0, pollIntervalMs: 1, killGraceMs: 1_000 });
		const spec = specFixture("/opt/iweb/wasmd/iweb-wasmd", "/tmp/iweb-wasm-pids-unused");
		await runtime.spawnExecution("cmd-immune", spec);
		const outcome = await runtime.stopExecution("sbx-vector", 0);
		expect(outcome.result).toBe("forced-kill");
		expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
	});

	test("a wasmd that dies immediately is a deterministic spawn failure", async () => {
		// 启动活性确认的确定性契约：settle 窗口后进程不在 → SPAWN_FAILED（真实孤儿死亡
		// 的僵尸/reap 时序在 macOS 上不可移植，死亡事实以 IO 桩固定）。
		const relay = new ExecutingRelayStub();
		const io: WasmProcessRuntimeIO = {
			readFile: (path) => (path.endsWith("sbx-vector.pid") ? "424243\n" : null),
			sleep: async () => {},
			kill: () => true,
			isAlive: () => false,
			deleteFile: () => {},
		};
		const runtime = createProcessWasmSandboxRuntime({ relay, pidDirectory: "/run/iweb-sandbox/wasmd", io, settleMs: 0, pollIntervalMs: 1 });
		const spec = specFixture("/opt/iweb/wasmd/iweb-wasmd", "/run/iweb-sandbox/wasmd");
		let failure: unknown = null;
		try {
			await runtime.spawnExecution("cmd-dies", spec);
		} catch (error) {
			failure = error;
		}
		expect(failure).toBeInstanceOf(RuntimeFailure);
		expect((failure as RuntimeFailure).message).toContain(WASM_EXECUTION_SPAWN_FAILED);
	});

	test("a relay transport failure is WASM_SPAWN_RELAY_UNAVAILABLE", async () => {
		const relay = new ExecutingRelayStub();
		relay.spawnExitCode = 9; // 非 relay 错误路径：launcher 侧非零退出。
		const runtime = createProcessWasmSandboxRuntime({ relay, pidDirectory: "/tmp/iweb-wasm-pids-unused", settleMs: 10, pollIntervalMs: 10 });
		const spec = specFixture("/opt/iweb/wasmd/iweb-wasmd", "/tmp/iweb-wasm-pids-unused");
		let failure: unknown = null;
		try {
			await runtime.spawnExecution("cmd-relay", spec);
		} catch (error) {
			failure = error;
		}
		expect(failure).toBeInstanceOf(RuntimeFailure);
		expect((failure as RuntimeFailure).message).toContain(WASM_EXECUTION_SPAWN_FAILED);
	});

	test("stop without a pidfile is the idempotent stopped state", async () => {
		const relay = new ExecutingRelayStub();
		const runtime = createProcessWasmSandboxRuntime({ relay, pidDirectory: "/tmp/iweb-wasm-pids-absent", pollIntervalMs: 10 });
		const outcome = await runtime.stopExecution("sbx-never-started", 100);
		expect(outcome.result).toBe("stopped");
		expect(await runtime.isRunning("sbx-never-started")).toBe(false);
	});
});

describe("relay client wire constants stay aligned with the native relay", () => {
	test("the fixed snapshot socket path remains the spec literal", () => {
		// relay 二进制默认 --fd-socket 与 spec SnapshotFdTransportV1.socketPath 同字面量；
		// Node 侧仅经控制 socket 交互，但路径纪律由 snapshot-fd.ts 判定层保证。
		expect(validateConfiguredSnapshotSocketPath("/run/iweb-sandbox/snapshot-fd.sock")).toBeNull();
		expect(validateConfiguredSnapshotSocketPath("/tmp/other.sock")?.code).toBe("SNAPSHOT_SOCKET_PATH_REJECTED");
	});
});

// 桩类型完整性哨兵（避免 World 接口悄悄偏离 WasmAcceptedExecutionRecord 消费面）。
type _RecordProbe = WasmAcceptedExecutionRecord;
// WasmProcessRuntimeIO 消费面哨兵（进程口径端口的 IO 注入形状）。
type _IoProbe = WasmProcessRuntimeIO;
