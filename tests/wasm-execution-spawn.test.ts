// 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2）：supervisor executor 真实
//   副作用段的集成测试——prepare 建网、start 经 relay handoff 复核 + FD 注入 spawn、
//   drain 优雅停/强杀时序、stop 清理、readiness 探测采纳与 epoch 计数入口；失败路径全部
//   fail-closed 回 journal（rejected ack 或 received-incomplete）。
// 正交意图：以 runtime/relay 桩验证调用序列与失败回滚（真实 Linux podman/wasmd spawn
//   归 5.x 镜像批次——桩即本批次的可执行证明）；判定语义复用 contracts/snapshot-fd 纯函数，
//   不在测试里造第二套比对。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
	createPodmanWasmSandboxRuntime,
	WASM_EXECUTION_SPAWN_FAILED,
	WASM_SPAWN_RELAY_UNAVAILABLE,
	type WasmSandboxRuntime,
	type WasmStopOutcome,
} from "../supervisor/wasm-runtime.ts";
import {
	SnapshotFdRelayError,
	type SnapshotFdRelayClient,
	type SnapshotFdRelayHandoffView,
	type SnapshotFdRelayLookup,
} from "../supervisor/snapshot-fd-relay-client.ts";
import { RuntimeFailure } from "../supervisor/runtime.ts";
import { systemStateStoreIO } from "../supervisor/desired-state.ts";
import { computeSnapshotFdDigest, validateConfiguredSnapshotSocketPath } from "../supervisor/snapshot-fd.ts";
import { buildWasmdAppContainerCreateArgs, type WasmSandboxSpawnSpec } from "../supervisor/wasm-spawn.ts";
import {
	computeExecutionCommandDigestV1,
	exampleExecutionCommandV1,
	exampleNormalizedWasmManifestV1,
	type ExecutionCommandV1,
} from "../packages/contracts/wasm-execution.ts";
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

// 契约 example 的浅层副本（纯数据 fixture；逐次展开避免用例间共享可变引用）。
function exampleBaseCommand(): ExecutionCommandV1 {
	const example = exampleExecutionCommandV1();
	return { ...example, identity: { ...example.identity }, runtimeBinding: { ...example.runtimeBinding } };
}

function command(overrides: Partial<ExecutionCommandV1> = {}): ExecutionCommandV1 {
	commandCounter += 1;
	return {
		...exampleBaseCommand(),
		commandId: uuidOf(commandCounter),
		expectedJournalRevision: 0,
		secretValuesDigest: SECRET_VALUES_DIGEST,
		secretSnapshotRef: "5".repeat(64),
		// 默认 secret-only（configRevision 0 ⇔ ref/digest null 的契约耦合）；config 场景显式覆盖。
		configRevision: 0,
		configSnapshotRef: null,
		configValuesDigest: null,
		...overrides,
	};
}

function handoffView(command: ExecutionCommandV1, kind: "secret" | "config", fdBytes: Buffer, valuesDigest: string): SnapshotFdRelayHandoffView {
	return {
		commandId: command.commandId,
		kind,
		commandDigest: computeExecutionCommandDigestV1(command),
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

	async spawn(commandId: string, podmanArgv: readonly string[]): Promise<{ ok: true; exitCode: number } | { ok: false; code: string; message: string }> {
		this.spawns.push({ commandId, argv: [...podmanArgv] });
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
	readonly networks: WasmSandboxSpawnSpec[] = [];
	readonly spawnCalls: { readonly commandId: string; readonly spec: WasmSandboxSpawnSpec }[] = [];
	readonly stopCalls: { readonly sandboxId: string; readonly budgetMs: number }[] = [];
	readonly removes: string[] = [];
	readonly runningChecks: string[] = [];
	running = true;
	networkFailure: Error | null = null;
	spawnFailure: Error | null = null;
	stopOutcome: WasmStopOutcome = { result: "stopped" };
	stopFailure: Error | null = null;
	removeFailure: Error | null = null;

	async ensureNetwork(spec: WasmSandboxSpawnSpec): Promise<void> {
		if (this.networkFailure !== null) throw this.networkFailure;
		this.networks.push(spec);
	}

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
	stateDirectory: "/var/lib/iweb-sandbox-test",
	runtimeImageRepository: "localhost/iweb-wasmd",
	capabilityRecordHostPath: "/etc/iweb-wasmd/node-capability.json",
	architecture: "linux/arm64" as const,
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

function world(options: { readonly policy?: boolean; readonly spawnOptions?: boolean; readonly now?: () => string } = {}): World {
	const directory = tempDirectory();
	const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
	const runtime = new RuntimeStub();
	const relay = new RelayStub();
	const executor = createWasmSupervisorExecutor({
		journal,
		runtime,
		relay,
		policySource: options.policy === false ? undefined : () => exampleNormalizedWasmManifestV1(),
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

async function preparedStarted(worldRef: World, overrides: Partial<ExecutionCommandV1> = {}): Promise<ExecutionCommandV1> {
	const prepare = command({ operation: "prepare", identity: { sandboxId: "sbx-vector", versionId: exampleBaseCommand().identity.versionId, preparationGeneration: 1, executionGeneration: 1 }, ...overrides });
	await worldRef.deliver({ kind: "command", command: prepare });
	const start = command({ operation: "start", identity: prepare.identity, expectedJournalRevision: 2, ...overrides });
	worldRef.relay.handoffs.set(start.commandId, { secret: handoffView(start, "secret", SECRET_FD_BYTES, SECRET_VALUES_DIGEST), config: null });
	await worldRef.deliver({ kind: "command", command: start });
	return start;
}

describe("wasm executor real side effects: prepare (归档终审 2)", () => {
	test("prepare resolves the policy, allocates a subnet, and creates the internal network", async () => {
		const worldRef = world();
		const outcome = await worldRef.deliver({ kind: "command", command: command({ operation: "prepare" }) });
		expect(outcome.ok).toBe(true);
		if (outcome.ok) expect(outcome.result).toBe("applied");
		expect(worldRef.runtime.networks).toHaveLength(1);
		const spec = worldRef.runtime.networks[0];
		expect(spec?.sandboxId).toBe("sbx-vector");
		expect(spec?.subnetIndex).toBe(0);
		// spawn spec 组装单一来源（wasm-spawn.ts）：10 元素 wasmd argv + digest-pinned image。
		expect(spec?.argv).toHaveLength(10);
		expect(spec?.runtimeImage).toBe(SPAWN_OPTIONS.runtimeImageRepository + "@" + exampleBaseCommand().runtimeBinding.imageDigest);
		const record = worldRef.executor.fence.current("sbx-vector");
		expect(record?.subnetIndex).toBe(0);
		expect(record?.substate).toBe("prepared");
	});

	test("two sandboxes get distinct deterministic subnets", async () => {
		const worldRef = world();
		await worldRef.deliver({ kind: "command", command: command({ operation: "prepare", identity: { ...exampleBaseCommand().identity, sandboxId: "sbx-alpha" } }) });
		await worldRef.deliver({ kind: "command", command: command({ operation: "prepare", identity: { ...exampleBaseCommand().identity, sandboxId: "sbx-beta" }, expectedJournalRevision: 2 }) });
		expect(worldRef.runtime.networks.map((spec) => spec.subnetIndex)).toEqual([0, 1]);
	});

	test("missing policy source and missing spawn options fail closed with named codes", async () => {
		const noPolicy = world({ policy: false });
		const rejectedPolicy = await noPolicy.deliver({ kind: "command", command: command({ operation: "prepare" }) });
		expect(rejectedPolicy.ok && rejectedPolicy.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
		expect(noPolicy.runtime.networks).toHaveLength(0);
		const noOptions = world({ spawnOptions: false });
		const rejectedOptions = await noOptions.deliver({ kind: "command", command: command({ operation: "prepare" }) });
		expect(rejectedOptions.ok && rejectedOptions.failureCode).toBe(WASM_SPAWN_UNCONFIGURED);
	});

	test("an unexpected network error keeps the command received-incomplete for replay", async () => {
		const worldRef = world();
		worldRef.runtime.networkFailure = new Error("podman vanished");
		const prepare = command({ operation: "prepare" });
		const outcome = await worldRef.deliver({ kind: "command", command: prepare });
		expect(outcome.ok).toBe(false);
		if (!outcome.ok) {
			expect(outcome.status).toBe(500);
			expect(outcome.code).toBe("EXECUTION_EXECUTOR_FAILED");
		}
		const found = worldRef.journal.find(prepare.commandId);
		expect(found.received).not.toBeNull();
		expect(found.completed).toBeNull();
		// 恢复：故障移除后 replay 续跑成功（received-incomplete 幂等恢复）。
		worldRef.runtime.networkFailure = null;
		const resumed = await worldRef.deliver({ kind: "replay", command: prepare });
		expect(resumed.ok && resumed.result).toBe("applied");
		expect(worldRef.runtime.networks).toHaveLength(1);
	});

	test("a deterministic runtime failure is recorded as a rejected acknowledgement", async () => {
		const worldRef = world();
		worldRef.runtime.networkFailure = new RuntimeFailure("infrastructure", "podman network create failed");
		const prepare = command({ operation: "prepare" });
		const outcome = await worldRef.deliver({ kind: "command", command: prepare });
		expect(outcome.ok && outcome.failureCode).toBe(WASM_EXECUTION_SPAWN_FAILED);
		const found = worldRef.journal.find(prepare.commandId);
		expect(found.completed?.acknowledgement.result).toBe("rejected");
	});
});

describe("wasm executor real side effects: start via relay FD handoff", () => {
	test("start correlates both handoffs and spawns through the runtime port", async () => {
		const worldRef = world();
		const start = await preparedStarted(worldRef);
		expect(worldRef.relay.lookups).toEqual([start.commandId]);
		expect(worldRef.runtime.spawnCalls).toHaveLength(1);
		expect(worldRef.runtime.spawnCalls[0]?.commandId).toBe(start.commandId);
		const record = worldRef.executor.fence.current("sbx-vector");
		expect(record?.substate).toBe("running");
		expect(record?.spawnCommandId).toBe(start.commandId);
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

	test("relay transport failure and non-zero podman exit are deterministic rejections", async () => {
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
		worldRef.runtime.spawnFailure = new RuntimeFailure("infrastructure", "podman exited with 7");
		const exited = await worldRef.deliver({ kind: "command", command: startB });
		expect(exited.ok && exited.failureCode).toBe(WASM_EXECUTION_SPAWN_FAILED);
		expect(worldRef.journal.find(startB.commandId)?.completed?.acknowledgement.failureCode).toBe(WASM_EXECUTION_SPAWN_FAILED);
	});

	test("an optional readiness probe records adoption without flipping the command result", async () => {
		const directory = tempDirectory();
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
		const runtime = new RuntimeStub();
		const relay = new RelayStub();
		const healthOf = (cmd: ExecutionCommandV1) => ({
			schemaVersion: 2 as const,
			ok: true,
			sandboxId: cmd.identity.sandboxId,
			versionId: cmd.identity.versionId,
			packageDigest: cmd.packageDigest,
			runtimeBinding: cmd.runtimeBinding,
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
		let startCommand: ExecutionCommandV1 | null = null;
		const executor = createWasmSupervisorExecutor({
			journal,
			runtime,
			relay,
			policySource: () => exampleNormalizedWasmManifestV1(),
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
			runtimeBinding: drain.runtimeBinding,
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
			policySource: () => exampleNormalizedWasmManifestV1(),
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
			runtimeBinding: drain.runtimeBinding,
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
			policySource: () => exampleNormalizedWasmManifestV1(),
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

describe("podman wasm runtime port: argv and lifecycle mapping", () => {
	function portHarness(): { readonly runtime: WasmSandboxRuntime; readonly relay: RelayStub; readonly execCalls: string[][] } {
		const execCalls: string[][] = [];
		const relay = new RelayStub();
		const runtime = createPodmanWasmSandboxRuntime({
			exec: (args) => {
				execCalls.push([...args]);
				if (args[0] === "inspect") return "false\n";
				return "";
			},
			relay,
		});
		return { runtime, relay, execCalls };
	}

	function spawnSpecFixture(): WasmSandboxSpawnSpec {
		const cmd = command({ operation: "start" });
		const spec = buildSpecOf(cmd);
		if (spec === null) throw new Error("fixture spec failed to build");
		return spec;
	}

	function buildSpecOf(cmd: ExecutionCommandV1): WasmSandboxSpawnSpec | null {
		const built = buildWasmSandboxSpec({ command: cmd, policy: exampleNormalizedWasmManifestV1() }, { ...SPAWN_OPTIONS, subnetIndex: 0 });
		return built.ok ? built.value : null;
	}

	test("spawn sends the run form of the create argv to the relay", async () => {
		const { runtime, relay } = portHarness();
		const spec = spawnSpecFixture();
		await runtime.ensureNetwork(spec);
		await runtime.spawnExecution(spec.sandboxId + "-cmd", spec);
		// 建网：internal 子网创建参数（sandbox-spec 单一来源）。
		// spawn：create 头替换为 run -d，其余逐字节保留（--preserve-fds 2 / 10 元素 argv）。
		expect(relay.spawns).toHaveLength(1);
		const argv = relay.spawns[0]?.argv ?? [];
		expect(argv[0]).toBe("run");
		expect(argv[1]).toBe("-d");
		const createArgs = buildWasmdAppContainerCreateArgs(spec);
		expect(argv.slice(2)).toEqual(createArgs.slice(1));
		expect(argv.includes("--preserve-fds")).toBe(true);
	});

	test("stop maps the graceful budget to podman stop -t and reports stopped", async () => {
		const { runtime, execCalls } = portHarness();
		const outcome = await runtime.stopExecution("sbx-vector", 4_500);
		expect(outcome.result).toBe("stopped");
		const stop = execCalls.find((args) => args[0] === "stop");
		expect(stop).toEqual(["stop", "-t", "5", "sbx-vector-app"]);
		expect(execCalls.some((args) => args[0] === "kill")).toBe(false);
	});

	test("a container surviving podman stop is force-killed and reported", async () => {
		const execCalls: string[][] = [];
		const relay = new RelayStub();
		const runtime = createPodmanWasmSandboxRuntime({
			exec: (args) => {
				execCalls.push([...args]);
				if (args[0] === "inspect") {
					// 第一次 inspect（stop 后）仍 running；kill 后不 running。
					const killSeen = execCalls.some((call) => call[0] === "kill");
					return (killSeen ? "false" : "true") + "\n";
				}
				return "";
			},
			relay,
		});
		const outcome = await runtime.stopExecution("sbx-vector", 1_000);
		expect(outcome.result).toBe("forced-kill");
		expect(execCalls.some((args) => args[0] === "kill" && args[1] === "sbx-vector-app")).toBe(true);
	});

	test("a non-zero relay spawn exit surfaces as WASM_EXECUTION_SPAWN_FAILED", async () => {
		const { runtime, relay } = portHarness();
		relay.spawnExitCode = 9;
		const spec = spawnSpecFixture();
		let failure: unknown = null;
		try {
			await runtime.spawnExecution("cmd-1", spec);
		} catch (error) {
			failure = error;
		}
		expect(failure).toBeInstanceOf(RuntimeFailure);
		expect((failure as RuntimeFailure).message).toContain(WASM_EXECUTION_SPAWN_FAILED);
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
