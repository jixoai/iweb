// 用户原始需求（2026-08-28，add-wasm-host-services 第四轮复审 5.5/10 P1 缺口收尾）：
//   备份服务接线证明——wasm-serve.ts 装配 WasmHostBackupService（此前服务类从未被生产
//   装配实例化）；数据目录根从 stateDirectory 派生（<stateDirectory>/wasm-data，即容器
//   内 /data/kernel/wasm-data 的宿主挂载源）；executor 的 start/stop/drain 生命周期钩子
//   通知备份 quiesce 注册表（活动写入窗口的开始与释放）。
// 正交意图：
//   1. 装配面：assembleWasmExecutionServices 产物携带 quiesce 注册表 + per-app 服务
//      工厂（幂等实例化、数据目录布局与 wasm-spawn 的挂载源逐字一致）；备份留存目录
//      显式环境变量（未配置 = 只报告不持久化；非法值 fail-closed 拒绝启用）。
//   2. 生命周期钩子：V2（host-service）start 真实 spawn 成功 → 活动写入窗口开始
//      （policy pin 记录在案）；stop 容器移除确认 → 释放；drain 在无 retiring 事实的
//      确定性拒绝路径上保守保持活动标记（误报活动只是拒绝捕获，误报静止会时点混批）。
//      单一命令形态恒携带 applicationId（无 V1 分支）。
//   3. 真实链 capture：装配工厂产出的服务经装配 executionRpc 投递真实 drain
//      （journal CAS + retiring 台账文件），从派生数据目录捕获三成员并把备份集持久化
//      到配置目录（与 wasm-host-backup.test.ts 的服务级测试互补——这里证明「装配产物
//      即生产链」，那边证明服务契约本身）。
// 规范权威：openspec/changes/add-wasm-host-services/design.md「Decisions 3」（备份
//   quiesce 语义：活动写入/未恢复/未冻结一律拒绝捕获）与 specs/wasm-application-runtime/
//   spec.md「Resource, directory, durability and failure boundaries are explicit」。
// 歧义备注（fail-closed 取舍）：
//   - V2 命令的 drain applied 路径当前不可达——retiring 台账 wire（WasmRetirementRecordV1）
//     的 runtimeBinding 钉 ABI 1.0.0，V2 命令 binding（1.1.0）在 matchesRetirementFence 的
//     精确比对下必然 mismatch（V2 retiring wire 对偶属 kernel-rs/后续批次）。因此 drain
//     settle 通知只以「确定性拒绝路径保持活动标记」形态测试；钩子代码在 V2 retiring
//     wire 落地后即生效（stop settle 通知以同款结构证明）。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	assembleWasmExecutionServices,
	IWEB_SANDBOX_WASM_BACKUP_DIR_ENV,
	IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV,
	KERNEL_WASM_POLICY_DIRECTORY,
	WASM_HOST_SERVICE_POLICY_FILE_SUFFIX,
	WASM_SERVE_UNCONFIGURED,
	type WasmServeIO,
} from "../supervisor/wasm-serve.ts";
import {
	wasmApplicationDataPath,
} from "../supervisor/wasm-spawn.ts";
import {
	WasmHostBackupServiceRegistry,
	systemWasmHostBackupFileIO,
	wasmHostBackupDataDirectoryRoot,
	WASM_BACKUP_FILE_NAMES_V2,
} from "../supervisor/wasm-host-backup.ts";
import type { ExecutionRpcHandler } from "../supervisor/wasm-control.ts";
import type { WasmSandboxRuntime, WasmStopOutcome } from "../supervisor/wasm-runtime.ts";
import type { SnapshotFdRelayClient, SnapshotFdRelayHandoffView, SnapshotFdRelayLookup } from "../supervisor/snapshot-fd-relay-client.ts";
import type { WasmSandboxSpawnSpec } from "../supervisor/wasm-spawn.ts";
import { computeSupervisorExecutionCommandDigest } from "../supervisor/wasm-spawn.ts";
import { computeSnapshotFdDigest } from "../supervisor/snapshot-fd.ts";
import {
	sealWasmHostServiceCapabilityIncrementV2,
	sealWasmHostServicePolicyV2,
	WASM_CAPABILITY_MATRIX_V2,
	WASM_HOST_SERVICE_NODE_MAXIMA,
	computeWasmHostServiceVersionDigestV2,
} from "../packages/contracts/wasm-host-policy.ts";
import {
	exampleExecutionCommand,
	exampleNormalizedWasmManifestV1,
	type ExecutionCommand,
} from "../packages/contracts/wasm-execution.ts";
import { exampleNodeCapabilityRecordV1 } from "../packages/contracts/wasm-catalog.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";

// ---------------------------------------------------------------------------
// fixtures：V2 文件世界 + 装配世界（wasm-host-service-execution / wasm-serve 测试同款纪律）
// ---------------------------------------------------------------------------

class MemoryIO implements WasmServeIO {
	readonly files = new Map<string, string>();

	write(path: string, content: string): void {
		this.files.set(path, content);
	}

	readFile(path: string): string | null {
		return this.files.get(path) ?? null;
	}
}

function jcsText(value: unknown): string {
	return Buffer.from(jcsCanonicalBytes(value)).toString("utf8");
}

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-backup-serve-"));
}

const PACKAGE_DIGEST = "b".repeat(64);
const FENCE_NONCE = "ab".repeat(16);
const RESOURCES = { cpuMillis: 500, memoryBytes: 268435456, pidLimit: 256, storageBytes: 1073741824 };
const SECRET_FD_BYTES = Buffer.from('{"applicationId":"vector","values":{}}', "utf8");
const SECRET_VALUES_DIGEST = computeSnapshotFdDigest("secret", SECRET_FD_BYTES);

const V2_INCREMENT = sealWasmHostServiceCapabilityIncrementV2({
	schemaVersion: 2,
	matrixRevision: 2,
	hostAbi: "iweb-wasmd-abi@1.1.0",
	world: WASM_CAPABILITY_MATRIX_V2.world,
	hostImports: WASM_CAPABILITY_MATRIX_V2.hostImports,
	hostServiceMaxima: WASM_HOST_SERVICE_NODE_MAXIMA,
});
if (!V2_INCREMENT.ok) throw new Error("fixture error: increment must seal");
// 顶层取值固定 narrowing（函数体内引用 V2_INCREMENT.value 无法跨边界保留判别 narrowing）。
const V2_INCREMENT_RECORD = V2_INCREMENT.value;
const V2_RECORD_HASH: string = V2_INCREMENT.value.recordHash;

function policyPayload(): unknown {
	return {
		schemaVersion: 2,
		matrixRevision: 2,
		hostAbi: "iweb-wasmd-abi@1.1.0",
		hostServices: {
			kv: {
				profile: "bounded-cas-list-v1",
				limits: { maxListItems: 64, maxListBytes: 65536, cursorTtlMs: 60000, entryOverheadBytes: 256 },
				consistency: "single-key-linearizable-cas-v1",
				durability: "sqlite-full-fsync-v1",
				retention: "tombstone-window-v1",
			},
			sql: null,
			logging: null,
		},
		storageBytes: 104857600,
		reserveBytes: 33554432,
		dataDirectoryProfile: "per-app-sqlite-v1",
		durabilityProfile: "sqlite-full-fsync-v1",
	};
}

class RelayStub implements Pick<SnapshotFdRelayClient, "lookup" | "spawn" | "discard"> {
	readonly lookups: string[] = [];
	readonly discards: string[] = [];
	readonly handoffs = new Map<string, SnapshotFdRelayLookup>();

	async lookup(commandId: string): Promise<SnapshotFdRelayLookup> {
		this.lookups.push(commandId);
		return this.handoffs.get(commandId) ?? { secret: null, config: null };
	}

	async spawn(): Promise<{ readonly ok: true; readonly exitCode: number }> {
		return { ok: true, exitCode: 0 };
	}

	async discard(commandId: string): Promise<number> {
		this.discards.push(commandId);
		return 1;
	}
}

class RuntimeStub implements WasmSandboxRuntime {
	readonly spawnCalls: { readonly commandId: string; readonly spec: WasmSandboxSpawnSpec }[] = [];
	readonly stopCalls: { readonly sandboxId: string; readonly budgetMs: number }[] = [];
	readonly removes: string[] = [];

	async spawnExecution(commandId: string, spec: WasmSandboxSpawnSpec): Promise<void> {
		this.spawnCalls.push({ commandId, spec });
	}

	async stopExecution(sandboxId: string, budgetMs: number): Promise<WasmStopOutcome> {
		this.stopCalls.push({ sandboxId, budgetMs });
		return { result: "stopped" };
	}

	async removeSandbox(sandboxId: string): Promise<void> {
		this.removes.push(sandboxId);
	}

	async isRunning(_sandboxId: string): Promise<boolean> {
		return true;
	}
}

interface BackupWiringWorld {
	readonly stateDirectory: string;
	readonly io: MemoryIO;
	readonly relay: RelayStub;
	readonly runtime: RuntimeStub;
	readonly policyDigest: string;
	readonly versionId: string;
	/** 每条投递命令消耗两个 journal revision（received + completed）；per-world 计数。 */
	nextJournalRevision(): number;
	assemble(environment?: Record<string, string | undefined>): ReturnType<typeof assembleWasmExecutionServices>;
}

function backupWiringWorld(options: { readonly backupDir?: string } = {}): BackupWiringWorld {
	const stateDirectory = tempDirectory();
	const policyDirectory = KERNEL_WASM_POLICY_DIRECTORY;
	const capabilityRecordV2Path = join(stateDirectory, "node-capability-v2.json");
	const capabilityRecordPath = join(stateDirectory, "node-capability.json");
	const retirementsPath = join(stateDirectory, "retirements.json");
	const io = new MemoryIO();
	io.write(capabilityRecordPath, jcsText(exampleNodeCapabilityRecordV1()));
	io.write(capabilityRecordV2Path, jcsText(V2_INCREMENT_RECORD));

	const sealedPolicy = sealWasmHostServicePolicyV2(policyPayload());
	if (!sealedPolicy.ok) throw new Error("fixture error: policy must seal");
	const manifest = { ...exampleNormalizedWasmManifestV1(), resources: RESOURCES };
	const versionDigest = computeWasmHostServiceVersionDigestV2({
		packageDigest: PACKAGE_DIGEST,
		normalizedPolicy: manifest,
		hostServicePolicyDigest: sealedPolicy.value.policyDigest,
	});
	if (!versionDigest.ok) throw new Error("fixture error: version digest must compute");
	const versionId = versionDigest.value + "-1";
	io.write(join(policyDirectory, versionId + ".json"), jcsText(manifest));
	io.write(join(policyDirectory, versionId + WASM_HOST_SERVICE_POLICY_FILE_SUFFIX), jcsText(sealedPolicy.value));

	const relay = new RelayStub();
	const runtime = new RuntimeStub();
	// journal revision 计数绑定 world（每个 world 一个独立 journal store，从 0 起）。
	let journalRevision = 0;
	return {
		stateDirectory,
		io,
		relay,
		runtime,
		policyDigest: sealedPolicy.value.policyDigest,
		versionId,
		nextJournalRevision: () => {
			const current = journalRevision;
			journalRevision += 2;
			return current;
		},
		assemble: (environment: Record<string, string | undefined> = {}) =>
			assembleWasmExecutionServices({
				environment: {
					IWEB_SANDBOX_WASM_EXECUTION_ENABLED: "1",
					IWEB_SANDBOX_WASM_CAPABILITY_RECORD: capabilityRecordPath,
					[IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV]: capabilityRecordV2Path,
					IWEB_SANDBOX_WASM_BIN: "/opt/iweb/wasmd/iweb-wasmd",
					IWEB_SANDBOX_WASM_RETIREMENTS_FILE: retirementsPath,
					...(options.backupDir !== undefined ? { [IWEB_SANDBOX_WASM_BACKUP_DIR_ENV]: options.backupDir } : {}),
					...environment,
				},
				stateDirectory,
				runtimeDirectory: join(stateDirectory, "run"),
				arch: "arm64",
				io,
				relayClient: relay,
				runtime,
			}),
	};
}

// ---------------------------------------------------------------------------
// 命令构造（V2 seam 形状 + V1 wire）与投递
// ---------------------------------------------------------------------------

let commandCounter = 0;

function uuidOf(counter: number): string {
	const sequence = counter.toString(16).padStart(3, "0").slice(-3);
	return "018f1e2c-3d4b-7" + sequence + "-9e01-00112233445" + (counter % 16).toString(16);
}

function v2Command(world: BackupWiringWorld, overrides: Partial<ExecutionCommand> = {}): ExecutionCommand {
	commandCounter += 1;
	const example = exampleExecutionCommand();
	return {
		...example,
		expectedControlRevision: 12,
		schemaVersion: 2,
		commandId: uuidOf(commandCounter),
		expectedJournalRevision: world.nextJournalRevision(),
		operation: "prepare",
		identity: { sandboxId: "sbx-vector", versionId: world.versionId, preparationGeneration: 1, executionGeneration: 1 },
		packageDigest: PACKAGE_DIGEST,
		runtimeBinding: { ...example.runtimeBinding, hostABI: "iweb-wasmd-abi@1.1.0" },
		capabilityRecordHash: V2_RECORD_HASH,
		secretValuesDigest: SECRET_VALUES_DIGEST,
		secretSnapshotRef: "5".repeat(64),
		configRevision: 0,
		configSnapshotRef: null,
		configValuesDigest: null,
		applicationId: "vector",
		matrixRevision: 2,
		hostServicePolicyDigest: world.policyDigest,
		fenceNonce: FENCE_NONCE,
		...overrides,
	};
}

function handoffView(command: ExecutionCommand): SnapshotFdRelayHandoffView {
	// 摘要键 = digestV2("iweb-wasm-execution-command-v2", JCS(command))（唯一公式）。
	const commandDigest = computeSupervisorExecutionCommandDigest(command);
	return {
		commandId: command.commandId,
		kind: "secret",
		commandDigest,
		ref: command.secretSnapshotRef,
		applicationId: "vector",
		versionId: command.identity.versionId,
		preparationGeneration: command.identity.preparationGeneration,
		revision: command.secretRevision,
		valuesDigest: SECRET_VALUES_DIGEST,
		fdDigest: SECRET_VALUES_DIGEST,
		expiresAt: "2100-01-01T00:00:00Z",
		fdBytesBase64: SECRET_FD_BYTES.toString("base64"),
		descriptorRegularFile: true,
		descriptorReadOnly: true,
	};
}

async function deliver(handler: ExecutionRpcHandler, command: ExecutionCommand): Promise<{ readonly result: string; readonly failureCode: string | null }> {
	const result = await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: uuidOf(++commandCounter), body: { kind: "command", command } });
	if (!result.ok) throw new Error("delivery failed: " + result.code);
	if (result.body.kind !== "acknowledgement") throw new Error("expected an acknowledgement");
	return { result: result.body.acknowledgement.result, failureCode: result.body.acknowledgement.failureCode };
}

function retiringFact(drain: ExecutionCommand): unknown {
	return {
		drainCommandId: drain.commandId,
		applicationId: "vector",
		execution: drain.identity,
		packageDigest: drain.packageDigest,
		// admission 事实形 binding（ABI 1.0.0；correlate 前经 runtimeBindingIdentityV2FromV1 归一）。
		runtimeBinding: { ...drain.runtimeBinding, hostABI: "iweb-wasmd-abi@1.0.0" },
		routeGeneration: 4,
		deadlineAtEpochMillis: Date.parse("2100-01-01T00:00:00Z"),
		flipAtEpochMillis: Date.parse("2026-08-27T00:00:00Z"),
		retired: false,
		acceptedReceiptDigest: null,
	};
}

// V2 生命周期的最小序列：prepare → start（真实 spawn 桩 + relay handoff）。
async function startV2Execution(world: BackupWiringWorld, services: { readonly executionRpc: ExecutionRpcHandler }): Promise<ExecutionCommand> {
	const prepare = v2Command(world);
	const prepared = await deliver(services.executionRpc, prepare);
	expect(prepared.result).toBe("applied");
	const start = v2Command(world, { operation: "start", identity: prepare.identity });
	world.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
	const started = await deliver(services.executionRpc, start);
	expect(started.result).toBe("applied");
	return start;
}

// ---------------------------------------------------------------------------
// 装配面
// ---------------------------------------------------------------------------

describe("backup wiring (fourth-review P1): assembly", () => {
	test("the assembly carries the quiesce registry and the per-app service factory", async () => {
		const world = backupWiringWorld();
		const services = await world.assemble();
		expect(services.enabled).toBe(true);
		if (!services.enabled) return;
		expect(services.backup.quiesce).toBeDefined();
		expect(services.backup.services).toBeInstanceOf(WasmHostBackupServiceRegistry);
		// 工厂幂等：同 (applicationId, policyDigest) 复用同实例（owner 并发调度见同一状态）。
		const first = services.backup.services.forApplication("vector", world.policyDigest);
		expect(services.backup.services.forApplication("vector", world.policyDigest)).toBe(first);
		expect(services.backup.services.size).toBe(1);
		// 初始无活动写入。
		expect(services.backup.quiesce.hasActiveExecution("vector")).toBe(false);
		expect(services.backup.quiesce.activeApplications()).toEqual([]);
	});

	test("the derived data-directory root matches the spawn mount source layout exactly", async () => {
		// 单一目录布局权威在 wasm-spawn.ts 的 wasmApplicationDataPath（容器内
		// /data/kernel/wasm-data/<app> 的宿主挂载源）；备份根派生必须与之逐字一致。
		const stateDirectory = "/var/lib/iweb-sandbox";
		const root = wasmHostBackupDataDirectoryRoot(stateDirectory);
		expect(root).toBe(stateDirectory + "/wasm-data");
		for (const applicationId of ["vector", "notes-app", "a"]) {
			expect(join(root, applicationId)).toBe(wasmApplicationDataPath(stateDirectory, applicationId));
		}
	});

	test("an explicitly configured backup directory assembles; an invalid one refuses enablement", async () => {
		const valid = backupWiringWorld({ backupDir: "/var/lib/iweb-sandbox/wasm-backups" });
		const assembled = await valid.assemble();
		expect(assembled.enabled).toBe(true);
		const invalid = backupWiringWorld({ backupDir: "relative/backup-sets" });
		const failure = await invalid.assemble().then(
			() => null,
			(error: unknown) => error,
		);
		expect(failure).toBeInstanceOf(Error);
		expect((failure as { readonly code?: unknown }).code).toBe(WASM_SERVE_UNCONFIGURED);
	});
});

// ---------------------------------------------------------------------------
// executor 生命周期钩子 → quiesce 注册表
// ---------------------------------------------------------------------------

describe("backup wiring: executor lifecycle hooks notify the quiesce registry", () => {
	test("a V2 start with a real spawn opens the active-write window with the policy pin", async () => {
		const world = backupWiringWorld();
		const services = await world.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		await startV2Execution(world, services);
		expect(services.backup.quiesce.hasActiveExecution("vector")).toBe(true);
		expect(services.backup.quiesce.lastAdoptedPolicyDigest("vector")).toBe(world.policyDigest);
		expect(services.backup.quiesce.activeApplications()).toEqual(["vector"]);
	});

	test("a V2 stop releases the marker only after the container removal is confirmed", async () => {
		const world = backupWiringWorld();
		const services = await world.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		const started = await startV2Execution(world, services);
		const stop = v2Command(world, { operation: "stop", identity: started.identity });
		const stopped = await deliver(services.executionRpc, stop);
		expect(stopped.result).toBe("applied");
		expect(world.runtime.removes).toEqual(["sbx-vector"]);
		expect(services.backup.quiesce.hasActiveExecution("vector")).toBe(false);
		expect(services.backup.quiesce.activeApplications()).toEqual([]);
		// settle 后 policy pin 仍保留（owner 调度的期望身份提示，非活动标记）。
		expect(services.backup.quiesce.lastAdoptedPolicyDigest("vector")).toBe(world.policyDigest);
	});

	test("a V2 drain that is deterministically rejected (no retiring fact) keeps the marker active", async () => {
		const world = backupWiringWorld();
		const services = await world.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		const started = await startV2Execution(world, services);
		const drain = v2Command(world, { operation: "drain", identity: started.identity });
		const drained = await deliver(services.executionRpc, drain);
		expect(drained.result).toBe("rejected");
		// 保守方向：未知/失败路径保持「活动」（宁可拒绝捕获，绝不让备份时点混批）。
		expect(services.backup.quiesce.hasActiveExecution("vector")).toBe(true);
	});

	test("a rejected start (unprovable policy pin) never opens the active-write window", async () => {
		const world = backupWiringWorld();
		const services = await world.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		const prepare = v2Command(world);
		await deliver(services.executionRpc, prepare);
		const start = v2Command(world, { operation: "start", identity: prepare.identity, hostServicePolicyDigest: "e".repeat(64) });
		world.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
		const started = await deliver(services.executionRpc, start);
		expect(started.result).toBe("rejected");
		expect(services.backup.quiesce.hasActiveExecution("vector")).toBe(false);
	});

});

// ---------------------------------------------------------------------------
// 真实链 capture：装配工厂的服务经装配 executionRpc 捕获并持久化
// ---------------------------------------------------------------------------

describe("backup wiring: capture through the assembled per-app service", () => {
	test("the assembled service drains through the real journal and persists the set into the configured directory", async () => {
		const backupRoot = tempDirectory();
		const world = backupWiringWorld({ backupDir: join(backupRoot, "sets") });
		const services = await world.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		// 建立已采纳的 execution（drain 的 fence 前置需要命中已采纳 tuple）。
		const prepare = v2Command(world);
		await deliver(services.executionRpc, prepare);
		const start = v2Command(world, { operation: "start", identity: prepare.identity });
		world.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
		await deliver(services.executionRpc, start);
		// 数据目录三成员（0600、非零）落在派生根下（与 spawn 挂载源同一路径布局）。
		const dataRoot = wasmHostBackupDataDirectoryRoot(world.stateDirectory);
		systemWasmHostBackupFileIO.ensureDirectory(join(dataRoot, "vector"));
		const memberBytes = new Map<string, Buffer>();
		for (const kind of ["kv", "sql", "quota"] as const) {
			const bytes = Buffer.from("sqlite-image:" + kind, "utf8");
			memberBytes.set(kind, bytes);
			systemWasmHostBackupFileIO.writeFileBytes(join(dataRoot, "vector", WASM_BACKUP_FILE_NAMES_V2[kind]), bytes, 0o600);
		}
		// 全新 drain 命令（capture 自己投递）：retiring 事实为它建档（MemoryIO 文件）。
		const drain = v2Command(world, { operation: "drain", identity: start.identity });
		world.io.write(join(world.stateDirectory, "retirements.json"), jcsText([retiringFact(drain)]));
		const service = services.backup.services.forApplication("vector", world.policyDigest);
		const captured = await service.capture({
			drainCommand: drain,
			quiesceState: { outstandingReservedBytes: 0, recoveryStatus: "healthy", ledgerRevision: 7, frozenLedgerRevision: 7 },
			usageRevision: 3,
		});
		expect(captured.ok).toBe(true);
		if (!captured.ok) throw new Error("expected a successful capture");
		// 持久化落点在配置目录（成员字节 + JCS 描述符；0600）。
		expect(captured.persistedPath).toBe(join(backupRoot, "sets", "vector", "backup-set-v2.json"));
		for (const kind of ["kv", "sql", "quota"] as const) {
			const retained = systemWasmHostBackupFileIO.readFileBytes(join(backupRoot, "sets", "vector", WASM_BACKUP_FILE_NAMES_V2[kind]));
			expect(retained?.equals(memberBytes.get(kind) as Buffer)).toBe(true);
		}
		// 真实 drain 走了 runtime 端口（经装配 executionRpc → executor）。
		expect(world.runtime.stopCalls.length).toBe(1);
		// drain 进程终止确认后活动写入窗口关闭（settle 通知）。
		expect(services.backup.quiesce.hasActiveExecution("vector")).toBe(false);
	});
});
