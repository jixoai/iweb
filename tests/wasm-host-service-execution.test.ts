// 用户原始需求（2026-08-28，add-wasm-host-services P0-3 supervisor 半边；2026-08-29
//   simplify-wasm-host-services 单版本化）：host-service 生命周期贯穿 supervisor 生产链
//   的证明——serve 装配把 hostServicePolicySource 注入 executor；执行命令（单一
//   ExecutionCommand 形态，hostServicePolicyDigest 在身）经 policy 权限/限额判定后生成
//   argv@2（11 元素，host-services context JCS，对位 argv.rs @2 分支）。V1 命令形态已
//   删除（编译期保证，见文末）；不存在 V1/V2 分派路径。
// 正交意图：ABI/标记耦合（@2 ⇔ 1.1.0，@1 恒 1.0.0）、资源门（1 <= reserveBytes <
//   memoryBytes，WASM_RESOURCE_RECORD_INVALID）、policy 权限 pin
//（WASM_HOST_POLICY_DIGEST_MISMATCH）、V2 能力 pin（记录轮换后旧命令确定性拒绝）、
//   snapshot handoff 的 V2 摘要域、V1 readiness/metrics wire 对 1.1.0 执行的 fail-closed。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	assembleWasmExecutionServices,
	createFileWasmHostServicePolicySource,
	IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV,
	KERNEL_WASM_POLICY_DIRECTORY,
	WASM_HOST_SERVICE_POLICY_FILE_SUFFIX,
	type WasmServeIO,
} from "../supervisor/wasm-serve.ts";
import {
	correlateEngineMetrics,
	correlateReadinessHealthV2,
	createWasmSupervisorExecutor,
	sampleWasmEngineMetrics,
	WASM_EXECUTION_POLICY_UNAVAILABLE,
	WASM_EXECUTION_WIRE_INVALID,
	type WasmSupervisorExecutor,
} from "../supervisor/wasm-executor.ts";
import {
	buildWasmdAppContainerCreateArgs,
	buildWasmdArgvV2,
	buildWasmSandboxSpec,
	computeSupervisorExecutionCommandDigest,
	verifyWasmdArgvV2,
	WASMD_ARGV_INVALID,
	WASMD_ARGV_MARKER,
	WASMD_ARGV_MARKER_V2,
	WASMD_ARGV_V2_ELEMENT_COUNT,
	WASMD_ARGV_WIRE_INVALID,
	WASM_HOST_POLICY_DIGEST_MISMATCH,
	WASM_RESOURCE_RECORD_INVALID,
} from "../supervisor/wasm-spawn.ts";
import type { WasmSandboxRuntime, WasmStopOutcome } from "../supervisor/wasm-runtime.ts";
import type { SnapshotFdRelayClient, SnapshotFdRelayHandoffView, SnapshotFdRelayLookup } from "../supervisor/snapshot-fd-relay-client.ts";
import type { WasmSandboxSpawnSpec } from "../supervisor/wasm-spawn.ts";
import { computeSnapshotFdDigest } from "../supervisor/snapshot-fd.ts";
import { systemStateStoreIO } from "../supervisor/wasm-shared.ts";
import { WasmExecutionJournalStore } from "../supervisor/wasm-control.ts";
import {
	sealWasmHostServiceCapabilityIncrementV2,
	sealWasmHostServicePolicyV2,
	WASM_CAPABILITY_MATRIX_V2,
	WASM_HOST_SERVICE_NODE_MAXIMA,
	computeWasmHostServiceVersionDigestV2,
	type WasmHostServicePolicyV2,
} from "../packages/contracts/wasm-host-policy.ts";
import {
	exampleExecutionCommand,
	exampleNormalizedWasmManifestV1,
	EXECUTION_COMMAND_INVALID,
	validateExecutionCommand,
	type ExecutionCommand,
} from "../packages/contracts/wasm-execution.ts";
import * as wasmExecutionModule from "../packages/contracts/wasm-execution.ts";

// 编译期保证（V1 命令形态不存在）：命名空间导入的 keyof 不含任何 V1/版本联合导出。
// 若有人重新导出 ExecutionCommandV1/Versioned* 等符号，下一行的类型立即失配（tsc 报错）。
type WasmExecutionExports = keyof typeof wasmExecutionModule;
type ForbidV1Exports = "ExecutionCommandV1" | "ExecutionCommandV2" | "VersionedExecutionCommand" | "VersionedExecutionAcknowledgement";
const noV1CommandForm: Exclude<WasmExecutionExports, ForbidV1Exports> extends WasmExecutionExports ? true : never = true;
void noV1CommandForm;
import { exampleNodeCapabilityRecordV1 } from "../packages/contracts/wasm-catalog.ts";
import { exampleServiceReadinessHealthV2, exampleWasmReadinessHealthV2 } from "../packages/contracts/wasm-health.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";

// ---------------------------------------------------------------------------
// fixtures：V2 文件世界（increment + policy + manifest，V2 versionDigest 绑定）
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
	return mkdtempSync(join(tmpdir(), "iweb-wasm-host-service-exec-"));
}

const PACKAGE_DIGEST = "b".repeat(64);
const FENCE_NONCE = "ab".repeat(16);
/** 资源向量与 Rust argv.rs 向量同值：memoryBytes 268435456 > reserveBytes 33554432。 */
const RESOURCES = { cpuMillis: 500, memoryBytes: 268435456, pidLimit: 256, storageBytes: 1073741824 };
/** 快照字节 → valuesDigest（域前缀单次 SHA-256；与 snapshot-fd.ts 同源）。 */
const SECRET_FD_BYTES = Buffer.from('{"applicationId":"vector","values":{}}', "utf8");
const SECRET_VALUES_DIGEST = computeSnapshotFdDigest("secret", SECRET_FD_BYTES);

function incrementPayload(): unknown {
	return {
		schemaVersion: 2,
		matrixRevision: 2,
		hostAbi: "iweb-wasmd-abi@1.1.0",
		world: WASM_CAPABILITY_MATRIX_V2.world,
		hostImports: WASM_CAPABILITY_MATRIX_V2.hostImports,
		hostServiceMaxima: WASM_HOST_SERVICE_NODE_MAXIMA,
	};
}

const V2_INCREMENT = sealWasmHostServiceCapabilityIncrementV2(incrementPayload());
if (!V2_INCREMENT.ok) throw new Error("fixture error: increment must seal");
const V2_RECORD_HASH = V2_INCREMENT.value.recordHash;

/** logging-only 服务成员（limits 全在节点 maxima 内；reserve 见各用例覆写）。 */
function policyPayload(reserveBytes: number): unknown {
	return {
		schemaVersion: 2,
		matrixRevision: 2,
		hostAbi: "iweb-wasmd-abi@1.1.0",
		hostServices: {
			kv: null,
			sql: null,
			logging: {
				profile: "bounded-memory-ring-v1",
				limits: { maxEventBytes: 8192, ringMaxEvents: 256, ringMaxBytes: 262144 },
				consistency: "append-only-drop-on-full-v1",
				durability: "no-durable-claim-v1",
				retention: "runtime-lifecycle-only-v1",
			},
		},
		storageBytes: 104857600,
		reserveBytes,
		dataDirectoryProfile: "per-app-sqlite-v1",
		durabilityProfile: "sqlite-full-fsync-v1",
	};
}

interface V2World {
	readonly io: MemoryIO;
	readonly policyDirectory: string;
	readonly capabilityRecordV2Path: string;
	readonly capabilityRecordPath: string;
	readonly stateDirectory: string;
	readonly policy: WasmHostServicePolicyV2;
	readonly versionId: string;
}

/** 装 V2 文件集（V1 记录 + V2 increment + manifest + policy），manifest 资源向量可覆写。 */
function v2World(reserveBytes = 33554432): V2World {
	const stateDirectory = tempDirectory();
	const policyDirectory = KERNEL_WASM_POLICY_DIRECTORY;
	const capabilityRecordV2Path = join(stateDirectory, "node-capability-v2.json");
	const capabilityRecordPath = join(stateDirectory, "node-capability.json");
	const io = new MemoryIO();
	io.write(capabilityRecordPath, jcsText(exampleNodeCapabilityRecordV1()));
	io.write(capabilityRecordV2Path, jcsText(V2_INCREMENT.value));

	const sealedPolicy = sealWasmHostServicePolicyV2(policyPayload(reserveBytes));
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
	return { io, policyDirectory, capabilityRecordV2Path, capabilityRecordPath, stateDirectory, policy: sealedPolicy.value, versionId };
}

let commandCounter = 0;

function uuidOf(counter: number): string {
	const sequence = counter.toString(16).padStart(3, "0").slice(-3);
	return "018f1e2c-3d4b-7" + sequence + "-9e01-00112233445" + (counter % 16).toString(16);
}

/** 执行命令（单一形态）：example 命令字段 + world 的 V2 身份增量（policy/capability pin）。 */
function hostServiceCommand(world: V2World, overrides: Partial<ExecutionCommand> = {}): ExecutionCommand {
	commandCounter += 1;
	const example = exampleExecutionCommand();
	return {
		...example,
		schemaVersion: 2,
		commandId: uuidOf(commandCounter),
		expectedControlRevision: 12,
		expectedJournalRevision: 0,
		operation: "prepare",
		identity: { sandboxId: "sbx-vector", versionId: world.versionId, preparationGeneration: 1, executionGeneration: 1 },
		packageDigest: PACKAGE_DIGEST,
		runtimeBinding: example.runtimeBinding,
		capabilityRecordRevision: 1,
		capabilityRecordHash: V2_RECORD_HASH,
		secretRevision: 1,
		secretValuesDigest: SECRET_VALUES_DIGEST,
		secretSnapshotRef: "5".repeat(64),
		configRevision: 0,
		configSnapshotRef: null,
		configValuesDigest: null,
		applicationId: "vector",
		matrixRevision: 2,
		hostServicePolicyDigest: world.policy.policyDigest,
		fenceNonce: FENCE_NONCE,
		...overrides,
	};
}

function handoffView(command: ExecutionCommand): SnapshotFdRelayHandoffView {
	return {
		commandId: command.commandId,
		kind: "secret",
		// V2 命令的 handoff 摘要域随 schemaVersion 切换（iweb-wasm-execution-command-v2）。
		commandDigest: computeSupervisorExecutionCommandDigest(command),
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

// --- 桩：relay 客户端与 runtime 端口（wasm-execution-spawn.test.ts 同款纪律） ------------------

class RelayStub implements Pick<SnapshotFdRelayClient, "lookup" | "spawn" | "discard"> {
	readonly lookups: string[] = [];
	readonly spawns: { readonly commandId: string; readonly argv: readonly string[] }[] = [];
	readonly discards: string[] = [];
	handoffs = new Map<string, SnapshotFdRelayLookup>();

	async lookup(commandId: string): Promise<SnapshotFdRelayLookup> {
		this.lookups.push(commandId);
		return this.handoffs.get(commandId) ?? { secret: null, config: null };
	}

	async spawn(commandId: string, podmanArgv: readonly string[]): Promise<{ ok: true; exitCode: number }> {
		this.spawns.push({ commandId, argv: [...podmanArgv] });
		return { ok: true, exitCode: 0 };
	}

	async discard(commandId: string): Promise<number> {
		this.discards.push(commandId);
		return 1;
	}
}

class RuntimeStub implements WasmSandboxRuntime {
	readonly spawnCalls: { readonly commandId: string; readonly spec: WasmSandboxSpawnSpec }[] = [];
	readonly removes: string[] = [];

	async spawnExecution(commandId: string, spec: WasmSandboxSpawnSpec): Promise<void> {
		this.spawnCalls.push({ commandId, spec });
	}

	async stopExecution(_sandboxId: string, _budgetMs: number): Promise<WasmStopOutcome> {
		return { result: "stopped" };
	}

	async removeSandbox(sandboxId: string): Promise<void> {
		this.removes.push(sandboxId);
	}

	async isRunning(_sandboxId: string): Promise<boolean> {
		return true;
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

interface Harness {
	readonly executor: WasmSupervisorExecutor;
	readonly runtime: RuntimeStub;
	readonly relay: RelayStub;
}

function harness(world: V2World, options: { readonly withV2Source?: boolean } = {}): Harness {
	const runtime = new RuntimeStub();
	const relay = new RelayStub();
	const executor = createWasmSupervisorExecutor({
		journal: new WasmExecutionJournalStore(systemStateStoreIO, tempDirectory()),
		runtime,
		relay,
		policySource: () => exampleNormalizedWasmManifestV1(),
		hostServicePolicySource:
			options.withV2Source === false
				? undefined
				: createFileWasmHostServicePolicySource(world.io, { policyDirectory: world.policyDirectory, capabilityRecordV2Path: world.capabilityRecordV2Path }),
		spawnOptions: SPAWN_OPTIONS,
		now: () => "2026-08-28T00:00:00.000Z",
	});
	return { executor, runtime, relay };
}

// ---------------------------------------------------------------------------
// argv@2：11 元素契约（argv.rs @2 分支对位）
// ---------------------------------------------------------------------------

describe("wasmd argv v2: exact 11-element contract (argv.rs @2 counterpart)", () => {
	test("the builder emits 11 elements with the host-services context as canonical JCS", () => {
		const world = v2World();
		const command = hostServiceCommand(world, { operation: "start" });
		const built = buildWasmdArgvV2({
			command,
			resources: RESOURCES,
			listen: "10.88.0.2:8787",
			gateway: "10.88.0.1:8081",
			componentPath: "/opt/iweb/wasm/component.wasm",
			capabilityRecordPath: "/etc/iweb-wasmd/node-capability.json",
			architecture: "linux/arm64",
			hostServicePolicy: world.policy,
		});
		expect(built.ok).toBe(true);
		if (!built.ok) return;
		const argv = built.value.argv;
		expect(argv.length).toBe(WASMD_ARGV_V2_ELEMENT_COUNT);
		expect(argv[0]).toBe("iweb-wasmd");
		expect(argv[1]).toBe(WASMD_ARGV_MARKER_V2);
		// binding/identity JSON 内嵌 ABI 1.1.0（标记与 ABI 严格耦合）。
		expect(JSON.parse(argv[7] ?? "{}").hostABI).toBe("iweb-wasmd-abi@1.1.0");
		expect(JSON.parse(argv[8] ?? "{}").runtimeBinding.hostABI).toBe("iweb-wasmd-abi@1.1.0");
		// 第 11 元素 = JCS({schemaVersion:2, applicationId, fenceNonce, hostServicePolicy})。
		expect(argv[10]).toBe(
			jcsText({ schemaVersion: 2, applicationId: "vector", fenceNonce: FENCE_NONCE, hostServicePolicy: world.policy }),
		);
		// verifier round-trip（builder 与 parser 契约不漂移）。
		const verified = verifyWasmdArgvV2([...argv]);
		expect(verified.ok).toBe(true);
		if (!verified.ok) return;
		expect(verified.value.hostServices.applicationId).toBe("vector");
		expect(verified.value.hostServices.hostServicePolicy.policyDigest).toBe(world.policy.policyDigest);
	});

	test("the @2 marker is strictly coupled to ABI 1.1.0 and rejects the @1 shape", () => {
		const world = v2World();
		const command = hostServiceCommand(world, { operation: "start" });
		const built = buildWasmdArgvV2({
			command,
			resources: RESOURCES,
			listen: "10.88.0.2:8787",
			gateway: "10.88.0.1:8081",
			componentPath: "/opt/iweb/wasm/component.wasm",
			capabilityRecordPath: "/etc/iweb-wasmd/node-capability.json",
			architecture: "linux/arm64",
			hostServicePolicy: world.policy,
		});
		if (!built.ok) throw new Error("fixture error");
		const argv = [...built.value.argv];
		// ABI 回拨 1.0.0（binding + identity 内嵌）：@2 拒绝（argv.rs validate_with_host_abi 对位）。
		const staleAbi = [...argv];
		staleAbi[7] = (argv[7] ?? "").replaceAll("iweb-wasmd-abi@1.1.0", "iweb-wasmd-abi@1.0.0");
		const staleBinding = verifyWasmdArgvV2(staleAbi);
		expect(staleBinding.ok).toBe(false);
		if (!staleBinding.ok) expect(staleBinding.errors[0]?.code).toBe(WASMD_ARGV_WIRE_INVALID);
		// @1 标记在 @2 verifier 下是形状错误；@2 元素数不是 10。
		const wrongMarker = verifyWasmdArgvV2([argv[0] ?? "", WASMD_ARGV_MARKER, ...argv.slice(2)]);
		expect(wrongMarker.ok).toBe(false);
		if (!wrongMarker.ok) expect(wrongMarker.errors[0]?.code).toBe(WASMD_ARGV_INVALID);
		const truncated = verifyWasmdArgvV2(argv.slice(0, -1));
		expect(truncated.ok).toBe(false);
		if (!truncated.ok) expect(truncated.errors[0]?.code).toBe(WASMD_ARGV_INVALID);
	});

	test("the V2 spec carries the per-app data directory as a child-accessible local path (process-era)", () => {
		const world = v2World();
		const command = hostServiceCommand(world);
		const spec = buildWasmSandboxSpec({ command, policy: { ...exampleNormalizedWasmManifestV1(), resources: RESOURCES }, hostServicePolicy: world.policy }, { ...SPAWN_OPTIONS, listenIndex: 0 });
		expect(spec.ok).toBe(true);
		if (!spec.ok) return;
		// per-app 数据目录由 supervisor 状态目录派生（<stateDirectory>/wasm-data/<applicationId>）；
		// 子进程直接读写（kv/sql/quota 三个 SQLite 后端都要在目录内创建与提交）。
		expect(spec.value.dataDirectoryPath).toBe(SPAWN_OPTIONS.stateDirectory + "/wasm-data/" + command.applicationId);
		expect(spec.value.pidFilePath).toBe(SPAWN_OPTIONS.pidDirectory + "/" + command.identity.sandboxId + ".pid");
	});

	test("a reserve covering the memory limit fails closed with the spec-named code", () => {
		// reserveBytes == memoryBytes：资源门违约（design §3；wasmd cross_check 同名码）。
		const world = v2World(RESOURCES.memoryBytes);
		const command = hostServiceCommand(world);
		const spec = buildWasmSandboxSpec({ command, policy: { ...exampleNormalizedWasmManifestV1(), resources: RESOURCES }, hostServicePolicy: world.policy }, { ...SPAWN_OPTIONS, listenIndex: 0 });
		expect(spec.ok).toBe(false);
		if (!spec.ok) {
			expect(spec.errors.some((error) => error.code === WASM_RESOURCE_RECORD_INVALID)).toBe(true);
		}
	});

	test("non-canonical or unknown-field context bytes and bad fence nonce fail closed", () => {
		const world = v2World();
		const command = hostServiceCommand(world, { operation: "start" });
		const built = buildWasmdArgvV2({
			command,
			resources: RESOURCES,
			listen: "10.88.0.2:8787",
			gateway: "10.88.0.1:8081",
			componentPath: "/opt/iweb/wasm/component.wasm",
			capabilityRecordPath: "/etc/iweb-wasmd/node-capability.json",
			architecture: "linux/arm64",
			hostServicePolicy: world.policy,
		});
		if (!built.ok) throw new Error("fixture error");
		const argv = built.value.argv;
		// 非规范 JCS（尾随空格）。
		const trailing = verifyWasmdArgvV2([...argv.slice(0, 10), (argv[10] ?? "") + " "]);
		expect(trailing.ok).toBe(false);
		if (!trailing.ok) expect(trailing.errors.some((error) => error.code === WASMD_ARGV_WIRE_INVALID)).toBe(true);
		// 未知 context 字段。
		const withUnknown: Record<string, unknown> = { schemaVersion: 2, applicationId: "vector", fenceNonce: FENCE_NONCE, hostServicePolicy: world.policy, extra: 1 };
		const unknownField = verifyWasmdArgvV2([...argv.slice(0, 10), jcsText(withUnknown)]);
		expect(unknownField.ok).toBe(false);
		// fenceNonce 大写/短长度拒绝（jcs.rs validate_fence_nonce 对位）。
		const upperNonce: Record<string, unknown> = { schemaVersion: 2, applicationId: "vector", fenceNonce: "AB".repeat(16), hostServicePolicy: world.policy };
		const badNonce = verifyWasmdArgvV2([...argv.slice(0, 10), jcsText(upperNonce)]);
		expect(badNonce.ok).toBe(false);
	});

	test("the command validator rejects ABI 1.0.0 bindings and missing identity fields", () => {
		const world = v2World();
		const command = hostServiceCommand(world);
		expect(validateExecutionCommand(command).ok).toBe(true);
		// binding ABI 回拨 1.0.0：解析器拒绝（不存在 V1 解释）。
		const staleBinding = validateExecutionCommand({ ...command, runtimeBinding: { ...command.runtimeBinding, hostABI: "iweb-wasmd-abi@1.0.0" } });
		expect(staleBinding.ok).toBe(false);
		if (!staleBinding.ok) expect(staleBinding.errors[0]?.code).toBe(EXECUTION_COMMAND_INVALID);
		const noNonce = validateExecutionCommand({ ...command, fenceNonce: undefined });
		expect(noNonce.ok).toBe(false);
		const badDigest = validateExecutionCommand({ ...command, hostServicePolicyDigest: "zz" });
		expect(badDigest.ok).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// executor：V2 命令的权限/限额判定 + spawn spec（argv@2）；V1 路径零改动
// ---------------------------------------------------------------------------

describe("wasm executor host-service V2 path (P0-3)", () => {
	test("prepare resolves the V2 policy and records the listen index without spawning", async () => {
		const world = v2World();
		const harnessRef = harness(world);
		const prepare = hostServiceCommand(world, { operation: "prepare" });
		const outcome = await harnessRef.executor.execute(prepare);
		expect(outcome.result).toBe("applied");
		// 进程口径：prepare 无进程副作用（spawn spec 的 argv@2 组装在 start 才消费）。
		expect(harnessRef.runtime.spawnCalls).toHaveLength(0);
		const record = harnessRef.executor.fence.current("sbx-vector");
		expect(record?.substate).toBe("prepared");
		expect(record?.listenIndex).toBe(0);
		// 幂等：同一命令（同 V2 摘要域 digest）重投递返回存档结果，不重复副作用。
		const replay = await harnessRef.executor.execute(prepare);
		expect(replay.result).toBe("applied");
		expect(harnessRef.runtime.spawnCalls).toHaveLength(0);
	});

	test("start correlates the V2-domain handoff digest and reaches the runtime spawn port", async () => {
		const world = v2World();
		const harnessRef = harness(world);
		await harnessRef.executor.execute(hostServiceCommand(world, { operation: "prepare" }));
		const start = hostServiceCommand(world, { operation: "start", commandId: uuidOf(++commandCounter) });
		harnessRef.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
		const outcome = await harnessRef.executor.execute(start);
		expect(outcome.result).toBe("applied");
		expect(harnessRef.relay.lookups).toEqual([start.commandId]);
		expect(harnessRef.runtime.spawnCalls).toHaveLength(1);
		expect(harnessRef.runtime.spawnCalls[0]?.commandId).toBe(start.commandId);
		// spawn spec 携带 11 元素 argv@2（RuntimeStub 只记录 spec；relay 的 podman argv
		// 组装由 createPodmanWasmSandboxRuntime 端口完成，wasm-execution-spawn.test.ts 已覆盖）。
		const spec = harnessRef.runtime.spawnCalls[0]?.spec;
		expect(spec?.argv.length).toBe(11);
		expect(spec?.argv[1]).toBe(WASMD_ARGV_MARKER_V2);
	});

	test("a command pinning different policy bytes is rejected without any side effect", async () => {
		const world = v2World();
		const harnessRef = harness(world);
		const pinned = hostServiceCommand(world, { hostServicePolicyDigest: "0".repeat(64) });
		const outcome = await harnessRef.executor.execute(pinned);
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_HOST_POLICY_DIGEST_MISMATCH);
		expect(harnessRef.runtime.spawnCalls).toHaveLength(0);
	});

	test("a stale V2 capability record pin is unprovable (owner rotated the record)", async () => {
		const world = v2World();
		const harnessRef = harness(world);
		const stale = hostServiceCommand(world, { capabilityRecordHash: "0".repeat(64) });
		const outcome = await harnessRef.executor.execute(stale);
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
	});

	test("a V2 command without a configured V2 source stays unprovable (no silent V1 fallback)", async () => {
		const world = v2World();
		const harnessRef = harness(world, { withV2Source: false });
		const outcome = await harnessRef.executor.execute(hostServiceCommand(world, { operation: "prepare" }));
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
		expect(harnessRef.runtime.spawnCalls).toHaveLength(0);
	});

	test("a V2 policy violating the reserve gate is rejected before any container work", async () => {
		const world = v2World(RESOURCES.memoryBytes);
		const harnessRef = harness(world);
		const outcome = await harnessRef.executor.execute(hostServiceCommand(world, { operation: "prepare" }));
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_RESOURCE_RECORD_INVALID);
		expect(harnessRef.runtime.spawnCalls).toHaveLength(0);
	});

	test("V2 readiness/metrics adoption correlates through the service wires (P0-3 wire formalization)", async () => {
		const world = v2World();
		const harnessRef = harness(world);
		const command = hostServiceCommand(world, { operation: "prepare" });
		await harnessRef.executor.execute(command);
		// 基础 readiness wire（ABI 1.0.0 binding、无 policy pin）无法证明 1.1.0 执行：
		// wire 拒绝（fail-closed；无降级路径）。
		const staleAdoption = correlateReadinessHealthV2(harnessRef.executor.fence, "sbx-vector", exampleWasmReadinessHealthV2());
		expect(staleAdoption.ok).toBe(false);
		if (!staleAdoption.ok) expect(staleAdoption.code).toBe(WASM_EXECUTION_WIRE_INVALID);
		// ServiceReadinessHealthV2（policy pin 与命令一致）→ adopted。
		const health = {
			...exampleServiceReadinessHealthV2(),
			versionId: command.identity.versionId,
			packageDigest: command.packageDigest,
			capabilityRecordRevision: command.capabilityRecordRevision,
			capabilityRecordHash: command.capabilityRecordHash,
			secretRevision: command.secretRevision,
			secretValuesDigest: command.secretValuesDigest,
			hostServicePolicyDigest: command.hostServicePolicyDigest,
			configRevision: 0,
			configSnapshotRef: null,
			configValuesDigest: null,
		};
		const adoption = correlateReadinessHealthV2(harnessRef.executor.fence, "sbx-vector", health);
		expect(adoption.ok).toBe(true);
		// policy pin 失配 → mismatch 拒绝（不采纳、不降级 V1）。
		const wrongPolicy = correlateReadinessHealthV2(harnessRef.executor.fence, "sbx-vector", { ...health, hostServicePolicyDigest: "0".repeat(64) });
		expect(wrongPolicy.ok).toBe(false);
		if (!wrongPolicy.ok) expect(wrongPolicy.code).toBe("WASM_READINESS_HEALTH_MISMATCH");
		// metrics：1.1.0 记录采样产出 ServiceEngineMetricsV2（schemaVersion:2 + policy pin）。
		const sample = sampleWasmEngineMetrics(harnessRef.executor.fence, "sbx-vector");
		expect(sample).not.toBeNull();
		expect(sample?.schemaVersion).toBe(2);
		if (sample?.schemaVersion === 2) {
			expect(sample.hostServicePolicyDigest).toBe(command.hostServicePolicyDigest);
			// 采样载荷与当前记录 correlate 采纳（同族 wire 的自洽 round-trip）。
			const metricsAdoption = correlateEngineMetrics(harnessRef.executor.fence, "sbx-vector", sample);
			expect(metricsAdoption.ok).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// serve 装配：启用 V2 时 executor 拿到 V2 policy 来源（生产链贯穿）
// ---------------------------------------------------------------------------

describe("wasm serve assembly wires the V2 policy source into the executor", () => {
	function baseEnvironment(world: V2World): Record<string, string | undefined> {
		return {
			IWEB_SANDBOX_WASM_EXECUTION_ENABLED: "1",
			IWEB_SANDBOX_WASM_CAPABILITY_RECORD: world.capabilityRecordPath,
			IWEB_SANDBOX_WASM_BIN: SPAWN_OPTIONS.wasmdBinaryPath,
		};
	}

	test("with the V2 env the assembled executor executes a V2 command end to argv@2", async () => {
		const world = v2World();
		const services = await assembleWasmExecutionServices({
			environment: { ...baseEnvironment(world), [IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV]: world.capabilityRecordV2Path },
			stateDirectory: world.stateDirectory,
			runtimeDirectory: join(world.stateDirectory, "run"),
			arch: "arm64",
			io: world.io,
			relayClient: new RelayStub(),
			runtime: new RuntimeStub(),
		});
		expect(services.enabled).toBe(true);
		if (!services.enabled) return;
		const outcome = await services.executor.execute(hostServiceCommand(world, { operation: "prepare" }));
		expect(outcome.result).toBe("applied");
	});

	test("without the V2 record env the assembly fails closed (single-version law)", async () => {
		const world = v2World();
		// 单一命令形态恒携带 hostServicePolicyDigest——revision-2 increment 是必备启动门，
		// 不存在「未启用 host services 的 V1 executor」装配形态。
		let rejected: unknown = null;
		try {
			await assembleWasmExecutionServices({
				environment: baseEnvironment(world),
				stateDirectory: world.stateDirectory,
				runtimeDirectory: join(world.stateDirectory, "run"),
				arch: "arm64",
				io: world.io,
				relayClient: new RelayStub(),
				runtime: new RuntimeStub(),
			});
		} catch (error) {
			rejected = error;
		}
		expect(rejected).toBeInstanceOf(Error);
		expect((rejected as Error).message).toContain(IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV);
	});

	// simplify-wasm-host-services：V1 命令形态不存在的编译期保证——以下断言只在
	// V1 wire 符号重新出现时才会编译失败（bun 运行时不做类型检查，typecheck 门禁
	// 对本文件生效前由 CI 的 tsc 覆盖面之外的守门注释承担）。
	test("the V1 command wire form is gone for good (compile-time guarantee)", () => {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
		const contracts = wasmExecutionModule as Record<string, unknown>;
		for (const gone of ["ExecutionCommandV1", "ExecutionCommandV2", "VersionedExecutionCommand", "VersionedExecutionAcknowledgement", "validateExecutionCommandV1", "validateVersionedExecutionCommand", "computeExecutionCommandDigestV1", "computeVersionedExecutionCommandDigest", "correlateVersionedExecutionAcknowledgement"]) {
			expect(contracts[gone]).toBeUndefined();
		}
		expect(typeof wasmExecutionModule.validateExecutionCommand).toBe("function");
		expect(typeof wasmExecutionModule.computeExecutionCommandDigest).toBe("function");
	});
});
