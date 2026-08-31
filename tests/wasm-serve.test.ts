// 用户原始需求（2026-08-27，codex-final 复审 P0-2）：supervisor serve 路径的 wasm 装配
//   （wasm-serve.ts）必须有接线证明——依赖缺失/无效 → 拒绝启用（fail-closed，relay 子进程
//   一并回收）；齐备 → executor/execution-rpc/metrics 通道注册成功，prepare/start/drain
//   经 policySource（只读 manifest 文件 + capability pin）与 retiring 台账（只读事实文件，
//   miss 刷新）走真实副作用路径，不再因缺依赖而确定性拒绝。
// 正交意图：以内存 IO 桩驱动装配两端（真实 relay/子进程归实机批次）；判定语义
//   复用 contracts 纯函数与 wasm-execution 既有 executor，不在测试里造第二套比对。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	assembleWasmExecutionServices,
	FileBackedWasmRetirementLedger,
	WASM_SERVE_CAPABILITY_RECORD_INVALID,
	WASM_SERVE_READINESS_CONFIG_INVALID,
	WASM_SERVE_RELAY_MISSING,
	WASM_SERVE_RETIREMENTS_FILE_INVALID,
	WASM_SERVE_UNCONFIGURED,
	WasmServeError,
	IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV,
	KERNEL_WASM_POLICY_DIRECTORY,
	KERNEL_WASM_RETIREMENTS_FILE,
	WASM_HOST_SERVICE_POLICY_FILE_SUFFIX,
	type WasmServeIO,
} from "../supervisor/wasm-serve.ts";
import type { ExecutionRpcHandler } from "../supervisor/wasm-control.ts";
import { EXECUTION_DRAIN_RECEIPT_UNAVAILABLE, WASM_EXECUTION_POLICY_UNAVAILABLE } from "../supervisor/wasm-executor.ts";
import type { WasmSandboxRuntime, WasmStopOutcome } from "../supervisor/wasm-runtime.ts";
import type { SnapshotFdRelayClient, SnapshotFdRelayHandoffView, SnapshotFdRelayLookup } from "../supervisor/snapshot-fd-relay-client.ts";
import { computeSnapshotFdDigest } from "../supervisor/snapshot-fd.ts";
import type { WasmSandboxSpawnSpec } from "../supervisor/wasm-spawn.ts";
import {
	computeExecutionCommandDigest,
	exampleExecutionCommand,
	exampleNormalizedWasmManifestV1,
	type ExecutionCommand,
	type RuntimeBindingIdentityV1,
} from "../packages/contracts/wasm-execution.ts";
import { exampleNodeCapabilityRecordV1 } from "../packages/contracts/wasm-catalog.ts";
import { jcsCanonicalBytes, WASM_HOST_ABI_LITERAL } from "../packages/contracts/wasm-package.ts";
import {
	computeWasmHostServiceVersionDigestV2,
	sealWasmHostServiceCapabilityIncrementV2,
	sealWasmHostServicePolicyV2,
	WASM_CAPABILITY_MATRIX_V2,
	WASM_HOST_SERVICE_NODE_MAXIMA,
} from "../packages/contracts/wasm-host-policy.ts";

const REQUEST_ID = "018f1e2c-3d4b-7c6d-8e9f-001122334455";
const SECRET_FD_BYTES = Buffer.from('{"applicationId":"vector","values":{}}', "utf8");
const SECRET_VALUES_DIGEST = computeSnapshotFdDigest("secret", SECRET_FD_BYTES);

const CAPABILITY_RECORD = exampleNodeCapabilityRecordV1();
const COMPONENT_BYTES = Buffer.from("serve-test-component", "utf8");
const COMPONENT_SHA = require("node:crypto").createHash("sha256").update(COMPONENT_BYTES).digest("hex");
const MANIFEST = { ...exampleNormalizedWasmManifestV1(), runtime: { ...exampleNormalizedWasmManifestV1().runtime, entryLayerDigest: "sha256:" + COMPONENT_SHA } };
const BASE_COMMAND = exampleExecutionCommand();

// --- 单一命令形态的 revision-2 文件世界（increment + policy + versionDigest 绑定） -------
const V2_INCREMENT = sealWasmHostServiceCapabilityIncrementV2({
	schemaVersion: 2,
	matrixRevision: 2,
	hostAbi: "iweb-wasmd-abi@1.1.0",
	world: WASM_CAPABILITY_MATRIX_V2.world,
	hostImports: WASM_CAPABILITY_MATRIX_V2.hostImports,
	hostServiceMaxima: WASM_HOST_SERVICE_NODE_MAXIMA,
});
if (!V2_INCREMENT.ok) throw new Error("fixture error: increment must seal");
const HOST_SERVICE_POLICY = sealWasmHostServicePolicyV2({
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
});
if (!HOST_SERVICE_POLICY.ok) throw new Error("fixture error: policy must seal");
const VERSION_DIGEST = computeWasmHostServiceVersionDigestV2({
	packageDigest: BASE_COMMAND.packageDigest,
	normalizedPolicy: MANIFEST,
	hostServicePolicyDigest: HOST_SERVICE_POLICY.value.policyDigest,
});
if (!VERSION_DIGEST.ok) throw new Error("fixture error: version digest must compute");
const VERSION_ID = VERSION_DIGEST.value + "-1";

function jcsText(value: unknown): string {
	return Buffer.from(jcsCanonicalBytes(value)).toString("utf8");
}

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-serve-"));
}

let commandCounter = 0;

function uuidOf(counter: number): string {
	const sequence = counter.toString(16).padStart(3, "0").slice(-3);
	return "018f1e2c-3d4b-7" + sequence + "-9e01-00112233445" + (counter % 16).toString(16);
}

function command(overrides: Partial<ExecutionCommand> = {}): ExecutionCommand {
	commandCounter += 1;
	const base = exampleExecutionCommand();
	return {
		...base,
		identity: { ...base.identity, versionId: VERSION_ID },
		runtimeBinding: { ...base.runtimeBinding },
		commandId: uuidOf(commandCounter),
		expectedJournalRevision: 0,
		capabilityRecordRevision: CAPABILITY_RECORD.revision,
		capabilityRecordHash: CAPABILITY_RECORD.recordHash,
		hostServicePolicyDigest: HOST_SERVICE_POLICY.value.policyDigest,
		secretValuesDigest: SECRET_VALUES_DIGEST,
		secretSnapshotRef: "5".repeat(64),
		configRevision: 0,
		configSnapshotRef: null,
		configValuesDigest: null,
		...overrides,
	};
}

/** admission 事实形 binding（retiring 记录的持久面；ABI 1.0.0）。 */
function factBindingOf(source: ExecutionCommand): RuntimeBindingIdentityV1 {
	return { ...source.runtimeBinding, hostABI: WASM_HOST_ABI_LITERAL };
}

// --- 桩：内存 IO / 已认证 relay 客户端 / runtime 端口 ------------------------------------------

class MemoryIO implements WasmServeIO {
	readonly files = new Map<string, string>();

	write(path: string, content: string): void {
		this.files.set(path, content);
	}

	readFile(path: string): string | null {
		return this.files.get(path) ?? null;
	}

}

class RelayStub implements Pick<SnapshotFdRelayClient, "lookup" | "spawn" | "discard"> {
	readonly lookups: string[] = [];
	readonly spawns: { readonly commandId: string; readonly argv: readonly string[] }[] = [];
	readonly discards: string[] = [];
	readonly handoffs = new Map<string, SnapshotFdRelayLookup>();

	async lookup(commandId: string): Promise<SnapshotFdRelayLookup> {
		this.lookups.push(commandId);
		return this.handoffs.get(commandId) ?? { secret: null, config: null };
	}

	async spawn(commandId: string, argv: readonly string[]): Promise<{ readonly ok: true; readonly pid: number }> {
		this.spawns.push({ commandId, argv: [...argv] });
		return { ok: true, pid: 4242 };
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
	stopOutcome: WasmStopOutcome = { result: "stopped" };

	async spawnExecution(commandId: string, spec: WasmSandboxSpawnSpec): Promise<void> {
		this.spawnCalls.push({ commandId, spec });
	}

	async stopExecution(sandboxId: string, budgetMs: number): Promise<WasmStopOutcome> {
		this.stopCalls.push({ sandboxId, budgetMs });
		return this.stopOutcome;
	}

	async removeSandbox(sandboxId: string): Promise<void> {
		this.removes.push(sandboxId);
	}

	async isRunning(_sandboxId: string): Promise<boolean> {
		return true;
	}
}

function handoffView(target: ExecutionCommand): SnapshotFdRelayHandoffView {
	return {
		commandId: target.commandId,
		kind: "secret",
		commandDigest: computeExecutionCommandDigest(target),
		ref: target.secretSnapshotRef,
		applicationId: "vector",
		versionId: target.identity.versionId,
		preparationGeneration: target.identity.preparationGeneration,
		revision: target.secretRevision,
		valuesDigest: SECRET_VALUES_DIGEST,
		fdDigest: SECRET_VALUES_DIGEST,
		expiresAt: "2100-01-01T00:00:00Z",
		fdBytesBase64: SECRET_FD_BYTES.toString("base64"),
		descriptorRegularFile: true,
		descriptorReadOnly: true,
	};
}

interface World {
	readonly io: MemoryIO;
	readonly relay: RelayStub;
	readonly runtime: RuntimeStub;
	readonly paths: {
		readonly stateDirectory: string;
		readonly runtimeDirectory: string;
		readonly policyDirectory: string;
		readonly capabilityRecordPath: string;
		readonly retirementsPath: string;
	};
	assemble(environment?: Record<string, string | undefined>, includeRelay?: boolean): ReturnType<typeof assembleWasmExecutionServices>;
}

function world(options: { readonly prepareFiles?: (io: MemoryIO, paths: World["paths"]) => void } = {}): World {
	const stateDirectory = tempDirectory();
	const paths = {
		stateDirectory,
		runtimeDirectory: join(stateDirectory, "run"),
		// Production defaults are Kernel-owned facts, never supervisor-private state.
		policyDirectory: KERNEL_WASM_POLICY_DIRECTORY,
		capabilityRecordPath: join(stateDirectory, "wasm", "node-capability.json"),
		capabilityRecordV2Path: join(stateDirectory, "wasm", "node-capability-v2.json"),
		retirementsPath: KERNEL_WASM_RETIREMENTS_FILE,
	};
	const io = new MemoryIO();
	io.write(paths.capabilityRecordPath, jcsText(CAPABILITY_RECORD));
	io.write(paths.capabilityRecordV2Path, jcsText(V2_INCREMENT.value));
	io.write(join(paths.policyDirectory, VERSION_ID + ".json"), jcsText(MANIFEST));
	io.write(join(paths.policyDirectory, VERSION_ID + WASM_HOST_SERVICE_POLICY_FILE_SUFFIX), jcsText(HOST_SERVICE_POLICY.value));
	options.prepareFiles?.(io, paths);
	// 物化端口读真实文件系统：组件 blob 以真 fs 落盘（MemoryIO 是文本 stub）。
	const objectsDirectory = join(stateDirectory, "admission-objects");
	require("node:fs").mkdirSync(join(objectsDirectory, `vector/${VERSION_ID}/blobs`), { recursive: true });
	require("node:fs").writeFileSync(join(objectsDirectory, `vector/${VERSION_ID}/blobs/${COMPONENT_SHA}`), COMPONENT_BYTES);
	const relay = new RelayStub();
	const runtime = new RuntimeStub();
	return {
		io,
		relay,
		runtime,
		paths,
		assemble: (environment: Record<string, string | undefined> = {}, includeRelay = true) =>
			assembleWasmExecutionServices({
				environment: {
					IWEB_SANDBOX_WASM_EXECUTION_ENABLED: "1",
					IWEB_WASM_DATA_ROOT: join(stateDirectory, "wasm-data"),
					IWEB_SANDBOX_WASM_CAPABILITY_RECORD: paths.capabilityRecordPath,
					[IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV]: paths.capabilityRecordV2Path,
					IWEB_SANDBOX_WASM_OBJECTS_DIR: join(stateDirectory, "admission-objects"),
					IWEB_SANDBOX_WASM_BIN: "/opt/iweb/wasmd/iweb-wasmd",
					...environment,
				},
				stateDirectory,
				runtimeDirectory: paths.runtimeDirectory,
				arch: "arm64",
				io,
				...(includeRelay ? { relayClient: relay } : {}),
				runtime,
			}),
	};
}

async function captureFailure(promise: Promise<unknown>): Promise<unknown> {
	return promise.then(
		() => null,
		(error: unknown) => error,
	);
}

interface DeliveryOutcome {
	readonly ok: boolean;
	readonly result?: string;
	readonly failureCode?: string | null;
	readonly drainReceiptDigest?: string | null;
}

async function deliver(handler: ExecutionRpcHandler, body: Parameters<ExecutionRpcHandler["handle"]>[0]["body"]): Promise<DeliveryOutcome> {
	const result = await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body });
	if (!result.ok) return { ok: false };
	if (result.body.kind === "acknowledgement") {
		return {
			ok: true,
			result: result.body.acknowledgement.result,
			failureCode: result.body.acknowledgement.failureCode,
			drainReceiptDigest: result.body.acknowledgement.drainReceiptDigest,
		};
	}
	return { ok: true };
}

function retiringFact(drain: ExecutionCommand): unknown {
	return {
		drainCommandId: drain.commandId,
		applicationId: "vector",
		execution: drain.identity,
		packageDigest: drain.packageDigest,
		runtimeBinding: factBindingOf(drain),
		routeGeneration: 4,
		deadlineAtEpochMillis: Date.parse("2100-01-01T00:00:00Z"),
		flipAtEpochMillis: Date.parse("2026-08-27T00:00:00Z"),
		retired: false,
		acceptedReceiptDigest: null,
	};
}

// ---------------------------------------------------------------------------
// 拒绝启用（依赖缺失/无效 → fail-closed；公开 relay 由 main.ts 统一回收）
// ---------------------------------------------------------------------------

describe("wasm serve assembly: refusing enablement (codex-final P0-2)", () => {
	test("without the opt-in flag nothing is assembled", async () => {
		const worldRef = world();
		const services = await worldRef.assemble({ IWEB_SANDBOX_WASM_EXECUTION_ENABLED: undefined });
		expect(services.enabled).toBe(false);
	});

	test("a missing authenticated relay injection refuses enablement", async () => {
		const worldRef = world();
		const failure = await captureFailure(worldRef.assemble({}, false));
		expect(failure).toBeInstanceOf(WasmServeError);
		expect((failure as WasmServeError).code).toBe(WASM_SERVE_RELAY_MISSING);
	});

	test("a missing capability record path refuses enablement", async () => {
		const worldRef = world();
		const failure = await captureFailure(worldRef.assemble({ IWEB_SANDBOX_WASM_CAPABILITY_RECORD: undefined }));
		expect(failure).toBeInstanceOf(WasmServeError);
		expect((failure as WasmServeError).code).toBe(WASM_SERVE_UNCONFIGURED);
	});

	test("an absent capability record file refuses enablement", async () => {
		const worldRef = world({ prepareFiles: (io, paths) => io.files.delete(paths.capabilityRecordPath) });
		const failure = await captureFailure(worldRef.assemble());
		expect(failure).toBeInstanceOf(WasmServeError);
		expect((failure as WasmServeError).code).toBe(WASM_SERVE_CAPABILITY_RECORD_INVALID);
	});

	test("a capability record with a broken recordHash refuses enablement (NodeCapabilityRecordV1 recomputation)", async () => {
		const tampered = { ...CAPABILITY_RECORD, revision: CAPABILITY_RECORD.revision + 1 };
		const worldRef = world({ prepareFiles: (io, paths) => io.write(paths.capabilityRecordPath, jcsText(tampered)) });
		const failure = await captureFailure(worldRef.assemble());
		expect(failure).toBeInstanceOf(WasmServeError);
		expect((failure as WasmServeError).code).toBe(WASM_SERVE_CAPABILITY_RECORD_INVALID);
	});

	test("non-canonical capability record bytes refuse enablement (JCS authority)", async () => {
		const worldRef = world({ prepareFiles: (io, paths) => io.write(paths.capabilityRecordPath, JSON.stringify(CAPABILITY_RECORD, null, 2)) });
		const failure = await captureFailure(worldRef.assemble());
		expect(failure).toBeInstanceOf(WasmServeError);
	});

	test("a relative wasmd binary path refuses enablement (no half-configured run)", async () => {
		const worldRef = world();
		const failure = await captureFailure(worldRef.assemble({ IWEB_SANDBOX_WASM_BIN: "iweb-wasmd" }));
		expect(failure).toBeInstanceOf(WasmServeError);
		expect((failure as WasmServeError).code).toBe(WASM_SERVE_UNCONFIGURED);
	});

	test("a malformed retiring facts file present at startup refuses enablement", async () => {
		const worldRef = world({ prepareFiles: (io, paths) => io.write(paths.retirementsPath, jcsText({ not: "an array" })) });
		const failure = await captureFailure(worldRef.assemble());
		expect(failure).toBeInstanceOf(WasmServeError);
		expect((failure as WasmServeError).code).toBe(WASM_SERVE_RETIREMENTS_FILE_INVALID);
	});

	test("a malformed readiness probe tunable refuses enablement", async () => {
		const worldRef = world();
		const failure = await captureFailure(worldRef.assemble({ IWEB_SANDBOX_WASM_READINESS_PROBE: "1", IWEB_SANDBOX_WASM_READINESS_MAX_ATTEMPTS: "zero" }));
		expect(failure).toBeInstanceOf(WasmServeError);
		expect((failure as WasmServeError).code).toBe(WASM_SERVE_READINESS_CONFIG_INVALID);
	});
});

// ---------------------------------------------------------------------------
// 注册成功：齐备配置 → executor/execution-rpc/metrics 注册，命令走真实副作用路径
// ---------------------------------------------------------------------------

describe("wasm serve assembly: registering with complete dependencies (codex-final P0-2)", () => {
	test("complete configuration registers the executor, execution-rpc, metrics sampler, and authenticated relay client", async () => {
		const worldRef = world();
		const services = await worldRef.assemble();
		expect(services.enabled).toBe(true);
		if (!services.enabled) return;
		expect(services.executor).toBeDefined();
		expect(services.executionRpc).toBeDefined();
		// metrics 通道已接线：未知 sandbox 返回 null（不合成载荷）。
		expect(services.sampleEngineMetrics("sbx-vector")).toBeNull();
		// relay 生命周期/HTTP peer auth 是 main.ts 的唯一职责；装配只接受已认证 client。
		expect(worldRef.relay.lookups).toEqual([]);
	});

	test("the default policy and retirement projections are the shared Kernel paths", async () => {
		const worldRef = world();
		expect(worldRef.paths.policyDirectory).toBe("/data/kernel/wasm/admission");
		expect(worldRef.paths.retirementsPath).toBe("/data/kernel/wasm/retirements.json");
		const services = await worldRef.assemble({ IWEB_SANDBOX_WASM_GATEWAY_ADDRESS: "127.0.0.1:9081" });
		expect(services.enabled).toBe(true);
		// The injected runtime hides the process port; production relay receives the launcher from main.ts.
		if (services.enabled) expect(services.executor).toBeDefined();
	});

	test("prepare resolves the policy from the read-only manifest file and records the listen index", async () => {
		const worldRef = world();
		const services = await worldRef.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		const prepare = command({ operation: "prepare" });
		const outcome = await deliver(services.executionRpc, { kind: "command", command: prepare });
		expect(outcome).toEqual({ ok: true, result: "applied", failureCode: null, drainReceiptDigest: null });
		// 进程口径：prepare 无进程副作用，spawn spec 解析成功以监听索引注记为证。
		expect(worldRef.runtime.spawnCalls).toHaveLength(0);
		expect(services.executor.fence.current("sbx-vector")?.listenIndex).toBe(0);
	});

	test("prepare rejects with WASM_EXECUTION_POLICY_UNAVAILABLE when the version has no manifest file", async () => {
		const worldRef = world();
		const services = await worldRef.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		// 未落盘的 versionId（sequence +1 → 无文件）：策略不可证明 → 确定性拒绝。
		const missing = command({ operation: "prepare", identity: { ...BASE_COMMAND.identity, versionId: BASE_COMMAND.identity.versionId.replace(/-1$/, "-2"), preparationGeneration: 2 } });
		const outcome = await deliver(services.executionRpc, { kind: "command", command: missing });
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
	});

	test("prepare rejects when the manifest bytes do not bind to the command version digest", async () => {
		const tamperedManifest = { ...MANIFEST, resources: { ...MANIFEST.resources, cpuMillis: 5 } };
		const worldRef = world({ prepareFiles: (io, paths) => io.write(join(paths.policyDirectory, VERSION_ID + ".json"), jcsText(tamperedManifest)) });
		const services = await worldRef.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		const outcome = await deliver(services.executionRpc, { kind: "command", command: command({ operation: "prepare" }) });
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
	});

	test("prepare rejects when the command capability pin does not match the loaded record", async () => {
		const worldRef = world();
		const services = await worldRef.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		const stale = command({ operation: "prepare", capabilityRecordHash: "0".repeat(64) });
		const outcome = await deliver(services.executionRpc, { kind: "command", command: stale });
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_EXECUTION_POLICY_UNAVAILABLE);
	});

	test("start spawns through the relay-injected runtime and records readiness as unprobed by default", async () => {
		const worldRef = world();
		const services = await worldRef.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		await deliver(services.executionRpc, { kind: "command", command: command({ operation: "prepare" }) });
		const start = command({ operation: "start", expectedJournalRevision: 2 });
		worldRef.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
		const outcome = await deliver(services.executionRpc, { kind: "command", command: start });
		expect(outcome).toEqual({ ok: true, result: "applied", failureCode: null, drainReceiptDigest: null });
		expect(worldRef.runtime.spawnCalls).toHaveLength(1);
		expect(worldRef.relay.lookups).toEqual([start.commandId]);
		// readiness 探测缺省关闭（gateway 接线归 5.x）：观测态保持 unprobed。
		expect(services.executor.fence.current("sbx-vector")?.readiness).toBe("unprobed");
	});

	test("a trailing-whitespace data root is validated and passed trimmed (no literal path mismatch)", async () => {
		// Codex R5 非阻塞：校验 trim 后仍绝对，且传给 spawn 的 dataRoot 必须是同一
		// trim 值——尾空格进入字面路径会与 wasmd 侧 env 根逐字不一致。
		const worldRef = world();
		const injectedRoot = join(worldRef.paths.stateDirectory, "wasm-data") + "  ";
		const services = await worldRef.assemble({ IWEB_WASM_DATA_ROOT: injectedRoot });
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		await deliver(services.executionRpc, { kind: "command", command: command({ operation: "prepare" }) });
		const start = command({ operation: "start", expectedJournalRevision: 2 });
		worldRef.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
		await deliver(services.executionRpc, { kind: "command", command: start });
		expect(worldRef.runtime.spawnCalls[0]?.spec.dataDirectoryPath).toBe(join(worldRef.paths.stateDirectory, "wasm-data", "vector"));
	});

	test("drain reads the retiring fact delivered after startup and produces a receipt", async () => {
		const worldRef = world();
		const services = await worldRef.assemble();
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		await deliver(services.executionRpc, { kind: "command", command: command({ operation: "prepare" }) });
		const start = command({ operation: "start", expectedJournalRevision: 2 });
		worldRef.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
		await deliver(services.executionRpc, { kind: "command", command: start });
		// 无 retiring 事实：drain 确定性拒绝（fail-closed，不伪造 receipt）。
		const earlyDrain = command({ operation: "drain", identity: start.identity, expectedJournalRevision: 4 });
		const early = await deliver(services.executionRpc, { kind: "command", command: earlyDrain });
		expect(early.result).toBe("rejected");
		expect(early.failureCode).toBe(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
		// Kernel 在运行期投递 retiring 事实（文件落盘）：miss 刷新路径拾取，无需重启。
		const drain = command({ operation: "drain", identity: start.identity, expectedJournalRevision: 6 });
		worldRef.io.write(worldRef.paths.retirementsPath, jcsText([retiringFact(drain)]));
		const outcome = await deliver(services.executionRpc, { kind: "command", command: drain });
		expect(outcome).toEqual({ ok: true, result: "applied", failureCode: null, drainReceiptDigest: expect.any(String) });
		expect(worldRef.runtime.stopCalls).toEqual([{ sandboxId: "sbx-vector", budgetMs: expect.any(Number) }]);
		expect(worldRef.relay.discards).toEqual([start.commandId]);
		expect(services.executor.fence.current("sbx-vector")?.substate).toBe("retiring");
	});

	test("an explicit readiness probe configuration records an observation without flipping the start result", async () => {
		const worldRef = world();
		const services = await worldRef.assemble({
			IWEB_SANDBOX_WASM_READINESS_PROBE: "1",
			IWEB_SANDBOX_WASM_READINESS_MAX_ATTEMPTS: "1",
			IWEB_SANDBOX_WASM_READINESS_ATTEMPT_TIMEOUT_MS: "100",
			IWEB_SANDBOX_WASM_READINESS_INTERVAL_MS: "0",
		});
		if (!services.enabled) throw new Error("assembly unexpectedly disabled");
		await deliver(services.executionRpc, { kind: "command", command: command({ operation: "prepare" }) });
		const start = command({ operation: "start", expectedJournalRevision: 2 });
		worldRef.relay.handoffs.set(start.commandId, { secret: handoffView(start), config: null });
		const outcome = await deliver(services.executionRpc, { kind: "command", command: start });
		expect(outcome.result).toBe("applied");
		// 探测目标（沙箱内 wasmd 地址）不可达：not-ready 是诚实观测，不改命令结果。
		expect(services.executor.fence.current("sbx-vector")?.readiness).toBe("not-ready");
	});
});

// ---------------------------------------------------------------------------
// FileBackedWasmRetirementLedger：文件台账的直接契约
// ---------------------------------------------------------------------------

describe("file-backed retirement ledger (codex-final P0-2)", () => {
	test("malformed facts fail closed on refresh and a later valid delivery is adopted", () => {
		const io = new MemoryIO();
		const path = "/var/lib/iweb-sandbox/wasm/retirements.json";
		const ledger = new FileBackedWasmRetirementLedger(io, path);
		// 缺省文件：合法（尚未投递）。
		ledger.loadFromFile();
		io.write(path, jcsText([{ broken: true }]));
		expect(() => ledger.loadFromFile()).toThrow(WasmServeError);
		// 畸形事实之后的合法投递仍可被采纳（文件被修复后）。
		const drain = command({ operation: "drain" });
		io.write(path, jcsText([retiringFact(drain)]));
		ledger.loadFromFile();
		expect(ledger.find(drain.commandId)?.routeGeneration).toBe(4);
	});
});
