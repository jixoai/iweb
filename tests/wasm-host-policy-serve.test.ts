// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：catalog/能力记录 revision 2
//   接线的证明——wasm-serve 的 policy 装配消费 HostServicePolicyV2（revision-2 校验、matrix 增量、
//   digestV2 hash domain 复算、limits<=maxima、V2 versionDigest 绑定），wasm-catalog-store 的
//   owner 读侧 binding fence 投影；supervisor 侧 v2/v1 共存（V1 记录语义不变，V2 不可证明即 null，
//   V1 entry 与 V2 policy 同场 fail-closed）。
// 正交意图：V2 增量启动门（缺失/坏 hash/非 JCS → 拒绝启用）；policy 来源正/负例（缺文件、篡改
//   digest、超 maxima、versionId 不绑定）；装配共存（未配置 env → hostServicePolicySource:null 且
//   V1 路径照常）；catalog fence（V1 catalog entry + V2 policy → ABI mismatch；未初始化 → 拒绝）。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	assembleWasmExecutionServices,
	createFileWasmHostServicePolicySource,
	IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV,
	KERNEL_WASM_POLICY_DIRECTORY,
	loadHostServiceCapabilityIncrementV2,
	WASM_SERVE_CAPABILITY_RECORD_V2_INVALID,
	WasmServeError,
	WASM_HOST_SERVICE_POLICY_FILE_SUFFIX,
	type WasmServeIO,
} from "../supervisor/wasm-serve.ts";
import {
	hostServiceLimitsWithinMaxima,
	systemWasmCatalogStoreIO,
	WasmCatalogStore,
	WASM_CATALOG_HOST_SERVICE_ABI_MISMATCH,
	WASM_CATALOG_STORE_UNINITIALIZED,
} from "../supervisor/wasm-catalog-store.ts";
import type { WasmSandboxRuntime, WasmStopOutcome } from "../supervisor/wasm-runtime.ts";
import type {
	SnapshotFdRelayClient,
	SnapshotFdRelayLookup,
} from "../supervisor/snapshot-fd-relay-client.ts";
import type { WasmSandboxSpawnSpec } from "../supervisor/wasm-spawn.ts";
import {
	sealWasmHostServiceCapabilityIncrementV2,
	sealWasmHostServicePolicyV2,
	WASM_CAPABILITY_MATRIX_V2,
	WASM_EMPTY_HOST_SERVICE_POLICY_V2,
	WASM_HOST_SERVICE_NODE_MAXIMA,
	WASM_HOST_SERVICE_PROFILE_DEFAULTS,
	computeWasmHostServiceVersionDigestV2,
	type WasmHostServicePolicyV2,
} from "../packages/contracts/wasm-host-policy.ts";
import {
	exampleNodeCapabilityRecordV1,
	exampleRuntimeCatalogV1,
} from "../packages/contracts/wasm-catalog.ts";
import { exampleNormalizedWasmManifestV1 } from "../packages/contracts/wasm-execution.ts";
import { computeWasmVersionDigestV1, jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";

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
	async lookup(_commandId: string): Promise<SnapshotFdRelayLookup> {
		return { secret: null, config: null };
	}
	async spawn(
		_commandId: string,
		_argv: readonly string[],
	): Promise<{ readonly ok: true; readonly pid: number }> {
		return { ok: true, pid: 4242 };
	}
	async discard(_commandId: string): Promise<number> {
		return 1;
	}
}

class RuntimeStub implements WasmSandboxRuntime {
	async ensureNetwork(_spec: WasmSandboxSpawnSpec): Promise<void> {}
	async spawnExecution(_commandId: string, _spec: WasmSandboxSpawnSpec): Promise<void> {}
	async stopExecution(_sandboxId: string, _budgetMs: number): Promise<WasmStopOutcome> {
		return { result: "stopped" };
	}
	async removeSandbox(_sandboxId: string): Promise<void> {}
	async isRunning(_sandboxId: string): Promise<boolean> {
		return true;
	}
}

function jcsText(value: unknown): string {
	return Buffer.from(jcsCanonicalBytes(value)).toString("utf8");
}

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-host-policy-serve-"));
}

const PACKAGE_DIGEST = "b".repeat(64);

/** 合法 increment payload（matrix 增量 + 节点 maxima；recordHash = digestV2(capability-record-v2 域)）。 */
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

/** 增量记录的确定性 recordHash（命令 capabilityRecordHash pin 的期望值）。 */
const V2_RECORD_HASH = sealWasmHostServiceCapabilityIncrementV2(incrementPayload()).value.recordHash;

/** 合法 HostServicePolicyV2 payload（logging-only 服务；limits 在节点 maxima 内）。 */
function policyPayload(): unknown {
	return {
		schemaVersion: 2,
		matrixRevision: 2,
		hostAbi: "iweb-wasmd-abi@1.1.0",
		hostServices: {
			kv: null,
			sql: null,
			logging: {
				profile: "bounded-memory-ring-v1",
				limits: WASM_HOST_SERVICE_PROFILE_DEFAULTS.logging,
				consistency: "append-only-drop-on-full-v1",
				durability: "no-durable-claim-v1",
				retention: "runtime-lifecycle-only-v1",
			},
		},
		storageBytes: 104857600,
		reserveBytes: 1048576,
		dataDirectoryProfile: "per-app-sqlite-v1",
		durabilityProfile: "sqlite-full-fsync-v1",
	};
}

interface V2World {
	readonly io: MemoryIO;
	readonly paths: {
		readonly policyDirectory: string;
		readonly capabilityRecordV2Path: string;
		readonly capabilityRecordPath: string;
		readonly stateDirectory: string;
		readonly runtimeDirectory: string;
	};
	readonly policy: WasmHostServicePolicyV2;
	readonly versionId: string;
}

/** 装 V2 文件集（increment + policy + manifest），返回 versionId（V2 versionDigest 绑定）。 */
function v2World(): V2World {
	const stateDirectory = tempDirectory();
	const policyDirectory = KERNEL_WASM_POLICY_DIRECTORY;
	const capabilityRecordV2Path = join(stateDirectory, "node-capability-v2.json");
	const capabilityRecordPath = join(stateDirectory, "node-capability.json");
	const io = new MemoryIO();
	io.write(capabilityRecordPath, jcsText(exampleNodeCapabilityRecordV1()));
	io.write(
		capabilityRecordV2Path,
		jcsText(sealWasmHostServiceCapabilityIncrementV2(incrementPayload()).value),
	);

	const sealedPolicy = sealWasmHostServicePolicyV2(policyPayload());
	if (!sealedPolicy.ok) throw new Error("fixture error: policy must seal");
	const manifest = exampleNormalizedWasmManifestV1();
	const versionDigest = computeWasmHostServiceVersionDigestV2({
		packageDigest: PACKAGE_DIGEST,
		normalizedPolicy: manifest,
		hostServicePolicyDigest: sealedPolicy.value.policyDigest,
	});
	if (!versionDigest.ok) throw new Error("fixture error: version digest must compute");
	const versionId = versionDigest.value + "-1";
	io.write(join(policyDirectory, versionId + ".json"), jcsText(manifest));
	io.write(
		join(policyDirectory, versionId + WASM_HOST_SERVICE_POLICY_FILE_SUFFIX),
		jcsText(sealedPolicy.value),
	);
	return {
		io,
		paths: {
			policyDirectory,
			capabilityRecordV2Path,
			capabilityRecordPath,
			stateDirectory,
			runtimeDirectory: join(stateDirectory, "run"),
		},
		policy: sealedPolicy.value,
		versionId,
	};
}

// ---------------------------------------------------------------------------
// revision-2 capability increment 启动门
// ---------------------------------------------------------------------------

describe("revision-2 capability record loading (startup gate)", () => {
	test("a valid increment file loads with its digestV2 recordHash recomputed", () => {
		const world = v2World();
		const loaded = loadHostServiceCapabilityIncrementV2(
			world.io,
			world.paths.capabilityRecordV2Path,
		);
		expect(loaded.matrixRevision).toBe(2);
		expect(loaded.hostAbi).toBe("iweb-wasmd-abi@1.1.0");
		expect(loaded.hostImports).toHaveLength(WASM_CAPABILITY_MATRIX_V2.hostImports.length);
	});

	test("a missing file fails closed", () => {
		const world = v2World();
		expect(() =>
			loadHostServiceCapabilityIncrementV2(
				world.io,
				join(world.paths.stateDirectory, "absent.json"),
			),
		).toThrow(WasmServeError);
	});

	test("a tampered recordHash fails closed (digestV2 domain recomputation)", () => {
		const world = v2World();
		const sealed = sealWasmHostServiceCapabilityIncrementV2(incrementPayload()).value;
		const tampered = { ...sealed, recordHash: "0".repeat(64) };
		const path = join(world.paths.stateDirectory, "tampered-v2.json");
		world.io.write(path, jcsText(tampered));
		try {
			loadHostServiceCapabilityIncrementV2(world.io, path);
			throw new Error("unreachable: tampered recordHash must fail");
		} catch (error) {
			expect(error).toBeInstanceOf(WasmServeError);
			expect((error as WasmServeError).code).toBe(WASM_SERVE_CAPABILITY_RECORD_V2_INVALID);
		}
	});

	test("non-canonical bytes fail closed (JCS authority)", () => {
		const world = v2World();
		const path = join(world.paths.stateDirectory, "pretty-v2.json");
		world.io.write(
			path,
			JSON.stringify(sealWasmHostServiceCapabilityIncrementV2(incrementPayload()).value, null, 2),
		);
		expect(() => loadHostServiceCapabilityIncrementV2(world.io, path)).toThrow(WasmServeError);
	});
});

// ---------------------------------------------------------------------------
// V2 host-service policy 装配（fail-closed：任一环节不可证明 → null，不降级 V1）
// ---------------------------------------------------------------------------

describe("file-backed V2 host-service policy source", () => {
	test("a complete, bound file set resolves the sealed policy", async () => {
		const world = v2World();
		const source = createFileWasmHostServicePolicySource(world.io, {
			policyDirectory: world.paths.policyDirectory,
			capabilityRecordV2Path: world.paths.capabilityRecordV2Path,
		});
		const resolved = await source({
			applicationId: "notes-app",
			versionId: world.versionId,
			packageDigest: PACKAGE_DIGEST,
			capabilityRecordHash: V2_RECORD_HASH,
		});
		expect(resolved).not.toBeNull();
		// 解析产物 = sealed policy + 同一 V2 versionDigest 绑定下的 V1 normalized manifest。
		expect(resolved?.policy.policyDigest).toBe(world.policy.policyDigest);
		expect(resolved?.policy.hostServices.logging).not.toBeNull();
		expect(resolved?.normalizedPolicy.resources).toBeDefined();
	});

	test("a missing host-service policy file or manifest is unprovable (null)", async () => {
		const world = v2World();
		const source = createFileWasmHostServicePolicySource(world.io, {
			policyDirectory: world.paths.policyDirectory,
			capabilityRecordV2Path: world.paths.capabilityRecordV2Path,
		});
		// 该 versionId 是 V2 versionDigest 绑定：policy 文件缺席落入 policyless 半边后，
		// V1 公式复算不匹配（域分隔互不碰撞）→ 仍不可证明（不合成零值，也不降级）。
		world.io.files.delete(
			join(world.paths.policyDirectory, world.versionId + WASM_HOST_SERVICE_POLICY_FILE_SUFFIX),
		);
		expect(
			await source({
				applicationId: "notes-app",
				versionId: world.versionId,
				packageDigest: PACKAGE_DIGEST,
				capabilityRecordHash: V2_RECORD_HASH,
			}),
		).toBeNull();
		world.io.files.delete(join(world.paths.policyDirectory, world.versionId + ".json"));
		expect(
			await source({
				applicationId: "notes-app",
				versionId: world.versionId,
				packageDigest: PACKAGE_DIGEST,
				capabilityRecordHash: V2_RECORD_HASH,
			}),
		).toBeNull();
	});

	// simplify-wasm-host-services P0 空串闭环：policy 文件缺席 + V1 versionDigest 绑定成立
	// 的 policyless 准入行解析为零值策略（policyDigest ""）；绑定不符仍 fail-closed。
	test("a policyless row (no policy file, V1 versionDigest binding) resolves the zero-value policy", async () => {
		const world = v2World();
		const source = createFileWasmHostServicePolicySource(world.io, {
			policyDirectory: world.paths.policyDirectory,
			capabilityRecordV2Path: world.paths.capabilityRecordV2Path,
		});
		const manifest = exampleNormalizedWasmManifestV1();
		const manifestText = jcsText(manifest);
		const policylessVersionId = computeWasmVersionDigestV1(PACKAGE_DIGEST, Buffer.from(manifestText, "utf8")) + "-1";
		world.io.write(join(world.paths.policyDirectory, policylessVersionId + ".json"), manifestText);
		const resolved = await source({
			applicationId: "notes-app",
			versionId: policylessVersionId,
			packageDigest: PACKAGE_DIGEST,
			capabilityRecordHash: V2_RECORD_HASH,
		});
		expect(resolved).not.toBeNull();
		expect(resolved?.policy).toEqual(WASM_EMPTY_HOST_SERVICE_POLICY_V2);
		expect(resolved?.normalizedPolicy.resources).toBeDefined();
		// policyless 半边同样 fail-closed：packageDigest 与 versionId 绑定不符 → null。
		expect(
			await source({
				applicationId: "notes-app",
				versionId: policylessVersionId,
				packageDigest: "c".repeat(64),
				capabilityRecordHash: V2_RECORD_HASH,
			}),
		).toBeNull();
	});

	test("a tampered policyDigest is unprovable (digestV2 policy domain recomputation)", async () => {
		const world = v2World();
		const source = createFileWasmHostServicePolicySource(world.io, {
			policyDirectory: world.paths.policyDirectory,
			capabilityRecordV2Path: world.paths.capabilityRecordV2Path,
		});
		world.io.write(
			join(world.paths.policyDirectory, world.versionId + WASM_HOST_SERVICE_POLICY_FILE_SUFFIX),
			jcsText({ ...world.policy, policyDigest: "0".repeat(64) }),
		);
		expect(
			await source({
				applicationId: "notes-app",
				versionId: world.versionId,
				packageDigest: PACKAGE_DIGEST,
				capabilityRecordHash: V2_RECORD_HASH,
			}),
		).toBeNull();
	});

	test("a policy limit above the record hostServiceMaxima is unprovable", async () => {
		const world = v2World();
		const manifest = exampleNormalizedWasmManifestV1();
		// 节点硬天花板内、但超「收紧后 record maxima」的 policy：契约可封口（<= NODE_MAXIMA），
		// 但 increment 的 hostServiceMaxima 收紧后装配必须拒绝——节点 maxima 的 record 载体语义。
		const tightenedIncrement = sealWasmHostServiceCapabilityIncrementV2({
			...(incrementPayload() as object),
			hostServiceMaxima: {
				...WASM_HOST_SERVICE_NODE_MAXIMA,
				logging: { ...WASM_HOST_SERVICE_PROFILE_DEFAULTS.logging },
			},
		});
		if (!tightenedIncrement.ok) throw new Error("fixture error");
		const tightenedPath = join(world.paths.stateDirectory, "tightened-v2.json");
		world.io.write(tightenedPath, jcsText(tightenedIncrement.value));
		const tightenedSource = createFileWasmHostServicePolicySource(world.io, {
			policyDirectory: world.paths.policyDirectory,
			capabilityRecordV2Path: tightenedPath,
		});
		// defaults 内的 limits 恰等于收紧后的 maxima → 通过（<= 语义；pin = 收紧记录的 recordHash）。
		expect(
			await tightenedSource({
				applicationId: "notes-app",
				versionId: world.versionId,
				packageDigest: PACKAGE_DIGEST,
				capabilityRecordHash: tightenedIncrement.value.recordHash,
			}),
		).not.toBeNull();
		const slightly = sealWasmHostServicePolicyV2({
			...(policyPayload() as object),
			hostServices: {
				kv: null,
				sql: null,
				logging: {
					profile: "bounded-memory-ring-v1",
					limits: {
						...WASM_HOST_SERVICE_PROFILE_DEFAULTS.logging,
						ringMaxEvents: WASM_HOST_SERVICE_PROFILE_DEFAULTS.logging.ringMaxEvents + 1,
					},
					consistency: "append-only-drop-on-full-v1",
					durability: "no-durable-claim-v1",
					retention: "runtime-lifecycle-only-v1",
				},
			},
		});
		if (!slightly.ok) throw new Error("fixture error");
		const slightlyDigest = computeWasmHostServiceVersionDigestV2({
			packageDigest: PACKAGE_DIGEST,
			normalizedPolicy: manifest,
			hostServicePolicyDigest: slightly.value.policyDigest,
		});
		if (!slightlyDigest.ok) throw new Error("fixture error");
		const slightlyVersionId = slightlyDigest.value + "-1";
		world.io.write(
			join(world.paths.policyDirectory, slightlyVersionId + ".json"),
			jcsText(manifest),
		);
		world.io.write(
			join(world.paths.policyDirectory, slightlyVersionId + WASM_HOST_SERVICE_POLICY_FILE_SUFFIX),
			jcsText(slightly.value),
		);
		expect(
			await tightenedSource({
				applicationId: "notes-app",
				versionId: slightlyVersionId,
				packageDigest: PACKAGE_DIGEST,
				capabilityRecordHash: tightenedIncrement.value.recordHash,
			}),
		).toBeNull();
	});

	test("a versionId the V2 digest does not bind is unprovable", async () => {
		const world = v2World();
		const source = createFileWasmHostServicePolicySource(world.io, {
			policyDirectory: world.paths.policyDirectory,
			capabilityRecordV2Path: world.paths.capabilityRecordV2Path,
		});
		// 同一 policy 文件键下，换一个 packageDigest 即失去 versionDigest 绑定。
		expect(
			await source({
				applicationId: "notes-app",
				versionId: world.versionId,
				packageDigest: "c".repeat(64),
				capabilityRecordHash: V2_RECORD_HASH,
			}),
		).toBeNull();
	});

	test("a tampered increment file makes every resolution unprovable (per-call re-read)", async () => {
		const world = v2World();
		const source = createFileWasmHostServicePolicySource(world.io, {
			policyDirectory: world.paths.policyDirectory,
			capabilityRecordV2Path: world.paths.capabilityRecordV2Path,
		});
		expect(
			await source({
				applicationId: "notes-app",
				versionId: world.versionId,
				packageDigest: PACKAGE_DIGEST,
				capabilityRecordHash: V2_RECORD_HASH,
			}),
		).not.toBeNull();
		world.io.write(
			world.paths.capabilityRecordV2Path,
			jcsText({
				...sealWasmHostServiceCapabilityIncrementV2(incrementPayload()).value,
				recordHash: "0".repeat(64),
			}),
		);
		expect(
			await source({
				applicationId: "notes-app",
				versionId: world.versionId,
				packageDigest: PACKAGE_DIGEST,
				capabilityRecordHash: V2_RECORD_HASH,
			}),
		).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// 装配门：未配置 V2 env → fail-closed 拒绝启用；配置且有效 → source 注册；配置且无效 → 拒绝启用
// ---------------------------------------------------------------------------

describe("wasm serve assembly coexistence (v2/v1)", () => {
	function baseEnvironment(world: V2World): Record<string, string | undefined> {
		return {
			IWEB_SANDBOX_WASM_EXECUTION_ENABLED: "1",
			IWEB_SANDBOX_WASM_CAPABILITY_RECORD: world.paths.capabilityRecordPath,
			IWEB_SANDBOX_WASM_BIN: "/opt/iweb/wasmd/iweb-wasmd",
		};
	}

	test("without the V2 record env the assembly fails closed (single-version startup gate)", async () => {
		const world = v2World();
		// simplify-wasm-host-services：单一命令形态恒携带 hostServicePolicyDigest——
		// revision-2 increment 是必备启动门，不再有「V1 语义」装配形态。
		const outcome = await assembleWasmExecutionServices({
			environment: baseEnvironment(world),
			stateDirectory: world.paths.stateDirectory,
			runtimeDirectory: world.paths.runtimeDirectory,
			arch: "arm64",
			io: world.io,
			relayClient: new RelayStub(),
			runtime: new RuntimeStub(),
		}).then(
			() => null,
			(error: unknown) => error,
		);
		expect(outcome).toBeInstanceOf(WasmServeError);
	});

	test("with a valid V2 record env the policy source is wired and resolves the sealed policy", async () => {
		const world = v2World();
		const services = await assembleWasmExecutionServices({
			environment: {
				...baseEnvironment(world),
				[IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV]: world.paths.capabilityRecordV2Path,
			},
			stateDirectory: world.paths.stateDirectory,
			runtimeDirectory: world.paths.runtimeDirectory,
			arch: "arm64",
			io: world.io,
			relayClient: new RelayStub(),
			runtime: new RuntimeStub(),
		});
		expect(services.enabled).toBe(true);
		if (!services.enabled || services.hostServicePolicySource === null)
			throw new Error("fixture error: source must be wired");
		const resolved = await services.hostServicePolicySource({
			applicationId: "notes-app",
			versionId: world.versionId,
			packageDigest: PACKAGE_DIGEST,
			capabilityRecordHash: V2_RECORD_HASH,
		});
		expect(resolved?.policy.policyDigest).toBe(world.policy.policyDigest);
	});

	test("an invalid V2 record file refuses enablement entirely (fail-closed startup gate)", async () => {
		const world = v2World();
		const badPath = join(world.paths.stateDirectory, "bad-v2.json");
		world.io.write(
			badPath,
			jcsText({
				...sealWasmHostServiceCapabilityIncrementV2(incrementPayload()).value,
				recordHash: "0".repeat(64),
			}),
		);
		const outcome = await assembleWasmExecutionServices({
			environment: {
				...baseEnvironment(world),
				[IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV]: badPath,
			},
			stateDirectory: world.paths.stateDirectory,
			runtimeDirectory: world.paths.runtimeDirectory,
			arch: "arm64",
			io: world.io,
			relayClient: new RelayStub(),
			runtime: new RuntimeStub(),
		}).then(
			() => null,
			(error: unknown) => error,
		);
		expect(outcome).toBeInstanceOf(WasmServeError);
	});
});

// ---------------------------------------------------------------------------
// catalog-store：V2 binding fence（owner 读侧投影；V1 entry 与 V2 policy 同场 fail-closed）
// ---------------------------------------------------------------------------

describe("catalog store host-service binding fence", () => {
	function bootstrappedStore(): WasmCatalogStore {
		const directory = tempDirectory();
		const store = new WasmCatalogStore(systemWasmCatalogStoreIO, directory, {
			now: () => "2026-08-28T00:00:00.000Z",
		});
		const example = exampleRuntimeCatalogV1();
		const outcome = store.bootstrap({
			schemaVersion: 1,
			revision: example.revision,
			entries: example.entries,
		});
		if (!outcome.ok) throw new Error("fixture error: bootstrap failed");
		return store;
	}

	test("an uninitialized store refuses the fence", () => {
		const store = new WasmCatalogStore(systemWasmCatalogStoreIO, tempDirectory(), {
			now: () => "2026-08-28T00:00:00.000Z",
		});
		const outcome = store.hostServiceBindingFence({
			entryKey: "iweb-wasmd",
			policy: policyPayload(),
			capabilityIncrement: incrementPayload(),
		});
		expect(outcome.ok).toBe(false);
		if (!outcome.ok) expect(outcome.code).toBe(WASM_CATALOG_STORE_UNINITIALIZED);
	});

	test("a V2 policy against a V1 (abi 1.0.0) catalog entry fails closed — never downgraded", () => {
		const store = bootstrappedStore();
		const entryKey = exampleRuntimeCatalogV1().entries[0]?.entryKey ?? "iweb-wasmd";
		const outcome = store.hostServiceBindingFence({
			entryKey,
			policy: policyPayload(),
			capabilityIncrement: incrementPayload(),
		});
		expect(outcome.ok).toBe(false);
		if (!outcome.ok) expect(outcome.code).toBe(WASM_CATALOG_HOST_SERVICE_ABI_MISMATCH);
		// V1 记录语义不变：同一 entry 的 V1 binding fence 照常工作。
		expect(store.current()).not.toBeNull();
	});

	test("an unknown entry key fails closed with the contract code", () => {
		const store = bootstrappedStore();
		const outcome = store.hostServiceBindingFence({
			entryKey: "no-such-entry",
			policy: policyPayload(),
			capabilityIncrement: incrementPayload(),
		});
		expect(outcome.ok).toBe(false);
		if (!outcome.ok) expect(outcome.code).toBe("WASM_CATALOG_ENTRY_NOT_FOUND");
	});

	test("limits-within-maxima is the single shared comparison authority", () => {
		expect(
			hostServiceLimitsWithinMaxima(
				sealWasmHostServicePolicyV2(policyPayload()).value.hostServices,
				WASM_HOST_SERVICE_NODE_MAXIMA,
			),
		).toBe(true);
		// 同值边界：limits == maxima 通过（<=）；超出才拒绝。
		const atMaxima = sealWasmHostServicePolicyV2({
			...(policyPayload() as object),
			hostServices: {
				kv: null,
				sql: null,
				logging: {
					profile: "bounded-memory-ring-v1",
					limits: { ...WASM_HOST_SERVICE_NODE_MAXIMA.logging },
					consistency: "append-only-drop-on-full-v1",
					durability: "no-durable-claim-v1",
					retention: "runtime-lifecycle-only-v1",
				},
			},
		});
		if (!atMaxima.ok) throw new Error("fixture error");
		expect(
			hostServiceLimitsWithinMaxima(atMaxima.value.hostServices, WASM_HOST_SERVICE_NODE_MAXIMA),
		).toBe(true);
	});
});
