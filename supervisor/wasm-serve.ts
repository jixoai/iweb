// 用户原始需求（2026-08-27，codex-final 复审 P0-2）：supervisor serve 路径的 wasm executor
//   依赖必须以生产形态注入——策略来源（node capability record 启动门 + admitted manifest
//   只读文件）、retiring 台账（Kernel route-CAS 事实的只读文件投递）、readiness 探测的
//   显式配置项；依赖缺失/无效时拒绝启用（fail-closed），齐备启用后 prepare/start/drain
//   不再因缺依赖而确定性拒绝。
// 正交意图：
//   1. 把 main.ts 的 wasm 装配段提炼为可注入 IO 的装配函数（测试以桩驱动「拒绝启用/
//      注册成功」两端；生产 IO 与 main.ts 原实现同语义）；
//   2. policySource：capability record 文件（validateNodeCapabilityRecordV1 契约校验 +
//      JCS 字节权威）作启动门与每命令能力 pin 复核（checkNodeCapabilityPin）；admitted
//      normalized manifest 按 versionId 键从只读 policy 目录解析，以
//      computeWasmVersionDigestV1 与命令做密码学绑定——缺文件/非规范字节/digest 不符/
//      能力 pin 不符一律 null（prepare/start 以 WASM_EXECUTION_POLICY_UNAVAILABLE
//      确定性拒绝，绝不静默降级）；
//   3. retiring 台账：Kernel 在 route 指针翻转 CAS 建档的 RetiringExecutionRecord 事实
//      以独立只读文件投递（activation RPC 之外的既有 wire 均不承载该记录——命令内嵌字段
//      被 spec 的精确键集刻意排除；取舍见文末备注 1）——启动加载 + drain 未命中时按文件
//      刷新，文件畸形 fail-closed；
//   4. readiness 探测：IWEB_SANDBOX_WASM_READINESS_PROBE=1 显式开启（缺省关闭，readiness
//      保持 "unprobed"——gateway ingress 接线归 5.x），attempts/timeout/interval 可调，
//      畸形数值 fail-closed；fetch 用运行时全局实现。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//   「Supervisor alone generates every argv element ...」「the exact drain deadline supplied
//   by the Kernel capability record」「Wasm readiness is a full identity attestation」。
// 轮次注记（2026-08-28，add-wasm-host-services supervisor 接线层）：catalog/capability record
//   revision 2 接线——可选装配 IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2（WasmHostServiceCapability
//   IncrementV2 启动门 + digestV2(iweb-wasm-capability-record-v2) 复算），并暴露
//   createFileWasmHostServicePolicySource（<versionId>.host-service-policy.json + matrix 增量 +
//   limits<=maxima + V2 versionDigest 绑定）。V1 记录/manifest/digest 语义一字不变；V2 不可证明
//   时返回 null（fail-closed），绝不把 V1 记录解释为 revision 2、也绝不为 V2 版本合成空 policy。
// 轮次注记（2026-08-28，add-wasm-host-services P0-3 supervisor 半边）：启用 V2 时把
//   hostServicePolicySource 注入 executor（未启用 → 不注入，V1 语义零改动）；来源解析产物
//   携带同一 V2 versionDigest 绑定下的 V1 normalized manifest（spawn spec 的 resources/entry
//   layer 输入），调用方不再有第二次独立 manifest 解析。
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { systemStateStoreIO } from "./desired-state.ts";
import { createExecutionRpcHandler, WasmExecutionJournalStore, type ExecutionRpcHandler } from "./wasm-control.ts";
import {
	createWasmSupervisorExecutor,
	sampleWasmEngineMetrics,
	validateWasmRetirementRecordV1,
	WasmRetirementLedger,
	type WasmPolicySource,
	type WasmReadinessProbeOptions,
	type WasmSupervisorExecutor,
} from "./wasm-executor.ts";
import { createPodmanWasmSandboxRuntime, type WasmSandboxRuntime } from "./wasm-runtime.ts";
import type { WasmRuntimeArchitecture } from "./wasm-spawn.ts";
import { SnapshotFdRelayClient } from "./snapshot-fd-relay-client.ts";
import {
	checkNodeCapabilityPin,
	validateNodeCapabilityRecordV1,
	type NodeCapabilityRecordV1,
} from "../packages/contracts/wasm-catalog.ts";
import {
	computeWasmVersionDigestV1,
	jcsCanonicalBytes,
	parseStrictJson,
	parseWasmVersionId,
	validateNormalizedWasmManifestV1,
	type NormalizedWasmManifestV1,
} from "../packages/contracts/wasm-package.ts";
import type { ServiceEngineMetricsV2, WasmEngineMetricsV1 } from "../packages/contracts/wasm-health.ts";
import {
	computeWasmHostServiceVersionDigestV2,
	validateWasmHostServiceCapabilityIncrementV2,
	validateWasmHostServicePolicyV2,
	WASM_CAPABILITY_MATRIX_REVISION_2,
	WASM_HOST_ABI_LITERAL_V2,
	type WasmHostServiceCapabilityIncrementV2,
	type WasmHostServicePolicyV2,
} from "../packages/contracts/wasm-host-policy.ts";
// limits <= record maxima 的逐字段单一权威在 wasm-catalog-store.ts（hostServiceLimitsWithinMaxima）：
// V2 policy 装配（本文件）与 V2 binding fence（catalog-store）共用，绝不建第二套比较语义。
import { hostServiceLimitsWithinMaxima } from "./wasm-catalog-store.ts";

// ---------------------------------------------------------------------------
// 稳定错误码与错误类型（owner 可见；启用失败即 supervisor 启动失败，绝不带病降级）
// ---------------------------------------------------------------------------

export const WASM_SERVE_UNCONFIGURED = "WASM_SERVE_UNCONFIGURED";
export const WASM_SERVE_RELAY_MISSING = "WASM_SERVE_RELAY_MISSING";
export const WASM_SERVE_CAPABILITY_RECORD_INVALID = "WASM_SERVE_CAPABILITY_RECORD_INVALID";
export const WASM_SERVE_RETIREMENTS_FILE_INVALID = "WASM_SERVE_RETIREMENTS_FILE_INVALID";
export const WASM_SERVE_READINESS_CONFIG_INVALID = "WASM_SERVE_READINESS_CONFIG_INVALID";
export const WASM_SERVE_CANONICAL_JSON_INVALID = "WASM_SERVE_CANONICAL_JSON_INVALID";

export class WasmServeError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.name = "WasmServeError";
		this.code = code;
	}
}

// Kernel is the producer for both facts. Deployment must mount this one shared
// directory read-only into the supervisor; a private supervisor state directory
// is never an alternate authority for admitted policy or retirements.
export const KERNEL_WASM_STATE_ROOT = "/data/kernel/wasm";
export const KERNEL_WASM_POLICY_DIRECTORY = KERNEL_WASM_STATE_ROOT + "/admission";
export const KERNEL_WASM_RETIREMENTS_FILE = KERNEL_WASM_STATE_ROOT + "/retirements.json";

function absolutePath(value: string | undefined, fallback: string, name: string): string {
	const normalized = (value ?? fallback).trim();
	if (normalized.length === 0 || !normalized.startsWith("/")) throw new WasmServeError(WASM_SERVE_UNCONFIGURED, name + " must be a non-empty absolute path");
	return normalized;
}

// ---------------------------------------------------------------------------
// 可注入 IO（测试桩替换；systemWasmServeIO 与 main.ts 原内联实现同语义）
// ---------------------------------------------------------------------------

export interface WasmServeIO {
	readFile(path: string): string | null;
}

export const systemWasmServeIO: WasmServeIO = {
	readFile: (path) => {
		try {
			return readFileSync(path, "utf8");
		} catch (error) {
			const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
			if (code === "ENOENT") return null;
			throw error;
		}
	},
};

// 严格 JSON + JCS 字节权威读（wasm-catalog-store 同款纪律：原始字节必须等于
// JCS(parse(raw))；重复键在覆盖前报错）。absent 返回 null；非规范/不可解析抛错。
type CanonicalJsonText = { readonly text: string; readonly value: unknown };

function readCanonicalJson(io: WasmServeIO, path: string, noun: string): CanonicalJsonText | null {
	const text = io.readFile(path);
	if (text === null) return null;
	const parsed = parseStrictJson(text);
	if (!parsed.ok) throw new WasmServeError(WASM_SERVE_CANONICAL_JSON_INVALID, noun + " is not strict JSON: " + path);
	if (Buffer.from(jcsCanonicalBytes(parsed.value)).toString("utf8") !== text) {
		throw new WasmServeError(WASM_SERVE_CANONICAL_JSON_INVALID, noun + " bytes are not canonical JCS: " + path);
	}
	return { text, value: parsed.value };
}

// ---------------------------------------------------------------------------
// node capability record：启动门 + 每命令能力 pin 复核的唯一来源
// ---------------------------------------------------------------------------

function loadCapabilityRecord(io: WasmServeIO, path: string): NodeCapabilityRecordV1 {
	const record = readCanonicalJson(io, path, "node capability record");
	if (record === null) throw new WasmServeError(WASM_SERVE_CAPABILITY_RECORD_INVALID, "the node capability record file is missing: " + path);
	const validated = validateNodeCapabilityRecordV1(record.value);
	if (!validated.ok) {
		const first = validated.errors[0];
		throw new WasmServeError(WASM_SERVE_CAPABILITY_RECORD_INVALID, "the node capability record failed NodeCapabilityRecordV1 validation at " + (first ? first.path : "") + ": " + (first ? first.message : "unknown issue"));
	}
	return validated.value;
}

// ---------------------------------------------------------------------------
// policySource：只读 policy 目录（<versionId>.json）+ capability record pin 复核
// ---------------------------------------------------------------------------

export interface FileWasmPolicySourceOptions {
	/** admitted manifest 的只读目录；文件名 = <versionId>.json，内容为 JCS 规范 manifest。 */
	readonly policyDirectory: string;
	/** pinned NodeCapabilityRecordV1 宿主路径（每命令重读 + pin 复核）。 */
	readonly capabilityRecordPath: string;
}

export function createFileWasmPolicySource(io: WasmServeIO, options: FileWasmPolicySourceOptions): WasmPolicySource {
	return async (command) => {
		try {
			// 能力 pin：命令的 (revision, recordHash) 必须与当前 capability record 精确相等
			//（owner CAS 更新后旧 pin 命令确定性拒绝，Kernel 以新命令重试）。
			const record = loadCapabilityRecord(io, options.capabilityRecordPath);
			const pin = checkNodeCapabilityPin(record, { revision: command.capabilityRecordRevision, recordHash: command.capabilityRecordHash });
			if (!pin.ok) return null;
			// 版本绑定：versionId 携带 versionDigest；文件字节必须在该 digest 下可证明。
			const version = parseWasmVersionId(command.identity.versionId);
			if (!version.ok) return null;
			const manifest = readCanonicalJson(io, join(options.policyDirectory, command.identity.versionId + ".json"), "admitted manifest");
			if (manifest === null) return null;
			const policy = validateNormalizedWasmManifestV1(manifest.value);
			if (!policy.ok) return null;
			// 密码学绑定以盘上字节为准（上方已证 raw == JCS(parse)）。
			if (computeWasmVersionDigestV1(command.packageDigest, Buffer.from(manifest.text, "utf8")) !== version.value.versionDigest) return null;
			return policy.value;
		} catch {
			// 任一环节不可证明 → 无策略（prepare/start 确定性拒绝；不静默降级）。
			return null;
		}
	};
}

// ---------------------------------------------------------------------------
// catalog/capability record revision 2（add-wasm-host-services）：启动门 + policy 装配
// ---------------------------------------------------------------------------

export const WASM_SERVE_CAPABILITY_RECORD_V2_INVALID = "WASM_SERVE_CAPABILITY_RECORD_V2_INVALID";
/** V1 admitted manifest 与 V2 host-service policy 同目录共存（Kernel 投递的只读 admission 目录）。 */
export const WASM_HOST_SERVICE_POLICY_FILE_SUFFIX = ".host-service-policy.json";
/** revision-2 capability increment 宿主路径的环境变量名（可选装配；缺省 = V2 不可用）。 */
export const IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV = "IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2";

/**
 * revision-2 capability increment（matrix 增量 + hostServiceMaxima + recordHash）装载：
 * 文件必须在场、JCS 规范、且通过 validateWasmHostServiceCapabilityIncrementV2 完整校验
 * （recordHash = digestV2("iweb-wasm-capability-record-v2", JCS(increment)) 复算）。
 * 缺失/无效即 fail-closed 抛出（启动门拒绝启用）。
 */
export function loadHostServiceCapabilityIncrementV2(io: WasmServeIO, path: string): WasmHostServiceCapabilityIncrementV2 {
	const record = readCanonicalJson(io, path, "host service capability record v2");
	if (record === null) throw new WasmServeError(WASM_SERVE_CAPABILITY_RECORD_V2_INVALID, "the host service capability record file is missing: " + path);
	const validated = validateWasmHostServiceCapabilityIncrementV2(record.value);
	if (!validated.ok) {
		const first = validated.errors[0];
		throw new WasmServeError(WASM_SERVE_CAPABILITY_RECORD_V2_INVALID, "the host service capability record failed revision-2 validation at " + (first ? first.path : "") + ": " + (first ? first.message : "unknown issue"));
	}
	return validated.value;
}

/** V2 policy 装配的身份输入（versionId 键文件解析 + V2 versionDigest 绑定 + V2 能力 pin 复核）。 */
export interface WasmHostServicePolicyIdentityInput {
	readonly applicationId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	/**
	 * 命令携带的 revision-2 capability recordHash pin（iweb-wasm-capability-record-v2 域）。
	 * 与 V1 policySource 的 checkNodeCapabilityPin 同律：owner 更新 V2 记录后，旧 pin 命令
	 * 确定性 null（fail-closed），绝不以当前记录静默解释旧命令。
	 */
	readonly capabilityRecordHash: string;
}

/**
 * V2 host-service policy 解析产物（policy + 同一 versionDigest 绑定下的 V1 normalized
 * manifest）：spawn spec 组装同时需要两者（resources/entry layer 来自 manifest，host
 * 服务上限来自 policy），且二者由同一 V2 versionDigest 证明联合绑定——绝不给调用方
 * 第二次独立解析（漂移面）。
 */
export interface WasmHostServicePolicyResolutionV2 {
	readonly policy: WasmHostServicePolicyV2;
	readonly normalizedPolicy: NormalizedWasmManifestV1;
}

/**
 * V2 host-service policy 来源（V1 WasmPolicySource 的 revision-2 对偶；ExecutionCommandV2
 * 接线前的类型化 seam）。返回 null = 不可证明（fail-closed）：缺 manifest/policy 文件、
 * 非规范字节、policyDigest 复算不符、matrix/ABI 字面量不符、limits 超 record maxima、
 * V2 versionDigest 与 versionId 不绑定——一律 null，绝不降级到 V1 记录语义。
 */
export type WasmHostServicePolicySource = (identity: WasmHostServicePolicyIdentityInput) => Promise<WasmHostServicePolicyResolutionV2 | null>;

export interface FileWasmHostServicePolicySourceOptions {
	/** 与 V1 admitted manifest 同一只读 policy 目录；V2 policy 文件名 = <versionId>.host-service-policy.json。 */
	readonly policyDirectory: string;
	/** pinned WasmHostServiceCapabilityIncrementV2 宿主路径（每次解析重读 + 复验）。 */
	readonly capabilityRecordV2Path: string;
}

export function createFileWasmHostServicePolicySource(io: WasmServeIO, options: FileWasmHostServicePolicySourceOptions): WasmHostServicePolicySource {
	return async (identity) => {
		try {
			// capability record revision 2：重读 + recordHash（digestV2 域）复算——
			// owner 更新记录后旧 policy 解析确定性 null，Kernel 以新 revision 重新投递。
			const increment = loadHostServiceCapabilityIncrementV2(io, options.capabilityRecordV2Path);
			if (increment.matrixRevision !== WASM_CAPABILITY_MATRIX_REVISION_2 || increment.hostAbi !== WASM_HOST_ABI_LITERAL_V2) return null;
			// V2 能力 pin 复核（V1 checkNodeCapabilityPin 对偶）：命令 pin 必须等于当前记录
			// 复算的 recordHash——不符即不可证明（owner 轮换记录后旧 pin 命令确定性拒绝）。
			if (increment.recordHash !== identity.capabilityRecordHash) return null;
			// V1 normalized manifest（V2 versionDigest 的 normalizedPolicy 输入；文件字节即 JCS 权威）。
			const manifest = readCanonicalJson(io, join(options.policyDirectory, identity.versionId + ".json"), "admitted manifest");
			if (manifest === null) return null;
			const normalized = validateNormalizedWasmManifestV1(manifest.value);
			if (!normalized.ok) return null;
			// V2 host-service policy 文件（sealed：policyDigest = digestV2(policy domain, JCS(payload)) 复算）。
			const hostService = readCanonicalJson(io, join(options.policyDirectory, identity.versionId + WASM_HOST_SERVICE_POLICY_FILE_SUFFIX), "host service policy");
			if (hostService === null) return null;
			const sealed = validateWasmHostServicePolicyV2(hostService.value);
			if (!sealed.ok) return null;
			if (sealed.value.matrixRevision !== WASM_CAPABILITY_MATRIX_REVISION_2 || sealed.value.hostAbi !== WASM_HOST_ABI_LITERAL_V2) return null;
			if (!hostServiceLimitsWithinMaxima(sealed.value.hostServices, increment.hostServiceMaxima)) return null;
			// V2 versionDigest 绑定：versionId 必须以 digestV2(host-identity domain, {packageDigest,
			// normalizedPolicy, hostServicePolicyDigest, matrixRevision:2, hostAbi}) 开头。
			const versionDigest = computeWasmHostServiceVersionDigestV2({
				packageDigest: identity.packageDigest,
				normalizedPolicy: normalized.value,
				hostServicePolicyDigest: sealed.value.policyDigest,
			});
			if (!versionDigest.ok) return null;
			if (!identity.versionId.startsWith(versionDigest.value + "-")) return null;
			return { policy: sealed.value, normalizedPolicy: normalized.value };
		} catch {
			// 任一环节不可证明 → 无 V2 policy（调用方确定性拒绝；不静默降级）。
			return null;
		}
	};
}

// ---------------------------------------------------------------------------
// retiring 台账：Kernel route-CAS 事实的只读文件投影（启动加载 + miss 刷新）
// ---------------------------------------------------------------------------

export class FileBackedWasmRetirementLedger extends WasmRetirementLedger {
	private readonly io: WasmServeIO;
	private readonly path: string;

	constructor(io: WasmServeIO, path: string) {
		super();
		this.io = io;
		this.path = path;
	}

	/**
	 * 从文件重读 Kernel 投递的 retiring 事实（数组；每条经 validateWasmRetirementRecordV1）。
	 * 文件缺省（尚未投递）是合法状态；存在但畸形/重复建档 fail-closed 抛出。
	 */
	loadFromFile(): void {
		const facts = readCanonicalJson(this.io, this.path, "retiring facts file");
		if (facts === null) return;
		if (!Array.isArray(facts.value)) {
			throw new WasmServeError(WASM_SERVE_RETIREMENTS_FILE_INVALID, "the retiring facts file must be a canonical JSON array: " + this.path);
		}
		for (const element of facts.value) {
			const validated = validateWasmRetirementRecordV1(element);
			if (!validated.ok) {
				const first = validated.errors[0];
				throw new WasmServeError(WASM_SERVE_RETIREMENTS_FILE_INVALID, "a retiring fact failed validation at " + (first ? first.path : "") + ": " + (first ? first.message : "unknown issue"));
			}
			// append-only 视图：已在册的事实不重录（文件收缩不遗忘，保守侧）。
			if (super.find(validated.value.drainCommandId) === null) {
				const recorded = this.record(element);
				if (!recorded.ok) {
					throw new WasmServeError(WASM_SERVE_RETIREMENTS_FILE_INVALID, "a retiring fact could not be recorded: " + this.path);
				}
			}
		}
	}

	/** drain 未命中时按文件刷新一次（Kernel 在 supervisor 运行中投递的事实无需重启生效）。 */
	find(drainCommandId: string) {
		const hit = super.find(drainCommandId);
		if (hit !== null) return hit;
		this.loadFromFile();
		return super.find(drainCommandId);
	}
}

// ---------------------------------------------------------------------------
// readiness 探测：显式配置项（缺省关闭 → "unprobed"；gateway 接线归 5.x）
// ---------------------------------------------------------------------------

function requirePositiveIntEnv(environment: Readonly<Record<string, string | undefined>>, name: string, fallback: number, minimum: number): number {
	const raw = environment[name]?.trim();
	if (raw === undefined || raw.length === 0) return fallback;
	const parsed = Number(raw);
	if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > 1_000_000) {
		throw new WasmServeError(WASM_SERVE_READINESS_CONFIG_INVALID, name + " must be an integer >= " + minimum);
	}
	return parsed;
}

function createReadinessProbeFromEnvironment(environment: Readonly<Record<string, string | undefined>>): WasmReadinessProbeOptions | undefined {
	if (environment.IWEB_SANDBOX_WASM_READINESS_PROBE?.trim() !== "1") return undefined;
	// 运行时全局 fetch（Bun/Node 18+ 均有；缺失即配置不可用，fail-closed）。
	const runtimeFetch = (globalThis as { readonly fetch?: (url: string, init: { readonly signal: AbortSignal }) => Promise<{ readonly status: number; text(): Promise<string> }> }).fetch;
	if (runtimeFetch === undefined) {
		throw new WasmServeError(WASM_SERVE_READINESS_CONFIG_INVALID, "the runtime provides no fetch implementation for wasm readiness probing");
	}
	return {
		fetch: (url, options) => runtimeFetch(url, { signal: options.signal }).then(async (response) => ({ status: response.status, body: await response.text() })),
		maxAttempts: requirePositiveIntEnv(environment, "IWEB_SANDBOX_WASM_READINESS_MAX_ATTEMPTS", 5, 1),
		attemptTimeoutMs: requirePositiveIntEnv(environment, "IWEB_SANDBOX_WASM_READINESS_ATTEMPT_TIMEOUT_MS", 2000, 100),
		intervalMs: requirePositiveIntEnv(environment, "IWEB_SANDBOX_WASM_READINESS_INTERVAL_MS", 500, 0),
	};
}

// ---------------------------------------------------------------------------
// serve 装配：依赖齐备 → 注册 executor/execution-rpc；缺失/无效 → 拒绝启用
// ---------------------------------------------------------------------------

export interface AssembleWasmExecutionServicesInput {
	readonly environment: Readonly<Record<string, string | undefined>>;
	readonly stateDirectory: string;
	/** supervisor.sock 所在 runtime 目录；relay 控制 socket 与之同目录（main.ts 既有语义）。 */
	readonly runtimeDirectory: string;
	readonly arch: string;
	readonly io?: WasmServeIO;
	/** 测试注入端口：覆盖 Podman 副作用端口（生产缺省为 createPodmanWasmSandboxRuntime）。 */
	readonly runtime?: WasmSandboxRuntime;
	/**
	 * The already-running native relay. main.ts creates it before this assembly
	 * so the public socket can never fall back to a Node listener without
	 * SO_PEERCRED verification. Tests inject an in-process stub here.
	 */
	readonly relayClient?: Pick<SnapshotFdRelayClient, "lookup" | "spawn" | "discard">;
	/**
	 * logging 权威登记面（第三轮复审）：V2 执行 start/stop 时登记/注销该应用 wasmd
	 * ingress 的 base URL（owner drain/summary 拉取目标；main.ts 以
	 * WasmLoggingIngressRegistry 承载）。缺省不登记（owner 面对该应用 404）。
	 */
	readonly loggingIngressRegistry?: { register(applicationId: string, baseUrl: string): void; unregister(applicationId: string): void };
}

export type WasmExecutionServices =
	| { readonly enabled: false }
	| {
			readonly enabled: true;
			readonly journal: WasmExecutionJournalStore;
			readonly executor: WasmSupervisorExecutor;
			readonly executionRpc: ExecutionRpcHandler;
			readonly sampleEngineMetrics: (sandboxId: string) => WasmEngineMetricsV1 | ServiceEngineMetricsV2 | null;
			/** revision-2 host-service policy 来源（IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2 未配置时为 null；V1 语义不变）。 */
			readonly hostServicePolicySource: WasmHostServicePolicySource | null;
		};

export async function assembleWasmExecutionServices(input: AssembleWasmExecutionServicesInput): Promise<WasmExecutionServices> {
	const environment = input.environment;
	const io = input.io ?? systemWasmServeIO;
	if (environment.IWEB_SANDBOX_WASM_EXECUTION_ENABLED?.trim() !== "1") return { enabled: false };
	const journal = new WasmExecutionJournalStore(systemStateStoreIO, input.stateDirectory);
	const relayClient = input.relayClient;
	if (relayClient === undefined) {
		throw new WasmServeError(WASM_SERVE_RELAY_MISSING, "wasm execution requires the already-authenticated native execution relay from main.ts");
	}

	try {

		// P0-2 capability record 启动门：文件必须在场、JCS 规范、且通过
		// NodeCapabilityRecordV1 完整校验（recordHash 复算）；缺失/无效即拒绝启用。
		const capabilityRecordEnv = environment.IWEB_SANDBOX_WASM_CAPABILITY_RECORD?.trim();
		if (capabilityRecordEnv === undefined || capabilityRecordEnv.length === 0) {
			throw new WasmServeError(WASM_SERVE_UNCONFIGURED, "wasm execution requires IWEB_SANDBOX_WASM_CAPABILITY_RECORD to name the pinned NodeCapabilityRecordV1 host file");
		}
		const capabilityRecordHostPath = absolutePath(capabilityRecordEnv, "", "IWEB_SANDBOX_WASM_CAPABILITY_RECORD");
		loadCapabilityRecord(io, capabilityRecordHostPath);

		// P0-2 policySource：admitted manifest 只读目录（<versionId>.json）。
		const policyDirectory = absolutePath(environment.IWEB_SANDBOX_WASM_POLICY_DIR, KERNEL_WASM_POLICY_DIRECTORY, "IWEB_SANDBOX_WASM_POLICY_DIR");
		const policySource = createFileWasmPolicySource(io, { policyDirectory, capabilityRecordPath: capabilityRecordHostPath });

		// add-wasm-host-services：revision-2 capability increment 启动门（可选装配）。
		// 缺省（环境变量未设置）= V2 host-service policy 不可用（hostServicePolicySource:null），
		// V1 记录/命令语义一字不变；设置了但缺失/无效 → fail-closed 拒绝启用（启动失败）。
		const capabilityRecordV2Env = environment[IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV]?.trim();
		let hostServicePolicySource: WasmHostServicePolicySource | null = null;
		if (capabilityRecordV2Env !== undefined && capabilityRecordV2Env.length > 0) {
			const capabilityRecordV2Path = absolutePath(capabilityRecordV2Env, "", IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2_ENV);
			loadHostServiceCapabilityIncrementV2(io, capabilityRecordV2Path);
			hostServicePolicySource = createFileWasmHostServicePolicySource(io, { policyDirectory, capabilityRecordV2Path });
		}

		// spawn 组装输入（原 main.ts 语义：显式配置；缺 repo → 拒绝启用，不再以
		// WASM_SPAWN_UNCONFIGURED 半配置运行）。
		const runtimeImageRepository = environment.IWEB_SANDBOX_WASM_RUNTIME_IMAGE_REPO?.trim();
		if (runtimeImageRepository === undefined || runtimeImageRepository.length === 0) {
			throw new WasmServeError(WASM_SERVE_UNCONFIGURED, "wasm execution requires IWEB_SANDBOX_WASM_RUNTIME_IMAGE_REPO (bare repository name; the digest comes only from the runtime binding)");
		}
		const architectureByProcess: Record<string, WasmRuntimeArchitecture> = { arm64: "linux/arm64", x64: "linux/amd64" };
		const architecture = architectureByProcess[input.arch];
		if (architecture === undefined) {
			throw new WasmServeError(WASM_SERVE_UNCONFIGURED, "unsupported supervisor architecture for wasm execution: " + input.arch);
		}

		// P0-2 retiring 台账：Kernel 投递事实文件（缺省合法 = 无 retirements）。
		const retirementsPath = absolutePath(environment.IWEB_SANDBOX_WASM_RETIREMENTS_FILE, KERNEL_WASM_RETIREMENTS_FILE, "IWEB_SANDBOX_WASM_RETIREMENTS_FILE");
		const retirements = new FileBackedWasmRetirementLedger(io, retirementsPath);
		retirements.loadFromFile();

		// P0-2 readiness 探测显式配置（缺省关闭 → unprobed；gateway 接线归 5.x）。
		const readinessProbe = createReadinessProbeFromEnvironment(environment);

		const podmanPath = environment.IWEB_SANDBOX_WASM_PODMAN?.trim() || "podman";
		const runtime = input.runtime ?? createPodmanWasmSandboxRuntime({
			exec: (args) => execFileSync(podmanPath, [...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }),
			relay: relayClient,
		});
		const executor = createWasmSupervisorExecutor({
			journal,
			runtime,
			relay: relayClient,
			spawnOptions: { stateDirectory: input.stateDirectory, runtimeImageRepository, capabilityRecordHostPath, architecture },
			policySource,
			// V2 显式启用（IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2 装配成功）才注入；null =
			// 未启用，executor 保持纯 V1 语义（V1 路径零改动）。
			hostServicePolicySource: hostServicePolicySource ?? undefined,
			retirements,
			readinessProbe,
			loggingIngressRegistry: input.loggingIngressRegistry,
		});
		const executionRpc = createExecutionRpcHandler({ journal, executor });
		return {
			enabled: true,
			journal,
			executor,
			executionRpc,
			sampleEngineMetrics: (sandboxId) => sampleWasmEngineMetrics(executor.fence, sandboxId),
			hostServicePolicySource,
		};
	} catch (error) {
		throw error;
	}
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. retiring 事实投递取舍：ExecutionCommandV1 的精确键集刻意不含
//    routeGeneration/deadlineAt/applicationId（receipt 权威字段必须来自 Kernel route-CAS
//    记录，绝不从命令推断），activation RPC 之外的既有 wire 也不承载该记录，因此本批次以
//    「独立只读文件」（JCS 数组，supervisor 状态目录下）作为最简投递形态：Kernel 侧把
//    authorize_retirement 建档的事实投影到该文件（接线归后续任务），supervisor 启动加载、
//    drain 未命中时重读。文件只有记录级契约校验（无签名）——它位于 supervisor 专属状态
//    目录，来源边界由宿主文件系统保证；正式投递通道落地后替换本形态，fence 语义不变。
// 2. capability record 每命令重读：owner CAS 更新记录后，旧 pin 命令确定性拒绝
//    （WASM_EXECUTION_POLICY_UNAVAILABLE），Kernel 以新 revision 重新授权发令；启动门
//    只证明「文件在场且可验证」，不冻结 revision。
// 3. policy 文件按 versionId 键（不是 packageDigest）：versionId 是 spec 钦定进入执行命令
//    的唯一版本身份；同 digest 再准入会分配更高 sequence → 不同 versionId → 不同文件，
//    与 Kernel registry 的 (applicationId, versionId) 版本键一致。
// 4. relay 生命周期由 main.ts 的 socket-relay.ts 统一持有：它先绑定并认证公开 HTTP
//    socket，再把同一 relay client 注入本装配；这里不允许自行 spawn 一个没有 HTTP 前端的
//    FD relay。main.ts 在后续装配失败时回收该子进程。
