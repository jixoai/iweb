// 用户原始需求（2026-08-26，add-wasm-runtime 任务 2.1/2.2 + 归档终审阻塞 2）：supervisor 侧 wasm
//   执行器——消费 Kernel owner-authorized ExecutionCommand，推进（采纳 Kernel 分配的）P/E 代次，
//   产出 typed acknowledgement；失败保持 received-incomplete（由 wasm-control.ts 的
//   resume 路径保证）。执行器维护每 sandbox 的双 generation fence 状态，并把
//   readiness/health v2 与 metrics v1 的 correlate 精确比对接线到该状态上。
// 真实副作用段（归档终审 2，2026-08-26；two-tier-runtime-trust 2026-08-30 去 Podman）：
//   配置 runtime 端口（WasmSandboxRuntime，生产为 relay 注入型 wasmd 子进程）时，
//   prepare 解析/校验 spawn spec 并注记监听索引，start 经 relay FD 3/4 注入启动子进程、
//   drain 优雅停（SIGTERM→预算→SIGKILL）、stop 清理子进程/代持 FD；未配置 runtime 时保持
//   纯 fence 语义（既有行为，供降级观测）。readiness/metrics/journal/command 语义不变
//   （协议不动）。
// 正交意图：supervisor journal 只接受幂等 execution commands——不铸 version、不改 route
//   pointer、不更新 Kernel lifecycle（那些是 Kernel 权威）；旧 execution 可 drain/stop 但
//   绝不作为当前 execution 报告（stale 拒绝路径）；一切 fence 判定复用 packages/contracts
//   纯函数（checkWasmExecutionFence / correlateWasmReadinessHealthV2 /
//   correlateWasmEngineMetricsV1），不造第二套比对语义。
// TODO(7.6 DrainReceiptV1 wire，生产接线已完成)：drain 的 receipt 权威字段
//   （routeGeneration/deadlineAt/applicationId）不在 ExecutionCommand 身份中（契约
//   键集精确，spec 亦未把 routeGeneration 放入命令）；唯一来源是 Kernel 在 route 指针
//   翻转同一 controlRevision CAS 建档的 RetiringExecutionRecord（kernel-rs
//   wasm_commands.rs authorize_retirement）。supervisor 侧以其 wire 形状维护本地台账
//   （WasmRetirementLedger，见下）：drain 命令同步查询，命中且身份 echo 一致才产出
//   DrainReceiptDraftV1（digest 由 wasm-control.ts 在 journalRevision 确定后计算）；
//   无记录/身份不一致/计数不可证明一律拒绝，绝不伪造 digest。Kernel → supervisor 的
//   retiring 事实投递通道（activation RPC 之外的既有 wire 均不承载该记录）属后续任务；
//   台账为空时保持 EXECUTION_DRAIN_RECEIPT_UNAVAILABLE 保守分支。
// TODO(3.x gateway)：gateway/wasmd 侧的 fence 接线留 3.x；本模块暴露
//   correlateReadinessHealthV2 / correlateEngineMetrics 供 ingress 探测与采样上报调用。
// TODO(4.1 engine metrics v1)：executor 内部计数器经 sampleWasmEngineMetrics 构成
//   WasmEngineMetricsV1 wire（supervisor → Kernel）；wasmd 进程内 counters 的真实采集
//   接线点属 5.x——届时以 WasmEngineCounterSource 替换 executorInternalEngineCounterSource，
//   fence/身份语义不变。
// 轮次注记（2026-08-28，add-wasm-host-services P0-3 supervisor 半边）：host-service
//   命令贯穿本执行器——execute 接受 SupervisorExecutionCommand（contracts 单一
//   ExecutionCommand 形态）；resolveSpawnSpec 走 hostServicePolicySource 权限判定
//（policyDigest pin + 能力 pin 复核在来源内）与 buildWasmSandboxSpec（argv@2）；
//   幂等摘要键 = digestV2("iweb-wasm-execution-command-v2", ...)（单一域）。
// 轮次注记（2026-08-29，simplify-wasm-host-services）：单版本化——V1 命令路径与
//   readiness/metrics 的 V1 记录分支删除；readiness/metrics 采纳恒走 contracts
//   ServiceReadinessHealthV2/ServiceEngineMetricsV2 correlate（policy pin 精确比对），
//   采样产出 schemaVersion:2 载荷。
import { createHash as crypto_hash } from "node:crypto";
import {
	checkWasmExecutionFence,
	isAliveWasmExecutionIdentity,
	runtimeBindingIdentityV2FromV1,
	validateRuntimeBindingIdentityV1,
	validateWasmExecutionIdentityV1,
	WASM_UUIDV7_PATTERN,
	type DrainReceiptDraftV1,
	type RuntimeBindingIdentityV1,
	type RuntimeBindingIdentityV2,
	type WasmExecutionIdentityV1,
} from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalBytes, WASM_APPLICATION_ID_PATTERN, WASM_SHA256_HEX_PATTERN, WASM_U53_MAX } from "../packages/contracts/wasm-package.ts";
import { isWasmHostServicePolicyV2Empty, WASM_EMPTY_HOST_SERVICE_POLICY_V2 } from "../packages/contracts/wasm-host-policy.ts";
import { failure, isRecord, issue, ok, type ValidationResult } from "../packages/contracts/validation.ts";
import {
	correlateServiceEngineMetricsV2,
	correlateServiceReadinessHealthV2,
	validateServiceEngineMetricsV2,
	validateServiceReadinessHealthV2,
	type ServiceEngineMetricsFenceFields,
	type ServiceEngineMetricsV2,
	type ServiceReadinessFenceFields,
	type ServiceReadinessHealthV2,
	type WasmEngineCountersV1,
} from "../packages/contracts/wasm-health.ts";
import type { ValidationIssue } from "../packages/contracts/validation.ts";
import type { WasmExecutionJournalStore, WasmExecutionOutcome } from "./wasm-control.ts";
import { READINESS_PATH } from "./wasm-shared.ts";
import {
	buildWasmSandboxSpec,
	computeSupervisorExecutionCommandDigest,
	WASM_HOST_POLICY_DIGEST_MISMATCH,
	WASM_LISTEN_INDEX_MAX,
	WASM_SPAWN_INVALID,
	type SupervisorExecutionCommand,
	type WasmSandboxSpawnOptions,
	type WasmSandboxSpawnSpec,
} from "./wasm-spawn.ts";
// 类型化 seam（import type：零运行时环——wasm-serve 是装配层，方向仍 serve → executor）。
// V2 policy 来源的文件实现归 wasm-serve.ts；本模块只消费其证明产物。
import type { WasmHostServicePolicySource } from "./wasm-serve.ts";
// 备份 quiesce 生命周期通知（第四轮复审 P1）：同样 import type 的结构端口——
// 实现在 wasm-host-backup.ts（wasm-serve 装配注入），executor 只在真实副作用成功后调用。
import type { WasmHostBackupQuiesceNotifier } from "./wasm-host-backup.ts";
import { validateSnapshotHandoffAcceptance, type SnapshotDescriptorFacts, type SnapshotHandoffPayload } from "./snapshot-fd.ts";
import {
	SnapshotFdRelayClient,
	SnapshotFdRelayError,
	SNAPSHOT_HANDOFF_MISSING,
	type SnapshotFdRelayHandoffView,
} from "./snapshot-fd-relay-client.ts";
import { RuntimeFailure, WASM_EXECUTION_SPAWN_FAILED, WASM_SPAWN_RELAY_UNAVAILABLE, type WasmSandboxRuntime, type WasmStopOutcome } from "./wasm-runtime.ts";

// 宿主侧 fail-closed 码（spec 已命名 WASM_IDENTITY_INCOMPLETE 之外的执行器补充码；
// 见文末歧义备注）。
export const WASM_EXECUTION_FENCE_STALE = "WASM_EXECUTION_FENCE_STALE";
export const WASM_EXECUTION_NOT_PREPARED = "WASM_EXECUTION_NOT_PREPARED";
export const EXECUTION_DRAIN_RECEIPT_UNAVAILABLE = "EXECUTION_DRAIN_RECEIPT_UNAVAILABLE";
export const WASM_EXECUTION_WIRE_INVALID = "WASM_EXECUTION_WIRE_INVALID";
// 真实副作用段补充码（spec 未命名；沿用 wasm 系命名风格）：
// - 策略来源缺失（ExecutionCommand 不携带 normalized manifest，supervisor 必须有独立来源）。
export const WASM_EXECUTION_POLICY_UNAVAILABLE = "WASM_EXECUTION_POLICY_UNAVAILABLE";
// - spawn 组装输入未配置（spawnOptions 缺失）。
export const WASM_SPAWN_UNCONFIGURED = "WASM_SPAWN_UNCONFIGURED";

// 执行子状态（spec：retiring 是 supervisor-only executionSubstate，绝不写入 Kernel
// LifecycleState；本模块的 substate 只是 fence 内部记录）。
export type WasmExecutionSubstate = "prepared" | "running" | "retiring" | "stopped";

// readiness 探测的采纳状态（supervisor 侧观测；v2 lease 签发是 Kernel/gateway 权威——
// spec "Wasm readiness is a full identity attestation"）。
export type WasmReadinessAdoptionState = "unprobed" | "adopted" | "mismatch" | "stale" | "not-ready";

export interface WasmAcceptedExecutionRecord {
	readonly identity: WasmExecutionIdentityV1;
	readonly packageDigest: string;
	/** 命令 binding（单一形态恒 ABI 1.1.0；字节原样入册）。 */
	readonly runtimeBinding: RuntimeBindingIdentityV2;
	/** 命令的 policy pin（readiness/metrics correlate 的期望来源）。 */
	readonly hostServicePolicyDigest: string;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly secretSnapshotRef: string;
	readonly secretValuesDigest: string;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly configValuesDigest: string | null;
	readonly substate: WasmExecutionSubstate;
	// 4.1 engine metrics v1 的 executor 内部计数器（每 execution generation 一份，
	// adopt 归零；E 变更即随新记录重建——重置只能来自新 fence，不是旧样本）。
	// wasmd 进程内 counters（fuel/guest memory 的真实读数）属 5.x 采集接线。
	readonly epochTimeoutsCumulative: number;
	readonly instancesHighWaterCumulative: number;
	// 真实副作用段的记录（纯 fence 路径保持 null/"unprobed"）：
	readonly listenIndex: number | null;
	/** 触发本 tuple wasmd 子进程启动的 start command（stop/drain 后释放其代持 FD）。 */
	readonly spawnCommandId: string | null;
	readonly readiness: WasmReadinessAdoptionState;
}

// ---------------------------------------------------------------------------
// fence registry：每 sandbox 的已接受 execution 记录（含历史 tuple，供旧 execution
// drain/stop 与 stale 拒绝判定）。current 永远指向最新被接受的 tuple。
// ---------------------------------------------------------------------------

export class WasmExecutionFenceRegistry {
	private readonly currentBySandbox = new Map<string, WasmAcceptedExecutionRecord>();
	private readonly acceptedByIdentity = new Map<string, WasmAcceptedExecutionRecord>();
	private readonly appliedOutcomes = new Map<string, WasmExecutionOutcome>();

	current(sandboxId: string): WasmAcceptedExecutionRecord | null {
		return this.currentBySandbox.get(sandboxId) ?? null;
	}

	findByIdentity(identity: WasmExecutionIdentityV1): WasmAcceptedExecutionRecord | null {
		return this.acceptedByIdentity.get(fenceKey(identity)) ?? null;
	}

	recordAppliedOutcome(commandDigest: string, outcome: WasmExecutionOutcome): void {
		this.appliedOutcomes.set(commandDigest, outcome);
	}

	findAppliedOutcome(commandDigest: string): WasmExecutionOutcome | null {
		return this.appliedOutcomes.get(commandDigest) ?? null;
	}

	/** 采纳一条新 tuple 作为当前 execution（prepare/start 的新分配）。 */
	adopt(command: SupervisorExecutionCommand, substate: WasmExecutionSubstate): WasmAcceptedExecutionRecord {
		const record: WasmAcceptedExecutionRecord = {
			identity: command.identity,
			packageDigest: command.packageDigest,
			runtimeBinding: command.runtimeBinding,
			hostServicePolicyDigest: command.hostServicePolicyDigest,
			capabilityRecordRevision: command.capabilityRecordRevision,
			capabilityRecordHash: command.capabilityRecordHash,
			secretRevision: command.secretRevision,
			secretSnapshotRef: command.secretSnapshotRef,
			secretValuesDigest: command.secretValuesDigest,
			configRevision: command.configRevision,
			configSnapshotRef: command.configSnapshotRef,
			configValuesDigest: command.configValuesDigest,
			substate,
			// 新 execution generation 的计数器从可证明的零开始（executor 尚未观察到
			// 任何该 E 的事件；zero 只在可证明时出现）。
			epochTimeoutsCumulative: 0,
			instancesHighWaterCumulative: substate === "running" ? 1 : 0,
			listenIndex: null,
			spawnCommandId: null,
			readiness: "unprobed",
		};
		this.currentBySandbox.set(command.identity.sandboxId, record);
		this.acceptedByIdentity.set(fenceKey(command.identity), record);
		return record;
	}

	/** 同步 current 指针的公共不变式（updateSubstate/annotate 共用）。 */
	private syncCurrentIfNotNewer(identity: WasmExecutionIdentityV1, next: WasmAcceptedExecutionRecord): void {
		const current = this.currentBySandbox.get(identity.sandboxId);
		if (current !== undefined && current.identity.executionGeneration <= identity.executionGeneration) {
			this.currentBySandbox.set(identity.sandboxId, next);
		}
	}

	/** 真实副作用段注记：spawn/prepare 成功后记录触发命令与监听索引分配（不改 fence 语义）。 */
	annotateSpawn(identity: WasmExecutionIdentityV1, spawnCommandId: string | null, listenIndex: number): WasmAcceptedExecutionRecord | null {
		const record = this.acceptedByIdentity.get(fenceKey(identity));
		if (record === undefined) return null;
		const next: WasmAcceptedExecutionRecord = { ...record, spawnCommandId, listenIndex };
		this.acceptedByIdentity.set(fenceKey(identity), next);
		this.syncCurrentIfNotNewer(identity, next);
		return next;
	}

	/** readiness 探测结果注记（观测态；绝不影响 substate 与路由围栏）。 */
	annotateReadiness(identity: WasmExecutionIdentityV1, readiness: WasmReadinessAdoptionState): WasmAcceptedExecutionRecord | null {
		const record = this.acceptedByIdentity.get(fenceKey(identity));
		if (record === undefined) return null;
		const next: WasmAcceptedExecutionRecord = { ...record, readiness };
		this.acceptedByIdentity.set(fenceKey(identity), next);
		this.syncCurrentIfNotNewer(identity, next);
		return next;
	}

	/** 就地更新子状态（start/drain/stop 不改变 tuple 归属）。 */
	updateSubstate(identity: WasmExecutionIdentityV1, substate: WasmExecutionSubstate): WasmAcceptedExecutionRecord | null {
		const record = this.acceptedByIdentity.get(fenceKey(identity));
		if (record === undefined) return null;
		const next: WasmAcceptedExecutionRecord = {
			...record,
			substate,
			// 该 E 的存活实例高水位：executor 采纳过 running 即为 1（每 E 恰一个实例），
			// 同 E 内只增不减；live 瞬时值由 substate 推导，不落台账。
			instancesHighWaterCumulative: substate === "running" ? Math.max(record.instancesHighWaterCumulative, 1) : record.instancesHighWaterCumulative,
		};
		this.acceptedByIdentity.set(fenceKey(identity), next);
		this.syncCurrentIfNotNewer(identity, next);
		return next;
	}

	/**
	 * 4.1 计数接线点：记录一次该 execution 的 epoch 终止事件（executor 侧计数）。
	 * 真实事件源（wasmd epoch kill 观察）属 5.x；当前调用方为空，因此计数保持可证明的零。
	 */
	noteEngineEpochTimeout(identity: WasmExecutionIdentityV1): WasmAcceptedExecutionRecord | null {
		const record = this.acceptedByIdentity.get(fenceKey(identity));
		if (record === undefined) return null;
		const next: WasmAcceptedExecutionRecord = { ...record, epochTimeoutsCumulative: record.epochTimeoutsCumulative + 1 };
		this.acceptedByIdentity.set(fenceKey(identity), next);
		this.syncCurrentIfNotNewer(identity, next);
		return next;
	}
}

function fenceKey(identity: WasmExecutionIdentityV1): string {
	return identity.sandboxId + "\n" + identity.versionId + "\n" + identity.preparationGeneration + "\n" + identity.executionGeneration;
}

// 已接受 execution → correlate 期望的平铺 fence 字段（health v2 与 metrics v1 共用；
// WasmAcceptedExecutionRecord 结构性满足两类接口，多出的 secretSnapshotRef/
// configValuesDigest 是无害的额外只读字段——不构成第二套比对语义）。
// simplify-wasm-host-services：单一命令形态（ABI 1.1.0 + policy pin 在身）——
// readiness/metrics 采纳恒走 contracts ServiceReadinessHealthV2/ServiceEngineMetricsV2
// correlate（携带 hostServicePolicyDigest 精确比对；无 V1 分支、无代际分选）。
function serviceFenceFieldsOf(record: WasmAcceptedExecutionRecord): ServiceReadinessFenceFields & ServiceEngineMetricsFenceFields {
	return {
		sandboxId: record.identity.sandboxId,
		versionId: record.identity.versionId,
		packageDigest: record.packageDigest,
		runtimeBinding: record.runtimeBinding,
		hostServicePolicyDigest: record.hostServicePolicyDigest,
		capabilityRecordRevision: record.capabilityRecordRevision,
		capabilityRecordHash: record.capabilityRecordHash,
		secretRevision: record.secretRevision,
		secretValuesDigest: record.secretValuesDigest,
		configRevision: record.configRevision,
		configSnapshotRef: record.configSnapshotRef,
		configValuesDigest: record.configValuesDigest,
		preparationGeneration: record.identity.preparationGeneration,
		executionGeneration: record.identity.executionGeneration,
	};
}

// 已验证值域上的结构相等性：以 JCS 字节为准（与 contracts 的 jcsEqual 同语义；
// binding 对象经 journal JCS round-trip 后键序即 JCS 序，引用比较不可用）。
function jcsEqualValues(left: unknown, right: unknown): boolean {
	try {
		return Buffer.compare(Buffer.from(jcsCanonicalBytes(left)), Buffer.from(jcsCanonicalBytes(right))) === 0;
	} catch {
		return false;
	}
}

// 命令的全量 fence 字段与已记录 execution 是否逐字段一致（package/binding/capability/
// secret/config/policy pin——drain/stop 携带的 adopted snapshot digests 必须与采纳时完全相同）。
function matchesRecordedFenceFields(record: WasmAcceptedExecutionRecord, command: SupervisorExecutionCommand): boolean {
	return (
		record.packageDigest === command.packageDigest &&
		jcsEqualValues(record.runtimeBinding, command.runtimeBinding) &&
		record.hostServicePolicyDigest === command.hostServicePolicyDigest &&
		record.capabilityRecordRevision === command.capabilityRecordRevision &&
		record.capabilityRecordHash === command.capabilityRecordHash &&
		record.secretRevision === command.secretRevision &&
		record.secretSnapshotRef === command.secretSnapshotRef &&
		record.secretValuesDigest === command.secretValuesDigest &&
		record.configRevision === command.configRevision &&
		record.configSnapshotRef === command.configSnapshotRef &&
		record.configValuesDigest === command.configValuesDigest
	);
}

function stale(failureCode: string): WasmExecutionOutcome {
	return { result: "rejected", failureCode, drainReceiptDraft: null };
}

function applied(): WasmExecutionOutcome {
	return { result: "applied", failureCode: null, drainReceiptDraft: null };
}

// ---------------------------------------------------------------------------
// retiring 记录（Kernel route CAS 的 supervisor 对面）：drain receipt 的权威字段来源。
// 形状逐字对位 kernel-rs wasm_commands.rs 的 RetiringExecutionRecord serde wire
// （drainCommandId/applicationId/execution/packageDigest/runtimeBinding/routeGeneration/
// deadlineAtEpochMillis/flipAtEpochMillis/retired/acceptedReceiptDigest）。Kernel 在
// route 指针翻转的同一 controlRevision CAS 里 authorize_retirement 建档（与
// wasm_activation.rs 的 activation store 同提交绑定，Rust 侧已实现）；supervisor 只以
// 本地台账缓存同一判据，drain 命令到达时同步查询——receipt 的 routeGeneration 与
// deadlineAt 只认这份记录，绝不从命令或环境推断。retired/acceptedReceiptDigest 的
// 投影是 Kernel 权威（project_drain_receipt），台账建档即终态只读。
// ---------------------------------------------------------------------------

export interface WasmRetirementRecordV1 {
	/** 对应授权 drain 命令的 commandId（receipt 以它寻址）。 */
	readonly drainCommandId: string;
	readonly applicationId: string;
	readonly execution: WasmExecutionIdentityV1;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	/** 指针翻转前捕捉的 retired route generation（receipt 必须精确相等）。 */
	readonly routeGeneration: number;
	/** capability record 供给的精确 drain deadline（epoch 毫秒）。 */
	readonly deadlineAtEpochMillis: number;
	/** route 指针翻转时刻（deadline 不得早于它）。 */
	readonly flipAtEpochMillis: number;
	/** Kernel lifecycle 投影标记：supervisor 台账恒为 false（建档不变式）。 */
	readonly retired: boolean;
	readonly acceptedReceiptDigest: string | null;
}

export const WASM_RETIREMENT_RECORD_INVALID = "WASM_RETIREMENT_RECORD_INVALID";
export const WASM_RETIREMENT_DUPLICATE_COMMAND = "WASM_RETIREMENT_DUPLICATE_COMMAND";

const RETIREMENT_RECORD_KEYS: readonly string[] = [
	"drainCommandId",
	"applicationId",
	"execution",
	"packageDigest",
	"runtimeBinding",
	"routeGeneration",
	"deadlineAtEpochMillis",
	"flipAtEpochMillis",
	"retired",
	"acceptedReceiptDigest",
];

function requireRetirementEpochMillis(value: unknown, path: string, fieldName: string, errors: ValidationIssue[]): number | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > WASM_U53_MAX) {
		errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, path + "/" + fieldName, fieldName + " must be a u53 epoch-milliseconds integer"));
		return null;
	}
	return value;
}

// 建档不变式（authorize_retirement 对位）：精确键集、身份/绑定/文法校验、deadline 不早于
// 翻转、且只能以未退休形态建档（retired/acceptedReceiptDigest 的改写是 Kernel 的
// project_drain_receipt 权威，supervisor 台账绝不接受已投影形态）。
export function validateWasmRetirementRecordV1(input: unknown): ValidationResult<WasmRetirementRecordV1> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue(WASM_RETIREMENT_RECORD_INVALID, "", "retiring record must be an object")]);
	for (const key of Object.keys(input)) {
		if (!RETIREMENT_RECORD_KEYS.includes(key)) errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/" + key, "unknown field is not allowed"));
	}
	for (const key of RETIREMENT_RECORD_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/" + key, "required field is missing"));
	}
	if (typeof input.drainCommandId !== "string" || !WASM_UUIDV7_PATTERN.test(input.drainCommandId)) {
		errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/drainCommandId", "drainCommandId must be a lower-case UUIDv7"));
	}
	if (typeof input.applicationId !== "string" || !WASM_APPLICATION_ID_PATTERN.test(input.applicationId)) {
		errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/applicationId", "applicationId must be a lower-case application identifier of at most 63 ASCII bytes"));
	}
	if (typeof input.packageDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.packageDigest)) {
		errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/packageDigest", "packageDigest must be a 64-character lower-case hex digest"));
	}
	const execution = validateWasmExecutionIdentityV1(input.execution);
	if (!execution.ok) {
		for (const error of execution.errors) errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/execution", error.message));
	}
	const binding = validateRuntimeBindingIdentityV1(input.runtimeBinding);
	if (!binding.ok) {
		for (const error of binding.errors) errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/runtimeBinding", error.message));
	}
	const routeGeneration = typeof input.routeGeneration === "number" && Number.isSafeInteger(input.routeGeneration) && input.routeGeneration >= 0 && input.routeGeneration <= WASM_U53_MAX ? input.routeGeneration : null;
	if (routeGeneration === null) errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/routeGeneration", "routeGeneration must be a u53 integer"));
	const deadlineAtEpochMillis = requireRetirementEpochMillis(input.deadlineAtEpochMillis, "", "deadlineAtEpochMillis", errors);
	const flipAtEpochMillis = requireRetirementEpochMillis(input.flipAtEpochMillis, "", "flipAtEpochMillis", errors);
	if (input.retired !== false) errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/retired", "a retiring record is created unretired; retirement projection is Kernel authority"));
	if (input.acceptedReceiptDigest !== null) errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/acceptedReceiptDigest", "a retiring record is created without an accepted receipt; projection is Kernel authority"));
	if (
		typeof input.drainCommandId !== "string" ||
		typeof input.applicationId !== "string" ||
		typeof input.packageDigest !== "string" ||
		!execution.ok ||
		!binding.ok ||
		routeGeneration === null ||
		deadlineAtEpochMillis === null ||
		flipAtEpochMillis === null ||
		errors.length
	) {
		return failure(errors);
	}
	if (deadlineAtEpochMillis < flipAtEpochMillis) {
		errors.push(issue(WASM_RETIREMENT_RECORD_INVALID, "/deadlineAtEpochMillis", "the drain deadline supplied by the capability record must not precede the route flip"));
		return failure(errors);
	}
	return ok({
		drainCommandId: input.drainCommandId,
		applicationId: input.applicationId,
		execution: execution.value,
		packageDigest: input.packageDigest,
		runtimeBinding: binding.value,
		routeGeneration,
		deadlineAtEpochMillis,
		flipAtEpochMillis,
		retired: false,
		acceptedReceiptDigest: null,
	});
}

// supervisor 本地台账：每条 drain command 恰好一条 retiring 记录（重复建档 fail-closed）。
// Kernel → supervisor 的投递通道属后续任务（见文件头 TODO）；在此之前台账由宿主/测试
// 注入，未命中即 EXECUTION_DRAIN_RECEIPT_UNAVAILABLE。
export class WasmRetirementLedger {
	private readonly byDrainCommandId = new Map<string, WasmRetirementRecordV1>();

	record(input: unknown): ValidationResult<WasmRetirementRecordV1> {
		const validated = validateWasmRetirementRecordV1(input);
		if (!validated.ok) return validated;
		if (this.byDrainCommandId.has(validated.value.drainCommandId)) {
			return failure([issue(WASM_RETIREMENT_DUPLICATE_COMMAND, "/drainCommandId", "a retiring execution is recorded once per drain command")]);
		}
		this.byDrainCommandId.set(validated.value.drainCommandId, validated.value);
		return ok(validated.value);
	}

	find(drainCommandId: string): WasmRetirementRecordV1 | null {
		return this.byDrainCommandId.get(drainCommandId) ?? null;
	}
}

// ---------------------------------------------------------------------------
// drain receipt 的可证明输入：计数源与时钟
// ---------------------------------------------------------------------------

// drainedRequestCount 的来源（spec：计数 route CAS 之前获准的请求）。网关 ingress 的
// 获准计数接线属 5.x；内置计数源只报告本执行通道可证明的事实——supervisor 执行通道
// 从未获准任何访客请求（无网关接线即无获准事件），零是可证明零，不是占位。
export type WasmDrainRequestCounterSource = (retirement: WasmRetirementRecordV1, command: SupervisorExecutionCommand) => number;

export function provenZeroDrainRequestCounterSource(): WasmDrainRequestCounterSource {
	return () => 0;
}

// epoch 毫秒 → RFC3339-UTC（毫秒精度）：receipt.deadlineAt 必须与 retiring 记录的
// deadlineAtEpochMillis 精确往返（Kernel 侧 project_drain_receipt 按毫秒相等校验）。
export function epochMillisToRfc3339Utc(epochMillis: number): string {
	return new Date(epochMillis).toISOString();
}

// retiring 记录与 drain 命令的身份 echo：execution tuple、package、binding 任一不符
// 即拒绝（对位 Kernel correlate_drain_receipt 的 receipt 侧检查；此处是命令侧前置）。
function matchesRetirementFence(retirement: WasmRetirementRecordV1, command: SupervisorExecutionCommand): boolean {
	// retirement 的 binding 是 admission 事实形（ABI 1.0.0）；命令 binding 是单版本 wire 形
	//（ABI 1.1.0）——以 runtimeBindingIdentityV2FromV1 归一比较（Rust 对位语义）。
	const normalized = runtimeBindingIdentityV2FromV1(retirement.runtimeBinding);
	return (
		normalized.ok &&
		checkWasmExecutionFence(retirement.execution, command.identity).ok &&
		retirement.packageDigest === command.packageDigest &&
		jcsEqualValues(normalized.value, command.runtimeBinding)
	);
}

// ---------------------------------------------------------------------------
// supervisor 执行器：消费命令 → 推进 P/E 采纳 → 产出 outcome
// ---------------------------------------------------------------------------

export interface WasmSupervisorExecutor {
	readonly fence: WasmExecutionFenceRegistry;
	/** 幂等执行（同命令 digest 同结果）。输入 = contracts ExecutionCommand 单一形态。 */
	execute(command: SupervisorExecutionCommand): Promise<WasmExecutionOutcome>;
	/**
	 * epoch 终止事件入口（4.1 metrics 计数源）：记录到该 tuple 的 executor 侧计数器。
	 * 真实事件源（wasmd epoch kill 观察）属 5.x；本入口是唯一计数通道。
	 */
	noteEpochTimeout(identity: WasmExecutionIdentityV1): WasmAcceptedExecutionRecord | null;
}

/** start 成功后的可选 readiness 探测（v2 payload 校验 → fence 采纳注记；不翻转命令结果）。 */
export interface WasmReadinessProbeOptions {
	readonly fetch: (url: string, options: { readonly signal: AbortSignal }) => Promise<{ readonly status: number; readonly body: string }>;
	readonly maxAttempts?: number;
	readonly attemptTimeoutMs?: number;
	readonly intervalMs?: number;
	readonly sleep?: (ms: number) => Promise<void>;
}

export interface WasmSupervisorExecutorOptions {
	/** 提供 journal 时，构造即从 journal 条目重建 fence 状态（supervisor 重启恢复）。 */
	readonly journal?: WasmExecutionJournalStore;
	/** Kernel admission objects 根（组件 blob 来源）；缺省为生产固定路径。 */
	readonly admissionObjectsDirectory?: string;
	/** drain receipt 权威台账（Kernel route CAS 对面）；缺省无台账 → drain 恒不可证明。 */
	readonly retirements?: WasmRetirementLedger;
	/** drainedRequestCount 来源；缺省为可证明零（见 provenZeroDrainRequestCounterSource）。 */
	readonly drainCounterSource?: WasmDrainRequestCounterSource;
	/** 执行器时钟（receipt 的 completedAt/forcedKillAt 判定）；缺省真实时钟。 */
	readonly now?: () => string;
	// --- 真实副作用段（归档终审 2；全部可注入，测试以桩实现） ---
	/** 进程副作用端口（生产为 relay 注入型 wasmd 子进程）；未配置 = 纯 fence 语义（无副作用，既有行为）。 */
	readonly runtime?: WasmSandboxRuntime;
	/** 原生 relay 控制客户端（start 的 handoff 复核 + stop 的代持 FD 释放；消费面 =
	 * lookup/discard——codex-final P0-2 放宽为结构端口，wasm-serve 装配与测试桩均可注入）。 */
	readonly relay?: Pick<SnapshotFdRelayClient, "lookup" | "discard">;
	/**
	 * host-service policy 来源（wasm-serve 装配；normalized manifest 也由它解析）。
	 * 缺少来源或解析不可证明 → WASM_EXECUTION_POLICY_UNAVAILABLE；resolved policy 与
	 * 命令 pin 不符 → WASM_HOST_POLICY_DIGEST_MISMATCH（权限判定）。限额判定
	 *（limits<=maxima、versionDigest 绑定）由来源内部证明，本层不重复实现。
	 */
	readonly hostServicePolicySource?: WasmHostServicePolicySource;
	/** spawn 组装输入（wasm-spawn.ts WasmSandboxSpawnOptions，除 listenIndex 外）。 */
	readonly spawnOptions?: Omit<WasmSandboxSpawnOptions, never>;
	/**
	 * logging 权威接线的登记面（第三轮复审）：V2（host-service）执行 start 成功后登记
	 * 该应用 wasmd ingress 的 base URL（owner drain/summary 拉取目标），stop/drain 后
	 * 注销——L1 生命周期内「无活执行 = 无环」由 404 如实表达。V1 命令不携带
	 * applicationId，恒不登记。
	 */
	readonly loggingIngressRegistry?: { register(applicationId: string, baseUrl: string): void; unregister(applicationId: string): void };
	/**
	 * 备份 quiesce 生命周期通知面（第四轮复审 P1）：V2（host-service）执行 start 真实
	 * spawn 成功 → onExecutionStarted（活动写入窗口开始）；drain/stop 的进程终止确认 →
	 * onExecutionSettled。通知只在真实副作用成功路径发出（纯 fence 路径无进程即无写入），
	 * 失败路径不通知（保守保持「活动」标记——宁可拒绝捕获，绝不让备份时点混批）。
	 * V1 命令不携带 applicationId 且无 host-service 数据目录，恒不通知。
	 */
	readonly backupQuiesceNotifier?: WasmHostBackupQuiesceNotifier;
	/** 监听索引分配器；缺省为按 sandboxId 的确定性最低空闲分配。 */
	readonly allocateListenIndex?: (sandboxId: string) => number;
	/** start 成功后的 readiness 探测（可选；缺省不探测，readiness 保持 "unprobed"）。 */
	readonly readinessProbe?: WasmReadinessProbeOptions;
}

/** 缺省监听索引分配器：每 sandboxId 稳定的最低空闲 index（journal 重建按同序重放可得同值）。 */
export function createDeterministicListenIndexAllocator(): (sandboxId: string) => number {
	const assigned = new Map<string, number>();
	return (sandboxId: string): number => {
		const existing = assigned.get(sandboxId);
		if (existing !== undefined) return existing;
		const used = new Set(assigned.values());
		for (let index = 0; index <= WASM_LISTEN_INDEX_MAX; index += 1) {
			if (!used.has(index)) {
				assigned.set(sandboxId, index);
				return index;
			}
		}
		throw new RuntimeFailure("conflict", "wasm execution listen index pool is exhausted");
	};
}

/** Kernel admission objects 的版本 blob 目录（<dir>/<applicationId>/<versionId>/blobs/<hex>）。 */
export const ADMISSION_OBJECTS_DIRECTORY_DEFAULT = "/data/kernel/wasm/admission-objects/admission-object";
export const WASM_COMPONENT_MATERIALIZE_FAILED = "WASM_COMPONENT_MATERIALIZE_FAILED";

/**
 * 组件物化：从 Kernel admission objects 的内容寻址 blob 复制 entry layer 到
 * supervisor 状态目录（wasmComponentSnapshotPath 布局），sha256 逐字复核，幂等
 * （目标已存在且 digest 相同即成功）。返回 null = 成功；否则稳定失败码。
 */
function materializeComponentSnapshot(command: SupervisorExecutionCommand, targetPath: string, entryLayerDigest: string, objectsDirectory: string): string | null {
	const fs = require("node:fs") as typeof import("node:fs");
	const crypto = require("node:crypto") as typeof import("node:crypto");
	const nodePath = require("node:path") as typeof import("node:path");
	const hex = entryLayerDigest.replace(/^sha256:/, "");
	const source = `${objectsDirectory}/${command.applicationId}/${command.identity.versionId}/blobs/${hex}`;
	const sha256Of = (bytes: Buffer): string => crypto.createHash("sha256").update(bytes).digest("hex");
	try {
		const existing = fs.readFileSync(targetPath);
		if (sha256Of(existing) === hex) return null;
	} catch {
		// 目标缺席 = 正常首备路径。
	}
	let blob: Buffer;
	try {
		blob = fs.readFileSync(source);
	} catch {
		return WASM_COMPONENT_MATERIALIZE_FAILED;
	}
	if (sha256Of(blob) !== hex) return WASM_COMPONENT_MATERIALIZE_FAILED;
	try {
		fs.mkdirSync(nodePath.dirname(targetPath), { recursive: true, mode: 0o700 });
		fs.writeFileSync(targetPath, blob, { mode: 0o600 });
	} catch {
		return WASM_COMPONENT_MATERIALIZE_FAILED;
	}
	return null;
}

export function createWasmSupervisorExecutor(options: WasmSupervisorExecutorOptions = {}): WasmSupervisorExecutor {
	const fence = new WasmExecutionFenceRegistry();
	const retirements = options.retirements;
	const runtime = options.runtime;
	const relay = options.relay;
	const allocateListenIndex = options.allocateListenIndex ?? createDeterministicListenIndexAllocator();
	const drainCounterSource = options.drainCounterSource ?? provenZeroDrainRequestCounterSource();
	const now = options.now ?? (() => new Date().toISOString());
	const loggingIngress = options.loggingIngressRegistry;
	const backupQuiesce = options.backupQuiesceNotifier;

	// drain 的纯 fence 前置（decide 与真实副作用段共用）：目标 tuple 曾被采纳、adopted
	// snapshot digests 一致、retiring 台账命中且身份 echo 一致；失败路径同步推进 substate。
	type DrainPreflight =
		| { readonly ok: false; readonly outcome: WasmExecutionOutcome }
		| { readonly ok: true; readonly retirement: WasmRetirementRecordV1 };
	const drainPreflight = (command: SupervisorExecutionCommand): DrainPreflight => {
		const target = fence.findByIdentity(command.identity);
		if (target === null) return { ok: false, outcome: stale(WASM_EXECUTION_FENCE_STALE) };
		if (!matchesRecordedFenceFields(target, command)) return { ok: false, outcome: stale(WASM_EXECUTION_FENCE_STALE) };
		if (target.substate === "stopped") return { ok: false, outcome: stale(WASM_EXECUTION_FENCE_STALE) };
		const retirement = retirements === undefined ? null : retirements.find(command.commandId);
		if (retirement === null) {
			fence.updateSubstate(command.identity, "retiring");
			return { ok: false, outcome: stale(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE) };
		}
		if (!matchesRetirementFence(retirement, command)) {
			fence.updateSubstate(command.identity, "retiring");
			return { ok: false, outcome: stale(WASM_EXECUTION_FENCE_STALE) };
		}
		return { ok: true, retirement };
	};

	const applyCommand = async (command: SupervisorExecutionCommand): Promise<WasmExecutionOutcome> => {
		// 幂等键：V1 命令 = iweb-execution-command-v1 域 digest（原语义一字不变）；V2 seam
		// 命令 = digestV2("iweb-wasm-execution-command-v2", JCS(command))——两域互不碰撞。
		const commandDigest = computeSupervisorExecutionCommandDigest(command);
		const remembered = fence.findAppliedOutcome(commandDigest);
		if (remembered !== null) return remembered;

		const outcome = await perform(command);
		fence.recordAppliedOutcome(commandDigest, outcome);
		return outcome;
	};

	// 命令执行 = 纯 fence 决策 + （配置 runtime 时的）真实副作用。确定性失败 → rejected
	// （回 journal 终态）；意外异常向上抛（wasm-control 捕获 → received-incomplete，replay 恢复）。
	const perform = async (command: SupervisorExecutionCommand): Promise<WasmExecutionOutcome> => {
		if (runtime === undefined) return decide(command);
		switch (command.operation) {
			case "drain":
				return performDrainWithRuntime(command, runtime);
			case "prepare":
			case "start":
			case "stop": {
				const decision = decide(command);
				if (decision.result === "rejected") return decision;
				if (command.operation === "prepare") return effectPrepare(command, decision);
				if (command.operation === "start") return effectStart(command, decision, runtime);
				return effectStop(command, decision, runtime);
			}
			default:
				return decide(command);
		}
	};

	// spawn spec 组装（policy 来源 + 监听索引分配 + wasm-spawn.ts 单一 argv 权威）。
	// 权限/限额判定：非空 policy 必须经 hostServicePolicySource 可证明地解析（文件来源内部
	// 已证 limits<=maxima 与 versionDigest 绑定），且 resolved policy 的 policyDigest
	// 必须等于命令 pin——Kernel 只授权它准入过的策略字节。空串 pin（policyless 准入行，
	// simplify-wasm-host-services 单一命令 wire）不消费 policy 文件面：supervisor 直接以
	// 契约零值策略（三服务全 null、storageBytes 0、ABI 1.1.0、policyDigest ""）进 spawn；
	// 来源仍须以 policyless 半边（manifest + V1 versionDigest 绑定）解析出同一零值——
	// 磁盘事实与命令 pin 不一致即 MISMATCH，绝不给空串 pin 携带 sealed 策略字节。
	const resolveSpawnSpec = async (command: SupervisorExecutionCommand): Promise<{ readonly ok: true; readonly spec: WasmSandboxSpawnSpec; readonly listenIndex: number } | { readonly ok: false; readonly code: string }> => {
		if (options.spawnOptions === undefined) return { ok: false, code: WASM_SPAWN_UNCONFIGURED };
		if (options.hostServicePolicySource === undefined) return { ok: false, code: WASM_EXECUTION_POLICY_UNAVAILABLE };
		const listenIndex = allocateListenIndex(command.identity.sandboxId);
		const resolved = await options.hostServicePolicySource({ applicationId: command.applicationId, versionId: command.identity.versionId, packageDigest: command.packageDigest, capabilityRecordHash: command.capabilityRecordHash });
		if (resolved === null || resolved === undefined) return { ok: false, code: WASM_EXECUTION_POLICY_UNAVAILABLE };
		if (command.hostServicePolicyDigest === "" && !isWasmHostServicePolicyV2Empty(resolved.policy)) {
			return { ok: false, code: WASM_HOST_POLICY_DIGEST_MISMATCH };
		}
		const hostServicePolicy = command.hostServicePolicyDigest === "" ? WASM_EMPTY_HOST_SERVICE_POLICY_V2 : resolved.policy;
		if (hostServicePolicy.policyDigest !== command.hostServicePolicyDigest) return { ok: false, code: WASM_HOST_POLICY_DIGEST_MISMATCH };
		const spec = buildWasmSandboxSpec({ command, policy: resolved.normalizedPolicy, hostServicePolicy }, { ...options.spawnOptions, listenIndex });
		if (!spec.ok) {
			const first = spec.errors[0];
			return { ok: false, code: first !== undefined && typeof first.code === "string" ? first.code : WASM_SPAWN_INVALID };
		}
		return { ok: true, spec: spec.value, listenIndex, entryLayerDigest: resolved.normalizedPolicy.runtime.entryLayerDigest };
	};

	// RuntimeFailure → 确定性 rejected（Kernel 以新命令重试；同命令 replay 返回存档 ack，
	// 避免同命令半成品循环）；其余异常向上抛（received-incomplete）。
	const runtimeFailureOutcome = (error: unknown, operation: string): WasmExecutionOutcome => {
		if (error instanceof RuntimeFailure) {
			// 拒绝码保持稳定；具体原因进 stderr（owner 诊断面——relay 拒绝码/基础设施
			// 分类只在 message 里，不落 journal）。
			console.error("iweb-supervisor: execution rejected [" + operation + "]: " + error.kind + ": " + error.message);
			return { result: "rejected", failureCode: WASM_EXECUTION_SPAWN_FAILED, drainReceiptDraft: null };
		}
		throw error instanceof Error ? error : new Error(operation + " side effect failed");
	};

	// prepare（进程口径）：无进程副作用——只做 spawn spec 的可证明解析（策略来源、权限 pin、
	// argv 组装），失败确定性拒绝；成功注记监听索引。wasmd 子进程的启动只发生在 start。
	const effectPrepare = async (command: SupervisorExecutionCommand, decision: WasmExecutionOutcome): Promise<WasmExecutionOutcome> => {
		const built = await resolveSpawnSpec(command);
		if (!built.ok) return stale(built.code);
		// 组件物化（生产实证 2026-08-31：此前无人写 wasm-components/，wasmd 因组件缺失
		// 秒死）。从 Kernel admission objects 的内容寻址 blob 取 entry layer，sha256 复核
		// 后幂等落盘到 supervisor 状态目录；任何偏差 fail-closed 拒绝 prepare。
		const materialized = materializeComponentSnapshot(command, built.spec.componentPath, built.entryLayerDigest, options.admissionObjectsDirectory ?? ADMISSION_OBJECTS_DIRECTORY_DEFAULT);
		if (materialized !== null) return stale(materialized);
		fence.annotateSpawn(command.identity, null, built.listenIndex);
		return decision;
	};

	const effectStart = async (command: SupervisorExecutionCommand, decision: WasmExecutionOutcome, activeRuntime: WasmSandboxRuntime): Promise<WasmExecutionOutcome> => {
		const built = await resolveSpawnSpec(command);
		if (!built.ok) return stale(built.code);
		// handoff 复核：relay 代持视图 + fd 字节 → snapshot-fd.ts 的同一判定链（不造第二套）。
		if (relay === undefined) return stale(WASM_SPAWN_RELAY_UNAVAILABLE);
		let secretView: SnapshotFdRelayHandoffView | null;
		let configView: SnapshotFdRelayHandoffView | null;
		try {
			const lookup = await relay.lookup(command.commandId);
			secretView = lookup.secret;
			configView = lookup.config;
		} catch (error) {
			if (error instanceof SnapshotFdRelayError) return stale(WASM_SPAWN_RELAY_UNAVAILABLE);
			throw error;
		}
		if (secretView === null) return stale(SNAPSHOT_HANDOFF_MISSING);
		const nowStamp = now();
		const secretHandoff = handoffOfView(secretView);
		const descriptorFacts: SnapshotDescriptorFacts = { regularFile: secretView.descriptorRegularFile, readOnly: secretView.descriptorReadOnly };
		const secretAcceptance = validateSnapshotHandoffAcceptance({
			command,
			handoff: secretHandoff,
			descriptorFacts,
			fdBytes: Buffer.from(secretView.fdBytesBase64, "base64"),
			now: nowStamp,
		});
		if (!secretAcceptance.ok) return stale(secretAcceptance.code);
		if (command.configRevision > 0) {
			if (configView === null) return stale(SNAPSHOT_HANDOFF_MISSING);
			const configHandoff = handoffOfView(configView);
			const configAcceptance = validateSnapshotHandoffAcceptance({
				command,
				handoff: configHandoff,
				descriptorFacts: { regularFile: configView.descriptorRegularFile, readOnly: configView.descriptorReadOnly },
				fdBytes: Buffer.from(configView.fdBytesBase64, "base64"),
				now: nowStamp,
			});
			if (!configAcceptance.ok) return stale(configAcceptance.code);
		} else if (configView !== null) {
			// configRevision:0 却收到 config 帧：身份冲突（spec：FD 4 MUST be absent）。
			return stale("SNAPSHOT_HANDOFF_ID_CONFLICT");
		}
		try {
			await activeRuntime.spawnExecution(command.commandId, built.spec);
		} catch (error) {
			return runtimeFailureOutcome(error, "start");
		}
		fence.annotateSpawn(command.identity, command.commandId, built.listenIndex);
		// logging 权威登记：owner drain/summary 从本 wasmd ingress 拉取。
		if (loggingIngress !== undefined) {
			// 与 wasmd host_logging_access_token 同式：sha256 前 32 hex
				const tokenInput = `iweb-host-logging-token\x00${command.applicationId}\x00${command.identity.versionId}\x00${command.identity.preparationGeneration}\x00${command.identity.executionGeneration}`;
				const token = crypto_hash("sha256").update(tokenInput).digest("hex").slice(0, 32);
				loggingIngress.register(command.applicationId, "http://" + built.spec.listenAddress, token);
		}
		// 备份 quiesce 通知：真实 spawn 成功即活动写入窗口开始（第四轮复审 P1）。
		if (backupQuiesce !== undefined) {
			backupQuiesce.onExecutionStarted(command.applicationId, command.hostServicePolicyDigest, command.identity);
		}
		// 可选 readiness 探测：结果只注记观测态（lease 签发是 Kernel/gateway 权威）。
		if (options.readinessProbe !== undefined) {
			const adoption = await probeWasmExecutionReadiness(fence, command.identity.sandboxId, "http://" + built.spec.listenAddress, options.readinessProbe);
			fence.annotateReadiness(command.identity, adoption);
		}
		return decision;
	};

	const effectStop = async (command: SupervisorExecutionCommand, decision: WasmExecutionOutcome, activeRuntime: WasmSandboxRuntime): Promise<WasmExecutionOutcome> => {
		const target = fence.findByIdentity(command.identity);
		if (loggingIngress !== undefined) {
			loggingIngress.unregister(command.applicationId);
		}
		try {
			await activeRuntime.removeSandbox(command.identity.sandboxId);
			// 释放触发 spawn 的命令的代持 FD（spawn 失败重放可能仍持有）。
			if (relay !== undefined && target !== null && target.spawnCommandId !== null) {
				await relay.discard(target.spawnCommandId);
			}
		} catch (error) {
			return runtimeFailureOutcome(error, "stop");
		}
		// 备份 quiesce 通知（V2 执行）：与 logging 注销不同，静止通知放在子进程清理成功
		// 之后——removeSandbox 失败时执行状态未知，保守保持「活动」标记（误报活动只是
		// 拒绝捕获；误报静止会让备份捕获到在飞写入）。重复通知幂等（resume/replay 重放）。
		if (backupQuiesce !== undefined) {
			backupQuiesce.onExecutionSettled(command.applicationId, command.identity);
		}
		return decision;
	};

	// drain（真实副作用版）：前置 fence → 优雅停（deadline 预算）→ 强杀兜底 → receipt 草稿。
	const performDrainWithRuntime = async (command: SupervisorExecutionCommand, activeRuntime: WasmSandboxRuntime): Promise<WasmExecutionOutcome> => {
		const preflight = drainPreflight(command);
		if (!preflight.ok) return preflight.outcome;
		const retirement = preflight.retirement;
		const target = fence.findByIdentity(command.identity);
		const completedAtBefore = now();
		const budgetMs = retirement.deadlineAtEpochMillis - Date.parse(completedAtBefore);
		let stop: WasmStopOutcome;
		try {
			stop = await activeRuntime.stopExecution(command.identity.sandboxId, Number.isNaN(budgetMs) ? 0 : Math.max(0, budgetMs));
		} catch (error) {
			fence.updateSubstate(command.identity, "retiring");
			return runtimeFailureOutcome(error, "drain");
		}
		const completedAt = now();
		const completedAtMillis = Date.parse(completedAt);
		const drainedRequestCount = drainCounterSource(retirement, command);
		// 不可证明的时钟或计数 → 不伪造 receipt（与纯 fence 路径同一判据）。
		if (Number.isNaN(completedAtMillis) || typeof drainedRequestCount !== "number" || !Number.isSafeInteger(drainedRequestCount) || drainedRequestCount < 0 || drainedRequestCount > WASM_U53_MAX) {
			fence.updateSubstate(command.identity, "retiring");
			return stale(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
		}
		const deadlineAt = epochMillisToRfc3339Utc(retirement.deadlineAtEpochMillis);
		if (target !== null && target.spawnCommandId !== null && relay !== undefined) {
			// 容器已停：释放代持 FD（失败向上抛 → received-incomplete，replay 幂等恢复）。
			// （进程口径下 stopExecution 返回即进程终止已确认；discard 语义不变。）
			await relay.discard(target.spawnCommandId);
		}
		// logging 权威注销：进程停止后环随进程消亡（L1 生命周期限定）。
		if (loggingIngress !== undefined) {
			loggingIngress.unregister(command.applicationId);
		}
		// 备份 quiesce 通知（V2 执行）：stopExecution 返回（stopped/forced-kill）即进程
		// 终止已确认——静止与 receipt 可证明性无关，两种结果都释放该 execution 的活动
		// 标记；stopExecution 抛错的 catch 路径保持活动（未知状态按在飞处理）。
		if (backupQuiesce !== undefined) {
			backupQuiesce.onExecutionSettled(command.applicationId, command.identity);
		}
		if (stop.result === "forced-kill" && completedAtMillis < retirement.deadlineAtEpochMillis) {
			// 端口在 deadline 前报告强杀 = 预算违约：forcedKillAt 必须 >= deadlineAt（spec），
			// 此时不存在可诚实写出的 receipt——不伪造，保持可证明性失败（replay/Kernel 侧对账）。
			fence.updateSubstate(command.identity, "stopped");
			return stale(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
		}
		if (stop.result === "stopped") {
			// 优雅停止完成：drained（forcedKillAt 恒 null），子状态保持 retiring
			//（Kernel 投影 retired 由 receipt 驱动；后续 stop 命令做最终清理）。
			fence.updateSubstate(command.identity, "retiring");
			const draft: DrainReceiptDraftV1 = {
				schemaVersion: 1,
				commandId: command.commandId,
				applicationId: retirement.applicationId,
				execution: command.identity,
				packageDigest: command.packageDigest,
				runtimeBinding: retirement.runtimeBinding,
				routeGeneration: retirement.routeGeneration,
				drainedRequestCount,
				deadlineAt,
				forcedKillAt: null,
				result: "drained",
				completedAt,
			};
			return { result: "applied", failureCode: null, drainReceiptDraft: draft };
		}
		// 强杀：forcedKillAt 记录本执行器作出/确认强杀的时刻（>= deadline 由校验器复验）。
		fence.updateSubstate(command.identity, "stopped");
		const draft: DrainReceiptDraftV1 = {
			schemaVersion: 1,
			commandId: command.commandId,
			applicationId: retirement.applicationId,
			execution: command.identity,
			packageDigest: command.packageDigest,
			runtimeBinding: retirement.runtimeBinding,
			routeGeneration: retirement.routeGeneration,
			drainedRequestCount,
			deadlineAt,
			forcedKillAt: completedAt,
			result: "forced-kill",
			completedAt,
		};
		return { result: "applied", failureCode: null, drainReceiptDraft: draft };
	};

	// 单命令决策（纯 fence 层；无 runtime 配置时的完整路径，drain/stop 的时序判定在此）。
	const decide = (command: SupervisorExecutionCommand): WasmExecutionOutcome => {
		switch (command.operation) {
			case "prepare": {
				const current = fence.current(command.identity.sandboxId);
				if (current !== null) {
					// 同 tuple 的重复 prepare（received-incomplete 的 resume/replay）：按其
					// 存储 fence 幂等续跑（spec replay 条款"resumes exactly its recorded
					// operation under its stored fence"），不视为回退；副作用由 perform 层
					// 重新执行，此处只重新确认采纳（不 adopt、不重置 substate）。
					const sameTuple = checkWasmExecutionFence(current.identity, command.identity);
					if (sameTuple.ok && matchesRecordedFenceFields(current, command)) {
						return applied();
					}
					// Kernel 分配单调不回退：新 tuple 必须非回退且至少一个代次严格更高；
					// 回退或原地复用均为 stale（绝不把旧 tuple 再当作新 preparation）。
					const preparationHigher = command.identity.preparationGeneration > current.identity.preparationGeneration;
					const executionHigher = command.identity.executionGeneration > current.identity.executionGeneration;
					const noRegression =
						command.identity.preparationGeneration >= current.identity.preparationGeneration &&
						command.identity.executionGeneration >= current.identity.executionGeneration;
					if (!noRegression || (!preparationHigher && !executionHigher)) {
						return stale(WASM_EXECUTION_FENCE_STALE);
					}
				}
				fence.adopt(command, "prepared");
				return applied();
			}
			case "start": {
				// 无 preparation 的 spawn 一律拒绝（不接纳无 fence 的 execution）。
				if (!isAliveWasmExecutionIdentity(command.identity)) return stale(WASM_EXECUTION_FENCE_STALE);
				const current = fence.current(command.identity.sandboxId);
				if (current === null) return stale(WASM_EXECUTION_NOT_PREPARED);
				const sameTuple = checkWasmExecutionFence(current.identity, command.identity);
				if (sameTuple.ok) {
					// 同 tuple 启动：全量 fence 字段必须与采纳时逐字段一致。
					if (!matchesRecordedFenceFields(current, command)) return stale(WASM_EXECUTION_FENCE_STALE);
				} else {
					// 新 tuple（restart/rebind）：只接受非回退分配。
					const noRegression =
						command.identity.preparationGeneration >= current.identity.preparationGeneration &&
						command.identity.executionGeneration >= current.identity.executionGeneration;
					if (!noRegression) return stale(WASM_EXECUTION_FENCE_STALE);
					fence.adopt(command, "running");
					return applied();
				}
				const updated = fence.updateSubstate(command.identity, "running");
				if (updated === null) return stale(WASM_EXECUTION_FENCE_STALE);
				return applied();
			}
			case "drain": {
				// 旧 execution 可 drain（纯 fence 路径）：前置与真实副作用段共用 drainPreflight；
				// 可证明后按时钟判定 drained/forced-kill（无进程可杀——真实进程停止在
				// performDrainWithRuntime 的 runtime 端口上）。
				const preflight = drainPreflight(command);
				if (!preflight.ok) return preflight.outcome;
				const retirement = preflight.retirement;
				const completedAt = now();
				const completedAtMillis = Date.parse(completedAt);
				const drainedRequestCount = drainCounterSource(retirement, command);
				// 不可证明的时钟或计数 → 不伪造 receipt（计数源必须给出可证明的非负整数）。
				if (Number.isNaN(completedAtMillis) || typeof drainedRequestCount !== "number" || !Number.isSafeInteger(drainedRequestCount) || drainedRequestCount < 0 || drainedRequestCount > WASM_U53_MAX) {
					fence.updateSubstate(command.identity, "retiring");
					return stale(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
				}
				const deadlineAt = epochMillisToRfc3339Utc(retirement.deadlineAtEpochMillis);
				if (completedAtMillis <= retirement.deadlineAtEpochMillis) {
					// deadline 内完成：drained（forcedKillAt 恒 null），子状态保持 retiring
					//（进程停止由后续 stop 命令/Kernel 投影驱动）。
					fence.updateSubstate(command.identity, "retiring");
					const draft: DrainReceiptDraftV1 = {
						schemaVersion: 1,
						commandId: command.commandId,
						applicationId: retirement.applicationId,
						execution: command.identity,
						packageDigest: command.packageDigest,
						runtimeBinding: retirement.runtimeBinding,
						routeGeneration: retirement.routeGeneration,
						drainedRequestCount,
						deadlineAt,
						forcedKillAt: null,
						result: "drained",
						completedAt,
					};
					return { result: "applied", failureCode: null, drainReceiptDraft: draft };
				}
				// deadline 已过：forced-kill。supervisor 侧的 kill 效应是把该 execution 置为
				// stopped（纯 fence 路径无进程可杀；配置 runtime 时进程停止由
				// performDrainWithRuntime 的 stopExecution 端口执行，forcedKillAt 记录的
				// 是本执行器作出强杀判定的时刻，>= deadline 由校验器复验）。
				fence.updateSubstate(command.identity, "stopped");
				const draft: DrainReceiptDraftV1 = {
					schemaVersion: 1,
					commandId: command.commandId,
					applicationId: retirement.applicationId,
					execution: command.identity,
					packageDigest: command.packageDigest,
					runtimeBinding: retirement.runtimeBinding,
					routeGeneration: retirement.routeGeneration,
					drainedRequestCount,
					deadlineAt,
					forcedKillAt: completedAt,
					result: "forced-kill",
					completedAt,
				};
				return { result: "applied", failureCode: null, drainReceiptDraft: draft };
			}
			case "stop": {
				const target = fence.findByIdentity(command.identity);
				if (target === null) return stale(WASM_EXECUTION_FENCE_STALE);
				if (!matchesRecordedFenceFields(target, command)) return stale(WASM_EXECUTION_FENCE_STALE);
				fence.updateSubstate(command.identity, "stopped");
				return applied();
			}
			default:
				return stale(WASM_EXECUTION_WIRE_INVALID);
		}
	};

	const executor: WasmSupervisorExecutor = {
		fence,
		execute: (command) => applyCommand(command),
		noteEpochTimeout: (identity) => fence.noteEngineEpochTimeout(identity),
	};

	// 重启恢复：按 journal 条目顺序重建 fence 状态——
	// - command-received 条目只重放纯 fence 决策（decide）：副作用不重放（received-
	//   incomplete 条目由 execution-rpc 的 resume 路径带副作用幂等续跑；completed 条目的
	//   存档 ack 由 handler 直接回放，不再执行）；
	// - completed 条目以其存档 ack 恢复 outcome 缓存（同 digest 命令重投递返回同一结果，
	//   不重复采纳/不重放副作用）。
	if (options.journal !== undefined) {
		for (const entry of options.journal.read().entries) {
			if (entry.kind === "command-received") {
				const replayed = decide(entry.command);
				// start 命令的采纳即意味着该 tuple 的 wasmd 子进程由该命令触发：恢复 spawn 注记
				//（监听索引按确定性分配器重放同值），stop/drain 后的代持 FD 释放依赖它。
				if (replayed.result === "applied" && entry.command.operation === "start") {
					fence.annotateSpawn(entry.command.identity, entry.commandId, allocateListenIndex(entry.command.identity.sandboxId));
				}
			} else {
				fence.recordAppliedOutcome(entry.commandDigest, { result: entry.acknowledgement.result, failureCode: entry.acknowledgement.failureCode, drainReceiptDraft: null });
			}
		}
	}

	return executor;
}

// relay 代持视图 → snapshot-fd.ts 的 handoff 契约对象（revision 按 kind 映射；其余字段
// 逐字对位——relay 不改写任何身份/digest 值，Node 侧以同一 validateSnapshotHandoffAcceptance
// 判定链复核命令相关性、过期窗口、描述符事实与摘要链）。
function handoffOfView(view: SnapshotFdRelayHandoffView): SnapshotHandoffPayload {
	const common = {
		schemaVersion: 1 as const,
		kind: view.kind,
		commandId: view.commandId,
		commandDigest: view.commandDigest,
		ref: view.ref,
		applicationId: view.applicationId,
		versionId: view.versionId,
		preparationGeneration: view.preparationGeneration,
		valuesDigest: view.valuesDigest,
		fdDigest: view.fdDigest,
		expiresAt: view.expiresAt,
	};
	if (view.kind === "secret") return { ...common, kind: "secret", secretRevision: view.revision };
	return { ...common, kind: "config", configRevision: view.revision };
}

// ---------------------------------------------------------------------------
// readiness 探测（health v2 payload 校验 → fence 采纳注记；supervisor 侧观测）
// ---------------------------------------------------------------------------

const READINESS_MAX_ATTEMPTS = 100;

/**
 * 对某 sandbox 的 wasmd ingress 做 health v2 探测并按 correlate 采纳：
 * - 200 + correlate 通过 → "adopted"；
 * - 200 但 tuple 不等于当前 → "stale"（旧 execution 信号）；wire/correlate 失败 → "mismatch"；
 * - 尝试耗尽/超时/非 200 → "not-ready"。
 * 探测绝不翻转 start 命令结果（v2 lease 签发是 Kernel/gateway 权威——spec readiness 条款）。
 */
export async function probeWasmExecutionReadiness(
	fence: WasmExecutionFenceRegistry,
	sandboxId: string,
	baseUrl: string,
	options: WasmReadinessProbeOptions,
): Promise<WasmReadinessAdoptionState> {
	const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
	const maxAttempts = Math.min(Math.max(1, Math.floor(options.maxAttempts ?? 5)), READINESS_MAX_ATTEMPTS);
	const timeoutMs = Math.min(Math.max(100, Math.floor(options.attemptTimeoutMs ?? 2000)), 60_000);
	for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const response = await options.fetch(baseUrl + READINESS_PATH, { signal: controller.signal });
			if (response.status === 200) {
				let payload: unknown = null;
				try {
					payload = JSON.parse(response.body);
				} catch {
					return "mismatch";
				}
				const adoption = correlateReadinessHealthV2(fence, sandboxId, payload);
				if (adoption.ok) return "adopted";
				return adoption.stale ? "stale" : "mismatch";
			}
		} catch {
			// 超时/连接失败：计入下一轮尝试。
		} finally {
			clearTimeout(timer);
		}
		if (attempt < maxAttempts) await sleep(Math.max(0, Math.floor(options.intervalMs ?? 500)));
	}
	return "not-ready";
}

// ---------------------------------------------------------------------------
// readiness/health v2 与 metrics 的 correlate 接线（tuple + binding 精确比对）
// ---------------------------------------------------------------------------

export type WasmSignalAdoption<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly code: string; readonly stale: boolean; readonly issues: readonly ValidationIssue[] };

function rejectSignal(code: string, staleSignal: boolean, issues: readonly ValidationIssue[]): { readonly ok: false; readonly code: string; readonly stale: boolean; readonly issues: readonly ValidationIssue[] } {
	return { ok: false, code, stale: staleSignal, issues };
}

/**
 * readiness/health 采纳判定：payload 必须先通过 ServiceReadinessHealthV2 wire 校验
 *（ABI 1.1.0 binding + policy pin），再与当前 execution 的 tuple 精确比对（旧
 * execution 信号 → stale 拒绝），最后做全字段 correlate（binding、capability pin、
 * secret/config 快照、policy pin）。任一步失败都不签发/采纳 lease。
 */
export function correlateReadinessHealthV2(
	fence: WasmExecutionFenceRegistry,
	sandboxId: string,
	payload: unknown,
): WasmSignalAdoption<ServiceReadinessHealthV2> {
	const current = fence.current(sandboxId);
	if (current === null) {
		return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, []);
	}
	const validated = validateServiceReadinessHealthV2(payload);
	if (!validated.ok) return rejectSignal(WASM_EXECUTION_WIRE_INVALID, false, validated.errors);
	// 旧 execution 信号：tuple 不等于当前 tuple 即 stale（不是 mismatch、绝不采纳）。
	const tupleCheck = checkWasmExecutionFence(current.identity, validated.value);
	if (!tupleCheck.ok) return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, tupleCheck.errors);
	const correlated = correlateServiceReadinessHealthV2(serviceFenceFieldsOf(current), validated.value);
	if (!correlated.ok) return rejectSignal("WASM_READINESS_HEALTH_MISMATCH", false, correlated.errors);
	return { ok: true, value: correlated.value };
}

/**
 * metrics 采纳判定：同一当前 execution 的精确比对；旧 generation 的延迟样本是
 * stale（不是 reset），绝不改动当前 execution 的报告口径。计数单调窗口属任务 4.1。
 */
export function correlateEngineMetrics(
	fence: WasmExecutionFenceRegistry,
	sandboxId: string,
	payload: unknown,
): WasmSignalAdoption<ServiceEngineMetricsV2> {
	const current = fence.current(sandboxId);
	if (current === null) {
		return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, []);
	}
	const validated = validateServiceEngineMetricsV2(payload);
	if (!validated.ok) return rejectSignal(WASM_EXECUTION_WIRE_INVALID, false, validated.errors);
	const tupleCheck = checkWasmExecutionFence(current.identity, validated.value);
	if (!tupleCheck.ok) return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, tupleCheck.errors);
	const correlated = correlateServiceEngineMetricsV2(serviceFenceFieldsOf(current), validated.value);
	if (!correlated.ok) return rejectSignal("WASM_ENGINE_METRICS_MISMATCH", false, correlated.errors);
	return { ok: true, value: correlated.value };
}

// ---------------------------------------------------------------------------
// drain 之后的路由围栏视图（gateway 接线属 3.x TODO；本视图是唯一判定出口）
// ---------------------------------------------------------------------------

/**
 * 某 tuple 是否还允许接收新流量：只有当前 execution 且 substate 为 running 才允许。
 * retiring/stopped 或非当前 tuple（旧 execution）一律 false——它们可完成 drain，但
 * gateway 不得把新请求路由过去，也不得把它们报告为新 execution。
 */
export function acceptsNewTraffic(fence: WasmExecutionFenceRegistry, identity: WasmExecutionIdentityV1): boolean {
	const current = fence.current(identity.sandboxId);
	if (current === null) return false;
	return checkWasmExecutionFence(current.identity, identity).ok && current.substate === "running";
}

// ---------------------------------------------------------------------------
// engine metrics v1 采样（executor 内部计数器 → WasmEngineMetricsV1 wire；4.1）
// ---------------------------------------------------------------------------

// 5.x 采集接线点：wasmd 进程内 counters（fuel/guest memory/epoch 事件的真实读数）
// 通过本接口注入；fence/身份字段一律来自已接受 execution 记录，不由计数源提供。
export interface WasmEngineCounterSample {
	/** false = 本周期无法证明引擎度量（唯一投影 availability:"unavailable" + engine:null）。 */
	readonly available: boolean;
	readonly engine: WasmEngineCountersV1 | null;
}

export type WasmEngineCounterSource = (record: WasmAcceptedExecutionRecord) => WasmEngineCounterSample;

/**
 * 内置计数源（5.x 前的唯一实现）：只上报 executor 自身可证明的事实。
 * - running/retiring：实例存活，但 guest memory 无 wasmd 读数即不可证明 → 整样本
 *   unavailable（绝不用 0 冒充运行中引擎内存）。
 * - prepared/stopped：无进程存活，instances/guestMemory 的零可证明；fuel 无法证明
 *   数值 → null（null 是「fuel 禁用」唯一表示；pinned record 启用 fuel 时 Kernel
 *   拒绝本样本，窗口保持无首样本——fail-closed，见歧义备注 7）。
 */
export function executorInternalEngineCounterSource(): WasmEngineCounterSource {
	return (record) => {
		if (record.substate === "running" || record.substate === "retiring") {
			return { available: false, engine: null };
		}
		return {
			available: true,
			engine: {
				fuelConsumedCumulative: null,
				epochTimeoutsCumulative: record.epochTimeoutsCumulative,
				instancesLiveInstant: 0,
				instancesHighWaterCumulative: record.instancesHighWaterCumulative,
				guestMemoryBytesInstant: 0,
			},
		};
	};
}

export interface WasmEngineMetricsSampleOptions {
	readonly counterSource?: WasmEngineCounterSource;
	readonly now?: () => string;
}

/**
 * 为某 sandbox 构造 supervisor → Kernel 的 metrics 载荷（ServiceEngineMetricsV2——
 * schemaVersion:2 + 采纳时的 policy pin）。
 * - 身份/binding/capability/secret/config 全部来自当前已接受 execution 记录
 *   （不采纳任何外部声明）；unknown sandbox → null（未知即拒绝，不合成载荷）。
 * - 构造完成后先过对应 validator；计数源产物不合法时 fail-closed 降级为同身份的
 *   unavailable 形态（engine:null 是 unavailable 的唯一表示），绝不发送半合法 counters。
 */
export function sampleWasmEngineMetrics(
	fence: WasmExecutionFenceRegistry,
	sandboxId: string,
	options: WasmEngineMetricsSampleOptions = {},
): ServiceEngineMetricsV2 | null {
	const current = fence.current(sandboxId);
	if (current === null) return null;
	const now = options.now ?? (() => new Date().toISOString());
	const counterSource = options.counterSource ?? executorInternalEngineCounterSource();
	const sampled = counterSource(current);
	const identityFields = {
		schemaVersion: 2 as const,
		sandboxId: current.identity.sandboxId,
		versionId: current.identity.versionId,
		packageDigest: current.packageDigest,
		runtimeBinding: current.runtimeBinding,
		hostServicePolicyDigest: current.hostServicePolicyDigest,
		capabilityRecordRevision: current.capabilityRecordRevision,
		capabilityRecordHash: current.capabilityRecordHash,
		secretRevision: current.secretRevision,
		configRevision: current.configRevision,
		configSnapshotRef: current.configSnapshotRef,
		preparationGeneration: current.identity.preparationGeneration,
		executionGeneration: current.identity.executionGeneration,
	};
	const candidate: ServiceEngineMetricsV2 = {
		...identityFields,
		sampledAt: now(),
		availability: sampled.available ? "available" : "unavailable",
		engine: sampled.available ? sampled.engine : null,
	};
	const validated = validateServiceEngineMetricsV2(candidate);
	if (validated.ok) return validated.value;
	// 计数源与 wire 矛盾（如 available 却缺 counters）：降级为同身份 unavailable，
	// 保持 unavailable 唯一表示；身份本身来自已验证命令，仍需通过 wire 校验。
	const degraded: ServiceEngineMetricsV2 = { ...identityFields, sampledAt: now(), availability: "unavailable", engine: null };
	const fallback = validateServiceEngineMetricsV2(degraded);
	return fallback.ok ? fallback.value : null;
}


// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. supervisor 不复刻 Kernel 的 +1 步进分配策略，只强制单调性（非回退 + prepare 至少
//    一个代次严格更高、start 新 tuple 非回退）：精确步进是 Kernel 权威，重复实现会在
//    两侧策略漂移时把合法命令误判为 stale。
// 2. 同 tuple 的 start 要求全量 fence 字段与采纳记录逐字段一致（同 tuple 换 binding/
//    secret/config 属 Kernel 侧矛盾，必须拒绝而非静默改写记录）。
// 3. drain receipt 的权威字段三来源（routeGeneration/deadlineAt/applicationId）只认
//    WasmRetirementLedger 中的 Kernel route-CAS 判据；ExecutionCommand 键集不含这些
//    字段，supervisor 绝不从命令/环境推断。台账未命中（含未注入台账）→ rejected +
//    EXECUTION_DRAIN_RECEIPT_UNAVAILABLE（spec 允许 drain 以 rejected ack 终结）；
//    记录命中但身份 echo 不一致 → WASM_EXECUTION_FENCE_STALE。配置 runtime 时进程侧
//    停止由 stopExecution 端口执行（SIGTERM→预算→SIGKILL）；纯 fence 路径的 supervisor
//    侧效应是 substate → stopped。
// 4. correlate 接线的三层顺序：wire 校验 → 当前 tuple 精确比对（旧 execution = stale）
//    → 全字段 correlate（mismatch）。stale 与 mismatch 分开暴露，供宿主区分 409/503。
// 5. journal 重建按条目顺序重放命令；同一 commandDigest 的幂等 outcome 在重建中同样
//    生效，保证 supervisor 重启后 resume 与首次执行结果一致。
// 6. updateSubstate 只更新 tuple 归属的记录，current 指针仅在目标不新于当前时同步，
//    防止 stop 旧 execution 意外把 current 回拨（current 只随 adopt 前进）。
// 7.（4.1 采样取舍）内置计数源在 running/retiring 时整体 unavailable：guest memory
//    无 wasmd 读数即不可证明，"available + 补零" 是伪测量；prepared/stopped 的零是
//    可证明零（无进程存活）。fuel 恒 null：executor 无法证明数值消耗，null 仅在
//    pinned record 禁用 fuel 时被 Kernel 采纳——启用 fuel 的执行在 5.x 接线前保持
//    unavailable 投影，这是 fail-closed 而非缺陷。
// 8.（4.1 重置语义）计数器属 WasmAcceptedExecutionRecord：adopt 新 tuple 即新 E 从
//    零起步；旧 E 的延迟样本由 Kernel 侧窗口按 stale 拒绝（绝不是 reset）。
