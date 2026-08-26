// 用户原始需求（2026-08-26，add-wasm-runtime 任务 2.1/2.2）：supervisor 侧 wasm 执行器——
//   消费 Kernel owner-authorized ExecutionCommandV1，推进（采纳 Kernel 分配的）P/E 代次，
//   产出 typed acknowledgement；失败保持 received-incomplete（由 wasm-control.ts 的
//   resume 路径保证）。执行器维护每 sandbox 的双 generation fence 状态，并把
//   readiness/health v2 与 metrics v1 的 correlate 精确比对接线到该状态上。
// 正交意图：supervisor journal 只接受幂等 execution commands——不铸 version、不改 route
//   pointer、不更新 Kernel lifecycle（那些是 Kernel 权威）；旧 execution 可 drain/stop 但
//   绝不作为当前 execution 报告（stale 拒绝路径）；一切 fence 判定复用 packages/contracts
//   纯函数（checkWasmExecutionFence / correlateWasmReadinessHealthV2 /
//   correlateWasmEngineMetricsV1），不造第二套比对语义。
// TODO(3.1 iweb-wasmd 固定启动契约)：prepare/start 的 applied 目前是 fence 层的接受与
//   记录；真实 digest-pinned wasmd spawn、Podman argv 与 snapshot FD handoff 属任务 3.1/7.3，
//   届时在本执行器的 side-effect 段接线，fence 语义不变。
// TODO(7.6 DrainReceiptV1 wire)：drain 的 drainReceiptDigest 需要 routeGeneration 与
//   capability record 的 drainDeadlineMs——supervisor 均不持有；本执行器对 fence 合法的
//   drain 一律产出 rejected + EXECUTION_DRAIN_RECEIPT_UNAVAILABLE（spec 允许 drain 命令
//   以 rejected acknowledgement 终结），绝不伪造 receipt digest。
// TODO(3.x gateway)：gateway/wasmd 侧的 fence 接线留 3.x；本模块暴露
//   correlateReadinessHealthV2 / correlateEngineMetrics 供 ingress 探测与采样上报调用。
// TODO(4.1 engine metrics v1)：executor 内部计数器经 sampleWasmEngineMetrics 构成
//   WasmEngineMetricsV1 wire（supervisor → Kernel）；wasmd 进程内 counters 的真实采集
//   接线点属 5.x——届时以 WasmEngineCounterSource 替换 executorInternalEngineCounterSource，
//   fence/身份语义不变。
import {
	checkWasmExecutionFence,
	computeExecutionCommandDigestV1,
	isAliveWasmExecutionIdentity,
	type ExecutionCommandV1,
	type RuntimeBindingIdentityV1,
	type WasmExecutionIdentityV1,
} from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";
import {
	correlateWasmEngineMetricsV1,
	correlateWasmReadinessHealthV2,
	validateWasmEngineMetricsV1,
	validateWasmReadinessHealthV2,
	type WasmEngineCountersV1,
	type WasmEngineMetricsFenceFields,
	type WasmReadinessFenceFields,
	type WasmEngineMetricsV1,
	type WasmReadinessHealthV2,
} from "../packages/contracts/wasm-health.ts";
import type { ValidationIssue } from "../packages/contracts/validation.ts";
import type { WasmExecutionJournalStore, WasmExecutionOutcome } from "./wasm-control.ts";

// 宿主侧 fail-closed 码（spec 已命名 WASM_IDENTITY_INCOMPLETE 之外的执行器补充码；
// 见文末歧义备注）。
export const WASM_EXECUTION_FENCE_STALE = "WASM_EXECUTION_FENCE_STALE";
export const WASM_EXECUTION_NOT_PREPARED = "WASM_EXECUTION_NOT_PREPARED";
export const EXECUTION_DRAIN_RECEIPT_UNAVAILABLE = "EXECUTION_DRAIN_RECEIPT_UNAVAILABLE";
export const WASM_EXECUTION_WIRE_INVALID = "WASM_EXECUTION_WIRE_INVALID";

// 执行子状态（spec：retiring 是 supervisor-only executionSubstate，绝不写入 Kernel
// LifecycleState；本模块的 substate 只是 fence 内部记录）。
export type WasmExecutionSubstate = "prepared" | "running" | "retiring" | "stopped";

export interface WasmAcceptedExecutionRecord {
	readonly identity: WasmExecutionIdentityV1;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
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
	adopt(command: ExecutionCommandV1, substate: WasmExecutionSubstate): WasmAcceptedExecutionRecord {
		const record: WasmAcceptedExecutionRecord = {
			identity: command.identity,
			packageDigest: command.packageDigest,
			runtimeBinding: command.runtimeBinding,
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
		};
		this.currentBySandbox.set(command.identity.sandboxId, record);
		this.acceptedByIdentity.set(fenceKey(command.identity), record);
		return record;
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
		const current = this.currentBySandbox.get(identity.sandboxId);
		if (current !== undefined && current.identity.executionGeneration <= identity.executionGeneration) {
			this.currentBySandbox.set(identity.sandboxId, next);
		}
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
		const current = this.currentBySandbox.get(identity.sandboxId);
		if (current !== undefined && current.identity.executionGeneration <= identity.executionGeneration) {
			this.currentBySandbox.set(identity.sandboxId, next);
		}
		return next;
	}
}

function fenceKey(identity: WasmExecutionIdentityV1): string {
	return identity.sandboxId + "\n" + identity.versionId + "\n" + identity.preparationGeneration + "\n" + identity.executionGeneration;
}

// 已接受 execution → correlate 期望的平铺 fence 字段（health v2 与 metrics v1 共用；
// WasmAcceptedExecutionRecord 结构性满足两类接口，多出的 secretSnapshotRef/
// configValuesDigest 是无害的额外只读字段——不构成第二套比对语义）。
function fenceFieldsOf(record: WasmAcceptedExecutionRecord): WasmReadinessFenceFields & WasmEngineMetricsFenceFields {
	return {
		sandboxId: record.identity.sandboxId,
		versionId: record.identity.versionId,
		packageDigest: record.packageDigest,
		runtimeBinding: record.runtimeBinding,
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
// secret/config——drain/stop 携带的 adopted snapshot digests 必须与采纳时完全相同）。
function matchesRecordedFenceFields(record: WasmAcceptedExecutionRecord, command: ExecutionCommandV1): boolean {
	return (
		record.packageDigest === command.packageDigest &&
		jcsEqualValues(record.runtimeBinding, command.runtimeBinding) &&
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
	return { result: "rejected", failureCode, drainReceiptDigest: null };
}

function applied(): WasmExecutionOutcome {
	return { result: "applied", failureCode: null, drainReceiptDigest: null };
}

// ---------------------------------------------------------------------------
// supervisor 执行器：消费命令 → 推进 P/E 采纳 → 产出 outcome
// ---------------------------------------------------------------------------

export interface WasmSupervisorExecutor {
	readonly fence: WasmExecutionFenceRegistry;
	/** wasm-control.ts 的 WasmExecutionExecutor 实现（幂等：同 commandDigest 同结果）。 */
	execute(command: ExecutionCommandV1): Promise<WasmExecutionOutcome>;
}

export interface WasmSupervisorExecutorOptions {
	/** 提供 journal 时，构造即从 journal 条目重建 fence 状态（supervisor 重启恢复）。 */
	readonly journal?: WasmExecutionJournalStore;
}

export function createWasmSupervisorExecutor(options: WasmSupervisorExecutorOptions = {}): WasmSupervisorExecutor {
	const fence = new WasmExecutionFenceRegistry();

	const applyCommand = (command: ExecutionCommandV1): WasmExecutionOutcome => {
		const commandDigest = computeExecutionCommandDigestV1(command);
		const remembered = fence.findAppliedOutcome(commandDigest);
		if (remembered !== null) return remembered;

		const outcome = decide(command);
		fence.recordAppliedOutcome(commandDigest, outcome);
		return outcome;
	};

	// 单命令决策（纯 fence 层；真实 spawn/stop 副作用属 3.1，在本层之上接线）。
	const decide = (command: ExecutionCommandV1): WasmExecutionOutcome => {
		switch (command.operation) {
			case "prepare": {
				const current = fence.current(command.identity.sandboxId);
				if (current !== null) {
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
				// 旧 execution 可 drain：目标 tuple 必须曾被告知（含历史），且 adopted
				// snapshot digests 与采纳时一致；标记 retiring 后以 rejected ack 终结
				//（DrainReceiptV1 wire 属 7.6，绝不伪造 digest）。
				const target = fence.findByIdentity(command.identity);
				if (target === null) return stale(WASM_EXECUTION_FENCE_STALE);
				if (!matchesRecordedFenceFields(target, command)) return stale(WASM_EXECUTION_FENCE_STALE);
				if (target.substate === "stopped") return stale(WASM_EXECUTION_FENCE_STALE);
				fence.updateSubstate(command.identity, "retiring");
				return stale(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
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
		execute: async (command) => applyCommand(command),
	};

	// 重启恢复：按 journal 条目顺序重放命令，重建 fence 状态。每个 commandId 恰好
	// 有一条 command-received 条目（completed 条目不重复携带命令体）；received-
	// incomplete 条目重放后由 resume 幂等续跑。
	if (options.journal !== undefined) {
		for (const entry of options.journal.read().entries) {
			if (entry.kind === "command-received") applyCommand(entry.command);
		}
	}

	return executor;
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
 * readiness/health v2 采纳判定：payload 必须先通过 v2 wire 校验，再与当前 execution 的
 * tuple 精确比对（旧 execution 信号 → stale 拒绝），最后做全字段 correlate（binding、
 * capability pin、secret/config 快照）。任一步失败都不签发/采纳 lease。
 */
export function correlateReadinessHealthV2(
	fence: WasmExecutionFenceRegistry,
	sandboxId: string,
	payload: unknown,
): WasmSignalAdoption<WasmReadinessHealthV2> {
	const validated = validateWasmReadinessHealthV2(payload);
	if (!validated.ok) return rejectSignal(WASM_EXECUTION_WIRE_INVALID, false, validated.errors);
	const current = fence.current(sandboxId);
	if (current === null) {
		return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, []);
	}
	// 旧 execution 信号：tuple 不等于当前 tuple 即 stale（不是 mismatch、绝不采纳）。
	const tupleCheck = checkWasmExecutionFence(current.identity, validated.value);
	if (!tupleCheck.ok) return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, tupleCheck.errors);
	const correlated = correlateWasmReadinessHealthV2(fenceFieldsOf(current), validated.value);
	if (!correlated.ok) return rejectSignal("WASM_READINESS_HEALTH_MISMATCH", false, correlated.errors);
	return { ok: true, value: correlated.value };
}

/**
 * metrics v1 采纳判定：同一当前 execution 的精确比对；旧 generation 的延迟样本是
 * stale（不是 reset），绝不改动当前 execution 的报告口径。计数单调窗口属任务 4.1。
 */
export function correlateEngineMetrics(
	fence: WasmExecutionFenceRegistry,
	sandboxId: string,
	payload: unknown,
): WasmSignalAdoption<WasmEngineMetricsV1> {
	const validated = validateWasmEngineMetricsV1(payload);
	if (!validated.ok) return rejectSignal(WASM_EXECUTION_WIRE_INVALID, false, validated.errors);
	const current = fence.current(sandboxId);
	if (current === null) {
		return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, []);
	}
	const tupleCheck = checkWasmExecutionFence(current.identity, validated.value);
	if (!tupleCheck.ok) return rejectSignal(WASM_EXECUTION_FENCE_STALE, true, tupleCheck.errors);
	const correlated = correlateWasmEngineMetricsV1(fenceFieldsOf(current), validated.value);
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
 * 为某 sandbox 构造 supervisor → Kernel 的 metrics v1 wire 载荷。
 * - 身份/binding/capability/secret/config 全部来自当前已接受 execution 记录
 *   （不采纳任何外部声明）；unknown sandbox → null（未知即拒绝，不合成载荷）。
 * - 构造完成后先过 validateWasmEngineMetricsV1；计数源产物不合法时 fail-closed
 *   降级为同身份的 unavailable 形态（engine:null 是 unavailable 的唯一表示），
 *   绝不发送半合法 counters。
 */
export function sampleWasmEngineMetrics(
	fence: WasmExecutionFenceRegistry,
	sandboxId: string,
	options: WasmEngineMetricsSampleOptions = {},
): WasmEngineMetricsV1 | null {
	const current = fence.current(sandboxId);
	if (current === null) return null;
	const now = options.now ?? (() => new Date().toISOString());
	const counterSource = options.counterSource ?? executorInternalEngineCounterSource();
	const sampled = counterSource(current);
	const identityFields = {
		schemaVersion: 1 as const,
		sandboxId: current.identity.sandboxId,
		versionId: current.identity.versionId,
		packageDigest: current.packageDigest,
		runtimeBinding: current.runtimeBinding,
		capabilityRecordRevision: current.capabilityRecordRevision,
		capabilityRecordHash: current.capabilityRecordHash,
		secretRevision: current.secretRevision,
		configRevision: current.configRevision,
		configSnapshotRef: current.configSnapshotRef,
		preparationGeneration: current.identity.preparationGeneration,
		executionGeneration: current.identity.executionGeneration,
	};
	const candidate: WasmEngineMetricsV1 = {
		...identityFields,
		sampledAt: now(),
		availability: sampled.available ? "available" : "unavailable",
		engine: sampled.available ? sampled.engine : null,
	};
	const validated = validateWasmEngineMetricsV1(candidate);
	if (validated.ok) return validated.value;
	// 计数源与 wire 矛盾（如 available 却缺 counters）：降级为同身份 unavailable，
	// 保持 unavailable 唯一表示；身份本身来自已验证命令，仍需通过 wire 校验。
	const degraded: WasmEngineMetricsV1 = { ...identityFields, sampledAt: now(), availability: "unavailable", engine: null };
	const fallback = validateWasmEngineMetricsV1(degraded);
	return fallback.ok ? fallback.value : null;
}


// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. supervisor 不复刻 Kernel 的 +1 步进分配策略，只强制单调性（非回退 + prepare 至少
//    一个代次严格更高、start 新 tuple 非回退）：精确步进是 Kernel 权威，重复实现会在
//    两侧策略漂移时把合法命令误判为 stale。
// 2. 同 tuple 的 start 要求全量 fence 字段与采纳记录逐字段一致（同 tuple 换 binding/
//    secret/config 属 Kernel 侧矛盾，必须拒绝而非静默改写记录）。
// 3. drain 的 rejected + EXECUTION_DRAIN_RECEIPT_UNAVAILABLE：spec 要求 drain 命令要么
//    成功 receipt、要么 rejected ack；receipt 需要 routeGeneration（Kernel route 事件）
//    与 drainDeadlineMs（pinned capability record），supervisor 都不持有——伪造 digest
//    比诚实拒绝更危险。fence 语义（标记 retiring、可继续 stop）不受影响。
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
