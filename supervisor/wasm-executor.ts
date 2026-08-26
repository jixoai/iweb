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
		};
		this.currentBySandbox.set(command.identity.sandboxId, record);
		this.acceptedByIdentity.set(fenceKey(command.identity), record);
		return record;
	}

	/** 就地更新子状态（start/drain/stop 不改变 tuple 归属）。 */
	updateSubstate(identity: WasmExecutionIdentityV1, substate: WasmExecutionSubstate): WasmAcceptedExecutionRecord | null {
		const record = this.acceptedByIdentity.get(fenceKey(identity));
		if (record === undefined) return null;
		const next: WasmAcceptedExecutionRecord = { ...record, substate };
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
