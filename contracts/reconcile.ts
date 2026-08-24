// 用户原始需求（2026-08-14）：Kernel 重启后只从 admitted immutable versions 对账；缺失 active 报告不可用并从 admitted version 重启，未知资源隔离。
// 正交意图：纯规划函数，供 Kernel 与 supervisor 协作。
import { deriveSandboxId } from "./protocol.ts";
import { type ControlState } from "./control-db.ts";

export interface ReconciliationPlan {
	readonly expectedActive: readonly string[];
	readonly missingActive: readonly string[];
	readonly unknownObserved: readonly string[];
}

export function planReconciliation(state: ControlState, observedSandboxIds: readonly string[]): ReconciliationPlan {
	const expectedActive: string[] = [];
	for (const application of Object.values(state.applications)) {
		if (application.active.kind === "active") {
			expectedActive.push(deriveSandboxId(application.active.applicationId, application.active.version.digest, application.active.version.sequence));
		}
	}
	const observed = new Set(observedSandboxIds);
	const expected = new Set(expectedActive);
	const missingActive = expectedActive.filter((sandboxId) => !observed.has(sandboxId));
	const unknownObserved = observedSandboxIds.filter((sandboxId) => !expected.has(sandboxId));
	return { expectedActive, missingActive, unknownObserved };
}

