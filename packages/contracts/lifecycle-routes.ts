// 用户原始需求（2026-08-14）：生命周期 HTTP 端点必须等待单写者提交完成后才返回；drain 只在激活指针已落库后进行。
// 正交意图：7.3/7.4/9.2 端点集成证据——纯 dispatcher 被生产 handleApi 调用；activate/rollback 是 Promise，必须 await。
export interface LifecycleOutcome {
	readonly status: number;
	readonly body: unknown;
	readonly drainAfterCommit: boolean;
	readonly error?: { readonly code: string; readonly message: string };
}

export interface LifecycleControl {
	inspectVersion(applicationId: string, versionId: string): Promise<unknown>;
	prepare(applicationId: string, versionId: string): Promise<unknown>;
	probeReady(applicationId: string, versionId: string): Promise<unknown>;
	activate(applicationId: string, versionId: string): Promise<{ generation: number; retired: string | null }>;
	rollback(applicationId: string, versionId: string): Promise<{ generation: number; retired: string | null }>;
	startVersion(applicationId: string, versionId: string): Promise<unknown>;
	stopVersion(applicationId: string, versionId: string): Promise<unknown>;
	drainRetired(applicationId: string): Promise<string[]>;
}

// Dispatches one version action. activate/rollback AWAIT the committed result
// before returning so callers serialize the real generation (never a Promise);
// drainAfterCommit tells the transport layer the commit is durable and draining
// may now run in the background.
export async function handleVersionAction(
	control: LifecycleControl,
	applicationId: string,
	versionId: string,
	method: string,
	action: string | null,
): Promise<LifecycleOutcome> {
	if (method === "GET" && action === null) {
		return { status: 200, body: await control.inspectVersion(applicationId, versionId), drainAfterCommit: false };
	}
	if (method === "POST" && action === "prepare") {
		return { status: 201, body: await control.prepare(applicationId, versionId), drainAfterCommit: false };
	}
	if (method === "POST" && action === "readiness") {
		return { status: 200, body: await control.probeReady(applicationId, versionId), drainAfterCommit: false };
	}
	if (method === "POST" && action === "activate") {
		const activation = await control.activate(applicationId, versionId);
		return { status: 200, body: activation, drainAfterCommit: true };
	}
	if (method === "POST" && action === "rollback") {
		const rollback = await control.rollback(applicationId, versionId);
		return { status: 200, body: rollback, drainAfterCommit: true };
	}
	if (method === "POST" && action === "start") {
		return { status: 200, body: await control.startVersion(applicationId, versionId), drainAfterCommit: false };
	}
	if (method === "POST" && action === "stop") {
		return { status: 200, body: await control.stopVersion(applicationId, versionId), drainAfterCommit: false };
	}
	return { status: 405, body: { error: "method not allowed" }, drainAfterCommit: false };
}
