// 用户原始需求（2026-08-12）：Admin 通过 api.<base> 管理 iweb，而不是拥有后端特权。
// 正交意图：推导控制面地址；封装带鉴权请求；校验 Kernel API 响应；暴露明确失败状态。
import {
	applicationsResponseSchema,
	appNameSchema,
	hostIdSchema,
	monitorTicketSchema,
	nodeStatusWithApplicationsSchema,
	keyIssuanceSchema,
	keysResponseSchema,
	auditResponseSchema,
	ownerKeySchema,
	routeSchema,
	routeStoreSchema,
	workspaceSchema,
	workspaceFileContentSchema,
	workspaceFileWriteSchema,
	type ApplicationsResponse,
	type AppRoute,
	type CreateRouteInput,
	type NodeStatusWithApplications,
	type KeyIssuance,
	type KeyMetadata,
	type AuditEvent,
	type OwnerKey,
	type RouteStore,
	type Workspace,
	type WorkspaceFileContent,
	type WorkspaceFileWrite,
	type MonitorTicket
} from "$lib/iweb/contracts";

export class KernelApiError extends Error {
	constructor(
		message: string,
		readonly status: number
	) {
		super(message);
		this.name = "KernelApiError";
	}
}

export function apiOriginFromAdminOrigin(origin: URL): string {
	const hostname = origin.hostname.toLowerCase();
	const baseHost = hostname.startsWith("admin.app.")
		? hostname.slice("admin.app.".length)
		: hostname.startsWith("admin.")
			? hostname.slice("admin.".length)
			: hostname;
	const port = origin.port ? `:${origin.port}` : "";
	return `${origin.protocol}//api.${baseHost}${port}`;
}

export function publicOrigin(baseHost: string, hostId: string, protocol: string, port: string): string {
	return `${protocol}//${hostId}.${baseHost}${port ? `:${port}` : ""}`;
}

function messageFromUnknown(value: unknown, fallback: string): string {
	if (typeof value === "object" && value !== null && "error" in value && typeof value.error === "string") {
		return value.error;
	}
	return fallback;
}

export class KernelApiClient {
	constructor(
		readonly origin: string,
		private readonly getToken: () => string
	) {}

	private async request(path: string, init: RequestInit = {}): Promise<unknown> {
		const token = this.getToken().trim();
		if (!token) throw new KernelApiError("请先以管理员身份登录", 401);
		const headers = new Headers(init.headers);
		headers.set("authorization", `Bearer ${token}`);
		if (init.body) headers.set("content-type", "application/json");

		let response: Response;
		try {
			response = await fetch(`${this.origin}${path}`, { ...init, headers });
		} catch {
			throw new KernelApiError("无法连接 iweb Kernel API", 0);
		}

		if (response.status === 204) return undefined;
		const body: unknown = await response.json().catch(() => undefined);
		if (!response.ok) throw new KernelApiError(messageFromUnknown(body, `请求失败（HTTP ${response.status}）`), response.status);
		return body;
	}

	async status(): Promise<NodeStatusWithApplications> {
		// 真实 /v1/status 恒带 sandboxSupervisor/applications（+ 看门狗投影 watchdog）；
		// 精确解析用完整 schema（Codex R2：strict 的基础 schema 会拒收完整载荷）。
		return nodeStatusWithApplicationsSchema.parse(await this.request("/v1/status"));
	}

	async keysList(): Promise<{ keys: KeyMetadata[] }> {
		return keysResponseSchema.parse(await this.request("/v1/keys"));
	}

	async keysCreate(label: string, expiresAt: string | null): Promise<KeyIssuance> {
		return keyIssuanceSchema.parse(
			await this.request("/v1/keys", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ label, expiresAt }) })
		);
	}

	async keysBan(keyId: string): Promise<void> {
		await this.request(`/v1/keys/${encodeURIComponent(keyId)}`, { method: "DELETE" });
	}

	async audit(keyId: string | null, limit: number): Promise<{ events: AuditEvent[]; dropped: number }> {
		const params = new URLSearchParams({ limit: String(limit) });
		if (keyId) params.set("keyId", keyId);
		return auditResponseSchema.parse(await this.request(`/v1/audit?${params.toString()}`));
	}

	async routes(): Promise<RouteStore> {
		return routeStoreSchema.parse(await this.request("/v1/routes"));
	}

	async workspace(): Promise<Workspace> {
		return workspaceSchema.parse(await this.request("/v1/workspace"));
	}

	async workspaceFile(path: string): Promise<WorkspaceFileContent> {
		return workspaceFileContentSchema.parse(
			await this.request(`/v1/workspace/file?path=${encodeURIComponent(path)}`)
		);
	}

	async writeWorkspaceFile(input: { path: string; content: string }): Promise<WorkspaceFileWrite> {
		return workspaceFileWriteSchema.parse(
			await this.request("/v1/workspace/file", {
				method: "PUT",
				body: JSON.stringify(input)
			})
		);
	}

	async deleteWorkspaceFile(path: string): Promise<void> {
		await this.request(`/v1/workspace/file?path=${encodeURIComponent(path)}`, { method: "DELETE" });
	}

	async createMonitorTicket(): Promise<MonitorTicket> {
		return monitorTicketSchema.parse(await this.request("/v1/monitor/session", { method: "POST" }));
	}

	async ownerKey(): Promise<OwnerKey> {
		return ownerKeySchema.parse(await this.request("/v1/key"));
	}

	async createRoute(input: CreateRouteInput): Promise<AppRoute> {
		const hostId = hostIdSchema.parse(input.hostId);
		const appName = appNameSchema.parse(input.appName);
		return routeSchema.parse(
			await this.request("/v1/routes", {
				method: "POST",
				body: JSON.stringify({ hostId, appName })
			})
		);
	}

	async deleteRoute(hostId: string): Promise<void> {
		await this.request(`/v1/routes/${encodeURIComponent(hostId)}`, { method: "DELETE" });
	}

	async recoverAdmin(): Promise<void> {
		await this.request("/v1/recover/admin", { method: "POST" });
	}

	// --- application projections（two-tier-runtime-trust：celld 版本生命周期
	// 方法已随运行时准入一起删除；应用投影只剩只读列表与状态派生两条路径） ---

	async listApplications(): Promise<ApplicationsResponse> {
		return applicationsResponseSchema.parse(await this.request("/v1/applications"));
	}

	async statusApplications(): Promise<ApplicationsResponse> {
		// /v1/status carries the full node status; parse it with the status schema
		// (not applicationsResponseSchema, which rejects the status-only keys).
		// two-tier-runtime-trust：applications 是路由派生的 celld fleet 投影
		// （runtimeKind 恒 "celld"、无沙箱身份、无版本生命周期）。
		const status = nodeStatusWithApplicationsSchema.parse(await this.request("/v1/status"));
		return { applications: status.applications };
	}
}
