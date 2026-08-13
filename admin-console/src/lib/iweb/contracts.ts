// 用户原始需求（2026-08-12）：iweb Admin 管理应用路由、访问密钥与 Admin 恢复。
// 正交意图：描述 Kernel API 的稳定响应；在边界解析不可信 JSON；复用 UI 与测试的类型。
import { z } from "zod";

export const appNameSchema = z
	.string()
	.trim()
	.toLowerCase()
	.regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/, "仅允许小写字母、数字和连字符");

export const hostIdSchema = z
	.string()
	.trim()
	.toLowerCase()
	.regex(
		/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/,
		"请输入合法的相对主机名"
	)
	.refine((value) => value.endsWith(".app"), "用户应用必须位于 .app 命名空间")
	.refine((value) => !["api", "admin", "mcp"].includes(value.split(".")[0] ?? ""), "该主机名前缀已被内置服务保留");

export const routeSchema = z.object({
	hostId: z.string(),
	target: z.object({
		kind: z.literal("celld-app"),
		appName: z.string()
	}),
	system: z.boolean().default(false),
	enabled: z.boolean().default(true)
});

export const routeStoreSchema = z.object({
	version: z.literal(1),
	routes: z.array(routeSchema)
});

export const nodeStatusSchema = z.object({
	baseHost: z.string(),
	runtime: z.literal("celld"),
	routes: z.number().int().nonnegative(),
	memory: z.object({
		usageBytes: z.number().int().nonnegative().nullable(),
		limitBytes: z.number().int().positive().nullable(),
		usagePercent: z.number().nonnegative().nullable(),
		kernelHeapUsedBytes: z.number().int().nonnegative()
	})
});

export const workspaceFileSchema = z.object({
	path: z.string(),
	size: z.number().nonnegative(),
	lastModified: z.string()
});

export const workspaceAppSchema = z.object({
	id: z.string(),
	sourcePath: z.string(),
	manifestPath: z.string(),
	deployed: z.boolean(),
	system: z.boolean(),
	domains: z.array(z.string())
});

export const workspaceSchema = z.object({
	root: z.literal("/"),
	files: z.array(workspaceFileSchema),
	apps: z.array(workspaceAppSchema)
});

export const workspaceFileContentSchema = z.object({
	path: z.string(),
	content: z.string()
});

export const workspaceFileWriteSchema = z.object({
	path: z.string(),
	bytes: z.number().int().nonnegative()
});

export const monitorAppSchema = z.object({
	id: z.string(),
	sourcePath: z.string(),
	domains: z.array(z.string()),
	deployed: z.boolean(),
	system: z.boolean(),
	requests: z.number().int().nonnegative(),
	errors: z.number().int().nonnegative(),
	inFlight: z.number().int().nonnegative(),
	averageLatencyMs: z.number().nonnegative(),
	lastRequestAt: z.string().nullable()
});

export const monitorSnapshotSchema = z.object({
	type: z.literal("snapshot"),
	emittedAt: z.string(),
	node: z.object({
		uptimeSeconds: z.number().nonnegative(),
		routeCount: z.number().int().nonnegative(),
		workspaceFileCount: z.number().int().nonnegative(),
		workspaceBytes: z.number().nonnegative(),
		memory: z.object({
			usageBytes: z.number().int().nonnegative().nullable(),
			limitBytes: z.number().int().positive().nullable(),
			usagePercent: z.number().nonnegative().nullable(),
			kernelHeapUsedBytes: z.number().int().nonnegative()
		})
	}),
	apps: z.array(monitorAppSchema)
});

export const monitorTicketSchema = z.object({
	ticket: z.string().min(1),
	expiresAt: z.string()
});

export const ownerKeySchema = z.object({
	kind: z.literal("owner"),
	capabilities: z.object({
		read: z.array(z.string()),
		write: z.array(z.string()),
		deploy: z.array(z.string()),
		domains: z.array(z.string()),
		environment: z.array(z.string())
	})
});

export type AppRoute = z.infer<typeof routeSchema>;
export type RouteStore = z.infer<typeof routeStoreSchema>;
export type NodeStatus = z.infer<typeof nodeStatusSchema>;
export type CreateRouteInput = Pick<AppRoute, "hostId"> & { appName: string };
export type WorkspaceFile = z.infer<typeof workspaceFileSchema>;
export type WorkspaceApp = z.infer<typeof workspaceAppSchema>;
export type Workspace = z.infer<typeof workspaceSchema>;
export type WorkspaceFileContent = z.infer<typeof workspaceFileContentSchema>;
export type WorkspaceFileWrite = z.infer<typeof workspaceFileWriteSchema>;
export type MonitorApp = z.infer<typeof monitorAppSchema>;
export type MonitorSnapshot = z.infer<typeof monitorSnapshotSchema>;
export type MonitorTicket = z.infer<typeof monitorTicketSchema>;
export type OwnerKey = z.infer<typeof ownerKeySchema>;
