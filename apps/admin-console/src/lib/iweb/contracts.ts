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

export const routeSchema = z.strictObject({
	hostId: z.string(),
	target: z.strictObject({
		kind: z.literal("celld-app"),
		appName: z.string()
	}),
	system: z.boolean().default(false),
	enabled: z.boolean().default(true)
});

export const routeStoreSchema = z.strictObject({
	version: z.literal(1),
	routes: z.array(routeSchema)
});

export const nodeStatusSchema = z.strictObject({
	baseHost: z.string(),
	runtime: z.literal("celld"),
	routes: z.number().int().nonnegative(),
	memory: z.strictObject({
		usageBytes: z.number().int().nonnegative().nullable(),
		limitBytes: z.number().int().positive().nullable(),
		usagePercent: z.number().nonnegative().nullable(),
		kernelHeapUsedBytes: z.number().int().nonnegative().nullable()
	}),
	// wasm 简化批次新增：发布门状态投影（单开关 + 验收记录摘要）。
	wasmPublication: z.strictObject({
		enabled: z.boolean(),
		acceptanceRecord: z.string().nullable()
	}).optional()
});

export const workspaceFileSchema = z.strictObject({
	path: z.string(),
	size: z.number().nonnegative(),
	lastModified: z.string()
});

export const workspaceAppSchema = z.strictObject({
	id: z.string(),
	deployed: z.boolean(),
	system: z.boolean(),
	domains: z.array(z.string())
});

export const workspaceSchema = z.strictObject({
	root: z.literal("/"),
	files: z.array(workspaceFileSchema),
	apps: z.array(workspaceAppSchema)
});

export const workspaceFileContentSchema = z.strictObject({
	path: z.string(),
	content: z.string()
});

export const workspaceFileWriteSchema = z.strictObject({
	path: z.string(),
	bytes: z.number().int().nonnegative()
});

// --- application sandbox projections (tasks 9.3-9.5, 10.3) ---
// 计量值要么带可证明的值，要么 unavailable；unavailable 绝不能渲染为 0。
export const measuredValueSchema = z.union([
	z.object({ available: z.literal(false) }).strict(),
	z.object({ available: z.literal(true), value: z.number().int().nonnegative() }).strict()
]);

export const resourceLimitsSchema = z
	.object({
		cpuMillis: z.number().int().nonnegative().nullable(),
		memoryBytes: z.number().int().nonnegative().nullable(),
		pidLimit: z.number().int().nonnegative().nullable(),
		storageBytes: z.number().int().nonnegative().nullable()
	})
	.strict();

export const resourceSampleSchema = z
	.object({
		versionId: z.string(),
		sampledAt: z.string(),
		cpuMillis: measuredValueSchema,
		memoryBytes: measuredValueSchema,
		pidCount: measuredValueSchema,
		terminated: measuredValueSchema,
		limits: resourceLimitsSchema.nullable()
	})
	.strict();

export const applicationVersionSchema = z
	.object({
		versionId: z.string(),
		sequence: z.number().int().positive(),
		lifecycle: z.string(),
		admittedAt: z.string(),
		readinessExpiresAt: z.string().nullable()
	})
	.strict();

// Kernel 在无样本时发出 { unavailable: true }（controlApplicationProjection），
// 而不是 null；在边界统一归一化为 null，让调用方只处理 ResourceSample | null。
const normalizeResources = (value: unknown): unknown =>
	value !== null && typeof value === "object" && !Array.isArray(value) && !("versionId" in value) ? null : value;

export const applicationProjectionSchema = z
	.object({
		id: z.string(),
		sandboxId: z.string().nullable(),
		activeVersion: z
			.object({
				digest: z.string(),
				sequence: z.number().int().positive()
			})
			.strict()
			.nullable(),
		routeGeneration: z.number().int().nonnegative(),
		lifecycle: z.string(),
		versions: z.array(applicationVersionSchema),
		resources: z.preprocess(normalizeResources, resourceSampleSchema.nullable())
	})
	.strict();

export const applicationsResponseSchema = z
	.object({
		applications: z.array(applicationProjectionSchema)
	})
	.strict();

// The complete GET /v1/status payload from the Kernel. statusApplications() must
// parse the status endpoint with this schema: reusing applicationsResponseSchema
// there rejected the six status-only top-level keys (baseHost, runtime, routes,
// memory, applicationPublication, sandboxSupervisor) with unrecognized_keys and
// broke the admin console against a real node.
export const nodeStatusWithApplicationsSchema = nodeStatusSchema.extend({
	applicationPublication: z.strictObject({
		enabled: z.boolean(),
		reasons: z.array(z.string())
	}),
	sandboxSupervisor: z.strictObject({
		configured: z.boolean(),
		available: z.boolean(),
		version: z.number().int().nullable()
	}),
	applications: z.array(applicationProjectionSchema)
});

export type NodeStatusWithApplications = z.infer<typeof nodeStatusWithApplicationsSchema>;

export const admissionResultSchema = z
	.object({
		versionId: z.string(),
		identity: z.unknown()
	})
	.strict();

export const sandboxResultSchema = z
	.object({
		sandboxId: z.string()
	})
	.strict();

export const readinessResultSchema = z
	.object({
		ready: z.boolean(),
		attempts: z.number().int().nonnegative(),
		lastStatus: z.number().int().nullable(),
		mismatch: z.boolean(),
		timedOut: z.boolean()
	})
	.strict();

export const activationResultSchema = z
	.object({
		generation: z.number().int().nonnegative(),
		retired: z.string().nullable()
	})
	.strict();

export const rollbackResultSchema = z
	.object({
		generation: z.number().int().nonnegative(),
		// 7.3 operation-specific union: rollback commits generation AND names
		// the retired version's sandbox (null when nothing was retired).
		retired: z.string().nullable()
	})
	.strict();

export const normalizedPolicySchema = z
	.object({
		resources: z
			.object({
				cpuMillis: z.number().int().nonnegative(),
				memoryBytes: z.number().int().nonnegative(),
				pidLimit: z.number().int().nonnegative(),
				storageBytes: z.number().int().nonnegative()
			})
			.strict(),
		egress: z
			.object({
				default: z.literal("deny"),
				allow: z.array(z.object({ host: z.string(), port: z.number().int().min(1).max(65535) }).strict())
			})
			.strict()
	})
	.strict();

// --- wasm engine metrics projection（add-wasm-runtime 4.1/4.4）---
// Kernel 权威投影的 engine 口径（与 resources 的 cgroup/进程口径分开标注，互不换算）。
// wire 权威：packages/contracts/wasm-health.ts WasmEngineMetricsV1；此处只描述 Kernel
// monitor 帧的 app 行投影。unavailable 唯一表示 engine:null；fuel 禁用唯一表示 null；
// 无首样本 sampledAt 为 null（缺测绝不补零）。
export const wasmEngineCountersSchema = z
	.object({
		fuelConsumedCumulative: z.number().int().nonnegative().nullable(),
		epochTimeoutsCumulative: z.number().int().nonnegative(),
		instancesLiveInstant: z.number().int().nonnegative(),
		instancesHighWaterCumulative: z.number().int().nonnegative(),
		guestMemoryBytesInstant: z.number().int().nonnegative()
	})
	.strict();

export const wasmEngineMetricsProjectionSchema = z
	.object({
		scope: z.literal("wasm-engine"),
		sandboxId: z.string(),
		versionId: z.string(),
		preparationGeneration: z.number().int().positive(),
		executionGeneration: z.number().int().positive(),
		sampledAt: z.string().nullable(),
		availability: z.enum(["available", "unavailable"]),
		engine: wasmEngineCountersSchema.nullable()
	})
	.strict();

// --- wasm host-services 摘要投影（add-wasm-host-services supervisor 接线层，2026-08-28）---
// wire 权威：supervisor /v1/host-logging/summary 的 IwebLoggingMonitorSummaryV1
// （packages/contracts/wasm-host-logging.ts）。最小投影：仅计数/容量/水位与可用性状态——
// 无日志正文、无字段值、无跨应用数据（spec「Owner-authorized monitor projection」）。
// unavailable 唯一表示 logging:null；Kernel monitor 帧尚未发射该字段（optional）。
export const wasmHostLoggingSummarySchema = z
	.object({
		applicationId: z.string(),
		retainedEvents: z.number().int().nonnegative(),
		retainedBytes: z.number().int().nonnegative(),
		droppedCount: z.number().int().nonnegative(),
		lastEventId: z.number().int().nonnegative(),
		capacity: z
			.object({
				maxEvents: z.number().int().positive(),
				maxBytes: z.number().int().positive()
			})
			.strict()
	})
	.strict();

export const wasmHostServicesSummarySchema = z
	.object({
		availability: z.enum(["available", "unavailable"]),
		logging: wasmHostLoggingSummarySchema.nullable()
	})
	.strict();

export const monitorAppSchema = z.strictObject({
	id: z.string(),
	domains: z.array(z.string()),
	deployed: z.boolean(),
	system: z.boolean(),
	requests: z.number().int().nonnegative(),
	errors: z.number().int().nonnegative(),
	inFlight: z.number().int().nonnegative(),
	averageLatencyMs: z.number().nonnegative(),
	lastRequestAt: z.string().nullable(),
	// 用户设计（2026-08-15）：控制面应用（独立 celld 进程）的进程 RSS 采样——
	// 真实逐应用内存测量；沙箱化应用的资源仍在 sandboxes 投影（cgroup）。
	resources: resourceSampleSchema.nullable().optional(),
	// wasm 应用的引擎（Wasmtime）口径投影（4.4，owner-only 监控面）：celld 应用
	// 不携带该字段（optional——JS 参考内核帧不发射 engine）。
	engine: wasmEngineMetricsProjectionSchema.nullable().optional(),
	// wasm 应用宿主服务（kv/sql/logging）的摘要投影（add-wasm-host-services）：仅计数/状态，
	// 无正文无值；非 host-services 应用与尚未发射该字段的内核帧不携带（optional）。
	hostServices: wasmHostServicesSummarySchema.nullable().optional()
});

export const monitorSnapshotSchema = z.strictObject({
	type: z.literal("snapshot"),
	emittedAt: z.string(),
	node: z.strictObject({
		uptimeSeconds: z.number().nonnegative(),
		routeCount: z.number().int().nonnegative(),
		workspaceFileCount: z.number().int().nonnegative(),
		workspaceBytes: z.number().nonnegative(),
		memory: z.strictObject({
			usageBytes: z.number().int().nonnegative().nullable(),
			limitBytes: z.number().int().positive().nullable(),
			usagePercent: z.number().nonnegative().nullable(),
			kernelHeapUsedBytes: z.number().int().nonnegative().nullable()
		})
	}),
	apps: z.array(monitorAppSchema),
	sandboxes: z.array(applicationProjectionSchema)
});

export const monitorTicketSchema = z.strictObject({
	ticket: z.string().min(1),
	expiresAt: z.string()
});

export const ownerKeySchema = z.strictObject({
	kind: z.literal("owner"),
	capabilities: z.strictObject({
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
export type WasmEngineCounters = z.infer<typeof wasmEngineCountersSchema>;
export type WasmEngineMetricsProjection = z.infer<typeof wasmEngineMetricsProjectionSchema>;
export type WasmHostLoggingSummary = z.infer<typeof wasmHostLoggingSummarySchema>;
export type WasmHostServicesSummary = z.infer<typeof wasmHostServicesSummarySchema>;

// --- owner-key-management（2026-08-23）：一个身份多把可吊销令牌 ---
const utcStamp = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/);

export const keyMetadataSchema = z.strictObject({
	keyId: z.string().regex(/^(bootstrap|[0-9a-f]{8})$/),
	label: z.string().nullable(),
	createdAt: utcStamp.nullable(),
	expiresAt: utcStamp.nullable(),
	bannedAt: utcStamp.nullable(),
	status: z.enum(["active", "expired", "banned"]),
	revocable: z.boolean()
});

export const keysResponseSchema = z.strictObject({ keys: z.array(keyMetadataSchema) });

export const keyIssuanceSchema = z.strictObject({
	token: z.string().regex(/^iwb_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$/),
	key: keyMetadataSchema
});

export const auditEventSchema = z.strictObject({
	ts: utcStamp,
	keyId: z.string().regex(/^(bootstrap|[0-9a-f]{8})$/).nullable(),
	action: z.string().regex(/^[a-z][a-z0-9.]{0,63}$/),
	method: z.string().regex(/^[A-Z]+$/),
	path: z.string().max(256),
	status: z.number().int().nonnegative(),
	txn: z.string().regex(/^[0-9a-f]{16}$/).optional()
});

export const auditResponseSchema = z.strictObject({
	events: z.array(auditEventSchema),
	dropped: z.number().int().nonnegative()
});

export type KeyMetadata = z.infer<typeof keyMetadataSchema>;
export type KeyIssuance = z.infer<typeof keyIssuanceSchema>;
export type AuditEvent = z.infer<typeof auditEventSchema>;
export type MeasuredValue = z.infer<typeof measuredValueSchema>;
export type ResourceLimits = z.infer<typeof resourceLimitsSchema>;
export type ResourceSample = z.infer<typeof resourceSampleSchema>;
export type ApplicationVersion = z.infer<typeof applicationVersionSchema>;
export type ApplicationProjection = z.infer<typeof applicationProjectionSchema>;
export type ApplicationsResponse = z.infer<typeof applicationsResponseSchema>;
export type AdmissionResult = z.infer<typeof admissionResultSchema>;
export type SandboxResult = z.infer<typeof sandboxResultSchema>;
export type ReadinessResult = z.infer<typeof readinessResultSchema>;
export type ActivationResult = z.infer<typeof activationResultSchema>;
export type RollbackResult = z.infer<typeof rollbackResultSchema>;
export type NormalizedPolicy = z.infer<typeof normalizedPolicySchema>;
