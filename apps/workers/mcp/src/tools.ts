// 用户原始需求（2026-08-13）：MCP 工具从请求处理器拆出，让部署代理验证、发布与运维应用。
// 正交意图：工具定义与调度是纯 ESM，可被 bun test 直接导入；不依赖 Worker 全局；
// 不接触 request/env，因此绝不持有 owner key；Kernel 边界错误只以文本传播，不带堆栈。
// two-tier-runtime-trust（2026-08-29，任务 7.1）：工具面收窄 wasm-only——celld 运行时
// 准入永久移除，MCP 不再触达任何已移除的 celld 准入端点（Kernel 侧终态 410
// CELLD_ADMISSION_REMOVED）；celld 目标一律返回 CELLD_IMAGE_ONLY 两层引导文案。
// wasm 读面走 /v1/wasm/status 投影，发布走 /v1/wasm/admission 事务透传。
export const serverInfo = { name: "iweb-mcp", version: "0.3.0" };

const APPLICATION_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const VERSION_ID_PATTERN = /^[a-f0-9]{64}$/;

// 两层部署引导（two-tier-runtime-trust 决策 7）：错误文案与工具描述共用同一权威文本。
// 第一层（唯一运行时准入路径）：不可信/网络来源代码编译为 wasi:http 组件经 wasm 准入；
// 第二层（信任层）：可信且需原生能力的代码构建进 owner 节点镜像。celld 没有运行时准入。
export const CELLD_IMAGE_ONLY_CODE = "CELLD_IMAGE_ONLY";
const GUIDANCE_WASM_TIER =
	"untrusted or network-sourced code must be compiled to a wasi:http component (QuickJS or StarlingMonkey host JavaScript, MoonBit for native) and admitted as a wasm application through iweb_application_admit";
const GUIDANCE_IMAGE_TIER = "trusted code that needs native capabilities belongs in the owner-built node image; celld has no runtime admission path";
const TWO_TIER_GUIDANCE = "Two deployment paths exist: (1) " + GUIDANCE_WASM_TIER + "; (2) " + GUIDANCE_IMAGE_TIER + ".";
const CELLD_IMAGE_ONLY_GUIDANCE =
	CELLD_IMAGE_ONLY_CODE + ": celld runtime admission is permanently removed; celld applications enter this node only through the owner-built node image. " +
	TWO_TIER_GUIDANCE;
// Kernel 对已移除 celld 准入端点的终态错误（410 CELLD_ADMISSION_REMOVED）不裸传历史
// 端点语义：任何残余透传都在 MCP 边界映射为这份有界呈现。
const CELLD_ADMISSION_REMOVED_PRESENTATION =
	"The Kernel retired the celld admission endpoints permanently (terminal state CELLD_ADMISSION_REMOVED). " + CELLD_IMAGE_ONLY_GUIDANCE;

function isRecordObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireApplicationId(value: unknown): string {
	if (typeof value !== "string" || !APPLICATION_ID_PATTERN.test(value)) {
		throw new Error("applicationId must be lowercase letters, digits, and hyphens");
	}
	return value;
}

function requireVersionId(value: unknown): string {
	if (typeof value !== "string" || !VERSION_ID_PATTERN.test(value)) {
		throw new Error("versionId must be a 64-character lowercase hex digest");
	}
	return value;
}

function celldTargetMessage(detail: string): string {
	return CELLD_IMAGE_ONLY_CODE + ": " + detail + "; celld is image-only. " + TWO_TIER_GUIDANCE;
}

// 已退役的 celld 准入生命周期工具：不触达任何 Kernel 端点，只回有界引导。
// wasm 执行生命周期由 Kernel /v1/wasm/* 控制面驱动；MCP 只保留读投影与准入透传。
function retiredLifecycleError(toolName: string): Error {
	return new Error(
		toolName +
			" is retired: the celld admission lifecycle it drove no longer exists; the Kernel answers those removed endpoints with the terminal state CELLD_ADMISSION_REMOVED. " +
			"Wasm application state is read from the Kernel /v1/wasm/status projection (iweb_application_list, iweb_application_versions, iweb_application_inspect) and wasm execution lifecycle is driven by the Kernel /v1/wasm/* control plane. " +
			CELLD_IMAGE_ONLY_GUIDANCE,
	);
}

function unknownWasmApplicationError(applicationId: string): Error {
	return new Error(
		'application "' +
			applicationId +
			'" has no admitted wasm versions in the Kernel projection. If this is a celld-seeded application it is image-only and has no runtime admission. ' +
			CELLD_IMAGE_ONLY_GUIDANCE,
	);
}

const applicationTools = [
	{
		name: "iweb_application_list",
		description:
			"List the admitted wasm applications with runtime kind, retained versions, active pointer, and route generation, read from the Kernel /v1/wasm/status projection. celld applications are image-seeded fleet entries, not runtime admissions; list their routes with iweb_domain_list. " +
			TWO_TIER_GUIDANCE,
		inputSchema: { type: "object", properties: {}, additionalProperties: false },
	},
	{
		name: "iweb_application_admit",
		description:
			"Admit a wasm application version: forward a Kernel wasm admission transaction (schemaVersion 1 wire: wasi:http component package with base64 blobs, normalized policy, runtime binding, capability pin) to the Kernel admission contract and report its structured result verbatim. celld is not a valid admission target. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				kind: {
					type: "string",
					description: 'Optional explicit target runtime kind; only "wasm" is accepted. Naming celld (or any non-wasm kind) is rejected with the CELLD_IMAGE_ONLY guidance before any kernel call.',
				},
				transaction: {
					type: "object",
					description: "The Kernel wasm admission transaction object, forwarded verbatim; the Kernel validates the package, policy, and capability matrix and returns the structured admission result.",
				},
			},
			required: ["transaction"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_prepare",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Wasm execution preparation is driven by the Kernel /v1/wasm/* control plane, not by MCP. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_readiness",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Wasm readiness is part of the Kernel admission and activation contract. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_activate",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Wasm route-pointer activation is a Kernel /v1/wasm/* control-plane operation with its own acceptance contract. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_start",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Wasm execution lifecycle is supervised by the Kernel; celld fleet processes are restarted only by the node entrypoint. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_stop",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Stopping a celld application is an image/entrypoint concern; wasm execution lifecycle belongs to the Kernel control plane. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_rollback",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Wasm route-pointer rollback is a Kernel /v1/wasm/* control-plane operation with its own acceptance contract. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_delete_version",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Retired wasm versions are managed by the Kernel control plane, never by MCP. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_inspect",
		description:
			"Inspect one admitted wasm application from the Kernel /v1/wasm/status projection: runtime kind, retained versions, active pointer, and route generation. celld applications are image-seeded and have no runtime lifecycle to inspect. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string", description: "Wasm application id, e.g. vector" },
			},
			required: ["applicationId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_versions",
		description:
			"List the retained admitted wasm versions of one application (version identity, lifecycle, active pointer) from the Kernel /v1/wasm/status projection. celld applications are image-seeded and have no admitted versions. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
			},
			required: ["applicationId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_delete_data",
		description:
			"Retired (two-tier trust): the celld admission lifecycle is permanently removed; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Wasm persistent-data destruction is a Kernel control-plane operation, never an MCP tool side effect. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
			},
			required: ["applicationId"],
			additionalProperties: false,
		},
	},
	{
		name: "iweb_application_metrics",
		description:
			"Retired (two-tier trust): the celld sandbox metrics projection behind this tool no longer exists; this tool performs no operation and returns the bounded CELLD_IMAGE_ONLY guidance. Wasm engine metrics flow through the Kernel monitor surface; wasm registry state is available via iweb_application_inspect. " +
			TWO_TIER_GUIDANCE,
		inputSchema: {
			type: "object",
			properties: {
				applicationId: { type: "string" },
				versionId: { type: "string", description: "64-character lowercase hex version digest" },
			},
			required: ["applicationId", "versionId"],
			additionalProperties: false,
		},
	},
];

export const tools = [
	{
		name: "iweb_workspace_list",
		description: "List the unified iweb MinIO workspace. Application folders and ordinary files share the same root.",
		inputSchema: { type: "object", properties: { prefix: { type: "string", description: "Optional path prefix" } }, additionalProperties: false },
	},
	{
		name: "iweb_workspace_read_text",
		description: "Read a UTF-8 text file from the unified iweb workspace.",
		inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false },
	},
	{
		name: "iweb_workspace_write_text",
		description: "Write a UTF-8 text file to the unified iweb workspace. This writes source or assets; workspace writes never deploy, admit, or publish code of either tier.",
		inputSchema: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"], additionalProperties: false },
	},
	{
		name: "iweb_workspace_delete",
		description: "Delete one workspace file. This permanently removes that MinIO object.",
		inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false },
	},
	{
		name: "iweb_domain_list",
		description: "List iweb domain mappings, including protected admin and mcp system mappings.",
		inputSchema: { type: "object", properties: {}, additionalProperties: false },
	},
	{
		name: "iweb_domain_register",
		description:
			"Register a user application domain in the required <app>.app namespace. User routes target the wasm tier; celld targets exist only on image-seeded system routes and cannot be registered here. " +
			TWO_TIER_GUIDANCE,
		inputSchema: { type: "object", properties: { hostId: { type: "string" }, appName: { type: "string" } }, required: ["hostId", "appName"], additionalProperties: false },
	},
	...applicationTools,
];

// 已退役工具（原 celld 准入生命周期驱动面）：调度只回有界引导，绝不发出 kernel 调用。
const retiredApplicationTools = new Set([
	"iweb_application_prepare",
	"iweb_application_readiness",
	"iweb_application_activate",
	"iweb_application_start",
	"iweb_application_stop",
	"iweb_application_rollback",
	"iweb_application_delete_version",
	"iweb_application_delete_data",
	"iweb_application_metrics",
]);

function argsOf(raw: unknown): Record<string, unknown> {
	return isRecordObject(raw) ? raw : {};
}

function workspacePath(input: Record<string, unknown>): string {
	return String(input.path ?? "");
}

// /v1/wasm/status 投影行的有界读取：只保留对象形行，字段由 Kernel 投影权威决定。
async function wasmStatusRows(context: ToolContext): Promise<Array<Record<string, unknown>>> {
	const status = await context.kernelFetch("/v1/wasm/status");
	const applications = (status as { applications?: unknown }).applications;
	return Array.isArray(applications) ? applications.filter(isRecordObject) : [];
}

function findWasmApplication(rows: Array<Record<string, unknown>>, applicationId: string): Record<string, unknown> | null {
	return rows.find((row) => row.applicationId === applicationId) ?? null;
}

async function dispatch(name: string, input: Record<string, unknown>, context: ToolContext): Promise<unknown> {
	switch (name) {
		case "iweb_workspace_list":
			return { result: await context.kernelFetch("/v1/workspace?prefix=" + encodeURIComponent(String(input.prefix ?? ""))) };
		case "iweb_workspace_read_text":
			return { result: await context.kernelFetch("/v1/workspace/file?path=" + encodeURIComponent(workspacePath(input))) };
		case "iweb_workspace_write_text":
			return { result: await context.kernelFetch("/v1/workspace/file", { method: "PUT", body: JSON.stringify(input) }) };
		case "iweb_workspace_delete":
			return { result: await context.kernelFetch("/v1/workspace/file?path=" + encodeURIComponent(workspacePath(input)), { method: "DELETE" }) };
		case "iweb_domain_list":
			return { result: await context.kernelFetch("/v1/routes") };
		case "iweb_domain_register":
			return { result: await context.kernelFetch("/v1/routes", { method: "POST", body: JSON.stringify(input) }) };
		case "iweb_application_list":
			return { result: { applications: await wasmStatusRows(context) } };
		case "iweb_application_admit": {
			const transaction = input.transaction;
			if (!isRecordObject(transaction)) {
				throw new Error("transaction must be the Kernel wasm admission transaction object (schemaVersion 1 wire)");
			}
			// celld 目标在 MCP 边界拒绝（两层引导），绝不把 celld 语义带回 Kernel。
			const declaredKind = typeof input.kind === "string" ? input.kind : undefined;
			if (declaredKind !== undefined && declaredKind !== "wasm") {
				throw new Error(celldTargetMessage('iweb_application_admit was asked to admit runtime kind "' + declaredKind + '"'));
			}
			const binding = transaction.runtimeBinding;
			const bindingKind = isRecordObject(binding) && typeof binding.kind === "string" ? binding.kind : undefined;
			if (bindingKind !== undefined && bindingKind !== "wasm") {
				throw new Error(celldTargetMessage('the admission transaction names runtimeBinding.kind "' + bindingKind + '"'));
			}
			// 准入事务逐字透传：包/策略/能力矩阵校验的唯一权威是 Kernel 准入契约。
			return { result: await context.kernelFetch("/v1/wasm/admission", { method: "POST", body: JSON.stringify(transaction) }) };
		}
		case "iweb_application_inspect": {
			const applicationId = requireApplicationId(input.applicationId);
			const rows = await wasmStatusRows(context);
			const row = findWasmApplication(rows, applicationId);
			if (!row) throw unknownWasmApplicationError(applicationId);
			return { result: row };
		}
		case "iweb_application_versions": {
			const applicationId = requireApplicationId(input.applicationId);
			const rows = await wasmStatusRows(context);
			const row = findWasmApplication(rows, applicationId);
			if (!row) throw unknownWasmApplicationError(applicationId);
			return { result: { applicationId, runtimeKind: row.runtimeKind ?? "wasm", active: row.active ?? null, versions: row.versions ?? [] } };
		}
		default: {
			if (retiredApplicationTools.has(name)) {
				// 有界输入纪律保留：先拒绝畸形 id，再回两层引导；全程零 kernel 调用。
				requireApplicationId(input.applicationId);
				if (name !== "iweb_application_delete_data") requireVersionId(input.versionId);
				throw retiredLifecycleError(name);
			}
			throw new Error("unknown MCP tool: " + name);
		}
	}
}

// 调度层只传播有界错误文本：任何异常都被重新包装为不含堆栈的 Error，
// 因此 Kernel 的 {error} 文本可以到达代理，而堆栈与内部细节不会。
// 若消息本身混入了 "at <file>" 堆栈行，也在边界处截断。
function boundedMessage(error: unknown): string {
	const raw = error instanceof Error ? error.message : "MCP tool failed";
	const lines = raw.split("\n");
	const kept = [];
	for (const line of lines) {
		if (/^\s+at\s/.test(line) || /^\s+node:internal\//.test(line)) break;
		kept.push(line);
	}
	const bounded = kept.join("\n").trim();
	// 已移除 celld 准入端点的 Kernel 终态（CELLD_ADMISSION_REMOVED）映射为有界引导呈现，
	// 不向代理裸传历史端点语义。
	if (bounded.includes("CELLD_ADMISSION_REMOVED")) return CELLD_ADMISSION_REMOVED_PRESENTATION;
	return bounded;
}

interface ToolContext {
	kernelFetch(path: string, init?: RequestInit): Promise<{ ok: boolean; [key: string]: unknown }>;
}

export async function dispatchTool(name: string, args: Record<string, unknown>, context: ToolContext): Promise<Record<string, unknown>> {
	try {
		return await dispatch(name, argsOf(args), context) as { content: Array<{ type: string; text: string }> };
	} catch (error: unknown) {
		throw new Error(boundedMessage(error));
	}
}
