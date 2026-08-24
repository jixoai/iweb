// 用户原始需求（2026-08-13）：MCP 工具从请求处理器拆出，让部署代理验证、发布与运维应用。
// 正交意图：工具定义与调度是纯 ESM，可被 bun test 直接导入；不依赖 Worker 全局；
// 不接触 request/env，因此绝不持有 owner key；Kernel 边界错误只以文本传播，不带堆栈。
export const serverInfo = { name: "iweb-mcp", version: "0.2.0" };

const APPLICATION_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const VERSION_ID_PATTERN = /^[a-f0-9]{64}$/;

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

// 策略权威只有 workspace iweb.json：Kernel 在 admission 时校验 manifest 并
// 由 manifest 推导 NormalizedPolicy；MCP 不接受任何 policy 覆盖。

const applicationTools = [
  {
    name: "iweb_application_list",
    description: "List every admitted application with its sandbox identity, active version, lifecycle state, route generation, and version history.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "iweb_application_admit",
    description:
      "Admit a new immutable version of a workspace application from the canonical owner workspace snapshot. The Kernel collects and validates the package (iweb.json manifest is the sole policy authority) and creates the version exactly once.",
    inputSchema: {
      type: "object",
      properties: {
        applicationId: { type: "string", description: "Workspace application id, e.g. notes" },
      },
      required: ["applicationId"],
      additionalProperties: false,
    },
  },
  {
    name: "iweb_application_prepare",
    description: "Prepare an admitted version: persist its sandbox credential and create the sandbox runtime without starting traffic.",
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
    description: "Probe the prepared sandbox against the fixed health contract and record a readiness lease on success.",
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
    description: "Atomically activate a ready version: switch the active pointer, increment the route generation, and retire the previous active version.",
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
    description: "Start a prepared or stopped sandbox runtime.",
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
    description: "Stop a running sandbox runtime without deleting the retained version.",
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
    description: "Roll back to a retained admitted version through the same readiness gate; the target must be ready with a valid readiness lease.",
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
    description: "Delete a retained non-active version and its sandbox runtime. The active version is protected by the Kernel.",
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
    description: "Inspect one version's sandbox runtime through the supervisor protocol: runtime state, identity, and observed lifecycle.",
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
    name: "iweb_application_versions",
    description: "List the retained versions of one application with lifecycle state, sequence, and the active pointer. Use this to pick a rollback target or a safe version to delete.",
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
    description: "Owner-authorized destruction of an application's persistent-data namespace. This is a SEPARATE destructive operation from version deletion: deleting versions never touches this data, and this operation destroys it permanently.",
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
      "Return the application projection from the live node status, including sandbox identity, active version, lifecycle, and the measured resources sample (per-version metrics arrive through the projection's resources field with limits and an availability flag).",
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
    description: "Write a UTF-8 text file to the unified iweb workspace. This writes source or assets; deployment remains an explicit future operation.",
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
    description: "Register a user application domain in the required <app>.app namespace.",
    inputSchema: { type: "object", properties: { hostId: { type: "string" }, appName: { type: "string" } }, required: ["hostId", "appName"], additionalProperties: false },
  },
  ...applicationTools,
];

const lifecycleActions = {
  iweb_application_prepare: "prepare",
  iweb_application_readiness: "readiness",
  iweb_application_activate: "activate",
  iweb_application_start: "start",
  iweb_application_stop: "stop",
  iweb_application_rollback: "rollback",
};

function argsOf(raw: unknown): Record<string, unknown> {
  return raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
}

function workspacePath(input: Record<string, unknown>): string {
  return String(input.path ?? "");
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
      return { result: await context.kernelFetch("/v1/applications") };
    case "iweb_application_admit": {
      const applicationId = requireApplicationId(input.applicationId);
      return {
        result: await context.kernelFetch("/v1/applications/" + encodeURIComponent(applicationId) + "/versions", {
          method: "POST",
          body: JSON.stringify({}),
        }),
      };
    }
    case "iweb_application_metrics": {
      const applicationId = requireApplicationId(input.applicationId);
      requireVersionId(input.versionId);
      const status = await context.kernelFetch("/v1/status") as { applications?: unknown };
      const projection = asApplicationArray(status?.applications).find((app) => app.id === applicationId) ?? null;
      if (!projection) throw new Error("application \"" + applicationId + "\" not found in node status");
      return { result: projection };
    }
    case "iweb_application_inspect": {
      const applicationId = requireApplicationId(input.applicationId);
      const versionId = requireVersionId(input.versionId);
      return {
        result: await context.kernelFetch("/v1/applications/" + encodeURIComponent(applicationId) + "/versions/" + versionId),
      };
    }
    case "iweb_application_versions": {
      const applicationId = requireApplicationId(input.applicationId);
      const listing = await context.kernelFetch("/v1/applications") as { applications?: unknown };
      const projection = asApplicationArray(listing?.applications).find((app) => app.id === applicationId) ?? null;
      if (!projection) throw new Error("application \"" + applicationId + "\" has no admitted versions");
      return { result: { applicationId, active: projection.activeVersion ?? null, versions: projection.versions ?? [] } };
    }
    case "iweb_application_delete_data": {
      const applicationId = requireApplicationId(input.applicationId);
      return {
        result: await context.kernelFetch("/v1/applications/" + encodeURIComponent(applicationId) + "/data", {
          method: "DELETE",
        }),
      };
    }
    case "iweb_application_delete_version": {
      const applicationId = requireApplicationId(input.applicationId);
      const versionId = requireVersionId(input.versionId);
      // Active-version safety (9.2): refuse locally BEFORE the destructive
      // call when the requested version is the one the active pointer serves.
      // The Kernel enforces the same protection; this pre-flight gives the
      // agent a bounded, actionable error without a state change request.
      const listing = await context.kernelFetch("/v1/applications") as { applications?: unknown };
      const projection = asApplicationArray(listing?.applications).find((app) => app.id === applicationId) ?? null;
      if (projection && projection.activeVersion?.digest === versionId) {
        throw new Error("the active version cannot be deleted; activate another version or roll back first");
      }
      return {
        result: await context.kernelFetch(
          "/v1/applications/" + encodeURIComponent(applicationId) + "/versions/" + versionId,
          { method: "DELETE" },
        ),
      };
    }
    default: {
      const action = (lifecycleActions as Record<string, string | undefined>)[name];
      if (action) {
        const applicationId = requireApplicationId(input.applicationId);
        const versionId = requireVersionId(input.versionId);
        return {
          result: await context.kernelFetch(
            "/v1/applications/" + encodeURIComponent(applicationId) + "/versions/" + versionId + "/" + action,
            { method: "POST" },
          ),
        };
      }
      throw new Error("unknown MCP tool: " + name);
    }
  }
}

// 调度层只传播有界错误文本：任何异常都被重新包装为不含堆栈的 Error，
// 因此 Kernel 的 {error} 文本可以到达代理，而堆栈与内部细节不会。
// 若消息本身混入了 "at <file>" 堆栈行，也在边界处截断。
type ApplicationEntry = { id?: string; activeVersion?: { digest?: string }; versions?: unknown[] };

function isApplicationEntry(value: unknown): value is ApplicationEntry {
  return typeof value === "object" && value !== null && "id" in value;
}

function asApplicationArray(source: unknown): ApplicationEntry[] {
  return Array.isArray(source) ? source.filter(isApplicationEntry) : [];
}

function textResult(value: unknown): { content: Array<{ type: string; text: string }> } {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] };
}

function boundedMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : "MCP tool failed";
  const lines = raw.split("\n");
  const kept = [];
  for (const line of lines) {
    if (/^\s+at\s/.test(line) || /^\s+node:internal\//.test(line)) break;
    kept.push(line);
  }
  return kept.join("\n").trim();
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
