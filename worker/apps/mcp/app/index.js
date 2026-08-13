// 用户原始需求（2026-08-12）：mcp 是一个可见、可替换的 celld 应用，让本地 Codex 管理 iweb 工作区。
// 正交意图：MCP 握手；声明工作区与域名工具；将 owner key 原样转交 Kernel；不在 Worker 内保存任何密钥。
const serverInfo = { name: "iweb-mcp", version: "0.1.0" };

function jsonRpc(id, result) {
  return Response.json({ jsonrpc: "2.0", id, result });
}

function jsonRpcError(id, code, message) {
  return Response.json({ jsonrpc: "2.0", id, error: { code, message } }, { status: 400 });
}

function textResult(value) {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] };
}

function tools() {
  return [
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
  ];
}

async function kernel(request, env, path, init = {}) {
  const authorization = request.headers.get("authorization");
  const headers = new Headers(init.headers);
  headers.set("x-iweb-internal-control", "1");
  if (authorization) headers.set("authorization", authorization);
  if (init.body) headers.set("content-type", "application/json");
  const origin = String(env.IWEB_KERNEL_ORIGIN ?? "");
  if (!origin) throw new Error("Kernel origin is not configured");
  // This module exports a Worker handler named `fetch`; qualify the platform
  // API so a control call cannot recursively invoke this handler.
  const response = await globalThis.fetch(`${origin}${path}`, { ...init, headers });
  if (response.status === 204) return { deleted: true };
  const body = await response.json().catch(() => ({ error: `Kernel returned HTTP ${response.status}` }));
  if (!response.ok) {
    const detail = typeof body.error === "string" ? body.error : `Kernel returned HTTP ${response.status}`;
    throw new Error(detail);
  }
  return body;
}

async function hasOwnerAccess(request, env) {
  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ") || authorization.slice(7).trim().length === 0) return false;
  try {
    await kernel(request, env, "/v1/status");
    return true;
  } catch {
    return false;
  }
}

async function callTool(request, env, name, input) {
  switch (name) {
    case "iweb_workspace_list":
      return kernel(request, env, `/v1/workspace?prefix=${encodeURIComponent(String(input?.prefix ?? ""))}`);
    case "iweb_workspace_read_text":
      return kernel(request, env, `/v1/workspace/file?path=${encodeURIComponent(String(input?.path ?? ""))}`);
    case "iweb_workspace_write_text":
      return kernel(request, env, "/v1/workspace/file", { method: "PUT", body: JSON.stringify(input ?? {}) });
    case "iweb_workspace_delete":
      return kernel(request, env, `/v1/workspace/file?path=${encodeURIComponent(String(input?.path ?? ""))}`, { method: "DELETE" });
    case "iweb_domain_list":
      return kernel(request, env, "/v1/routes");
    case "iweb_domain_register":
      return kernel(request, env, "/v1/routes", { method: "POST", body: JSON.stringify(input ?? {}) });
    default:
      throw new Error(`unknown MCP tool: ${name}`);
  }
}

export async function fetch(request, env) {
  if (request.method !== "POST") return new Response("iweb MCP accepts POST /mcp", { status: 405, headers: { allow: "POST" } });
  const url = new URL(request.url);
  if (url.pathname !== "/" && url.pathname !== "/mcp") return new Response("not found", { status: 404 });
  if (!(await hasOwnerAccess(request, env))) {
    return new Response("missing or invalid owner key", {
      status: 401,
      headers: { "cache-control": "no-store", "www-authenticate": "Bearer" },
    });
  }

  let message;
  try {
    message = await request.json();
  } catch {
    return jsonRpcError(null, -32700, "parse error");
  }
  if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    return jsonRpcError(message?.id ?? null, -32600, "invalid request");
  }
  if (message.method === "notifications/initialized") return new Response(null, { status: 202 });
  if (message.method === "initialize") {
    return jsonRpc(message.id, {
      protocolVersion: typeof message.params?.protocolVersion === "string" ? message.params.protocolVersion : "2025-11-25",
      capabilities: { tools: {} },
      serverInfo,
    });
  }
  if (message.method === "tools/list") return jsonRpc(message.id, { tools: tools() });
  if (message.method === "tools/call") {
    try {
      return jsonRpc(message.id, textResult(await callTool(request, env, message.params?.name, message.params?.arguments)));
    } catch (error) {
      return jsonRpc(message.id, { content: [{ type: "text", text: error instanceof Error ? error.message : "MCP tool failed" }], isError: true });
    }
  }
  return jsonRpcError(message.id, -32601, "method not found");
}
