// 用户原始需求（2026-08-12）：mcp 是一个可见、可替换的 celld 应用，让本地 Codex 管理 iweb 工作区。
// 正交意图：MCP 握手；鉴权每个 JSON-RPC 请求；将 owner key 原样转交 Kernel（仅当前请求）；
// 工具定义与调度在 tools.js（纯 ESM）；不在 Worker 内保存任何密钥。
import { serverInfo, tools, dispatchTool } from "./tools.js";

function jsonRpc(id, result) {
  return Response.json({ jsonrpc: "2.0", id, result });
}

function jsonRpcError(id, code, message) {
  return Response.json({ jsonrpc: "2.0", id, error: { code, message } }, { status: 400 });
}

function textResult(value) {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] };
}

async function kernel(request, env, path, init = {}) {
  const authorization = request.headers.get("authorization");
  const headers = new Headers(init.headers);
  // rust-kernel-rustfs-storage §5.3：X-Iweb-Internal-Control 头路由已废除（Codex R2），
  // 控制调用只凭 owner Bearer 打到回环控制监听器。
  if (authorization) headers.set("authorization", authorization);
  if (init.body) headers.set("content-type", "application/json");
  const origin = String(env.IWEB_KERNEL_ORIGIN ?? "");
  if (!origin) throw new Error("Kernel origin is not configured");
  // This module exports a Worker handler named `fetch`; qualify the platform
  // API so a control call cannot recursively invoke this handler.
  const response = await globalThis.fetch(origin + path, { ...init, headers });
  if (response.status === 204) return { deleted: true };
  const body = await response.json().catch(() => ({ error: "Kernel returned HTTP " + response.status }));
  if (!response.ok) {
    const detail = typeof body.error === "string" ? body.error : "Kernel returned HTTP " + response.status;
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
  if (message.method === "tools/list") return jsonRpc(message.id, { tools });
  if (message.method === "tools/call") {
    try {
      // The context forwards the current request's credential only; tools.js
      // never sees request or env and cannot store the owner key.
      const context = { kernelFetch: (path, init) => kernel(request, env, path, init) };
      return jsonRpc(message.id, textResult(await dispatchTool(message.params?.name, message.params?.arguments, context)));
    } catch (error) {
      return jsonRpc(message.id, { content: [{ type: "text", text: error instanceof Error ? error.message : "MCP tool failed" }], isError: true });
    }
  }
  return jsonRpcError(message.id, -32601, "method not found");
}
