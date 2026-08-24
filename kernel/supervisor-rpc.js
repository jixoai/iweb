// 用户原始需求（2026-08-14）：Kernel 只能经 0600 Unix socket 使用窄 supervisor 协议；错误有界且不回显凭据；响应规模受限。
// 正交意图：prepare/start/stop/inspect/metrics/delete 客户端；版本化请求；语义错误稳定映射。
const http = require("node:http");
const bundle = require("./contracts-bundle.cjs");

const MAXIMUM_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;

class SupervisorRpcError extends Error {
  constructor(code, status) {
    super(code);
    this.name = "SupervisorRpcError";
    this.code = code;
    this.status = status;
  }
}

function rpc(socketPath, operation, payload, options = {}) {
  if (!socketPath) return Promise.reject(new SupervisorRpcError("SUPERVISOR_NOT_CONFIGURED", null));
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const body = JSON.stringify({ version: 1, operation, ...payload });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const request = http.request(
      { socketPath, method: "POST", path: "/v1/rpc", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, timeout: timeoutMs },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          text += chunk;
          if (Buffer.byteLength(text, "utf8") > MAXIMUM_RESPONSE_BYTES) {
            request.destroy();
            finish(new SupervisorRpcError("SUPERVISOR_RESPONSE_TOO_LARGE", null));
          }
        });
        response.on("end", () => {
          try {
            const parsed = JSON.parse(text);
            if (response.statusCode === 200) {
              // Kernel never trusts a supervisor response shape or identity:
              // validate per-operation fields with the shared contract, then
              // correlate the echoed identities (operation, sandboxId, and the
              // metrics versionId) with the request (2.28).
              const validated = bundle.validateSupervisorResponse(parsed);
              if (!validated.ok) throw new Error("invalid response shape");
              const correlated = bundle.correlateResponse({ version: 1, operation, ...payload }, validated.value);
              if (!correlated.ok) throw new Error("response identity mismatch");
              finish(null, correlated.value);
            } else {
              finish(new SupervisorRpcError(parsed?.code ?? "SUPERVISOR_ERROR", response.statusCode));
            }
          } catch {
            finish(new SupervisorRpcError("SUPERVISOR_INVALID_RESPONSE", response.statusCode));
          }
        });
      },
    );
    request.once("timeout", () => {
      request.destroy();
      finish(new SupervisorRpcError("SUPERVISOR_TIMEOUT", null));
    });
    request.once("error", () => finish(new SupervisorRpcError("SUPERVISOR_UNREACHABLE", null)));
    request.write(body);
    request.end();
  });
}

function prepare(socketPath, request, options) {
  return rpc(socketPath, "prepare", request, options);
}

function start(socketPath, sandboxId, options) {
  return rpc(socketPath, "start", { sandboxId }, options);
}

function stop(socketPath, sandboxId, options) {
  return rpc(socketPath, "stop", { sandboxId }, options);
}

function inspect(socketPath, sandboxId, options) {
  return rpc(socketPath, "inspect", { sandboxId }, options);
}

function metrics(socketPath, sandboxId, versionId, options) {
  return rpc(socketPath, "metrics", { sandboxId, versionId }, options);
}

function remove(socketPath, sandboxId, options) {
  return rpc(socketPath, "delete", { sandboxId }, options);
}

// Bounded HTTP GET over a unix socket, used by Kernel for the gateway ingress
// readiness contract. Never follows redirects and never reflects diagnostics.
function socketGet(socketPath, path, options = {}) {
  const timeoutMs = options.timeoutMs ?? 5000;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const request = http.request({ socketPath, method: "GET", path, timeout: timeoutMs }, (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        text += chunk;
        if (Buffer.byteLength(text, "utf8") > MAXIMUM_RESPONSE_BYTES) {
          request.destroy();
          finish(new SupervisorRpcError("INGRESS_RESPONSE_TOO_LARGE", null));
        }
      });
      response.on("end", () => finish(null, { status: response.statusCode ?? 0, body: text }));
    });
    request.once("timeout", () => {
      request.destroy();
      finish(new SupervisorRpcError("INGRESS_TIMEOUT", null));
    });
    request.once("error", () => finish(new SupervisorRpcError("INGRESS_UNREACHABLE", null)));
    request.end();
  });
}

module.exports = { SupervisorRpcError, rpc, prepare, start, stop, inspect, metrics, remove, socketGet };
