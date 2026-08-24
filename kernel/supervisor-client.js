// 用户原始需求（2026-08-14）：Kernel 只能经私有 Unix socket 识别独立 sandbox supervisor，不能获得 OCI daemon 权限。
// 正交意图：固定健康端点；限制响应规模；限制等待时间；失败时返回不可用而不泄露宿主细节。
const http = require("node:http");

const MAXIMUM_RESPONSE_BYTES = 16 * 1024;

function supervisorHealth(socketPath, options = {}) {
  if (!socketPath) return Promise.resolve({ configured: false, available: false, version: null });
  const timeoutMs = options.timeoutMs ?? 500;
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const request = http.request({ socketPath, method: "GET", path: "/v1/health", timeout: timeoutMs }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
        if (Buffer.byteLength(body, "utf8") > MAXIMUM_RESPONSE_BYTES) request.destroy();
      });
      response.on("end", () => {
        try {
          const value = JSON.parse(body);
          const valid = response.statusCode === 200 && value?.service === "iweb-sandbox-supervisor" && value.version === 1 && value.ready === true;
          finish({ configured: true, available: valid, version: valid ? 1 : null });
        } catch {
          finish({ configured: true, available: false, version: null });
        }
      });
    });
    request.once("timeout", () => request.destroy());
    request.once("error", () => finish({ configured: true, available: false, version: null }));
    request.end();
  });
}

module.exports = { supervisorHealth };
