// 用户原始需求（2026-08-24）：Worker 共享工具（HTML 转义、JSON 响应）。
// 正交意图：Worker-safe 纯函数，零 Node 依赖；celld 与 workers-types 的 API 差异本地声明。

export { escapeHtml } from "./html.ts";
export { jsonResponse } from "./responses.ts";
