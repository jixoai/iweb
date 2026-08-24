// 用户原始需求（2026-08-15）：mcp 作为普通 celld 应用部署：项目主模块需要 default export。
import * as app from "./index.ts";
import type { Env } from "./index.ts";

export default {
  fetch: (request: Request, env: Env): Promise<Response> => app.fetch(request, env),
};
