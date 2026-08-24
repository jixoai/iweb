// 用户原始需求（2026-08-15）：admin 作为普通 celld 应用部署：项目主模块需要 default export（celld v0.2 Worker loader 约定）。
// 正交意图：app/index.js 保持 workspace 契约（具名 fetch）；部署包装只存在于项目根，绝不进入用户工作区镜像。
import * as app from "./index.ts";
import type { Env } from "./index.ts";

export default {
  fetch: (request: Request, env: Env): Promise<Response> => app.fetch(request, env),
};
