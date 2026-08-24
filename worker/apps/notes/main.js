// 用户原始需求（2026-08-15）：notes 作为普通 celld 应用部署（沙箱迁移前的 image-seeded 回滚权威）。
// 正交意图：NotesCell Durable Object 类随主模块再导出，供 wrangler DO 绑定解析。
import * as app from "./app/index.js";

export { NotesCell } from "./app/index.js";

export default {
  fetch: (request, env) => app.fetch(request, env),
};
