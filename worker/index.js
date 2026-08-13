// 用户原始需求（2026-08-12）：admin/mcp 等以应用方式部署，api 保留在 Kernel；应用目录映射到统一存储根。
// 正交意图：解析 celld 应用主机；分发已实现的内置/示例应用；拒绝未实现应用；不暴露运行时内部状态。
// 不可调和的原因：celld 当前一个 fleet 只加载一个 Worker，Dispatcher 必须作为唯一部署入口。
import { fetch as fetchAdmin } from "./apps/admin/app/index.js";
import { fetch as fetchMcp } from "./apps/mcp/app/index.js";
import { fetch as fetchNotes, NotesCell } from "./apps/notes/app/index.js";

function appNameFromHost(host) {
  const marker = ".app.";
  const markerIndex = host.indexOf(marker);
  return markerIndex > 0 ? host.slice(0, markerIndex) : null;
}

function appNameFromRequest(request) {
  const host = request.headers.get("host") ?? new URL(request.url).host;
  return appNameFromHost(host.split(":")[0].toLowerCase());
}

// Kept solely so existing v1 Durable Object migrations remain resolvable for
// installations that already deployed the earlier demo. It is never routed.
export class AppCell {
  constructor(state) {
    this.state = state;
  }
}

export { NotesCell };

export default {
  async fetch(request, env) {
    const appName = appNameFromRequest(request);
    if (!appName) {
      return Response.json({ error: "use a registered <app>.app.<base> host" }, { status: 404 });
    }
    if (appName === "admin") return fetchAdmin(request, env);
    if (appName === "mcp") return fetchMcp(request, env);
    if (appName === "notes") return fetchNotes(request, env);
    return new Response("application unavailable", { status: 502, headers: { "cache-control": "no-store" } });
  },
};
