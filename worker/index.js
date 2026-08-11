// 用户原始需求（2026-08-12）：admin/mcp 等以应用方式部署，api 保留在 Kernel；应用代码按项目/app 组织。
// 正交意图：解析 celld 应用主机；分发内置 admin；保留 notes Durable Object demo。
// 不可调和的原因：celld 当前一个 fleet 只加载一个 Worker，Dispatcher 必须作为唯一部署入口。
import { fetch as fetchAdmin } from "./apps/admin/app/index.js";

function appNameFromHost(host) {
  const marker = ".app.";
  const markerIndex = host.indexOf(marker);
  return markerIndex > 0 ? host.slice(0, markerIndex) : null;
}

function appNameFromRequest(request) {
  const host = request.headers.get("host") ?? new URL(request.url).host;
  return appNameFromHost(host.split(":")[0].toLowerCase());
}

export class AppCell {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const appName = appNameFromRequest(request);
    if (!appName) {
      return Response.json({ error: "missing app subdomain" }, { status: 400 });
    }

    const visits = ((await this.state.storage.get("visits")) ?? 0) + 1;
    await this.state.storage.put("visits", visits);

    return Response.json({
      app: appName,
      runtime: "celld",
      storage: "durable-object-sqlite",
      visits,
    });
  }
}

export default {
  async fetch(request, env) {
    const appName = appNameFromRequest(request);
    if (!appName) {
      return Response.json({ error: "use a registered <app>.app.<base> host" }, { status: 404 });
    }
    if (appName === "admin") return fetchAdmin(request, env);

    const id = env.APP_CELL.idFromName(appName);
    return env.APP_CELL.get(id).fetch(request);
  },
};
