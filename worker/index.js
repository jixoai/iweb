// 用户原始需求（2026-08-11）：通过 <app>.app.<username>.iweb.xin 执行单租户家庭节点的应用代码。
// 约束：celld v0.1.0 的一个 fleet 只加载一个 Worker；此路由 Worker 是该 fleet 的应用汇编点。
function appNameFromHost(host) {
  const appMarker = ".app.";
  const markerIndex = host.indexOf(appMarker);
  return markerIndex > 0 ? host.slice(0, markerIndex) : null;
}

function appNameFromRequest(request) {
  const host = request.headers.get("host") ?? new URL(request.url).host;
  return appNameFromHost(host.split(":")[0]);
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
      return Response.json({ error: "use <app>.app.<domain>" }, { status: 404 });
    }

    const id = env.APP_CELL.idFromName(appName);
    return env.APP_CELL.get(id).fetch(request);
  },
};
