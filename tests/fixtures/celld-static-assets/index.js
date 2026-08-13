// 用户原始需求（2026-08-13）：确认 celld v0.2 的 Worker-first 与原生资产 binding 语义。
// 正交意图：证明静态资源先经过 Worker；证明 env.ASSETS.fetch 返回原生响应。

export default {
  /** @param {Request} request @param {{ ASSETS: { fetch(request: Request): Promise<Response> } }} env */
  async fetch(request, env) {
    if (new URL(request.url).pathname === "/worker") {
      return new Response("worker response", { headers: { "x-fixture-worker": "direct" } });
    }
    const response = await env.ASSETS.fetch(request);
    const headers = new Headers(response.headers);
    headers.set("x-fixture-worker", "binding");
    return new Response(response.body, { status: response.status, headers });
  },
};
