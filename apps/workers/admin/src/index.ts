// 用户原始需求（2026-08-12）：admin 是可替换的 celld 应用，但要具备企业级管理 UI。
// 正交意图：交付 SvelteKit 静态资产；支持 root 与路径别名；维持 HTTP 缓存语义；不读取或保存 Kernel API token。

interface AdminAssets {
	fetch(request: Request): Promise<Response>;
}

export interface Env {
	ADMIN_ASSETS: AdminAssets;
}

const pathAliasPattern = /^\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/app\/$/;

function appBasePath(request: Request): string {
	const candidate = request.headers.get("x-iweb-app-base") ?? "";
	return pathAliasPattern.test(candidate) ? candidate : "";
}

async function indexResponse(request: Request, response: Response): Promise<Response> {
	const basePath = appBasePath(request);
	if (!basePath || request.method === "HEAD") return response;
	const headers = new Headers(response.headers);
	const html = await response.text();
	return new Response(html.replace("<head>", `<head><base href="${basePath}">`), {
		status: response.status,
		headers
	});
}

function assetRequest(request: Request, path: string): Request {
	const url = new URL(request.url);
	url.pathname = path;
	url.search = "";
	return new Request(url, request);
}

/** @param {Request} request @param {AdminEnvironment} env */
export async function fetch(request: Request, env: Env): Promise<Response> {
	if (request.method !== "GET" && request.method !== "HEAD") {
		return new Response("method not allowed", { status: 405, headers: { allow: "GET, HEAD" } });
	}

	const requestPath = new URL(request.url).pathname;
	if (requestPath !== "/") {
		const asset = await env.ADMIN_ASSETS.fetch(request);
		if (asset.status !== 404) return asset;
	}

	const index = await env.ADMIN_ASSETS.fetch(assetRequest(request, "/index.html"));
	if (!index.ok) return new Response("admin assets are unavailable", { status: 503 });
	return indexResponse(request, index);
}
