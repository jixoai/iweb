// Orthogonal intents (2026-09-06): [official-site] iweb 官网静态构建；
// [base-path] SITE_BASE → kit.paths.base，一份代码同时支持 GitHub Pages
// 子路径（jixoai.github.io/openiweb）与自定义域名根路径两种服务形态；
// [static-output] adapter-static 全量预渲染，无服务端运行时。
//
// Original request (2026-09-06, Asia/Shanghai): 新增 ./openiweb 官网站点。
// base-path 契约：SITE_BASE=/openiweb 时 kit.paths.base = "/openiweb"，站内链接
// 一律走 $app/paths 的 base（严禁硬编码前缀）；留空 = 根路径服务（Owner
// 配好 DNS 后，配合 SITE_CNAME=1 的 CNAME 门控切换，无代码变更）。
import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** 把环境变量规格化成 SvelteKit base："/openiweb" 或 "openiweb" → "/openiweb"；空 → ""。 */
function resolveBase(raw) {
	if (!raw) return "";
	return `/${String(raw).replace(/^\/+|\/+$/g, "")}`;
}

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess({ script: true }),
	kit: {
		adapter: adapter({ pages: "dist", assets: "dist", strict: true }),
		// GitHub Pages 子路径起步：绝对资源 URL 由 base 前缀承载。
		paths: { base: resolveBase(process.env.SITE_BASE), relative: false },
	},
};

export default config;
