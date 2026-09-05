// Orthogonal intents (2026-09-06): [official-site] vite 构建入口；
// [design-language] @tailwindcss/vite 消费 jixoai token 表（CSS-first）；
// [ai-export] llmsTxt() 是唯一的 llms.txt 生成点（普通 vite build 站点用
// 插件形态，严禁再接编排式 generateLlmsTxt 造成双生成）。
//
// Original request (2026-09-06, Asia/Shanghai): 新增 ./openiweb 官网站点。
// baseUrl 契约：SITE_URL > 按 SITE_BASE 推导（子路径模式 →
// https://jixoai.github.io/openiweb；根路径模式 → https://jixoai.github.io，
// 自定义域名切换时由 workflow 同时设 SITE_URL + 置空 SITE_BASE）。
import { sveltekit } from "@sveltejs/kit/vite";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";
// registry item llms-txt 安装于项目相对路径 vite-plugins/llms-txt.mjs。
// @ts-expect-error — 无类型声明的 .mjs 注册表产物
import { llmsTxt } from "./vite-plugins/llms-txt.mjs";

function resolveBase(raw: string | undefined): string {
	if (!raw) return "";
	return `/${String(raw).replace(/^\/+|\/+$/g, "")}`;
}

const base = resolveBase(process.env.SITE_BASE);
const siteUrl =
	process.env.SITE_URL ?? `https://jixoai.github.io${base}`;

export default defineConfig({
	plugins: [
		sveltekit(),
		tailwindcss(),
		llmsTxt({
			distDir: "dist",
			siteUrl,
			title: "iweb",
			summary:
				"iweb is an open-source personal application node for people who don't want to learn containers, databases, or network operations: hand your MCP endpoint and one owner key to an AI coding agent, and it deploys and operates applications on your own node.",
		}),
	],
});
