// 用户原始需求（2026-08-12）：用 SvelteKit 与 shadcn-svelte 交付企业级 iweb Admin。
// 正交意图：静态预渲染；让内置 celld Worker 只需提供资产；不在构建产物中注入控制面密钥。
export const prerender = true;
