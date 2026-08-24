// 用户原始需求（2026-08-22）：iweb 实用性实战 2——需要数据库的搜索网站。
// 正交意图：搜索完全走 D1 SQL（绑定参数防注入）；静态 UI 由本 Worker 直出。
// 安全底线：查询词永不拼接进 SQL 文本，只作为绑定参数；错误细节不回显给访客。
// TS 化（2026-08-24）：@cloudflare/workers-types 上下文安全；escapeHtml 从 worker-shared 相对源码 import。
import { escapeHtml } from "../../../../packages/worker-shared/src/html.ts";

interface CheatsheetRow {
	command: string;
	description: string;
	category: string;
}

interface Env {
	DB: D1Database;
}

const page = (rows: CheatsheetRow[], query: string) => `<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>命令速查 · iweb 搜索实战</title>
	<style>
		body { font-family: system-ui, -apple-system, "PingFang SC", sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }
		header { padding: 2rem 1.5rem 1rem; max-width: 42rem; margin: 0 auto; }
		form { display: flex; gap: .5rem; }
		input { flex: 1; padding: .7rem 1rem; border: 1px solid #cbd5e1; border-radius: .6rem; font-size: 1rem; }
		button { padding: .7rem 1.4rem; border: 0; border-radius: .6rem; background: #0f172a; color: white; font-size: 1rem; cursor: pointer; }
		main { max-width: 42rem; margin: 0 auto; padding: 1rem 1.5rem 3rem; }
		.row { background: white; border-radius: .6rem; padding: .8rem 1rem; margin-bottom: .6rem; box-shadow: 0 2px 8px rgb(15 23 42 / .06); }
		.cmd { font-family: ui-monospace, monospace; background: #f1f5f9; padding: .1em .4em; border-radius: .3em; }
		.note { color: #64748b; }
		.count { color: #475569; margin: .8rem 0; }
	</style>
</head>
<body>
	<header>
		<h1>命令速查搜索</h1>
		<p class="note">数据存放在 celld D1（SQLite）数据库 <code>search</code> 中，检索由 SQL LIKE 完成。</p>
		<form method="get" action="/">
			<input name="q" placeholder="例如：端口 / 回滚 / 镜像" value="${escapeHtml(query)}" autofocus />
			<button type="submit">搜索</button>
		</form>
	</header>
	<main>
		${query ? `<p class="count">“${escapeHtml(query)}” 命中 ${rows.length} 条</p>` : `<p class="count">输入关键词开始搜索（库中共 ${rows.length} 条）</p>`}
		${rows.map((row: CheatsheetRow) => `<div class="row"><span class="cmd">${escapeHtml(row.command)}</span> — ${escapeHtml(row.description)} <span class="note">（${escapeHtml(row.category)}）</span></div>`).join("")}
	</main>
</body>
</html>`;

// LIKE 通配符转义：搜索语义是字面匹配（Codex 安全挑战建议——否则 %/_ 变宽查询）。
const escapeLike = (value: string): string => value.replaceAll("\\", "\\\\").replaceAll("%", "\\%").replaceAll("_", "\\_");

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		if (request.method !== "GET" || url.pathname !== "/") {
			return new Response("not found", { status: 404 });
		}
		const query: string = (url.searchParams.get("q") ?? "").trim().slice(0, 64);
		try {
			const statement = query
				? env.DB.prepare("SELECT command, description, category FROM cheatsheet WHERE command LIKE ?1 ESCAPE '\\' OR description LIKE ?1 ESCAPE '\\' ORDER BY command LIMIT 50").bind(`%${escapeLike(query)}%`)
				: env.DB.prepare("SELECT command, description, category FROM cheatsheet ORDER BY command LIMIT 50");
			const { results } = await statement.all<CheatsheetRow>();
			return new Response(page(results ?? [], query), { headers: { "content-type": "text/html; charset=utf-8" } });
		} catch (error: unknown) {
			// 数据库错误细节只进日志，访客拿到泛化错误。
			console.error("search failed", error);
			return new Response("search is temporarily unavailable", { status: 503 });
		}
	},
};
