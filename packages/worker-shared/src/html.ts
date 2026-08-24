// HTML 转义（Worker-safe 纯函数；供 search/collab 等渲染型 Worker 复用）。
export function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;");
}
