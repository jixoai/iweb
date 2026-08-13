// 用户原始需求（2026-08-13）：工作区提供企业级代码编辑，而不仅是对象列表。
// 正交意图：按文件扩展名选择 CodeMirror 语言支持；保持未知文本可编辑；不承担文件读取或保存。
import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import type { Extension } from "@codemirror/state";

export function languageExtensionFor(path: string): Extension {
	const extension = path.split(".").at(-1)?.toLowerCase();
	switch (extension) {
		case "js":
		case "mjs":
		case "cjs":
		case "ts":
		case "mts":
		case "cts":
			return javascript({ typescript: extension.includes("ts") });
		case "json":
			return json();
		case "html":
		case "htm":
			return html();
		case "css":
			return css();
		case "md":
		case "mdx":
			return markdown();
		default:
			return [];
	}
}
