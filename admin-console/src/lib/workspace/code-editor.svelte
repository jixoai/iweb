<script lang="ts">
	// 用户原始需求（2026-08-13）：工作区使用 CodeMirror 提供完整编辑体验。
	// 正交意图：挂载编辑器；提供文本编辑能力；映射保存快捷键；同步受控文本值；不读取网络数据。
	import { onMount } from "svelte";
	import { autocompletion, closeBrackets, closeBracketsKeymap } from "@codemirror/autocomplete";
	import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
	import { bracketMatching, defaultHighlightStyle, foldGutter, indentOnInput, syntaxHighlighting } from "@codemirror/language";
	import { highlightSelectionMatches, searchKeymap } from "@codemirror/search";
	import { EditorState } from "@codemirror/state";
	import { drawSelection, dropCursor, EditorView, highlightActiveLine, highlightActiveLineGutter, highlightSpecialChars, keymap, lineNumbers } from "@codemirror/view";
	import { languageExtensionFor } from "$lib/workspace/code-editor-language";

	type Props = {
		path: string;
		content: string;
		readonly?: boolean;
		onchange: (content: string) => void;
		onsave: () => void;
	};

	let { path, content, readonly = false, onchange, onsave }: Props = $props();
	let host = $state<HTMLDivElement>();
	let editor = $state<EditorView>();
	let currentPath = $state("");

	function createEditor(): EditorView {
		return new EditorView({
			state: EditorState.create({
				doc: content,
				extensions: [
					lineNumbers(),
					highlightActiveLineGutter(),
					highlightSpecialChars(),
					history(),
					foldGutter(),
					drawSelection(),
					dropCursor(),
					EditorState.allowMultipleSelections.of(true),
					indentOnInput(),
					syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
					bracketMatching(),
					closeBrackets(),
					autocompletion(),
					highlightActiveLine(),
					highlightSelectionMatches(),
					EditorView.editable.of(!readonly),
					EditorView.lineWrapping,
					EditorView.updateListener.of((update) => {
						if (update.docChanged) onchange(update.state.doc.toString());
					}),
					keymap.of([
						{ key: "Mod-s", run: () => { onsave(); return true; } },
						indentWithTab,
						...closeBracketsKeymap,
						...defaultKeymap,
						...historyKeymap,
						...searchKeymap
					]),
					languageExtensionFor(path),
					EditorView.theme({
						"&": { height: "100%", fontSize: "13px" },
						".cm-editor": { height: "100%" },
						".cm-scroller": { overflow: "auto", fontFamily: "var(--font-mono)" }
					})
				]
			}),
			parent: host
		});
	}

	onMount(() => {
		editor = createEditor();
		currentPath = path;
		return () => editor?.destroy();
	});

	$effect(() => {
		if (!editor) return;
		if (path !== currentPath) {
			currentPath = path;
			editor.destroy();
			editor = createEditor();
			return;
		}
		const currentContent = editor.state.doc.toString();
		if (content !== currentContent) {
			editor.dispatch({ changes: { from: 0, to: currentContent.length, insert: content } });
		}
	});
</script>

<div bind:this={host} class="h-full min-h-0 overflow-hidden" aria-label={`编辑 ${path}`}></div>
