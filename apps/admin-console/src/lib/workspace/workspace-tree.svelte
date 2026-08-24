<script lang="ts">
	// 用户原始需求（2026-08-13）：文件树使用 shadcn-svelte-extras Tree View，而非自行组合组件。
	// 正交意图：递归投影工作区树；使用 extras Root/Folder/File；维持选择状态；不加载或保存文件。
	import FileCode2Icon from "@lucide/svelte/icons/file-code-2";
	import FolderIcon from "@lucide/svelte/icons/folder";
	import FolderOpenIcon from "@lucide/svelte/icons/folder-open";
	import * as TreeView from "$lib/components/ui/tree-view";
	import { cn } from "$lib/utils";
	import type { WorkspaceFile } from "$lib/iweb/contracts";
	import type { FileTreeNode } from "$lib/workspace/file-tree";

	type Props = {
		nodes: FileTreeNode[];
		selectedPath: string | null;
		onselect: (file: WorkspaceFile) => void;
	};

	let { nodes, selectedPath, onselect }: Props = $props();

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}
</script>

{#snippet Nodes({ items, depth }: { items: FileTreeNode[]; depth: number })}
	{#each items as item (item.path)}
		{#if item.children.length > 0}
			<TreeView.Folder name={item.name} open={depth < 2} class={cn("w-full rounded-md px-2 py-1.5 font-mono text-xs font-medium text-muted-foreground hover:bg-accent focus-within:bg-accent", depth > 0 && "ml-1")}>
				{#snippet icon({ open })}
					{#if open}<FolderOpenIcon />{:else}<FolderIcon />{/if}
				{/snippet}
				{@render Nodes({ items: item.children, depth: depth + 1 })}
			</TreeView.Folder>
		{/if}
		{#if item.file}
			{@const file = item.file}
				<TreeView.File name={item.name} class={cn("w-full rounded-md px-2 py-2 font-mono text-left text-xs hover:bg-accent focus-visible:outline-ring", selectedPath === file.path && "!bg-accent")} onclick={() => onselect(file)}>
				{#snippet icon()}<FileCode2Icon />{/snippet}
				<span class="ml-auto shrink-0 text-muted-foreground">{formatBytes(file.size)}</span>
			</TreeView.File>
		{/if}
	{/each}
{/snippet}

<TreeView.Root class="gap-0.5" aria-label="工作区文件树">{@render Nodes({ items: nodes, depth: 0 })}</TreeView.Root>
