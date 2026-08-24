<script lang="ts">
	// 用户原始需求（2026-08-13）：文件树使用 shadcn-svelte-extras Tree View。
	// 正交意图：提供官方 Folder 节点；折叠展开；默认/定制图标；嵌套结构；不管理文件选择。
	import * as Collapsible from "$lib/components/ui/collapsible";
	import FolderIcon from "@lucide/svelte/icons/folder";
	import FolderOpenIcon from "@lucide/svelte/icons/folder-open";
	import { cn } from "$lib/utils";
	import type { Snippet } from "svelte";

	type Props = {
		name: string;
		open?: boolean;
		class?: string;
		icon?: Snippet<[{ name: string; open: boolean }]>;
		children?: Snippet;
	};

	let { name, open = $bindable(true), class: className, icon, children }: Props = $props();
</script>

<Collapsible.Root bind:open>
	<Collapsible.Trigger class={cn("flex place-items-center gap-1", className)}>
		{#if icon}
			{@render icon({ name, open })}
		{:else if open}
			<FolderOpenIcon class="size-4" />
		{:else}
			<FolderIcon class="size-4" />
		{/if}
		<span>{name}</span>
	</Collapsible.Trigger>
	<Collapsible.Content class="ml-2 border-l">
		<div class="relative flex place-items-start"><div class="mx-2 h-full w-px bg-border"></div><div class="flex flex-1 flex-col">{@render children?.()}</div></div>
	</Collapsible.Content>
</Collapsible.Root>
