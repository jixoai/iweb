<script lang="ts">
	// 用户原始需求（2026-08-13）：文件树使用 shadcn-svelte-extras Tree View。
	// 正交意图：提供官方 File 节点；支持定制图标；透传 button 事件与属性；不绑定业务数据。
	import FileIcon from "@lucide/svelte/icons/file";
	import { cn } from "$lib/utils";
	import type { Snippet } from "svelte";
	import type { HTMLButtonAttributes } from "svelte/elements";

	type Props = HTMLButtonAttributes & {
		name: string;
		icon?: Snippet<[{ name: string }]>;
	};

	let { name, icon, type = "button", class: className, children, ...restProps }: Props = $props();
</script>

<button {type} class={cn("flex place-items-center gap-1 pl-[3px]", className)} {...restProps}>
	{#if icon}
		{@render icon({ name })}
	{:else}
		<FileIcon class="size-4" />
	{/if}
	<span>{name}</span>
	{@render children?.()}
</button>
