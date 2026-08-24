<script lang="ts">
	// 用户原始需求（2026-08-13）：文件树使用 shadcn-svelte-extras Tree View。
	// 正交意图：提供 Tree View 根语义；接收样式；渲染子节点；不处理选择与展开状态。
	import { cn } from "$lib/utils";
	import type { HTMLAttributes } from "svelte/elements";

	let { children, class: className, ...restProps }: HTMLAttributes<HTMLDivElement> = $props();
</script>

<div role="tree" class={cn("flex flex-col", className)} {...restProps}>{@render children?.()}</div>
