<script lang="ts">
	// 用户原始需求（2026-08-14）：应用监控主表逐应用展示实测内存与强制上限；请求与生命周期并列；unavailable 显式呈现。
	// 正交意图：10.3——control-plane 标注节点开销；未沙箱化应用仍可见；资源列永不因无采样而隐藏；节点总额不进入本表。
	import AppWindowIcon from "@lucide/svelte/icons/app-window";
	import { Badge } from "$lib/components/ui/badge";
	import { applicationResourceRows, type ApplicationResourceRow, type CellText } from "$lib/monitor/application-resource-table";
	import type { ApplicationProjection, MonitorApp } from "$lib/iweb/contracts";

	type Props = {
		apps: MonitorApp[] | null;
		sandboxes: ApplicationProjection[] | null;
		applications: ApplicationProjection[] | null;
	};

	let { apps, sandboxes, applications }: Props = $props();
	const rows = $derived(applicationResourceRows({ apps: apps ?? [], sandboxes, applications }));

	function cellClass(cell: CellText): string {
		return cell.kind === "unavailable" ? "text-muted-foreground" : "";
	}
	// Non-value cells carry their reason as a native tooltip: an honest
	// "cannot measure" must explain itself instead of looking broken.
	function cellTitle(cell: CellText): string | undefined {
		return cell.kind === "value" ? undefined : cell.reason;
	}
	function lifecycleLabel(row: ApplicationResourceRow): string {
		const labels: Record<string, string> = { admitted: "已收录", preparing: "准备中", ready: "就绪", active: "运行中", retired: "已退役", stopped: "已停止", failed: "失败" };
		return row.lifecycle.kind === "value" ? (labels[row.lifecycle.text] ?? row.lifecycle.text) : row.lifecycle.text;
	}
</script>

<div class="overflow-x-auto" data-testid="application-resource-table">
	<table class="w-full text-sm">
		<thead class="border-y bg-muted/40 text-left text-xs text-muted-foreground">
			<tr>
				<th class="px-6 py-3 font-medium">应用</th>
				<th class="px-6 py-3 font-medium">请求</th>
				<th class="px-6 py-3 font-medium">生命周期</th>
				<th class="px-6 py-3 font-medium">内存（实测）</th>
				<th class="px-6 py-3 font-medium">内存上限</th>
				<th class="px-6 py-3 font-medium">进程</th>
				<th class="px-6 py-3 font-medium">CPU</th>
				<th class="px-6 py-3 font-medium">状态</th>
			</tr>
		</thead>
		<tbody>
			{#each rows as row (row.id)}
				<tr class="border-b last:border-0" data-app={row.id}>
					<td class="px-6 py-3">
						<div class="flex items-center gap-2">
							<AppWindowIcon />
							<div>
								<p class="font-medium">{row.id}</p>
								<p class="font-mono text-xs text-muted-foreground">{row.domains?.[0] ?? ""}</p>
							</div>
						</div>
					</td>
					<td class="px-6 py-3">{row.requests.text}</td>
					<td class="px-6 py-3">{#if row.lifecycle.kind === "value"}<Badge variant={row.lifecycle.text === "active" ? "default" : "secondary"}>{lifecycleLabel(row)}</Badge>{:else}<span class="text-muted-foreground">{lifecycleLabel(row)}</span>{/if}</td>
					<td class="px-6 py-3 {cellClass(row.memory)}" data-cell="memory" title={cellTitle(row.memory)}>{row.memory.text}</td>
					<td class="px-6 py-3 {cellClass(row.memoryLimit)}" data-cell="memory-limit" title={cellTitle(row.memoryLimit)}>{row.memoryLimit.text}</td>
					<td class="px-6 py-3 {cellClass(row.pid)}" title={cellTitle(row.pid)}>{row.pid.text}</td>
					<td class="px-6 py-3 {cellClass(row.cpu)}" title={cellTitle(row.cpu)}>{row.cpu.text}</td>
					<td class="px-6 py-3">{#if row.terminated}<Badge variant="destructive">已终止</Badge>{:else if row.inFlight > 0}<Badge variant="outline">{row.inFlight} 进行中</Badge>{:else}<Badge variant="secondary">空闲</Badge>{/if}</td>
				</tr>
			{/each}
			{#if rows.length === 0}
				<tr><td colspan="8" class="px-6 py-8 text-sm text-muted-foreground" data-testid="no-applications">暂无可见应用。应用出现在路由注册表后即在此列出。</td></tr>
			{/if}
		</tbody>
	</table>
</div>
<p class="mt-2 px-6 pb-2 text-xs text-muted-foreground" data-testid="resource-table-note">
	每个应用都有<strong>独立的 celld 进程</strong>：控制面应用（admin/mcp）显示本进程 RSS 实测内存，沙箱化应用显示沙箱 cgroup 实测值 + 强制上限。「不可用（未沙箱化）」= 尚未运行在独立沙箱，沙箱化后显示 cgroup 实测。悬停单元格可查看原因；任何测不到的值都不会用 0 代替。
</p>