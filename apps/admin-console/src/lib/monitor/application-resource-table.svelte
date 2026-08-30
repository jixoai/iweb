<script lang="ts">
	// 用户原始需求（2026-08-14）：应用监控主表逐应用展示实测内存与上限；请求与生命周期并列；unavailable 显式呈现。
	// 正交意图：10.3——节点总额不进入本表；资源列永不因无采样而隐藏。
	// 4.4（2026-08-26）：wasm 应用行并列「引擎（Wasmtime）」列——engine 口径与进程
	// 口径分开标注；非 wasm 应用显式「不适用」，与测量失败（unavailable）区分。
	// add-wasm-host-services（2026-08-28）：「宿主服务」列——仅计数/状态，无正文无值。
	// two-tier-runtime-trust（2026-08-30）：新增「软上限」（看门狗软限，15 秒采样、
	// 越限 SIGKILL 单进程、entrypoint 退避重启）与「看门狗」（最近一次越限处决）列。
	import AppWindowIcon from "@lucide/svelte/icons/app-window";
	import { Badge } from "$lib/components/ui/badge";
	import { applicationResourceRows, type ApplicationResourceRow, type CellText } from "$lib/monitor/application-resource-table";
	import type { ApplicationProjection, MonitorApp, WatchdogProjection } from "$lib/iweb/contracts";

	type Props = {
		apps: MonitorApp[] | null;
		applications: ApplicationProjection[] | null;
		watchdog?: WatchdogProjection | null;
	};

	let { apps, applications, watchdog = null }: Props = $props();
	const rows = $derived(applicationResourceRows({ apps: apps ?? [], applications, watchdog }));

	function cellClass(cell: CellText): string {
		return cell.kind === "value" ? "" : "text-muted-foreground";
	}
	// Non-value cells carry their reason as a native tooltip: an honest
	// "cannot measure" (or "not applicable") must explain itself instead of looking broken.
	function cellTitle(cell: CellText): string | undefined {
		return cell.kind === "value" ? undefined : cell.reason;
	}
	function lifecycleLabel(row: ApplicationResourceRow): string {
		const labels: Record<string, string> = { active: "运行中", unavailable: "不可用" };
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
				<th class="px-6 py-3 font-medium">软上限</th>
				<th class="px-6 py-3 font-medium">看门狗</th>
				<th class="px-6 py-3 font-medium">进程</th>
				<th class="px-6 py-3 font-medium">CPU</th>
				<th class="px-6 py-3 font-medium">引擎（Wasmtime）</th>
				<th class="px-6 py-3 font-medium">宿主服务</th>
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
					<td class="px-6 py-3 {cellClass(row.softLimit)}" data-cell="soft-limit" title={cellTitle(row.softLimit)}>{row.softLimit.text}</td>
					<td class="px-6 py-3 {cellClass(row.watchdog)}" data-cell="watchdog" title={cellTitle(row.watchdog)}>{row.watchdog.text}</td>
					<td class="px-6 py-3 {cellClass(row.pid)}" title={cellTitle(row.pid)}>{row.pid.text}</td>
					<td class="px-6 py-3 {cellClass(row.cpu)}" title={cellTitle(row.cpu)}>{row.cpu.text}</td>
					<td class="px-6 py-3 {cellClass(row.engine)}" data-cell="engine" title={cellTitle(row.engine)}>{row.engine.text}</td>
					<td class="px-6 py-3 {cellClass(row.hostServices)}" data-cell="host-services" title={cellTitle(row.hostServices)}>{row.hostServices.text}</td>
					<td class="px-6 py-3">{#if row.terminated}<Badge variant="destructive">已终止</Badge>{:else if row.inFlight > 0}<Badge variant="outline">{row.inFlight} 进行中</Badge>{:else}<Badge variant="secondary">空闲</Badge>{/if}</td>
				</tr>
			{/each}
			{#if rows.length === 0}
				<tr><td colspan="12" class="px-6 py-8 text-sm text-muted-foreground" data-testid="no-applications">暂无可见应用。应用出现在路由注册表后即在此列出。</td></tr>
			{/if}
		</tbody>
	</table>
</div>
<p class="mt-2 px-6 pb-2 text-xs text-muted-foreground" data-testid="resource-table-note">
	每个 <strong>celld 应用</strong>都有独立的 celld 进程：「内存（实测）」显示该进程的 RSS 采样（进程驻留内存，非 cgroup 全口径）；wasm 应用没有进程口径，对应单元格显示「不适用」。<strong>软上限</strong>是看门狗软限（15 秒采样，超限 SIGKILL 单个进程，entrypoint 按退避自动重启该应用、不影响邻居）——不是强制天花板；<strong>看门狗</strong>列显示该应用最近一次越限处决（时间 + 处决时采样值）。wasm 应用另列<strong>引擎（Wasmtime）口径</strong>：Guest 内存实测 + 存活实例数，与进程口径分开计量、互不换算；<strong>宿主服务</strong>列只显示计数与状态（日志保留/丢弃），绝不显示日志正文或存储值。悬停单元格可查看原因；任何测不到的值都不会用 0 代替。
</p>