<script lang="ts">
	// 用户原始需求（2026-08-13）：应用路由从工作区拆出，按应用为主对象管理，参考 Cloudflare Workers。
	// 正交意图：应用列表与详情；显示运行时与进程监督状态；路由增删；不编辑文件内容。
	// two-tier-runtime-trust（2026-08-30）：celld 版本生命周期 UI 永久移除——应用只能经
	// owner 构建的节点镜像进入；投影是路由注册表派生的 celld fleet（无沙箱身份、无版本）。
	import { onMount } from "svelte";
	import AppWindowIcon from "@lucide/svelte/icons/app-window";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Card from "$lib/components/ui/card";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Empty from "$lib/components/ui/empty";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import { Spinner } from "$lib/components/ui/spinner";
	import { toast } from "svelte-sonner";
	import { KernelApiClient, publicOrigin } from "$lib/iweb/api";
	import type { ApplicationProjection, AppRoute, MonitorSnapshot, NodeStatus, WorkspaceApp } from "$lib/iweb/contracts";

	type Props = {
		apps: WorkspaceApp[];
		routes: AppRoute[];
		status: NodeStatus | null;
		monitor: MonitorSnapshot | null;
		client: KernelApiClient;
		protocol: string;
		port: string;
		applications?: ApplicationProjection[] | null;
		onrefresh: () => void;
	};

	let { apps, routes, status, monitor, client, protocol, port, applications = null, onrefresh }: Props = $props();
	let selectedId = $state<string | null>(null);
	let createDialogOpen = $state(false);
	let deleteDialogOpen = $state(false);
	let pendingDeletion = $state<AppRoute | null>(null);
	let appName = $state("");
	let hostId = $state("");
	let formError = $state("");
	let submitting = $state(false);

	// --- applications data loader：路由派生 celld fleet 投影（只读） ---
	let liveApplications = $state<ApplicationProjection[] | null>(null);
	let applicationsLoading = $state(false);
	let applicationsError = $state("");

	$effect(() => {
		if (applications) liveApplications = applications;
	});

	async function loadApplications(): Promise<void> {
		applicationsLoading = true;
		try {
			// 投影权威是 /v1/status 的 applications（路由注册表派生）；celld 生命周期
			// 端点已随运行时准入删除，这里不再依赖 /v1/applications。
			const response = await client.statusApplications();
			liveApplications = response.applications;
			applicationsError = "";
		} catch (error) {
			applicationsError = error instanceof Error ? error.message : "无法读取应用状态";
		} finally {
			applicationsLoading = false;
		}
	}

	onMount(() => {
		void loadApplications();
		const refreshWhenVisible = () => {
			if (document.visibilityState === "visible") void loadApplications();
		};
		window.addEventListener("focus", refreshWhenVisible);
		document.addEventListener("visibilitychange", refreshWhenVisible);
		const interval = setInterval(() => void loadApplications(), 15_000);
		return () => {
			window.removeEventListener("focus", refreshWhenVisible);
			document.removeEventListener("visibilitychange", refreshWhenVisible);
			clearInterval(interval);
		};
	});

	// 运行时标签：fleet 投影自带 runtimeKind（两层信任模型下恒为 celld）；
	// 无投影时系统应用架构上恒为 celld。
	const runtimeKindLabel = (kind: string | undefined): string => {
		if (kind === "wasm") return "Wasmtime";
		if (kind === "celld") return "celld";
		return kind ?? "未收录";
	};
	// two-tier-runtime-trust：fleet 投影的生命周期只剩活跃/不可用两态。
	const lifecycleLabels: Record<string, string> = {
		active: "活跃",
		unavailable: "不可用"
	};

	const selected = $derived(apps.find((app) => app.id === selectedId) ?? apps[0] ?? null);
	const selectedProjection = $derived(selected ? liveApplications?.find((app) => app.id === selected.id) ?? null : null);
	const selectedRoutes = $derived(selected ? routes.filter((route) => route.target.appName === selected.id) : []);
	const selectedMetric = $derived(selected ? monitor?.apps.find((app) => app.id === selected.id) ?? null : null);

	function routeUrl(route: AppRoute): string {
		return status ? publicOrigin(status.baseHost, route.hostId, protocol, port) : "#";
	}

	function metricFor(app: WorkspaceApp) {
		return monitor?.apps.find((metric) => metric.id === app.id) ?? null;
	}

	function digestPrefix(digest: string): string {
		return digest.length > 12 ? digest.slice(0, 12) : digest;
	}

	function openCreate(app: WorkspaceApp): void {
		appName = app.id;
		hostId = app.system ? "" : app.id + ".app";
		formError = "";
		createDialogOpen = true;
	}

	async function createRoute(): Promise<void> {
		submitting = true;
		formError = "";
		try {
			await client.createRoute({ appName, hostId });
			createDialogOpen = false;
			toast.success("应用路由已创建");
			onrefresh();
		} catch (error) {
			formError = error instanceof Error ? error.message : "创建路由失败";
		} finally {
			submitting = false;
		}
	}

	function requestDelete(route: AppRoute): void {
		pendingDeletion = route;
		deleteDialogOpen = true;
	}

	async function deleteRoute(): Promise<void> {
		if (!pendingDeletion) return;
		submitting = true;
		try {
			await client.deleteRoute(pendingDeletion.hostId);
			toast.success("已移除 " + pendingDeletion.hostId);
			deleteDialogOpen = false;
			pendingDeletion = null;
			onrefresh();
		} catch (error) {
			toast.error(error instanceof Error ? error.message : "删除路由失败");
		} finally {
			submitting = false;
		}
	}
</script>
<section class="flex flex-col gap-6">
	{#if apps.length === 0}
		<Empty.Root class="min-h-80 border"><Empty.Header><Empty.Media variant="icon"><AppWindowIcon /></Empty.Media><Empty.Title>尚未识别到应用</Empty.Title><Empty.Description>注册应用路由后，它会出现在这里（路由注册表是应用身份的唯一权威）。</Empty.Description></Empty.Header></Empty.Root>
	{:else}
		<div class="grid gap-4 lg:grid-cols-[minmax(16rem,0.7fr)_minmax(0,1.5fr)]">
			<Card.Root class="overflow-hidden"><Card.Header class="border-b"><Card.Title>应用</Card.Title><Card.Description>{apps.length} 个工作区应用</Card.Description></Card.Header><Card.Content class="p-2"><div class="flex flex-col gap-1">{#each apps as app (app.id)}{@const metric = metricFor(app)}{@const projection = liveApplications?.find((candidate) => candidate.id === app.id) ?? null}<button class:!bg-accent={selected?.id === app.id} class="flex w-full items-center gap-3 rounded-md p-3 text-left hover:bg-accent focus-visible:outline-ring" onclick={() => (selectedId = app.id)}><div class="flex size-8 shrink-0 items-center justify-center rounded-md bg-muted"><AppWindowIcon /></div><div class="min-w-0 flex-1"><p class="truncate font-medium">{app.id}</p><p class="truncate font-mono text-xs text-muted-foreground"></p><p class="truncate text-xs text-muted-foreground">{runtimeKindLabel(projection?.runtimeKind ?? (app.system ? "celld" : undefined))} · {projection ? (lifecycleLabels[projection.lifecycle] ?? projection.lifecycle) : "不可用"}</p></div>{#if metric && metric.inFlight > 0}<Badge variant="outline">活动中</Badge>{:else}<Badge variant="secondary">{app.system ? "系统" : "用户"}</Badge>{/if}</button>{/each}</div></Card.Content></Card.Root>

			{#if selected}
				<Card.Root><Card.Header><div class="flex min-w-0 items-center gap-3"><div class="flex size-10 shrink-0 items-center justify-center rounded-md bg-muted"><AppWindowIcon /></div><div class="min-w-0"><Card.Title class="truncate">{selected.id}</Card.Title><Card.Description class="truncate">{selected.domains[0] ?? selected.id} · {runtimeKindLabel(selectedProjection?.runtimeKind ?? (selected.system ? "celld" : undefined))}</Card.Description></div></div><Card.Action>{#if !selected.system}<Button size="sm" onclick={() => openCreate(selected)}><PlusIcon data-icon="inline-start" />添加路由</Button>{/if}</Card.Action></Card.Header><Card.Content class="flex flex-col gap-6">
					{#if applicationsError}<div class="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">{applicationsError}{#if applicationsLoading}<span class="ml-2 inline-flex items-center gap-1"><Spinner class="size-3" />刷新中</span>{/if}</div>{/if}
					<div class="grid gap-3 sm:grid-cols-3"><div class="rounded-md bg-muted/60 p-3"><p class="text-xs text-muted-foreground">请求</p><p class="mt-1 text-lg font-semibold">{selectedMetric?.requests ?? 0}</p></div><div class="rounded-md bg-muted/60 p-3"><p class="text-xs text-muted-foreground">错误</p><p class="mt-1 text-lg font-semibold">{selectedMetric?.errors ?? 0}</p></div><div class="rounded-md bg-muted/60 p-3"><p class="text-xs text-muted-foreground">平均延迟</p><p class="mt-1 text-lg font-semibold">{selectedMetric?.averageLatencyMs ?? 0} ms</p></div></div>
					<div class="flex flex-col gap-3">
						<div class="flex items-center justify-between"><h2 class="font-medium">运行时与监督状态</h2>{#if selectedProjection}<Badge variant="outline">路由代数 {selectedProjection.routeGeneration}</Badge>{/if}</div>
						<div class="grid gap-3 sm:grid-cols-2">
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">运行时</p><p class="mt-1 text-sm">{runtimeKindLabel(selectedProjection?.runtimeKind ?? (selected.system ? "celld" : undefined))}{#if selectedProjection?.runtimeKind === "wasm"}<span class="ml-1 text-xs text-muted-foreground">（Wasmtime 组件）</span>{/if}</p></div>
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">进程监督</p>{#if selectedProjection?.sandboxId}<p class="mt-1 truncate font-mono text-sm">{selectedProjection.sandboxId}</p>{:else}<p class="mt-1 text-sm">镜像种子 · 进程监督</p><p class="mt-1 text-xs text-muted-foreground">celld 应用无沙箱身份：只能经 owner 构建的节点镜像进入，由入口监督循环与看门狗软限约束。</p>{/if}</div>
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">活跃版本</p>{#if selectedProjection?.activeVersion}<p class="mt-1 font-mono text-sm">{digestPrefix(selectedProjection.activeVersion.digest)}… · seq {selectedProjection.activeVersion.sequence}</p>{:else}<p class="mt-1 text-sm">—</p>{/if}</div>
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">生命周期</p><p class="mt-1 text-sm">{selectedProjection ? (lifecycleLabels[selectedProjection.lifecycle] ?? selectedProjection.lifecycle) : "—"}</p></div>
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">路由代数</p><p class="mt-1 text-sm">{selectedProjection ? selectedProjection.routeGeneration : "—"}</p></div>
						</div>
					</div>
					<div class="flex flex-col gap-3"><div><h2 class="font-medium">域名映射</h2><p class="mt-1 text-sm text-muted-foreground">路由由 Kernel 持久化；实时指标是当前 Kernel 进程生命周期的窗口。</p></div><div class="flex flex-col gap-2">{#each selectedRoutes as route (route.hostId)}<div class="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center"><NetworkIcon /><div class="min-w-0 flex-1"><p class="truncate font-mono text-sm">{route.hostId}.{status?.baseHost ?? ""}</p><p class="text-xs text-muted-foreground">{route.system ? "内置系统映射，受保护" : "用户管理的应用入口"}</p></div><div class="flex items-center gap-2"><Button variant="outline" size="sm" onclick={() => window.open(routeUrl(route), "_blank", "noopener,noreferrer")}><ExternalLinkIcon data-icon="inline-start" />访问</Button>{#if !route.system}<Button variant="ghost" size="icon-sm" aria-label={"删除 " + route.hostId} onclick={() => requestDelete(route)}><Trash2Icon /></Button>{/if}</div></div>{:else}<div class="rounded-md border border-dashed p-4 text-sm text-muted-foreground">此应用还没有公开域名。添加一个 <code>.app</code> 命名空间路由后即可访问。</div>{/each}</div></div>
					{#if selected.system}<div class="rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground">这是镜像内置应用。它仍在统一工作区中可见；系统域名映射只读保护，保留 <code>api</code> 作为永久恢复控制面。</div>{/if}
				</Card.Content></Card.Root>
			{/if}
		</div>
	{/if}
</section>

<Dialog.Root bind:open={createDialogOpen}><Dialog.Content><Dialog.Header><Dialog.Title>添加应用路由</Dialog.Title><Dialog.Description>为 <code>{appName}</code> 创建一个位于 <code>.app</code> 命名空间的公开入口。</Dialog.Description></Dialog.Header><form class="flex flex-col gap-5" onsubmit={(event) => { event.preventDefault(); void createRoute(); }}><Field.FieldGroup><Field.Field data-invalid={Boolean(formError)}><Field.FieldLabel for="route-host-id">Host ID</Field.FieldLabel><Input id="route-host-id" bind:value={hostId} placeholder="notes.app" aria-invalid={Boolean(formError)} /><Field.FieldDescription>例如 <code>notes.app</code> 会映射为 <code>notes.app.&lt;base-host&gt;</code>。</Field.FieldDescription>{#if formError}<Field.FieldError>{formError}</Field.FieldError>{/if}</Field.Field></Field.FieldGroup><Dialog.Footer><Button variant="outline" type="button" onclick={() => (createDialogOpen = false)} disabled={submitting}>取消</Button><Button type="submit" disabled={submitting}>{#if submitting}<Spinner data-icon="inline-start" />{/if}创建路由</Button></Dialog.Footer></form></Dialog.Content></Dialog.Root>
<AlertDialog.Root bind:open={deleteDialogOpen}><AlertDialog.Content><AlertDialog.Header><AlertDialog.Title>删除 {pendingDeletion?.hostId}？</AlertDialog.Title><AlertDialog.Description>这会撤销公开入口，但不会删除 MinIO 工作区文件或 celld 的 Durable Object 数据。</AlertDialog.Description></AlertDialog.Header><AlertDialog.Footer><AlertDialog.Cancel disabled={submitting}>取消</AlertDialog.Cancel><AlertDialog.Action variant="destructive" onclick={() => void deleteRoute()} disabled={submitting}>{#if submitting}<Spinner data-icon="inline-start" />{/if}删除路由</AlertDialog.Action></AlertDialog.Footer></AlertDialog.Content></AlertDialog.Root>