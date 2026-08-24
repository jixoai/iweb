<script lang="ts">
	// 用户原始需求（2026-08-13）：应用路由从工作区拆出，按应用为主对象管理，参考 Cloudflare Workers。
	// 正交意图：应用列表与详情；显示沙箱身份与生命周期；版本级生命周期操作；不编辑文件内容。
	// 任务 9.3-9.5：合并 /v1/applications 投影；加载锁与失败恢复；聚焦/定时实时刷新；owner key 仍只存于标签页 sessionStorage。
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
	import type { ApplicationProjection, ApplicationVersion, AppRoute, MonitorSnapshot, NodeStatus, WorkspaceApp } from "$lib/iweb/contracts";


	type LifecycleAction = "prepare" | "start" | "readiness" | "activate" | "stop" | "rollback" | "delete";

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

	// --- applications data loader（任务 9.3/9.4）：合并 /v1/applications 投影 ---
	let liveApplications = $state<ApplicationProjection[] | null>(null);
	let applicationsLoading = $state(false);
	let applicationsError = $state("");

	$effect(() => {
		if (applications) liveApplications = applications;
	});

	async function loadApplications(): Promise<void> {
		applicationsLoading = true;
		try {
			const response = await client.listApplications();
			liveApplications = response.applications;
			applicationsError = "";
		} catch (error) {
			applicationsError = error instanceof Error ? error.message : "无法读取应用生命周期";
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

	// --- 生命周期操作：按应用版本加锁，失败显示有界 Kernel 错误并刷新 ---
	const actionLocks = $state(new Set<string>());
	const lifecycleLabels: Record<string, string> = {
		admitted: "已收录",
		preparing: "准备中",
		ready: "就绪",
		active: "活跃",
		retired: "已退役",
		stopped: "已停止",
		failed: "失败",
		unavailable: "不可用"
	};
	const actionSuccessLabels: Record<LifecycleAction, string> = {
		prepare: "已准备沙箱",
		start: "已启动沙箱",
		readiness: "就绪探测完成",
		activate: "已激活版本",
		stop: "已停止沙箱",
		rollback: "已回滚版本",
		delete: "已删除版本"
	};

	function lockKey(action: LifecycleAction, versionId: string): string {
		return action + ":" + versionId;
	}

	function isLocked(action: LifecycleAction, versionId: string): boolean {
		return actionLocks.has(lockKey(action, versionId));
	}

	function canPrepare(version: ApplicationVersion): boolean {
		return version.lifecycle === "admitted";
	}

	function canStart(version: ApplicationVersion): boolean {
		// retired 沙箱已排空但保留用于回滚；回滚前需要先重启它。
		return version.lifecycle === "preparing" || version.lifecycle === "stopped" || version.lifecycle === "retired";
	}

	function canProbeReadiness(version: ApplicationVersion): boolean {
		return version.lifecycle === "preparing" || version.lifecycle === "ready";
	}

	function canActivate(version: ApplicationVersion): boolean {
		return version.lifecycle === "preparing" || version.lifecycle === "ready";
	}

	function canStop(version: ApplicationVersion): boolean {
		return version.lifecycle === "preparing" || version.lifecycle === "ready" || version.lifecycle === "active";
	}

	function canRollback(version: ApplicationVersion): boolean {
		return version.lifecycle === "retired";
	}

	function canDelete(version: ApplicationVersion): boolean {
		return version.lifecycle !== "active" && selectedProjection?.activeVersion?.digest !== version.versionId;
	}

	async function runLifecycle(action: LifecycleAction, versionId: string): Promise<void> {
		if (!selected) return;
		const key = lockKey(action, versionId);
		if (actionLocks.has(key)) return;
		actionLocks.add(key);
		try {
			switch (action) {
				case "prepare":
					await client.prepareVersion(selected.id, versionId);
					break;
				case "start":
					await client.startVersion(selected.id, versionId);
					break;
				case "readiness":
					await client.probeReadiness(selected.id, versionId);
					break;
				case "activate":
					await client.activateVersion(selected.id, versionId);
					break;
				case "stop":
					await client.stopVersion(selected.id, versionId);
					break;
				case "rollback":
					await client.rollbackVersion(selected.id, versionId);
					break;
				case "delete":
					await client.deleteVersion(selected.id, versionId);
					break;
			}
			toast.success(actionSuccessLabels[action] + "：" + digestPrefix(versionId) + "…");
		} catch (error) {
			toast.error(error instanceof Error ? error.message : "生命周期操作失败");
		} finally {
			actionLocks.delete(key);
			void loadApplications();
		}
	}

	// --- 收录新版本（POST versions；策略权威只有工作区 iweb.json） ---
	let admitDialogOpen = $state(false);
	let admitTarget = $state<WorkspaceApp | null>(null);
	let admitError = $state("");
	let admitting = $state(false);

	function openAdmit(app: WorkspaceApp): void {
		admitTarget = app;
		admitError = "";
		admitDialogOpen = true;
	}

	async function admitVersion(): Promise<void> {
		if (!admitTarget) return;
		admitting = true;
		admitError = "";
		try {
			const result = await client.admitApplication(admitTarget.id);
			toast.success("已收录新版本 " + digestPrefix(result.versionId) + "…");
			admitDialogOpen = false;
		} catch (error) {
			admitError = error instanceof Error ? error.message : "收录版本失败";
		} finally {
			admitting = false;
			void loadApplications();
		}
	}

	// --- 版本删除确认 ---
	let pendingDeleteVersion = $state<ApplicationVersion | null>(null);
	let deleteVersionDialogOpen = $state(false);

	function requestDeleteVersion(version: ApplicationVersion): void {
		pendingDeleteVersion = version;
		deleteVersionDialogOpen = true;
	}

	async function confirmDeleteVersion(): Promise<void> {
		if (!pendingDeleteVersion) return;
		await runLifecycle("delete", pendingDeleteVersion.versionId);
		deleteVersionDialogOpen = false;
		pendingDeleteVersion = null;
	}

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

	function formatDateTime(iso: string | null): string {
		if (!iso) return "—";
		const date = new Date(iso);
		return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
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
			<Card.Root class="overflow-hidden"><Card.Header class="border-b"><Card.Title>应用</Card.Title><Card.Description>{apps.length} 个工作区应用</Card.Description></Card.Header><Card.Content class="p-2"><div class="flex flex-col gap-1">{#each apps as app (app.id)}{@const metric = metricFor(app)}{@const projection = liveApplications?.find((candidate) => candidate.id === app.id) ?? null}<button class:!bg-accent={selected?.id === app.id} class="flex w-full items-center gap-3 rounded-md p-3 text-left hover:bg-accent focus-visible:outline-ring" onclick={() => (selectedId = app.id)}><div class="flex size-8 shrink-0 items-center justify-center rounded-md bg-muted"><AppWindowIcon /></div><div class="min-w-0 flex-1"><p class="truncate font-medium">{app.id}</p><p class="truncate font-mono text-xs text-muted-foreground"></p><p class="truncate text-xs text-muted-foreground">{projection ? (lifecycleLabels[projection.lifecycle] ?? projection.lifecycle) + " · " + (projection.sandboxId ? projection.sandboxId.slice(0, 10) + "…" : app.system ? "控制面 · 未沙箱化" : "用户应用 · 未沙箱化") : app.system ? "控制面 · 未沙箱化" : "用户应用 · 未沙箱化"}</p></div>{#if metric && metric.inFlight > 0}<Badge variant="outline">活动中</Badge>{:else}<Badge variant="secondary">{app.system ? "系统" : "用户"}</Badge>{/if}</button>{/each}</div></Card.Content></Card.Root>

			{#if selected}
				<Card.Root><Card.Header><div class="flex min-w-0 items-center gap-3"><div class="flex size-10 shrink-0 items-center justify-center rounded-md bg-muted"><AppWindowIcon /></div><div class="min-w-0"><Card.Title class="truncate">{selected.id}</Card.Title><Card.Description class="truncate">{selected.domains[0] ?? selected.id} · </Card.Description></div></div><Card.Action>{#if !selected.system}<Button size="sm" variant="outline" onclick={() => openAdmit(selected)}>收录新版本</Button><Button size="sm" onclick={() => openCreate(selected)}><PlusIcon data-icon="inline-start" />添加路由</Button>{/if}</Card.Action></Card.Header><Card.Content class="flex flex-col gap-6">
					{#if applicationsError}<div class="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">{applicationsError}{#if applicationsLoading}<span class="ml-2 inline-flex items-center gap-1"><Spinner class="size-3" />刷新中</span>{/if}</div>{/if}
					<div class="grid gap-3 sm:grid-cols-3"><div class="rounded-md bg-muted/60 p-3"><p class="text-xs text-muted-foreground">请求</p><p class="mt-1 text-lg font-semibold">{selectedMetric?.requests ?? 0}</p></div><div class="rounded-md bg-muted/60 p-3"><p class="text-xs text-muted-foreground">错误</p><p class="mt-1 text-lg font-semibold">{selectedMetric?.errors ?? 0}</p></div><div class="rounded-md bg-muted/60 p-3"><p class="text-xs text-muted-foreground">平均延迟</p><p class="mt-1 text-lg font-semibold">{selectedMetric?.averageLatencyMs ?? 0} ms</p></div></div>
					<div class="flex flex-col gap-3">
						<div class="flex items-center justify-between"><h2 class="font-medium">沙箱身份与生命周期</h2>{#if selectedProjection}<Badge variant="outline">路由代数 {selectedProjection.routeGeneration}</Badge>{/if}</div>
						<div class="grid gap-3 sm:grid-cols-2">
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">沙箱身份</p>{#if selectedProjection?.sandboxId}<p class="mt-1 truncate font-mono text-sm">{selectedProjection.sandboxId}</p>{:else if selected?.system}<p class="mt-1 text-sm">控制面 · 未沙箱化</p>{:else}<p class="mt-1 text-sm">用户应用 · 未沙箱化</p>{/if}</div>
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">活跃版本</p>{#if selectedProjection?.activeVersion}<p class="mt-1 font-mono text-sm">{digestPrefix(selectedProjection.activeVersion.digest)}… · seq {selectedProjection.activeVersion.sequence}</p>{:else}<p class="mt-1 text-sm">unavailable</p>{/if}</div>
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">生命周期</p><p class="mt-1 text-sm">{selectedProjection ? (lifecycleLabels[selectedProjection.lifecycle] ?? selectedProjection.lifecycle) : "unavailable"}</p></div>
							<div class="rounded-md border p-3"><p class="text-xs text-muted-foreground">路由代数</p><p class="mt-1 text-sm">{selectedProjection ? selectedProjection.routeGeneration : "—"}</p></div>
						</div>
					</div>
					{#if selectedProjection && selectedProjection.versions.length > 0}
						<div class="flex flex-col gap-2">
							<div class="flex items-center justify-between"><h2 class="font-medium">版本生命周期</h2><Badge variant="outline">{selectedProjection.versions.length} 个版本</Badge></div>
							<div class="overflow-x-auto rounded-md border"><table class="w-full text-sm"><thead class="border-b bg-muted/40 text-left text-xs text-muted-foreground"><tr><th class="px-3 py-2 font-medium">版本</th><th class="px-3 py-2 font-medium">序列</th><th class="px-3 py-2 font-medium">状态</th><th class="px-3 py-2 font-medium">收录时间</th><th class="px-3 py-2 font-medium">就绪截止</th><th class="px-3 py-2 font-medium">操作</th></tr></thead><tbody>{#each selectedProjection.versions as version (version.versionId)}<tr class="border-b last:border-0"><td class="px-3 py-2 font-mono text-xs">{digestPrefix(version.versionId)}…</td><td class="px-3 py-2">#{version.sequence}</td><td class="px-3 py-2"><Badge variant={version.lifecycle === "active" ? "default" : version.lifecycle === "ready" ? "outline" : "secondary"}>{lifecycleLabels[version.lifecycle] ?? version.lifecycle}</Badge></td><td class="px-3 py-2 text-xs text-muted-foreground">{formatDateTime(version.admittedAt)}</td><td class="px-3 py-2 text-xs text-muted-foreground">{formatDateTime(version.readinessExpiresAt)}</td><td class="px-3 py-2"><div class="flex flex-wrap items-center gap-1">{#if canPrepare(version)}<Button size="sm" variant="outline" disabled={isLocked("prepare", version.versionId)} onclick={() => void runLifecycle("prepare", version.versionId)}>{#if isLocked("prepare", version.versionId)}<Spinner class="size-3" />{/if}准备</Button>{/if}{#if canStart(version)}<Button size="sm" variant="outline" disabled={isLocked("start", version.versionId)} onclick={() => void runLifecycle("start", version.versionId)}>{#if isLocked("start", version.versionId)}<Spinner class="size-3" />{/if}启动</Button>{/if}{#if canProbeReadiness(version)}<Button size="sm" variant="outline" disabled={isLocked("readiness", version.versionId)} onclick={() => void runLifecycle("readiness", version.versionId)}>{#if isLocked("readiness", version.versionId)}<Spinner class="size-3" />{/if}就绪探测</Button>{/if}{#if canActivate(version)}<Button size="sm" variant="outline" disabled={isLocked("activate", version.versionId)} onclick={() => void runLifecycle("activate", version.versionId)}>{#if isLocked("activate", version.versionId)}<Spinner class="size-3" />{/if}激活</Button>{/if}{#if canStop(version)}<Button size="sm" variant="outline" disabled={isLocked("stop", version.versionId)} onclick={() => void runLifecycle("stop", version.versionId)}>{#if isLocked("stop", version.versionId)}<Spinner class="size-3" />{/if}停止</Button>{/if}{#if canRollback(version)}<Button size="sm" variant="outline" disabled={isLocked("rollback", version.versionId)} onclick={() => void runLifecycle("rollback", version.versionId)}>{#if isLocked("rollback", version.versionId)}<Spinner class="size-3" />{/if}回滚</Button>{/if}{#if canDelete(version)}<Button size="sm" variant="ghost" class="text-destructive hover:text-destructive" disabled={isLocked("delete", version.versionId)} onclick={() => requestDeleteVersion(version)}>删除</Button>{/if}</div></td></tr>{/each}</tbody></table></div>
						</div>
					{:else if selectedProjection}
						<div class="rounded-md border border-dashed p-4 text-sm text-muted-foreground">该应用还没有已收录的版本。使用「收录新版本」从当前工作区快照创建第一个不可变版本。</div>
					{/if}
					<div class="flex flex-col gap-3"><div><h2 class="font-medium">域名映射</h2><p class="mt-1 text-sm text-muted-foreground">路由由 Kernel 持久化；实时指标是当前 Kernel 进程生命周期的窗口。</p></div><div class="flex flex-col gap-2">{#each selectedRoutes as route (route.hostId)}<div class="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center"><NetworkIcon /><div class="min-w-0 flex-1"><p class="truncate font-mono text-sm">{route.hostId}.{status?.baseHost ?? ""}</p><p class="text-xs text-muted-foreground">{route.system ? "内置系统映射，受保护" : "用户管理的应用入口"}</p></div><div class="flex items-center gap-2"><Button variant="outline" size="sm" onclick={() => window.open(routeUrl(route), "_blank", "noopener,noreferrer")}><ExternalLinkIcon data-icon="inline-start" />访问</Button>{#if !route.system}<Button variant="ghost" size="icon-sm" aria-label={"删除 " + route.hostId} onclick={() => requestDelete(route)}><Trash2Icon /></Button>{/if}</div></div>{:else}<div class="rounded-md border border-dashed p-4 text-sm text-muted-foreground">此应用还没有公开域名。添加一个 <code>.app</code> 命名空间路由后即可访问。</div>{/each}</div></div>
					{#if selected.system}<div class="rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground">这是镜像内置应用。它仍在统一工作区中可见；系统域名映射只读保护，保留 <code>api</code> 作为永久恢复控制面。</div>{/if}
				</Card.Content></Card.Root>
			{/if}
		</div>
	{/if}
</section>

<Dialog.Root bind:open={createDialogOpen}><Dialog.Content><Dialog.Header><Dialog.Title>添加应用路由</Dialog.Title><Dialog.Description>为 <code>{appName}</code> 创建一个位于 <code>.app</code> 命名空间的公开入口。</Dialog.Description></Dialog.Header><form class="flex flex-col gap-5" onsubmit={(event) => { event.preventDefault(); void createRoute(); }}><Field.FieldGroup><Field.Field data-invalid={Boolean(formError)}><Field.FieldLabel for="route-host-id">Host ID</Field.FieldLabel><Input id="route-host-id" bind:value={hostId} placeholder="notes.app" aria-invalid={Boolean(formError)} /><Field.FieldDescription>例如 <code>notes.app</code> 会映射为 <code>notes.app.&lt;base-host&gt;</code>。</Field.FieldDescription>{#if formError}<Field.FieldError>{formError}</Field.FieldError>{/if}</Field.Field></Field.FieldGroup><Dialog.Footer><Button variant="outline" type="button" onclick={() => (createDialogOpen = false)} disabled={submitting}>取消</Button><Button type="submit" disabled={submitting}>{#if submitting}<Spinner data-icon="inline-start" />{/if}创建路由</Button></Dialog.Footer></form></Dialog.Content></Dialog.Root>
<AlertDialog.Root bind:open={deleteDialogOpen}><AlertDialog.Content><AlertDialog.Header><AlertDialog.Title>删除 {pendingDeletion?.hostId}？</AlertDialog.Title><AlertDialog.Description>这会撤销公开入口，但不会删除 MinIO 工作区文件或 celld 的 Durable Object 数据。</AlertDialog.Description></AlertDialog.Header><AlertDialog.Footer><AlertDialog.Cancel disabled={submitting}>取消</AlertDialog.Cancel><AlertDialog.Action variant="destructive" onclick={() => void deleteRoute()} disabled={submitting}>{#if submitting}<Spinner data-icon="inline-start" />{/if}删除路由</AlertDialog.Action></AlertDialog.Footer></AlertDialog.Content></AlertDialog.Root>

<Dialog.Root bind:open={admitDialogOpen}><Dialog.Content><Dialog.Header><Dialog.Title>收录新版本</Dialog.Title><Dialog.Description>从当前工作区快照为 <code>{admitTarget?.id}</code> 创建不可变版本；资源与 egress 策略一律来自工作区 <code>iweb.json</code>，不提供覆盖。</Dialog.Description></Dialog.Header><form class="flex flex-col gap-5" onsubmit={(event) => { event.preventDefault(); void admitVersion(); }}><Field.FieldGroup>{#if admitError}<Field.FieldError>{admitError}</Field.FieldError>{/if}</Field.FieldGroup><Dialog.Footer><Button variant="outline" type="button" onclick={() => (admitDialogOpen = false)} disabled={admitting}>取消</Button><Button type="submit" disabled={admitting}>{#if admitting}<Spinner data-icon="inline-start" />{/if}收录版本</Button></Dialog.Footer></form></Dialog.Content></Dialog.Root>
<AlertDialog.Root bind:open={deleteVersionDialogOpen}><AlertDialog.Content><AlertDialog.Header><AlertDialog.Title>删除版本 {pendingDeleteVersion ? digestPrefix(pendingDeleteVersion.versionId) + "…" : ""}？</AlertDialog.Title><AlertDialog.Description>这会删除该版本的沙箱运行时并移除保留记录；活跃版本受 Kernel 保护，无法删除。</AlertDialog.Description></AlertDialog.Header><AlertDialog.Footer><AlertDialog.Cancel>取消</AlertDialog.Cancel><AlertDialog.Action variant="destructive" onclick={() => void confirmDeleteVersion()}>{#if pendingDeleteVersion && isLocked("delete", pendingDeleteVersion.versionId)}<Spinner data-icon="inline-start" />{/if}删除版本</AlertDialog.Action></AlertDialog.Footer></AlertDialog.Content></AlertDialog.Root>