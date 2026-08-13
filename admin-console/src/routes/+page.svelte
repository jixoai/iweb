<script lang="ts">
	// 用户原始需求（2026-08-13）：完成 iweb Admin 的文件编辑、应用路由与实时应用监控体验；应用监控第二行显示文件夹路径；每页只保留一个 Header，并将登录信息与退出入口收拢到侧栏底部。
	// 正交意图：管理员登录壳；控制台导航与数据同步；实时总览；组合工作区/路由/恢复模块；不承担 Kernel 业务逻辑。
	import { onMount } from "svelte";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import AppWindowIcon from "@lucide/svelte/icons/app-window";
	import CircleAlertIcon from "@lucide/svelte/icons/circle-alert";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import FolderTreeIcon from "@lucide/svelte/icons/folder-tree";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import LayoutDashboardIcon from "@lucide/svelte/icons/layout-dashboard";
	import LogOutIcon from "@lucide/svelte/icons/log-out";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import RouteIcon from "@lucide/svelte/icons/route";
	import ServerCogIcon from "@lucide/svelte/icons/server-cog";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import UserRoundIcon from "@lucide/svelte/icons/user-round";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import * as Alert from "$lib/components/ui/alert";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Card from "$lib/components/ui/card";
	import * as Empty from "$lib/components/ui/empty";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import * as Sidebar from "$lib/components/ui/sidebar";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Spinner } from "$lib/components/ui/spinner";
	import { Toaster } from "$lib/components/ui/sonner";
	import { toast } from "svelte-sonner";
	import iwebLogo from "$lib/assets/favicon.svg";
	import { KernelApiError } from "$lib/iweb/api";
	import type { NodeStatus, OwnerKey, RouteStore, Workspace } from "$lib/iweb/contracts";
	import { ApiSession } from "$lib/iweb/session.svelte";
	import { MonitorSession } from "$lib/monitor/monitor-session.svelte";
	import RouteManager from "$lib/routes/route-manager.svelte";
	import WorkspaceManager from "$lib/workspace/workspace-manager.svelte";

	type View = "overview" | "workspace" | "routes" | "recovery";
	type NavigationItem = { id: View; label: string; title: string; description: string; icon: typeof LayoutDashboardIcon };

	const session = new ApiSession();
	const monitor = new MonitorSession();
	const navigation: NavigationItem[] = [
		{ id: "overview", label: "总览", title: "你的 iweb 节点", description: "当前指标通过 WebSocket 推送，表示本次 Kernel 进程生命周期内的应用活动。", icon: LayoutDashboardIcon },
		{ id: "workspace", label: "工作区", title: "文件工作区", description: "浏览、编辑并保存 MinIO 工作区中的文本对象；保存不会自动重新发布 celld 应用。", icon: FolderTreeIcon },
		{ id: "routes", label: "应用路由", title: "应用路由", description: "应用是第一对象，域名是入口投影；内置系统映射只读保护。", icon: RouteIcon },
		{ id: "recovery", label: "恢复", title: "恢复内置 Admin", description: "从 Kernel 控制面重新部署镜像内置 Dispatcher，并保留 MinIO 数据与用户应用路由。", icon: RotateCcwIcon }
	];

	let activeView = $state<View>("overview");
	let status = $state<NodeStatus | null>(null);
	let routeStore = $state<RouteStore | null>(null);
	let workspace = $state<Workspace | null>(null);
	let ownerKey = $state<OwnerKey | null>(null);
	let externalProtocol = $state("https:");
	let externalPort = $state("");
	let adminKeyDraft = $state("");
	let loading = $state(false);
	let recovering = $state(false);
	let connectionError = $state("");
	let recoveryDialogOpen = $state(false);

	const routes = $derived(routeStore?.routes ?? []);
	const workspaceApps = $derived(workspace?.apps ?? []);
	const isAuthenticated = $derived(session.authenticated);
	const hasConnection = $derived(isAuthenticated && status !== null);
	const currentView = $derived(navigation.find((item) => item.id === activeView) ?? navigation[0]);
	const monitorStateLabel = $derived(
		monitor.state === "connected" ? "实时监控已连接" : monitor.state === "reconnecting" ? "正在重连实时监控" : monitor.state === "connecting" ? "正在连接实时监控" : "实时监控未连接"
	);
	const accountConnectionLabel = $derived(monitor.state === "connected" ? "已连接" : monitor.state === "connecting" || monitor.state === "reconnecting" ? "连接中" : "未连接");

	function showConnectionError(error: unknown): void {
		if (error instanceof KernelApiError && error.status === 401) {
			logout(false);
			connectionError = "管理员密钥无效或已失效，请重新登录。";
			return;
		}
		connectionError = error instanceof Error ? error.message : "无法读取节点状态";
	}

	function formatBytes(bytes: number | null | undefined, unavailable = "不可用"): string {
		if (bytes === null || bytes === undefined) return unavailable;
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
		return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
	}

	function formatMemoryLimit(limitBytes: number | null): string {
		return limitBytes === null ? "未设置上限" : formatBytes(limitBytes);
	}

	function formatMemoryUsagePercent(memory: NodeStatus["memory"]): string {
		if (memory.usageBytes === null) return "采集不可用";
		if (memory.limitBytes === null) return "未设置上限";
		return memory.usagePercent === null ? "不可用" : `${memory.usagePercent}%`;
	}

	async function refresh(): Promise<void> {
		if (!session.authenticated) return;
		loading = true;
		connectionError = "";
		try {
			const [nextStatus, nextRoutes, nextWorkspace, nextOwnerKey] = await Promise.all([
				session.client().status(),
				session.client().routes(),
				session.client().workspace(),
				session.client().ownerKey()
			]);
			status = nextStatus;
			routeStore = nextRoutes;
			workspace = nextWorkspace;
			ownerKey = nextOwnerKey;
		} catch (error) {
			showConnectionError(error);
		} finally {
			loading = false;
		}
	}

	async function login(): Promise<void> {
		if (!adminKeyDraft.trim()) {
			connectionError = "请输入管理员密钥。";
			return;
		}
		session.login(adminKeyDraft);
		await refresh();
		if (!connectionError) {
			adminKeyDraft = "";
			monitor.start(session.client());
			activeView = "overview";
			toast.success("管理员登录成功");
		}
	}

	function logout(showToast = true): void {
		monitor.stop();
		session.logout();
		adminKeyDraft = "";
		status = null;
		routeStore = null;
		workspace = null;
		ownerKey = null;
		if (showToast) {
			connectionError = "";
			toast.message("已退出管理员会话");
		}
	}

	async function recoverAdmin(): Promise<void> {
		recovering = true;
		try {
			await session.client().recoverAdmin();
			toast.success("恢复指令已提交，节点将短暂重启。", { duration: 6000 });
		} catch (error) {
			toast.error(error instanceof Error ? error.message : "提交恢复失败");
			showConnectionError(error);
		} finally {
			recovering = false;
		}
	}

	onMount(() => {
		session.initialize();
		const locationUrl = new URL(window.location.href);
		externalProtocol = locationUrl.protocol;
		externalPort = locationUrl.port;
		if (session.authenticated) {
			void refresh();
			monitor.start(session.client());
		}
		return () => monitor.stop();
	});
</script>

<svelte:head><title>iweb Admin</title><meta name="description" content="The local control surface for an iweb node." /></svelte:head>

{#if !isAuthenticated}
	<main class="scrollbar-thin scrollbar-track-transparent scrollbar-thumb-[color-mix(in_srgb,currentColor,transparent)] grid min-h-svh place-items-center overflow-y-auto bg-muted/30 p-4 sm:p-6">
		<section class="grid w-full max-w-5xl overflow-hidden rounded-2xl bg-background shadow-sm lg:grid-cols-[1.1fr_0.9fr]">
			<div class="flex min-h-80 flex-col justify-between gap-8 bg-primary p-6 text-primary-foreground sm:p-10"><div class="flex items-center gap-3"><div class="flex size-10 items-center justify-center rounded-xl bg-primary-foreground/15 p-1.5"><img src={iwebLogo} alt="iweb" class="size-full" /></div><div><p class="font-semibold tracking-tight">iweb</p><p class="text-sm text-primary-foreground/70">Personal cloud node</p></div></div><div class="max-w-md"><p class="text-sm font-medium text-primary-foreground/75">管理员控制台</p><h1 class="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">管理你的个人云节点。</h1><p class="mt-4 text-sm leading-relaxed text-primary-foreground/75">登录后才能查看工作区、应用、域名、恢复能力与管理员级操作。</p></div><p class="text-xs leading-relaxed text-primary-foreground/60">管理员密钥只保存在当前浏览器标签页；关闭标签页或主动退出后不会保留。</p></div>
			<div class="flex items-center p-6 sm:p-10"><Card.Root class="w-full border-0 shadow-none"><Card.Header class="px-0"><Card.Title>管理员登录</Card.Title><Card.Description>使用安装此 iweb 节点时设置的管理员密钥登录。</Card.Description></Card.Header><Card.Content class="px-0"><form class="flex flex-col gap-5" onsubmit={(event) => { event.preventDefault(); void login(); }}><Field.FieldGroup><Field.Field data-invalid={Boolean(connectionError)}><Field.FieldLabel for="admin-key">管理员密钥</Field.FieldLabel><Input id="admin-key" type="password" autocomplete="current-password" placeholder="输入管理员密钥" bind:value={adminKeyDraft} aria-invalid={Boolean(connectionError)} autofocus /><Field.FieldDescription>这是节点的 bootstrap owner key，不会上传到 Admin 静态应用或写入长期浏览器存储。</Field.FieldDescription>{#if connectionError}<Field.FieldError>{connectionError}</Field.FieldError>{/if}</Field.Field></Field.FieldGroup><Button type="submit" disabled={loading}>{#if loading}<Spinner data-icon="inline-start" />{:else}<KeyRoundIcon data-icon="inline-start" />{/if}登录管理控制台</Button></form><Alert.Root class="mt-6"><ShieldCheckIcon /><Alert.Title>恢复入口仍独立存在</Alert.Title><Alert.Description><code>api.&lt;base-host&gt;</code> 位于 celld 之外。Admin 被替换或损坏时，管理员仍可借助 owner key 恢复节点。</Alert.Description></Alert.Root></Card.Content></Card.Root></div>
		</section>
	</main>
{:else}
<Sidebar.Provider class="h-svh overflow-hidden"><Sidebar.Root variant="inset" collapsible="icon"><Sidebar.Header class="p-3"><div class="flex items-center gap-2 px-1 py-1.5"><div class="flex size-7 items-center justify-center rounded-lg bg-primary text-primary-foreground p-1"><img src={iwebLogo} alt="iweb" class="size-full" /></div><div class="min-w-0 group-data-[collapsible=icon]:hidden"><p class="truncate text-sm font-semibold tracking-tight">iweb</p><p class="truncate text-xs text-muted-foreground">Personal cloud node</p></div></div></Sidebar.Header><Sidebar.Content><Sidebar.Group><Sidebar.GroupLabel>控制台</Sidebar.GroupLabel><Sidebar.Menu>{#each navigation as item (item.id)}<Sidebar.MenuItem><Sidebar.MenuButton isActive={activeView === item.id} tooltipContent={item.label} onclick={() => (activeView = item.id)}><item.icon /><span>{item.label}</span></Sidebar.MenuButton></Sidebar.MenuItem>{/each}</Sidebar.Menu></Sidebar.Group></Sidebar.Content><Sidebar.Footer class="p-3"><Sidebar.Menu><Sidebar.MenuItem><div class="flex h-12 items-center gap-2 rounded-md p-2 group-data-[collapsible=icon]:size-8 group-data-[collapsible=icon]:p-2" title="节点管理员"><div class="relative flex size-8 shrink-0 items-center justify-center rounded-md bg-sidebar-accent text-sidebar-accent-foreground group-data-[collapsible=icon]:size-4"><UserRoundIcon class="size-4" /><span class:animate-pulse={monitor.state === "connecting" || monitor.state === "reconnecting"} class="absolute right-0 bottom-0 size-2 rounded-full ring-2 ring-sidebar" class:bg-primary={monitor.state === "connected"} class:bg-muted-foreground={monitor.state !== "connected"}></span></div><div class="min-w-0 group-data-[collapsible=icon]:hidden"><p class="truncate text-sm font-medium">节点管理员</p><p class="truncate text-xs text-muted-foreground">{status ? `api.${status.baseHost}` : "Kernel API"} · {accountConnectionLabel}</p></div></div></Sidebar.MenuItem><Sidebar.MenuItem><Sidebar.MenuButton tooltipContent="退出登录" onclick={() => logout()}><LogOutIcon /><span>退出登录</span></Sidebar.MenuButton></Sidebar.MenuItem></Sidebar.Menu></Sidebar.Footer><Sidebar.Rail /></Sidebar.Root>
		<Sidebar.Inset class="min-w-0 min-h-0 overflow-hidden"><header class="shrink-0 border-b px-4 py-3 sm:px-6"><div class="flex min-w-0 items-start gap-3"><Sidebar.Trigger class="mt-0.5" /><div class="flex min-w-0 flex-1 flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div class="min-w-0"><h1 class="text-base font-semibold text-balance">{currentView.title}</h1><p class="mt-0.5 max-w-3xl text-xs leading-relaxed text-muted-foreground text-pretty">{currentView.description}</p></div><div class="flex shrink-0 flex-wrap items-center gap-2">{#if activeView === "overview"}<Badge variant={monitor.state === "connected" ? "secondary" : "outline"}><ActivityIcon />{monitorStateLabel}</Badge>{/if}{#if activeView !== "recovery"}<Button variant="outline" size="sm" onclick={() => void refresh()} disabled={loading}>{#if loading}<Spinner data-icon="inline-start" />{:else}<RefreshCwIcon data-icon="inline-start" />{/if}<span>{activeView === "workspace" ? "刷新文件树" : "刷新"}</span></Button>{/if}</div></div></div></header><div class:overflow-y-auto={activeView !== "workspace"} class:overflow-hidden={activeView === "workspace"} class="scrollbar-thin scrollbar-track-transparent scrollbar-thumb-[color-mix(in_srgb,currentColor,transparent)] min-h-0 flex-1"><div class:mx-auto={activeView !== "workspace"} class:overflow-hidden={activeView === "workspace"} class="flex h-full min-h-0 w-full max-w-7xl flex-col p-4 sm:p-6 lg:p-8">{#if connectionError}<Alert.Root variant="destructive" class="mb-6 shrink-0"><CircleAlertIcon /><Alert.Title>无法同步节点</Alert.Title><Alert.Description>{connectionError}</Alert.Description><Alert.Action><Button variant="outline" size="sm" onclick={() => logout()}>返回登录</Button></Alert.Action></Alert.Root>{/if}
			{#if activeView === "overview"}
				<section class="flex flex-col gap-6">{#if loading && !status}<div class="grid gap-4 md:grid-cols-4">{#each ["node", "runtime", "workspace", "memory"] as item (item)}<Card.Root><Card.Header><Skeleton class="h-4 w-24" /></Card.Header><Card.Content><Skeleton class="h-8 w-32" /></Card.Content></Card.Root>{/each}</div>{:else if !status}<Empty.Root class="min-h-80 border"><Empty.Header><Empty.Media variant="icon"><KeyRoundIcon /></Empty.Media><Empty.Title>正在加载节点总览</Empty.Title><Empty.Description>管理员身份已验证，正在读取节点状态。</Empty.Description></Empty.Header><Empty.Content><Button onclick={() => void refresh()}>重试读取</Button></Empty.Content></Empty.Root>{:else}{@const nodeMemory = monitor.snapshot?.node.memory ?? status.memory}<div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4"><Card.Root><Card.Header><Card.Description>基础域名</Card.Description><Card.Title class="truncate text-xl">{status.baseHost}</Card.Title></Card.Header><Card.Footer class="flex items-center gap-2 border-t px-4 py-3 text-xs text-muted-foreground"><WifiIcon />Caddy 入口在线</Card.Footer></Card.Root><Card.Root><Card.Header><Card.Description>计算运行时</Card.Description><Card.Title class="text-xl">{status.runtime}</Card.Title></Card.Header><Card.Footer class="flex items-center gap-2 border-t px-4 py-3 text-xs text-muted-foreground"><ServerCogIcon />Durable Object SQLite</Card.Footer></Card.Root><Card.Root><Card.Header><Card.Description>工作区</Card.Description><Card.Title class="text-xl">{monitor.snapshot?.node.workspaceFileCount ?? workspace?.files.length ?? 0} 个对象</Card.Title></Card.Header><Card.Footer class="flex items-center gap-2 border-t px-4 py-3 text-xs text-muted-foreground"><DatabaseIcon />{monitor.snapshot ? `${(monitor.snapshot.node.workspaceBytes / 1024).toFixed(1)} KB` : "等待实时统计"}</Card.Footer></Card.Root><Card.Root><Card.Header><Card.Description>容器内存</Card.Description><Card.Title class="text-xl">{formatBytes(nodeMemory.usageBytes)}</Card.Title></Card.Header><Card.Footer class="flex items-center gap-2 border-t px-4 py-3 text-xs text-muted-foreground"><ActivityIcon />{formatMemoryUsagePercent(nodeMemory)} · 上限 {formatMemoryLimit(nodeMemory.limitBytes)}</Card.Footer></Card.Root></div><Card.Root><Card.Header><Card.Title>应用监控</Card.Title><Card.Description>请求、错误和延迟由 Kernel 在代理到 celld 时原子记录，并通过当前 WebSocket 会话推送。</Card.Description><Card.Action><Button variant="outline" size="sm" onclick={() => (activeView = "routes")}><AppWindowIcon data-icon="inline-start" />管理应用路由</Button></Card.Action></Card.Header><Card.Content class="px-0">{#if !monitor.snapshot}<div class="flex items-center gap-2 px-6 py-8 text-sm text-muted-foreground"><Spinner />正在等待实时监控快照…</div>{:else}<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="border-y bg-muted/40 text-left text-xs text-muted-foreground"><tr><th class="px-6 py-3 font-medium">应用</th><th class="px-6 py-3 font-medium">请求</th><th class="px-6 py-3 font-medium">错误</th><th class="px-6 py-3 font-medium">延迟</th><th class="px-6 py-3 font-medium">状态</th></tr></thead><tbody>{#each monitor.snapshot.apps as app (app.id)}<tr class="border-b last:border-0"><td class="px-6 py-3"><div class="flex items-center gap-2"><AppWindowIcon /><div><p class="font-medium">{app.id}</p><p class="font-mono text-xs text-muted-foreground">{app.sourcePath}</p></div></div></td><td class="px-6 py-3">{app.requests}</td><td class="px-6 py-3">{app.errors}</td><td class="px-6 py-3">{app.averageLatencyMs} ms</td><td class="px-6 py-3"><Badge variant={app.inFlight > 0 ? "outline" : "secondary"}>{app.inFlight > 0 ? `${app.inFlight} 进行中` : "空闲"}</Badge></td></tr>{/each}</tbody></table></div>{/if}</Card.Content></Card.Root>{/if}</section>
			{:else if activeView === "workspace"}
				<WorkspaceManager {workspace} client={session.client()} {loading} onrefresh={() => void refresh()} />
			{:else if activeView === "routes"}
				<RouteManager apps={workspaceApps} {routes} {status} monitor={monitor.snapshot} client={session.client()} protocol={externalProtocol} port={externalPort} onrefresh={() => void refresh()} />
			{:else}
				<section class="mx-auto flex max-w-3xl flex-col gap-6"><Alert.Root variant="destructive"><CircleAlertIcon /><Alert.Title>会导致节点短暂重启</Alert.Title><Alert.Description>恢复会触发 celld 的重新部署与 iweb 容器内进程重启。请确认当前没有依赖此节点的写入操作。</Alert.Description></Alert.Root><Card.Root><Card.Header><Card.Title>镜像恢复点</Card.Title><Card.Description>恢复目标是当前 iweb 镜像附带的内置 Admin 应用与 Dispatcher。</Card.Description></Card.Header><Card.Content><div class="grid gap-3 rounded-lg border p-4 text-sm sm:grid-cols-3"><div><p class="text-xs text-muted-foreground">恢复入口</p><p class="mt-1 font-mono">api/v1/recover/admin</p></div><div><p class="text-xs text-muted-foreground">保留数据</p><p class="mt-1">MinIO + 路由注册表</p></div><div><p class="text-xs text-muted-foreground">预计影响</p><p class="mt-1">短暂服务中断</p></div></div></Card.Content><Card.Footer class="flex justify-end border-t px-4 py-3"><Button variant="destructive" onclick={() => (recoveryDialogOpen = true)} disabled={!isAuthenticated}><RotateCcwIcon data-icon="inline-start" />恢复内置 Admin</Button></Card.Footer></Card.Root></section>
			{/if}</div></div></Sidebar.Inset></Sidebar.Provider>
{/if}

<AlertDialog.Root bind:open={recoveryDialogOpen}><AlertDialog.Content><AlertDialog.Header><AlertDialog.Title>确认恢复镜像内置 Admin？</AlertDialog.Title><AlertDialog.Description>Kernel 将重部署内置 Dispatcher，并让节点短暂重启。用户路由和 MinIO 数据会保留，但正在进行中的请求可能中断。</AlertDialog.Description></AlertDialog.Header><AlertDialog.Footer><AlertDialog.Cancel disabled={recovering}>取消</AlertDialog.Cancel><AlertDialog.Action variant="destructive" onclick={() => void recoverAdmin()} disabled={recovering}>{#if recovering}<Spinner data-icon="inline-start" />{/if}确认恢复</AlertDialog.Action></AlertDialog.Footer></AlertDialog.Content></AlertDialog.Root>
<Toaster />
