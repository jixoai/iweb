<!-- 用户原始需求（2026-08-23）：owner-key-management——Keys 视图：签发/吊销/审计/一键复制部署提示词。
     正交意图：列表+创建（过期预设）+一次性 token 展示+ban 确认+审计过滤；不承担 Kernel 逻辑。 -->
<script lang="ts">
	import CircleAlertIcon from "@lucide/svelte/icons/circle-alert";
	import ClipboardCopyIcon from "@lucide/svelte/icons/clipboard-copy";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import ScrollTextIcon from "@lucide/svelte/icons/scroll-text";
	import ShieldBanIcon from "@lucide/svelte/icons/shield-ban";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import * as Alert from "$lib/components/ui/alert";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Card from "$lib/components/ui/card";
	import * as Empty from "$lib/components/ui/empty";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import { Spinner } from "$lib/components/ui/spinner";
	import { toast } from "svelte-sonner";
	import type { AuditEvent, KeyIssuance, KeyMetadata } from "$lib/iweb/contracts";
	import { KernelApiError, type KernelApiClient } from "$lib/iweb/api";

	type Client = Pick<KernelApiClient, "keysList" | "keysCreate" | "keysBan" | "audit">;

	let { client, baseHost = "", onrefresh, onauthfailure }: { client: Client; baseHost?: string; onrefresh?: () => void; onauthfailure?: () => void } = $props();

	let keys = $state<KeyMetadata[] | null>(null);
	let events = $state<AuditEvent[] | null>(null);
	let droppedLines = $state(0);
	let loading = $state(false);
	let error = $state("");
	let createOpen = $state(false);
	let labelDraft = $state("");
	let expiryPreset = $state("never");
	let creating = $state(false);
	let issuance = $state<KeyIssuance | null>(null);
	let banTarget = $state<KeyMetadata | null>(null);
	let banning = $state(false);
	let auditFilter = $state("");
	let copiedPrompt = $state(false);

	const expiryPresets: { value: string; label: string; days: number | null }[] = [
		{ value: "never", label: "永不过期", days: null },
		{ value: "1", label: "1 天", days: 1 },
		{ value: "7", label: "7 天", days: 7 },
		{ value: "30", label: "30 天", days: 30 }
	];

	const statusVariant = (status: string) => (status === "active" ? "secondary" : "outline");

	function presetToIso(days: number | null): string | null {
		if (days === null) return null;
		return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, ".000Z");
	}

	function deploymentPrompt(token: string): string {
		return [
			"你是 iweb 个人节点上的部署代理。使用以下 MCP 端点管理此节点：",
			"",
			"- 端点： https://mcp." + baseHost + "/mcp",
			"- 密钥： " + token,
			"",
			"规则：",
			"1. 每个 JSON-RPC 请求（包括 initialize 与 notifications 之后的每个调用）都必须携带请求头 Authorization: Bearer <上述密钥>。",
			"2. 该密钥等同于节点管理员凭据：绝不写入文件、URL、日志或代码仓库。",
			"3. 可用工具：iweb_workspace_*（工作区文件）、iweb_domain_*（域名路由）；应用发布闸门未开放时 iweb_application_* 返回 503 属预期行为。",
			"4. 部署完成后向用户报告变更内容。"
		].join("\n");
	}

	async function copyPrompt(token: string): Promise<void> {
		await navigator.clipboard.writeText(deploymentPrompt(token));
		copiedPrompt = true;
		setTimeout(() => (copiedPrompt = false), 2000);
	}

	async function refresh(): Promise<void> {
		loading = true;
		error = "";
		try {
			const [nextKeys, nextAudit] = await Promise.all([client.keysList(), client.audit(auditFilter || null, 50)]);
			keys = nextKeys.keys;
			events = nextAudit.events;
			droppedLines = nextAudit.dropped;
		} catch (cause) {
			if (cause instanceof KernelApiError && cause.status === 401) {
				onauthfailure?.();
				return;
			}
			error = cause instanceof Error ? cause.message : "无法读取密钥状态";
		} finally {
			loading = false;
		}
	}

	async function create(): Promise<void> {
		creating = true;
		try {
			issuance = await client.keysCreate(labelDraft.trim() || "agent", presetToIso(expiryPresets.find((preset) => preset.value === expiryPreset)?.days ?? null));
			createOpen = false;
			labelDraft = "";
			toast.success("密钥已创建；明文只显示这一次");
			await refresh();
			onrefresh?.();
		} catch (cause) {
			if (cause instanceof KernelApiError && cause.status === 401) {
				onauthfailure?.();
				return;
			}
			toast.error(cause instanceof Error ? cause.message : "创建失败");
		} finally {
			creating = false;
		}
	}

	async function ban(): Promise<void> {
		if (!banTarget) return;
		banning = true;
		try {
			await client.keysBan(banTarget.keyId);
			toast.success(`密钥 ${banTarget.keyId} 已吊销`);
			banTarget = null;
			await refresh();
		} catch (cause) {
			if (cause instanceof KernelApiError && cause.status === 401) {
				onauthfailure?.();
				return;
			}
			toast.error(cause instanceof Error ? cause.message : "吊销失败");
		} finally {
			banning = false;
		}
	}

	$effect(() => {
		void auditFilter;
		void refresh();
	});
</script>

<section class="flex flex-col gap-6">
	{#if error}
		<Alert.Root variant="destructive"><CircleAlertIcon /><Alert.Title>无法读取密钥状态</Alert.Title><Alert.Description>{error}</Alert.Description></Alert.Root>
	{/if}

	{#if issuance}
		<Card.Root class="border-primary/40">
			<Card.Header><Card.Title class="flex items-center gap-2"><KeyRoundIcon />新密钥（仅此一次可见）</Card.Title><Card.Description>关闭此卡片后明文不再出现；请立即复制部署提示词或妥善保存 token。</Card.Description></Card.Header>
			<Card.Content class="flex flex-col gap-3">
				<div class="grid gap-2 rounded-lg border bg-muted/40 p-3 font-mono text-xs break-all">
					<span class="text-muted-foreground">token</span>
					<span>{issuance.token}</span>
				</div>
				<div class="flex flex-wrap gap-2">
					<Button size="sm" onclick={() => void copyPrompt(issuance!.token)}>
						<ClipboardCopyIcon data-icon="inline-start" />{copiedPrompt ? "已复制部署提示词" : "复制部署提示词"}
					</Button>
					<Button size="sm" variant="outline" onclick={() => navigator.clipboard.writeText(issuance!.token).then(() => toast.success("token 已复制"))}>仅复制 token</Button>
					<Button size="sm" variant="ghost" onclick={() => (issuance = null)}>我已保存，关闭</Button>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}

	<Card.Root>
		<Card.Header>
			<Card.Title>密钥</Card.Title>
			<Card.Description>每把密钥都具有完整 owner 权限；按密钥分发给不同 Agent，异常时可单独吊销。bootstrap 恢复密钥来自节点配置，不可吊销。</Card.Description>
			<Card.Action><Button size="sm" onclick={() => (createOpen = true)} disabled={loading}><KeyRoundIcon data-icon="inline-start" />新建密钥</Button></Card.Action>
		</Card.Header>
		<Card.Content class="px-0">
			{#if loading && !keys}
				<div class="flex items-center gap-2 px-6 pb-3 text-xs text-muted-foreground"><Spinner />正在读取密钥列表…</div>
			{:else if !keys || keys.length === 0}
				<Empty.Root class="min-h-40 border"><Empty.Title>没有密钥</Empty.Title><Empty.Description>创建一把密钥即可开始向 Agent 分发部署能力。</Empty.Description></Empty.Root>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full text-sm">
						<thead><tr class="border-b text-left text-xs text-muted-foreground"><th class="px-6 py-2 font-medium">标识</th><th class="px-3 py-2 font-medium">标签</th><th class="px-3 py-2 font-medium">状态</th><th class="px-3 py-2 font-medium">过期</th><th class="px-6 py-2 text-right font-medium">操作</th></tr></thead>
						<tbody>
							{#each keys as key (key.keyId)}
								<tr class="border-b last:border-0">
									<td class="px-6 py-2.5 font-mono text-xs">{key.keyId}</td>
									<td class="px-3 py-2.5">{key.label ?? "—"}</td>
									<td class="px-3 py-2.5"><Badge variant={statusVariant(key.status)}>{key.status === "active" ? "活跃" : key.status === "banned" ? "已吊销" : "已过期"}</Badge>{#if !key.revocable}<span class="ml-1 text-xs text-muted-foreground">恢复密钥</span>{/if}</td>
									<td class="px-3 py-2.5 text-xs text-muted-foreground">{key.expiresAt ? new Date(key.expiresAt).toLocaleString("zh-CN") : "永不过期"}</td>
									<td class="px-6 py-2.5 text-right">{#if key.revocable && key.status === "active"}<Button size="sm" variant="outline" onclick={() => (banTarget = key)}><ShieldBanIcon data-icon="inline-start" />吊销</Button>{/if}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title>审计</Card.Title>
			<Card.Description>控制面操作按密钥归因（含 401 拒绝）；只保留最近 4 MiB。{#if droppedLines > 0}<span class=text-destructive>⚠ {droppedLines} 行损坏审计已被跳过。</span>{/if}</Card.Description>
			<Card.Action>
				<Input class="h-8 w-36 font-mono text-xs" placeholder="按 keyId 过滤" bind:value={auditFilter} oninput={() => void 0} />
			</Card.Action>
		</Card.Header>
		<Card.Content class="px-0">
			{#if !events || events.length === 0}
				<Empty.Root class="min-h-32 border"><Empty.Header><Empty.Media variant="icon"><ScrollTextIcon /></Empty.Media><Empty.Title>暂无审计事件</Empty.Title></Empty.Header></Empty.Root>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full text-sm">
						<thead><tr class="border-b text-left text-xs text-muted-foreground"><th class="px-6 py-2 font-medium">时间</th><th class="px-3 py-2 font-medium">密钥</th><th class="px-3 py-2 font-medium">动作</th><th class="px-6 py-2 font-medium">路径</th><th class="px-6 py-2 text-right font-medium">状态</th></tr></thead>
						<tbody>
							{#each events as event, index (event.ts + String(index))}
								<tr class="border-b last:border-0 font-mono text-xs">
									<td class="px-6 py-2.5">{new Date(event.ts).toLocaleString("zh-CN")}</td>
									<td class="px-3 py-2.5">{event.keyId ?? "未归属"}</td>
									<td class="px-3 py-2.5">{event.action}</td>
									<td class="px-6 py-2.5">{event.method} {event.path}</td>
									<td class="px-6 py-2.5 text-right">{event.status}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</section>

<AlertDialog.Root bind:open={createOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header><AlertDialog.Title>新建密钥</AlertDialog.Title><AlertDialog.Description>新密钥与 bootstrap 密钥具有相同的完整权限；建议按 Agent 用途命名。</AlertDialog.Description></AlertDialog.Header>
		<div class="flex flex-col gap-4">
			<Field.Field><Field.FieldLabel for="key-label">标签</Field.FieldLabel><Input id="key-label" placeholder="例如：claude-code / codex / 备用" bind:value={labelDraft} maxlength={128} /></Field.Field>
			<Field.Field><Field.FieldLabel for="key-expiry">有效期</Field.FieldLabel>
				<select id="key-expiry" class="h-9 w-full rounded-md border bg-transparent px-3 text-sm" bind:value={expiryPreset}>
					{#each expiryPresets as preset (preset.value)}<option value={preset.value}>{preset.label}</option>{/each}
				</select>
				<Field.FieldDescription>到期后密钥自动失效，无需手动吊销。</Field.FieldDescription>
			</Field.Field>
		</div>
		<AlertDialog.Footer><AlertDialog.Cancel disabled={creating}>取消</AlertDialog.Cancel><AlertDialog.Action onclick={() => void create()} disabled={creating || !labelDraft.trim()}>{#if creating}<Spinner data-icon="inline-start" />{/if}创建</AlertDialog.Action></AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>

<AlertDialog.Root open={banTarget !== null}>
	<AlertDialog.Content>
		<AlertDialog.Header><AlertDialog.Title>吊销密钥 {banTarget?.keyId}？</AlertDialog.Title><AlertDialog.Description>吊销立即生效且不可撤销：使用此密钥的 Agent 将立即失去节点访问权，进行中的监控连接会被关闭。</AlertDialog.Description></AlertDialog.Header>
		<AlertDialog.Footer><AlertDialog.Cancel onclick={() => (banTarget = null)} disabled={banning}>取消</AlertDialog.Cancel><AlertDialog.Action variant="destructive" onclick={() => void ban()} disabled={banning}>{#if banning}<Spinner data-icon="inline-start" />{/if}确认吊销</AlertDialog.Action></AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
