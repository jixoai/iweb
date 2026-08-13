<script lang="ts">
	// 用户原始需求（2026-08-13）：工作区只呈现文件树和文件详情，并提供企业级编辑体验。
	// 正交意图：选择和读取对象；编辑与保存文本；防止未保存切换；显示文件树；不管理应用域名。
	import FileCode2Icon from "@lucide/svelte/icons/file-code-2";
	import FolderTreeIcon from "@lucide/svelte/icons/folder-tree";
	import SaveIcon from "@lucide/svelte/icons/save";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import * as Empty from "$lib/components/ui/empty";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Card from "$lib/components/ui/card";
	import { Spinner } from "$lib/components/ui/spinner";
	import { toast } from "svelte-sonner";
	import { KernelApiClient } from "$lib/iweb/api";
	import type { Workspace, WorkspaceFile } from "$lib/iweb/contracts";
	import CodeEditor from "$lib/workspace/code-editor.svelte";
	import { workspaceTree } from "$lib/workspace/file-tree";
	import WorkspaceTree from "$lib/workspace/workspace-tree.svelte";

	type Props = {
		workspace: Workspace | null;
		client: KernelApiClient;
		loading: boolean;
		onrefresh: () => void;
	};

	let { workspace, client, loading, onrefresh }: Props = $props();
	let selectedFile = $state<WorkspaceFile | null>(null);
	let draft = $state("");
	let savedContent = $state("");
	let fileLoading = $state(false);
	let saving = $state(false);
	let fileError = $state("");
	let pendingFile = $state<WorkspaceFile | null>(null);
	let discardDialogOpen = $state(false);

	const tree = $derived(workspaceTree(workspace?.files ?? []));
	const dirty = $derived(selectedFile !== null && draft !== savedContent);
	const selectedSize = $derived(selectedFile ? formatBytes(selectedFile.size) : "");

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}

	async function loadFile(file: WorkspaceFile): Promise<void> {
		fileLoading = true;
		fileError = "";
		selectedFile = file;
		draft = "";
		savedContent = "";
		try {
			const result = await client.workspaceFile(file.path);
			if (selectedFile?.path !== file.path) return;
			draft = result.content;
			savedContent = result.content;
		} catch (error) {
			if (selectedFile?.path === file.path) fileError = error instanceof Error ? error.message : "无法读取文件";
		} finally {
			if (selectedFile?.path === file.path) fileLoading = false;
		}
	}

	function selectFile(file: WorkspaceFile): void {
		if (selectedFile?.path === file.path) return;
		if (dirty) {
			pendingFile = file;
			discardDialogOpen = true;
			return;
		}
		void loadFile(file);
	}

	function discardAndContinue(): void {
		const next = pendingFile;
		pendingFile = null;
		discardDialogOpen = false;
		if (next) void loadFile(next);
	}

	async function save(): Promise<void> {
		if (!selectedFile || !dirty || saving) return;
		saving = true;
		fileError = "";
		try {
			const result = await client.writeWorkspaceFile({ path: selectedFile.path, content: draft });
			savedContent = draft;
			toast.success(`已保存 ${result.path}`, { description: `${formatBytes(result.bytes)} 已写入 MinIO 工作区` });
			onrefresh();
		} catch (error) {
			fileError = error instanceof Error ? error.message : "保存文件失败";
			toast.error(fileError);
		} finally {
			saving = false;
		}
	}
</script>

<section class="flex h-full min-h-0 flex-1 flex-col gap-4">
	{#if !workspace && !loading}
		<Empty.Root class="min-h-80 border">
			<Empty.Header><Empty.Media variant="icon"><FolderTreeIcon /></Empty.Media><Empty.Title>暂时无法读取工作区</Empty.Title><Empty.Description>管理员已登录，但节点状态尚未完成同步。</Empty.Description></Empty.Header>
			<Empty.Content><Button onclick={onrefresh}>重新同步</Button></Empty.Content>
		</Empty.Root>
	{:else}
		<div class="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(16rem,0.7fr)_minmax(0,1.5fr)]">
			<Card.Root class="flex min-h-0 flex-col overflow-hidden">
				<Card.Header class="border-b">
					<Card.Title>文件树</Card.Title>
					<Card.Description>{workspace?.files.length ?? 0} 个对象 · owner key 可读写整个工作区。</Card.Description>
				</Card.Header>
				<Card.Content class="scrollbar-thin scrollbar-track-transparent scrollbar-thumb-[color-mix(in_srgb,currentColor,transparent)] min-h-0 flex-1 overflow-y-auto p-2">
					{#if tree.length === 0}
						<Empty.Root class="min-h-52"><Empty.Header><Empty.Media variant="icon"><FolderTreeIcon /></Empty.Media><Empty.Title>工作区为空</Empty.Title><Empty.Description>将文件上传到 MinIO 后会在这里出现。</Empty.Description></Empty.Header></Empty.Root>
					{:else}
						<WorkspaceTree nodes={tree} selectedPath={selectedFile?.path ?? null} onselect={selectFile} />
					{/if}
				</Card.Content>
			</Card.Root>

			<Card.Root class="flex min-h-0 flex-col overflow-hidden">
				{#if !selectedFile}
					<Empty.Root class="h-full min-h-80"><Empty.Header><Empty.Media variant="icon"><FileCode2Icon /></Empty.Media><Empty.Title>选择一个文件</Empty.Title><Empty.Description>从左侧文件树选择文本对象，即可查看详情并编辑。</Empty.Description></Empty.Header></Empty.Root>
				{:else}
					<Card.Header class="border-b py-3">
						<div class="flex min-w-0 items-center gap-3"><FileCode2Icon /><div class="min-w-0"><Card.Title class="truncate font-mono text-sm">/{selectedFile.path}</Card.Title><Card.Description>{selectedSize} · 最后修改于 {new Date(selectedFile.lastModified).toLocaleString()}</Card.Description></div></div>
						<Card.Action><div class="flex items-center gap-2"><Badge variant={dirty ? "outline" : "secondary"}>{dirty ? "未保存" : "已保存"}</Badge><Button size="sm" onclick={() => void save()} disabled={!dirty || saving || fileLoading}>{#if saving}<Spinner data-icon="inline-start" />{:else}<SaveIcon data-icon="inline-start" />{/if}保存</Button></div></Card.Action>
					</Card.Header>
					{#if fileError}
						<div class="m-4 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{fileError}</div>
					{:else if fileLoading}
						<div class="flex min-h-0 flex-1 items-center justify-center"><Spinner /> <span class="ml-2 text-sm text-muted-foreground">正在读取文件…</span></div>
					{:else}
						<div class="min-h-0 flex-1"><CodeEditor path={selectedFile.path} content={draft} onchange={(value) => (draft = value)} onsave={() => void save()} /></div>
					{/if}
				{/if}
			</Card.Root>
		</div>
	{/if}
</section>

<AlertDialog.Root bind:open={discardDialogOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header><AlertDialog.Title>放弃未保存的修改？</AlertDialog.Title><AlertDialog.Description>切换文件会丢弃当前编辑器中的未保存内容。你可以先按 Cmd/Ctrl + S 保存。</AlertDialog.Description></AlertDialog.Header>
		<AlertDialog.Footer><AlertDialog.Cancel>继续编辑</AlertDialog.Cancel><AlertDialog.Action variant="destructive" onclick={discardAndContinue}>放弃并切换</AlertDialog.Action></AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
