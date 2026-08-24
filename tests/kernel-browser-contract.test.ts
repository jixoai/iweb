// 用户原始需求（2026-08-21）：Admin 真浏览器登录暴露 Rust 内核响应结构漂移（memory 包装、
// monitor 帧缺字段）——curl 级验证无法覆盖浏览器边界解析。
// 正交意图：用 Admin 实际使用的 zod schema 作为单一契约真源，驱动任一 Kernel 实现
// （KERNEL_TEST_COMMAND 参数化，同 recovery 套件约定），杜绝跨实现结构漂移再次上线。
// 覆盖面：/v1/status、/v1/key、/v1/routes、/v1/workspace（mc shim 确定性列举）、
// monitor 票据、WS 首帧 + 代理请求触发的广播帧、strict schema 拒绝多余字段。
import { describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import {
	admitVersion,
	activateVersion,
	controlStateToFile,
	emptyControlState,
	markVersionReady,
} from "../packages/contracts/control-db.ts";
import { packageFilesDigest, versionDigest } from "../packages/contracts/package-collection.ts";
import {
	monitorSnapshotSchema,
	monitorTicketSchema,
	nodeStatusWithApplicationsSchema,
	ownerKeySchema,
	routeStoreSchema,
	workspaceSchema,
} from "../apps/admin-console/src/lib/iweb/contracts.ts";

const BASE_HOST = "browsercontract.test";
const TOKEN = "browser-contract-token-000";
const PORT = 7070;
// 显式钉死：bun 自动加载仓库 .env（IWEB_HTTP_PORT=9010）会漂移入口端口。
const INGRESS_PORT = 38080;

const resources = { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 };
const policy = { resources, egress: { default: "deny" as const, allow: [] } };
const manifest = {
	schemaVersion: 1 as const,
	name: "notes",
	runtime: { kind: "celld" as const, celldVersion: "0.2.0", entrypoint: "index.js" },
	assets: { root: "app" },
	resources,
	storage: { persistent: false, requestBytes: 0 },
	egress: { default: "deny" as const, allow: [] },
};
const snapshot = [{ path: "app/index.js", content: Buffer.from("export default {};\n") }];
const digest = packageFilesDigest(snapshot);

/** 确定性 workspace：伪造 mc（两内核都以子进程调 mc ls），返回固定的 notes 清单。 */
// typescript-monorepo：workspace 只含普通 owner 文件（无应用清单/代码镜像）。
const WORKSPACE_FILES = [
	{ key: "readme.md", size: 128, lastModified: "2026-08-24T00:00:00.000Z" },
	{ key: "orphan-dir/iweb.json", size: 64, lastModified: "2026-08-24T00:00:00.000Z" },
	{ key: "box/readme.md", size: 32, lastModified: "2026-08-24T00:00:00.000Z" },
];

function seededDirectory(): string {
	const directory = mkdtempSync(join(tmpdir(), "iweb-browser-contract-"));
	let state = emptyControlState();
	const admitted = admitVersion(state, { applicationId: "notes", packageDigest: digest, manifest, policy, admittedAt: "2026-08-14T00:00:00.000Z" });
	if (!admitted.ok) throw new Error("seed admission failed");
	state = admitted.value.state;
	const ready = markVersionReady(state, "notes", admitted.value.version.versionId, "2099-01-01T00:00:00.000Z");
	if (!ready.ok) throw new Error("seed readiness failed");
	state = ready.value.state;
	const active = activateVersion(state, "notes", admitted.value.version.versionId);
	if (!active.ok) throw new Error("seed activation failed");
	state = active.value.state;
	writeFileSync(join(directory, "control-db.json"), `${JSON.stringify(controlStateToFile(state), null, 2)}\n`);
	const routes = { version: 1, routes: [
		{ hostId: "admin", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
		{ hostId: "admin.app", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
		{ hostId: "mcp", target: { kind: "celld-app", appName: "mcp" }, system: true, enabled: true },
		{ hostId: "mcp.app", target: { kind: "celld-app", appName: "mcp" }, system: true, enabled: true },
		{ hostId: "notes.app", target: { kind: "celld-app", appName: "notes" }, system: false, enabled: true },
	] };
	writeFileSync(join(directory, "routes.json"), `${JSON.stringify(routes, null, 2)}\n`);
	// mc shim：ls 输出 NDJSON（内存 listing）；cp/rm 追加/删除 listing（对象增删投影断言用）。
	const binDirectory = join(directory, "bin");
	mkdirSync(binDirectory, { recursive: true });
	const listingPath = join(binDirectory, "listing.ndjson");
	writeFileSync(listingPath, WORKSPACE_FILES.map((file) => JSON.stringify({ status: "success", type: "file", ...file })).join("\n") + "\n");
	writeFileSync(join(binDirectory, "mc"), `#!/bin/sh
if [ "$1" = "ls" ]; then
	cat '${listingPath}'
	exit 0
fi
if [ "$1" = "cp" ]; then
	printf '%s\\n' "{\\"status\\":\\"success\\",\\"type\\":\\"file\\",\\"key\\":\\"$(basename "$3")\\",\\"size\\":1,\\"lastModified\\":\\"2099-01-01T00:00:00.000Z\\"}" >> '${listingPath}'
	exit 0
fi
if [ "$1" = "rm" ]; then
	grep -v "\\"$(basename "$2")\\"" '${listingPath}' > '${listingPath}.tmp' && mv '${listingPath}.tmp' '${listingPath}'
	exit 0
fi
echo "mc shim: unsupported" >&2
exit 1
`);
	chmodSync(join(binDirectory, "mc"), 0o755);
	return directory;
}

async function waitHealthy(timeoutMs: number): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const response = await fetch(`http://127.0.0.1:${PORT}/health`);
			if (response.ok) return;
		} catch {
			// not listening yet
		}
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
	throw new Error("kernel subprocess did not become healthy in time");
}

async function api(path: string, init: RequestInit = {}): Promise<Response> {
	const headers = new Headers(init.headers);
	headers.set("host", `api.${BASE_HOST}`);
	headers.set("authorization", `Bearer ${TOKEN}`);
	return fetch(`http://127.0.0.1:${PORT}${path}`, { ...init, headers });
}

/** 持续的 WS 帧读取器：fetch 不能发 Upgrade，走裸 socket。 */
class WebSocketFrames {
	private seen = Buffer.alloc(0);
	readonly frames: string[] = [];
	private waiters: Array<{ test: (frame: string) => boolean; resolve: (frame: string) => void }> = [];
	private failure: Error | undefined;

	constructor(socket: net.Socket) {
		socket.on("data", (chunk: Buffer) => {
			this.seen = Buffer.concat([this.seen, chunk]);
			for (;;) {
				const headerEnd = this.seen.indexOf("\r\n\r\n");
				const body = headerEnd < 0 ? this.seen : this.seen.subarray(headerEnd + 4);
				if (body.length < 2) return;
				const flag = body[1] & 0x7f;
				const size = flag < 0x7e ? 2 : flag === 0x7e ? 4 : 10;
				if (body.length < size) return;
				const length = flag < 0x7e ? flag
					: flag === 0x7e ? body.readUInt16BE(2)
						: Number(body.readBigUInt64BE(2));
				if (body.length < size + length) return;
				this.seen = headerEnd < 0 ? body.subarray(size + length) : Buffer.concat([Buffer.alloc(0), body.subarray(size + length)]);
				// 头部与首帧可能同包到达：保留残余字节。
				const frame = body.subarray(size, size + length).toString("utf8");
				this.frames.push(frame);
				this.waiters = this.waiters.filter((waiter) => {
					if (waiter.test(frame)) {
						waiter.resolve(frame);
						return false;
					}
					return true;
				});
			}
		});
		socket.on("error", (error) => {
			this.failure = error;
			this.waiters.forEach((waiter) => waiter.resolve(""));
			this.waiters = [];
		});
	}

	async nextMatching(test: (frame: string) => boolean, timeoutMs: number): Promise<string> {
		const existing = this.frames.find(test);
		if (existing !== undefined) return existing;
		return new Promise((resolve) => {
			const timer = setTimeout(() => {
				this.waiters = this.waiters.filter((waiter) => waiter.resolve !== resolve);
				resolve("");
			}, timeoutMs);
			this.waiters.push({ test, resolve: (frame) => { clearTimeout(timer); resolve(frame); } });
			if (this.failure) resolve("");
		});
	}
}

describe("browser contract (admin zod schemas drive any kernel)", () => {
	test("status, key, routes, workspace, ticket, WS frames all parse with the Admin's own schemas", async () => {
		const directory = seededDirectory();
		// 同 recovery 套件约定：KERNEL_TEST_COMMAND 例
		// "<repo>/kernel-rs/target/debug/iweb-kernel" 或 "node <repo>/kernel/index.js"。
		const command = (process.env.KERNEL_TEST_COMMAND ?? `node ${join(import.meta.dir, "..", "kernel", "index.js")}`).split(" ");
		// 拓扑差异（过渡期）：Rust 内核有专属发布入口（IWEB_HTTP_PORT）；JS 参考实现
		// 是 Caddy 时代单监听器（控制+入口同在 7070）。
		const rustIngress = !command[0].endsWith("node");
		const ingressPort = rustIngress ? INGRESS_PORT : PORT;
		const child = spawn(command[0], command.slice(1), {
			env: {
				...process.env,
				PATH: `${join(directory, "bin")}:${process.env.PATH ?? ""}`,
				IWEB_BASE_HOST: BASE_HOST,
				IWEB_API_TOKEN: TOKEN,
				IWEB_HTTP_PORT: String(INGRESS_PORT),
				IWEB_ROUTES_FILE: join(directory, "routes.json"),
				IWEB_WORKSPACE_OBJECT: "local/iweb-workspace",
				IWEB_RECOVERY_WORKER: "recovery-worker",
				IWEB_ADMIN_CELLD_BUCKET: "iweb-cells-admin",
				IWEB_CELLD_ENDPOINT: "http://127.0.0.1:9000",
				IWEB_CELLD_REGION: "us-east-1",
				IWEB_SANDBOX_SOCKET: join(directory, "supervisor.sock"),
				IWEB_CONTROL_DB_FILE: join(directory, "control-db.json"),
				IWEB_CONTROL_SECRETS_FILE: join(directory, "control-secrets.json"),
				IWEB_SANDBOX_GATEWAY_DIR: join(directory, "gw"),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stderr = "";
		child.stderr.on("data", (chunk) => { stderr += String(chunk); });
		try {
			await waitHealthy(15_000);

			// 1) /v1/status —— Admin 登录后首次同步的精确契约（strict，多余键即拒收）。
			const statusResponse = await api("/v1/status");
			expect(statusResponse.status).toBe(200);
			const statusPayload = await statusResponse.json();
			const status = nodeStatusWithApplicationsSchema.parse(statusPayload);
			expect(status.baseHost).toBe(BASE_HOST);
			// heap 是真实测量：可测为正整数，缺测为 null（开发宿主无 /proc），绝不 0 冒充。
			expect(typeof status.memory.kernelHeapUsedBytes === "number"
				? status.memory.kernelHeapUsedBytes > 0
				: status.memory.kernelHeapUsedBytes === null).toBe(true);
			const seeded = status.applications.find((application) => application.id === "notes");
			expect(seeded?.lifecycle).toBe("active");
			expect(seeded?.activeVersion?.digest).toBe(versionDigest(digest, manifest));
			expect(JSON.stringify(statusPayload)).not.toContain(TOKEN);
			// strict 回归：多余字段必须被拒（schema 与内核载荷同时被此断言约束）。
			expect(nodeStatusWithApplicationsSchema.safeParse({ ...statusPayload, surplus: 1 }).success).toBe(false);

			// 2) /v1/key —— ownerKeySchema。
			const keyResponse = await api("/v1/key");
			expect(keyResponse.status).toBe(200);
			expect(ownerKeySchema.parse(await keyResponse.json()).kind).toBe("owner");

			// 3) /v1/routes —— routeStoreSchema（种子系统路由）。
			const routesResponse = await api("/v1/routes");
			expect(routesResponse.status).toBe(200);
			const store = routeStoreSchema.parse(await routesResponse.json());
			expect(store.routes.length).toBeGreaterThanOrEqual(4);
			expect(store.routes.some((route) => route.hostId === "admin" && route.system)).toBe(true);

			// 4) /v1/workspace —— mc shim 的确定性列举 + apps 派生（workspaceSchema）。
			const workspaceResponse = await api("/v1/workspace");
			expect(workspaceResponse.status).toBe(200);
			const workspacePayload = await workspaceResponse.json();
			const workspace = workspaceSchema.parse(workspacePayload);
			expect(workspace.files.map((file) => file.path)).toContain("readme.md");
			const notes = workspace.apps.find((application) => application.id === "notes");
			expect(notes?.domains.length).toBeGreaterThan(0);
			// workspace-only 目录（有 iweb.json 但无 route）不投影；普通文件保留但 readme 不是应用。
			expect(workspace.apps.find((application) => application.id === "orphan-dir")).toBeUndefined();
			expect(workspace.apps.find((application) => application.id === "box")).toBeUndefined();
			// 三投影集合相等：workspace apps == route registry（monitor 帧断言覆盖第三投影）。
			expect(workspace.apps.map((application) => application.id).sort()).toEqual(
				[...new Set(store.routes.filter((route) => route.target.kind === "celld-app").map((route) => route.target.appName).filter(Boolean))].sort(),
			);
			// 逐字段：domains == 该应用全部 hostId（排序）、deployed/system 来自路由。
			for (const application of workspace.apps) {
				const expected = store.routes.filter((route) => route.target.kind === "celld-app" && route.target.appName === application.id).map((route) => route.hostId).sort();
				expect(application.domains.slice().sort()).toEqual(expected);
				expect(application.deployed).toBe(store.routes.some((route) => route.target.appName === application.id && route.enabled));
				expect(application.system).toBe(store.routes.some((route) => route.target.appName === application.id && route.system));
			}
			expect(JSON.stringify(workspacePayload)).not.toContain("sourcePath");
			expect(JSON.stringify(workspacePayload)).not.toContain("manifestPath");
			expect(workspaceSchema.safeParse({ ...workspacePayload, surplus: 1 }).success).toBe(false);
			// workspace 对象增删不改变任何 apps 投影（纯路由派生的语义锁）。
			const put = await api("/v1/workspace/file", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ path: "added-by-test.md", content: "x" }) });
			expect([200, 201]).toContain(put.status);
			const after = workspaceSchema.parse(await (await api("/v1/workspace")).json());
			expect(after.apps).toEqual(workspace.apps);
			const remove = await api("/v1/workspace/file?path=added-by-test.md", { method: "DELETE" });
			expect([200, 204]).toContain(remove.status);
			const afterDelete = workspaceSchema.parse(await (await api("/v1/workspace")).json());
			expect(afterDelete.apps).toEqual(workspace.apps);

			// 5) 监控票据 —— Admin monitor 视图的入场景。
			const ticketResponse = await api("/v1/monitor/session", { method: "POST" });
			expect(ticketResponse.status).toBe(201);
			const ticket = monitorTicketSchema.parse(await ticketResponse.json());

			// 6) WS 帧 —— 首帧 schema 全解析 + 经 ingress 的真实代理请求触发广播帧。
			const socket = net.connect(PORT, "127.0.0.1", () => {
				socket.write(`GET /v1/monitor?ticket=${encodeURIComponent(ticket.ticket)} HTTP/1.1\r\nHost: api.${BASE_HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
			});
			const frames = new WebSocketFrames(socket);
			const firstText = await frames.nextMatching(() => true, 5000);
			expect(firstText).toBeTruthy();
			const firstFrame = monitorSnapshotSchema.parse(JSON.parse(firstText));
			expect(firstFrame.node.routeCount).toBeGreaterThanOrEqual(4);
			// monitor app 集合 == route registry（celld-app 目标去重；sandbox 目标不投影）。
			expect(firstFrame.apps.map((application) => application.id).sort()).toEqual(
				[...new Set(store.routes.filter((route) => route.target.kind === "celld-app").map((route) => route.target.appName).filter(Boolean))].sort(),
			);
			// monitor 帧逐字段：domains 与路由一致（deployed/system 属 workspace 投影域，帧内语义不同不比较）。
			for (const application of firstFrame.apps) {
				const expected = store.routes.filter((route) => route.target.kind === "celld-app" && route.target.appName === application.id).map((route) => route.hostId).sort();
				expect([...application.domains].sort()).toEqual(expected);
			}
			expect(firstFrame.apps.find((application) => application.id === "admin")?.domains).toContain("admin");
			const seededProjection = firstFrame.sandboxes.find((application) => application.id === "notes");
			expect(seededProjection?.lifecycle).toBe("active");
			expect(firstText).not.toContain(TOKEN);
			// 代理请求（无 celld → 502）必须计入该应用指标并广播新帧（对位 JS broadcastMonitorSnapshot）。
			const proxied = await fetch(`http://127.0.0.1:${ingressPort}/`, { headers: { host: `admin.${BASE_HOST}` } });
			expect(proxied.status).toBe(502);
			// 广播帧与首帧同构：先过完整 monitorSnapshotSchema（Codex R2：
			// 只查指标字段会让缺 type/emittedAt/node/sandboxes 的退化帧漏网），再断言指标。
			const secondText = await frames.nextMatching(
				(text) => {
					const parsed = monitorSnapshotSchema.safeParse(JSON.parse(text));
					if (!parsed.success) return false;
					const admin = parsed.data.apps.find((application) => application.id === "admin");
					return Boolean(admin && admin.requests === 1 && admin.errors === 1);
				},
				5000,
			);
			expect(secondText).toBeTruthy();
			monitorSnapshotSchema.parse(JSON.parse(secondText));
			expect(secondText).not.toContain(TOKEN);
			socket.destroy();
		} finally {
			child.kill("SIGTERM");
			await new Promise((resolve) => child.once("exit", resolve));
			rmSync(directory, { recursive: true, force: true });
			if (stderr.includes("panicked")) throw new Error(`kernel panicked:\n${stderr}`);
		}
	}, 30_000);
});
