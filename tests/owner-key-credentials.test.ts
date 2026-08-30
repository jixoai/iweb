// 任务 1.3（owner-key-management）：credential-scan fixtures——证明 bootstrap/委托 key
// 明文、bearer 头、monitor ticket 与部署提示词文本从不进入 日志、workspace 对象、
// 应用包、浏览器资产或测试输出。做法：真实 Rust Kernel 子进程跑一轮完整 owner-key
// 流量（创建/401/票据/审计/工作区写入），把产生的所有可扫描表面交给
// scripts/credential-scan-run.bun.ts（fail-closed 扫描器）以真实 needle 验证。
import { describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE_HOST = "ownercred.test";
const BOOTSTRAP = "bootstrap-owner-token-000";
const PORT = 7070;
const REPO = join(import.meta.dir, "..");

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

const command = (process.env.KERNEL_TEST_COMMAND ?? "").split(" ").filter(Boolean);
const isRustKernel = command.length > 0 && !command[0].endsWith("node");

describe.skipIf(!isRustKernel)("owner-key credential surfaces stay clean (1.3, rust kernel only)", () => {
	test("plaintext keys, bearer headers, tickets, and prompt text never reach scannable surfaces", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-owner-cred-"));
		const workspaceRoot = join(directory, "objects");
		const shimDirectory = join(directory, "bin");
		mkdirSync(workspaceRoot, { recursive: true });
		mkdirSync(shimDirectory, { recursive: true });
		const listingPath = join(shimDirectory, "listing.ndjson");
		writeFileSync(listingPath, "");
		// mc shim：ls 投影 + cp 把“对象内容”落盘（对象存储表面）——凭证若被写入
		// workspace 会被这里的 objects.log 捕获。
		writeFileSync(join(shimDirectory, "mc"), `#!/bin/sh
if [ "$1" = "ls" ]; then cat '${listingPath}'; exit 0; fi
if [ "$1" = "cp" ]; then cat "$2" >> '${join(workspaceRoot, "objects.log")}'; printf '%s\\n' "{\\"status\\":\\"success\\",\\"type\\":\\"file\\",\\"key\\":\\"$(basename "$3")\\",\\"size\\":1,\\"lastModified\\":\\"2099-01-01T00:00:00.000Z\\"}" >> '${listingPath}'; exit 0; fi
exit 0
`);
		chmodSync(join(shimDirectory, "mc"), 0o755);
		const routes = { version: 1, routes: [
			{ hostId: "admin", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
		] };
		writeFileSync(join(directory, "routes.json"), `${JSON.stringify(routes)}\n`);

		const child = spawn(command[0], command.slice(1), {
			env: {
				...process.env,
				PATH: `${shimDirectory}:${process.env.PATH ?? ""}`,
				IWEB_BASE_HOST: BASE_HOST,
				IWEB_API_TOKEN: BOOTSTRAP,
				IWEB_HTTP_PORT: "38080",
				IWEB_ROUTES_FILE: join(directory, "routes.json"),
				IWEB_KEYS_FILE: join(directory, "keys.json"),
				IWEB_WORKSPACE_OBJECT: "local/iweb-workspace",
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdio = "";
		let stopped = false;
		child.stdout.on("data", (chunk) => { stdio += String(chunk); });
		child.stderr.on("data", (chunk) => { stdio += String(chunk); });

		const api = (path: string, init: RequestInit = {}) =>
			fetch(`http://127.0.0.1:${PORT}${path}`, { ...init, headers: { host: `api.${BASE_HOST}`, ...(init.headers ?? {}) } });

		try {
			await waitHealthy(15_000);

			// 完整 owner-key 流量：委托 key 创建 → 使用 → 401 拒绝 → monitor 票据 →
			// 审计读取 → 工作区对象写入（部署提示词只在内存构造，绝不写入任何表面）。
			const createResponse = await api("/v1/keys", { method: "POST", headers: { authorization: `Bearer ${BOOTSTRAP}`, "content-type": "application/json" }, body: JSON.stringify({ label: "credential-scan-agent" }) });
			expect(createResponse.status).toBe(201);
			const created = (await createResponse.json()) as { token: string; key: { keyId: string } };
			const delegated = created.token;

			expect((await api("/v1/status", { headers: { authorization: `Bearer ${delegated}` } })).status).toBe(200);
			expect((await api("/v1/status", { headers: { authorization: "Bearer iwb_00000000_" + "w".repeat(43) } })).status).toBe(401);
			expect((await api("/v1/status")).status).toBe(401);

			const ticketResponse = await api("/v1/monitor/session", { method: "POST", headers: { authorization: `Bearer ${delegated}` } });
			expect(ticketResponse.status).toBe(201);
			const ticket = ((await ticketResponse.json()) as { ticket: string }).ticket;

			const auditResponse = await api("/v1/audit?limit=100", { headers: { authorization: `Bearer ${BOOTSTRAP}` } });
			expect(auditResponse.status).toBe(200);
			const auditBody = await auditResponse.json();
			const keysResponse = await api("/v1/keys", { headers: { authorization: `Bearer ${BOOTSTRAP}` } });
			const keysBody = await keysResponse.json();

			// 工作区写入：内容是普通文件（不是凭证）；提示词永不写入。
			const workspaceWrite = await api("/v1/workspace/file", { method: "PUT", headers: { authorization: `Bearer ${delegated}`, "content-type": "application/json" }, body: JSON.stringify({ path: "deploy-notes/readme.md", content: "# deployment notes\nnothing sensitive here\n" }) });
			expect([200, 201]).toContain(workspaceWrite.status);

			// 内存中的部署提示词（与 Admin key-manager 同构）：只构造、只比较，绝不落盘。
			const deploymentPrompt = ["你是 iweb 个人节点上的部署代理。", "- 密钥： " + delegated, "- 端点： https://mcp." + BASE_HOST + "/mcp"].join("\n");

			// 测试输出表面：本测试实际产生并可能打印的载荷（响应体序列化）。
			const testOutput = JSON.stringify({ keys: keysBody, audit: auditBody }, null, 2);
			writeFileSync(join(directory, "test-output.json"), testOutput + "\n");
			expect(testOutput).not.toContain(delegated);
			expect(testOutput).not.toContain(BOOTSTRAP);

			// 快照表面：hash 落盘（sha256），明文绝不落盘。
			const snapshotText = readFileSync(join(directory, "keys.json"), "utf8");
			expect(snapshotText).toContain("secretHash");
			expect(snapshotText).not.toContain(delegated);
			expect(snapshotText).not.toContain(BOOTSTRAP);
			// 审计表面：无 hash、无票据、无 bearer。
			const auditLogText = readFileSync(join(directory, "audit.log"), "utf8");
			expect(auditLogText).not.toContain("secretHash");
			expect(auditLogText).not.toContain(ticket);
			expect(auditLogText).not.toContain(delegated);

			// 停机后：kernel stdio 也扫描（日志表面）。
			child.kill("SIGTERM");
			await new Promise((resolve) => child.once("exit", resolve));
			stopped = true;
			writeFileSync(join(directory, "kernel-stdio.log"), stdio);
			expect(stdio).not.toContain(delegated);
			expect(stdio).not.toContain(ticket);

			// needle 文件：真实 bootstrap token、委托 token、票据（runner 自动把
			// 该文件从所有扫描表面排除；提示词含 token，token needle 即覆盖）。
			const secretsPath = join(directory, "needles.txt");
			writeFileSync(secretsPath, [BOOTSTRAP, delegated, ticket].join("\n") + "\n");

			const locations = [
				"log:" + join(directory, "kernel-stdio.log"),
				"log:" + join(directory, "keys.json"),
				"log:" + join(directory, "audit.log"),
				"object-store:" + workspaceRoot,
				"package:" + join(REPO, "apps", "workers", "mcp", "src"),
				"admin-assets:" + join(REPO, "apps", "admin-console", "build"),
				"test-output:" + join(directory, "test-output.json"),
			];
			// 与 credential-scan-run.test.ts 同约定：Bun.spawnSync（exitCode 语义）。
			const scan = Bun.spawnSync(["bun", join(REPO, "scripts", "credential-scan-run.bun.ts"), "--secrets-file", secretsPath, ...locations], {
				cwd: REPO,
				stdout: "pipe",
				stderr: "pipe",
			});
			const stdout = scan.stdout.toString("utf8");
			if (scan.exitCode !== 0) console.error("credential scan report:\n" + stdout);
			expect(scan.exitCode).toBe(0);
			const report = JSON.parse(stdout);
			expect(report.clean).toBe(true);
			expect(report.failures).toEqual([]);
			expect(report.findings).toEqual([]);
			expect(report.patternFindings).toEqual([]);
			expect(report.secretsProvided).toBe(3);
			// 每个声明的 kind 都真实覆盖（fail-closed 扫描器自身的保证）。
			for (const kind of ["log", "object-store", "package", "admin-assets", "test-output"]) {
				expect(report.kindsCovered[kind], kind + " must be covered").toBeGreaterThanOrEqual(1);
			}
			// 报告本身也绝不回显 secret。
			expect(stdout).not.toContain(delegated);
			expect(stdout).not.toContain(BOOTSTRAP);
			expect(stdout).not.toContain(ticket);
			// 提示词文本未被写入任何扫描表面（token needle 已保证；再直接排除一次）。
			expect(stdio).not.toContain(deploymentPrompt);
			expect(auditLogText).not.toContain(deploymentPrompt);
			expect(snapshotText).not.toContain(deploymentPrompt);
		} finally {
			if (!stopped && child.exitCode === null) {
				child.kill("SIGTERM");
				await new Promise((resolve) => child.once("exit", resolve));
			}
			rmSync(directory, { recursive: true, force: true });
		}
	}, 45_000);
});
