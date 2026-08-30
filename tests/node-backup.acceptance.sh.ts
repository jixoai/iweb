// 用户原始需求（2026-08-14）：在可丢弃 Linux 节点固化 previous-image 恢复验收（1.4/2.7）。
// 正交意图：明确 image digest；backup-node -> 破坏 volume -> restore-previous -> pinned old image -> owner 授权 api.<base> + 对象/route 恢复；secret 仅经 curl stdin config，不进入 argv/stdout。
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

// 运行前提（一次性 Linux 节点）：仓库已 checkout，docker + bun 可用，docker-compose.yml/.env 就绪。
// 通过环境变量注入（不进入 argv）：
//   IWEB_CURRENT_IMAGE   当前节点镜像（显式 digest）
//   IWEB_PREVIOUS_IMAGE  要回滚到的 pinned 旧镜像（显式 digest）
//   IWEB_OWNER_KEY       可选；缺省读 .env 的 IWEB_API_TOKEN
//   IWEB_BASE_HOST       可选；缺省读 .env 的 IWEB_BASE_HOST

// Contributor verification (no Linux): IWEB_ACCEPTANCE_PLAN=1 prints the exact
// operator evidence contract — phases, command shapes, expected observables,
// and the secret-handling rule (owner key only via curl --config stdin) —
// without touching any host. This mode never claims host acceptance.
if (process.env.IWEB_ACCEPTANCE_PLAN === "1") {
	process.stdout.write(JSON.stringify({
		mode: "plan",
		hostAcceptance: "NOT claimed by this mode",
		phases: {
			backup: { command: "bun scripts/node-backup.bun.ts backup", expected: "consistent snapshot of MinIO + celld + Kernel state, 0600/0700 artifacts" },
			mutate: { expected: "workspace object + route count changed on the disposable volume" },
			restorePrevious: { env: "IWEB_PREVIOUS_IMAGE=<explicit digest>", expected: "current node stopped first; old and new celld never share the fleet bucket; staged tree verified before atomic replace" },
			verify: { probes: ["GET https://api.<base>/v1/status with owner key -> 200", "workspace object restored byte-equal", "route count equal to pre-mutation"], secretRule: "owner key passes to curl --config via stdin only; never argv/stdout/evidence" },
		},
	}, null, 2) + "\n");
	process.exit(0);
}
const currentImage = (process.env.IWEB_CURRENT_IMAGE ?? "").trim();
const previousImage = (process.env.IWEB_PREVIOUS_IMAGE ?? "").trim();
const baseHost = (process.env.IWEB_BASE_HOST ?? readEnvValue(".env", "IWEB_BASE_HOST")).trim();
const port = (process.env.IWEB_HTTP_PORT ?? readEnvValue(".env", "IWEB_HTTP_PORT") ?? "9010").trim();
const ownerKey = (process.env.IWEB_OWNER_KEY ?? readEnvValue(".env", "IWEB_API_TOKEN")).trim();

function assert(condition: unknown, message: string): asserts condition {
	if (!condition) throw new Error(message);
}

function readEnvValue(path: string, key: string): string {
	try {
		for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
			const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
			if (match && match[1] === key) return match[2].replace(/^["']|["']$/g, "");
		}
	} catch {
		// .env may be absent; the caller must then pass the value via environment.
	}
	return "";
}

function run(command: string, args: readonly string[], options: { input?: string; env?: NodeJS.ProcessEnv } = {}): string {
	return execFileSync(command, [...args], { encoding: "utf8", stdio: "pipe", input: options.input, env: options.env ?? process.env });
}

function runQuiet(command: string, args: readonly string[], options: { env?: NodeJS.ProcessEnv } = {}): void {
	try {
		execFileSync(command, [...args], { stdio: ["ignore", "pipe", "pipe"], env: options.env ?? process.env });
	} catch {
		// best-effort cleanup / idempotent commands; the caller asserts where it matters.
	}
}

function sleep(milliseconds: number): void {
	execFileSync("sleep", [String(milliseconds / 1000)]);
}

function composeArgs(): string[] {
	return ["-f", "docker-compose.yml", "--project-name", projectName];
}

// owner key 只经 curl --config stdin 进入，绝不进入 argv 或 stdout。
function curlWithKey(host: string, method: string, path: string, body?: unknown): string {
	const config = 'header = "Authorization: Bearer ' + ownerKey.replace(/["\\\r\n]/g, "") + '"\n';
	const args = ["--config", "-", "--silent", "--show-error", "--fail", "--max-time", "20", "-X", method, "-H", "Host: api." + host, "-H", "Content-Type: application/json"];
	if (body !== undefined) args.push("--data", JSON.stringify(body));
	args.push("http://127.0.0.1:" + port + path);
	return run("curl", args, { input: config });
}

function waitForApi(): void {
	for (let attempt = 0; attempt < 90; attempt += 1) {
		try {
			curlWithKey(baseHost, "GET", "/v1/status");
			return;
		} catch {
			sleep(500);
		}
	}
	throw new Error("api.<base> did not become ready");
}

assert(currentImage, "IWEB_CURRENT_IMAGE is required (explicit digest)");
assert(previousImage, "IWEB_PREVIOUS_IMAGE is required (explicit digest)");
assert(ownerKey, "owner key is required via IWEB_OWNER_KEY or .env IWEB_API_TOKEN");
assert(baseHost, "base host is required via IWEB_BASE_HOST or .env IWEB_BASE_HOST");

const suffix = randomUUID().slice(0, 8);
const projectName = "iweb-backup-accept-" + suffix;
const marker = "accept-marker-" + suffix;
const workspacePath = "accept/" + marker + ".txt";
const backupRoot = mkdtempSync(join(tmpdir(), "iweb-backup-"));
let started = false;

try {
	// 1. 启动当前节点（明确 image digest）
	runQuiet("docker", ["compose", ...composeArgs(), "up", "--detach"], { env: { ...process.env, IWEB_IMAGE: currentImage } });
	started = true;
	waitForApi();

	// 2. 写入可辨识的 workspace 对象与 route
	curlWithKey(baseHost, "PUT", "/v1/workspace/file", { path: workspacePath, content: marker });
	curlWithKey(baseHost, "POST", "/v1/routes", { hostId: marker + ".app", appName: "notes" });
	const routesBefore = (JSON.parse(curlWithKey(baseHost, "GET", "/v1/routes")) as { routes: unknown[] }).routes.length;

	// 3. 停机一致备份（stop -> readonly helper backup -> start）
	run("bun", ["scripts/node-backup.bun.ts", "backup-node"], { env: { ...process.env, COMPOSE_PROJECT_NAME: projectName, IWEB_BACKUP_OUTPUT: backupRoot } });
	const latest = JSON.parse(readFileSync(join(backupRoot, "latest.json"), "utf8")) as { backupId: string };
	const backupDir = join(backupRoot, latest.backupId);
	const manifest = JSON.parse(readFileSync(join(backupDir, "manifest.json"), "utf8")) as { sources: { label: string; fileCount: number; sha256: string }[] };

	// 4. 破坏 volume
	runQuiet("docker", ["run", "--rm", "--mount", "type=volume,source=" + projectName + "_iweb-data,target=/data", "alpine", "sh", "-c", "rm -rf /data/minio /data/celld /data/kernel"]);

	// 5. 恢复到 pinned previous image
	run("bun", ["scripts/node-backup.bun.ts", "restore-previous"], { env: { ...process.env, COMPOSE_PROJECT_NAME: projectName, IWEB_PREVIOUS_IMAGE: previousImage, IWEB_BACKUP_DIR: backupDir, IWEB_BASE_HOST: baseHost } });

	// 6. 验证：启动的是 pinned previous image，api.<base> + 对象 + route 恢复
	waitForApi();
	const containerId = run("docker", ["compose", ...composeArgs(), "ps", "-q"]).trim();
	assert(containerId.length > 0, "compose project has no running container");
	const runningImage = run("docker", ["inspect", "--format", "{{.Config.Image}}", containerId]).trim();
	assert(runningImage === previousImage, "node is not running the pinned previous image: " + runningImage);

	const status = JSON.parse(curlWithKey(baseHost, "GET", "/v1/status")) as { baseHost?: string; applicationPublication?: unknown; wasmPublication?: { enabled?: boolean } };
	assert(status.baseHost === baseHost, "status belongs to another node");
	assert(status.applicationPublication === undefined, "celld applicationPublication key unexpectedly present after restore");
	assert(status.wasmPublication?.enabled === false, "wasm publication is unexpectedly enabled after restore");

	const file = JSON.parse(curlWithKey(baseHost, "GET", "/v1/workspace/file?path=" + encodeURIComponent(workspacePath))) as { content?: string };
	assert(file.content === marker, "workspace object content did not recover");

	const routesAfter = (JSON.parse(curlWithKey(baseHost, "GET", "/v1/routes")) as { routes: unknown[] }).routes.length;
	assert(routesAfter === routesBefore, "route count did not recover: " + routesBefore + " -> " + routesAfter);

	process.stdout.write(JSON.stringify({
		projectName,
		currentImage,
		previousImage,
		backup: { id: latest.backupId, sources: manifest.sources.map((source) => ({ label: source.label, fileCount: source.fileCount, sha256: source.sha256 })) },
		recovered: { api: status.baseHost, wasmPublicationEnabled: status.wasmPublication?.enabled, workspaceObject: true, routeCount: routesAfter, runningImage },
	}) + "\n");
} finally {
	if (started) runQuiet("docker", ["compose", ...composeArgs(), "down", "-v"]);
	rmSync(backupRoot, { recursive: true, force: true });
}

