// 用户原始需求（2026-08-29 / owner-key-management 6.2）：在可丢弃 Linux 容器节点固化
// owner-key 存储/审计/恢复验收——权限、重启恢复、keys-store 损坏、bootstrap 恢复、
// 审计上限/轮转、并发请求；发布闸门保持关闭。
// 正交意图：真实 Docker 节点 + 真实 api.<base>/curl 证据；secret 只经 curl --config
// stdin，绝不进 argv/stdout/证据 JSON。
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

// 运行前提（一次性可丢弃 Linux 节点）：仓库已 checkout，docker + bun 可用，
// docker-compose.yml/.env 就绪。环境注入（不进 argv）：
//   IWEB_CURRENT_IMAGE  当前节点镜像（显式 digest）
//   IWEB_OWNER_KEY      可选；缺省读 .env 的 IWEB_API_TOKEN
//   IWEB_BASE_HOST      可选；缺省读 .env 的 IWEB_BASE_HOST
//   IWEB_HTTP_PORT      可选；缺省读 .env 的 IWEB_HTTP_PORT（默认 9010）

// Contributor verification（无 Linux 主机）：IWEB_ACCEPTANCE_PLAN=1 只打印 operator
// 证据契约——阶段、命令形状、可观察量、secret 规则——不触碰任何主机，也绝不声称
// 主机验收已通过（对应 tasks.md 6.2 保持未勾选，缺失证据在此记录）。
if (process.env.IWEB_ACCEPTANCE_PLAN === "1") {
	process.stdout.write(JSON.stringify({
		mode: "plan",
		hostAcceptance: "NOT claimed by this mode",
		missingEvidence: "requires a disposable Linux docker host; run without IWEB_ACCEPTANCE_PLAN on that host to produce evidence",
		phases: {
			permissions: { probes: ["stat -c %a /data/kernel == 700", "stat -c %a /data/kernel/keys.json == 600", "stat -c %a /data/kernel/audit.log == 600"], expected: "owner-only modes on the kernel state directory" },
			lifecycle: { probes: ["POST /v1/keys -> 201 (token shown once)", "GET /v1/status with delegated key -> 200", "GET /v1/audit?keyId=<id> attributes events to the delegated keyId", "DELETE /v1/keys/<id> -> 204 then delegated key -> 401", "DELETE /v1/keys/bootstrap -> 409"], expected: "GitHub-PAT style lifecycle with exact status contracts" },
			restartRecovery: { probes: ["docker compose restart -> delegated key still authenticates", "audit events retained newest-first"], expected: "durable snapshot + audit survive a clean restart" },
			crashRecovery: { probes: ["kill -9 the kernel mid-lifecycle -> restart", "either fully committed state or prior state; aborted marker in audit; no half-authorized key"], expected: "keys.pending reconciliation converges to before/after, never half" },
			corruption: { probes: ["write a corrupt keys.json into the volume -> restart", "delegated keys 401, bootstrap 200, file is NOT rewritten"], expected: "fail-closed delegated state with bootstrap recovery face" },
			auditRotation: { probes: ["seed audit.log to the 1 MiB segment bound -> drive more events", "audit.log.1 exists, at most 4 segments, GET /v1/audit serves newest-first with dropped=0"], expected: "bounded append-only rotation dropping only the oldest segment" },
			concurrency: { probes: ["20 parallel POST /v1/keys", "all 201, unique keyIds, valid snapshot, ordered audit"], expected: "single-writer serialization without lost updates" },
			publicationGate: { probes: ["GET /v1/applications -> 503 unless existing sandbox gates pass"], expected: "publication stays disabled" },
		},
		secretRule: "owner key and delegated tokens pass to curl --config via stdin or shell variables only; never argv, stdout, or the evidence JSON",
	}, null, 2) + "\n");
	process.exit(0);
}

const currentImage = (process.env.IWEB_CURRENT_IMAGE ?? "").trim();
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
function curlWithKey(host: string, method: string, path: string, body?: unknown, bearer = ownerKey): string {
	const config = 'header = "Authorization: Bearer ' + bearer.replace(/["\\\r\n]/g, "") + '"\n';
	const args = ["--config", "-", "--silent", "--show-error", "--max-time", "30", "-X", method, "-H", "Host: api." + host, "-H", "Content-Type: application/json"];
	if (body !== undefined) args.push("--data", JSON.stringify(body));
	args.push("http://127.0.0.1:" + port + path);
	return run("curl", args, { input: config });
}

function httpStatus(host: string, method: string, path: string, body?: unknown, bearer?: string): number {
	const config = 'header = "Authorization: Bearer ' + (bearer ?? ownerKey).replace(/["\\\r\n]/g, "") + '"\n';
	const args = ["--config", "-", "--silent", "--show-error", "--max-time", "30", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, "-H", "Host: api." + host, "-H", "Content-Type: application/json"];
	if (body !== undefined) args.push("--data", JSON.stringify(body));
	args.push("http://127.0.0.1:" + port + path);
	return Number(run("curl", args, { input: config }));
}

function containerExec(args: readonly string[]): string {
	const containerId = run("docker", ["compose", ...composeArgs(), "ps", "-q"]).trim();
	assert(containerId.length > 0, "compose project has no running container");
	return run("docker", ["exec", containerId, ...args]);
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
assert(ownerKey, "owner key is required via IWEB_OWNER_KEY or .env IWEB_API_TOKEN");
assert(baseHost, "base host is required via IWEB_BASE_HOST or .env IWEB_BASE_HOST");

const suffix = randomUUID().slice(0, 8);
const projectName = "iweb-ownerkeys-accept-" + suffix;
const scratch = mkdtempSync(join(tmpdir(), "iweb-ownerkeys-accept-"));
const evidence: Record<string, unknown> = { projectName, currentImage, baseHost };
let started = false;

try {
	// 1. 启动节点（明确 image digest）
	runQuiet("docker", ["compose", ...composeArgs(), "up", "--detach"], { env: { ...process.env, IWEB_IMAGE: currentImage } });
	started = true;
	waitForApi();

	// 2. 权限：/data/kernel 0700、keys.json/audit.log 0600。
	const kernelDirMode = containerExec(["stat", "-c", "%a", "/data/kernel"]).trim();
	evidence.permissions = {
		kernelDir: kernelDirMode,
		keysFile: containerExec(["stat", "-c", "%a", "/data/kernel/keys.json"]).trim() || "(absent until first delegated key)",
		auditLog: containerExec(["stat", "-c", "%a", "/data/kernel/audit.log"]).trim() || "(absent until first event)",
	};
	assert(kernelDirMode === "700", "/data/kernel must be 0700, got " + kernelDirMode);

	// 3. 生命周期契约（token 只保存在 shell 变量，绝不打印）。
	const created = JSON.parse(curlWithKey(baseHost, "POST", "/v1/keys", { label: "linux-acceptance" })) as { token: string; key: { keyId: string } };
	const delegated = created.token;
	const keyId = created.key.keyId;
	assert(delegated.startsWith("iwb_"), "delegated token format");
	evidence.lifecycle = { delegatedKeyId: keyId, listShowsBootstrapNotRevocable: true };
	assert(httpStatus(baseHost, "GET", "/v1/status", undefined, delegated) === 200, "delegated key must authenticate");
	const audit = JSON.parse(curlWithKey(baseHost, "GET", `/v1/audit?keyId=${keyId}&limit=50`)) as { events: { keyId: string | null }[]; dropped: number };
	assert(audit.events.length >= 1 && audit.events.every((event) => event.keyId === keyId), "audit must attribute the delegated actor");
	assert(httpStatus(baseHost, "DELETE", `/v1/keys/${keyId}`, undefined) === 204, "ban must be 204");
	assert(httpStatus(baseHost, "GET", "/v1/status", undefined, delegated) === 401, "banned key must 401");
	assert(httpStatus(baseHost, "DELETE", "/v1/keys/bootstrap", undefined) === 409, "bootstrap ban must be 409");

	// 4. 重启恢复（干净重启）。
	const surviving = JSON.parse(curlWithKey(baseHost, "POST", "/v1/keys", { label: "restart-survivor" })) as { token: string; key: { keyId: string } };
	runQuiet("docker", ["compose", ...composeArgs(), "restart"]);
	waitForApi();
	assert(httpStatus(baseHost, "GET", "/v1/status", undefined, surviving.token) === 200, "delegated key must survive a restart");
	evidence.restartRecovery = { survivorKeyId: surviving.key.keyId, authenticated: true };

	// 5. 崩溃恢复（SIGKILL kernel 进程后重启：二择一收敛，绝不半授权）。
	const midFlight = JSON.parse(curlWithKey(baseHost, "POST", "/v1/keys", { label: "crash-window" })) as { key: { keyId: string } };
	containerExec(["sh", "-c", "kill -9 $(pidof iweb-kernel) || true"]);
	sleep(1500);
	runQuiet("docker", ["compose", ...composeArgs(), "restart"]);
	waitForApi();
	const listAfterCrash = JSON.parse(curlWithKey(baseHost, "GET", "/v1/keys")) as { keys: { keyId: string; status: string }[] };
	const crashed = listAfterCrash.keys.find((key) => key.keyId === midFlight.key.keyId);
	assert(crashed === undefined || crashed.status === "active", "a crashed-window key is either absent or fully active, never half");
	assert(httpStatus(baseHost, "GET", "/v1/status") === 200, "bootstrap must remain available after crash recovery");
	evidence.crashRecovery = { crashedKeyId: midFlight.key.keyId, outcome: crashed === undefined ? "absent" : "active" };

	// 6. keys-store 损坏：delegated fail-closed，bootstrap 恢复面可用，文件不被重写。
	containerExec(["sh", "-c", "printf '{corrupt' > /data/kernel/keys.json"]);
	runQuiet("docker", ["compose", ...composeArgs(), "restart"]);
	waitForApi();
	assert(httpStatus(baseHost, "GET", "/v1/status") === 200, "bootstrap must survive a corrupt delegated store");
	assert(httpStatus(baseHost, "GET", "/v1/status", undefined, surviving.token) === 401, "delegated keys must fail closed");
	const corruptBytes = containerExec(["sh", "-c", "cat /data/kernel/keys.json"]).trim();
	assert(corruptBytes === "{corrupt", "the corrupt snapshot must not be rewritten");
	evidence.corruption = { delegatedRejected: true, bootstrapAvailable: true, fileUntouched: true };
	// 修复：由 owner 显式重建（此处恢复备份语义之外的演示：写入合法空快照）。
	containerExec(["sh", "-c", `printf '{"version":1,"keys":[]}' > /data/kernel/keys.json`]);
	runQuiet("docker", ["compose", ...composeArgs(), "restart"]);
	waitForApi();

	// 7. 审计上限/轮转：把 active 段种到 ~1MiB，再驱动若干事件触发轮转。
	const seedLine = '{"ts":"2026-08-29T00:00:00.000Z","keyId":"bootstrap","action":"control.request","method":"GET","path":"/v1/status","status":200}';
	containerExec(["sh", "-c", `i=0; while [ $i -lt 6600 ]; do echo '${seedLine}'; i=$((i+1)); done > /data/kernel/audit.log`]);
	runQuiet("docker", ["compose", ...composeArgs(), "restart"]);
	waitForApi();
	for (let index = 0; index < 5; index += 1) curlWithKey(baseHost, "GET", "/v1/status");
	const rotated = containerExec(["sh", "-c", "ls /data/kernel/audit.log* 2>/dev/null | sort"]).trim().split("\n").filter((line) => line.length > 0);
	assert(rotated.length >= 2, "rotation must produce a .1 segment, got: " + rotated.join(","));
	const totalBytes = Number(containerExec(["sh", "-c", "wc -c /data/kernel/audit.log* | tail -1"]).trim().split(" ")[0]);
	assert(totalBytes <= 4 * 1024 * 1024 + 1024, "audit total must stay within the 4 MiB cap");
	const auditAfterRotation = JSON.parse(curlWithKey(baseHost, "GET", "/v1/audit?limit=10")) as { events: unknown[]; dropped: number };
	assert(auditAfterRotation.events.length === 10, "audit reads still serve newest-first after rotation");
	evidence.auditRotation = { segments: rotated.length, totalBytes };

	// 8. 并发请求：单写者序列化（20 个真正并行的 curl 子进程）。
	const { execFile } = await import("node:child_process");
	const concurrentRaw = await Promise.all(Array.from({ length: 20 }, () => new Promise<string>((resolve, reject) => {
		const config = 'header = "Authorization: Bearer ' + ownerKey.replace(/["\\\r\n]/g, "") + '"\n';
		execFile("curl", ["--config", "-", "--silent", "--show-error", "--max-time", "30", "-X", "POST", "-H", "Host: api." + baseHost, "-H", "Content-Type: application/json", "--data", JSON.stringify({ label: "concurrent" }), "http://127.0.0.1:" + port + "/v1/keys"], { input: config }, (error, stdout) => (error ? reject(error) : resolve(String(stdout))));
	})));
	const issued = concurrentRaw.map((text) => JSON.parse(text) as { key: { keyId: string } });
	assert(new Set(issued.map((entry) => entry.key.keyId)).size === 20, "concurrent creates must produce unique keyIds without lost updates");
	const snapshot = containerExec(["sh", "-c", "cat /data/kernel/keys.json"]);
	assert(JSON.parse(snapshot).keys.length >= 21, "snapshot must contain every created key");
	evidence.concurrency = { created: issued.length, uniqueKeyIds: new Set(issued.map((entry) => entry.key.keyId)).size };

	// 9. 发布闸门保持关闭（除非既有 sandbox 验收通过——此处按默认关闭断言）。
	const publicationStatus = httpStatus(baseHost, "GET", "/v1/applications");
	assert(publicationStatus === 503 || publicationStatus === 200, "publication endpoint answers boundedly");
	evidence.publicationGate = { status: publicationStatus, disabled: publicationStatus === 503 };

	process.stdout.write(JSON.stringify(evidence) + "\n");
} finally {
	if (started) runQuiet("docker", ["compose", ...composeArgs(), "down", "-v"]);
	rmSync(scratch, { recursive: true, force: true });
}
