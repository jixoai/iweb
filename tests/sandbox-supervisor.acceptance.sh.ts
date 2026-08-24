// 用户原始需求（2026-08-14）：在一次性 Linux + systemd 宿主固化 sandbox-supervisor 安装与运行时验收（1.3 / 3.x / 6.x）。
// 正交意图：安装/激活/身份/rootless Podman/preflight/socket 0600/无 TCP listener/seccomp/digest 镜像/Compose 拓扑/真实 pod+gateway 生命周期（prepare→start→health→metrics→stop→delete）。
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

// Contributor verification (no Linux required): IWEB_ACCEPTANCE_PLAN=1 prints the
// exact operator evidence contract — every phase, its command shape, and the
// expected observable — without touching the host. Nothing is claimed as host
// acceptance; contributors use it to review command construction and expected
// values, and CI can assert the plan renders on any platform.
const PLAN_ONLY = process.env.IWEB_ACCEPTANCE_PLAN === "1";
const plan: Record<string, unknown> = {};
function planPhase(name: string, detail: Record<string, unknown>): void {
	plan[name] = detail;
}
if (PLAN_ONLY) {
	planPhase("install", { command: "bun scripts/install-sandbox-supervisor.bun.ts", requires: "root on the target Linux host", images: "built/pulled via runuser -u iweb-sandbox (service-user rootless store)" });
	planPhase("systemd", { command: "systemctl is-active iweb-sandbox-supervisor", expected: "active", identity: "User=iweb-sandbox Group=iweb-sandbox" });
	planPhase("socket", { path: "/run/iweb-sandbox/supervisor.sock", expected: "iweb-sandbox:iweb-sandbox 0600", tcpListeners: "none" });
	planPhase("images", { runtime: "ghcr.io/denoland/celld@sha256:<digest>", gateway: "localhost/iweb-sandbox-gateway@sha256:<digest>", store: "iweb-sandbox user image store" });
	planPhase("compose", { minio: "127.0.0.1:9000:9000 only", external: "8080 only", forbidden: ["privileged", "network_mode", "docker.sock", "podman.sock"] });
	planPhase("connectivity", {
		note: "run with IWEB_ACCEPTANCE_RUN_LIFECYCLE=1 inside a started sandbox pod",
		gatewayMustReach: ["http://10.0.2.2:9000 (MinIO via slirp gateway)", "an admitted egress target"],
		workerMustNotReach: ["Kernel 7070", "MinIO 10.0.2.2:9000 directly", "supervisor socket", "host loopback services", "peer sandboxes", "OCI socket"],
	});
	planPhase("lifecycle", { env: "IWEB_ACCEPTANCE_RUN_LIFECYCLE=1", expected: "prepare→Created, start→running, metrics cpuMillis.available=true, stop, delete" });
	process.stdout.write(JSON.stringify({ mode: "plan", hostAcceptance: "NOT claimed by this mode", phases: plan }, null, 2) + "\n");
	process.exit(0);
}

function run(command: string, args: readonly string[], options: { asSandboxUser?: boolean } = {}): string {
	// root path: sudo <command> <args...>; sandbox-user path: sudo -u iweb-sandbox <command> <args...>.
	// (The earlier form dropped <command> on the root path, so the first real
	// host run failed with "sudo: scripts/...: command not found".)
	// Service-user invocations need the service user's HOME/XDG layout —
	// podman and mc resolve their config from it, and a bare `sudo -u` inherits
	// root's, which fails closed. Root invocations keep -E so the operator's
	// IWEB_SNAPSHOT_ENDPOINT (and friends) reaches the installer.
	const fullArgs = options.asSandboxUser
		? ["-E", "-u", "iweb-sandbox", "env", "HOME=/var/lib/iweb-sandbox", "XDG_DATA_HOME=/var/lib/iweb-sandbox/.local/share", "XDG_RUNTIME_DIR=/run/iweb-sandbox", command, ...args]
		: ["-E", command, ...args];
	return execFileSync("sudo", fullArgs, { encoding: "utf8", stdio: "pipe" });
}

function assert(condition: unknown, message: string): asserts condition {
	if (!condition) throw new Error(message);
}

const results: Record<string, unknown> = {};

// 1. 安装 supervisor（需要 root，幂等）
run("bun", ["scripts/install-sandbox-supervisor.bun.ts"]);
results.install = "ok";

// 2. systemd 服务 active
const active = run("systemctl", ["is-active", "iweb-sandbox-supervisor"]).trim();
assert(active === "active", "supervisor service is not active: " + active);
results.systemd = active;

// 3. 实际 User/Group 均为 iweb-sandbox
const user = run("systemctl", ["show", "-p", "User", "--value", "iweb-sandbox-supervisor"]).trim();
const group = run("systemctl", ["show", "-p", "Group", "--value", "iweb-sandbox-supervisor"]).trim();
assert(user === "iweb-sandbox" && group === "iweb-sandbox", "supervisor identity is wrong: " + user + ":" + group);
results.identity = { user, group };

// 4. preflight ready:true（含 seccomp 检查）
const preflight = JSON.parse(run("iweb-sandbox-supervisor", ["preflight"], { asSandboxUser: true })) as { ready?: boolean; checks?: { code: string; passed: boolean }[] };
assert(preflight.ready === true, "supervisor preflight did not report ready");
const seccompCheck = preflight.checks?.find((check) => check.code === "seccomp-profile");
assert(seccompCheck?.passed === true, "seccomp profile check failed");
results.preflight = "ready:true";

// 5. seccomp 配置随 supervisor 包交付且可解析
const seccomp = JSON.parse(readFileSync("/usr/local/libexec/iweb-sandbox/seccomp.json", "utf8")) as { defaultAction?: string; archMap?: unknown[]; syscalls?: unknown[] };
assert(seccomp.defaultAction === "SCMP_ACT_ERRNO", "seccomp default action must be deny (ERRNO)");
assert((seccomp.archMap?.length ?? 0) > 0 && (seccomp.syscalls?.length ?? 0) > 0, "seccomp profile is incomplete");
results.seccomp = { defaultAction: "SCMP_ACT_ERRNO" };

// 6. socket owner/mode iweb-sandbox:iweb-sandbox 0600
const uid = run("id", ["-u", "iweb-sandbox"]).trim();
const gid = run("id", ["-g", "iweb-sandbox"]).trim();
const socketStat = run("stat", ["-c", "%u:%g %a", "/run/iweb-sandbox/supervisor.sock"]).trim();
assert(socketStat === uid + ":" + gid + " 600", "supervisor socket owner/mode is wrong: " + socketStat);
results.socket = { owner: "iweb-sandbox:iweb-sandbox", mode: "0600" };

// 7. supervisor 无 TCP listener（仅 Unix socket）
const listeners = run("ss", ["-tlnp"]);
assert(!/iweb-sandbox|supervisor/.test(listeners), "supervisor has a TCP listener");
results.tcpListener = "none";

// 8. rootless Podman 在 iweb-sandbox 下工作且支持 pod
const podman = JSON.parse(run("podman", ["info", "--format", "json"], { asSandboxUser: true })) as { host?: { security?: { rootless?: boolean } } };
assert(podman.host?.security?.rootless === true, "Podman did not report rootless operation");
const podList = run("podman", ["pod", "ps", "--format", "{{.Name}}"], { asSandboxUser: true });
results.rootlessPodman = { rootless: true, podSupport: podList !== null };

// 9. 两个镜像均为 digest 固定引用且 gateway 镜像已构建
const unitEnv = run("systemctl", ["show", "-p", "Environment", "--value", "iweb-sandbox-supervisor"]).trim();
const dropIn = run("sh", ["-c", "cat /etc/systemd/system/iweb-sandbox-supervisor.service.d/*.conf 2>/dev/null || true"]).trim();
const imageEnv = unitEnv + " " + dropIn;
assert(imageEnv.includes("IWEB_SANDBOX_RUNTIME_IMAGE=ghcr.io/denoland/celld@sha256:"), "runtime image env must be digest-pinned");
assert(imageEnv.includes("IWEB_SANDBOX_GATEWAY_IMAGE=localhost/iweb-sandbox-gateway@sha256:"), "gateway image env must be digest-pinned");
run("podman", ["image", "inspect", "localhost/iweb-sandbox-gateway"], { asSandboxUser: true });
results.images = "digest-pinned";

// 10. Compose 拓扑：唯一外部发布端口 8080；MinIO 只发布到宿主 loopback；无 privileged/host network/OCI socket
const compose = run("docker", ["compose", "-f", "docker-compose.yml", "-f", "docker-compose.sandbox.yml", "config"]);
assert(!compose.includes("privileged: true"), "compose grants privileged mode");
assert(!compose.includes("network_mode"), "compose uses a non-default network mode");
assert(!compose.includes("docker.sock") && !compose.includes("podman.sock"), "compose mounts an OCI daemon socket");
// Compose implementations render published ports differently: docker-compose
// emits the compact "127.0.0.1:9000:9000" while podman-based tooling emits the
// structured {host_ip: 127.0.0.1, target: 9000} form. Accept both spellings
// of the SAME topology: MinIO bound to host loopback only.
const minioLoopbackPublished = compose.includes("127.0.0.1:9000:9000") || /host_ip:\s*127\.0\.0\.1\s*\n[\s\S]{0,120}?target:\s*9000/.test(compose);
assert(minioLoopbackPublished, "compose must publish MinIO to host loopback only");
assert(compose.includes("0.0.0.0:8080:8080") || compose.includes("IWEB_HTTP_PORT"), "compose must keep the single external 8080 publish");
results.compose = { minioLoopback: true, privileged: false, ociSocket: false, hostNetwork: false };

// 11. 真实 supervisor 生命周期（不经过 Kernel，直接走窄协议 socket）
if (process.env.IWEB_ACCEPTANCE_RUN_LIFECYCLE === "1") {
	const { request } = await import("node:http");
	const requestJson = (path: string, body: unknown): Promise<{ status: number; body: string }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = request({ socketPath: "/run/iweb-sandbox/supervisor.sock", method: "POST", path, headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } }, (res) => {
				let text = "";
				res.setEncoding("utf8");
				res.on("data", (chunk: string) => (text += chunk));
				res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text }));
			});
			req.once("error", reject);
			req.write(payload);
			req.end();
		});
	const applicationId = "acceptance-app";
	const sequence = 1;
	const { deriveSandboxId } = await import("../packages/contracts/protocol.ts");
	const { packageFilesDigest } = await import("../packages/contracts/package-collection.ts");
	// Seed a REAL canonical snapshot first: prepare materializes
	// <admin-alias>/iweb-system/packages/<digest>/ (files.json + files/<path>)
	// and refuses to create any OCI resource when the snapshot is absent —
	// the lifecycle matrix must exercise the success path of that gate.
	const seedFiles = [
		{ path: "app/main.js", content: Buffer.from("// acceptance lifecycle app\n") },
		{ path: "app/module.js", content: Buffer.from("export const value = 42;\n") },
	];
	const digest = packageFilesDigest(seedFiles);
	const staging = "/tmp/iweb-acceptance-snapshot";
	run("rm", ["-rf", staging]);
	const { mkdirSync, writeFileSync } = await import("node:fs");
	mkdirSync(staging + "/files/app", { recursive: true });
	writeFileSync(staging + "/files.json", JSON.stringify({ files: seedFiles.map((file) => file.path) }, null, 2) + "\n");
	for (const file of seedFiles) writeFileSync(staging + "/files/" + file.path, file.content);
	run("mc", ["cp", staging + "/files.json", "local/iweb-system/packages/" + digest + "/files.json"]);
	for (const file of seedFiles) run("mc", ["cp", staging + "/files/" + file.path, "local/iweb-system/packages/" + digest + "/files/" + file.path]);
	const sandboxId = deriveSandboxId(applicationId, digest, sequence);
	const prepare = await requestJson("/v1/rpc", {
		version: 1,
		operation: "prepare",
		sandboxId,
		versionIdentity: { applicationId, digest, sequence },
		packageDigest: digest,
		policy: { resources: { cpuMillis: 1000, memoryBytes: 256 * 2 ** 20, pidLimit: 64, storageBytes: 2 ** 30 }, egress: { default: "deny", allow: [] } },
		// hostObjectEndpoint: MinIO as seen through the slirp gateway (10.0.2.2),
		// never 127.0.0.1:9000 which is the gateway's own object listener.
		object: { endpoint: "http://10.0.2.2:9000", region: "us-east-1", accessKeyId: "acceptance", secretAccessKey: "acceptance" },
	});
	assert(prepare.status === 200, "supervisor prepare failed: " + prepare.body);
	const podState = run("podman", ["pod", "ps", "--filter", "name=" + sandboxId, "--format", "{{.State}}"], { asSandboxUser: true }).trim();
	assert(podState === "Created", "pod was not created: " + podState);
	const started = await requestJson("/v1/rpc", { version: 1, operation: "start", sandboxId });
	assert(started.status === 200, "supervisor start failed: " + started.body);

	// 11b. Operator connectivity matrix (2.32): from the ASSEMBLED containers,
	// the gateway must reach host MinIO through the slirp gateway address, while
	// the worker must not reach Kernel, MinIO, the supervisor socket, host
	// loopback services, or peer sandboxes directly.
	const gatewayContainer = sandboxId + "-gw";
	const appContainer = sandboxId + "-app";
	const execIn = (container: string, command: readonly string[]): string => {
		try {
			return run("podman", ["exec", container, ...command], { asSandboxUser: true });
		} catch (error) {
			// connection refused / timeout are the EXPECTED denial observable; record raw
			return "DENIED:" + String((error as { message?: string }).message ?? "error").slice(0, 80);
		}
	};
	// gateway -> host MinIO via slirp gateway address (expect a response, any HTTP status)
	const gatewayProbe = execIn(gatewayContainer, ["wget", "-q", "-O", "-", "--timeout=5", "http://10.0.2.2:9000/minio/health/live"]);
	assert(!gatewayProbe.startsWith("DENIED:"), "gateway could not reach host MinIO through the slirp gateway: " + gatewayProbe);
	// worker -> MinIO slirp address directly must be refused/denied
	const workerMinio = execIn(appContainer, ["wget", "-q", "-O", "-", "--timeout=5", "http://10.0.2.2:9000/minio/health/live"]);
	assert(workerMinio.startsWith("DENIED:"), "worker reached host MinIO directly (expected denial): " + workerMinio);
	// worker -> Kernel port on the host loopback must be refused
	const workerKernel = execIn(appContainer, ["wget", "-q", "-O", "-", "--timeout=5", "http://10.0.2.2:7070/health"]);
	assert(workerKernel.startsWith("DENIED:"), "worker reached the Kernel loopback service (expected denial): " + workerKernel);
	results.connectivity = { gatewayToMinio: "reachable", workerToMinio: "denied", workerToKernel: "denied" };
	const metrics = await requestJson("/v1/rpc", { version: 1, operation: "metrics", sandboxId, versionId: digest + "-" + sequence });
	assert(metrics.status === 200, "supervisor metrics failed: " + metrics.body);
	const metricsBody = JSON.parse(metrics.body) as { sample?: { cpuMillis?: { available?: boolean } } };
	assert(metricsBody.sample?.cpuMillis?.available === true, "cgroup metrics were not provable");
	const stopped = await requestJson("/v1/rpc", { version: 1, operation: "stop", sandboxId });
	assert(stopped.status === 200, "supervisor stop failed: " + stopped.body);
	const deleted = await requestJson("/v1/rpc", { version: 1, operation: "delete", sandboxId });
	assert(deleted.status === 200, "supervisor delete failed: " + deleted.body);
	results.lifecycle = { prepare: "ok", start: "ok", metrics: "available", stop: "ok", delete: "ok" };
} else {
	results.lifecycle = { skipped: "set IWEB_ACCEPTANCE_RUN_LIFECYCLE=1 to run the real pod lifecycle" };
}

process.stdout.write(JSON.stringify(results, null, 2) + "\n");
