// 用户原始需求（2026-08-14）：以专用宿主身份运行 supervisor，启动前必须证明隔离前提；image 必须 digest 固定。
// 正交意图：解析固定目录；执行 preflight；从 durable store 重建 desired state；启动即 reconcile；绑定 Unix socket；安全响应终止信号。
// 轮次注记（2026-08-26，归档终审 2+3）：启用 wasm execution 时拉起原生 snapshot-fd relay 子进程
//   （SOCK_SEQPACKET/SCM_RIGHTS/SO_PEERCRED 的 Node 能力缺口由它补齐），executor 注册真实
//   副作用端口（Podman + relay FD 注入）；开关语义不变（未启用 → /v1/execution-rpc 503）。
import { execFileSync, spawn as spawnChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { createSandboxAdapter, reconcileSandboxes } from "./adapter.ts";
import type { SnapshotMaterializerOptions } from "./snapshot-materialize.ts";
import { JsonStateStore, systemStateStoreIO } from "./desired-state.ts";
import { runSandboxPreflight } from "./preflight.ts";
import { PodmanRuntime } from "./runtime.ts";
import { SECCOMP_PROFILE_HOST_PATH } from "./sandbox-spec.ts";
import { SNAPSHOT_FD_SOCKET_PATH } from "./snapshot-fd.ts";
import { SnapshotFdRelayClient } from "./snapshot-fd-relay-client.ts";
import { startSupervisorServer } from "./server.ts";
import { createExecutionRpcHandler, WasmExecutionJournalStore } from "./wasm-control.ts";
import { createWasmSupervisorExecutor, sampleWasmEngineMetrics } from "./wasm-executor.ts";
import { createPodmanWasmSandboxRuntime, type WasmSandboxRuntime } from "./wasm-runtime.ts";
import type { WasmRuntimeArchitecture } from "./wasm-spawn.ts";

function absolutePath(value: string | undefined, fallback: string, name: string): string {
	const normalized = (value ?? fallback).trim();
	if (!normalized.startsWith("/")) throw new Error(name + " must be an absolute path");
	return normalized;
}

const stateDirectory = absolutePath(process.env.IWEB_SANDBOX_STATE_DIR, "/var/lib/iweb-sandbox", "IWEB_SANDBOX_STATE_DIR");
const socketPath = absolutePath(process.env.IWEB_SANDBOX_SOCKET, "/run/iweb-sandbox/supervisor.sock", "IWEB_SANDBOX_SOCKET");
const gatewayRuntimeDirectory = absolutePath(process.env.IWEB_SANDBOX_GATEWAY_DIR, "/run/iweb-sandbox/gw", "IWEB_SANDBOX_GATEWAY_DIR");
const command = process.argv[2] ?? "serve";
const report = await runSandboxPreflight({ stateDirectory, runtimeDirectory: dirname(socketPath), seccompProfilePath: SECCOMP_PROFILE_HOST_PATH });

if (command === "preflight") {
	process.stdout.write(JSON.stringify(report) + "\n");
	if (!report.ready) process.exitCode = 1;
} else if (command === "serve") {
	if (!report.ready) throw new Error("sandbox supervisor preflight failed");
	// Immutable digests only; a floating tag would break the single-executable
	// authority and the reproducible-sandbox contract.
	const runtimeImage = process.env.IWEB_SANDBOX_RUNTIME_IMAGE?.trim();
	const gatewayImage = process.env.IWEB_SANDBOX_GATEWAY_IMAGE?.trim();
	if (!runtimeImage || !gatewayImage) throw new Error("IWEB_SANDBOX_RUNTIME_IMAGE and IWEB_SANDBOX_GATEWAY_IMAGE must be digest-pinned");
	const region = process.env.IWEB_SANDBOX_REGION?.trim() || "us-east-1";
	// The system alias the materializer reads snapshots through. Explicit
	// configuration with a startup reachability check: a supervisor that cannot
	// read the object store would fail every prepare, so it fails closed here
	// instead of discovering the gap on the first sandbox (2.48).
	const systemAlias = process.env.IWEB_SANDBOX_SYSTEM_ALIAS?.trim() || "local/iweb-system";
	try {
		// The supervisor credential's ListBucket permission is prefix-conditioned
		// to packages/ (by design), so the reachability proof must operate inside
		// that scope — a bucket-root stat is denied for the service identity.
		execFileSync("mc", ["ls", systemAlias + "/packages/"], { stdio: ["ignore", "pipe", "pipe"] });
	} catch {
		throw new Error("sandbox supervisor cannot read the snapshot alias " + systemAlias + "; configure the mc alias and credentials for the supervisor user");
	}
	const stores = {
		state: new JsonStateStore(systemStateStoreIO, stateDirectory),
		// 2.48 production materializer: every prepare materializes the admitted
		// digest into the exact read-only mount the app container binds and fails
		// closed on missing/partial/mismatched snapshots — no unverified bytes
		// ever reach a sandbox.
		materializer: { alias: systemAlias } satisfies SnapshotMaterializerOptions,
	};
	const runtime = new PodmanRuntime();
	const adapter = createSandboxAdapter(runtime, { runtimeImage, gatewayImage, stateDirectory, gatewayRuntimeDirectory, region }, stores);
	// Startup reconciliation: quarantine unknown iweb-labeled resources and
	// report missing desired sandboxes; never adopt or execute anything.
	const desiredRecords = stores.state.readDesired().records;
	const reconciliation = await reconcileSandboxes(runtime, new Set(Object.keys(desiredRecords)), stores);
	process.stdout.write("iweb sandbox supervisor reconcile: quarantined=" + reconciliation.quarantined.length + " missing=" + reconciliation.missing.length + "\n");
	// wasm execution 通道（add-wasm-runtime 2.1/2.2 + 归档终审 2/3）：显式 opt-in 才注册
	// executor；未配置时 startSupervisorServer 对 /v1/execution-rpc 维持 503 fail-closed，绝不
	// 降级到 celld /v1/rpc。executor 构造时从 journal 重建双 generation fence 状态；启用时
	// 同步拉起原生 snapshot-fd relay 子进程并注册真实副作用端口（Podman + relay FD 注入）。
	const wasmExecutionEnabled = process.env.IWEB_SANDBOX_WASM_EXECUTION_ENABLED?.trim() === "1";
	// executor 提升为变量：同一 journal 实例既驱动 execution-rpc 命令，也作为
	// 引擎计数源供 /v1/execution-metrics 采样（add-wasm-runtime 4.1）。
	const wasmJournal = wasmExecutionEnabled ? new WasmExecutionJournalStore(systemStateStoreIO, stateDirectory) : undefined;

	// 拉起 relay 子进程：持有 /run/iweb-sandbox/snapshot-fd.sock 的 SOCK_SEQPACKET 循环
	// （SCM_RIGHTS/SO_PEERCRED 原生半边），控制 socket 与 supervisor.sock 同目录。
	// relay 死亡不拖垮 supervisor：celld 通道继续服务，wasm start/drain 命令以
	// WASM_SPAWN_RELAY_UNAVAILABLE 确定性拒绝（fail-closed），重启后恢复。
	let wasmRelayClient: SnapshotFdRelayClient | undefined;
	let wasmRelayChild: ReturnType<typeof spawnChildProcess> | undefined;
	if (wasmExecutionEnabled) {
		const relayBinary = absolutePath(process.env.IWEB_SANDBOX_WASM_RELAY_BIN, "/usr/local/libexec/iweb-sandbox/snapshot-fd-relay", "IWEB_SANDBOX_WASM_RELAY_BIN");
		if (!existsSync(relayBinary)) throw new Error("wasm execution requires the native snapshot-fd relay binary at " + relayBinary + "; build kernel-rs/snapshot-fd-relay and install it, or unset IWEB_SANDBOX_WASM_EXECUTION_ENABLED");
		const controlSocket = dirname(socketPath) + "/snapshot-fd-relay.sock";
		const kernelPeerUid = Number.parseInt(process.env.IWEB_SANDBOX_WASM_KERNEL_PEER_UID?.trim() ?? "0", 10);
		const kernelPeerGid = Number.parseInt(process.env.IWEB_SANDBOX_WASM_KERNEL_PEER_GID?.trim() ?? "0", 10);
		const podmanPath = process.env.IWEB_SANDBOX_WASM_PODMAN?.trim() || "podman";
		const relayChild = spawnChildProcess(relayBinary, [
			"--fd-socket", SNAPSHOT_FD_SOCKET_PATH,
			"--control-socket", controlSocket,
			"--kernel-peer-uid", String(Number.isSafeInteger(kernelPeerUid) ? kernelPeerUid : 0),
			"--kernel-peer-gid", String(Number.isSafeInteger(kernelPeerGid) ? kernelPeerGid : 0),
			"--podman", podmanPath,
		], { stdio: ["ignore", "ignore", "inherit"] });
		wasmRelayChild = relayChild;
		relayChild.on("exit", (code, signal) => {
			process.stderr.write("iweb sandbox supervisor: snapshot-fd relay exited (code=" + String(code) + " signal=" + String(signal) + "); wasm execution commands fail closed until restart\n");
		});
		// 控制就绪探测（有界等待绑定）：连不上即 fail-closed 启动失败。
		let relayReady = false;
		for (let attempt = 0; attempt < 100 && !relayReady; attempt += 1) {
			relayReady = existsSync(controlSocket);
			if (!relayReady) await new Promise((resolve) => setTimeout(resolve, 50));
		}
		if (!relayReady) {
			relayChild.kill("SIGTERM");
			throw new Error("the snapshot-fd relay did not bind its control socket in time; refusing to start with wasm execution half-configured");
		}
		wasmRelayClient = new SnapshotFdRelayClient({ controlSocketPath: controlSocket });
	}

	// 真实副作用端口：wasm 的 podman 调用经 relay 注入 FD 3/4（spawn）或直连执行器
	// （建网/停止/清理）。策略来源（ExecutionCommandV1 不携带 normalized manifest）与
	// spawn 组装输入按环境显式配置；缺失时 prepare/start 以
	// WASM_EXECUTION_POLICY_UNAVAILABLE / WASM_SPAWN_UNCONFIGURED 确定性拒绝（fail-closed，
	// 不静默降级为纯 fence applied——归档终审阻塞 2 的相反面）。
	let wasmRuntime: WasmSandboxRuntime | undefined;
	if (wasmExecutionEnabled && wasmRelayClient !== undefined) {
		const podmanExecutor = (args: readonly string[]): string => execFileSync("podman", [...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
		wasmRuntime = createPodmanWasmSandboxRuntime({ exec: podmanExecutor, relay: wasmRelayClient });
	}
	const runtimeImageRepository = process.env.IWEB_SANDBOX_WASM_RUNTIME_IMAGE_REPO?.trim();
	const capabilityRecordHostPath = process.env.IWEB_SANDBOX_WASM_CAPABILITY_RECORD?.trim();
	const architectureByProcess: Record<string, WasmRuntimeArchitecture> = { arm64: "linux/arm64", x64: "linux/amd64" };
	const architecture = architectureByProcess[process.arch];
	const wasmSpawnOptions = runtimeImageRepository && capabilityRecordHostPath && architecture
		? { stateDirectory, runtimeImageRepository, capabilityRecordHostPath, architecture }
		: undefined;
	if (wasmExecutionEnabled && (wasmSpawnOptions === undefined || wasmRuntime === undefined)) {
		process.stderr.write("iweb sandbox supervisor: wasm execution side effects are partially unconfigured (need IWEB_SANDBOX_WASM_RUNTIME_IMAGE_REPO, IWEB_SANDBOX_WASM_CAPABILITY_RECORD); prepare/start commands will fail closed until configured\n");
	}
	const wasmExecutor = wasmJournal
		? createWasmSupervisorExecutor({ journal: wasmJournal, runtime: wasmRuntime, relay: wasmRelayClient, spawnOptions: wasmSpawnOptions })
		: undefined;
	const executionRpc = wasmExecutor && wasmJournal ? createExecutionRpcHandler({ journal: wasmJournal, executor: wasmExecutor }) : undefined;
	const running = await startSupervisorServer({
		socketPath,
		adapter,
		executionRpc,
		executionMetrics: wasmExecutor ? (id: string) => sampleWasmEngineMetrics(wasmExecutor.fence, id) : undefined,
	});
	const stop = async (): Promise<void> => {
		await running.close();
		// supervisor 退出即关闭全部代持描述符（spec：supervisor crash/exit closes all
		// descriptors；恢复经 Kernel query/replay 重发字节相同的帧）。
		wasmRelayChild?.kill("SIGTERM");
		process.exit(0);
	};
	process.once("SIGINT", stop);
	process.once("SIGTERM", stop);
	process.stdout.write("iweb sandbox supervisor ready on its private Unix socket\n");
} else {
	throw new Error("unknown supervisor command: " + command);
}
