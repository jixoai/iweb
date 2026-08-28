// 用户原始需求（2026-08-14）：以专用宿主身份运行 supervisor，启动前必须证明隔离前提；image 必须 digest 固定。
// 正交意图：解析固定目录；执行 preflight；从 durable store 重建 desired state；启动即 reconcile；绑定 Unix socket；安全响应终止信号。
// 轮次注记（2026-08-26，归档终审 2+3）：启用 wasm execution 时拉起原生 snapshot-fd relay 子进程
//   （SOCK_SEQPACKET/SCM_RIGHTS/SO_PEERCRED 的 Node 能力缺口由它补齐），executor 注册真实
//   副作用端口（Podman + relay FD 注入）；开关语义不变（未启用 → /v1/execution-rpc 503）。
// 轮次注记（2026-08-27，codex-final 复审 P0-2）：executor 的生产依赖（capability record 启动门、
//   policySource、retiring 台账、readiness 探测配置、relay 交付）统一在 wasm-serve.ts 装配——
//   依赖缺失/无效即拒绝启用（启动失败），齐备时 prepare/start/drain 走真实副作用路径。
import { execFileSync } from "node:child_process";
import { dirname } from "node:path";
import { createSandboxAdapter, reconcileSandboxes } from "./adapter.ts";
import type { SnapshotMaterializerOptions } from "./snapshot-materialize.ts";
import { JsonStateStore, systemStateStoreIO } from "./desired-state.ts";
import { runSandboxPreflight } from "./preflight.ts";
import { PodmanRuntime } from "./runtime.ts";
import { SECCOMP_PROFILE_HOST_PATH } from "./sandbox-spec.ts";
import { startSupervisorServer, type RunningSupervisorServer } from "./server.ts";
import { startSupervisorSocketRelay } from "./socket-relay.ts";
import {
	createRelayAuthorizationToken,
	createRelayRequestAuthorization,
	fixedSupervisorInternalSocketPath,
	requireFixedSupervisorSocketPath,
} from "./socket-auth.ts";
import { assembleWasmExecutionServices, type WasmExecutionServices } from "./wasm-serve.ts";
import { assembleWasmLoggingOwnerFace, createHttpWasmLoggingProjectionSource, WasmLoggingIngressRegistry, type WasmLoggingOwnerServices } from "./wasm-host-logging.ts";

function absolutePath(value: string | undefined, fallback: string, name: string): string {
	const normalized = (value ?? fallback).trim();
	if (!normalized.startsWith("/")) throw new Error(name + " must be an absolute path");
	return normalized;
}

const stateDirectory = absolutePath(process.env.IWEB_SANDBOX_STATE_DIR, "/var/lib/iweb-sandbox", "IWEB_SANDBOX_STATE_DIR");
const socketPath = requireFixedSupervisorSocketPath(process.env.IWEB_SANDBOX_SOCKET);
const internalSocketPath = fixedSupervisorInternalSocketPath();
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
	// 7.1：公开固定 socket 永远由原生 relay 监听（即使 wasm execution 尚未启用，
	// 也不能回退到 Node 无 SO_PEERCRED 的 listener）。relay 对每个连接验证 Linux
	// SO_PEERCRED=Kernel 0/0 与自身 inode，再代理到下方的 Node 私有 socket。
	const relayAuthorization = createRelayAuthorizationToken();
	const relay = await startSupervisorSocketRelay({
		environment: process.env,
		runtimeDirectory: dirname(socketPath),
		publicSocketPath: socketPath,
		upstreamSocketPath: internalSocketPath,
		upstreamAuthorization: relayAuthorization,
	});
	// logging 权威登记面（第三轮复审）：V2 执行 start 时登记其 wasmd ingress base URL，
	// stop/drain 后注销——owner drain/summary 经 createHttpWasmLoggingProjectionSource
	// 直接拉 wasmd 进程的保留端点；无登记（无活执行）= 404（L1 生命周期内如实的「无环」）。
	const loggingIngress = new WasmLoggingIngressRegistry();
	let wasm: WasmExecutionServices;
	try {
		// wasm execution 通道（add-wasm-runtime 2.1/2.2 + 归档终审 2/3 + codex-final
		// P0-2）：显式 opt-in 才装配 executor；未配置时私有 Node upstream 对
		// /v1/execution-rpc 维持 503。relay 是上方唯一已认证的 FD/HTTP 原生边界，
		// 装配只消费它的控制 client，绝不自行生成无 HTTP peer-auth 的替代 relay。
		wasm = await assembleWasmExecutionServices({
			environment: process.env,
			stateDirectory,
			runtimeDirectory: dirname(socketPath),
			arch: process.arch,
			relayClient: relay.client,
			loggingIngressRegistry: loggingIngress,
		});
	} catch (error) {
		relay.stop();
		throw error;
	}
	let running: RunningSupervisorServer;
	try {
		// logging owner 面（add-wasm-host-services；终审缺口修正后形态）：装配做转发配置
		// 宿主装载（默认关、无效 fail-closed → 启动失败）；环权威是 wasmd 进程内 ring，
		// supervisor 不持有本地台账——权威投影源（wasmd owner-drain 端点）接线前，
		// drain/summary 端点在既有 relay 凭据之下显式 503 WASM_LOG_AUTHORITY_UNAVAILABLE，
		// 绝不合成事件。装配失败同样回收 relay。
		const logging: WasmLoggingOwnerServices = assembleWasmLoggingOwnerFace({
			environment: process.env,
			source: createHttpWasmLoggingProjectionSource({ resolveBaseUrl: (applicationId) => loggingIngress.resolve(applicationId) }),
		});
		running = await startSupervisorServer({
			socketPath: internalSocketPath,
			adapter,
			executionRpc: wasm.enabled ? wasm.executionRpc : undefined,
			executionMetrics: wasm.enabled ? wasm.sampleEngineMetrics : undefined,
			loggingFace: logging.enabled ? logging.face : undefined,
			requestAuthorization: createRelayRequestAuthorization(relayAuthorization),
		});
	} catch (error) {
		relay.stop();
		throw error;
	}
	const stop = async (): Promise<void> => {
		await running.close();
		// supervisor 退出即关闭 relay 代持的全部描述符（spec：supervisor crash/exit
		// closes all descriptors；恢复经 Kernel query/replay 重发字节相同的帧）。
		relay.stop();
		process.exit(0);
	};
	process.once("SIGINT", stop);
	process.once("SIGTERM", stop);
	process.stdout.write("iweb sandbox supervisor ready behind its authenticated Unix socket relay\n");
} else {
	throw new Error("unknown supervisor command: " + command);
}
