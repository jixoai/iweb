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
import { startSupervisorServer } from "./server.ts";
import { assembleWasmExecutionServices } from "./wasm-serve.ts";

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
	// wasm execution 通道（add-wasm-runtime 2.1/2.2 + 归档终审 2/3 + codex-final P0-2）：显式
	// opt-in 才装配 executor；未配置时 startSupervisorServer 对 /v1/execution-rpc 维持 503
	// fail-closed，绝不降级到 celld /v1/rpc。装配内含生产依赖门（capability record 的
	// NodeCapabilityRecordV1 校验、policySource 只读目录、retiring 台账、readiness 探测配置、
	// relay 二进制与 spawn 输入）：缺失/无效即抛错拒绝启用（supervisor 启动失败， systemd
	// 重启并在 journal 暴露原因），齐备时 executor 注册真实副作用端口（Podman + relay FD
	// 注入 + 文件策略/台账来源），prepare/start/drain 不再因缺依赖而确定性拒绝。
	const wasm = await assembleWasmExecutionServices({
		environment: process.env,
		stateDirectory,
		runtimeDirectory: dirname(socketPath),
		arch: process.arch,
	});
	const running = await startSupervisorServer({
		socketPath,
		adapter,
		executionRpc: wasm.enabled ? wasm.executionRpc : undefined,
		executionMetrics: wasm.enabled ? wasm.sampleEngineMetrics : undefined,
	});
	const stop = async (): Promise<void> => {
		await running.close();
		// supervisor 退出即关闭全部代持描述符（spec：supervisor crash/exit closes all
		// descriptors；恢复经 Kernel query/replay 重发字节相同的帧）。
		if (wasm.enabled) wasm.stopRelay();
		process.exit(0);
	};
	process.once("SIGINT", stop);
	process.once("SIGTERM", stop);
	process.stdout.write("iweb sandbox supervisor ready on its private Unix socket\n");
} else {
	throw new Error("unknown supervisor command: " + command);
}
