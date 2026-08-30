// 用户原始需求（2026-08-14）：以专用身份运行 supervisor，启动前证明容器内执行前提。
// 轮次注记（2026-08-26，归档终审 2+3）：启用 wasm execution 时由原生 snapshot-fd relay
//   子进程承担 SOCK_SEQPACKET/SCM_RIGHTS/SO_PEERCRED（Node 能力缺口由它补齐）。
// 轮次注记（2026-08-30，two-tier-runtime-trust）：supervisor 移入节点容器，以专用非 root
//   用户运行；celld adapter/OCI 沙箱机器永久退役（/v1/rpc 恒拒 CELLD_PROTOCOL_MISMATCH，
//   见 server.ts）；状态目录缺省 /data/wasm-supervisor（持久卷）；preflight 是
//   容器内检查（socket 目录属主、relay 二进制、RustFS 回环、Unix socket 绑定），不再
//   探测宿主机 podman/subuid/cgroup/seccomp。
// 正交意图：解析固定目录；执行 preflight；绑定 Unix socket；安全响应终止信号。
import { dirname } from "node:path";
import { runSandboxPreflight } from "./preflight.ts";
import { startSupervisorServer, type RunningSupervisorServer } from "./server.ts";
import { SUPERVISOR_SOCKET_RELAY_BINARY, startSupervisorSocketRelay } from "./socket-relay.ts";
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

// two-tier-runtime-trust：容器内持久卷布局——supervisor 状态（journal、wasm-components）
// 在 /data/wasm-supervisor；Kernel wasm 投影在 /data/kernel/wasm（wasm-serve.ts 固定读
// 该目录，语义不变）；per-app 数据根经 IWEB_WASM_DATA_ROOT 显式注入（R2 9.5 统一根
// /data/wasm-data，与 Kernel preparation 同根；未注入时回落 <stateDirectory>/wasm-data）。
// entrypoint 以 IWEB_SANDBOX_STATE_DIR 显式传入同值；本缺省值保证容器内裸启动也落在持久卷。
const stateDirectory = absolutePath(process.env.IWEB_SANDBOX_STATE_DIR, "/data/wasm-supervisor", "IWEB_SANDBOX_STATE_DIR");
const socketPath = requireFixedSupervisorSocketPath(process.env.IWEB_SANDBOX_SOCKET);
const internalSocketPath = fixedSupervisorInternalSocketPath();
const relayBinaryPath = absolutePath(process.env.IWEB_SANDBOX_WASM_RELAY_BIN, SUPERVISOR_SOCKET_RELAY_BINARY, "IWEB_SANDBOX_WASM_RELAY_BIN");
const command = process.argv[2] ?? "serve";
const report = await runSandboxPreflight({ stateDirectory, runtimeDirectory: dirname(socketPath), relayBinaryPath });

if (command === "preflight") {
	process.stdout.write(JSON.stringify(report) + "\n");
	if (!report.ready) process.exitCode = 1;
} else if (command === "serve") {
	if (!report.ready) throw new Error("wasm supervisor preflight failed");
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
	// logging 权威登记面：V2 执行 start 时登记其 wasmd ingress base URL，stop/drain 后
	// 注销——owner drain/summary 经 createHttpWasmLoggingProjectionSource 直接拉 wasmd
	// 进程的保留端点；无登记（无活执行）= 404（L1 生命周期内如实的「无环」）。
	const loggingIngress = new WasmLoggingIngressRegistry();
	let wasm: WasmExecutionServices;
	try {
		// wasm execution 通道：显式 opt-in 才装配 executor；未配置时私有 Node upstream 对
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
		// logging owner 面：装配做转发配置宿主装载（默认关、无效 fail-closed → 启动失败）；
		// 环权威是 wasmd 进程内 ring，supervisor 不持有本地台账。装配失败同样回收 relay。
		const logging: WasmLoggingOwnerServices = assembleWasmLoggingOwnerFace({
			environment: process.env,
			source: createHttpWasmLoggingProjectionSource({
				resolveBaseUrl: (applicationId) => loggingIngress.resolve(applicationId),
				// 安全法：token 从 ingress registry 读取——executor start 时
				// 与 baseUrl 同步登记（与 wasmd host_logging_access_token 同式）。
				accessToken: (applicationId) => loggingIngress.resolveToken(applicationId),
			}),
		});
		running = await startSupervisorServer({
			socketPath: internalSocketPath,
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
	process.stdout.write("iweb wasm supervisor ready behind its authenticated Unix socket relay\n");
} else {
	throw new Error("unknown supervisor command: " + command);
}
