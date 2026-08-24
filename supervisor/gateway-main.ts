// 用户原始需求（2026-08-14）：gateway 是 supervisor 所有的 pod 内策略进程；只读挂载配置；仅绑定 pod loopback 与挂载目录中的 Unix socket。
// 正交意图：入口最小；解析挂载配置；启动三面（对象/egress/ingress/data）；持久 nonce 防重放；信号安全退出。
import { join } from "node:path";
import { loadGatewayConfig, startGateway, systemGatewayIO } from "./gateway.ts";
import { DurableNonceStore } from "../packages/contracts/storage-gateway.ts";

const configPath = process.env.IWEB_GATEWAY_CONFIG?.trim();
const socketDirectory = process.env.IWEB_GATEWAY_SOCKET_DIR?.trim();
if (!configPath || !socketDirectory) throw new Error("IWEB_GATEWAY_CONFIG and IWEB_GATEWAY_SOCKET_DIR are required");
if (!socketDirectory.startsWith("/")) throw new Error("IWEB_GATEWAY_SOCKET_DIR must be an absolute path");

const config = loadGatewayConfig(configPath);
// Capability replay protection must survive a gateway restart: the nonce journal
// lives in the mounted socket directory (a supervisor-owned host path), not in
// container memory. Without it, a captured capability could be replayed after a
// gateway restart within its TTL.
const nonceStore = new DurableNonceStore({ filePath: join(socketDirectory, "capability-nonces") });
const running = await startGateway({ ...config, socketDirectory }, systemGatewayIO, {}, { nonceStore });
process.stdout.write("iweb sandbox gateway ready for " + config.sandboxId + "\n");

const stop = async (): Promise<void> => {
	await running.close();
	process.exit(0);
};
process.once("SIGINT", stop);
process.once("SIGTERM", stop);
