// two-tier-runtime-trust P0-1 ingress 最后一公里（原标记「gateway ingress 接线归 5.x」，
// 2026-08-31 为跑通真实路由提前落地）：Kernel 公开入口以 sandboxId 寻址
// /run/iweb-sandbox/gw/<sbx>/ingress.sock（kernel-rs/iweb-kernel/src/proxy.rs
// sandbox_ingress_socket 同一契约）；本模块为每个已 spawn 的沙箱在该路径提供
// 0600 unix listener，把字节流裸转发到 wasmd 的唯一 listener（127.200.x.3:8787
// 确定性回环地址）。HTTP 语义（host 重写、头部契约、泛化 502）全在 Kernel 侧；
// 这里只做传输，绝不解析、绝不缓存、绝不落日志。
//
// 生命周期纪律：forwarder 由 start 命令的成功副作用创建、stop/drain 成功后拆除；
// 崩溃残留 socket 由下一次同 sandboxId start 的 stale-unlink 收敛（/run 为容器内
// 易失目录，容器重启即清零）。

import { chmod, mkdir } from "node:fs/promises";
import { mkdtempSync, rmSync, statSync, unlinkSync } from "node:fs";
import { createServer, Socket, type Server } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";

export const SANDBOX_GATEWAY_DIRECTORY_ENV = "IWEB_SANDBOX_GATEWAY_DIR";
export const SANDBOX_GATEWAY_DIRECTORY_DEFAULT = "/run/iweb-sandbox/gw";
const INGRESS_SOCKET_NAME = "ingress.sock";

/** sandboxId 文法（与 kernel proxy::valid_sandbox_route_id 同一形状；路径拼接安全前提）。 */
export function validSandboxGatewayId(value: string): boolean {
	return /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/.test(value);
}

export interface SandboxIngressForwarder {
	readonly sandboxId: string;
	readonly listenAddress: string;
	close(): Promise<void>;
}

export interface WasmIngressGatewayController {
	/** start 命令 spawn 成功后建立转发；已存在同 id 转发器则先拆旧（幂等收敛）。 */
	start(sandboxId: string, listenAddress: string): Promise<void>;
	/** stop/drain 成功后拆除；未知 id 是 no-op（幂等）。 */
	stop(sandboxId: string): Promise<void>;
}

export function sandboxIngressGatewayDirectory(environment: Readonly<Record<string, string | undefined>>): string {
	const fromEnv = environment[SANDBOX_GATEWAY_DIRECTORY_ENV]?.trim();
	return fromEnv && fromEnv.length > 0 ? fromEnv : SANDBOX_GATEWAY_DIRECTORY_DEFAULT;
}

interface ActiveForwarder {
	readonly server: Server;
	readonly socketPath: string;
	readonly upstreams: Set<Socket>;
}

export function createWasmIngressGatewayController(
	directory: string,
	io: { readonly mkDirRecursive?: typeof mkdir; readonly now?: () => number } = {},
): WasmIngressGatewayController {
	const active = new Map<string, ActiveForwarder>();
	const mkDirRecursive = io.mkDirRecursive ?? mkdir;

	const teardown = async (sandboxId: string, entry: ActiveForwarder): Promise<void> => {
		active.delete(sandboxId);
		for (const upstream of entry.upstreams) upstream.destroy();
		await new Promise<void>((resolve) => {
			entry.server.close(() => resolve());
		});
		try {
			unlinkSync(entry.socketPath);
		} catch {
			// 竞态下已被清理（容器停机/上一次 teardown）——目录干净即可。
		}
	};

	return {
		async start(sandboxId, listenAddress) {
			if (!validSandboxGatewayId(sandboxId)) {
				throw new Error(`sandbox id is not a valid gateway directory segment: ${sandboxId}`);
			}
			const existing = active.get(sandboxId);
			if (existing !== undefined) await teardown(sandboxId, existing);
			const directoryForSandbox = join(directory, sandboxId);
			await mkDirRecursive(directoryForSandbox, { recursive: true, mode: 0o700 });
			const socketPath = join(directoryForSandbox, INGRESS_SOCKET_NAME);
			// 崩溃残留的同路径旧 socket 会让 bind 撞 EADDRINUSE：只清 socket 文件本身。
			try {
				const stats = statSync(socketPath);
				if (stats.isSocket()) unlinkSync(socketPath);
			} catch {
				// 无残留。
			}
			const upstreams = new Set<Socket>();
			const server = createServer((downstream) => {
				// 单请求单连接（Kernel 契约）；上游失败即拆该连接，绝不半开滞留。
				const upstream = new Socket();
				upstreams.add(upstream);
				const drop = (): void => {
					upstream.destroy();
					downstream.destroy();
					upstreams.delete(upstream);
				};
				// 显式字节泵（不做协议解析）：对端已 end/destroy 后绝不再写，
				// 避免 pipe 机制在拆连接竞态下抛 EPIPE。
				const pump = (from: Socket, to: Socket): void => {
					from.on("data", (chunk: Buffer) => {
						if (!to.destroyed && to.writable) to.write(chunk);
					});
				};
				upstream.on("error", drop);
				downstream.on("error", drop);
				upstream.connect(
					Number.parseInt(listenAddress.slice(listenAddress.lastIndexOf(":") + 1), 10),
					listenAddress.slice(0, listenAddress.lastIndexOf(":")),
				);
				pump(downstream, upstream);
				pump(upstream, downstream);
				upstream.on("close", () => {
					downstream.end();
					upstreams.delete(upstream);
				});
				downstream.on("close", () => upstream.destroy());
			});
			const listening = new Promise<void>((resolve, reject) => {
				server.once("listening", () => resolve());
				server.once("error", reject);
			});
			server.listen(socketPath);
			await listening;
			// 0600：仅属主（iweb-sandbox）与 root（Kernel）可连；chmod 失败即拒绝启用并拆除。
			try {
				await chmod(socketPath, 0o600);
			} catch (error) {
				await teardown(sandboxId, { server, socketPath, upstreams });
				throw error;
			}
			active.set(sandboxId, { server, socketPath, upstreams });
		},
		async stop(sandboxId) {
			const entry = active.get(sandboxId);
			if (entry !== undefined) await teardown(sandboxId, entry);
		},
	};
}

/** 测试辅助：临时网关根目录。 */
export function tempGatewayRoot(prefix = "iweb-gw-"): string {
	return mkdtempSync(join(tmpdir(), prefix));
}

/** 测试辅助：递归清理网关根目录。 */
export function removeGatewayRoot(root: string): void {
	rmSync(root, { recursive: true, force: true });
}

export type { SandboxIngressForwarder as _SandboxIngressForwarder };
