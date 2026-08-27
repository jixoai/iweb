// 用户原始需求（2026-08-27，add-wasm-runtime 终审接线）：supervisor execution RPC
// 必须只在固定私有 Unix socket 上服务；Node 无 SO_PEERCRED 时至少在 HTTP 解析前
// 验证监听 inode 的路径、类型、属主与权限。原生 relay 仍是 Linux peer credential
// 的权威验证端。
// 正交意图：固定路径解析；Node 可见的 socket inode 判定；供 server.ts/main.ts 接线。

import { lstatSync } from "node:fs";
import type { Socket } from "node:net";

export const SUPERVISOR_SOCKET_PATH = "/run/iweb-sandbox/supervisor.sock";

export interface SupervisorSocketStat {
	isSocket(): boolean;
	readonly mode: number;
	readonly uid: number;
	readonly gid: number;
}

export interface FixedSupervisorConnectionAuthorizationOptions {
	readonly socketPath: string;
	readonly expectedUid: number;
	readonly expectedGid: number;
	/** Test seam only. Production uses lstatSync. */
	readonly lstat?: (path: string) => SupervisorSocketStat;
	/** The fixed v1 socket may be overridden only by an explicit test seam. */
	readonly canonicalPath?: string;
}

export type SupervisorConnectionAuthorization = (socket: Pick<Socket, "destroyed">) => boolean;

/** Reject environment redirection; the execution protocol has one v1 endpoint. */
export function requireFixedSupervisorSocketPath(value: string | undefined): string {
	const requested = value?.trim();
	if (requested !== undefined && requested.length > 0 && requested !== SUPERVISOR_SOCKET_PATH) {
		throw new Error("IWEB_SANDBOX_SOCKET must be exactly " + SUPERVISOR_SOCKET_PATH);
	}
	return SUPERVISOR_SOCKET_PATH;
}

/**
 * Node exposes neither SO_PEERCRED nor SCM credentials. This closes the available
 * filesystem side of the contract before request parsing: only the fixed 0600
 * socket inode owned by the supervisor account is accepted. The native relay
 * verifies actual Linux peer credentials for snapshot handoff separately.
 */
export function createFixedSupervisorConnectionAuthorization(
	options: FixedSupervisorConnectionAuthorizationOptions,
): SupervisorConnectionAuthorization {
	const canonicalPath = options.canonicalPath ?? SUPERVISOR_SOCKET_PATH;
	const lstat = options.lstat ?? lstatSync;
	return (socket) => {
		if (socket.destroyed || options.socketPath !== canonicalPath) return false;
		try {
			const stat = lstat(options.socketPath);
			return stat.isSocket()
				&& (stat.mode & 0o777) === 0o600
				&& stat.uid === options.expectedUid
				&& stat.gid === options.expectedGid;
		} catch {
			return false;
		}
	};
}
