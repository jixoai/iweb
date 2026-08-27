// 用户原始需求（2026-08-27，add-wasm-runtime 7.1）：Node 不能读取 SO_PEERCRED，公开
// supervisor socket 只可由原生 relay 监听；Node 私有 upstream 必须拒绝所有未携带 relay
// 进程凭据的请求。
// 正交意图：固定 public/private socket 字面量；private upstream request token 判定。

import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";

export const SUPERVISOR_SOCKET_PATH = "/run/iweb-sandbox/supervisor.sock";
export const SUPERVISOR_INTERNAL_SOCKET_PATH = "/run/iweb-sandbox/supervisor-internal.sock";
export const RELAY_AUTHORIZATION_HEADER = "x-iweb-relay-authorization";

export type SupervisorRequestAuthorization = (headers: IncomingHttpHeaders) => boolean;

/** Reject environment redirection; the Kernel-visible execution protocol has one v1 endpoint. */
export function requireFixedSupervisorSocketPath(value: string | undefined): string {
	if (value !== undefined && value !== SUPERVISOR_SOCKET_PATH) {
		throw new Error("IWEB_SANDBOX_SOCKET must be exactly " + SUPERVISOR_SOCKET_PATH);
	}
	return SUPERVISOR_SOCKET_PATH;
}

/** The Node listener is an implementation-private endpoint, never configurable. */
export function fixedSupervisorInternalSocketPath(): string {
	return SUPERVISOR_INTERNAL_SOCKET_PATH;
}

/** A process-lifetime capability, generated after preflight and never persisted or logged. */
export function createRelayAuthorizationToken(): string {
	return randomBytes(32).toString("hex");
}

/**
 * Node cannot ask the kernel for SO_PEERCRED. It therefore accepts only the
 * header injected by the native relay after that relay has verified the public
 * peer credentials and its bound socket inode. Direct upstream callers stop
 * here, before a body is buffered or an execution journal is consulted.
 */
export function createRelayRequestAuthorization(expectedToken: string): SupervisorRequestAuthorization {
	if (!/^[0-9a-f]{64}$/.test(expectedToken)) throw new Error("the relay authorization token must be 32 bytes of lowercase hex");
	const expected = Buffer.from(expectedToken, "utf8");
	return (headers) => {
		const supplied = headers[RELAY_AUTHORIZATION_HEADER];
		if (typeof supplied !== "string") return false;
		const actual = Buffer.from(supplied, "utf8");
		return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected);
	};
}
