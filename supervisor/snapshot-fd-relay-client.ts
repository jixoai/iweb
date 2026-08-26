// 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 3）：snapshot FD 原生 relay
//   （kernel-rs/snapshot-fd-relay）的 Node 侧控制客户端——supervisor 进程经 SOCK_STREAM
//   控制 socket 查询代持 handoff、触发 FD 3/4 注入的 podman spawn、释放代持描述符。
// 规范权威：spec "Snapshot FD content is bound across Kernel, supervisor, Podman, and
//   wasmd"（三方 FD 契约；relay 是 supervisor 侧唯一持有描述符的原生半边）。
// 正交意图：
//   1. wire 与 relay src/control.rs 逐字段对位（camelCase 键、每行一个 JSON 请求/响应、
//      每请求一条新连接——本地 UDS 低频控制面，无长连接状态机）；
//   2. fd 字节以 base64 回传，Node 用 supervisor/snapshot-fd.ts 的
//      validateSnapshotHandoffAcceptance 复核摘要链（relay 不引入第二套比对语义）；
//   3. 任何传输失败都抛 SnapshotFdRelayError（调用方 fail-closed，绝不静默降级为
//      “无 handoff”成功路径）。
import { connect } from "node:net";

/** 控制 socket 固定默认路径（与 relay main.rs DEFAULT_CONTROL_SOCKET_PATH 对位）。 */
export const SNAPSHOT_FD_RELAY_CONTROL_SOCKET = "/run/iweb-sandbox/snapshot-fd-relay.sock";

/** relay 控制面内部失败码（与 relay src/control.rs / src/handoff.rs 对位；非 spec wire 稳定码）。 */
export const SNAPSHOT_HANDOFF_MISSING = "SNAPSHOT_HANDOFF_MISSING";
export const SNAPSHOT_SPAWN_FAILED = "SNAPSHOT_SPAWN_FAILED";
export const SNAPSHOT_CONTROL_REQUEST_INVALID = "SNAPSHOT_CONTROL_REQUEST_INVALID";

export class SnapshotFdRelayError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.name = "SnapshotFdRelayError";
		this.code = code;
	}
}

/** relay 回传的单个 handoff 视图（src/control.rs HandoffView 逐字段对位）。 */
export interface SnapshotFdRelayHandoffView {
	readonly commandId: string;
	readonly kind: "secret" | "config";
	/** Kernel 在帧 payload 中给出的命令摘要（Node 侧命令相关性核验的绑定证明）。 */
	readonly commandDigest: string;
	readonly ref: string;
	readonly applicationId: string;
	readonly versionId: string;
	readonly preparationGeneration: number;
	/** 按 kind 即 secretRevision 或 configRevision。 */
	readonly revision: number;
	readonly valuesDigest: string;
	readonly fdDigest: string;
	readonly expiresAt: string;
	readonly fdBytesBase64: string;
	readonly descriptorRegularFile: boolean;
	readonly descriptorReadOnly: boolean;
}

export interface SnapshotFdRelayLookup {
	readonly secret: SnapshotFdRelayHandoffView | null;
	readonly config: SnapshotFdRelayHandoffView | null;
}

export type SnapshotFdRelaySpawnResult =
	| { readonly ok: true; readonly exitCode: number }
	| { readonly ok: false; readonly code: string; readonly message: string };

export interface SnapshotFdRelayClientOptions {
	/** 控制 socket 路径；缺省固定字面量（生产 relay 由 main.ts 以同值启动）。 */
	readonly controlSocketPath?: string;
	/** 单请求往返超时（毫秒）；缺省 10s（spawn 含 podman run，放宽上限见 spawnTimeoutMs）。 */
	readonly requestTimeoutMs?: number;
	/** spawn 请求专用超时（毫秒）；缺省 120s。 */
	readonly spawnTimeoutMs?: number;
}

interface RelayResponse {
	readonly ok?: unknown;
	readonly secret?: unknown;
	readonly config?: unknown;
	readonly exitCode?: unknown;
	readonly dropped?: unknown;
	readonly code?: unknown;
	readonly message?: unknown;
}

function isHandoffView(value: unknown): value is SnapshotFdRelayHandoffView {
	if (typeof value !== "object" || value === null) return false;
	const view = value as Record<string, unknown>;
	return (
		typeof view.commandId === "string" &&
		(view.kind === "secret" || view.kind === "config") &&
		typeof view.commandDigest === "string" &&
		typeof view.ref === "string" &&
		typeof view.applicationId === "string" &&
		typeof view.versionId === "string" &&
		typeof view.preparationGeneration === "number" &&
		typeof view.revision === "number" &&
		typeof view.valuesDigest === "string" &&
		typeof view.fdDigest === "string" &&
		typeof view.expiresAt === "string" &&
		typeof view.fdBytesBase64 === "string" &&
		typeof view.descriptorRegularFile === "boolean" &&
		typeof view.descriptorReadOnly === "boolean"
	);
}

function requireHandoffView(value: unknown, kind: "secret" | "config"): SnapshotFdRelayHandoffView | null {
	if (value === null) return null;
	if (!isHandoffView(value) || value.kind !== kind) {
		throw new SnapshotFdRelayError(SNAPSHOT_CONTROL_REQUEST_INVALID, "the relay returned a malformed handoff view for kind " + kind);
	}
	return value;
}

export class SnapshotFdRelayClient {
	private readonly controlSocketPath: string;
	private readonly requestTimeoutMs: number;
	private readonly spawnTimeoutMs: number;

	constructor(options: SnapshotFdRelayClientOptions = {}) {
		this.controlSocketPath = options.controlSocketPath ?? SNAPSHOT_FD_RELAY_CONTROL_SOCKET;
		this.requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
		this.spawnTimeoutMs = options.spawnTimeoutMs ?? 120_000;
	}

	/** 单请求-单响应：连接 → 写一行 JSON → 读一行 JSON → 关闭。 */
	private roundTrip(request: unknown, timeoutMs: number): Promise<RelayResponse> {
		return new Promise<RelayResponse>((resolve, reject) => {
			const socket = connect(this.controlSocketPath);
			const finish = (error: Error | null, response?: RelayResponse): void => {
				socket.destroy();
				if (error !== null) reject(error);
				else if (response === undefined) reject(new SnapshotFdRelayError(SNAPSHOT_SPAWN_FAILED, "the relay closed the control connection without a response"));
				else resolve(response);
			};
			socket.setTimeout(timeoutMs, () => finish(new SnapshotFdRelayError(SNAPSHOT_SPAWN_FAILED, "the relay control request timed out")));
			socket.on("error", (error: Error) => finish(new SnapshotFdRelayError(SNAPSHOT_SPAWN_FAILED, "the relay control socket is unreachable: " + error.message)));
			socket.on("connect", () => {
				socket.write(JSON.stringify(request) + "\n");
			});
			let buffered = "";
			socket.on("data", (chunk: Buffer) => {
				buffered += chunk.toString("utf8");
				const newline = buffered.indexOf("\n");
				if (newline < 0) {
					if (buffered.length > 2 * 1024 * 1024) finish(new SnapshotFdRelayError(SNAPSHOT_CONTROL_REQUEST_INVALID, "the relay control response exceeded the fixed bound"));
					return;
				}
				let parsed: unknown;
				try {
					parsed = JSON.parse(buffered.slice(0, newline));
				} catch {
					finish(new SnapshotFdRelayError(SNAPSHOT_CONTROL_REQUEST_INVALID, "the relay control response is not JSON"));
					return;
				}
				if (typeof parsed !== "object" || parsed === null) {
					finish(new SnapshotFdRelayError(SNAPSHOT_CONTROL_REQUEST_INVALID, "the relay control response is not an object"));
					return;
				}
				finish(null, parsed as RelayResponse);
			});
		});
	}

	/** 查询某 commandId 的代持 handoff（secret/config 视图 + fd 字节 + 描述符事实）。 */
	async lookup(commandId: string): Promise<SnapshotFdRelayLookup> {
		const response = await this.roundTrip({ op: "lookup", commandId }, this.requestTimeoutMs);
		if (response.ok !== true) {
			throw new SnapshotFdRelayError(typeof response.code === "string" ? response.code : SNAPSHOT_CONTROL_REQUEST_INVALID, typeof response.message === "string" ? response.message : "the relay rejected the lookup request");
		}
		return {
			secret: requireHandoffView(response.secret, "secret"),
			config: requireHandoffView(response.config, "config"),
		};
	}

	/** 以代持 FD 3/4 spawn（argv 不含程序名；relay 侧 exec 其 podman 路径）。 */
	async spawn(commandId: string, podmanArgv: readonly string[]): Promise<SnapshotFdRelaySpawnResult> {
		const response = await this.roundTrip({ op: "spawn", commandId, podmanArgv }, this.spawnTimeoutMs);
		if (response.ok !== true) {
			return { ok: false, code: typeof response.code === "string" ? response.code : SNAPSHOT_CONTROL_REQUEST_INVALID, message: typeof response.message === "string" ? response.message : "the relay rejected the spawn request" };
		}
		if (typeof response.exitCode !== "number" || !Number.isSafeInteger(response.exitCode)) {
			return { ok: false, code: SNAPSHOT_CONTROL_REQUEST_INVALID, message: "the relay spawn response lacks a valid exitCode" };
		}
		return { ok: true, exitCode: response.exitCode };
	}

	/** 释放某 commandId 的全部代持描述符；返回释放条数。 */
	async discard(commandId: string): Promise<number> {
		const response = await this.roundTrip({ op: "discard", commandId }, this.requestTimeoutMs);
		if (response.ok !== true) {
			throw new SnapshotFdRelayError(typeof response.code === "string" ? response.code : SNAPSHOT_CONTROL_REQUEST_INVALID, typeof response.message === "string" ? response.message : "the relay rejected the discard request");
		}
		if (typeof response.dropped !== "number" || !Number.isSafeInteger(response.dropped) || response.dropped < 0) {
			throw new SnapshotFdRelayError(SNAPSHOT_CONTROL_REQUEST_INVALID, "the relay discard response lacks a valid dropped count");
		}
		return response.dropped;
	}
}
