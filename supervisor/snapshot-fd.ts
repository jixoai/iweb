// 用户原始需求（2026-08-26，add-wasm-runtime 任务 7.3 + 7.4 的 supervisor 侧）：秘密/配置
//   快照 FD 经独立 raw-UDS SOCK_SEQPACKET 通道 `/run/iweb-sandbox/snapshot-fd.sock`
//   单一 SCM_RIGHTS 描述符 handoff 的判定层——帧编解码、预解析拒绝、ancillary 事实
//   判定、handoff/ack payload 契约、digest 公式、command 相关性与 FD 策略。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
// "Snapshot descriptors use an independent framed raw socket"（SnapshotFdTransportV1）。
// 纯函数对位：packages/contracts/wasm-execution.ts（WASM_SNAPSHOT_FRAME_MAGIC_HEX、
// ExecutionCommand/computeExecutionCommandDigest——Rust kernel-rs 为 wire 权威）；
// Rust 侧实现：kernel-rs/iweb-kernel/src/wasm_snapshot_fd.rs。
//
// 能力边界（诚实声明，不得静默降级）：Node/Bun 均无 AF_UNIX SOCK_SEQPACKET 与
// recvmsg/SCM_RIGHTS ancillary 的原生 API（node:net 只有 SOCK_STREAM，node:dgram 只有
// SOCK_DGRAM 且无控制消息）。因此：
// 1. 本文件是该传输的**判定权威**（帧/拒绝/校验/digest），socket 原生循环
//    （SOCK_SEQPACKET bind/listen/accept、单 recvmsg、SCM_RIGHTS 提取、SO_PEERCRED、
//    fstat/F_GETFL）必须由 Linux 原生层提供——生产形态是 supervisor 进程内的原生
//    组件（Rust 模块同款语义已由 cargo 测试证明），或后续 native addon；
//    `snapshotFdTransportCapability()` 是显式能力探针，缺失即 fail-closed。
// 2. 原生层把一次 recvmsg 的事实（MSG_EOR/MSG_TRUNC/MSG_CTRUNC/cmsg 数/FD 数）与本
//    文件的纯函数对接；帧语义与拒绝规则与 spec 逐字一致，不因载体缺失而放松。
// 3. supervisor/wasm-control.ts 的 journal `snapshotHandoffDigest` 字段已预留非空
//    hex；原生循环落地后以 `computeSnapshotHandoffDigest` 的返回值写入（接线点：
// wasm-control.ts 的 appendReceived 内 `snapshotHandoffDigest: null` 处，本文件不改它）。
//
// 歧义备注（保守 fail-closed 取舍，供 review 对照）：
// 1. HTTP-on-raw 检测置于 magic 之前：`POST `/`GET ` 前缀或首行 `METHOD SP target SP
//    HTTP/x` 的包不可能同时携带合法 magic，先分类为 SNAPSHOT_HTTP_ON_RAW_SOCKET。
// 2. spec 打印的 framing 向量 header 字面量（30 个 hex 字符）与其自身规范性约束
//    （headerBytes:16、offset 12..15 的 u32-BE、total 35 = 16+19）矛盾；实现按 offset
//    表复算的唯一 32 字符 header 执行（见测试与 Rust 对拍的同款复算）。
// 3. applicationId 与 handoff 的 tuple 绑定由 Kernel ref 解析层保证（supervisor 视 ref
//    为 opaque）；supervisor 只对 command 可得字段做字节级相关性核验。
import {
	WASM_FAILURE_CODE_PATTERN,
	WASM_RFC3339_UTC_PATTERN,
	WASM_SNAPSHOT_FRAME_MAGIC_HEX,
	WASM_UUIDV7_PATTERN,
} from "../packages/contracts/wasm-execution.ts";
// 命令的摘要键（digestV2 域）与输入类型（单一 ExecutionCommand 形态）——handoff 的
// 命令相关性判定以唯一摘要域复算。
import { computeSupervisorExecutionCommandDigest, type SupervisorExecutionCommand } from "./wasm-spawn.ts";
import { jcsCanonicalBytes, sha256Hex, WASM_SHA256_HEX_PATTERN } from "../packages/contracts/wasm-package.ts";
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "../packages/contracts/validation.ts";

// ---------------------------------------------------------------------------
// 路径、帧常量与稳定错误码
// ---------------------------------------------------------------------------

export const SNAPSHOT_FD_SOCKET_PATH = "/run/iweb-sandbox/snapshot-fd.sock";
export const SNAPSHOT_FRAME_MAGIC: Buffer = Buffer.from(WASM_SNAPSHOT_FRAME_MAGIC_HEX, "hex");
export const SNAPSHOT_FRAME_HEADER_BYTES = 16;
export const SNAPSHOT_FRAME_VERSION = 1;
export const SNAPSHOT_MAX_PAYLOAD_BYTES = 65536;
export const SNAPSHOT_FRAME_TYPE_SECRET_REQUEST = 1;
export const SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST = 2;
export const SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT = 0x81;

// spec 已命名的 raw 传输稳定码。
export const SNAPSHOT_SOCKET_PATH_REJECTED = "SNAPSHOT_SOCKET_PATH_REJECTED";
export const SNAPSHOT_FRAME_INVALID = "SNAPSHOT_FRAME_INVALID";
export const SNAPSHOT_WIRE_INVALID = "SNAPSHOT_WIRE_INVALID";
export const SNAPSHOT_HTTP_ON_RAW_SOCKET = "SNAPSHOT_HTTP_ON_RAW_SOCKET";
export const SNAPSHOT_HANDOFF_ID_CONFLICT = "SNAPSHOT_HANDOFF_ID_CONFLICT";
export const SNAPSHOT_VALUES_DIGEST_MISMATCH = "SNAPSHOT_VALUES_DIGEST_MISMATCH";
export const SNAPSHOT_FD_POLICY_REJECTED = "SNAPSHOT_FD_POLICY_REJECTED";
export const SUPERVISOR_PEER_CREDENTIALS_REJECTED = "SUPERVISOR_PEER_CREDENTIALS_REJECTED";
// spec 已命名的过期码（secret/config 各一）。
export const IWEB_SECRET_SNAPSHOT_EXPIRED = "IWEB_SECRET_SNAPSHOT_EXPIRED";
export const IWEB_CONFIG_SNAPSHOT_EXPIRED = "IWEB_CONFIG_SNAPSHOT_EXPIRED";

export const SECRET_SNAPSHOT_DIGEST_DOMAIN = "iweb-secret-snapshot-v1";
export const CONFIG_SNAPSHOT_DIGEST_DOMAIN = "iweb-config-snapshot-v1";
export const SNAPSHOT_HANDOFF_DIGEST_DOMAIN = "iweb-snapshot-handoff-v1";

// ---------------------------------------------------------------------------
// 帧编解码（纯函数；预解析拒绝与 spec 逐字）
// ---------------------------------------------------------------------------

export type SnapshotFrameType = typeof SNAPSHOT_FRAME_TYPE_SECRET_REQUEST | typeof SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST | typeof SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT;

export interface SnapshotFrameHeader {
	readonly frameType: SnapshotFrameType;
	readonly payloadLength: number;
}

export type SnapshotFrameRejection = { readonly code: typeof SNAPSHOT_HTTP_ON_RAW_SOCKET | typeof SNAPSHOT_FRAME_INVALID; readonly message: string };

/** raw socket 收到 `POST `/`GET `/HTTP 头：先于 magic 分类（与合法 magic 互斥）。 */
export function rejectHttpOnRawSocket(packet: Uint8Array): SnapshotFrameRejection | null {
	const text = Buffer.from(packet.buffer, packet.byteOffset, Math.min(packet.byteLength, 8192)).toString("latin1");
	if (text.startsWith("POST ") || text.startsWith("GET ")) {
		return { code: SNAPSHOT_HTTP_ON_RAW_SOCKET, message: "the raw snapshot socket carries framed snapshot bytes only; an HTTP request preamble is rejected before any parsing" };
	}
	const firstLine = text.split("\r\n", 1)[0] ?? "";
	const parts = firstLine.split(" ");
	const looksLikeRequestLine =
		parts.length >= 3 &&
		parts[0].length > 0 &&
		parts[0].length <= 16 &&
		[...parts[0]].every((c) => c >= "A" && c <= "Z") &&
		parts[2].startsWith("HTTP/");
	if (looksLikeRequestLine || firstLine.startsWith("HTTP/")) {
		return { code: SNAPSHOT_HTTP_ON_RAW_SOCKET, message: "the raw snapshot socket carries framed snapshot bytes only; an HTTP header line is rejected before any parsing" };
	}
	return null;
}

/** 预解析帧头：HTTP 前缀 → magic → version → frameType → flags → length → 包边界。 */
export function parseSnapshotFdFrame(packet: Uint8Array): ValidationResult<SnapshotFrameHeader> {
	const http = rejectHttpOnRawSocket(packet);
	if (http !== null) return failure([issue(http.code, "", http.message)]);
	if (packet.byteLength < SNAPSHOT_FRAME_HEADER_BYTES) {
		return failure([issue(SNAPSHOT_FRAME_INVALID, "", "frame shorter than the fixed 16-byte header")]);
	}
	const view = Buffer.from(packet.buffer, packet.byteOffset, packet.byteLength);
	if (!view.subarray(0, 8).equals(SNAPSHOT_FRAME_MAGIC)) {
		return failure([issue(SNAPSHOT_FRAME_INVALID, "", "frame magic must be the ASCII bytes IWEBFD1 NUL")]);
	}
	const version = view.readUInt16BE(8);
	if (version !== SNAPSHOT_FRAME_VERSION) {
		return failure([issue(SNAPSHOT_FRAME_INVALID, "", "frame version must be exactly 1")]);
	}
	const frameTypeByte = view.readUInt8(10);
	let frameType: SnapshotFrameType;
	if (frameTypeByte === SNAPSHOT_FRAME_TYPE_SECRET_REQUEST) frameType = SNAPSHOT_FRAME_TYPE_SECRET_REQUEST;
	else if (frameTypeByte === SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST) frameType = SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST;
	else if (frameTypeByte === SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT) frameType = SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT;
	else {
		return failure([issue(SNAPSHOT_FRAME_INVALID, "", "frame type must be 1 (secret-request), 2 (config-request), or 0x81 (acknowledgement)")]);
	}
	if (view.readUInt8(11) !== 0) {
		return failure([issue(SNAPSHOT_FRAME_INVALID, "", "frame flags must be exactly 0")]);
	}
	const payloadLength = view.readUInt32BE(12);
	if (payloadLength < 1 || payloadLength > SNAPSHOT_MAX_PAYLOAD_BYTES) {
		return failure([issue(SNAPSHOT_FRAME_INVALID, "", "frame payloadLength must be between 1 and 65536 bytes")]);
	}
	if (packet.byteLength !== SNAPSHOT_FRAME_HEADER_BYTES + payloadLength) {
		return failure([issue(SNAPSHOT_FRAME_INVALID, "", "packet boundary must equal the fixed header plus payloadLength with no stream reassembly")]);
	}
	return ok({ frameType, payloadLength });
}

/** 编码完整帧（单一缓冲区；发送侧单 iovec 的物化基础）。 */
export function encodeSnapshotFdFrame(frameType: SnapshotFrameType, payload: Uint8Array): Buffer {
	if (payload.byteLength < 1 || payload.byteLength > SNAPSHOT_MAX_PAYLOAD_BYTES) {
		throw new Error(SNAPSHOT_FRAME_INVALID + ": frame payloadLength must be between 1 and 65536 bytes");
	}
	const frame = Buffer.alloc(SNAPSHOT_FRAME_HEADER_BYTES + payload.byteLength);
	SNAPSHOT_FRAME_MAGIC.copy(frame, 0);
	frame.writeUInt16BE(SNAPSHOT_FRAME_VERSION, 8);
	frame.writeUInt8(frameType, 10);
	frame.writeUInt8(0, 11);
	frame.writeUInt32BE(payload.byteLength, 12);
	Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength).copy(frame, SNAPSHOT_FRAME_HEADER_BYTES);
	return frame;
}

// ---------------------------------------------------------------------------
// recvmsg ancillary 判定（原生层供给事实；本层拥有全部拒绝规则）
// ---------------------------------------------------------------------------

export interface SnapshotRecvAncillaryFacts {
	/** MSG_EOR：完整记录（SOCK_SEQPACKET 每个包必须置位）。 */
	readonly eor: boolean;
	/** MSG_TRUNC。 */
	readonly truncated: boolean;
	/** MSG_CTRUNC。 */
	readonly controlTruncated: boolean;
	/** 控制消息条数（多于一条即 extra control messages）。 */
	readonly controlMessageCount: number;
	/** SCM_RIGHTS 送达的描述符总数。 */
	readonly descriptorCount: number;
}

/** 请求帧（frameType 1/2）：恰好一条 SCM_RIGHTS 控制消息、恰好一个描述符。 */
export function validateRequestAncillary(facts: SnapshotRecvAncillaryFacts): SnapshotFrameRejection | null {
	const common = validateCommonAncillary(facts);
	if (common !== null) return common;
	if (facts.controlMessageCount !== 1 || facts.descriptorCount !== 1) {
		return { code: SNAPSHOT_FRAME_INVALID, message: "a request frame requires exactly one SCM_RIGHTS control message carrying exactly one descriptor" };
	}
	return null;
}

/** ack 帧（frameType 0x81）：无任何 ancillary 描述符。 */
export function validateAckAncillary(facts: SnapshotRecvAncillaryFacts): SnapshotFrameRejection | null {
	const common = validateCommonAncillary(facts);
	if (common !== null) return common;
	if (facts.controlMessageCount !== 0 || facts.descriptorCount !== 0) {
		return { code: SNAPSHOT_FRAME_INVALID, message: "an acknowledgement frame must carry no ancillary descriptor" };
	}
	return null;
}

function validateCommonAncillary(facts: SnapshotRecvAncillaryFacts): SnapshotFrameRejection | null {
	if (!facts.eor) return { code: SNAPSHOT_FRAME_INVALID, message: "recvmsg must report MSG_EOR for a complete frame" };
	if (facts.truncated) return { code: SNAPSHOT_FRAME_INVALID, message: "recvmsg reported MSG_TRUNC; truncated frames are rejected" };
	if (facts.controlTruncated) return { code: SNAPSHOT_FRAME_INVALID, message: "recvmsg reported MSG_CTRUNC; truncated control data is rejected" };
	return null;
}

// ---------------------------------------------------------------------------
// digest 公式（域前缀单次 SHA-256；绝不二次 hash 十六进制串）
// ---------------------------------------------------------------------------

function domainDigest(domain: string, payload: Uint8Array): string {
	const prefixed = Buffer.concat([Buffer.from(domain + "\n", "utf8"), Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength)]);
	return sha256Hex(prefixed);
}

/** fdDigest = hex(SHA-256(UTF8("iweb-secret-snapshot-v1\n" || fdBytes)))（kind 对应域）。 */
export function computeSnapshotFdDigest(kind: "secret" | "config", fdBytes: Uint8Array): string {
	return domainDigest(kind === "secret" ? SECRET_SNAPSHOT_DIGEST_DOMAIN : CONFIG_SNAPSHOT_DIGEST_DOMAIN, fdBytes);
}

// ---------------------------------------------------------------------------
// handoff / ack payload 契约（typed JCS；字节必须等于 JCS(parse(bytes))）
// ---------------------------------------------------------------------------

export interface SecretSnapshotFdHandoffV1 {
	readonly schemaVersion: 1;
	readonly kind: "secret";
	readonly commandId: string;
	readonly commandDigest: string;
	readonly ref: string;
	readonly applicationId: string;
	readonly versionId: string;
	readonly preparationGeneration: number;
	readonly secretRevision: number;
	readonly valuesDigest: string;
	readonly fdDigest: string;
	readonly expiresAt: string;
}

export interface ConfigSnapshotFdHandoffV1 {
	readonly schemaVersion: 1;
	readonly kind: "config";
	readonly commandId: string;
	readonly commandDigest: string;
	readonly ref: string;
	readonly applicationId: string;
	readonly versionId: string;
	readonly preparationGeneration: number;
	readonly configRevision: number;
	readonly valuesDigest: string;
	readonly fdDigest: string;
	readonly expiresAt: string;
}

export type SnapshotHandoffPayload = SecretSnapshotFdHandoffV1 | ConfigSnapshotFdHandoffV1;

export interface SnapshotFdAckV1 {
	readonly schemaVersion: 1;
	readonly kind: "ack";
	readonly commandId: string;
	readonly handoffDigest: string;
	readonly status: "accepted" | "rejected";
	readonly failureCode: string | null;
	readonly journalRevision: number;
}

const WIRE_CODE = SNAPSHOT_WIRE_INVALID;

function requireExactHandoffKeys(input: Record<string, unknown>, kindFields: readonly string[], errors: ValidationIssue[]): void {
	for (const key of Object.keys(input)) {
		if (!kindFields.includes(key)) errors.push(issue(WIRE_CODE, "/" + key, "unknown field is not allowed"));
	}
	for (const key of kindFields) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(WIRE_CODE, "/" + key, "required field is missing"));
	}
}

function requireCommonHandoffFields(input: Record<string, unknown>, kindLiteral: "secret" | "config", errors: ValidationIssue[]): Record<string, unknown> | null {
	if (input.schemaVersion !== 1) errors.push(issue(WIRE_CODE, "/schemaVersion", "schemaVersion must be exactly 1"));
	if (input.kind !== kindLiteral) errors.push(issue(WIRE_CODE, "/kind", 'kind must be exactly "' + kindLiteral + '"'));
	if (typeof input.commandId !== "string" || !WASM_UUIDV7_PATTERN.test(input.commandId)) errors.push(issue(WIRE_CODE, "/commandId", "commandId must be a lower-case UUIDv7"));
	for (const field of ["commandDigest", "ref", "valuesDigest", "fdDigest"] as const) {
		if (typeof input[field] !== "string" || !WASM_SHA256_HEX_PATTERN.test(input[field])) {
			errors.push(issue(WIRE_CODE, "/" + field, field + " must be 64 lower-case hex characters"));
		}
	}
	if (typeof input.applicationId !== "string" || !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(input.applicationId)) {
		errors.push(issue(WIRE_CODE, "/applicationId", "applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"));
	}
	if (typeof input.versionId !== "string" || !/^[a-f0-9]{64}-[1-9][0-9]{0,15}$/.test(input.versionId)) {
		errors.push(issue(WIRE_CODE, "/versionId", "versionId must be <64 lower-case hex>-<positive sequence>"));
	}
	const preparationGeneration = input.preparationGeneration;
	if (typeof preparationGeneration !== "number" || !Number.isSafeInteger(preparationGeneration) || preparationGeneration < 1) {
		errors.push(issue(WIRE_CODE, "/preparationGeneration", "preparationGeneration must be a u53 integer >= 1"));
	}
	if (typeof input.expiresAt !== "string" || !WASM_RFC3339_UTC_PATTERN.test(input.expiresAt) || Number.isNaN(Date.parse(input.expiresAt))) {
		errors.push(issue(WIRE_CODE, "/expiresAt", "expiresAt must be RFC3339 UTC ending in Z"));
	}
	return null;
}

function parseCanonicalJcsPayload<T>(payload: Uint8Array, validate: (value: unknown) => ValidationResult<T>): ValidationResult<T> {
	const text = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength).toString("utf8");
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return failure([issue(WIRE_CODE, "", "payload bytes do not parse as JSON")]);
	}
	// JCS 字节权威：payload 必须逐字节等于 JCS(parse(bytes))（重复键由 JSON.parse 后写
	// 者胜出 + 字节比对拒绝；键序/白空格偏差同样拒绝）。
	if (Buffer.compare(Buffer.from(jcsCanonicalBytes(parsed)), Buffer.from(text, "utf8")) !== 0) {
		return failure([issue(WIRE_CODE, "", "payload bytes must equal JCS(parse(bytes)); reordered or non-canonical bytes are rejected")]);
	}
	return validate(parsed);
}

function requireSecretHandoff(input: unknown): ValidationResult<SecretSnapshotFdHandoffV1> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue(WIRE_CODE, "", "secret handoff payload must be an object")]);
	requireExactHandoffKeys(input, ["schemaVersion", "kind", "commandId", "commandDigest", "ref", "applicationId", "versionId", "preparationGeneration", "secretRevision", "valuesDigest", "fdDigest", "expiresAt"], errors);
	requireCommonHandoffFields(input, "secret", errors);
	if (typeof input.secretRevision !== "number" || !Number.isSafeInteger(input.secretRevision) || input.secretRevision < 0) {
		errors.push(issue(WIRE_CODE, "/secretRevision", "secretRevision must be a u53 integer"));
	}
	if (errors.length) return failure(errors);
	return ok(input as unknown as SecretSnapshotFdHandoffV1);
}

function requireConfigHandoff(input: unknown): ValidationResult<ConfigSnapshotFdHandoffV1> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue(WIRE_CODE, "", "config handoff payload must be an object")]);
	requireExactHandoffKeys(input, ["schemaVersion", "kind", "commandId", "commandDigest", "ref", "applicationId", "versionId", "preparationGeneration", "configRevision", "valuesDigest", "fdDigest", "expiresAt"], errors);
	requireCommonHandoffFields(input, "config", errors);
	if (typeof input.configRevision !== "number" || !Number.isSafeInteger(input.configRevision) || input.configRevision < 0) {
		errors.push(issue(WIRE_CODE, "/configRevision", "configRevision must be a u53 integer"));
	}
	if (errors.length) return failure(errors);
	return ok(input as unknown as ConfigSnapshotFdHandoffV1);
}

function requireAckPayload(input: unknown): ValidationResult<SnapshotFdAckV1> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue(WIRE_CODE, "", "acknowledgement payload must be an object")]);
	requireExactHandoffKeys(input, ["schemaVersion", "kind", "commandId", "handoffDigest", "status", "failureCode", "journalRevision"], errors);
	if (input.schemaVersion !== 1) errors.push(issue(WIRE_CODE, "/schemaVersion", "schemaVersion must be exactly 1"));
	if (input.kind !== "ack") errors.push(issue(WIRE_CODE, "/kind", 'kind must be exactly "ack"'));
	if (typeof input.commandId !== "string" || !WASM_UUIDV7_PATTERN.test(input.commandId)) errors.push(issue(WIRE_CODE, "/commandId", "commandId must be a lower-case UUIDv7"));
	if (typeof input.handoffDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.handoffDigest)) errors.push(issue(WIRE_CODE, "/handoffDigest", "handoffDigest must be 64 lower-case hex characters"));
	if (input.status !== "accepted" && input.status !== "rejected") errors.push(issue(WIRE_CODE, "/status", "status must be accepted or rejected"));
	if (typeof input.journalRevision !== "number" || !Number.isSafeInteger(input.journalRevision) || input.journalRevision < 0) {
		errors.push(issue(WIRE_CODE, "/journalRevision", "journalRevision must be a u53 integer"));
	}
	// failureCode 为 null 当且仅当 status 为 accepted；非空时匹配稳定码文法。
	if (input.status === "accepted" && input.failureCode !== null) errors.push(issue(WIRE_CODE, "/failureCode", "an accepted acknowledgement must carry failureCode null"));
	if (input.status === "rejected") {
		if (typeof input.failureCode !== "string") errors.push(issue(WIRE_CODE, "/failureCode", "a rejected acknowledgement must carry a bounded failureCode"));
		else if (!WASM_FAILURE_CODE_PATTERN.test(input.failureCode)) errors.push(issue(WIRE_CODE, "/failureCode", "failureCode must match ^[A-Z][A-Z0-9_]{0,63}$"));
	}
	if (errors.length) return failure(errors);
	return ok(input as unknown as SnapshotFdAckV1);
}

/** frameType 与 JCS kind 必须一致（1↔secret，2↔config；0x81 不是 handoff）。 */
export function parseSnapshotHandoffPayload(frameType: SnapshotFrameType, payload: Uint8Array): ValidationResult<SnapshotHandoffPayload> {
	if (frameType === SNAPSHOT_FRAME_TYPE_SECRET_REQUEST) return parseCanonicalJcsPayload(payload, requireSecretHandoff);
	if (frameType === SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST) return parseCanonicalJcsPayload(payload, requireConfigHandoff);
	return failure([issue(WIRE_CODE, "", "an acknowledgement payload is not a snapshot handoff")]);
}

export function parseSnapshotFdAckPayload(frameType: SnapshotFrameType, payload: Uint8Array): ValidationResult<SnapshotFdAckV1> {
	if (frameType !== SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT) {
		return failure([issue(WIRE_CODE, "", "an acknowledgement payload requires frameType 0x81")]);
	}
	return parseCanonicalJcsPayload(payload, requireAckPayload);
}

export function snapshotHandoffJcsBytes(handoff: SnapshotHandoffPayload): Uint8Array {
	return jcsCanonicalBytes(handoff);
}

/** handoffDigest = hex(SHA-256(UTF8("iweb-snapshot-handoff-v1\n" || JCS(request payload))))。 */
export function computeSnapshotHandoffDigest(handoff: SnapshotHandoffPayload): string {
	return domainDigest(SNAPSHOT_HANDOFF_DIGEST_DOMAIN, snapshotHandoffJcsBytes(handoff));
}

/** 发送侧构造请求帧（原生层单 sendmsg/单 iovec/单 SCM_RIGHTS 的载荷物化）。 */
export function encodeSnapshotHandoffFrame(handoff: SnapshotHandoffPayload): Buffer {
	return encodeSnapshotFdFrame(handoff.kind === "secret" ? SNAPSHOT_FRAME_TYPE_SECRET_REQUEST : SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST, snapshotHandoffJcsBytes(handoff));
}

/** supervisor 回 ack 帧（frameType 0x81，无 ancillary）。 */
export function encodeSnapshotAckFrame(ack: SnapshotFdAckV1): Buffer {
	return encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT, jcsCanonicalBytes(ack));
}

// ---------------------------------------------------------------------------
// supervisor 端 handoff 接受编排（命令相关性 + FD 策略 + 摘要链 + 过期窗口）
// ---------------------------------------------------------------------------

/** 原生层对收到的描述符供给的 fstat/F_GETFL 事实。 */
export interface SnapshotDescriptorFacts {
	/** fstat: S_ISREG。 */
	readonly regularFile: boolean;
	/** fcntl(F_GETFL) 的 access mode 是 O_RDONLY。 */
	readonly readOnly: boolean;
}

export type SnapshotHandoffAcceptance =
	| { readonly ok: true; readonly handoffDigest: string }
	| { readonly ok: false; readonly code: string; readonly message: string };

/**
 * supervisor 接受 handoff 前的完整判定链（spec "Snapshot FD content is bound across
 * Kernel, supervisor, Podman, and wasmd" 的 supervisor 侧等式）：
 * commandId/commandDigest/ref/revision/valuesDigest/versionId/preparationGeneration 与
 * 命令字节级相关 → expiresAt 未过（handoff 窗口语义）→ 描述符策略（regular +
 * read-only）→ fdDigest 复算并等于 valuesDigest。通过即返回 handoffDigest（journal
 * 的 snapshotHandoffDigest 非空来源）。
 */
export function validateSnapshotHandoffAcceptance(input: {
	readonly command: SupervisorExecutionCommand;
	readonly handoff: SnapshotHandoffPayload;
	readonly descriptorFacts: SnapshotDescriptorFacts;
	readonly fdBytes: Uint8Array;
	readonly now: string;
}): SnapshotHandoffAcceptance {
	const command = input.command;
	const handoff = input.handoff;
	// 摘要键 = digestV2("iweb-wasm-execution-command-v2", JCS(command))（design 域表）。
	const commandDigest = computeSupervisorExecutionCommandDigest(command);

	// 1) 命令相关性（SNAPSHOT_HANDOFF_ID_CONFLICT：commandDigest/tuple/ref/valuesDigest 分歧）。
	if (handoff.commandId !== command.commandId || handoff.commandDigest !== commandDigest) {
		return { ok: false, code: SNAPSHOT_HANDOFF_ID_CONFLICT, message: "handoff commandId or commandDigest does not match the accepted execution command" };
	}
	if (handoff.kind === "secret") {
		if (handoff.ref !== command.secretSnapshotRef || handoff.valuesDigest !== command.secretValuesDigest || handoff.secretRevision !== command.secretRevision) {
			return { ok: false, code: SNAPSHOT_HANDOFF_ID_CONFLICT, message: "secret handoff ref, valuesDigest, or revision does not match the command snapshot binding" };
		}
	} else {
		if (command.configSnapshotRef === null || command.configValuesDigest === null) {
			return { ok: false, code: SNAPSHOT_HANDOFF_ID_CONFLICT, message: "a config handoff was sent for a command with configRevision 0" };
		}
		if (handoff.ref !== command.configSnapshotRef || handoff.valuesDigest !== command.configValuesDigest || handoff.configRevision !== command.configRevision) {
			return { ok: false, code: SNAPSHOT_HANDOFF_ID_CONFLICT, message: "config handoff ref, valuesDigest, or revision does not match the command snapshot binding" };
		}
	}
	if (handoff.versionId !== command.identity.versionId || handoff.preparationGeneration !== command.identity.preparationGeneration) {
		return { ok: false, code: SNAPSHOT_HANDOFF_ID_CONFLICT, message: "handoff execution tuple does not match the command identity fence" };
	}

	// 2) 过期窗口（handoff/adopt 前；激活后的执行不受此限——由 Kernel activation 层保证）。
	if (Date.parse(input.now) >= Date.parse(handoff.expiresAt)) {
		return {
			ok: false,
			code: handoff.kind === "secret" ? IWEB_SECRET_SNAPSHOT_EXPIRED : IWEB_CONFIG_SNAPSHOT_EXPIRED,
			message: "the snapshot handoff window has expired; no descriptor is retained",
		};
	}

	// 3) 描述符策略：fstat regular + F_GETFL read-only。
	if (!input.descriptorFacts.regularFile || !input.descriptorFacts.readOnly) {
		return { ok: false, code: SNAPSHOT_FD_POLICY_REJECTED, message: "the received descriptor must reference a regular read-only file" };
	}

	// 4) 摘要链：fdDigest(域前缀单次 SHA-256(fdBytes)) == handoff.fdDigest == valuesDigest。
	const recomputed = computeSnapshotFdDigest(handoff.kind, input.fdBytes);
	if (recomputed !== handoff.fdDigest || recomputed !== handoff.valuesDigest) {
		return { ok: false, code: SNAPSHOT_VALUES_DIGEST_MISMATCH, message: "the descriptor bytes digest does not equal the handoff fdDigest and command valuesDigest" };
	}

	return { ok: true, handoffDigest: computeSnapshotHandoffDigest(handoff) };
}

// ---------------------------------------------------------------------------
// 原生能力探针（诚实边界；缺失即 fail-closed，绝不降级到其它 socket 类型）
// ---------------------------------------------------------------------------

export interface SnapshotFdTransportCapability {
	readonly seqpacket: false;
	readonly scmRightsRecv: false;
	readonly peerCredentials: false;
	readonly reason: string;
}

let cachedCapability: SnapshotFdTransportCapability | null = null;

/** Node/Bun 无 AF_UNIX SOCK_SEQPACKET / SCM_RIGHTS / SO_PEERCRED 原生 API（探针恒假）。 */
export function snapshotFdTransportCapability(): SnapshotFdTransportCapability {
	if (cachedCapability === null) {
		cachedCapability = {
			seqpacket: false,
			scmRightsRecv: false,
			peerCredentials: false,
			reason:
				"Node/Bun expose no AF_UNIX SOCK_SEQPACKET socket and no recvmsg/SCM_RIGHTS ancillary or SO_PEERCRED API; the raw snapshot-fd socket loop must be provided by the native supervisor component (same semantics as kernel-rs/iweb-kernel/src/wasm_snapshot_fd.rs) and wired to this decision layer",
		};
	}
	return cachedCapability;
}

/** 配置路径必须逐字节等于固定字面量（空/相对/备选一律拒绝，无 fallback）。 */
export function validateConfiguredSnapshotSocketPath(configured: string): SnapshotFrameRejection | null {
	if (configured !== SNAPSHOT_FD_SOCKET_PATH) {
		return { code: SNAPSHOT_SOCKET_PATH_REJECTED, message: "the snapshot fd socket path must equal the fixed literal /run/iweb-sandbox/snapshot-fd.sock; empty, relative, alternate, symlinked, or TCP paths are rejected with no fallback" };
	}
	return null;
}
