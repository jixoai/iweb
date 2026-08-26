// 用户原始需求（2026-08-26，add-wasm-runtime 任务 7.3 + 7.4）：SnapshotFdTransportV1 的
// supervisor 判定层向量——固定 framing vector 复算、预解析拒绝（magic/version/flags/
// length/边界/frameType）、ancillary 事实矩阵（MSG_EOR 必须、TRUNC/CTRUNC/多余 cmsg/
// 缺失或多于一个 FD 拒绝）、HTTP 与 raw 双向互拒（raw 收 HTTP 负例；HTTP 收 raw magic
// 由 tests/wasm-execution-rpc.test.ts 的 W7 向量覆盖）、handoff/ack payload 契约（JCS
// 字节权威、kind-frameType 一致、digest 公式）、command 相关性与 FD 策略/过期窗口。
// 正交意图：负例断言稳定错误码而非字符串匹配；digest 用 node:crypto 手拼 preimage
// 独立 oracle；Rust 对拍实现（kernel-rs/iweb-kernel/src/wasm_snapshot_fd.rs）持有同套
// 向量，跨实现字节一致。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { exampleExecutionCommandV1, computeExecutionCommandDigestV1, type ExecutionCommandV1 } from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";
import {
	computeSnapshotFdDigest,
	computeSnapshotHandoffDigest,
	encodeSnapshotAckFrame,
	encodeSnapshotFdFrame,
	encodeSnapshotHandoffFrame,
	IWEB_CONFIG_SNAPSHOT_EXPIRED,
	IWEB_SECRET_SNAPSHOT_EXPIRED,
	parseSnapshotFdAckPayload,
	parseSnapshotFdFrame,
	parseSnapshotHandoffPayload,
	SNAPSHOT_FD_SOCKET_PATH,
	SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT,
	SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST,
	SNAPSHOT_FRAME_TYPE_SECRET_REQUEST,
	SNAPSHOT_HANDOFF_ID_CONFLICT,
	SNAPSHOT_HTTP_ON_RAW_SOCKET,
	SNAPSHOT_FD_POLICY_REJECTED,
	SNAPSHOT_FRAME_INVALID,
	SNAPSHOT_SOCKET_PATH_REJECTED,
	SNAPSHOT_VALUES_DIGEST_MISMATCH,
	SNAPSHOT_WIRE_INVALID,
	snapshotFdTransportCapability,
	validateAckAncillary,
	validateConfiguredSnapshotSocketPath,
	validateRequestAncillary,
	validateSnapshotHandoffAcceptance,
	type ConfigSnapshotFdHandoffV1,
	type SecretSnapshotFdHandoffV1,
	type SnapshotDescriptorFacts,
	type SnapshotRecvAncillaryFacts,
} from "../supervisor/snapshot-fd.ts";

// spec 打印的 header 字面量 `495745424644310000010100000013`（30 hex 字符）与其自身
// 规范性约束矛盾（headerBytes:16、offset 12..15 的 u32-BE 长度、同句 total 35 = 16+19）；
// 按规范性 offset 表复算的唯一 header 是 32 字符（u32-BE 19 = 00000013，打印字面量恰
// 好少了长度域一对 "00"）。实现以 offset 表 + total 35 为准；Rust 对拍同款复算。
const VECTOR_PAYLOAD_HEX = "7b22736368656d6156657273696f6e223a317d";
const VECTOR_HEADER_HEX = "49574542464431000001010000000013";

const factsRequestOk: SnapshotRecvAncillaryFacts = { eor: true, truncated: false, controlTruncated: false, controlMessageCount: 1, descriptorCount: 1 };
const descriptorOk: SnapshotDescriptorFacts = { regularFile: true, readOnly: true };

function sha256HexOracle(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

function domainDigestOracle(domain: string, bytes: Uint8Array): string {
	return sha256HexOracle(Buffer.concat([Buffer.from(domain + "\n", "utf8"), Buffer.from(bytes)]));
}

// spec 摘要等式链要求 command.*ValuesDigest == handoff.valuesDigest == fdDigest(fdBytes)：
// 构造与两种 fd 字节真实绑定的命令（secret/config 各自的域前缀与 payload 字节）。
function buildCommandWithBoundDigestes(): { command: ExecutionCommandV1; secretFdBytes: Buffer; configFdBytes: Buffer } {
	const base = exampleExecutionCommandV1();
	const secretFdBytes = Buffer.from(jcsCanonicalBytes({ applicationId: "vector", versionId: base.identity.versionId, preparationGeneration: 1, secretRevision: base.secretRevision, keys: [], values: {} }));
	const configFdBytes = Buffer.from(jcsCanonicalBytes({ applicationId: "vector", versionId: base.identity.versionId, preparationGeneration: 1, configRevision: base.configRevision, keys: [], values: {} }));
	return {
		command: {
			...base,
			secretValuesDigest: computeSnapshotFdDigest("secret", secretFdBytes),
			configValuesDigest: computeSnapshotFdDigest("config", configFdBytes),
		},
		secretFdBytes,
		configFdBytes,
	};
}

function exampleSecretHandoff(command: ExecutionCommandV1, fdBytes: Uint8Array): SecretSnapshotFdHandoffV1 {
	return {
		schemaVersion: 1,
		kind: "secret",
		commandId: command.commandId,
		commandDigest: computeExecutionCommandDigestV1(command),
		ref: command.secretSnapshotRef,
		applicationId: "vector",
		versionId: command.identity.versionId,
		preparationGeneration: command.identity.preparationGeneration,
		secretRevision: command.secretRevision,
		valuesDigest: command.secretValuesDigest,
		fdDigest: computeSnapshotFdDigest("secret", fdBytes),
		expiresAt: "2026-09-01T00:00:00Z",
	};
}

function exampleConfigHandoff(command: ExecutionCommandV1, fdBytes: Uint8Array): ConfigSnapshotFdHandoffV1 {
	if (command.configSnapshotRef === null || command.configValuesDigest === null) throw new Error("example command must carry a config binding");
	return {
		schemaVersion: 1,
		kind: "config",
		commandId: command.commandId,
		commandDigest: computeExecutionCommandDigestV1(command),
		ref: command.configSnapshotRef,
		applicationId: "vector",
		versionId: command.identity.versionId,
		preparationGeneration: command.identity.preparationGeneration,
		configRevision: command.configRevision,
		valuesDigest: command.configValuesDigest,
		fdDigest: computeSnapshotFdDigest("config", fdBytes),
		expiresAt: "2026-09-01T00:00:00Z",
	};
}

describe("SnapshotFdTransportV1 framing", () => {
	test("the fixed vector is byte-exact: 16-byte header, 19-byte payload, 35-byte total", () => {
		const payload = Buffer.from(VECTOR_PAYLOAD_HEX, "hex");
		expect(payload.toString("utf8")).toBe('{"schemaVersion":1}');
		const frame = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, payload);
		expect(frame.byteLength).toBe(35);
		expect(frame.subarray(0, 16).toString("hex")).toBe(VECTOR_HEADER_HEX);
		expect(frame.toString("hex")).toBe(VECTOR_HEADER_HEX + VECTOR_PAYLOAD_HEX);
		const header = parseSnapshotFdFrame(frame);
		expect(header.ok).toBe(true);
		if (header.ok) {
			expect(header.value.frameType).toBe(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST);
			expect(header.value.payloadLength).toBe(19);
		}
	});

	test("the vector boundary is accepted, then the payload is rejected as SNAPSHOT_WIRE_INVALID", () => {
		const frame = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, Buffer.from(VECTOR_PAYLOAD_HEX, "hex"));
		const header = parseSnapshotFdFrame(frame);
		expect(header.ok).toBe(true);
		expect(validateRequestAncillary(factsRequestOk)).toBeNull();
		if (!header.ok) throw new Error("unreachable");
		const rejected = parseSnapshotHandoffPayload(header.value.frameType, frame.subarray(16));
		expect(rejected.ok).toBe(false);
		if (!rejected.ok) expect(rejected.errors[0].code).toBe(SNAPSHOT_WIRE_INVALID);
	});

	test("appending one byte changes the expected total length and returns SNAPSHOT_FRAME_INVALID", () => {
		const frame = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, Buffer.from(VECTOR_PAYLOAD_HEX, "hex"));
		const rejected = parseSnapshotFdFrame(Buffer.concat([frame, Buffer.from([0])]));
		expect(rejected.ok).toBe(false);
		if (!rejected.ok) expect(rejected.errors[0].code).toBe(SNAPSHOT_FRAME_INVALID);
	});

	test("wrong magic, version, flags, length, boundary, or frame type are pre-parse rejections", () => {
		const base = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, Buffer.from('{"schemaVersion":1}', "utf8"));
		const mutate = (fn: (frame: Buffer) => void): Buffer => {
			const copy = Buffer.from(base);
			fn(copy);
			return copy;
		};
		const cases: Array<[Buffer, string]> = [
			[mutate((f) => { f[0] = 0x58; }), "wrong magic"],
			[mutate((f) => { f.writeUInt16BE(2, 8); }), "wrong version"],
			[mutate((f) => { f.writeUInt8(1, 11); }), "wrong flags"],
			[mutate((f) => { f.writeUInt32BE(0, 12); }), "zero length"],
			[mutate((f) => { f.writeUInt32BE(65537, 12); }), "oversize length"],
			[mutate((f) => { f.writeUInt8(3, 10); }), "unknown frame type"],
			[Buffer.from(base.subarray(0, 10)), "shorter than header"],
			[mutate((f) => { f.writeUInt32BE(20, 12); }), "header length disagrees with packet"],
		];
		for (const [packet, label] of cases) {
			const rejected = parseSnapshotFdFrame(packet);
			expect(rejected.ok).toBe(false);
			if (!rejected.ok) {
				expect(rejected.errors[0].code).toBe(SNAPSHOT_FRAME_INVALID);
				expect(label).toBeTruthy();
			}
		}
		// 0x81 是合法 framing（ack 帧）：请求语义的拒绝发生在 payload 层——
		// parseSnapshotHandoffPayload 必须拒绝把它当 handoff。
		const ackTyped = mutate((f) => { f.writeUInt8(SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT, 10); });
		const ackHeader = parseSnapshotFdFrame(ackTyped);
		expect(ackHeader.ok).toBe(true);
		if (!ackHeader.ok) throw new Error("unreachable");
		const notAHandoff = parseSnapshotHandoffPayload(ackHeader.value.frameType, ackTyped.subarray(16));
		expect(notAHandoff.ok).toBe(false);
		if (!notAHandoff.ok) expect(notAHandoff.errors[0].code).toBe(SNAPSHOT_WIRE_INVALID);
	});

	test("encode rejects out-of-range payload lengths", () => {
		expect(() => encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, Buffer.alloc(0))).toThrow();
		expect(() => encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, Buffer.alloc(65537))).toThrow();
		const maxFrame = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, Buffer.alloc(65536));
		expect(maxFrame.byteLength).toBe(16 + 65536);
	});
});

describe("SnapshotFdTransportV1 HTTP/raw mutual rejection", () => {
	test("POST, GET, and HTTP header lines on the raw socket are SNAPSHOT_HTTP_ON_RAW_SOCKET", () => {
		const packets = [
			Buffer.from("POST /v1/execution-rpc HTTP/1.1\r\nHost: supervisor\r\n\r\n"),
			Buffer.from("GET /v1/rpc HTTP/1.1\r\nHost: supervisor\r\n\r\n"),
			Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		];
		for (const packet of packets) {
			const rejected = parseSnapshotFdFrame(packet);
			expect(rejected.ok).toBe(false);
			if (!rejected.ok) expect(rejected.errors[0].code).toBe(SNAPSHOT_HTTP_ON_RAW_SOCKET);
		}
	});

	test("the HTTP-side negative (raw magic rejected by /v1/rpc and /v1/execution-rpc) is covered by the W7 vector", () => {
		// 见 tests/wasm-execution-rpc.test.ts "the raw snapshot frame magic is rejected on
		// both endpoints before body parsing"（CELLD_PROTOCOL_MISMATCH 与
		// EXECUTION_HTTP_FRAME_REJECTED）；此处仅钉住两向量共享同一 magic 常量来源。
		expect(Buffer.from("4957454246443100", "hex").toString("latin1")).toBe("IWEBFD1\0");
	});
});

describe("SnapshotFdTransportV1 ancillary facts", () => {
	test("missing MSG_EOR, truncation, extra control messages, and wrong descriptor counts are SNAPSHOT_FRAME_INVALID", () => {
		expect(validateRequestAncillary({ ...factsRequestOk, eor: false })?.code).toBe(SNAPSHOT_FRAME_INVALID);
		expect(validateRequestAncillary({ ...factsRequestOk, truncated: true })?.code).toBe(SNAPSHOT_FRAME_INVALID);
		expect(validateRequestAncillary({ ...factsRequestOk, controlTruncated: true })?.code).toBe(SNAPSHOT_FRAME_INVALID);
		expect(validateRequestAncillary({ ...factsRequestOk, descriptorCount: 0 })?.code).toBe(SNAPSHOT_FRAME_INVALID);
		expect(validateRequestAncillary({ ...factsRequestOk, descriptorCount: 2 })?.code).toBe(SNAPSHOT_FRAME_INVALID);
		expect(validateRequestAncillary({ ...factsRequestOk, controlMessageCount: 2 })?.code).toBe(SNAPSHOT_FRAME_INVALID);

		const ackFacts: SnapshotRecvAncillaryFacts = { eor: true, truncated: false, controlTruncated: false, controlMessageCount: 0, descriptorCount: 0 };
		expect(validateAckAncillary(ackFacts)).toBeNull();
		expect(validateAckAncillary({ ...ackFacts, descriptorCount: 1 })?.code).toBe(SNAPSHOT_FRAME_INVALID);
		expect(validateAckAncillary({ ...ackFacts, controlMessageCount: 1, descriptorCount: 0 })?.code).toBe(SNAPSHOT_FRAME_INVALID);
		expect(validateAckAncillary({ ...ackFacts, eor: false })?.code).toBe(SNAPSHOT_FRAME_INVALID);
	});
});

describe("SnapshotFdTransportV1 handoff and acknowledgement payloads", () => {
	const { command, secretFdBytes, configFdBytes } = buildCommandWithBoundDigestes();

	test("secret and config handoffs round-trip with kind/frameType agreement", () => {
		const secret = exampleSecretHandoff(command, secretFdBytes);
		const secretFrame = encodeSnapshotHandoffFrame(secret);
		const secretHeader = parseSnapshotFdFrame(secretFrame);
		expect(secretHeader.ok && secretHeader.value.frameType).toBe(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST);
		if (!secretHeader.ok) throw new Error("unreachable");
		const parsedSecret = parseSnapshotHandoffPayload(secretHeader.value.frameType, secretFrame.subarray(16));
		expect(parsedSecret.ok).toBe(true);
		if (parsedSecret.ok) expect(parsedSecret.value).toEqual(secret);

		const config = exampleConfigHandoff(command, configFdBytes);
		const configFrame = encodeSnapshotHandoffFrame(config);
		const configHeader = parseSnapshotFdFrame(configFrame);
		expect(configHeader.ok && configHeader.value.frameType).toBe(SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST);
		if (!configHeader.ok) throw new Error("unreachable");
		const parsedConfig = parseSnapshotHandoffPayload(configHeader.value.frameType, configFrame.subarray(16));
		expect(parsedConfig.ok).toBe(true);
		if (parsedConfig.ok) expect(parsedConfig.value).toEqual(config);

		// kind 与 frameType 交叉：secret payload 放进 config 帧。
		const crossed = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST, jcsCanonicalBytes(secret));
		const crossedHeader = parseSnapshotFdFrame(crossed);
		expect(crossedHeader.ok).toBe(true);
		if (!crossedHeader.ok) throw new Error("unreachable");
		const rejected = parseSnapshotHandoffPayload(crossedHeader.value.frameType, crossed.subarray(16));
		expect(rejected.ok).toBe(false);
		if (!rejected.ok) expect(rejected.errors[0].code).toBe(SNAPSHOT_WIRE_INVALID);
	});

	test("unknown fields and non-canonical JCS bytes are SNAPSHOT_WIRE_INVALID", () => {
		const secret = exampleSecretHandoff(command, secretFdBytes);
		const withExtra = { ...secret, extra: 1 } as unknown;
		const extraFrame = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, jcsCanonicalBytes(withExtra));
		const extraHeader = parseSnapshotFdFrame(extraFrame);
		if (!extraHeader.ok) throw new Error("unreachable");
		const rejectedExtra = parseSnapshotHandoffPayload(extraHeader.value.frameType, extraFrame.subarray(16));
		expect(rejectedExtra.ok).toBe(false);
		if (!rejectedExtra.ok) expect(rejectedExtra.errors[0].code).toBe(SNAPSHOT_WIRE_INVALID);

		// 非 JCS 字节：手工反转前两个键的顺序（canonical 是 applicationId 在前）。
		const canonical = jcsCanonicalBytes(secret);
		const text = canonical.toString("utf8");
		const reordered = text.replace(/^\{"applicationId":"vector","commandDigest":"([0-9a-f]{64})",/, '{"commandId":"' + secret.commandId + '","commandDigest":"$1",').replace(',"commandId":"' + secret.commandId + '"', "");
		expect(reordered).not.toBe(text);
		const reorderedFrame = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_SECRET_REQUEST, Buffer.from(reordered, "utf8"));
		const reorderedHeader = parseSnapshotFdFrame(reorderedFrame);
		if (!reorderedHeader.ok) throw new Error("unreachable");
		const rejectedReordered = parseSnapshotHandoffPayload(reorderedHeader.value.frameType, reorderedFrame.subarray(16));
		expect(rejectedReordered.ok).toBe(false);
		if (!rejectedReordered.ok) expect(rejectedReordered.errors[0].code).toBe(SNAPSHOT_WIRE_INVALID);
	});

	test("the acknowledgement payload contract enforces status/failureCode coupling and bounded codes", () => {
		const handoff = exampleSecretHandoff(command, secretFdBytes);
		const ack = {
			schemaVersion: 1 as const,
			kind: "ack" as const,
			commandId: handoff.commandId,
			handoffDigest: computeSnapshotHandoffDigest(handoff),
			status: "accepted" as const,
			failureCode: null,
			journalRevision: 5,
		};
		const frame = encodeSnapshotAckFrame(ack);
		const header = parseSnapshotFdFrame(frame);
		expect(header.ok && header.value.frameType).toBe(SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT);
		if (!header.ok) throw new Error("unreachable");
		const parsed = parseSnapshotFdAckPayload(header.value.frameType, frame.subarray(16));
		expect(parsed.ok).toBe(true);
		if (parsed.ok) expect(parsed.value).toEqual(ack);

		const badVariants: Array<Record<string, unknown>> = [
			{ ...ack, status: "rejected", failureCode: null },
			{ ...ack, status: "rejected", failureCode: "lower-case" },
			{ ...ack, failureCode: "SNAPSHOT_FRAME_INVALID" },
			{ ...ack, journalRevision: -1 },
		];
		for (const variant of badVariants) {
			const variantFrame = encodeSnapshotFdFrame(SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT, jcsCanonicalBytes(variant));
			const variantHeader = parseSnapshotFdFrame(variantFrame);
			if (!variantHeader.ok) throw new Error("unreachable");
			const rejected = parseSnapshotFdAckPayload(variantHeader.value.frameType, variantFrame.subarray(16));
			expect(rejected.ok).toBe(false);
			if (!rejected.ok) expect(rejected.errors[0].code).toBe(SNAPSHOT_WIRE_INVALID);
		}
	});

	test("digest formulas are domain-separated single SHA-256 operations", () => {
		expect(computeSnapshotFdDigest("secret", secretFdBytes)).toBe(domainDigestOracle("iweb-secret-snapshot-v1", secretFdBytes));
		expect(computeSnapshotFdDigest("config", configFdBytes)).toBe(domainDigestOracle("iweb-config-snapshot-v1", configFdBytes));
		expect(computeSnapshotFdDigest("secret", secretFdBytes)).not.toBe(computeSnapshotFdDigest("config", configFdBytes));
		const handoff = exampleSecretHandoff(command, secretFdBytes);
		expect(computeSnapshotHandoffDigest(handoff)).toBe(domainDigestOracle("iweb-snapshot-handoff-v1", jcsCanonicalBytes(handoff)));
	});
});

describe("supervisor handoff acceptance", () => {
	const bound = buildCommandWithBoundDigestes();
	const command = bound.command;
	const fdBytes = bound.secretFdBytes;

	test("a fully correlated secret handoff is accepted and yields the journal handoff digest", () => {
		const handoff = exampleSecretHandoff(command, fdBytes);
		const accepted = validateSnapshotHandoffAcceptance({ command, handoff, descriptorFacts: descriptorOk, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(accepted.ok).toBe(true);
		if (accepted.ok) expect(accepted.handoffDigest).toBe(computeSnapshotHandoffDigest(handoff));
	});

	test("a fully correlated config handoff is accepted", () => {
		const configHandoff = exampleConfigHandoff(command, bound.configFdBytes);
		const accepted = validateSnapshotHandoffAcceptance({ command, handoff: configHandoff, descriptorFacts: descriptorOk, fdBytes: bound.configFdBytes, now: "2026-08-26T00:00:00Z" });
		expect(accepted.ok).toBe(true);
	});

	test("command, tuple, ref, and values-digest conflicts are SNAPSHOT_HANDOFF_ID_CONFLICT", () => {
		const handoff = exampleSecretHandoff(command, fdBytes);
		const mutatedCommand: ExecutionCommandV1 = { ...command, secretSnapshotRef: "f".repeat(64) };
		const refConflict = validateSnapshotHandoffAcceptance({ command: mutatedCommand, handoff, descriptorFacts: descriptorOk, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(!refConflict.ok && refConflict.code).toBe(SNAPSHOT_HANDOFF_ID_CONFLICT);

		const wrongCommandId: SecretSnapshotFdHandoffV1 = { ...handoff, commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abce" };
		const idConflict = validateSnapshotHandoffAcceptance({ command, handoff: wrongCommandId, descriptorFacts: descriptorOk, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(!idConflict.ok && idConflict.code).toBe(SNAPSHOT_HANDOFF_ID_CONFLICT);

		const wrongGeneration: SecretSnapshotFdHandoffV1 = { ...handoff, preparationGeneration: handoff.preparationGeneration + 1 };
		const generationConflict = validateSnapshotHandoffAcceptance({ command, handoff: wrongGeneration, descriptorFacts: descriptorOk, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(!generationConflict.ok && generationConflict.code).toBe(SNAPSHOT_HANDOFF_ID_CONFLICT);

		// config/secret ref 交叉：把 config handoff 对到 secret 绑定（ref 不匹配即冲突）。
		const configHandoff = exampleConfigHandoff(command, fdBytes);
		const secretOnlyCommand: ExecutionCommandV1 = { ...command, configRevision: 0, configSnapshotRef: null, configValuesDigest: null };
		const crossKind = validateSnapshotHandoffAcceptance({ command: secretOnlyCommand, handoff: configHandoff, descriptorFacts: descriptorOk, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(!crossKind.ok && crossKind.code).toBe(SNAPSHOT_HANDOFF_ID_CONFLICT);
	});

	test("expired handoff windows fail with the kind-specific expiry code", () => {
		const secretHandoff = exampleSecretHandoff(command, fdBytes);
		const expiredSecret = validateSnapshotHandoffAcceptance({ command, handoff: secretHandoff, descriptorFacts: descriptorOk, fdBytes, now: "2026-09-02T00:00:00Z" });
		expect(!expiredSecret.ok && expiredSecret.code).toBe(IWEB_SECRET_SNAPSHOT_EXPIRED);

		const configHandoff = exampleConfigHandoff(command, fdBytes);
		const expiredConfig = validateSnapshotHandoffAcceptance({ command, handoff: configHandoff, descriptorFacts: descriptorOk, fdBytes, now: "2026-09-02T00:00:00Z" });
		expect(!expiredConfig.ok && expiredConfig.code).toBe(IWEB_CONFIG_SNAPSHOT_EXPIRED);
	});

	test("non-regular or writable descriptors are SNAPSHOT_FD_POLICY_REJECTED", () => {
		const handoff = exampleSecretHandoff(command, fdBytes);
		const nonRegular = validateSnapshotHandoffAcceptance({ command, handoff, descriptorFacts: { regularFile: false, readOnly: true }, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(!nonRegular.ok && nonRegular.code).toBe(SNAPSHOT_FD_POLICY_REJECTED);
		const writable = validateSnapshotHandoffAcceptance({ command, handoff, descriptorFacts: { regularFile: true, readOnly: false }, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(!writable.ok && writable.code).toBe(SNAPSHOT_FD_POLICY_REJECTED);
	});

	test("descriptor bytes that do not recompute the bound digests are SNAPSHOT_VALUES_DIGEST_MISMATCH", () => {
		const handoff = exampleSecretHandoff(command, fdBytes);
		const wrongBytes = Buffer.from(jcsCanonicalBytes({ applicationId: "tampered" }));
		const mismatch = validateSnapshotHandoffAcceptance({ command, handoff, descriptorFacts: descriptorOk, fdBytes: wrongBytes, now: "2026-08-26T00:00:00Z" });
		expect(!mismatch.ok && mismatch.code).toBe(SNAPSHOT_VALUES_DIGEST_MISMATCH);

		const wrongFieldDigest: SecretSnapshotFdHandoffV1 = { ...handoff, fdDigest: "0".repeat(64) };
		const fieldMismatch = validateSnapshotHandoffAcceptance({ command, handoff: wrongFieldDigest, descriptorFacts: descriptorOk, fdBytes, now: "2026-08-26T00:00:00Z" });
		expect(!fieldMismatch.ok && fieldMismatch.code).toBe(SNAPSHOT_VALUES_DIGEST_MISMATCH);
	});
});

describe("snapshot fd transport boundary declarations", () => {
	test("the native capability probe reports the Node/Bun boundary honestly", () => {
		const capability = snapshotFdTransportCapability();
		expect(capability.seqpacket).toBe(false);
		expect(capability.scmRightsRecv).toBe(false);
		expect(capability.peerCredentials).toBe(false);
		expect(capability.reason).toContain("SOCK_SEQPACKET");
	});

	test("only the fixed socket literal is accepted as the configured path", () => {
		expect(validateConfiguredSnapshotSocketPath(SNAPSHOT_FD_SOCKET_PATH)).toBeNull();
		for (const bad of ["", "/tmp/snapshot-fd.sock", "run/iweb-sandbox/snapshot-fd.sock", "/run/iweb-sandbox/snapshot-fd.sock/", "/run/iweb-sandbox/snapshot-fd.sock.extra"]) {
			expect(validateConfiguredSnapshotSocketPath(bad)?.code).toBe(SNAPSHOT_SOCKET_PATH_REJECTED);
		}
	});
});
