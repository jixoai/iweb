// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.2）：代次与绑定契约的 typed schema 必须有正/负向量——未知字段拒绝、u53 越界、非 JCS 排序数组拒绝、celld 旧信号拒绝、bootstrap 记录 digest 公式、CAS revision 冲突。
// 正交意图：负例断言稳定错误码而非字符串匹配；digest 用手拼 preimage 的独立 oracle；celld 既有 validator 行为保持全绿。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
	allocateWasmExecutionIdentity,
	checkControlRevisionCas,
	checkWasmExecutionFence,
	computeDrainReceiptDigestV1,
	computeExecutionCommandDigest,
	computeKindClaimBootstrapDigest,
	computeRuntimeKindClaimBindingDigest,
	CONTROL_REVISION_CONFLICT,
	correlateExecutionAcknowledgement,
	correlateExecutionRpcResponse,
	EXECUTION_COMMAND_INVALID,
	EXECUTION_RPC_PROTOCOL_LITERAL,
	exampleDrainReceiptV1,
	exampleExecutionAcknowledgement,
	exampleExecutionCommand,
	exampleKindClaimBootstrapV1,
	exampleNormalizedWasmManifestV1,
	exampleRuntimeBindingIdentityV1,
	exampleWasmControlStateFileV2,
	exampleWasmExecutionIdentityV1,
	initialWasmExecutionIdentity,
	isAliveWasmExecutionIdentity,
	matchesSecretRevisionFence,
	matchesWasmExecutionFence,
	nextSecretRevision,
	prepareWasmExecutionIdentity,
	runtimeBindingIdentityV2FromV1,
	validateCommandReceivedV1,
	validateDrainReceiptV1,
	validateExecutionAcknowledgement,
	validateExecutionCommand,
	validateExecutionRpcRequestEnvelopeV1,
	validateExecutionRpcResponseEnvelopeV1,
	validateKindClaimBootstrapV1,
	validateRuntimeBindingIdentityV1,
	validateRuntimeBindingIdentityV2,
	validateWasmApplicationControlRecordV1,
	validateWasmControlStateFileV2,
	validateWasmExecutionIdentityV1,
	WASM_FENCE_NONCE_PATTERN,
	WASM_GENERATION_EXHAUSTED,
	WASM_IDENTITY_INCOMPLETE,
	type DrainReceiptV1,
	type KindClaimBootstrapV1,
	type RuntimeKindClaimV1,
} from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalize, validateNormalizedWasmManifestV1 } from "../packages/contracts/wasm-package.ts";
import { carriesExecutionRpcFields, validateSupervisorRequest } from "../packages/contracts/protocol.ts";
import { validateRuntimeKind } from "../packages/contracts/records.ts";
import type { ValidationIssue, ValidationResult } from "../packages/contracts/validation.ts";

const VECTOR_VERSION_DIGEST = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";
const SPEC_VECTOR_MANIFEST_JCS =
	'{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}';
const REQUEST_ID = "018f1e2c-3d4b-7c6d-8e9f-001122334455";

function expectRejected(result: ValidationResult<unknown>): readonly ValidationIssue[] {
	expect(result.ok).toBe(false);
	if (result.ok) throw new Error("expected rejection");
	return result.errors;
}

function hasCode(errors: readonly ValidationIssue[], code: string): boolean {
	return errors.some((entry) => entry.code === code);
}

function roundTrip(value: unknown): unknown {
	return JSON.parse(JSON.stringify(value));
}

function sha256Text(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex");
}

describe("runtime binding identity", () => {
	test("round-trips the seven-field object through JSON", () => {
		const example = exampleRuntimeBindingIdentityV1();
		const result = validateRuntimeBindingIdentityV1(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);
	});

	test("rejects unknown and missing fields", () => {
		const extra = { ...exampleRuntimeBindingIdentityV1(), runtimeKind: "wasm" };
		expect(hasCode(expectRejected(validateRuntimeBindingIdentityV1(extra)), "WASM_BINDING_INVALID")).toBe(true);
		const missingWorld = { ...exampleRuntimeBindingIdentityV1() } as Record<string, unknown>;
		delete missingWorld.world;
		expectRejected(validateRuntimeBindingIdentityV1(missingWorld));
	});

	test("rejects out-of-range and non-integer revisions", () => {
		for (const catalogRevision of [0, -1, 1.5, 9007199254740992, "9"]) {
			expectRejected(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), catalogRevision }));
		}
		expect(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), catalogRevision: 9007199254740991 }).ok).toBe(true);
	});

	test("rejects grammar violations (entryKey, imageDigest, literals)", () => {
		expectRejected(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), entryKey: "1iweb" }));
		expectRejected(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), imageDigest: "sha256:" + "X".repeat(64) }));
		expectRejected(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), imageDigest: "0".repeat(64) }));
		expectRejected(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), world: "wasi:http/proxy@0.2.7" }));
		expectRejected(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), hostABI: "iweb-wasmd-abi@1.1.0" }));
		expectRejected(validateRuntimeBindingIdentityV1({ ...exampleRuntimeBindingIdentityV1(), kind: "celld" }));
	});
});

describe("wasm execution identity and dual-generation fence", () => {
	test("round-trips the (sandboxId, versionId, P, E) tuple", () => {
		const example = exampleWasmExecutionIdentityV1();
		const result = validateWasmExecutionIdentityV1(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);
	});

	test("rejects unknown/missing fields, bad sandbox grammar, and malformed versionId", () => {
		expectRejected(validateWasmExecutionIdentityV1({ ...exampleWasmExecutionIdentityV1(), generation: 4 }));
		const missing = { ...exampleWasmExecutionIdentityV1() } as Record<string, unknown>;
		delete missing.executionGeneration;
		expectRejected(validateWasmExecutionIdentityV1(missing));
		expectRejected(validateWasmExecutionIdentityV1({ ...exampleWasmExecutionIdentityV1(), sandboxId: "1sbx" }));
		// celld VersionRecord.versionId = digest（无 sequence 后缀）不是 wasm versionId。
		expectRejected(validateWasmExecutionIdentityV1({ ...exampleWasmExecutionIdentityV1(), versionId: VECTOR_VERSION_DIGEST }));
		expectRejected(validateWasmExecutionIdentityV1({ ...exampleWasmExecutionIdentityV1(), versionId: VECTOR_VERSION_DIGEST + "-01" }));
		expectRejected(validateWasmExecutionIdentityV1({ ...exampleWasmExecutionIdentityV1(), versionId: VECTOR_VERSION_DIGEST + "-9999999999999999" }));
	});

	test("rejects u53 violations on both generations", () => {
		for (const value of [9007199254740992, -1, 1.5, "5", null]) {
			expectRejected(validateWasmExecutionIdentityV1({ ...exampleWasmExecutionIdentityV1(), preparationGeneration: value }));
			expectRejected(validateWasmExecutionIdentityV1({ ...exampleWasmExecutionIdentityV1(), executionGeneration: value }));
		}
	});

	test("marks celld sequence/generation signals as WASM_IDENTITY_INCOMPLETE", () => {
		const celldHealth = { sandboxId: "sbx-vector", versionId: VECTOR_VERSION_DIGEST + "-1", generation: 4 };
		expect(hasCode(expectRejected(validateWasmExecutionIdentityV1(celldHealth)), WASM_IDENTITY_INCOMPLETE)).toBe(true);
		const versionOnly = { versionId: VECTOR_VERSION_DIGEST + "-1" };
		expect(hasCode(expectRejected(validateWasmExecutionIdentityV1(versionOnly)), WASM_IDENTITY_INCOMPLETE)).toBe(true);
		const celldSequence = { sandboxId: "sbx-vector", versionId: VECTOR_VERSION_DIGEST + "-1", sequence: 3 };
		expect(hasCode(expectRejected(validateWasmExecutionIdentityV1(celldSequence)), WASM_IDENTITY_INCOMPLETE)).toBe(true);
	});

	test("first preparation allocates (1,1) and generations never decrease", () => {
		const initial = initialWasmExecutionIdentity("sbx-vector", VECTOR_VERSION_DIGEST + "-1");
		expect(initial).toEqual({ sandboxId: "sbx-vector", versionId: VECTOR_VERSION_DIGEST + "-1", preparationGeneration: 0, executionGeneration: 0 });
		expect(isAliveWasmExecutionIdentity(initial)).toBe(false);

		const first = prepareWasmExecutionIdentity(initial);
		expect(first.ok).toBe(true);
		if (first.ok) expect(first.value).toEqual({ ...initial, preparationGeneration: 1, executionGeneration: 1 });
		expect(isAliveWasmExecutionIdentity(first.ok ? first.value : initial)).toBe(true);

		const reprepare = prepareWasmExecutionIdentity(first.ok ? first.value : initial);
		expect(reprepare.ok).toBe(true);
		if (reprepare.ok) expect(reprepare.value.preparationGeneration).toBe(2);

		const restart = allocateWasmExecutionIdentity(first.ok ? first.value : initial);
		expect(restart.ok).toBe(true);
		if (restart.ok) {
			expect(restart.value.preparationGeneration).toBe(1);
			expect(restart.value.executionGeneration).toBe(2);
		}
	});

	test("execution allocation requires an existing preparation", () => {
		const initial = initialWasmExecutionIdentity("sbx-vector", VECTOR_VERSION_DIGEST + "-1");
		expectRejected(allocateWasmExecutionIdentity(initial));
		const preparedOnly = { ...initial, preparationGeneration: 1, executionGeneration: 0 };
		expect(isAliveWasmExecutionIdentity(preparedOnly)).toBe(false);
		const allocated = allocateWasmExecutionIdentity(preparedOnly);
		expect(allocated.ok).toBe(true);
		if (allocated.ok) expect(isAliveWasmExecutionIdentity(allocated.value)).toBe(true);
	});

	test("exhaustion fails closed with WASM_GENERATION_EXHAUSTED", () => {
		const atPrepareLimit = { ...exampleWasmExecutionIdentityV1(), preparationGeneration: 9007199254740991 };
		expect(hasCode(expectRejected(prepareWasmExecutionIdentity(atPrepareLimit)), WASM_GENERATION_EXHAUSTED)).toBe(true);
		const atExecutionLimit = { ...exampleWasmExecutionIdentityV1(), executionGeneration: 9007199254740991 };
		expect(hasCode(expectRejected(allocateWasmExecutionIdentity(atExecutionLimit)), WASM_GENERATION_EXHAUSTED)).toBe(true);
	});

	test("fence comparison rejects any differing tuple element as stale", () => {
		const expected = exampleWasmExecutionIdentityV1();
		expect(matchesWasmExecutionFence(expected, expected)).toBe(true);
		expect(matchesWasmExecutionFence(expected, { ...expected, executionGeneration: 2 })).toBe(false);
		expect(matchesWasmExecutionFence(expected, { ...expected, versionId: VECTOR_VERSION_DIGEST + "-2" })).toBe(false);
		expect(checkWasmExecutionFence(expected, expected).ok).toBe(true);
		expectRejected(checkWasmExecutionFence(expected, { ...expected, preparationGeneration: 2 }));
	});
});

describe("secretRevision record semantics", () => {
	test("rotation allocates a strictly higher u53 revision", () => {
		const first = nextSecretRevision(0);
		expect(first.ok).toBe(true);
		if (first.ok) expect(first.value).toBe(1);
		const second = nextSecretRevision(7);
		expect(second.ok).toBe(true);
		if (second.ok) expect(second.value).toBe(8);
	});

	test("exhaustion and invalid inputs fail closed", () => {
		expectRejected(nextSecretRevision(9007199254740991));
		expectRejected(nextSecretRevision(-1));
		expectRejected(nextSecretRevision(1.5));
	});

	test("activation fence requires exact revision equality", () => {
		expect(matchesSecretRevisionFence(8, 8)).toBe(true);
		expect(matchesSecretRevisionFence(8, 7)).toBe(false);
		expect(matchesSecretRevisionFence(7, 8)).toBe(false);
	});
});

describe("execution command wire (single form)", () => {
	test("round-trips through JSON", () => {
		const example = exampleExecutionCommand();
		const result = validateExecutionCommand(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);
	});

	test("rejects unknown and missing fields", () => {
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), extra: true }));
		const missing = { ...exampleExecutionCommand() } as Record<string, unknown>;
		delete missing.runtimeBinding;
		expectRejected(validateExecutionCommand(missing));
	});

	test("rejects non-UUIDv7 command IDs and celld operations", () => {
		const v4 = "018f1e2c-3d4b-4a5e-9f01-23456789abcd";
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), commandId: v4 }));
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), commandId: "018F1E2C-3D4B-7A5E-9F01-23456789ABCD" }));
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), operation: "inspect" }));
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), operation: "delete" }));
	});

	test("rejects u53 violations on the double CAS fence and capability pin", () => {
		for (const field of ["expectedControlRevision", "expectedJournalRevision", "secretRevision", "configRevision"] as const) {
			expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), [field]: 9007199254740992 }));
			expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), [field]: "12" }));
		}
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), capabilityRecordRevision: 0 }));
	});

	test("enforces configRevision:0 <=> null ref/digest coupling", () => {
		const zeroConfig = { ...exampleExecutionCommand(), configRevision: 0, configSnapshotRef: null, configValuesDigest: null };
		expect(validateExecutionCommand(zeroConfig).ok).toBe(true);
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), configRevision: 0, configSnapshotRef: "7".repeat(64), configValuesDigest: null }));
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), configRevision: 3, configSnapshotRef: null, configValuesDigest: null }));
		expectRejected(validateExecutionCommand({ ...exampleExecutionCommand(), configValuesDigest: null }));
	});

	test("celld packageFilesDigest/versionIdentity are rejected, never converted", () => {
		const swapped: Record<string, unknown> = { ...exampleExecutionCommand(), packageFilesDigest: "0".repeat(64) };
		delete swapped.packageDigest;
		const rejection = expectRejected(validateExecutionCommand(swapped));
		expect(hasCode(rejection, EXECUTION_COMMAND_INVALID)).toBe(true);
		const celldIdentity: Record<string, unknown> = {
			...exampleExecutionCommand(),
			versionIdentity: { applicationId: "vector", digest: VECTOR_VERSION_DIGEST, sequence: 1 },
		};
		delete celldIdentity.identity;
		expectRejected(validateExecutionCommand(celldIdentity));
	});

	test("commandDigest matches an independently framed digestV2 oracle", () => {
		const command = exampleExecutionCommand();
		// 独立 oracle：SHA-256(ASCII(domain) || 0x00 || JCS(command))——preimage 框架手拼，
		// JCS 字节由 wasm-package 的编码器产出（单一编码权威）。
		const oracle = createHash("sha256")
			.update("iweb-wasm-execution-command-v2", "ascii")
			.update(Buffer.from([0x00]))
			.update(Buffer.from(jcsCanonicalize(command)))
			.digest("hex");
		expect(computeExecutionCommandDigest(command)).toBe(oracle);
	});
});

describe("execution acknowledgement wire", () => {
	test("round-trips and correlates with its command", () => {
		const command = exampleExecutionCommand();
		const ack = exampleExecutionAcknowledgement(command);
		const result = validateExecutionAcknowledgement(roundTrip(ack));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(ack);
		expect(correlateExecutionAcknowledgement(command, ack).ok).toBe(true);
	});

	test("failureCode is null if and only if result is applied", () => {
		expectRejected(validateExecutionAcknowledgement({ ...exampleExecutionAcknowledgement(exampleExecutionCommand()), failureCode: "SOMETHING" }));
		const rejected = { ...exampleExecutionAcknowledgement(exampleExecutionCommand()), result: "rejected" as const };
		expectRejected(validateExecutionAcknowledgement(rejected));
		expect(validateExecutionAcknowledgement({ ...rejected, failureCode: "EXECUTION_FENCE_STALE" }).ok).toBe(true);
		expectRejected(validateExecutionAcknowledgement({ ...rejected, failureCode: "lower_case" }));
		expectRejected(validateExecutionAcknowledgement({ ...rejected, failureCode: "A" + "A".repeat(64) }));
	});

	test("drainReceiptDigest only exists for an applied drain", () => {
		const command = { ...exampleExecutionCommand(), operation: "drain" as const };
		const appliedDrain = { ...exampleExecutionAcknowledgement(command), operation: "drain" as const, drainReceiptDigest: "f".repeat(64) };
		expect(validateExecutionAcknowledgement(appliedDrain).ok).toBe(true);
		expectRejected(validateExecutionAcknowledgement({ ...appliedDrain, drainReceiptDigest: null }));
		const rejectedDrain = { ...appliedDrain, result: "rejected" as const, failureCode: "WASM_EXECUTION_FENCE_STALE", drainReceiptDigest: null };
		expect(validateExecutionAcknowledgement(rejectedDrain).ok).toBe(true);
		expectRejected(validateExecutionAcknowledgement({ ...rejectedDrain, drainReceiptDigest: "f".repeat(64) }));
		expectRejected(validateExecutionAcknowledgement({ ...exampleExecutionAcknowledgement(exampleExecutionCommand()), drainReceiptDigest: "f".repeat(64) }));
	});

	test("correlation rejects every echoed-field mismatch", () => {
		const command = exampleExecutionCommand();
		const base = exampleExecutionAcknowledgement(command);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, commandId: "018f1e2c-3d4b-7a5e-9f01-23456789ffff" })), "COMMAND_ID_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, identity: { ...base.identity, executionGeneration: 2 } })), "IDENTITY_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, secretValuesDigest: "6".repeat(63) + "0" })), "SECRET_SNAPSHOT_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, configSnapshotRef: "7".repeat(63) + "0" })), "CONFIG_SNAPSHOT_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, packageDigest: "0".repeat(63) + "1" })), "PACKAGE_DIGEST_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, capabilityRecordRevision: 6 })), "CAPABILITY_RECORD_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, hostServicePolicyDigest: "e".repeat(64) })), "POLICY_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, fenceNonce: "f".repeat(32) })), "IDENTITY_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, applicationId: "other" })), "IDENTITY_MISMATCH")).toBe(true);
		expect(hasCode(expectRejected(correlateExecutionAcknowledgement(command, { ...base, matrixRevision: 1 as unknown as 2 })), "IDENTITY_MISMATCH")).toBe(true);
	});
});

describe("execution rpc envelope, query and replay wire", () => {
	const command = exampleExecutionCommand();
	const requestEnvelope = { protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: REQUEST_ID, body: { kind: "command", command } };
	const received = {
		kind: "command-received",
		commandId: command.commandId,
		commandDigest: computeExecutionCommandDigest(command),
		command,
		snapshotHandoffDigest: null,
		receivedAt: "2026-08-26T00:00:00Z",
		journalRevision: 4,
	};

	test("round-trips command, query and replay request envelopes", () => {
		for (const body of [{ kind: "command", command }, { kind: "query", commandId: command.commandId }, { kind: "replay", command }]) {
			const result = validateExecutionRpcRequestEnvelopeV1(roundTrip({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: REQUEST_ID, body }));
			expect(result.ok).toBe(true);
			if (result.ok) expect(result.value.body).toEqual(body);
		}
	});

	test("rejects wrong protocol literal, bad requestId, unknown fields, and query-result bodies", () => {
		expectRejected(validateExecutionRpcRequestEnvelopeV1({ ...requestEnvelope, protocol: "iweb-wasm-activation-v1" }));
		expectRejected(validateExecutionRpcRequestEnvelopeV1({ ...requestEnvelope, requestId: "018f1e2c-3d4b-4c6d-8e9f-001122334455" }));
		expectRejected(validateExecutionRpcRequestEnvelopeV1({ ...requestEnvelope, version: 1 }));
		expectRejected(validateExecutionRpcRequestEnvelopeV1({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: REQUEST_ID, body: { kind: "query-result", commandId: command.commandId, status: "missing", received: null, acknowledgement: null } }));
	});

	test("round-trips the acknowledgement and query-result response envelopes with correlation", () => {
		const ackEnvelope = {
			protocol: EXECUTION_RPC_PROTOCOL_LITERAL,
			requestId: REQUEST_ID,
			body: { kind: "acknowledgement", acknowledgement: exampleExecutionAcknowledgement(command) },
		};
		const parsed = validateExecutionRpcResponseEnvelopeV1(roundTrip(ackEnvelope));
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error("expected response envelope to parse");
		expect(parsed.value.body).toEqual(ackEnvelope.body);
		const request = validateExecutionRpcRequestEnvelopeV1(requestEnvelope);
		expect(request.ok).toBe(true);
		if (!request.ok) throw new Error("expected request envelope to parse");
		expect(correlateExecutionRpcResponse(request.value, parsed.value).ok).toBe(true);

		const mismatched = { ...ackEnvelope, requestId: "018f1e2c-3d4b-7c6d-8e9f-001122334456" };
		const parsedMismatch = validateExecutionRpcResponseEnvelopeV1(mismatched);
		expect(parsedMismatch.ok).toBe(true);
		if (!parsedMismatch.ok) throw new Error("expected mismatched envelope to parse");
		expect(hasCode(expectRejected(correlateExecutionRpcResponse(request.value, parsedMismatch.value)), "REQUEST_ID_MISMATCH")).toBe(true);

		const queryResult = {
			protocol: EXECUTION_RPC_PROTOCOL_LITERAL,
			requestId: REQUEST_ID,
			body: { kind: "query-result", commandId: command.commandId, status: "completed", received, acknowledgement: exampleExecutionAcknowledgement(command) },
		};
		const parsedQuery = validateExecutionRpcResponseEnvelopeV1(queryResult);
		expect(parsedQuery.ok).toBe(true);
		const missing = {
			protocol: EXECUTION_RPC_PROTOCOL_LITERAL,
			requestId: REQUEST_ID,
			body: { kind: "query-result", commandId: command.commandId, status: "missing", received: null, acknowledgement: null },
		};
		expect(validateExecutionRpcResponseEnvelopeV1(missing).ok).toBe(true);
	});

	test("rejects query-result coupling violations", () => {
		const base = { kind: "query-result", commandId: command.commandId };
		expectRejected(validateExecutionRpcResponseEnvelopeV1({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: REQUEST_ID, body: { ...base, status: "received", received: null, acknowledgement: null } }));
		expectRejected(validateExecutionRpcResponseEnvelopeV1({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: REQUEST_ID, body: { ...base, status: "completed", received, acknowledgement: null } }));
		expectRejected(validateExecutionRpcResponseEnvelopeV1({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: REQUEST_ID, body: { ...base, status: "missing", received, acknowledgement: null } }));
		expectRejected(validateExecutionRpcResponseEnvelopeV1({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: REQUEST_ID, body: { ...base, status: "missing", received: null, acknowledgement: exampleExecutionAcknowledgement(command) } }));
	});

	test("CommandReceivedV1 recomputes its commandDigest and rejects mismatches", () => {
		expect(validateCommandReceivedV1(roundTrip(received)).ok).toBe(true);
		expect(hasCode(expectRejected(validateCommandReceivedV1({ ...received, commandDigest: "0".repeat(64) })), "EXECUTION_COMMAND_DIGEST_MISMATCH")).toBe(true);
	});

	test("celld /v1/rpc and execution envelopes stay mutually exclusive", () => {
		expect(validateSupervisorRequest(requestEnvelope).ok).toBe(false);
		expect(carriesExecutionRpcFields(requestEnvelope)).toBe(true);
		expect(carriesExecutionRpcFields(received)).toBe(true);
		const celldStop = { version: 1, operation: "stop", sandboxId: "notes" };
		expect(carriesExecutionRpcFields(celldStop)).toBe(false);
		expect(validateSupervisorRequest(celldStop).ok).toBe(true);
		expectRejected(validateExecutionRpcRequestEnvelopeV1({ version: 1, operation: "prepare", sandboxId: "notes" }));
	});
});


// ---------------------------------------------------------------------------
// simplify-wasm-host-services：单一命令形态（原 V2 wire 正式化与版本联合段已合并）。
// outbox/journal/envelope 的命令与 ack 只有一种形态；无跨版本分派、无版本联合判别式。
// ---------------------------------------------------------------------------

describe("control-state outbox and journal digest (single form)", () => {
	test("the outbox carries the single-form command and recomputes its digest", () => {
		const file = exampleWasmControlStateFileV2();
		const second = { ...exampleExecutionCommand(), commandId: "018f1e2c-3d4b-7d6d-8e9f-001122334455" };
		const withSecond = {
			...file,
			commandOutbox: [
				...file.commandOutbox,
				{
					commandId: second.commandId,
					command: second,
					createdAt: "2026-08-28T00:00:00Z",
					deliveryState: "pending" as const,
					attempts: 0,
					lastAttemptAt: null,
				},
			],
		};
		const validated = validateWasmControlStateFileV2(withSecond);
		expect(validated.ok).toBe(true);
		if (validated.ok) expect(validated.value.commandOutbox).toHaveLength(2);
		// 单一形态键：expectedControlRevision + ABI 1.1.0 binding；旧键名不再出现。
		const jcs = Buffer.from(jcsCanonicalize(withSecond)).toString("utf8");
		expect(jcs.includes('"expectedControlRevision":12')).toBe(true);
		expect(jcs.includes("iweb-wasmd-abi@1.1.0")).toBe(true);
		expect(jcs.includes("expectedKernelControlRevision")).toBe(false);
		// journal received 条目按唯一公式复算 digest；错值 digest 拒绝。
		const received = validateCommandReceivedV1({
			kind: "command-received",
			commandId: second.commandId,
			commandDigest: computeExecutionCommandDigest(second),
			command: second,
			snapshotHandoffDigest: null,
			receivedAt: "2026-08-28T00:00:00Z",
			journalRevision: 1,
		});
		expect(received.ok).toBe(true);
		expect(
			validateCommandReceivedV1({
				kind: "command-received",
				commandId: second.commandId,
				commandDigest: "0".repeat(64),
				command: second,
				snapshotHandoffDigest: null,
				receivedAt: "2026-08-28T00:00:00Z",
				journalRevision: 1,
			}).ok,
		).toBe(false);
	});
});

describe("execution command wire invariants (service-enabled single form)", () => {
	test("the example vector validates and its digest recomputes from an independent oracle", () => {
		const command = exampleExecutionCommand();
		const validated = validateExecutionCommand(command);
		expect(validated.ok).toBe(true);
		if (!validated.ok) return;
		const oracle = createHash("sha256")
			.update("iweb-wasm-execution-command-v2", "ascii")
			.update(Buffer.from([0x00]))
			.update(Buffer.from(jcsCanonicalize(validated.value)))
			.digest("hex");
		expect(computeExecutionCommandDigest(validated.value)).toBe(oracle);
	});

	test("the single-form invariants are pinned (ABI 1.1.0, matrixRevision 2, fenceNonce, policy pin)", () => {
		const command = exampleExecutionCommand();
		expect(validateExecutionCommand({ ...command, schemaVersion: 1 }).ok).toBe(false);
		expect(validateExecutionCommand({ ...command, matrixRevision: 1 }).ok).toBe(false);
		expect(validateExecutionCommand({ ...command, fenceNonce: "AB".repeat(16) }).ok).toBe(false);
		expect(validateExecutionCommand({ ...command, hostServicePolicyDigest: "zz" }).ok).toBe(false);
		expect(validateExecutionCommand({ ...command, applicationId: "Vector" }).ok).toBe(false);
		// ABI 1.0.0 binding 不是本 wire 的合法形态。
		const staleBinding = { ...command.runtimeBinding, hostABI: "iweb-wasmd-abi@1.0.0" };
		expect(validateExecutionCommand({ ...command, runtimeBinding: staleBinding }).ok).toBe(false);
		// 未知/缺失字段 fail-closed。
		expect(validateExecutionCommand({ ...command, extra: 1 }).ok).toBe(false);
		expect(validateExecutionCommand({ ...command, fenceNonce: undefined }).ok).toBe(false);
		// config 耦合破坏。
		expect(validateExecutionCommand({ ...command, configValuesDigest: null }).ok).toBe(false);
	});

	test("the binding validator pins the ABI 1.1.0 literal only", () => {
		expect(validateRuntimeBindingIdentityV2(exampleExecutionCommand().runtimeBinding).ok).toBe(true);
		const factForm = exampleRuntimeBindingIdentityV1();
		expect(validateRuntimeBindingIdentityV2(factForm).ok).toBe(false);
		expect(validateRuntimeBindingIdentityV1(exampleExecutionCommand().runtimeBinding).ok).toBe(false);
	});

	test("runtimeBindingIdentityV2FromV1 derives the wire form from the admission fact form", () => {
		const derived = runtimeBindingIdentityV2FromV1(exampleRuntimeBindingIdentityV1());
		expect(derived.ok).toBe(true);
		if (derived.ok) {
			expect(derived.value.hostABI).toBe("iweb-wasmd-abi@1.1.0");
			expect(derived.value.catalogRevision).toBe(exampleRuntimeBindingIdentityV1().catalogRevision);
			expect(derived.value.imageDigest).toBe(exampleRuntimeBindingIdentityV1().imageDigest);
		}
	});

	test("the digestV2 framing never collides with the legacy newline framing on the same bytes", () => {
		const command = exampleExecutionCommand();
		const digest = computeExecutionCommandDigest(command);
		const legacyStyle = createHash("sha256").update("iweb-execution-command-v1\n").update(Buffer.from(jcsCanonicalize(command))).digest("hex");
		expect(digest).not.toBe(legacyStyle);
		expect(WASM_FENCE_NONCE_PATTERN.test(exampleExecutionCommand().fenceNonce)).toBe(true);
	});

	test("rejections use the dedicated stable code", () => {
		const outcome = validateExecutionCommand({ ...exampleExecutionCommand(), matrixRevision: 3 });
		expect(outcome.ok).toBe(false);
		if (!outcome.ok) expect(outcome.errors.some((error) => error.code === EXECUTION_COMMAND_INVALID)).toBe(true);
	});
});

describe("wasm control state file and controlRevision CAS", () => {
	test("round-trips the complete file and application record through JSON", () => {
		const example = exampleWasmControlStateFileV2();
		const result = validateWasmControlStateFileV2(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);
		const application = validateWasmApplicationControlRecordV1(example.applications.vector);
		expect(application.ok).toBe(true);
	});

	test("rejects unknown fields at every depth", () => {
		expectRejected(validateWasmControlStateFileV2({ ...exampleWasmControlStateFileV2(), extra: 1 }));
		expectRejected(validateWasmControlStateFileV2({ ...exampleWasmControlStateFileV2(), migration: { ...exampleWasmControlStateFileV2().migration, extra: 1 } }));
		const file = exampleWasmControlStateFileV2();
		const tamperedRow = { ...file.applications.vector.versions[0], extra: 1 };
		expectRejected(
			validateWasmControlStateFileV2({
				...file,
				applications: { vector: { ...file.applications.vector, versions: [tamperedRow] } },
			}),
		);
	});

	test("rejects the celld ControlStateFile shape instead of migrating it", () => {
		const celldState = { version: 1, applications: [{ id: "notes", active: null }] };
		const rejection = expectRejected(validateWasmControlStateFileV2(celldState));
		expect(hasCode(rejection, "WASM_CONTROL_STATE_INVALID")).toBe(true);
	});

	test("rejects duplicate versionIds and an active pointer naming a missing version", () => {
		const file = exampleWasmControlStateFileV2();
		const duplicated = { ...file.applications.vector.versions[0] };
		expectRejected(
			validateWasmControlStateFileV2({
				...file,
				applications: { vector: { ...file.applications.vector, versions: [file.applications.vector.versions[0], duplicated] } },
			}),
		);
		const pointerToMissing = { ...file.applications.vector.active, versionId: VECTOR_VERSION_DIGEST + "-9" };
		expectRejected(
			validateWasmControlStateFileV2({
				...file,
				applications: { vector: { ...file.applications.vector, active: pointerToMissing } },
			}),
		);
	});

	test("rejects key mismatches, missing lease digests, and proof-ref formula violations", () => {
		const file = exampleWasmControlStateFileV2();
		expectRejected(validateWasmControlStateFileV2({ ...file, applications: { notes: file.applications.vector } }));
		const readyWithoutLease = { ...file.applications.vector.versions[0], lifecycle: "ready" as const, readinessLeaseDigest: null };
		expectRejected(
			validateWasmControlStateFileV2({
				...file,
				applications: { vector: { ...file.applications.vector, versions: [readyWithoutLease] } },
			}),
		);
		const badProofRef = { ...file.applications.vector.versions[0], admissionProofRef: "admission-proof/vector/wrong" };
		expectRejected(
			validateWasmControlStateFileV2({
				...file,
				applications: { vector: { ...file.applications.vector, versions: [badProofRef] } },
			}),
		);
		const badVersionId = { ...file.applications.vector.versions[0], versionId: "b".repeat(64) + "-1" };
		expectRejected(
			validateWasmControlStateFileV2({
				...file,
				applications: { vector: { ...file.applications.vector, versions: [badVersionId] } },
			}),
		);
	});

	test("rejects a celld manifest as normalizedPolicy", () => {
		const file = exampleWasmControlStateFileV2();
		const celldManifest = {
			schemaVersion: 1,
			name: "vector",
			runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint: "index.js" },
			assets: { root: "app" },
			resources: { cpuMillis: 100, memoryBytes: 1024, pidLimit: 10, storageBytes: 1024 },
			storage: { persistent: false, requestBytes: 0 },
			egress: { default: "deny", allow: [] },
		};
		expect(validateNormalizedWasmManifestV1(celldManifest).ok).toBe(false);
		const row = { ...file.applications.vector.versions[0], normalizedPolicy: celldManifest };
		expectRejected(
			validateWasmControlStateFileV2({
				...file,
				applications: { vector: { ...file.applications.vector, versions: [row] } },
			}),
		);
	});

	test("the active pointer accepts the simplified service-increment keys and rejects the legacy v2* set", () => {
		const file = exampleWasmControlStateFileV2();
		const base = { ...file.applications.vector.active };
		// simplify-wasm-host-services：hostServicePolicyDigest?/preparationGeneration?/executionGeneration? 被容忍（wire 权威在 Rust）。
		const simplified = { ...base, hostServicePolicyDigest: "b".repeat(64), preparationGeneration: 1, executionGeneration: 1 };
		expect(validateWasmControlStateFileV2({ ...file, applications: { vector: { ...file.applications.vector, active: simplified } } }).ok).toBe(true);
		// 旧 v2* 增量键（v2CatalogRevision 等）不再是合法指针形状。
		const legacy = { ...base, v2CatalogRevision: 9, v2ExecutionFenceNonce: "0".repeat(32) };
		expect(validateWasmControlStateFileV2({ ...file, applications: { vector: { ...file.applications.vector, active: legacy } } }).ok).toBe(false);
	});

	test("controlRevision CAS requires next = current + 1", () => {
		const ok = checkControlRevisionCas(7, 8);
		expect(ok.ok).toBe(true);
		if (ok.ok) expect(ok.value).toBe(8);
		expect(checkControlRevisionCas(0, 1).ok).toBe(true);
		expect(hasCode(expectRejected(checkControlRevisionCas(7, 9)), CONTROL_REVISION_CONFLICT)).toBe(true);
		expect(hasCode(expectRejected(checkControlRevisionCas(7, 7)), CONTROL_REVISION_CONFLICT)).toBe(true);
		expectRejected(checkControlRevisionCas(9007199254740991, 0));
		expectRejected(checkControlRevisionCas(-1, 0));
		expectRejected(checkControlRevisionCas(1.5, 2));
	});
});

describe("normalized wasm manifest vectors", () => {
	test("the example fixture is byte-identical to the published 405-byte JCS vector", () => {
		expect(jcsCanonicalize(exampleNormalizedWasmManifestV1())).toBe(SPEC_VECTOR_MANIFEST_JCS);
		expect(Buffer.byteLength(SPEC_VECTOR_MANIFEST_JCS, "utf8")).toBe(405);
		expect(validateNormalizedWasmManifestV1(exampleNormalizedWasmManifestV1()).ok).toBe(true);
	});

	test("rejects non-JCS-sorted arrays and duplicate keys", () => {
		const base = exampleNormalizedWasmManifestV1();
		const unsortedImports = {
			...base,
			runtime: {
				...base.runtime,
				declaredHostImports: [
					{ package: "wasi:io@0.2.8", interface: "streams", direction: "import" },
					{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
				],
			},
		};
		expectRejected(validateNormalizedWasmManifestV1(unsortedImports));
		const duplicateImports = {
			...base,
			runtime: {
				...base.runtime,
				declaredHostImports: [
					{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
					{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
				],
			},
		};
		expectRejected(validateNormalizedWasmManifestV1(duplicateImports));
		const unsortedEgress = {
			...base,
			egress: {
				default: "deny" as const,
				allow: [
					{ host: "b.example.com", port: 443 },
					{ host: "a.example.com", port: 443 },
				],
			},
		};
		expectRejected(validateNormalizedWasmManifestV1(unsortedEgress));
		const duplicateEgress = {
			...base,
			egress: { default: "deny" as const, allow: [{ host: "a.example.com", port: 443 }, { host: "a.example.com", port: 443 }] },
		};
		expectRejected(validateNormalizedWasmManifestV1(duplicateEgress));
	});
});

describe("KindClaimBootstrapV1 digest formula", () => {
	function withClaims(claims: readonly RuntimeKindClaimV1[]): KindClaimBootstrapV1 {
		const base = exampleKindClaimBootstrapV1();
		const { completionReceiptDigest, ...rest } = base;
		void completionReceiptDigest;
		return { ...rest, sortedClaims: claims, completionReceiptDigest: computeKindClaimBootstrapDigest({ ...rest, sortedClaims: claims }) };
	}

	test("reproduces the spec digest formulas from hand-built preimage oracles", () => {
		const adminClaimJcs = '{"applicationId":"admin","bindingRevision":1,"runtimeKind":"celld","schemaVersion":1}';
		const adminBindingDigest = sha256Text("iweb-application-kind-binding-v1\n" + adminClaimJcs);
		const notesClaimJcs = '{"applicationId":"notes","bindingRevision":1,"runtimeKind":"celld","schemaVersion":1}';
		const notesBindingDigest = sha256Text("iweb-application-kind-binding-v1\n" + notesClaimJcs);
		const bootstrapJcs =
			'{"bootstrapRevision":1,"controlStateRawDigest":"' + "9".repeat(64) +
			'","schemaVersion":1,"sortedClaims":[' +
			'{"applicationId":"admin","bindingDigest":"' + adminBindingDigest + '","bindingRevision":1,"runtimeKind":"celld"},' +
			'{"applicationId":"notes","bindingDigest":"' + notesBindingDigest + '","bindingRevision":1,"runtimeKind":"celld"}' +
			'],"sourceKind":"celld","sourceRevision":0}';
		const oracleReceipt = sha256Text("iweb-kind-claim-bootstrap-v1\n" + bootstrapJcs);

		const example = exampleKindClaimBootstrapV1();
		expect(example.sortedClaims[0].bindingDigest).toBe(adminBindingDigest);
		expect(example.sortedClaims[1].bindingDigest).toBe(notesBindingDigest);
		expect(example.completionReceiptDigest).toBe(oracleReceipt);
		expect(computeRuntimeKindClaimBindingDigest(example.sortedClaims[0])).toBe(adminBindingDigest);

		const result = validateKindClaimBootstrapV1(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);
	});

	test("rejects a tampered record or claim digest", () => {
		const example = exampleKindClaimBootstrapV1();
		expect(hasCode(expectRejected(validateKindClaimBootstrapV1({ ...example, sourceRevision: 1 })), "KIND_CLAIM_DIGEST_MISMATCH")).toBe(true);
		const tamperedClaim = { ...example.sortedClaims[0], bindingDigest: "0".repeat(64) };
		const rebuilt = withClaims([tamperedClaim, example.sortedClaims[1]]);
		expect(hasCode(expectRejected(validateKindClaimBootstrapV1(rebuilt)), "KIND_CLAIM_BINDING_DIGEST_MISMATCH")).toBe(true);
	});

	test("rejects unsorted claims, duplicate applicationIds, wasm claims, and unknown fields", () => {
		const example = exampleKindClaimBootstrapV1();
		expectRejected(validateKindClaimBootstrapV1(withClaims([example.sortedClaims[1], example.sortedClaims[0]])));
		expectRejected(validateKindClaimBootstrapV1(withClaims([example.sortedClaims[0], example.sortedClaims[0]])));
		const wasmClaimAttempt = {
			schemaVersion: 1,
			bootstrapRevision: 1,
			sourceKind: "celld",
			controlStateRawDigest: "9".repeat(64),
			sourceRevision: 0,
			sortedClaims: [{ applicationId: "vector", runtimeKind: "wasm", bindingRevision: 1, bindingDigest: "0".repeat(64) }],
			completionReceiptDigest: "0".repeat(64),
		};
		expect(hasCode(expectRejected(validateKindClaimBootstrapV1(wasmClaimAttempt)), "WASM_KIND_CLAIM_INVALID")).toBe(true);
		expectRejected(validateKindClaimBootstrapV1({ ...example, extra: true }));
	});
});

describe("drain receipt v1 wire (task 7.6)", () => {
	// 独立 oracle：手拼 preimage（域前缀 + 单次 SHA-256），不复用被测实现。
	function oracleReceiptDigest(record: DrainReceiptV1): string {
		const { receiptDigest: _omitted, ...rest } = record;
		return createHash("sha256").update("iweb-drain-receipt-v1\n").update(jcsCanonicalize(rest)).digest("hex");
	}

	// 变异后重封 receiptDigest：digest 公式覆盖"除 receiptDigest 外"的全部字段，
	// 必须先剥掉旧值再算（与 Rust drain_receipt_digest_v1 的 remove 语义一致）。
	function resealed(mutations: Partial<DrainReceiptV1>): DrainReceiptV1 {
		const { receiptDigest: _stale, ...draft } = { ...exampleDrainReceiptV1(), ...mutations };
		return { ...draft, receiptDigest: computeDrainReceiptDigestV1(draft) };
	}

	test("golden example validates and its digest recomputes from an independent oracle", () => {
		const receipt = exampleDrainReceiptV1();
		expect(validateDrainReceiptV1(receipt).ok).toBe(true);
		// Rust kernel-rs 为 wire 权威；TS 侧以独立手拼 preimage oracle 复算（无跨语言 golden 锁）。
		expect(receipt.receiptDigest).toBe(oracleReceiptDigest(receipt));
		const { receiptDigest: _stripped, ...rest } = receipt;
		void _stripped;
		expect(computeDrainReceiptDigestV1(rest)).toBe(oracleReceiptDigest(receipt));
	});

	test("digest must recompute exactly from the remaining fields", () => {
		const receipt = exampleDrainReceiptV1();
		expectRejected(validateDrainReceiptV1({ ...receipt, drainedRequestCount: 3 }));
		expectRejected(validateDrainReceiptV1({ ...receipt, journalRevision: 8 }));
		expectRejected(validateDrainReceiptV1({ ...receipt, deadlineAt: "2026-08-26T00:00:29.000Z" }));
		// 篡改后重封 digest：通过 digest 检查，正例证明可自洽复算。
		expect(validateDrainReceiptV1(resealed({ drainedRequestCount: 3 })).ok).toBe(true);
	});

	test("forcedKillAt is non-null if and only if forced-kill and never precedes the deadline", () => {
		expectRejected(validateDrainReceiptV1(resealed({ result: "forced-kill" })));
		expectRejected(validateDrainReceiptV1(resealed({ forcedKillAt: "2026-08-26T00:00:30.000Z" })));
		expectRejected(validateDrainReceiptV1(resealed({ result: "forced-kill", forcedKillAt: "2026-08-26T00:00:29.999Z" })));
		// forcedKillAt 恰等于 deadlineAt（at or after）合法；deadline 强杀的 0 计数也合法。
		expect(validateDrainReceiptV1(resealed({ result: "forced-kill", forcedKillAt: "2026-08-26T00:00:30.000Z", drainedRequestCount: 0, completedAt: "2026-08-26T00:00:30.500Z" })).ok).toBe(true);
	});

	test("rejects unknown fields, bad identities, and out-of-domain values", () => {
		const receipt = exampleDrainReceiptV1();
		expectRejected(validateDrainReceiptV1({ ...receipt, extra: true }));
		expectRejected(validateDrainReceiptV1({ ...receipt, schemaVersion: 2 }));
		expectRejected(validateDrainReceiptV1({ ...receipt, commandId: "not-a-uuid" }));
		expectRejected(validateDrainReceiptV1({ ...receipt, applicationId: "Vector" }));
		expectRejected(validateDrainReceiptV1({ ...receipt, execution: { ...receipt.execution, sandboxId: "Bad-Sandbox" } }));
		expectRejected(validateDrainReceiptV1({ ...receipt, packageDigest: "0".repeat(63) + "g" }));
		expectRejected(validateDrainReceiptV1({ ...receipt, routeGeneration: -1 }));
		expectRejected(validateDrainReceiptV1({ ...receipt, drainedRequestCount: 1.5 }));
		expectRejected(validateDrainReceiptV1({ ...receipt, deadlineAt: "2026-08-26T00:00:30" }));
		expectRejected(validateDrainReceiptV1({ ...receipt, result: "cancelled" }));
	});
});

describe("shared runtime kind export", () => {
	test("accepts exactly celld and wasm", () => {
		expect(validateRuntimeKind("celld").ok).toBe(true);
		expect(validateRuntimeKind("wasm").ok).toBe(true);
		expectRejected(validateRuntimeKind("bash"));
		expectRejected(validateRuntimeKind(""));
	});
});
