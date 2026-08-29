// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.2 剩余）：readiness health v2 / ReadinessLeaseV2 / engine metrics v1 的 typed wire 契约必须有正/负向量——身份错配逐字段、celld v1 信号不被采纳、nonce 重放、lease CAS 过期、fuel null vs 0、unavailable 唯一表示、counter 单调/重置/乱序、unknown 字段、u53。
// 正交意图：负例断言稳定错误码而非字符串匹配；leaseDigest 用 node:crypto 手拼 preimage 的独立 oracle；celld 既有 validator（validateReadinessLease）行为保持全绿。
// 任务 1.2 文本点名的代次向量（初始 (P=1,E=1)、no-execution E=0、CAS 失败、旧 tuple、celld sequence/generation）已由 tests/wasm-execution-contracts.test.ts 覆盖，此处不重复实现。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
	acceptWasmEngineMetricsSample,
	checkReadinessLeaseExpiry,
	composeWasmVersionId,
	computeReadinessLeaseDigestV2,
	consumeReadinessLeaseV2,
	correlateReadinessLeaseV2,
	correlateWasmEngineMetricsV1,
	correlateWasmReadinessHealthV2,
	exampleReadinessLeaseV2,
	exampleWasmEngineMetricsV1,
	exampleWasmReadinessHealthV2,
	isReadinessLeaseNonceConsumed,
	openWasmEngineMetricsWindow,
	READINESS_LEASE_EXPIRED,
	READINESS_LEASE_MISMATCH,
	validateReadinessLeaseV2,
	validateActivationCommand,
	validateRollbackRecord,
	validateRouteEvent,
	validateServiceReadinessLeaseV2,
	correlateServiceReadinessLeaseV2,
	computeServiceReadinessLeaseDigestV2,
	computeActivationCommandDigest,
	computeRouteEventDigest,
	computeRollbackRecordDigest,
	exampleActivationCommand,
	exampleRollbackRecord,
	exampleRouteEvent,
	exampleServiceReadinessLeaseV2,
	validateWasmApplicationIdGrammar,
	validateWasmEngineMetricsV1,
	validateWasmReadinessHealthV2,
	validateWasmVersionIdGrammar,
	WASM_ENGINE_METRICS_COUNTER_REGRESSION,
	WASM_ENGINE_METRICS_FUEL_REPRESENTATION,
	WASM_ENGINE_METRICS_STALE,
	WASM_ENGINE_METRICS_TIME_REGRESSION,
	WASM_IDENTITY_INCOMPLETE,
	type WasmEngineMetricsV1,
	type WasmEngineMetricsWindow,
	type ReadinessLeaseV2,
} from "../packages/contracts/wasm-health.ts";
import { jcsCanonicalBytes, jcsCanonicalize } from "../packages/contracts/wasm-package.ts";
import { WASM_IDENTITY_INCOMPLETE as EXECUTION_INCOMPLETE_CODE } from "../packages/contracts/wasm-execution.ts";
import { validateReadinessLease } from "../packages/contracts/records.ts";
import type { ValidationIssue, ValidationResult } from "../packages/contracts/validation.ts";

const VECTOR_VERSION_DIGEST = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";

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

describe("grammar 统一助手（applicationId 63 / versionId 无前导零）", () => {
	test("accepts the maximal 63-byte applicationId and rejects 64 bytes or bad grammar", () => {
		const maxId = "a".repeat(62) + "0";
		expect(maxId.length).toBe(63);
		expect(validateWasmApplicationIdGrammar(maxId).ok).toBe(true);
		expect(validateWasmApplicationIdGrammar("a".repeat(63) + "0").ok).toBe(false);
		expect(validateWasmApplicationIdGrammar("-alpha").ok).toBe(false);
		expect(validateWasmApplicationIdGrammar("Alpha").ok).toBe(false);
	});

	test("versionId sequence forbids leading zeros, zero, and non-u53 sequences", () => {
		expect(validateWasmVersionIdGrammar(VECTOR_VERSION_DIGEST + "-1").ok).toBe(true);
		expect(validateWasmVersionIdGrammar(VECTOR_VERSION_DIGEST + "-01").ok).toBe(false);
		expect(validateWasmVersionIdGrammar(VECTOR_VERSION_DIGEST + "-0").ok).toBe(false);
		// 16 位十进制 9999999999999999 越过 u53 上界：文法允许，parse 必须拒绝。
		expect(validateWasmVersionIdGrammar(VECTOR_VERSION_DIGEST + "-9999999999999999").ok).toBe(false);
		expect(validateWasmVersionIdGrammar(VECTOR_VERSION_DIGEST).ok).toBe(false);
		expect(composeWasmVersionId(VECTOR_VERSION_DIGEST, 1)).toBe(VECTOR_VERSION_DIGEST + "-1");
	});
});

describe("readiness health v2 payload", () => {
	test("round-trips the exact 15-field v2 shape", () => {
		const example = exampleWasmReadinessHealthV2();
		const result = validateWasmReadinessHealthV2(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);
	});

	test("rejects unknown fields, missing fields, ok:false, and wrong schema version", () => {
		expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), extra: 1 }));
		const missing = { ...exampleWasmReadinessHealthV2() } as Record<string, unknown>;
		delete missing.capabilityRecordHash;
		expectRejected(validateWasmReadinessHealthV2(missing));
		expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), ok: false }));
		expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), schemaVersion: 1 }));
	});

	test("requires both generations >= 1 and u53 bounds", () => {
		expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), preparationGeneration: 0 }));
		expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), executionGeneration: 0 }));
		for (const bad of [-1, 1.5, 9007199254740992, "1"]) {
			expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), executionGeneration: bad }));
		}
		expect(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), executionGeneration: 9007199254740991 }).ok).toBe(true);
	});

	test("enforces configRevision 0 <=> null ref/digest and non-zero <=> both present", () => {
		const noConfig = { ...exampleWasmReadinessHealthV2(), configRevision: 0, configSnapshotRef: null, configValuesDigest: null };
		expect(validateWasmReadinessHealthV2(noConfig).ok).toBe(true);
		expectRejected(validateWasmReadinessHealthV2({ ...noConfig, configSnapshotRef: "7".repeat(64) }));
		expectRejected(validateWasmReadinessHealthV2({ ...noConfig, configValuesDigest: "8".repeat(64) }));
		expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), configValuesDigest: null }));
		expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), configSnapshotRef: null }));
	});

	test("never adopts celld v1 signals (generation/sequence-only health)", () => {
		const celldGenerationOnly = { ok: true, versionId: VECTOR_VERSION_DIGEST + "-1", generation: 4 };
		expect(hasCode(expectRejected(validateWasmReadinessHealthV2(celldGenerationOnly)), WASM_IDENTITY_INCOMPLETE)).toBe(true);
		const celldSequenceOnly = { sandboxId: "sbx-vector", versionId: VECTOR_VERSION_DIGEST + "-1", sequence: 3 };
		expect(hasCode(expectRejected(validateWasmReadinessHealthV2(celldSequenceOnly)), WASM_IDENTITY_INCOMPLETE)).toBe(true);
		// 完整 v2 payload 夹带 celld generation 字段：unknown + incomplete 双重拒绝。
		const smuggled = expectRejected(validateWasmReadinessHealthV2({ ...exampleWasmReadinessHealthV2(), generation: 4 }));
		expect(hasCode(smuggled, WASM_IDENTITY_INCOMPLETE)).toBe(true);
		// celld {versionId,expiresAt} readiness 记录不是 wasm lease，也不是 v2 health。
		expectRejected(validateWasmReadinessHealthV2({ versionId: "v1", expiresAt: "2026-08-14T00:00:00.000Z" }));
		// celld 既有解析路径行为不变（独立路径互不采纳）。
		expect(validateReadinessLease({ versionId: "v1", expiresAt: "2026-08-14T00:00:00.000Z" }).ok).toBe(true);
		expect(EXECUTION_INCOMPLETE_CODE).toBe(WASM_IDENTITY_INCOMPLETE);
	});

	test("correlate rejects each identity mismatch with its field code", () => {
		const expected = exampleWasmReadinessHealthV2();
		expect(correlateWasmReadinessHealthV2(expected, expected).ok).toBe(true);
		const cases: readonly [string, unknown, string][] = [
			["sandboxId", "sbx-other", "SANDBOX_ID_MISMATCH"],
			["versionId", VECTOR_VERSION_DIGEST + "-2", "VERSION_ID_MISMATCH"],
			["preparationGeneration", 2, "EXECUTION_GENERATION_MISMATCH"],
			["executionGeneration", 2, "EXECUTION_GENERATION_MISMATCH"],
			["packageDigest", "1".repeat(64), "PACKAGE_DIGEST_MISMATCH"],
			["capabilityRecordRevision", 6, "CAPABILITY_RECORD_MISMATCH"],
			["capabilityRecordHash", "3".repeat(64), "CAPABILITY_RECORD_MISMATCH"],
			["secretRevision", 4, "SECRET_SNAPSHOT_MISMATCH"],
			["secretValuesDigest", "9".repeat(64), "SECRET_SNAPSHOT_MISMATCH"],
			["configRevision", 3, "CONFIG_SNAPSHOT_MISMATCH"],
			["configSnapshotRef", "a".repeat(64), "CONFIG_SNAPSHOT_MISMATCH"],
			["configValuesDigest", "b".repeat(64), "CONFIG_SNAPSHOT_MISMATCH"],
		];
		for (const [field, value, code] of cases) {
			const reported = validateWasmReadinessHealthV2(roundTrip({ ...expected, [field]: value }));
			expect(reported.ok).toBe(true);
			if (!reported.ok) continue;
			const errors = expectRejected(correlateWasmReadinessHealthV2(expected, reported.value));
			expect(hasCode(errors, code)).toBe(true);
		}
		// binding 错配覆盖可变字段（catalogRevision/catalogHash/entryKey/imageDigest）：
		// 这些值合法但与期望不同，由 correlate 判 RUNTIME_BINDING_MISMATCH。
		const bindingCases: readonly Record<string, unknown>[] = [
			{ catalogRevision: 10 },
			{ catalogHash: "ac".repeat(32) },
			{ entryKey: "other-wasmd" },
			{ imageDigest: "sha256:" + "ce".repeat(32) },
		];
		for (const override of bindingCases) {
			const reported = validateWasmReadinessHealthV2(roundTrip({ ...expected, runtimeBinding: { ...expected.runtimeBinding, ...override } }));
			expect(reported.ok).toBe(true);
			if (!reported.ok) continue;
			expect(hasCode(expectRejected(correlateWasmReadinessHealthV2(expected, reported.value)), "RUNTIME_BINDING_MISMATCH")).toBe(true);
		}
		// hostABI/world 是 v1 固定字面量：不存在「合法但不同」的 wire，错配即 schema 级 fail-closed。
		expectRejected(validateWasmReadinessHealthV2(roundTrip({ ...expected, runtimeBinding: { ...expected.runtimeBinding, hostABI: "iweb-wasmd-abi@1.1.0" } })));
		expectRejected(validateWasmReadinessHealthV2(roundTrip({ ...expected, runtimeBinding: { ...expected.runtimeBinding, world: "wasi:http/proxy@0.2.7" } })));
	});
});

describe("ReadinessLeaseV2 canonical wire", () => {
	test("round-trips and reproduces the digest with an independent oracle", () => {
		const lease = exampleReadinessLeaseV2();
		const result = validateReadinessLeaseV2(roundTrip(lease));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(lease);
		const { leaseDigest, ...withoutDigest } = lease;
		const oracle = createHash("sha256").update("iweb-readiness-lease-v2\n" + jcsCanonicalize(withoutDigest), "utf8").digest("hex");
		expect(leaseDigest).toBe(oracle);
		expect(computeReadinessLeaseDigestV2(withoutDigest)).toBe(oracle);
	});

	test("rejects tampered bytes: digest mismatch is READINESS_LEASE_MISMATCH", () => {
		const tampered = { ...exampleReadinessLeaseV2(), secretRevision: 4 };
		expect(hasCode(expectRejected(validateReadinessLeaseV2(tampered)), READINESS_LEASE_MISMATCH)).toBe(true);
	});

	test("nonce grammar is exactly 32 lower-case hex characters", () => {
		for (const leaseNonce of ["f".repeat(31), "F".repeat(32), "f".repeat(33), "z".repeat(32), 42]) {
			expectRejected(validateReadinessLeaseV2(recomputeLease({ leaseNonce: leaseNonce as unknown as string })));
		}
	});

	test("expiresAt must be later than issuedAt and within the pinned staging TTL", () => {
		expect(validateReadinessLeaseV2(roundTrip(exampleReadinessLeaseV2()), { stagingTtlSeconds: 600 }).ok).toBe(true);
		expect(validateReadinessLeaseV2(roundTrip(exampleReadinessLeaseV2()), { stagingTtlSeconds: 599 }).ok).toBe(false);
		expect(validateReadinessLeaseV2(roundTrip(exampleReadinessLeaseV2()), { stagingTtlSeconds: 3600 }).ok).toBe(true);
		for (const stagingTtlSeconds of [0, 3601, 1.5]) {
			expectRejected(validateReadinessLeaseV2(roundTrip(exampleReadinessLeaseV2()), { stagingTtlSeconds }));
		}
		const inverted = recomputeLease({ issuedAt: "2026-08-26T00:10:00Z", expiresAt: "2026-08-26T00:00:00Z" });
		expectRejected(validateReadinessLeaseV2(inverted));
		const equal = recomputeLease({ issuedAt: "2026-08-26T00:00:00Z", expiresAt: "2026-08-26T00:00:00Z" });
		expectRejected(validateReadinessLeaseV2(equal));
	});

	test("a celld {versionId,expiresAt} lease row is invalid for wasm (restart scenario)", () => {
		const legacyRow = { versionId: VECTOR_VERSION_DIGEST + "-1", expiresAt: "2026-08-26T00:10:00Z" };
		expectRejected(validateReadinessLeaseV2(legacyRow));
		const withSequence = { ...legacyRow, sequence: 3 };
		expect(hasCode(expectRejected(validateReadinessLeaseV2(withSequence)), WASM_IDENTITY_INCOMPLETE)).toBe(true);
	});

	test("CAS expiry: an instant equal to or later than expiresAt rejects", () => {
		const lease = exampleReadinessLeaseV2();
		const expiresMs = Date.parse(lease.expiresAt);
		expect(checkReadinessLeaseExpiry(lease, expiresMs - 1).ok).toBe(true);
		expect(hasCode(expectRejected(checkReadinessLeaseExpiry(lease, expiresMs)), READINESS_LEASE_EXPIRED)).toBe(true);
		expect(hasCode(expectRejected(checkReadinessLeaseExpiry(lease, expiresMs + 1)), READINESS_LEASE_EXPIRED)).toBe(true);
	});

	test("correlate rejects every mismatched fence field as READINESS_LEASE_MISMATCH", () => {
		const expected = exampleReadinessLeaseV2();
		expect(correlateReadinessLeaseV2(expected, exampleReadinessLeaseV2()).ok).toBe(true);
		for (const [field, value] of [["sandboxId", "sbx-other"], ["versionId", VECTOR_VERSION_DIGEST + "-2"], ["executionGeneration", 2], ["packageDigest", "1".repeat(64)], ["secretRevision", 4]] as const) {
			const lease = validateReadinessLeaseV2(recomputeLease({ [field]: value } as Record<string, unknown>));
			expect(lease.ok).toBe(true);
			if (!lease.ok) continue;
			expect(hasCode(expectRejected(correlateReadinessLeaseV2(expected, lease.value)), READINESS_LEASE_MISMATCH)).toBe(true);
		}
	});

	test("nonce consume is one-shot; replay and cross-tuple reuse fail closed", () => {
		const lease = exampleReadinessLeaseV2();
		const beforeMs = Date.parse(lease.issuedAt);
		const empty: ReadonlyMap<string, string> = new Map();
		expect(isReadinessLeaseNonceConsumed(empty, lease.leaseNonce)).toBe(false);

		const first = consumeReadinessLeaseV2(empty, lease, beforeMs);
		expect(first.outcome).toBe("consumed");
		if (first.outcome === "consumed") expect(isReadinessLeaseNonceConsumed(first.nextLedger, lease.leaseNonce)).toBe(true);

		// 同一 lease 重放：already-consumed（宿主按 activationId 返回原始结果，不二次激活）。
		const replay = consumeReadinessLeaseV2(first.outcome === "consumed" ? first.nextLedger : empty, lease, beforeMs);
		expect(replay.outcome).toBe("already-consumed");

		// 同 nonce 绑定另一 tuple：READINESS_LEASE_MISMATCH（duplicate nonce for another tuple）。
		const otherTuple = validateReadinessLeaseV2(recomputeLease({ secretRevision: 4 }));
		expect(otherTuple.ok).toBe(true);
		if (otherTuple.ok && first.outcome === "consumed") {
			const crossTuple = consumeReadinessLeaseV2(first.nextLedger, otherTuple.value, beforeMs);
			expect(crossTuple.outcome).toBe("rejected");
			if (crossTuple.outcome === "rejected") expect(hasCode(crossTuple.errors, READINESS_LEASE_MISMATCH)).toBe(true);
		}

		// 未消费但已过期的 lease：CAS 时刻拒绝，nonce 不入账。
		const expiredAt = Date.parse(lease.expiresAt);
		const expired = consumeReadinessLeaseV2(empty, lease, expiredAt);
		expect(expired.outcome).toBe("rejected");
		if (expired.outcome === "rejected") expect(hasCode(expired.errors, READINESS_LEASE_EXPIRED)).toBe(true);
	});
});

describe("engine metrics v1 wire", () => {
	test("round-trips an available sample with the exact five counter fields", () => {
		const example = exampleWasmEngineMetricsV1();
		const result = validateWasmEngineMetricsV1(roundTrip(example));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toEqual(example);
	});

	test("unavailable is the sole no-sample representation: engine null iff unavailable", () => {
		const unavailable = { ...exampleWasmEngineMetricsV1(), availability: "unavailable", engine: null };
		expect(validateWasmEngineMetricsV1(roundTrip(unavailable)).ok).toBe(true);
		expectRejected(validateWasmEngineMetricsV1({ ...unavailable, engine: { ...exampleWasmEngineMetricsV1().engine } }));
		expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), engine: null }));
		const missingChild = { ...exampleWasmEngineMetricsV1().engine } as Record<string, unknown>;
		delete missingChild.guestMemoryBytesInstant;
		expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), engine: missingChild }));
		expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), engine: { ...exampleWasmEngineMetricsV1().engine, extra: 1 } }));
	});

	test("fuel null is the disabled-only representation; numeric zero is a proven zero", () => {
		expect(validateWasmEngineMetricsV1(roundTrip({ ...exampleWasmEngineMetricsV1(), engine: { ...exampleWasmEngineMetricsV1().engine, fuelConsumedCumulative: null } })).ok).toBe(true);
		expect(validateWasmEngineMetricsV1(roundTrip({ ...exampleWasmEngineMetricsV1(), engine: { ...exampleWasmEngineMetricsV1().engine, fuelConsumedCumulative: 0 } })).ok).toBe(true);
		for (const bad of [-1, 1.5, 9007199254740992, "10"]) {
			expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), engine: { ...exampleWasmEngineMetricsV1().engine, fuelConsumedCumulative: bad } }));
		}
		const window = openWasmEngineMetricsWindow(1);
		expect(window.ok).toBe(true);
		if (!window.ok) return;
		const nullFuel = validateWasmEngineMetricsV1(roundTrip({ ...exampleWasmEngineMetricsV1(), engine: { ...exampleWasmEngineMetricsV1().engine, fuelConsumedCumulative: null } }));
		expect(nullFuel.ok).toBe(true);
		if (nullFuel.ok) {
			expect(hasCode(expectRejected(acceptWasmEngineMetricsSample(window.value, nullFuel.value, { fuelEnabled: true })), WASM_ENGINE_METRICS_FUEL_REPRESENTATION)).toBe(true);
			expect(acceptWasmEngineMetricsSample(window.value, nullFuel.value, { fuelEnabled: false }).ok).toBe(true);
		}
		const zeroFuel = validateWasmEngineMetricsV1(roundTrip({ ...exampleWasmEngineMetricsV1(), engine: { ...exampleWasmEngineMetricsV1().engine, fuelConsumedCumulative: 0 } }));
		expect(zeroFuel.ok).toBe(true);
		if (zeroFuel.ok) {
			expect(hasCode(expectRejected(acceptWasmEngineMetricsSample(window.value, zeroFuel.value, { fuelEnabled: false })), WASM_ENGINE_METRICS_FUEL_REPRESENTATION)).toBe(true);
			expect(acceptWasmEngineMetricsSample(window.value, zeroFuel.value, { fuelEnabled: true }).ok).toBe(true);
		}
	});

	test("rejects unknown fields, missing fields, wrong schema, bad config coupling, and celld signals", () => {
		expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), extra: 1 }));
		const missing = { ...exampleWasmEngineMetricsV1() } as Record<string, unknown>;
		delete missing.sampledAt;
		expectRejected(validateWasmEngineMetricsV1(missing));
		expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), schemaVersion: 2 }));
		const noConfig = { ...exampleWasmEngineMetricsV1(), configRevision: 0, configSnapshotRef: null };
		expect(validateWasmEngineMetricsV1(noConfig).ok).toBe(true);
		expectRejected(validateWasmEngineMetricsV1({ ...noConfig, configSnapshotRef: "7".repeat(64) }));
		expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), preparationGeneration: 0 }));
		expect(hasCode(expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), generation: 4 })), WASM_IDENTITY_INCOMPLETE)).toBe(true);
		expectRejected(validateWasmEngineMetricsV1({ ...exampleWasmEngineMetricsV1(), sampledAt: "2026-08-26T00:00:00+00:00" }));
	});

	test("correlate rejects stale or mismatched identity against the current execution record", () => {
		const fence = exampleWasmEngineMetricsV1();
		expect(correlateWasmEngineMetricsV1(fence, exampleWasmEngineMetricsV1()).ok).toBe(true);
		for (const [field, value, code] of [
			["sandboxId", "sbx-other", "SANDBOX_ID_MISMATCH"],
			["versionId", VECTOR_VERSION_DIGEST + "-2", "VERSION_ID_MISMATCH"],
			["executionGeneration", 2, WASM_ENGINE_METRICS_STALE],
			["packageDigest", "1".repeat(64), "PACKAGE_DIGEST_MISMATCH"],
			["capabilityRecordRevision", 6, "CAPABILITY_RECORD_MISMATCH"],
			["secretRevision", 4, "SECRET_REVISION_MISMATCH"],
			["configSnapshotRef", "a".repeat(64), "CONFIG_SNAPSHOT_MISMATCH"],
		] as const) {
			const reported = validateWasmEngineMetricsV1(roundTrip({ ...fence, [field]: value }));
			expect(reported.ok).toBe(true);
			if (!reported.ok) continue;
			expect(hasCode(expectRejected(correlateWasmEngineMetricsV1(fence, reported.value)), code)).toBe(true);
		}
	});
});

describe("engine metrics acceptance state machine", () => {
	function sampleAt(overrides: Record<string, unknown>): WasmEngineMetricsV1 {
		const parsed = validateWasmEngineMetricsV1(roundTrip({ ...exampleWasmEngineMetricsV1(), ...overrides }));
		if (!parsed.ok) throw new Error("test fixture must stay valid: " + JSON.stringify(parsed.errors));
		return parsed.value;
	}

	// baseline counters 固定为 (fuel 1000, epoch 2, highWater 3)；所有样本显式携带引擎值。
	const BASELINE_ENGINE = { fuelConsumedCumulative: 1000, epochTimeoutsCumulative: 2, instancesHighWaterCumulative: 3, instancesLiveInstant: 2, guestMemoryBytesInstant: 2097152 };

	function trackingWindow(overrides: Partial<Extract<WasmEngineMetricsWindow, { kind: "tracking" }>>): WasmEngineMetricsWindow {
		return { kind: "tracking", executionGeneration: 1, lastAcceptedSampledAt: "2026-08-26T00:00:00Z", fuelConsumedCumulative: 1000, epochTimeoutsCumulative: 2, instancesHighWaterCumulative: 3, ...overrides };
	}

	test("a new generation without a first sample projects unavailable and never zeroes counters", () => {
		const window = openWasmEngineMetricsWindow(5);
		expect(window.ok).toBe(true);
		if (!window.ok) return;
		expect(window.value.kind).toBe("awaiting-first-sample");
		const unavailable = sampleAt({ executionGeneration: 5, availability: "unavailable", engine: null, sampledAt: "2026-08-26T00:00:00Z" });
		const next = acceptWasmEngineMetricsSample(window.value, unavailable, { fuelEnabled: null });
		expect(next.ok).toBe(true);
		if (next.ok) expect(next.value.kind).toBe("awaiting-first-sample");
	});

	test("the first available sample establishes the baseline; later samples need strictly later sampledAt", () => {
		const window = openWasmEngineMetricsWindow(1);
		expect(window.ok).toBe(true);
		if (!window.ok) return;
		const first = acceptWasmEngineMetricsSample(window.value, sampleAt({ sampledAt: "2026-08-26T00:00:01Z" }), { fuelEnabled: true });
		expect(first.ok).toBe(true);
		if (!first.ok) return;
		expect(first.value.kind).toBe("tracking");

		const tied = acceptWasmEngineMetricsSample(first.value, sampleAt({ sampledAt: "2026-08-26T00:00:01Z" }), { fuelEnabled: true });
		expect(hasCode(expectRejected(tied), WASM_ENGINE_METRICS_TIME_REGRESSION)).toBe(true);
		const earlier = acceptWasmEngineMetricsSample(first.value, sampleAt({ sampledAt: "2026-08-26T00:00:00Z" }), { fuelEnabled: true });
		expect(hasCode(expectRejected(earlier), WASM_ENGINE_METRICS_TIME_REGRESSION)).toBe(true);
	});

	test("counters are non-negative monotonic within one generation; equal is accepted", () => {
		const window = trackingWindow({});
		const okSample = acceptWasmEngineMetricsSample(window, sampleAt({ sampledAt: "2026-08-26T00:00:02Z", engine: { ...BASELINE_ENGINE } }), { fuelEnabled: true });
		expect(okSample.ok).toBe(true);
		for (const engine of [
			{ ...BASELINE_ENGINE, fuelConsumedCumulative: 999 },
			{ ...BASELINE_ENGINE, epochTimeoutsCumulative: 1 },
			{ ...BASELINE_ENGINE, instancesHighWaterCumulative: 2 },
		] as const) {
			const regression = acceptWasmEngineMetricsSample(window, sampleAt({ sampledAt: "2026-08-26T00:00:02Z", engine }), { fuelEnabled: true });
			expect(hasCode(expectRejected(regression), WASM_ENGINE_METRICS_COUNTER_REGRESSION)).toBe(true);
		}
	});

	test("instantaneous values may move in either direction", () => {
		const window = trackingWindow({});
		const lowerInstant = acceptWasmEngineMetricsSample(
			window,
			sampleAt({ sampledAt: "2026-08-26T00:00:02Z", engine: { ...BASELINE_ENGINE, instancesLiveInstant: 0, guestMemoryBytesInstant: 0 } }),
			{ fuelEnabled: true },
		);
		expect(lowerInstant.ok).toBe(true);
	});

	test("a delayed prior-generation payload is stale, not a reset; only a new window resets counters", () => {
		const generation5 = trackingWindow({ executionGeneration: 5, fuelConsumedCumulative: 5000, epochTimeoutsCumulative: 7, instancesHighWaterCumulative: 9 });
		const delayedGeneration4 = sampleAt({ executionGeneration: 4, sampledAt: "2026-08-26T00:09:00Z" });
		expect(hasCode(expectRejected(acceptWasmEngineMetricsSample(generation5, delayedGeneration4, { fuelEnabled: true })), WASM_ENGINE_METRICS_STALE)).toBe(true);

		// Kernel 接受 generation 6 fence 后重开窗口：低 counter 的新 baseline 合法（reset 只经新 E）。
		const generation6 = openWasmEngineMetricsWindow(6);
		expect(generation6.ok).toBe(true);
		if (!generation6.ok) return;
		const fresh = acceptWasmEngineMetricsSample(generation6.value, sampleAt({ executionGeneration: 6, sampledAt: "2026-08-26T00:10:00Z", engine: { ...exampleWasmEngineMetricsV1().engine, fuelConsumedCumulative: 10, epochTimeoutsCumulative: 0, instancesHighWaterCumulative: 1 } }), { fuelEnabled: true });
		expect(fresh.ok).toBe(true);
	});

	test("unavailable samples keep the baseline and the fuel representation cannot switch within a generation", () => {
		const window = trackingWindow({});
		const unavailable = sampleAt({ availability: "unavailable", engine: null, sampledAt: "2026-08-26T00:00:02Z" });
		const afterUnavailable = acceptWasmEngineMetricsSample(window, unavailable, { fuelEnabled: true });
		expect(afterUnavailable.ok).toBe(true);
		if (!afterUnavailable.ok) return;
		expect(afterUnavailable.value.kind).toBe("tracking");

		const switchToNull = sampleAt({ sampledAt: "2026-08-26T00:00:03Z", engine: { ...exampleWasmEngineMetricsV1().engine, fuelConsumedCumulative: null } });
		expect(hasCode(expectRejected(acceptWasmEngineMetricsSample(afterUnavailable.value, switchToNull, { fuelEnabled: null })), WASM_ENGINE_METRICS_FUEL_REPRESENTATION)).toBe(true);
		// baseline 未被 unavailable 样本清零：counter 回退仍被拒绝。
		const regressed = sampleAt({ sampledAt: "2026-08-26T00:00:03Z", engine: { ...exampleWasmEngineMetricsV1().engine, epochTimeoutsCumulative: 0 } });
		expect(hasCode(expectRejected(acceptWasmEngineMetricsSample(afterUnavailable.value, regressed, { fuelEnabled: true })), WASM_ENGINE_METRICS_COUNTER_REGRESSION)).toBe(true);
	});
});

// 以重算 digest 的方式构造合法 lease fixture（字段覆盖后必须重算，否则 digest 判负）。
function recomputeLease(overrides: Record<string, unknown>): ReadinessLeaseV2 {
	const base = exampleReadinessLeaseV2();
	const merged: Record<string, unknown> = { ...base, ...overrides };
	const { leaseDigest, ...withoutDigest } = merged;
	void leaseDigest;
	return { ...(withoutDigest as Omit<ReadinessLeaseV2, "leaseDigest">), leaseDigest: computeReadinessLeaseDigestV2(withoutDigest as Omit<ReadinessLeaseV2, "leaseDigest">) };
}

// ---------------------------------------------------------------------------
// 激活面 wire（simplify-wasm-host-services 单一形态）——Rust kernel-rs 为 wire 权威；
// 本段只做 TS 侧 digest 复算（独立 bun oracle）与 fail-closed 校验，无跨语言 golden 对拍。
// ---------------------------------------------------------------------------

describe("activation/route wire（单一形态）", () => {
	function sha256Hex(bytes: Uint8Array): string {
		return createHash("sha256").update(bytes).digest("hex");
	}

	test("ServiceReadinessLeaseV2 recomputes the digest with an independent digestV2 oracle", () => {
		const lease = exampleServiceReadinessLeaseV2();
		expect(validateServiceReadinessLeaseV2(roundTrip(lease)).ok).toBe(true);
		// 独立 oracle：SHA-256(ASCII(domain) || 0x00 || JCS(record minus leaseDigest))。
		const { leaseDigest: _omitted, ...payload } = lease;
		const oracle = createHash("sha256")
			.update("iweb-wasm-readiness-v2", "ascii")
			.update(Buffer.from([0x00]))
			.update(Buffer.from(jcsCanonicalBytes(payload)))
			.digest("hex");
		expect(computeServiceReadinessLeaseDigestV2(payload)).toBe(oracle);
		expect(lease.leaseDigest).toBe(oracle);
		// 基础租约域与 service 租约域公式互不碰撞（"\n" vs 0x00 分隔）。
		expect(exampleReadinessLeaseV2().leaseDigest).not.toBe(lease.leaseDigest);
		// 负例：篡改任一字段 → digest 复算失败（READINESS_LEASE_MISMATCH）。
		const tampered = { ...lease, hostServicePolicyDigest: "9".repeat(64) };
		const rejected = expectRejected(validateServiceReadinessLeaseV2(roundTrip(tampered)));
		expect(hasCode(rejected, READINESS_LEASE_MISMATCH)).toBe(true);
	});

	test("ActivationCommand pins the service-enabled increments and recomputes its digest", () => {
		const command = exampleActivationCommand();
		expect(validateActivationCommand(roundTrip(command)).ok).toBe(true);
		expect(command.expectedControlRevision).toBe(0);
		expect(command.candidate.runtimeBinding.hostABI).toBe("iweb-wasmd-abi@1.1.0");
		expect(correlateServiceReadinessLeaseV2(command, exampleServiceReadinessLeaseV2()).ok).toBe(true);
		// 独立 oracle：commandDigest = SHA-256(ASCII(domain) || 0x00 || JCS(record minus digest))。
		const { commandDigest: _omitDigest, ...payload } = command;
		const oracle = createHash("sha256")
			.update("iweb-wasm-activation-v2", "ascii")
			.update(Buffer.from([0x00]))
			.update(Buffer.from(jcsCanonicalBytes(payload)))
			.digest("hex");
		expect(command.commandDigest).toBe(oracle);
		expect(sha256Hex(jcsCanonicalBytes(command))).not.toBe(oracle);
		// 负例：schemaVersion 钳 2、policy digest 文法、ABI 1.0.0 binding、未知字段、
		// 缺 hostServicePolicyDigest 的形状不落入解析器。
		expect(validateActivationCommand(roundTrip({ ...command, schemaVersion: 1 })).ok).toBe(false);
		expect(validateActivationCommand(roundTrip({ ...command, hostServicePolicyDigest: "zz" })).ok).toBe(false);
		const staleBinding = { ...command, candidate: { ...command.candidate, runtimeBinding: { ...command.candidate.runtimeBinding, hostABI: "iweb-wasmd-abi@1.0.0" } } };
		expect(validateActivationCommand(roundTrip(staleBinding)).ok).toBe(false);
		expect(validateActivationCommand(roundTrip({ ...command, extra: 1 })).ok).toBe(false);
		const { hostServicePolicyDigest: _missing, ...withoutPolicy } = command;
		expect(validateActivationCommand(roundTrip(withoutPolicy)).ok).toBe(false);
		// expectedControlRevision u53 + commandDigest 复算 fail-closed。
		expect(validateActivationCommand(roundTrip({ ...command, expectedControlRevision: 2 ** 53 })).ok).toBe(false);
		const tamperedDigest = { ...command, commandDigest: "0".repeat(64) };
		const digestRejected = expectRejected(validateActivationCommand(roundTrip(tamperedDigest)));
		expect(hasCode(digestRejected, "WASM_ACTIVATION_COMMAND_INVALID")).toBe(true);
		// 被覆盖字段（policy digest）篡改而摘要未重算 → 复算失败。
		expect(validateActivationCommand(roundTrip({ ...command, hostServicePolicyDigest: "9".repeat(64) })).ok).toBe(false);
		// 合法变异后重算摘要 → 通过（policy 钉由 correlate 另行把关）。
		const resealed = { ...payload, hostServicePolicyDigest: "9".repeat(64) };
		expect(validateActivationCommand(roundTrip({ ...resealed, commandDigest: computeActivationCommandDigest(resealed) })).ok).toBe(true);
		// correlate 负例：policy 钉不等 → WASM_HOST_POLICY_DIGEST_MISMATCH。
		const otherPolicy = { ...command, hostServicePolicyDigest: "9".repeat(64) };
		const rejected = expectRejected(correlateServiceReadinessLeaseV2(otherPolicy, exampleServiceReadinessLeaseV2()));
		expect(hasCode(rejected, "WASM_HOST_POLICY_DIGEST_MISMATCH")).toBe(true);
	});

	test("RouteEvent validates the activated/rejected coupling and recomputes eventDigest", () => {
		const event = exampleRouteEvent();
		expect(validateRouteEvent(roundTrip(event)).ok).toBe(true);
		expect(event.controlRevision).toBe(1);
		expect(event.hostServicePolicyDigest).toBe(exampleActivationCommand().hostServicePolicyDigest);
		// 独立 oracle：eventDigest = SHA-256(ASCII(domain) || 0x00 || JCS(record minus digest))。
		const { eventDigest: _omitDigest, ...payload } = event;
		const oracle = createHash("sha256")
			.update("iweb-wasm-route-event-v2", "ascii")
			.update(Buffer.from([0x00]))
			.update(Buffer.from(jcsCanonicalBytes(payload)))
			.digest("hex");
		expect(event.eventDigest).toBe(oracle);
		// 负例：activated 带 reasonCode / rejected 缺 reasonCode / 拒绝翻指针 / 未知字段。
		expect(validateRouteEvent(roundTrip({ ...event, reasonCode: "NOPE" })).ok).toBe(false);
		const rejectedShape = { ...event, result: "rejected" as const };
		expect(validateRouteEvent(roundTrip(rejectedShape)).ok).toBe(false);
		expect(validateRouteEvent(roundTrip({ ...event, extra: 1 })).ok).toBe(false);
		// eventDigest 复算 fail-closed（篡改摘要 / 被覆盖字段 controlRevision）。
		const digestRejected = expectRejected(validateRouteEvent(roundTrip({ ...event, eventDigest: "0".repeat(64) })));
		expect(hasCode(digestRejected, "WASM_ROUTE_EVENT_INVALID")).toBe(true);
		expect(validateRouteEvent(roundTrip({ ...event, controlRevision: 7 })).ok).toBe(false);
		// 合法变异后重算摘要 → 通过。
		const resealed = { ...payload, controlRevision: 7 };
		expect(validateRouteEvent(roundTrip({ ...resealed, eventDigest: computeRouteEventDigest(resealed) })).ok).toBe(true);
	});

	test("RollbackRecord carries the complete envelope and recomputes rollbackDigest", () => {
		const record = exampleRollbackRecord();
		expect(validateRollbackRecord(roundTrip(record)).ok).toBe(true);
		expect(record.schemaVersion).toBe(2);
		expect(record.result).toBe("applied");
		expect(record.reasonCode).toBeNull();
		expect(record.routeEvent.operation).toBe("rollback");
		// 独立 oracle：rollbackDigest = SHA-256(ASCII(domain) || 0x00 || JCS(record minus digest))。
		const { rollbackDigest: _omitDigest, ...payload } = record;
		const oracle = createHash("sha256")
			.update("iweb-wasm-rollback-v2", "ascii")
			.update(Buffer.from([0x00]))
			.update(Buffer.from(jcsCanonicalBytes(payload)))
			.digest("hex");
		expect(record.rollbackDigest).toBe(oracle);
		// 负例：policy digest 缺失/文法、未知字段、rollbackDigest 复算、reason/result 耦合。
		const { hostServicePolicyDigest: _missing, ...withoutPolicy } = record;
		expect(validateRollbackRecord(roundTrip(withoutPolicy)).ok).toBe(false);
		expect(validateRollbackRecord(roundTrip({ ...record, hostServicePolicyDigest: "zz" })).ok).toBe(false);
		expect(validateRollbackRecord(roundTrip({ ...record, extra: 1 })).ok).toBe(false);
		const digestRejected = expectRejected(validateRollbackRecord(roundTrip({ ...record, rollbackDigest: "0".repeat(64) })));
		expect(hasCode(digestRejected, "WASM_ROLLBACK_RECORD_INVALID")).toBe(true);
		expect(validateRollbackRecord(roundTrip({ ...record, expectedControlRevision: 5 })).ok).toBe(false);
		// applied 带 reasonCode：即使重算摘要也必须拒绝（reason/result 耦合）。
		const badReason = { ...payload, reasonCode: "NOPE" };
		expect(validateRollbackRecord(roundTrip({ ...badReason, rollbackDigest: computeRollbackRecordDigest(badReason) })).ok).toBe(false);
	});

	// simplify-wasm-host-services P0 空串闭环：hostServicePolicyDigest 空串（policyless
	// 版本）在 lease/activation/route-event/rollback 四个校验器均为合法——摘要按新钉值
	// 复算通过；命令与 lease 同钉空串的 correlate 匹配。
	test("an empty hostServicePolicyDigest is legal across the lease/activation/route/rollback wires", () => {
		const lease = exampleServiceReadinessLeaseV2();
		const { leaseDigest: _omitLeaseDigest, ...leasePayload } = lease;
		const policylessLeasePayload = { ...leasePayload, hostServicePolicyDigest: "" };
		const policylessLease = { ...policylessLeasePayload, leaseDigest: computeServiceReadinessLeaseDigestV2(policylessLeasePayload) };
		expect(validateServiceReadinessLeaseV2(roundTrip(policylessLease)).ok).toBe(true);

		const command = exampleActivationCommand();
		const { commandDigest: _omitCommandDigest, ...commandPayload } = command;
		// 命令候选引用同一 policyless lease（真实链路：Kernel 先铸 lease，命令再引用其 digest）。
		const policylessCommandPayload = { ...commandPayload, hostServicePolicyDigest: "", candidate: { ...commandPayload.candidate, leaseDigest: policylessLease.leaseDigest } };
		const policylessCommand = { ...policylessCommandPayload, commandDigest: computeActivationCommandDigest(policylessCommandPayload) };
		expect(validateActivationCommand(roundTrip(policylessCommand)).ok).toBe(true);
		expect(correlateServiceReadinessLeaseV2(policylessCommand, policylessLease).ok).toBe(true);

		const event = exampleRouteEvent();
		const { eventDigest: _omitEventDigest, ...eventPayload } = event;
		const policylessEventPayload = { ...eventPayload, hostServicePolicyDigest: "" };
		expect(validateRouteEvent(roundTrip({ ...policylessEventPayload, eventDigest: computeRouteEventDigest(policylessEventPayload) })).ok).toBe(true);

		const rollback = exampleRollbackRecord();
		const { rollbackDigest: _omitRollbackDigest, ...rollbackPayload } = rollback;
		const policylessRollbackPayload = { ...rollbackPayload, hostServicePolicyDigest: "" };
		expect(validateRollbackRecord(roundTrip({ ...policylessRollbackPayload, rollbackDigest: computeRollbackRecordDigest(policylessRollbackPayload) })).ok).toBe(true);
	});

	// P1 收紧：active pointer 三个可选增量不再是任意 string/number——hostServicePolicyDigest
	// 空串或 64 位 hex、preparationGeneration/executionGeneration 安全整数 1..u53。
	test("active pointer increments are strictly validated (empty-or-hex digest, safe-integer generations >= 1)", () => {
		const event = exampleRouteEvent();
		const { eventDigest: _omit, ...payload } = event;
		const withIncrements = {
			...event.next,
			hostServicePolicyDigest: event.hostServicePolicyDigest,
			preparationGeneration: 1,
			executionGeneration: 1,
		};
		if (withIncrements.kind !== "active") throw new Error("fixture error: example next pointer must be active");
		const sealedValid = { ...payload, next: withIncrements };
		expect(validateRouteEvent(roundTrip({ ...sealedValid, eventDigest: computeRouteEventDigest(sealedValid) })).ok).toBe(true);
		// 空串钉同样合法（policyless 活动指针）。
		const sealedEmpty = { ...payload, next: { ...withIncrements, hostServicePolicyDigest: "" } };
		expect(validateRouteEvent(roundTrip({ ...sealedEmpty, eventDigest: computeRouteEventDigest(sealedEmpty) })).ok).toBe(true);
		// 负例（重算摘要后仍拒——指针字段校验先于摘要复算）："zz"、-1、1.5、0。
		const badIncrements: readonly Record<string, unknown>[] = [
			{ hostServicePolicyDigest: "zz" },
			{ hostServicePolicyDigest: "e" },
			{ preparationGeneration: -1 },
			{ preparationGeneration: 1.5 },
			{ preparationGeneration: 0 },
			{ executionGeneration: -1 },
			{ executionGeneration: 1.5 },
			{ executionGeneration: 0 },
		];
		for (const bad of badIncrements) {
			const mutated = { ...payload, next: { ...withIncrements, ...bad } };
			const rejected = expectRejected(validateRouteEvent(roundTrip({ ...mutated, eventDigest: computeRouteEventDigest(mutated) })));
			expect(hasCode(rejected, "WASM_ROUTE_EVENT_INVALID")).toBe(true);
		}
	});
});
