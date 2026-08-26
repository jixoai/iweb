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
import { jcsCanonicalize } from "../packages/contracts/wasm-package.ts";
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
