// 用户原始需求（2026-08-14）：typed records 必须 round-trip，并拒绝 deep unknown field、超长字符串、非法 Unicode/控制字符、路径穿越与越界数值。
// 正交意图：禁止 any/as any；所有外部输入 runtime-validate。
import { describe, expect, test } from "bun:test";
import {
	validateActiveVersionRecord,
	validateApplicationIdentity,
	validateFailureCategory,
	validateLifecycleState,
	validateNormalizedPolicy,
	validateReadinessLease,
	validateResourceSample,
	validateVersionIdentity,
} from "../packages/contracts/records.ts";

const sha = "a".repeat(64);

describe("application records", () => {
	test("round-trips application and version identity", () => {
		const app = validateApplicationIdentity({ id: "notes" });
		expect(app.ok).toBe(true);
		if (app.ok) expect(app.value.id).toBe("notes");
		const version = validateVersionIdentity({ applicationId: "notes", digest: sha, sequence: 3 });
		expect(version.ok).toBe(true);
		if (version.ok) expect(version.value.sequence).toBe(3);
	});

	test("rejects unknown fields at any depth", () => {
		const top = validateApplicationIdentity({ id: "notes", extra: true });
		expect(top.ok).toBe(false);
		if (!top.ok) expect(top.errors.some((issue) => issue.code === "UNKNOWN_FIELD")).toBe(true);
		const deep = validateNormalizedPolicy({
			resources: { cpuMillis: 100, memoryBytes: 1024, pidLimit: 10, storageBytes: 1024, extra: 1 },
			egress: { default: "deny", allow: [] },
		});
		expect(deep.ok).toBe(false);
		if (!deep.ok) expect(deep.errors.some((issue) => issue.code === "UNKNOWN_FIELD")).toBe(true);
	});

	test("rejects overlong and control-character identifiers", () => {
		const overlong = validateApplicationIdentity({ id: "x".repeat(100) });
		expect(overlong.ok).toBe(false);
		const control = validateApplicationIdentity({ id: "notes\nroot" });
		expect(control.ok).toBe(false);
		const unicode = validateApplicationIdentity({ id: "笔记" });
		expect(unicode.ok).toBe(false);
	});

	test("rejects path traversal and wrong identity shapes", () => {
		for (const id of ["../notes", "a/b", "/etc", "..", "."]) {
			expect(validateApplicationIdentity({ id }).ok).toBe(false);
		}
		const wrongDigest = validateVersionIdentity({ applicationId: "notes", digest: "not-hex", sequence: 1 });
		expect(wrongDigest.ok).toBe(false);
		if (!wrongDigest.ok) expect(wrongDigest.errors.some((issue) => issue.code === "INVALID_DIGEST")).toBe(true);
	});

	test("rejects out-of-range and non-safe numeric values", () => {
		for (const sequence of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, Number.POSITIVE_INFINITY]) {
			expect(validateVersionIdentity({ applicationId: "notes", digest: sha, sequence }).ok).toBe(false);
		}
	});

	test("round-trips policy, lease, lifecycle, failure category and resource sample", () => {
		const policy = validateNormalizedPolicy({
			resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 },
			egress: { default: "deny", allow: [{ host: "api.example.com", port: 443 }] },
		});
		expect(policy.ok).toBe(true);
		const lease = validateReadinessLease({ versionId: "v1", expiresAt: "2026-08-14T00:00:00.000Z" });
		expect(lease.ok).toBe(true);
		expect(validateLifecycleState("ready").ok).toBe(true);
		expect(validateLifecycleState("bogus").ok).toBe(false);
		expect(validateFailureCategory("resource-limit").ok).toBe(true);
		expect(validateFailureCategory("bogus").ok).toBe(false);
		const sample = validateResourceSample({
			versionId: "v1",
			sampledAt: "2026-08-14T00:00:00.000Z",
			cpuMillis: { available: true, value: 12 },
			memoryBytes: { available: true, value: 3000000 },
			pidCount: { available: true, value: 4 },
			terminated: { available: true, value: 0 },
			limits: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 },
		});
		expect(sample.ok).toBe(true);
		if (sample.ok) expect(sample.value.memoryBytes).toEqual({ available: true, value: 3000000 });
	});

	test("preserves unavailable measurements and nullable limits without substituting zero", () => {
		const sample = validateResourceSample({
			versionId: "v1",
			sampledAt: "2026-08-14T00:00:00.000Z",
			cpuMillis: { available: false },
			memoryBytes: { available: true, value: 0 },
			pidCount: { available: false },
			terminated: { available: false },
			limits: { cpuMillis: null, memoryBytes: 128 * 2 ** 20, pidLimit: null, storageBytes: null },
		});
		expect(sample.ok).toBe(true);
		if (!sample.ok) return;
		expect(sample.value.cpuMillis).toEqual({ available: false });
		expect(sample.value.memoryBytes).toEqual({ available: true, value: 0 });
		expect(sample.value.limits?.cpuMillis).toBeNull();
	});

	test("rejects unavailable measurements carrying values and wrong limit shapes", () => {
		const carried = validateResourceSample({
			versionId: "v1",
			sampledAt: "2026-08-14T00:00:00.000Z",
			cpuMillis: { available: false, value: 1 },
			memoryBytes: { available: true, value: 2 },
			pidCount: { available: true, value: 3 },
			terminated: { available: true, value: 0 },
			limits: null,
		});
		expect(carried.ok).toBe(false);
		const negativeLimit = validateResourceSample({
			versionId: "v1",
			sampledAt: "2026-08-14T00:00:00.000Z",
			cpuMillis: { available: true, value: 1 },
			memoryBytes: { available: true, value: 2 },
			pidCount: { available: true, value: 3 },
			terminated: { available: true, value: 0 },
			limits: { cpuMillis: -5, memoryBytes: null, pidLimit: null, storageBytes: null },
		});
		expect(negativeLimit.ok).toBe(false);
	});
});


describe("active-version pointer record", () => {
	test("round-trips unavailable and active pointers", () => {
		const unavailable = validateActiveVersionRecord({ kind: "unavailable", applicationId: "notes", routeGeneration: 0 });
		expect(unavailable.ok).toBe(true);
		if (unavailable.ok) expect(unavailable.value.kind).toBe("unavailable");
		const active = validateActiveVersionRecord({ kind: "active", applicationId: "notes", routeGeneration: 1, version: { applicationId: "notes", digest: sha, sequence: 2 } });
		expect(active.ok).toBe(true);
		if (active.ok) expect(active.value.kind).toBe("active");
	});

	test("rejects mismatched version identity, unavailable carrying a version, and unknown kind", () => {
		const mismatch = validateActiveVersionRecord({ kind: "active", applicationId: "notes", routeGeneration: 1, version: { applicationId: "other", digest: sha, sequence: 2 } });
		expect(mismatch.ok).toBe(false);
		if (!mismatch.ok) expect(mismatch.errors.some((issue) => issue.code === "IDENTITY_MISMATCH")).toBe(true);
		const carriedVersion = validateActiveVersionRecord({ kind: "unavailable", applicationId: "notes", routeGeneration: 0, version: { applicationId: "notes", digest: sha, sequence: 1 } });
		expect(carriedVersion.ok).toBe(false);
		const badKind = validateActiveVersionRecord({ kind: "bogus", applicationId: "notes", routeGeneration: 0 });
		expect(badKind.ok).toBe(false);
		const negativeGeneration = validateActiveVersionRecord({ kind: "unavailable", applicationId: "notes", routeGeneration: -1 });
		expect(negativeGeneration.ok).toBe(false);
	});
});

