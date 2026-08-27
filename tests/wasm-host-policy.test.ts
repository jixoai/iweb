// 用户原始需求（2026-08-27，add-wasm-host-services Kernel 数据面权威批次）：wasm-host-policy.ts 的
// digestV2 域分隔（0x00）、HostServicePolicyV2 seal/validate、capability matrix/record revision 2 增量、
// HostServiceIdentityV2 与 guestMemory reserve 公式必须有 fail-closed 契约测试。
// 正交意图：digestV2 oracle 与 V1 域分隔不可混用；policy 精确键集/上限/全 null 拒绝；矩阵 rev2 并集与排序；
// capability increment hash；identity/versionDigest/versionId 投影；SQL 占位 limits 的权威锚点一致性。
// 规范权威：openspec/changes/add-wasm-host-services/design.md「Decisions 1/2/3」。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
	computeWasmHostServicePolicyDigestV2,
	computeWasmHostServiceVersionDigestV2,
	digestV2,
	formatWasmVersionIdV2,
	sealWasmHostServiceCapabilityIncrementV2,
	sealWasmHostServicePolicyV2,
	validateWasmCapabilityMatrixV2,
	validateWasmHostServiceCapabilityIncrementV2,
	validateWasmHostServiceIdentityV2,
	validateWasmHostServicePolicyV2,
	WASM_CAPABILITY_MATRIX_V2,
	WASM_CAPABILITY_MATRIX_REVISION_2_HOST_IMPORTS,
	WASM_DIGEST_V2_DOMAINS,
	WASM_HOST_ABI_LITERAL_V2,
	WASM_HOST_SERVICE_NODE_MAXIMA,
	WASM_HOST_SERVICE_PROFILE_DEFAULTS,
	checkWasmGuestMemoryReserve,
} from "../packages/contracts/wasm-host-policy.ts";
import { WASM_CAPABILITY_MATRIX_REVISION_1 } from "../packages/contracts/wasm-capability.ts";
import { IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS } from "../packages/contracts/wasm-host-sql.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";

const HEX_64 = /^[a-f0-9]{64}$/;

function oracleDigestV2(domain: string, payload: Uint8Array): string {
	return createHash("sha256")
		.update(domain, "ascii")
		.update(Buffer.from([0x00]))
		.update(Buffer.from(payload))
		.digest("hex");
}

function policyPayloadFixture(): Record<string, unknown> {
	return {
		schemaVersion: 2,
		matrixRevision: 2,
		hostAbi: WASM_HOST_ABI_LITERAL_V2,
		hostServices: {
			kv: {
				profile: "bounded-cas-list-v1",
				limits: WASM_HOST_SERVICE_PROFILE_DEFAULTS.kv,
				consistency: "single-key-linearizable-cas-v1",
				durability: "sqlite-full-fsync-v1",
				retention: "tombstone-window-v1",
			},
			sql: {
				profile: "minimal-sqlite-v1",
				limits: IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS,
				consistency: "implicit-transaction-per-call-v1",
				durability: "sqlite-full-fsync-v1",
				retention: "retained-until-application-deletion-v1",
			},
			logging: {
				profile: "bounded-memory-ring-v1",
				limits: WASM_HOST_SERVICE_PROFILE_DEFAULTS.logging,
				consistency: "append-only-drop-on-full-v1",
				durability: "no-durable-claim-v1",
				retention: "runtime-lifecycle-only-v1",
			},
		},
		storageBytes: 240000000,
		reserveBytes: 33554432,
		dataDirectoryProfile: "per-app-sqlite-v1",
		durabilityProfile: "sqlite-full-fsync-v1",
	};
}

describe("digestV2", () => {
	test("frames the domain with a single 0x00 separator", () => {
		const payload = jcsCanonicalBytes({ a: 1 });
		expect(digestV2("iweb-wasm-host-policy-v2", payload)).toBe(oracleDigestV2("iweb-wasm-host-policy-v2", payload));
	});

	test("does not collide with the V1 newline-separated domain convention", () => {
		const payload = jcsCanonicalBytes({ schemaVersion: 2 });
		const v2 = digestV2("iweb-wasm-host-policy-v2", payload);
		const v1Style = createHash("sha256").update("iweb-wasm-host-policy-v2", "ascii").update("\n").update(Buffer.from(payload)).digest("hex");
		expect(v2).not.toBe(v1Style);
		expect(v2).toMatch(HEX_64);
	});

	test("never hashes hex text twice", () => {
		const payload = jcsCanonicalBytes({ b: 2 });
		const once = digestV2("iweb-wasm-quota-reservation-v2", payload);
		const twice = digestV2("iweb-wasm-quota-reservation-v2", new TextEncoder().encode(once));
		expect(once).not.toBe(twice);
	});

	test("exports the exact 16-domain table from the design", () => {
		expect(WASM_DIGEST_V2_DOMAINS).toHaveLength(16);
		expect(WASM_DIGEST_V2_DOMAINS).toContain("iweb-wasm-host-policy-v2");
		expect(WASM_DIGEST_V2_DOMAINS).toContain("iweb-wasm-quota-reservation-v2");
	});
});

describe("HostServicePolicyV2", () => {
	test("seals a valid payload with the policy-domain digest", () => {
		const sealed = sealWasmHostServicePolicyV2(policyPayloadFixture());
		expect(sealed.ok).toBe(true);
		if (sealed.ok) {
			expect(sealed.value.policyDigest).toBe(oracleDigestV2("iweb-wasm-host-policy-v2", jcsCanonicalBytes(policyPayloadFixture())));
			const validated = validateWasmHostServicePolicyV2(sealed.value);
			expect(validated.ok).toBe(true);
		}
	});

	test("rejects a tampered digest", () => {
		const sealed = sealWasmHostServicePolicyV2(policyPayloadFixture());
		expect(sealed.ok).toBe(true);
		if (!sealed.ok) return;
		const tampered = { ...sealed.value, storageBytes: sealed.value.storageBytes + 1 };
		const result = validateWasmHostServicePolicyV2(tampered);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((entry) => entry.code === "WASM_HOST_POLICY_DIGEST_MISMATCH")).toBe(true);
	});

	test("rejects an all-null hostServices policy (a no-service version stays V1)", () => {
		const payload = policyPayloadFixture();
		(payload as Record<string, unknown>).hostServices = { kv: null, sql: null, logging: null };
		const result = sealWasmHostServicePolicyV2(payload);
		expect(result.ok).toBe(false);
	});

	test("rejects limits above the node maxima", () => {
		const payload = policyPayloadFixture();
		const services = payload.hostServices as Record<string, { limits: Record<string, number> }>;
		services.kv.limits = { ...services.kv.limits, maxListItems: WASM_HOST_SERVICE_NODE_MAXIMA.kv.maxListItems + 1 };
		const result = sealWasmHostServicePolicyV2(payload);
		expect(result.ok).toBe(false);
	});

	test("rejects unknown fields and non-literal profiles", () => {
		const withExtra = { ...policyPayloadFixture(), extra: true };
		expect(sealWasmHostServicePolicyV2(withExtra).ok).toBe(false);
		const payload = policyPayloadFixture();
		const services = payload.hostServices as Record<string, Record<string, unknown>>;
		services.sql.profile = "wide-sqlite-v9";
		expect(sealWasmHostServicePolicyV2(payload).ok).toBe(false);
	});

	test("the policy digest never covers dynamic usage", () => {
		const sealed = sealWasmHostServicePolicyV2(policyPayloadFixture());
		expect(sealed.ok).toBe(true);
		if (!sealed.ok) return;
		// 未知字段 committedBytes 直接拒绝：动态用量进不了静态策略摘要。
		const withUsage = { ...policyPayloadFixture(), committedBytes: 1 } as unknown;
		expect(sealWasmHostServicePolicyV2(withUsage).ok).toBe(false);
		const { policyDigest: _digest, ...payload } = sealed.value;
		const recomputed = computeWasmHostServicePolicyDigestV2(payload);
		expect(recomputed.ok).toBe(true);
		if (recomputed.ok) expect(recomputed.value).toBe(sealed.value.policyDigest);
	});
});

describe("guest memory reserve", () => {
	test("computes guestMemoryBytes = memoryBytes - reserveBytes", () => {
		expect(checkWasmGuestMemoryReserve(268435456, 33554432)).toEqual({ ok: true, guestMemoryBytes: 234881024 });
	});

	test("fails closed on missing, zero-substituted or consuming reserve", () => {
		expect(checkWasmGuestMemoryReserve(268435456, 0).ok).toBe(false);
		expect(checkWasmGuestMemoryReserve(268435456, 268435456).ok).toBe(false);
		expect(checkWasmGuestMemoryReserve(268435456, 268435457).ok).toBe(false);
		expect(checkWasmGuestMemoryReserve(0, 1).ok).toBe(false);
	});
});

describe("capability matrix revision 2", () => {
	test("is the bytewise-sorted union of revision 1 and the three new imports", () => {
		const rev1Keys = WASM_CAPABILITY_MATRIX_REVISION_1.hostImports.map((entry) => entry.package + "/" + entry.interface);
		const rev2Keys = WASM_CAPABILITY_MATRIX_REVISION_2_HOST_IMPORTS.map((entry) => entry.package + "/" + entry.interface);
		for (const key of rev1Keys) expect(rev2Keys).toContain(key);
		expect(rev2Keys).toContain("iweb:kv@1.0.0/store");
		expect(rev2Keys).toContain("iweb:sql@1.0.0/store");
		expect(rev2Keys).toContain("iweb:logging@1.0.0/logger");
		expect(rev2Keys).toHaveLength(rev1Keys.length + 3);
		const sorted = [...rev2Keys].sort();
		expect(rev2Keys).toEqual(sorted);
	});

	test("validates the canonical matrix and rejects a V1 ABI or a missing service import", () => {
		expect(validateWasmCapabilityMatrixV2(WASM_CAPABILITY_MATRIX_V2).ok).toBe(true);
		const v1Abi = { ...WASM_CAPABILITY_MATRIX_V2, hostABI: "iweb-wasmd-abi@1.0.0" };
		expect(validateWasmCapabilityMatrixV2(v1Abi).ok).toBe(false);
		const missing = { ...WASM_CAPABILITY_MATRIX_V2, hostImports: WASM_CAPABILITY_MATRIX_REVISION_2_HOST_IMPORTS.slice(0, -1) };
		expect(validateWasmCapabilityMatrixV2(missing).ok).toBe(false);
	});
});

describe("capability record revision 2 increment", () => {
	test("seals and validates with the iweb-wasm-capability-record-v2 domain", () => {
		const payload = {
			schemaVersion: 2,
			matrixRevision: 2,
			hostAbi: WASM_HOST_ABI_LITERAL_V2,
			world: "wasi:http/proxy@0.2.8",
			hostImports: WASM_CAPABILITY_MATRIX_REVISION_2_HOST_IMPORTS,
			hostServiceMaxima: WASM_HOST_SERVICE_NODE_MAXIMA,
		};
		const sealed = sealWasmHostServiceCapabilityIncrementV2(payload);
		expect(sealed.ok).toBe(true);
		if (sealed.ok) {
			expect(sealed.value.recordHash).toBe(oracleDigestV2("iweb-wasm-capability-record-v2", jcsCanonicalBytes(payload)));
			expect(validateWasmHostServiceCapabilityIncrementV2(sealed.value).ok).toBe(true);
			const tampered = { ...sealed.value, hostServiceMaxima: { ...sealed.value.hostServiceMaxima, sql: { ...sealed.value.hostServiceMaxima.sql, maxRows: 999999999 } } };
			const result = validateWasmHostServiceCapabilityIncrementV2(tampered);
			expect(result.ok).toBe(false);
		}
	});
});

describe("HostServiceIdentityV2", () => {
	test("validates the exact 11-field shape and versionId projection", () => {
		const versionDigest = computeWasmHostServiceVersionDigestV2({
			packageDigest: "a".repeat(64),
			normalizedPolicy: { resources: { memoryBytes: 268435456 } },
			hostServicePolicyDigest: "b".repeat(64),
		});
		expect(versionDigest.ok).toBe(true);
		if (!versionDigest.ok) return;
		const versionId = formatWasmVersionIdV2(versionDigest.value, 1);
		expect(versionId).toBe(versionDigest.value + "-1");
		const identity = {
			schemaVersion: 2,
			applicationId: "notes-app",
			versionId,
			packageDigest: "a".repeat(64),
			versionDigest: versionDigest.value,
			matrixRevision: 2,
			hostAbi: WASM_HOST_ABI_LITERAL_V2,
			capabilityRecordRevision: 2,
			capabilityRecordHash: "c".repeat(64),
			catalogRevision: 1,
			catalogHash: "d".repeat(64),
			hostServicePolicyDigest: "b".repeat(64),
		};
		expect(validateWasmHostServiceIdentityV2(identity).ok).toBe(true);
		expect(validateWasmHostServiceIdentityV2({ ...identity, extra: 1 }).ok).toBe(false);
		expect(validateWasmHostServiceIdentityV2({ ...identity, versionId: "e".repeat(64) + "-1" }).ok).toBe(false);
		expect(formatWasmVersionIdV2(versionDigest.value, 0)).toBeNull();
	});

	test("versionDigest binds the normalized policy bytes", () => {
		const base = {
			packageDigest: "a".repeat(64),
			normalizedPolicy: { resources: { memoryBytes: 268435456 } },
			hostServicePolicyDigest: "b".repeat(64),
		};
		const first = computeWasmHostServiceVersionDigestV2(base);
		const second = computeWasmHostServiceVersionDigestV2({ ...base, normalizedPolicy: { resources: { memoryBytes: 134217728 } } });
		expect(first.ok && second.ok && first.value !== second.value).toBe(true);
	});
});

describe("SQL placeholder limits authority anchor", () => {
	test("policy defaults equal the SQL contract placeholder and stay within node maxima", () => {
		expect(WASM_HOST_SERVICE_PROFILE_DEFAULTS.sql).toEqual(IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS);
		for (const [field, value] of Object.entries(WASM_HOST_SERVICE_PROFILE_DEFAULTS.sql)) {
			expect(value).toBeLessThanOrEqual((WASM_HOST_SERVICE_NODE_MAXIMA.sql as Record<string, number>)[field]!);
		}
	});
});
