// 用户原始需求（2026-08-28，add-wasm-host-services 任务 7.5）：宿主服务三件套（kv/sql/logging）
// 与 policy/quota 的共享语义需要 TS contracts ↔ Rust（kernel-rs/iweb-kernel + kernel-rs/wasmd）
// 的向量互锁。本文件是 TS 侧：从 packages/contracts 现算每一个向量并与
// tests/fixtures/wasm/host-services-golden-vectors.json 钉死值逐个相等；Rust 侧
// kernel-rs/iweb-kernel/tests/wasm_host_services_golden.rs 与 kernel-rs/wasmd/tests/
// host_services_golden.rs 吃同一份 fixture——任何一侧的实现漂移都会让两侧同时变红。
// 覆盖：digestV2 公式（0x00 分隔）、policy digestV2、quota reservation proof
// （state 归一 "reserved"、proof 省略）、kv cursor 决策表、sql/kv/logging 错误码映射、
// logging 环计量与 sql 值 wire 字节数；正/负向量双向各至少一组。
// 轮次注记（2026-08-28，第四轮复审 P1）：补 V2 wire digest 向量（ServiceReadinessHealthV2/
// ServiceEngineMetricsV2/ExecutionCommandV2）——payload 必须先过对应 contracts validator，
// digest 按 digestV2 域表复算并与 fixture 钉死值相等；ExecutionCommandV2 额外对齐正式公式
// computeExecutionCommandDigestV2。payload 与 contracts example 向量逐 JCS 字节一致
//（example 是权威，fixture 钉死其当前形状，防止 fixture 变成第二权威）。
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	WASM_DIGEST_V2_DOMAINS,
	digestV2,
	computeWasmHostServicePolicyDigestV2,
	sealWasmHostServicePolicyV2,
	validateWasmHostServicePolicyV2,
	type WasmDigestV2Domain,
	type WasmHostServicePolicyPayloadV2,
} from "../packages/contracts/wasm-host-policy.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";
import { IWEB_KV_WIRE_ERROR_BY_CASE, checkIwebKvCursor } from "../packages/contracts/wasm-host-kv.ts";
import {
	IWEB_SQL_WIRE_ERROR_BY_CASE,
	IWEB_SQL_HOST_CALL_ERROR_BY_CASE,
	iwebSqlValueWireBytes,
	type IwebSqlValue,
} from "../packages/contracts/wasm-host-sql.ts";
import {
	IWEB_LOG_WIRE_ERROR_BY_CASE,
	measureIwebLoggingEventBytes,
	type IwebLoggingEventV1,
	type IwebLoggingHostContextV1,
} from "../packages/contracts/wasm-host-logging.ts";
import {
	exampleServiceEngineMetricsV2,
	exampleServiceReadinessHealthV2,
	validateServiceEngineMetricsV2,
	validateServiceReadinessHealthV2,
} from "../packages/contracts/wasm-health.ts";
import {
	computeExecutionCommandDigestV2,
	exampleExecutionCommandV2,
	validateExecutionCommandV2,
} from "../packages/contracts/wasm-execution.ts";

interface GoldenDoc {
	readonly version: number;
	readonly digestV2Domains: readonly string[];
	readonly digestV2NegativeDomains: readonly string[];
	readonly digestV2Primitive: readonly { readonly name: string; readonly domain: string; readonly payloadText: string; readonly expectedHex: string }[];
	readonly v2WireDigest: readonly { readonly name: string; readonly domain: string; readonly payloadKind: string; readonly payload: Record<string, unknown>; readonly expectedHex: string }[];
	readonly policyDigest: readonly { readonly name: string; readonly payload: unknown; readonly expectedPolicyDigest: string }[];
	readonly policyNegative: readonly { readonly name: string; readonly payload: unknown; readonly policyDigest: string; readonly tsErrorCode: string }[];
	readonly quotaReservationProof: readonly {
		readonly name: string;
		readonly reservation: Record<string, unknown>;
		readonly proofStateOverride: string;
		readonly expectedProofDigest: string;
	}[];
	readonly quotaProofNegative: { readonly name: string; readonly baseVector: string; readonly tamperedReservation: Record<string, unknown> };
	readonly sqlValueWireBytes: readonly { readonly name: string; readonly value: { readonly kind: string; readonly value?: number; readonly base64?: string }; readonly expectedBytes: number }[];
	readonly sqlErrorMap: readonly { readonly case: string; readonly wireCode: string; readonly hostCallCode: string }[];
	readonly kvErrorMap: readonly { readonly case: string; readonly wireCode: string }[];
	readonly loggingErrorMap: readonly { readonly case: string; readonly wireCode: string }[];
	readonly loggingMetering: readonly {
		readonly name: string;
		readonly hostContext: IwebLoggingHostContextV1;
		readonly event: IwebLoggingEventV1;
		readonly eventId: number;
		readonly expectedBytes: number;
	}[];
	readonly kvCursorDecisions: readonly {
		readonly name: string;
		readonly binding: Parameters<typeof checkIwebKvCursor>[0]["cursor"];
		readonly request: Omit<Parameters<typeof checkIwebKvCursor>[0], "cursor">;
		readonly expected: string;
		readonly rustKnownDivergence?: string;
	}[];
}

const doc = JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "wasm", "host-services-golden-vectors.json"), "utf8")) as GoldenDoc;

/** TS 侧复算 reservation proof：state 归一为 "reserved"、proof 字段省略（design 逐字公式）。 */
function tsProofDigest(reservation: Record<string, unknown>, stateOverride: string): string {
	const payload = { ...reservation, state: stateOverride };
	delete payload.reservationProofDigest;
	return digestV2("iweb-wasm-quota-reservation-v2", jcsCanonicalBytes(payload));
}

describe("host-services golden vectors (TS side)", () => {
	test("fixture version is pinned", () => {
		expect(doc.version).toBe(1);
		expect(doc.digestV2Primitive.length).toBeGreaterThanOrEqual(4);
		expect(doc.policyDigest.length).toBeGreaterThanOrEqual(2);
		expect(doc.kvCursorDecisions.length).toBeGreaterThanOrEqual(7);
	});

	test("V2 hash domain table matches the contracts authority", () => {
		expect(doc.digestV2Domains).toEqual([...WASM_DIGEST_V2_DOMAINS]);
		expect(WASM_DIGEST_V2_DOMAINS.length).toBe(16);
	});

	for (const vector of doc.digestV2Primitive) {
		test(`digestV2 primitive: ${vector.name}`, () => {
			const computed = digestV2(vector.domain as WasmDigestV2Domain, new TextEncoder().encode(vector.payloadText));
			expect(computed).toBe(vector.expectedHex);
		});
	}

	test("digestV2 domains outside the table are not expressible (fail-closed)", () => {
		// 负例：未知/拼错 domain 在类型层不可表达；运行时对闭表外输入不做任何解释。
		const known = new Set<string>(WASM_DIGEST_V2_DOMAINS);
		for (const bad of doc.digestV2NegativeDomains) expect(known.has(bad)).toBe(false);
		expect(doc.digestV2NegativeDomains.length).toBeGreaterThanOrEqual(3);
	});

	// 第四轮复审 P1：V2 wire digest 向量（payload 先过 validator，digest 按域表复算钉死）。
	for (const vector of doc.v2WireDigest) {
		test(`v2 wire digest: ${vector.name}`, () => {
			// payloadKind ↔ domain 的耦合在类型层钉死（跨域组合不参与向量表）。
			const domainByKind: Readonly<Record<string, string>> = {
				"service-readiness-health-v2": "iweb-wasm-readiness-v2",
				"service-engine-metrics-v2": "iweb-wasm-metrics-v2",
				"execution-command-v2": "iweb-wasm-execution-command-v2",
			};
			expect(domainByKind[vector.payloadKind]).toBe(vector.domain);
			if (vector.payloadKind === "service-readiness-health-v2") {
				expect(validateServiceReadinessHealthV2(vector.payload).ok).toBe(true);
			} else if (vector.payloadKind === "service-engine-metrics-v2") {
				expect(validateServiceEngineMetricsV2(vector.payload).ok).toBe(true);
			} else {
				const validated = validateExecutionCommandV2(vector.payload);
				expect(validated.ok).toBe(true);
				// 正式公式（supervisor journal/memo 的幂等键）与域表复算一字不差。
				if (validated.ok) expect(computeExecutionCommandDigestV2(validated.value)).toBe(vector.expectedHex);
			}
			expect(digestV2(vector.domain as WasmDigestV2Domain, jcsCanonicalBytes(vector.payload))).toBe(vector.expectedHex);
		});
	}

	test("v2 wire digest payloads are the contracts example vectors (JCS-identical)", () => {
		// example 函数是权威；fixture 钉死其当前形状——example 漂移必须显式更新 fixture，
		// 绝不允许两侧静默各自演化（fixture 不构成第二权威）。
		const exampleByKind: Readonly<Record<string, unknown>> = {
			"service-readiness-health-v2": exampleServiceReadinessHealthV2(),
			"service-engine-metrics-v2": exampleServiceEngineMetricsV2(),
			"execution-command-v2": exampleExecutionCommandV2(),
		};
		for (const vector of doc.v2WireDigest) {
			const example = exampleByKind[vector.payloadKind];
			expect(example).toBeDefined();
			expect(Buffer.compare(Buffer.from(jcsCanonicalBytes(example)), Buffer.from(jcsCanonicalBytes(vector.payload)))).toBe(0);
		}
		expect(doc.v2WireDigest.length).toBe(3);
	});

	for (const vector of doc.policyDigest) {
		test(`policy digestV2: ${vector.name}`, () => {
			const sealed = sealWasmHostServicePolicyV2(vector.payload);
			expect(sealed.ok).toBe(true);
			if (sealed.ok) expect(sealed.value.policyDigest).toBe(vector.expectedPolicyDigest);
			expect(computeWasmHostServicePolicyDigestV2(vector.payload as WasmHostServicePolicyPayloadV2).value).toBe(vector.expectedPolicyDigest);
		});
	}

	for (const vector of doc.policyNegative) {
		test(`policy negative: ${vector.name}`, () => {
			const result = validateWasmHostServicePolicyV2({ ...(vector.payload as object), policyDigest: vector.policyDigest });
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.errors.some((entry) => entry.code === vector.tsErrorCode)).toBe(true);
		});
	}

	for (const vector of doc.quotaReservationProof) {
		test(`quota reservation proof: ${vector.name}`, () => {
			expect(tsProofDigest(vector.reservation, vector.proofStateOverride)).toBe(vector.expectedProofDigest);
		});
	}

	test("quota proof negative: tampered reservation breaks the proof", () => {
		const base = doc.quotaReservationProof.find((entry) => entry.name === doc.quotaProofNegative.baseVector);
		expect(base).toBeDefined();
		const tampered = tsProofDigest(doc.quotaProofNegative.tamperedReservation, "reserved");
		expect(tampered).not.toBe(base?.expectedProofDigest);
	});

	for (const vector of doc.sqlValueWireBytes) {
		test(`sql value wire bytes: ${vector.name}`, () => {
			let value: IwebSqlValue;
			if (vector.value.kind === "null") value = { kind: "null" };
			else if (vector.value.kind === "integer") value = { kind: "integer", value: vector.value.value as number };
			else if (vector.value.kind === "real") value = { kind: "real", value: vector.value.value as number };
			else if (vector.value.kind === "text") value = { kind: "text", value: vector.value.value as unknown as string };
			else value = { kind: "blob", value: new Uint8Array(Buffer.from(vector.value.base64 as string, "base64")) };
			expect(iwebSqlValueWireBytes(value)).toBe(vector.expectedBytes);
		});
	}

	test("sql error case mapping equals the contracts tables", () => {
		for (const entry of doc.sqlErrorMap) {
			expect(IWEB_SQL_WIRE_ERROR_BY_CASE[entry.case as keyof typeof IWEB_SQL_WIRE_ERROR_BY_CASE]).toBe(entry.wireCode);
			expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE[entry.case as keyof typeof IWEB_SQL_HOST_CALL_ERROR_BY_CASE]).toBe(entry.hostCallCode);
		}
		expect(doc.sqlErrorMap.length).toBe(8);
	});

	test("kv error case mapping equals the contracts table", () => {
		for (const entry of doc.kvErrorMap) {
			expect(IWEB_KV_WIRE_ERROR_BY_CASE[entry.case as keyof typeof IWEB_KV_WIRE_ERROR_BY_CASE]).toBe(entry.wireCode);
		}
		expect(doc.kvErrorMap.length).toBe(8);
	});

	test("logging error case mapping equals the contracts table", () => {
		for (const entry of doc.loggingErrorMap) {
			expect(IWEB_LOG_WIRE_ERROR_BY_CASE[entry.case as keyof typeof IWEB_LOG_WIRE_ERROR_BY_CASE]).toBe(entry.wireCode);
		}
		expect(doc.loggingErrorMap.length).toBe(4);
	});

	for (const vector of doc.loggingMetering) {
		test(`logging ring metering: ${vector.name}`, () => {
			expect(measureIwebLoggingEventBytes(vector.event, vector.hostContext, vector.eventId)).toBe(vector.expectedBytes);
		});
	}

	for (const vector of doc.kvCursorDecisions) {
		test(`kv cursor decision: ${vector.name}`, () => {
			const decision = checkIwebKvCursor({ cursor: vector.binding, ...vector.request });
			expect(decision.status).toBe(vector.expected);
		});
	}
});
