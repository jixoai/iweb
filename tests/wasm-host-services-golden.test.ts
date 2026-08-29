// 用户原始需求（2026-08-28，add-wasm-host-services 任务 7.5；2026-08-29 simplify-wasm-host-services 重写）：
//   宿主服务三件套（kv/sql/logging）与 policy/quota 的共享语义需要 TS contracts 的纯函数
//   复算测试。原实现从 tests/fixtures/wasm/host-services-golden-vectors.json 读取 Rust 侧
//   钉死值做跨语言双向 golden 对拍；simplify-wasm-host-services 已删除该锁（Rust kernel-rs
//   为 wire 权威，TS 契约为便捷封装）——本文件只保留 TS 单侧复算：digest 公式以独立
//   node:crypto oracle 复核，payload/决策向量内联（不再与 Rust 共享 fixture 文件）。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
	WASM_DIGEST_V2_DOMAINS,
	digestV2,
	computeWasmHostServicePolicyDigestV2,
	sealWasmHostServicePolicyV2,
	validateWasmHostServicePolicyV2,
	type WasmDigestV2Domain,
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
	computeExecutionCommandDigest,
	exampleExecutionCommand,
	validateExecutionCommand,
} from "../packages/contracts/wasm-execution.ts";

/** 独立 oracle：digestV2 = SHA-256(ASCII(domain) || 0x00 || payload)。 */
function digestV2Oracle(domain: string, payload: Uint8Array): string {
	return createHash("sha256")
		.update(domain, "ascii")
		.update(Buffer.from([0x00]))
		.update(Buffer.from(payload))
		.digest("hex");
}

// ---------------------------------------------------------------------------
// 内联向量（payload 形状沿用 add-wasm-host-services 任务 7.5 的既有向量；期望值不再
// 由 fixture 钉死，全部由本文件的独立 oracle/contracts 纯函数现场复算）。
// ---------------------------------------------------------------------------

const POLICY_DIGEST_VECTORS: readonly { readonly name: string; readonly payload: unknown }[] = [
  {
    "name": "all-three-services",
    "payload": {
      "schemaVersion": 2,
      "matrixRevision": 2,
      "hostAbi": "iweb-wasmd-abi@1.1.0",
      "hostServices": {
        "kv": {
          "profile": "bounded-cas-list-v1",
          "limits": {
            "maxListItems": 64,
            "maxListBytes": 65536,
            "cursorTtlMs": 60000,
            "entryOverheadBytes": 256
          },
          "consistency": "single-key-linearizable-cas-v1",
          "durability": "sqlite-full-fsync-v1",
          "retention": "tombstone-window-v1"
        },
        "sql": {
          "profile": "minimal-sqlite-v1",
          "limits": {
            "statementMaxBytes": 8192,
            "maxParameters": 128,
            "parameterMaxBytes": 65536,
            "maxRows": 1000,
            "resultMaxBytes": 262144,
            "maxAffectedRows": 4096,
            "executionMaxMs": 5000,
            "lockWaitMaxMs": 2000,
            "maxConcurrentCalls": 2
          },
          "consistency": "implicit-transaction-per-call-v1",
          "durability": "sqlite-full-fsync-v1",
          "retention": "retained-until-application-deletion-v1"
        },
        "logging": {
          "profile": "bounded-memory-ring-v1",
          "limits": {
            "maxEventBytes": 8192,
            "ringMaxEvents": 256,
            "ringMaxBytes": 262144
          },
          "consistency": "append-only-drop-on-full-v1",
          "durability": "no-durable-claim-v1",
          "retention": "runtime-lifecycle-only-v1"
        }
      },
      "storageBytes": 1048576,
      "reserveBytes": 33554432,
      "dataDirectoryProfile": "per-app-sqlite-v1",
      "durabilityProfile": "sqlite-full-fsync-v1"
    },
    "expectedPolicyDigest": "e8ada705a6ffa5c65e98b6869457b7b570aa5473bdd26948977df0fe916e6847"
  },
  {
    "name": "kv-only",
    "payload": {
      "schemaVersion": 2,
      "matrixRevision": 2,
      "hostAbi": "iweb-wasmd-abi@1.1.0",
      "hostServices": {
        "kv": {
          "profile": "bounded-cas-list-v1",
          "limits": {
            "maxListItems": 64,
            "maxListBytes": 65536,
            "cursorTtlMs": 60000,
            "entryOverheadBytes": 256
          },
          "consistency": "single-key-linearizable-cas-v1",
          "durability": "sqlite-full-fsync-v1",
          "retention": "tombstone-window-v1"
        },
        "sql": null,
        "logging": null
      },
      "storageBytes": 65536,
      "reserveBytes": 16777216,
      "dataDirectoryProfile": "per-app-sqlite-v1",
      "durabilityProfile": "sqlite-full-fsync-v1"
    },
    "expectedPolicyDigest": "b21afb8e8cb4e6482b137ef5749ea2b9c39e4ef35619bfb079d4c83bd75bb665"
  }
];

const QUOTA_RESERVATION_VECTORS: readonly {
	readonly name: string;
	readonly reservation: Record<string, unknown>;
	readonly proofStateOverride: string;
}[] = [
  {
    "name": "reserved-kv-row",
    "reservation": {
      "schemaVersion": 2,
      "reservationId": "01890f2e-4a1e-7356-8f0c-6c2f11a7b901",
      "operationId": "01890f2e-4a1e-7456-9f0c-6c2f11a7b902",
      "applicationId": "notes-app",
      "backend": "kv",
      "ledgerRevision": 3,
      "expectedUsageRevision": 2,
      "baseCommittedBytes": 4096,
      "reservedDeltaBytes": 300,
      "projectedCommittedBytes": 4396,
      "expiresAt": 1724726400000,
      "state": "reserved"
    },
    "proofStateOverride": "reserved"
  },
  {
    "name": "committed-sql-row-proof-uses-reserved-shape",
    "reservation": {
      "schemaVersion": 2,
      "reservationId": "01890f2e-4a1e-7556-8f0c-6c2f11a7b903",
      "operationId": "01890f2e-4a1e-7656-9f0c-6c2f11a7b904",
      "applicationId": "notes-app",
      "backend": "sql",
      "ledgerRevision": 7,
      "expectedUsageRevision": 5,
      "baseCommittedBytes": 8192,
      "reservedDeltaBytes": 1024,
      "projectedCommittedBytes": 9216,
      "expiresAt": 1724726400000,
      "state": "committed"
    },
    "proofStateOverride": "reserved"
  }
];

const QUOTA_PROOF_NEGATIVE = {
  "name": "tampered-reserved-delta-breaks-proof",
  "baseVector": "reserved-kv-row",
  "tamperedReservation": {
    "schemaVersion": 2,
    "reservationId": "01890f2e-4a1e-7356-8f0c-6c2f11a7b901",
    "operationId": "01890f2e-4a1e-7456-9f0c-6c2f11a7b902",
    "applicationId": "notes-app",
    "backend": "kv",
    "ledgerRevision": 3,
    "expectedUsageRevision": 2,
    "baseCommittedBytes": 4096,
    "reservedDeltaBytes": 301,
    "projectedCommittedBytes": 4396,
    "expiresAt": 1724726400000,
    "state": "reserved"
  }
} as { readonly baseVector: string; readonly tamperedReservation: Record<string, unknown> };

const SQL_VALUE_WIRE_BYTES: readonly { readonly name: string; readonly value: { readonly kind: string; readonly value?: number; readonly base64?: string }; readonly expectedBytes: number }[] = [
  {
    "name": "null",
    "value": {
      "kind": "null"
    },
    "expectedBytes": 0
  },
  {
    "name": "integer",
    "value": {
      "kind": "integer",
      "value": 42
    },
    "expectedBytes": 8
  },
  {
    "name": "integer-negative",
    "value": {
      "kind": "integer",
      "value": -7
    },
    "expectedBytes": 8
  },
  {
    "name": "real",
    "value": {
      "kind": "real",
      "value": 1.5
    },
    "expectedBytes": 8
  },
  {
    "name": "text-ascii",
    "value": {
      "kind": "text",
      "value": "hello"
    },
    "expectedBytes": 5
  },
  {
    "name": "text-multibyte",
    "value": {
      "kind": "text",
      "value": "héllo日志"
    },
    "expectedBytes": 12
  },
  {
    "name": "blob",
    "value": {
      "kind": "blob",
      "base64": "AAH//g=="
    },
    "expectedBytes": 4
  }
];

const SQL_ERROR_MAP: readonly { readonly case: string; readonly wireCode: string; readonly hostCallCode: string }[] = [
  {
    "case": "invalid-sql",
    "wireCode": "IWEB_SQL_INVALID_SQL",
    "hostCallCode": "INVALID_ARGUMENT"
  },
  {
    "case": "invalid-parameter",
    "wireCode": "IWEB_SQL_INVALID_PARAMETER",
    "hostCallCode": "INVALID_ARGUMENT"
  },
  {
    "case": "constraint",
    "wireCode": "IWEB_SQL_CONSTRAINT",
    "hostCallCode": "CONFLICT"
  },
  {
    "case": "busy",
    "wireCode": "IWEB_SQL_BUSY",
    "hostCallCode": "BUSY"
  },
  {
    "case": "quota-exceeded",
    "wireCode": "IWEB_SQL_QUOTA_EXCEEDED",
    "hostCallCode": "QUOTA_EXCEEDED"
  },
  {
    "case": "limit-exceeded",
    "wireCode": "IWEB_SQL_LIMIT_EXCEEDED",
    "hostCallCode": "LIMIT_EXCEEDED"
  },
  {
    "case": "unavailable",
    "wireCode": "IWEB_SQL_UNAVAILABLE",
    "hostCallCode": "UNAVAILABLE"
  },
  {
    "case": "internal",
    "wireCode": "IWEB_SQL_INTERNAL",
    "hostCallCode": "INTERNAL"
  }
];

const KV_ERROR_MAP: readonly { readonly case: string; readonly wireCode: string }[] = [
  {
    "case": "invalid-key",
    "wireCode": "IWEB_KV_INVALID_KEY"
  },
  {
    "case": "not-found",
    "wireCode": "IWEB_KV_NOT_FOUND"
  },
  {
    "case": "conflict",
    "wireCode": "IWEB_KV_CONFLICT"
  },
  {
    "case": "quota-exceeded",
    "wireCode": "IWEB_KV_QUOTA_EXCEEDED"
  },
  {
    "case": "limit-exceeded",
    "wireCode": "IWEB_KV_LIMIT_EXCEEDED"
  },
  {
    "case": "cursor-expired",
    "wireCode": "IWEB_KV_CURSOR_EXPIRED"
  },
  {
    "case": "unavailable",
    "wireCode": "IWEB_KV_UNAVAILABLE"
  },
  {
    "case": "internal",
    "wireCode": "IWEB_KV_INTERNAL"
  }
];

const LOGGING_ERROR_MAP: readonly { readonly case: string; readonly wireCode: string }[] = [
  {
    "case": "invalid-event",
    "wireCode": "IWEB_LOG_INVALID_EVENT"
  },
  {
    "case": "limit-exceeded",
    "wireCode": "IWEB_LOG_LIMIT_EXCEEDED"
  },
  {
    "case": "unavailable",
    "wireCode": "IWEB_LOG_UNAVAILABLE"
  },
  {
    "case": "internal",
    "wireCode": "IWEB_LOG_INTERNAL"
  }
];

const LOGGING_METERING: readonly {
	readonly name: string;
	readonly hostContext: IwebLoggingHostContextV1;
	readonly event: IwebLoggingEventV1;
	readonly eventId: number;
	readonly expectedBytes: number;
}[] = [
  {
    "name": "minimal-info",
    "hostContext": {
      "applicationId": "alpha",
      "versionId": "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1",
      "preparationGeneration": 1,
      "executionGeneration": 1,
      "timestampUtc": "2026-08-27T00:00:00.000Z"
    },
    "event": {
      "level": "info",
      "message": "ok",
      "fields": []
    },
    "eventId": 1,
    "expectedBytes": 104
  },
  {
    "name": "multibyte-message",
    "hostContext": {
      "applicationId": "alpha",
      "versionId": "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1",
      "preparationGeneration": 1,
      "executionGeneration": 1,
      "timestampUtc": "2026-08-27T12:34:56.789Z"
    },
    "event": {
      "level": "warn",
      "message": "héllo 日志",
      "fields": [
        {
          "key": "code",
          "value": "401"
        }
      ]
    },
    "eventId": 42,
    "expectedBytes": 123
  },
  {
    "name": "redaction-shrinks-value-before-metering",
    "hostContext": {
      "applicationId": "alpha",
      "versionId": "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1",
      "preparationGeneration": 1,
      "executionGeneration": 1,
      "timestampUtc": "2026-08-27T00:00:00.000Z"
    },
    "event": {
      "level": "error",
      "message": "auth failed",
      "fields": [
        {
          "key": "authorization",
          "value": "Bearer abcdefghijklmnopqrstuvwxyz"
        },
        {
          "key": "code",
          "value": "401"
        }
      ]
    },
    "eventId": 7,
    "expectedBytes": 144
  },
  {
    "name": "multi-digit-generations-and-event-id",
    "hostContext": {
      "applicationId": "alpha",
      "versionId": "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1",
      "preparationGeneration": 12345,
      "executionGeneration": 678901,
      "timestampUtc": "2026-08-27T00:00:00.000Z"
    },
    "event": {
      "level": "trace",
      "message": "m",
      "fields": [
        {
          "key": "a",
          "value": "1"
        },
        {
          "key": "b",
          "value": "2"
        }
      ]
    },
    "eventId": 987654321,
    "expectedBytes": 125
  }
];

const KV_CURSOR_DECISIONS: readonly {
	readonly name: string;
	readonly binding: Parameters<typeof checkIwebKvCursor>[0]["cursor"];
	readonly request: Omit<Parameters<typeof checkIwebKvCursor>[0], "cursor">;
	readonly expected: string;
}[] = [
  {
    "name": "valid-continuation",
    "binding": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "lastKey": "n.1",
      "expiresAtMs": 60000
    },
    "request": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "snapshotAlive": true,
      "nowMs": 30000
    },
    "expected": "valid"
  },
  {
    "name": "cross-application",
    "binding": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "lastKey": "n.1",
      "expiresAtMs": 60000
    },
    "request": {
      "applicationId": "beta",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "snapshotAlive": true,
      "nowMs": 30000
    },
    "expected": "invalid-scope"
  },
  {
    "name": "cross-policy-digest",
    "binding": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "lastKey": "n.1",
      "expiresAtMs": 60000
    },
    "request": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "snapshotAlive": true,
      "nowMs": 30000
    },
    "expected": "invalid-scope"
  },
  {
    "name": "cross-prefix",
    "binding": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "lastKey": "n.1",
      "expiresAtMs": 60000
    },
    "request": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "x.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "snapshotAlive": true,
      "nowMs": 30000
    },
    "expected": "invalid-scope"
  },
  {
    "name": "cross-snapshot-token",
    "binding": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "lastKey": "n.1",
      "expiresAtMs": 60000
    },
    "request": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7856-8f0c-6c2f11a7b906",
      "snapshotAlive": true,
      "nowMs": 30000
    },
    "expected": "invalid-scope"
  },
  {
    "name": "expired-at-boundary",
    "binding": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "lastKey": "n.1",
      "expiresAtMs": 60000
    },
    "request": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "snapshotAlive": true,
      "nowMs": 60000
    },
    "expected": "expired"
  },
  {
    "name": "snapshot-recycled-while-cursor-live",
    "binding": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "lastKey": "n.1",
      "expiresAtMs": 60000
    },
    "request": {
      "applicationId": "alpha",
      "hostServicePolicyDigest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "prefix": "n.",
      "snapshotToken": "01890f2e-4a1e-7756-8f0c-6c2f11a7b905",
      "snapshotAlive": false,
      "nowMs": 45000
    },
    "expected": "expired"
  }
];

/** TS 侧复算 reservation proof：state 归一为 "reserved"、proof 字段省略（design 逐字公式）。 */
function tsProofDigest(reservation: Record<string, unknown>, stateOverride: string): string {
	const payload = { ...reservation, state: stateOverride };
	delete payload.reservationProofDigest;
	return digestV2("iweb-wasm-quota-reservation-v2", jcsCanonicalBytes(payload));
}

describe("host-services digest recompute (TS side)", () => {
	test("digestV2 formula matches an independent node:crypto oracle", () => {
		const payloads: readonly { readonly domain: string; readonly text: string }[] = [
			{ domain: "iweb-wasm-quota-reservation-v2", text: "" },
			{ domain: "iweb-wasm-execution-command-v2", text: '{"a":1}' },
			{ domain: "iweb-wasm-host-policy-v2", text: "ascii payload" },
			{ domain: "iweb-wasm-readiness-v2", text: "多字节 ✓" },
		];
		for (const vector of payloads) {
			const computed = digestV2(vector.domain as WasmDigestV2Domain, new TextEncoder().encode(vector.text));
			expect(computed).toBe(digestV2Oracle(vector.domain, new TextEncoder().encode(vector.text)));
		}
	});

	test("digestV2 domains outside the table are not expressible (fail-closed)", () => {
		const known = new Set<string>(WASM_DIGEST_V2_DOMAINS);
		expect(WASM_DIGEST_V2_DOMAINS.length).toBe(16);
		for (const bad of ["iweb-wasm-host-policy-v3", "iweb-wasm-quota-reservation-v1", "", "iweb-wasm-execution-command-v1"]) {
			expect(known.has(bad)).toBe(false);
		}
	});

	test("v2 wire digests: example payloads validate and recompute through the formal formulas", () => {
		const health = exampleServiceReadinessHealthV2();
		expect(validateServiceReadinessHealthV2(health).ok).toBe(true);
		expect(digestV2Oracle("iweb-wasm-readiness-v2", jcsCanonicalBytes(health))).toBe(digestV2("iweb-wasm-readiness-v2", jcsCanonicalBytes(health)));

		const metrics = exampleServiceEngineMetricsV2();
		expect(validateServiceEngineMetricsV2(metrics).ok).toBe(true);
		expect(digestV2Oracle("iweb-wasm-metrics-v2", jcsCanonicalBytes(metrics))).toBe(digestV2("iweb-wasm-metrics-v2", jcsCanonicalBytes(metrics)));

		const command = exampleExecutionCommand();
		const validated = validateExecutionCommand(command);
		expect(validated.ok).toBe(true);
		// 正式公式（supervisor journal/memo 的幂等键）= 域表公式 = 独立 oracle。
		const expected = digestV2Oracle("iweb-wasm-execution-command-v2", jcsCanonicalBytes(command));
		expect(computeExecutionCommandDigest(command)).toBe(expected);
		expect(digestV2("iweb-wasm-execution-command-v2", jcsCanonicalBytes(command))).toBe(expected);
	});

	for (const vector of POLICY_DIGEST_VECTORS) {
		test(`policy digestV2: ${vector.name}`, () => {
			const sealed = sealWasmHostServicePolicyV2(vector.payload);
			expect(sealed.ok).toBe(true);
			if (sealed.ok) {
				expect(sealed.value.policyDigest).toBe(computeWasmHostServicePolicyDigestV2(vector.payload).value);
				// seal 产物重验通过（digest 复算 fail-closed）。
				expect(validateWasmHostServicePolicyV2(sealed.value).ok).toBe(true);
			}
		});
	}

	test("policy negative: a tampered policy digest is rejected with the spec-named code", () => {
		const base = POLICY_DIGEST_VECTORS[0];
		expect(base).toBeDefined();
		const sealed = sealWasmHostServicePolicyV2(base!.payload);
		expect(sealed.ok).toBe(true);
		if (!sealed.ok) return;
		const tampered = validateWasmHostServicePolicyV2({ ...sealed.value, policyDigest: "0".repeat(64) });
		expect(tampered.ok).toBe(false);
		if (!tampered.ok) expect(tampered.errors.some((entry) => entry.code === "WASM_HOST_POLICY_DIGEST_MISMATCH")).toBe(true);
	});

	for (const vector of QUOTA_RESERVATION_VECTORS) {
		test(`quota reservation proof: ${vector.name}`, () => {
			const computed = tsProofDigest(vector.reservation, vector.proofStateOverride);
			// 独立 oracle 复核（state 归一 + proof 字段省略的同一 preimage）。
			const payload = { ...vector.reservation, state: vector.proofStateOverride };
			delete payload.reservationProofDigest;
			expect(computed).toBe(digestV2Oracle("iweb-wasm-quota-reservation-v2", jcsCanonicalBytes(payload)));
		});
	}

	test("quota proof negative: tampered reservation breaks the proof", () => {
		const base = QUOTA_RESERVATION_VECTORS.find((entry) => entry.name === QUOTA_PROOF_NEGATIVE.baseVector);
		expect(base).toBeDefined();
		const original = tsProofDigest(base!.reservation, "reserved");
		const tampered = tsProofDigest(QUOTA_PROOF_NEGATIVE.tamperedReservation, "reserved");
		expect(tampered).not.toBe(original);
	});

	for (const vector of SQL_VALUE_WIRE_BYTES) {
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
		for (const entry of SQL_ERROR_MAP) {
			expect(IWEB_SQL_WIRE_ERROR_BY_CASE[entry.case as keyof typeof IWEB_SQL_WIRE_ERROR_BY_CASE]).toBe(entry.wireCode);
			expect(IWEB_SQL_HOST_CALL_ERROR_BY_CASE[entry.case as keyof typeof IWEB_SQL_HOST_CALL_ERROR_BY_CASE]).toBe(entry.hostCallCode);
		}
		expect(SQL_ERROR_MAP.length).toBe(8);
	});

	test("kv error case mapping equals the contracts table", () => {
		for (const entry of KV_ERROR_MAP) {
			expect(IWEB_KV_WIRE_ERROR_BY_CASE[entry.case as keyof typeof IWEB_KV_WIRE_ERROR_BY_CASE]).toBe(entry.wireCode);
		}
		expect(KV_ERROR_MAP.length).toBe(8);
	});

	test("logging error case mapping equals the contracts table", () => {
		for (const entry of LOGGING_ERROR_MAP) {
			expect(IWEB_LOG_WIRE_ERROR_BY_CASE[entry.case as keyof typeof IWEB_LOG_WIRE_ERROR_BY_CASE]).toBe(entry.wireCode);
		}
		expect(LOGGING_ERROR_MAP.length).toBe(4);
	});

	for (const vector of LOGGING_METERING) {
		test(`logging ring metering: ${vector.name}`, () => {
			expect(measureIwebLoggingEventBytes(vector.event, vector.hostContext, vector.eventId)).toBe(vector.expectedBytes);
		});
	}

	for (const vector of KV_CURSOR_DECISIONS) {
		test(`kv cursor decision: ${vector.name}`, () => {
			const decision = checkIwebKvCursor({ cursor: vector.binding, ...vector.request });
			expect(decision.status).toBe(vector.expected);
		});
	}
});
