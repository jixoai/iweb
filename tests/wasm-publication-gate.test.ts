// 用户原始需求（2026-08-26，add-wasm-runtime 任务 4.3 + 6.3 + 7.8）：发布门 v2 与双 runtime
// gate 的跨实现黑盒契约——kernel/application-publication-gate.js 与
// kernel-rs/iweb-kernel/src/wasm_publication.rs 双实现同套断言；golden recordDigest 向量
// 由 bun 按公式独立拼 preimage 产出（2026-08-26），Rust cargo test 固定同一常量。
// 正交意图：golden digest 向量、malformed/digest/字段失配拒绝面、v1 不开 wasm、v2 不开
// celld、无 fallback、路径重定向拒绝、reasons wire 稳定顺序、runtime-kind 精确选择。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
// "Wasm publication requires a canonical kind-bound acceptance record" 与
// "Runtime-kind publication gate selection is a dual-gate wire"。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import gateModule from "../kernel/application-publication-gate.js";

const {
	WASM_ACCEPTANCE_FILE,
	DEFAULT_ACCEPTANCE_FILE,
	WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN,
	computeWasmAcceptanceRecordDigestV2,
	validateWasmAcceptanceRecordV2,
	evaluateWasmPublicationGate,
	evaluatePublicationGateSet,
	selectPublicationGate,
	publicationGateForRuntimeKind,
	requireWasmPublication,
} = gateModule;

// -- golden 向量（与 Rust 侧 wasm_publication.rs GOLDEN_RECORD_DIGEST 同一常量）：
//    bun oracle 按公式手工拼 preimage 产出，recordDigest =
//    69f0125fdd737b9b6f662fabd2c3cd52a3d0d93b82835ee9c10f19de7c2eea1f。 --
const GOLDEN_RECORD_DIGEST = "69f0125fdd737b9b6f662fabd2c3cd52a3d0d93b82835ee9c10f19de7c2eea1f";

const goldenPayload = {
	version: 2,
	result: "passed",
	gate: "application-sandbox",
	runtimeKind: "wasm",
	runtimeImageDigest: "sha256:" + "cd".repeat(32),
	hostABI: "iweb-wasmd-abi@1.0.0",
	world: "wasi:http/proxy@0.2.8",
	arch: "linux/amd64",
	capabilityRecordRevision: 5,
	capabilityRecordHash: "2".repeat(64),
	catalogRevision: 9,
	catalogHash: "ab".repeat(32),
	catalogEntryKey: "iweb-wasmd",
	evidenceDigest: "e".repeat(64),
};

const goldenFull = { ...goldenPayload, recordDigest: GOLDEN_RECORD_DIGEST };
// JCS：键按 UTF-8 字节序（全 ASCII 域内与 RFC 8785 一致）。
function jcsText(value: Record<string, unknown>): string {
	const keys = Object.keys(value).sort((a: string, b: string) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
	return "{" + keys.map((key: string) => JSON.stringify(key) + ":" + JSON.stringify(value[key])).join(",") + "}";
}

const goldenRecordText = jcsText(goldenFull);

const nodeIdentity = {
	architecture: "linux/amd64",
	capabilityRecordRevision: 5,
	capabilityRecordHash: "2".repeat(64),
	catalogRevision: 9,
	catalogHash: "ab".repeat(32),
	catalogEntry: {
		entryKey: "iweb-wasmd",
		imageDigest: "sha256:" + "cd".repeat(32),
		hostABI: "iweb-wasmd-abi@1.0.0",
		world: "wasi:http/proxy@0.2.8",
	},
};

const allOnEnvironment = { IWEB_APPLICATION_PUBLICATION_ENABLED: "1", IWEB_WASM_PUBLICATION_ENABLED: "1" };

const celldV1Record = JSON.stringify({
	version: 1,
	gate: "application-sandbox",
	result: "passed",
	evidenceDigest: "a".repeat(64),
});

// 独立 oracle：手工拼 preimage 再单次 SHA-256（不复用被测实现的 JCS）。
function oracleDomainDigest(domain: string, payloadJcs: string): string {
	return createHash("sha256")
		.update(Buffer.from(domain + "\n", "utf8"))
		.update(Buffer.from(payloadJcs, "utf8"))
		.digest("hex");
}

function oraclePayloadJcs(): string {
	return jcsText(goldenPayload as unknown as Record<string, unknown>);
}

describe("wasm publication gate v2 (dual-implementation contract)", () => {
	test("golden record digest matches the formula oracle", () => {
		expect(computeWasmAcceptanceRecordDigestV2(goldenPayload)).toBe(GOLDEN_RECORD_DIGEST);
		expect(oracleDomainDigest(WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN, oraclePayloadJcs())).toBe(GOLDEN_RECORD_DIGEST);
	});

	test("golden record validates and round-trips", () => {
		const record = validateWasmAcceptanceRecordV2(goldenRecordText);
		expect(record).not.toBeNull();
		expect(record?.recordDigest).toBe(GOLDEN_RECORD_DIGEST);
	});

	test("unknown field is rejected before enablement", () => {
		const payload = { ...goldenPayload, evidenceDigest: "f".repeat(64) };
		const digest = computeWasmAcceptanceRecordDigestV2(payload);
		// 记录本身是合法 JCS 且 digest 对「另一字段集」计算：拒绝必须由未知字段触发。
		const forged = jcsText({ ...payload, extra: true, recordDigest: digest });
		expect(validateWasmAcceptanceRecordV2(forged)).toBeNull();
		const gate = evaluateWasmPublicationGate({ environment: allOnEnvironment, readText: () => forged, node: nodeIdentity });
		expect(gate.enabled).toBe(false);
		expect(gate.reasons).toEqual(["wasm-acceptance-invalid"]);
	});

	test("missing field is rejected", () => {
		const { evidenceDigest: _omit, ...rest } = goldenPayload;
		const without = jcsText({ ...rest, recordDigest: GOLDEN_RECORD_DIGEST });
		expect(validateWasmAcceptanceRecordV2(without)).toBeNull();
	});

	test("digest mismatch is rejected", () => {
		const bad = jcsText({ ...goldenPayload, recordDigest: "0".repeat(64) });
		expect(validateWasmAcceptanceRecordV2(bad)).toBeNull();
	});

	test("non-JCS bytes are rejected (parse-equivalent is not enough)", () => {
		const reordered = JSON.stringify({ ...goldenPayload, recordDigest: GOLDEN_RECORD_DIGEST });
		expect(validateWasmAcceptanceRecordV2(reordered)).toBeNull();
	});

	test("duplicate member is rejected before last-value override", () => {
		const duplicated = goldenRecordText.replace('"result":"passed"', '"result":"passed","arch":"linux/arm64"');
		expect(validateWasmAcceptanceRecordV2(duplicated)).toBeNull();
	});

	test("malformed JSON is rejected", () => {
		expect(validateWasmAcceptanceRecordV2("{ not json")).toBeNull();
	});

	test("v1 record cannot open wasm", () => {
		expect(validateWasmAcceptanceRecordV2(celldV1Record)).toBeNull();
		const gate = evaluateWasmPublicationGate({ environment: allOnEnvironment, readText: () => celldV1Record, node: nodeIdentity });
		expect(gate.enabled).toBe(false);
		expect(gate.reasons).toEqual(["wasm-acceptance-invalid"]);
		// 只有 application switch（没有 wasm switch）同样不开 wasm。
		const gate2 = evaluateWasmPublicationGate({
			environment: { IWEB_APPLICATION_PUBLICATION_ENABLED: "1" },
			readText: () => goldenRecordText,
			node: nodeIdentity,
		});
		expect(gate2.enabled).toBe(false);
		expect(gate2.reasons).toEqual(["publication-not-requested"]);
	});

	test("cross-kind gate result carries runtime-kind-mismatch without fallback", () => {
		const set = evaluatePublicationGateSet({
			environment: allOnEnvironment,
			readText: (path: string) => {
				if (path === DEFAULT_ACCEPTANCE_FILE) return celldV1Record;
				throw new Error("missing");
			},
			node: nodeIdentity,
		});
		const cross = publicationGateForRuntimeKind(set.celld, "wasm");
		expect(cross.runtimeKind).toBe("wasm");
		expect(cross.enabled).toBe(false);
		expect(cross.reasons).toEqual(["runtime-kind-mismatch"]);
	});

	test("v2 record cannot open celld", () => {
		const set = evaluatePublicationGateSet({
			environment: allOnEnvironment,
			readText: (path: string) => {
				if (path === WASM_ACCEPTANCE_FILE) return goldenRecordText;
				throw new Error("missing");
			},
			node: nodeIdentity,
		});
		expect(set.wasm.enabled).toBe(true);
		expect(set.celld.enabled).toBe(false);
		expect(set.celld.reasons).toEqual(["sandbox-acceptance-missing"]);
		const selection = selectPublicationGate("celld", set);
		expect(selection.enabled).toBe(false);
		expect(selection.reasons).toEqual(["sandbox-acceptance-missing"]);
	});

	test("identity mismatch returns exact reason codes in stable order", () => {
		const payload = {
			...goldenPayload,
			catalogRevision: 10,
			capabilityRecordHash: "3".repeat(64),
			arch: "linux/arm64",
			runtimeImageDigest: "sha256:" + "ce".repeat(32),
		};
		const text = jcsText({ ...payload, recordDigest: computeWasmAcceptanceRecordDigestV2(payload) });
		const gate = evaluateWasmPublicationGate({ environment: allOnEnvironment, readText: () => text, node: nodeIdentity });
		expect(gate.enabled).toBe(false);
		// 稳定顺序：identity < capability < catalog < unsupported-architecture。
		expect(gate.reasons).toEqual(["wasm-identity-mismatch", "capability-record-mismatch", "catalog-mismatch", "unsupported-architecture"]);

		const withNode = (override: Record<string, unknown>) =>
			evaluateWasmPublicationGate({
				environment: allOnEnvironment,
				readText: () => goldenRecordText,
				node: { ...nodeIdentity, ...override },
			});
		expect(withNode({ capabilityRecordRevision: 6 }).reasons).toEqual(["capability-record-mismatch"]);
		expect(withNode({ catalogHash: "ac".repeat(32) }).reasons).toEqual(["catalog-mismatch"]);
		expect(withNode({ catalogEntry: { ...nodeIdentity.catalogEntry, entryKey: "other-wasmd" } }).reasons).toEqual(["wasm-identity-mismatch"]);
		expect(withNode({ architecture: "darwin/arm64" }).reasons).toEqual(["unsupported-architecture"]);
	});

	test("missing node pins fail closed", () => {
		const gate = evaluateWasmPublicationGate({ environment: allOnEnvironment, readText: () => goldenRecordText });
		expect(gate.enabled).toBe(false);
		expect(gate.accepted).toBe(true);
		expect(gate.reasons).toEqual(["wasm-identity-mismatch", "capability-record-mismatch", "catalog-mismatch"]);
	});

	test("dual gates evaluate independently without fallback", () => {
		// celld 记录有效 + wasm 记录损坏：celld 开、wasm 关（malformed celld 不产生合法 wasm gate）。
		const set = evaluatePublicationGateSet({
			environment: allOnEnvironment,
			readText: (path: string) => {
				if (path === DEFAULT_ACCEPTANCE_FILE) return celldV1Record;
				if (path === WASM_ACCEPTANCE_FILE) return "{ broken";
				throw new Error("unexpected path " + path);
			},
			node: nodeIdentity,
		});
		expect(set.celld.enabled).toBe(true);
		expect(set.wasm.enabled).toBe(false);
		expect(set.wasm.reasons).toEqual(["wasm-acceptance-invalid"]);

		// 双开：选择按 runtime kind 精确命中。
		const both = evaluatePublicationGateSet({
			environment: allOnEnvironment,
			readText: (path: string) => {
				if (path === DEFAULT_ACCEPTANCE_FILE) return celldV1Record;
				if (path === WASM_ACCEPTANCE_FILE) return goldenRecordText;
				throw new Error("unexpected path " + path);
			},
			node: nodeIdentity,
		});
		expect(both.celld.enabled && both.wasm.enabled).toBe(true);
		expect(selectPublicationGate("celld", both)).toEqual({ schemaVersion: 1, runtimeKind: "celld", enabled: true, reasons: [] });
		expect(selectPublicationGate("wasm", both)).toEqual({ schemaVersion: 1, runtimeKind: "wasm", enabled: true, reasons: [] });
		expect(() => requireWasmPublication(both.wasm)).not.toThrow();
	});

	test("unknown runtime kind is a typed selection error", () => {
		const set = evaluatePublicationGateSet({ environment: {}, readText: () => { throw new Error("missing"); } });
		try {
			selectPublicationGate("deno", set);
			expect.unreachable("selectPublicationGate must throw for an unknown kind");
		} catch (error) {
			expect((error as { code?: string }).code).toBe("RUNTIME_KIND_UNSUPPORTED");
		}
	});

	test("path redirection is rejected without reading any wasm file", () => {
		const readPaths: string[] = [];
		const set = evaluatePublicationGateSet({
			environment: { ...allOnEnvironment, IWEB_WASM_SANDBOX_ACCEPTANCE_FILE: "/tmp/forged.json" },
			readText: (path: string) => {
				readPaths.push(path);
				throw new Error("missing");
			},
			node: nodeIdentity,
		});
		// wasm 侧不读任何文件（重定向即拒绝）；celld 侧仍只读自己的固定路径。
		expect(readPaths).toEqual([DEFAULT_ACCEPTANCE_FILE]);
		expect(set.wasm.enabled).toBe(false);
		expect(set.wasm.reasons).toEqual(["wasm-acceptance-invalid"]);
	});

	test("disabled wasm gate throws a stable guard error", () => {
		const gate = evaluateWasmPublicationGate({ environment: {}, readText: () => goldenRecordText, node: nodeIdentity });
		try {
			requireWasmPublication(gate);
			expect.unreachable("requireWasmPublication must throw when the gate is closed");
		} catch (error) {
			expect((error as { code?: string }).code).toBe("WASM_PUBLICATION_DISABLED");
			expect((error as Error).message).toContain("wasm publication is disabled");
		}
	});

	test("gate selection response wire is exactly four keys", () => {
		const set = evaluatePublicationGateSet({
			environment: allOnEnvironment,
			readText: (path: string) => {
				if (path === WASM_ACCEPTANCE_FILE) return goldenRecordText;
				throw new Error("missing");
			},
			node: nodeIdentity,
		});
		const selection = selectPublicationGate("wasm", set);
		expect(Object.keys(selection).sort()).toEqual(["enabled", "reasons", "runtimeKind", "schemaVersion"]);
		expect(selection).toEqual({ schemaVersion: 1, runtimeKind: "wasm", enabled: true, reasons: [] });
	});
});
