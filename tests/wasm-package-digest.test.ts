// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.1）：wasm 制品 digest 契约必须有可复算向量——spec 已发布的 405 字节 version digest 向量、严格 OCI 布局的正/负例、以及"绝不调用 celld versionDigest"的隔离证明。
// 正交意图：向量同时充当跨实现 oracle（手工拼装 preimage 再独立 SHA-256），负例全部断言稳定错误码而不是字符串匹配。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	computeWasmAdmissionProofDigestV1,
	computeWasmPackageDigestV1,
	computeWasmVersionDigestV1,
	composeWasmVersionId,
	jcsCanonicalBytes,
	jcsCanonicalize,
	parseStrictJson,
	parseWasmVersionId,
	validateNormalizedWasmManifestV1,
	validateWasmAdmissionConsistency,
	validateWasmConfigV1,
	validateWasmOciLayoutV1,
	verifyWasmAdmissionProofDigestFields,
	WASM_APPLICATION_ID_PATTERN,
	type NormalizedWasmManifestV1,
	type WasmConfigV1,
} from "../packages/contracts/wasm-package.ts";
import type { ValidationIssue, ValidationResult } from "../packages/contracts/validation.ts";

// ---------------------------------------------------------------------------
// spec 已发布向量（wasm-application-runtime spec.md "Published digest vector is reproduced"）
// ---------------------------------------------------------------------------

const SPEC_VECTOR_MANIFEST =
	'{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}';
const SPEC_VECTOR_PACKAGE_DIGEST = "0".repeat(64);
const SPEC_VECTOR_VERSION_DIGEST = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";

// ---------------------------------------------------------------------------
// 独立 oracle 工具（不复用被测实现）
// ---------------------------------------------------------------------------

function sha256Hex(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

function jcsBuffer(value: unknown): Buffer {
	return Buffer.from(jcsCanonicalize(value), "utf8");
}

const OCI_MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA = "application/vnd.iweb.wasm.config.v1+json";
const COMPONENT_MEDIA = "application/vnd.iweb.wasm.component.v1+wasm";
const CORE_MEDIA = "application/vnd.iweb.wasm.core-module.v1+wasm";
const ADAPTER_MEDIA = "application/vnd.iweb.wasm.adapter.v1+wasm";

interface DescriptorJson {
	readonly mediaType: string;
	readonly digest: string;
	readonly size: number;
}

function descriptorOf(bytes: Uint8Array, mediaType: string): DescriptorJson {
	return { mediaType, digest: "sha256:" + sha256Hex(bytes), size: bytes.length };
}

function blobPathOf(digest: string): string {
	return "blobs/sha256/" + digest.slice("sha256:".length);
}

function baseConfig(entryDigest: string): Record<string, unknown> {
	return {
		schemaVersion: 1,
		kind: "wasm",
		entryLayerDigest: entryDigest,
		world: "wasi:http/proxy@0.2.8",
		hostABI: "iweb-wasmd-abi@1.0.0",
		declaredHostImports: [
			{ package: "wasi:http@0.2.8", interface: "outgoing-handler", direction: "import" },
			{ package: "wasi:io@0.2.8", interface: "streams", direction: "import" },
		],
	};
}

interface LayoutPieces {
	readonly configObject: Record<string, unknown>;
	readonly configBytes: Buffer;
	readonly configDescriptor: DescriptorJson;
	readonly layerDescriptors: readonly DescriptorJson[];
	readonly manifestBytes: Buffer;
	readonly manifestDescriptor: DescriptorJson;
}

function buildLayout(options: {
	readonly layers?: readonly { readonly bytes: Buffer; readonly mediaType: string }[];
	readonly configRaw?: Buffer;
	readonly configTransform?: (config: Record<string, unknown>) => void;
	readonly manifestTransform?: (manifest: Record<string, unknown>) => void;
	readonly indexTransform?: (index: Record<string, unknown>) => void;
	readonly afterFiles?: (files: Map<string, Buffer>, pieces: LayoutPieces) => void;
} = {}): { readonly files: ReadonlyMap<string, Buffer>; readonly pieces: LayoutPieces } {
	const layers = options.layers ?? [
		{ bytes: Buffer.from("iweb wasm component entry payload"), mediaType: COMPONENT_MEDIA },
		{ bytes: Buffer.from("iweb wasm core module payload"), mediaType: CORE_MEDIA },
		{ bytes: Buffer.from("iweb wasm adapter payload"), mediaType: ADAPTER_MEDIA },
	];
	const layerDescriptors: DescriptorJson[] = layers.map((layer) => descriptorOf(layer.bytes, layer.mediaType));
	const config = baseConfig(layerDescriptors[0].digest);
	if (options.configTransform) options.configTransform(config);
	const configBytes = options.configRaw ?? jcsBuffer(config);
	const configDescriptor = descriptorOf(configBytes, CONFIG_MEDIA);
	const manifest: Record<string, unknown> = { config: configDescriptor, layers: layerDescriptors, schemaVersion: 2 };
	if (options.manifestTransform) options.manifestTransform(manifest);
	const manifestBytes = jcsBuffer(manifest);
	const manifestDescriptor = descriptorOf(manifestBytes, OCI_MANIFEST_MEDIA);
	const index: Record<string, unknown> = { manifests: [manifestDescriptor], schemaVersion: 2 };
	if (options.indexTransform) options.indexTransform(index);
	const indexBytes = jcsBuffer(index);
	const files = new Map<string, Buffer>([
		["oci-layout", Buffer.from('{"imageLayoutVersion":"1.0.0"}', "utf8")],
		["index.json", indexBytes],
	]);
	files.set(blobPathOf(manifestDescriptor.digest), manifestBytes);
	files.set(blobPathOf(configDescriptor.digest), configBytes);
	layers.forEach((layer, i) => files.set(blobPathOf(layerDescriptors[i].digest), layer.bytes));
	const pieces: LayoutPieces = { configObject: config, configBytes, configDescriptor, layerDescriptors, manifestBytes, manifestDescriptor };
	if (options.afterFiles) options.afterFiles(files, pieces);
	return { files, pieces };
}

function admissionFromConfig(config: Record<string, unknown>, name: string): Record<string, unknown> {
	return {
		schemaVersion: 1,
		name,
		runtime: {
			kind: config.kind,
			entryLayerDigest: config.entryLayerDigest,
			world: config.world,
			hostABI: config.hostABI,
			declaredHostImports: config.declaredHostImports,
		},
		resources: { cpuMillis: 500, memoryBytes: 268435456, pidLimit: 128, storageBytes: 1048576 },
		storage: { persistent: false, requestBytes: 65536 },
		egress: { default: "deny", allow: [{ host: "api.example.com", port: 443 }, { host: "api.example.com", port: 8443 }, { host: "mirror.example.org", port: 443 }] },
	};
}

type AnyValidationResult = { readonly ok: true } | { readonly ok: false; readonly errors: readonly ValidationIssue[] };

function expectFailureCode(result: AnyValidationResult, code: string): void {
	if (result.ok) throw new Error("expected validation failure, got success");
	expect(result.errors.some((entry) => entry.code === code)).toBe(true);
}

function expectManifestOk(input: unknown): NormalizedWasmManifestV1 {
	const result = validateNormalizedWasmManifestV1(input);
	if (!result.ok) throw new Error("expected manifest success: " + JSON.stringify(result.errors));
	return result.value;
}

function expectConfigOk(input: unknown): WasmConfigV1 {
	const errors: ValidationIssue[] = [];
	const config = validateWasmConfigV1(input, "/config", "WASM_OCI_CONFIG_INVALID", errors);
	if (config === null) throw new Error("expected config success: " + JSON.stringify(errors));
	return config;
}

// ---------------------------------------------------------------------------
// spec 发布向量复算
// ---------------------------------------------------------------------------

describe("wasm digest contract: published spec vectors", () => {
	test("the 405-byte admission manifest reproduces the published wasmVersionDigestV1", () => {
		const bytes = Buffer.from(SPEC_VECTOR_MANIFEST, "utf8");
		expect(bytes.length).toBe(405);
		const parsed = parseStrictJson(SPEC_VECTOR_MANIFEST);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) expect(Buffer.compare(jcsCanonicalBytes(parsed.value), bytes)).toBe(0);
		expect(computeWasmVersionDigestV1(SPEC_VECTOR_PACKAGE_DIGEST, bytes)).toBe(SPEC_VECTOR_VERSION_DIGEST);
	});

	test("the spec vector is a valid NormalizedWasmManifestV1 with name vector", () => {
		const parsed = parseStrictJson(SPEC_VECTOR_MANIFEST);
		expect(parsed.ok).toBe(true);
		if (parsed.ok) {
			const manifest = expectManifestOk(parsed.value);
			expect(manifest.name).toBe("vector");
			expect(manifest.storage.requestBytes).toBe(0);
			expect(manifest.egress.allow).toHaveLength(0);
		}
	});

	test("wasmVersionDigestV1 equals the independently assembled domain-prefixed preimage", () => {
		const admission = admissionFromConfig(baseConfig("sha256:" + "1".repeat(64)), "vector");
		const admissionBytes = jcsBuffer(admission);
		const packageDigest = "b".repeat(64);
		const preimage = Buffer.concat([
			Buffer.from("iweb-wasm-version-digest-v1\npackage " + packageDigest + "\nadmission-manifest " + admissionBytes.length + "\n", "utf8"),
			admissionBytes,
		]);
		expect(computeWasmVersionDigestV1(packageDigest, admissionBytes)).toBe(sha256Hex(preimage));
	});

	test("AdmissionProofV1 digest fields verify against the spec vector", () => {
		const parsed = parseStrictJson(SPEC_VECTOR_MANIFEST);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) return;
		const result = verifyWasmAdmissionProofDigestFields({
			applicationId: "vector",
			packageDigest: SPEC_VECTOR_PACKAGE_DIGEST,
			versionDigest: SPEC_VECTOR_VERSION_DIGEST,
			sequence: 1,
			versionId: SPEC_VECTOR_VERSION_DIGEST + "-1",
			normalizedPolicy: parsed.value,
		});
		if (!result.ok) throw new Error("expected proof success: " + JSON.stringify(result.errors));
		expect(result.value.versionId).toBe(SPEC_VECTOR_VERSION_DIGEST + "-1");
		expect(result.value.admissionManifestBytes.length).toBe(405);
	});

	test("the implementation never calls the celld digest serializer", () => {
		const source = readFileSync(join(import.meta.dir, "..", "packages", "contracts", "wasm-package.ts"), "utf8");
		// 模块级隔离：不 import celld 序列化器，也不引用其入口函数。
		expect(source).not.toContain('from "./package-collection');
		expect(source).not.toContain("collectPackage");
		expect(source).not.toContain("canonicalSerializeManifest");
		// 行为隔离：celld versionDigest 的 preimage 是 "package:...\0manifest:..."，与 wasm 域前缀不同。
		const celldStyle = createHash("sha256").update("package:" + SPEC_VECTOR_PACKAGE_DIGEST).update("\0").update("manifest:" + SPEC_VECTOR_MANIFEST).digest("hex");
		expect(computeWasmVersionDigestV1(SPEC_VECTOR_PACKAGE_DIGEST, Buffer.from(SPEC_VECTOR_MANIFEST, "utf8"))).not.toBe(celldStyle);
	});
});

// ---------------------------------------------------------------------------
// RFC 8785 JCS 与严格 JSON 解析
// ---------------------------------------------------------------------------

describe("wasm digest contract: JCS and strict JSON parsing", () => {
	test("object keys sort bytewise and arrays preserve order", () => {
		expect(jcsCanonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
		expect(jcsCanonicalize({ schemaVersion: 2, manifests: [{ z: 1, a: 2 }] })).toBe('{"manifests":[{"a":2,"z":1}],"schemaVersion":2}');
		expect(jcsCanonicalize([3, 1, 2])).toBe("[3,1,2]");
		expect(jcsCanonicalize({ a: [1, { c: true, b: null }] })).toBe('{"a":[1,{"b":null,"c":true}]}');
	});

	test("string escaping follows RFC 8785 minimal escapes with lower-case \\u hex", () => {
		expect(jcsCanonicalize({ quote: '"', backslash: "\\", slash: "/" })).toBe('{"backslash":"\\\\","quote":"\\"","slash":"/"}');
		expect(jcsCanonicalize("\b\t\n\f\r")).toBe('"\\b\\t\\n\\f\\r"');
		expect(jcsCanonicalize("\u000b")).toBe('"\\u000b"');
		expect(jcsCanonicalize("\u001f")).toBe('"\\u001f"');
		expect(jcsCanonicalize("héllo→")).toBe('"héllo→"');
	});

	test("numbers serialize per ECMAScript shortest round-trip and -0 becomes 0", () => {
		expect(jcsCanonicalize(-0)).toBe("0");
		expect(jcsCanonicalize(0)).toBe("0");
		expect(jcsCanonicalize(1e21)).toBe("1e+21");
		expect(jcsCanonicalize(1e-7)).toBe("1e-7");
		expect(jcsCanonicalize(100)).toBe("100");
		expect(() => jcsCanonicalize(Number.NaN)).toThrow();
		expect(() => jcsCanonicalize(Number.POSITIVE_INFINITY)).toThrow();
	});

	test("non-JSON values are rejected", () => {
		expect(() => jcsCanonicalize(undefined)).toThrow();
		expect(() => jcsCanonicalize(() => 1)).toThrow();
		expect(() => jcsCanonicalize(BigInt(1))).toThrow();
		expect(() => jcsCanonicalize(new Date(0))).toThrow();
		expect(() => jcsCanonicalize("\ud800")).toThrow();
		expect(() => jcsCanonicalize("a\udc00")).toThrow();
	});

	test("duplicate object members are rejected before last-value override", () => {
		const duplicated = parseStrictJson('{"kind":"wasm","kind":"wasm","schemaVersion":1}');
		expect(duplicated.ok).toBe(false);
		if (!duplicated.ok) expect(duplicated.error).toContain("duplicate");
	});

	test("strict parser rejects BOM, trailing content, raw control chars, lone escapes, and float overflow", () => {
		expect(parseStrictJson("﻿{\"a\":1}").ok).toBe(false);
		expect(parseStrictJson("\uFEFF" + '{"a":1}').ok).toBe(false);
		expect(parseStrictJson('{"a":1} trailing').ok).toBe(false);
		expect(parseStrictJson('{"a":1,}').ok).toBe(false);
		expect(parseStrictJson('{"a":"raw\x01control"}').ok).toBe(false);
		expect(parseStrictJson('"\\ud800"').ok).toBe(false);
		expect(parseStrictJson('{"a":"\\ud800\\udc00"}').ok).toBe(true);
		expect(parseStrictJson("01").ok).toBe(false);
		expect(parseStrictJson("1.").ok).toBe(false);
		expect(parseStrictJson("1e400").ok).toBe(false);
		expect(parseStrictJson('{"a": 1, "b": [2, 3] }\n').ok).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// 严格 OCI 布局正例
// ---------------------------------------------------------------------------

describe("wasm digest contract: strict OCI layout positive vectors", () => {
	test("a strict layout validates and commits layout, index, descriptors, config and layer order", () => {
		const { files, pieces } = buildLayout();
		const result = validateWasmOciLayoutV1(files);
		if (!result.ok) throw new Error("expected valid layout: " + JSON.stringify(result.errors));
		const layoutBytes = files.get("oci-layout") as Buffer;
		const indexBytes = files.get("index.json") as Buffer;
		let preimage = "iweb-wasm-package-digest-v1\n";
		preimage += "layout " + sha256Hex(layoutBytes) + " " + layoutBytes.length + "\n";
		preimage += "index " + sha256Hex(indexBytes) + " " + indexBytes.length + "\n";
		preimage += "manifest " + OCI_MANIFEST_MEDIA + " " + pieces.manifestDescriptor.digest + " " + pieces.manifestDescriptor.size + "\n";
		preimage += "config " + CONFIG_MEDIA + " " + pieces.configDescriptor.digest + " " + pieces.configDescriptor.size + "\n";
		pieces.layerDescriptors.forEach((layer, i) => {
			preimage += "layer " + i + " " + layer.mediaType + " " + layer.digest + " " + layer.size + "\n";
		});
		const expected = sha256Hex(Buffer.from(preimage, "utf8"));
		expect(result.value.packageDigest).toBe(expected);
		expect(computeWasmPackageDigestV1(result.value.layout)).toBe(expected);
		expect(result.value.layout.config.declaredHostImports).toHaveLength(2);
		expect(result.value.layout.manifest.layers.map((layer) => layer.mediaType)).toEqual([COMPONENT_MEDIA, CORE_MEDIA, ADAPTER_MEDIA]);
		expect(result.value.layout.blobPaths).toHaveLength(5);
	});

	test("OCI layer order is significant and part of the digest", () => {
		const entry = { bytes: Buffer.from("iweb wasm component entry payload"), mediaType: COMPONENT_MEDIA };
		const core = { bytes: Buffer.from("iweb wasm core module payload"), mediaType: CORE_MEDIA };
		const adapter = { bytes: Buffer.from("iweb wasm adapter payload"), mediaType: ADAPTER_MEDIA };
		const first = validateWasmOciLayoutV1(buildLayout({ layers: [entry, core, adapter] }).files);
		const second = validateWasmOciLayoutV1(buildLayout({ layers: [entry, adapter, core] }).files);
		if (!first.ok || !second.ok) throw new Error("expected both layouts valid");
		expect(first.value.packageDigest).not.toBe(second.value.packageDigest);
	});

	test("the validated package digest feeds admission consistency checks end to end", () => {
		const { files, pieces } = buildLayout();
		const result = validateWasmOciLayoutV1(files);
		if (!result.ok) throw new Error("expected valid layout");
		const config = expectConfigOk(pieces.configObject);
		const admission = expectManifestOk(admissionFromConfig({ ...baseConfig(pieces.configObject.entryLayerDigest as string) }, "notes"));
		expect(validateWasmAdmissionConsistency(config, admission).ok).toBe(true);
		const admissionBytes = jcsBuffer(admission);
		const versionDigest = computeWasmVersionDigestV1(result.value.packageDigest, admissionBytes);
		const proof = verifyWasmAdmissionProofDigestFields({
			applicationId: "notes",
			packageDigest: result.value.packageDigest,
			versionDigest,
			sequence: 3,
			versionId: composeWasmVersionId(versionDigest, 3),
			normalizedPolicy: admission,
		});
		expect(proof.ok).toBe(true);
	});

	test("admission bounds are enforced before layout work", () => {
		const { files } = buildLayout();
		expectFailureCode(
			validateWasmOciLayoutV1(files, { maxPackageBytes: 0, maxBlobBytes: 134217728, maxLayerCount: 128 }),
			"WASM_ADMISSION_BOUNDS_INVALID",
		);
	});
});

// ---------------------------------------------------------------------------
// 严格 OCI 布局负例
// ---------------------------------------------------------------------------

describe("wasm digest contract: strict OCI layout negative vectors", () => {
	test("pretty-printed index.json is semantically valid but not raw JCS", () => {
		const { files, pieces } = buildLayout();
		const indexValue = { manifests: [pieces.manifestDescriptor], schemaVersion: 2 };
		files.set("index.json", Buffer.from(JSON.stringify(indexValue, null, 2), "utf8"));
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_NON_CANONICAL_JSON");
	});

	test("a trailing newline after oci-layout breaks the byte-equality rule", () => {
		const { files } = buildLayout();
		files.set("oci-layout", Buffer.from('{"imageLayoutVersion":"1.0.0"}\n', "utf8"));
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_NON_CANONICAL_JSON");
	});

	test("a config whose keys are not in JCS order is rejected as non-canonical", () => {
		// 插入序与排序序不同：JSON.stringify 保留插入序，raw != JCS(JSON.parse(raw))。
		const config = baseConfig("sha256:" + "2".repeat(64));
		const reordered: Record<string, unknown> = { world: config.world, hostABI: config.hostABI, declaredHostImports: config.declaredHostImports, schemaVersion: 1, kind: "wasm", entryLayerDigest: config.entryLayerDigest };
		const { files } = buildLayout({ configRaw: Buffer.from(JSON.stringify(reordered), "utf8") });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_NON_CANONICAL_JSON");
	});

	test("duplicate config member names are rejected before last-value override", () => {
		const digest = "sha256:" + "2".repeat(64);
		const raw = '{"schemaVersion":1,"kind":"wasm","kind":"wasm","entryLayerDigest":"' + digest + '","world":"wasi:http/proxy@0.2.8","hostABI":"iweb-wasmd-abi@1.0.0","declaredHostImports":[]}';
		const { files } = buildLayout({ configRaw: Buffer.from(raw, "utf8") });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_JSON_INVALID");
	});

	test("a blob unreachable from the single index descriptor is rejected", () => {
		const { files } = buildLayout({ afterFiles: (map) => map.set(blobPathOf("sha256:" + "3".repeat(64)), Buffer.from("orphan")) });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_UNREFERENCED_BLOB");
	});

	test("two descriptors naming the same digest are rejected", () => {
		const entry = { bytes: Buffer.from("shared payload"), mediaType: COMPONENT_MEDIA };
		const sameBytes = { bytes: Buffer.from("shared payload"), mediaType: CORE_MEDIA };
		const { files } = buildLayout({ layers: [entry, sameBytes, { bytes: Buffer.from("adapter payload"), mediaType: ADAPTER_MEDIA }] });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_DUPLICATE_DIGEST");
	});

	test("a manifest with an empty layer list is an empty artifact", () => {
		const { files } = buildLayout({ manifestTransform: (manifest) => (manifest.layers = []) });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_EMPTY_ARTIFACT");
	});

	test("a zero-byte layer with a lying descriptor size is an empty artifact", () => {
		// 零字节的 blob 文件名是 sha256(空) 的 hex；descriptor 声明 size 1 让 digest 文本校验可通过，
		// 暴露"layer 为零字节"这一 spec 场景。
		const emptyDigest = "sha256:" + sha256Hex(Buffer.alloc(0));
		const config = baseConfig("sha256:" + "2".repeat(64));
		const configBytes = jcsBuffer(config);
		const configDescriptor = descriptorOf(configBytes, CONFIG_MEDIA);
		const manifest = { config: configDescriptor, layers: [{ mediaType: CORE_MEDIA, digest: emptyDigest, size: 1 }], schemaVersion: 2 };
		const manifestBytes = jcsBuffer(manifest);
		const manifestDescriptor = descriptorOf(manifestBytes, OCI_MANIFEST_MEDIA);
		const index = { manifests: [manifestDescriptor], schemaVersion: 2 };
		const files = new Map<string, Buffer>([
			["oci-layout", Buffer.from('{"imageLayoutVersion":"1.0.0"}', "utf8")],
			["index.json", jcsBuffer(index)],
			[blobPathOf(manifestDescriptor.digest), manifestBytes],
			[blobPathOf(configDescriptor.digest), configBytes],
			[blobPathOf(emptyDigest), Buffer.alloc(0)],
		]);
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_EMPTY_ARTIFACT");
	});

	test("a tampered layer blob breaks the content-addressed filename contract", () => {
		const { files } = buildLayout({ afterFiles: (map, pieces) => map.set(blobPathOf(pieces.layerDescriptors[1].digest), Buffer.from("tampered core payload")) });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_DIGEST_MISMATCH");
	});

	test("a config descriptor size that disagrees with raw bytes is rejected", () => {
		const { files } = buildLayout({
			manifestTransform: (manifest) => {
				manifest.config = { mediaType: CONFIG_MEDIA, digest: (manifest.config as DescriptorJson).digest, size: (manifest.config as DescriptorJson).size + 1 };
			},
		});
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_SIZE_MISMATCH");
	});

	test("a missing referenced blob is rejected", () => {
		const { files } = buildLayout({ afterFiles: (map, pieces) => map.delete(blobPathOf(pieces.configDescriptor.digest)) });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_BLOB_MISSING");
	});

	test("an unknown layer media type is rejected", () => {
		const { files } = buildLayout({ layers: [{ bytes: Buffer.from("entry"), mediaType: COMPONENT_MEDIA }, { bytes: Buffer.from("x"), mediaType: "application/octet-stream" }] });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_MANIFEST_INVALID");
	});

	test("an index descriptor with annotations or a second descriptor is rejected", () => {
		const withAnnotation = buildLayout({
			indexTransform: (index) => {
				const manifests = index.manifests as DescriptorJson[];
				manifests[0] = { ...manifests[0], annotations: { "org.opencontainers.image.source": "https://example.invalid" } } as unknown as DescriptorJson;
			},
		});
		expectFailureCode(validateWasmOciLayoutV1(withAnnotation.files), "WASM_OCI_INDEX_INVALID");
		const twoDescriptors = buildLayout({
			indexTransform: (index) => {
				const manifests = index.manifests as DescriptorJson[];
				index.manifests = [manifests[0], manifests[0]];
			},
		});
		expectFailureCode(validateWasmOciLayoutV1(twoDescriptors.files), "WASM_OCI_INDEX_INVALID");
	});

	test("a manifest with an unknown top-level field is rejected", () => {
		const { files } = buildLayout({ manifestTransform: (manifest) => (manifest.annotations = {}) });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_MANIFEST_INVALID");
	});

	test("float and negative descriptor sizes are rejected as non-integers", () => {
		const floatSize = buildLayout({
			manifestTransform: (manifest) => {
				manifest.config = { mediaType: CONFIG_MEDIA, digest: (manifest.config as DescriptorJson).digest, size: 1.5 };
			},
		});
		expectFailureCode(validateWasmOciLayoutV1(floatSize.files), "WASM_OCI_INTEGER_INVALID");
		const negativeSize = buildLayout({
			manifestTransform: (manifest) => {
				manifest.config = { mediaType: CONFIG_MEDIA, digest: (manifest.config as DescriptorJson).digest, size: -1 };
			},
		});
		expectFailureCode(validateWasmOciLayoutV1(negativeSize.files), "WASM_OCI_INTEGER_INVALID");
	});

	test("node admission bounds reject layer count, blob size and package size breaches", () => {
		const base = buildLayout();
		expectFailureCode(validateWasmOciLayoutV1(base.files, { maxPackageBytes: 536870912, maxBlobBytes: 134217728, maxLayerCount: 2 }), "WASM_OCI_LAYER_COUNT_INVALID");
		expectFailureCode(validateWasmOciLayoutV1(base.files, { maxPackageBytes: 536870912, maxBlobBytes: 8, maxLayerCount: 128 }), "WASM_OCI_SIZE_OUT_OF_RANGE");
		expectFailureCode(validateWasmOciLayoutV1(base.files, { maxPackageBytes: 100, maxBlobBytes: 134217728, maxLayerCount: 128 }), "WASM_OCI_PACKAGE_TOO_LARGE");
	});

	test("unknown layout paths and malformed blob filenames are rejected", () => {
		const extraPath = buildLayout({ afterFiles: (map) => map.set("refs/tags/latest", Buffer.from("{}")) });
		expectFailureCode(validateWasmOciLayoutV1(extraPath.files), "WASM_OCI_LAYOUT_PATH_INVALID");
		const uppercaseBlob = buildLayout({ afterFiles: (map) => map.set("blobs/sha256/" + "A".repeat(64), Buffer.from("x")) });
		expectFailureCode(validateWasmOciLayoutV1(uppercaseBlob.files), "WASM_OCI_LAYOUT_PATH_INVALID");
	});

	test("oci-layout with a different imageLayoutVersion is rejected", () => {
		const { files } = buildLayout({ afterFiles: (map) => map.set("oci-layout", Buffer.from('{"imageLayoutVersion":"1.0.1"}', "utf8")) });
		expectFailureCode(validateWasmOciLayoutV1(files), "WASM_OCI_LAYOUT_FILE_INVALID");
	});

	test("entryLayerDigest must name exactly one component layer", () => {
		// entryLayerDigest 指向 adapter layer：
		const adapterOnly = buildLayout({
			layers: [
				{ bytes: Buffer.from("entry payload"), mediaType: COMPONENT_MEDIA },
				{ bytes: Buffer.from("adapter payload"), mediaType: ADAPTER_MEDIA },
			],
		});
		const adapterDigest = adapterOnly.pieces.layerDescriptors[1].digest;
		const adapterEntry = buildLayout({
			layers: [
				{ bytes: Buffer.from("entry payload"), mediaType: COMPONENT_MEDIA },
				{ bytes: Buffer.from("adapter payload"), mediaType: ADAPTER_MEDIA },
			],
			configTransform: (config) => (config.entryLayerDigest = adapterDigest),
		});
		expectFailureCode(validateWasmOciLayoutV1(adapterEntry.files), "WASM_OCI_ENTRY_LAYER_INVALID");
		const unknownEntry = buildLayout({
			configTransform: (config) => (config.entryLayerDigest = "sha256:" + "4".repeat(64)),
		});
		expectFailureCode(validateWasmOciLayoutV1(unknownEntry.files), "WASM_OCI_ENTRY_LAYER_INVALID");
	});

	test("config literals, import grammar, ordering and direction are enforced", () => {
		const wrongWorld = buildLayout({ configTransform: (config) => (config.world = "wasi:http/proxy@0.2.9") });
		expectFailureCode(validateWasmOciLayoutV1(wrongWorld.files), "WASM_OCI_CONFIG_INVALID");
		const wrongHostABI = buildLayout({ configTransform: (config) => (config.hostABI = "iweb-wasmd-abi@1.1.0") });
		expectFailureCode(validateWasmOciLayoutV1(wrongHostABI.files), "WASM_OCI_CONFIG_INVALID");
		const unsortedImports = buildLayout({
			configTransform: (config) =>
				(config.declaredHostImports = [
					{ package: "wasi:io@0.2.8", interface: "streams", direction: "import" },
					{ package: "wasi:http@0.2.8", interface: "outgoing-handler", direction: "import" },
				]),
		});
		expectFailureCode(validateWasmOciLayoutV1(unsortedImports.files), "WASM_OCI_CONFIG_INVALID");
		const duplicateImports = buildLayout({
			configTransform: (config) =>
				(config.declaredHostImports = [
					{ package: "wasi:http@0.2.8", interface: "outgoing-handler", direction: "import" },
					{ package: "wasi:http@0.2.8", interface: "outgoing-handler", direction: "import" },
				]),
		});
		expectFailureCode(validateWasmOciLayoutV1(duplicateImports.files), "WASM_OCI_CONFIG_INVALID");
		const exportDirection = buildLayout({
			configTransform: (config) =>
				(config.declaredHostImports = [{ package: "wasi:http@0.2.8", interface: "incoming-handler", direction: "export" }]),
		});
		expectFailureCode(validateWasmOciLayoutV1(exportDirection.files), "WASM_OCI_CONFIG_INVALID");
		const unversionedPackage = buildLayout({
			configTransform: (config) => (config.declaredHostImports = [{ package: "wasi:http", interface: "outgoing-handler", direction: "import" }]),
		});
		expectFailureCode(validateWasmOciLayoutV1(unversionedPackage.files), "WASM_OCI_CONFIG_INVALID");
		const leadingZeroVersion = buildLayout({
			configTransform: (config) => (config.declaredHostImports = [{ package: "wasi:http@0.2.08", interface: "outgoing-handler", direction: "import" }]),
		});
		expectFailureCode(validateWasmOciLayoutV1(leadingZeroVersion.files), "WASM_OCI_CONFIG_INVALID");
	});
});

// ---------------------------------------------------------------------------
// 归一化 admission manifest 负例
// ---------------------------------------------------------------------------

describe("wasm digest contract: normalized admission manifest vectors", () => {
	const base = (): Record<string, unknown> => admissionFromConfig(baseConfig("sha256:" + "5".repeat(64)), "notes");

	test("celld executable-authority fields are rejected", () => {
		const withEntrypoint = base();
		(withEntrypoint.runtime as Record<string, unknown>).entrypoint = "worker.js";
		expectFailureCode(validateNormalizedWasmManifestV1(withEntrypoint), "WASM_MANIFEST_INVALID");
		const withAssets = base();
		withAssets.assets = { root: "public" };
		expectFailureCode(validateNormalizedWasmManifestV1(withAssets), "WASM_MANIFEST_INVALID");
		const withImage = base();
		withImage.image = "docker.io/example/app:latest";
		expectFailureCode(validateNormalizedWasmManifestV1(withImage), "WASM_MANIFEST_INVALID");
	});

	test("resource, storage and egress bounds are enforced", () => {
		const zeroCpu = base();
		(zeroCpu.resources as Record<string, unknown>).cpuMillis = 0;
		expectFailureCode(validateNormalizedWasmManifestV1(zeroCpu), "WASM_MANIFEST_INVALID");
		const floatCpu = base();
		(floatCpu.resources as Record<string, unknown>).cpuMillis = 1.5;
		expectFailureCode(validateNormalizedWasmManifestV1(floatCpu), "WASM_MANIFEST_INVALID");
		const hugeMemory = base();
		(hugeMemory.resources as Record<string, unknown>).memoryBytes = 68719476737;
		expectFailureCode(validateNormalizedWasmManifestV1(hugeMemory), "WASM_MANIFEST_INVALID");
		const negativePid = base();
		(negativePid.resources as Record<string, unknown>).pidLimit = -3;
		expectFailureCode(validateNormalizedWasmManifestV1(negativePid), "WASM_MANIFEST_INVALID");
		const overRequest = base();
		(overRequest.storage as Record<string, unknown>).requestBytes = 1048577;
		expectFailureCode(validateNormalizedWasmManifestV1(overRequest), "WASM_MANIFEST_INVALID");
	});

	test("egress must stay default-deny, sorted, unique and bounded", () => {
		const allowDefault = base();
		(allowDefault.egress as Record<string, unknown>).default = "allow";
		expectFailureCode(validateNormalizedWasmManifestV1(allowDefault), "WASM_MANIFEST_INVALID");
		const unsorted = base();
		(unsorted.egress as Record<string, unknown>).allow = [{ host: "mirror.example.org", port: 443 }, { host: "api.example.com", port: 443 }];
		expectFailureCode(validateNormalizedWasmManifestV1(unsorted), "WASM_MANIFEST_INVALID");
		const duplicate = base();
		(duplicate.egress as Record<string, unknown>).allow = [{ host: "api.example.com", port: 443 }, { host: "api.example.com", port: 443 }];
		expectFailureCode(validateNormalizedWasmManifestV1(duplicate), "WASM_MANIFEST_INVALID");
		const zeroPort = base();
		(zeroPort.egress as Record<string, unknown>).allow = [{ host: "api.example.com", port: 0 }];
		expectFailureCode(validateNormalizedWasmManifestV1(zeroPort), "WASM_MANIFEST_INVALID");
		const highPort = base();
		(highPort.egress as Record<string, unknown>).allow = [{ host: "api.example.com", port: 65536 }];
		expectFailureCode(validateNormalizedWasmManifestV1(highPort), "WASM_MANIFEST_INVALID");
		const ipHost = base();
		(ipHost.egress as Record<string, unknown>).allow = [{ host: "127.0.0.1", port: 443 }];
		expectFailureCode(validateNormalizedWasmManifestV1(ipHost), "INVALID_HOST");
		const tooMany: { host: string; port: number }[] = [];
		for (let i = 0; i < 257; i++) tooMany.push({ host: "h" + String(i).padStart(3, "0") + ".example.com", port: 443 });
		const overflow = base();
		(overflow.egress as Record<string, unknown>).allow = tooMany;
		expectFailureCode(validateNormalizedWasmManifestV1(overflow), "WASM_MANIFEST_INVALID");
	});

	test("name grammar matches the applicationId pattern with its 63-byte boundary", () => {
		const ok63 = base();
		ok63.name = "a".repeat(63);
		expect(validateNormalizedWasmManifestV1(ok63).ok).toBe(true);
		const bad64 = base();
		bad64.name = "a".repeat(64);
		expectFailureCode(validateNormalizedWasmManifestV1(bad64), "WASM_MANIFEST_INVALID");
		const upper = base();
		upper.name = "Vector";
		expectFailureCode(validateNormalizedWasmManifestV1(upper), "WASM_MANIFEST_INVALID");
		expect(WASM_APPLICATION_ID_PATTERN.test("a")).toBe(true);
		expect(WASM_APPLICATION_ID_PATTERN.test("a-")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// config runtime projection ↔ admission manifest
// ---------------------------------------------------------------------------

describe("wasm digest contract: config runtime projection consistency", () => {
	test("byte-identical projections pass", () => {
		const config = expectConfigOk(baseConfig("sha256:" + "6".repeat(64)));
		const admission = expectManifestOk(admissionFromConfig(baseConfig("sha256:" + "6".repeat(64)), "notes"));
		expect(validateWasmAdmissionConsistency(config, admission).ok).toBe(true);
	});

	test("any runtime divergence fails closed with WASM_CONFIG_MANIFEST_MISMATCH", () => {
		const config = expectConfigOk(baseConfig("sha256:" + "6".repeat(64)));
		const differentImports = admissionFromConfig(baseConfig("sha256:" + "6".repeat(64)), "notes");
		(differentImports.runtime as Record<string, unknown>).declaredHostImports = [
			{ package: "wasi:http@0.2.8", interface: "outgoing-handler", direction: "import" },
			{ package: "wasi:io@0.2.8", interface: "streams", direction: "import" },
			{ package: "wasi:random@0.2.8", interface: "random", direction: "import" },
		];
		const manifestWithExtra = expectManifestOk(differentImports);
		expectFailureCode(validateWasmAdmissionConsistency(config, manifestWithExtra), "WASM_CONFIG_MANIFEST_MISMATCH");

		const differentEntry = admissionFromConfig(baseConfig("sha256:" + "6".repeat(64)), "notes");
		(differentEntry.runtime as Record<string, unknown>).entryLayerDigest = "sha256:" + "7".repeat(64);
		expectFailureCode(validateWasmAdmissionConsistency(config, expectManifestOk(differentEntry)), "WASM_CONFIG_MANIFEST_MISMATCH");
	});
});

// ---------------------------------------------------------------------------
// versionId 与 AdmissionProof digest 字段
// ---------------------------------------------------------------------------

describe("wasm digest contract: versionId and admission proof digests", () => {
	test("versionId composes and parses with the u53 boundary", () => {
		const digest = "a".repeat(64);
		const max = 9007199254740991;
		expect(composeWasmVersionId(digest, max)).toBe(digest + "-" + max);
		const parsed = parseWasmVersionId(digest + "-" + max);
		if (!parsed.ok) throw new Error("expected parse success");
		expect(parsed.value.versionDigest).toBe(digest);
		expect(parsed.value.sequence).toBe(max);
	});

	test("versionId grammar rejects leading zeros, zero and oversized sequences", () => {
		const digest = "a".repeat(64);
		expect(parseWasmVersionId(digest + "-01").ok).toBe(false);
		expect(parseWasmVersionId(digest + "-0").ok).toBe(false);
		expect(parseWasmVersionId(digest + "-" + "9".repeat(17)).ok).toBe(false);
		expect(parseWasmVersionId(digest.toUpperCase() + "-1").ok).toBe(false);
		expect(parseWasmVersionId(digest).ok).toBe(false);
	});

	test("proof digest fields fail closed on every divergence", () => {
		const parsed = parseStrictJson(SPEC_VECTOR_MANIFEST);
		if (!parsed.ok) throw new Error("spec vector must parse");
		const good = {
			applicationId: "vector",
			packageDigest: SPEC_VECTOR_PACKAGE_DIGEST,
			versionDigest: SPEC_VECTOR_VERSION_DIGEST,
			sequence: 1,
			versionId: SPEC_VECTOR_VERSION_DIGEST + "-1",
			normalizedPolicy: parsed.value,
		};
		expect(verifyWasmAdmissionProofDigestFields(good).ok).toBe(true);
		const wrongVersionDigest = { ...good, versionDigest: "e".repeat(64), versionId: "e".repeat(64) + "-1" };
		expectFailureCode(verifyWasmAdmissionProofDigestFields(wrongVersionDigest), "WASM_VERSION_DIGEST_MISMATCH");
		const wrongComposition = { ...good, versionId: SPEC_VECTOR_VERSION_DIGEST + "-2" };
		expectFailureCode(verifyWasmAdmissionProofDigestFields(wrongComposition), "WASM_VERSION_ID_INVALID");
		const wrongName = { ...good, applicationId: "other" };
		expectFailureCode(verifyWasmAdmissionProofDigestFields(wrongName), "WASM_APPLICATION_ID_MISMATCH");
		const upperPackageDigest = { ...good, packageDigest: "F".repeat(64) };
		expectFailureCode(verifyWasmAdmissionProofDigestFields(upperPackageDigest), "INVALID_DIGEST");
	});

	test("admission proof digest uses the domain-prefixed single SHA-256 operation", () => {
		const proof = { schemaVersion: 1, applicationId: "vector", versionId: SPEC_VECTOR_VERSION_DIGEST + "-1" };
		const expected = sha256Hex(Buffer.concat([Buffer.from("iweb-admission-proof-v1\n", "utf8"), jcsBuffer(proof)]));
		expect(computeWasmAdmissionProofDigestV1(proof)).toBe(expected);
	});
});
