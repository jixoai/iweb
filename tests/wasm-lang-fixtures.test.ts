// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x）：三条一级参考语言（Rust/TypeScript/
// MoonBit）的 wasi:http@0.2.8 proxy world 组件 fixture 必须作为真实工具链产物进入电池——
// 每个产物用 contracts 的 iweb-wasm-oci-layout-v1 布局校验 + 二进制闭包扫描（imports ⊆
// revision-1 能力矩阵、声明=发现），三者 packageDigest 互异且可复算。
// 正交意图：产物缺失 skip 不 fail（构建需要各语言工具链，见各 build.sh.ts）；TS 线的
// StarlingMonkey 已知缺口按实证行为钉死（fail-closed 拒绝码 + 0.2.10 import 面形状），
// 不假装通过矩阵。
//
// 产物来源（工具链钉死，各目录 build.sh.ts 单一来源再生）：
// - lang-rust：rustc 1.98.0（wit-component 0.234.0，wasm32-wasip2）+ cargo --locked
//   （wit-bindgen 0.57.1）；产物 core module 的 canonical ABI raw import 全部绑定到
//   component typed 实例导入（scanner instanceBoundImports 路径）。
// - lang-ts：componentize-js 0.22.0（StarlingMonkey 引擎）；组件 import 面钉在
//   wasi 0.2.10，引擎 0.2.8 命名 raw import 面经 inline core instance 接线（scanner
//   不建模）→ WASM_IMPORT_UNMAPPABLE fail-closed（见 build.sh.ts 已知缺口注记）。
// - lang-moonbit：moon 0.1.20260824 + wit-bindgen-cli 0.57.1 + wasm-tools 1.258.0。
import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import {
	computeWasmPackageDigestV1,
	jcsCanonicalBytes,
	sha256Hex,
	validateDeclaredHostImports,
	validateWasmOciLayoutV1,
	WASM_COMPONENT_LAYER_MEDIA_TYPE,
	WASM_CONFIG_MEDIA_TYPE,
	WASM_HOST_ABI_LITERAL,
	WASM_OCI_MANIFEST_MEDIA_TYPE,
	WASM_WORLD_LITERAL,
	type WasmImportCapability,
} from "../packages/contracts/wasm-package.ts";
import {
	scanAndValidateWasmClosure,
	scanWasmClosureGraph,
	validateWasmLayerRole,
	WASM_CLOSURE_SCAN_ADMISSION_MAXIMA,
	type WasmClosureScanErrorCode,
} from "../packages/contracts/wasm-closure-scanner.ts";
import { compareWasmCapabilityIds, isAllowedWasmHostImport } from "../packages/contracts/wasm-capability.ts";
import type { ValidationIssue } from "../packages/contracts/validation.ts";

const FIXTURES = `${import.meta.dir}/fixtures/wasm`;

const PROXY_DECLARED_HOST_IMPORTS: readonly WasmImportCapability[] = [
	{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
	{ package: "wasi:io@0.2.8", interface: "error", direction: "import" },
	{ package: "wasi:io@0.2.8", interface: "streams", direction: "import" },
];

// StarlingMonkey 引擎实际 import 面（0.2.10；grammar 合法、矩阵外）——与 build.sh.ts 的
// 形状钉死一致，防止工具链静默漂移。
const STARLINGMONKEY_IMPORT_FACE: readonly string[] = [
	"wasi:clocks@0.2.10/monotonic-clock",
	"wasi:http@0.2.10/outgoing-handler",
	"wasi:http@0.2.10/types",
	"wasi:io@0.2.10/error",
	"wasi:io@0.2.10/poll",
	"wasi:io@0.2.10/streams",
];

interface LangFixture {
	readonly name: string;
	readonly dir: string;
	readonly artifact: string;
	/** config.declaredHostImports（布局校验用；须 (package, interface, direction) 字节序）。 */
	readonly declaredHostImports: readonly WasmImportCapability[];
	/** 闭包判定预期：矩阵内通过（声明=发现 ⊆ revision-1）或 fail-closed 拒绝码。 */
	readonly matrixOutcome: { readonly kind: "pass" } | { readonly kind: "rejected"; readonly code: WasmClosureScanErrorCode };
}

const LANG_FIXTURES: readonly LangFixture[] = [
	{ name: "rust", dir: "lang-rust", artifact: "lang-rust-proxy.wasm", declaredHostImports: PROXY_DECLARED_HOST_IMPORTS, matrixOutcome: { kind: "pass" } },
	{ name: "moonbit", dir: "lang-moonbit", artifact: "lang-moonbit-proxy.wasm", declaredHostImports: PROXY_DECLARED_HOST_IMPORTS, matrixOutcome: { kind: "pass" } },
	{
		name: "typescript",
		dir: "lang-ts",
		artifact: "lang-ts-proxy.wasm",
		declaredHostImports: STARLINGMONKEY_IMPORT_FACE.map((key) => {
			const slash = key.lastIndexOf("/");
			return { package: key.slice(0, slash), interface: key.slice(slash + 1), direction: "import" } as WasmImportCapability;
		}),
		matrixOutcome: { kind: "rejected", code: "WASM_IMPORT_UNMAPPABLE" },
	},
];

/** 把单一 component 产物打包成合法 iweb-wasm-oci-layout-v1 文件映射（单层 component entry）。 */
function buildLayoutFiles(componentBytes: Uint8Array, declaredHostImports: readonly WasmImportCapability[]): ReadonlyMap<string, Uint8Array> {
	const declaredErrors: ValidationIssue[] = [];
	if (validateDeclaredHostImports(declaredHostImports, "", "TEST", declaredErrors) === null) {
		throw new Error("fixture declaredHostImports invalid: " + JSON.stringify(declaredErrors));
	}
	const layer = { mediaType: WASM_COMPONENT_LAYER_MEDIA_TYPE, digest: "sha256:" + sha256Hex(componentBytes), size: componentBytes.length };
	const configBytes = jcsCanonicalBytes({
		schemaVersion: 1,
		kind: "wasm",
		entryLayerDigest: layer.digest,
		world: WASM_WORLD_LITERAL,
		hostABI: WASM_HOST_ABI_LITERAL,
		declaredHostImports,
	});
	const config = { mediaType: WASM_CONFIG_MEDIA_TYPE, digest: "sha256:" + sha256Hex(configBytes), size: configBytes.length };
	const manifestBytes = jcsCanonicalBytes({ schemaVersion: 2, config, layers: [layer] });
	const manifest = { mediaType: WASM_OCI_MANIFEST_MEDIA_TYPE, digest: "sha256:" + sha256Hex(manifestBytes), size: manifestBytes.length };
	const indexBytes = jcsCanonicalBytes({ schemaVersion: 2, manifests: [manifest] });
	const files = new Map<string, Uint8Array>();
	files.set("oci-layout", new Uint8Array(Buffer.from('{"imageLayoutVersion":"1.0.0"}', "utf8")));
	files.set("index.json", indexBytes);
	const putBlob = (digest: string, bytes: Uint8Array): void => {
		files.set("blobs/sha256/" + digest.slice("sha256:".length), bytes);
	};
	putBlob(manifest.digest, manifestBytes);
	putBlob(config.digest, configBytes);
	putBlob(layer.digest, componentBytes);
	return files;
}

async function artifactBytes(lang: LangFixture): Promise<Uint8Array> {
	return new Uint8Array(await Bun.file(`${FIXTURES}/${lang.dir}/${lang.artifact}`).arrayBuffer());
}

// 每语言 digest 收集（互异性断言用；产物缺失的语言不产生条目）。
const packageDigests = new Map<string, string>();

describe("real-language proxy fixtures", () => {
	for (const lang of LANG_FIXTURES) {
		const present = existsSync(`${FIXTURES}/${lang.dir}/${lang.artifact}`);
		if (!present) {
			// 产物由各目录 build.sh.ts 用钉死工具链再生；缺失时 skip 不 fail（无工具链环境可跑电池）。
			test.skip(`${lang.name}: artifact ${lang.dir}/${lang.artifact} is absent (rebuild with its build.sh.ts)`, () => {});
			continue;
		}

		test(`${lang.name}: component layer passes role validation and a strict iweb-wasm-oci-layout-v1 packaging`, async () => {
			const bytes = await artifactBytes(lang);
			const role = validateWasmLayerRole("component", bytes);
			expect(role.ok).toBe(true);

			const validated = validateWasmOciLayoutV1(buildLayoutFiles(bytes, lang.declaredHostImports));
			expect(validated.ok).toBe(true);
			if (!validated.ok) return;
			const { layout } = validated.value;
			// entry 层即产物本体：descriptor digest/size 与 config 指向逐字一致。
			expect(layout.manifest.layers).toHaveLength(1);
			expect(layout.manifest.layers[0].digest).toBe("sha256:" + sha256Hex(bytes));
			expect(layout.manifest.layers[0].size).toBe(bytes.length);
			expect(layout.config.entryLayerDigest).toBe(layout.manifest.layers[0].digest);
			expect(layout.layerBytes[0].byteLength).toBe(bytes.length);
			packageDigests.set(lang.name, validated.value.packageDigest);
		});

		test(`${lang.name}: packageDigest is recomputable from the raw artifact bytes`, async () => {
			const bytes = await artifactBytes(lang);
			const first = validateWasmOciLayoutV1(buildLayoutFiles(bytes, lang.declaredHostImports));
			const second = validateWasmOciLayoutV1(buildLayoutFiles(bytes, lang.declaredHostImports));
			expect(first.ok).toBe(true);
			expect(second.ok).toBe(true);
			if (!first.ok || !second.ok) return;
			expect(first.value.packageDigest).toBe(second.value.packageDigest);
			expect(first.value.packageDigest).toBe(computeWasmPackageDigestV1(first.value.layout));
		});

		test(`${lang.name}: closure scan against the revision-1 matrix matches the recorded outcome`, async () => {
			const bytes = await artifactBytes(lang);
			const scan = scanAndValidateWasmClosure({
				entry: bytes,
				world: WASM_WORLD_LITERAL,
				hostABI: WASM_HOST_ABI_LITERAL,
				declaredHostImports: lang.declaredHostImports,
				budget: WASM_CLOSURE_SCAN_ADMISSION_MAXIMA,
			});
			if (lang.matrixOutcome.kind === "pass") {
				expect(scan.ok).toBe(true);
				if (!scan.ok) return;
				// imports ⊆ revision-1 矩阵（逐项分类）且声明=发现。
				for (const discovered of scan.discoveredHostImports) expect(isAllowedWasmHostImport(discovered)).toBe(true);
				expect(scan.discoveredHostImports).toEqual([...lang.declaredHostImports].sort(compareWasmCapabilityIds));
			} else {
				expect(scan.ok).toBe(false);
				if (scan.ok) return;
				expect(scan.code).toBe(lang.matrixOutcome.code);
				expect(scan.detail.length).toBeGreaterThan(0);
			}
		});
	}

	const tsArtifact = `${FIXTURES}/lang-ts/lang-ts-proxy.wasm`;
	if (!existsSync(tsArtifact)) {
		test.skip("starlingmonkey import face: artifact absent", () => {});
	} else {
		test("the starlingmonkey fixture pins its engine import face at wasi 0.2.10", async () => {
			const scanned = scanWasmClosureGraph({
				entry: new Uint8Array(await Bun.file(tsArtifact).arrayBuffer()),
				world: WASM_WORLD_LITERAL,
				hostABI: WASM_HOST_ABI_LITERAL,
				declaredHostImports: [],
				budget: WASM_CLOSURE_SCAN_ADMISSION_MAXIMA,
			});
			expect(scanned.ok).toBe(true);
			if (!scanned.ok) return;
			const imports = new Set<string>();
			for (const node of scanned.graph.nodes) {
				for (const occurrence of node.interfaces) {
					if (occurrence.direction === "import") imports.add(occurrence.package + "/" + occurrence.interface);
				}
			}
			expect([...imports].sort()).toEqual([...STARLINGMONKEY_IMPORT_FACE]);
		});
	}

	test("the three language package digests are mutually distinct", () => {
		// 至少两个产物在场才构成互异性证据；全缺时本文件整体 skip。
		const present = LANG_FIXTURES.filter((lang) => packageDigests.has(lang.name)).map((lang) => lang.name);
		if (present.length < 2) return;
		const seen = new Map<string, string>();
		for (const [name, digest] of packageDigests) {
			expect(seen.has(digest)).toBe(false);
			seen.set(digest, name);
			expect(digest).toMatch(/^[a-f0-9]{64}$/);
		}
	});
});
