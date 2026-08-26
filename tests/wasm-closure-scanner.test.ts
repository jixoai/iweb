// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.3 剩余部分）：二进制 imports 闭包 scanner 必须把
// component/core module/adapter 制品解码为 typed 图并复现 spec 五步判定：唯一类型一致内部解析、re-export
// 折叠、歧义/类型不一致/未解析拒绝、adapter 翻译闭包、node/edge/depth 预算、声明集合=发现集合；畸形二进制
// fail-closed（结构化错误码、不崩溃）。
// 正交意图：真实工具链 fixture 的端到端扫描；typed 图形状/折叠/确定性断言；预算与畸形输入负例。
//
// fixture 来源（版本钉死）：tests/fixtures/wasm/generate-wasm-fixtures.sh.ts 用 wasm-tools 1.258.0
// （Homebrew；wit-component 0.258.0，见产物 producers 段）生成并提交；测试不依赖工具链与网络。
// 签名形状：wasi:http@0.2.8 的 types/incoming-handler 为最小替身（resource request + make/handle），
// 接口身份与版本为真值；iweb:config/store 的接口形状逐字段对齐 packages/contracts/wit/iweb-config.wit。
import { describe, expect, test } from "bun:test";
import {
	scanAndValidateWasmClosure,
	scanWasmClosureGraph,
	validateWasmLayerRole,
	WASM_CLOSURE_SCAN_ADMISSION_MAXIMA,
	type WasmClosureScanErrorCode,
	type WasmClosureScanInput,
} from "../packages/contracts/wasm-closure-scanner.ts";
import { WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL, type WasmImportCapability } from "../packages/contracts/wasm-package.ts";

const FIXTURES = `${import.meta.dir}/fixtures/wasm`;

async function fixture(name: string): Promise<Uint8Array> {
	return new Uint8Array(await Bun.file(`${FIXTURES}/${name}`).arrayBuffer());
}

const GENEROUS_BUDGET = { maxNodes: 64, maxEdges: 64, maxDepth: 16 };
const TYPES_IMPORT: WasmImportCapability = { package: "wasi:http@0.2.8", interface: "types", direction: "import" };
const CONFIG_STORE_IMPORT: WasmImportCapability = { package: "iweb:config@1.0.0", interface: "store", direction: "import" };
const SECRETS_STORE_IMPORT: WasmImportCapability = { package: "iweb:secrets@1.0.0", interface: "store", direction: "import" };

function input(entry: Uint8Array, declaredHostImports: readonly WasmImportCapability[], overrides: Partial<WasmClosureScanInput> = {}): WasmClosureScanInput {
	return { entry, world: WASM_WORLD_LITERAL, hostABI: WASM_HOST_ABI_LITERAL, declaredHostImports, budget: GENEROUS_BUDGET, ...overrides };
}

function expectCode(result: { readonly ok: boolean; readonly code?: WasmClosureScanErrorCode }, code: WasmClosureScanErrorCode): void {
	expect(result.ok).toBe(false);
	if (!result.ok) {
		expect(result.code).toBe(code);
		expect(result.detail.length).toBeGreaterThan(0);
	}
}

describe("closure resolution through real binaries", () => {
	test("a declared matrix host import is discovered from the decoded component import", async () => {
		const result = scanAndValidateWasmClosure(input(await fixture("proxy-minimal.wasm"), [TYPES_IMPORT]));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.discoveredHostImports).toEqual([TYPES_IMPORT]);
	});

	test("an import provided by exactly one reachable nested component resolves internally", async () => {
		const result = scanAndValidateWasmClosure(input(await fixture("proxy-composed.wasm"), []));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.discoveredHostImports).toEqual([]);
	});

	test("a re-export aliases its original provider instead of creating a second one", async () => {
		const scanned = scanWasmClosureGraph(input(await fixture("proxy-composed.wasm"), []));
		expect(scanned.ok).toBe(true);
		if (!scanned.ok) return;
		const { graph } = scanned;
		// 入口自身的根导出折叠到 consumer 嵌套 component（组合器以 alias+export 重导出）。
		const entry = graph.nodes.find((node) => node.id === graph.entryNodeId);
		expect(entry).toBeDefined();
		const rootExport = entry?.interfaces.find((occurrence) => occurrence.direction === "export");
		expect(rootExport).toMatchObject({ package: "wasi:http@0.2.8", interface: "incoming-handler" });
		expect(rootExport?.providerAlias).toBeDefined();
		expect(rootExport?.providerAlias).not.toBe(graph.entryNodeId);
		const folded = graph.nodes.find((node) => node.id === rootExport?.providerAlias);
		expect(folded?.kind).toBe("component");
		// provider 侧（导出 types 的嵌套 component）同样折叠到其 shim；两个折叠后 types 只剩一个 provider。
		const typesExporters = graph.nodes.filter((node) => node.interfaces.some((occurrence) => occurrence.package === "wasi:http@0.2.8" && occurrence.interface === "types" && occurrence.direction === "export"));
		expect(typesExporters).toHaveLength(1);
	});

	test("scanning is deterministic and the graph echoes config, declared set, and budget", async () => {
		const entry = await fixture("proxy-composed.wasm");
		const first = scanWasmClosureGraph(input(entry, [TYPES_IMPORT]));
		const second = scanWasmClosureGraph(input(entry, [TYPES_IMPORT]));
		expect(first.ok).toBe(true);
		expect(second.ok).toBe(true);
		if (first.ok && second.ok) expect(first.graph).toEqual(second.graph);
		if (first.ok) {
			expect(first.graph.world).toBe(WASM_WORLD_LITERAL);
			expect(first.graph.hostABI).toBe(WASM_HOST_ABI_LITERAL);
			expect(first.graph.declaredHostImports).toEqual([TYPES_IMPORT]);
			expect(first.graph.budget).toEqual(GENEROUS_BUDGET);
		}
	});

	test("the composed graph shape is decoded with containment and instantiation edges", async () => {
		const scanned = scanWasmClosureGraph(input(await fixture("proxy-composed.wasm"), []));
		expect(scanned.ok).toBe(true);
		if (!scanned.ok) return;
		const { graph } = scanned;
		expect(graph.nodes.map((node) => node.kind).sort()).toEqual(["component", "component", "component", "component", "component", "core-module", "core-module"]);
		expect(graph.edges).toHaveLength(6);
		for (const edge of graph.edges) {
			expect(graph.nodes.some((node) => node.id === edge.from)).toBe(true);
			expect(graph.nodes.some((node) => node.id === edge.to)).toBe(true);
		}
	});

	test("two type-identical internal providers are rejected as ambiguous", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("two-providers.wasm"), [])), "WASM_IMPORT_AMBIGUOUS");
	});

	test("a provider with a different structural type identity is rejected", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("provider-type-mismatch.wasm"), [])), "WASM_INTERNAL_TYPE_MISMATCH");
	});

	test("an interface outside the normalized mapping is rejected", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("unknown-interface.wasm"), [])), "WASM_INTERFACE_UNKNOWN");
	});

	test("a known interface at an unlisted version is rejected", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("unlisted-version.wasm"), [])), "WASM_INTERFACE_VERSION_UNLISTED");
	});

	test("importing the root export identity is unresolved", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("import-root-export-identity.wasm"), [])), "WASM_IMPORT_UNRESOLVED");
	});

	test("an entry import without a typed interface mapping is unmappable", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("entry-func-import.wasm"), [])), "WASM_IMPORT_UNMAPPABLE");
	});

	test("the discovered set must equal the declared set in both directions", async () => {
		const entry = await fixture("proxy-minimal.wasm");
		expectCode(scanAndValidateWasmClosure(input(entry, [])), "WASM_DECLARATION_MISMATCH");
		expectCode(scanAndValidateWasmClosure(input(entry, [SECRETS_STORE_IMPORT])), "WASM_DECLARATION_MISMATCH");
	});

	test("a non-matrix world or host ABI is rejected by the closure validator", async () => {
		const entry = await fixture("proxy-minimal.wasm");
		expectCode(scanAndValidateWasmClosure(input(entry, [TYPES_IMPORT], { world: "wasi:http/proxy@0.2.7" })), "WASM_WORLD_UNSUPPORTED");
		expectCode(scanAndValidateWasmClosure(input(entry, [TYPES_IMPORT], { hostABI: "iweb-wasmd-abi@0.9.0" })), "WASM_HOST_ABI_MISMATCH");
	});

	test("the root export set must be exactly the required export", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("provider-only.wasm"), [])), "WASM_EXPORT_MISMATCH");
		const entry = await fixture("extra-type-export.wasm");
		// 入口未声明任何 host import；导出条目数 ≠ 1 在扫描层先 fail-closed。
		expectCode(scanAndValidateWasmClosure(input(entry, [TYPES_IMPORT])), "WASM_EXPORT_MISMATCH");
	});

	test("an iweb:config store import is discovered from the decoded interface shape", async () => {
		const entry = await fixture("iweb-store-import.wasm");
		const result = scanAndValidateWasmClosure(input(entry, [CONFIG_STORE_IMPORT]));
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.discoveredHostImports).toEqual([CONFIG_STORE_IMPORT]);
		expectCode(scanAndValidateWasmClosure(input(entry, [])), "WASM_DECLARATION_MISMATCH");
	});
});

describe("adapter translation closure", () => {
	test("an adapter module translates the core module raw imports", async () => {
		const scanned = scanWasmClosureGraph(input(await fixture("proxy-adapter.wasm"), [TYPES_IMPORT]));
		expect(scanned.ok).toBe(true);
		if (!scanned.ok) return;
		const { graph } = scanned;
		const adapter = graph.nodes.find((node) => node.kind === "adapter");
		expect(adapter?.adapterTranslations).toEqual(["wasi_snapshot_preview1.fd_write", "wasi_snapshot_preview1.random_get"]);
		const main = graph.nodes.find((node) => node.kind === "core-module" && (node.rawImports?.length ?? 0) > 0);
		expect(main?.rawImports).toEqual(["wasi_snapshot_preview1.fd_write", "wasi_snapshot_preview1.random_get"]);
		const validated = scanAndValidateWasmClosure(input(await fixture("proxy-adapter.wasm"), [TYPES_IMPORT]));
		expect(validated.ok).toBe(true);
	});

	test("a renamed adapter no longer covers the raw imports", async () => {
		expectCode(scanAndValidateWasmClosure(input(await fixture("proxy-adapter-renamed.wasm"), [TYPES_IMPORT])), "WASM_IMPORT_UNMAPPABLE");
	});
});

describe("closure budgets", () => {
	test("a depth budget breach is rejected before continuing", async () => {
		const entry = await fixture("nested-deep.wasm");
		expectCode(scanWasmClosureGraph(input(entry, [], { budget: { maxNodes: 16, maxEdges: 16, maxDepth: 4 } })), "WASM_CLOSURE_BUDGET_EXCEEDED");
	});

	test("node and edge budget breaches are rejected", async () => {
		const entry = await fixture("nested-deep.wasm");
		expectCode(scanWasmClosureGraph(input(entry, [], { budget: { maxNodes: 3, maxEdges: 16, maxDepth: 16 } })), "WASM_CLOSURE_BUDGET_EXCEEDED");
		expectCode(scanWasmClosureGraph(input(entry, [], { budget: { maxNodes: 16, maxEdges: 3, maxDepth: 16 } })), "WASM_CLOSURE_BUDGET_EXCEEDED");
	});

	test("within budget the deep chain decodes with exact node, edge, and depth counts", async () => {
		const result = scanAndValidateWasmClosure(input(await fixture("nested-deep.wasm"), [TYPES_IMPORT], { budget: { maxNodes: 16, maxEdges: 16, maxDepth: 8 } }));
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const { graph } = result;
		expect(graph.nodes).toHaveLength(6);
		expect(graph.edges).toHaveLength(5);
		let deepest = 1;
		const depthOf = new Map<string, number>([[graph.entryNodeId, 1]]);
		// 边按解析序为深优先（递归返回后补 containment 边），循环到不动点再取最大深度。
		for (let round = 0; round < graph.edges.length; round++) {
			for (const edge of graph.edges) {
				const from = depthOf.get(edge.from);
				if (from === undefined) continue;
				const known = depthOf.get(edge.to);
				if (known === undefined || known < from + 1) depthOf.set(edge.to, from + 1);
			}
		}
		for (const depth of depthOf.values()) if (depth > deepest) deepest = depth;
		expect(deepest).toBe(6);
		expect(graph.nodes.every((node) => node.interfaces.length === (node.id === graph.entryNodeId ? 2 : 0))).toBe(true);
	});

	test("admission maxima match the spec NodeCapabilityRecordV1 bounds", () => {
		expect(WASM_CLOSURE_SCAN_ADMISSION_MAXIMA).toEqual({ maxNodes: 4096, maxEdges: 16384, maxDepth: 64 });
	});
});

describe("malformed binaries fail closed without crashing", () => {
	test("empty, header-only, bad magic, and wrong-layer inputs are structured rejections", async () => {
		expectCode(scanWasmClosureGraph(input(new Uint8Array(0), [])), "WASM_BINARY_INVALID_HEADER");
		expectCode(scanWasmClosureGraph(input(new Uint8Array([0x00, 0x61, 0x73, 0x6d]), [])), "WASM_BINARY_INVALID_HEADER");
		expectCode(scanWasmClosureGraph(input(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01]), [])), "WASM_BINARY_INVALID_HEADER");
		const badMagic = new Uint8Array(await fixture("proxy-minimal.wasm"));
		badMagic[1] = 0x62;
		expectCode(scanWasmClosureGraph(input(badMagic, [])), "WASM_BINARY_INVALID_HEADER");
		const core = await fixture("core-raw-imports.wasm");
		expectCode(scanWasmClosureGraph(input(core, [])), "WASM_BINARY_INVALID_HEADER");
	});

	test("every truncation prefix fails closed with a structured rejection", async () => {
		const bytes = await fixture("proxy-composed.wasm");
		for (let length = 1; length < bytes.length; length += 7) {
			// 空前缀（如仅 header）本身可解码为空 component，但闭包判定必然 fail-closed（缺根导出等）。
			const result = scanAndValidateWasmClosure(input(bytes.slice(0, length), []));
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.detail.length).toBeGreaterThan(0);
		}
	});

	test("an unknown section id and an oversized section are structured rejections", async () => {
		const unknownSection = new Uint8Array(await fixture("proxy-minimal.wasm"));
		// 在文件末尾追加 section id 13（超出当前 component 段范围）。
		const appended = new Uint8Array([...unknownSection, 0x0d, 0x00]);
		expectCode(scanWasmClosureGraph(input(appended, [])), "WASM_BINARY_SECTION_INVALID");
		// 末尾追加一个声明 127 字节但实际只有 1 字节 payload 的 core module 段 → 截断。
		const oversized = new Uint8Array([...unknownSection, 0x01, 0x7f, 0x00]);
		expectCode(scanWasmClosureGraph(input(oversized, [])), "WASM_BINARY_TRUNCATED");
	});

	test("seeded byte mutations never throw and only return structured results", async () => {
		const original = await fixture("proxy-adapter.wasm");
		let state = 0x2a;
		const next = (): number => {
			state = (state * 1103515245 + 12345) % 2 ** 31;
			return state;
		};
		for (let round = 0; round < 240; round++) {
			const mutated = new Uint8Array(original);
			const mutations = 1 + (next() % 4);
			for (let m = 0; m < mutations; m++) mutated[next() % mutated.length] = next() % 256;
			const result = scanWasmClosureGraph(input(mutated, []));
			expect(result === null || result === undefined).toBe(false);
			if (!result.ok) expect(result.detail.length).toBeGreaterThan(0);
		}
	});
});

describe("layer role validation", () => {
	test("component, core-module, and adapter roles decode their declared forms", async () => {
		expect(validateWasmLayerRole("component", await fixture("proxy-minimal.wasm")).ok).toBe(true);
		expect(validateWasmLayerRole("component", await fixture("proxy-composed.wasm")).ok).toBe(true);
		expect(validateWasmLayerRole("core-module", await fixture("core-raw-imports.wasm")).ok).toBe(true);
		expect(validateWasmLayerRole("core-module", await fixture("core-empty.wasm")).ok).toBe(true);
		// adapter 层在 wit-component 编码中是 core module 形态。
		expect(validateWasmLayerRole("adapter", await fixture("core-raw-imports.wasm")).ok).toBe(true);
	});

	test("role mismatches are rejected as role violations", async () => {
		expectCode(validateWasmLayerRole("component", await fixture("core-raw-imports.wasm")), "WASM_BINARY_ROLE_INVALID");
		expectCode(validateWasmLayerRole("core-module", await fixture("proxy-minimal.wasm")), "WASM_BINARY_ROLE_INVALID");
		expectCode(validateWasmLayerRole("adapter", await fixture("proxy-minimal.wasm")), "WASM_BINARY_ROLE_INVALID");
	});
});
