// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.3 契约先行）：revision 1 能力矩阵必须精确等于 spec 的
// package@version 集合；未列版本、未知接口/跨包归属、host ABI 不匹配、闭包解析歧义与声明集合不一致均以稳定错误码拒绝。
// 正交意图：矩阵内容/排序/校验；标识规范化与分类正负例；闭包解析接口级全场景与错误码可达性。
import { describe, expect, test } from "bun:test";
import {
	WASM_CAPABILITY_ERROR_TABLE,
	WASM_CAPABILITY_MATRIX_REVISION_1,
	classifyWasmHostImport,
	compareWasmCapabilityIds,
	isAllowedWasmHostImport,
	normalizeWitPackageIdentity,
	sortWasmCapabilityIds,
	validateWasmCapabilityClosure,
	validateWasmCapabilityId,
	validateWasmCapabilityMatrix,
	type WasmCapabilityId,
	type WasmClosureGraph,
	type WasmClosureInterfaceOccurrence,
	type WasmClosureNode,
	type WasmClosureNodeKind,
} from "../packages/contracts/wasm-capability.ts";
import { validateDeclaredHostImports, WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL } from "../packages/contracts/wasm-package.ts";
import type { ValidationIssue } from "../packages/contracts/validation.ts";

// spec 矩阵原文（package 分组展示顺序）的 13 个精确 host import。
const SPEC_ORDER_HOST_IMPORTS: readonly WasmCapabilityId[] = [
	{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
	{ package: "wasi:http@0.2.8", interface: "outgoing-handler", direction: "import" },
	{ package: "wasi:clocks@0.2.8", interface: "monotonic-clock", direction: "import" },
	{ package: "wasi:clocks@0.2.8", interface: "wall-clock", direction: "import" },
	{ package: "wasi:random@0.2.8", interface: "random", direction: "import" },
	{ package: "wasi:io@0.2.8", interface: "streams", direction: "import" },
	{ package: "wasi:io@0.2.8", interface: "error", direction: "import" },
	{ package: "wasi:io@0.2.8", interface: "poll", direction: "import" },
	{ package: "wasi:cli@0.2.8", interface: "stdin", direction: "import" },
	{ package: "wasi:cli@0.2.8", interface: "stdout", direction: "import" },
	{ package: "wasi:cli@0.2.8", interface: "stderr", direction: "import" },
	{ package: "iweb:config@1.0.0", interface: "store", direction: "import" },
	{ package: "iweb:secrets@1.0.0", interface: "store", direction: "import" },
];

describe("revision 1 capability matrix", () => {
	test("content equals the exact spec set and the record form is canonically sorted", () => {
		expect(WASM_CAPABILITY_MATRIX_REVISION_1.world).toBe("wasi:http/proxy@0.2.8");
		expect(WASM_CAPABILITY_MATRIX_REVISION_1.hostABI).toBe("iweb-wasmd-abi@1.0.0");
		expect(WASM_CAPABILITY_MATRIX_REVISION_1.requiredRootExport).toEqual({ package: "wasi:http@0.2.8", interface: "incoming-handler", direction: "export" });
		const sorted = sortWasmCapabilityIds(SPEC_ORDER_HOST_IMPORTS);
		expect(WASM_CAPABILITY_MATRIX_REVISION_1.hostImports).toEqual(sorted);
		for (let i = 1; i < sorted.length; i++) {
			expect(compareWasmCapabilityIds(sorted[i - 1], sorted[i])).toBeLessThan(0);
		}
	});

	test("matrix host imports satisfy the config/manifest declared-import grammar", () => {
		const errors: ValidationIssue[] = [];
		const validated = validateDeclaredHostImports(WASM_CAPABILITY_MATRIX_REVISION_1.hostImports, "", "TEST", errors);
		expect(validated).not.toBeNull();
		expect(errors).toHaveLength(0);
	});

	test("error code table matches the spec rejection table verbatim", () => {
		expect(WASM_CAPABILITY_ERROR_TABLE).toEqual([
			{ code: "WASM_WORLD_UNSUPPORTED", rejection: "world is not the exact matrix world" },
			{ code: "WASM_EXPORT_MISMATCH", rejection: "root export package/interface/direction differs" },
			{ code: "WASM_INTERFACE_UNKNOWN", rejection: "package/interface is not in the normalized WIT mapping" },
			{ code: "WASM_INTERFACE_VERSION_UNLISTED", rejection: "known interface has a non-recorded patch" },
			{ code: "WASM_HOST_ABI_MISMATCH", rejection: "host ABI is not the matrix ABI" },
			{ code: "WASM_IMPORT_UNMAPPABLE", rejection: "raw core/adapter import has no typed Component Model mapping" },
			{ code: "WASM_IMPORT_UNRESOLVED", rejection: "no unique internal provider and no exact host capability" },
			{ code: "WASM_IMPORT_AMBIGUOUS", rejection: "more than one type-identical provider is reachable" },
			{ code: "WASM_INTERNAL_TYPE_MISMATCH", rejection: "provider exists but its full type identity/direction differs" },
			{ code: "WASM_ADAPTER_EXTERNAL_IMPORT", rejection: "adapter leaks an import outside the decoded closure" },
			{ code: "WASM_CLOSURE_CYCLE", rejection: "component/module/adapter graph contains a cycle" },
			{ code: "WASM_CLOSURE_BUDGET_EXCEEDED", rejection: "node, edge, or depth budget is exceeded" },
			{ code: "WASM_DECLARATION_MISMATCH", rejection: "discovered set differs from config or normalized manifest" },
		]);
	});
});

describe("validateWasmCapabilityMatrix", () => {
	function matrixRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
		return {
			world: WASM_WORLD_LITERAL,
			hostABI: WASM_HOST_ABI_LITERAL,
			requiredRootExport: { package: "wasi:http@0.2.8", interface: "incoming-handler", direction: "export" },
			hostImports: WASM_CAPABILITY_MATRIX_REVISION_1.hostImports,
			...overrides,
		};
	}

	test("accepts the canonical revision-1 record", () => {
		const result = validateWasmCapabilityMatrix(matrixRecord());
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.value).toBe(WASM_CAPABILITY_MATRIX_REVISION_1);
	});

	test("rejects an unlisted package version inside the matrix record", () => {
		const unlisted = WASM_CAPABILITY_MATRIX_REVISION_1.hostImports.map((entry) =>
			entry.interface === "types" ? { package: "wasi:http@0.2.7", interface: "types", direction: "import" } : entry,
		);
		const result = validateWasmCapabilityMatrix(matrixRecord({ hostImports: unlisted }));
		expect(result.ok).toBe(false);
	});

	test("rejects unsorted, duplicate, missing-entry, wrong-literal and unknown-field records", () => {
		const reversed = [...WASM_CAPABILITY_MATRIX_REVISION_1.hostImports].reverse();
		expect(validateWasmCapabilityMatrix(matrixRecord({ hostImports: reversed })).ok).toBe(false);
		const duplicated = [...WASM_CAPABILITY_MATRIX_REVISION_1.hostImports, WASM_CAPABILITY_MATRIX_REVISION_1.hostImports[0]].sort(compareWasmCapabilityIds);
		expect(validateWasmCapabilityMatrix(matrixRecord({ hostImports: duplicated })).ok).toBe(false);
		const missing = WASM_CAPABILITY_MATRIX_REVISION_1.hostImports.slice(1);
		expect(validateWasmCapabilityMatrix(matrixRecord({ hostImports: missing })).ok).toBe(false);
		expect(validateWasmCapabilityMatrix(matrixRecord({ world: "wasi:http/proxy@0.2.7" })).ok).toBe(false);
		expect(validateWasmCapabilityMatrix(matrixRecord({ hostABI: "iweb-wasmd-abi@0.9.0" })).ok).toBe(false);
		expect(validateWasmCapabilityMatrix(matrixRecord({ requiredRootExport: { package: "wasi:http@0.2.8", interface: "types", direction: "export" } })).ok).toBe(false);
		expect(validateWasmCapabilityMatrix(matrixRecord({ extra: true })).ok).toBe(false);
	});
});

describe("WIT identifier normalization and classification", () => {
	test("normalizes package identities and rejects malformed ones", () => {
		expect(normalizeWitPackageIdentity("wasi:http@0.2.8")).toEqual({ namespace: "wasi", name: "http", major: 0, minor: 2, patch: 8 });
		expect(normalizeWitPackageIdentity("iweb:secrets@1.0.0")).toEqual({ namespace: "iweb", name: "secrets", major: 1, minor: 0, patch: 0 });
		for (const malformed of ["wasi:http", "wasi:http@0.2", "WASI:http@0.2.8", "wasi:http@02.2.8", "wasi:http@0.2.x", "wasi:http@0.2.8-rc1", "was i:http@0.2.8", ""]) {
			expect(normalizeWitPackageIdentity(malformed)).toBeNull();
		}
	});

	test("accepts every matrix host import and the root export shape", () => {
		for (const entry of SPEC_ORDER_HOST_IMPORTS) expect(isAllowedWasmHostImport(entry)).toBe(true);
		const root = validateWasmCapabilityId({ package: "wasi:http@0.2.8", interface: "incoming-handler", direction: "export" });
		expect(root.ok).toBe(true);
	});

	test("rejects unknown interfaces, cross-package attribution, unlisted versions and the root export identity", () => {
		const expectations: readonly { readonly candidate: { package: string; interface: string }; readonly code: string }[] = [
			{ candidate: { package: "wasi:sockets@0.2.8", interface: "tcp" }, code: "WASM_INTERFACE_UNKNOWN" },
			{ candidate: { package: "wasi:tls@0.2.8", interface: "tls" }, code: "WASM_INTERFACE_UNKNOWN" },
			{ candidate: { package: "wasi:filesystem@0.2.8", interface: "preopens" }, code: "WASM_INTERFACE_UNKNOWN" },
			{ candidate: { package: "wasi:io@0.2.8", interface: "types" }, code: "WASM_INTERFACE_UNKNOWN" },
			{ candidate: { package: "wasi:http@0.2.8", interface: "" }, code: "WASM_INTERFACE_UNKNOWN" },
			{ candidate: { package: "iweb:other@1.0.0", interface: "store" }, code: "WASM_INTERFACE_UNKNOWN" },
			{ candidate: { package: "wasi:http@0.2.7", interface: "outgoing-handler" }, code: "WASM_INTERFACE_VERSION_UNLISTED" },
			{ candidate: { package: "wasi:http@0.3.0", interface: "types" }, code: "WASM_INTERFACE_VERSION_UNLISTED" },
			{ candidate: { package: "iweb:secrets@1.1.0", interface: "store" }, code: "WASM_INTERFACE_VERSION_UNLISTED" },
			{ candidate: { package: "wasi:http@0.2.8", interface: "incoming-handler" }, code: "WASM_IMPORT_UNRESOLVED" },
		];
		for (const { candidate, code } of expectations) {
			const classification = classifyWasmHostImport(candidate);
			expect(classification.kind).toBe("rejected");
			if (classification.kind === "rejected") expect(classification.code).toBe(code);
		}
	});

	test("rejects malformed typed capability objects", () => {
		expect(validateWasmCapabilityId({ package: "wasi:http@0.2.8", interface: "types", direction: "import", extra: 1 }).ok).toBe(false);
		expect(validateWasmCapabilityId({ package: "wasi:http", interface: "types", direction: "import" }).ok).toBe(false);
		expect(validateWasmCapabilityId({ package: "wasi:http@0.2.8", interface: "Types", direction: "import" }).ok).toBe(false);
		expect(validateWasmCapabilityId({ package: "wasi:http@0.2.8", interface: "types", direction: "both" }).ok).toBe(false);
		expect(validateWasmCapabilityId("nope").ok).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// 闭包解析：typed 图构造助手
// ---------------------------------------------------------------------------

function occ(packageName: string, interfaceName: string, direction: "import" | "export", typeTag = "type-a", providerAlias?: string): WasmClosureInterfaceOccurrence {
	return providerAlias === undefined
		? { package: packageName, interface: interfaceName, direction, typeTag }
		: { package: packageName, interface: interfaceName, direction, typeTag, providerAlias };
}

function node(id: string, kind: WasmClosureNodeKind, interfaces: readonly WasmClosureInterfaceOccurrence[], extra: Pick<WasmClosureNode, "rawImports" | "adapterTranslations" | "instanceBoundImports"> = {}): WasmClosureNode {
	return { id, kind, interfaces, ...extra };
}

const ROOT_EXPORT = occ("wasi:http@0.2.8", "incoming-handler", "export", "root-export");
const TYPES_IMPORT = occ("wasi:http@0.2.8", "types", "import", "types-tag");

function baseGraph(overrides: Partial<WasmClosureGraph> = {}): WasmClosureGraph {
	return {
		world: WASM_WORLD_LITERAL,
		hostABI: WASM_HOST_ABI_LITERAL,
		entryNodeId: "entry",
		nodes: [node("entry", "component", [ROOT_EXPORT])],
		edges: [],
		declaredHostImports: [],
		budget: { maxNodes: 8, maxEdges: 8, maxDepth: 8 },
		...overrides,
	};
}

interface ClosureCase {
	readonly name: string;
	readonly graph: WasmClosureGraph;
	readonly expectCode?: string;
	readonly expectDiscovered?: readonly string[];
}

const CLOSURE_CASES: readonly ClosureCase[] = [
	{
		name: "accepts an entry component with only the required root export",
		graph: baseGraph(),
		expectDiscovered: [],
	},
	{
		name: "resolves a declared matrix host import",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT])],
			declaredHostImports: [{ package: "wasi:http@0.2.8", interface: "types", direction: "import" }],
		}),
		expectDiscovered: ["wasi:http@0.2.8/types"],
	},
	{
		name: "resolves an import from one unique internal provider (in-package closure)",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT]), node("nested", "component", [occ("wasi:http@0.2.8", "types", "export", "types-tag")])],
			edges: [{ from: "entry", to: "nested" }],
		}),
		expectDiscovered: [],
	},
	{
		name: "folds a re-export alias onto its original provider",
		graph: baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT]),
				node("nested", "component", [occ("wasi:http@0.2.8", "types", "export", "types-tag")]),
				node("wrapper", "component", [occ("wasi:http@0.2.8", "types", "export", "types-tag", "nested")]),
			],
			edges: [{ from: "entry", to: "nested" }, { from: "entry", to: "wrapper" }],
		}),
		expectDiscovered: [],
	},
	{
		name: "rejects two type-identical internal providers",
		graph: baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT]),
				node("left", "component", [occ("wasi:http@0.2.8", "types", "export", "types-tag")]),
				node("right", "component", [occ("wasi:http@0.2.8", "types", "export", "types-tag")]),
			],
			edges: [{ from: "entry", to: "left" }, { from: "entry", to: "right" }],
		}),
		expectCode: "WASM_IMPORT_AMBIGUOUS",
	},
	{
		name: "rejects an internal provider with a different type identity",
		graph: baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT]),
				node("nested", "component", [occ("wasi:http@0.2.8", "types", "export", "different-tag")]),
			],
			edges: [{ from: "entry", to: "nested" }],
		}),
		expectCode: "WASM_INTERNAL_TYPE_MISMATCH",
	},
	{
		name: "rejects an interface outside the normalized mapping",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, occ("wasi:sockets@0.2.8", "tcp", "import")])],
			declaredHostImports: [{ package: "wasi:sockets@0.2.8", interface: "tcp", direction: "import" }],
		}),
		expectCode: "WASM_INTERFACE_UNKNOWN",
	},
	{
		name: "rejects a known interface at an unlisted version",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, occ("wasi:http@0.2.7", "outgoing-handler", "import")])],
			declaredHostImports: [{ package: "wasi:http@0.2.7", interface: "outgoing-handler", direction: "import" }],
		}),
		expectCode: "WASM_INTERFACE_VERSION_UNLISTED",
	},
	{
		name: "rejects a host ABI mismatch",
		graph: baseGraph({ hostABI: "iweb-wasmd-abi@0.9.0" }),
		expectCode: "WASM_HOST_ABI_MISMATCH",
	},
	{
		name: "rejects a non-matrix world",
		graph: baseGraph({ world: "wasi:http/proxy@0.2.7" }),
		expectCode: "WASM_WORLD_UNSUPPORTED",
	},
	{
		name: "rejects importing the root export identity",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, occ("wasi:http@0.2.8", "incoming-handler", "import")])],
			declaredHostImports: [{ package: "wasi:http@0.2.8", interface: "incoming-handler", direction: "import" }],
		}),
		expectCode: "WASM_IMPORT_UNRESOLVED",
	},
	{
		name: "rejects a discovered matrix import absent from the declared set",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT])],
			declaredHostImports: [],
		}),
		expectCode: "WASM_DECLARATION_MISMATCH",
	},
	{
		name: "rejects a declared import absent from the discovered set",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT])],
			declaredHostImports: [{ package: "iweb:secrets@1.0.0", interface: "store", direction: "import" }],
		}),
		expectCode: "WASM_DECLARATION_MISMATCH",
	},
	{
		name: "rejects a graph cycle",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT]), node("a", "component", []), node("b", "component", [])],
			edges: [{ from: "entry", to: "a" }, { from: "a", to: "b" }, { from: "b", to: "a" }],
		}),
		expectCode: "WASM_CLOSURE_CYCLE",
	},
	{
		name: "rejects a node budget breach",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT]), node("a", "component", []), node("b", "component", []), node("c", "component", []), node("d", "component", []), node("e", "component", []), node("f", "component", []), node("g", "component", []), node("h", "component", [])],
			edges: [],
			budget: { maxNodes: 8, maxEdges: 8, maxDepth: 8 },
		}),
		expectCode: "WASM_CLOSURE_BUDGET_EXCEEDED",
	},
	{
		name: "rejects a depth budget breach",
		graph: baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT]),
				node("n1", "component", []),
				node("n2", "component", []),
				node("n3", "component", []),
				node("n4", "component", []),
				node("n5", "component", []),
			],
			edges: [{ from: "entry", to: "n1" }, { from: "n1", to: "n2" }, { from: "n2", to: "n3" }, { from: "n3", to: "n4" }, { from: "n4", to: "n5" }],
			budget: { maxNodes: 8, maxEdges: 8, maxDepth: 4 },
		}),
		expectCode: "WASM_CLOSURE_BUDGET_EXCEEDED",
	},
	{
		name: "rejects an untranslated core-module raw import",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT]), node("core", "core-module", [], { rawImports: ["wasi_snapshot_preview1.fd_write"] })],
			edges: [{ from: "entry", to: "core" }],
		}),
		expectCode: "WASM_IMPORT_UNMAPPABLE",
	},
	{
		name: "accepts a core-module raw import translated by an adapter",
		graph: baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT]),
				node("core", "core-module", [], { rawImports: ["wasi_snapshot_preview1.fd_write"] }),
				node("adapter", "adapter", [], { adapterTranslations: ["wasi_snapshot_preview1.fd_write"] }),
			],
			edges: [{ from: "entry", to: "core" }, { from: "entry", to: "adapter" }],
		}),
		expectDiscovered: [],
	},
	{
		name: "accepts a core-module raw import bound to a typed instance-import member",
		graph: baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT]),
				node("core", "core-module", [], { rawImports: ["wasi:http/types@0.2.8.make"], instanceBoundImports: ["wasi:http/types@0.2.8.make"] }),
			],
			edges: [{ from: "entry", to: "core" }],
		}),
		expectDiscovered: [],
	},
	{
		name: "rejects a core-module raw import that is only partially instance-bound",
		graph: baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT]),
				node("core", "core-module", [], { rawImports: ["wasi:http/types@0.2.8.make", "wasi:http/types@0.2.8.steal"], instanceBoundImports: ["wasi:http/types@0.2.8.make"] }),
			],
			edges: [{ from: "entry", to: "core" }],
		}),
		expectCode: "WASM_IMPORT_UNMAPPABLE",
	},
	{
		name: "an adapter cannot excuse its raw import with instance bindings",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT]), node("adapter", "adapter", [], { rawImports: ["wasi_snapshot_preview1.random_get"], instanceBoundImports: ["wasi_snapshot_preview1.random_get"] })],
			edges: [{ from: "entry", to: "adapter" }],
		}),
		expectCode: "WASM_ADAPTER_EXTERNAL_IMPORT",
	},
	{
		name: "rejects an adapter import leaking outside the decoded closure",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT]), node("adapter", "adapter", [], { rawImports: ["wasi_snapshot_preview1.random_get"] })],
			edges: [{ from: "entry", to: "adapter" }],
		}),
		expectCode: "WASM_ADAPTER_EXTERNAL_IMPORT",
	},
	{
		name: "rejects export store for iweb:secrets",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, occ("iweb:secrets@1.0.0", "store", "export", "secret-store")])],
		}),
		expectCode: "IWEB_SECRET_WIT_DIRECTION_INVALID",
	},
	{
		name: "rejects export store for iweb:config",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, occ("iweb:config@1.0.0", "store", "export", "config-store")])],
		}),
		expectCode: "IWEB_CONFIG_WIT_DIRECTION_INVALID",
	},
	{
		name: "rejects a missing root export",
		graph: baseGraph({ nodes: [node("entry", "component", [])] }),
		expectCode: "WASM_EXPORT_MISMATCH",
	},
	{
		name: "rejects an extra root export beside the required one",
		graph: baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, occ("wasi:http@0.2.8", "types", "export", "types-tag")])],
		}),
		expectCode: "WASM_EXPORT_MISMATCH",
	},
];

describe("closure-resolved interface-level validation", () => {
	for (const closureCase of CLOSURE_CASES) {
		test(closureCase.name, () => {
			const result = validateWasmCapabilityClosure(closureCase.graph);
			if (closureCase.expectCode !== undefined) {
				expect(result.ok).toBe(false);
				if (!result.ok) expect(result.code).toBe(closureCase.expectCode);
				return;
			}
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.discoveredHostImports.map((entry) => entry.package + "/" + entry.interface)).toEqual(closureCase.expectDiscovered);
			}
		});
	}

	test("every spec rejection code is reachable through the closure validator", () => {
		const seen = new Set<string>();
		for (const closureCase of CLOSURE_CASES) {
			if (closureCase.expectCode === undefined) continue;
			const result = validateWasmCapabilityClosure(closureCase.graph);
			expect(result.ok).toBe(false);
			if (!result.ok) seen.add(result.code);
		}
		for (const entry of WASM_CAPABILITY_ERROR_TABLE) expect(seen.has(entry.code)).toBe(true);
	});

	test("deduplicates repeated host import occurrences across the graph", () => {
		const graph = baseGraph({
			nodes: [
				node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT]),
				node("nested", "component", [occ("wasi:http@0.2.8", "types", "import", "types-tag")]),
			],
			edges: [{ from: "entry", to: "nested" }],
			declaredHostImports: [{ package: "wasi:http@0.2.8", interface: "types", direction: "import" }],
		});
		const result = validateWasmCapabilityClosure(graph);
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.discoveredHostImports).toHaveLength(1);
	});

	test("rejects a malformed declared entry and a duplicate declaration", () => {
		const malformed = baseGraph({
			declaredHostImports: [{ package: "wasi:sockets@0.2.8", interface: "tcp", direction: "import" }],
		});
		expect(validateWasmCapabilityClosure(malformed).ok).toBe(false);
		const duplicate = baseGraph({
			nodes: [node("entry", "component", [ROOT_EXPORT, TYPES_IMPORT, occ("wasi:http@0.2.8", "types", "import", "types-tag")])],
			declaredHostImports: [
				{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
				{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
			],
		});
		const result = validateWasmCapabilityClosure(duplicate);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("WASM_DECLARATION_MISMATCH");
	});

	test("rejects caller graphs with dangling or duplicate node identities", () => {
		const danglingEdge = baseGraph({ edges: [{ from: "entry", to: "ghost" }] });
		const result = validateWasmCapabilityClosure(danglingEdge);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("WASM_CLOSURE_GRAPH_INVALID");
		const duplicateId = baseGraph({ nodes: [node("entry", "component", [ROOT_EXPORT]), node("entry", "component", [])] });
		const duplicateResult = validateWasmCapabilityClosure(duplicateId);
		expect(duplicateResult.ok).toBe(false);
		if (!duplicateResult.ok) expect(duplicateResult.code).toBe("WASM_CLOSURE_GRAPH_INVALID");
	});
});
