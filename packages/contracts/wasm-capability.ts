// 用户原始需求（2026-08-25，add-wasm-runtime 任务 1.3 契约先行）：wasm 组件可用的宿主能力只能来自 revision 1 精确矩阵（`wasi:http/proxy@0.2.8` 线 + 依赖包归属规范化 + `iweb:config`/`iweb:secrets` store）；未知接口、未列版本与 host ABI 不匹配必须以稳定错误码 fail-closed。
// 正交意图：revision 1 typed 矩阵与精确校验；WIT 标识规范化与接口分类；闭包解析的接口级校验（唯一类型一致内部 provider / host import 判定 / 声明集合一致性）。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md「Capability record revision 1 is a typed exact matrix」。
// 二进制闭包遍历（解码 Component Model 类型信息驱动）属后续任务；本文件消费 scanner 已解码的 typed 图。
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "./validation.ts";
import { iwebStoreWitDirectionErrorCode, type IwebStoreWitDirectionErrorCode } from "./wasm-host-store.ts";
import { WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL, type WasmImportCapability } from "./wasm-package.ts";

export type WasmCapabilityDirection = "import" | "export";

// 与 wasm-package.ts 的 WasmImportCapability 同一 typed 形状；direction:"export" 仅用于根导出表示，
// 不是宿主能力（spec：「A root export is represented separately by the same typed shape」）。
export interface WasmCapabilityId {
	readonly package: string;
	readonly interface: string;
	readonly direction: WasmCapabilityDirection;
}

// 与 wasm-package.ts 的模块私有 WIT_PACKAGE_PATTERN/WIT_INTERFACE_PATTERN 同文（该文件属任务 1.1 批次，
// 本文件不改它）；tests/wasm-capability.test.ts 以一致性向量锁定两份 grammar 行为等价。
const WIT_PACKAGE_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*:[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*@(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const WIT_INTERFACE_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*$/;

// ---------------------------------------------------------------------------
// 接口标识规范化
// ---------------------------------------------------------------------------

export interface NormalizedWitPackageIdentity {
	readonly namespace: string;
	readonly name: string;
	readonly major: number;
	readonly minor: number;
	readonly patch: number;
}

// package identity 拆解为 namespace/name/@semver；畸形输入（含 bare package、range、free-form 后缀）
// 返回 null，绝不按名字猜测归属（fail-closed）。
export function normalizeWitPackageIdentity(text: string): NormalizedWitPackageIdentity | null {
	if (typeof text !== "string" || !WIT_PACKAGE_ID_PATTERN.test(text)) return null;
	const at = text.lastIndexOf("@");
	const colon = text.indexOf(":");
	const version = text.slice(at + 1).split(".");
	const major = Number(version[0]);
	const minor = Number(version[1]);
	const patch = Number(version[2]);
	if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) return null;
	return { namespace: text.slice(0, colon), name: text.slice(colon + 1, at), major, minor, patch };
}

export function wasmInterfaceKey(id: { readonly package: string; readonly interface: string }): string {
	return id.package + "/" + id.interface;
}

export function wasmCapabilityKey(id: WasmCapabilityId): string {
	return id.direction + ":" + id.package + "/" + id.interface;
}

// 规范排序键 (package, interface, direction) 的 UTF-8 字节序；grammar 保证 ASCII，
// code-unit 序即 bytewise 序。digest 排序（32 原始字节升序）不在此处。
export function compareWasmCapabilityIds(left: WasmCapabilityId, right: WasmCapabilityId): number {
	if (left.package !== right.package) return left.package < right.package ? -1 : 1;
	if (left.interface !== right.interface) return left.interface < right.interface ? -1 : 1;
	if (left.direction !== right.direction) return left.direction < right.direction ? -1 : 1;
	return 0;
}

export function sortWasmCapabilityIds<T extends WasmCapabilityId>(ids: readonly T[]): T[] {
	return [...ids].sort(compareWasmCapabilityIds);
}

// ---------------------------------------------------------------------------
// 稳定拒绝码表（spec 逐字；owner 可见，public traffic 只见 generic availability）
// ---------------------------------------------------------------------------

export type WasmCapabilityErrorCode =
	| "WASM_WORLD_UNSUPPORTED"
	| "WASM_EXPORT_MISMATCH"
	| "WASM_INTERFACE_UNKNOWN"
	| "WASM_INTERFACE_VERSION_UNLISTED"
	| "WASM_HOST_ABI_MISMATCH"
	| "WASM_IMPORT_UNMAPPABLE"
	| "WASM_IMPORT_UNRESOLVED"
	| "WASM_IMPORT_AMBIGUOUS"
	| "WASM_INTERNAL_TYPE_MISMATCH"
	| "WASM_ADAPTER_EXTERNAL_IMPORT"
	| "WASM_CLOSURE_CYCLE"
	| "WASM_CLOSURE_BUDGET_EXCEEDED"
	| "WASM_DECLARATION_MISMATCH";

export interface WasmCapabilityErrorTableEntry {
	readonly code: WasmCapabilityErrorCode;
	readonly rejection: string;
}

export const WASM_CAPABILITY_ERROR_TABLE: readonly WasmCapabilityErrorTableEntry[] = [
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
];

export const WASM_CAPABILITY_ERROR_CODES: readonly WasmCapabilityErrorCode[] = WASM_CAPABILITY_ERROR_TABLE.map((entry) => entry.code);

// ---------------------------------------------------------------------------
// Revision 1 精确矩阵（NodeCapabilityRecordV1.matrix 的内容权威）
// ---------------------------------------------------------------------------

export interface WasmRequiredRootExportV1 {
	readonly package: "wasi:http@0.2.8";
	readonly interface: "incoming-handler";
	readonly direction: "export";
}

export interface WasmCapabilityMatrixV1 {
	readonly world: typeof WASM_WORLD_LITERAL;
	readonly hostABI: typeof WASM_HOST_ABI_LITERAL;
	readonly requiredRootExport: WasmRequiredRootExportV1;
	readonly hostImports: readonly WasmImportCapability[];
}

// spec 矩阵原文按 package 分组展示；持久化 record 要求 hostImports 是
// (package, interface, direction) UTF-8 字节序的精确有序列表，二者集合相同。
const REVISION_1_HOST_IMPORTS_SPEC_ORDER: readonly WasmImportCapability[] = [
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

export const WASM_CAPABILITY_MATRIX_REVISION_1: WasmCapabilityMatrixV1 = {
	world: WASM_WORLD_LITERAL,
	hostABI: WASM_HOST_ABI_LITERAL,
	requiredRootExport: { package: "wasi:http@0.2.8", interface: "incoming-handler", direction: "export" },
	hostImports: sortWasmCapabilityIds(REVISION_1_HOST_IMPORTS_SPEC_ORDER),
};

// ---------------------------------------------------------------------------
// 单个 typed 能力对象与矩阵 record 的 unknown-field-rejecting 校验
// ---------------------------------------------------------------------------

// 单个 {package, interface, direction} typed 形状；direction 允许 "import"（host 能力）与
// "export"（根导出表示）。declaredHostImports 列表级排序/去重校验属 wasm-package.validateDeclaredHostImports。
export function validateWasmCapabilityId(input: unknown, path = ""): ValidationResult<WasmCapabilityId> {
	if (!isRecord(input)) return failure([issue("INVALID_WIT_CAPABILITY", path, "capability must be an object")]);
	const errors: ValidationIssue[] = [];
	for (const field of Object.keys(input)) {
		if (field !== "package" && field !== "interface" && field !== "direction") {
			errors.push(issue("UNKNOWN_FIELD", path + "/" + field, "capability has exactly package, interface, direction"));
		}
	}
	if (typeof input.package !== "string" || !WIT_PACKAGE_ID_PATTERN.test(input.package)) {
		errors.push(issue("INVALID_WIT_PACKAGE", path + "/package", "package must be a lower-case WIT namespace:name@major.minor.patch identity"));
	}
	if (typeof input.interface !== "string" || !WIT_INTERFACE_NAME_PATTERN.test(input.interface)) {
		errors.push(issue("INVALID_WIT_INTERFACE", path + "/interface", "interface must be a lower-case WIT interface identifier"));
	}
	if (input.direction !== "import" && input.direction !== "export") {
		errors.push(issue("INVALID_DIRECTION", path + "/direction", "direction must be the literal import or export"));
	}
	if (errors.length) return failure(errors);
	return ok({ package: input.package as string, interface: input.interface as string, direction: input.direction as WasmCapabilityDirection });
}

const MATRIX_ISSUE_CODE = "WASM_CAPABILITY_MATRIX_INVALID";

// NodeCapabilityRecordV1.matrix 精确校验：字面量 world/hostABI、精确根导出对象、hostImports
// 逐项属于 revision 1 集合、严格排序、无重复、无缺失。通过即返回 canonical revision 1 矩阵。
export function validateWasmCapabilityMatrix(input: unknown): ValidationResult<WasmCapabilityMatrixV1> {
	if (!isRecord(input)) return failure([issue(MATRIX_ISSUE_CODE, "", "capability matrix must be an object")]);
	const errors: ValidationIssue[] = [];
	for (const field of Object.keys(input)) {
		if (field !== "world" && field !== "hostABI" && field !== "requiredRootExport" && field !== "hostImports") {
			errors.push(issue(MATRIX_ISSUE_CODE, "/" + field, "matrix has exactly world, hostABI, requiredRootExport, hostImports"));
		}
	}
	if (input.world !== WASM_CAPABILITY_MATRIX_REVISION_1.world) {
		errors.push(issue(MATRIX_ISSUE_CODE, "/world", "world must be exactly " + WASM_CAPABILITY_MATRIX_REVISION_1.world));
	}
	if (input.hostABI !== WASM_CAPABILITY_MATRIX_REVISION_1.hostABI) {
		errors.push(issue(MATRIX_ISSUE_CODE, "/hostABI", "hostABI must be exactly " + WASM_CAPABILITY_MATRIX_REVISION_1.hostABI));
	}
	const rootExport = validateWasmCapabilityId(input.requiredRootExport, "/requiredRootExport");
	if (!rootExport.ok) errors.push(...rootExport.errors);
	else {
		const expected = WASM_CAPABILITY_MATRIX_REVISION_1.requiredRootExport;
		if (rootExport.value.package !== expected.package || rootExport.value.interface !== expected.interface || rootExport.value.direction !== expected.direction) {
			errors.push(issue(MATRIX_ISSUE_CODE, "/requiredRootExport", "requiredRootExport must be exactly wasi:http@0.2.8/incoming-handler export"));
		}
	}
	if (!Array.isArray(input.hostImports)) {
		errors.push(issue(MATRIX_ISSUE_CODE, "/hostImports", "hostImports must be an array"));
	} else {
		const expected = WASM_CAPABILITY_MATRIX_REVISION_1.hostImports;
		const seen = new Set<string>();
		let sorted = true;
		let previous: WasmCapabilityId | null = null;
		for (let i = 0; i < input.hostImports.length; i++) {
			const entry = validateWasmCapabilityId(input.hostImports[i], "/hostImports/" + i);
			if (!entry.ok) {
				errors.push(...entry.errors);
				continue;
			}
			if (entry.value.direction !== "import") {
				errors.push(issue(MATRIX_ISSUE_CODE, "/hostImports/" + i, "host import direction must be the literal import"));
			}
			const key = wasmCapabilityKey(entry.value);
			if (seen.has(key)) errors.push(issue(MATRIX_ISSUE_CODE, "/hostImports/" + i, "duplicate host import is rejected"));
			seen.add(key);
			if (previous !== null && compareWasmCapabilityIds(previous, entry.value) > 0) sorted = false;
			previous = entry.value;
			if (!isAllowedWasmHostImport(entry.value)) {
				errors.push(issue(MATRIX_ISSUE_CODE, "/hostImports/" + i, "host import is not part of the revision-1 matrix"));
			}
		}
		if (!sorted) errors.push(issue(MATRIX_ISSUE_CODE, "/hostImports", "hostImports must be sorted by (package, interface, direction) in UTF-8 byte order"));
		if (input.hostImports.length !== expected.length) {
			errors.push(issue(MATRIX_ISSUE_CODE, "/hostImports", "revision-1 matrix has exactly " + expected.length + " host imports"));
		}
		for (const allowed of expected) {
			if (!seen.has(wasmCapabilityKey(allowed))) {
				errors.push(issue(MATRIX_ISSUE_CODE, "/hostImports", "revision-1 host import " + wasmCapabilityKey(allowed) + " is missing"));
			}
		}
	}
	if (errors.length) return failure(errors);
	return ok(WASM_CAPABILITY_MATRIX_REVISION_1);
}

// ---------------------------------------------------------------------------
// 接口级分类：依赖包归属规范化映射
// ---------------------------------------------------------------------------

export interface WasmHostImportCandidate {
	readonly package: string;
	readonly interface: string;
}

export type WasmHostImportRejectionCode = "WASM_INTERFACE_UNKNOWN" | "WASM_INTERFACE_VERSION_UNLISTED" | "WASM_IMPORT_UNRESOLVED";

export type WasmHostImportClassification =
	| { readonly kind: "allowed-host-import" }
	| { readonly kind: "rejected"; readonly code: WasmHostImportRejectionCode };

// wasi-http v0.2.8 官方 WIT 树的 package→interface 归属：wasi:http 拥有 types/outgoing-handler，
// 依赖包拥有 clock/random/io/cli 接口；跨包引用（如 wasi:io/types）不属于 normalized mapping。
export function classifyWasmHostImport(candidate: WasmHostImportCandidate, matrix: WasmCapabilityMatrixV1 = WASM_CAPABILITY_MATRIX_REVISION_1): WasmHostImportClassification {
	// 畸形标识（含 bare package、未知 namespace、free-form 后缀）fail-closed 为 unknown。
	const identity = normalizeWitPackageIdentity(candidate.package);
	if (identity === null || !WIT_INTERFACE_NAME_PATTERN.test(candidate.interface)) {
		return { kind: "rejected", code: "WASM_INTERFACE_UNKNOWN" };
	}
	// 根导出身份（incoming-handler）是 export-only 能力：导入它既无内部 provider 也无宿主能力。
	if (candidate.package === matrix.requiredRootExport.package && candidate.interface === matrix.requiredRootExport.interface) {
		return { kind: "rejected", code: "WASM_IMPORT_UNRESOLVED" };
	}
	const known = matrix.hostImports.find((allowed) => {
		const owner = normalizeWitPackageIdentity(allowed.package);
		return owner !== null && owner.namespace === identity.namespace && owner.name === identity.name && allowed.interface === candidate.interface;
	});
	if (known === undefined) return { kind: "rejected", code: "WASM_INTERFACE_UNKNOWN" };
	// 版本是 package identity 的一部分：已知接口的任何未记录版本（0.2.7、0.3.0 同罪）拒绝。
	if (known.package !== candidate.package) return { kind: "rejected", code: "WASM_INTERFACE_VERSION_UNLISTED" };
	return { kind: "allowed-host-import" };
}

export function isAllowedWasmHostImport(candidate: WasmHostImportCandidate, matrix: WasmCapabilityMatrixV1 = WASM_CAPABILITY_MATRIX_REVISION_1): boolean {
	return classifyWasmHostImport(candidate, matrix).kind === "allowed-host-import";
}

// ---------------------------------------------------------------------------
// 闭包解析的接口级校验（消费 scanner 解码后的 typed 图）
// ---------------------------------------------------------------------------

export interface WasmClosureInterfaceOccurrence {
	readonly package: string;
	readonly interface: string;
	readonly direction: WasmCapabilityDirection;
	/** 解码后的 Component Model 类型身份（结构摘要等不透明标记）；同接口不同 typeTag 即类型不一致。 */
	readonly typeTag: string;
	/** re-export 别名：指向原始 provider 节点 id；re-export 不产生新 provider。 */
	readonly providerAlias?: string;
}

export type WasmClosureNodeKind = "component" | "core-module" | "adapter";

export interface WasmClosureNode {
	readonly id: string;
	readonly kind: WasmClosureNodeKind;
	readonly interfaces: readonly WasmClosureInterfaceOccurrence[];
	/** core-module/adapter 的未类型化原始 import 名（来自解码信息，绝非 import-name 字符串切分）。 */
	readonly rawImports?: readonly string[];
	/** raw import 中绑定到所属 component typed 实例导入成员的部分（wit-component 主模块 canonical ABI 接线；
	 * 函数面 = 实例成员名，资源面 = "[resource-drop]" 前缀去掉后的实例资源成员）。⊆ rawImports。 */
	readonly instanceBoundImports?: readonly string[];
	/** adapter 声明它能翻译为 typed Component Model 接口的原始 import 名。 */
	readonly adapterTranslations?: readonly string[];
}

export interface WasmClosureEdge {
	readonly from: string;
	readonly to: string;
}

export interface WasmClosureBudget {
	readonly maxNodes: number;
	readonly maxEdges: number;
	readonly maxDepth: number;
}

export interface WasmClosureGraph {
	readonly world: string;
	readonly hostABI: string;
	readonly entryNodeId: string;
	readonly nodes: readonly WasmClosureNode[];
	readonly edges: readonly WasmClosureEdge[];
	/** config 与 normalized manifest 声明的 declared set（先经 wasm-package.validateDeclaredHostImports 校验形状）。 */
	readonly declaredHostImports: readonly WasmImportCapability[];
	readonly budget: WasmClosureBudget;
}

// WASM_CLOSURE_GRAPH_INVALID 非 spec 工件分类码：仅用于调用方图输入自完整性（重复/悬空 id、空 typeTag），
// 不呈现给 owner 作为工件拒绝原因。
export type WasmClosureRejectionCode = WasmCapabilityErrorCode | IwebStoreWitDirectionErrorCode | "WASM_CLOSURE_GRAPH_INVALID";

export type WasmClosureValidation =
	| { readonly ok: true; readonly discoveredHostImports: readonly WasmImportCapability[] }
	| { readonly ok: false; readonly code: WasmClosureRejectionCode };

// 确定性判定顺序（spec scanner 步骤 1-5 的接口级投影）：
// world → hostABI → 图自完整性 → node/edge/depth 预算与环 → raw import 翻译闭包 →
// 逐节点（节点序、出现序）grammar / iweb 方向 / import 解析 → 根导出 → 声明集合一致性。
export function validateWasmCapabilityClosure(graph: WasmClosureGraph, matrix: WasmCapabilityMatrixV1 = WASM_CAPABILITY_MATRIX_REVISION_1): WasmClosureValidation {
	const reject = (code: WasmClosureRejectionCode): WasmClosureValidation => ({ ok: false, code });

	// 1. 非精确矩阵 world 与 ABI 不匹配立即 fail-closed。
	if (graph.world !== matrix.world) return reject("WASM_WORLD_UNSUPPORTED");
	if (graph.hostABI !== matrix.hostABI) return reject("WASM_HOST_ABI_MISMATCH");

	// 2. 调用方图自完整性。
	const nodesById = new Map<string, WasmClosureNode>();
	for (const node of graph.nodes) {
		if (node.id === "" || nodesById.has(node.id)) return reject("WASM_CLOSURE_GRAPH_INVALID");
		nodesById.set(node.id, node);
	}
	const entry = nodesById.get(graph.entryNodeId);
	if (entry === undefined) return reject("WASM_CLOSURE_GRAPH_INVALID");
	for (const edge of graph.edges) {
		if (!nodesById.has(edge.from) || !nodesById.has(edge.to)) return reject("WASM_CLOSURE_GRAPH_INVALID");
	}

	// 3. 预算与环：计数先判，DFS 同时检测环与最大深度（深度以路径节点数计）。
	if (graph.nodes.length > graph.budget.maxNodes || graph.edges.length > graph.budget.maxEdges) {
		return reject("WASM_CLOSURE_BUDGET_EXCEEDED");
	}
	const adjacency = new Map<string, string[]>();
	for (const node of graph.nodes) adjacency.set(node.id, []);
	for (const edge of graph.edges) {
		const targets = adjacency.get(edge.from);
		if (targets !== undefined) targets.push(edge.to);
	}
	const visitState = new Map<string, "visiting" | "done">();
	let maxDepth = 0;
	const hasNoCycle = (nodeId: string, depth: number): boolean => {
		const state = visitState.get(nodeId);
		if (state === "visiting") return false;
		if (state === "done") return true;
		visitState.set(nodeId, "visiting");
		if (depth > maxDepth) maxDepth = depth;
		for (const next of adjacency.get(nodeId) ?? []) {
			if (!hasNoCycle(next, depth + 1)) return false;
		}
		visitState.set(nodeId, "done");
		return true;
	};
	if (!hasNoCycle(entry.id, 1)) return reject("WASM_CLOSURE_CYCLE");
	if (maxDepth > graph.budget.maxDepth) return reject("WASM_CLOSURE_BUDGET_EXCEEDED");

	// 4. 翻译闭包：未类型化 raw import 只能经显式 adapter 翻译或所属 component 的 typed 实例导入
	// 绑定（instanceBoundImports，解码层验证的成员存在性）消化，永不按名字成为 host capability。
	const translatedRawImports = new Set<string>();
	for (const node of graph.nodes) {
		for (const raw of node.adapterTranslations ?? []) translatedRawImports.add(raw);
	}
	for (const node of graph.nodes) {
		if (node.kind === "core-module") {
			const instanceBound = new Set(node.instanceBoundImports ?? []);
			for (const raw of node.rawImports ?? []) {
				if (!translatedRawImports.has(raw) && !instanceBound.has(raw)) return reject("WASM_IMPORT_UNMAPPABLE");
			}
		} else if (node.kind === "adapter") {
			for (const raw of node.rawImports ?? []) {
				if (!translatedRawImports.has(raw)) return reject("WASM_ADAPTER_EXTERNAL_IMPORT");
			}
		}
	}

	// 5. 逐节点接口出现：grammar → iweb 方向法 → import 解析（唯一一致 provider 内部消化，否则提案 host import）。
	const discovered = new Map<string, WasmImportCapability>();
	for (const node of graph.nodes) {
		for (const occurrence of node.interfaces) {
			if (normalizeWitPackageIdentity(occurrence.package) === null || !WIT_INTERFACE_NAME_PATTERN.test(occurrence.interface) || occurrence.typeTag === "") {
				return reject("WASM_IMPORT_UNMAPPABLE");
			}
			const directionError = iwebStoreWitDirectionErrorCode(occurrence);
			if (directionError !== null) return reject(directionError);
			if (occurrence.direction !== "import") continue;
			const providers = new Map<string, string>();
			for (const provider of graph.nodes) {
				if (provider.id === node.id) continue;
				for (const exported of provider.interfaces) {
					if (exported.direction !== "export") continue;
					if (exported.package !== occurrence.package || exported.interface !== occurrence.interface) continue;
					if (exported.typeTag === "") return reject("WASM_CLOSURE_GRAPH_INVALID");
					const providerId = exported.providerAlias ?? provider.id;
					if (providerId === node.id) continue;
					if (!nodesById.has(providerId)) return reject("WASM_CLOSURE_GRAPH_INVALID");
					if (!providers.has(providerId)) providers.set(providerId, exported.typeTag);
				}
			}
			if (providers.size > 0) {
				// fail-closed 顺序：先类型不一致，再多 provider 歧义；唯一类型一致即内部消化，不产生 host capability。
				for (const typeTag of providers.values()) {
					if (typeTag !== occurrence.typeTag) return reject("WASM_INTERNAL_TYPE_MISMATCH");
				}
				if (providers.size > 1) return reject("WASM_IMPORT_AMBIGUOUS");
				continue;
			}
			const classification = classifyWasmHostImport(occurrence, matrix);
			if (classification.kind === "rejected") return reject(classification.code);
			const capability: WasmImportCapability = { package: occurrence.package, interface: occurrence.interface, direction: "import" };
			discovered.set(wasmCapabilityKey(capability), capability);
		}
	}

	// 6. 根导出最后解析：入口外部可见 export 集合必须恰好等于矩阵根导出对象。
	const exportKeys = new Set<string>();
	for (const occurrence of entry.interfaces) {
		if (occurrence.direction === "export") exportKeys.add(wasmInterfaceKey(occurrence));
	}
	if (exportKeys.size !== 1 || !exportKeys.has(wasmInterfaceKey(matrix.requiredRootExport))) {
		return reject("WASM_EXPORT_MISMATCH");
	}

	// 7. 声明集合一致性：发现集合（排序去重）必须逐项等于 declared set。
	const declared = new Map<string, WasmImportCapability>();
	for (const declaredImport of graph.declaredHostImports) {
		const key = wasmCapabilityKey(declaredImport);
		const shapeValid = declaredImport.direction === "import"
			&& normalizeWitPackageIdentity(declaredImport.package) !== null
			&& WIT_INTERFACE_NAME_PATTERN.test(declaredImport.interface)
			&& classifyWasmHostImport(declaredImport, matrix).kind === "allowed-host-import";
		if (declared.has(key) || !shapeValid) return reject("WASM_DECLARATION_MISMATCH");
		declared.set(key, declaredImport);
	}
	if (declared.size !== discovered.size) return reject("WASM_DECLARATION_MISMATCH");
	for (const key of discovered.keys()) {
		if (!declared.has(key)) return reject("WASM_DECLARATION_MISMATCH");
	}

	return { ok: true, discoveredHostImports: sortWasmCapabilityIds([...discovered.values()]) };
}
