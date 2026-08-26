// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.3 剩余部分）：wasm 制品的二进制 imports 闭包
// scanner——按 Component Model type identity 解码 component/core module/adapter 二进制，产出 typed 闭包图，
// 交由 wasm-capability.ts 的 validateWasmCapabilityClosure 判定；畸形二进制 fail-closed（结构化错误码、
// 不崩溃），node/edge/depth 预算来自参数，全程无网络与文件系统访问。
// 正交意图：纯解码层（core module 段 + component 六段 + component-name 约定）；typed 图组装（接口出现/
// re-export 折叠/结构兼容 → typeTag）；入口级 fail-closed 判定（不可映射 import、根导出条目唯一性、预算）。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md「The scanner SHALL
// obtain WIT package/interface identities from decoded Component Model type information ...」五步。
//
// 编码依据（实证钉死）：Component Model Binary.md 与 wasmparser（bytecodealliance/wasm-tools）读取器；
// fixture 由 wasm-tools 1.258.0 / wit-component 0.258.0 生成（tests/fixtures/wasm/，生成脚本同目录）。
// 关键编码事实：component 段可重复且无固定顺序，索引空间按二进制出现序增长；嵌套 component 段（id 4）
// 恰含一个完整 component 二进制；外部类型引用中 core module 为双字节 0x00 0x11；wit-component 的命名
// 约定是 adapter/glue 识别的唯一信号——适配器核心模块名 `wit-component:adapter:<abi>`（translations =
// `<abi>.<导出函数名>`），胶水模块名 `wit-component-shim-*` / `wit-component-fixup`（raw import 不计费）。
// 真实语言工具链（2026-08-26，任务 8.x 实证）：rustc 1.98（wit-component 0.234.0）不写 component-name
// 段——胶水识别补结构形状（空/"shim" 模块名 + 纯数字/"$imports" 字段，见 isShimRewiringFacts）；主
// core module 的 canonical ABI raw import（`<iface>.[method|constructor|static|resource-drop]…`）直接
// 绑定到 component 自身的实例导入（函数面 = 实例成员名，资源面 = canon resource.drop 的实例资源成员），
// 绑定事实记入 node.instanceBoundImports，由 validateWasmCapabilityClosure 第 4 步豁免——宿主表面仍完全
// 由 typed 实例导入决定，raw 名永不构成新能力。
// 妥协声明：component 二进制不能跨 OCI 层引用（无 digest 字段），跨层连接是 wasmd 物化期语义；本 scanner
// 的闭包 = entry 层二进制的内嵌闭包，非 entry 层的角色由 validateWasmLayerRole 单独校验（准入职责）。
import {
	WASM_CAPABILITY_MATRIX_REVISION_1,
	validateWasmCapabilityClosure,
	type WasmCapabilityMatrixV1,
	type WasmClosureBudget,
	type WasmClosureGraph,
	type WasmClosureInterfaceOccurrence,
	type WasmClosureNode,
	type WasmClosureNodeKind,
	type WasmClosureRejectionCode,
	type WasmClosureValidation,
} from "./wasm-capability.ts";
import type { WasmImportCapability } from "./wasm-package.ts";

// ---------------------------------------------------------------------------
// 公共类型与稳定错误码
// ---------------------------------------------------------------------------

/** OCI wasm 层角色（media type 的角色面）。adapter 层在 wit-component 编码中是 core module 形态。 */
export type WasmLayerRole = "component" | "core-module" | "adapter";

/** 二进制解码层 fail-closed 错误码（非 spec 工件拒绝表成员；owner 可见，public traffic 只见 generic）。 */
export type WasmBinaryErrorCode =
	| "WASM_BINARY_INVALID_HEADER"
	| "WASM_BINARY_TRUNCATED"
	| "WASM_BINARY_SECTION_INVALID"
	| "WASM_BINARY_LEB_INVALID"
	| "WASM_BINARY_STRING_INVALID"
	| "WASM_BINARY_ROLE_INVALID";

/** scanner 结果错误码：二进制码 + 闭包判定码（spec 表 + 图自完整性码透传）。 */
export type WasmClosureScanErrorCode = WasmBinaryErrorCode | WasmClosureRejectionCode;

export interface WasmClosureScanInput {
	/** entry 层二进制（config entryLayerDigest 指向的 component 层 blob）。 */
	readonly entry: Uint8Array;
	/** config/manifest 声明（形状先经 wasm-package.validateDeclaredHostImports 校验），原样进入 typed 图。 */
	readonly world: string;
	readonly hostABI: string;
	readonly declaredHostImports: readonly WasmImportCapability[];
	readonly budget: WasmClosureBudget;
}

export type WasmClosureScanResult =
	| { readonly ok: true; readonly graph: WasmClosureGraph }
	| { readonly ok: false; readonly code: WasmClosureScanErrorCode; readonly detail: string };

export type WasmClosureScanValidation =
	| { readonly ok: true; readonly graph: WasmClosureGraph; readonly discoveredHostImports: readonly WasmImportCapability[] }
	| { readonly ok: false; readonly code: WasmClosureScanErrorCode; readonly detail: string };

export type WasmLayerRoleValidation = { readonly ok: true } | { readonly ok: false; readonly code: WasmClosureScanErrorCode; readonly detail: string };

/** spec NodeCapabilityRecordV1 admission.maxClosure* 的上界（角色校验的解码预算）。 */
export const WASM_CLOSURE_SCAN_ADMISSION_MAXIMA: WasmClosureBudget = { maxNodes: 4096, maxEdges: 16384, maxDepth: 64 };

// ---------------------------------------------------------------------------
// 解码基元：定界读取器 + 结构化中止（内部异常只作控制流，公共 API 全捕获，永不崩溃）
// ---------------------------------------------------------------------------

class WasmBinaryAbort {
	constructor(readonly code: WasmClosureScanErrorCode, readonly detail: string) {}
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

class ByteReader {
	private pos: number;
	constructor(private readonly bytes: Uint8Array, private readonly end: number, start = 0) {
		this.pos = start;
	}

	get offset(): number {
		return this.pos;
	}
	get remaining(): number {
		return this.end - this.pos;
	}
	private take(count: number): Uint8Array {
		if (count < 0 || this.pos + count > this.end) throw new WasmBinaryAbort("WASM_BINARY_TRUNCATED", `unexpected end at offset ${this.pos} needing ${count} bytes`);
		const slice = this.bytes.subarray(this.pos, this.pos + count);
		this.pos += count;
		return slice;
	}
	/** 取出 count 字节的切片（section-4 嵌套 component 与内嵌 core module 提取用）。 */
	takeBytes(count: number): Uint8Array {
		return this.take(count);
	}
	byte(): number {
		if (this.pos >= this.end) throw new WasmBinaryAbort("WASM_BINARY_TRUNCATED", `unexpected end at offset ${this.pos}`);
		return this.bytes[this.pos++];
	}
	peek(): number {
		if (this.pos >= this.end) throw new WasmBinaryAbort("WASM_BINARY_TRUNCATED", `unexpected end at offset ${this.pos}`);
		return this.bytes[this.pos];
	}
	u32(): number {
		let result = 0;
		let shift = 0;
		for (let i = 0; i < 5; i++) {
			const b = this.byte();
			result += (b & 0x7f) * 2 ** shift;
			if ((b & 0x80) === 0) {
				if (result > 0xffffffff) throw new WasmBinaryAbort("WASM_BINARY_LEB_INVALID", `u32 LEB overflows 32 bits at offset ${this.pos - 1}`);
				return result;
			}
			shift += 7;
		}
		throw new WasmBinaryAbort("WASM_BINARY_LEB_INVALID", `u32 LEB exceeds 5 bytes at offset ${this.pos - 5}`);
	}
	/** s33：非负 = 类型索引，负 = primitive/defined 类型 opcode。 */
	s33(): number {
		let result = 0;
		let shift = 0;
		for (let i = 0; i < 5; i++) {
			const b = this.byte();
			result += (b & 0x7f) * 2 ** shift;
			shift += 7;
			if ((b & 0x80) === 0) {
				const value = (b & 0x40) !== 0 ? result - 2 ** shift : result;
				if (value > 2 ** 32 - 1 || value < -(2 ** 32)) throw new WasmBinaryAbort("WASM_BINARY_LEB_INVALID", `s33 LEB out of range at offset ${this.pos - 1}`);
				return value;
			}
		}
		throw new WasmBinaryAbort("WASM_BINARY_LEB_INVALID", `s33 LEB exceeds 5 bytes at offset ${this.pos - 5}`);
	}
	/** core 风格名字：LEB 长度 + UTF-8 字节。 */
	name(what: string): string {
		const len = this.u32();
		return utf8Strict(this.take(len), what);
	}
	/** component 外部名 nameattributes：仅 0x00 明文形态（wit-component 实际产出）；0x01/0x02 fail-closed。 */
	externName(): string {
		const form = this.byte();
		if (form !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unsupported name attributes form 0x${form.toString(16)} at offset ${this.pos - 1}`);
		return this.name("component extern name");
	}
	consume(count: number): void {
		this.take(count);
	}
}

function utf8Strict(raw: Uint8Array, what: string): string {
	try {
		return utf8Decoder.decode(raw);
	} catch {
		throw new WasmBinaryAbort("WASM_BINARY_STRING_INVALID", `invalid UTF-8 in ${what}`);
	}
}

// ---------------------------------------------------------------------------
// 结构渲染：instance/component 形状的规范化 MemberShape（typeTag 与兼容判定的载体）
// ---------------------------------------------------------------------------

interface MemberShape {
	readonly canonical: string;
	/** instance/component 形状成员表；叶子成员无 shape。 */
	readonly shape?: ReadonlyMap<string, MemberShape>;
}

function member(canonical: string, shape?: ReadonlyMap<string, MemberShape>): MemberShape {
	return shape === undefined ? { canonical } : { canonical, shape };
}

function shapeCanonical(prefix: string, members: ReadonlyMap<string, MemberShape>): string {
	const parts: string[] = [];
	for (const name of [...members.keys()].sort()) parts.push(name + "=" + (members.get(name) as MemberShape).canonical);
	return prefix + "{" + parts.join(",") + "}";
}

/** 类型索引解析域：instance/component type 的局部域，父链到 component 域（outer alias 用）。 */
interface TypeDomain {
	resolveType(index: number): MemberShape | undefined;
}

function domainOf(renders: readonly MemberShape[]): TypeDomain {
	return {
		resolveType(index: number): MemberShape | undefined {
			return index >= 0 && index < renders.length ? renders[index] : undefined;
		},
	};
}

function resolveTypeMember(scope: TypeDomain, index: number): MemberShape {
	const resolved = scope.resolveType(index);
	if (resolved === undefined) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `type index ${index} unresolved`);
	return resolved;
}

// ---------------------------------------------------------------------------
// core module 解码（import/export 段；scanner 只取导入导出名）
// ---------------------------------------------------------------------------

interface CoreModuleFacts {
	/** "module.field" 形式的原始导入名。 */
	readonly rawImports: readonly string[];
	/** 结构化 (module, field) 对——实例绑定判定用；与 rawImports 一一对应。 */
	readonly rawImportPairs: readonly { readonly module: string; readonly field: string }[];
	/** 函数类导出名（adapter translations 的原始 ABI 面）。 */
	readonly exportedFuncs: readonly string[];
}

function decodeCoreModule(bytes: Uint8Array): CoreModuleFacts {
	if (bytes.length < 8) throw new WasmBinaryAbort("WASM_BINARY_INVALID_HEADER", "core module shorter than 8 bytes");
	if (!(bytes[0] === 0x00 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d)) throw new WasmBinaryAbort("WASM_BINARY_INVALID_HEADER", "core module magic mismatch");
	if (!(bytes[4] === 0x01 && bytes[5] === 0x00 && bytes[6] === 0x00 && bytes[7] === 0x00)) throw new WasmBinaryAbort("WASM_BINARY_INVALID_HEADER", "core module version mismatch");
	const reader = new ByteReader(bytes, bytes.length, 8);
	const rawImports: string[] = [];
	const rawImportPairs: { module: string; field: string }[] = [];
	const exportedFuncs: string[] = [];
	while (reader.remaining > 0) {
		const id = reader.byte();
		const size = reader.u32();
		if (id > 13) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown core section id ${id}`);
		if (reader.remaining < size) throw new WasmBinaryAbort("WASM_BINARY_TRUNCATED", `core section ${id} exceeds input`);
		if (id === 2) {
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const module = reader.name("core import module");
				const field = reader.name("core import field");
				const kind = reader.byte();
				if (kind === 0x00) reader.u32();
				else if (kind === 0x01) {
					reader.byte();
					skipLimits(reader);
				} else if (kind === 0x02) skipLimits(reader);
				else if (kind === 0x03) {
					reader.byte();
					reader.byte();
				} else if (kind === 0x04) {
					reader.byte();
					reader.u32();
				} else throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown core import kind ${kind}`);
				rawImports.push(module + "." + field);
				rawImportPairs.push({ module, field });
			}
		} else if (id === 7) {
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const name = reader.name("core export name");
				const kind = reader.byte();
				reader.u32();
				if (kind === 0x00) exportedFuncs.push(name);
				else if (kind > 4) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown core export kind ${kind}`);
			}
		} else {
			// 其余段（含 custom）按长度跳过；scanner 不依赖 core 侧内容。
			reader.consume(size);
		}
	}
	return { rawImports, rawImportPairs, exportedFuncs };
}

function skipLimits(reader: ByteReader): void {
	const flags = reader.byte();
	reader.u32();
	if (flags === 0x01) reader.u32();
	else if (flags !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown limits flags ${flags}`);
}

// ---------------------------------------------------------------------------
// 类型渲染：deftype / externtype ref / valtype（canonical 字符串 + shape 递归）
// ---------------------------------------------------------------------------

const SORT_FUNC = 0x01;
const SORT_VALUE = 0x02;
const SORT_TYPE = 0x03;
const SORT_COMPONENT = 0x04;
const SORT_INSTANCE = 0x05;

const PRIMITIVE_CANONICAL: ReadonlyMap<number, string> = new Map([
	[0x7f, "bool"], [0x7e, "s8"], [0x7d, "u8"], [0x7c, "s16"], [0x7b, "u16"], [0x7a, "s32"], [0x79, "u32"],
	[0x78, "s64"], [0x77, "u64"], [0x76, "f32"], [0x75, "f64"], [0x74, "char"], [0x73, "string"], [0x64, "error-context"],
]);

interface ComponentTypeRef {
	/** SORT_*；module 类型引用（0x00 0x11）规约为 -1。 */
	readonly sort: number;
	/** type/value/instance/component 引用的类型索引；module/资源 bound 为 -1。 */
	readonly index: number;
	/** SORT_TYPE 的 (sub resource) bound。 */
	readonly boundSub: boolean;
	/** SORT_VALUE 的内联 valtype canonical。 */
	readonly valtypeCanonical: string | null;
	/** SORT_INSTANCE / SORT_COMPONENT 引用解析出的形状（预解析，供出现收集直接消费）。 */
	readonly resolved: MemberShape | null;
}

function readComponentTypeRef(reader: ByteReader, scope: TypeDomain): ComponentTypeRef {
	const first = reader.byte();
	if (first === 0x00) {
		const second = reader.byte();
		if (second !== 0x11) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown core extern kind 0x${second.toString(16)}`);
		return { sort: -1, index: -1, boundSub: false, valtypeCanonical: null, resolved: null };
	}
	if (first < SORT_FUNC || first > SORT_INSTANCE) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown component extern type 0x${first.toString(16)}`);
	if (first === SORT_VALUE) return { sort: first, index: -1, boundSub: false, valtypeCanonical: renderValtype(reader, scope), resolved: null };
	if (first === SORT_TYPE) {
		const bound = reader.byte();
		if (bound === 0x01) return { sort: first, index: -1, boundSub: true, valtypeCanonical: null, resolved: null };
		if (bound === 0x00) {
			const index = reader.u32();
			return { sort: first, index, boundSub: false, valtypeCanonical: null, resolved: resolveTypeMember(scope, index) };
		}
		throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown type bound 0x${bound.toString(16)}`);
	}
	const index = reader.u32();
	return { sort: first, index, boundSub: false, valtypeCanonical: null, resolved: resolveTypeMember(scope, index) };
}

function typeRefCanonical(ref: ComponentTypeRef): string {
	if (ref.sort === -1) return "coremod";
	if (ref.sort === SORT_FUNC) return ref.resolved === null ? "fn?" : ref.resolved.canonical;
	if (ref.sort === SORT_VALUE) return "val:" + (ref.valtypeCanonical as string);
	if (ref.sort === SORT_TYPE) return ref.boundSub ? "res" : (ref.resolved === null ? "ty?" : ref.resolved.canonical);
	return ref.resolved === null ? "comp?" : ref.resolved.canonical;
}

function renderValtype(reader: ByteReader, scope: TypeDomain): string {
	const leading = reader.s33();
	if (leading >= 0) return resolveTypeMember(scope, leading).canonical;
	return renderValtypeByte(reader, scope, leading & 0x7f);
}

function renderValtypeByte(reader: ByteReader, scope: TypeDomain, byte: number): string {
	const primitive = PRIMITIVE_CANONICAL.get(byte);
	if (primitive !== undefined) return primitive;
	switch (byte) {
		case 0x69:
			return "own:" + resolveTypeMember(scope, reader.u32()).canonical;
		case 0x68:
			return "borrow:" + resolveTypeMember(scope, reader.u32()).canonical;
		case 0x72: {
			const count = reader.u32();
			const fields: string[] = [];
			for (let i = 0; i < count; i++) {
				const label = reader.name("record label");
				fields.push(label + ":" + renderValtype(reader, scope));
			}
			fields.sort();
			return "record{" + fields.join(",") + "}";
		}
		case 0x71: {
			const count = reader.u32();
			const cases: string[] = [];
			for (let i = 0; i < count; i++) {
				const label = reader.name("variant label");
				const payload = optionalValtype(reader, scope);
				const terminator = reader.byte();
				if (terminator !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "variant case terminator must be 0x00");
				cases.push(label + (payload === null ? "" : ":" + payload));
			}
			return "variant[" + cases.join("|") + "]";
		}
		case 0x70:
			return "list:" + renderValtype(reader, scope);
		case 0x63:
			return "map:" + renderValtype(reader, scope) + "," + renderValtype(reader, scope);
		case 0x67:
			return "fixedlist:" + renderValtype(reader, scope) + ":" + reader.u32();
		case 0x6f: {
			const count = reader.u32();
			const items: string[] = [];
			for (let i = 0; i < count; i++) items.push(renderValtype(reader, scope));
			return "tuple[" + items.join(",") + "]";
		}
		case 0x6e: {
			const count = reader.u32();
			const names: string[] = [];
			for (let i = 0; i < count; i++) names.push(reader.name("flag label"));
			names.sort();
			return "flags{" + names.join(",") + "}";
		}
		case 0x6d: {
			const count = reader.u32();
			const names: string[] = [];
			for (let i = 0; i < count; i++) names.push(reader.name("enum label"));
			return "enum[" + names.join(",") + "]";
		}
		case 0x6b:
			return "option:" + renderValtype(reader, scope);
		case 0x6a:
			return "result:" + String(optionalValtype(reader, scope)) + "," + String(optionalValtype(reader, scope));
		case 0x66:
			return "stream:" + String(optionalValtype(reader, scope));
		case 0x65:
			return "future:" + String(optionalValtype(reader, scope));
		default:
			throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown value type opcode 0x${byte.toString(16)} at offset ${reader.offset}`);
	}
}

function optionalValtype(reader: ByteReader, scope: TypeDomain): string | null {
	const present = reader.byte();
	if (present === 0x00) return null;
	if (present === 0x01) return renderValtype(reader, scope);
	throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown optional marker 0x${present.toString(16)}`);
}

/** 局部类型域（instance/component type 内部）；count 0 = 本域，1 = 父 component 域（outer alias 解析）。 */
class LocalTypeScope implements TypeDomain {
	private readonly locals: MemberShape[] = [];
	constructor(private readonly parent: TypeDomain) {}
	push(rendered: MemberShape): void {
		this.locals.push(rendered);
	}
	resolveType(index: number): MemberShape | undefined {
		return index >= 0 && index < this.locals.length ? this.locals[index] : this.parent.resolveType(index);
	}
	resolveOuter(count: number, index: number): MemberShape | undefined {
		if (count === 0) return this.resolveType(index);
		if (count === 1) return this.parent.resolveType(index);
		return undefined;
	}
}

function renderDeftype(reader: ByteReader, scope: LocalTypeScope, depth: number): MemberShape {
	if (depth > 256) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "type rendering nests deeper than 256");
	const tag = reader.byte();
	if (tag === 0x40 || tag === 0x43) {
		// 0x40 同步 functype；0x43 async functype（布局相同，canonical 区分）。
		const paramCount = reader.u32();
		const params: string[] = [];
		for (let i = 0; i < paramCount; i++) {
			const label = reader.name("function parameter label");
			params.push(label + ":" + renderValtype(reader, scope));
		}
		const resultForm = reader.byte();
		let result: string;
		if (resultForm === 0x00) result = renderValtype(reader, scope);
		else if (resultForm === 0x01) {
			const inner = reader.byte();
			if (inner !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "labeled result list must be empty");
			result = "";
		} else throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown function result form 0x${resultForm.toString(16)}`);
		return member((tag === 0x43 ? "afn(" : "fn(") + params.join(",") + ")->" + result);
	}
	if (tag === 0x41 || tag === 0x42) {
		const local = new LocalTypeScope(scope);
		const declCount = reader.u32();
		const exports = new Map<string, MemberShape>();
		const imports = new Map<string, MemberShape>();
		for (let i = 0; i < declCount; i++) {
			const decl = reader.byte();
			if (decl === 0x00) {
				skipCoreTypeInInstance(reader);
			} else if (decl === 0x01) {
				local.push(renderDeftype(reader, local, depth + 1));
			} else if (decl === 0x02) {
				const alias = readComponentAlias(reader);
				if (alias.sort === SORT_TYPE && alias.kind === "outer") {
					const resolved = local.resolveOuter(alias.count, alias.index);
					local.push(resolved === undefined ? member(`outer:${alias.count}:${alias.index}`) : resolved);
				} else if (alias.kind !== "outer") {
					throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "type-scope alias must target outer types");
				}
			} else if (decl === 0x03) {
				if (tag === 0x42) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "instance type cannot contain an import declaration");
				const name = reader.externName();
				const ref = readComponentTypeRef(reader, local);
				// 编码事实（2026-08-26，rustc wasm32-wasip2 组件实证）：instance type 内
				// import/export decl 引用 SORT_TYPE 时会把该类型引入局部 type 索引空间——
				// wit-component 只用显式 type decl + alias，故此前路径未被 fixture 覆盖；
				// (sub resource) 引入新资源类型，(eq N) 别名既有渲染。漏 push 会让后续
				// borrow/own 局部索引解析失败（WASM_BINARY_SECTION_INVALID 误报）。
				if (ref.sort === SORT_TYPE) local.push(ref.boundSub ? member("res") : typeRefMember(ref));
				imports.set(name, typeRefMember(ref));
			} else if (decl === 0x04) {
				const name = reader.externName();
				const ref = readComponentTypeRef(reader, local);
				if (ref.sort === SORT_TYPE) local.push(ref.boundSub ? member("res") : typeRefMember(ref));
				exports.set(name, typeRefMember(ref));
			} else throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown type declaration 0x${decl.toString(16)}`);
		}
		if (tag === 0x42) return member(shapeCanonical("inst", exports), exports);
		const merged = new Map<string, MemberShape>();
		for (const [name, m] of imports) merged.set("import:" + name, m);
		for (const [name, m] of exports) merged.set(name, m);
		return member(shapeCanonical("comp", merged), merged);
	}
	if (tag === 0x3f) {
		// resource：rep 是 core ValType（单字节），析构为可选 u32。
		reader.byte();
		const dtor = reader.byte();
		if (dtor === 0x01) reader.u32();
		else if (dtor !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown resource destructor marker 0x${dtor.toString(16)}`);
		return member("resource");
	}
	return member(renderValtypeByte(reader, scope, tag));
}

function typeRefMember(ref: ComponentTypeRef): MemberShape {
	if (ref.sort === -1) return member("coremod");
	if (ref.sort === SORT_VALUE) return member("val:" + (ref.valtypeCanonical as string));
	if (ref.sort === SORT_TYPE) return ref.boundSub ? member("res") : (ref.resolved ?? member("ty?"));
	return ref.resolved ?? member("comp?");
}

/** instance/component type 内的 core type decl：wit-component 产出中不存在，仅支持 0x60 functype，其余 fail-closed。 */
function skipCoreTypeInInstance(reader: ByteReader): void {
	const tag = reader.byte();
	if (tag !== 0x60) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unsupported core type 0x${tag.toString(16)} inside an instance type`);
	const a = reader.u32();
	for (let i = 0; i < a; i++) reader.byte();
	const b = reader.u32();
	for (let i = 0; i < b; i++) reader.byte();
}

// ---------------------------------------------------------------------------
// component 域解析：六段解码 + 索引空间（按二进制出现序增长）+ provenance
// ---------------------------------------------------------------------------

/** wit-component 命名约定前缀（adapter/glue 识别；版本钉死见文件头注释）。 */
const ADAPTER_NAME_PREFIX = "wit-component:adapter:";
const GLUE_NAME_PREFIXES: readonly string[] = ["wit-component-shim-", "wit-component-fixup"];

// 未命名胶水模块的结构识别（2026-08-26 实证，任务 8.x）：rustc 1.98 内嵌 wit-component 0.234.0
// 不写 component-name 段，shim/fixup 模块全部匿名；fixup 的 raw import 形如 ("", "0".."N")
// + ("", "$imports")，wasm-tools 1.258.0 的命名变体是 ("shim", "$imports")。只认 field 为纯
// 数字或 "$imports" 且 module 为空串/"shim" 的全量形状（shim 数字重接线 + funcref 表）；
// 任何偏离（如再带一个具名函数导入）都保持计费、按未翻译 raw 拒绝——fail-closed。
const SHIM_REWIRING_FIELD_PATTERN = /^(?:\d+|\$imports)$/;
const SHIM_REWIRING_MODULES: ReadonlySet<string> = new Set(["", "shim"]);

function isShimRewiringFacts(facts: CoreModuleFacts): boolean {
	return facts.rawImportPairs.length > 0 && facts.rawImportPairs.every((pair) => SHIM_REWIRING_MODULES.has(pair.module) && SHIM_REWIRING_FIELD_PATTERN.test(pair.field));
}

type InstanceProv =
	| { readonly kind: "instantiated"; readonly componentIdx: number }
	| { readonly kind: "imported"; readonly shape: MemberShape | undefined }
	| { readonly kind: "export-of"; readonly instanceIdx: number; readonly name: string }
	| { readonly kind: "inline"; readonly shape: MemberShape | undefined }
	| { readonly kind: "outer" };

interface ComponentImportEntry {
	readonly name: string;
	readonly sort: number;
	readonly shape: MemberShape | null;
}

interface ComponentExportEntry {
	readonly name: string;
	readonly sort: number;
	readonly index: number;
	readonly typeRef: ComponentTypeRef | null;
}

interface CoreModuleSlot {
	/** 内嵌模块的解码事实；导入/outer 引入的槽位无事实（不产生节点）。 */
	readonly facts: CoreModuleFacts | null;
	/** component-name 段给出的名字（未命名 = null）。 */
	name: string | null;
}

interface ComponentScope {
	readonly nodeId: string;
	readonly imports: ComponentImportEntry[];
	readonly exports: ComponentExportEntry[];
	readonly typeRenders: MemberShape[];
	readonly instancesProv: InstanceProv[];
	readonly componentsNodeId: (string | null)[];
	readonly funcsCanonical: string[];
	readonly coreModuleSlots: CoreModuleSlot[];
	/** component-name 段解析出的模块名（槽位索引 → 名）。 */
	readonly moduleNames: Map<number, string>;
}

interface ComponentAlias {
	readonly sort: number;
	readonly kind: "export" | "core-export" | "outer";
	readonly index: number;
	readonly name: string | null;
	readonly count: number;
}

function readComponentAlias(reader: ByteReader): ComponentAlias {
	const first = reader.byte();
	let sort = first;
	if (first === 0x00) {
		sort = -1;
		reader.byte();
	} else if (first < SORT_FUNC || first > SORT_INSTANCE) {
		throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown alias sort 0x${first.toString(16)}`);
	}
	const kindByte = reader.byte();
	if (kindByte === 0x00) {
		const index = reader.u32();
		return { sort, kind: "export", index, name: reader.name("alias export name"), count: 0 };
	}
	if (kindByte === 0x01) {
		const index = reader.u32();
		return { sort, kind: "core-export", index, name: reader.name("alias core export name"), count: 0 };
	}
	if (kindByte === 0x02) {
		return { sort, kind: "outer", index: reader.u32(), name: null, count: reader.u32() };
	}
	throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown alias kind 0x${kindByte.toString(16)}`);
}

interface ParseContext {
	readonly nodes: WasmClosureNode[];
	readonly edges: { readonly from: string; readonly to: string }[];
	readonly edgeKeys: Set<string>;
	readonly budget: WasmClosureBudget;
	readonly scopes: Map<string, ComponentScope>;
	entryNodeId: string;
	nodeSeq: number;
}

function allocateNode(ctx: ParseContext, kind: WasmClosureNodeKind): string {
	if (ctx.nodes.length + 1 > ctx.budget.maxNodes) throw new WasmBinaryAbort("WASM_CLOSURE_BUDGET_EXCEEDED", `closure node budget ${ctx.budget.maxNodes} exceeded`);
	const id = "n" + ctx.nodeSeq++;
	ctx.nodes.push({ id, kind, interfaces: [] });
	return id;
}

function addEdge(ctx: ParseContext, from: string, to: string): void {
	const key = from + "\0" + to;
	if (ctx.edgeKeys.has(key)) return;
	if (ctx.edges.length + 1 > ctx.budget.maxEdges) throw new WasmBinaryAbort("WASM_CLOSURE_BUDGET_EXCEEDED", `closure edge budget ${ctx.budget.maxEdges} exceeded`);
	ctx.edgeKeys.add(key);
	ctx.edges.push({ from, to });
}

function parseComponent(bytes: Uint8Array, nodeId: string, depth: number, ctx: ParseContext): void {
	if (depth > ctx.budget.maxDepth) throw new WasmBinaryAbort("WASM_CLOSURE_BUDGET_EXCEEDED", `component nesting depth ${depth} exceeds budget ${ctx.budget.maxDepth}`);
	if (bytes.length < 8) throw new WasmBinaryAbort("WASM_BINARY_INVALID_HEADER", "component shorter than 8 bytes");
	if (!(bytes[0] === 0x00 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d)) throw new WasmBinaryAbort("WASM_BINARY_INVALID_HEADER", "component magic mismatch");
	if (!(bytes[4] === 0x0d && bytes[5] === 0x00 && bytes[6] === 0x01 && bytes[7] === 0x00)) throw new WasmBinaryAbort("WASM_BINARY_INVALID_HEADER", "component version/layer mismatch");
	const reader = new ByteReader(bytes, bytes.length, 8);
	const scope: ComponentScope = {
		nodeId,
		imports: [],
		exports: [],
		typeRenders: [],
		instancesProv: [],
		componentsNodeId: [],
		funcsCanonical: [],
		coreModuleSlots: [],
		moduleNames: new Map(),
	};
	ctx.scopes.set(nodeId, scope);
	const componentDomain = domainOfScope(scope);
	while (reader.remaining > 0) {
		const id = reader.byte();
		const size = reader.u32();
		if (id > 12) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown component section id ${id} at offset ${reader.offset}`);
		if (reader.remaining < size) throw new WasmBinaryAbort("WASM_BINARY_TRUNCATED", `component section ${id} exceeds input`);
		if (id === 1) {
			// core module 段：恰含一个完整 core 二进制（wit-component 产出可重复出现该段）。
			const moduleBytes = reader.takeBytes(size);
			scope.coreModuleSlots.push({ facts: decodeCoreModule(moduleBytes), name: null });
		} else if (id === 4) {
			const nestedBytes = reader.takeBytes(size);
			const nestedId = allocateNode(ctx, "component");
			scope.componentsNodeId.push(nestedId);
			parseComponent(nestedBytes, nestedId, depth + 1, ctx);
			addEdge(ctx, nodeId, nestedId);
		} else if (id === 5) {
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const form = reader.byte();
				if (form === 0x00) {
					const componentIdx = reader.u32();
					const argCount = reader.u32();
					for (let a = 0; a < argCount; a++) {
						reader.name("instantiation argument name");
						readExternIndex(reader);
					}
					scope.instancesProv.push({ kind: "instantiated", componentIdx });
					const target = componentIdx < scope.componentsNodeId.length ? scope.componentsNodeId[componentIdx] : null;
					if (target !== null) addEdge(ctx, nodeId, target);
				} else if (form === 0x01) {
					const exportCount = reader.u32();
					const members = new Map<string, MemberShape>();
					for (let e = 0; e < exportCount; e++) {
						const name = reader.externName();
						const item = readExternIndex(reader);
						members.set(name, memberOfIndex(scope, item.sort, item.index));
					}
					scope.instancesProv.push({ kind: "inline", shape: member(shapeCanonical("inst", members), members) });
				} else throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown instance form 0x${form.toString(16)}`);
			}
		} else if (id === 6) {
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const alias = readComponentAlias(reader);
				if (alias.sort === SORT_INSTANCE && alias.kind === "export") {
					scope.instancesProv.push({ kind: "export-of", instanceIdx: alias.index, name: alias.name as string });
				} else if (alias.sort === SORT_TYPE) {
					if (alias.kind === "outer") {
						const resolved = componentDomain.resolveType(alias.index);
						scope.typeRenders.push(resolved === undefined ? member(`outer:${alias.count}:${alias.index}`) : resolved);
					} else if (alias.kind === "export") {
						const owner = shapeOfInstance(ctx, scope, alias.index);
						const found = owner.shape?.get(alias.name as string);
						if (found === undefined) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `alias references missing export ${String(alias.name)}`);
						scope.typeRenders.push(found);
					} else {
						throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "type alias core-export form is invalid");
					}
				} else if (alias.sort === SORT_FUNC && alias.kind === "export") {
					const owner = shapeOfInstance(ctx, scope, alias.index);
					scope.funcsCanonical.push(owner.shape?.get(alias.name as string)?.canonical ?? "fn?");
				} else if (alias.kind === "outer") {
					if (alias.sort === SORT_COMPONENT) scope.componentsNodeId.push(null);
					else if (alias.sort === SORT_INSTANCE) scope.instancesProv.push({ kind: "outer" });
					else if (alias.sort === -1) scope.coreModuleSlots.push({ facts: null, name: null });
				}
			}
		} else if (id === 7) {
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const local = new LocalTypeScope(componentDomain);
				scope.typeRenders.push(renderDeftype(reader, local, 0));
			}
		} else if (id === 8) {
			// canon 段：仅 lift 追加 funcs 索引空间；其余 opcode 按 wasmparser 布局精确跳过。
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const op = reader.byte();
				if (op === 0x00 || op === 0x01) {
					const inner = reader.byte();
					if (inner !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown canonical ${op === 0x00 ? "lift" : "lower"} tag 0x${inner.toString(16)}`);
					reader.u32();
					skipCanonOpts(reader);
					if (op === 0x00) {
						const ft = reader.u32();
						scope.funcsCanonical.push(componentDomain.resolveType(ft)?.canonical ?? "fn?");
					}
				} else if (CANON_U32_OPS.has(op)) {
					reader.u32();
				} else if (CANON_NONE_OPS.has(op)) {
					// 无 payload。
				} else if (CANON_BOOL_OPS.has(op)) {
					reader.byte();
				} else if (CANON_VALTYPE_OPS.has(op)) {
					skipComponentValtype(reader);
				} else if (CANON_VALTYPE_BOOL_OPS.has(op)) {
					skipComponentValtype(reader);
					reader.byte();
				} else if (CANON_VALTYPE_OPTS_OPS.has(op)) {
					skipComponentValtype(reader);
					skipCanonOpts(reader);
				} else if (CANON_OPTS_OPS.has(op)) {
					skipCanonOpts(reader);
				} else if (CANON_U32_U32_OPS.has(op)) {
					reader.u32();
					reader.u32();
				} else if (CANON_BOOL_U32_OPS.has(op)) {
					reader.byte();
					reader.u32();
				} else if (CANON_CORETYPE_U32_OPS.has(op)) {
					reader.byte();
					reader.u32();
				} else if (op === 0x09) {
					// task-return：resultlist + opts。
					const form = reader.byte();
					if (form === 0x00) skipComponentValtype(reader);
					else if (form !== 0x01 || reader.byte() !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "invalid task-return result list");
					skipCanonOpts(reader);
				} else throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown canon opcode 0x${op.toString(16)}`);
			}
		} else if (id === 10) {
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const name = reader.externName();
				const ref = readComponentTypeRef(reader, componentDomain);
				let shape: MemberShape | null = null;
				if (ref.sort === -1) {
					scope.coreModuleSlots.push({ facts: null, name: null });
				} else if (ref.sort === SORT_FUNC) {
					scope.funcsCanonical.push(typeRefCanonical(ref));
				} else if (ref.sort === SORT_TYPE) {
					scope.typeRenders.push(ref.boundSub ? member("res") : (ref.resolved as MemberShape));
				} else if (ref.sort === SORT_VALUE) {
					// value 索引空间不跟踪。
				} else if (ref.sort === SORT_COMPONENT) {
					scope.componentsNodeId.push(null);
				} else if (ref.sort === SORT_INSTANCE) {
					shape = ref.resolved as MemberShape;
					scope.instancesProv.push({ kind: "imported", shape });
				}
				scope.imports.push({ name, sort: ref.sort, shape });
			}
		} else if (id === 11) {
			const count = reader.u32();
			for (let i = 0; i < count; i++) {
				const name = reader.externName();
				const item = readExternIndex(reader);
				const explicit = reader.byte();
				let typeRef: ComponentTypeRef | null = null;
				if (explicit === 0x01) typeRef = readComponentTypeRef(reader, componentDomain);
				else if (explicit !== 0x00) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown export type marker 0x${explicit.toString(16)}`);
				scope.exports.push({ name, sort: item.sort, index: item.index, typeRef });
				// export 向被导出种类的索引空间追加别名项。
				if (item.sort === SORT_INSTANCE) {
					const prov = item.index < scope.instancesProv.length ? scope.instancesProv[item.index] : ({ kind: "outer" } as const);
					scope.instancesProv.push(prov);
				} else if (item.sort === SORT_TYPE) {
					scope.typeRenders.push(item.index < scope.typeRenders.length ? scope.typeRenders[item.index] : member("ty?"));
				} else if (item.sort === SORT_FUNC) {
					scope.funcsCanonical.push(item.index < scope.funcsCanonical.length ? scope.funcsCanonical[item.index] : (typeRef === null ? "fn?" : typeRefCanonical(typeRef)));
				}
			}
		} else if (id === 0) {
			const sectionStart = reader.offset;
			const nameLen = reader.u32();
			const customName = utf8Strict(reader.takeBytes(nameLen), "custom section name");
			if (customName === "component-name") parseComponentNameSection(reader, sectionStart + size, scope);
			reader.consume(sectionStart + size - reader.offset);
		} else {
			// core instance(2)/core type(3)/start(9)/value(12)：无索引空间依赖，按长度跳过。
			reader.consume(size);
		}
	}
	applyModuleNames(scope);
}

/** export/inline/instantiation-arg 位置的 extern 索引：0x00 0x11 双字节 module 或单字节 0x01..0x05。 */
function readExternIndex(reader: ByteReader): { sort: number; index: number } {
	const first = reader.byte();
	if (first === 0x00) {
		const second = reader.byte();
		if (second !== 0x11) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown core extern kind 0x${second.toString(16)}`);
		return { sort: -1, index: -1 };
	}
	if (first < SORT_FUNC || first > SORT_INSTANCE) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown component extern kind 0x${first.toString(16)}`);
	return { sort: first, index: reader.u32() };
}

// canon 段 opcode 布局表（wasmparser canonicals.rs；0x00 lift / 0x01 lower 在 handler 内联处理）。
const CANON_U32_OPS: ReadonlySet<number> = new Set([0x02, 0x03, 0x04, 0x40]);
const CANON_NONE_OPS: ReadonlySet<number> = new Set([0x05, 0x0d, 0x1e, 0x1f, 0x22, 0x23, 0x24, 0x25, 0x26, 0x28, 0x42]);
const CANON_BOOL_OPS: ReadonlySet<number> = new Set([0x06, 0x0c, 0x29, 0x2a, 0x2b, 0x2c, 0x2d]);
const CANON_VALTYPE_OPS: ReadonlySet<number> = new Set([0x0e, 0x13, 0x14, 0x15, 0x1a, 0x1b]);
const CANON_VALTYPE_BOOL_OPS: ReadonlySet<number> = new Set([0x11, 0x12, 0x18, 0x19]);
const CANON_VALTYPE_OPTS_OPS: ReadonlySet<number> = new Set([0x0f, 0x10, 0x16, 0x17]);
const CANON_OPTS_OPS: ReadonlySet<number> = new Set([0x1c, 0x1d]);
const CANON_U32_U32_OPS: ReadonlySet<number> = new Set([0x27, 0x41]);
const CANON_BOOL_U32_OPS: ReadonlySet<number> = new Set([0x20, 0x21]);
const CANON_CORETYPE_U32_OPS: ReadonlySet<number> = new Set([0x0a, 0x0b]);

/** canon 位置的 ComponentValType：primitive 单字节（负 s33）或类型索引 LEB（非负 s33）。 */
function skipComponentValtype(reader: ByteReader): void {
	const leading = reader.s33();
	if (leading >= 0) return;
	if (!PRIMITIVE_CANONICAL.has(leading & 0x7f)) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown canon value type 0x${(leading & 0x7f).toString(16)}`);
}

function skipCanonOpts(reader: ByteReader): void {
	const count = reader.u32();
	for (let i = 0; i < count; i++) {
		const tag = reader.byte();
		if (tag === 0x03 || tag === 0x04 || tag === 0x05 || tag === 0x07 || tag === 0x08) reader.u32();
		else if (tag > 0x09) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `unknown canon option 0x${tag.toString(16)}`);
	}
}

function domainOfScope(scope: ComponentScope): TypeDomain {
	return domainOf(scope.typeRenders);
}

/** component-name 自定义段：只需 core module 名映射（adapter/glue 识别）。 */
function parseComponentNameSection(reader: ByteReader, sectionEnd: number, scope: ComponentScope): void {
	while (reader.offset < sectionEnd) {
		const subId = reader.byte();
		const subSize = reader.u32();
		const subEnd = reader.offset + subSize;
		if (subEnd > sectionEnd) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", "component-name subsection exceeds section");
		if (subId === 1) {
			const level = reader.byte();
			if (level === 0x00 && reader.peek() === 0x11) {
				reader.byte();
				const count = reader.u32();
				for (let i = 0; i < count; i++) {
					const index = reader.u32();
					scope.moduleNames.set(index, reader.name("core module name"));
				}
			}
		}
		reader.consume(subEnd - reader.offset);
	}
}

function applyModuleNames(scope: ComponentScope): void {
	for (const [index, named] of scope.moduleNames) {
		if (index < 0 || index >= scope.coreModuleSlots.length) continue;
		scope.coreModuleSlots[index].name = named;
	}
}

/** 实例索引 → 其形状（provenance 解析；instantiated 取嵌套 component 的导出形状）。 */
function shapeOfInstance(ctx: ParseContext, scope: ComponentScope, index: number): MemberShape {
	let guard = 0;
	let current = index;
	while (guard++ <= scope.instancesProv.length + 1) {
		if (current < 0 || current >= scope.instancesProv.length) return member("inst?");
		const prov = scope.instancesProv[current];
		switch (prov.kind) {
			case "instantiated": {
				const nestedId = prov.componentIdx < scope.componentsNodeId.length ? scope.componentsNodeId[prov.componentIdx] : null;
				if (nestedId === null) return member("inst?");
				const nested = ctx.scopes.get(nestedId);
				if (nested === undefined) return member("inst?");
				const members = componentExportShape(ctx, nested);
				return member(shapeCanonical("inst", members), members);
			}
			case "imported":
			case "inline":
				return prov.shape === undefined ? member("inst?") : prov.shape;
			case "export-of": {
				const owner = shapeOfInstance(ctx, scope, prov.instanceIdx);
				const found = owner.shape?.get(prov.name);
				if (found === undefined) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `alias references missing export ${prov.name}`);
				return found;
			}
			case "outer":
				return member("inst?");
		}
	}
	return member("inst?");
}

function memberOfIndex(scope: ComponentScope, sort: number, index: number): MemberShape {
	if (sort === -1) return member("coremod");
	if (sort === SORT_FUNC) return member(index >= 0 && index < scope.funcsCanonical.length ? scope.funcsCanonical[index] : "fn?");
	if (sort === SORT_VALUE) return member("val");
	if (sort === SORT_TYPE) return index >= 0 && index < scope.typeRenders.length ? scope.typeRenders[index] : member("ty?");
	if (sort === SORT_COMPONENT) return member("comp");
	return member("inst?");
}

function componentExportShape(ctx: ParseContext, scope: ComponentScope): Map<string, MemberShape> {
	const members = new Map<string, MemberShape>();
	for (const entry of scope.exports) {
		if (entry.typeRef !== null) {
			members.set(entry.name, typeRefMember(entry.typeRef));
			continue;
		}
		if (entry.sort === SORT_INSTANCE) {
			const shape = shapeOfInstance(ctx, scope, entry.index);
			members.set(entry.name, shape);
			continue;
		}
		members.set(entry.name, memberOfIndex(scope, entry.sort, entry.index));
	}
	return members;
}

/** re-export 折叠：export 的 provenance 落到被实例化 component 时，返回该嵌套 component 节点 id。 */
function providerAliasOfExport(ctx: ParseContext, scope: ComponentScope, index: number): string | null {
	let guard = 0;
	let current = index;
	while (guard++ <= scope.instancesProv.length + 1) {
		if (current < 0 || current >= scope.instancesProv.length) return null;
		const prov = scope.instancesProv[current];
		if (prov.kind === "instantiated") return prov.componentIdx < scope.componentsNodeId.length ? scope.componentsNodeId[prov.componentIdx] : null;
		if (prov.kind === "export-of") {
			current = prov.instanceIdx;
			continue;
		}
		return null;
	}
	return null;
}

// ---------------------------------------------------------------------------
// typed 图组装与入口级判定
// ---------------------------------------------------------------------------

interface OccurrenceDraft {
	readonly nodeId: string;
	readonly pkg: string;
	readonly iface: string;
	readonly direction: "import" | "export";
	readonly shape: ReadonlyMap<string, MemberShape>;
	readonly providerAlias: string | null;
}

const WIT_PACKAGE_PREFIX_PATTERN = /^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*@(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const WIT_IFACE_PATTERN = /^[a-z][a-z0-9-]*$/;

/** component 外部名（解码信息，非 core import-name 切分）→ WIT 接口身份：ns:name/iface@ver。 */
function parseWitInterfaceName(name: string): { readonly pkg: string; readonly iface: string } | null {
	const slash = name.lastIndexOf("/");
	if (slash <= 0) return null;
	const namespacePart = name.slice(0, slash);
	const ifacePart = name.slice(slash + 1);
	const at = ifacePart.lastIndexOf("@");
	if (at <= 0) return null;
	const iface = ifacePart.slice(0, at);
	const version = ifacePart.slice(at + 1);
	const pkg = namespacePart + "@" + version;
	if (!WIT_PACKAGE_PREFIX_PATTERN.test(pkg) || !WIT_IFACE_PATTERN.test(iface)) return null;
	return { pkg, iface };
}

function shapeSubsumed(imported: ReadonlyMap<string, MemberShape>, provided: ReadonlyMap<string, MemberShape>): boolean {
	for (const [name, needed] of imported) {
		const target = provided.get(name);
		if (target === undefined) return false;
		if (needed.canonical === target.canonical) continue;
		if (needed.shape !== undefined && target.shape !== undefined && shapeSubsumed(needed.shape, target.shape)) continue;
		return false;
	}
	return true;
}

function scanWasmClosureOrAbort(input: WasmClosureScanInput): WasmClosureGraph {
	const ctx: ParseContext = {
		nodes: [],
		edges: [],
		edgeKeys: new Set<string>(),
		budget: input.budget,
		scopes: new Map<string, ComponentScope>(),
		entryNodeId: "",
		nodeSeq: 0,
	};
	const entryId = allocateNode(ctx, "component");
	ctx.entryNodeId = entryId;
	parseComponent(input.entry, entryId, 1, ctx);
	const entryScope = ctx.scopes.get(entryId) as ComponentScope;

	// 入口级判定 1：入口的每个 import 必须可类型化为接口出现（revision 1 矩阵的宿主能力全为接口；
	// 未类型化导入既无内部 provider 也无法进入声明集合）。
	for (const entryImport of entryScope.imports) {
		if (entryImport.sort !== SORT_INSTANCE || parseWitInterfaceName(entryImport.name) === null) {
			throw new WasmBinaryAbort("WASM_IMPORT_UNMAPPABLE", `entry import "${entryImport.name}" has no typed Component Model interface mapping`);
		}
	}
	// 入口级判定 2：入口外部可见导出恰好一条（身份匹配由 validateWasmCapabilityClosure 完成）。
	if (entryScope.exports.length !== 1) {
		throw new WasmBinaryAbort("WASM_EXPORT_MISMATCH", `entry component must export exactly one interface, found ${entryScope.exports.length}`);
	}

	// 接口出现收集（entry + 全部嵌套 component 域，按解析序）。
	const drafts: OccurrenceDraft[] = [];
	for (const scope of ctx.scopes.values()) {
		for (const imp of scope.imports) {
			if (imp.sort !== SORT_INSTANCE) continue;
			const parsed = parseWitInterfaceName(imp.name);
			if (parsed === null) continue;
			const shape = imp.shape?.shape;
			if (shape === undefined) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `instance import "${imp.name}" lacks a decodable instance type`);
			drafts.push({ nodeId: scope.nodeId, pkg: parsed.pkg, iface: parsed.iface, direction: "import", shape, providerAlias: null });
		}
		for (const ex of scope.exports) {
			if (ex.sort !== SORT_INSTANCE) continue;
			const parsed = parseWitInterfaceName(ex.name);
			if (parsed === null) continue;
			const providerAlias = providerAliasOfExport(ctx, scope, ex.index);
			const shapeMember = ex.typeRef !== null && ex.typeRef.sort === SORT_INSTANCE ? (ex.typeRef.resolved as MemberShape) : shapeOfInstance(ctx, scope, ex.index);
			drafts.push({ nodeId: scope.nodeId, pkg: parsed.pkg, iface: parsed.iface, direction: "export", shape: shapeMember.shape ?? new Map<string, MemberShape>(), providerAlias });
		}
	}

	// 结构兼容（import ⊆ provider，即 component 实例化要求的 instance 子类型方向）→ anchor typeTag；
	// 同名接口任何一对失配 → 该 anchor 全部出现分化为互异标签（fail-closed：
	// validateWasmCapabilityClosure 报 WASM_INTERNAL_TYPE_MISMATCH，永不静默放行）。
	const anchorOf = (draft: OccurrenceDraft): string => draft.pkg + "/" + draft.iface;
	const diverged = new Set<string>();
	for (const candidate of drafts) {
		if (candidate.direction !== "import") continue;
		for (const provider of drafts) {
			if (provider.direction !== "export" || anchorOf(provider) !== anchorOf(candidate)) continue;
			if (!shapeSubsumed(candidate.shape, provider.shape)) diverged.add(anchorOf(candidate));
		}
	}
	let divergeSeq = 0;
	const interfacesByNode = new Map<string, WasmClosureInterfaceOccurrence[]>();
	for (const draft of drafts) {
		const anchor = anchorOf(draft);
		const typeTag = diverged.has(anchor) ? `wit:v1:${anchor}#div:${divergeSeq++}` : `wit:v1:${anchor}`;
		const list = interfacesByNode.get(draft.nodeId) ?? [];
		const occurrence: WasmClosureInterfaceOccurrence = draft.providerAlias === null
			? { package: draft.pkg, interface: draft.iface, direction: draft.direction, typeTag }
			: { package: draft.pkg, interface: draft.iface, direction: draft.direction, typeTag, providerAlias: draft.providerAlias };
		list.push(occurrence);
		interfacesByNode.set(draft.nodeId, list);
	}
	for (let i = 0; i < ctx.nodes.length; i++) {
		const node = ctx.nodes[i];
		const interfaces = interfacesByNode.get(node.id) ?? [];
		ctx.nodes[i] = { id: node.id, kind: node.kind, interfaces };
	}

	// core module / adapter 节点（内嵌槽位才产生节点；导入/outer 槽位是接线，不是闭包成员）。
	// 实例导入表面（名字 → 解码出的成员表）：主 core module 的 canonical ABI raw import
	// 以「模块名 = 实例导入名」按名接线（wit-component 实例化期双射）。绑定判定沿所属
	// component 的祖先链查实例导入（嵌套 component 的模块可消费下投的实例参数），仍只消费
	// 解码出的实例类型成员，绝不对 raw 名做能力分类——接口身份始终由 component import 段
	// 持有。已知边界（StarlingMonkey，componentize-js 0.22.0，2026-08-26 实证）：引擎 core
	// module 直接嵌在 entry 域，其 0.2.10 命名面绑到 entry 的 typed 实例导入；0.2.8 命名面经
	// inline core instance（canon lower 拼装）接线——本 scanner 刻意不建模 core instance 段，
	// 这些 raw 保持未绑定、按 WASM_IMPORT_UNMAPPABLE fail-closed（见 tests/wasm-lang-fixtures.test.ts）。
	const scopeMembers = new Map<string, Map<string, ReadonlyMap<string, MemberShape>>>();
	for (const scope of ctx.scopes.values()) {
		const members = new Map<string, ReadonlyMap<string, MemberShape>>();
		for (const imp of scope.imports) {
			if (imp.sort !== SORT_INSTANCE || imp.shape?.shape === undefined) continue;
			if (!members.has(imp.name)) members.set(imp.name, imp.shape.shape);
		}
		scopeMembers.set(scope.nodeId, members);
	}
	const parentsOf = new Map<string, string[]>();
	for (const edge of ctx.edges) {
		if (!ctx.scopes.has(edge.from) || !ctx.scopes.has(edge.to) || edge.from === edge.to) continue;
		const list = parentsOf.get(edge.to) ?? [];
		list.push(edge.from);
		parentsOf.set(edge.to, list);
	}
	const instanceMembersInScopeChain = (nodeId: string): Map<string, ReadonlyMap<string, MemberShape>> => {
		const merged = new Map(scopeMembers.get(nodeId) ?? []);
		const pending = [...(parentsOf.get(nodeId) ?? [])];
		while (pending.length > 0) {
			const parent = pending.pop() as string;
			for (const [name, members] of scopeMembers.get(parent) ?? []) {
				if (!merged.has(name)) merged.set(name, members);
			}
			pending.push(...(parentsOf.get(parent) ?? []));
		}
		return merged;
	};
	for (const scope of ctx.scopes.values()) {
		const instanceImportMembers = instanceMembersInScopeChain(scope.nodeId);
		for (const slot of scope.coreModuleSlots) {
			if (slot.facts === null) continue;
			const named = slot.name;
			if (named !== null && named.startsWith(ADAPTER_NAME_PREFIX)) {
				const abi = named.slice(ADAPTER_NAME_PREFIX.length);
				const translations = slot.facts.exportedFuncs.map((fn) => abi + "." + fn);
				const adapterId = allocateNode(ctx, "adapter");
				addEdge(ctx, scope.nodeId, adapterId);
				replaceNode(ctx, adapterId, { id: adapterId, kind: "adapter", interfaces: [], adapterTranslations: translations });
				continue;
			}
			const isGlue = (named !== null && GLUE_NAME_PREFIXES.some((prefix) => named.startsWith(prefix))) || isShimRewiringFacts(slot.facts);
			const moduleId = allocateNode(ctx, "core-module");
			addEdge(ctx, scope.nodeId, moduleId);
			// 胶水模块的 raw import 是 component 内部接线（shim/fixup 约定），不计费；重命名逃避只会
			// 让 raw import 更保守（运行期实例化仍由 wasmd 完整校验，raw 名永不可能成为宿主能力）。
			const rawImports = isGlue ? [] : slot.facts.rawImports;
			// 实例绑定 raw：绑定到宿主实例导入成员（函数面）或 canon resource.drop（资源面——
			// 成员名去掉 "[resource-drop]" 前缀后必须是同一实例导入的真实成员）。二者都只验证
			// 「宿主实例类型确实提供该成员」，不产生新的能力来源；未绑定的 raw 保持计费。
			const instanceBoundImports = isGlue
				? []
				: slot.facts.rawImportPairs
					.filter((pair) => {
						const members = instanceImportMembers.get(pair.module);
						if (members === undefined) return false;
						if (members.has(pair.field)) return true;
						return pair.field.startsWith("[resource-drop]") && members.has(pair.field.slice("[resource-drop]".length));
					})
					.map((pair) => pair.module + "." + pair.field);
			replaceNode(
				ctx,
				moduleId,
				rawImports.length === 0
					? { id: moduleId, kind: "core-module", interfaces: [] }
					: instanceBoundImports.length === 0
						? { id: moduleId, kind: "core-module", interfaces: [], rawImports }
						: { id: moduleId, kind: "core-module", interfaces: [], rawImports, instanceBoundImports },
			);
		}
	}

	return {
		world: input.world,
		hostABI: input.hostABI,
		entryNodeId: entryId,
		nodes: ctx.nodes,
		edges: ctx.edges,
		declaredHostImports: input.declaredHostImports,
		budget: input.budget,
	};
}

function replaceNode(ctx: ParseContext, id: string, node: WasmClosureNode): void {
	const index = ctx.nodes.findIndex((candidate) => candidate.id === id);
	if (index < 0) throw new WasmBinaryAbort("WASM_BINARY_SECTION_INVALID", `internal node ${id} missing`);
	ctx.nodes[index] = node;
}

// ---------------------------------------------------------------------------
// 公共 API
// ---------------------------------------------------------------------------

export function scanWasmClosureGraph(input: WasmClosureScanInput): WasmClosureScanResult {
	try {
		return { ok: true, graph: scanWasmClosureOrAbort(input) };
	} catch (failureValue) {
		if (failureValue instanceof WasmBinaryAbort) return { ok: false, code: failureValue.code, detail: failureValue.detail };
		return { ok: false, code: "WASM_BINARY_SECTION_INVALID", detail: failureValue instanceof Error ? failureValue.message : "unknown decode failure" };
	}
}

/** 层角色校验：component 层解码为 component；core-module/adapter 层解码为 core module（wit-component 形态）。 */
export function validateWasmLayerRole(role: WasmLayerRole, bytes: Uint8Array): WasmLayerRoleValidation {
	try {
		if (role === "component") {
			const ctx = emptyContext(WASM_CLOSURE_SCAN_ADMISSION_MAXIMA);
			const id = allocateNode(ctx, "component");
			parseComponent(bytes, id, 1, ctx);
			return { ok: true };
		}
		decodeCoreModule(bytes);
		return { ok: true };
	} catch (failureValue) {
		if (failureValue instanceof WasmBinaryAbort) {
			const code = failureValue.code === "WASM_BINARY_INVALID_HEADER" ? "WASM_BINARY_ROLE_INVALID" : failureValue.code;
			return { ok: false, code, detail: failureValue.detail };
		}
		return { ok: false, code: "WASM_BINARY_SECTION_INVALID", detail: failureValue instanceof Error ? failureValue.message : "unknown decode failure" };
	}
}

export function scanAndValidateWasmClosure(input: WasmClosureScanInput, matrix: WasmCapabilityMatrixV1 = WASM_CAPABILITY_MATRIX_REVISION_1): WasmClosureScanValidation {
	const scanned = scanWasmClosureGraph(input);
	if (!scanned.ok) return scanned;
	const validation: WasmClosureValidation = validateWasmCapabilityClosure(scanned.graph, matrix);
	if (validation.ok) return { ok: true, graph: scanned.graph, discoveredHostImports: validation.discoveredHostImports };
	return { ok: false, code: validation.code, detail: `closure validator rejected the decoded graph with ${validation.code}` };
}

function emptyContext(budget: WasmClosureBudget): ParseContext {
	return {
		nodes: [],
		edges: [],
		edgeKeys: new Set<string>(),
		budget,
		scopes: new Map<string, ComponentScope>(),
		entryNodeId: "",
		nodeSeq: 0,
	};
}
