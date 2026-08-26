// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.1 契约先行）：`iweb-wasm-oci-layout-v1` 严格子集校验与 `wasmPackageDigestV1`/`wasmVersionDigestV1` 必须先于一切宿主实现落地，并可跨实现复算 spec 向量。
// 正交意图：RFC 8785 JCS 字节权威（raw bytes 必须等于 JCS(JSON.parse(bytes))）、精确键集/重复成员/未知字段 fail-closed、typed 错误码；绝不调用或宣称等价于 celld `versionDigest`/`packageFilesDigest`。
import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { failure, isRecord, issue, ok, validateDnsName, type ValidationIssue, type ValidationResult } from "./validation.ts";

// ---------------------------------------------------------------------------
// 基础编码与名称（spec "Normative Encoding and Names"）
// ---------------------------------------------------------------------------

export const WASM_U53_MAX = 9007199254740991;
export const WASM_SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
export const WASM_OCI_SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
export const WASM_APPLICATION_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const WASM_VERSION_ID_PATTERN = /^[a-f0-9]{64}-[1-9][0-9]{0,15}$/;
export const WASM_WORLD_LITERAL = "wasi:http/proxy@0.2.8";
export const WASM_HOST_ABI_LITERAL = "iweb-wasmd-abi@1.0.0";

export function sha256Hex(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

function asBuffer(bytes: Uint8Array): Buffer {
	return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function compareUtf8Bytes(left: string, right: string): number {
	return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

// ---------------------------------------------------------------------------
// RFC 8785 JSON Canonicalization Scheme（JCS）
// ---------------------------------------------------------------------------

class WasmJcsError extends Error {}

function serializeJcsNumber(value: number): string {
	// RFC 8785 跟随 ECMAScript Number::toString；-0 序列化为 "0"；
	// NaN/±Infinity 不是合法 JSON 数值，必须报错而不是输出。
	if (!Number.isFinite(value)) throw new WasmJcsError("NaN and Infinity are not JSON values");
	return String(value);
}

function serializeJcsString(value: string): string {
	let out = '"';
	for (let i = 0; i < value.length; i++) {
		const unit = value.charCodeAt(i);
		if (unit === 0x22) out += '\\"';
		else if (unit === 0x5c) out += "\\\\";
		else if (unit === 0x08) out += "\\b";
		else if (unit === 0x09) out += "\\t";
		else if (unit === 0x0a) out += "\\n";
		else if (unit === 0x0c) out += "\\f";
		else if (unit === 0x0d) out += "\\r";
		else if (unit < 0x20) out += "\\u00" + unit.toString(16).padStart(2, "0");
		else if (unit >= 0xd800 && unit <= 0xdfff) {
			// RFC 8785 要求输入是良构 Unicode；孤立代理对必须报错。
			const isHigh = unit <= 0xdbff;
			const next = value.charCodeAt(i + 1);
			const nextIsLow = next >= 0xdc00 && next <= 0xdfff;
			if (isHigh && nextIsLow) {
				out += value[i] + value[i + 1];
				i++;
			} else {
				throw new WasmJcsError("lone surrogate is not valid Unicode for JCS");
			}
		} else out += value[i];
	}
	return out + '"';
}

function compareJcsKeys(left: string, right: string): number {
	// RFC 8785 §3.2.3：按成员名的 UTF-16 code unit 序排序（全部规范键均为 ASCII，
	// 与本 capability 的 UTF-8 bytewise 排序口径一致；见文件末尾歧义备注）。
	const length = Math.min(left.length, right.length);
	for (let i = 0; i < length; i++) {
		const delta = left.charCodeAt(i) - right.charCodeAt(i);
		if (delta !== 0) return delta;
	}
	return left.length - right.length;
}

function isPlainObject(value: object): boolean {
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
}

export function jcsCanonicalize(value: unknown): string {
	return serializeJcsValue(value);
}

function serializeJcsValue(value: unknown): string {
	if (value === null) return "null";
	switch (typeof value) {
		case "boolean":
			return value ? "true" : "false";
		case "number":
			return serializeJcsNumber(value);
		case "string":
			return serializeJcsString(value);
		case "object": {
			if (Array.isArray(value)) {
				let out = "[";
				for (let i = 0; i < value.length; i++) {
					if (i > 0) out += ",";
					out += serializeJcsValue(value[i]);
				}
				return out + "]";
			}
			if (!isPlainObject(value as object)) throw new WasmJcsError("only plain JSON objects are serializable as JCS");
			const record = value as Record<string, unknown>;
			const keys = Object.keys(record).sort(compareJcsKeys);
			let out = "{";
			for (let i = 0; i < keys.length; i++) {
				if (i > 0) out += ",";
				out += serializeJcsString(keys[i]) + ":" + serializeJcsValue(record[keys[i]]);
			}
			return out + "}";
		}
		default:
			throw new WasmJcsError("value of type " + typeof value + " is not JSON");
	}
}

export function jcsCanonicalBytes(value: unknown): Uint8Array {
	return Buffer.from(jcsCanonicalize(value), "utf8");
}

// ---------------------------------------------------------------------------
// 严格 JSON 解析：重复成员名必须在覆盖前报错（不得依赖 JSON.parse 的最后值覆盖）
// ---------------------------------------------------------------------------

class JsonSyntaxError extends Error {}

type StrictJsonResult = { readonly ok: true; readonly value: unknown } | { readonly ok: false; readonly error: string };

export function parseStrictJson(text: string): StrictJsonResult {
	if (text.charCodeAt(0) === 0xfeff) return { ok: false, error: "byte-order mark is not valid JSON" };
	let pos = 0;
	try {
		skipWhitespace();
		const value = parseValue();
		skipWhitespace();
		if (pos !== text.length) throw new JsonSyntaxError("unexpected trailing content after JSON value");
		return { ok: true, value };
	} catch (error) {
		if (error instanceof JsonSyntaxError) return { ok: false, error: error.message };
		throw error;
	}

	function skipWhitespace(): void {
		while (pos < text.length) {
			const c = text.charCodeAt(pos);
			if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
			else break;
		}
	}

	function consume(char: string): boolean {
		if (text[pos] === char) {
			pos++;
			return true;
		}
		return false;
	}

	function isDigit(c: number): boolean {
		return c >= 0x30 && c <= 0x39;
	}

	function parseValue(): unknown {
		if (pos >= text.length) throw new JsonSyntaxError("unexpected end of JSON input");
		const c = text.charCodeAt(pos);
		if (c === 0x7b) return parseObject();
		if (c === 0x5b) return parseArray();
		if (c === 0x22) return parseString();
		if (c === 0x74) return parseLiteral("true", true);
		if (c === 0x66) return parseLiteral("false", false);
		if (c === 0x6e) return parseLiteral("null", null);
		if (c === 0x2d || isDigit(c)) return parseNumber();
		throw new JsonSyntaxError("unexpected character in JSON input");
	}

	function parseLiteral(word: string, value: unknown): unknown {
		if (text.slice(pos, pos + word.length) !== word) throw new JsonSyntaxError("invalid JSON literal");
		pos += word.length;
		return value;
	}

	function parseObject(): Record<string, unknown> {
		pos++; // '{'
		const result: Record<string, unknown> = Object.create(null);
		skipWhitespace();
		if (consume("}")) return result;
		for (;;) {
			skipWhitespace();
			if (text.charCodeAt(pos) !== 0x22) throw new JsonSyntaxError("object member name must be a string");
			const key = parseString();
			skipWhitespace();
			if (!consume(":")) throw new JsonSyntaxError("expected ':' after member name");
			skipWhitespace();
			const value = parseValue();
			// spec：在成员被覆盖前检测重复名称，绝不允许最后值覆盖静默通过。
			if (Object.prototype.hasOwnProperty.call(result, key)) throw new JsonSyntaxError("duplicate object member name");
			Object.defineProperty(result, key, { value, enumerable: true, writable: true, configurable: true });
			skipWhitespace();
			if (consume(",")) continue;
			if (consume("}")) return result;
			throw new JsonSyntaxError("expected ',' or '}' in object");
		}
	}

	function parseArray(): unknown[] {
		pos++; // '['
		const result: unknown[] = [];
		skipWhitespace();
		if (consume("]")) return result;
		for (;;) {
			skipWhitespace();
			result.push(parseValue());
			skipWhitespace();
			if (consume(",")) continue;
			if (consume("]")) return result;
			throw new JsonSyntaxError("expected ',' or ']' in array");
		}
	}

	function parseString(): string {
		pos++; // opening quote
		let out = "";
		for (;;) {
			if (pos >= text.length) throw new JsonSyntaxError("unterminated string");
			const c = text.charCodeAt(pos);
			if (c === 0x22) {
				pos++;
				return out;
			}
			if (c === 0x5c) {
				out += parseEscape();
				continue;
			}
			if (c < 0x20) throw new JsonSyntaxError("raw control character in string");
			out += text[pos];
			pos++;
		}
	}

	function parseEscape(): string {
		pos++; // backslash
		const c = text.charCodeAt(pos);
		switch (c) {
			case 0x22:
				pos++;
				return '"';
			case 0x5c:
				pos++;
				return "\\";
			case 0x2f:
				pos++;
				return "/";
			case 0x62:
				pos++;
				return "\b";
			case 0x66:
				pos++;
				return "\f";
			case 0x6e:
				pos++;
				return "\n";
			case 0x72:
				pos++;
				return "\r";
			case 0x74:
				pos++;
				return "\t";
			case 0x75:
				pos++; // past 'u'
				return parseUnicodeEscape();
			default:
				throw new JsonSyntaxError("invalid string escape");
		}
	}

	function hexDigit(c: number): number {
		if (c >= 0x30 && c <= 0x39) return c - 0x30;
		if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
		if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
		return -1;
	}

	function readHex4(): number {
		let value = 0;
		for (let i = 0; i < 4; i++) {
			const digit = hexDigit(text.charCodeAt(pos));
			if (digit < 0) throw new JsonSyntaxError("invalid \\u escape");
			value = value * 16 + digit;
			pos++;
		}
		return value;
	}

	function parseUnicodeEscape(): string {
		const unit = readHex4();
		if (unit >= 0xd800 && unit <= 0xdbff) {
			if (text.charCodeAt(pos) !== 0x5c || text.charCodeAt(pos + 1) !== 0x75) throw new JsonSyntaxError("lone high surrogate");
			pos += 2;
			const low = readHex4();
			if (low < 0xdc00 || low > 0xdfff) throw new JsonSyntaxError("invalid surrogate pair");
			return String.fromCharCode(unit, low);
		}
		if (unit >= 0xdc00 && unit <= 0xdfff) throw new JsonSyntaxError("lone low surrogate");
		return String.fromCharCode(unit);
	}

	function parseNumber(): number {
		const start = pos;
		if (text.charCodeAt(pos) === 0x2d) pos++;
		if (text.charCodeAt(pos) === 0x30) pos++;
		else if (isDigit(text.charCodeAt(pos))) {
			while (isDigit(text.charCodeAt(pos))) pos++;
		} else throw new JsonSyntaxError("invalid number");
		if (text.charCodeAt(pos) === 0x2e) {
			pos++;
			if (!isDigit(text.charCodeAt(pos))) throw new JsonSyntaxError("invalid number fraction");
			while (isDigit(text.charCodeAt(pos))) pos++;
		}
		const exponent = text.charCodeAt(pos);
		if (exponent === 0x65 || exponent === 0x45) {
			pos++;
			const sign = text.charCodeAt(pos);
			if (sign === 0x2b || sign === 0x2d) pos++;
			if (!isDigit(text.charCodeAt(pos))) throw new JsonSyntaxError("invalid number exponent");
			while (isDigit(text.charCodeAt(pos))) pos++;
		}
		const token = text.slice(start, pos);
		const value = Number(token);
		if (!Number.isFinite(value)) throw new JsonSyntaxError("number exceeds IEEE 754 double range");
		return value;
	}
}

// ---------------------------------------------------------------------------
// 布局常量与类型（iweb-wasm-oci-layout-v1）
// ---------------------------------------------------------------------------

export const WASM_OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";
export const WASM_CONFIG_MEDIA_TYPE = "application/vnd.iweb.wasm.config.v1+json";
export const WASM_COMPONENT_LAYER_MEDIA_TYPE = "application/vnd.iweb.wasm.component.v1+wasm";
export const WASM_CORE_MODULE_LAYER_MEDIA_TYPE = "application/vnd.iweb.wasm.core-module.v1+wasm";
export const WASM_ADAPTER_LAYER_MEDIA_TYPE = "application/vnd.iweb.wasm.adapter.v1+wasm";
export const WASM_LAYER_MEDIA_TYPES: readonly string[] = [WASM_COMPONENT_LAYER_MEDIA_TYPE, WASM_CORE_MODULE_LAYER_MEDIA_TYPE, WASM_ADAPTER_LAYER_MEDIA_TYPE];

export const WASM_OCI_ABSOLUTE_MAX_BLOB_BYTES = 134217728;
export const WASM_OCI_MAX_PACKAGE_BYTES = 536870912;
export const WASM_OCI_MAX_LAYER_COUNT = 128;

// NodeCapabilityRecordV1 的 admission 子集；所有 size 比较都以原始字节为单位。
export interface WasmAdmissionBounds {
	readonly maxPackageBytes: number;
	readonly maxBlobBytes: number;
	readonly maxLayerCount: number;
}

export const DEFAULT_WASM_ADMISSION_BOUNDS: WasmAdmissionBounds = {
	maxPackageBytes: WASM_OCI_MAX_PACKAGE_BYTES,
	maxBlobBytes: WASM_OCI_ABSOLUTE_MAX_BLOB_BYTES,
	maxLayerCount: WASM_OCI_MAX_LAYER_COUNT,
};

export interface WasmOciDescriptor {
	readonly mediaType: string;
	readonly digest: string;
	readonly size: number;
}

export interface WasmOciManifest {
	readonly schemaVersion: 2;
	readonly config: WasmOciDescriptor;
	readonly layers: readonly WasmOciDescriptor[];
}

export interface WasmImportCapability {
	readonly package: string;
	readonly interface: string;
	readonly direction: "import";
}

export interface WasmConfigV1 {
	readonly schemaVersion: 1;
	readonly kind: "wasm";
	readonly entryLayerDigest: string;
	readonly world: typeof WASM_WORLD_LITERAL;
	readonly hostABI: typeof WASM_HOST_ABI_LITERAL;
	readonly declaredHostImports: readonly WasmImportCapability[];
}

export interface ValidatedWasmOciLayout {
	readonly layoutBytes: Uint8Array;
	readonly indexBytes: Uint8Array;
	readonly indexDescriptor: WasmOciDescriptor;
	readonly manifestBytes: Uint8Array;
	readonly manifest: WasmOciManifest;
	readonly configBytes: Uint8Array;
	readonly config: WasmConfigV1;
	readonly layerBytes: readonly Uint8Array[];
	/** referenced blob paths in digest order: manifest, config, then each layer. */
	readonly blobPaths: readonly string[];
}

export interface ValidatedWasmPackage {
	readonly layout: ValidatedWasmOciLayout;
	readonly packageDigest: string;
}

// ---------------------------------------------------------------------------
// 共享小工具
// ---------------------------------------------------------------------------

function requireObject(value: unknown, path: string, noun: string, code: string, errors: ValidationIssue[]): Record<string, unknown> | null {
	if (!isRecord(value)) {
		errors.push(issue(code, path, noun + " must be an object"));
		return null;
	}
	return value;
}

function requireExactKeys(input: Record<string, unknown>, path: string, allowed: readonly string[], code: string, errors: ValidationIssue[]): void {
	for (const key of Object.keys(input)) {
		if (!allowed.includes(key)) errors.push(issue(code, path + "/" + key, "unknown field is not allowed"));
	}
	for (const key of allowed) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(code, path + "/" + key, "required field is missing"));
	}
}

function requireSafeInteger(value: unknown, path: string, fieldName: string, minimum: number, maximum: number, code: string, errors: ValidationIssue[]): number | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be an integer between " + minimum + " and " + maximum));
		return null;
	}
	return value;
}

function requireOciSha256(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_OCI_SHA256_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be sha256: plus 64 lower-case hex characters"));
		return null;
	}
	return value;
}

function requireStringLiteral(value: unknown, path: string, fieldName: string, literal: string, code: string, errors: ValidationIssue[]): string | null {
	if (value !== literal) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + ' must be exactly "' + literal + '"'));
		return null;
	}
	return literal;
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

function parseCanonicalJson(bytes: Uint8Array, path: string, errors: ValidationIssue[]): unknown | null {
	// spec：所有被称为 JCS 的原始 JSON 文件必须字节等于 JCS(JSON.parse(file))，
	// 而不是"解析后等价"。解析失败（含重复成员）与"可解析但非 JCS"是两种不同错误。
	let text: string;
	try {
		text = utf8Decoder.decode(bytes);
	} catch {
		errors.push(issue("WASM_OCI_JSON_INVALID", path, "file bytes are not valid UTF-8"));
		return null;
	}
	const parsed = parseStrictJson(text);
	if (!parsed.ok) {
		errors.push(issue("WASM_OCI_JSON_INVALID", path, parsed.error));
		return null;
	}
	try {
		if (Buffer.compare(asBuffer(jcsCanonicalBytes(parsed.value)), asBuffer(bytes)) !== 0) {
			errors.push(issue("WASM_OCI_NON_CANONICAL_JSON", path, "raw bytes must equal JCS(JSON.parse(bytes))"));
			return null;
		}
	} catch {
		errors.push(issue("WASM_OCI_JSON_INVALID", path, "parsed value cannot be canonicalized as JCS"));
		return null;
	}
	return parsed.value;
}

// ---------------------------------------------------------------------------
// ImportCapability / config / 归一化 admission manifest
// ---------------------------------------------------------------------------

// WIT package identity：namespace:name@major.minor.patch，全小写。
// 版本号按 semver 惯例拒绝前导零（保守 fail-closed；spec 未写明前导零，见文件末尾备注）。
const WIT_PACKAGE_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*:[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*@(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const WIT_INTERFACE_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*$/;

function compareImportCapabilities(left: WasmImportCapability, right: WasmImportCapability): number {
	// 规范排序键：(package, interface, direction) 的 UTF-8 字节序。
	const byPackage = compareUtf8Bytes(left.package, right.package);
	if (byPackage !== 0) return byPackage;
	const byInterface = compareUtf8Bytes(left.interface, right.interface);
	if (byInterface !== 0) return byInterface;
	return compareUtf8Bytes(left.direction, right.direction);
}

export function validateDeclaredHostImports(value: unknown, path: string, code: string, errors: ValidationIssue[]): readonly WasmImportCapability[] | null {
	if (!Array.isArray(value)) {
		errors.push(issue(code, path, "declaredHostImports must be an array"));
		return null;
	}
	const list: WasmImportCapability[] = [];
	let valid = true;
	for (let i = 0; i < value.length; i++) {
		const entryPath = path + "/" + i;
		const entry = requireObject(value[i], entryPath, "import capability", code, errors);
		if (entry === null) {
			valid = false;
			continue;
		}
		requireExactKeys(entry, entryPath, ["package", "interface", "direction"], code, errors);
		const packageName = typeof entry.package === "string" && WIT_PACKAGE_PATTERN.test(entry.package) ? entry.package : null;
		if (packageName === null) errors.push(issue(code, entryPath + "/package", "package must be a lower-case WIT namespace:name@major.minor.patch identity"));
		const interfaceName = typeof entry.interface === "string" && WIT_INTERFACE_PATTERN.test(entry.interface) ? entry.interface : null;
		if (interfaceName === null) errors.push(issue(code, entryPath + "/interface", "interface must be a lower-case WIT interface identifier"));
		// declaredHostImports 是组件到宿主的能力集合；direction 只接受字面量 "import"。
		// 根导出（direction:"export"）是另一个独立 typed 形状，不属于该字段。
		if (entry.direction !== "import") errors.push(issue(code, entryPath + "/direction", 'direction must be the literal "import" for a declared host import'));
		if (packageName === null || interfaceName === null || entry.direction !== "import") {
			valid = false;
			continue;
		}
		list.push({ package: packageName, interface: interfaceName, direction: "import" });
	}
	if (!valid) return null;
	for (let i = 1; i < list.length; i++) {
		const comparison = compareImportCapabilities(list[i - 1], list[i]);
		if (comparison === 0) {
			errors.push(issue(code, path, "duplicate (package, interface, direction) key is rejected"));
			return null;
		}
		if (comparison > 0) {
			errors.push(issue(code, path, "declaredHostImports must be sorted by (package, interface, direction) in UTF-8 byte order"));
			return null;
		}
	}
	return list;
}

export function validateWasmConfigV1(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmConfigV1 | null {
	const config = requireObject(input, path, "wasm config", code, errors);
	if (config === null) return null;
	requireExactKeys(config, path, ["schemaVersion", "kind", "entryLayerDigest", "world", "hostABI", "declaredHostImports"], code, errors);
	const schemaVersion = requireSafeInteger(config.schemaVersion, path, "schemaVersion", 1, 1, code, errors);
	const kind = requireStringLiteral(config.kind, path, "kind", "wasm", code, errors);
	const entryLayerDigest = requireOciSha256(config.entryLayerDigest, path, "entryLayerDigest", code, errors);
	const world = requireStringLiteral(config.world, path, "world", WASM_WORLD_LITERAL, code, errors);
	const hostABI = requireStringLiteral(config.hostABI, path, "hostABI", WASM_HOST_ABI_LITERAL, code, errors);
	const declaredHostImports = validateDeclaredHostImports(config.declaredHostImports, path + "/declaredHostImports", code, errors);
	if (schemaVersion === null || kind === null || entryLayerDigest === null || world === null || hostABI === null || declaredHostImports === null) return null;
	return { schemaVersion: 1, kind: "wasm", entryLayerDigest, world: WASM_WORLD_LITERAL, hostABI: WASM_HOST_ABI_LITERAL, declaredHostImports };
}

export interface WasmRuntimeV1 {
	readonly kind: "wasm";
	readonly entryLayerDigest: string;
	readonly world: typeof WASM_WORLD_LITERAL;
	readonly hostABI: typeof WASM_HOST_ABI_LITERAL;
	readonly declaredHostImports: readonly WasmImportCapability[];
}

export interface WasmResourcesV1 {
	readonly cpuMillis: number;
	readonly memoryBytes: number;
	readonly pidLimit: number;
	readonly storageBytes: number;
}

export interface WasmStorageV1 {
	readonly persistent: boolean;
	readonly requestBytes: number;
}

export interface WasmEgressRuleV1 {
	readonly host: string;
	readonly port: number;
}

export interface WasmEgressV1 {
	readonly default: "deny";
	readonly allow: readonly WasmEgressRuleV1[];
}

export interface NormalizedWasmManifestV1 {
	readonly schemaVersion: 1;
	readonly name: string;
	readonly runtime: WasmRuntimeV1;
	readonly resources: WasmResourcesV1;
	readonly storage: WasmStorageV1;
	readonly egress: WasmEgressV1;
}

export const WASM_MAX_EGRESS_RULES = 256;

const MANIFEST_CODE = "WASM_MANIFEST_INVALID";

function validateWasmRuntime(input: unknown, path: string, errors: ValidationIssue[]): WasmRuntimeV1 | null {
	const runtime = requireObject(input, path, "runtime", MANIFEST_CODE, errors);
	if (runtime === null) return null;
	requireExactKeys(runtime, path, ["kind", "entryLayerDigest", "world", "hostABI", "declaredHostImports"], MANIFEST_CODE, errors);
	const kind = requireStringLiteral(runtime.kind, path, "kind", "wasm", MANIFEST_CODE, errors);
	const entryLayerDigest = requireOciSha256(runtime.entryLayerDigest, path, "entryLayerDigest", MANIFEST_CODE, errors);
	const world = requireStringLiteral(runtime.world, path, "world", WASM_WORLD_LITERAL, MANIFEST_CODE, errors);
	const hostABI = requireStringLiteral(runtime.hostABI, path, "hostABI", WASM_HOST_ABI_LITERAL, MANIFEST_CODE, errors);
	const declaredHostImports = validateDeclaredHostImports(runtime.declaredHostImports, path + "/declaredHostImports", MANIFEST_CODE, errors);
	if (kind === null || entryLayerDigest === null || world === null || hostABI === null || declaredHostImports === null) return null;
	return { kind: "wasm", entryLayerDigest, world: WASM_WORLD_LITERAL, hostABI: WASM_HOST_ABI_LITERAL, declaredHostImports };
}

function validateWasmResources(input: unknown, path: string, errors: ValidationIssue[]): WasmResourcesV1 | null {
	const resources = requireObject(input, path, "resources", MANIFEST_CODE, errors);
	if (resources === null) return null;
	requireExactKeys(resources, path, ["cpuMillis", "memoryBytes", "pidLimit", "storageBytes"], MANIFEST_CODE, errors);
	const cpuMillis = requireSafeInteger(resources.cpuMillis, path, "cpuMillis", 1, 1000000, MANIFEST_CODE, errors);
	const memoryBytes = requireSafeInteger(resources.memoryBytes, path, "memoryBytes", 1, 68719476736, MANIFEST_CODE, errors);
	const pidLimit = requireSafeInteger(resources.pidLimit, path, "pidLimit", 1, 1000000, MANIFEST_CODE, errors);
	const storageBytes = requireSafeInteger(resources.storageBytes, path, "storageBytes", 0, 1099511627776, MANIFEST_CODE, errors);
	if (cpuMillis === null || memoryBytes === null || pidLimit === null || storageBytes === null) return null;
	return { cpuMillis, memoryBytes, pidLimit, storageBytes };
}

function validateWasmStorage(input: unknown, path: string, errors: ValidationIssue[]): WasmStorageV1 | null {
	const storage = requireObject(input, path, "storage", MANIFEST_CODE, errors);
	if (storage === null) return null;
	requireExactKeys(storage, path, ["persistent", "requestBytes"], MANIFEST_CODE, errors);
	if (typeof storage.persistent !== "boolean") {
		errors.push(issue(MANIFEST_CODE, path + "/persistent", "persistent must be a boolean"));
		return null;
	}
	const requestBytes = requireSafeInteger(storage.requestBytes, path, "requestBytes", 0, 1099511627776, MANIFEST_CODE, errors);
	if (requestBytes === null) return null;
	return { persistent: storage.persistent, requestBytes };
}

function validateWasmEgress(input: unknown, path: string, errors: ValidationIssue[]): WasmEgressV1 | null {
	const egress = requireObject(input, path, "egress", MANIFEST_CODE, errors);
	if (egress === null) return null;
	requireExactKeys(egress, path, ["default", "allow"], MANIFEST_CODE, errors);
	const fallback = requireStringLiteral(egress.default, path, "default", "deny", MANIFEST_CODE, errors);
	if (!Array.isArray(egress.allow)) {
		errors.push(issue(MANIFEST_CODE, path + "/allow", "allow must be an array"));
		return null;
	}
	if (egress.allow.length > WASM_MAX_EGRESS_RULES) {
		errors.push(issue(MANIFEST_CODE, path + "/allow", "allow must have at most " + WASM_MAX_EGRESS_RULES + " items"));
		return null;
	}
	const allow: WasmEgressRuleV1[] = [];
	for (let i = 0; i < egress.allow.length; i++) {
		const entryPath = path + "/allow/" + i;
		const entry = requireObject(egress.allow[i], entryPath, "egress rule", MANIFEST_CODE, errors);
		if (entry === null) return null;
		requireExactKeys(entry, entryPath, ["host", "port"], MANIFEST_CODE, errors);
		const host = validateDnsName(entry.host, entryPath, "host", errors);
		const port = requireSafeInteger(entry.port, entryPath, "port", 1, 65535, MANIFEST_CODE, errors);
		if (host === null || port === null) return null;
		allow.push({ host, port });
	}
	for (let i = 1; i < allow.length; i++) {
		const previous = allow[i - 1];
		const current = allow[i];
		const byHost = compareUtf8Bytes(previous.host, current.host);
		if (byHost > 0 || (byHost === 0 && previous.port >= current.port)) {
			errors.push(issue(MANIFEST_CODE, path + "/allow", "allow must be sorted by (host, port) with no duplicate pair"));
			return null;
		}
	}
	if (fallback === null) return null;
	return { default: "deny", allow };
}

export function validateNormalizedWasmManifestV1(input: unknown): ValidationResult<NormalizedWasmManifestV1> {
	const errors: ValidationIssue[] = [];
	const manifest = requireObject(input, "", "normalized wasm manifest", MANIFEST_CODE, errors);
	if (manifest === null) return failure(errors);
	requireExactKeys(manifest, "", ["schemaVersion", "name", "runtime", "resources", "storage", "egress"], MANIFEST_CODE, errors);
	requireSafeInteger(manifest.schemaVersion, "", "schemaVersion", 1, 1, MANIFEST_CODE, errors);
	if (typeof manifest.name !== "string" || !WASM_APPLICATION_ID_PATTERN.test(manifest.name)) {
		errors.push(issue(MANIFEST_CODE, "/name", "name must be a lower-case application identifier of at most 63 ASCII bytes"));
	}
	const runtime = validateWasmRuntime(manifest.runtime, "/runtime", errors);
	const resources = validateWasmResources(manifest.resources, "/resources", errors);
	const storage = validateWasmStorage(manifest.storage, "/storage", errors);
	const egress = validateWasmEgress(manifest.egress, "/egress", errors);
	if (resources !== null && storage !== null && storage.requestBytes > resources.storageBytes) {
		errors.push(issue(MANIFEST_CODE, "/storage/requestBytes", "storage.requestBytes must be <= resources.storageBytes"));
	}
	if (errors.length) return failure(errors);
	return ok({
		schemaVersion: 1,
		name: manifest.name as string,
		runtime: runtime as WasmRuntimeV1,
		resources: resources as WasmResourcesV1,
		storage: storage as WasmStorageV1,
		egress: egress as WasmEgressV1,
	});
}

// ConfigRuntimeProjectionV1(config)：JCS({"kind",...,"declaredHostImports"})，
// schemaVersion 是 config wrapper 的 revision，刻意不进入 projection。
export function wasmConfigRuntimeProjectionJcsBytes(config: WasmConfigV1): Uint8Array {
	return jcsCanonicalBytes({
		kind: config.kind,
		entryLayerDigest: config.entryLayerDigest,
		world: config.world,
		hostABI: config.hostABI,
		declaredHostImports: config.declaredHostImports,
	});
}

export function validateWasmAdmissionConsistency(config: WasmConfigV1, manifest: NormalizedWasmManifestV1): ValidationResult<true> {
	const projection = asBuffer(wasmConfigRuntimeProjectionJcsBytes(config));
	const runtimeBytes = asBuffer(jcsCanonicalBytes(manifest.runtime));
	if (Buffer.compare(projection, runtimeBytes) !== 0) {
		return failure([issue("WASM_CONFIG_MANIFEST_MISMATCH", "/runtime", "ConfigRuntimeProjectionV1(config) must be byte-for-byte equal to JCS(normalizedManifest.runtime)")]);
	}
	return ok(true);
}

// ---------------------------------------------------------------------------
// iweb-wasm-oci-layout-v1 校验
// ---------------------------------------------------------------------------

export function validateWasmAdmissionBounds(input: WasmAdmissionBounds): ValidationResult<WasmAdmissionBounds> {
	const errors: ValidationIssue[] = [];
	requireSafeIntegerObject(input, "maxPackageBytes", 1, WASM_OCI_MAX_PACKAGE_BYTES, errors);
	requireSafeIntegerObject(input, "maxBlobBytes", 1, WASM_OCI_ABSOLUTE_MAX_BLOB_BYTES, errors);
	requireSafeIntegerObject(input, "maxLayerCount", 1, WASM_OCI_MAX_LAYER_COUNT, errors);
	if (errors.length) return failure(errors);
	return ok(input);
}

function requireSafeIntegerObject(bounds: WasmAdmissionBounds, field: keyof WasmAdmissionBounds, minimum: number, maximum: number, errors: ValidationIssue[]): void {
	const value = bounds[field];
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
		errors.push(issue("WASM_ADMISSION_BOUNDS_INVALID", "/bounds/" + field, field + " must be an integer between " + minimum + " and " + maximum));
	}
}

const BLOB_PATH_PATTERN = /^blobs\/sha256\/([0-9a-f]{64})$/;

function blobPathFor(digest: string): string {
	return "blobs/sha256/" + digest.slice("sha256:".length);
}

interface DescriptorCheck {
	readonly descriptor: WasmOciDescriptor;
	readonly bytes: Uint8Array;
}

function verifyBlobBytes(check: DescriptorCheck, path: string, effectiveBlobMax: number, errors: ValidationIssue[]): boolean {
	if (check.descriptor.size === 0 || check.bytes.length === 0) {
		// spec scenario：layer 为零字节属于空 artifact。
		errors.push(issue("WASM_OCI_EMPTY_ARTIFACT", "/" + path, "referenced blob must not be zero bytes"));
		return false;
	}
	if (sha256Hex(check.bytes) !== check.descriptor.digest.slice("sha256:".length)) {
		errors.push(issue("WASM_OCI_DIGEST_MISMATCH", "/" + path, "descriptor digest must equal SHA-256 of the referenced raw bytes"));
		return false;
	}
	if (check.descriptor.size !== check.bytes.length) {
		errors.push(issue("WASM_OCI_SIZE_MISMATCH", "/" + path, "descriptor size must equal the referenced raw byte length"));
		return false;
	}
	if (check.bytes.length > effectiveBlobMax) {
		errors.push(issue("WASM_OCI_SIZE_OUT_OF_RANGE", "/" + path, "referenced blob must be at most " + effectiveBlobMax + " bytes"));
		return false;
	}
	return true;
}

function parseOciDescriptor(input: unknown, path: string, code: string, errors: ValidationIssue[], allowedMediaTypes: readonly string[], minimumSize: number): WasmOciDescriptor | null {
	const descriptor = requireObject(input, path, "descriptor", code, errors);
	if (descriptor === null) return null;
	requireExactKeys(descriptor, path, ["mediaType", "digest", "size"], code, errors);
	if (typeof descriptor.mediaType !== "string" || !allowedMediaTypes.includes(descriptor.mediaType)) {
		errors.push(issue(code, path + "/mediaType", "mediaType must be one of the exact allowed literals"));
	}
	// 下界 0 只为让"layer 为零字节"落到 verifyBlobBytes 的 WASM_OCI_EMPTY_ARTIFACT；
	// index descriptor（唯一 manifest 引用）按 spec 保持下界 1。
	const digest = requireOciSha256(descriptor.digest, path, "digest", code, errors);
	const size = requireSafeInteger(descriptor.size, path, "size", minimumSize, WASM_OCI_ABSOLUTE_MAX_BLOB_BYTES, "WASM_OCI_INTEGER_INVALID", errors);
	if (digest === null || size === null || typeof descriptor.mediaType !== "string" || !allowedMediaTypes.includes(descriptor.mediaType)) return null;
	return { mediaType: descriptor.mediaType, digest, size };
}

export function validateWasmOciLayoutV1(files: ReadonlyMap<string, Uint8Array>, bounds: WasmAdmissionBounds = DEFAULT_WASM_ADMISSION_BOUNDS): ValidationResult<ValidatedWasmPackage> {
	const boundsResult = validateWasmAdmissionBounds(bounds);
	if (!boundsResult.ok) return failure(boundsResult.errors);
	const effectiveBlobMax = Math.min(bounds.maxBlobBytes, WASM_OCI_ABSOLUTE_MAX_BLOB_BYTES);
	const errors: ValidationIssue[] = [];

	// 1. 路径集合必须精确：oci-layout、index.json、blobs/sha256/<64 小写 hex>，无其它路径。
	let layoutBytes: Uint8Array | null = null;
	let indexBytes: Uint8Array | null = null;
	const blobs = new Map<string, Uint8Array>();
	for (const [path, bytes] of files) {
		if (path === "oci-layout") layoutBytes = bytes;
		else if (path === "index.json") indexBytes = bytes;
		else if (BLOB_PATH_PATTERN.test(path)) blobs.set(path, bytes);
		else {
			errors.push(issue("WASM_OCI_LAYOUT_PATH_INVALID", "/" + boundedPath(path), "layout path is not part of iweb-wasm-oci-layout-v1"));
		}
	}
	if (layoutBytes === null) errors.push(issue("WASM_OCI_LAYOUT_FILE_INVALID", "/oci-layout", "oci-layout file is required"));
	if (indexBytes === null) errors.push(issue("WASM_OCI_LAYOUT_FILE_INVALID", "/index.json", "index.json file is required"));
	if (layoutBytes === null || indexBytes === null) return failure(errors);

	// 2. oci-layout 必须字节等于 JCS({"imageLayoutVersion":"1.0.0"})。
	const layoutValue = parseCanonicalJson(layoutBytes, "/oci-layout", errors);
	if (layoutValue === null) return failure(errors);
	if (!isRecord(layoutValue) || Object.keys(layoutValue).length !== 1 || layoutValue.imageLayoutVersion !== "1.0.0") {
		errors.push(issue("WASM_OCI_LAYOUT_FILE_INVALID", "/oci-layout", 'oci-layout must be exactly JCS({"imageLayoutVersion":"1.0.0"})'));
		return failure(errors);
	}

	// 3. index.json：JCS + 精确键集 {schemaVersion, manifests}，恰好一个 descriptor D。
	const indexValue = parseCanonicalJson(indexBytes, "/index.json", errors);
	if (indexValue === null) return failure(errors);
	const index = requireObject(indexValue, "/index.json", "index", "WASM_OCI_INDEX_INVALID", errors);
	if (index === null) return failure(errors);
	requireExactKeys(index, "/index.json", ["schemaVersion", "manifests"], "WASM_OCI_INDEX_INVALID", errors);
	requireSafeInteger(index.schemaVersion, "/index.json", "schemaVersion", 2, 2, "WASM_OCI_INDEX_INVALID", errors);
	if (!Array.isArray(index.manifests) || index.manifests.length !== 1) {
		errors.push(issue("WASM_OCI_INDEX_INVALID", "/index.json/manifests", "manifests must be an array with exactly one descriptor"));
		return failure(errors);
	}
	const indexDescriptor = parseOciDescriptor(index.manifests[0], "/index.json/manifests/0", "WASM_OCI_INDEX_INVALID", errors, [WASM_OCI_MANIFEST_MEDIA_TYPE], 1);
	if (indexDescriptor === null) return failure(errors);

	// 4. 唯一 manifest blob：存在、digest/size/范围校验、JCS、精确键集 {schemaVersion, config, layers}。
	const manifestPath = blobPathFor(indexDescriptor.digest);
	const manifestBytes = blobs.get(manifestPath);
	if (manifestBytes === undefined) {
		errors.push(issue("WASM_OCI_BLOB_MISSING", "/" + manifestPath, "referenced manifest blob is missing"));
		return failure(errors);
	}
	if (!verifyBlobBytes({ descriptor: indexDescriptor, bytes: manifestBytes }, manifestPath, effectiveBlobMax, errors)) return failure(errors);
	const manifestValue = parseCanonicalJson(manifestBytes, "/" + manifestPath, errors);
	if (manifestValue === null) return failure(errors);
	const manifestRecord = requireObject(manifestValue, "/" + manifestPath, "manifest", "WASM_OCI_MANIFEST_INVALID", errors);
	if (manifestRecord === null) return failure(errors);
	requireExactKeys(manifestRecord, "/" + manifestPath, ["schemaVersion", "config", "layers"], "WASM_OCI_MANIFEST_INVALID", errors);
	requireSafeInteger(manifestRecord.schemaVersion, "/" + manifestPath, "schemaVersion", 2, 2, "WASM_OCI_MANIFEST_INVALID", errors);
	const configDescriptor = parseOciDescriptor(manifestRecord.config, "/" + manifestPath + "/config", "WASM_OCI_MANIFEST_INVALID", errors, [WASM_CONFIG_MEDIA_TYPE], 0);
	if (configDescriptor === null) return failure(errors);
	if (!Array.isArray(manifestRecord.layers)) {
		errors.push(issue("WASM_OCI_MANIFEST_INVALID", "/" + manifestPath + "/layers", "layers must be an array"));
		return failure(errors);
	}
	if (manifestRecord.layers.length === 0) {
		// spec scenario：manifest 无 layer 属于空 artifact。
		errors.push(issue("WASM_OCI_EMPTY_ARTIFACT", "/" + manifestPath + "/layers", "layers must not be empty"));
		return failure(errors);
	}
	if (manifestRecord.layers.length > bounds.maxLayerCount) {
		errors.push(issue("WASM_OCI_LAYER_COUNT_INVALID", "/" + manifestPath + "/layers", "layers must have at most " + bounds.maxLayerCount + " items"));
		return failure(errors);
	}
	const layerDescriptors: WasmOciDescriptor[] = [];
	for (let i = 0; i < manifestRecord.layers.length; i++) {
		const descriptor = parseOciDescriptor(manifestRecord.layers[i], "/" + manifestPath + "/layers/" + i, "WASM_OCI_MANIFEST_INVALID", errors, WASM_LAYER_MEDIA_TYPES, 0);
		if (descriptor === null) return failure(errors);
		layerDescriptors.push(descriptor);
	}

	// 5. config blob：存在、digest/size/范围校验、JCS、精确键集。
	const configPath = blobPathFor(configDescriptor.digest);
	const configBytes = blobs.get(configPath);
	if (configBytes === undefined) {
		errors.push(issue("WASM_OCI_BLOB_MISSING", "/" + configPath, "referenced config blob is missing"));
		return failure(errors);
	}
	if (!verifyBlobBytes({ descriptor: configDescriptor, bytes: configBytes }, configPath, effectiveBlobMax, errors)) return failure(errors);
	const configValue = parseCanonicalJson(configBytes, "/" + configPath, errors);
	if (configValue === null) return failure(errors);
	const config = validateWasmConfigV1(configValue, "/" + configPath, "WASM_OCI_CONFIG_INVALID", errors);
	if (config === null) return failure(errors);

	// 6. 每个 layer blob：存在、digest/size/范围校验（二进制角色解码是闭包 scanner 的职责）。
	const layerBytesList: Uint8Array[] = [];
	for (let i = 0; i < layerDescriptors.length; i++) {
		const layerPath = blobPathFor(layerDescriptors[i].digest);
		const layerBytes = blobs.get(layerPath);
		if (layerBytes === undefined) {
			errors.push(issue("WASM_OCI_BLOB_MISSING", "/" + layerPath, "referenced layer blob is missing"));
			return failure(errors);
		}
		if (!verifyBlobBytes({ descriptor: layerDescriptors[i], bytes: layerBytes }, layerPath, effectiveBlobMax, errors)) return failure(errors);
		layerBytesList.push(layerBytes);
	}

	// 7. descriptor digest 两两互异（index-manifest、config、全部 layer）。
	const seenDigests = new Map<string, string>();
	const duplicate = (digest: string, path: string): void => {
		const first = seenDigests.get(digest);
		if (first !== undefined) {
			errors.push(issue("WASM_OCI_DUPLICATE_DIGEST", "/" + path, "descriptor digest already used at /" + first));
			return;
		}
		seenDigests.set(digest, path);
	};
	duplicate(indexDescriptor.digest, manifestPath);
	duplicate(configDescriptor.digest, configPath);
	for (let i = 0; i < layerDescriptors.length; i++) duplicate(layerDescriptors[i].digest, manifestPath + "/layers/" + i);
	if (errors.length) return failure(errors);

	// 8. 不允许从唯一 index descriptor 不可达的 blob。
	const referencedPaths = new Set<string>([manifestPath, configPath, ...layerDescriptors.map((descriptor) => blobPathFor(descriptor.digest))]);
	for (const path of blobs.keys()) {
		if (!referencedPaths.has(path)) {
			errors.push(issue("WASM_OCI_UNREFERENCED_BLOB", "/" + path, "blob is not reachable from the single index descriptor"));
		}
	}
	if (errors.length) return failure(errors);

	// 9. config.entryLayerDigest 必须恰好命名一个 component layer。
	const entryMatches = layerDescriptors.filter((descriptor) => descriptor.digest === config.entryLayerDigest);
	if (entryMatches.length !== 1 || entryMatches[0].mediaType !== WASM_COMPONENT_LAYER_MEDIA_TYPE) {
		errors.push(issue("WASM_OCI_ENTRY_LAYER_INVALID", "/" + configPath + "/entryLayerDigest", "entryLayerDigest must name exactly one component layer"));
		return failure(errors);
	}

	// 10. 整包字节预算：oci-layout + index.json + 全部被引用 blob。
	let totalBytes = layoutBytes.length + indexBytes.length + manifestBytes.length + configBytes.length;
	for (const layerBytes of layerBytesList) totalBytes += layerBytes.length;
	if (totalBytes > bounds.maxPackageBytes) {
		errors.push(issue("WASM_OCI_PACKAGE_TOO_LARGE", "", "complete layout is " + totalBytes + " bytes, exceeding maxPackageBytes " + bounds.maxPackageBytes));
		return failure(errors);
	}

	const layout: ValidatedWasmOciLayout = {
		layoutBytes,
		indexBytes,
		indexDescriptor,
		manifestBytes,
		manifest: { schemaVersion: 2, config: configDescriptor, layers: layerDescriptors },
		configBytes,
		config,
		layerBytes: layerBytesList,
		blobPaths: [manifestPath, configPath, ...layerDescriptors.map((descriptor) => blobPathFor(descriptor.digest))],
	};
	return ok({ layout, packageDigest: computeWasmPackageDigestV1(layout) });
}

function boundedPath(path: string): string {
	return path.length > 120 ? path.slice(0, 120) : path;
}

// ---------------------------------------------------------------------------
// digest 算法（逐字对照 spec；绝不调用 celld versionDigest/packageFilesDigest）
// ---------------------------------------------------------------------------

export function computeWasmPackageDigestV1(layout: ValidatedWasmOciLayout): string {
	const hash = createHash("sha256");
	hash.update("iweb-wasm-package-digest-v1\n");
	hash.update("layout " + sha256Hex(layout.layoutBytes) + " " + layout.layoutBytes.length + "\n");
	hash.update("index " + sha256Hex(layout.indexBytes) + " " + layout.indexBytes.length + "\n");
	hash.update("manifest " + layout.indexDescriptor.mediaType + " " + layout.indexDescriptor.digest + " " + layout.indexDescriptor.size + "\n");
	hash.update("config " + layout.manifest.config.mediaType + " " + layout.manifest.config.digest + " " + layout.manifest.config.size + "\n");
	// OCI layer 顺序是 digest 的一部分；行号 dec(i) 从 0 开始。
	for (let i = 0; i < layout.manifest.layers.length; i++) {
		const layer = layout.manifest.layers[i];
		hash.update("layer " + i + " " + layer.mediaType + " " + layer.digest + " " + layer.size + "\n");
	}
	return hash.digest("hex");
}

export function computeWasmVersionDigestV1(packageDigest: string, admissionManifestJcsBytes: Uint8Array): string {
	const hash = createHash("sha256");
	hash.update("iweb-wasm-version-digest-v1\n");
	hash.update("package " + packageDigest + "\n");
	hash.update("admission-manifest " + admissionManifestJcsBytes.length + "\n");
	hash.update(admissionManifestJcsBytes);
	return hash.digest("hex");
}

export function computeWasmAdmissionProofDigestV1(proof: unknown): string {
	return sha256Hex(Buffer.concat([Buffer.from("iweb-admission-proof-v1\n", "utf8"), asBuffer(jcsCanonicalBytes(proof))]));
}

// ---------------------------------------------------------------------------
// versionId 与 AdmissionProofV1 的 digest 相关字段
// ---------------------------------------------------------------------------

export function composeWasmVersionId(versionDigest: string, sequence: number): string {
	return versionDigest + "-" + sequence;
}

export function parseWasmVersionId(versionId: string): ValidationResult<{ readonly versionDigest: string; readonly sequence: number }> {
	if (!WASM_VERSION_ID_PATTERN.test(versionId)) {
		return failure([issue("WASM_VERSION_ID_INVALID", "/versionId", "versionId must be <64 lower-case hex>-<positive sequence without leading zero>")]);
	}
	const dash = versionId.indexOf("-");
	const versionDigest = versionId.slice(0, dash);
	const sequence = Number(versionId.slice(dash + 1));
	if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > WASM_U53_MAX) {
		return failure([issue("WASM_VERSION_ID_INVALID", "/versionId", "versionId sequence must be a positive u53 integer")]);
	}
	return ok({ versionDigest, sequence });
}

export interface WasmAdmissionProofDigestFields {
	readonly applicationId: string;
	readonly packageDigest: string;
	readonly versionDigest: string;
	readonly sequence: number;
	readonly versionId: string;
	readonly normalizedPolicy: unknown;
}

export interface VerifiedWasmAdmissionProofDigests {
	readonly versionId: string;
	readonly admissionManifestBytes: Uint8Array;
	readonly normalizedPolicy: NormalizedWasmManifestV1;
}

// AdmissionProofV1 的 digest 相关字段的独立复算（完整 proof 校验属于准入事务任务）：
// versionDigest 必须等于 wasmVersionDigestV1(packageDigest, JCS(normalizedPolicy))，
// versionId 必须是 versionDigest 与 sequence 的精确拼接，name 必须等于 applicationId。
export function verifyWasmAdmissionProofDigestFields(input: WasmAdmissionProofDigestFields): ValidationResult<VerifiedWasmAdmissionProofDigests> {
	const errors: ValidationIssue[] = [];
	if (typeof input.applicationId !== "string" || !WASM_APPLICATION_ID_PATTERN.test(input.applicationId)) {
		errors.push(issue("WASM_APPLICATION_ID_INVALID", "/applicationId", "applicationId must be a lower-case application identifier of at most 63 ASCII bytes"));
	}
	if (typeof input.packageDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.packageDigest)) {
		errors.push(issue("INVALID_DIGEST", "/packageDigest", "packageDigest must be a 64-character lower-case hex digest"));
	}
	if (typeof input.versionDigest !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.versionDigest)) {
		errors.push(issue("INVALID_DIGEST", "/versionDigest", "versionDigest must be a 64-character lower-case hex digest"));
	}
	if (typeof input.sequence !== "number" || !Number.isSafeInteger(input.sequence) || input.sequence < 1 || input.sequence > WASM_U53_MAX) {
		errors.push(issue("INVALID_NUMBER", "/sequence", "sequence must be an integer between 1 and " + WASM_U53_MAX));
	}
	if (errors.length) return failure(errors);
	const policy = validateNormalizedWasmManifestV1(input.normalizedPolicy);
	if (!policy.ok) return failure(policy.errors);
	if (policy.value.name !== input.applicationId) {
		errors.push(issue("WASM_APPLICATION_ID_MISMATCH", "/normalizedPolicy/name", "normalizedPolicy.name must exactly equal applicationId"));
		return failure(errors);
	}
	if (input.versionId !== composeWasmVersionId(input.versionDigest, input.sequence) || !WASM_VERSION_ID_PATTERN.test(input.versionId)) {
		errors.push(issue("WASM_VERSION_ID_INVALID", "/versionId", "versionId must be versionDigest + '-' + decimal(sequence)"));
		return failure(errors);
	}
	const admissionManifestBytes = jcsCanonicalBytes(policy.value);
	if (computeWasmVersionDigestV1(input.packageDigest, admissionManifestBytes) !== input.versionDigest) {
		errors.push(issue("WASM_VERSION_DIGEST_MISMATCH", "/versionDigest", "versionDigest must equal wasmVersionDigestV1(packageDigest, JCS(normalizedPolicy))"));
		return failure(errors);
	}
	return ok({ versionId: input.versionId, admissionManifestBytes, normalizedPolicy: policy.value });
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. JCS 键排序按 RFC 8785 的 UTF-16 code unit 序实现；本 capability 全部规范键均为 ASCII，
//    与 spec "UTF-8 bytewise ascending" 的通用排序口径一致，非 ASCII 键仅在两种口径分歧时受影响。
// 2. WIT package 版本号拒绝前导零与任何 pre-release/build 后缀（spec 只给 `major.minor.patch` 且
//    明言"不是 range 或 free-form suffix"）；拒绝是更严格的解释。
// 3. declaredHostImports 内 direction 只接受 "import"；`direction:"export"` 的根导出是另一个
//    typed 形状（capability matrix 任务），不出现在该字段。
// 4. spec 只为 JSON 非规范（NON_CANONICAL_JSON）、未引用 blob、重复 digest、空 artifact 与
//    config↔manifest 不一致命名了稳定错误码；其余拒绝码（WASM_OCI_LAYOUT_PATH_INVALID、
//    WASM_OCI_INDEX_INVALID、WASM_OCI_MANIFEST_INVALID、WASM_OCI_CONFIG_INVALID、
//    WASM_OCI_BLOB_MISSING、WASM_OCI_DIGEST_MISMATCH、WASM_OCI_SIZE_MISMATCH、
//    WASM_OCI_SIZE_OUT_OF_RANGE、WASM_OCI_LAYER_COUNT_INVALID、WASM_OCI_INTEGER_INVALID、
//    WASM_OCI_PACKAGE_TOO_LARGE、WASM_OCI_ENTRY_LAYER_INVALID、WASM_OCI_JSON_INVALID、
//    WASM_MANIFEST_INVALID、WASM_VERSION_ID_INVALID 等）沿用同一命名风格补齐，未覆盖 spec 已命名的码。
