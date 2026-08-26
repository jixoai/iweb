// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.4 契约先行）：runtime catalog 与 node capability record v1 必须先有 unknown-field-rejecting typed schema——catalog hash 自校验、revision 追加 CAS、entry 引用保护、CVE revoke/release/re-delete 与历史 revision 恢复索引，以及 capability record 的精确字段界与按 binding+arch 的 reserve 字节比较；后续宿主代码不得自行解释字段。
// 正交意图：(1) RuntimeCatalogV1 校验/hash/CAS/entry 选择与 revoke；(2) entry 引用保护与 release→delete 状态机及审计对象；(3) CatalogHistoryRecordV1/索引重建/GC 恢复；(4) NodeCapabilityRecordV1 校验/hash/CAS；(5) reserve/pin/ABI fence 纯函数。
// 不可调和原因：五组意图共享同一套 hash/select/reserve 原语且同属 spec「catalog/node record」条款簇，物理拆分会重引入公式权威分歧（已处 5 意图上限）。
// 复用约束：JCS/sha256Hex/名称文法一律复用 wasm-package.ts 与 wasm-execution.ts，矩阵校验复用 wasm-capability.ts；本文件不建第二套编码实现。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//   「Node capability records are canonical revisioned bounds」「Runtime binding and catalog are replayable and revocable」
//   「Catalog history has fixed recovery and deletion records」。
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "./validation.ts";
import { validateWasmCapabilityMatrix, WASM_CAPABILITY_MATRIX_REVISION_1, type WasmCapabilityMatrixV1 } from "./wasm-capability.ts";
import {
	validateRuntimeBindingIdentityV1,
	WASM_ENTRY_KEY_PATTERN,
	WASM_RFC3339_UTC_PATTERN,
	WASM_UUIDV7_PATTERN,
	type RuntimeBindingIdentityV1,
} from "./wasm-execution.ts";
import {
	jcsCanonicalBytes,
	parseWasmVersionId,
	sha256Hex,
	WASM_APPLICATION_ID_PATTERN,
	WASM_HOST_ABI_LITERAL,
	WASM_OCI_SHA256_PATTERN,
	WASM_SHA256_HEX_PATTERN,
	WASM_U53_MAX,
	WASM_VERSION_ID_PATTERN,
	WASM_WORLD_LITERAL,
} from "./wasm-package.ts";

// ---------------------------------------------------------------------------
// 域前缀常量与稳定错误码（spec 域前缀单次 SHA-256；与 wasm-execution.ts 同模式）
// ---------------------------------------------------------------------------

/** `catalogHash = hex(SHA-256(UTF8("iweb-runtime-catalog-v1\n" || JCS(catalog with catalogHash omitted))))`。 */
export const RUNTIME_CATALOG_HASH_DOMAIN = "iweb-runtime-catalog-v1";
/** `recordHash = hex(SHA-256(UTF8("iweb-node-capability-record-v1\n" || JCS(record with recordHash omitted))))`。 */
export const NODE_CAPABILITY_RECORD_HASH_DOMAIN = "iweb-node-capability-record-v1";
/** `recordDigest = hex(SHA-256(UTF8("iweb-catalog-history-v1\n" || JCS(record with recordDigest omitted))))`。 */
export const CATALOG_HISTORY_RECORD_DIGEST_DOMAIN = "iweb-catalog-history-v1";
// spec 未为 index/receipt digest 给出公式；按本 capability 域前缀单次 SHA-256 的统一风格补齐（见文末歧义备注）。
/** `indexDigest`（补充域）：对 index wrapper 去 digest 域后的单次域前缀 SHA-256。 */
export const CATALOG_HISTORY_INDEX_DIGEST_DOMAIN = "iweb-catalog-history-index-v1";
/** `receiptDigest`（补充域）：对 release receipt 去 digest 域后的单次域前缀 SHA-256。 */
export const CATALOG_RELEASE_RECEIPT_DIGEST_DOMAIN = "iweb-catalog-release-receipt-v1";

/** release 保留期下界：`releaseRetentionUntil >= releasedAt + 31536000s`（spec 逐字）。 */
export const CATALOG_RELEASE_RETENTION_SECONDS = 31536000;

// spec 已命名/由 scenario 命名的稳定码。
export const WASM_RESOURCE_RECORD_INVALID = "WASM_RESOURCE_RECORD_INVALID";
export const CATALOG_REVISION_CONFLICT = "CATALOG_REVISION_CONFLICT";
// spec 场景要求的 owner 可见「protected-reference reason」与 revoke/release 阻断码（spec 未逐字命名，按命名风格补齐）。
export const WASM_CATALOG_ENTRY_PROTECTED = "WASM_CATALOG_ENTRY_PROTECTED";
export const WASM_CATALOG_ENTRY_NOT_FOUND = "WASM_CATALOG_ENTRY_NOT_FOUND";
export const WASM_RUNTIME_BINDING_REVOKED = "WASM_RUNTIME_BINDING_REVOKED";
export const WASM_RUNTIME_BINDING_RELEASED = "WASM_RUNTIME_BINDING_RELEASED";
export const WASM_CAPABILITY_REVISION_CONFLICT = "WASM_CAPABILITY_REVISION_CONFLICT";

// 结构性拒绝码（沿用 wasm-package/wasm-execution 的命名风格补齐，不覆盖 spec 已命名码）。
const CATALOG_CODE = "WASM_CATALOG_INVALID";
const WASM_CATALOG_DIGEST_MISMATCH = "WASM_CATALOG_DIGEST_MISMATCH";
const WASM_CATALOG_BINDING_MISMATCH = "WASM_CATALOG_BINDING_MISMATCH";
const WASM_CATALOG_ENTRY_ALREADY_REVOKED = "WASM_CATALOG_ENTRY_ALREADY_REVOKED";
const WASM_CATALOG_REVOCATION_REGRESSION = "WASM_CATALOG_REVOCATION_REGRESSION";
const ROLLBACK_CODE = "WASM_ROLLBACK_RECORD_INVALID";
const HISTORY_CODE = "WASM_CATALOG_HISTORY_INVALID";
const WASM_CATALOG_HISTORY_DIGEST_MISMATCH = "WASM_CATALOG_HISTORY_DIGEST_MISMATCH";
const INDEX_CODE = "WASM_CATALOG_INDEX_INVALID";
const WASM_CATALOG_INDEX_DIGEST_MISMATCH = "WASM_CATALOG_INDEX_DIGEST_MISMATCH";
const RELEASE_CODE = "CATALOG_RELEASE_INVALID";
const CATALOG_RELEASE_RECEIPT_DIGEST_MISMATCH = "CATALOG_RELEASE_RECEIPT_DIGEST_MISMATCH";
const CATALOG_RELEASE_RECEIPT_MISMATCH = "CATALOG_RELEASE_RECEIPT_MISMATCH";
const CATALOG_RELEASE_RETENTION_ACTIVE = "CATALOG_RELEASE_RETENTION_ACTIVE";
const DELETE_AUDIT_CODE = "CATALOG_DELETE_AUDIT_INVALID";
const CAPABILITY_CODE = "WASM_NODE_CAPABILITY_INVALID";
const WASM_NODE_CAPABILITY_DIGEST_MISMATCH = "WASM_NODE_CAPABILITY_DIGEST_MISMATCH";
const WASM_CAPABILITY_PIN_MISMATCH = "WASM_CAPABILITY_PIN_MISMATCH";
const WASM_POLICY_MAXIMA_EXCEEDED = "WASM_POLICY_MAXIMA_EXCEEDED";
// 与 wasm-capability.ts 错误码表同文的两个码（矩阵 world/ABI fence 复用，不另造）。
const WASM_WORLD_UNSUPPORTED = "WASM_WORLD_UNSUPPORTED";
const WASM_HOST_ABI_MISMATCH = "WASM_HOST_ABI_MISMATCH";

// ---------------------------------------------------------------------------
// 共享小工具（与 wasm-execution.ts 同款私有实现；编码语义唯一权威在 wasm-package.ts）
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

function requireSha256Hex(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_SHA256_HEX_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be a 64-character lower-case hex digest"));
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

function requireStringUnion(value: unknown, path: string, fieldName: string, allowed: readonly string[], code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be one of: " + allowed.join(", ")));
		return null;
	}
	return value;
}

function requireUuidV7(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_UUIDV7_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be a lower-case UUIDv7"));
		return null;
	}
	return value;
}

function requireRfc3339Utc(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_RFC3339_UTC_PATTERN.test(value) || Number.isNaN(Date.parse(value))) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be an RFC3339 UTC timestamp ending in Z"));
		return null;
	}
	return value;
}

function requireWasmVersionId(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_VERSION_ID_PATTERN.test(value) || !parseWasmVersionId(value).ok) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be <64 lower-case hex>-<positive sequence without leading zero>"));
		return null;
	}
	return value;
}

function compareUtf8Bytes(left: string, right: string): number {
	return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function domainPrefixedDigest(domain: string, payload: Uint8Array): string {
	return sha256Hex(Buffer.concat([Buffer.from(domain + "\n", "utf8"), payload]));
}

// 已验证值域上的结构相等性以 JCS 字节为准（不引入第二套 deep-equal 语义）。
function jcsEqual(left: unknown, right: unknown): boolean {
	return Buffer.compare(Buffer.from(jcsCanonicalBytes(left)), Buffer.from(jcsCanonicalBytes(right))) === 0;
}

// ---------------------------------------------------------------------------
// RuntimeCatalogV1：typed record、hash、entry 选择、revision CAS、revoke
// ---------------------------------------------------------------------------

export const WASM_RUNTIME_ARCHITECTURES = ["linux/amd64", "linux/arm64"] as const;
export type WasmRuntimeArchitecture = (typeof WASM_RUNTIME_ARCHITECTURES)[number];

// spec `cve matches CVE-YYYY-NNNN...`：年份 4 位、序号至少 4 位十进制（补充文法，见文末备注）。
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;
// spec `reasonCode is a bounded opaque lower-case identifier`（补充文法，与 entryKey 同风格）。
const REVOCATION_REASON_CODE_PATTERN = /^[a-z][a-z0-9.-]{0,63}$/;
export const WASM_CATALOG_MAX_ENTRIES = 128;

export interface RuntimeCatalogRevocationV1 {
	readonly cve: string;
	readonly reasonCode: string;
	readonly revokedAt: string;
}

export type RuntimeCatalogEntryV1 =
	| {
			readonly entryKey: string;
			readonly kind: "wasm";
			readonly imageDigest: string;
			readonly hostABI: typeof WASM_HOST_ABI_LITERAL;
			readonly world: typeof WASM_WORLD_LITERAL;
			readonly architecture: WasmRuntimeArchitecture;
			readonly status: "active";
	  }
	| {
			readonly entryKey: string;
			readonly kind: "wasm";
			readonly imageDigest: string;
			readonly hostABI: typeof WASM_HOST_ABI_LITERAL;
			readonly world: typeof WASM_WORLD_LITERAL;
			readonly architecture: WasmRuntimeArchitecture;
			readonly status: "revoked";
			readonly revocation: RuntimeCatalogRevocationV1;
	  };

/** hash 输入对象：catalog 去掉 catalogHash 本身（spec：「it excludes only catalogHash itself」）。 */
export interface RuntimeCatalogPayloadV1 {
	readonly schemaVersion: 1;
	readonly revision: number;
	readonly entries: readonly RuntimeCatalogEntryV1[];
}

export interface RuntimeCatalogV1 extends RuntimeCatalogPayloadV1 {
	readonly catalogHash: string;
}

function requireRuntimeCatalogRevocation(input: unknown, path: string, code: string, errors: ValidationIssue[]): RuntimeCatalogRevocationV1 | null {
	const revocation = requireObject(input, path, "revocation", code, errors);
	if (revocation === null) return null;
	requireExactKeys(revocation, path, ["cve", "reasonCode", "revokedAt"], code, errors);
	const cve = typeof revocation.cve === "string" && CVE_PATTERN.test(revocation.cve) ? revocation.cve : null;
	if (cve === null) errors.push(issue(code, path + "/cve", "cve must match CVE-YYYY-NNNN with a 4-digit year and at least 4 digits"));
	const reasonCode = typeof revocation.reasonCode === "string" && REVOCATION_REASON_CODE_PATTERN.test(revocation.reasonCode) ? revocation.reasonCode : null;
	if (reasonCode === null) errors.push(issue(code, path + "/reasonCode", "reasonCode must be a bounded lower-case opaque identifier"));
	const revokedAt = requireRfc3339Utc(revocation.revokedAt, path, "revokedAt", code, errors);
	if (cve === null || reasonCode === null || revokedAt === null || errors.length) return null;
	return { cve, reasonCode, revokedAt };
}

function requireRuntimeCatalogEntry(input: unknown, path: string, errors: ValidationIssue[]): RuntimeCatalogEntryV1 | null {
	const entry = requireObject(input, path, "catalog entry", CATALOG_CODE, errors);
	if (entry === null) return null;
	const baseKeys = ["entryKey", "kind", "imageDigest", "hostABI", "world", "architecture", "status"];
	// revocation 是唯一可选成员：未知字段一律拒绝，active 携带 revocation 同样拒绝。
	for (const key of Object.keys(entry)) {
		if (key !== "revocation" && !baseKeys.includes(key)) errors.push(issue(CATALOG_CODE, path + "/" + key, "unknown field is not allowed"));
	}
	for (const key of baseKeys) {
		if (!Object.prototype.hasOwnProperty.call(entry, key)) errors.push(issue(CATALOG_CODE, path + "/" + key, "required field is missing"));
	}
	const entryKey = typeof entry.entryKey === "string" && WASM_ENTRY_KEY_PATTERN.test(entry.entryKey) ? entry.entryKey : null;
	if (entryKey === null) errors.push(issue(CATALOG_CODE, path + "/entryKey", "entryKey must match ^[a-z][a-z0-9.-]{0,63}$"));
	const kind = requireStringLiteral(entry.kind, path, "kind", "wasm", CATALOG_CODE, errors);
	const imageDigest = requireOciSha256(entry.imageDigest, path, "imageDigest", CATALOG_CODE, errors);
	const hostABI = requireStringLiteral(entry.hostABI, path, "hostABI", WASM_HOST_ABI_LITERAL, CATALOG_CODE, errors);
	const world = requireStringLiteral(entry.world, path, "world", WASM_WORLD_LITERAL, CATALOG_CODE, errors);
	const architecture = requireStringUnion(entry.architecture, path, "architecture", WASM_RUNTIME_ARCHITECTURES, CATALOG_CODE, errors);
	const status = requireStringUnion(entry.status, path, "status", ["active", "revoked"], CATALOG_CODE, errors);
	if (entryKey === null || kind === null || imageDigest === null || hostABI === null || world === null || architecture === null || status === null) return null;

	if (status === "active") {
		if (Object.prototype.hasOwnProperty.call(entry, "revocation")) {
			errors.push(issue(CATALOG_CODE, path + "/revocation", "a revocation exists exactly when status is revoked"));
			return null;
		}
		return { entryKey, kind: "wasm", imageDigest, hostABI: WASM_HOST_ABI_LITERAL, world: WASM_WORLD_LITERAL, architecture: architecture as WasmRuntimeArchitecture, status: "active" };
	}
	if (!Object.prototype.hasOwnProperty.call(entry, "revocation")) {
		errors.push(issue(CATALOG_CODE, path + "/revocation", "a revoked entry must carry exactly {cve, reasonCode, revokedAt}"));
		return null;
	}
	const revocation = requireRuntimeCatalogRevocation(entry.revocation, path + "/revocation", CATALOG_CODE, errors);
	if (revocation === null) return null;
	return { entryKey, kind: "wasm", imageDigest, hostABI: WASM_HOST_ABI_LITERAL, world: WASM_WORLD_LITERAL, architecture: architecture as WasmRuntimeArchitecture, status: "revoked", revocation };
}

// entries 列表级校验：UTF-8 bytewise 按 entryKey 排序、唯一、至多 128 项。
function requireRuntimeCatalogEntries(input: unknown, path: string, errors: ValidationIssue[]): readonly RuntimeCatalogEntryV1[] | null {
	if (!Array.isArray(input)) {
		errors.push(issue(CATALOG_CODE, path, "entries must be an array"));
		return null;
	}
	if (input.length > WASM_CATALOG_MAX_ENTRIES) {
		errors.push(issue(CATALOG_CODE, path, "entries must have at most " + WASM_CATALOG_MAX_ENTRIES + " items"));
		return null;
	}
	const entries: RuntimeCatalogEntryV1[] = [];
	for (let i = 0; i < input.length; i++) {
		const entry = requireRuntimeCatalogEntry(input[i], path + "/" + i, errors);
		if (entry === null) return null;
		entries.push(entry);
	}
	for (let i = 1; i < entries.length; i++) {
		const comparison = compareUtf8Bytes(entries[i - 1].entryKey, entries[i].entryKey);
		if (comparison === 0) {
			errors.push(issue(CATALOG_CODE, path, "entryKey must be unique; a multi-architecture runtime uses distinct entry keys"));
			return null;
		}
		if (comparison > 0) {
			errors.push(issue(CATALOG_CODE, path, "entries must be sorted by entryKey in UTF-8 byte order"));
			return null;
		}
	}
	return entries;
}

// payload 形状（无 catalogHash）：seal 与 append 的共同入口；调用方提供的 catalogHash 一律拒绝。
function requireRuntimeCatalogPayload(input: unknown, path: string, errors: ValidationIssue[]): RuntimeCatalogPayloadV1 | null {
	const payload = requireObject(input, path, "runtime catalog payload", CATALOG_CODE, errors);
	if (payload === null) return null;
	requireExactKeys(payload, path, ["schemaVersion", "revision", "entries"], CATALOG_CODE, errors);
	const schemaVersion = requireSafeInteger(payload.schemaVersion, path, "schemaVersion", 1, 1, CATALOG_CODE, errors);
	const revision = requireSafeInteger(payload.revision, path, "revision", 1, WASM_U53_MAX, CATALOG_CODE, errors);
	const entries = requireRuntimeCatalogEntries(payload.entries, path + "/entries", errors);
	if (schemaVersion === null || revision === null || entries === null || errors.length) return null;
	return { schemaVersion: 1, revision, entries };
}

/** 计算 `catalogHash`（域前缀单次 SHA-256；输入必须是已通过结构校验的 payload）。 */
export function computeRuntimeCatalogHashV1(payload: RuntimeCatalogPayloadV1): string {
	return domainPrefixedDigest(RUNTIME_CATALOG_HASH_DOMAIN, jcsCanonicalBytes({ schemaVersion: payload.schemaVersion, revision: payload.revision, entries: payload.entries }));
}

/** 校验无 hash 的 payload 并附加计算出的 `catalogHash`（owner append/CAS 的 seal 步骤）。 */
export function sealRuntimeCatalogV1(payload: unknown): ValidationResult<RuntimeCatalogV1> {
	const errors: ValidationIssue[] = [];
	const parsed = requireRuntimeCatalogPayload(payload, "", errors);
	if (parsed === null || errors.length) return failure(errors);
	const catalogHash = computeRuntimeCatalogHashV1(parsed);
	return ok({ schemaVersion: 1, revision: parsed.revision, entries: parsed.entries, catalogHash });
}

/** RuntimeCatalogV1 完整校验：精确键集、entry 文法/排序/唯一、revocation 耦合、hash 复算。 */
export function validateRuntimeCatalogV1(input: unknown): ValidationResult<RuntimeCatalogV1> {
	const errors: ValidationIssue[] = [];
	const record = requireObject(input, "", "runtime catalog", CATALOG_CODE, errors);
	if (record === null) return failure(errors);
	requireExactKeys(record, "", ["schemaVersion", "revision", "catalogHash", "entries"], CATALOG_CODE, errors);
	const catalogHash = requireSha256Hex(record.catalogHash, "", "catalogHash", CATALOG_CODE, errors);
	// payload 校验输入必须是去掉 catalogHash 的干净子集，避免把 digest 字段误判为未知字段。
	const payload = requireRuntimeCatalogPayload({ schemaVersion: record.schemaVersion, revision: record.revision, entries: record.entries }, "", errors);
	if (payload === null || catalogHash === null || errors.length) return failure(errors);
	const expected = computeRuntimeCatalogHashV1(payload);
	if (expected !== catalogHash) {
		errors.push(issue(WASM_CATALOG_DIGEST_MISMATCH, "/catalogHash", "catalogHash must equal hex(SHA-256(UTF8(\"iweb-runtime-catalog-v1\\n\" || JCS(catalog with catalogHash omitted))))"));
		return failure(errors);
	}
	return ok({ schemaVersion: 1, revision: payload.revision, entries: payload.entries, catalogHash });
}

// --- entry 选择：精确五字段相等，无 fallback / range 选择 ---

export interface RuntimeCatalogEntrySelectorV1 {
	readonly entryKey: string;
	readonly imageDigest: string;
	readonly hostABI: string;
	readonly world: string;
	readonly architecture: WasmRuntimeArchitecture;
}

/** 按 `(entryKey, architecture, imageDigest, hostABI, world)` 精确相等选择唯一 entry；无 fallback。 */
export function selectRuntimeCatalogEntry(catalog: RuntimeCatalogV1, selector: RuntimeCatalogEntrySelectorV1): ValidationResult<RuntimeCatalogEntryV1> {
	for (const entry of catalog.entries) {
		if (
			entry.entryKey === selector.entryKey &&
			entry.architecture === selector.architecture &&
			entry.imageDigest === selector.imageDigest &&
			entry.hostABI === selector.hostABI &&
			entry.world === selector.world
		) {
			return ok(entry);
		}
	}
	return failure([issue(WASM_CATALOG_ENTRY_NOT_FOUND, "/entries", "no catalog entry matches the exact (entryKey, architecture, imageDigest, hostABI, world) selector; no fallback or range selection exists")]);
}

/** binding 必须钉住当前 catalog revision/hash，再按其五字段精确选择 entry（「a binding not equal to the selected entry/revision/hash ... fails closed」）。 */
export function selectRuntimeBindingEntry(catalog: RuntimeCatalogV1, runtimeBinding: RuntimeBindingIdentityV1, architecture: WasmRuntimeArchitecture): ValidationResult<RuntimeCatalogEntryV1> {
	if (runtimeBinding.catalogRevision !== catalog.revision || runtimeBinding.catalogHash !== catalog.catalogHash) {
		return failure([issue(WASM_CATALOG_BINDING_MISMATCH, "/runtimeBinding", "the runtime binding must pin the selected catalog revision and hash exactly")]);
	}
	return selectRuntimeCatalogEntry(catalog, {
		entryKey: runtimeBinding.entryKey,
		imageDigest: runtimeBinding.imageDigest,
		hostABI: runtimeBinding.hostABI,
		world: runtimeBinding.world,
		architecture,
	});
}

/** 新 prepare/activation/rebind/rollback 的统一可用性 fence：pin 匹配 + entry 精确命中 + 未 revoked。 */
export function checkRuntimeBindingUsable(catalog: RuntimeCatalogV1, runtimeBinding: RuntimeBindingIdentityV1, architecture: WasmRuntimeArchitecture): ValidationResult<RuntimeCatalogEntryV1> {
	const selected = selectRuntimeBindingEntry(catalog, runtimeBinding, architecture);
	if (!selected.ok) return selected;
	if (selected.value.status === "revoked") {
		return failure([issue(WASM_RUNTIME_BINDING_REVOKED, "/entries", "revocation immediately rejects new prepare, activation, rebind, and rollback using that binding")]);
	}
	return selected;
}

// --- revision 追加 CAS + owner 更新协议 ---

export interface RuntimeCatalogRevisionPinV1 {
	readonly revision: number;
	readonly catalogHash: string;
}

function requireRevisionPin(pin: RuntimeCatalogRevisionPinV1, code: string, errors: ValidationIssue[]): void {
	if (typeof pin.revision !== "number" || !Number.isSafeInteger(pin.revision) || pin.revision < 1 || pin.revision > WASM_U53_MAX) {
		errors.push(issue(code, "/expected/revision", "expected catalog revision must be a u53 integer >= 1"));
	}
	if (typeof pin.catalogHash !== "string" || !WASM_SHA256_HEX_PATTERN.test(pin.catalogHash)) {
		errors.push(issue(code, "/expected/catalogHash", "expected catalogHash must be a 64-character lower-case hex digest"));
	}
}

/** 引用集合 → 受保护 entryKey 集合（active 版本 / ready/preparing 候选 / 保留 rollback 目标）。 */
export function protectedRuntimeCatalogEntryKeys(references: readonly WasmCatalogEntryReferenceV1[]): ReadonlySet<string> {
	const keys = new Set<string>();
	for (const reference of references) keys.add(reference.runtimeBinding.entryKey);
	return keys;
}

/**
 * owner 更新协议（纯函数）：expected `(revision, catalogHash)` CAS + `next.revision = current.revision + 1` +
 * 结构校验 + 受保护 entry 禁删 + revoke 单向性，最后原子「追加」密封新 revision。
 * 注意：origin 检查（必须 owner 发起、拒绝 supervisor 来源）属宿主授权层，纯函数不感知来源。
 */
export function appendRuntimeCatalogRevision(
	current: RuntimeCatalogV1,
	expected: RuntimeCatalogRevisionPinV1,
	next: unknown,
	references: readonly WasmCatalogEntryReferenceV1[] = [],
): ValidationResult<RuntimeCatalogV1> {
	const errors: ValidationIssue[] = [];
	requireRevisionPin(expected, CATALOG_CODE, errors);
	if (errors.length) return failure(errors);
	// stale CAS：expected 必须逐字等于当前持久化 revision/hash。
	if (expected.revision !== current.revision || expected.catalogHash !== current.catalogHash) {
		return failure([issue(CATALOG_REVISION_CONFLICT, "/expected", "stale expected (revision, catalogHash); the append writes nothing and no binding is silently rebound")]);
	}
	const payload = requireRuntimeCatalogPayload(next, "", errors);
	if (payload === null || errors.length) return failure(errors);
	if (payload.revision !== current.revision + 1) {
		return failure([issue(CATALOG_REVISION_CONFLICT, "/revision", "the next catalog revision must equal current.revision + 1")]);
	}
	// 受保护 entry 禁删：active/ready-preparing/rollback 引用的 entryKey 不得从后续 revision 消失。
	const protectedKeys = protectedRuntimeCatalogEntryKeys(references);
	const nextKeys = new Set(payload.entries.map((entry) => entry.entryKey));
	for (const entry of current.entries) {
		if (protectedKeys.has(entry.entryKey) && !nextKeys.has(entry.entryKey)) {
			errors.push(issue(WASM_CATALOG_ENTRY_PROTECTED, "/entries", "entry " + entry.entryKey + " is referenced by an active version, ready/preparing candidate, or retained rollback target and must not be deleted"));
		}
	}
	// revoke 单向性：已 revoked 的 entry 在后续 revision 中必须保持 revoked 且 revocation 逐字段不变。
	for (const previous of current.entries) {
		if (previous.status !== "revoked") continue;
		const nextEntry = payload.entries.find((entry) => entry.entryKey === previous.entryKey);
		if (nextEntry === undefined) continue; // 已由禁删规则覆盖（revoked entry 仍受 rollback 引用保护）。
		if (nextEntry.status !== "revoked" || !jcsEqual(nextEntry.revocation, previous.revocation)) {
			errors.push(issue(WASM_CATALOG_REVOCATION_REGRESSION, "/entries", "a revoked entry must stay revoked with an identical revocation; a released or revoked binding cannot be reactivated"));
		}
	}
	if (errors.length) return failure(errors);
	const catalogHash = computeRuntimeCatalogHashV1(payload);
	return ok({ schemaVersion: 1, revision: payload.revision, entries: payload.entries, catalogHash });
}

/**
 * CVE revoke 状态机：追加 `revision + 1`，把既有 entry 标记 `revoked` 并附 `{cve, reasonCode, revokedAt}`；
 * 不删除 entry，历史 revision 保留供 binding replay。
 */
export function revokeRuntimeCatalogEntry(
	current: RuntimeCatalogV1,
	expected: RuntimeCatalogRevisionPinV1,
	entryKey: string,
	revocation: RuntimeCatalogRevocationV1,
): ValidationResult<RuntimeCatalogV1> {
	const errors: ValidationIssue[] = [];
	if (typeof entryKey !== "string" || !WASM_ENTRY_KEY_PATTERN.test(entryKey)) {
		return failure([issue(CATALOG_CODE, "/entryKey", "entryKey must match ^[a-z][a-z0-9.-]{0,63}$")]);
	}
	const validatedRevocation = requireRuntimeCatalogRevocation(revocation, "/revocation", CATALOG_CODE, errors);
	if (validatedRevocation === null || errors.length) return failure(errors);
	const target = current.entries.find((entry) => entry.entryKey === entryKey);
	if (target === undefined) {
		return failure([issue(WASM_CATALOG_ENTRY_NOT_FOUND, "/entries", "revocation names an entry that does not exist in the current revision")]);
	}
	if (target.status === "revoked") {
		return failure([issue(WASM_CATALOG_ENTRY_ALREADY_REVOKED, "/entries", "the entry is already revoked; revocation is one-way")]);
	}
	const entries = current.entries.map((entry) =>
		entry.entryKey === entryKey
			? { ...entry, status: "revoked" as const, revocation: validatedRevocation }
			: entry,
	);
	return appendRuntimeCatalogRevision(current, expected, { schemaVersion: 1, revision: current.revision + 1, entries });
}

// ---------------------------------------------------------------------------
// entry 引用保护：rollback 记录与引用类型
// ---------------------------------------------------------------------------

export type WasmCatalogEntryReferenceKind = "active-version" | "ready-or-preparing-candidate" | "rollback-target";

export interface WasmCatalogEntryReferenceV1 {
	readonly kind: WasmCatalogEntryReferenceKind;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
}

/** spec 定义的 rollback 记录：目标携带完整 binding identity，而非重新解析可变 catalog。 */
export interface WasmRollbackRecordV1 {
	readonly applicationId: string;
	readonly fromVersionId: string;
	readonly toVersionId: string;
	readonly targetRuntimeBinding: RuntimeBindingIdentityV1;
	readonly routeGeneration: number;
	readonly createdAt: string;
	readonly ownerCommandId: string;
}

export function validateWasmRollbackRecordV1(input: unknown): ValidationResult<WasmRollbackRecordV1> {
	const errors: ValidationIssue[] = [];
	const record = requireObject(input, "", "wasm rollback record", ROLLBACK_CODE, errors);
	if (record === null) return failure(errors);
	requireExactKeys(record, "", ["applicationId", "fromVersionId", "toVersionId", "targetRuntimeBinding", "routeGeneration", "createdAt", "ownerCommandId"], ROLLBACK_CODE, errors);
	const applicationId = typeof record.applicationId === "string" && WASM_APPLICATION_ID_PATTERN.test(record.applicationId) ? record.applicationId : null;
	if (applicationId === null) errors.push(issue(ROLLBACK_CODE, "/applicationId", "applicationId must be a lower-case application identifier of at most 63 ASCII bytes"));
	const fromVersionId = requireWasmVersionId(record.fromVersionId, "", "fromVersionId", ROLLBACK_CODE, errors);
	const toVersionId = requireWasmVersionId(record.toVersionId, "", "toVersionId", ROLLBACK_CODE, errors);
	const binding = validateRuntimeBindingIdentityV1(record.targetRuntimeBinding);
	if (!binding.ok) errors.push(...binding.errors);
	const routeGeneration = requireSafeInteger(record.routeGeneration, "", "routeGeneration", 0, WASM_U53_MAX, ROLLBACK_CODE, errors);
	const createdAt = requireRfc3339Utc(record.createdAt, "", "createdAt", ROLLBACK_CODE, errors);
	const ownerCommandId = requireUuidV7(record.ownerCommandId, "", "ownerCommandId", ROLLBACK_CODE, errors);
	if (applicationId === null || fromVersionId === null || toVersionId === null || !binding.ok || routeGeneration === null || createdAt === null || ownerCommandId === null || errors.length) {
		return failure(errors);
	}
	return ok({ applicationId, fromVersionId, toVersionId, targetRuntimeBinding: binding.value, routeGeneration, createdAt, ownerCommandId });
}

/** rollback 记录 → 引用保护输入。 */
export function rollbackRecordReference(record: WasmRollbackRecordV1): WasmCatalogEntryReferenceV1 {
	return { kind: "rollback-target", runtimeBinding: record.targetRuntimeBinding };
}

// ---------------------------------------------------------------------------
// Catalog history：固定路径存储、wrapper 自校验、恢复索引、GC
// ---------------------------------------------------------------------------

export const CATALOG_HISTORY_REVISIONS_DIR = "/data/kernel/runtime-catalog/revisions";
export const CATALOG_HISTORY_INDEX_PATH = "/data/kernel/runtime-catalog/catalog-history-index-v1.json";
export const CATALOG_RELEASE_RECEIPTS_DIR = "/data/kernel/runtime-catalog/release-receipts";
export const CATALOG_DELETE_AUDIT_DIR = "/data/kernel/runtime-catalog/delete-audit";

/** 固定历史文件名 `<revision>-<catalogHash>.json`。 */
export function catalogHistoryRevisionFileName(revision: number, catalogHash: string): string {
	return revision + "-" + catalogHash + ".json";
}

/** 固定历史文件路径 `/data/kernel/runtime-catalog/revisions/<revision>-<catalogHash>.json`。 */
export function catalogHistoryRevisionFilePath(revision: number, catalogHash: string): string {
	return CATALOG_HISTORY_REVISIONS_DIR + "/" + catalogHistoryRevisionFileName(revision, catalogHash);
}

/** release receipt 固定路径 `/data/kernel/runtime-catalog/release-receipts/<releaseId>.json`。 */
export function catalogReleaseReceiptFilePath(releaseId: string): string {
	return CATALOG_RELEASE_RECEIPTS_DIR + "/" + releaseId + ".json";
}

/** delete audit 固定路径 `/data/kernel/runtime-catalog/delete-audit/<deleteId>.json`。 */
export function catalogDeleteAuditFilePath(deleteId: string): string {
	return CATALOG_DELETE_AUDIT_DIR + "/" + deleteId + ".json";
}

export interface CatalogHistoryRecordV1 {
	readonly schemaVersion: 1;
	readonly runtimeKind: "wasm";
	readonly revision: number;
	readonly catalogHash: string;
	readonly catalog: RuntimeCatalogV1;
	readonly storedAt: string;
	readonly recordDigest: string;
}

export type CatalogHistoryRecordPayloadV1 = Omit<CatalogHistoryRecordV1, "recordDigest">;

/** `recordDigest = hex(SHA-256(UTF8("iweb-catalog-history-v1\n" || JCS(record with recordDigest omitted))))`。 */
export function computeCatalogHistoryRecordDigestV1(payload: CatalogHistoryRecordPayloadV1): string {
	return domainPrefixedDigest(
		CATALOG_HISTORY_RECORD_DIGEST_DOMAIN,
		jcsCanonicalBytes({ schemaVersion: payload.schemaVersion, runtimeKind: payload.runtimeKind, revision: payload.revision, catalogHash: payload.catalogHash, catalog: payload.catalog, storedAt: payload.storedAt }),
	);
}

/** 校验 history wrapper payload（不含 recordDigest）并密封。 */
export function sealCatalogHistoryRecordV1(payload: unknown): ValidationResult<CatalogHistoryRecordV1> {
	const errors: ValidationIssue[] = [];
	const record = requireObject(payload, "", "catalog history payload", HISTORY_CODE, errors);
	if (record === null) return failure(errors);
	requireExactKeys(record, "", ["schemaVersion", "runtimeKind", "revision", "catalogHash", "catalog", "storedAt"], HISTORY_CODE, errors);
	const schemaVersion = requireSafeInteger(record.schemaVersion, "", "schemaVersion", 1, 1, HISTORY_CODE, errors);
	const runtimeKind = requireStringLiteral(record.runtimeKind, "", "runtimeKind", "wasm", HISTORY_CODE, errors);
	const revision = requireSafeInteger(record.revision, "", "revision", 1, WASM_U53_MAX, HISTORY_CODE, errors);
	const catalogHash = requireSha256Hex(record.catalogHash, "", "catalogHash", HISTORY_CODE, errors);
	const catalog = validateRuntimeCatalogV1(record.catalog);
	if (!catalog.ok) errors.push(...catalog.errors);
	const storedAt = requireRfc3339Utc(record.storedAt, "", "storedAt", HISTORY_CODE, errors);
	if (schemaVersion === null || runtimeKind === null || revision === null || catalogHash === null || !catalog.ok || storedAt === null || errors.length) return failure(errors);
	// 文件名三元一致：wrapper revision/hash 必须与嵌套 catalog 完全一致。
	if (revision !== catalog.value.revision || catalogHash !== catalog.value.catalogHash) {
		errors.push(issue(HISTORY_CODE, "", "wrapper revision/catalogHash must agree with the nested catalog revision/catalogHash"));
		return failure(errors);
	}
	const sealed = { schemaVersion: 1 as const, runtimeKind: "wasm" as const, revision, catalogHash, catalog: catalog.value, storedAt };
	return ok({ ...sealed, recordDigest: computeCatalogHistoryRecordDigestV1(sealed) });
}

/** CatalogHistoryRecordV1 完整校验：wrapper/catalog/文件名三元一致 + recordDigest 复算。 */
export function validateCatalogHistoryRecordV1(input: unknown): ValidationResult<CatalogHistoryRecordV1> {
	const errors: ValidationIssue[] = [];
	const record = requireObject(input, "", "catalog history record", HISTORY_CODE, errors);
	if (record === null) return failure(errors);
	requireExactKeys(record, "", ["schemaVersion", "runtimeKind", "revision", "catalogHash", "catalog", "storedAt", "recordDigest"], HISTORY_CODE, errors);
	const recordDigest = requireSha256Hex(record.recordDigest, "", "recordDigest", HISTORY_CODE, errors);
	const sealed = sealCatalogHistoryRecordV1({
		schemaVersion: record.schemaVersion,
		runtimeKind: record.runtimeKind,
		revision: record.revision,
		catalogHash: record.catalogHash,
		catalog: record.catalog,
		storedAt: record.storedAt,
	});
	if (!sealed.ok) return failure(sealed.errors);
	if (recordDigest === null) return failure(errors);
	if (sealed.value.recordDigest !== recordDigest) {
		errors.push(issue(WASM_CATALOG_HISTORY_DIGEST_MISMATCH, "/recordDigest", "recordDigest must equal hex(SHA-256(UTF8(\"iweb-catalog-history-v1\\n\" || JCS(record with recordDigest omitted))))"));
		return failure(errors);
	}
	return ok(sealed.value);
}

/** 校验历史文件名与记录内容一致（文件名 revision/hash、wrapper、nested catalog、digest 四方一致）。 */
export function validateCatalogHistoryFileName(fileName: string, record: CatalogHistoryRecordV1): ValidationResult<true> {
	if (fileName !== catalogHistoryRevisionFileName(record.revision, record.catalogHash)) {
		return failure([issue(HISTORY_CODE, "/fileName", "the history file name must be <revision>-<catalogHash>.json and agree with the wrapper and nested catalog")]);
	}
	return ok(true);
}

// --- 恢复索引 ---

export interface CatalogHistoryIndexRevisionEntryV1 {
	readonly revision: number;
	readonly catalogHash: string;
	readonly path: string;
	readonly status: "present" | "deleted";
	readonly protectedReferenceCount: number;
	readonly releaseRetentionUntil: string | null;
	readonly deletedAt: string | null;
}

export interface CatalogHistoryIndexV1 {
	readonly schemaVersion: 1;
	readonly runtimeKind: "wasm";
	readonly currentRevision: number;
	readonly currentHash: string;
	readonly revisions: readonly CatalogHistoryIndexRevisionEntryV1[];
	readonly updatedAt: string;
	readonly indexDigest: string;
}

export type CatalogHistoryIndexPayloadV1 = Omit<CatalogHistoryIndexV1, "indexDigest">;

/** `indexDigest`（补充域公式）：对 index wrapper 去 indexDigest 后的域前缀单次 SHA-256。 */
export function computeCatalogHistoryIndexDigestV1(payload: CatalogHistoryIndexPayloadV1): string {
	return domainPrefixedDigest(
		CATALOG_HISTORY_INDEX_DIGEST_DOMAIN,
		jcsCanonicalBytes({ schemaVersion: payload.schemaVersion, runtimeKind: payload.runtimeKind, currentRevision: payload.currentRevision, currentHash: payload.currentHash, revisions: payload.revisions, updatedAt: payload.updatedAt }),
	);
}

function requireIndexRevisionEntry(input: unknown, path: string, errors: ValidationIssue[]): CatalogHistoryIndexRevisionEntryV1 | null {
	const entry = requireObject(input, path, "catalog history index entry", INDEX_CODE, errors);
	if (entry === null) return null;
	requireExactKeys(entry, path, ["revision", "catalogHash", "path", "status", "protectedReferenceCount", "releaseRetentionUntil", "deletedAt"], INDEX_CODE, errors);
	const revision = requireSafeInteger(entry.revision, path, "revision", 1, WASM_U53_MAX, INDEX_CODE, errors);
	const catalogHash = requireSha256Hex(entry.catalogHash, path, "catalogHash", INDEX_CODE, errors);
	const status = requireStringUnion(entry.status, path, "status", ["present", "deleted"], INDEX_CODE, errors);
	const protectedReferenceCount = requireSafeInteger(entry.protectedReferenceCount, path, "protectedReferenceCount", 0, WASM_U53_MAX, INDEX_CODE, errors);
	let releaseRetentionUntil: string | null = null;
	let retentionParsed = false;
	if (entry.releaseRetentionUntil === null) retentionParsed = true;
	else {
		const parsed = requireRfc3339Utc(entry.releaseRetentionUntil, path, "releaseRetentionUntil", INDEX_CODE, errors);
		if (parsed !== null) {
			releaseRetentionUntil = parsed;
			retentionParsed = true;
		}
	}
	let deletedAt: string | null = null;
	let deletedParsed = false;
	if (entry.deletedAt === null) deletedParsed = true;
	else {
		const parsed = requireRfc3339Utc(entry.deletedAt, path, "deletedAt", INDEX_CODE, errors);
		if (parsed !== null) {
			deletedAt = parsed;
			deletedParsed = true;
		}
	}
	if (revision === null || catalogHash === null || status === null || protectedReferenceCount === null || !retentionParsed || !deletedParsed || errors.length) return null;
	if (typeof entry.path !== "string" || entry.path !== catalogHistoryRevisionFilePath(revision, catalogHash)) {
		errors.push(issue(INDEX_CODE, path + "/path", "path must equal the fixed /data/kernel/runtime-catalog/revisions/<revision>-<catalogHash>.json"));
		return null;
	}
	// status 与 deletedAt 耦合（补充 fail-closed：deleted 必有 deletedAt，present 必无）。
	if (status === "deleted" && deletedAt === null) {
		errors.push(issue(INDEX_CODE, path + "/deletedAt", "a deleted index entry must carry deletedAt"));
		return null;
	}
	if (status === "present" && deletedAt !== null) {
		errors.push(issue(INDEX_CODE, path + "/deletedAt", "a present index entry must carry deletedAt null"));
		return null;
	}
	return { revision, catalogHash, path: entry.path, status: status as "present" | "deleted", protectedReferenceCount, releaseRetentionUntil, deletedAt };
}

/** CatalogHistoryIndexV1 完整校验：排序/唯一、路径公式、current 指向最高 present revision、indexDigest 复算。 */
export function validateCatalogHistoryIndexV1(input: unknown): ValidationResult<CatalogHistoryIndexV1> {
	const errors: ValidationIssue[] = [];
	const index = requireObject(input, "", "catalog history index", INDEX_CODE, errors);
	if (index === null) return failure(errors);
	requireExactKeys(index, "", ["schemaVersion", "runtimeKind", "currentRevision", "currentHash", "revisions", "updatedAt", "indexDigest"], INDEX_CODE, errors);
	const schemaVersion = requireSafeInteger(index.schemaVersion, "", "schemaVersion", 1, 1, INDEX_CODE, errors);
	const runtimeKind = requireStringLiteral(index.runtimeKind, "", "runtimeKind", "wasm", INDEX_CODE, errors);
	const currentRevision = requireSafeInteger(index.currentRevision, "", "currentRevision", 1, WASM_U53_MAX, INDEX_CODE, errors);
	const currentHash = requireSha256Hex(index.currentHash, "", "currentHash", INDEX_CODE, errors);
	const updatedAt = requireRfc3339Utc(index.updatedAt, "", "updatedAt", INDEX_CODE, errors);
	const indexDigest = requireSha256Hex(index.indexDigest, "", "indexDigest", INDEX_CODE, errors);

	let revisions: CatalogHistoryIndexRevisionEntryV1[] | null = null;
	if (Array.isArray(index.revisions)) {
		const entries: CatalogHistoryIndexRevisionEntryV1[] = [];
		let valid = true;
		for (let i = 0; i < index.revisions.length; i++) {
			const entry = requireIndexRevisionEntry(index.revisions[i], "/revisions/" + i, errors);
			if (entry === null) {
				valid = false;
				continue;
			}
			entries.push(entry);
		}
		if (valid) {
			for (let i = 1; i < entries.length; i++) {
				if (entries[i - 1].revision >= entries[i].revision) {
					errors.push(issue(INDEX_CODE, "/revisions", "revisions must be sorted by revision with no duplicate revision"));
					valid = false;
					break;
				}
			}
		}
		if (valid) revisions = entries;
	} else {
		errors.push(issue(INDEX_CODE, "/revisions", "revisions must be an array"));
	}
	if (schemaVersion === null || runtimeKind === null || currentRevision === null || currentHash === null || updatedAt === null || indexDigest === null || revisions === null || errors.length) {
		return failure(errors);
	}
	// current 指针必须指向最高 present revision 且 hash 一致；索引/文件分歧 fail-closed，绝不选"最近"revision。
	const present = revisions.filter((entry) => entry.status === "present");
	if (present.length === 0) {
		errors.push(issue(INDEX_CODE, "/currentRevision", "the index must contain at least one present revision"));
		return failure(errors);
	}
	const highest = present[present.length - 1];
	if (currentRevision !== highest.revision || currentHash !== highest.catalogHash) {
		errors.push(issue(INDEX_CODE, "/currentRevision", "currentRevision/currentHash must equal the highest non-deleted revision whose nested catalog hash agrees"));
		return failure(errors);
	}
	const payload: CatalogHistoryIndexPayloadV1 = { schemaVersion: 1, runtimeKind: "wasm", currentRevision, currentHash, revisions, updatedAt };
	const expected = computeCatalogHistoryIndexDigestV1(payload);
	if (expected !== indexDigest) {
		errors.push(issue(WASM_CATALOG_INDEX_DIGEST_MISMATCH, "/indexDigest", "indexDigest must equal the domain digest of the index wrapper with the digest omitted"));
		return failure(errors);
	}
	return ok({ ...payload, indexDigest });
}

export interface CatalogHistoryRebuildContextV1 {
	readonly updatedAt: string;
	readonly references?: readonly WasmCatalogEntryReferenceV1[];
	readonly releaseReceipts?: readonly CatalogReleaseReceiptV1[];
}

/**
 * 恢复：扫描固定 revision 路径的全部历史文件，逐一复算 recordDigest，重建索引；
 * 任一文件不合法、或同 revision 出现分歧，fail-closed 而不是选择最近的 revision。
 * current 指针 = 最高 present revision（重建自仍存在的文件，deleted 标记由 GC 流程写入）。
 */
export function rebuildCatalogHistoryIndex(records: readonly unknown[], context: CatalogHistoryRebuildContextV1): ValidationResult<CatalogHistoryIndexV1> {
	const errors: ValidationIssue[] = [];
	const updatedAt = requireRfc3339Utc(context.updatedAt, "", "updatedAt", INDEX_CODE, errors);
	if (updatedAt === null || errors.length) return failure(errors);
	const valid: CatalogHistoryRecordV1[] = [];
	const seenRevisions = new Set<number>();
	for (let i = 0; i < records.length; i++) {
		const record = validateCatalogHistoryRecordV1(records[i]);
		if (!record.ok) {
			errors.push(...record.errors);
			continue;
		}
		if (seenRevisions.has(record.value.revision)) {
			errors.push(issue(INDEX_CODE, "/records/" + i, "revision " + record.value.revision + " appears more than once; an index/file disagreement fails closed"));
			continue;
		}
		seenRevisions.add(record.value.revision);
		valid.push(record.value);
	}
	if (errors.length) return failure(errors);
	if (valid.length === 0) {
		return failure([issue(INDEX_CODE, "/records", "no valid catalog history revision survives digest verification; the gate stays closed")]);
	}
	valid.sort((left, right) => left.revision - right.revision);
	const references = context.references ?? [];
	const receipts = context.releaseReceipts ?? [];
	const revisions: CatalogHistoryIndexRevisionEntryV1[] = valid.map((record) => ({
		revision: record.revision,
		catalogHash: record.catalogHash,
		path: catalogHistoryRevisionFilePath(record.revision, record.catalogHash),
		status: "present" as const,
		protectedReferenceCount: references.filter((reference) => reference.runtimeBinding.catalogRevision === record.revision).length,
		releaseRetentionUntil: latestReleaseRetention(receipts, record.revision, record.catalogHash),
		deletedAt: null,
	}));
	const highest = revisions[revisions.length - 1];
	const payload: CatalogHistoryIndexPayloadV1 = { schemaVersion: 1, runtimeKind: "wasm", currentRevision: highest.revision, currentHash: highest.catalogHash, revisions, updatedAt };
	return ok({ ...payload, indexDigest: computeCatalogHistoryIndexDigestV1(payload) });
}

function latestReleaseRetention(receipts: readonly CatalogReleaseReceiptV1[], revision: number, catalogHash: string): string | null {
	let latest: number | null = null;
	for (const receipt of receipts) {
		if (receipt.catalogRevision !== revision || receipt.catalogHash !== catalogHash) continue;
		const at = Date.parse(receipt.releaseRetentionUntil);
		if (latest === null || at > latest) latest = at;
	}
	return latest === null ? null : new Date(latest).toISOString();
}

// ---------------------------------------------------------------------------
// release receipt / 释放状态机 / delete audit / GC
// ---------------------------------------------------------------------------

export interface CatalogReleaseReceiptV1 {
	readonly schemaVersion: 1;
	readonly runtimeKind: "wasm";
	readonly releaseId: string;
	readonly entryKey: string;
	readonly catalogRevision: number;
	readonly catalogHash: string;
	readonly targetRuntimeBinding: RuntimeBindingIdentityV1;
	readonly ownerCommandId: string;
	readonly protectedReferenceCount: 0;
	readonly drainedAt: string;
	readonly releasedAt: string;
	readonly releaseRetentionUntil: string;
	readonly receiptDigest: string;
}

export type CatalogReleaseReceiptPayloadV1 = Omit<CatalogReleaseReceiptV1, "receiptDigest">;

/** `receiptDigest`（补充域公式）：对 release receipt 去 receiptDigest 后的域前缀单次 SHA-256。 */
export function computeCatalogReleaseReceiptDigestV1(payload: CatalogReleaseReceiptPayloadV1): string {
	return domainPrefixedDigest(
		CATALOG_RELEASE_RECEIPT_DIGEST_DOMAIN,
		jcsCanonicalBytes({
			schemaVersion: payload.schemaVersion,
			runtimeKind: payload.runtimeKind,
			releaseId: payload.releaseId,
			entryKey: payload.entryKey,
			catalogRevision: payload.catalogRevision,
			catalogHash: payload.catalogHash,
			targetRuntimeBinding: payload.targetRuntimeBinding,
			ownerCommandId: payload.ownerCommandId,
			protectedReferenceCount: payload.protectedReferenceCount,
			drainedAt: payload.drainedAt,
			releasedAt: payload.releasedAt,
			releaseRetentionUntil: payload.releaseRetentionUntil,
		}),
	);
}

function requireReleaseReceiptPayload(input: unknown, path: string, errors: ValidationIssue[]): CatalogReleaseReceiptPayloadV1 | null {
	const receipt = requireObject(input, path, "catalog release receipt", RELEASE_CODE, errors);
	if (receipt === null) return null;
	requireExactKeys(
		receipt,
		path,
		["schemaVersion", "runtimeKind", "releaseId", "entryKey", "catalogRevision", "catalogHash", "targetRuntimeBinding", "ownerCommandId", "protectedReferenceCount", "drainedAt", "releasedAt", "releaseRetentionUntil"],
		RELEASE_CODE,
		errors,
	);
	const schemaVersion = requireSafeInteger(receipt.schemaVersion, path, "schemaVersion", 1, 1, RELEASE_CODE, errors);
	const runtimeKind = requireStringLiteral(receipt.runtimeKind, path, "runtimeKind", "wasm", RELEASE_CODE, errors);
	const releaseId = requireUuidV7(receipt.releaseId, path, "releaseId", RELEASE_CODE, errors);
	const entryKey = typeof receipt.entryKey === "string" && WASM_ENTRY_KEY_PATTERN.test(receipt.entryKey) ? receipt.entryKey : null;
	if (entryKey === null) errors.push(issue(RELEASE_CODE, path + "/entryKey", "entryKey must match ^[a-z][a-z0-9.-]{0,63}$"));
	const catalogRevision = requireSafeInteger(receipt.catalogRevision, path, "catalogRevision", 1, WASM_U53_MAX, RELEASE_CODE, errors);
	const catalogHash = requireSha256Hex(receipt.catalogHash, path, "catalogHash", RELEASE_CODE, errors);
	const binding = validateRuntimeBindingIdentityV1(receipt.targetRuntimeBinding);
	if (!binding.ok) errors.push(...binding.errors);
	const ownerCommandId = requireUuidV7(receipt.ownerCommandId, path, "ownerCommandId", RELEASE_CODE, errors);
	// spec：protectedReferenceCount 必须为 0（active/ready-preparing/rollback 扫描 + drain receipt 全部完成后才允许 release）。
	if (receipt.protectedReferenceCount !== 0) {
		errors.push(issue(RELEASE_CODE, path + "/protectedReferenceCount", "protectedReferenceCount must be the literal 0 on a release receipt"));
	}
	const drainedAt = requireRfc3339Utc(receipt.drainedAt, path, "drainedAt", RELEASE_CODE, errors);
	const releasedAt = requireRfc3339Utc(receipt.releasedAt, path, "releasedAt", RELEASE_CODE, errors);
	const releaseRetentionUntil = requireRfc3339Utc(receipt.releaseRetentionUntil, path, "releaseRetentionUntil", RELEASE_CODE, errors);
	if (
		schemaVersion === null || runtimeKind === null || releaseId === null || entryKey === null || catalogRevision === null || catalogHash === null ||
		!binding.ok || ownerCommandId === null || drainedAt === null || releasedAt === null || releaseRetentionUntil === null || errors.length
	) {
		return null;
	}
	// drain 先于 release；保留期至少 releasedAt + 31536000s。
	if (Date.parse(drainedAt) > Date.parse(releasedAt)) {
		errors.push(issue(RELEASE_CODE, path + "/drainedAt", "drainedAt must not be later than releasedAt; the drain receipt precedes the release"));
		return null;
	}
	if (Date.parse(releaseRetentionUntil) < Date.parse(releasedAt) + CATALOG_RELEASE_RETENTION_SECONDS * 1000) {
		errors.push(issue(RELEASE_CODE, path + "/releaseRetentionUntil", "releaseRetentionUntil must be at least releasedAt + 31536000 seconds"));
		return null;
	}
	return {
		schemaVersion: 1,
		runtimeKind: "wasm",
		releaseId,
		entryKey,
		catalogRevision,
		catalogHash,
		targetRuntimeBinding: binding.value,
		ownerCommandId,
		protectedReferenceCount: 0,
		drainedAt,
		releasedAt,
		releaseRetentionUntil,
	};
}

/** CatalogReleaseReceiptV1 完整校验（含 receiptDigest 复算与保留期下界）。 */
export function validateCatalogReleaseReceiptV1(input: unknown): ValidationResult<CatalogReleaseReceiptV1> {
	const errors: ValidationIssue[] = [];
	const record = requireObject(input, "", "catalog release receipt", RELEASE_CODE, errors);
	if (record === null) return failure(errors);
	requireExactKeys(record, "", ["schemaVersion", "runtimeKind", "releaseId", "entryKey", "catalogRevision", "catalogHash", "targetRuntimeBinding", "ownerCommandId", "protectedReferenceCount", "drainedAt", "releasedAt", "releaseRetentionUntil", "receiptDigest"], RELEASE_CODE, errors);
	const receiptDigest = requireSha256Hex(record.receiptDigest, "", "receiptDigest", RELEASE_CODE, errors);
	// payload 校验输入必须是去掉 receiptDigest 的干净子集，避免把 digest 字段误判为未知字段。
	const payload = requireReleaseReceiptPayload({
		schemaVersion: record.schemaVersion,
		runtimeKind: record.runtimeKind,
		releaseId: record.releaseId,
		entryKey: record.entryKey,
		catalogRevision: record.catalogRevision,
		catalogHash: record.catalogHash,
		targetRuntimeBinding: record.targetRuntimeBinding,
		ownerCommandId: record.ownerCommandId,
		protectedReferenceCount: record.protectedReferenceCount,
		drainedAt: record.drainedAt,
		releasedAt: record.releasedAt,
		releaseRetentionUntil: record.releaseRetentionUntil,
	}, "", errors);
	if (payload === null || receiptDigest === null || errors.length) return failure(errors);
	const expected = computeCatalogReleaseReceiptDigestV1(payload);
	if (expected !== receiptDigest) {
		errors.push(issue(CATALOG_RELEASE_RECEIPT_DIGEST_MISMATCH, "/receiptDigest", "receiptDigest must equal the domain digest of the receipt with the digest omitted"));
		return failure(errors);
	}
	return ok({ ...payload, receiptDigest });
}

export interface CatalogReleaseRequestV1 {
	readonly catalog: RuntimeCatalogV1;
	readonly entryKey: string;
	readonly references: readonly WasmCatalogEntryReferenceV1[];
	readonly releaseId: string;
	readonly ownerCommandId: string;
	readonly drainedAt: string;
	readonly releasedAt: string;
}

/**
 * release 状态机（纯函数）：只有零受保护引用的 entry 可释放；产出带一年保留期与 receiptDigest 的审计对象。
 * owner 前置流程（停/退役候选、移除全部 rollback 保留、等待 drain receipt）由引用集合为空来证明。
 */
export function releaseRuntimeCatalogEntry(input: CatalogReleaseRequestV1): ValidationResult<CatalogReleaseReceiptV1> {
	const entry = input.catalog.entries.find((candidate) => candidate.entryKey === input.entryKey);
	if (entry === undefined) {
		return failure([issue(WASM_CATALOG_ENTRY_NOT_FOUND, "/entryKey", "release names an entry that does not exist in the pinned catalog revision")]);
	}
	const protectedCount = input.references.filter((reference) => reference.runtimeBinding.entryKey === input.entryKey).length;
	if (protectedCount > 0) {
		return failure([issue(WASM_CATALOG_ENTRY_PROTECTED, "/references", "only an entry with no active/ready-preparing/rollback reference may be released; protectedReferenceCount must be 0")]);
	}
	const targetRuntimeBinding: RuntimeBindingIdentityV1 = {
		kind: "wasm",
		catalogRevision: input.catalog.revision,
		catalogHash: input.catalog.catalogHash,
		entryKey: entry.entryKey,
		imageDigest: entry.imageDigest,
		hostABI: entry.hostABI,
		world: entry.world,
	};
	const releaseRetentionUntil = new Date(Date.parse(input.releasedAt) + CATALOG_RELEASE_RETENTION_SECONDS * 1000).toISOString();
	const payload: CatalogReleaseReceiptPayloadV1 = {
		schemaVersion: 1,
		runtimeKind: "wasm",
		releaseId: input.releaseId,
		entryKey: entry.entryKey,
		catalogRevision: input.catalog.revision,
		catalogHash: input.catalog.catalogHash,
		targetRuntimeBinding,
		ownerCommandId: input.ownerCommandId,
		protectedReferenceCount: 0,
		drainedAt: input.drainedAt,
		releasedAt: input.releasedAt,
		releaseRetentionUntil,
	};
	return validateCatalogReleaseReceiptV1({ ...payload, receiptDigest: computeCatalogReleaseReceiptDigestV1(payload) });
}

/** 已释放的 binding 不可重新激活（prepare/rebind/rollback/activation 共用 fence）。 */
export function checkRuntimeBindingNotReleased(receipts: readonly CatalogReleaseReceiptV1[], runtimeBinding: RuntimeBindingIdentityV1): ValidationResult<true> {
	for (const receipt of receipts) {
		if (jcsEqual(receipt.targetRuntimeBinding, runtimeBinding)) {
			return failure([issue(WASM_RUNTIME_BINDING_RELEASED, "/targetRuntimeBinding", "a released binding cannot be reactivated; the immutable version/rollback history remains auditable only")]);
		}
	}
	return ok(true);
}

// --- delete audit 与 GC ---

export interface CatalogDeleteAuditV1 {
	readonly schemaVersion: 1;
	readonly runtimeKind: "wasm";
	readonly deleteId: string;
	readonly revision: number;
	readonly catalogHash: string;
	readonly path: string;
	readonly releaseId: string;
	readonly ownerCommandId: string;
	readonly deletedAt: string;
	readonly reason: string;
	readonly objectDigest: string;
}

// spec 未定义 reason 文法；按有界可打印字符串处理（补充文法，见文末备注）。
function requireDeleteReason(value: unknown, path: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || value.length === 0 || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) {
		errors.push(issue(code, path, "reason must be a non-empty printable string of at most 128 characters"));
		return null;
	}
	return value;
}

/** CatalogDeleteAuditV1 形状校验（path 必须命中该 revision/hash 的固定公式）。 */
export function validateCatalogDeleteAuditV1(input: unknown): ValidationResult<CatalogDeleteAuditV1> {
	const errors: ValidationIssue[] = [];
	const audit = requireObject(input, "", "catalog delete audit", DELETE_AUDIT_CODE, errors);
	if (audit === null) return failure(errors);
	requireExactKeys(audit, "", ["schemaVersion", "runtimeKind", "deleteId", "revision", "catalogHash", "path", "releaseId", "ownerCommandId", "deletedAt", "reason", "objectDigest"], DELETE_AUDIT_CODE, errors);
	const schemaVersion = requireSafeInteger(audit.schemaVersion, "", "schemaVersion", 1, 1, DELETE_AUDIT_CODE, errors);
	const runtimeKind = requireStringLiteral(audit.runtimeKind, "", "runtimeKind", "wasm", DELETE_AUDIT_CODE, errors);
	const deleteId = requireUuidV7(audit.deleteId, "", "deleteId", DELETE_AUDIT_CODE, errors);
	const revision = requireSafeInteger(audit.revision, "", "revision", 1, WASM_U53_MAX, DELETE_AUDIT_CODE, errors);
	const catalogHash = requireSha256Hex(audit.catalogHash, "", "catalogHash", DELETE_AUDIT_CODE, errors);
	const releaseId = requireUuidV7(audit.releaseId, "", "releaseId", DELETE_AUDIT_CODE, errors);
	const ownerCommandId = requireUuidV7(audit.ownerCommandId, "", "ownerCommandId", DELETE_AUDIT_CODE, errors);
	const deletedAt = requireRfc3339Utc(audit.deletedAt, "", "deletedAt", DELETE_AUDIT_CODE, errors);
	const reason = requireDeleteReason(audit.reason, "/reason", DELETE_AUDIT_CODE, errors);
	const objectDigest = requireSha256Hex(audit.objectDigest, "", "objectDigest", DELETE_AUDIT_CODE, errors);
	if (schemaVersion === null || runtimeKind === null || deleteId === null || revision === null || catalogHash === null || releaseId === null || ownerCommandId === null || deletedAt === null || reason === null || objectDigest === null || errors.length) {
		return failure(errors);
	}
	if (audit.path !== catalogHistoryRevisionFilePath(revision, catalogHash)) {
		errors.push(issue(DELETE_AUDIT_CODE, "/path", "path must equal the fixed revision file path for the audited revision and hash"));
		return failure(errors);
	}
	return ok({ schemaVersion: 1, runtimeKind: "wasm", deleteId, revision, catalogHash, path: audit.path, releaseId, ownerCommandId, deletedAt, reason, objectDigest });
}

export interface CatalogHistoryGcRequestV1 {
	readonly record: CatalogHistoryRecordV1;
	readonly receipt: CatalogReleaseReceiptV1;
	readonly references: readonly WasmCatalogEntryReferenceV1[];
	readonly deleteId: string;
	readonly ownerCommandId: string;
	readonly deletedAt: string;
	readonly reason: string;
}

export interface CatalogHistoryGcResultV1 {
	readonly audit: CatalogDeleteAuditV1;
	readonly indexEntry: CatalogHistoryIndexRevisionEntryV1;
}

/**
 * GC 状态机（纯函数）：先写 delete audit，再标记 index 条目 `deleted`。
 * 门条件：release receipt 与该 revision/hash/entry 一致、零受保护引用、保留期已过、owner 显式批准（ownerCommandId）。
 * 并发 rollback 引用使删除 CAS 失败（受保护引用判定在此处 fail-closed），文件保持原样。
 */
export function gcCatalogHistoryRevision(input: CatalogHistoryGcRequestV1): ValidationResult<CatalogHistoryGcResultV1> {
	const errors: ValidationIssue[] = [];
	const deleteId = requireUuidV7(input.deleteId, "", "deleteId", DELETE_AUDIT_CODE, errors);
	const ownerCommandId = requireUuidV7(input.ownerCommandId, "", "ownerCommandId", DELETE_AUDIT_CODE, errors);
	const deletedAt = requireRfc3339Utc(input.deletedAt, "", "deletedAt", DELETE_AUDIT_CODE, errors);
	const reason = requireDeleteReason(input.reason, "/reason", DELETE_AUDIT_CODE, errors);
	if (deleteId === null || ownerCommandId === null || deletedAt === null || reason === null || errors.length) return failure(errors);

	// receipt 必须精确绑定被删的 revision/hash/entry。
	if (input.receipt.catalogRevision !== input.record.revision || input.receipt.catalogHash !== input.record.catalogHash) {
		return failure([issue(CATALOG_RELEASE_RECEIPT_MISMATCH, "/receipt", "the release receipt must name the exact revision and hash being garbage-collected")]);
	}
	if (!input.record.catalog.entries.some((entry) => entry.entryKey === input.receipt.entryKey)) {
		return failure([issue(CATALOG_RELEASE_RECEIPT_MISMATCH, "/receipt", "the release receipt entryKey must exist in the collected revision")]);
	}
	// 受保护引用扫描：钉住该 revision 的任何 active/ready-preparing/rollback 引用都阻止删除。
	const protectedCount = input.references.filter((reference) => reference.runtimeBinding.catalogRevision === input.record.revision).length;
	if (protectedCount > 0) {
		return failure([issue(WASM_CATALOG_ENTRY_PROTECTED, "/references", "a history revision with a remaining active/ready/preparing/rollback reference is never eligible for deletion")]);
	}
	// 保留期未过不得删除。
	if (Date.parse(deletedAt) < Date.parse(input.receipt.releaseRetentionUntil)) {
		return failure([issue(CATALOG_RELEASE_RETENTION_ACTIVE, "/deletedAt", "the release retention window has not elapsed; the entry and all referenced history remain recoverable")]);
	}
	// objectDigest：被删对象的原始 JCS 字节的 SHA-256（与 spec 的 raw-file digest 同风格；见文末备注）。
	const audit: CatalogDeleteAuditV1 = {
		schemaVersion: 1,
		runtimeKind: "wasm",
		deleteId,
		revision: input.record.revision,
		catalogHash: input.record.catalogHash,
		path: catalogHistoryRevisionFilePath(input.record.revision, input.record.catalogHash),
		releaseId: input.receipt.releaseId,
		ownerCommandId,
		deletedAt,
		reason,
		objectDigest: sha256Hex(jcsCanonicalBytes(input.record)),
	};
	const indexEntry: CatalogHistoryIndexRevisionEntryV1 = {
		revision: input.record.revision,
		catalogHash: input.record.catalogHash,
		path: audit.path,
		status: "deleted",
		protectedReferenceCount: 0,
		releaseRetentionUntil: input.receipt.releaseRetentionUntil,
		deletedAt,
	};
	const auditResult = validateCatalogDeleteAuditV1(audit);
	if (!auditResult.ok) return failure(auditResult.errors);
	return ok({ audit: auditResult.value, indexEntry });
}

// ---------------------------------------------------------------------------
// NodeCapabilityRecordV1：精确字段界、hash、revision CAS、reserve/pin fence
// ---------------------------------------------------------------------------

export interface NodePolicyMaximaV1 {
	readonly cpuMillis: number;
	readonly memoryBytes: number;
	readonly pidLimit: number;
	readonly storageBytes: number;
}

export interface NodeHttpLimitsV1 {
	readonly maxRequestBytes: number;
	readonly maxResponseBytes: number;
	readonly maxRequestHeaderBytes: number;
	readonly maxResponseHeaderBytes: number;
	readonly maxRequestHeaderCount: number;
	readonly maxResponseHeaderCount: number;
	readonly maxConcurrentRequests: number;
}

export interface NodeEngineLimitsV1 {
	readonly maxEpochDeadlineMs: number;
	readonly fuelPerRequest: number | null;
	readonly maxLiveInstances: number;
}

export interface NodeAdmissionLimitsV1 {
	readonly maxPackageBytes: number;
	readonly maxBlobBytes: number;
	readonly maxLayerCount: number;
	readonly maxClosureNodes: number;
	readonly maxClosureEdges: number;
	readonly maxClosureDepth: number;
	readonly stagingTtlSeconds: number;
}

export interface NodeRestartBudgetV1 {
	readonly maxRestarts: number;
	readonly windowMs: number;
}

export interface RuntimeReserveEntryV1 {
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly architecture: WasmRuntimeArchitecture;
	readonly reserveBytes: number;
}

export interface NodeCapabilityRecordV1 {
	readonly schemaVersion: 1;
	readonly revision: number;
	readonly recordHash: string;
	readonly policyMaxima: NodePolicyMaximaV1;
	readonly http: NodeHttpLimitsV1;
	readonly engine: NodeEngineLimitsV1;
	readonly admission: NodeAdmissionLimitsV1;
	readonly restart: NodeRestartBudgetV1;
	readonly drainDeadlineMs: number;
	readonly runtimeReserves: readonly RuntimeReserveEntryV1[];
	readonly matrix: WasmCapabilityMatrixV1;
}

export type NodeCapabilityRecordPayloadV1 = Omit<NodeCapabilityRecordV1, "recordHash">;

export const WASM_NODE_RESERVE_MAX_ENTRIES = 256;
// reserveBytes 上界 68719476735 刻意比 policyMaxima.memoryBytes 上界 68719476736 小 1：
// reserve 必须严格小于任何合法的 memoryBytes 限额。
const MAX_RESERVE_BYTES = 68719476735;

function requireNodePolicyMaxima(input: unknown, path: string, errors: ValidationIssue[]): NodePolicyMaximaV1 | null {
	const value = requireObject(input, path, "policyMaxima", CAPABILITY_CODE, errors);
	if (value === null) return null;
	requireExactKeys(value, path, ["cpuMillis", "memoryBytes", "pidLimit", "storageBytes"], CAPABILITY_CODE, errors);
	const cpuMillis = requireSafeInteger(value.cpuMillis, path, "cpuMillis", 1, 1000000, CAPABILITY_CODE, errors);
	const memoryBytes = requireSafeInteger(value.memoryBytes, path, "memoryBytes", 1, 68719476736, CAPABILITY_CODE, errors);
	const pidLimit = requireSafeInteger(value.pidLimit, path, "pidLimit", 1, 1000000, CAPABILITY_CODE, errors);
	const storageBytes = requireSafeInteger(value.storageBytes, path, "storageBytes", 0, 1099511627776, CAPABILITY_CODE, errors);
	if (cpuMillis === null || memoryBytes === null || pidLimit === null || storageBytes === null || errors.length) return null;
	return { cpuMillis, memoryBytes, pidLimit, storageBytes };
}

function requireNodeHttpLimits(input: unknown, path: string, errors: ValidationIssue[]): NodeHttpLimitsV1 | null {
	const value = requireObject(input, path, "http", CAPABILITY_CODE, errors);
	if (value === null) return null;
	requireExactKeys(value, path, ["maxRequestBytes", "maxResponseBytes", "maxRequestHeaderBytes", "maxResponseHeaderBytes", "maxRequestHeaderCount", "maxResponseHeaderCount", "maxConcurrentRequests"], CAPABILITY_CODE, errors);
	const maxRequestBytes = requireSafeInteger(value.maxRequestBytes, path, "maxRequestBytes", 1, 16777216, CAPABILITY_CODE, errors);
	const maxResponseBytes = requireSafeInteger(value.maxResponseBytes, path, "maxResponseBytes", 1, 67108864, CAPABILITY_CODE, errors);
	const maxRequestHeaderBytes = requireSafeInteger(value.maxRequestHeaderBytes, path, "maxRequestHeaderBytes", 1, 65536, CAPABILITY_CODE, errors);
	const maxResponseHeaderBytes = requireSafeInteger(value.maxResponseHeaderBytes, path, "maxResponseHeaderBytes", 1, 65536, CAPABILITY_CODE, errors);
	const maxRequestHeaderCount = requireSafeInteger(value.maxRequestHeaderCount, path, "maxRequestHeaderCount", 1, 256, CAPABILITY_CODE, errors);
	const maxResponseHeaderCount = requireSafeInteger(value.maxResponseHeaderCount, path, "maxResponseHeaderCount", 1, 256, CAPABILITY_CODE, errors);
	const maxConcurrentRequests = requireSafeInteger(value.maxConcurrentRequests, path, "maxConcurrentRequests", 1, 4096, CAPABILITY_CODE, errors);
	if (maxRequestBytes === null || maxResponseBytes === null || maxRequestHeaderBytes === null || maxResponseHeaderBytes === null || maxRequestHeaderCount === null || maxResponseHeaderCount === null || maxConcurrentRequests === null || errors.length) {
		return null;
	}
	return { maxRequestBytes, maxResponseBytes, maxRequestHeaderBytes, maxResponseHeaderBytes, maxRequestHeaderCount, maxResponseHeaderCount, maxConcurrentRequests };
}

function requireNodeEngineLimits(input: unknown, path: string, errors: ValidationIssue[]): NodeEngineLimitsV1 | null {
	const value = requireObject(input, path, "engine", CAPABILITY_CODE, errors);
	if (value === null) return null;
	requireExactKeys(value, path, ["maxEpochDeadlineMs", "fuelPerRequest", "maxLiveInstances"], CAPABILITY_CODE, errors);
	const maxEpochDeadlineMs = requireSafeInteger(value.maxEpochDeadlineMs, path, "maxEpochDeadlineMs", 1, 300000, CAPABILITY_CODE, errors);
	// fuelPerRequest：null 关闭 fuel；数值启用且 1..1000000000000。
	let fuelPerRequest: number | null = null;
	let fuelParsed = false;
	if (value.fuelPerRequest === null) fuelParsed = true;
	else {
		const parsed = requireSafeInteger(value.fuelPerRequest, path, "fuelPerRequest", 1, 1000000000000, CAPABILITY_CODE, errors);
		if (parsed !== null) {
			fuelPerRequest = parsed;
			fuelParsed = true;
		}
	}
	const maxLiveInstances = requireSafeInteger(value.maxLiveInstances, path, "maxLiveInstances", 1, 4096, CAPABILITY_CODE, errors);
	if (maxEpochDeadlineMs === null || !fuelParsed || maxLiveInstances === null || errors.length) return null;
	return { maxEpochDeadlineMs, fuelPerRequest, maxLiveInstances };
}

function requireNodeAdmissionLimits(input: unknown, path: string, errors: ValidationIssue[]): NodeAdmissionLimitsV1 | null {
	const value = requireObject(input, path, "admission", CAPABILITY_CODE, errors);
	if (value === null) return null;
	requireExactKeys(value, path, ["maxPackageBytes", "maxBlobBytes", "maxLayerCount", "maxClosureNodes", "maxClosureEdges", "maxClosureDepth", "stagingTtlSeconds"], CAPABILITY_CODE, errors);
	const maxPackageBytes = requireSafeInteger(value.maxPackageBytes, path, "maxPackageBytes", 1, 536870912, CAPABILITY_CODE, errors);
	const maxBlobBytes = requireSafeInteger(value.maxBlobBytes, path, "maxBlobBytes", 1, 134217728, CAPABILITY_CODE, errors);
	const maxLayerCount = requireSafeInteger(value.maxLayerCount, path, "maxLayerCount", 1, 128, CAPABILITY_CODE, errors);
	const maxClosureNodes = requireSafeInteger(value.maxClosureNodes, path, "maxClosureNodes", 1, 4096, CAPABILITY_CODE, errors);
	const maxClosureEdges = requireSafeInteger(value.maxClosureEdges, path, "maxClosureEdges", 1, 16384, CAPABILITY_CODE, errors);
	const maxClosureDepth = requireSafeInteger(value.maxClosureDepth, path, "maxClosureDepth", 1, 64, CAPABILITY_CODE, errors);
	const stagingTtlSeconds = requireSafeInteger(value.stagingTtlSeconds, path, "stagingTtlSeconds", 1, 3600, CAPABILITY_CODE, errors);
	if (maxPackageBytes === null || maxBlobBytes === null || maxLayerCount === null || maxClosureNodes === null || maxClosureEdges === null || maxClosureDepth === null || stagingTtlSeconds === null || errors.length) {
		return null;
	}
	return { maxPackageBytes, maxBlobBytes, maxLayerCount, maxClosureNodes, maxClosureEdges, maxClosureDepth, stagingTtlSeconds };
}

function requireNodeRestartBudget(input: unknown, path: string, errors: ValidationIssue[]): NodeRestartBudgetV1 | null {
	const value = requireObject(input, path, "restart", CAPABILITY_CODE, errors);
	if (value === null) return null;
	requireExactKeys(value, path, ["maxRestarts", "windowMs"], CAPABILITY_CODE, errors);
	const maxRestarts = requireSafeInteger(value.maxRestarts, path, "maxRestarts", 0, 100, CAPABILITY_CODE, errors);
	const windowMs = requireSafeInteger(value.windowMs, path, "windowMs", 1000, 86400000, CAPABILITY_CODE, errors);
	if (maxRestarts === null || windowMs === null || errors.length) return null;
	return { maxRestarts, windowMs };
}

// runtimeReserves：(JCS(runtimeBinding), architecture) 唯一，先按 raw JCS UTF-8 字节再按 architecture 排序。
function compareRuntimeReserveEntries(left: RuntimeReserveEntryV1, right: RuntimeReserveEntryV1): number {
	const byBinding = Buffer.compare(Buffer.from(jcsCanonicalBytes(left.runtimeBinding)), Buffer.from(jcsCanonicalBytes(right.runtimeBinding)));
	if (byBinding !== 0) return byBinding;
	return compareUtf8Bytes(left.architecture, right.architecture);
}

function requireRuntimeReserves(input: unknown, path: string, errors: ValidationIssue[]): readonly RuntimeReserveEntryV1[] | null {
	if (!Array.isArray(input)) {
		errors.push(issue(CAPABILITY_CODE, path, "runtimeReserves must be a non-empty array"));
		return null;
	}
	if (input.length === 0) {
		errors.push(issue(CAPABILITY_CODE, path, "runtimeReserves must be non-empty"));
		return null;
	}
	if (input.length > WASM_NODE_RESERVE_MAX_ENTRIES) {
		errors.push(issue(CAPABILITY_CODE, path, "runtimeReserves must have at most " + WASM_NODE_RESERVE_MAX_ENTRIES + " items"));
		return null;
	}
	const entries: RuntimeReserveEntryV1[] = [];
	for (let i = 0; i < input.length; i++) {
		const entryPath = path + "/" + i;
		const entry = requireObject(input[i], entryPath, "runtime reserve entry", CAPABILITY_CODE, errors);
		if (entry === null) return null;
		requireExactKeys(entry, entryPath, ["runtimeBinding", "architecture", "reserveBytes"], CAPABILITY_CODE, errors);
		const binding = validateRuntimeBindingIdentityV1(entry.runtimeBinding);
		if (!binding.ok) errors.push(...binding.errors);
		const architecture = requireStringUnion(entry.architecture, entryPath, "architecture", WASM_RUNTIME_ARCHITECTURES, CAPABILITY_CODE, errors);
		const reserveBytes = requireSafeInteger(entry.reserveBytes, entryPath, "reserveBytes", 1, MAX_RESERVE_BYTES, CAPABILITY_CODE, errors);
		if (!binding.ok || architecture === null || reserveBytes === null || errors.length) return null;
		entries.push({ runtimeBinding: binding.value, architecture: architecture as WasmRuntimeArchitecture, reserveBytes });
	}
	for (let i = 1; i < entries.length; i++) {
		const comparison = compareRuntimeReserveEntries(entries[i - 1], entries[i]);
		if (comparison === 0) {
			errors.push(issue(CAPABILITY_CODE, path, "(JCS(runtimeBinding), architecture) must be unique"));
			return null;
		}
		if (comparison > 0) {
			errors.push(issue(CAPABILITY_CODE, path, "runtimeReserves must be sorted first by the raw JCS UTF-8 bytes of runtimeBinding, then by architecture"));
			return null;
		}
	}
	return entries;
}

function requireNodeCapabilityPayload(input: unknown, path: string, errors: ValidationIssue[]): NodeCapabilityRecordPayloadV1 | null {
	const record = requireObject(input, path, "node capability record payload", CAPABILITY_CODE, errors);
	if (record === null) return null;
	requireExactKeys(record, path, ["schemaVersion", "revision", "policyMaxima", "http", "engine", "admission", "restart", "drainDeadlineMs", "runtimeReserves", "matrix"], CAPABILITY_CODE, errors);
	const schemaVersion = requireSafeInteger(record.schemaVersion, path, "schemaVersion", 1, 1, CAPABILITY_CODE, errors);
	const revision = requireSafeInteger(record.revision, path, "revision", 1, WASM_U53_MAX, CAPABILITY_CODE, errors);
	const policyMaxima = requireNodePolicyMaxima(record.policyMaxima, path + "/policyMaxima", errors);
	const http = requireNodeHttpLimits(record.http, path + "/http", errors);
	const engine = requireNodeEngineLimits(record.engine, path + "/engine", errors);
	const admission = requireNodeAdmissionLimits(record.admission, path + "/admission", errors);
	const restart = requireNodeRestartBudget(record.restart, path + "/restart", errors);
	const drainDeadlineMs = requireSafeInteger(record.drainDeadlineMs, path, "drainDeadlineMs", 1, 300000, CAPABILITY_CODE, errors);
	const runtimeReserves = requireRuntimeReserves(record.runtimeReserves, path + "/runtimeReserves", errors);
	// 能力矩阵 pin：复用 wasm-capability.ts 的 revision-1 精确矩阵校验（不建第二套实现）。
	const matrix = validateWasmCapabilityMatrix(record.matrix);
	if (!matrix.ok) errors.push(...matrix.errors);
	if (schemaVersion === null || revision === null || policyMaxima === null || http === null || engine === null || admission === null || restart === null || drainDeadlineMs === null || runtimeReserves === null || !matrix.ok || errors.length) {
		return null;
	}
	return { schemaVersion: 1, revision, policyMaxima, http, engine, admission, restart, drainDeadlineMs, runtimeReserves, matrix: matrix.value };
}

/** `recordHash`（域前缀单次 SHA-256；输入必须是已通过结构校验的 payload）。 */
export function computeNodeCapabilityRecordHashV1(payload: NodeCapabilityRecordPayloadV1): string {
	return domainPrefixedDigest(
		NODE_CAPABILITY_RECORD_HASH_DOMAIN,
		jcsCanonicalBytes({
			schemaVersion: payload.schemaVersion,
			revision: payload.revision,
			policyMaxima: payload.policyMaxima,
			http: payload.http,
			engine: payload.engine,
			admission: payload.admission,
			restart: payload.restart,
			drainDeadlineMs: payload.drainDeadlineMs,
			runtimeReserves: payload.runtimeReserves,
			matrix: payload.matrix,
		}),
	);
}

/** 校验无 hash 的 payload 并密封（owner CAS 更新的 seal 步骤）。 */
export function sealNodeCapabilityRecordV1(payload: unknown): ValidationResult<NodeCapabilityRecordV1> {
	const errors: ValidationIssue[] = [];
	const parsed = requireNodeCapabilityPayload(payload, "", errors);
	if (parsed === null || errors.length) return failure(errors);
	return ok({ ...parsed, recordHash: computeNodeCapabilityRecordHashV1(parsed) });
}

/** NodeCapabilityRecordV1 完整校验：全部字段的精确界 + recordHash 复算。 */
export function validateNodeCapabilityRecordV1(input: unknown): ValidationResult<NodeCapabilityRecordV1> {
	const errors: ValidationIssue[] = [];
	const record = requireObject(input, "", "node capability record", CAPABILITY_CODE, errors);
	if (record === null) return failure(errors);
	requireExactKeys(record, "", ["schemaVersion", "revision", "recordHash", "policyMaxima", "http", "engine", "admission", "restart", "drainDeadlineMs", "runtimeReserves", "matrix"], CAPABILITY_CODE, errors);
	const recordHash = requireSha256Hex(record.recordHash, "", "recordHash", CAPABILITY_CODE, errors);
	// payload 校验输入必须是去掉 recordHash 的干净子集，避免把 digest 字段误判为未知字段。
	const payload = requireNodeCapabilityPayload({
		schemaVersion: record.schemaVersion,
		revision: record.revision,
		policyMaxima: record.policyMaxima,
		http: record.http,
		engine: record.engine,
		admission: record.admission,
		restart: record.restart,
		drainDeadlineMs: record.drainDeadlineMs,
		runtimeReserves: record.runtimeReserves,
		matrix: record.matrix,
	}, "", errors);
	if (payload === null || recordHash === null || errors.length) return failure(errors);
	const expected = computeNodeCapabilityRecordHashV1(payload);
	if (expected !== recordHash) {
		errors.push(issue(WASM_NODE_CAPABILITY_DIGEST_MISMATCH, "/recordHash", "recordHash must equal hex(SHA-256(UTF8(\"iweb-node-capability-record-v1\\n\" || JCS(record with recordHash omitted))))"));
		return failure(errors);
	}
	return ok({ ...payload, recordHash });
}

export interface NodeCapabilityRevisionPinV1 {
	readonly revision: number;
	readonly recordHash: string;
}

/**
 * owner 更新协议（纯函数）：expected `(revision, recordHash)` CAS + `next.revision = current.revision + 1` +
 * 全字段校验 + hash 复算；stale expected pair 一律拒绝且不写任何东西。
 * 历史 revision 不可变更、supervisor 来源更新拒绝——两者由宿主存储层与授权层强制，纯函数不感知来源。
 */
export function appendNodeCapabilityRecordV1(current: NodeCapabilityRecordV1, expected: NodeCapabilityRevisionPinV1, next: unknown): ValidationResult<NodeCapabilityRecordV1> {
	const errors: ValidationIssue[] = [];
	if (typeof expected.revision !== "number" || !Number.isSafeInteger(expected.revision) || expected.revision < 1 || expected.revision > WASM_U53_MAX) {
		errors.push(issue(CAPABILITY_CODE, "/expected/revision", "expected record revision must be a u53 integer >= 1"));
	}
	if (typeof expected.recordHash !== "string" || !WASM_SHA256_HEX_PATTERN.test(expected.recordHash)) {
		errors.push(issue(CAPABILITY_CODE, "/expected/recordHash", "expected recordHash must be a 64-character lower-case hex digest"));
	}
	if (errors.length) return failure(errors);
	if (expected.revision !== current.revision || expected.recordHash !== current.recordHash) {
		return failure([issue(WASM_CAPABILITY_REVISION_CONFLICT, "/expected", "a stale expected (revision, recordHash) pair is rejected and writes nothing")]);
	}
	const payload = requireNodeCapabilityPayload(next, "", errors);
	if (payload === null || errors.length) return failure(errors);
	if (payload.revision !== current.revision + 1) {
		return failure([issue(WASM_CAPABILITY_REVISION_CONFLICT, "/revision", "the next record revision must equal current.revision + 1 (strictly increasing)")]);
	}
	return ok({ ...payload, recordHash: computeNodeCapabilityRecordHashV1(payload) });
}

// --- reserve / pin / policy fence ---

/** 按完整 `(JCS(runtimeBinding), architecture)` 精确匹配查找 reserve；缺失返回 null，绝不推断默认值。 */
export function findRuntimeReserve(record: NodeCapabilityRecordV1, runtimeBinding: RuntimeBindingIdentityV1, architecture: WasmRuntimeArchitecture): RuntimeReserveEntryV1 | null {
	const wanted = Buffer.from(jcsCanonicalBytes(runtimeBinding));
	for (const entry of record.runtimeReserves) {
		if (entry.architecture !== architecture) continue;
		if (Buffer.compare(Buffer.from(jcsCanonicalBytes(entry.runtimeBinding)), wanted) === 0) return entry;
	}
	return null;
}

export interface WasmMemoryReservationInputV1 {
	readonly record: NodeCapabilityRecordV1;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly architecture: WasmRuntimeArchitecture;
	readonly memoryBytes: number;
}

export interface WasmMemoryReservationResultV1 {
	/** guest 线性内存上限 = `resources.memoryBytes - reserveBytes`（同一字节单位）。 */
	readonly guestLinearMemoryBytes: number;
}

/**
 * admission/preparation 的内存 reserve fence：`reserveBytes` 与 `resources.memoryBytes` 以相同字节单位比较；
 * 缺失当前架构 reserve、或 `reserveBytes >= memoryBytes` 一律 `WASM_RESOURCE_RECORD_INVALID`，
 * 绝不代入默认值或零 reserve。catalog 永不提供 reserve，也不从镜像标签/RSS/其它 revision/其它架构推断。
 */
export function checkWasmMemoryReservation(input: WasmMemoryReservationInputV1): ValidationResult<WasmMemoryReservationResultV1> {
	const { record, runtimeBinding, architecture, memoryBytes } = input;
	if (typeof memoryBytes !== "number" || !Number.isSafeInteger(memoryBytes) || memoryBytes < 1) {
		return failure([issue(WASM_RESOURCE_RECORD_INVALID, "/memoryBytes", "resources.memoryBytes must be a positive byte integer")]);
	}
	const reserve = findRuntimeReserve(record, runtimeBinding, architecture);
	if (reserve === null) {
		return failure([issue(WASM_RESOURCE_RECORD_INVALID, "/runtimeReserves", "no reserve entry exists for the complete runtime binding on " + architecture + "; no default or zero reserve is substituted")]);
	}
	if (reserve.reserveBytes >= memoryBytes) {
		return failure([issue(WASM_RESOURCE_RECORD_INVALID, "/runtimeReserves", "reserveBytes " + reserve.reserveBytes + " is compared in identical byte units and must be strictly less than resources.memoryBytes " + memoryBytes)]);
	}
	return ok({ guestLinearMemoryBytes: memoryBytes - reserve.reserveBytes });
}

export interface WasmPolicyRequestV1 {
	readonly cpuMillis: number;
	readonly memoryBytes: number;
	readonly pidLimit: number;
	readonly storageBytes: number;
}

/** admission/preparation 的 policy maxima fence：任一请求字段超过其匹配 `policyMaxima` 字段即拒绝。 */
export function checkWasmPolicyMaxima(record: NodeCapabilityRecordV1, request: WasmPolicyRequestV1): ValidationResult<true> {
	const pairs = [
		["cpuMillis", request.cpuMillis, record.policyMaxima.cpuMillis],
		["memoryBytes", request.memoryBytes, record.policyMaxima.memoryBytes],
		["pidLimit", request.pidLimit, record.policyMaxima.pidLimit],
		["storageBytes", request.storageBytes, record.policyMaxima.storageBytes],
	] as const;
	const errors: ValidationIssue[] = [];
	for (const [field, requested, maximum] of pairs) {
		if (typeof requested !== "number" || !Number.isSafeInteger(requested) || requested < 0) {
			errors.push(issue(WASM_POLICY_MAXIMA_EXCEEDED, "/" + field, field + " must be a non-negative integer byte/millicore request"));
			continue;
		}
		if (requested > maximum) {
			errors.push(issue(WASM_POLICY_MAXIMA_EXCEEDED, "/" + field, field + " " + requested + " exceeds the policyMaxima bound " + maximum));
		}
	}
	if (errors.length) return failure(errors);
	return ok(true);
}

export interface NodeCapabilityPinV1 {
	readonly revision: number;
	readonly recordHash: string;
}

/** preparation 必须钉住当前 capability revision/hash；缺失或不一致 fail-closed。 */
export function checkNodeCapabilityPin(current: NodeCapabilityRecordV1, pin: NodeCapabilityPinV1): ValidationResult<true> {
	if (typeof pin.revision !== "number" || !Number.isSafeInteger(pin.revision) || pin.revision < 1 || typeof pin.recordHash !== "string" || !WASM_SHA256_HEX_PATTERN.test(pin.recordHash) || pin.revision !== current.revision || pin.recordHash !== current.recordHash) {
		return failure([issue(WASM_CAPABILITY_PIN_MISMATCH, "/pin", "the pinned capability record must equal the current (revision, recordHash) exactly")]);
	}
	return ok(true);
}

/** binding 与 capability record 矩阵的 ABI/world 兼容 fence（复用矩阵错误码表）。 */
export function checkRuntimeBindingCapabilityCompatibility(record: NodeCapabilityRecordV1, runtimeBinding: RuntimeBindingIdentityV1): ValidationResult<true> {
	if (runtimeBinding.world !== record.matrix.world) {
		return failure([issue(WASM_WORLD_UNSUPPORTED, "/world", "the runtime binding world is not the matrix world of the pinned node capability record")]);
	}
	if (runtimeBinding.hostABI !== record.matrix.hostABI) {
		return failure([issue(WASM_HOST_ABI_MISMATCH, "/hostABI", "the runtime binding host ABI is not the matrix ABI of the pinned node capability record")]);
	}
	return ok(true);
}

// ---------------------------------------------------------------------------
// 向量/示例构造器（供跨实现 round-trip 与后续任务 fixture 复用）
// ---------------------------------------------------------------------------

export function exampleRuntimeCatalogV1(): RuntimeCatalogV1 {
	const payload: RuntimeCatalogPayloadV1 = {
		schemaVersion: 1,
		revision: 8,
		entries: [
			{ entryKey: "iweb-wasmd-amd64", kind: "wasm", imageDigest: "sha256:" + "aa".repeat(32), hostABI: WASM_HOST_ABI_LITERAL, world: WASM_WORLD_LITERAL, architecture: "linux/amd64", status: "active" },
			{ entryKey: "iweb-wasmd-arm64", kind: "wasm", imageDigest: "sha256:" + "bb".repeat(32), hostABI: WASM_HOST_ABI_LITERAL, world: WASM_WORLD_LITERAL, architecture: "linux/arm64", status: "active" },
			{
				entryKey: "legacy-wasmd-amd64",
				kind: "wasm",
				imageDigest: "sha256:" + "cc".repeat(32),
				hostABI: WASM_HOST_ABI_LITERAL,
				world: WASM_WORLD_LITERAL,
				architecture: "linux/amd64",
				status: "revoked",
				revocation: { cve: "CVE-2026-1234", reasonCode: "wasmd-memory-corruption", revokedAt: "2026-08-01T00:00:00Z" },
			},
		],
	};
	return { ...payload, catalogHash: computeRuntimeCatalogHashV1(payload) };
}

/** 从示例 catalog 派生绑定该 entry 的完整七字段 binding（含 revision/hash pin）。 */
export function exampleRuntimeBindingForCatalogEntry(catalog: RuntimeCatalogV1, entryKey: string): RuntimeBindingIdentityV1 {
	const entry = catalog.entries.find((candidate) => candidate.entryKey === entryKey);
	if (entry === undefined) throw new Error("example entry key not found: " + entryKey);
	return { kind: "wasm", catalogRevision: catalog.revision, catalogHash: catalog.catalogHash, entryKey: entry.entryKey, imageDigest: entry.imageDigest, hostABI: entry.hostABI, world: entry.world };
}

export function exampleNodeCapabilityRecordV1(): NodeCapabilityRecordV1 {
	const binding = exampleRuntimeBindingForCatalogEntry(exampleRuntimeCatalogV1(), "iweb-wasmd-amd64");
	const payload: NodeCapabilityRecordPayloadV1 = {
		schemaVersion: 1,
		revision: 5,
		policyMaxima: { cpuMillis: 500000, memoryBytes: 68719476736, pidLimit: 100000, storageBytes: 1099511627776 },
		http: { maxRequestBytes: 16777216, maxResponseBytes: 67108864, maxRequestHeaderBytes: 8192, maxResponseHeaderBytes: 8192, maxRequestHeaderCount: 64, maxResponseHeaderCount: 64, maxConcurrentRequests: 256 },
		engine: { maxEpochDeadlineMs: 60000, fuelPerRequest: null, maxLiveInstances: 128 },
		admission: { maxPackageBytes: 536870912, maxBlobBytes: 134217728, maxLayerCount: 128, maxClosureNodes: 4096, maxClosureEdges: 16384, maxClosureDepth: 64, stagingTtlSeconds: 3600 },
		restart: { maxRestarts: 3, windowMs: 600000 },
		drainDeadlineMs: 30000,
		// 同一 binding 的双架构条目：JCS 相同时按 architecture 决定排序（amd64 < arm64）。
		runtimeReserves: [
			{ runtimeBinding: binding, architecture: "linux/amd64", reserveBytes: 33554432 },
			{ runtimeBinding: binding, architecture: "linux/arm64", reserveBytes: 33554432 },
		],
		matrix: WASM_CAPABILITY_MATRIX_REVISION_1,
	};
	return { ...payload, recordHash: computeNodeCapabilityRecordHashV1(payload) };
}

export function exampleWasmRollbackRecordV1(targetRuntimeBinding: RuntimeBindingIdentityV1): WasmRollbackRecordV1 {
	return {
		applicationId: "vector",
		fromVersionId: "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-2",
		toVersionId: "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1",
		targetRuntimeBinding,
		routeGeneration: 4,
		createdAt: "2026-08-26T00:00:00Z",
		ownerCommandId: "018f1e2c-3d4b-7a5e-9f01-23456789abcd",
	};
}

export function exampleCatalogHistoryRecordV1(catalog: RuntimeCatalogV1 = exampleRuntimeCatalogV1(), storedAt = "2026-08-26T00:00:00Z"): CatalogHistoryRecordV1 {
	const payload: CatalogHistoryRecordPayloadV1 = { schemaVersion: 1, runtimeKind: "wasm", revision: catalog.revision, catalogHash: catalog.catalogHash, catalog, storedAt };
	return { ...payload, recordDigest: computeCatalogHistoryRecordDigestV1(payload) };
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. spec 未为 indexDigest/receiptDigest 给出显式公式；按本 capability「域前缀单次 SHA-256 over
//    JCS(record with digest omitted)」的统一风格补齐域常量（iweb-catalog-history-index-v1 /
//    iweb-catalog-release-receipt-v1），并以导出常量固定，跨实现不会漂移。
// 2. delete audit 的 objectDigest：spec 只写 `objectDigest` 未给公式。取被删对象的完整 JCS 字节的
//    无前缀 SHA-256（与 spec 中 sourceDigest/targetDigest 的 raw-file digest 同风格），可在删除后
//    对照历史记录复算验证。
// 3. 「CVE-revoked ... entries are never eligible for release deletion」与 owner CVE 路径
//    「release/delete only after no protected reference remains」存在字面张力；按后者与 GC 门条件实现：
//    资格由受保护引用（而非 revoked 状态）决定，revocation 本身既不启用也不阻断删除。
// 4. revoke 单向性：append 拒绝把已 revoked entry 翻回 active 或改写 revocation（由
//    WASM_CATALOG_REVOCATION_REGRESSION 补充码承载），落实「a released/revoked binding cannot be reactivated」。
// 5. CVE 文法取 /^CVE-\d{4}-\d{4,}$/；reasonCode 取 /^[a-z][a-z0-9.-]{0,63}$/（spec 仅说 bounded opaque
//    lower-case identifier）；delete audit reason 取 ≤128 可打印字符。均为补充文法，拒绝更宽松输入。
// 6. entry 的 imageDigest 在 schema 层只做 oci-sha256 文法校验；「manifest 而非 index/list digest」的
//    内容级判定属发布门 v2（任务 4.3）的 acceptance record 对照，不在本文件伪造。
// 7. catalog entries 允许为空（spec 只给 ≤128 上界）；runtimeReserves 依 spec 必须非空。
// 8. 索引 current 指针必须等于最高 present revision 且 hash 一致（「index/file disagreement fails closed」
//    的严格化）；索引条目 deleted ⇔ deletedAt 非空为补充耦合。
// 9. release 要求 drainedAt <= releasedAt（drain receipt 先于 release 记录）为补充排序约束。
// 10. owner 更新协议的「supervisor 来源拒绝」与「历史 revision 不可变更」由宿主授权层/存储层强制；
//     纯函数只做 CAS 与结构校验，不感知调用来源（文档化而非伪造 origin 参数）。
// 11. 补充错误码（CATALOG_*、WASM_CATALOG_*、WASM_NODE_CAPABILITY_*、WASM_CAPABILITY_* 等）沿用
//     既有命名风格补齐；spec 已命名码（WASM_RESOURCE_RECORD_INVALID、WASM_WORLD_UNSUPPORTED、
//     WASM_HOST_ABI_MISMATCH）逐字复用。catalog revision conflict 场景码定为 CATALOG_REVISION_CONFLICT
//     （与 CONTROL/SECRET/CONFIG_REVISION_CONFLICT 命名一致）。
