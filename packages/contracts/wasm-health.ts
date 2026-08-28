// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.2 剩余，schema+向量先行）：readiness health v2、ReadinessLeaseV2 与 engine metrics v1 必须先有 unknown-field-rejecting typed wire 契约，宿主（gateway probe / Kernel CAS / metrics 投影）不得自行解释字段。
// 正交意图：精确键集（缺失/未知字段一律拒绝）、u53 与双代次下界、celld health v1 / celld readiness lease 只拒绝绝不采纳或推断转换、fuel 禁用唯一表示 null、unavailable 唯一表示 engine:null、同 E 内 counter 非负单调、E 变更才可重置、乱序/unknown/mismatch 拒绝；复用 wasm-package.ts 的 JCS/digest/名称文法与 wasm-execution.ts 的 RuntimeBindingIdentityV1，绝不定义第二套编码。
// 轮次注记：本文件承载 WasmReadinessHealthV2 校验与期望比对、ReadinessLeaseV2（nonce 文法/leaseDigest 公式/过期与 consume/replay 纯函数）、WasmEngineMetricsV1 wire 与单调查看状态机、applicationId/versionId grammar 统一助手；激活 envelope 全 wire（ActivationCommandV1/RouteEventV1）属后续任务，不在此文件。
// 轮次注记（2026-08-28，add-wasm-host-services P0-3 V2 wire 正式化）：新增 ServiceReadinessHealthV2/ServiceEngineMetricsV2（readiness/metrics 两族 wire 的 V2 扩展——V1 全字段 + ABI 1.1.0 binding + hostServicePolicyDigest；validator/correlate/example）。既有 ReadinessLeaseV2（Kernel 激活租约）与 V1 代际 wire 一字不变。
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "./validation.ts";
import {
	composeWasmVersionId,
	jcsCanonicalBytes,
	parseWasmVersionId,
	sha256Hex,
	WASM_APPLICATION_ID_PATTERN,
	WASM_SHA256_HEX_PATTERN,
	WASM_U53_MAX,
	WASM_VERSION_ID_PATTERN,
} from "./wasm-package.ts";
import {
	validateRuntimeBindingIdentityV1,
	validateRuntimeBindingIdentityV2,
	WASM_IDENTITY_INCOMPLETE,
	WASM_RFC3339_UTC_PATTERN,
	type RuntimeBindingIdentityV1,
	type RuntimeBindingIdentityV2,
} from "./wasm-execution.ts";
import { WASM_HOST_POLICY_DIGEST_MISMATCH } from "./wasm-host-policy.ts";

// ---------------------------------------------------------------------------
// 稳定错误码与文法常量
// ---------------------------------------------------------------------------

// spec 已命名码：任一 lease 采纳判负（celld v1 lease、缺 nonce、跨 tuple 复用 nonce、
// config 引用与 revision 矛盾）→ READINESS_LEASE_MISMATCH；CAS 线性化时刻 expiresAt
// 相等或更晚 → READINESS_LEASE_EXPIRED；celld 单字段信号 → WASM_IDENTITY_INCOMPLETE。
export const READINESS_LEASE_MISMATCH = "READINESS_LEASE_MISMATCH";
export const READINESS_LEASE_EXPIRED = "READINESS_LEASE_EXPIRED";

// spec 未命名的补充稳定码（沿用 wasm-package/wasm-execution 的命名风格；不覆盖已命名码）。
const HEALTH_CODE = "WASM_READINESS_HEALTH_V2_INVALID";
const LEASE_CODE = "WASM_READINESS_LEASE_INVALID";
const METRICS_CODE = "WASM_ENGINE_METRICS_INVALID";
const LEASE_NONCE_REPLAY = "READINESS_LEASE_NONCE_REPLAY";

// leaseNonce 是 16 个随机字节的 32 位小写十六进制渲染；绝不从时间戳或 versionId 派生。
export const WASM_LEASE_NONCE_PATTERN = /^[a-f0-9]{32}$/;

// leaseDigest = hex(SHA-256(UTF8("iweb-readiness-lease-v2\n" || JCS(record with leaseDigest omitted))))。
export const READINESS_LEASE_DIGEST_DOMAIN = "iweb-readiness-lease-v2";

// NodeCapabilityRecordV1.admission.stagingTtlSeconds 的 record 界（1..3600 秒）。
export const WASM_STAGING_TTL_SECONDS_MIN = 1;
export const WASM_STAGING_TTL_SECONDS_MAX = 3600;

// ---------------------------------------------------------------------------
// grammar 统一助手：ApplicationId（<=63 ASCII 字节）与 VersionId（64 hex-无前导零 sequence）
// ---------------------------------------------------------------------------

// 文法唯一权威在 wasm-package.ts 的 pattern 与 parse/compose；这里只做薄封装供
// health/lease/metrics 三类 wire 与宿主复用，绝不重写第二套解释。
export function validateWasmApplicationIdGrammar(input: unknown): ValidationResult<string> {
	if (typeof input !== "string" || !WASM_APPLICATION_ID_PATTERN.test(input)) {
		return failure([issue("WASM_APPLICATION_ID_INVALID", "", "applicationId must match ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$ (max 63 ASCII bytes)")]);
	}
	return ok(input);
}

export function validateWasmVersionIdGrammar(input: unknown): ValidationResult<string> {
	if (typeof input !== "string" || !WASM_VERSION_ID_PATTERN.test(input)) {
		return failure([issue("WASM_VERSION_ID_INVALID", "", "versionId must match ^[a-f0-9]{64}-[1-9][0-9]{0,15}$ (sequence without leading zero)")]);
	}
	const parsed = parseWasmVersionId(input);
	if (!parsed.ok) {
		return failure([issue("WASM_VERSION_ID_INVALID", "/sequence", "versionId sequence must be a positive u53 integer without leading zero")]);
	}
	return ok(input);
}

// ---------------------------------------------------------------------------
// 共享 require 小工具（与 wasm-execution.ts 同款私有助手；不跨文件导出编码语义）
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

function requireNullableSha256Hex(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null | undefined {
	if (value === null) return null;
	if (typeof value === "string" && WASM_SHA256_HEX_PATTERN.test(value)) return value;
	errors.push(issue(code, path + "/" + fieldName, fieldName + " must be null or a 64-character lower-case hex digest"));
	return undefined;
}

function requireSandboxId(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be a lower-case sandbox identifier starting with a letter (max 63 ASCII bytes)"));
		return null;
	}
	return value;
}

function requireVersionId(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_VERSION_ID_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be <64 lower-case hex>-<positive sequence without leading zero>"));
		return null;
	}
	const parsed = parseWasmVersionId(value);
	if (!parsed.ok) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " sequence must be a positive u53 integer"));
		return null;
	}
	return value;
}

function requireLeaseNonce(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_LEASE_NONCE_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be exactly 32 lower-case hexadecimal characters (16 random bytes)"));
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

// configRevision:0 ⇔ configSnapshotRef:null ⇔（如该 wire 携带）configValuesDigest:null；
// 非零 revision 三者齐全。这是 readiness v2 / lease v2 / metrics v1 共用的耦合法则。
function checkConfigSnapshotCoupling(
	configRevision: number,
	configSnapshotRef: string | null,
	configValuesDigest: string | null | undefined,
	path: string,
	code: string,
	errors: ValidationIssue[],
): void {
	// 注意：configValuesDigest 为 undefined 表示该 wire（如 metrics v1）不携带该字段，
	// 只对「已携带且非 null」配合 revision 0 判负；不得把 undefined 当成 null 处理。
	if (configRevision === 0 && (configSnapshotRef !== null || (configValuesDigest !== undefined && configValuesDigest !== null))) {
		errors.push(issue(code, path + "/configSnapshotRef", "configRevision 0 requires configSnapshotRef null and configValuesDigest null"));
	}
	if (configRevision > 0 && (configSnapshotRef === null || configValuesDigest === null)) {
		errors.push(issue(code, path + "/configSnapshotRef", "a non-zero configRevision requires both configSnapshotRef and configValuesDigest"));
	}
	if (configValuesDigest !== undefined && (configSnapshotRef === null) !== (configValuesDigest === null)) {
		errors.push(issue(code, path + "/configValuesDigest", "configValuesDigest is null exactly when configSnapshotRef is null"));
	}
}

// celld 兼容边界（与 wasm-execution.ts 的 WasmExecutionIdentityV1 判定同款）：
// 携带 sandboxId/versionId 却缺双代次、或携带 celld `generation`/`sequence` 信号的
// health/metrics/readiness 载荷是 WASM_IDENTITY_INCOMPLETE，绝不采纳、绝不推断转换。
function pushIdentityIncompleteIfCelldSignal(input: Record<string, unknown>, path: string, errors: ValidationIssue[]): void {
	const carriesIdentityKey = "sandboxId" in input || "versionId" in input;
	const missingFence = !("preparationGeneration" in input) || !("executionGeneration" in input);
	const celldSignal = "generation" in input || "sequence" in input;
	if (carriesIdentityKey && (missingFence || celldSignal)) {
		errors.push(
			issue(
				WASM_IDENTITY_INCOMPLETE,
				path,
				"a wasm health/lease/metrics signal must carry the full identity and (preparationGeneration, executionGeneration) fence; celld sequence/generation signals never substitute for wasm generations",
			),
		);
	}
}

function domainPrefixedDigest(domain: string, payload: Uint8Array): string {
	return sha256Hex(Buffer.concat([Buffer.from(domain + "\n", "utf8"), Buffer.from(payload)]));
}

function jcsEqual(left: unknown, right: unknown): boolean {
	// 已验证值域上的结构相等性：以 JCS 字节为准（不引入第二套 deep-equal 语义）。
	return Buffer.compare(Buffer.from(jcsCanonicalBytes(left)), Buffer.from(jcsCanonicalBytes(right))) === 0;
}

function epochMs(timestamp: string): number {
	return Date.parse(timestamp);
}

// ---------------------------------------------------------------------------
// readiness health v2（wasmd 内部健康载荷；唯一合法形态是 ok:true 的精确 15 字段 JCS）
// ---------------------------------------------------------------------------

export interface WasmReadinessHealthV2 {
	readonly schemaVersion: 2;
	readonly ok: true;
	readonly sandboxId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly secretValuesDigest: string;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly configValuesDigest: string | null;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
}

function requireWasmReadinessHealthV2(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmReadinessHealthV2 | null {
	const health = requireObject(input, path, "wasm readiness health v2 payload", code, errors);
	if (health === null) return null;
	requireExactKeys(
		health,
		path,
		[
			"schemaVersion",
			"ok",
			"sandboxId",
			"versionId",
			"packageDigest",
			"runtimeBinding",
			"capabilityRecordRevision",
			"capabilityRecordHash",
			"secretRevision",
			"secretValuesDigest",
			"configRevision",
			"configSnapshotRef",
			"configValuesDigest",
			"preparationGeneration",
			"executionGeneration",
		],
		code,
		errors,
	);
	pushIdentityIncompleteIfCelldSignal(health, path, errors);

	const schemaVersion = requireSafeInteger(health.schemaVersion, path, "schemaVersion", 2, 2, code, errors);
	if (health.ok !== true) {
		// v2 wire 只有 ok:true 这一形态；ok:false/缺失属 not-ready 级别的 wire 拒绝，不是健康状态位。
		errors.push(issue(code, path + "/ok", 'ok must be the literal true; a not-ready wasmd emits no v2 payload'));
	}
	const sandboxId = requireSandboxId(health.sandboxId, path, "sandboxId", code, errors);
	const versionId = requireVersionId(health.versionId, path, "versionId", code, errors);
	const packageDigest = requireSha256Hex(health.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentityField(health.runtimeBinding, path + "/runtimeBinding", code, errors);
	const capabilityRecordRevision = requireSafeInteger(health.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASM_U53_MAX, code, errors);
	const capabilityRecordHash = requireSha256Hex(health.capabilityRecordHash, path, "capabilityRecordHash", code, errors);
	const secretRevision = requireSafeInteger(health.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const secretValuesDigest = requireSha256Hex(health.secretValuesDigest, path, "secretValuesDigest", code, errors);
	const configRevision = requireSafeInteger(health.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);
	const configSnapshotRef = requireNullableSha256Hex(health.configSnapshotRef, path, "configSnapshotRef", code, errors);
	const configValuesDigest = requireNullableSha256Hex(health.configValuesDigest, path, "configValuesDigest", code, errors);
	// 存活/报告健康的 execution 双代次必须 >= 1（executionGeneration:0 只允许出现在首次分配前）。
	const preparationGeneration = requireSafeInteger(health.preparationGeneration, path, "preparationGeneration", 1, WASM_U53_MAX, code, errors);
	const executionGeneration = requireSafeInteger(health.executionGeneration, path, "executionGeneration", 1, WASM_U53_MAX, code, errors);

	if (
		schemaVersion === null ||
		sandboxId === null ||
		versionId === null ||
		packageDigest === null ||
		runtimeBinding === null ||
		capabilityRecordRevision === null ||
		capabilityRecordHash === null ||
		secretRevision === null ||
		secretValuesDigest === null ||
		configRevision === null ||
		configSnapshotRef === undefined ||
		configValuesDigest === undefined ||
		preparationGeneration === null ||
		executionGeneration === null ||
		errors.length
	) {
		return null;
	}
	checkConfigSnapshotCoupling(configRevision, configSnapshotRef, configValuesDigest, path, code, errors);
	if (errors.length) return null;
	return {
		schemaVersion: 2,
		ok: true,
		sandboxId,
		versionId,
		packageDigest,
		runtimeBinding,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
		preparationGeneration,
		executionGeneration,
	};
}

function requireRuntimeBindingIdentityField(input: unknown, path: string, code: string, errors: ValidationIssue[]): RuntimeBindingIdentityV1 | null {
	const parsed = validateRuntimeBindingIdentityV1(input);
	if (parsed.ok) return parsed.value;
	for (const entry of parsed.errors) errors.push(issue(code, path + entry.path, entry.message));
	return null;
}

export function validateWasmReadinessHealthV2(input: unknown): ValidationResult<WasmReadinessHealthV2> {
	const errors: ValidationIssue[] = [];
	const value = requireWasmReadinessHealthV2(input, "", HEALTH_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

// 期望 fence：gateway probe 的期望来自 supervisor command / Kernel 记录，携带与
// health v2 / lease v2 相同的身份 + 快照 digest 字段（两类记录结构性满足本接口）。
export interface WasmReadinessFenceFields {
	readonly sandboxId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly secretValuesDigest: string;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly configValuesDigest: string | null;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
}

// 任一身份字段错配 → 内部 mismatch 码（宿主映射 409）；probe 不签发/采纳 lease。
// 比较含 binding 的 catalogRevision/catalogHash、entry key、image digest、ABI、world 全七字段。
export function correlateWasmReadinessHealthV2(expected: WasmReadinessFenceFields, reported: WasmReadinessHealthV2): ValidationResult<WasmReadinessHealthV2> {
	const errors: ValidationIssue[] = [];
	if (expected.sandboxId !== reported.sandboxId) errors.push(issue("SANDBOX_ID_MISMATCH", "/sandboxId", "health sandbox ID does not match the expected execution"));
	if (expected.versionId !== reported.versionId) errors.push(issue("VERSION_ID_MISMATCH", "/versionId", "health version ID does not match the expected execution"));
	if (expected.preparationGeneration !== reported.preparationGeneration || expected.executionGeneration !== reported.executionGeneration) {
		errors.push(issue("EXECUTION_GENERATION_MISMATCH", "/preparationGeneration", "health preparation/execution generations do not match the expected execution"));
	}
	if (expected.packageDigest !== reported.packageDigest) errors.push(issue("PACKAGE_DIGEST_MISMATCH", "/packageDigest", "health package digest does not match the expected execution"));
	if (!jcsEqual(expected.runtimeBinding, reported.runtimeBinding)) {
		errors.push(issue("RUNTIME_BINDING_MISMATCH", "/runtimeBinding", "health runtime binding (including catalog revision/hash) does not match the expected execution"));
	}
	if (expected.capabilityRecordRevision !== reported.capabilityRecordRevision || expected.capabilityRecordHash !== reported.capabilityRecordHash) {
		errors.push(issue("CAPABILITY_RECORD_MISMATCH", "/capabilityRecordRevision", "health capability record pin does not match the expected execution"));
	}
	if (expected.secretRevision !== reported.secretRevision || expected.secretValuesDigest !== reported.secretValuesDigest) {
		errors.push(issue("SECRET_SNAPSHOT_MISMATCH", "/secretRevision", "health secret revision/values digest do not match the expected execution"));
	}
	if (
		expected.configRevision !== reported.configRevision ||
		expected.configSnapshotRef !== reported.configSnapshotRef ||
		expected.configValuesDigest !== reported.configValuesDigest
	) {
		errors.push(issue("CONFIG_SNAPSHOT_MISMATCH", "/configRevision", "health config revision/reference/digest do not match the expected execution"));
	}
	if (errors.length) return failure(errors);
	return ok(reported);
}

// ---------------------------------------------------------------------------
// ReadinessLeaseV2（nonce 绑定的 canonical wire；不是 celld {versionId,expiresAt} 记录）
// ---------------------------------------------------------------------------

export interface ReadinessLeaseV2 {
	readonly schemaVersion: 2;
	readonly leaseNonce: string;
	readonly sandboxId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly secretValuesDigest: string;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly configValuesDigest: string | null;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
	readonly issuedAt: string;
	readonly expiresAt: string;
	readonly leaseDigest: string;
}

export type ReadinessLeaseV2WithoutDigest = Omit<ReadinessLeaseV2, "leaseDigest">;

// leaseDigest = hex(SHA-256(UTF8("iweb-readiness-lease-v2\n" || JCS(record with leaseDigest omitted))))。
export function computeReadinessLeaseDigestV2(record: ReadinessLeaseV2WithoutDigest): string {
	return domainPrefixedDigest(READINESS_LEASE_DIGEST_DOMAIN, jcsCanonicalBytes(record));
}

export interface ReadinessLeaseValidationOptions {
	// 节点 capability record 的 admission.stagingTtlSeconds（1..3600）；提供时强制
	// expiresAt 不晚于 issuedAt + TTL。租约字节自身无法证明 pinned TTL，宿主持久化
	// 校验必须传入；省略时只校验 expiresAt > issuedAt（fail-closed 备注：见文末歧义）。
	readonly stagingTtlSeconds?: number;
}

function requireReadinessLeaseV2(input: unknown, path: string, options: ReadinessLeaseValidationOptions | undefined, code: string, errors: ValidationIssue[]): ReadinessLeaseV2 | null {
	const lease = requireObject(input, path, "readiness lease v2", code, errors);
	if (lease === null) return null;
	requireExactKeys(
		lease,
		path,
		[
			"schemaVersion",
			"leaseNonce",
			"sandboxId",
			"versionId",
			"packageDigest",
			"runtimeBinding",
			"capabilityRecordRevision",
			"capabilityRecordHash",
			"secretRevision",
			"secretValuesDigest",
			"configRevision",
			"configSnapshotRef",
			"configValuesDigest",
			"preparationGeneration",
			"executionGeneration",
			"issuedAt",
			"expiresAt",
			"leaseDigest",
		],
		code,
		errors,
	);
	pushIdentityIncompleteIfCelldSignal(lease, path, errors);

	const schemaVersion = requireSafeInteger(lease.schemaVersion, path, "schemaVersion", 2, 2, code, errors);
	const leaseNonce = requireLeaseNonce(lease.leaseNonce, path, "leaseNonce", code, errors);
	const sandboxId = requireSandboxId(lease.sandboxId, path, "sandboxId", code, errors);
	const versionId = requireVersionId(lease.versionId, path, "versionId", code, errors);
	const packageDigest = requireSha256Hex(lease.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentityField(lease.runtimeBinding, path + "/runtimeBinding", code, errors);
	const capabilityRecordRevision = requireSafeInteger(lease.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASM_U53_MAX, code, errors);
	const capabilityRecordHash = requireSha256Hex(lease.capabilityRecordHash, path, "capabilityRecordHash", code, errors);
	const secretRevision = requireSafeInteger(lease.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const secretValuesDigest = requireSha256Hex(lease.secretValuesDigest, path, "secretValuesDigest", code, errors);
	const configRevision = requireSafeInteger(lease.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);
	const configSnapshotRef = requireNullableSha256Hex(lease.configSnapshotRef, path, "configSnapshotRef", code, errors);
	const configValuesDigest = requireNullableSha256Hex(lease.configValuesDigest, path, "configValuesDigest", code, errors);
	const preparationGeneration = requireSafeInteger(lease.preparationGeneration, path, "preparationGeneration", 1, WASM_U53_MAX, code, errors);
	const executionGeneration = requireSafeInteger(lease.executionGeneration, path, "executionGeneration", 1, WASM_U53_MAX, code, errors);
	const issuedAt = requireRfc3339Utc(lease.issuedAt, path, "issuedAt", code, errors);
	const expiresAt = requireRfc3339Utc(lease.expiresAt, path, "expiresAt", code, errors);
	const leaseDigest = requireSha256Hex(lease.leaseDigest, path, "leaseDigest", code, errors);

	if (
		schemaVersion === null ||
		leaseNonce === null ||
		sandboxId === null ||
		versionId === null ||
		packageDigest === null ||
		runtimeBinding === null ||
		capabilityRecordRevision === null ||
		capabilityRecordHash === null ||
		secretRevision === null ||
		secretValuesDigest === null ||
		configRevision === null ||
		configSnapshotRef === undefined ||
		configValuesDigest === undefined ||
		preparationGeneration === null ||
		executionGeneration === null ||
		issuedAt === null ||
		expiresAt === null ||
		leaseDigest === null ||
		errors.length
	) {
		return null;
	}
	checkConfigSnapshotCoupling(configRevision, configSnapshotRef, configValuesDigest, path, code, errors);

	// expiresAt 必须严格晚于 issuedAt，且（提供 pinned TTL 时）不晚于 issuedAt + stagingTtlSeconds。
	if (epochMs(expiresAt) <= epochMs(issuedAt)) {
		errors.push(issue(code, path + "/expiresAt", "expiresAt must be later than issuedAt"));
	}
	if (options !== undefined && options.stagingTtlSeconds !== undefined) {
		const ttl = options.stagingTtlSeconds;
		if (typeof ttl !== "number" || !Number.isSafeInteger(ttl) || ttl < WASM_STAGING_TTL_SECONDS_MIN || ttl > WASM_STAGING_TTL_SECONDS_MAX) {
			errors.push(issue(code, path + "/expiresAt", "stagingTtlSeconds option must be an integer between 1 and 3600"));
		} else if (epochMs(expiresAt) - epochMs(issuedAt) > ttl * 1000) {
			errors.push(issue(code, path + "/expiresAt", "expiresAt must be no farther than stagingTtlSeconds from issuedAt"));
		}
	}

	if (errors.length) return null;

	// fail-closed：leaseDigest 必须可由其余字段精确复算（持久化候选存完整 canonical 字节或
	// 内容寻址引用 + digest；重启后重载必须过本复算，否则按 not-ready 处理）。
	const expectedDigest = computeReadinessLeaseDigestV2({
		schemaVersion: 2,
		leaseNonce,
		sandboxId,
		versionId,
		packageDigest,
		runtimeBinding,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
		preparationGeneration,
		executionGeneration,
		issuedAt,
		expiresAt,
	});
	if (leaseDigest !== expectedDigest) {
		errors.push(issue(READINESS_LEASE_MISMATCH, path + "/leaseDigest", 'leaseDigest must equal hex(SHA-256(UTF8("iweb-readiness-lease-v2\\n" || JCS(record with leaseDigest omitted))))'));
		return null;
	}
	return {
		schemaVersion: 2,
		leaseNonce,
		sandboxId,
		versionId,
		packageDigest,
		runtimeBinding,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
		preparationGeneration,
		executionGeneration,
		issuedAt,
		expiresAt,
		leaseDigest,
	};
}

export function validateReadinessLeaseV2(input: unknown, options?: ReadinessLeaseValidationOptions): ValidationResult<ReadinessLeaseV2> {
	const errors: ValidationIssue[] = [];
	const value = requireReadinessLeaseV2(input, "", options, LEASE_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

// CAS 线性化时刻的过期判定：单调时钟与 expiresAt 相等或更晚即拒绝（READINESS_LEASE_EXPIRED）。
export function checkReadinessLeaseExpiry(lease: Pick<ReadinessLeaseV2, "expiresAt">, nowEpochMs: number): ValidationResult<true> {
	if (typeof nowEpochMs !== "number" || !Number.isSafeInteger(nowEpochMs)) {
		return failure([issue(LEASE_CODE, "/expiresAt", "the CAS instant must be a safe integer epoch millisecond value")]);
	}
	if (nowEpochMs >= epochMs(lease.expiresAt)) {
		return failure([issue(READINESS_LEASE_EXPIRED, "/expiresAt", "the readiness lease expired at or before the CAS linearization instant; a fresh preparation plus exact health attestation is required")]);
	}
	return ok(true);
}

// lease 与激活 fence 的一致性（期望来自 Kernel 当前执行记录/激活 candidate）；
// 任一字段错配（含跨 tuple 复用 nonce 时宿主另行判定）→ READINESS_LEASE_MISMATCH 级别拒绝。
export function correlateReadinessLeaseV2(expected: WasmReadinessFenceFields, lease: ReadinessLeaseV2): ValidationResult<ReadinessLeaseV2> {
	const errors: ValidationIssue[] = [];
	if (expected.sandboxId !== lease.sandboxId) errors.push(issue(READINESS_LEASE_MISMATCH, "/sandboxId", "lease sandbox ID does not match the expected execution"));
	if (expected.versionId !== lease.versionId) errors.push(issue(READINESS_LEASE_MISMATCH, "/versionId", "lease version ID does not match the expected execution"));
	if (expected.preparationGeneration !== lease.preparationGeneration || expected.executionGeneration !== lease.executionGeneration) {
		errors.push(issue(READINESS_LEASE_MISMATCH, "/preparationGeneration", "lease preparation/execution generations do not match the expected execution"));
	}
	if (expected.packageDigest !== lease.packageDigest) errors.push(issue(READINESS_LEASE_MISMATCH, "/packageDigest", "lease package digest does not match the expected execution"));
	if (!jcsEqual(expected.runtimeBinding, lease.runtimeBinding)) {
		errors.push(issue(READINESS_LEASE_MISMATCH, "/runtimeBinding", "lease runtime binding (including catalog revision/hash) does not match the expected execution"));
	}
	if (expected.capabilityRecordRevision !== lease.capabilityRecordRevision || expected.capabilityRecordHash !== lease.capabilityRecordHash) {
		errors.push(issue(READINESS_LEASE_MISMATCH, "/capabilityRecordRevision", "lease capability record pin does not match the expected execution"));
	}
	if (expected.secretRevision !== lease.secretRevision || expected.secretValuesDigest !== lease.secretValuesDigest) {
		errors.push(issue(READINESS_LEASE_MISMATCH, "/secretRevision", "lease secret revision/values digest do not match the expected execution"));
	}
	if (expected.configRevision !== lease.configRevision || expected.configSnapshotRef !== lease.configSnapshotRef || expected.configValuesDigest !== lease.configValuesDigest) {
		errors.push(issue(READINESS_LEASE_MISMATCH, "/configRevision", "lease config revision/reference/digest do not match the expected execution"));
	}
	if (errors.length) return failure(errors);
	return ok(lease);
}

// --- nonce consume/replay 纯函数（Kernel route CAS 使用） ---
//
// 台账以 nonce -> 已消费 leaseDigest 的只读 Map 表示（持久化投影由宿主落
// LeaseConsumeRecordV1/route event；本层只做纯判定）。同一 nonce 绑定同一 tuple：
// - 已存在且 digest 相同 → already-consumed（宿主必须按 activationId 返回原始结果，
//   不二次激活、不递增 route generation）；
// - 已存在且 digest 不同 → READINESS_LEASE_MISMATCH（跨 tuple 复用 nonce）；
// - 未消费 → 先判过期（相等或更晚拒绝），再消费。
// 判定顺序：nonce 先于过期（重放场景返回原始结果，而非新的过期错误）。
export type ReadinessLeaseNonceLedger = ReadonlyMap<string, string>;

export type ReadinessLeaseConsumeOutcome =
	| { readonly outcome: "consumed"; readonly nextLedger: ReadinessLeaseNonceLedger }
	| { readonly outcome: "already-consumed"; readonly leaseDigest: string }
	| { readonly outcome: "rejected"; readonly errors: readonly ValidationIssue[] };

export function isReadinessLeaseNonceConsumed(ledger: ReadinessLeaseNonceLedger, leaseNonce: string): boolean {
	return ledger.has(leaseNonce);
}

export function consumeReadinessLeaseV2(ledger: ReadinessLeaseNonceLedger, lease: ReadinessLeaseV2, nowEpochMs: number): ReadinessLeaseConsumeOutcome {
	const recorded = ledger.get(lease.leaseNonce);
	if (recorded !== undefined) {
		if (recorded !== lease.leaseDigest) {
			return {
				outcome: "rejected",
				errors: [issue(READINESS_LEASE_MISMATCH, "/leaseNonce", "a duplicate nonce for another tuple is rejected; the same nonce cannot activate, rollback, or rebind twice")],
			};
		}
		return { outcome: "already-consumed", leaseDigest: recorded };
	}
	const expiry = checkReadinessLeaseExpiry(lease, nowEpochMs);
	if (!expiry.ok) return { outcome: "rejected", errors: expiry.errors };
	const nextLedger: Map<string, string> = new Map(ledger);
	nextLedger.set(lease.leaseNonce, lease.leaseDigest);
	return { outcome: "consumed", nextLedger };
}

// ---------------------------------------------------------------------------
// engine metrics v1（supervisor -> Kernel 的完整可用性 wire）
// ---------------------------------------------------------------------------

export interface WasmEngineCountersV1 {
	readonly fuelConsumedCumulative: number | null;
	readonly epochTimeoutsCumulative: number;
	readonly instancesLiveInstant: number;
	readonly instancesHighWaterCumulative: number;
	readonly guestMemoryBytesInstant: number;
}

export interface WasmEngineMetricsV1 {
	readonly schemaVersion: 1;
	readonly sandboxId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
	readonly sampledAt: string;
	readonly availability: "available" | "unavailable";
	readonly engine: WasmEngineCountersV1 | null;
}

// Kernel 当前执行记录的比对 fence（metrics wire 不携带 values digest 与 secret ref）。
export interface WasmEngineMetricsFenceFields {
	readonly sandboxId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
}

export const WASM_ENGINE_METRICS_STALE = "WASM_ENGINE_METRICS_STALE";
export const WASM_ENGINE_METRICS_TIME_REGRESSION = "WASM_ENGINE_METRICS_TIME_REGRESSION";
export const WASM_ENGINE_METRICS_COUNTER_REGRESSION = "WASM_ENGINE_METRICS_COUNTER_REGRESSION";
export const WASM_ENGINE_METRICS_FUEL_REPRESENTATION = "WASM_ENGINE_METRICS_FUEL_REPRESENTATION";

function requireWasmEngineCountersV1(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmEngineCountersV1 | null {
	const engine = requireObject(input, path, "engine counters", code, errors);
	if (engine === null) return null;
	requireExactKeys(engine, path, ["fuelConsumedCumulative", "epochTimeoutsCumulative", "instancesLiveInstant", "instancesHighWaterCumulative", "guestMemoryBytesInstant"], code, errors);
	let fuelConsumedCumulative: number | null = null;
	let fuelParsed = false;
	if (engine.fuelConsumedCumulative === null) fuelParsed = true;
	else if (typeof engine.fuelConsumedCumulative === "number") {
		const value = requireSafeInteger(engine.fuelConsumedCumulative, path, "fuelConsumedCumulative", 0, WASM_U53_MAX, code, errors);
		if (value !== null) {
			fuelConsumedCumulative = value;
			fuelParsed = true;
		}
	} else {
		errors.push(issue(code, path + "/fuelConsumedCumulative", "fuelConsumedCumulative must be null (fuel disabled) or a non-negative u53 integer"));
	}
	const epochTimeoutsCumulative = requireSafeInteger(engine.epochTimeoutsCumulative, path, "epochTimeoutsCumulative", 0, WASM_U53_MAX, code, errors);
	const instancesLiveInstant = requireSafeInteger(engine.instancesLiveInstant, path, "instancesLiveInstant", 0, WASM_U53_MAX, code, errors);
	const instancesHighWaterCumulative = requireSafeInteger(engine.instancesHighWaterCumulative, path, "instancesHighWaterCumulative", 0, WASM_U53_MAX, code, errors);
	const guestMemoryBytesInstant = requireSafeInteger(engine.guestMemoryBytesInstant, path, "guestMemoryBytesInstant", 0, WASM_U53_MAX, code, errors);
	if (!fuelParsed || epochTimeoutsCumulative === null || instancesLiveInstant === null || instancesHighWaterCumulative === null || guestMemoryBytesInstant === null || errors.length) {
		return null;
	}
	return { fuelConsumedCumulative, epochTimeoutsCumulative, instancesLiveInstant, instancesHighWaterCumulative, guestMemoryBytesInstant };
}

function requireWasmEngineMetricsV1(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmEngineMetricsV1 | null {
	const metrics = requireObject(input, path, "wasm engine metrics v1 payload", code, errors);
	if (metrics === null) return null;
	requireExactKeys(
		metrics,
		path,
		[
			"schemaVersion",
			"sandboxId",
			"versionId",
			"packageDigest",
			"runtimeBinding",
			"capabilityRecordRevision",
			"capabilityRecordHash",
			"secretRevision",
			"configRevision",
			"configSnapshotRef",
			"preparationGeneration",
			"executionGeneration",
			"sampledAt",
			"availability",
			"engine",
		],
		code,
		errors,
	);
	pushIdentityIncompleteIfCelldSignal(metrics, path, errors);

	const schemaVersion = requireSafeInteger(metrics.schemaVersion, path, "schemaVersion", 1, 1, code, errors);
	const sandboxId = requireSandboxId(metrics.sandboxId, path, "sandboxId", code, errors);
	const versionId = requireVersionId(metrics.versionId, path, "versionId", code, errors);
	const packageDigest = requireSha256Hex(metrics.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentityField(metrics.runtimeBinding, path + "/runtimeBinding", code, errors);
	const capabilityRecordRevision = requireSafeInteger(metrics.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASM_U53_MAX, code, errors);
	const capabilityRecordHash = requireSha256Hex(metrics.capabilityRecordHash, path, "capabilityRecordHash", code, errors);
	const secretRevision = requireSafeInteger(metrics.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const configRevision = requireSafeInteger(metrics.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);
	const configSnapshotRef = requireNullableSha256Hex(metrics.configSnapshotRef, path, "configSnapshotRef", code, errors);
	// 报告 metrics 的存活 execution 双代次必须 >= 1。
	const preparationGeneration = requireSafeInteger(metrics.preparationGeneration, path, "preparationGeneration", 1, WASM_U53_MAX, code, errors);
	const executionGeneration = requireSafeInteger(metrics.executionGeneration, path, "executionGeneration", 1, WASM_U53_MAX, code, errors);
	const sampledAt = requireRfc3339Utc(metrics.sampledAt, path, "sampledAt", code, errors);

	const availability = typeof metrics.availability === "string" && (metrics.availability === "available" || metrics.availability === "unavailable") ? metrics.availability : null;
	if (availability === null) errors.push(issue(code, path + "/availability", 'availability must be exactly "available" or "unavailable"'));

	// unavailable 唯一表示：engine 当且仅当 unavailable 为 null；available 必须携带
	// 完整五字段 counters（engine 与每个子字段绝不允许缺失）。
	let engine: WasmEngineCountersV1 | null = null;
	let engineParsed = false;
	if (metrics.engine === null) {
		if (availability === "available") errors.push(issue(code, path + "/engine", 'an available sample must carry the exact engine counters object'));
		engineParsed = true;
	} else if (availability === "unavailable") {
		errors.push(issue(code, path + "/engine", 'engine must be null exactly when availability is unavailable'));
	} else {
		const parsed = requireWasmEngineCountersV1(metrics.engine, path + "/engine", code, errors);
		if (parsed !== null) {
			engine = parsed;
			engineParsed = true;
		}
	}

	if (
		schemaVersion === null ||
		sandboxId === null ||
		versionId === null ||
		packageDigest === null ||
		runtimeBinding === null ||
		capabilityRecordRevision === null ||
		capabilityRecordHash === null ||
		secretRevision === null ||
		configRevision === null ||
		configSnapshotRef === undefined ||
		preparationGeneration === null ||
		executionGeneration === null ||
		sampledAt === null ||
		availability === null ||
		!engineParsed ||
		errors.length
	) {
		return null;
	}
	// configRevision:0 要求 configSnapshotRef:null（metrics wire 无 configValuesDigest 字段）。
	checkConfigSnapshotCoupling(configRevision, configSnapshotRef, undefined, path, code, errors);
	if (errors.length) return null;
	return {
		schemaVersion: 1,
		sandboxId,
		versionId,
		packageDigest,
		runtimeBinding,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		configRevision,
		configSnapshotRef,
		preparationGeneration,
		executionGeneration,
		sampledAt,
		availability,
		engine,
	};
}

export function validateWasmEngineMetricsV1(input: unknown): ValidationResult<WasmEngineMetricsV1> {
	const errors: ValidationIssue[] = [];
	const value = requireWasmEngineMetricsV1(input, "", METRICS_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

// Kernel 只接受与当前执行记录完全一致的 metrics（旧 generation/错配 tuple 是 stale，
// 不是 reset；绝不因此改动当前 counters 或 availability）。
export function correlateWasmEngineMetricsV1(expected: WasmEngineMetricsFenceFields, reported: WasmEngineMetricsV1): ValidationResult<WasmEngineMetricsV1> {
	const errors: ValidationIssue[] = [];
	if (expected.sandboxId !== reported.sandboxId) errors.push(issue("SANDBOX_ID_MISMATCH", "/sandboxId", "metrics sandbox ID does not match the current execution record"));
	if (expected.versionId !== reported.versionId) errors.push(issue("VERSION_ID_MISMATCH", "/versionId", "metrics version ID does not match the current execution record"));
	if (expected.preparationGeneration !== reported.preparationGeneration || expected.executionGeneration !== reported.executionGeneration) {
		errors.push(issue(WASM_ENGINE_METRICS_STALE, "/executionGeneration", "metrics preparation/execution generations do not match the current execution record"));
	}
	if (expected.packageDigest !== reported.packageDigest) errors.push(issue("PACKAGE_DIGEST_MISMATCH", "/packageDigest", "metrics package digest does not match the current execution record"));
	if (!jcsEqual(expected.runtimeBinding, reported.runtimeBinding)) {
		errors.push(issue("RUNTIME_BINDING_MISMATCH", "/runtimeBinding", "metrics runtime binding does not match the current execution record"));
	}
	if (expected.capabilityRecordRevision !== reported.capabilityRecordRevision || expected.capabilityRecordHash !== reported.capabilityRecordHash) {
		errors.push(issue("CAPABILITY_RECORD_MISMATCH", "/capabilityRecordRevision", "metrics capability record pin does not match the current execution record"));
	}
	if (expected.secretRevision !== reported.secretRevision) {
		errors.push(issue("SECRET_REVISION_MISMATCH", "/secretRevision", "metrics secret revision does not match the current execution record"));
	}
	if (expected.configRevision !== reported.configRevision || expected.configSnapshotRef !== reported.configSnapshotRef) {
		errors.push(issue("CONFIG_SNAPSHOT_MISMATCH", "/configRevision", "metrics config revision/reference do not match the current execution record"));
	}
	if (errors.length) return failure(errors);
	return ok(reported);
}

// ---------------------------------------------------------------------------
// V2（service-enabled）readiness/metrics wire 扩展（add-wasm-host-services P0-3）
//
// V1 代际 readiness/health 与 metrics wire 钉 ABI 1.0.0 binding，无法证明
// service-enabled（ABI 1.1.0）执行。本段是该两族 wire 的 V2 扩展：V1 全字段 +
// runtimeBinding.hostABI 钉 iweb-wasmd-abi@1.1.0 + hostServicePolicyDigest
//（HostServiceIdentityV2 的增量；design 的完整 ReadinessLeaseV2/MetricsSampleV2
// envelope —— listener proof、sampleId、digest 域 —— 属后续任务，本层只冻结
// supervisor 采纳判定所需的身份增量）。既有 ReadinessLeaseV2（Kernel 激活租约）
// 字节形状不变：V1 应用继续消费它，绝不携带 V2 增量键（协议分代物理隔离）。
// ---------------------------------------------------------------------------

const SERVICE_READINESS_HEALTH_V2_CODE = "WASM_SERVICE_READINESS_HEALTH_V2_INVALID";
const SERVICE_ENGINE_METRICS_V2_CODE = "WASM_SERVICE_ENGINE_METRICS_V2_INVALID";

/** V2（service-enabled）health fence：V1 fence + ABI 1.1.0 binding + policy pin。 */
export interface ServiceReadinessFenceFields extends Omit<WasmReadinessFenceFields, "runtimeBinding"> {
	readonly runtimeBinding: RuntimeBindingIdentityV2;
	readonly hostServicePolicyDigest: string;
}

/** V2（service-enabled）readiness/health 载荷：V1 health v2 15 字段 + hostServicePolicyDigest（binding ABI 1.1.0）。 */
export interface ServiceReadinessHealthV2 extends Omit<WasmReadinessHealthV2, "runtimeBinding"> {
	readonly runtimeBinding: RuntimeBindingIdentityV2;
	readonly hostServicePolicyDigest: string;
}

function requireRuntimeBindingIdentityV2Field(input: unknown, path: string, code: string, errors: ValidationIssue[]): RuntimeBindingIdentityV2 | null {
	const parsed = validateRuntimeBindingIdentityV2(input);
	if (parsed.ok) return parsed.value;
	for (const entry of parsed.errors) errors.push(issue(code, path + entry.path, entry.message));
	return null;
}

function requireServiceReadinessHealthV2(input: unknown, path: string, code: string, errors: ValidationIssue[]): ServiceReadinessHealthV2 | null {
	const health = requireObject(input, path, "service readiness health v2 payload", code, errors);
	if (health === null) return null;
	requireExactKeys(
		health,
		path,
		[
			"schemaVersion",
			"ok",
			"sandboxId",
			"versionId",
			"packageDigest",
			"runtimeBinding",
			"hostServicePolicyDigest",
			"capabilityRecordRevision",
			"capabilityRecordHash",
			"secretRevision",
			"secretValuesDigest",
			"configRevision",
			"configSnapshotRef",
			"configValuesDigest",
			"preparationGeneration",
			"executionGeneration",
		],
		code,
		errors,
	);
	pushIdentityIncompleteIfCelldSignal(health, path, errors);

	const schemaVersion = requireSafeInteger(health.schemaVersion, path, "schemaVersion", 2, 2, code, errors);
	if (health.ok !== true) {
		errors.push(issue(code, path + "/ok", 'ok must be the literal true; a not-ready wasmd emits no v2 payload'));
	}
	const sandboxId = requireSandboxId(health.sandboxId, path, "sandboxId", code, errors);
	const versionId = requireVersionId(health.versionId, path, "versionId", code, errors);
	const packageDigest = requireSha256Hex(health.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentityV2Field(health.runtimeBinding, path + "/runtimeBinding", code, errors);
	const hostServicePolicyDigest = requireSha256Hex(health.hostServicePolicyDigest, path, "hostServicePolicyDigest", code, errors);
	const capabilityRecordRevision = requireSafeInteger(health.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASM_U53_MAX, code, errors);
	const capabilityRecordHash = requireSha256Hex(health.capabilityRecordHash, path, "capabilityRecordHash", code, errors);
	const secretRevision = requireSafeInteger(health.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const secretValuesDigest = requireSha256Hex(health.secretValuesDigest, path, "secretValuesDigest", code, errors);
	const configRevision = requireSafeInteger(health.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);
	const configSnapshotRef = requireNullableSha256Hex(health.configSnapshotRef, path, "configSnapshotRef", code, errors);
	const configValuesDigest = requireNullableSha256Hex(health.configValuesDigest, path, "configValuesDigest", code, errors);
	const preparationGeneration = requireSafeInteger(health.preparationGeneration, path, "preparationGeneration", 1, WASM_U53_MAX, code, errors);
	const executionGeneration = requireSafeInteger(health.executionGeneration, path, "executionGeneration", 1, WASM_U53_MAX, code, errors);

	if (
		schemaVersion === null ||
		sandboxId === null ||
		versionId === null ||
		packageDigest === null ||
		runtimeBinding === null ||
		hostServicePolicyDigest === null ||
		capabilityRecordRevision === null ||
		capabilityRecordHash === null ||
		secretRevision === null ||
		secretValuesDigest === null ||
		configRevision === null ||
		configSnapshotRef === undefined ||
		configValuesDigest === undefined ||
		preparationGeneration === null ||
		executionGeneration === null ||
		errors.length
	) {
		return null;
	}
	checkConfigSnapshotCoupling(configRevision, configSnapshotRef, configValuesDigest, path, code, errors);
	if (errors.length) return null;
	return {
		schemaVersion: 2,
		ok: true,
		sandboxId,
		versionId,
		packageDigest,
		runtimeBinding,
		hostServicePolicyDigest,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
		preparationGeneration,
		executionGeneration,
	};
}

export function validateServiceReadinessHealthV2(input: unknown): ValidationResult<ServiceReadinessHealthV2> {
	const errors: ValidationIssue[] = [];
	const value = requireServiceReadinessHealthV2(input, "", SERVICE_READINESS_HEALTH_V2_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

/** V2 health 采纳判定：V1 correlate 全字段 + policy pin 精确相等（binding 含 ABI 1.1.0）。 */
export function correlateServiceReadinessHealthV2(expected: ServiceReadinessFenceFields, reported: ServiceReadinessHealthV2): ValidationResult<ServiceReadinessHealthV2> {
	const errors: ValidationIssue[] = [];
	if (expected.sandboxId !== reported.sandboxId) errors.push(issue("SANDBOX_ID_MISMATCH", "/sandboxId", "health sandbox ID does not match the expected execution"));
	if (expected.versionId !== reported.versionId) errors.push(issue("VERSION_ID_MISMATCH", "/versionId", "health version ID does not match the expected execution"));
	if (expected.preparationGeneration !== reported.preparationGeneration || expected.executionGeneration !== reported.executionGeneration) {
		errors.push(issue("EXECUTION_GENERATION_MISMATCH", "/preparationGeneration", "health preparation/execution generations do not match the expected execution"));
	}
	if (expected.packageDigest !== reported.packageDigest) errors.push(issue("PACKAGE_DIGEST_MISMATCH", "/packageDigest", "health package digest does not match the expected execution"));
	if (!jcsEqual(expected.runtimeBinding, reported.runtimeBinding)) {
		errors.push(issue("RUNTIME_BINDING_MISMATCH", "/runtimeBinding", "health runtime binding (service-enabled ABI 1.1.0) does not match the expected execution"));
	}
	if (expected.hostServicePolicyDigest !== reported.hostServicePolicyDigest) {
		errors.push(issue(WASM_HOST_POLICY_DIGEST_MISMATCH, "/hostServicePolicyDigest", "health host service policy digest does not match the Kernel-authorized policy bytes"));
	}
	if (expected.capabilityRecordRevision !== reported.capabilityRecordRevision || expected.capabilityRecordHash !== reported.capabilityRecordHash) {
		errors.push(issue("CAPABILITY_RECORD_MISMATCH", "/capabilityRecordRevision", "health capability record pin does not match the expected execution"));
	}
	if (expected.secretRevision !== reported.secretRevision || expected.secretValuesDigest !== reported.secretValuesDigest) {
		errors.push(issue("SECRET_SNAPSHOT_MISMATCH", "/secretRevision", "health secret revision/values digest do not match the expected execution"));
	}
	if (
		expected.configRevision !== reported.configRevision ||
		expected.configSnapshotRef !== reported.configSnapshotRef ||
		expected.configValuesDigest !== reported.configValuesDigest
	) {
		errors.push(issue("CONFIG_SNAPSHOT_MISMATCH", "/configRevision", "health config revision/reference/digest do not match the expected execution"));
	}
	if (errors.length) return failure(errors);
	return ok(reported);
}

/** V2（service-enabled）metrics fence：V1 fence + ABI 1.1.0 binding + policy pin。 */
export interface ServiceEngineMetricsFenceFields extends Omit<WasmEngineMetricsFenceFields, "runtimeBinding"> {
	readonly runtimeBinding: RuntimeBindingIdentityV2;
	readonly hostServicePolicyDigest: string;
}

/** V2（service-enabled）engine metrics 载荷：V1 metrics 字段 + schemaVersion:2 + policy pin（binding ABI 1.1.0）。 */
export interface ServiceEngineMetricsV2 extends Omit<WasmEngineMetricsV1, "schemaVersion" | "runtimeBinding"> {
	readonly schemaVersion: 2;
	readonly runtimeBinding: RuntimeBindingIdentityV2;
	readonly hostServicePolicyDigest: string;
}

function requireServiceEngineMetricsV2(input: unknown, path: string, code: string, errors: ValidationIssue[]): ServiceEngineMetricsV2 | null {
	const metrics = requireObject(input, path, "service engine metrics v2 payload", code, errors);
	if (metrics === null) return null;
	requireExactKeys(
		metrics,
		path,
		[
			"schemaVersion",
			"sandboxId",
			"versionId",
			"packageDigest",
			"runtimeBinding",
			"hostServicePolicyDigest",
			"capabilityRecordRevision",
			"capabilityRecordHash",
			"secretRevision",
			"configRevision",
			"configSnapshotRef",
			"preparationGeneration",
			"executionGeneration",
			"sampledAt",
			"availability",
			"engine",
		],
		code,
		errors,
	);
	pushIdentityIncompleteIfCelldSignal(metrics, path, errors);

	const schemaVersion = requireSafeInteger(metrics.schemaVersion, path, "schemaVersion", 2, 2, code, errors);
	const sandboxId = requireSandboxId(metrics.sandboxId, path, "sandboxId", code, errors);
	const versionId = requireVersionId(metrics.versionId, path, "versionId", code, errors);
	const packageDigest = requireSha256Hex(metrics.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentityV2Field(metrics.runtimeBinding, path + "/runtimeBinding", code, errors);
	const hostServicePolicyDigest = requireSha256Hex(metrics.hostServicePolicyDigest, path, "hostServicePolicyDigest", code, errors);
	const capabilityRecordRevision = requireSafeInteger(metrics.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASM_U53_MAX, code, errors);
	const capabilityRecordHash = requireSha256Hex(metrics.capabilityRecordHash, path, "capabilityRecordHash", code, errors);
	const secretRevision = requireSafeInteger(metrics.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const configRevision = requireSafeInteger(metrics.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);
	const configSnapshotRef = requireNullableSha256Hex(metrics.configSnapshotRef, path, "configSnapshotRef", code, errors);
	const preparationGeneration = requireSafeInteger(metrics.preparationGeneration, path, "preparationGeneration", 1, WASM_U53_MAX, code, errors);
	const executionGeneration = requireSafeInteger(metrics.executionGeneration, path, "executionGeneration", 1, WASM_U53_MAX, code, errors);
	const sampledAt = requireRfc3339Utc(metrics.sampledAt, path, "sampledAt", code, errors);

	const availability = typeof metrics.availability === "string" && (metrics.availability === "available" || metrics.availability === "unavailable") ? metrics.availability : null;
	if (availability === null) errors.push(issue(code, path + "/availability", 'availability must be exactly "available" or "unavailable"'));

	let engine: WasmEngineCountersV1 | null = null;
	let engineParsed = false;
	if (metrics.engine === null) {
		if (availability === "available") errors.push(issue(code, path + "/engine", 'an available sample must carry the exact engine counters object'));
		engineParsed = true;
	} else if (availability === "unavailable") {
		errors.push(issue(code, path + "/engine", 'engine must be null exactly when availability is unavailable'));
	} else {
		const parsed = requireWasmEngineCountersV1(metrics.engine, path + "/engine", code, errors);
		if (parsed !== null) {
			engine = parsed;
			engineParsed = true;
		}
	}

	if (
		schemaVersion === null ||
		sandboxId === null ||
		versionId === null ||
		packageDigest === null ||
		runtimeBinding === null ||
		hostServicePolicyDigest === null ||
		capabilityRecordRevision === null ||
		capabilityRecordHash === null ||
		secretRevision === null ||
		configRevision === null ||
		configSnapshotRef === undefined ||
		preparationGeneration === null ||
		executionGeneration === null ||
		sampledAt === null ||
		availability === null ||
		!engineParsed ||
		errors.length
	) {
		return null;
	}
	checkConfigSnapshotCoupling(configRevision, configSnapshotRef, undefined, path, code, errors);
	if (errors.length) return null;
	return {
		schemaVersion: 2,
		sandboxId,
		versionId,
		packageDigest,
		runtimeBinding,
		hostServicePolicyDigest,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		configRevision,
		configSnapshotRef,
		preparationGeneration,
		executionGeneration,
		sampledAt,
		availability,
		engine,
	};
}

export function validateServiceEngineMetricsV2(input: unknown): ValidationResult<ServiceEngineMetricsV2> {
	const errors: ValidationIssue[] = [];
	const value = requireServiceEngineMetricsV2(input, "", SERVICE_ENGINE_METRICS_V2_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

/** V2 metrics 采纳判定：V1 correlate 全字段 + policy pin 精确相等（binding 含 ABI 1.1.0）。 */
export function correlateServiceEngineMetricsV2(expected: ServiceEngineMetricsFenceFields, reported: ServiceEngineMetricsV2): ValidationResult<ServiceEngineMetricsV2> {
	const errors: ValidationIssue[] = [];
	if (expected.sandboxId !== reported.sandboxId) errors.push(issue("SANDBOX_ID_MISMATCH", "/sandboxId", "metrics sandbox ID does not match the current execution record"));
	if (expected.versionId !== reported.versionId) errors.push(issue("VERSION_ID_MISMATCH", "/versionId", "metrics version ID does not match the current execution record"));
	if (expected.preparationGeneration !== reported.preparationGeneration || expected.executionGeneration !== reported.executionGeneration) {
		errors.push(issue(WASM_ENGINE_METRICS_STALE, "/executionGeneration", "metrics preparation/execution generations do not match the current execution record"));
	}
	if (expected.packageDigest !== reported.packageDigest) errors.push(issue("PACKAGE_DIGEST_MISMATCH", "/packageDigest", "metrics package digest does not match the current execution record"));
	if (!jcsEqual(expected.runtimeBinding, reported.runtimeBinding)) {
		errors.push(issue("RUNTIME_BINDING_MISMATCH", "/runtimeBinding", "metrics runtime binding (service-enabled ABI 1.1.0) does not match the current execution record"));
	}
	if (expected.hostServicePolicyDigest !== reported.hostServicePolicyDigest) {
		errors.push(issue(WASM_HOST_POLICY_DIGEST_MISMATCH, "/hostServicePolicyDigest", "metrics host service policy digest does not match the Kernel-authorized policy bytes"));
	}
	if (expected.capabilityRecordRevision !== reported.capabilityRecordRevision || expected.capabilityRecordHash !== reported.capabilityRecordHash) {
		errors.push(issue("CAPABILITY_RECORD_MISMATCH", "/capabilityRecordRevision", "metrics capability record pin does not match the current execution record"));
	}
	if (expected.secretRevision !== reported.secretRevision) {
		errors.push(issue("SECRET_REVISION_MISMATCH", "/secretRevision", "metrics secret revision does not match the current execution record"));
	}
	if (expected.configRevision !== reported.configRevision || expected.configSnapshotRef !== reported.configSnapshotRef) {
		errors.push(issue("CONFIG_SNAPSHOT_MISMATCH", "/configRevision", "metrics config revision/reference do not match the current execution record"));
	}
	if (errors.length) return failure(errors);
	return ok(reported);
}

// --- 同 E 非负单调状态机（纯函数；Kernel 投影层使用） ---
//
// 每个 execution generation 一个窗口：首条 available 样本建立 baseline；此后样本
// sampledAt 必须严格更晚；fuel（启用时）/epochTimeouts/highWater 在同 E 内只增不减；
// 瞬时值（live instances、guest memory）可双向。E 变更只能通过 Kernel 接受新
// generation fence 后 openWasmEngineMetricsWindow 重开窗口——延迟的旧 generation
// 样本是 stale，不是 reset。首样本前/无法证明的唯一投影是 unavailable + engine:null。

export type WasmEngineMetricsWindow =
	| { readonly kind: "awaiting-first-sample"; readonly executionGeneration: number }
	| {
			readonly kind: "tracking";
			readonly executionGeneration: number;
			readonly lastAcceptedSampledAt: string;
			readonly fuelConsumedCumulative: number | null;
			readonly epochTimeoutsCumulative: number;
			readonly instancesHighWaterCumulative: number;
	  };

export function openWasmEngineMetricsWindow(executionGeneration: number): ValidationResult<WasmEngineMetricsWindow> {
	if (typeof executionGeneration !== "number" || !Number.isSafeInteger(executionGeneration) || executionGeneration < 1 || executionGeneration > WASM_U53_MAX) {
		return failure([issue(METRICS_CODE, "/executionGeneration", "a metrics window requires an alive execution generation (u53 >= 1)")]);
	}
	return ok({ kind: "awaiting-first-sample", executionGeneration });
}

export interface WasmEngineMetricsAcceptOptions {
	// pinned NodeCapabilityRecordV1.engine.fuelPerRequest === null 表示禁用。
	// true：样本 fuel 必须非 null（null 是禁用唯一表示，启用时为 0 也不合法）；
	// false：样本 fuel 必须为 null；null（未提供 pinned record）：只强制同 E 窗口内
	// null/数值表示前后一致（fail-closed 备注：见文末歧义）。
	readonly fuelEnabled: boolean | null;
}

function checkFuelRepresentation(fuel: number | null, fuelEnabled: boolean | null, errors: ValidationIssue[]): void {
	if (fuelEnabled === true && fuel === null) {
		errors.push(issue(WASM_ENGINE_METRICS_FUEL_REPRESENTATION, "/engine/fuelConsumedCumulative", "fuel is enabled by the pinned node record; null is the disabled-only representation"));
	}
	if (fuelEnabled === false && fuel !== null) {
		errors.push(issue(WASM_ENGINE_METRICS_FUEL_REPRESENTATION, "/engine/fuelConsumedCumulative", "fuel is disabled by the pinned node record; fuelConsumedCumulative must remain null for that execution generation"));
	}
}

export function acceptWasmEngineMetricsSample(
	window: WasmEngineMetricsWindow,
	payload: WasmEngineMetricsV1,
	options: WasmEngineMetricsAcceptOptions = { fuelEnabled: null },
): ValidationResult<WasmEngineMetricsWindow> {
	const errors: ValidationIssue[] = [];
	if (payload.executionGeneration !== window.executionGeneration) {
		// 旧 generation 的延迟样本：stale，不是 reset；不得改动当前窗口。
		return failure([
			issue(WASM_ENGINE_METRICS_STALE, "/executionGeneration", "a delayed prior-generation metrics payload is stale, not a reset; a fresh baseline requires the Kernel-accepted new generation fence"),
		]);
	}
	if (window.kind === "tracking" && epochMs(payload.sampledAt) <= epochMs(window.lastAcceptedSampledAt)) {
		errors.push(issue(WASM_ENGINE_METRICS_TIME_REGRESSION, "/sampledAt", "later accepted samples need strictly later sampledAt"));
	}
	if (payload.availability === "unavailable") {
		// unavailable 样本不带 counters：baseline（若有）保持不变，仅推进接受时刻。
		if (errors.length) return failure(errors);
		if (window.kind === "awaiting-first-sample") return ok(window);
		return ok({ ...window, lastAcceptedSampledAt: payload.sampledAt });
	}
	const engine = payload.engine;
	if (engine === null) {
		// validator 已保证 available 必带 engine；此处为纯函数层的 fail-closed 双保险。
		return failure([issue(METRICS_CODE, "/engine", "an available sample must carry the exact engine counters object")]);
	}
	checkFuelRepresentation(engine.fuelConsumedCumulative, options.fuelEnabled, errors);
	if (window.kind === "tracking") {
		// 同 E 内：fuel 表示（null vs 数值）不可切换；启用时 fuel/epoch/highWater 非负单调不减。
		if ((window.fuelConsumedCumulative === null) !== (engine.fuelConsumedCumulative === null)) {
			errors.push(issue(WASM_ENGINE_METRICS_FUEL_REPRESENTATION, "/engine/fuelConsumedCumulative", "the fuel disabled/enabled representation must remain constant within one execution generation"));
		}
		if (window.fuelConsumedCumulative !== null && engine.fuelConsumedCumulative !== null && engine.fuelConsumedCumulative < window.fuelConsumedCumulative) {
			errors.push(issue(WASM_ENGINE_METRICS_COUNTER_REGRESSION, "/engine/fuelConsumedCumulative", "fuelConsumedCumulative must be greater than or equal to its prior accepted value within the same execution generation"));
		}
		if (engine.epochTimeoutsCumulative < window.epochTimeoutsCumulative) {
			errors.push(issue(WASM_ENGINE_METRICS_COUNTER_REGRESSION, "/engine/epochTimeoutsCumulative", "epochTimeoutsCumulative must be greater than or equal to its prior accepted value within the same execution generation"));
		}
		if (engine.instancesHighWaterCumulative < window.instancesHighWaterCumulative) {
			errors.push(issue(WASM_ENGINE_METRICS_COUNTER_REGRESSION, "/engine/instancesHighWaterCumulative", "instancesHighWaterCumulative must be greater than or equal to its prior accepted value within the same execution generation"));
		}
	}
	if (errors.length) return failure(errors);
	return ok({
		kind: "tracking",
		executionGeneration: window.executionGeneration,
		lastAcceptedSampledAt: payload.sampledAt,
		fuelConsumedCumulative: engine.fuelConsumedCumulative,
		epochTimeoutsCumulative: engine.epochTimeoutsCumulative,
		instancesHighWaterCumulative: engine.instancesHighWaterCumulative,
	});
}

// ---------------------------------------------------------------------------
// 向量/示例构造器（供跨实现 round-trip 与后续任务 fixture 复用）
// ---------------------------------------------------------------------------

const VECTOR_VERSION_DIGEST = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";
const EXAMPLE_LEASE_NONCE = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

export function exampleWasmReadinessHealthV2(): WasmReadinessHealthV2 {
	return {
		schemaVersion: 2,
		ok: true,
		sandboxId: "sbx-vector",
		versionId: VECTOR_VERSION_DIGEST + "-1",
		packageDigest: "0".repeat(64),
		runtimeBinding: {
			kind: "wasm",
			catalogRevision: 9,
			catalogHash: "ab".repeat(32),
			entryKey: "iweb-wasmd",
			imageDigest: "sha256:" + "cd".repeat(32),
			hostABI: "iweb-wasmd-abi@1.0.0",
			world: "wasi:http/proxy@0.2.8",
		},
		capabilityRecordRevision: 5,
		capabilityRecordHash: "2".repeat(64),
		secretRevision: 3,
		secretValuesDigest: "6".repeat(64),
		configRevision: 2,
		configSnapshotRef: "7".repeat(64),
		configValuesDigest: "8".repeat(64),
		preparationGeneration: 1,
		executionGeneration: 1,
	};
}

export function exampleReadinessLeaseV2(): ReadinessLeaseV2 {
	const record: ReadinessLeaseV2WithoutDigest = {
		schemaVersion: 2,
		leaseNonce: EXAMPLE_LEASE_NONCE,
		sandboxId: "sbx-vector",
		versionId: VECTOR_VERSION_DIGEST + "-1",
		packageDigest: "0".repeat(64),
		runtimeBinding: {
			kind: "wasm",
			catalogRevision: 9,
			catalogHash: "ab".repeat(32),
			entryKey: "iweb-wasmd",
			imageDigest: "sha256:" + "cd".repeat(32),
			hostABI: "iweb-wasmd-abi@1.0.0",
			world: "wasi:http/proxy@0.2.8",
		},
		capabilityRecordRevision: 5,
		capabilityRecordHash: "2".repeat(64),
		secretRevision: 3,
		secretValuesDigest: "6".repeat(64),
		configRevision: 2,
		configSnapshotRef: "7".repeat(64),
		configValuesDigest: "8".repeat(64),
		preparationGeneration: 1,
		executionGeneration: 1,
		issuedAt: "2026-08-26T00:00:00Z",
		expiresAt: "2026-08-26T00:10:00Z",
	};
	return { ...record, leaseDigest: computeReadinessLeaseDigestV2(record) };
}

export function exampleWasmEngineMetricsV1(): WasmEngineMetricsV1 {
	return {
		schemaVersion: 1,
		sandboxId: "sbx-vector",
		versionId: VECTOR_VERSION_DIGEST + "-1",
		packageDigest: "0".repeat(64),
		runtimeBinding: {
			kind: "wasm",
			catalogRevision: 9,
			catalogHash: "ab".repeat(32),
			entryKey: "iweb-wasmd",
			imageDigest: "sha256:" + "cd".repeat(32),
			hostABI: "iweb-wasmd-abi@1.0.0",
			world: "wasi:http/proxy@0.2.8",
		},
		capabilityRecordRevision: 5,
		capabilityRecordHash: "2".repeat(64),
		secretRevision: 3,
		configRevision: 2,
		configSnapshotRef: "7".repeat(64),
		preparationGeneration: 1,
		executionGeneration: 1,
		sampledAt: "2026-08-26T00:00:00Z",
		availability: "available",
		engine: {
			fuelConsumedCumulative: 1000,
			epochTimeoutsCumulative: 0,
			instancesLiveInstant: 1,
			instancesHighWaterCumulative: 1,
			guestMemoryBytesInstant: 2097152,
		},
	};
}

/** V2 示例 policy pin（与 wasm-execution.ts exampleExecutionCommandV2 同值）。 */
const EXAMPLE_HOST_SERVICE_POLICY_DIGEST = "b21afb8e8cb4e6482b137ef5749ea2b9c39e4ef35619bfb079d4c83bd75bb665";

export function exampleServiceReadinessHealthV2(): ServiceReadinessHealthV2 {
	return {
		schemaVersion: 2,
		ok: true,
		sandboxId: "sbx-vector",
		versionId: VECTOR_VERSION_DIGEST + "-1",
		packageDigest: "0".repeat(64),
		runtimeBinding: {
			kind: "wasm",
			catalogRevision: 9,
			catalogHash: "ab".repeat(32),
			entryKey: "iweb-wasmd",
			imageDigest: "sha256:" + "cd".repeat(32),
			hostABI: "iweb-wasmd-abi@1.1.0",
			world: "wasi:http/proxy@0.2.8",
		},
		hostServicePolicyDigest: EXAMPLE_HOST_SERVICE_POLICY_DIGEST,
		capabilityRecordRevision: 5,
		capabilityRecordHash: "2".repeat(64),
		secretRevision: 3,
		secretValuesDigest: "6".repeat(64),
		configRevision: 2,
		configSnapshotRef: "7".repeat(64),
		configValuesDigest: "8".repeat(64),
		preparationGeneration: 1,
		executionGeneration: 1,
	};
}

export function exampleServiceEngineMetricsV2(): ServiceEngineMetricsV2 {
	return {
		schemaVersion: 2,
		sandboxId: "sbx-vector",
		versionId: VECTOR_VERSION_DIGEST + "-1",
		packageDigest: "0".repeat(64),
		runtimeBinding: {
			kind: "wasm",
			catalogRevision: 9,
			catalogHash: "ab".repeat(32),
			entryKey: "iweb-wasmd",
			imageDigest: "sha256:" + "cd".repeat(32),
			hostABI: "iweb-wasmd-abi@1.1.0",
			world: "wasi:http/proxy@0.2.8",
		},
		hostServicePolicyDigest: EXAMPLE_HOST_SERVICE_POLICY_DIGEST,
		capabilityRecordRevision: 5,
		capabilityRecordHash: "2".repeat(64),
		secretRevision: 3,
		configRevision: 2,
		configSnapshotRef: "7".repeat(64),
		preparationGeneration: 1,
		executionGeneration: 1,
		sampledAt: "2026-08-26T00:00:00Z",
		availability: "available",
		engine: {
			fuelConsumedCumulative: 1000,
			epochTimeoutsCumulative: 0,
			instancesLiveInstant: 1,
			instancesHighWaterCumulative: 1,
			guestMemoryBytesInstant: 2097152,
		},
	};
}

// grammar 统一助手的复算出口（compose/parse 的唯一权威仍在 wasm-package.ts）。
export { composeWasmVersionId, parseWasmVersionId };
// celld 信号拒绝码在本文件三类 wire 的判定中使用，一并转出口（定义权威在 wasm-execution.ts）。
export { WASM_IDENTITY_INCOMPLETE };

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. stagingTtlSeconds 上界：lease 字节无法自证 pinned TTL，validateReadinessLeaseV2
//    仅在调用方传入 stagingTtlSeconds 时强制 expiresAt <= issuedAt + TTL；宿主持久化
//    重载路径必须传入。默认只保证 expiresAt > issuedAt，不隐式采用 3600 上界（那会是
//    最宽松解释而非 fail-closed）。
// 2. health v2 无 ok:false 形态：v2 wire 只定义 ok:true 的精确 15 字段对象；not-ready
//    由 dial 失败/malformed 映射（宿主 503），本 validator 把 ok:false 一律作为 wire
//    拒绝（WASM_READINESS_HEALTH_V2_INVALID），不引入第二健康状态位。
// 3. metrics 的 fuelEnabled 交叉校验在未提供 pinned record 时只强制同 E 窗口内表示
//    一致（null 恒 null / 数值恒数值且单调）；提供 record 时严格按启用/禁用判 null/数值。
// 4. unavailable 样本推进 lastAcceptedSampledAt 但绝不动 baseline counters；等待首样本
//    窗口保持 awaiting-first-sample（唯一投影 unavailable + engine:null，绝不补零）。
// 5. RFC3339 比较用 Date.parse 毫秒精度（沿用 wasm-execution.ts 口径）；亚毫秒差异视为
//    不严格更晚（fail-closed）。闰秒（:60）因无法被证明而拒绝。
// 6. consumeReadinessLeaseV2 的判定顺序是 nonce 先于过期：重放场景宿主必须返回原始
//    route-CAS 结果（按 activationId 幂等），而不是把重放报成新的 READINESS_LEASE_EXPIRED；
//    跨 tuple 复用 nonce 才是 READINESS_LEASE_MISMATCH。
// 7. READINESS_LEASE_NONCE_REPLAY 为补充稳定码（spec 未命名重放拒绝码）；spec 已命名码
//    （READINESS_LEASE_MISMATCH/READINESS_LEASE_EXPIRED/WASM_IDENTITY_INCOMPLETE）不被覆盖。
// 8. metrics/health/lease 的 preparationGeneration/executionGeneration 强制 >= 1：存活或
//    报告中的 execution 双代次必须 >= 1（fence 法则）；记录态的 0 值只存在于
//    WasmExecutionIdentityV1 层，不属于这三类 wire。
// 9. 时间比较均为闭区间语义以外收紧：CAS 时刻等于 expiresAt 即拒绝（"equal or later
//    instant rejects"）；sampledAt 相等即拒绝（"strictly later"）。
