// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.2 契约先行）：wasm 执行代次/运行时绑定契约与 execution、control、kind-claim wire 必须先有 unknown-field-rejecting typed schema，后续宿主代码不得自行解释字段。
// 正交意图：精确键集（含缺失字段检测）、u53/单调/CAS fencing、celld 旧信号只拒绝不推断转换、fail-closed；复用 wasm-package.ts 的 JCS/digest/名称文法，绝不定义第二套编码。
// 轮次注记：本文件承载 ExecutionCommandV1/ExecutionAcknowledgementV1/ExecutionRpcEnvelopeV1（双 CAS fence）、WasmExecutionIdentityV1 双代次与 secretRevision 语义、RuntimeBindingIdentityV1、WasmApplicationControlRecordV1/WasmControlStateFileV2 的 controlRevision CAS、celld 兼容边界与 KindClaimBootstrapV1；health v2/metrics v1（任务 3.3/4.1）与宿主接线不在本文件。
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "./validation.ts";
import { validateLifecycleState, type LifecycleState, type VersionIdentity } from "./records.ts";
import {
	composeWasmVersionId,
	jcsCanonicalBytes,
	parseWasmVersionId,
	sha256Hex,
	validateNormalizedWasmManifestV1,
	WASM_APPLICATION_ID_PATTERN,
	WASM_HOST_ABI_LITERAL,
	WASM_OCI_SHA256_PATTERN,
	WASM_SHA256_HEX_PATTERN,
	WASM_U53_MAX,
	WASM_VERSION_ID_PATTERN,
	WASM_WORLD_LITERAL,
	type NormalizedWasmManifestV1,
} from "./wasm-package.ts";

// ---------------------------------------------------------------------------
// 文法常量与稳定错误码
// ---------------------------------------------------------------------------

// sandboxId 与 applicationId 不同文法：sandboxId 必须以小写字母开头（spec 双代次 fence 一节）。
export const WASM_SANDBOX_ID_PATTERN = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const WASM_ENTRY_KEY_PATTERN = /^[a-z][a-z0-9.-]{0,63}$/;
// lower-case UUIDv7：version nibble 必须是 7，variant 位必须是 RFC 9562 的 10xx（[89ab]）。
export const WASM_UUIDV7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const WASM_RFC3339_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
export const WASM_FAILURE_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;

// spec 已命名的稳定码。
export const WASM_IDENTITY_INCOMPLETE = "WASM_IDENTITY_INCOMPLETE";
export const WASM_GENERATION_EXHAUSTED = "WASM_GENERATION_EXHAUSTED";
export const CONTROL_REVISION_CONFLICT = "CONTROL_REVISION_CONFLICT";

// 其余拒绝码沿用 wasm-package.ts 的命名风格补齐（不覆盖 spec 已命名码）。
const BINDING_CODE = "WASM_BINDING_INVALID";
const IDENTITY_CODE = "WASM_EXECUTION_IDENTITY_INVALID";
const COMMAND_CODE = "EXECUTION_COMMAND_INVALID";
const ACK_CODE = "EXECUTION_ACKNOWLEDGEMENT_INVALID";
const ENVELOPE_CODE = "EXECUTION_RPC_ENVELOPE_INVALID";
const CONTROL_CODE = "WASM_CONTROL_STATE_INVALID";
const KIND_CLAIM_CODE = "WASM_KIND_CLAIM_INVALID";

export const EXECUTION_RPC_PROTOCOL_LITERAL = "iweb-execution-rpc-v1";
export const EXECUTION_COMMAND_DIGEST_DOMAIN = "iweb-execution-command-v1";
export const KIND_CLAIM_BINDING_DIGEST_DOMAIN = "iweb-application-kind-binding-v1";
export const KIND_CLAIM_BOOTSTRAP_DIGEST_DOMAIN = "iweb-kind-claim-bootstrap-v1";

// ---------------------------------------------------------------------------
// 共享小工具（与 wasm-package.ts 同款；那边是模块私有，这里不重复定义编码语义）
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

function requireWasmApplicationId(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_APPLICATION_ID_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be a lower-case application identifier of at most 63 ASCII bytes"));
		return null;
	}
	return value;
}

function requireWasmSandboxId(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_SANDBOX_ID_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be a lower-case sandbox identifier starting with a letter (max 63 ASCII bytes)"));
		return null;
	}
	return value;
}

function requireWasmVersionId(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
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

function compareUtf8Bytes(left: string, right: string): number {
	return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function jcsEqual(left: unknown, right: unknown): boolean {
	// 已验证值域上的结构相等性：以 JCS 字节为准（不引入第二套 deep-equal 语义）。
	return Buffer.compare(Buffer.from(jcsCanonicalBytes(left)), Buffer.from(jcsCanonicalBytes(right))) === 0;
}

function domainPrefixedDigest(domain: string, payload: Uint8Array): string {
	return sha256Hex(Buffer.concat([Buffer.from(domain + "\n", "utf8"), Buffer.from(payload)]));
}

// ---------------------------------------------------------------------------
// RuntimeBindingIdentityV1（七字段 object；不得以 image digest 或 catalog revision 子集替代）
// ---------------------------------------------------------------------------

export interface RuntimeBindingIdentityV1 {
	readonly kind: "wasm";
	readonly catalogRevision: number;
	readonly catalogHash: string;
	readonly entryKey: string;
	readonly imageDigest: string;
	readonly hostABI: typeof WASM_HOST_ABI_LITERAL;
	readonly world: typeof WASM_WORLD_LITERAL;
}

function requireRuntimeBindingIdentity(input: unknown, path: string, code: string, errors: ValidationIssue[]): RuntimeBindingIdentityV1 | null {
	const binding = requireObject(input, path, "runtime binding identity", code, errors);
	if (binding === null) return null;
	requireExactKeys(binding, path, ["kind", "catalogRevision", "catalogHash", "entryKey", "imageDigest", "hostABI", "world"], code, errors);
	const kind = requireStringLiteral(binding.kind, path, "kind", "wasm", code, errors);
	const catalogRevision = requireSafeInteger(binding.catalogRevision, path, "catalogRevision", 1, WASM_U53_MAX, code, errors);
	const catalogHash = requireSha256Hex(binding.catalogHash, path, "catalogHash", code, errors);
	const entryKey = typeof binding.entryKey === "string" && WASM_ENTRY_KEY_PATTERN.test(binding.entryKey) ? binding.entryKey : null;
	if (entryKey === null) errors.push(issue(code, path + "/entryKey", "entryKey must match ^[a-z][a-z0-9.-]{0,63}$"));
	const imageDigest = requireOciSha256(binding.imageDigest, path, "imageDigest", code, errors);
	const hostABI = requireStringLiteral(binding.hostABI, path, "hostABI", WASM_HOST_ABI_LITERAL, code, errors);
	const world = requireStringLiteral(binding.world, path, "world", WASM_WORLD_LITERAL, code, errors);
	if (kind === null || catalogRevision === null || catalogHash === null || entryKey === null || imageDigest === null || hostABI === null || world === null) return null;
	return { kind: "wasm", catalogRevision, catalogHash, entryKey, imageDigest, hostABI: WASM_HOST_ABI_LITERAL, world: WASM_WORLD_LITERAL };
}

export function validateRuntimeBindingIdentityV1(input: unknown): ValidationResult<RuntimeBindingIdentityV1> {
	const errors: ValidationIssue[] = [];
	const value = requireRuntimeBindingIdentity(input, "", BINDING_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

// ---------------------------------------------------------------------------
// WasmExecutionIdentityV1：(sandboxId, versionId, preparationGeneration, executionGeneration) 四元组
// ---------------------------------------------------------------------------

export interface WasmExecutionIdentityV1 {
	readonly sandboxId: string;
	readonly versionId: string;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
}

export function validateWasmExecutionIdentityV1(input: unknown): ValidationResult<WasmExecutionIdentityV1> {
	const errors: ValidationIssue[] = [];
	const identity = requireObject(input, "", "wasm execution identity", IDENTITY_CODE, errors);
	if (identity === null) return failure(errors);
	requireExactKeys(identity, "", ["sandboxId", "versionId", "preparationGeneration", "executionGeneration"], IDENTITY_CODE, errors);
	const sandboxId = requireWasmSandboxId(identity.sandboxId, "", "sandboxId", IDENTITY_CODE, errors);
	const versionId = requireWasmVersionId(identity.versionId, "", "versionId", IDENTITY_CODE, errors);
	const preparationGeneration = requireSafeInteger(identity.preparationGeneration, "", "preparationGeneration", 0, WASM_U53_MAX, IDENTITY_CODE, errors);
	const executionGeneration = requireSafeInteger(identity.executionGeneration, "", "executionGeneration", 0, WASM_U53_MAX, IDENTITY_CODE, errors);

	// celld 兼容边界：只带 versionId（和/或 celld `generation`/`sequence`）的旧信号是
	// WASM_IDENTITY_INCOMPLETE，绝不把 celld 单字段 generation 推断为 wasm 代次。
	const carriesIdentityKey = "sandboxId" in identity || "versionId" in identity;
	const missingFence = !("preparationGeneration" in identity) || !("executionGeneration" in identity);
	const celldSignal = "generation" in identity || "sequence" in identity;
	if (carriesIdentityKey && (missingFence || celldSignal)) {
		errors.push(
			issue(
				WASM_IDENTITY_INCOMPLETE,
				"",
				"a wasm identity must carry the full (sandboxId, versionId, preparationGeneration, executionGeneration) tuple; celld sequence/generation signals never substitute for wasm generations",
			),
		);
	}

	if (sandboxId === null || versionId === null || preparationGeneration === null || executionGeneration === null || errors.length) return failure(errors);
	return ok({ sandboxId, versionId, preparationGeneration, executionGeneration });
}

// --- 双代次 fence 的纯函数语义（Kernel/supervisor/gateway 共用） ---
//
// 新分配的 sandbox 记录双代次均为 0；Kernel prepare CAS 使 (p,e) -> (p+1,e+1)
// （首次准备 (0,0) -> (1,1)，重备/恢复也推进 preparation）；进程重启/重绑只推进
// executionGeneration。两值永不回退；到达 u53 上限时对应分配失败 WASM_GENERATION_EXHAUSTED，
// 不回绕、不复用、不归零。

export function initialWasmExecutionIdentity(sandboxId: string, versionId: string): WasmExecutionIdentityV1 {
	return { sandboxId, versionId, preparationGeneration: 0, executionGeneration: 0 };
}

export function prepareWasmExecutionIdentity(current: WasmExecutionIdentityV1): ValidationResult<WasmExecutionIdentityV1> {
	if (current.preparationGeneration >= WASM_U53_MAX || current.executionGeneration >= WASM_U53_MAX) {
		return failure([issue(WASM_GENERATION_EXHAUSTED, "/preparationGeneration", "generation space is exhausted; the Kernel does not wrap, reuse, or substitute zero")]);
	}
	return ok({ ...current, preparationGeneration: current.preparationGeneration + 1, executionGeneration: current.executionGeneration + 1 });
}

export function allocateWasmExecutionIdentity(current: WasmExecutionIdentityV1): ValidationResult<WasmExecutionIdentityV1> {
	if (current.preparationGeneration < 1) {
		return failure([issue(IDENTITY_CODE, "/preparationGeneration", "an execution allocation requires an existing preparation")]);
	}
	if (current.executionGeneration >= WASM_U53_MAX) {
		return failure([issue(WASM_GENERATION_EXHAUSTED, "/executionGeneration", "generation space is exhausted; the Kernel does not wrap, reuse, or substitute zero")]);
	}
	return ok({ ...current, executionGeneration: current.executionGeneration + 1 });
}

// 存活/报告健康与 metrics 的 execution 双代次必须 >= 1；executionGeneration:0 只允许出现在首次分配前。
export function isAliveWasmExecutionIdentity(identity: WasmExecutionIdentityV1): boolean {
	return identity.preparationGeneration >= 1 && identity.executionGeneration >= 1;
}

export function matchesWasmExecutionFence(expected: WasmExecutionIdentityV1, reported: WasmExecutionIdentityV1): boolean {
	return (
		expected.sandboxId === reported.sandboxId &&
		expected.versionId === reported.versionId &&
		expected.preparationGeneration === reported.preparationGeneration &&
		expected.executionGeneration === reported.executionGeneration
	);
}

export function checkWasmExecutionFence(expected: WasmExecutionIdentityV1, reported: WasmExecutionIdentityV1): ValidationResult<true> {
	if (matchesWasmExecutionFence(expected, reported)) return ok(true);
	return failure([issue("WASM_EXECUTION_FENCE_STALE", "", "reported execution tuple differs from the fenced (sandboxId, versionId, preparationGeneration, executionGeneration) identity")]);
}

// --- secretRevision 记录语义：u53、单调、激活 fence 要求相等 ---
//
// revision 0 表示未分配；首次分配与轮换提交严格更高的 u53；激活 CAS 要求候选
// secretRevision 等于当前 secret-store revision（旧候选被 fence 拒绝）。

export function nextSecretRevision(currentSecretRevision: number): ValidationResult<number> {
	if (typeof currentSecretRevision !== "number" || !Number.isSafeInteger(currentSecretRevision) || currentSecretRevision < 0 || currentSecretRevision > WASM_U53_MAX) {
		return failure([issue("WASM_SECRET_REVISION_INVALID", "", "current secret revision must be a u53 integer")]);
	}
	if (currentSecretRevision >= WASM_U53_MAX) {
		return failure([issue("SECRET_REVISION_EXHAUSTED", "", "secret revision space is exhausted; no strictly higher u53 revision exists")]);
	}
	return ok(currentSecretRevision + 1);
}

export function matchesSecretRevisionFence(currentRevision: number, candidateRevision: number): boolean {
	return currentRevision === candidateRevision;
}

// ---------------------------------------------------------------------------
// ExecutionCommandV1 / ExecutionAcknowledgementV1（双 CAS fence + config/secret snapshot 绑定）
// ---------------------------------------------------------------------------

export type WasmExecutionOperation = "prepare" | "start" | "drain" | "stop";
const EXECUTION_OPERATIONS: readonly string[] = ["prepare", "start", "drain", "stop"];

export interface ExecutionCommandV1 {
	readonly schemaVersion: 1;
	readonly commandId: string;
	readonly expectedKernelControlRevision: number;
	readonly expectedJournalRevision: number;
	readonly operation: WasmExecutionOperation;
	readonly identity: WasmExecutionIdentityV1;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly secretSnapshotRef: string;
	readonly secretValuesDigest: string;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly configValuesDigest: string | null;
}

// configRevision:0 ⇔ configSnapshotRef:null ⇔ configValuesDigest:null；
// 非零 revision 必须三者齐全，且 ref/digest 精确相等（由 correlation/宿主校验）。
function checkConfigSnapshotCoupling(
	configRevision: number,
	configSnapshotRef: string | null,
	configValuesDigest: string | null,
	path: string,
	code: string,
	errors: ValidationIssue[],
): void {
	if (configRevision === 0 && (configSnapshotRef !== null || configValuesDigest !== null)) {
		errors.push(issue(code, path + "/configSnapshotRef", "configRevision 0 requires configSnapshotRef null and configValuesDigest null"));
	}
	if (configRevision > 0 && (configSnapshotRef === null || configValuesDigest === null)) {
		errors.push(issue(code, path + "/configSnapshotRef", "a non-zero configRevision requires both configSnapshotRef and configValuesDigest"));
	}
	if ((configSnapshotRef === null) !== (configValuesDigest === null)) {
		errors.push(issue(code, path + "/configValuesDigest", "configValuesDigest is null exactly when configSnapshotRef is null"));
	}
}

function requireExecutionCommand(input: unknown, path: string, code: string, errors: ValidationIssue[]): ExecutionCommandV1 | null {
	const command = requireObject(input, path, "execution command", code, errors);
	if (command === null) return null;
	requireExactKeys(
		command,
		path,
		[
			"schemaVersion",
			"commandId",
			"expectedKernelControlRevision",
			"expectedJournalRevision",
			"operation",
			"identity",
			"packageDigest",
			"runtimeBinding",
			"capabilityRecordRevision",
			"capabilityRecordHash",
			"secretRevision",
			"secretSnapshotRef",
			"secretValuesDigest",
			"configRevision",
			"configSnapshotRef",
			"configValuesDigest",
		],
		code,
		errors,
	);
	const schemaVersion = requireSafeInteger(command.schemaVersion, path, "schemaVersion", 1, 1, code, errors);
	const commandId = requireUuidV7(command.commandId, path, "commandId", code, errors);
	const expectedKernelControlRevision = requireSafeInteger(command.expectedKernelControlRevision, path, "expectedKernelControlRevision", 0, WASM_U53_MAX, code, errors);
	const expectedJournalRevision = requireSafeInteger(command.expectedJournalRevision, path, "expectedJournalRevision", 0, WASM_U53_MAX, code, errors);
	const operation = requireStringUnion(command.operation, path, "operation", EXECUTION_OPERATIONS, code, errors);
	const identity = requireWasmExecutionIdentity(command.identity, path + "/identity", code, errors);
	const packageDigest = requireSha256Hex(command.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentity(command.runtimeBinding, path + "/runtimeBinding", code, errors);
	const capabilityRecordRevision = requireSafeInteger(command.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASM_U53_MAX, code, errors);
	const capabilityRecordHash = requireSha256Hex(command.capabilityRecordHash, path, "capabilityRecordHash", code, errors);
	const secretRevision = requireSafeInteger(command.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const secretSnapshotRef = requireSha256Hex(command.secretSnapshotRef, path, "secretSnapshotRef", code, errors);
	const secretValuesDigest = requireSha256Hex(command.secretValuesDigest, path, "secretValuesDigest", code, errors);
	const configRevision = requireSafeInteger(command.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);

	let configSnapshotRef: string | null = null;
	let configSnapshotRefParsed = false;
	if (command.configSnapshotRef === null) configSnapshotRefParsed = true;
	else {
		const ref = requireSha256Hex(command.configSnapshotRef, path, "configSnapshotRef", code, errors);
		if (ref !== null) {
			configSnapshotRef = ref;
			configSnapshotRefParsed = true;
		}
	}
	let configValuesDigest: string | null = null;
	let configValuesDigestParsed = false;
	if (command.configValuesDigest === null) configValuesDigestParsed = true;
	else {
		const digest = requireSha256Hex(command.configValuesDigest, path, "configValuesDigest", code, errors);
		if (digest !== null) {
			configValuesDigest = digest;
			configValuesDigestParsed = true;
		}
	}

	if (
		schemaVersion === null ||
		commandId === null ||
		expectedKernelControlRevision === null ||
		expectedJournalRevision === null ||
		operation === null ||
		identity === null ||
		packageDigest === null ||
		runtimeBinding === null ||
		capabilityRecordRevision === null ||
		capabilityRecordHash === null ||
		secretRevision === null ||
		secretSnapshotRef === null ||
		secretValuesDigest === null ||
		configRevision === null ||
		!configSnapshotRefParsed ||
		!configValuesDigestParsed ||
		errors.length
	) {
		return null;
	}
	checkConfigSnapshotCoupling(configRevision, configSnapshotRef, configValuesDigest, path, code, errors);
	if (errors.length) return null;
	return {
		schemaVersion: 1,
		commandId,
		expectedKernelControlRevision,
		expectedJournalRevision,
		operation: operation as WasmExecutionOperation,
		identity,
		packageDigest,
		runtimeBinding,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretSnapshotRef,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
	};
}

function requireWasmExecutionIdentity(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmExecutionIdentityV1 | null {
	const identity = requireObject(input, path, "wasm execution identity", code, errors);
	if (identity === null) return null;
	requireExactKeys(identity, path, ["sandboxId", "versionId", "preparationGeneration", "executionGeneration"], code, errors);
	const sandboxId = requireWasmSandboxId(identity.sandboxId, path, "sandboxId", code, errors);
	const versionId = requireWasmVersionId(identity.versionId, path, "versionId", code, errors);
	const preparationGeneration = requireSafeInteger(identity.preparationGeneration, path, "preparationGeneration", 0, WASM_U53_MAX, code, errors);
	const executionGeneration = requireSafeInteger(identity.executionGeneration, path, "executionGeneration", 0, WASM_U53_MAX, code, errors);
	if (sandboxId === null || versionId === null || preparationGeneration === null || executionGeneration === null || errors.length) return null;
	return { sandboxId, versionId, preparationGeneration, executionGeneration };
}

export function validateExecutionCommandV1(input: unknown): ValidationResult<ExecutionCommandV1> {
	const errors: ValidationIssue[] = [];
	const value = requireExecutionCommand(input, "", COMMAND_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

// commandDigest = hex(SHA-256(UTF8("iweb-execution-command-v1\n" || JCS(command))))；
// journal received/completed 条目与 snapshot handoff 都以此 digest 为 replay 冲突判据。
export function computeExecutionCommandDigestV1(command: ExecutionCommandV1): string {
	return domainPrefixedDigest(EXECUTION_COMMAND_DIGEST_DOMAIN, jcsCanonicalBytes(command));
}

export interface ExecutionAcknowledgementV1 {
	readonly schemaVersion: 1;
	readonly commandId: string;
	readonly operation: WasmExecutionOperation;
	readonly identity: WasmExecutionIdentityV1;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly secretSnapshotRef: string;
	readonly secretValuesDigest: string;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly configValuesDigest: string | null;
	readonly drainReceiptDigest: string | null;
	readonly result: "applied" | "rejected";
	readonly failureCode: string | null;
	readonly journalRevision: number;
}

function requireExecutionAcknowledgement(input: unknown, path: string, code: string, errors: ValidationIssue[]): ExecutionAcknowledgementV1 | null {
	const ack = requireObject(input, path, "execution acknowledgement", code, errors);
	if (ack === null) return null;
	requireExactKeys(
		ack,
		path,
		[
			"schemaVersion",
			"commandId",
			"operation",
			"identity",
			"packageDigest",
			"runtimeBinding",
			"capabilityRecordRevision",
			"capabilityRecordHash",
			"secretRevision",
			"secretSnapshotRef",
			"secretValuesDigest",
			"configRevision",
			"configSnapshotRef",
			"configValuesDigest",
			"drainReceiptDigest",
			"result",
			"failureCode",
			"journalRevision",
		],
		code,
		errors,
	);
	const schemaVersion = requireSafeInteger(ack.schemaVersion, path, "schemaVersion", 1, 1, code, errors);
	const commandId = requireUuidV7(ack.commandId, path, "commandId", code, errors);
	const operation = requireStringUnion(ack.operation, path, "operation", EXECUTION_OPERATIONS, code, errors);
	const identity = requireWasmExecutionIdentity(ack.identity, path + "/identity", code, errors);
	const packageDigest = requireSha256Hex(ack.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentity(ack.runtimeBinding, path + "/runtimeBinding", code, errors);
	const capabilityRecordRevision = requireSafeInteger(ack.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASM_U53_MAX, code, errors);
	const capabilityRecordHash = requireSha256Hex(ack.capabilityRecordHash, path, "capabilityRecordHash", code, errors);
	const secretRevision = requireSafeInteger(ack.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const secretSnapshotRef = requireSha256Hex(ack.secretSnapshotRef, path, "secretSnapshotRef", code, errors);
	const secretValuesDigest = requireSha256Hex(ack.secretValuesDigest, path, "secretValuesDigest", code, errors);
	const configRevision = requireSafeInteger(ack.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);

	let configSnapshotRef: string | null = null;
	let configSnapshotRefParsed = false;
	if (ack.configSnapshotRef === null) configSnapshotRefParsed = true;
	else {
		const ref = requireSha256Hex(ack.configSnapshotRef, path, "configSnapshotRef", code, errors);
		if (ref !== null) {
			configSnapshotRef = ref;
			configSnapshotRefParsed = true;
		}
	}
	let configValuesDigest: string | null = null;
	let configValuesDigestParsed = false;
	if (ack.configValuesDigest === null) configValuesDigestParsed = true;
	else {
		const digest = requireSha256Hex(ack.configValuesDigest, path, "configValuesDigest", code, errors);
		if (digest !== null) {
			configValuesDigest = digest;
			configValuesDigestParsed = true;
		}
	}
	let drainReceiptDigest: string | null = null;
	let drainReceiptDigestParsed = false;
	if (ack.drainReceiptDigest === null) drainReceiptDigestParsed = true;
	else {
		const digest = requireSha256Hex(ack.drainReceiptDigest, path, "drainReceiptDigest", code, errors);
		if (digest !== null) {
			drainReceiptDigest = digest;
			drainReceiptDigestParsed = true;
		}
	}
	const result = requireStringUnion(ack.result, path, "result", ["applied", "rejected"], code, errors);

	let failureCode: string | null = null;
	let failureCodeParsed = false;
	if (ack.failureCode === null) failureCodeParsed = true;
	else if (typeof ack.failureCode === "string" && WASM_FAILURE_CODE_PATTERN.test(ack.failureCode)) {
		failureCode = ack.failureCode;
		failureCodeParsed = true;
	} else {
		errors.push(issue(code, path + "/failureCode", "failureCode must be null for an applied result, otherwise match ^[A-Z][A-Z0-9_]{0,63}$"));
	}
	const journalRevision = requireSafeInteger(ack.journalRevision, path, "journalRevision", 0, WASM_U53_MAX, code, errors);

	if (
		schemaVersion === null ||
		commandId === null ||
		operation === null ||
		identity === null ||
		packageDigest === null ||
		runtimeBinding === null ||
		capabilityRecordRevision === null ||
		capabilityRecordHash === null ||
		secretRevision === null ||
		secretSnapshotRef === null ||
		secretValuesDigest === null ||
		configRevision === null ||
		!configSnapshotRefParsed ||
		!configValuesDigestParsed ||
		!drainReceiptDigestParsed ||
		result === null ||
		!failureCodeParsed ||
		journalRevision === null ||
		errors.length
	) {
		return null;
	}
	checkConfigSnapshotCoupling(configRevision, configSnapshotRef, configValuesDigest, path, code, errors);

	// failureCode 为 null 当且仅当 result 为 applied。
	if (result === "applied" && failureCode !== null) {
		errors.push(issue(code, path + "/failureCode", "an applied acknowledgement must carry failureCode null"));
	}
	if (result === "rejected" && failureCode === null) {
		errors.push(issue(code, path + "/failureCode", "a rejected acknowledgement must carry a bounded failureCode"));
	}
	// drainReceiptDigest 仅在 operation:"drain" 且 result:"applied" 时非空（rejected drain 必须为 null）。
	const appliedDrain = operation === "drain" && result === "applied";
	if (appliedDrain && drainReceiptDigest === null) {
		errors.push(issue(code, path + "/drainReceiptDigest", "an applied drain acknowledgement must carry the DrainReceiptV1 digest"));
	}
	if (!appliedDrain && drainReceiptDigest !== null) {
		errors.push(issue(code, path + "/drainReceiptDigest", "drainReceiptDigest is non-null only for operation drain with result applied"));
	}
	if (errors.length) return null;
	return {
		schemaVersion: 1,
		commandId,
		operation: operation as WasmExecutionOperation,
		identity,
		packageDigest,
		runtimeBinding,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretSnapshotRef,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
		drainReceiptDigest,
		result: result as "applied" | "rejected",
		failureCode,
		journalRevision,
	};
}

export function validateExecutionAcknowledgementV1(input: unknown): ValidationResult<ExecutionAcknowledgementV1> {
	const errors: ValidationIssue[] = [];
	const value = requireExecutionAcknowledgement(input, "", ACK_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

// Kernel 只接受 commandId、全部回显命令字段、result wire 与当前 control revision 仍然
// 匹配的 acknowledgement；否则视为 stale（绝不路由）。
export function correlateExecutionAcknowledgement(command: ExecutionCommandV1, acknowledgement: ExecutionAcknowledgementV1): ValidationResult<ExecutionAcknowledgementV1> {
	const errors: ValidationIssue[] = [];
	if (acknowledgement.commandId !== command.commandId) errors.push(issue("COMMAND_ID_MISMATCH", "/commandId", "acknowledgement command ID does not match the command"));
	if (acknowledgement.operation !== command.operation) errors.push(issue("OPERATION_MISMATCH", "/operation", "acknowledgement operation does not match the command"));
	if (!jcsEqual(acknowledgement.identity, command.identity)) errors.push(issue("IDENTITY_MISMATCH", "/identity", "acknowledgement execution identity does not match the command"));
	if (acknowledgement.packageDigest !== command.packageDigest) errors.push(issue("PACKAGE_DIGEST_MISMATCH", "/packageDigest", "acknowledgement package digest does not match the command"));
	if (!jcsEqual(acknowledgement.runtimeBinding, command.runtimeBinding)) {
		errors.push(issue("RUNTIME_BINDING_MISMATCH", "/runtimeBinding", "acknowledgement runtime binding does not match the command"));
	}
	if (acknowledgement.capabilityRecordRevision !== command.capabilityRecordRevision || acknowledgement.capabilityRecordHash !== command.capabilityRecordHash) {
		errors.push(issue("CAPABILITY_RECORD_MISMATCH", "/capabilityRecordRevision", "acknowledgement capability record pin does not match the command"));
	}
	if (
		acknowledgement.secretRevision !== command.secretRevision ||
		acknowledgement.secretSnapshotRef !== command.secretSnapshotRef ||
		acknowledgement.secretValuesDigest !== command.secretValuesDigest
	) {
		errors.push(issue("SECRET_SNAPSHOT_MISMATCH", "/secretSnapshotRef", "acknowledgement secret snapshot fields do not match the command"));
	}
	if (
		acknowledgement.configRevision !== command.configRevision ||
		acknowledgement.configSnapshotRef !== command.configSnapshotRef ||
		acknowledgement.configValuesDigest !== command.configValuesDigest
	) {
		errors.push(issue("CONFIG_SNAPSHOT_MISMATCH", "/configSnapshotRef", "acknowledgement config snapshot fields do not match the command"));
	}
	if (errors.length) return failure(errors);
	return ok(acknowledgement);
}

// ---------------------------------------------------------------------------
// ExecutionRpcEnvelopeV1（/v1/execution-rpc 专用；celld /v1/rpc 与之互斥）
// ---------------------------------------------------------------------------

export interface CommandRequestV1 {
	readonly kind: "command";
	readonly command: ExecutionCommandV1;
}

export interface CommandQueryV1 {
	readonly kind: "query";
	readonly commandId: string;
}

export interface CommandReplayV1 {
	readonly kind: "replay";
	readonly command: ExecutionCommandV1;
}

export type ExecutionRpcRequestBodyV1 = CommandRequestV1 | CommandQueryV1 | CommandReplayV1;

// supervisor journal 的 received 条目（query-result 的 received 字段复用它）。
export interface CommandReceivedV1 {
	readonly kind: "command-received";
	readonly commandId: string;
	readonly commandDigest: string;
	readonly command: ExecutionCommandV1;
	readonly snapshotHandoffDigest: string | null;
	readonly receivedAt: string;
	readonly journalRevision: number;
}

export interface CommandResponseV1 {
	readonly kind: "acknowledgement";
	readonly acknowledgement: ExecutionAcknowledgementV1;
}

export interface CommandQueryResultV1 {
	readonly kind: "query-result";
	readonly commandId: string;
	readonly status: "missing" | "received" | "completed";
	readonly received: CommandReceivedV1 | null;
	readonly acknowledgement: ExecutionAcknowledgementV1 | null;
}

export type ExecutionRpcResponseBodyV1 = CommandResponseV1 | CommandQueryResultV1;

export interface ExecutionRpcRequestEnvelopeV1 {
	readonly protocol: typeof EXECUTION_RPC_PROTOCOL_LITERAL;
	readonly requestId: string;
	readonly body: ExecutionRpcRequestBodyV1;
}

export interface ExecutionRpcResponseEnvelopeV1 {
	readonly protocol: typeof EXECUTION_RPC_PROTOCOL_LITERAL;
	readonly requestId: string;
	readonly body: ExecutionRpcResponseBodyV1;
}

function requireCommandReceived(input: unknown, path: string, code: string, errors: ValidationIssue[]): CommandReceivedV1 | null {
	const received = requireObject(input, path, "command-received journal entry", code, errors);
	if (received === null) return null;
	requireExactKeys(received, path, ["kind", "commandId", "commandDigest", "command", "snapshotHandoffDigest", "receivedAt", "journalRevision"], code, errors);
	const kind = requireStringLiteral(received.kind, path, "kind", "command-received", code, errors);
	const commandId = requireUuidV7(received.commandId, path, "commandId", code, errors);
	const commandDigest = requireSha256Hex(received.commandDigest, path, "commandDigest", code, errors);
	const command = requireExecutionCommand(received.command, path + "/command", code, errors);
	let snapshotHandoffDigest: string | null = null;
	let snapshotHandoffParsed = false;
	if (received.snapshotHandoffDigest === null) snapshotHandoffParsed = true;
	else {
		const digest = requireSha256Hex(received.snapshotHandoffDigest, path, "snapshotHandoffDigest", code, errors);
		if (digest !== null) {
			snapshotHandoffDigest = digest;
			snapshotHandoffParsed = true;
		}
	}
	const receivedAt = requireRfc3339Utc(received.receivedAt, path, "receivedAt", code, errors);
	const journalRevision = requireSafeInteger(received.journalRevision, path, "journalRevision", 0, WASM_U53_MAX, code, errors);
	if (kind === null || commandId === null || commandDigest === null || command === null || !snapshotHandoffParsed || receivedAt === null || journalRevision === null || errors.length) {
		return null;
	}
	// fail-closed：received 条目携带的 commandDigest 必须可由其 command 精确复算。
	if (computeExecutionCommandDigestV1(command) !== commandDigest) {
		errors.push(issue("EXECUTION_COMMAND_DIGEST_MISMATCH", path + "/commandDigest", "commandDigest must equal hex(SHA-256(UTF8(\"iweb-execution-command-v1\\n\" || JCS(command))))"));
		return null;
	}
	return { kind: "command-received", commandId, commandDigest, command, snapshotHandoffDigest, receivedAt, journalRevision };
}

export function validateCommandReceivedV1(input: unknown): ValidationResult<CommandReceivedV1> {
	const errors: ValidationIssue[] = [];
	const value = requireCommandReceived(input, "", ENVELOPE_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

function requireExecutionRpcRequestBody(input: unknown, path: string, code: string, errors: ValidationIssue[]): ExecutionRpcRequestBodyV1 | null {
	const body = requireObject(input, path, "execution rpc body", code, errors);
	if (body === null) return null;
	if (body.kind === "command" || body.kind === "replay") {
		requireExactKeys(body, path, ["kind", "command"], code, errors);
		const command = requireExecutionCommand(body.command, path + "/command", code, errors);
		if (command === null || errors.length) return null;
		return body.kind === "command" ? { kind: "command", command } : { kind: "replay", command };
	}
	if (body.kind === "query") {
		requireExactKeys(body, path, ["kind", "commandId"], code, errors);
		const commandId = requireUuidV7(body.commandId, path, "commandId", code, errors);
		if (commandId === null || errors.length) return null;
		return { kind: "query", commandId };
	}
	errors.push(issue(code, path + "/kind", 'kind must be one of: command, query, replay'));
	return null;
}

function requireExecutionRpcResponseBody(input: unknown, path: string, code: string, errors: ValidationIssue[]): ExecutionRpcResponseBodyV1 | null {
	const body = requireObject(input, path, "execution rpc response body", code, errors);
	if (body === null) return null;
	if (body.kind === "acknowledgement") {
		requireExactKeys(body, path, ["kind", "acknowledgement"], code, errors);
		const acknowledgement = requireExecutionAcknowledgement(body.acknowledgement, path + "/acknowledgement", code, errors);
		if (acknowledgement === null || errors.length) return null;
		return { kind: "acknowledgement", acknowledgement };
	}
	if (body.kind === "query-result") {
		requireExactKeys(body, path, ["kind", "commandId", "status", "received", "acknowledgement"], code, errors);
		const commandId = requireUuidV7(body.commandId, path, "commandId", code, errors);
		const status = requireStringUnion(body.status, path, "status", ["missing", "received", "completed"], code, errors);
		let received: CommandReceivedV1 | null = null;
		if (body.received !== null) {
			const parsed = requireCommandReceived(body.received, path + "/received", code, errors);
			if (parsed !== null) received = parsed;
		}
		let acknowledgement: ExecutionAcknowledgementV1 | null = null;
		if (body.acknowledgement !== null) {
			const parsed = requireExecutionAcknowledgement(body.acknowledgement, path + "/acknowledgement", code, errors);
			if (parsed !== null) acknowledgement = parsed;
		}
		if (commandId === null || status === null || errors.length) return null;
		// received 仅在 status:"missing" 时为 null；acknowledgement 当且仅当 status:"completed" 非空。
		if (status === "missing" && received !== null) {
			errors.push(issue(code, path + "/received", "received must be null when status is missing"));
		}
		if (status !== "missing" && received === null) {
			errors.push(issue(code, path + "/received", "received must be the exact CommandReceivedV1 when status is received or completed"));
		}
		if (status === "completed" && acknowledgement === null) {
			errors.push(issue(code, path + "/acknowledgement", "acknowledgement must be non-null when status is completed"));
		}
		if (status !== "completed" && acknowledgement !== null) {
			errors.push(issue(code, path + "/acknowledgement", "acknowledgement is non-null if and only if status is completed"));
		}
		if (errors.length) return null;
		return { kind: "query-result", commandId, status: status as "missing" | "received" | "completed", received, acknowledgement };
	}
	errors.push(issue(code, path + "/kind", "kind must be one of: acknowledgement, query-result"));
	return null;
}

function requireExecutionRpcEnvelope(input: unknown, code: string, errors: ValidationIssue[]): { readonly requestId: string } | null {
	const envelope = requireObject(input, "", "execution rpc envelope", code, errors);
	if (envelope === null) return null;
	requireExactKeys(envelope, "", ["protocol", "requestId", "body"], code, errors);
	const protocol = requireStringLiteral(envelope.protocol, "", "protocol", EXECUTION_RPC_PROTOCOL_LITERAL, code, errors);
	const requestId = requireUuidV7(envelope.requestId, "", "requestId", code, errors);
	if (protocol === null || requestId === null) return null;
	return { requestId };
}

export function validateExecutionRpcRequestEnvelopeV1(input: unknown): ValidationResult<ExecutionRpcRequestEnvelopeV1> {
	const errors: ValidationIssue[] = [];
	const head = requireExecutionRpcEnvelope(input, ENVELOPE_CODE, errors);
	if (head === null) return failure(errors);
	const body = requireExecutionRpcRequestBody((input as Record<string, unknown>).body, "/body", ENVELOPE_CODE, errors);
	if (body === null || errors.length) return failure(errors);
	return ok({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: head.requestId, body });
}

export function validateExecutionRpcResponseEnvelopeV1(input: unknown): ValidationResult<ExecutionRpcResponseEnvelopeV1> {
	const errors: ValidationIssue[] = [];
	const head = requireExecutionRpcEnvelope(input, ENVELOPE_CODE, errors);
	if (head === null) return failure(errors);
	const body = requireExecutionRpcResponseBody((input as Record<string, unknown>).body, "/body", ENVELOPE_CODE, errors);
	if (body === null || errors.length) return failure(errors);
	return ok({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: head.requestId, body });
}

// 响应必须回显同一 protocol 与 requestId；requestId 是 envelope 级关联键。
export function correlateExecutionRpcResponse(request: ExecutionRpcRequestEnvelopeV1, response: ExecutionRpcResponseEnvelopeV1): ValidationResult<ExecutionRpcResponseEnvelopeV1> {
	const errors: ValidationIssue[] = [];
	if (response.protocol !== request.protocol) errors.push(issue("PROTOCOL_MISMATCH", "/protocol", "response protocol does not match the request envelope"));
	if (response.requestId !== request.requestId) errors.push(issue("REQUEST_ID_MISMATCH", "/requestId", "response requestId does not match the request envelope"));
	if (errors.length) return failure(errors);
	return ok(response);
}

// ---------------------------------------------------------------------------
// Wasm control state（wasm-control-state-v2.json + controlRevision CAS）
// ---------------------------------------------------------------------------

export interface WasmVersionRegistryRowV1 {
	readonly versionId: string;
	// 证明导出的 {applicationId, digest, sequence}（结构上等价 celld VersionIdentity 投影）。
	readonly identity: VersionIdentity;
	readonly packageDigest: string;
	readonly normalizedPolicy: NormalizedWasmManifestV1;
	readonly lifecycle: LifecycleState;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly admissionProofRef: string;
	readonly admissionProofDigest: string;
	readonly readinessLeaseDigest: string | null;
}

export type WasmActivePointerV1 =
	| {
			readonly kind: "active";
			readonly runtimeKind: "wasm";
			readonly applicationId: string;
			readonly versionId: string;
			readonly identity: VersionIdentity;
			readonly runtimeBinding: RuntimeBindingIdentityV1;
			readonly admissionProofRef: string;
			readonly admissionProofDigest: string;
			readonly routeGeneration: number;
	  }
	| {
			readonly kind: "unavailable";
			readonly runtimeKind: "wasm";
			readonly applicationId: string;
			readonly routeGeneration: number;
	  };

export interface WasmApplicationControlRecordV1 {
	readonly runtimeKind: "wasm";
	readonly applicationId: string;
	readonly versions: readonly WasmVersionRegistryRowV1[];
	readonly active: WasmActivePointerV1;
	readonly routeGeneration: number;
	readonly secretRevision: number;
	readonly configRevision: number;
}

export type WasmOutboxDeliveryState = "pending" | "sent" | "acknowledged" | "dead";

export interface CommandOutboxRecordV1 {
	readonly commandId: string;
	readonly command: ExecutionCommandV1;
	readonly createdAt: string;
	readonly deliveryState: WasmOutboxDeliveryState;
	readonly attempts: number;
	readonly lastAttemptAt: string | null;
}

export interface WasmControlMigrationStateV1 {
	readonly source: "celld-control-state-v1";
	readonly status: "not-started" | "in-progress" | "complete";
	readonly sourceDigest: string | null;
	readonly completedAt: string | null;
}

export interface WasmControlStateFileV2 {
	readonly schemaVersion: 2;
	readonly runtimeKind: "wasm";
	readonly controlRevision: number;
	readonly applications: Readonly<Record<string, WasmApplicationControlRecordV1>>;
	readonly commandOutbox: readonly CommandOutboxRecordV1[];
	readonly migration: WasmControlMigrationStateV1;
}

function requireVersionIdentityProjection(input: unknown, path: string, code: string, errors: ValidationIssue[]): VersionIdentity | null {
	const identity = requireObject(input, path, "version identity", code, errors);
	if (identity === null) return null;
	requireExactKeys(identity, path, ["applicationId", "digest", "sequence"], code, errors);
	const applicationId = requireWasmApplicationId(identity.applicationId, path, "applicationId", code, errors);
	const digest = requireSha256Hex(identity.digest, path, "digest", code, errors);
	const sequence = requireSafeInteger(identity.sequence, path, "sequence", 1, WASM_U53_MAX, code, errors);
	if (applicationId === null || digest === null || sequence === null || errors.length) return null;
	return { applicationId, digest, sequence };
}

function requireWasmVersionRegistryRow(input: unknown, applicationId: string, path: string, code: string, errors: ValidationIssue[]): WasmVersionRegistryRowV1 | null {
	const row = requireObject(input, path, "wasm version row", code, errors);
	if (row === null) return null;
	requireExactKeys(
		row,
		path,
		["versionId", "identity", "packageDigest", "normalizedPolicy", "lifecycle", "runtimeBinding", "admissionProofRef", "admissionProofDigest", "readinessLeaseDigest"],
		code,
		errors,
	);
	const versionId = requireWasmVersionId(row.versionId, path, "versionId", code, errors);
	const identity = requireVersionIdentityProjection(row.identity, path + "/identity", code, errors);
	const packageDigest = requireSha256Hex(row.packageDigest, path, "packageDigest", code, errors);
	const runtimeBinding = requireRuntimeBindingIdentity(row.runtimeBinding, path + "/runtimeBinding", code, errors);
	const admissionProofDigest = requireSha256Hex(row.admissionProofDigest, path, "admissionProofDigest", code, errors);

	let lifecycle: LifecycleState | null = null;
	if (typeof row.lifecycle === "string") {
		const parsed = validateLifecycleState(row.lifecycle);
		if (parsed.ok) lifecycle = parsed.value;
		else errors.push(issue(code, path + "/lifecycle", "lifecycle must be an existing Kernel LifecycleState literal and never retiring"));
	} else {
		errors.push(issue(code, path + "/lifecycle", "lifecycle must be an existing Kernel LifecycleState literal and never retiring"));
	}

	let normalizedPolicy: NormalizedWasmManifestV1 | null = null;
	if (row.normalizedPolicy !== undefined) {
		const parsed = validateNormalizedWasmManifestV1(row.normalizedPolicy);
		if (parsed.ok) normalizedPolicy = parsed.value;
		else errors.push(...parsed.errors);
	} else {
		errors.push(issue(code, path + "/normalizedPolicy", "required field is missing"));
	}

	let readinessLeaseDigest: string | null = null;
	let leaseParsed = false;
	if (row.readinessLeaseDigest === null) leaseParsed = true;
	else {
		const digest = requireSha256Hex(row.readinessLeaseDigest, path, "readinessLeaseDigest", code, errors);
		if (digest !== null) {
			readinessLeaseDigest = digest;
			leaseParsed = true;
		}
	}

	if (versionId === null || identity === null || packageDigest === null || runtimeBinding === null || admissionProofDigest === null || lifecycle === null || normalizedPolicy === null || !leaseParsed || errors.length) {
		return null;
	}

	// 行内交叉校验：versionId 必须是证明的完整 digest-sequence 标签；proof ref 是精确公式；
	// normalizedPolicy.name 必须等于 applicationId；ready/active 候选必须携带就绪租约 digest。
	if (identity.applicationId !== applicationId) {
		errors.push(issue(code, path + "/identity/applicationId", "version identity must belong to the same application"));
	}
	if (composeWasmVersionId(identity.digest, identity.sequence) !== versionId) {
		errors.push(issue(code, path + "/versionId", "versionId must be the proof's complete digest-sequence label"));
	}
	const expectedProofRef = "admission-proof/" + applicationId + "/" + versionId;
	if (row.admissionProofRef !== expectedProofRef) {
		errors.push(issue(code, path + "/admissionProofRef", 'admissionProofRef must equal "admission-proof/<applicationId>/<versionId>"'));
	}
	if (normalizedPolicy.name !== applicationId) {
		errors.push(issue(code, path + "/normalizedPolicy/name", "normalizedPolicy.name must equal the record applicationId"));
	}
	if ((lifecycle === "ready" || lifecycle === "active") && readinessLeaseDigest === null) {
		errors.push(issue(code, path + "/readinessLeaseDigest", "a ready or active candidate must carry a readiness lease digest"));
	}
	if (errors.length) return null;
	return { versionId, identity, packageDigest, normalizedPolicy, lifecycle, runtimeBinding, admissionProofRef: row.admissionProofRef as string, admissionProofDigest, readinessLeaseDigest };
}

function requireWasmActivePointer(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmActivePointerV1 | null {
	const pointer = requireObject(input, path, "wasm active pointer", code, errors);
	if (pointer === null) return null;
	if (pointer.kind === "active") {
		requireExactKeys(pointer, path, ["kind", "runtimeKind", "applicationId", "versionId", "identity", "runtimeBinding", "admissionProofRef", "admissionProofDigest", "routeGeneration"], code, errors);
		const runtimeKind = requireStringLiteral(pointer.runtimeKind, path, "runtimeKind", "wasm", code, errors);
		const applicationId = requireWasmApplicationId(pointer.applicationId, path, "applicationId", code, errors);
		const versionId = requireWasmVersionId(pointer.versionId, path, "versionId", code, errors);
		const identity = requireVersionIdentityProjection(pointer.identity, path + "/identity", code, errors);
		const runtimeBinding = requireRuntimeBindingIdentity(pointer.runtimeBinding, path + "/runtimeBinding", code, errors);
		const admissionProofDigest = requireSha256Hex(pointer.admissionProofDigest, path, "admissionProofDigest", code, errors);
		const routeGeneration = requireSafeInteger(pointer.routeGeneration, path, "routeGeneration", 0, WASM_U53_MAX, code, errors);
		if (runtimeKind === null || applicationId === null || versionId === null || identity === null || runtimeBinding === null || admissionProofDigest === null || routeGeneration === null || errors.length) {
			return null;
		}
		const expectedProofRef = "admission-proof/" + applicationId + "/" + versionId;
		if (pointer.admissionProofRef !== expectedProofRef) {
			errors.push(issue(code, path + "/admissionProofRef", 'admissionProofRef must equal "admission-proof/<applicationId>/<versionId>"'));
			return null;
		}
		return { kind: "active", runtimeKind: "wasm", applicationId, versionId, identity, runtimeBinding, admissionProofRef: expectedProofRef, admissionProofDigest, routeGeneration };
	}
	if (pointer.kind === "unavailable") {
		requireExactKeys(pointer, path, ["kind", "runtimeKind", "applicationId", "routeGeneration"], code, errors);
		const runtimeKind = requireStringLiteral(pointer.runtimeKind, path, "runtimeKind", "wasm", code, errors);
		const applicationId = requireWasmApplicationId(pointer.applicationId, path, "applicationId", code, errors);
		const routeGeneration = requireSafeInteger(pointer.routeGeneration, path, "routeGeneration", 0, WASM_U53_MAX, code, errors);
		if (runtimeKind === null || applicationId === null || routeGeneration === null || errors.length) return null;
		return { kind: "unavailable", runtimeKind: "wasm", applicationId, routeGeneration };
	}
	errors.push(issue(code, path + "/kind", "kind must be active or unavailable"));
	return null;
}

function requireWasmApplicationControlRecord(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmApplicationControlRecordV1 | null {
	const record = requireObject(input, path, "wasm application control record", code, errors);
	if (record === null) return null;
	requireExactKeys(record, path, ["runtimeKind", "applicationId", "versions", "active", "routeGeneration", "secretRevision", "configRevision"], code, errors);
	const runtimeKind = requireStringLiteral(record.runtimeKind, path, "runtimeKind", "wasm", code, errors);
	const applicationId = requireWasmApplicationId(record.applicationId, path, "applicationId", code, errors);
	const routeGeneration = requireSafeInteger(record.routeGeneration, path, "routeGeneration", 0, WASM_U53_MAX, code, errors);
	const secretRevision = requireSafeInteger(record.secretRevision, path, "secretRevision", 0, WASM_U53_MAX, code, errors);
	const configRevision = requireSafeInteger(record.configRevision, path, "configRevision", 0, WASM_U53_MAX, code, errors);

	let versions: WasmVersionRegistryRowV1[] | null = null;
	if (Array.isArray(record.versions)) {
		const rows: WasmVersionRegistryRowV1[] = [];
		const seen = new Set<string>();
		let rowsValid = true;
		for (let i = 0; i < record.versions.length; i++) {
			const row = requireWasmVersionRegistryRow(record.versions[i], applicationId === null ? "" : applicationId, path + "/versions/" + i, code, errors);
			if (row === null) {
				rowsValid = false;
				continue;
			}
			if (seen.has(row.versionId)) {
				errors.push(issue(code, path + "/versions", "versions must be unique by versionId"));
				rowsValid = false;
				continue;
			}
			seen.add(row.versionId);
			rows.push(row);
		}
		if (rowsValid) versions = rows;
	} else {
		errors.push(issue(code, path + "/versions", "versions must be an array"));
	}

	const active = requireWasmActivePointer(record.active, path + "/active", code, errors);
	if (runtimeKind === null || applicationId === null || routeGeneration === null || secretRevision === null || configRevision === null || versions === null || active === null || errors.length) {
		return null;
	}

	if (active.applicationId !== applicationId) {
		errors.push(issue(code, path + "/active/applicationId", "active pointer must belong to the same application"));
	}
	if (active.routeGeneration !== routeGeneration) {
		errors.push(issue(code, path + "/active/routeGeneration", "active pointer route generation must equal the record's current route generation"));
	}
	if (active.kind === "active") {
		const row = versions.find((candidate) => candidate.versionId === active.versionId);
		if (row === undefined) {
			errors.push(issue(code, path + "/active/versionId", "active pointer must name a registry version"));
		} else {
			if (!jcsEqual(row.identity, active.identity) || !jcsEqual(row.runtimeBinding, active.runtimeBinding) || row.admissionProofRef !== active.admissionProofRef || row.admissionProofDigest !== active.admissionProofDigest) {
				errors.push(issue(code, path + "/active", "active pointer identity, binding, and proof reference must match the registry version"));
			}
		}
	}
	if (errors.length) return null;
	return { runtimeKind: "wasm", applicationId, versions, active, routeGeneration, secretRevision, configRevision };
}

function requireCommandOutboxRecord(input: unknown, path: string, code: string, errors: ValidationIssue[]): CommandOutboxRecordV1 | null {
	const entry = requireObject(input, path, "command outbox record", code, errors);
	if (entry === null) return null;
	requireExactKeys(entry, path, ["commandId", "command", "createdAt", "deliveryState", "attempts", "lastAttemptAt"], code, errors);
	const commandId = requireUuidV7(entry.commandId, path, "commandId", code, errors);
	const command = requireExecutionCommand(entry.command, path + "/command", code, errors);
	const createdAt = requireRfc3339Utc(entry.createdAt, path, "createdAt", code, errors);
	const deliveryState = requireStringUnion(entry.deliveryState, path, "deliveryState", ["pending", "sent", "acknowledged", "dead"], code, errors);
	const attempts = requireSafeInteger(entry.attempts, path, "attempts", 0, WASM_U53_MAX, code, errors);
	let lastAttemptAt: string | null = null;
	let lastAttemptParsed = false;
	if (entry.lastAttemptAt === null) lastAttemptParsed = true;
	else {
		const parsed = requireRfc3339Utc(entry.lastAttemptAt, path, "lastAttemptAt", code, errors);
		if (parsed !== null) {
			lastAttemptAt = parsed;
			lastAttemptParsed = true;
		}
	}
	if (commandId === null || command === null || createdAt === null || deliveryState === null || attempts === null || !lastAttemptParsed || errors.length) return null;
	if (command.commandId !== commandId) {
		errors.push(issue(code, path + "/commandId", "outbox commandId must match the wrapped command"));
		return null;
	}
	return { commandId, command, createdAt, deliveryState: deliveryState as WasmOutboxDeliveryState, attempts, lastAttemptAt };
}

function requireWasmControlMigrationState(input: unknown, path: string, code: string, errors: ValidationIssue[]): WasmControlMigrationStateV1 | null {
	const migration = requireObject(input, path, "wasm control migration state", code, errors);
	if (migration === null) return null;
	requireExactKeys(migration, path, ["source", "status", "sourceDigest", "completedAt"], code, errors);
	const source = requireStringLiteral(migration.source, path, "source", "celld-control-state-v1", code, errors);
	const status = requireStringUnion(migration.status, path, "status", ["not-started", "in-progress", "complete"], code, errors);
	let sourceDigest: string | null = null;
	let sourceDigestParsed = false;
	if (migration.sourceDigest === null) sourceDigestParsed = true;
	else {
		const digest = requireSha256Hex(migration.sourceDigest, path, "sourceDigest", code, errors);
		if (digest !== null) {
			sourceDigest = digest;
			sourceDigestParsed = true;
		}
	}
	let completedAt: string | null = null;
	let completedAtParsed = false;
	if (migration.completedAt === null) completedAtParsed = true;
	else {
		const parsed = requireRfc3339Utc(migration.completedAt, path, "completedAt", code, errors);
		if (parsed !== null) {
			completedAt = parsed;
			completedAtParsed = true;
		}
	}
	if (source === null || status === null || !sourceDigestParsed || !completedAtParsed || errors.length) return null;
	if (status === "complete" && completedAt === null) {
		errors.push(issue(code, path + "/completedAt", "a complete migration must carry completedAt"));
	}
	if (status === "not-started" && completedAt !== null) {
		errors.push(issue(code, path + "/completedAt", "a not-started migration must not carry completedAt"));
	}
	if (errors.length) return null;
	return { source: "celld-control-state-v1", status: status as WasmControlMigrationStateV1["status"], sourceDigest, completedAt };
}

export function validateWasmApplicationControlRecordV1(input: unknown): ValidationResult<WasmApplicationControlRecordV1> {
	const errors: ValidationIssue[] = [];
	const value = requireWasmApplicationControlRecord(input, "", CONTROL_CODE, errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

export function validateWasmControlStateFileV2(input: unknown): ValidationResult<WasmControlStateFileV2> {
	const errors: ValidationIssue[] = [];
	const file = requireObject(input, "", "wasm control state file", CONTROL_CODE, errors);
	if (file === null) return failure(errors);
	requireExactKeys(file, "", ["schemaVersion", "runtimeKind", "controlRevision", "applications", "commandOutbox", "migration"], CONTROL_CODE, errors);
	const schemaVersion = requireSafeInteger(file.schemaVersion, "", "schemaVersion", 2, 2, CONTROL_CODE, errors);
	const runtimeKind = requireStringLiteral(file.runtimeKind, "", "runtimeKind", "wasm", CONTROL_CODE, errors);
	const controlRevision = requireSafeInteger(file.controlRevision, "", "controlRevision", 0, WASM_U53_MAX, CONTROL_CODE, errors);

	const applications: Record<string, WasmApplicationControlRecordV1> = {};
	if (isRecord(file.applications)) {
		for (const key of Object.keys(file.applications)) {
			if (!WASM_APPLICATION_ID_PATTERN.test(key)) {
				errors.push(issue(CONTROL_CODE, "/applications/" + key, "application key must be a lower-case application identifier of at most 63 ASCII bytes"));
				continue;
			}
			const record = requireWasmApplicationControlRecord(file.applications[key], "/applications/" + key, CONTROL_CODE, errors);
			if (record === null) continue;
			if (record.applicationId !== key) {
				errors.push(issue(CONTROL_CODE, "/applications/" + key, "application record must be keyed by its applicationId"));
				continue;
			}
			applications[key] = record;
		}
	} else {
		errors.push(issue(CONTROL_CODE, "/applications", "applications must be an object keyed by applicationId"));
	}

	const outbox: CommandOutboxRecordV1[] = [];
	if (Array.isArray(file.commandOutbox)) {
		const seen = new Set<string>();
		for (let i = 0; i < file.commandOutbox.length; i++) {
			const entry = requireCommandOutboxRecord(file.commandOutbox[i], "/commandOutbox/" + i, CONTROL_CODE, errors);
			if (entry === null) continue;
			if (seen.has(entry.commandId)) {
				errors.push(issue(CONTROL_CODE, "/commandOutbox", "outbox commandId must be unique"));
				continue;
			}
			seen.add(entry.commandId);
			outbox.push(entry);
		}
	} else {
		errors.push(issue(CONTROL_CODE, "/commandOutbox", "commandOutbox must be an array"));
	}

	const migration = requireWasmControlMigrationState(file.migration, "/migration", CONTROL_CODE, errors);
	if (schemaVersion === null || runtimeKind === null || controlRevision === null || migration === null || errors.length) return failure(errors);
	return ok({ schemaVersion: 2, runtimeKind: "wasm", controlRevision, applications, commandOutbox: outbox, migration });
}

// controlRevision CAS：从 0 起步，每次已提交 Kernel mutation 恰好 +1；
// 期望值不匹配返回 CONTROL_REVISION_CONFLICT 且不写任何东西。
export function checkControlRevisionCas(expectedControlRevision: number, nextControlRevision: number): ValidationResult<number> {
	for (const [fieldName, value] of [["expectedControlRevision", expectedControlRevision], ["nextControlRevision", nextControlRevision]] as const) {
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > WASM_U53_MAX) {
			return failure([issue(CONTROL_CODE, "/" + fieldName, fieldName + " must be a u53 integer")]);
		}
	}
	if (nextControlRevision !== expectedControlRevision + 1) {
		return failure([issue(CONTROL_REVISION_CONFLICT, "/controlRevision", "control revision CAS requires next = current + 1; a mismatch writes nothing")]);
	}
	return ok(nextControlRevision);
}

// ---------------------------------------------------------------------------
// KindClaimBootstrapV1（application-sandbox delta：升级节点的一次性 celld kind-claim bootstrap）
// ---------------------------------------------------------------------------

export interface RuntimeKindClaimV1 {
	readonly applicationId: string;
	readonly runtimeKind: "celld";
	readonly bindingRevision: number;
	readonly bindingDigest: string;
}

export interface KindClaimBootstrapV1 {
	readonly schemaVersion: 1;
	readonly bootstrapRevision: number;
	readonly sourceKind: "celld";
	readonly controlStateRawDigest: string;
	readonly sourceRevision: number;
	readonly sortedClaims: readonly RuntimeKindClaimV1[];
	readonly completionReceiptDigest: string;
}

// bindingDigest = hex(SHA-256(UTF8("iweb-application-kind-binding-v1\n" ||
// JCS({schemaVersion:1, applicationId, runtimeKind, bindingRevision}))))。
export function computeRuntimeKindClaimBindingDigest(claim: RuntimeKindClaimV1): string {
	return domainPrefixedDigest(
		KIND_CLAIM_BINDING_DIGEST_DOMAIN,
		jcsCanonicalBytes({ schemaVersion: 1, applicationId: claim.applicationId, runtimeKind: claim.runtimeKind, bindingRevision: claim.bindingRevision }),
	);
}

// completionReceiptDigest = hex(SHA-256(UTF8("iweb-kind-claim-bootstrap-v1\n" ||
// JCS(record with completionReceiptDigest omitted))))。
export function computeKindClaimBootstrapDigest(record: Omit<KindClaimBootstrapV1, "completionReceiptDigest">): string {
	return domainPrefixedDigest(
		KIND_CLAIM_BOOTSTRAP_DIGEST_DOMAIN,
		jcsCanonicalBytes({
			schemaVersion: record.schemaVersion,
			bootstrapRevision: record.bootstrapRevision,
			sourceKind: record.sourceKind,
			controlStateRawDigest: record.controlStateRawDigest,
			sourceRevision: record.sourceRevision,
			sortedClaims: record.sortedClaims,
		}),
	);
}

function requireRuntimeKindClaim(input: unknown, path: string, code: string, errors: ValidationIssue[]): RuntimeKindClaimV1 | null {
	const claim = requireObject(input, path, "runtime kind claim", code, errors);
	if (claim === null) return null;
	requireExactKeys(claim, path, ["applicationId", "runtimeKind", "bindingRevision", "bindingDigest"], code, errors);
	const applicationId = requireWasmApplicationId(claim.applicationId, path, "applicationId", code, errors);
	// bootstrap 只从 celld 控制态推导 claim；wasm claim 属于越权写入，必须拒绝。
	const runtimeKind = requireStringLiteral(claim.runtimeKind, path, "runtimeKind", "celld", code, errors);
	// bindingRevision 从 1 起且永不改变；bootstrap 是首次写入，唯一合法值是 1。
	const bindingRevision = requireSafeInteger(claim.bindingRevision, path, "bindingRevision", 1, 1, code, errors);
	const bindingDigest = requireSha256Hex(claim.bindingDigest, path, "bindingDigest", code, errors);
	if (applicationId === null || runtimeKind === null || bindingRevision === null || bindingDigest === null || errors.length) return null;
	if (computeRuntimeKindClaimBindingDigest({ applicationId, runtimeKind: "celld", bindingRevision, bindingDigest }) !== bindingDigest) {
		errors.push(issue("KIND_CLAIM_BINDING_DIGEST_MISMATCH", path + "/bindingDigest", "bindingDigest must equal the application-kind-binding-v1 domain digest of the claim"));
		return null;
	}
	return { applicationId, runtimeKind: "celld", bindingRevision, bindingDigest };
}

export function validateKindClaimBootstrapV1(input: unknown): ValidationResult<KindClaimBootstrapV1> {
	const errors: ValidationIssue[] = [];
	const record = requireObject(input, "", "kind claim bootstrap record", KIND_CLAIM_CODE, errors);
	if (record === null) return failure(errors);
	requireExactKeys(record, "", ["schemaVersion", "bootstrapRevision", "sourceKind", "controlStateRawDigest", "sourceRevision", "sortedClaims", "completionReceiptDigest"], KIND_CLAIM_CODE, errors);
	const schemaVersion = requireSafeInteger(record.schemaVersion, "", "schemaVersion", 1, 1, KIND_CLAIM_CODE, errors);
	const bootstrapRevision = requireSafeInteger(record.bootstrapRevision, "", "bootstrapRevision", 0, WASM_U53_MAX, KIND_CLAIM_CODE, errors);
	const sourceKind = requireStringLiteral(record.sourceKind, "", "sourceKind", "celld", KIND_CLAIM_CODE, errors);
	const controlStateRawDigest = requireSha256Hex(record.controlStateRawDigest, "", "controlStateRawDigest", KIND_CLAIM_CODE, errors);
	const sourceRevision = requireSafeInteger(record.sourceRevision, "", "sourceRevision", 0, WASM_U53_MAX, KIND_CLAIM_CODE, errors);
	const completionReceiptDigest = requireSha256Hex(record.completionReceiptDigest, "", "completionReceiptDigest", KIND_CLAIM_CODE, errors);

	let claims: RuntimeKindClaimV1[] | null = null;
	if (Array.isArray(record.sortedClaims)) {
		const parsed: RuntimeKindClaimV1[] = [];
		let valid = true;
		for (let i = 0; i < record.sortedClaims.length; i++) {
			const claim = requireRuntimeKindClaim(record.sortedClaims[i], "/sortedClaims/" + i, KIND_CLAIM_CODE, errors);
			if (claim === null) {
				valid = false;
				continue;
			}
			parsed.push(claim);
		}
		if (valid) {
			for (let i = 1; i < parsed.length; i++) {
				const comparison = compareUtf8Bytes(parsed[i - 1].applicationId, parsed[i].applicationId);
				if (comparison === 0) {
					errors.push(issue(KIND_CLAIM_CODE, "/sortedClaims", "claim applicationId must be unique"));
					valid = false;
					break;
				}
				if (comparison > 0) {
					errors.push(issue(KIND_CLAIM_CODE, "/sortedClaims", "sortedClaims must be bytewise sorted by applicationId"));
					valid = false;
					break;
				}
			}
		}
		if (valid) claims = parsed;
	} else {
		errors.push(issue(KIND_CLAIM_CODE, "/sortedClaims", "sortedClaims must be an array"));
	}

	if (schemaVersion === null || bootstrapRevision === null || sourceKind === null || controlStateRawDigest === null || sourceRevision === null || completionReceiptDigest === null || claims === null || errors.length) {
		return failure(errors);
	}
	const expected = computeKindClaimBootstrapDigest({
		schemaVersion: 1,
		bootstrapRevision,
		sourceKind: "celld",
		controlStateRawDigest,
		sourceRevision,
		sortedClaims: claims,
	});
	if (completionReceiptDigest !== expected) {
		errors.push(issue("KIND_CLAIM_DIGEST_MISMATCH", "/completionReceiptDigest", "completionReceiptDigest must equal the kind-claim-bootstrap-v1 domain digest of the record"));
		return failure(errors);
	}
	return ok({ schemaVersion: 1, bootstrapRevision, sourceKind: "celld", controlStateRawDigest, sourceRevision, sortedClaims: claims, completionReceiptDigest });
}

// ---------------------------------------------------------------------------
// 向量/示例构造器（供跨实现 round-trip 与后续任务 fixture 复用）
// ---------------------------------------------------------------------------

const VECTOR_VERSION_DIGEST = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";

export function exampleNormalizedWasmManifestV1(): NormalizedWasmManifestV1 {
	// spec 已发布的 405 字节 digest 向量 manifest（name 必须等于 applicationId "vector"）。
	return {
		schemaVersion: 1,
		name: "vector",
		runtime: {
			kind: "wasm",
			entryLayerDigest: "sha256:" + "1".repeat(64),
			world: WASM_WORLD_LITERAL,
			hostABI: WASM_HOST_ABI_LITERAL,
			declaredHostImports: [],
		},
		resources: { cpuMillis: 1, memoryBytes: 2, pidLimit: 3, storageBytes: 4 },
		storage: { persistent: false, requestBytes: 0 },
		egress: { default: "deny", allow: [] },
	};
}

export function exampleRuntimeBindingIdentityV1(): RuntimeBindingIdentityV1 {
	return {
		kind: "wasm",
		catalogRevision: 9,
		catalogHash: "ab".repeat(32),
		entryKey: "iweb-wasmd",
		imageDigest: "sha256:" + "cd".repeat(32),
		hostABI: WASM_HOST_ABI_LITERAL,
		world: WASM_WORLD_LITERAL,
	};
}

export function exampleWasmExecutionIdentityV1(): WasmExecutionIdentityV1 {
	return { sandboxId: "sbx-vector", versionId: VECTOR_VERSION_DIGEST + "-1", preparationGeneration: 1, executionGeneration: 1 };
}

export function exampleExecutionCommandV1(): ExecutionCommandV1 {
	return {
		schemaVersion: 1,
		commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abcd",
		expectedKernelControlRevision: 12,
		expectedJournalRevision: 4,
		operation: "prepare",
		identity: exampleWasmExecutionIdentityV1(),
		packageDigest: "0".repeat(64),
		runtimeBinding: exampleRuntimeBindingIdentityV1(),
		capabilityRecordRevision: 5,
		capabilityRecordHash: "2".repeat(64),
		secretRevision: 3,
		secretSnapshotRef: "5".repeat(64),
		secretValuesDigest: "6".repeat(64),
		configRevision: 2,
		configSnapshotRef: "7".repeat(64),
		configValuesDigest: "8".repeat(64),
	};
}

export function exampleExecutionAcknowledgementV1(command: ExecutionCommandV1): ExecutionAcknowledgementV1 {
	return {
		schemaVersion: 1,
		commandId: command.commandId,
		operation: command.operation,
		identity: command.identity,
		packageDigest: command.packageDigest,
		runtimeBinding: command.runtimeBinding,
		capabilityRecordRevision: command.capabilityRecordRevision,
		capabilityRecordHash: command.capabilityRecordHash,
		secretRevision: command.secretRevision,
		secretSnapshotRef: command.secretSnapshotRef,
		secretValuesDigest: command.secretValuesDigest,
		configRevision: command.configRevision,
		configSnapshotRef: command.configSnapshotRef,
		configValuesDigest: command.configValuesDigest,
		drainReceiptDigest: null,
		result: "applied",
		failureCode: null,
		journalRevision: 5,
	};
}

export function exampleWasmControlStateFileV2(): WasmControlStateFileV2 {
	const binding = exampleRuntimeBindingIdentityV1();
	const identity = exampleWasmExecutionIdentityV1();
	const command = exampleExecutionCommandV1();
	const admissionProofRef = "admission-proof/vector/" + identity.versionId;
	const row: WasmVersionRegistryRowV1 = {
		versionId: identity.versionId,
		identity: { applicationId: "vector", digest: VECTOR_VERSION_DIGEST, sequence: 1 },
		packageDigest: "0".repeat(64),
		normalizedPolicy: exampleNormalizedWasmManifestV1(),
		lifecycle: "active",
		runtimeBinding: binding,
		admissionProofRef,
		admissionProofDigest: "4".repeat(64),
		readinessLeaseDigest: "3".repeat(64),
	};
	const application: WasmApplicationControlRecordV1 = {
		runtimeKind: "wasm",
		applicationId: "vector",
		versions: [row],
		active: {
			kind: "active",
			runtimeKind: "wasm",
			applicationId: "vector",
			versionId: row.versionId,
			identity: row.identity,
			runtimeBinding: row.runtimeBinding,
			admissionProofRef: row.admissionProofRef,
			admissionProofDigest: row.admissionProofDigest,
			routeGeneration: 4,
		},
		routeGeneration: 4,
		secretRevision: 3,
		configRevision: 2,
	};
	return {
		schemaVersion: 2,
		runtimeKind: "wasm",
		controlRevision: 12,
		applications: { vector: application },
		commandOutbox: [
			{
				commandId: command.commandId,
				command,
				createdAt: "2026-08-26T00:00:00Z",
				deliveryState: "sent",
				attempts: 1,
				lastAttemptAt: "2026-08-26T00:00:01Z",
			},
		],
		migration: { source: "celld-control-state-v1", status: "not-started", sourceDigest: null, completedAt: null },
	};
}

export function exampleKindClaimBootstrapV1(): KindClaimBootstrapV1 {
	const buildClaim = (applicationId: string): RuntimeKindClaimV1 => {
		const claim: RuntimeKindClaimV1 = { applicationId, runtimeKind: "celld", bindingRevision: 1, bindingDigest: "0".repeat(64) };
		return { ...claim, bindingDigest: computeRuntimeKindClaimBindingDigest(claim) };
	};
	const record = {
		schemaVersion: 1 as const,
		bootstrapRevision: 1,
		sourceKind: "celld" as const,
		controlStateRawDigest: "9".repeat(64),
		sourceRevision: 0,
		sortedClaims: [buildClaim("admin"), buildClaim("notes")],
	};
	return { ...record, completionReceiptDigest: computeKindClaimBootstrapDigest(record) };
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. capabilityRecordRevision 在 command/ack 处取下界 1（spec 未在该处标注，但
//    NodeCapabilityRecordV1/AdmissionProofV1/readiness 的 revision 均 >= 1；引用不存在的
//    revision 0 属 fail-closed 拒绝）。
// 2. UUIDv7 强制 version nibble 7 与 RFC 9562 variant 位 [89ab]；lower-case 由文法固定。
// 3. RFC3339-UTC 以正则 + Date.parse 校验，闰秒（:60）因无法被证明而拒绝。
// 4. ack 的 drain+applied 必须携带非空 drainReceiptDigest（由"每个 drain 命令要么产出
//    成功 receipt、要么 rejected ack"推出）；非 drain 或 rejected 携带 digest 一律拒绝。
// 5. active 指针的 routeGeneration 必须等于所在应用记录当前 routeGeneration；active 指针的
//    identity/binding/proof 字段必须与 versionId 命中的行 JCS 字节一致。
// 6. lifecycle 为 ready/active 的版本行必须携带非空 readinessLeaseDigest。
// 7. outbox commandId 唯一；bootstrap claim 的 bindingRevision 恒为 1（首次写入）；
//    claim 的 bindingDigest 与外层 completionReceiptDigest 均按 spec 公式复算（外层 digest
//    已承诺全部字段，内层复算是更严格的 fail-closed）。
// 8. migration.status 为 complete 时必须有 completedAt，not-started 时必须为 null。
// 9. prepare 代次迁移统一为 (P+1, E+1)（首次准备 (0,0)->(1,1) 与 spec scenario 一致）；
//    execution 分配要求 P >= 1；两代次只增不减，上限处 WASM_GENERATION_EXHAUSTED。
// 10. CommandReceivedV1.commandDigest 复算校验（journal 自洽性）；replay 的 byte-identical
//     判定由宿主以 computeExecutionCommandDigestV1/JCS 字节实现，不在 schema 层做状态比对。
// 11. SECRET_REVISION_EXHAUSTED、WASM_EXECUTION_FENCE_STALE、WASM_SECRET_REVISION_INVALID、
//     WASM_GENERATION_TRANSITION 由 helper 层补齐，spec 未命名；不覆盖 spec 已命名码。
