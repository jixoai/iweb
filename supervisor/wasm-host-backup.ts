// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：备份/恢复的 owner 面——
//   plan_backup_quiesce / validate_restore_set 的契约纯函数已在 Rust 侧（kernel-rs/iweb-kernel/src/
//   wasm_host_services.rs，任务 4.5）；TS 侧按仓库 catalog-store 先例装「owner 调度面」：
//   类型化纯函数 + 有类型 façade，不挂任何未授权路由。
// 正交意图：
//   1. BackupQuiesceStateV2 / BackupStepV2：quiesce 前置检查 + 固定顺序计划的 TS 镜像
//      （wire 字段、kebab-case 字面量与错误码逐字对齐 Rust 权威；活动写入/未恢复/未冻结一律拒绝）；
//   2. BackupSetDescriptorV2 / BackupFileEntryV2：备份集完整性与身份校验的 TS 镜像
//      （恰好 kv/sql/quota 三成员、无 symlink、0600、64-hex、身份与 policy digest 匹配、quiesced）；
//   3. WasmHostBackupOwnerFace：owner 调度 façade（plan/validate 两入口 + 期望身份绑定）；
//      恢复侧任何失败都不静默创建空替身（由调用方保证不落地——本层不接触文件系统）。
// 规范权威：openspec/changes/add-wasm-host-services/design.md「Decisions 3」（sqlite-full-fsync-v1 的
//   备份 quiesce 语义：先 drain 在飞 host-call、清空 outstanding reservations、冻结 ledger revision、
//   fsync 三个后端文件、最后捕获身份与文件集；拒绝缺失/损坏/symlink/跨应用集合）与
//   specs/wasm-application-runtime/spec.md「Resource, directory, durability and failure boundaries are explicit」。
// 对齐声明：本文件是 Rust 权威的 TS 消费面镜像（owner 调度用），不是第二权威——任何语义分歧以
//   Rust 实现与 design.md 为准；跨实现 golden 由 tests/wasm-host-backup.test.ts 与 Rust 单测共同锁定。
import {
	failure,
	isRecord,
	issue,
	ok,
	OPAQUE_ID_PATTERN,
	type ValidationIssue,
	type ValidationResult,
} from "../packages/contracts/validation.ts";
import { WASM_SHA256_HEX_PATTERN, WASM_U53_MAX } from "../packages/contracts/wasm-package.ts";

// ---------------------------------------------------------------------------
// 稳定错误码（与 Rust 权威逐字一致；作为 issue code 携带在 ValidationResult 中）
// ---------------------------------------------------------------------------

export const WASM_HOST_SERVICE_BACKUP_INVALID = "WASM_HOST_SERVICE_BACKUP_INVALID";
export const WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED =
	"WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED";
export const WASM_HOST_SERVICE_ID_INVALID = "WASM_HOST_SERVICE_ID_INVALID";
export const WASM_HOST_SERVICE_LEDGER_INVALID = "WASM_HOST_SERVICE_LEDGER_INVALID";

// ---------------------------------------------------------------------------
// BackupStepV2 / LedgerRecoveryStatus（kebab-case 字面量与 Rust serde 逐字一致）
// ---------------------------------------------------------------------------

export const WASM_BACKUP_STEPS_V2 = [
	"drain-host-calls",
	"settle-reservations",
	"freeze-ledger",
	"fsync-backends",
	"capture-identity-and-files",
] as const;
export type WasmBackupStepV2 = (typeof WASM_BACKUP_STEPS_V2)[number];

export const WASM_LEDGER_RECOVERY_STATUSES_V2 = [
	"healthy",
	"recovering",
	"quarantined",
	"owner-recovery-required",
] as const;
export type WasmLedgerRecoveryStatusV2 = (typeof WASM_LEDGER_RECOVERY_STATUSES_V2)[number];

export interface WasmBackupQuiesceStateV2 {
	readonly outstandingReservedBytes: number;
	readonly recoveryStatus: WasmLedgerRecoveryStatusV2;
	readonly ledgerRevision: number;
	/** 冻结的 ledger revision；备份捕获前必须等于当前 ledgerRevision（null = 未冻结，拒绝）。 */
	readonly frozenLedgerRevision: number | null;
}

const QUIESCE_STATE_CODE = WASM_HOST_SERVICE_BACKUP_INVALID;

function requireU53(
	value: unknown,
	field: string,
	errors: ValidationIssue[],
	path = "",
): number | null {
	if (
		typeof value !== "number" ||
		!Number.isSafeInteger(value) ||
		value < 0 ||
		value > WASM_U53_MAX
	) {
		errors.push(
			issue(
				WASM_HOST_SERVICE_LEDGER_INVALID,
				path + "/" + field,
				field + " must be a u53 safe integer",
			),
		);
		return null;
	}
	return value;
}

export function validateWasmBackupQuiesceStateV2(
	input: unknown,
): ValidationResult<WasmBackupQuiesceStateV2> {
	if (!isRecord(input))
		return failure([issue(QUIESCE_STATE_CODE, "", "backup quiesce state must be an object")]);
	const errors: ValidationIssue[] = [];
	for (const key of Object.keys(input)) {
		if (
			key !== "outstandingReservedBytes" &&
			key !== "recoveryStatus" &&
			key !== "ledgerRevision" &&
			key !== "frozenLedgerRevision"
		) {
			errors.push(issue(QUIESCE_STATE_CODE, "/" + key, "unknown field is not allowed"));
		}
	}
	for (const key of [
		"outstandingReservedBytes",
		"recoveryStatus",
		"ledgerRevision",
		"frozenLedgerRevision",
	] as const) {
		if (!Object.prototype.hasOwnProperty.call(input, key))
			errors.push(issue(QUIESCE_STATE_CODE, "/" + key, "required field is missing"));
	}
	const outstandingReservedBytes = requireU53(
		input.outstandingReservedBytes,
		"outstandingReservedBytes",
		errors,
	);
	const ledgerRevision = requireU53(input.ledgerRevision, "ledgerRevision", errors);
	const recoveryStatus =
		typeof input.recoveryStatus === "string" &&
		(WASM_LEDGER_RECOVERY_STATUSES_V2 as readonly string[]).includes(input.recoveryStatus)
			? (input.recoveryStatus as WasmLedgerRecoveryStatusV2)
			: null;
	if (recoveryStatus === null)
		errors.push(
			issue(
				QUIESCE_STATE_CODE,
				"/recoveryStatus",
				"recoveryStatus must be one of " + WASM_LEDGER_RECOVERY_STATUSES_V2.join("|"),
			),
		);
	let frozenLedgerRevision: number | null = null;
	if (input.frozenLedgerRevision !== null) {
		const frozen = requireU53(input.frozenLedgerRevision, "frozenLedgerRevision", errors);
		if (frozen !== null) frozenLedgerRevision = frozen;
	}
	if (
		errors.length ||
		outstandingReservedBytes === null ||
		ledgerRevision === null ||
		recoveryStatus === null
	)
		return failure(errors);
	return ok({ outstandingReservedBytes, recoveryStatus, ledgerRevision, frozenLedgerRevision });
}

/**
 * quiesce 前置检查 + 固定顺序（Rust plan_backup_quiesce 的 TS 镜像，语义逐字一致）：
 * outstanding reservations 未清零、恢复未到 healthy、或冻结 revision 与当前 ledger revision
 * 不一致时拒绝（fail-closed，绝不在活动写入时捕获）；全过则返回固定五步计划。
 */
export function planWasmHostBackupQuiesceV2(
	state: WasmBackupQuiesceStateV2,
): ValidationResult<readonly WasmBackupStepV2[]> {
	if (state.outstandingReservedBytes > 0) {
		return failure([
			issue(
				WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED,
				"/outstandingReservedBytes",
				"outstanding reservations must settle before backup capture",
			),
		]);
	}
	if (state.recoveryStatus !== "healthy") {
		return failure([
			issue(
				WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED,
				"/recoveryStatus",
				"ledger recovery must complete (healthy) before backup capture",
			),
		]);
	}
	if (state.frozenLedgerRevision !== state.ledgerRevision) {
		return failure([
			issue(
				WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED,
				"/frozenLedgerRevision",
				"the frozen ledger revision must equal the current ledger revision",
			),
		]);
	}
	return ok(WASM_BACKUP_STEPS_V2);
}

// ---------------------------------------------------------------------------
// BackupSetDescriptorV2 / BackupFileEntryV2（wire 字段与 Rust serde 逐字一致）
// ---------------------------------------------------------------------------

export const WASM_BACKUP_FILE_KINDS_V2 = ["kv", "sql", "quota"] as const;
export type WasmBackupFileKindV2 = (typeof WASM_BACKUP_FILE_KINDS_V2)[number];

/** 成员文件名（与 Rust BackupFileKind::as_str 一致；仅诊断/审计呈现，不是路径拼接输入）。 */
export const WASM_BACKUP_FILE_NAMES_V2: Readonly<Record<WasmBackupFileKindV2, string>> = {
	kv: "kv.sqlite3",
	sql: "sql.sqlite3",
	quota: "quota.sqlite3",
};

/** 备份成员权限闭集：sqlite/ledger 文件一律 0600（sqlite-full-fsync-v1 目录法）。 */
export const WASM_BACKUP_FILE_MODE = 0o600;

export interface WasmBackupFileEntryV2 {
	readonly kind: WasmBackupFileKindV2;
	readonly byteLen: number;
	readonly sha256: string;
	readonly mode: number;
	readonly symlink: boolean;
}

export interface WasmBackupSetDescriptorV2 {
	readonly schemaVersion: 2;
	readonly applicationId: string;
	readonly hostServicePolicyDigest: string;
	readonly ledgerRevision: number;
	readonly usageRevision: number;
	readonly quiesced: boolean;
	readonly files: readonly WasmBackupFileEntryV2[];
}

const DESCRIPTOR_KEYS = [
	"schemaVersion",
	"applicationId",
	"hostServicePolicyDigest",
	"ledgerRevision",
	"usageRevision",
	"quiesced",
	"files",
] as const;
const FILE_ENTRY_KEYS = ["kind", "byteLen", "sha256", "mode", "symlink"] as const;

function validateFileEntry(
	input: unknown,
	path: string,
	errors: ValidationIssue[],
): WasmBackupFileEntryV2 | null {
	if (!isRecord(input)) {
		errors.push(
			issue(WASM_HOST_SERVICE_BACKUP_INVALID, path, "backup file entry must be an object"),
		);
		return null;
	}
	for (const key of Object.keys(input)) {
		if (!(FILE_ENTRY_KEYS as readonly string[]).includes(key))
			errors.push(
				issue(WASM_HOST_SERVICE_BACKUP_INVALID, path + "/" + key, "unknown field is not allowed"),
			);
	}
	for (const key of FILE_ENTRY_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key))
			errors.push(
				issue(WASM_HOST_SERVICE_BACKUP_INVALID, path + "/" + key, "required field is missing"),
			);
	}
	const kind =
		typeof input.kind === "string" &&
		(WASM_BACKUP_FILE_KINDS_V2 as readonly string[]).includes(input.kind)
			? (input.kind as WasmBackupFileKindV2)
			: null;
	if (kind === null)
		errors.push(
			issue(
				WASM_HOST_SERVICE_BACKUP_INVALID,
				path + "/kind",
				"kind must be one of " + WASM_BACKUP_FILE_KINDS_V2.join("|"),
			),
		);
	const byteLen = requireU53(input.byteLen, "byteLen", errors, path);
	if (typeof input.sha256 !== "string" || !WASM_SHA256_HEX_PATTERN.test(input.sha256)) {
		errors.push(
			issue(
				WASM_HOST_SERVICE_LEDGER_INVALID,
				path + "/sha256",
				"sha256 must be 64 lower-case hex characters",
			),
		);
	}
	if (
		typeof input.mode !== "number" ||
		!Number.isSafeInteger(input.mode) ||
		input.mode < 0 ||
		input.mode > 0o777
	) {
		errors.push(
			issue(
				WASM_HOST_SERVICE_BACKUP_INVALID,
				path + "/mode",
				"mode must be a unix permission bits integer",
			),
		);
	}
	if (typeof input.symlink !== "boolean") {
		errors.push(
			issue(WASM_HOST_SERVICE_BACKUP_INVALID, path + "/symlink", "symlink must be a boolean"),
		);
	}
	if (errors.length || kind === null || byteLen === null) return null;
	return {
		kind,
		byteLen,
		sha256: input.sha256 as string,
		mode: input.mode as number,
		symlink: input.symlink as boolean,
	};
}

/** 结构校验（不含期望身份比对）：精确键集 + 恰好三成员 + 完整性位。 */
export function validateWasmBackupSetDescriptorV2(
	input: unknown,
): ValidationResult<WasmBackupSetDescriptorV2> {
	if (!isRecord(input))
		return failure([
			issue(WASM_HOST_SERVICE_BACKUP_INVALID, "", "backup set descriptor must be an object"),
		]);
	const errors: ValidationIssue[] = [];
	for (const key of Object.keys(input)) {
		if (!(DESCRIPTOR_KEYS as readonly string[]).includes(key))
			errors.push(
				issue(WASM_HOST_SERVICE_BACKUP_INVALID, "/" + key, "unknown field is not allowed"),
			);
	}
	for (const key of DESCRIPTOR_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key))
			errors.push(issue(WASM_HOST_SERVICE_BACKUP_INVALID, "/" + key, "required field is missing"));
	}
	if (input.schemaVersion !== 2)
		errors.push(
			issue(
				WASM_HOST_SERVICE_BACKUP_INVALID,
				"/schemaVersion",
				"backup descriptor schemaVersion must be the literal 2",
			),
		);
	if (typeof input.applicationId !== "string" || !OPAQUE_ID_PATTERN.test(input.applicationId)) {
		errors.push(
			issue(
				WASM_HOST_SERVICE_ID_INVALID,
				"/applicationId",
				"applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
			),
		);
	}
	if (
		typeof input.hostServicePolicyDigest !== "string" ||
		!WASM_SHA256_HEX_PATTERN.test(input.hostServicePolicyDigest)
	) {
		errors.push(
			issue(
				WASM_HOST_SERVICE_LEDGER_INVALID,
				"/hostServicePolicyDigest",
				"hostServicePolicyDigest must be 64 lower-case hex characters",
			),
		);
	}
	const ledgerRevision = requireU53(input.ledgerRevision, "ledgerRevision", errors);
	const usageRevision = requireU53(input.usageRevision, "usageRevision", errors);
	if (input.quiesced !== true)
		errors.push(
			issue(
				WASM_HOST_SERVICE_BACKUP_INVALID,
				"/quiesced",
				"backup set must be captured under quiesce",
			),
		);
	if (!Array.isArray(input.files)) {
		errors.push(issue(WASM_HOST_SERVICE_BACKUP_INVALID, "/files", "files must be an array"));
		return failure(errors);
	}
	const entries: WasmBackupFileEntryV2[] = [];
	const seenKinds = new Set<string>();
	for (let index = 0; index < input.files.length; index++) {
		const entry = validateFileEntry(input.files[index], "/files/" + index, errors);
		if (entry === null) continue;
		if (seenKinds.has(entry.kind))
			errors.push(
				issue(
					WASM_HOST_SERVICE_BACKUP_INVALID,
					"/files/" + index,
					"backup set has a duplicate member kind",
				),
			);
		seenKinds.add(entry.kind);
		if (entry.byteLen === 0)
			errors.push(
				issue(
					WASM_HOST_SERVICE_BACKUP_INVALID,
					"/files/" + index,
					"a zero-length member cannot be a valid sqlite/ledger image",
				),
			);
		if (entry.symlink)
			errors.push(
				issue(WASM_HOST_SERVICE_BACKUP_INVALID, "/files/" + index, "a symlinked member is refused"),
			);
		if ((entry.mode & 0o7777) !== WASM_BACKUP_FILE_MODE)
			errors.push(
				issue(
					WASM_HOST_SERVICE_BACKUP_INVALID,
					"/files/" + index,
					"backup members must carry mode 0600",
				),
			);
		entries.push(entry);
	}
	if (input.files.length !== 3)
		errors.push(
			issue(
				WASM_HOST_SERVICE_BACKUP_INVALID,
				"/files",
				"backup set must contain exactly kv, sql and quota members",
			),
		);
	for (const expected of WASM_BACKUP_FILE_KINDS_V2) {
		if (!seenKinds.has(expected))
			errors.push(
				issue(
					WASM_HOST_SERVICE_BACKUP_INVALID,
					"/files",
					"backup set is missing a member: " + expected,
				),
			);
	}
	if (errors.length || ledgerRevision === null || usageRevision === null) return failure(errors);
	return ok({
		schemaVersion: 2,
		applicationId: input.applicationId as string,
		hostServicePolicyDigest: input.hostServicePolicyDigest as string,
		ledgerRevision,
		usageRevision,
		quiesced: true,
		files: entries,
	});
}

/** 期望身份绑定（备份与恢复共用）：结构校验 + applicationId 与 policy digest 匹配。 */
function validateDescriptorAgainstIdentity(
	descriptor: WasmBackupSetDescriptorV2,
	expectedApplicationId: string,
	expectedPolicyDigest: string,
): ValidationResult<WasmBackupSetDescriptorV2> {
	const errors: ValidationIssue[] = [];
	if (descriptor.applicationId !== expectedApplicationId) {
		errors.push(
			issue(
				WASM_HOST_SERVICE_BACKUP_INVALID,
				"/applicationId",
				"backup set belongs to another application",
			),
		);
	}
	if (descriptor.hostServicePolicyDigest !== expectedPolicyDigest) {
		errors.push(
			issue(
				WASM_HOST_SERVICE_BACKUP_INVALID,
				"/hostServicePolicyDigest",
				"backup set policy digest does not match the application",
			),
		);
	}
	if (errors.length) return failure(errors);
	return ok(descriptor);
}

/**
 * 恢复侧校验（Rust validate_restore_set 的 TS 镜像）：与备份相同的完整性 + 身份校验。
 * 与备份侧的差别按 Rust 权威同样落在「零长度成员拒绝」（空文件不是合法 SQLite/ledger 镜像，
 * 裁决 6）——结构校验已拒绝 byteLen:0，此处不放松。任何失败都不得静默创建空替身
 * （由调用方保证不落地；本层是纯函数，不接触文件系统）。
 */
export function validateWasmHostRestoreSetV2(
	input: unknown,
	expectedApplicationId: string,
	expectedPolicyDigest: string,
): ValidationResult<WasmBackupSetDescriptorV2> {
	const descriptor = validateWasmBackupSetDescriptorV2(input);
	if (!descriptor.ok) return descriptor;
	return validateDescriptorAgainstIdentity(
		descriptor.value,
		expectedApplicationId,
		expectedPolicyDigest,
	);
}

/** 备份侧校验：结构 + 期望身份（owner 捕获前自检）。 */
export function validateWasmHostBackupSetV2(
	input: unknown,
	expectedApplicationId: string,
	expectedPolicyDigest: string,
): ValidationResult<WasmBackupSetDescriptorV2> {
	const descriptor = validateWasmBackupSetDescriptorV2(input);
	if (!descriptor.ok) return descriptor;
	return validateDescriptorAgainstIdentity(
		descriptor.value,
		expectedApplicationId,
		expectedPolicyDigest,
	);
}

// ---------------------------------------------------------------------------
// owner 调度 façade（catalog-store 先例：类型化 API，无未授权路由）
// ---------------------------------------------------------------------------

export interface WasmHostBackupOwnerFaceInput {
	/** 期望 applicationId（owner 调度的目标应用；跨应用集合拒绝）。 */
	readonly applicationId: string;
	/** 期望 HostServicePolicyV2 policyDigest（备份集身份绑定的另一半）。 */
	readonly hostServicePolicyDigest: string;
}

/**
 * 备份/恢复 owner 调度 façade：plan（quiesce 计划）与 validateRestore（恢复集校验）两个入口，
 * 期望身份在构造时绑定。不挂 HTTP/RPC 路由（授权通道在 Kernel；catalog-store 备注 #8 同款边界），
 * 不接触文件系统（捕获/落地属 Kernel 数据面批次）。
 */
export class WasmHostBackupOwnerFace {
	readonly applicationId: string;
	readonly hostServicePolicyDigest: string;

	constructor(input: WasmHostBackupOwnerFaceInput) {
		if (typeof input.applicationId !== "string" || !OPAQUE_ID_PATTERN.test(input.applicationId)) {
			throw new Error(
				WASM_HOST_SERVICE_ID_INVALID + ": applicationId must match the opaque id grammar",
			);
		}
		if (
			typeof input.hostServicePolicyDigest !== "string" ||
			!WASM_SHA256_HEX_PATTERN.test(input.hostServicePolicyDigest)
		) {
			throw new Error(
				WASM_HOST_SERVICE_LEDGER_INVALID +
					": hostServicePolicyDigest must be 64 lower-case hex characters",
			);
		}
		this.applicationId = input.applicationId;
		this.hostServicePolicyDigest = input.hostServicePolicyDigest;
	}

	/** quiesce 计划：状态不满足前置条件即 fail-closed（Rust plan_backup_quiesce 同款语义）。 */
	plan(state: WasmBackupQuiesceStateV2): ValidationResult<readonly WasmBackupStepV2[]> {
		return planWasmHostBackupQuiesceV2(state);
	}

	/** 恢复集校验：任何失败都不得静默创建空替身（调用方保证不落地）。 */
	validateRestore(descriptor: unknown): ValidationResult<WasmBackupSetDescriptorV2> {
		return validateWasmHostRestoreSetV2(
			descriptor,
			this.applicationId,
			this.hostServicePolicyDigest,
		);
	}

	/** 备份集自检：捕获后、入档前的完整性 + 身份校验。 */
	validateBackup(descriptor: unknown): ValidationResult<WasmBackupSetDescriptorV2> {
		return validateWasmHostBackupSetV2(
			descriptor,
			this.applicationId,
			this.hostServicePolicyDigest,
		);
	}
}
