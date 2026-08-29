// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：备份/恢复的 owner 面——
//   plan_backup_quiesce / validate_restore_set 的契约纯函数已在 Rust 侧（kernel-rs/iweb-kernel/src/
//   wasm_host_services.rs，任务 4.5）；TS 侧按仓库 catalog-store 先例装「owner 调度面」：
//   类型化纯函数 + 有类型 façade，不挂任何未授权路由。
// 终审缺口修正（2026-08-28）：façade 之上的 WasmHostBackupService 接最小生产链——
//   quiesce 计划 → 经 wasm-control ExecutionRpcHandler 投递真实 drain 命令 → 从 wasmd
//   per-app 数据目录捕获 kv/sql/quota 三成员 → 备份集契约复验（digest/身份）→ 报告/持久化；
//   restore 从留存目录逐成员 digest 复验后落地目标目录。未接通部分（ledger facts wire、
//   生产数据目录挂载、备份留存配置）显式 unavailable，绝不伪造。
// 正交意图：
//   1. BackupQuiesceStateV2 / BackupStepV2：quiesce 前置检查 + 固定顺序计划的 TS 镜像
//      （wire 字段、kebab-case 字面量与错误码逐字对齐 Rust 权威；活动写入/未恢复/未冻结一律拒绝）；
//   2. BackupSetDescriptorV2 / BackupFileEntryV2：备份集完整性与身份校验的 TS 镜像
//      （恰好 kv/sql/quota 三成员、无 symlink、0600、64-hex、身份与 policy digest 匹配、quiesced）；
//   3. WasmHostBackupOwnerFace：owner 调度 façade（plan/validate 两入口 + 期望身份绑定）；
//      恢复侧任何失败都不静默创建空替身（service 层的落地只发生在全量 digest 复验之后）。
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
import { jcsCanonicalBytes, sha256Hex, WASM_SHA256_HEX_PATTERN, WASM_U53_MAX } from "../packages/contracts/wasm-package.ts";
import { randomFillSync } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
	EXECUTION_RPC_PROTOCOL_LITERAL,
	WASM_UUIDV7_PATTERN,
	type ExecutionCommand,
	type ExecutionRpcRequestEnvelopeV1,
	type WasmExecutionIdentityV1,
} from "../packages/contracts/wasm-execution.ts";
import type { ExecutionRpcHandler } from "./wasm-control.ts";

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

// ---------------------------------------------------------------------------
// 终审缺口修正（2026-08-28）：备份 façade 接真实链——quiesce → capture → restore 的
// 最小生产路径。纯类型化 façade 之上的 owner 调度服务：
//   1. quiesce：planWasmHostBackupQuiesceV2 前置检查（outstanding/healthy/frozen 全过才继续）；
//   2. drain execution：经 supervisor/wasm-control.ts 的 ExecutionRpcHandler 投递 owner 已授权
//      的 drain 命令（journal CAS + 幂等执行 + typed ack——supervisor 绝不自铸命令）；非 applied
//      即整体 fail-closed，零捕获、零落盘；
//   3. capture：从 wasmd per-app 数据目录（宿主侧 <dataDirectoryRoot>/<applicationId>/）读
//      kv/sql/quota 三个 sqlite 成员，lstat 复核非 symlink、mode 0600、非零长度、bytes 与
//      stat 长度一致，逐成员计算 sha256；
//   4. 校验 digest：组装 BackupSetDescriptorV2 并过 validateWasmHostBackupSetV2（结构 + 身份
//      + policy digest 绑定）；
//   5. 报告/持久化：配置 backupDirectory 时把三成员字节（0600）与描述符（JCS 字节）落盘，
//      未配置时只返回报告（persistedPath:null，显式不伪造持久化声明）。
// 未接通部分（显式 unavailable，不伪造）：
//   - ledger facts：quiesce state 与 usageRevision 由调用方注入（wasmd QuotaLedger 的
//     owner-drain wire 未落地；supervisor 直读 quota.sqlite3 会构成第二权威，刻意不做）；
//   - 生产数据目录根：wasm spawn 侧的数据目录挂载接线未落地，dataDirectoryRoot 未配置时
//     capture 显式 WASM_HOST_BACKUP_DATA_DIRECTORY_UNAVAILABLE；
//   - restore 落地：备份字节留存（backupDirectory）或目标根缺失时显式 unavailable；
//     任何校验失败都零落地，绝不静默创建空替身。
// ---------------------------------------------------------------------------

/** 显式 unavailable 码（本层新增；未接通链路的诚实形态，绝不用空数据顶替）。 */
export const WASM_HOST_BACKUP_DRAIN_FAILED = "WASM_HOST_BACKUP_DRAIN_FAILED";
export const WASM_HOST_BACKUP_DATA_DIRECTORY_UNAVAILABLE = "WASM_HOST_BACKUP_DATA_DIRECTORY_UNAVAILABLE";
export const WASM_HOST_BACKUP_RESTORE_UNAVAILABLE = "WASM_HOST_BACKUP_RESTORE_UNAVAILABLE";
export const WASM_HOST_BACKUP_RESTORE_TARGET_UNAVAILABLE = "WASM_HOST_BACKUP_RESTORE_TARGET_UNAVAILABLE";
export const WASM_HOST_BACKUP_MEMBER_INVALID = "WASM_HOST_BACKUP_MEMBER_INVALID";
export const WASM_HOST_BACKUP_IO_FAILED = "WASM_HOST_BACKUP_IO_FAILED";

/** 备份 IO 端口（lstat 语义；生产为 node:fs，测试注入内存实现）。 */
export interface WasmHostBackupFileIO {
	readFileBytes(path: string): Buffer | null;
	statEntry(path: string): { readonly mode: number; readonly symlink: boolean; readonly byteLen: number } | null;
	writeFileBytes(path: string, bytes: Buffer, mode: number): void;
	ensureDirectory(path: string): void;
}

export const systemWasmHostBackupFileIO: WasmHostBackupFileIO = {
	readFileBytes: (path) => {
		try {
			return readFileSync(path);
		} catch {
			return null;
		}
	},
	statEntry: (path) => {
		try {
			const stats = lstatSync(path);
			return { mode: stats.mode, symlink: stats.isSymbolicLink(), byteLen: stats.size };
		} catch {
			return null;
		}
	},
	writeFileBytes: (path, bytes, mode) => {
		const temporary = path + ".tmp-" + process.pid + "-" + Math.random().toString(36).slice(2);
		writeFileSync(temporary, bytes, { mode });
		renameSync(temporary, path);
	},
	ensureDirectory: (path) => {
		mkdirSync(path, { recursive: true });
	},
};

/** 备份集目录内的固定文件名（描述符唯一入口；成员名与 Rust BackupFileKind::as_str 对位）。 */
export const WASM_BACKUP_DESCRIPTOR_FILENAME = "backup-set-v2.json";

function randomUuidV7(nowMillis = Date.now()): string {
	const timestamp = BigInt(nowMillis) & 0xffffffffffffn;
	const bytes = new Uint8Array(16);
	for (let index = 5; index >= 0; index -= 1) {
		bytes[index] = Number((timestamp >> BigInt((5 - index) * 8)) & 0xffn);
	}
	randomFillSync(bytes.subarray(6));
	bytes[6] = (bytes[6] & 0x0f) | 0x70;
	bytes[8] = (bytes[8] & 0x3f) | 0x80;
	const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
	const candidate = hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
	if (!WASM_UUIDV7_PATTERN.test(candidate)) throw new Error("unreachable: generated requestId must be UUIDv7");
	return candidate;
}

export interface WasmHostBackupServiceOptions {
	readonly applicationId: string;
	readonly hostServicePolicyDigest: string;
	/**
	 * wasmd per-app 数据目录的宿主侧根（成员路径 = <root>/<applicationId>/<name>）。
	 * 未配置（spawn 侧数据目录挂载接线未落地）→ capture 显式 unavailable。
	 */
	readonly dataDirectoryRoot?: string;
	/**
	 * 备份集留存目录（<dir>/<applicationId>/{kv,sql,quota}.sqlite3 + backup-set-v2.json）。
	 * 未配置 → capture 只报告不持久化，restore 显式 unavailable。
	 */
	readonly backupDirectory?: string;
	/** wasm-control 的 execution-rpc handler：drain execution 的唯一真实通道。 */
	readonly executionRpc: ExecutionRpcHandler;
	readonly io?: WasmHostBackupFileIO;
}

export interface WasmHostBackupCaptureInput {
	/** owner 已授权的 drain 命令（expectedJournalRevision 必须对准 journal head）。 */
	readonly drainCommand: ExecutionCommand;
	/**
	 * wasmd QuotaLedger 的 quiesce 投影（wire 形状 BackupQuiesceStateV2）。来源是
	 * wasmd owner-diagnostic wire（未落地前由宿主/测试注入）；无法提供即不捕获。
	 */
	readonly quiesceState: unknown;
	/** ledger usage revision（同上来源；描述符必填，不可从 supervisor 侧证明）。 */
	readonly usageRevision: number;
}

export type WasmHostBackupCaptureResult =
	| {
			readonly ok: true;
			readonly descriptor: WasmBackupSetDescriptorV2;
			/** 配置了 backupDirectory 时的描述符落盘路径；未配置为 null（显式不伪造持久化）。 */
			readonly persistedPath: string | null;
			readonly drainedCommandId: string;
	  }
	| { readonly ok: false; readonly code: string; readonly message: string };

export type WasmHostBackupRestoreResult =
	| {
			readonly ok: true;
			readonly descriptor: WasmBackupSetDescriptorV2;
			readonly restoredFiles: readonly string[];
	  }
	| { readonly ok: false; readonly code: string; readonly message: string };

/**
 * 备份/恢复的最小生产路径（owner 调度服务）。身份（applicationId + policy digest）在构造期
 * 绑定；capture 消费注入的 ExecutionRpcHandler 做真实 drain，再从数据目录捕获三成员并按
 * 备份集契约复验；restore 从留存目录读字节、逐成员 digest 复验后才落地目标目录。
 */
export class WasmHostBackupService extends WasmHostBackupOwnerFace {
	private readonly dataDirectoryRoot: string | undefined;
	private readonly backupDirectory: string | undefined;
	private readonly executionRpc: ExecutionRpcHandler;
	private readonly io: WasmHostBackupFileIO;

	constructor(options: WasmHostBackupServiceOptions) {
		// 身份绑定复用 façade 的构造期校验（非法即抛，fail-closed）。
		super({
			applicationId: options.applicationId,
			hostServicePolicyDigest: options.hostServicePolicyDigest,
		});
		this.dataDirectoryRoot = options.dataDirectoryRoot;
		this.backupDirectory = options.backupDirectory;
		this.executionRpc = options.executionRpc;
		this.io = options.io ?? systemWasmHostBackupFileIO;
	}

	private memberHostPath(root: string, kind: WasmBackupFileKindV2): string {
		return join(root, this.applicationId, WASM_BACKUP_FILE_NAMES_V2[kind]);
	}

	/** 步骤 2：经 wasm-control 投递 drain 命令；非 applied 的 ack 即 fail-closed。 */
	private async drainExecution(command: ExecutionCommand): Promise<{ readonly ok: true; readonly commandId: string } | { readonly ok: false; readonly code: string; readonly message: string }> {
		const envelope: ExecutionRpcRequestEnvelopeV1 = {
			protocol: EXECUTION_RPC_PROTOCOL_LITERAL,
			requestId: randomUuidV7(),
			body: { kind: "command", command },
		};
		const result = await this.executionRpc.handle(envelope);
		if (!result.ok) {
			return {
				ok: false,
				code: WASM_HOST_BACKUP_DRAIN_FAILED,
				message: "the drain command was not delivered: " + result.code + " (" + result.message + ")",
			};
		}
		if (result.body.kind !== "acknowledgement") {
			return {
				ok: false,
				code: WASM_HOST_BACKUP_DRAIN_FAILED,
				message: "the drain delivery returned " + result.body.kind + " instead of an acknowledgement",
			};
		}
		const acknowledgement = result.body.acknowledgement;
		if (acknowledgement.result !== "applied" || acknowledgement.commandId !== command.commandId) {
			return {
				ok: false,
				code: WASM_HOST_BACKUP_DRAIN_FAILED,
				message: "the drain command was not applied (result=" + acknowledgement.result + ", failureCode=" + String(acknowledgement.failureCode) + ")",
			};
		}
		return { ok: true, commandId: command.commandId };
	}

	/** 步骤 3：捕获一个成员（lstat 复核 + bytes/digest；任何失败零副作用）。 */
	private captureMember(kind: WasmBackupFileKindV2): { readonly ok: true; readonly entry: WasmBackupFileEntryV2; readonly bytes: Buffer } | { readonly ok: false; readonly code: string; readonly message: string } {
		const path = this.memberHostPath(this.dataDirectoryRoot as string, kind);
		const stats = this.io.statEntry(path);
		if (stats === null) {
			return { ok: false, code: WASM_HOST_BACKUP_MEMBER_INVALID, message: "backup member is missing: " + kind };
		}
		if (stats.symlink) {
			return { ok: false, code: WASM_HOST_BACKUP_MEMBER_INVALID, message: "backup member is a symlink: " + kind };
		}
		if ((stats.mode & 0o7777) !== WASM_BACKUP_FILE_MODE) {
			return { ok: false, code: WASM_HOST_BACKUP_MEMBER_INVALID, message: "backup member must carry mode 0600: " + kind };
		}
		const bytes = this.io.readFileBytes(path);
		if (bytes === null || bytes.byteLength === 0) {
			return { ok: false, code: WASM_HOST_BACKUP_MEMBER_INVALID, message: "backup member is unreadable or zero-length: " + kind };
		}
		if (bytes.byteLength !== stats.byteLen) {
			// 读期间文件被写（drain 未真正静止）：fail-closed，绝不做时点混批。
			return { ok: false, code: WASM_HOST_BACKUP_MEMBER_INVALID, message: "backup member changed size during capture: " + kind };
		}
		return {
			ok: true,
			entry: { kind, byteLen: bytes.byteLength, sha256: sha256Hex(bytes), mode: stats.mode & 0o7777, symlink: false },
			bytes,
		};
	}

	/** quiesce → drain execution → capture → 校验 digest → 报告/持久化 的最小生产路径。 */
	async capture(input: WasmHostBackupCaptureInput): Promise<WasmHostBackupCaptureResult> {
		// 步骤 1：quiesce 前置检查（wire 校验 + 计划；Rust plan_backup_quiesce 同语义）。
		const state = validateWasmBackupQuiesceStateV2(input.quiesceState);
		if (!state.ok) {
			const first = state.errors[0];
			return { ok: false, code: first ? first.code : WASM_HOST_SERVICE_BACKUP_INVALID, message: "the quiesce state failed validation: " + (first ? first.message : "unknown issue") };
		}
		const plan = planWasmHostBackupQuiesceV2(state.value);
		if (!plan.ok) {
			const first = plan.errors[0];
			return { ok: false, code: first ? first.code : WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED, message: first ? first.message : "quiesce preconditions failed" };
		}
		if (typeof input.usageRevision !== "number" || !Number.isSafeInteger(input.usageRevision) || input.usageRevision < 0 || input.usageRevision > WASM_U53_MAX) {
			return { ok: false, code: WASM_HOST_SERVICE_LEDGER_INVALID, message: "usageRevision must be a u53 integer sourced from the ledger facts projection" };
		}
		// 步骤 2：drain execution（真实通道：journal CAS + 幂等执行 + typed ack）。
		const drained = await this.drainExecution(input.drainCommand);
		if (!drained.ok) return drained;
		// 步骤 3：三成员捕获（未接线的数据目录显式 unavailable，不伪造空集）。
		if (this.dataDirectoryRoot === undefined) {
			return {
				ok: false,
				code: WASM_HOST_BACKUP_DATA_DIRECTORY_UNAVAILABLE,
				message: "the wasmd per-application data directory root is not wired in this deployment; capture is unavailable rather than fabricated",
			};
		}
		const captured: WasmBackupFileEntryV2[] = [];
		const memberBytes = new Map<WasmBackupFileKindV2, Buffer>();
		for (const kind of WASM_BACKUP_FILE_KINDS_V2) {
			const member = this.captureMember(kind);
			if (!member.ok) return member;
			captured.push(member.entry);
			memberBytes.set(kind, member.bytes);
		}
		// 步骤 4：校验 digest（结构 + 身份 + policy digest 绑定；quiesced 由上面的前置链证明）。
		const descriptor: WasmBackupSetDescriptorV2 = {
			schemaVersion: 2,
			applicationId: this.applicationId,
			hostServicePolicyDigest: this.hostServicePolicyDigest,
			ledgerRevision: state.value.ledgerRevision,
			usageRevision: input.usageRevision,
			quiesced: true,
			files: captured,
		};
		const verified = this.validateBackup(descriptor);
		if (!verified.ok) {
			const first = verified.errors[0];
			return { ok: false, code: first ? first.code : WASM_HOST_SERVICE_BACKUP_INVALID, message: "the captured backup set failed validation: " + (first ? first.message : "unknown issue") };
		}
		// 步骤 5：报告/持久化（成员字节先落、描述符最后落——描述符存在即集合完整）。
		if (this.backupDirectory === undefined) {
			return { ok: true, descriptor: verified.value, persistedPath: null, drainedCommandId: drained.commandId };
		}
		const setDirectory = join(this.backupDirectory, this.applicationId);
		try {
			this.io.ensureDirectory(setDirectory);
			for (const kind of WASM_BACKUP_FILE_KINDS_V2) {
				this.io.writeFileBytes(join(setDirectory, WASM_BACKUP_FILE_NAMES_V2[kind]), memberBytes.get(kind) as Buffer, WASM_BACKUP_FILE_MODE);
			}
			const descriptorPath = join(setDirectory, WASM_BACKUP_DESCRIPTOR_FILENAME);
			this.io.writeFileBytes(descriptorPath, Buffer.from(jcsCanonicalBytes(verified.value)), WASM_BACKUP_FILE_MODE);
			return { ok: true, descriptor: verified.value, persistedPath: descriptorPath, drainedCommandId: drained.commandId };
		} catch {
			return { ok: false, code: WASM_HOST_BACKUP_IO_FAILED, message: "persisting the backup set failed; the in-memory report stands but nothing is claimed durable" };
		}
	}

	/**
	 * 恢复：恢复集校验（身份绑定 + 完整性）→ 从留存目录读成员字节并逐成员 digest 复验 →
	 * （全部通过后）落地目标目录（0600）。任何失败零落地；留存或目标缺失显式 unavailable。
	 */
	restore(descriptor: unknown, options: { readonly targetDataDirectoryRoot?: string } = {}): WasmHostBackupRestoreResult {
		const validated = this.validateRestore(descriptor);
		if (!validated.ok) {
			const first = validated.errors[0];
			return { ok: false, code: first ? first.code : WASM_HOST_SERVICE_BACKUP_INVALID, message: "the restore set failed validation: " + (first ? first.message : "unknown issue") };
		}
		if (this.backupDirectory === undefined) {
			return {
				ok: false,
				code: WASM_HOST_BACKUP_RESTORE_UNAVAILABLE,
				message: "no backup set directory is configured; retained member bytes are unavailable and nothing may be synthesized",
			};
		}
		const targetRoot = options.targetDataDirectoryRoot ?? this.dataDirectoryRoot;
		if (targetRoot === undefined) {
			return {
				ok: false,
				code: WASM_HOST_BACKUP_RESTORE_TARGET_UNAVAILABLE,
				message: "no target data directory is wired; restore is unavailable rather than landing anywhere",
			};
		}
		// 先全量复验（零落地窗口内不做任何写），再统一落地。
		const restores: { readonly path: string; readonly bytes: Buffer }[] = [];
		for (const entry of validated.value.files) {
			const retainedPath = join(this.backupDirectory, this.applicationId, WASM_BACKUP_FILE_NAMES_V2[entry.kind]);
			const bytes = this.io.readFileBytes(retainedPath);
			if (bytes === null) {
				return { ok: false, code: WASM_HOST_BACKUP_MEMBER_INVALID, message: "the retained backup member is missing: " + entry.kind };
			}
			if (bytes.byteLength !== entry.byteLen || sha256Hex(bytes) !== entry.sha256) {
				return { ok: false, code: WASM_HOST_BACKUP_MEMBER_INVALID, message: "the retained backup member does not match its digest: " + entry.kind };
			}
			restores.push({ path: this.memberHostPath(targetRoot, entry.kind), bytes });
		}
		try {
			this.io.ensureDirectory(join(targetRoot, this.applicationId));
			for (const restore of restores) {
				this.io.writeFileBytes(restore.path, restore.bytes, WASM_BACKUP_FILE_MODE);
			}
		} catch {
			return { ok: false, code: WASM_HOST_BACKUP_IO_FAILED, message: "landing the restore set failed partway; failures are reported, never silently replaced" };
		}
		return { ok: true, descriptor: validated.value, restoredFiles: restores.map((restore) => restore.path) };
	}
}

// ---------------------------------------------------------------------------
// 第四轮复审 P1（2026-08-28）：备份服务接线——executor 生命周期通知面 + 装配注册表。
//   1. WasmHostBackupQuiesceNotifier/Registry：V2（host-service）执行 start 成功即进入
//      「活动写入窗口」（kv/sql 后端可能在飞），drain/stop 静止后释放。方向性取舍
//      （fail-closed）：只把「确定静止」记成静止——stop/drain 副作用失败路径保持活动
//      标记（误报活动只是保守拒绝捕获；误报静止会造成时点混批的坏备份）。这是进程内
//      生命周期视图，不是 ledger 权威：capture 的真正前置检查仍是注入的 quiesceState
//      （wasmd QuotaLedger 的 owner-drain 投影，supervisor 绝不直读 quota.sqlite3 自造）。
//   2. WasmHostBackupServiceRegistry：装配期（wasm-serve.ts）持有的 owner 调度工厂——
//      per-app 身份只在 V2 执行命令到达时可知，因此装配期装「工厂 + 数据目录根」，
//      forApplication 按 (applicationId, policyDigest) 幂等实例化 WasmHostBackupService。
//   3. 数据目录根派生：宿主源 <stateDirectory>/wasm-data/，与 wasm-spawn.ts
//      wasmApplicationDataPath（容器内 /data/kernel/wasm-data/<applicationId> 的挂载源）
//      是同一条目录布局；跨文件一致性由测试锁定（join(root, app) === 挂载源路径），
//      不在此建立第二套目录语义。
// ---------------------------------------------------------------------------

/** executor → backup 的 quiesce 生命周期通知（结构端口；与 loggingIngressRegistry 同款纪律）。 */
export interface WasmHostBackupQuiesceNotifier {
	/**
	 * V2（host-service）执行 start 真实 spawn 成功：该 execution 进入活动写入窗口。
	 * 通知之后、settle 之前，该应用的数据面捕获必须拒绝（备份前置检查的 supervisor 半边）。
	 */
	onExecutionStarted(applicationId: string, hostServicePolicyDigest: string, identity: WasmExecutionIdentityV1): void;
	/**
	 * drain/stop 的进程终止已确认（容器移除或 stopExecution 返回）：该 execution 不再写入。
	 * per-app 是否整体静止由注册表聚合判定（同应用多 execution 全部 settle 才静止）。
	 */
	onExecutionSettled(applicationId: string, identity: WasmExecutionIdentityV1): void;
}

/** per-app 活动写入视图键（与 executor fence 的 tuple 判据同源：双代次 + 版本身份）。 */
function quiesceIdentityKey(identity: WasmExecutionIdentityV1): string {
	return identity.sandboxId + "\n" + identity.versionId + "\n" + identity.preparationGeneration + "\n" + identity.executionGeneration;
}

/**
 * 备份 quiesce 生命周期注册表：记录每个应用「已 start 且未静止」的 V2 execution 集合。
 * 误报方向固定为保守侧（宁可拒绝捕获，绝不时点混批）：只有确定静止的通知才释放标记；
 * 同一 execution 的重复 settle 幂等（journal resume/replay 会重放 stop 副作用）。
 */
export class WasmHostBackupQuiesceRegistry implements WasmHostBackupQuiesceNotifier {
	private readonly activeExecutions = new Map<string, Map<string, string>>();
	private readonly lastPolicyDigestByApplication = new Map<string, string>();

	onExecutionStarted(applicationId: string, hostServicePolicyDigest: string, identity: WasmExecutionIdentityV1): void {
		if (typeof applicationId !== "string" || typeof hostServicePolicyDigest !== "string") return;
		let byApplication = this.activeExecutions.get(applicationId);
		if (byApplication === undefined) {
			byApplication = new Map<string, string>();
			this.activeExecutions.set(applicationId, byApplication);
		}
		byApplication.set(quiesceIdentityKey(identity), hostServicePolicyDigest);
		this.lastPolicyDigestByApplication.set(applicationId, hostServicePolicyDigest);
	}

	onExecutionSettled(applicationId: string, identity: WasmExecutionIdentityV1): void {
		this.activeExecutions.get(applicationId)?.delete(quiesceIdentityKey(identity));
	}

	/** 该应用是否仍有已 start 未静止的 V2 execution（true = 数据面捕获必须拒绝）。 */
	hasActiveExecution(applicationId: string): boolean {
		const byApplication = this.activeExecutions.get(applicationId);
		return byApplication !== undefined && byApplication.size > 0;
	}

	/** 当前存在活动写入的应用清单（诊断/审计视图；顺序稳定）。 */
	activeApplications(): readonly string[] {
		return [...this.activeExecutions.entries()].filter(([, executions]) => executions.size > 0).map(([applicationId]) => applicationId).sort();
	}

	/** 该应用最近一次 start 携带的 policy pin（owner 捕获的期望身份提示；无活动历史为 null）。 */
	lastAdoptedPolicyDigest(applicationId: string): string | null {
		return this.lastPolicyDigestByApplication.get(applicationId) ?? null;
	}
}

/**
 * 宿主侧 per-app 数据目录根（<stateDirectory>/wasm-data）。与 wasm-spawn.ts 的
 * wasmApplicationDataPath 同一目录布局（容器内 /data/kernel/wasm-data 的挂载源）；
 * WasmHostBackupService 的成员路径 = join(root, applicationId, <成员名>) 与之精确对位。
 */
export function wasmHostBackupDataDirectoryRoot(stateDirectory: string): string {
	return stateDirectory + "/wasm-data";
}

export interface WasmHostBackupServiceRegistryOptions {
	/** wasm-control execution-rpc handler：所有 per-app 服务的 drain 唯一真实通道。 */
	readonly executionRpc: ExecutionRpcHandler;
	/** wasmd per-app 数据目录的宿主侧根（由 stateDirectory 派生；未接线目录一律 unavailable）。 */
	readonly dataDirectoryRoot: string;
	/** 备份集留存目录；未配置时 capture 只报告不持久化（service 既有语义）。 */
	readonly backupDirectory?: string;
	readonly io?: WasmHostBackupFileIO;
}

/**
 * 装配期备份服务注册表（owner 调度工厂）：per-app 身份在 V2 执行命令到达前不可知，
 * 因此装配只绑定通道与目录；forApplication 按 (applicationId, policyDigest) 幂等产出
 * WasmHostBackupService（同键复用同实例——owner 的并发调度看到同一服务状态）。
 */
export class WasmHostBackupServiceRegistry {
	private readonly options: WasmHostBackupServiceRegistryOptions;
	private readonly services = new Map<string, WasmHostBackupService>();

	constructor(options: WasmHostBackupServiceRegistryOptions) {
		this.options = options;
	}

	/** 幂等实例化：键 = applicationId + "\n" + policyDigest（重准入换 policy = 新键新实例，旧实例仍绑定旧身份）。 */
	forApplication(applicationId: string, hostServicePolicyDigest: string): WasmHostBackupService {
		const key = applicationId + "\n" + hostServicePolicyDigest;
		const existing = this.services.get(key);
		if (existing !== undefined) return existing;
		const service = new WasmHostBackupService({
			applicationId,
			hostServicePolicyDigest,
			dataDirectoryRoot: this.options.dataDirectoryRoot,
			...(this.options.backupDirectory !== undefined ? { backupDirectory: this.options.backupDirectory } : {}),
			executionRpc: this.options.executionRpc,
			...(this.options.io !== undefined ? { io: this.options.io } : {}),
		});
		this.services.set(key, service);
		return service;
	}

	/** 已实例化的应用身份数（诊断视图）。 */
	get size(): number {
		return this.services.size;
	}
}
