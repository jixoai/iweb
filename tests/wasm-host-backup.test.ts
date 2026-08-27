// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：备份/恢复 owner 面的
//   接线证明——plan_backup_quiesce / validate_restore_set 的 Rust 契约（kernel-rs
//   wasm_host_services.rs）在 TS 侧以 catalog-store 先例装 owner 调度面（类型化纯函数 façade，
//   不挂未授权路由）。本电池同时充当跨实现的语义对照（kebab 字面量、错误码、判定顺序）。
// 正交意图：quiesce 计划正/负例（outstanding 未清零、未恢复 healthy、未冻结/冻结错位）；
//   备份集/恢复集完整性（恰好三成员、无 symlink、0600、零长度拒绝、quiesced、身份与 policy
//   digest 绑定）；owner façade 构造期身份校验。
import { describe, expect, test } from "bun:test";
import {
	planWasmHostBackupQuiesceV2,
	validateWasmBackupQuiesceStateV2,
	validateWasmHostRestoreSetV2,
	validateWasmHostBackupSetV2,
	WasmHostBackupOwnerFace,
	WASM_BACKUP_STEPS_V2,
	WASM_HOST_SERVICE_BACKUP_INVALID,
	WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED,
	type WasmBackupQuiesceStateV2,
	type WasmBackupSetDescriptorV2,
} from "../supervisor/wasm-host-backup.ts";

const APPLICATION = "notes-app";
const POLICY_DIGEST = "d".repeat(64);

function healthyQuiesceState(
	overrides: Partial<WasmBackupQuiesceStateV2> = {},
): WasmBackupQuiesceStateV2 {
	return {
		outstandingReservedBytes: 0,
		recoveryStatus: "healthy",
		ledgerRevision: 7,
		frozenLedgerRevision: 7,
		...overrides,
	};
}

function fileEntry(
	kind: "kv" | "sql" | "quota",
	overrides: Partial<{ byteLen: number; sha256: string; mode: number; symlink: boolean }> = {},
) {
	return { kind, byteLen: 4096, sha256: "e".repeat(64), mode: 0o600, symlink: false, ...overrides };
}

function descriptor(
	overrides: Partial<WasmBackupSetDescriptorV2> | Record<string, unknown> = {},
): unknown {
	return {
		schemaVersion: 2,
		applicationId: APPLICATION,
		hostServicePolicyDigest: POLICY_DIGEST,
		ledgerRevision: 7,
		usageRevision: 3,
		quiesced: true,
		files: [fileEntry("kv"), fileEntry("sql"), fileEntry("quota")],
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// quiesce 计划（Rust plan_backup_quiesce 的 TS 镜像语义）
// ---------------------------------------------------------------------------

describe("backup quiesce plan (mirror of plan_backup_quiesce)", () => {
	test("a settled, healthy, frozen ledger yields the fixed five-step plan in order", () => {
		const plan = planWasmHostBackupQuiesceV2(healthyQuiesceState());
		expect(plan.ok).toBe(true);
		if (plan.ok) expect(plan.value).toEqual(WASM_BACKUP_STEPS_V2);
		expect(WASM_BACKUP_STEPS_V2).toEqual([
			"drain-host-calls",
			"settle-reservations",
			"freeze-ledger",
			"fsync-backends",
			"capture-identity-and-files",
		]);
	});

	test("outstanding reservations, non-healthy recovery and unfrozen or misaligned revisions fail closed", () => {
		for (const state of [
			healthyQuiesceState({ outstandingReservedBytes: 1 }),
			healthyQuiesceState({ recoveryStatus: "recovering" }),
			healthyQuiesceState({ recoveryStatus: "quarantined" }),
			healthyQuiesceState({ recoveryStatus: "owner-recovery-required" }),
			healthyQuiesceState({ frozenLedgerRevision: null }),
			healthyQuiesceState({ frozenLedgerRevision: 6 }),
		]) {
			const plan = planWasmHostBackupQuiesceV2(state);
			expect(plan.ok).toBe(false);
			if (!plan.ok) expect(plan.errors[0]?.code).toBe(WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED);
		}
	});

	test("a malformed quiesce state is rejected before planning", () => {
		// 错误码镜像 Rust 助手：数值越界 → LEDGER_INVALID；grammar/未知字段 → BACKUP_INVALID。
		const expectations: readonly [unknown, string][] = [
			[null, WASM_HOST_SERVICE_BACKUP_INVALID],
			[
				{
					outstandingReservedBytes: 0,
					recoveryStatus: "healthy",
					ledgerRevision: 7,
					frozenLedgerRevision: 7,
					extra: true,
				},
				WASM_HOST_SERVICE_BACKUP_INVALID,
			],
			[
				{
					outstandingReservedBytes: -1,
					recoveryStatus: "healthy",
					ledgerRevision: 7,
					frozenLedgerRevision: 7,
				},
				"WASM_HOST_SERVICE_LEDGER_INVALID",
			],
			[
				{
					outstandingReservedBytes: 0,
					recoveryStatus: "unknown",
					ledgerRevision: 7,
					frozenLedgerRevision: 7,
				},
				WASM_HOST_SERVICE_BACKUP_INVALID,
			],
		];
		for (const [input, expectedCode] of expectations) {
			const parsed = validateWasmBackupQuiesceStateV2(input);
			expect(parsed.ok).toBe(false);
			if (!parsed.ok) expect(parsed.errors[0]?.code).toBe(expectedCode);
		}
	});
});

// ---------------------------------------------------------------------------
// 备份集 / 恢复集校验（完整性 + 身份绑定；零长度成员拒绝）
// ---------------------------------------------------------------------------

describe("backup set and restore set validation", () => {
	test("a complete quiesced three-member set with the expected identity validates", () => {
		const backup = validateWasmHostBackupSetV2(descriptor(), APPLICATION, POLICY_DIGEST);
		expect(backup.ok).toBe(true);
		const restore = validateWasmHostRestoreSetV2(descriptor(), APPLICATION, POLICY_DIGEST);
		expect(restore.ok).toBe(true);
		if (restore.ok) {
			expect(restore.value.files.map((file) => file.kind).sort()).toEqual(["kv", "quota", "sql"]);
			expect(restore.value.quiesced).toBe(true);
		}
	});

	test("a set belonging to another application or policy digest is refused", () => {
		const crossApp = validateWasmHostRestoreSetV2(descriptor(), "search-app", POLICY_DIGEST);
		expect(crossApp.ok).toBe(false);
		if (!crossApp.ok) expect(crossApp.errors[0]?.message).toContain("another application");
		const wrongDigest = validateWasmHostRestoreSetV2(descriptor(), APPLICATION, "f".repeat(64));
		expect(wrongDigest.ok).toBe(false);
		if (!wrongDigest.ok) expect(wrongDigest.errors[0]?.code).toBe(WASM_HOST_SERVICE_BACKUP_INVALID);
	});

	test("member-level integrity failures are refused", () => {
		// 错误码镜像 Rust 助手：数量/重复/symlink/mode/零长度 → BACKUP_INVALID；非 hex digest → LEDGER_INVALID。
		const expectations: readonly [readonly unknown[], string][] = [
			[[fileEntry("kv"), fileEntry("sql")], WASM_HOST_SERVICE_BACKUP_INVALID],
			[[fileEntry("kv"), fileEntry("kv"), fileEntry("quota")], WASM_HOST_SERVICE_BACKUP_INVALID],
			[
				[fileEntry("kv", { symlink: true }), fileEntry("sql"), fileEntry("quota")],
				WASM_HOST_SERVICE_BACKUP_INVALID,
			],
			[
				[fileEntry("kv", { mode: 0o644 }), fileEntry("sql"), fileEntry("quota")],
				WASM_HOST_SERVICE_BACKUP_INVALID,
			],
			[
				[fileEntry("kv", { byteLen: 0 }), fileEntry("sql"), fileEntry("quota")],
				WASM_HOST_SERVICE_BACKUP_INVALID,
			],
			[
				[fileEntry("kv", { sha256: "not-hex" }), fileEntry("sql"), fileEntry("quota")],
				"WASM_HOST_SERVICE_LEDGER_INVALID",
			],
		];
		for (const [files, expectedCode] of expectations) {
			const outcome = validateWasmHostRestoreSetV2(
				descriptor({ files }),
				APPLICATION,
				POLICY_DIGEST,
			);
			expect(outcome.ok).toBe(false);
			if (!outcome.ok)
				expect(outcome.errors.some((entry) => entry.code === expectedCode)).toBe(true);
		}
	});

	test("descriptor-level failures fail closed", () => {
		// 错误码镜像 Rust 助手：schema/quiesced/未知字段 → BACKUP_INVALID；ID/digest/数值 → ID_INVALID/LEDGER_INVALID。
		const expectations: readonly [Record<string, unknown>, string][] = [
			[{ schemaVersion: 3 }, WASM_HOST_SERVICE_BACKUP_INVALID],
			[{ quiesced: false }, WASM_HOST_SERVICE_BACKUP_INVALID],
			[{ applicationId: "BAD_ID" }, "WASM_HOST_SERVICE_ID_INVALID"],
			[{ ledgerRevision: -1 }, "WASM_HOST_SERVICE_LEDGER_INVALID"],
			[{ extra: true }, WASM_HOST_SERVICE_BACKUP_INVALID],
		];
		for (const [overrides, expectedCode] of expectations) {
			const outcome = validateWasmHostBackupSetV2(
				descriptor(overrides),
				APPLICATION,
				POLICY_DIGEST,
			);
			expect(outcome.ok).toBe(false);
			if (!outcome.ok)
				expect(outcome.errors.some((entry) => entry.code === expectedCode)).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// owner 调度 façade（类型化 API；无未授权路由——构造期身份绑定）
// ---------------------------------------------------------------------------

describe("backup owner scheduling face", () => {
	test("the face binds the expected identity at construction and reuses it for both directions", () => {
		const face = new WasmHostBackupOwnerFace({
			applicationId: APPLICATION,
			hostServicePolicyDigest: POLICY_DIGEST,
		});
		const plan = face.plan(healthyQuiesceState());
		expect(plan.ok).toBe(true);
		expect(face.validateBackup(descriptor()).ok).toBe(true);
		expect(face.validateRestore(descriptor()).ok).toBe(true);
		const crossApp = face.validateRestore(descriptor({ applicationId: "search-app" }));
		expect(crossApp.ok).toBe(false);
	});

	test("an invalid construction identity fails closed", () => {
		expect(
			() =>
				new WasmHostBackupOwnerFace({
					applicationId: "BAD",
					hostServicePolicyDigest: POLICY_DIGEST,
				}),
		).toThrow();
		expect(
			() =>
				new WasmHostBackupOwnerFace({
					applicationId: APPLICATION,
					hostServicePolicyDigest: "nothex",
				}),
		).toThrow();
	});
});
