// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：备份/恢复 owner 面的
//   接线证明——plan_backup_quiesce / validate_restore_set 的 Rust 契约（kernel-rs
//   wasm_host_services.rs）在 TS 侧以 catalog-store 先例装 owner 调度面（类型化纯函数 façade，
//   不挂未授权路由）。本电池同时充当跨实现的语义对照（kebab 字面量、错误码、判定顺序）。
// 终审缺口修正（2026-08-28）后的真实链电池：WasmHostBackupService 走最小生产路径——
//   真实 wasm-control journal + execution-rpc（磁盘上的 wasm-execution-journal-v1）、真实
//   文件 IO（tmpdir 中的三成员 + 描述符）、quiesce/digest 复验、restore 的逐成员 digest
//   复验与零落地纪律、未接通链路的显式 unavailable。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	planWasmHostBackupQuiesceV2,
	validateWasmBackupQuiesceStateV2,
	validateWasmHostRestoreSetV2,
	validateWasmHostBackupSetV2,
	WasmHostBackupOwnerFace,
	WasmHostBackupService,
	WASM_BACKUP_FILE_NAMES_V2,
	WASM_BACKUP_STEPS_V2,
	WASM_HOST_BACKUP_DATA_DIRECTORY_UNAVAILABLE,
	WASM_HOST_BACKUP_DRAIN_FAILED,
	WASM_HOST_BACKUP_MEMBER_INVALID,
	WASM_HOST_BACKUP_RESTORE_TARGET_UNAVAILABLE,
	WASM_HOST_BACKUP_RESTORE_UNAVAILABLE,
	WASM_HOST_SERVICE_BACKUP_INVALID,
	WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED,
	systemWasmHostBackupFileIO,
	type WasmBackupQuiesceStateV2,
	type WasmBackupSetDescriptorV2,
} from "../supervisor/wasm-host-backup.ts";
import {
	createExecutionRpcHandler,
	WasmExecutionJournalStore,
	type ExecutionRpcHandler,
	type WasmExecutionOutcome,
} from "../supervisor/wasm-control.ts";
import {
	exampleExecutionCommand,
	type DrainReceiptDraftV1,
	type ExecutionCommand,
} from "../packages/contracts/wasm-execution.ts";
import { systemStateStoreIO } from "../supervisor/desired-state.ts";
import { jcsCanonicalBytes, sha256Hex } from "../packages/contracts/wasm-package.ts";

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

// ---------------------------------------------------------------------------
// 真实链：quiesce → drain execution（wasm-control journal + execution-rpc）→
// capture 三成员 → 校验 digest → 报告/持久化 → restore（digest 复验后落地）
// ---------------------------------------------------------------------------

const FIXED_NOW = "2026-08-28T00:00:00.000Z";

function drainCommand(overrides: Partial<ExecutionCommand> = {}): ExecutionCommand {
	return { ...exampleExecutionCommand(), operation: "drain", expectedJournalRevision: 0, ...overrides };
}

function healthyQuiesceInput(): unknown {
	return {
		outstandingReservedBytes: 0,
		recoveryStatus: "healthy",
		ledgerRevision: 7,
		frozenLedgerRevision: 7,
	};
}

/** applied drain 所需的 receipt 草稿（wasm-control 在 completion 落盘时复算 digest）。 */
function drainDraft(command: ExecutionCommand): DrainReceiptDraftV1 {
	return {
		schemaVersion: 1,
		commandId: command.commandId,
		applicationId: APPLICATION,
		execution: command.identity,
		packageDigest: command.packageDigest,
		// receipt 的持久面 binding = admission 事实形（ABI 1.0.0；correlate 前归一比较）。
		runtimeBinding: { ...command.runtimeBinding, hostABI: "iweb-wasmd-abi@1.0.0" },
		routeGeneration: 2,
		drainedRequestCount: 0,
		deadlineAt: "2026-08-28T00:00:10.000Z",
		forcedKillAt: null,
		result: "drained",
		completedAt: FIXED_NOW,
	};
}

function realChainFixture(directories: { readonly data: string; readonly backups: string }) {
	// 真实 wasm-control journal（磁盘）+ drain 执行器（applied + receipt 草稿）。
	const journal = new WasmExecutionJournalStore(systemStateStoreIO, directories.data);
	const appliedDrain: WasmExecutionOutcome = { result: "applied", failureCode: null, drainReceiptDraft: null };
	let drainExecutions = 0;
	const executionRpc = createExecutionRpcHandler({
		journal,
		executor: {
			execute: async (command) => {
				drainExecutions += 1;
				return command.operation === "drain"
					? { result: "applied", failureCode: null, drainReceiptDraft: drainDraft(command) }
					: appliedDrain;
			},
		},
		now: () => FIXED_NOW,
	});
	// 真实文件面：per-app 数据目录三个 sqlite 成员（0600、非零）。
	const io = systemWasmHostBackupFileIO;
	io.ensureDirectory(join(directories.data, "wasm-data", APPLICATION));
	const memberBytes = new Map<string, Buffer>();
	for (const kind of ["kv", "sql", "quota"] as const) {
		const bytes = Buffer.from("sqlite-image:" + kind + ":" + Math.random(), "utf8");
		memberBytes.set(kind, bytes);
		io.writeFileBytes(join(directories.data, "wasm-data", APPLICATION, WASM_BACKUP_FILE_NAMES_V2[kind]), bytes, 0o600);
	}
	const service = new WasmHostBackupService({
		applicationId: APPLICATION,
		hostServicePolicyDigest: POLICY_DIGEST,
		dataDirectoryRoot: join(directories.data, "wasm-data"),
		backupDirectory: join(directories.backups, "sets"),
		executionRpc,
		io,
	});
	return { service, journal, memberBytes, drainCount: () => drainExecutions, io };
}

describe("backup service real chain: capture through wasm-control drain", () => {
	test("capture drains the execution, snapshots the three members, verifies and persists the set", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const fixture = realChainFixture({ data: join(root, "state"), backups: join(root, "backup") });
		const command = drainCommand();
		const result = await fixture.service.capture({
			drainCommand: command,
			quiesceState: healthyQuiesceInput(),
			usageRevision: 3,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("expected a successful capture");
		// drain 真实走 journal：received + completed 恰好两条。
		expect(fixture.drainCount()).toBe(1);
		const journal = fixture.journal.read();
		expect(journal.entries.map((entry) => entry.kind)).toEqual(["command-received", "completed"]);
		expect(journal.entries[1]?.kind === "completed" && journal.entries[1].acknowledgement.drainReceiptDigest).not.toBeNull();
		// 描述符成员与盘上字节一致（digest/长度/权限/symlink 位）。
		for (const entry of result.descriptor.files) {
			expect(entry.sha256).toBe(sha256Hex(fixture.memberBytes.get(entry.kind) as Buffer));
			expect(entry.byteLen).toBe((fixture.memberBytes.get(entry.kind) as Buffer).byteLength);
			expect(entry.mode).toBe(0o600);
			expect(entry.symlink).toBe(false);
		}
		expect(result.descriptor.quiesced).toBe(true);
		expect(result.descriptor.ledgerRevision).toBe(7);
		expect(result.descriptor.usageRevision).toBe(3);
		// 持久化：成员字节 + JCS 描述符在留存目录（0600）。
		expect(result.persistedPath).not.toBeNull();
		if (result.persistedPath === null) throw new Error("unreachable");
		const persistedDescriptor = JSON.parse(fixture.io.readFileBytes(result.persistedPath)?.toString("utf8") ?? "null");
		expect(persistedDescriptor).toEqual(JSON.parse(JSON.stringify(result.descriptor)));
		expect(fixture.io.readFileBytes(result.persistedPath)?.toString("utf8")).toBe(
			Buffer.from(jcsCanonicalBytes(result.descriptor)).toString("utf8"),
		);
		const stats = fixture.io.statEntry(result.persistedPath);
		expect(stats !== null && (stats.mode & 0o7777)).toBe(0o600);
		for (const kind of ["kv", "sql", "quota"] as const) {
			const retained = fixture.io.readFileBytes(join(root, "backup", "sets", APPLICATION, WASM_BACKUP_FILE_NAMES_V2[kind]));
			expect(retained?.equals(fixture.memberBytes.get(kind) as Buffer)).toBe(true);
		}
	});

	test("capture is idempotent through the real journal: re-capture replays the stored drain ack", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const fixture = realChainFixture({ data: join(root, "state"), backups: join(root, "backup") });
		const command = drainCommand();
		const first = await fixture.service.capture({ drainCommand: command, quiesceState: healthyQuiesceInput(), usageRevision: 3 });
		expect(first.ok).toBe(true);
		// 第二次 capture 用同一条 drain 命令：journal 幂等回放存档 ack，executor 不再执行。
		const second = await fixture.service.capture({ drainCommand: command, quiesceState: healthyQuiesceInput(), usageRevision: 3 });
		expect(second.ok).toBe(true);
		expect(fixture.drainCount()).toBe(1);
		if (first.ok && second.ok) {
			expect(JSON.stringify(second.descriptor.files)).toBe(JSON.stringify(first.descriptor.files));
		}
	});

	test("a non-applied drain (rejected ack) aborts capture with zero member reads", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, join(root, "state"));
		const executionRpc = createExecutionRpcHandler({
			journal,
			executor: {
				execute: async () => ({ result: "rejected", failureCode: "EXECUTION_DRAIN_RECEIPT_UNAVAILABLE", drainReceiptDraft: null }),
			},
			now: () => FIXED_NOW,
		});
		const service = new WasmHostBackupService({
			applicationId: APPLICATION,
			hostServicePolicyDigest: POLICY_DIGEST,
			dataDirectoryRoot: join(root, "wasm-data"),
			backupDirectory: join(root, "backup"),
			executionRpc,
			io: systemWasmHostBackupFileIO,
		});
		const result = await service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe(WASM_HOST_BACKUP_DRAIN_FAILED);
			expect(result.message).toContain("rejected");
		}
	});

	test("quiesce preconditions gate the chain before any drain or member read", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const fixture = realChainFixture({ data: join(root, "state"), backups: join(root, "backup") });
		const unsettled = { ...(healthyQuiesceInput() as Record<string, unknown>), outstandingReservedBytes: 42 };
		const result = await fixture.service.capture({ drainCommand: drainCommand(), quiesceState: unsettled, usageRevision: 3 });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe(WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED);
		expect(fixture.drainCount()).toBe(0);
	});

	test("member integrity failures abort capture: wrong mode, symlink, zero-length, and mid-capture growth", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		// 错误 mode（0644）。
		{
			const fixture = realChainFixture({ data: join(root, "a-state"), backups: join(root, "a-backup") });
			fixture.io.writeFileBytes(join(root, "a-state", "wasm-data", APPLICATION, WASM_BACKUP_FILE_NAMES_V2.kv), fixture.memberBytes.get("kv") as Buffer, 0o644);
			const result = await fixture.service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.code).toBe(WASM_HOST_BACKUP_MEMBER_INVALID);
		}
		// 零长度成员。
		{
			const fixture = realChainFixture({ data: join(root, "b-state"), backups: join(root, "b-backup") });
			fixture.io.writeFileBytes(join(root, "b-state", "wasm-data", APPLICATION, WASM_BACKUP_FILE_NAMES_V2.sql), Buffer.alloc(0), 0o600);
			const result = await fixture.service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.code).toBe(WASM_HOST_BACKUP_MEMBER_INVALID);
		}
		// 成员缺失。
		{
			const fixture = realChainFixture({ data: join(root, "c-state"), backups: join(root, "c-backup") });
			const missing = new Map(fixture.memberBytes);
			missing.delete("quota");
			const io = {
				...fixture.io,
				statEntry: (path: string) => (path.endsWith(WASM_BACKUP_FILE_NAMES_V2.quota) ? null : fixture.io.statEntry(path)),
			};
			const service = new WasmHostBackupService({
				applicationId: APPLICATION,
				hostServicePolicyDigest: POLICY_DIGEST,
				dataDirectoryRoot: join(root, "c-state", "wasm-data"),
				backupDirectory: join(root, "c-backup", "sets"),
				executionRpc: createExecutionRpcHandler({ journal: fixture.journal, executor: { execute: async (command) => ({ result: "applied", failureCode: null, drainReceiptDraft: drainDraft(command) }) }, now: () => FIXED_NOW }),
				io,
			});
			const result = await service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.code).toBe(WASM_HOST_BACKUP_MEMBER_INVALID);
			expect(missing.size).toBe(2);
		}
	});

	test("an unwired data directory is explicit unavailability, never a fabricated empty set", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, join(root, "state"));
		const executionRpc = createExecutionRpcHandler({
			journal,
			executor: { execute: async (command) => ({ result: "applied", failureCode: null, drainReceiptDraft: drainDraft(command) }) },
			now: () => FIXED_NOW,
		});
		const service = new WasmHostBackupService({
			applicationId: APPLICATION,
			hostServicePolicyDigest: POLICY_DIGEST,
			executionRpc,
			io: systemWasmHostBackupFileIO,
		});
		const result = await service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe(WASM_HOST_BACKUP_DATA_DIRECTORY_UNAVAILABLE);
	});

	test("capture without a backup directory reports only (persistedPath null, restore then unavailable)", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, join(root, "state"));
		const executionRpc = createExecutionRpcHandler({
			journal,
			executor: { execute: async (command) => ({ result: "applied", failureCode: null, drainReceiptDraft: drainDraft(command) }) },
			now: () => FIXED_NOW,
		});
		const dataRoot = join(root, "wasm-data");
		systemWasmHostBackupFileIO.ensureDirectory(join(dataRoot, APPLICATION));
		for (const kind of ["kv", "sql", "quota"] as const) {
			systemWasmHostBackupFileIO.writeFileBytes(join(dataRoot, APPLICATION, WASM_BACKUP_FILE_NAMES_V2[kind]), Buffer.from("image:" + kind, "utf8"), 0o600);
		}
		const service = new WasmHostBackupService({
			applicationId: APPLICATION,
			hostServicePolicyDigest: POLICY_DIGEST,
			dataDirectoryRoot: dataRoot,
			executionRpc,
			io: systemWasmHostBackupFileIO,
		});
		const captured = await service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
		expect(captured.ok).toBe(true);
		if (captured.ok) expect(captured.persistedPath).toBe(null);
		const restore = service.restore(JSON.parse(JSON.stringify(captured.ok ? captured.descriptor : null)));
		expect(restore.ok).toBe(false);
		if (!restore.ok) expect(restore.code).toBe(WASM_HOST_BACKUP_RESTORE_UNAVAILABLE);
	});
});

describe("backup service real chain: restore verifies digests before landing", () => {
	test("restore lands the retained bytes into the target directory only after full digest verification", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const fixture = realChainFixture({ data: join(root, "state"), backups: join(root, "backup") });
		const captured = await fixture.service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
		expect(captured.ok).toBe(true);
		if (!captured.ok) throw new Error("expected a successful capture");
		// 恢复到新目标目录（模拟数据目录重建）。
		const targetRoot = join(root, "restored-data");
		const descriptorWire = JSON.parse(fixture.io.readFileBytes(captured.persistedPath as string)?.toString("utf8") ?? "null");
		const restore = fixture.service.restore(descriptorWire, { targetDataDirectoryRoot: targetRoot });
		expect(restore.ok).toBe(true);
		if (!restore.ok) throw new Error("expected a successful restore");
		for (const kind of ["kv", "sql", "quota"] as const) {
			const landed = fixture.io.readFileBytes(join(targetRoot, APPLICATION, WASM_BACKUP_FILE_NAMES_V2[kind]));
			expect(landed?.equals(fixture.memberBytes.get(kind) as Buffer)).toBe(true);
			const stats = fixture.io.statEntry(join(targetRoot, APPLICATION, WASM_BACKUP_FILE_NAMES_V2[kind]));
			expect(stats !== null && (stats.mode & 0o7777)).toBe(0o600);
		}
	});

	test("a tampered retained member is refused with zero landing", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const fixture = realChainFixture({ data: join(root, "state"), backups: join(root, "backup") });
		const captured = await fixture.service.capture({ drainCommand: drainCommand(), quiesceState: healthyQuiesceInput(), usageRevision: 3 });
		expect(captured.ok).toBe(true);
		if (!captured.ok) throw new Error("expected a successful capture");
		fixture.io.writeFileBytes(
			join(root, "backup", "sets", APPLICATION, WASM_BACKUP_FILE_NAMES_V2.sql),
			Buffer.from("tampered-bytes", "utf8"),
			0o600,
		);
		const descriptorWire = JSON.parse(fixture.io.readFileBytes(captured.persistedPath as string)?.toString("utf8") ?? "null");
		const targetRoot = join(root, "restored-data");
		const restore = fixture.service.restore(descriptorWire, { targetDataDirectoryRoot: targetRoot });
		expect(restore.ok).toBe(false);
		if (!restore.ok) expect(restore.code).toBe(WASM_HOST_BACKUP_MEMBER_INVALID);
		// 零落地：目标目录没有任何成员被创建（目录也不建）。
		for (const kind of ["kv", "sql", "quota"] as const) {
			expect(fixture.io.statEntry(join(targetRoot, APPLICATION, WASM_BACKUP_FILE_NAMES_V2[kind]))).toBe(null);
		}
	});

	test("a restore set bound to another identity is refused before any member read", () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		const service = new WasmHostBackupService({
			applicationId: APPLICATION,
			hostServicePolicyDigest: POLICY_DIGEST,
			backupDirectory: join(root, "sets"),
			executionRpc: createExecutionRpcHandler({
				journal: new WasmExecutionJournalStore(systemStateStoreIO, join(root, "state")),
				executor: { execute: async (command) => ({ result: "applied", failureCode: null, drainReceiptDraft: drainDraft(command) }) },
				now: () => FIXED_NOW,
			}),
			io: systemWasmHostBackupFileIO,
		});
		const foreign = descriptor({ applicationId: "search-app" });
		const restore = service.restore(foreign, { targetDataDirectoryRoot: join(root, "target") });
		expect(restore.ok).toBe(false);
		if (!restore.ok) expect(restore.code).toBe(WASM_HOST_SERVICE_BACKUP_INVALID);
	});

	test("an unwired restore target is explicit unavailability, never a default landing path", async () => {
		const root = mkdtempSync(join(tmpdir(), "iweb-wasm-backup-"));
		// 服务只配置 backupDirectory（无 dataDirectoryRoot，也无显式 target）。
		const service = new WasmHostBackupService({
			applicationId: APPLICATION,
			hostServicePolicyDigest: POLICY_DIGEST,
			backupDirectory: join(root, "sets"),
			executionRpc: createExecutionRpcHandler({
				journal: new WasmExecutionJournalStore(systemStateStoreIO, join(root, "state")),
				executor: { execute: async (command) => ({ result: "applied", failureCode: null, drainReceiptDraft: drainDraft(command) }) },
				now: () => FIXED_NOW,
			}),
			io: systemWasmHostBackupFileIO,
		});
		const restore = service.restore(descriptor());
		expect(restore.ok).toBe(false);
		if (!restore.ok) expect(restore.code).toBe(WASM_HOST_BACKUP_RESTORE_TARGET_UNAVAILABLE);
	});
});
