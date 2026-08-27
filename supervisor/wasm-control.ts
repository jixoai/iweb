// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.0）：wasm 执行传输与持久化边界——
//   /v1/execution-rpc 只收 iweb-execution-rpc-v1 envelope；wasm-control-state-v2.json 以
//   controlRevision CAS 提交（CONTROL_REVISION_CONFLICT 零写入）并承载 command outbox；
//   supervisor 独占 wasm-execution-journal-v1，记录 command-received → 幂等执行 →
//   completion ack 的唯一序列，query/replay 只读这份 journal。
// 正交意图：与 celld /v1/rpc、desired-state.json、ControlStateFile 物理/文法双向互斥，
//   禁降级解析、禁原地迁移；一切 wire 校验复用 packages/contracts 契约（不造第二套）；
//   持久化字节权威是 JCS（raw bytes 必须等于 JCS(JSON.parse(bytes))）；每个崩溃点恢复
//   只有唯一结果。Kernel 侧 outbox/投影 CAS 与 supervisor 侧 journal CAS 是独立计数器，
//   任何一方不得替代另一方。
// 7.1 SupervisorSocketAuthV1：Linux SO_PEERCRED、固定路径 inode/owner/mode 复查与
//   SCM_RIGHTS 拒绝由公开 socket 的原生 relay 在进入 Node 前完成；本文件只处理已认证的
//   HTTP-only 边界。
// TODO(7.3 SnapshotFdTransportV1)：raw-UDS 快照 FD handoff 与 snapshotHandoffDigest 的
//   非空来源属任务 7.3；本任务内所有 command 均无 snapshot handoff（journal 记 null）。
import { join } from "node:path";
import { systemStateStoreIO, type StateStoreIO } from "./desired-state.ts";
import { DEFAULT_MAX_REQUEST_BYTES, isJsonContentType } from "../packages/contracts/protocol-server.ts";
import { CELLD_PROTOCOL_MISMATCH, EXECUTION_PROTOCOL_MISMATCH } from "../packages/contracts/protocol.ts";
import { jcsCanonicalBytes, WASM_SHA256_HEX_PATTERN, WASM_U53_MAX } from "../packages/contracts/wasm-package.ts";
import {
	checkControlRevisionCas,
	computeDrainReceiptDigestV1,
	computeExecutionCommandDigestV1,
	CONTROL_REVISION_CONFLICT,
	correlateExecutionAcknowledgement,
	EXECUTION_RPC_PROTOCOL_LITERAL,
	validateCommandReceivedV1,
	validateDrainReceiptV1,
	validateExecutionAcknowledgementV1,
	validateExecutionRpcRequestEnvelopeV1,
	validateWasmControlStateFileV2,
	WASM_RFC3339_UTC_PATTERN,
	WASM_SNAPSHOT_FRAME_MAGIC_HEX,
	WASM_UUIDV7_PATTERN,
	type CommandOutboxRecordV1,
	type CommandReceivedV1,
	type DrainReceiptDraftV1,
	type DrainReceiptV1,
	type DrainReceiptV1WithoutDigest,
	type ExecutionAcknowledgementV1,
	type ExecutionCommandV1,
	type ExecutionRpcRequestEnvelopeV1,
	type ExecutionRpcResponseBodyV1,
	type WasmControlStateFileV2,
} from "../packages/contracts/wasm-execution.ts";
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "../packages/contracts/validation.ts";

// ---------------------------------------------------------------------------
// 路径、稳定错误码与 wire 常量
// ---------------------------------------------------------------------------

export const EXECUTION_RPC_PATH = "/v1/execution-rpc";
export const WASM_CONTROL_STATE_FILENAME = "wasm-control-state-v2.json";
export const WASM_EXECUTION_JOURNAL_FILENAME = "wasm-execution-journal-v1.json";

// spec 已命名的拒绝码（契约库只定义了 controlRevision 冲突码，此处沿用同名字面量语义）。
export const EXECUTION_COMMAND_ID_CONFLICT = "EXECUTION_COMMAND_ID_CONFLICT";
export const EXECUTION_HTTP_FRAME_REJECTED = "EXECUTION_HTTP_FRAME_REJECTED";
// 宿主侧 fail-closed 码（spec 未命名；见文件末尾歧义备注）。
export const JOURNAL_REVISION_CONFLICT = "JOURNAL_REVISION_CONFLICT";
export const EXECUTION_COMMAND_UNKNOWN = "EXECUTION_COMMAND_UNKNOWN";
export const EXECUTION_COMMAND_ALREADY_COMPLETED = "EXECUTION_COMMAND_ALREADY_COMPLETED";
export const EXECUTION_OUTBOX_DUPLICATE_COMMAND = "EXECUTION_OUTBOX_DUPLICATE_COMMAND";
export const EXECUTION_OUTBOX_COMMAND_UNKNOWN = "EXECUTION_OUTBOX_COMMAND_UNKNOWN";
export const EXECUTION_ACK_PROJECTION_CONFLICT = "EXECUTION_ACK_PROJECTION_CONFLICT";
export const EXECUTION_RPC_ENVELOPE_INVALID = "EXECUTION_RPC_ENVELOPE_INVALID";
export const EXECUTION_RPC_NOT_CONFIGURED = "EXECUTION_RPC_NOT_CONFIGURED";
export const EXECUTION_EXECUTOR_FAILED = "EXECUTION_EXECUTOR_FAILED";
export const EXECUTION_EXECUTOR_OUTCOME_INVALID = "EXECUTION_EXECUTOR_OUTCOME_INVALID";
export const WASM_CONTROL_STATE_CORRUPT = "WASM_CONTROL_STATE_CORRUPT";
export const WASM_EXECUTION_JOURNAL_CORRUPT = "WASM_EXECUTION_JOURNAL_CORRUPT";

const JOURNAL_CODE = "WASM_EXECUTION_JOURNAL_INVALID";
const JOURNAL_ENTRY_KEYS: readonly string[] = ["kind", "commandId", "commandDigest", "acknowledgement", "snapshotHandoffDigest", "completedAt", "journalRevision"];
const CELLD_ENVELOPE_MARKERS: readonly string[] = ["version", "operation"];
const snapshotFrameMagic: Buffer = Buffer.from(WASM_SNAPSHOT_FRAME_MAGIC_HEX, "hex");

// ---------------------------------------------------------------------------
// JCS 字节权威的持久化基元：读时 raw bytes 必须等于 JCS(parse)（重复键/白空格/键序
// 偏差一律按损坏拒绝），写时只落 JCS 字节。复用 desired-state.ts 的 tmp+fsync+rename IO。
// ---------------------------------------------------------------------------

type CanonicalReadResult = { readonly status: "absent" } | { readonly status: "present"; readonly value: unknown };

function readCanonicalRecord(io: StateStoreIO, path: string, failureCode: string): CanonicalReadResult {
	const text = io.readFile(path);
	if (text === null) return { status: "absent" };
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new Error(failureCode + ": file is not parseable JSON");
	}
	if (Buffer.from(jcsCanonicalBytes(parsed)).toString("utf8") !== text) {
		throw new Error(failureCode + ": file bytes are not canonical JCS");
	}
	return { status: "present", value: parsed };
}

function writeCanonicalRecord(io: StateStoreIO, path: string, value: unknown): void {
	io.writeFileAtomic(path, Buffer.from(jcsCanonicalBytes(value)).toString("utf8"));
}

// ---------------------------------------------------------------------------
// wasm-control-state-v2.json：Kernel 侧 controlRevision CAS 存储与 command outbox
// ---------------------------------------------------------------------------

export function emptyWasmControlStateFileV2(): WasmControlStateFileV2 {
	return {
		schemaVersion: 2,
		runtimeKind: "wasm",
		controlRevision: 0,
		applications: {},
		commandOutbox: [],
		migration: { source: "celld-control-state-v1", status: "not-started", sourceDigest: null, completedAt: null },
	};
}

export type WasmControlCasCode =
	| typeof CONTROL_REVISION_CONFLICT
	| typeof EXECUTION_OUTBOX_DUPLICATE_COMMAND
	| typeof EXECUTION_OUTBOX_COMMAND_UNKNOWN
	| typeof EXECUTION_ACK_PROJECTION_CONFLICT;

export type WasmControlCasResult =
	| { readonly ok: true; readonly state: WasmControlStateFileV2 }
	| { readonly ok: false; readonly code: WasmControlCasCode };

// controlRevision CAS 的物理载体：期望值不匹配（含非 u53/越界期望，由契约
// checkControlRevisionCas 判定）返回 CONTROL_REVISION_CONFLICT 且不写任何字节。
export class WasmControlStateStore {
	private readonly io: StateStoreIO;
	private readonly path: string;

	constructor(io: StateStoreIO = systemStateStoreIO, directory: string) {
		this.io = io;
		this.path = join(directory, WASM_CONTROL_STATE_FILENAME);
	}

	// 缺失文件 = 未初始化（migration not-started）；present-but-invalid 一律 fail-closed
	// 抛出，绝不静默归零、绝不当 celld 文件解析（spec "Celld state is presented to the
	// wasm store" 场景：只有 wasm 文件缺失才是 uninitialized/migration-required）。
	read(): WasmControlStateFileV2 {
		const record = readCanonicalRecord(this.io, this.path, WASM_CONTROL_STATE_CORRUPT);
		if (record.status === "absent") return emptyWasmControlStateFileV2();
		const validated = validateWasmControlStateFileV2(record.value);
		if (!validated.ok) {
			const first = validated.errors[0];
			throw new Error(WASM_CONTROL_STATE_CORRUPT + ": " + (first ? first.code + " at " + first.path : "validation failed"));
		}
		return validated.value;
	}

	// CAS 核心：current.controlRevision 必须等于 expected；mutate 产出的下一态由本方法
	// 强制 controlRevision = expected + 1 并整文件复验后才落盘。mutate 抛出的
	// WasmControlOperationFailure 映射为对应错误码（操作级冲突同样零写入）。
	commit(expectedControlRevision: number, mutate: (current: WasmControlStateFileV2) => WasmControlStateFileV2): WasmControlCasResult {
		const current = this.read();
		if (current.controlRevision !== expectedControlRevision) return { ok: false, code: CONTROL_REVISION_CONFLICT };
		// 复用契约 CAS 语义：expected 必须 u53 且 next = expected + 1 可表示（上限处拒绝）。
		const cas = checkControlRevisionCas(expectedControlRevision, expectedControlRevision + 1);
		if (!cas.ok) return { ok: false, code: CONTROL_REVISION_CONFLICT };
		let mutated: WasmControlStateFileV2;
		try {
			mutated = mutate(current);
		} catch (error) {
			if (error instanceof WasmControlOperationFailure) return { ok: false, code: error.code };
			throw error;
		}
		const next: WasmControlStateFileV2 = { ...mutated, controlRevision: expectedControlRevision + 1 };
		const validated = validateWasmControlStateFileV2(next);
		if (!validated.ok) throw new Error(WASM_CONTROL_STATE_CORRUPT + ": generated next state failed validation");
		writeCanonicalRecord(this.io, this.path, validated.value);
		return { ok: true, state: validated.value };
	}

	// outbox 追加：与授权该 command 的同一 controlRevision CAS 提交（spec 双 CAS 序列
	// 第 1 步）。commandId 必须唯一；重复追加 fail-closed，绝不静默合并。
	appendOutboxCommand(expectedControlRevision: number, command: ExecutionCommandV1, createdAt: string): WasmControlCasResult {
		return this.commit(expectedControlRevision, (current) => {
			if (current.commandOutbox.some((entry) => entry.commandId === command.commandId)) {
				throw new WasmControlOperationFailure(EXECUTION_OUTBOX_DUPLICATE_COMMAND);
			}
			const entry: CommandOutboxRecordV1 = { commandId: command.commandId, command, createdAt, deliveryState: "pending", attempts: 0, lastAttemptAt: null };
			return { ...current, commandOutbox: [...current.commandOutbox, entry] };
		});
	}

	// acknowledgement 投影：双 CAS 序列第 3 步。只有 identity-checked 的 ack 才能把
	// outbox 置为 acknowledged；重复投影同一 ack 幂等（不再消耗 revision），任何回显
	// 字段不匹配或 dead 终态的复活均 fail-closed。
	projectAcknowledgement(expectedControlRevision: number, acknowledgement: ExecutionAcknowledgementV1): WasmControlCasResult {
		const current = this.read();
		if (current.controlRevision !== expectedControlRevision) return { ok: false, code: CONTROL_REVISION_CONFLICT };
		const entry = current.commandOutbox.find((candidate) => candidate.commandId === acknowledgement.commandId);
		if (entry === undefined) return { ok: false, code: EXECUTION_OUTBOX_COMMAND_UNKNOWN };
		const correlated = correlateExecutionAcknowledgement(entry.command, acknowledgement);
		if (!correlated.ok) return { ok: false, code: EXECUTION_ACK_PROJECTION_CONFLICT };
		if (entry.deliveryState === "dead") return { ok: false, code: EXECUTION_ACK_PROJECTION_CONFLICT };
		if (entry.deliveryState === "acknowledged") return { ok: true, state: current };
		return this.commit(expectedControlRevision, (head) => ({
			...head,
			commandOutbox: head.commandOutbox.map((candidate) => (candidate.commandId === acknowledgement.commandId ? { ...candidate, deliveryState: "acknowledged" as const } : candidate)),
		}));
	}

	findOutboxCommand(commandId: string): CommandOutboxRecordV1 | null {
		const entry = this.read().commandOutbox.find((candidate) => candidate.commandId === commandId);
		return entry ?? null;
	}
}

// commit() 内的操作级 fail-closed：CAS 期望值已对，但操作本身非法（如重复 commandId）。
// commit 捕获后映射为对应错误码，保证"冲突零写入"对 CAS 与操作两级都成立。
export class WasmControlOperationFailure extends Error {
	readonly code: WasmControlCasCode;
	constructor(code: WasmControlCasCode) {
		super("wasm control operation failed: " + code);
		this.code = code;
	}
}

// ---------------------------------------------------------------------------
// wasm-execution-journal-v1：supervisor 独占的执行事务 journal
// ---------------------------------------------------------------------------

export interface CommandCompletedV1 {
	readonly kind: "completed";
	readonly commandId: string;
	readonly commandDigest: string;
	readonly acknowledgement: ExecutionAcknowledgementV1;
	readonly snapshotHandoffDigest: string | null;
	readonly completedAt: string;
	readonly journalRevision: number;
}

export type WasmExecutionJournalEntryV1 = CommandReceivedV1 | CommandCompletedV1;

export interface WasmExecutionJournalFileV1 {
	readonly schemaVersion: 1;
	readonly journalRevision: number;
	readonly entries: readonly WasmExecutionJournalEntryV1[];
}

function requireJournalInteger(value: unknown, path: string, fieldName: string, minimum: number, errors: ValidationIssue[]): number | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > WASM_U53_MAX) {
		errors.push(issue(JOURNAL_CODE, path + "/" + fieldName, fieldName + " must be a u53 integer"));
		return null;
	}
	return value;
}

function requireJournalDigest(value: unknown, path: string, fieldName: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_SHA256_HEX_PATTERN.test(value)) {
		errors.push(issue(JOURNAL_CODE, path + "/" + fieldName, fieldName + " must be a 64-character lower-case hex digest"));
		return null;
	}
	return value;
}

function requireCompletedEntry(input: unknown, path: string, errors: ValidationIssue[]): CommandCompletedV1 | null {
	if (!isRecord(input)) {
		errors.push(issue(JOURNAL_CODE, path, "journal entry must be an object"));
		return null;
	}
	for (const key of Object.keys(input)) {
		if (!JOURNAL_ENTRY_KEYS.includes(key)) errors.push(issue(JOURNAL_CODE, path + "/" + key, "unknown field is not allowed"));
	}
	for (const key of JOURNAL_ENTRY_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(JOURNAL_CODE, path + "/" + key, "required field is missing"));
	}
	if (input.kind !== "completed") {
		errors.push(issue(JOURNAL_CODE, path + "/kind", 'kind must be exactly "completed"'));
		return null;
	}
	const commandId = typeof input.commandId === "string" && WASM_UUIDV7_PATTERN.test(input.commandId) ? input.commandId : null;
	if (commandId === null) errors.push(issue(JOURNAL_CODE, path + "/commandId", "commandId must be a lower-case UUIDv7"));
	const commandDigest = requireJournalDigest(input.commandDigest, path, "commandDigest", errors);
	const acknowledgement = validateExecutionAcknowledgementV1(input.acknowledgement);
	if (!acknowledgement.ok) errors.push(...acknowledgement.errors);
	let snapshotHandoffDigest: string | null = null;
	if (input.snapshotHandoffDigest !== null) {
		const digest = requireJournalDigest(input.snapshotHandoffDigest, path, "snapshotHandoffDigest", errors);
		if (digest !== null) snapshotHandoffDigest = digest;
	}
	const completedAt = typeof input.completedAt === "string" && WASM_RFC3339_UTC_PATTERN.test(input.completedAt) && !Number.isNaN(Date.parse(input.completedAt)) ? input.completedAt : null;
	if (completedAt === null) errors.push(issue(JOURNAL_CODE, path + "/completedAt", "completedAt must be an RFC3339 UTC timestamp"));
	const journalRevision = requireJournalInteger(input.journalRevision, path, "journalRevision", 0, errors);
	if (commandId === null || commandDigest === null || !acknowledgement.ok || completedAt === null || journalRevision === null || errors.length) return null;
	if (acknowledgement.value.commandId !== commandId) {
		errors.push(issue(JOURNAL_CODE, path + "/acknowledgement/commandId", "acknowledgement commandId must match the completed entry"));
		return null;
	}
	return { kind: "completed", commandId, commandDigest, acknowledgement: acknowledgement.value, snapshotHandoffDigest, completedAt, journalRevision };
}

// 文件级严格校验：精确键集、逐条 received/completed 校验（received 复用契约
// validateCommandReceivedV1，含 commandDigest 复算）、revision 严格 +1 递增、
// received 必须先于其 completed、commandId 唯一。
export function validateWasmExecutionJournalFileV1(input: unknown): ValidationResult<WasmExecutionJournalFileV1> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue(JOURNAL_CODE, "", "journal file must be an object")]);
	for (const key of Object.keys(input)) {
		if (key !== "schemaVersion" && key !== "journalRevision" && key !== "entries") errors.push(issue(JOURNAL_CODE, "/" + key, "unknown field is not allowed"));
	}
	for (const key of ["schemaVersion", "journalRevision", "entries"] as const) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(JOURNAL_CODE, "/" + key, "required field is missing"));
	}
	if (input.schemaVersion !== 1) errors.push(issue(JOURNAL_CODE, "/schemaVersion", "schemaVersion must be exactly 1"));
	const journalRevision = requireJournalInteger(input.journalRevision, "", "journalRevision", 0, errors);
	if (!Array.isArray(input.entries)) {
		errors.push(issue(JOURNAL_CODE, "/entries", "entries must be an array"));
		return failure(errors);
	}
	const entries: WasmExecutionJournalEntryV1[] = [];
	const receivedDigests = new Map<string, string>();
	const completedCommands = new Set<string>();
	for (let index = 0; index < input.entries.length; index += 1) {
		const raw = input.entries[index];
		const path = "/entries/" + index;
		const expectedRevision = index + 1;
		if (!isRecord(raw)) {
			errors.push(issue(JOURNAL_CODE, path, "journal entry must be an object"));
			continue;
		}
		if (raw.kind === "command-received") {
			const parsed = validateCommandReceivedV1(raw);
			if (!parsed.ok) {
				errors.push(...parsed.errors);
				continue;
			}
			if (parsed.value.journalRevision !== expectedRevision) {
				errors.push(issue(JOURNAL_CODE, path + "/journalRevision", "journal revisions must increase by exactly one per entry"));
			}
			if (receivedDigests.has(parsed.value.commandId) || completedCommands.has(parsed.value.commandId)) {
				errors.push(issue(JOURNAL_CODE, path, "a commandId may be received only once"));
				continue;
			}
			receivedDigests.set(parsed.value.commandId, parsed.value.commandDigest);
			entries.push(parsed.value);
			continue;
		}
		if (raw.kind === "completed") {
			const parsed = requireCompletedEntry(raw, path, errors);
			if (parsed === null) continue;
			if (parsed.journalRevision !== expectedRevision) {
				errors.push(issue(JOURNAL_CODE, path + "/journalRevision", "journal revisions must increase by exactly one per entry"));
			}
			if (parsed.acknowledgement.journalRevision !== expectedRevision) {
				errors.push(issue(JOURNAL_CODE, path + "/acknowledgement/journalRevision", "acknowledgement journalRevision must equal the completed entry revision"));
			}
			const priorDigest = receivedDigests.get(parsed.commandId);
			if (priorDigest === undefined) {
				errors.push(issue(JOURNAL_CODE, path, "a received entry must precede its completed entry"));
				continue;
			}
			if (priorDigest !== parsed.commandDigest) {
				errors.push(issue(JOURNAL_CODE, path + "/commandDigest", "completed entry digest must match its received entry"));
			}
			if (completedCommands.has(parsed.commandId)) {
				errors.push(issue(JOURNAL_CODE, path, "a commandId may complete only once"));
				continue;
			}
			completedCommands.add(parsed.commandId);
			entries.push(parsed);
			continue;
		}
		errors.push(issue(JOURNAL_CODE, path + "/kind", 'kind must be "command-received" or "completed"'));
	}
	if (journalRevision !== null && journalRevision !== entries.length) {
		errors.push(issue(JOURNAL_CODE, "/journalRevision", "file journalRevision must equal the entry count"));
	}
	if (errors.length) return failure(errors);
	return ok({ schemaVersion: 1, journalRevision: journalRevision as number, entries });
}

export interface WasmJournalLookup {
	readonly received: CommandReceivedV1 | null;
	readonly completed: CommandCompletedV1 | null;
}

export type JournalAppendOutcome<T> =
	| { readonly ok: true; readonly entry: T }
	| { readonly ok: false; readonly code: typeof JOURNAL_REVISION_CONFLICT; readonly currentRevision: number };

export type JournalCompleteOutcome =
	| { readonly ok: true; readonly entry: CommandCompletedV1 }
	| { readonly ok: false; readonly code: typeof EXECUTION_COMMAND_ALREADY_COMPLETED; readonly entry: CommandCompletedV1 };

// journal CAS 存储：journalRevision 从 0 起步，每追加一条恰好 +1；期望值不匹配零写入。
// query/replay 只读本文件，绝不读 celld desired-state 或 /v1/rpc 历史（spec 控制态条款）。
export class WasmExecutionJournalStore {
	private readonly io: StateStoreIO;
	private readonly path: string;

	constructor(io: StateStoreIO = systemStateStoreIO, directory: string) {
		this.io = io;
		this.path = join(directory, WASM_EXECUTION_JOURNAL_FILENAME);
	}

	read(): WasmExecutionJournalFileV1 {
		const record = readCanonicalRecord(this.io, this.path, WASM_EXECUTION_JOURNAL_CORRUPT);
		if (record.status === "absent") return { schemaVersion: 1, journalRevision: 0, entries: [] };
		const validated = validateWasmExecutionJournalFileV1(record.value);
		if (!validated.ok) {
			const first = validated.errors[0];
			throw new Error(WASM_EXECUTION_JOURNAL_CORRUPT + ": " + (first ? first.code + " at " + first.path : "validation failed"));
		}
		return validated.value;
	}

	find(commandId: string): WasmJournalLookup {
		return this.findIn(this.read(), commandId);
	}

	// spec 双 CAS 序列第 2 步之一：supervisor 先在 expectedJournalRevision 处 CAS 写入
	// command-received，然后才允许执行副作用。
	appendReceived(expectedJournalRevision: number, command: ExecutionCommandV1, receivedAt: string): JournalAppendOutcome<CommandReceivedV1> {
		const current = this.read();
		if (current.journalRevision !== expectedJournalRevision) {
			return { ok: false, code: JOURNAL_REVISION_CONFLICT, currentRevision: current.journalRevision };
		}
		const entry: CommandReceivedV1 = {
			kind: "command-received",
			commandId: command.commandId,
			commandDigest: computeExecutionCommandDigestV1(command),
			command,
			snapshotHandoffDigest: null,
			receivedAt,
			journalRevision: expectedJournalRevision + 1,
		};
		const next: WasmExecutionJournalFileV1 = { schemaVersion: 1, journalRevision: expectedJournalRevision + 1, entries: [...current.entries, entry] };
		const validated = validateWasmExecutionJournalFileV1(next);
		if (!validated.ok) throw new Error(WASM_EXECUTION_JOURNAL_CORRUPT + ": generated received entry failed validation");
		writeCanonicalRecord(this.io, this.path, validated.value);
		return { ok: true, entry };
	}

	// spec 双 CAS 序列第 2 步之二：幂等执行完成后，completion ack 以 journalRevision CAS
	// 落盘。同一 commandId 已有 completion 时幂等返回已存条目（并发重复投递只有一个结果）。
	appendCompleted(
		commandId: string,
		commandDigest: string,
		buildAcknowledgement: (journalRevision: number) => ExecutionAcknowledgementV1,
		completedAt: string,
	): JournalCompleteOutcome {
		const current = this.read();
		const found = this.findIn(current, commandId);
		if (found.completed !== null) return { ok: false, code: EXECUTION_COMMAND_ALREADY_COMPLETED, entry: found.completed };
		if (found.received === null) {
			throw new Error(WASM_EXECUTION_JOURNAL_CORRUPT + ": a completed entry requires a preceding received entry");
		}
		if (found.received.commandDigest !== commandDigest) {
			throw new Error(WASM_EXECUTION_JOURNAL_CORRUPT + ": completed entry digest must match the received entry");
		}
		const journalRevision = current.journalRevision + 1;
		const entry: CommandCompletedV1 = {
			kind: "completed",
			commandId,
			commandDigest,
			acknowledgement: buildAcknowledgement(journalRevision),
			snapshotHandoffDigest: found.received.snapshotHandoffDigest,
			completedAt,
			journalRevision,
		};
		const next: WasmExecutionJournalFileV1 = { schemaVersion: 1, journalRevision: journalRevision, entries: [...current.entries, entry] };
		const validated = validateWasmExecutionJournalFileV1(next);
		if (!validated.ok) throw new Error(WASM_EXECUTION_JOURNAL_CORRUPT + ": generated completed entry failed validation");
		writeCanonicalRecord(this.io, this.path, validated.value);
		return { ok: true, entry };
	}

	private findIn(file: WasmExecutionJournalFileV1, commandId: string): WasmJournalLookup {
		let received: CommandReceivedV1 | null = null;
		let completed: CommandCompletedV1 | null = null;
		for (const entry of file.entries) {
			if (entry.commandId !== commandId) continue;
			if (entry.kind === "command-received") received = entry;
			else completed = entry;
		}
		return { received, completed };
	}
}

// ---------------------------------------------------------------------------
// /v1/execution-rpc 服务：command → received CAS → 幂等执行 → completion CAS → ack
// ---------------------------------------------------------------------------

export interface WasmExecutionOutcome {
	readonly result: "applied" | "rejected";
	readonly failureCode: string | null;
	/**
	 * drain 的 DrainReceiptV1 草稿（executor 只能产出草稿：receiptDigest 的输入含
	 * journalRevision，而 revision 在 completion 落盘时才分配）。非 drain 操作或
	 * rejected 的 drain 必须为 null；applied 的 drain 必须非 null——digest 由本模块
	 * 的 draftAcknowledgement 在 revision 确定后计算并填入 ack（契约备注：digest 由
	 * 投递层计算）。
	 */
	readonly drainReceiptDraft: DrainReceiptDraftV1 | null;
}

// 执行器契约：execute 必须按 commandDigest 幂等——supervisor 可能在"副作用已发生、
// completion 尚未落盘"的崩溃点之后再次调用（spec：received-but-incomplete 的 command
// 在其存储 fence 下恢复执行）；同一 command 的重复调用不得产生分歧结果。
export interface WasmExecutionExecutor {
	execute(command: ExecutionCommandV1): Promise<WasmExecutionOutcome>;
}

export type ExecutionRpcServiceResult =
	| { readonly ok: true; readonly body: ExecutionRpcResponseBodyV1 }
	| { readonly ok: false; readonly status: number; readonly code: string; readonly message: string };

export interface ExecutionRpcHandler {
	handle(envelope: ExecutionRpcRequestEnvelopeV1): Promise<ExecutionRpcServiceResult>;
}

// completion 落盘点的 drain receipt 生产（spec "Drain completion is a typed receipt
// before Kernel retirement"）：applied drain 必须携带草稿，在此处以确定后的
// journalRevision 计算 receiptDigest 并整单复验（validateDrainReceiptV1 是 fail-closed
// 自检——forcedKillAt 耦合、digest 复算任一不过即整体拒绝，绝不落半合法 ack）。
function drainReceiptDigestOfOutcome(command: ExecutionCommandV1, outcome: WasmExecutionOutcome, journalRevision: number): string | null {
	const appliedDrain = command.operation === "drain" && outcome.result === "applied";
	if (!appliedDrain) {
		// 非 drain / rejected drain 携带草稿属执行器产物矛盾：拒绝（不静默丢弃）。
		return outcome.drainReceiptDraft === null ? null : "invalid";
	}
	if (outcome.drainReceiptDraft === null) return "invalid";
	const withoutDigest: DrainReceiptV1WithoutDigest = { ...outcome.drainReceiptDraft, journalRevision };
	const receipt: DrainReceiptV1 = { ...withoutDigest, receiptDigest: computeDrainReceiptDigestV1(withoutDigest) };
	if (!validateDrainReceiptV1(receipt).ok) return "invalid";
	return receipt.receiptDigest;
}

function draftAcknowledgement(command: ExecutionCommandV1, outcome: WasmExecutionOutcome, journalRevision: number): ExecutionAcknowledgementV1 | null {
	const drainReceiptDigest = drainReceiptDigestOfOutcome(command, outcome, journalRevision);
	if (drainReceiptDigest === "invalid") return null;
	const draft: ExecutionAcknowledgementV1 = {
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
		drainReceiptDigest,
		result: outcome.result,
		failureCode: outcome.failureCode,
		journalRevision,
	};
	const validated = validateExecutionAcknowledgementV1(draft);
	if (!validated.ok) return null;
	return validated.value;
}

export function createExecutionRpcHandler(options: {
	readonly journal: WasmExecutionJournalStore;
	readonly executor: WasmExecutionExecutor;
	readonly now?: () => string;
}): ExecutionRpcHandler {
	const journal = options.journal;
	const executor = options.executor;
	const now = options.now ?? (() => new Date().toISOString());

	const conflict = (status: number, code: string, message: string): ExecutionRpcServiceResult => ({ ok: false, status, code, message });

	// 已完成命令：回放/重投一律返回存储的 ack，绝不重复执行副作用（spec query/replay 条款）。
	const acknowledgementBody = (acknowledgement: ExecutionAcknowledgementV1): ExecutionRpcServiceResult => ({ ok: true, body: { kind: "acknowledgement", acknowledgement } });

	// received-but-incomplete：在其存储的 command fence 下恢复执行（字节相同的命令才可能
	// 到达这里；调用方已校验 digest）。执行后 completion 以 head+1 CAS 落盘；并发重复投递
	// 落败方改读已存 completion，保证唯一结果。
	const resume = async (received: CommandReceivedV1, commandDigest: string): Promise<ExecutionRpcServiceResult> => {
		let outcome: WasmExecutionOutcome;
		try {
			outcome = await executor.execute(received.command);
		} catch {
			// 执行器失败：命令保持 received-incomplete，replay 可恢复；不落任何 completion。
			return conflict(500, EXECUTION_EXECUTOR_FAILED, "the wasm execution executor failed; the command stays received-incomplete and replay resumes it");
		}
		const head = journal.read();
		if (draftAcknowledgement(received.command, outcome, head.journalRevision + 1) === null) {
			return conflict(500, EXECUTION_EXECUTOR_OUTCOME_INVALID, "the executor returned an outcome that cannot form a valid acknowledgement");
		}
		const build = (revision: number): ExecutionAcknowledgementV1 => {
			const redraft = draftAcknowledgement(received.command, outcome, revision);
			if (redraft === null) throw new Error(EXECUTION_EXECUTOR_OUTCOME_INVALID + ": executor outcome stopped validating");
			return redraft;
		};
		const appended = journal.appendCompleted(received.commandId, commandDigest, build, now());
		return acknowledgementBody(appended.entry.acknowledgement);
	};

	const deliver = async (command: ExecutionCommandV1, mode: "command" | "replay"): Promise<ExecutionRpcServiceResult> => {
		const commandDigest = computeExecutionCommandDigestV1(command);
		const found = journal.find(command.commandId);
		if (found.completed !== null) {
			if (found.received === null || found.received.commandDigest !== commandDigest) {
				return conflict(409, EXECUTION_COMMAND_ID_CONFLICT, "a known commandId was re-sent with a differing command body; no side effect or journal write occurred");
			}
			return acknowledgementBody(found.completed.acknowledgement);
		}
		if (found.received !== null) {
			if (found.received.commandDigest !== commandDigest) {
				return conflict(409, EXECUTION_COMMAND_ID_CONFLICT, "a known commandId was re-sent with a differing command body; no side effect or journal write occurred");
			}
			return resume(found.received, commandDigest);
		}
		if (mode === "replay") {
			return conflict(404, EXECUTION_COMMAND_UNKNOWN, "replay requires a command the journal already received; Kernel must query or deliver the command first");
		}
		// 新命令：先校验 expectedJournalRevision（Kernel control revision 是 Kernel 侧
		// fence，随命令字节记录在 journal 中，由 Kernel 投影时校验，supervisor 不替代）。
		const head = journal.read();
		if (command.expectedJournalRevision !== head.journalRevision) {
			return conflict(409, JOURNAL_REVISION_CONFLICT, "command expectedJournalRevision does not match the journal head; no entry was written");
		}
		const appended = journal.appendReceived(head.journalRevision, command, now());
		if (!appended.ok) {
			return conflict(409, JOURNAL_REVISION_CONFLICT, "command expectedJournalRevision does not match the journal head; no entry was written");
		}
		return resume(appended.entry, commandDigest);
	};

	return {
		handle: async (envelope) => {
			switch (envelope.body.kind) {
				case "command":
					return deliver(envelope.body.command, "command");
				case "replay":
					return deliver(envelope.body.command, "replay");
				case "query": {
					const found = journal.find(envelope.body.commandId);
					if (found.received === null && found.completed === null) {
						return { ok: true, body: { kind: "query-result", commandId: envelope.body.commandId, status: "missing", received: null, acknowledgement: null } };
					}
					if (found.received === null) {
						return conflict(500, WASM_EXECUTION_JOURNAL_CORRUPT, "a completed entry has no preceding received entry");
					}
					if (found.completed !== null) {
						return { ok: true, body: { kind: "query-result", commandId: envelope.body.commandId, status: "completed", received: found.received, acknowledgement: found.completed.acknowledgement } };
					}
					return { ok: true, body: { kind: "query-result", commandId: envelope.body.commandId, status: "received", received: found.received, acknowledgement: null } };
				}
				default:
					return conflict(500, "EXECUTION_RPC_BODY_INVALID", "unreachable execution rpc body kind");
			}
		},
	};
}

// ---------------------------------------------------------------------------
// /v1/execution-rpc 的 HTTP-only 封装（framing/size/content-type/互斥/envelope 校验）
// ---------------------------------------------------------------------------

export interface ExecutionRpcHttpRequest {
	readonly method: string;
	readonly path: string;
	readonly contentType: string | null;
	readonly body: Buffer;
}

export interface ExecutionRpcHttpResult {
	readonly status: number;
	readonly body: string;
}

function executionError(status: number, code: string, message: string): ExecutionRpcHttpResult {
	return { status, body: JSON.stringify({ ok: false, code, message }) + "\n" };
}

// 与 celld handleSupervisorRpc 对称的六步 framing：方法/路径 → body 上限 → content type →
// raw snapshot magic（解析前拒绝）→ JSON → celld envelope 互斥 → envelope schema → handler。
// 错误体不携带 celld `version` 词汇；成功响应是 {protocol,requestId,body} envelope。
export async function handleExecutionRpcHttp(handler: ExecutionRpcHandler, request: ExecutionRpcHttpRequest, options: { readonly maxRequestBytes?: number } = {}): Promise<ExecutionRpcHttpResult> {
	if (request.method !== "POST" || request.path !== EXECUTION_RPC_PATH) {
		return executionError(404, "UNKNOWN_ROUTE", "unknown supervisor route");
	}
	const maximumBytes = options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
	if (request.body.byteLength > maximumBytes) {
		return executionError(413, "BODY_TOO_LARGE", "execution rpc request is too large");
	}
	if (!isJsonContentType(request.contentType)) {
		return executionError(415, "UNSUPPORTED_CONTENT_TYPE", "execution rpc expects application/json");
	}
	// HTTP socket 只承载 HTTP 请求/响应字节：raw snapshot magic 在解析 body 前拒绝。
	// （SCM_RIGHTS/非 HTTP 前缀属 7.1/7.3 的 socket 层实测。）
	if (request.body.byteLength >= snapshotFrameMagic.byteLength && request.body.subarray(0, snapshotFrameMagic.byteLength).equals(snapshotFrameMagic)) {
		return executionError(400, EXECUTION_HTTP_FRAME_REJECTED, "the execution HTTP socket carries HTTP request/response bytes only; raw snapshot frames are rejected before body parsing");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(request.body.toString("utf8"));
	} catch {
		return executionError(400, "INVALID_JSON", "execution rpc body must be JSON");
	}
	// celld version/operation envelope 一律 EXECUTION_PROTOCOL_MISMATCH：不降级解析、
	// 不 fallback 到 celld parser（spec "Celld RPC envelope is sent to the wasm endpoint"）。
	if (isRecord(parsed) && CELLD_ENVELOPE_MARKERS.some((marker) => Object.prototype.hasOwnProperty.call(parsed, marker))) {
		return executionError(400, EXECUTION_PROTOCOL_MISMATCH, "the celld version/operation envelope is not accepted on /v1/execution-rpc; no fallback parsing occurs");
	}
	const validated = validateExecutionRpcRequestEnvelopeV1(parsed);
	if (!validated.ok) {
		return {
			status: 400,
			body: JSON.stringify({ ok: false, code: EXECUTION_RPC_ENVELOPE_INVALID, message: "execution rpc request is invalid", issues: validated.errors.slice(0, 50) }) + "\n",
		};
	}
	const result = await handler.handle(validated.value);
	if (result.ok) {
		return {
			status: 200,
			body: JSON.stringify({ protocol: EXECUTION_RPC_PROTOCOL_LITERAL, requestId: validated.value.requestId, body: result.body }) + "\n",
		};
	}
	return executionError(result.status, result.code, result.message);
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. replay 一个 journal 从未收到的 commandId：spec 只定义了 known-ID 的 replay 行为；
//    此处按严格 replay 语义拒绝 EXECUTION_COMMAND_UNKNOWN（Kernel 应先 query/deliver），
//    不把 replay 当作首次投递执行。
// 2. journalRevision CAS 冲突码：spec 未命名（controlRevision 侧是
//    CONTROL_REVISION_CONFLICT）；此处新增 JOURNAL_REVISION_CONFLICT，两计数器语义独立。
// 3. 执行器抛错/产出非法 outcome：命令保持 received-incomplete、零 journal 写入，
//    以 500 EXECUTION_EXECUTOR_FAILED/EXECUTION_EXECUTOR_OUTCOME_INVALID 暴露；
//    不伪造终态 rejected ack 污染 journal。
// 4. HTTP 请求体不强制 JCS 字节（与 celld /v1/rpc 一致按解析值校验）；replay 的
//    byte-identical 判定按契约备注 #10 以 computeExecutionCommandDigestV1（即 JCS
//    command 字节）为准。持久化文件（control state/journal）强制 JCS 字节权威。
// 5. 错误响应体不携带 celld `version` 词汇（{ok,code,message[,issues]}）；spec 未定义
//    execution endpoint 的错误 envelope 形状。
// 6. outbox 幂等重投影：已 acknowledged 且 ack 相关性一致时不消耗 controlRevision；
//    dead 终态的投影一律 EXECUTION_ACK_PROJECTION_CONFLICT（dead 绝不复活）。
// 7. snapshotHandoffDigest 在本任务内恒为 null（raw-UDS handoff 属 7.3）；journal 校验
//    已允许非空 hex，为 7.3 预留而不放松当前写入路径。
