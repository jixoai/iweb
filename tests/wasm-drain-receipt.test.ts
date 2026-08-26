// 用户原始需求（2026-08-26，add-wasm-runtime 镜像批次 supervisor 半边）：drain receipt
//   生产接线——retiring 台账（Kernel route-CAS 判据的 supervisor 对面）命中且身份 echo
//   一致时，drain 以 DrainReceiptDraftV1 终结，digest 由 wasm-control.ts 在
//   journalRevision 确定后计算并填入 ack.drainReceiptDigest；无法证明（无台账/无记录/
//   计数不可证明）仍诚实拒绝 EXECUTION_DRAIN_RECEIPT_UNAVAILABLE，绝不伪造。
// 正交意图：receipt 权威字段三来源只认台账（routeGeneration/deadlineAt/applicationId
//   不在 ExecutionCommandV1 键集中）；deadline 内 drained / deadline 后 forced-kill 的
//   时序语义；台账建档不变式（authorize_retirement 对位：deadline >= flip、未退休形态、
//   每 drain command 恰一条）；幂等 replay 返回同一 ack。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createExecutionRpcHandler,
	WasmExecutionJournalStore,
	type ExecutionRpcHandler,
	type ExecutionRpcRequestEnvelopeV1,
} from "../supervisor/wasm-control.ts";
import {
	createWasmSupervisorExecutor,
	epochMillisToRfc3339Utc,
	EXECUTION_DRAIN_RECEIPT_UNAVAILABLE,
	WASM_EXECUTION_FENCE_STALE,
	WASM_RETIREMENT_DUPLICATE_COMMAND,
	WASM_RETIREMENT_RECORD_INVALID,
	WasmRetirementLedger,
	type WasmRetirementRecordV1,
	type WasmSupervisorExecutor,
} from "../supervisor/wasm-executor.ts";
import { systemStateStoreIO } from "../supervisor/desired-state.ts";
import {
	computeDrainReceiptDigestV1,
	exampleExecutionCommandV1,
	validateDrainReceiptV1,
	type DrainReceiptV1WithoutDigest,
	type ExecutionCommandV1,
	type ExecutionAcknowledgementV1,
	type WasmExecutionIdentityV1,
} from "../packages/contracts/wasm-execution.ts";

const REQUEST_ID = "018f1e2c-3d4b-7c6d-8e9f-001122334455";
// deadline=30s/flip=0s 的同一时间轴；drained 用 28s，forced-kill 用 31.5s。
const DRAIN_DEADLINE_MILLIS = Date.parse("2026-08-26T00:00:30.000Z");
const DRAIN_FLIP_MILLIS = Date.parse("2026-08-26T00:00:00.000Z");
const NOW_DRAINED = "2026-08-26T00:00:28.000Z";
const NOW_FORCED = "2026-08-26T00:00:31.500Z";

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-drain-"));
}

let commandCounter = 0;

function uuidOf(counter: number): string {
	const sequence = counter.toString(16).padStart(3, "0").slice(-3);
	return "018f1e2c-3d4b-7" + sequence + "-9e01-00112233445" + (counter % 16).toString(16);
}

function command(overrides: Partial<ExecutionCommandV1> = {}): ExecutionCommandV1 {
	commandCounter += 1;
	return { ...exampleExecutionCommandV1(), commandId: uuidOf(commandCounter), expectedJournalRevision: 0, ...overrides };
}

function identityOf(preparationGeneration: number, executionGeneration: number): WasmExecutionIdentityV1 {
	return { ...exampleExecutionCommandV1().identity, preparationGeneration, executionGeneration };
}

function retirementOf(drain: ExecutionCommandV1, overrides: Partial<WasmRetirementRecordV1> = {}): WasmRetirementRecordV1 {
	return {
		drainCommandId: drain.commandId,
		applicationId: "vector",
		execution: drain.identity,
		packageDigest: drain.packageDigest,
		runtimeBinding: drain.runtimeBinding,
		routeGeneration: 4,
		deadlineAtEpochMillis: DRAIN_DEADLINE_MILLIS,
		flipAtEpochMillis: DRAIN_FLIP_MILLIS,
		retired: false,
		acceptedReceiptDigest: null,
		...overrides,
	};
}

interface Harness {
	readonly executor: WasmSupervisorExecutor;
	readonly handler: ExecutionRpcHandler;
	readonly ledger: WasmRetirementLedger;
	readonly deliver: (command: ExecutionCommandV1) => Promise<{ readonly ok: boolean; readonly code?: string; readonly acknowledgement?: ExecutionAcknowledgementV1 }>;
}

function harness(options: { readonly now?: () => string; readonly withLedger?: boolean } = {}): Harness {
	const directory = tempDirectory();
	const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
	const ledger = new WasmRetirementLedger();
	const executor = createWasmSupervisorExecutor({
		journal,
		...(options.withLedger === false ? {} : { retirements: ledger }),
		...(options.now === undefined ? {} : { now: options.now }),
	});
	const handler = createExecutionRpcHandler({ journal, executor, now: () => options.now?.() ?? NOW_DRAINED });
	const deliver = async (body: ExecutionCommandV1) => {
		const envelope: ExecutionRpcRequestEnvelopeV1 = { protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: body } };
		const result = await handler.handle(envelope);
		if (!result.ok) return { ok: false, code: result.code };
		if (result.body.kind === "acknowledgement") return { ok: true, acknowledgement: result.body.acknowledgement };
		return { ok: true };
	};
	return { executor, handler, ledger, deliver };
}

// 独立 oracle：以契约公式复算 receipt digest（不依赖被测生产路径）。
function oracleReceiptDigest(draft: Omit<DrainReceiptV1WithoutDigest, never>): string {
	return computeDrainReceiptDigestV1(draft);
}

describe("drain receipt production: proven path through the retiring ledger", () => {
	test("a ledger-backed drain completes before deadline with a validated drained receipt", async () => {
		const world = harness({ now: () => NOW_DRAINED });
		await world.deliver(command({ operation: "prepare", identity: identityOf(1, 1) }));
		await world.deliver(command({ operation: "start", identity: identityOf(1, 1), expectedJournalRevision: 2 }));
		const drain = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 4 });
		const recorded = world.ledger.record(retirementOf(drain));
		expect(recorded.ok).toBe(true);
		const delivered = await world.deliver(drain);
		expect(delivered.ok).toBe(true);
		const ack = delivered.acknowledgement;
		expect(ack).toBeDefined();
		if (ack === undefined) throw new Error("expected acknowledgement");
		expect(ack.result).toBe("applied");
		expect(ack.failureCode).toBeNull();
		expect(ack.drainReceiptDigest).not.toBeNull();
		// 从 ack 反推完整 receipt：journalRevision 是 completion 落盘时分配的。
		const receiptWithoutDigest: DrainReceiptV1WithoutDigest = {
			schemaVersion: 1,
			commandId: drain.commandId,
			applicationId: "vector",
			execution: drain.identity,
			packageDigest: drain.packageDigest,
			runtimeBinding: drain.runtimeBinding,
			routeGeneration: 4,
			drainedRequestCount: 0,
			deadlineAt: epochMillisToRfc3339Utc(DRAIN_DEADLINE_MILLIS),
			forcedKillAt: null,
			result: "drained",
			completedAt: NOW_DRAINED,
			journalRevision: ack.journalRevision,
		};
		// deadlineAt 与 retiring 记录的 epoch 毫秒精确往返。
		expect(Date.parse(receiptWithoutDigest.deadlineAt)).toBe(DRAIN_DEADLINE_MILLIS);
		expect(oracleReceiptDigest(receiptWithoutDigest)).toBe(ack.drainReceiptDigest);
		// 完整 receipt 通过契约校验（digest 复算 + forcedKillAt 耦合）。
		expect(validateDrainReceiptV1({ ...receiptWithoutDigest, receiptDigest: ack.drainReceiptDigest ?? "" }).ok).toBe(true);
		// drained：supervisor 侧子状态保持 retiring（停止由 stop/Kernel 投影驱动）。
		expect(world.executor.fence.findByIdentity(identityOf(1, 1))?.substate).toBe("retiring");
		// 幂等：byte-identical replay 返回同一 ack（同一 receipt digest）。
		const replay = await world.handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "replay", command: drain } });
		expect(replay.ok).toBe(true);
		if (replay.ok && replay.body.kind === "acknowledgement") {
			expect(replay.body.acknowledgement.drainReceiptDigest).toBe(ack.drainReceiptDigest);
			expect(replay.body.acknowledgement.journalRevision).toBe(ack.journalRevision);
		}
	});

	test("a drain completing after deadline records forced-kill and stops the execution", async () => {
		const world = harness({ now: () => NOW_FORCED });
		await world.deliver(command({ operation: "prepare", identity: identityOf(1, 1) }));
		await world.deliver(command({ operation: "start", identity: identityOf(1, 1), expectedJournalRevision: 2 }));
		const drain = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 4 });
		expect(world.ledger.record(retirementOf(drain)).ok).toBe(true);
		const delivered = await world.deliver(drain);
		expect(delivered.ok).toBe(true);
		const ack = delivered.acknowledgement;
		if (ack === undefined) throw new Error("expected acknowledgement");
		expect(ack.result).toBe("applied");
		const receiptWithoutDigest: DrainReceiptV1WithoutDigest = {
			schemaVersion: 1,
			commandId: drain.commandId,
			applicationId: "vector",
			execution: drain.identity,
			packageDigest: drain.packageDigest,
			runtimeBinding: drain.runtimeBinding,
			routeGeneration: 4,
			drainedRequestCount: 0,
			deadlineAt: epochMillisToRfc3339Utc(DRAIN_DEADLINE_MILLIS),
			forcedKillAt: NOW_FORCED,
			result: "forced-kill",
			completedAt: NOW_FORCED,
			journalRevision: ack.journalRevision,
		};
		// forcedKillAt >= deadlineAt；digest 可由契约公式独立复算。
		expect(Date.parse(NOW_FORCED)).toBeGreaterThan(DRAIN_DEADLINE_MILLIS);
		expect(oracleReceiptDigest(receiptWithoutDigest)).toBe(ack.drainReceiptDigest);
		expect(validateDrainReceiptV1({ ...receiptWithoutDigest, receiptDigest: ack.drainReceiptDigest ?? "" }).ok).toBe(true);
		// forced-kill 的 supervisor 侧效应：该 execution 置为 stopped。
		expect(world.executor.fence.findByIdentity(identityOf(1, 1))?.substate).toBe("stopped");
	});

	test("the receipt counter source is injectable and unprovable counts refuse the receipt", async () => {
		const directory = tempDirectory();
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
		const ledger = new WasmRetirementLedger();
		const executor = createWasmSupervisorExecutor({
			journal,
			retirements: ledger,
			now: () => NOW_DRAINED,
			drainCounterSource: () => 7,
		});
		const handler = createExecutionRpcHandler({ journal, executor, now: () => NOW_DRAINED });
		// 经 handler 投递 prepare（journal 落盘，供后续 executor 重建 fence）。
		await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) } });
		const drain = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 2 });
		ledger.record(retirementOf(drain));
		const outcome = await executor.execute(drain);
		expect(outcome.result).toBe("applied");
		if (outcome.drainReceiptDraft === null) throw new Error("expected receipt draft");
		expect(outcome.drainReceiptDraft.drainedRequestCount).toBe(7);
		// 不可证明的计数（非安全整数）→ 同 fence 上的另一 drain 命令也拒绝，绝不伪造 receipt。
		const brokenCounter = createWasmSupervisorExecutor({
			journal,
			retirements: ledger,
			now: () => NOW_DRAINED,
			drainCounterSource: () => Number.NaN,
		});
		const other = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 2 });
		ledger.record(retirementOf(other));
		const refused = await brokenCounter.execute(other);
		expect(refused.result).toBe("rejected");
		expect(refused.failureCode).toBe(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
	});
});

describe("drain receipt production: unprovable and mismatched paths stay rejected", () => {
	test("without a ledger the drain stays the conservative rejection", async () => {
		const world = harness({ now: () => NOW_DRAINED, withLedger: false });
		await world.deliver(command({ operation: "prepare", identity: identityOf(1, 1) }));
		const drain = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 2 });
		const outcome = await world.deliver(drain);
		expect(outcome.ok).toBe(true);
		const ack = outcome.acknowledgement;
		if (ack === undefined) throw new Error("expected acknowledgement");
		expect(ack.result).toBe("rejected");
		expect(ack.failureCode).toBe(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
		expect(ack.drainReceiptDigest).toBeNull();
	});

	test("an empty ledger is equally unprovable", async () => {
		const world = harness({ now: () => NOW_DRAINED });
		await world.deliver(command({ operation: "prepare", identity: identityOf(1, 1) }));
		const drain = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 2 });
		const outcome = await world.executor.execute(drain);
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
	});

	test("a retiring record naming another execution or binding is a fence violation", async () => {
		const world = harness({ now: () => NOW_DRAINED });
		await world.deliver(command({ operation: "prepare", identity: identityOf(1, 1) }));
		const drain = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 2 });
		// 记录的 execution 是 (1,2)：命令 (1,1) 与判据不符 → stale，绝不产出 receipt。
		expect(world.ledger.record(retirementOf(drain, { execution: identityOf(1, 2) })).ok).toBe(true);
		const mismatched = await world.executor.execute(drain);
		expect(mismatched.result).toBe("rejected");
		expect(mismatched.failureCode).toBe(WASM_EXECUTION_FENCE_STALE);
		// 同样拒绝 binding 不一致的记录。
		const rebinding = command({ operation: "drain", identity: identityOf(1, 1), expectedJournalRevision: 3 });
		expect(world.ledger.record(retirementOf(rebinding, { runtimeBinding: { ...rebinding.runtimeBinding, catalogRevision: 10 } })).ok).toBe(true);
		const rebound = await world.executor.execute(rebinding);
		expect(rebound.result).toBe("rejected");
		expect(rebound.failureCode).toBe(WASM_EXECUTION_FENCE_STALE);
		// 从未采纳的 tuple 即使有台账记录也仍是 stale（台账不越过 fence）。
		const unknown = command({ operation: "drain", identity: identityOf(3, 3) });
		expect(world.ledger.record(retirementOf(unknown)).ok).toBe(true);
		const unknownOutcome = await world.executor.execute(unknown);
		expect(unknownOutcome.failureCode).toBe(WASM_EXECUTION_FENCE_STALE);
	});
});

describe("retiring ledger: authorize_retirement creation invariants (TS counterpart)", () => {
	test("valid records are accepted once per drain command", () => {
		const ledger = new WasmRetirementLedger();
		const drain = command({ operation: "drain", identity: identityOf(1, 1) });
		const first = ledger.record(retirementOf(drain));
		expect(first.ok).toBe(true);
		const duplicate = ledger.record(retirementOf(drain));
		expect(duplicate.ok).toBe(false);
		if (!duplicate.ok) expect(duplicate.errors[0]?.code).toBe(WASM_RETIREMENT_DUPLICATE_COMMAND);
	});

	test("deadline before flip, projected shapes, and unknown fields are rejected", () => {
		const ledger = new WasmRetirementLedger();
		const drain = command({ operation: "drain", identity: identityOf(1, 1) });
		// deadline 早于翻转为结构性非法。
		const early = ledger.record(retirementOf(drain, { deadlineAtEpochMillis: DRAIN_FLIP_MILLIS - 1 }));
		expect(early.ok).toBe(false);
		if (!early.ok) expect(early.errors[0]?.code).toBe(WASM_RETIREMENT_RECORD_INVALID);
		// 已退休/已接受 receipt 的形态不得建档（投影是 Kernel 权威）。
		expect(ledger.record(retirementOf(drain, { retired: true })).ok).toBe(false);
		expect(ledger.record(retirementOf(drain, { acceptedReceiptDigest: "f".repeat(64) })).ok).toBe(false);
		// 未知字段/缺失字段/非 u53 epoch/非法 commandId。
		const withUnknown = retirementOf(drain) as unknown as Record<string, unknown>;
		withUnknown.image = "localhost/evil:latest";
		expect(ledger.record(withUnknown).ok).toBe(false);
		const missing = retirementOf(drain) as unknown as Record<string, unknown>;
		delete missing.routeGeneration;
		expect(ledger.record(missing).ok).toBe(false);
		expect(ledger.record(retirementOf(drain, { deadlineAtEpochMillis: 1.5 })).ok).toBe(false);
		expect(ledger.record(retirementOf(drain, { drainCommandId: "not-a-uuid" })).ok).toBe(false);
		// find 只认精确 drainCommandId。
		expect(ledger.find(drain.commandId)).toBeNull();
	});
});
