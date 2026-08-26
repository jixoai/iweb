// 用户原始需求（2026-08-26，add-wasm-runtime 任务 2.1/2.2）：supervisor 执行器与双 generation
//   fence——幂等 execution command 消费、P/E 采纳推进、失败保持 received-incomplete、
//   journal 完成而 Kernel projection 失败时的 replay 语义、旧 execution 的 stale 拒绝
//   与 drain/stop 围栏。
// 正交意图：断言稳定错误码与 fence 子状态；以 commandDigest 幂等（同命令重复投递唯一
//   结果）；readiness/health v2 与 metrics correlate 的三层判定（wire → 当前 tuple 精确
//   比对 → 全字段 correlate）；supervisor 重启后从 journal 重建 fence。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createExecutionRpcHandler,
	EXECUTION_COMMAND_ID_CONFLICT,
	EXECUTION_EXECUTOR_FAILED,
	WasmExecutionJournalStore,
	type ExecutionRpcHandler,
	type WasmExecutionExecutor,
} from "../supervisor/wasm-control.ts";
import {
	acceptsNewTraffic,
	correlateEngineMetrics,
	correlateReadinessHealthV2,
	createWasmSupervisorExecutor,
	EXECUTION_DRAIN_RECEIPT_UNAVAILABLE,
	WASM_EXECUTION_FENCE_STALE,
	WASM_EXECUTION_NOT_PREPARED,
	type WasmSupervisorExecutor,
} from "../supervisor/wasm-executor.ts";
import { systemStateStoreIO } from "../supervisor/desired-state.ts";
import {
	exampleExecutionCommandV1,
	type ExecutionCommandV1,
	type ExecutionRpcRequestBodyV1,
	type ExecutionRpcRequestEnvelopeV1,
	type WasmExecutionIdentityV1,
} from "../packages/contracts/wasm-execution.ts";
import { exampleWasmEngineMetricsV1, exampleWasmReadinessHealthV2 } from "../packages/contracts/wasm-health.ts";

const REQUEST_ID = "018f1e2c-3d4b-7c6d-8e9f-001122334455";
const FIXED_NOW = "2026-08-26T00:00:00.000Z";

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-executor-"));
}

let commandCounter = 0;

function command(overrides: Partial<ExecutionCommandV1> = {}): ExecutionCommandV1 {
	commandCounter += 1;
	const base = exampleExecutionCommandV1();
	return {
		...base,
		commandId: uuidOf(commandCounter),
		expectedJournalRevision: 0,
		...overrides,
	};
}

// 确定性 UUIDv7（文法合法：version nibble 7、variant 9；计数器落在 clock_seq 与尾 nibble）。
function uuidOf(counter: number): string {
	const sequence = counter.toString(16).padStart(3, "0").slice(-3);
	return "018f1e2c-3d4b-7" + sequence + "-9e01-00112233445" + (counter % 16).toString(16);
}

function identityOf(preparationGeneration: number, executionGeneration: number, sandboxId = "sbx-vector"): WasmExecutionIdentityV1 {
	return { ...exampleExecutionCommandV1().identity, sandboxId, preparationGeneration, executionGeneration };
}

interface Harness {
	readonly directory: string;
	readonly journal: WasmExecutionJournalStore;
	readonly executor: WasmSupervisorExecutor;
	readonly handler: ExecutionRpcHandler;
	readonly deliver: (body: ExecutionRpcRequestBodyV1) => Promise<{ readonly ok: boolean; readonly status?: number; readonly code?: string; readonly acknowledgement?: { result: string; failureCode: string | null; journalRevision: number } }>;
}

function harness(wrapExecutor?: (executor: WasmExecutionExecutor) => WasmExecutionExecutor): Harness {
	const directory = tempDirectory();
	const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
	const executor = createWasmSupervisorExecutor({ journal });
	const wired = wrapExecutor === undefined ? executor : wrapExecutor(executor);
	const handler = createExecutionRpcHandler({ journal, executor: wired, now: () => FIXED_NOW });
	const deliver = async (body: ExecutionRpcRequestBodyV1) => {
		const envelope: ExecutionRpcRequestEnvelopeV1 = { protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body };
		const result = await handler.handle(envelope);
		if (!result.ok) return { ok: false, status: result.status, code: result.code };
		if (result.body.kind === "acknowledgement") {
			const ack = result.body.acknowledgement;
			return { ok: true, acknowledgement: { result: ack.result, failureCode: ack.failureCode, journalRevision: ack.journalRevision } };
		}
		return { ok: true };
	};
	return { directory, journal, executor, handler, deliver };
}

describe("supervisor executor: dual-generation fence adoption (2.2)", () => {
	test("prepare adopts the Kernel-allocated tuple and produces an applied acknowledgement", async () => {
		const world = harness();
		const outcome = await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		expect(outcome.ok).toBe(true);
		expect(outcome.acknowledgement?.result).toBe("applied");
		expect(outcome.acknowledgement?.journalRevision).toBe(2);
		const current = world.executor.fence.current("sbx-vector");
		expect(current?.identity.preparationGeneration).toBe(1);
		expect(current?.identity.executionGeneration).toBe(1);
		expect(current?.substate).toBe("prepared");
	});

	test("start requires a preparation and advances through restarts monotonically", async () => {
		const world = harness();
		// 无 preparation 的 spawn：拒绝，不产生任何 fence 记录。
		const unfenced = await world.executor.execute(command({ operation: "start", identity: identityOf(1, 1, "sbx-other") }));
		expect(unfenced.result).toBe("rejected");
		expect(unfenced.failureCode).toBe(WASM_EXECUTION_NOT_PREPARED);
		expect(world.executor.fence.current("sbx-other")).toBeNull();
		// 正常序列：prepare(1,1) → start(1,1) → restart start(1,2)。
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		const started = await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 1), expectedJournalRevision: 2 }) });
		expect(started.acknowledgement?.result).toBe("applied");
		expect(world.executor.fence.current("sbx-vector")?.substate).toBe("running");
		const restarted = await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 2), expectedJournalRevision: 4 }) });
		expect(restarted.acknowledgement?.result).toBe("applied");
		expect(world.executor.fence.current("sbx-vector")?.identity.executionGeneration).toBe(2);
		// 回退分配（旧 tuple 的 prepare）是 stale：绝不把旧代次当新 preparation。
		const regression = await world.executor.execute(command({ operation: "prepare", identity: identityOf(1, 1) }));
		expect(regression.result).toBe("rejected");
		expect(regression.failureCode).toBe(WASM_EXECUTION_FENCE_STALE);
		expect(world.executor.fence.current("sbx-vector")?.identity.preparationGeneration).toBe(1);
	});

	test("same-tuple start with a differing binding or snapshot field is a fence violation", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		const rebinding = command({ operation: "start", identity: identityOf(1, 1), expectedJournalRevision: 2 });
		const outcome = await world.executor.execute({
			...rebinding,
			runtimeBinding: { ...rebinding.runtimeBinding, catalogRevision: 10 },
		});
		expect(outcome.result).toBe("rejected");
		expect(outcome.failureCode).toBe(WASM_EXECUTION_FENCE_STALE);
	});

	test("same command digest is idempotent: repeated delivery returns one stored result", async () => {
		const world = harness();
		const prepare = command({ operation: "prepare", identity: identityOf(1, 1) });
		const first = await world.deliver({ kind: "command", command: prepare });
		const replayed = await world.deliver({ kind: "replay", command: prepare });
		expect(first.ok).toBe(true);
		expect(replayed.ok).toBe(true);
		expect(replayed.acknowledgement?.journalRevision).toBe(first.acknowledgement?.journalRevision);
		// 已知 commandId 携带不同命令体 → EXECUTION_COMMAND_ID_CONFLICT，零副作用。
		const conflict = await world.deliver({ kind: "command", command: { ...prepare, secretRevision: 4 } });
		expect(conflict.ok).toBe(false);
		expect(conflict.code).toBe(EXECUTION_COMMAND_ID_CONFLICT);
	});
});

describe("supervisor executor: failure keeps received-incomplete and replay resumes (2.1)", () => {
	test("executor failure leaves the command received-incomplete; replay after recovery completes it once", async () => {
		let failing = true;
		const world = harness((executor) => ({
			execute: async (received: ExecutionCommandV1) => {
				if (failing) throw new Error("simulated executor crash");
				return executor.execute(received);
			},
		}));
		const prepare = command({ operation: "prepare", identity: identityOf(1, 1) });
		const failed = await world.deliver({ kind: "command", command: prepare });
		expect(failed.ok).toBe(false);
		expect(failed.status).toBe(500);
		expect(failed.code).toBe(EXECUTION_EXECUTOR_FAILED);
		// journal 只有 received（query → status received），无 completion。
		const queried = await world.journal.find(prepare.commandId);
		expect(queried.completed).toBeNull();
		expect(queried.received).not.toBeNull();
		// 恢复后 byte-identical replay 续跑并完成（唯一 completion）。
		failing = false;
		const resumed = await world.deliver({ kind: "replay", command: prepare });
		expect(resumed.ok).toBe(true);
		expect(resumed.acknowledgement?.result).toBe("applied");
		expect(resumed.acknowledgement?.journalRevision).toBe(2);
		const after = await world.journal.find(prepare.commandId);
		expect(after.completed?.acknowledgement.result).toBe("applied");
	});

	test("expectedJournalRevision must match the journal head for a new command", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		const staleHead = await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 1), expectedJournalRevision: 0 }) });
		expect(staleHead.ok).toBe(false);
		expect(staleHead.code).toBe("JOURNAL_REVISION_CONFLICT");
	});
});

describe("supervisor executor: readiness/health v2 and metrics correlate wiring (2.2)", () => {
	test("old execution signals are stale; current tuple matches; binding mismatch is not adoption", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 2), expectedJournalRevision: 2 }) });
		// 旧 execution（E=1）的健康信号：stale 拒绝，绝不签发/采纳 lease。
		const oldHealth = correlateReadinessHealthV2(world.executor.fence, "sbx-vector", { ...exampleWasmReadinessHealthV2(), executionGeneration: 1 });
		expect(oldHealth.ok).toBe(false);
		if (!oldHealth.ok) {
			expect(oldHealth.stale).toBe(true);
			expect(oldHealth.code).toBe(WASM_EXECUTION_FENCE_STALE);
		}
		// 当前 execution（E=2）：全字段一致 → 采纳。
		const currentHealth = correlateReadinessHealthV2(world.executor.fence, "sbx-vector", { ...exampleWasmReadinessHealthV2(), executionGeneration: 2 });
		expect(currentHealth.ok).toBe(true);
		// 当前 tuple 但 binding 漂移：mismatch（非 stale），同样不采纳。
		const rebinding = correlateReadinessHealthV2(world.executor.fence, "sbx-vector", {
			...exampleWasmReadinessHealthV2(),
			executionGeneration: 2,
			runtimeBinding: { ...exampleWasmReadinessHealthV2().runtimeBinding, entryKey: "other-wasmd" },
		});
		expect(rebinding.ok).toBe(false);
		if (!rebinding.ok) {
			expect(rebinding.stale).toBe(false);
			expect(rebinding.code).toBe("WASM_READINESS_HEALTH_MISMATCH");
		}
		// metrics 同律：旧 E 的延迟样本是 stale，不是 reset；当前样本采纳。
		const oldMetrics = correlateEngineMetrics(world.executor.fence, "sbx-vector", { ...exampleWasmEngineMetricsV1(), executionGeneration: 1 });
		expect(oldMetrics.ok).toBe(false);
		if (!oldMetrics.ok) expect(oldMetrics.stale).toBe(true);
		const currentMetrics = correlateEngineMetrics(world.executor.fence, "sbx-vector", { ...exampleWasmEngineMetricsV1(), executionGeneration: 2 });
		expect(currentMetrics.ok).toBe(true);
		// 未知 sandbox：无当前 execution → stale 拒绝路径。
		const unknown = correlateEngineMetrics(world.executor.fence, "sbx-none", exampleWasmEngineMetricsV1());
		expect(unknown.ok).toBe(false);
		if (!unknown.ok) expect(unknown.stale).toBe(true);
	});

	test("an old execution may drain and stop but never accepts new traffic", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 2), expectedJournalRevision: 2 }) });
		// active pointer 已由 Kernel 切到 (1,2)：旧 execution (1,1) 不接新流量。
		expect(acceptsNewTraffic(world.executor.fence, identityOf(1, 1))).toBe(false);
		expect(acceptsNewTraffic(world.executor.fence, identityOf(1, 2))).toBe(true);
		// drain 旧 execution：fence 接受（标记 retiring），ack 以 rejected + 受限码终结
		//（DrainReceiptV1 wire 属 7.6；绝不伪造 digest）。
		const drain = await world.executor.execute(command({ operation: "drain", identity: identityOf(1, 1) }));
		expect(drain.result).toBe("rejected");
		expect(drain.failureCode).toBe(EXECUTION_DRAIN_RECEIPT_UNAVAILABLE);
		expect(world.executor.fence.findByIdentity(identityOf(1, 1))?.substate).toBe("retiring");
		// retiring 不接新流量，也不作为当前 execution 报告。
		expect(acceptsNewTraffic(world.executor.fence, identityOf(1, 1))).toBe(false);
		// 从未接受的 tuple 一律 stale。
		const unknownDrain = await world.executor.execute(command({ operation: "drain", identity: identityOf(3, 3) }));
		expect(unknownDrain.failureCode).toBe(WASM_EXECUTION_FENCE_STALE);
		// stop 旧 execution：applied（stop 无需 receipt）。
		const stop = await world.executor.execute(command({ operation: "stop", identity: identityOf(1, 1) }));
		expect(stop.result).toBe("applied");
		expect(world.executor.fence.findByIdentity(identityOf(1, 1))?.substate).toBe("stopped");
		// stop 当前 execution 后同样不接新流量。
		await world.executor.execute(command({ operation: "stop", identity: identityOf(1, 2) }));
		expect(acceptsNewTraffic(world.executor.fence, identityOf(1, 2))).toBe(false);
	});
});

describe("supervisor executor: restart rebuild from the journal (2.1/2.2)", () => {
	test("a fresh executor over the same journal rebuilds the fence and keeps stale rejections", async () => {
		const directory = tempDirectory();
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
		const first = createWasmSupervisorExecutor({ journal });
		const prepare = command({ operation: "prepare", identity: identityOf(1, 1) });
		const handler = createExecutionRpcHandler({ journal, executor: first, now: () => FIXED_NOW });
		await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: prepare } });
		const restart = command({ operation: "start", identity: identityOf(1, 2), expectedJournalRevision: 2 });
		await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body: { kind: "command", command: restart } });
		// supervisor 重启：新 executor 实例从 journal 条目重建 fence 状态。
		const rebuilt = createWasmSupervisorExecutor({ journal: new WasmExecutionJournalStore(systemStateStoreIO, directory) });
		const current = rebuilt.fence.current("sbx-vector");
		expect(current?.identity.executionGeneration).toBe(2);
		expect(current?.substate).toBe("running");
		// 旧 execution 信号在重建后的 fence 上同样 stale。
		const oldHealth = correlateReadinessHealthV2(rebuilt.fence, "sbx-vector", exampleWasmReadinessHealthV2());
		expect(oldHealth.ok).toBe(false);
		if (!oldHealth.ok) expect(oldHealth.stale).toBe(true);
		const currentHealth = correlateReadinessHealthV2(rebuilt.fence, "sbx-vector", { ...exampleWasmReadinessHealthV2(), executionGeneration: 2 });
		expect(currentHealth.ok).toBe(true);
		// 重建后的幂等：同 digest 命令返回同一结果，不重复采纳。
		const again = await rebuilt.execute(prepare);
		expect(again.result).toBe("applied");
		expect(rebuilt.fence.current("sbx-vector")?.identity.executionGeneration).toBe(2);
	});
});
