// 用户原始需求（2026-08-28，add-wasm-host-services 终审缺口项 3）：execution 投递通道的
//   并发 replay / response-lost / restart recovery 语义必须有直接电池——
//   1. 并发相同命令键（execution 通道的 at-most-once 键是 commandId；host-call 侧对应
//      (identity, service, method, requestId)，本电池映射为 commandId × operation × identity）：
//      同 payload 并发投递 → 幂等返回同一 ack、副作用恰一次；异 payload 并发投递 → conflict；
//   2. response-lost 后重发：Kernel 未收到响应重发字节相同命令 → journal 回放存档 ack，
//      executor 不再执行（副作用恰一次）；
//   3. 命令键复用拒绝：同 commandId 跨 operation（prepare/start/drain/stop——method 对位）
//      与跨 identity（sandboxId/代次——service/身份对位）一律 EXECUTION_COMMAND_ID_CONFLICT，
//      零 journal 写入；envelope 级 requestId 只是关联键，复用合法（边界文档化）；
//   4. 进程重启后 replay 表恢复：新 handler/executor 实例只认磁盘 journal——已完成命令
//      回放存档 ack 且零执行，journal head 续用。
// 判定语义全部复用 supervisor/wasm-control.ts 与 contracts 纯函数，不在测试里造第二套比对。
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createExecutionRpcHandler,
	EXECUTION_COMMAND_ID_CONFLICT,
	WasmExecutionJournalStore,
	WASM_EXECUTION_JOURNAL_FILENAME,
	type ExecutionRpcHandler,
	type WasmExecutionExecutor,
	type WasmExecutionOutcome,
} from "../supervisor/wasm-control.ts";
import { startSupervisorServer, type RunningSupervisorServer } from "../supervisor/server.ts";
import {
	computeExecutionCommandDigest,
	correlateExecutionRpcResponse,
	exampleExecutionCommand,
	type ExecutionCommand,
	validateExecutionRpcResponseEnvelopeV1,
	type ExecutionAcknowledgement,
	type ExecutionRpcRequestEnvelopeV1,
} from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";
import { systemStateStoreIO } from "../supervisor/desired-state.ts";

const FIXED_NOW = "2026-08-28T00:00:00.000Z";
const APPLIED: WasmExecutionOutcome = { result: "applied", failureCode: null, drainReceiptDraft: null };

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-replay-"));
}

function command(overrides: Partial<ExecutionCommand> = {}): ExecutionCommand {
	return { ...exampleExecutionCommand(), expectedJournalRevision: 0, ...overrides };
}

function commandEnvelope(body: ExecutionCommand, requestId: string): ExecutionRpcRequestEnvelopeV1 {
	return { protocol: "iweb-execution-rpc-v1", requestId, body: { kind: "command", command: body } };
}

function replayEnvelope(body: ExecutionCommand, requestId: string): ExecutionRpcRequestEnvelopeV1 {
	return { protocol: "iweb-execution-rpc-v1", requestId, body: { kind: "replay", command: body } };
}

function countingExecutor(outcome: WasmExecutionOutcome = APPLIED): { executor: WasmExecutionExecutor; calls: ExecutionCommand[] } {
	const calls: ExecutionCommand[] = [];
	return {
		calls,
		executor: {
			execute: async (input) => {
				calls.push(input);
				return outcome;
			},
		},
	};
}

function handler(directory: string, executor: WasmExecutionExecutor): ExecutionRpcHandler {
	return createExecutionRpcHandler({ journal: new WasmExecutionJournalStore(systemStateStoreIO, directory), executor, now: () => FIXED_NOW });
}

function journalPath(directory: string): string {
	return join(directory, WASM_EXECUTION_JOURNAL_FILENAME);
}

function jcsBytesOf(value: unknown): Buffer {
	return Buffer.from(jcsCanonicalBytes(value));
}

function acknowledgementOf(result: { readonly status: number; readonly body: string }): ExecutionAcknowledgement {
	const parsed = validateExecutionRpcResponseEnvelopeV1(JSON.parse(result.body));
	expect(parsed.ok).toBe(true);
	if (!parsed.ok) throw new Error("expected a valid response envelope");
	expect(parsed.value.body.kind).toBe("acknowledgement");
	if (parsed.value.body.kind !== "acknowledgement") throw new Error("expected an acknowledgement body");
	return parsed.value.body.acknowledgement;
}

function post(socketPath: string, body: unknown): Promise<{ readonly status: number; readonly body: string }> {
	const payload = JSON.stringify(body);
	return new Promise((resolve, reject) => {
		const value = request(
			{ socketPath, method: "POST", path: "/v1/execution-rpc", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } },
			(response) => {
				let data = "";
				response.setEncoding("utf8");
				response.on("data", (chunk: string) => (data += chunk));
				response.on("end", () => resolve({ status: response.statusCode ?? 0, body: data }));
			},
		);
		value.once("error", reject);
		value.write(payload);
		value.end();
	});
}

// ---------------------------------------------------------------------------
// 并发相同命令键（同 payload → 幂等返回、异 payload → conflict）
// ---------------------------------------------------------------------------

describe("concurrent identical command delivery has exactly one outcome", () => {
	test("five in-process deliveries of the same command return the same ack with one execution", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const body = command();
		const results = await Promise.all([
			rpc.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000001")),
			rpc.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000002")),
			rpc.handle(replayEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000003")),
			rpc.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000004")),
			rpc.handle(replayEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000005")),
		]);
		for (const result of results) expect(result.ok).toBe(true);
		expect(calls.length).toBe(1);
		const acknowledgements = results.map((result) => (result.ok && result.body.kind === "acknowledgement" ? result.body.acknowledgement : null));
		for (const acknowledgement of acknowledgements) {
			expect(acknowledgement).not.toBeNull();
			expect(jcsBytesOf(acknowledgement).equals(jcsBytesOf(acknowledgements[0]))).toBe(true);
		}
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory).read();
		expect(journal.entries.map((entry) => entry.kind)).toEqual(["command-received", "completed"]);
		expect(journal.journalRevision).toBe(2);
	});

	test("two concurrent HTTP posts of the same command both receive the identical stored ack", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		let executions = 0;
		const executor: WasmExecutionExecutor = {
			execute: async () => {
				executions += 1;
				// 拉宽竞态窗口：第二个投递必然落在 in-flight 窗口内。
				await new Promise((resolve) => setTimeout(resolve, 25));
				return APPLIED;
			},
		};
		const running: RunningSupervisorServer = await startSupervisorServer({ socketPath, executionRpc: handler(directory, executor) });
		try {
			const body = command();
			const envelope = commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000011");
			const responses = await Promise.all(
				Array.from({ length: 8 }, (_, index) =>
					post(socketPath, index % 2 === 0 ? envelope : replayEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a0000000" + (12 + index))),
				),
			);
			for (const response of responses) expect(response.status).toBe(200);
			expect(executions).toBe(1);
			// envelope requestId 是关联键（合法复用），响应体只在该字段回显上不同；
			// at-most-once 语义要求 acknowledgement 部分逐字节一致。
			const acknowledgements = responses.map((response) => acknowledgementOf(response));
			for (const acknowledgement of acknowledgements) {
				expect(jcsBytesOf(acknowledgement).equals(jcsBytesOf(acknowledgements[0]))).toBe(true);
			}
			const parsed = validateExecutionRpcResponseEnvelopeV1(JSON.parse(responses[0]!.body));
			expect(parsed.ok).toBe(true);
			if (parsed.ok) expect(correlateExecutionRpcResponse(envelope, parsed.value).ok).toBe(true);
		} finally {
			await running.close();
		}
	});

	test("a duplicate joining an in-flight delivery (gated executor) never re-executes", async () => {
		const directory = tempDirectory();
		const body = command();
		let release: (() => void) | null = null;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		let executions = 0;
		const executor: WasmExecutionExecutor = {
			execute: async (input) => {
				executions += 1;
				await gate;
				return APPLIED;
			},
		};
		const rpc = handler(directory, executor);
		const first = rpc.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000021"));
		// 轮询等待第一个投递真正进入 executor（in-flight 窗口打开）。
		await new Promise<void>((resolve) => {
			const check = () => (executions === 1 ? resolve() : setTimeout(check, 1));
			check();
		});
		const second = rpc.handle(replayEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000022"));
		(release as unknown as () => void)();
		const [firstResult, secondResult] = await Promise.all([first, second]);
		expect(firstResult.ok).toBe(true);
		expect(secondResult.ok).toBe(true);
		expect(executions).toBe(1);
		if (firstResult.ok && secondResult.ok) {
			expect(jcsBytesOf(secondResult).equals(jcsBytesOf(firstResult))).toBe(true);
		}
	});

	test("an in-flight replay of an unknown command does not absorb a same-tick first command delivery", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const body = command();
		// 同一 tick 内：replay（journal 尚不认识 → 404）与首次 command 投递并发。
		const [replayFirst, commandSecond] = await Promise.all([
			rpc.handle(replayEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000091")),
			rpc.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000092")),
		]);
		expect(replayFirst.ok).toBe(false);
		if (!replayFirst.ok) expect(replayFirst.code).toBe("EXECUTION_COMMAND_UNKNOWN");
		expect(commandSecond.ok).toBe(true);
		expect(calls.length).toBe(1);
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory).read();
		expect(journal.entries.map((entry) => entry.kind)).toEqual(["command-received", "completed"]);
	});

	test("a concurrent delivery with a differing payload under the same commandId is a conflict with zero writes", async () => {
		const directory = tempDirectory();
		const body = command();
		let release: (() => void) | null = null;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		let executions = 0;
		const executor: WasmExecutionExecutor = {
			execute: async () => {
				executions += 1;
				await gate;
				return APPLIED;
			},
		};
		const rpc = handler(directory, executor);
		const first = rpc.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000031"));
		await new Promise<void>((resolve) => {
			const check = () => (executions === 1 ? resolve() : setTimeout(check, 1));
			check();
		});
		const differing = rpc.handle(commandEnvelope(command({ secretValuesDigest: "f".repeat(64) }), "018f1e2c-3d4b-7c6d-8e9f-00a000000032"));
		(release as unknown as () => void)();
		const [firstResult, differingResult] = await Promise.all([first, differing]);
		expect(firstResult.ok).toBe(true);
		expect(differingResult.ok).toBe(false);
		if (!differingResult.ok) expect(differingResult.code).toBe(EXECUTION_COMMAND_ID_CONFLICT);
		expect(executions).toBe(1);
		// 冲突零写入：journal 只有第一条命令的 received/completed。
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory).read();
		expect(journal.entries.length).toBe(2);
		expect(journal.entries[0]?.commandDigest).toBe(computeExecutionCommandDigest(body));
	});
});

// ---------------------------------------------------------------------------
// response-lost 后重发（副作用恰一次）
// ---------------------------------------------------------------------------

describe("response-lost redelivery performs the side effect exactly once", () => {
	test("reposting a command whose response was lost replays the stored ack without re-execution", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const { executor, calls } = countingExecutor();
		const running = await startSupervisorServer({ socketPath, executionRpc: handler(directory, executor) });
		try {
			const body = command();
			const envelope = commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000041");
			// 响应“丢失”：投递但不解析（副作用与 journal 落盘已完成）。
			const lost = await post(socketPath, envelope);
			expect(lost.status).toBe(200);
			const journalBytesAfterFirst = readFileSync(journalPath(directory), "utf8");
			// Kernel 重发：command 与 replay 两种 envelope 混合，多个 requestId。
			const resendings = [
				commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000042"),
				replayEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000043"),
				commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000044"),
			];
			const results = await Promise.all(resendings.map((entry) => post(socketPath, entry)));
			for (const result of results) expect(result.status).toBe(200);
			expect(calls.length).toBe(1);
			const firstAck = acknowledgementOf(lost);
			for (const result of results) {
				const ack = acknowledgementOf(result);
				expect(jcsBytesOf(ack).equals(jcsBytesOf(firstAck))).toBe(true);
			}
			// journal 字节在首响应后不再变化（零追加、零改写）。
			expect(readFileSync(journalPath(directory), "utf8")).toBe(journalBytesAfterFirst);
		} finally {
			await running.close();
		}
	});
});

// ---------------------------------------------------------------------------
// 命令键跨 operation/跨 identity 复用拒绝（method/service 对位）
// ---------------------------------------------------------------------------

describe("commandId reuse across operations and identities is refused", () => {
	test("the same commandId under a different operation or identity is a conflict with zero journal writes", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const firstCommandId = command().commandId;
		const original = await rpc.handle(commandEnvelope(command(), "018f1e2c-3d4b-7c6d-8e9f-00a000000051"));
		expect(original.ok).toBe(true);
		const journalBytes = readFileSync(journalPath(directory), "utf8");
		// 跨 operation（host-call「跨 method」对位）：prepare 命令键复用为 start/drain/stop。
		const operationReuses = (["start", "drain", "stop"] as const).map((operation) =>
			command({ operation }),
		);
		// 跨 identity（host-call「跨 service/身份」对位）：不同 sandbox、不同代次、不同 version。
		const identityReuses = [
			command({ identity: { ...command().identity, sandboxId: "sbx-other" } }),
			command({ identity: { ...command().identity, preparationGeneration: 2, executionGeneration: 2 } }),
			command({ identity: { ...command().identity, executionGeneration: 5 } }),
		];
		for (const reuse of [...operationReuses, ...identityReuses]) {
			const result = await rpc.handle(commandEnvelope({ ...reuse, commandId: firstCommandId }, "018f1e2c-3d4b-7c6d-8e9f-00a000000052"));
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.code).toBe(EXECUTION_COMMAND_ID_CONFLICT);
		}
		// 零 journal 写入：文件字节不变，executor 只执行过第一条命令。
		expect(readFileSync(journalPath(directory), "utf8")).toBe(journalBytes);
		expect(calls.length).toBe(1);
	});

	test("the envelope requestId is correlation-only: reuse across different commands stays legal", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const sharedRequestId = "018f1e2c-3d4b-7c6d-8e9f-00a000000061";
		const first = await rpc.handle(commandEnvelope(command(), sharedRequestId));
		const second = await rpc.handle(commandEnvelope(command({ commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abce", expectedJournalRevision: 2 }), sharedRequestId));
		expect(first.ok).toBe(true);
		expect(second.ok).toBe(true);
		expect(calls.length).toBe(2);
		// at-most-once 键是 commandId（命令字节 digest），不是 envelope requestId。
		const differingSameKey = await rpc.handle(commandEnvelope(command({ secretValuesDigest: "e".repeat(64) }), sharedRequestId));
		expect(differingSameKey.ok).toBe(false);
		if (!differingSameKey.ok) expect(differingSameKey.code).toBe(EXECUTION_COMMAND_ID_CONFLICT);
	});
});

// ---------------------------------------------------------------------------
// 进程重启后 replay 表恢复（journal 是唯一跨重启幂等权威）
// ---------------------------------------------------------------------------

describe("restart recovery restores the replay table from the journal alone", () => {
	test("a restarted supervisor replays stored acks with zero executions and continues the journal head", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const before = handler(directory, executor);
		const body = command();
		const first = await before.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000071"));
		expect(first.ok).toBe(true);
		expect(calls.length).toBe(1);
		const firstAck = first.ok && first.body.kind === "acknowledgement" ? first.body.acknowledgement : null;
		expect(firstAck).not.toBeNull();
		// 模拟进程重启：全新 handler + executor 实例，只共享磁盘上的 journal。
		const { executor: restartedExecutor, calls: restartedCalls } = countingExecutor();
		const restarted = handler(directory, restartedExecutor);
		const replayed = await restarted.handle(replayEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000072"));
		expect(replayed.ok).toBe(true);
		const redelivered = await restarted.handle(commandEnvelope(body, "018f1e2c-3d4b-7c6d-8e9f-00a000000073"));
		expect(redelivered.ok).toBe(true);
		expect(restartedCalls.length).toBe(0);
		if (replayed.ok && replayed.body.kind === "acknowledgement" && firstAck !== null) {
			expect(jcsBytesOf(replayed.body.acknowledgement).equals(jcsBytesOf(firstAck))).toBe(true);
		}
		if (redelivered.ok && redelivered.body.kind === "acknowledgement" && firstAck !== null) {
			expect(jcsBytesOf(redelivered.body.acknowledgement).equals(jcsBytesOf(firstAck))).toBe(true);
		}
		// 重启后的 journal head 续用：新命令（新 commandId + 对准 head 的 expectedRevision）正常执行。
		const fresh = await restarted.handle(commandEnvelope(command({ commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abcf", expectedJournalRevision: 2 }), "018f1e2c-3d4b-7c6d-8e9f-00a000000074"));
		expect(fresh.ok).toBe(true);
		expect(restartedCalls.length).toBe(1);
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory).read();
		expect(journal.journalRevision).toBe(4);
		expect(journal.entries.map((entry) => entry.kind)).toEqual(["command-received", "completed", "command-received", "completed"]);
	});

	test("a restarted supervisor that never saw the command still refuses blind replay", async () => {
		const directory = tempDirectory();
		const rpc = handler(directory, countingExecutor().executor);
		const result = await rpc.handle(replayEnvelope(command(), "018f1e2c-3d4b-7c6d-8e9f-00a000000081"));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("EXECUTION_COMMAND_UNKNOWN");
		expect(existsSync(journalPath(directory))).toBe(false);
	});
});
