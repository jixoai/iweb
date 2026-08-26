// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.0）：wasm execution 传输与持久化边界——
//   envelope 双向互斥、controlRevision/journalRevision CAS 冲突、outbox/journal 幂等重放、
//   崩溃点（received 未执行/执行未 ack/ack 未投影）唯一结果、celld 文件隔离。
// 正交意图：负例断言稳定错误码；断言"零副作用"以文件字节与 executor/adapter 调用计数为准；
//   celld 既有 parser/存储行为在同目录共存下保持不变。
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createExecutionRpcHandler,
	EXECUTION_COMMAND_ID_CONFLICT,
	EXECUTION_COMMAND_UNKNOWN,
	EXECUTION_HTTP_FRAME_REJECTED,
	EXECUTION_OUTBOX_DUPLICATE_COMMAND,
	EXECUTION_OUTBOX_COMMAND_UNKNOWN,
	EXECUTION_RPC_NOT_CONFIGURED,
	JOURNAL_REVISION_CONFLICT,
	WasmControlStateStore,
	WASM_CONTROL_STATE_CORRUPT,
	WASM_CONTROL_STATE_FILENAME,
	WASM_EXECUTION_JOURNAL_CORRUPT,
	WASM_EXECUTION_JOURNAL_FILENAME,
	WasmExecutionJournalStore,
	type ExecutionCommandV1,
	type ExecutionRpcHandler,
	type WasmExecutionExecutor,
	type WasmExecutionOutcome,
} from "../supervisor/wasm-control.ts";
import { startSupervisorServer } from "../supervisor/server.ts";
import type { SupervisorAdapter } from "../packages/contracts/protocol-server.ts";
import {
	computeExecutionCommandDigestV1,
	CONTROL_REVISION_CONFLICT,
	correlateExecutionAcknowledgement,
	correlateExecutionRpcResponse,
	exampleExecutionCommandV1,
	exampleWasmControlStateFileV2,
	validateExecutionRpcResponseEnvelopeV1,
	validateWasmControlStateFileV2,
	type ExecutionAcknowledgementV1,
	type ExecutionRpcRequestEnvelopeV1,
} from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";
import { emptyControlStateFile, validateControlStateFile } from "../packages/contracts/control-db.ts";
import { JsonStateStore, systemStateStoreIO } from "../supervisor/desired-state.ts";

const REQUEST_ID = "018f1e2c-3d4b-7c6d-8e9f-001122334455";
const FIXED_NOW = "2026-08-26T00:00:00.000Z";
const APPLIED: WasmExecutionOutcome = { result: "applied", failureCode: null, drainReceiptDraft: null };

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-control-"));
}

function wasmCommand(overrides: Partial<ExecutionCommandV1> = {}): ExecutionCommandV1 {
	return { ...exampleExecutionCommandV1(), expectedJournalRevision: 0, ...overrides };
}

function commandEnvelope(command: ExecutionCommandV1, requestId: string = REQUEST_ID): ExecutionRpcRequestEnvelopeV1 {
	return { protocol: "iweb-execution-rpc-v1", requestId, body: { kind: "command", command } };
}

function queryEnvelope(commandId: string, requestId: string = REQUEST_ID): ExecutionRpcRequestEnvelopeV1 {
	return { protocol: "iweb-execution-rpc-v1", requestId, body: { kind: "query", commandId } };
}

function replayEnvelope(command: ExecutionCommandV1, requestId: string = REQUEST_ID): ExecutionRpcRequestEnvelopeV1 {
	return { protocol: "iweb-execution-rpc-v1", requestId, body: { kind: "replay", command } };
}

function countingExecutor(outcome: WasmExecutionOutcome = APPLIED): { executor: WasmExecutionExecutor; calls: ExecutionCommandV1[] } {
	const calls: ExecutionCommandV1[] = [];
	return {
		calls,
		executor: {
			execute: async (command) => {
				calls.push(command);
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

function controlPath(directory: string): string {
	return join(directory, WASM_CONTROL_STATE_FILENAME);
}

function jcsBytesOf(value: unknown): Buffer {
	return Buffer.from(jcsCanonicalBytes(value));
}

function post(socketPath: string, path: string, body: unknown | Buffer, contentType = "application/json"): Promise<{ status: number; body: string }> {
	const payload = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
	return new Promise((resolve, reject) => {
		const value = request(
			{ socketPath, method: "POST", path, headers: { "content-type": contentType, "content-length": Buffer.byteLength(payload as string) } },
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

function spyAdapter(): { adapter: SupervisorAdapter; calls: string[] } {
	const calls: string[] = [];
	const adapter: SupervisorAdapter = {
		prepare: async (request) => { calls.push("prepare"); return { version: 1, operation: "prepare", status: "prepared", sandboxId: request.sandboxId }; },
		start: async (request) => { calls.push("start"); return { version: 1, operation: "start", status: "started", sandboxId: request.sandboxId }; },
		stop: async (request) => { calls.push("stop"); return { version: 1, operation: "stop", status: "stopped", sandboxId: request.sandboxId }; },
		inspect: async (request) => { calls.push("inspect"); return { version: 1, operation: "inspect", sandboxId: request.sandboxId, state: "ready" }; },
		metrics: async () => { calls.push("metrics"); throw new Error("not needed"); },
		delete: async (request) => { calls.push("delete"); return { version: 1, operation: "delete", status: "deleted", sandboxId: request.sandboxId }; },
	};
	return { adapter, calls };
}

function acknowledgementOf(result: { readonly status: number; readonly body: string }): ExecutionAcknowledgementV1 {
	const parsed = validateExecutionRpcResponseEnvelopeV1(JSON.parse(result.body));
	expect(parsed.ok).toBe(true);
	if (!parsed.ok) throw new Error("expected a valid response envelope");
	expect(parsed.value.body.kind).toBe("acknowledgement");
	if (parsed.value.body.kind !== "acknowledgement") throw new Error("expected an acknowledgement body");
	return parsed.value.body.acknowledgement;
}

describe("execution rpc envelope mutual exclusion (real supervisor socket)", () => {
	test("a celld envelope on /v1/execution-rpc is rejected without journal or executor side effects", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const { executor, calls } = countingExecutor();
		const running = await startSupervisorServer({ socketPath, adapter: spyAdapter().adapter, executionRpc: handler(directory, executor) });
		try {
			const celldEnvelope = { version: 1, operation: "inspect", sandboxId: "sbx-inspect" };
			const result = await post(socketPath, "/v1/execution-rpc", celldEnvelope);
			expect(result.status).toBe(400);
			expect(JSON.parse(result.body).code).toBe("EXECUTION_PROTOCOL_MISMATCH");
			// 也拒绝只带 operation 成员的最小 celld 痕迹，以及双标记混合体。
			expect(JSON.parse((await post(socketPath, "/v1/execution-rpc", { operation: "prepare" })).body).code).toBe("EXECUTION_PROTOCOL_MISMATCH");
			expect(JSON.parse((await post(socketPath, "/v1/execution-rpc", { ...celldEnvelope, protocol: "iweb-execution-rpc-v1" })).body).code).toBe("EXECUTION_PROTOCOL_MISMATCH");
			expect(calls.length).toBe(0);
			expect(existsSync(journalPath(directory))).toBe(false);
		} finally {
			await running.close();
		}
	});

	test("an execution envelope on /v1/rpc is rejected as CELLD_PROTOCOL_MISMATCH with zero adapter calls", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const { adapter, calls } = spyAdapter();
		const running = await startSupervisorServer({ socketPath, adapter, executionRpc: handler(directory, countingExecutor().executor) });
		try {
			const command = wasmCommand();
			const markerBodies: unknown[] = [
				queryEnvelope(command.commandId),
				{ command },
				{ query: command.commandId },
				{ replay: command },
				{ version: 1, operation: "inspect", sandboxId: "sbx-a", protocol: "iweb-execution-rpc-v1" },
			];
			for (const body of markerBodies) {
				const result = await post(socketPath, "/v1/rpc", body);
				expect(result.status).toBe(400);
				expect(JSON.parse(result.body).code).toBe("CELLD_PROTOCOL_MISMATCH");
			}
			expect(calls.length).toBe(0);
		} finally {
			await running.close();
		}
	});

	test("the raw snapshot frame magic is rejected on both endpoints before body parsing", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const { executor, calls } = countingExecutor();
		const { adapter, calls: celldCalls } = spyAdapter();
		const running = await startSupervisorServer({ socketPath, adapter, executionRpc: handler(directory, executor) });
		try {
			const frame = Buffer.concat([Buffer.from("4957454246443100", "hex"), Buffer.from("rest-of-frame")]);
			const celldSide = await post(socketPath, "/v1/rpc", frame);
			expect(celldSide.status).toBe(400);
			expect(JSON.parse(celldSide.body).code).toBe("CELLD_PROTOCOL_MISMATCH");
			const executionSide = await post(socketPath, "/v1/execution-rpc", frame);
			expect(executionSide.status).toBe(400);
			expect(JSON.parse(executionSide.body).code).toBe(EXECUTION_HTTP_FRAME_REJECTED);
			expect(calls.length + celldCalls.length).toBe(0);
		} finally {
			await running.close();
		}
	});

	test("/v1/execution-rpc fails closed when no handler is configured and non-POST methods stay unrouted", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const { adapter } = spyAdapter();
		const running = await startSupervisorServer({ socketPath, adapter });
		try {
			const result = await post(socketPath, "/v1/execution-rpc", queryEnvelope(wasmCommand().commandId));
			expect(result.status).toBe(503);
			expect(JSON.parse(result.body).code).toBe(EXECUTION_RPC_NOT_CONFIGURED);
			const wrongMethod = await new Promise<{ status: number }>((resolve, reject) => {
				const value = request({ socketPath, method: "GET", path: "/v1/execution-rpc" }, (response) => {
					response.resume();
					response.on("end", () => resolve({ status: response.statusCode ?? 0 }));
				});
				value.once("error", reject);
				value.end();
			});
			expect(wrongMethod.status).toBe(404);
		} finally {
			await running.close();
		}
	});

	test("a valid envelope round-trips through the socket with protocol/requestId correlation", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const { executor } = countingExecutor();
		const running = await startSupervisorServer({ socketPath, adapter: spyAdapter().adapter, executionRpc: handler(directory, executor) });
		try {
			const command = wasmCommand();
			const result = await post(socketPath, "/v1/execution-rpc", commandEnvelope(command));
			expect(result.status).toBe(200);
			const parsed = validateExecutionRpcResponseEnvelopeV1(JSON.parse(result.body));
			expect(parsed.ok).toBe(true);
			if (parsed.ok) {
				const correlated = correlateExecutionRpcResponse(commandEnvelope(command), parsed.value);
				expect(correlated.ok).toBe(true);
			}
			const acknowledgement = acknowledgementOf(result);
			const correlatedAck = correlateExecutionAcknowledgement(command, acknowledgement);
			expect(correlatedAck.ok).toBe(true);
			expect(acknowledgement.journalRevision).toBe(2);
			// 非 iweb-execution-rpc-v1 协议字面量按 envelope-invalid 拒绝（非降级）。
			const wrongProtocol = await post(socketPath, "/v1/execution-rpc", { protocol: "iweb-execution-rpc-v2", requestId: REQUEST_ID, body: { kind: "query", commandId: command.commandId } });
			expect(wrongProtocol.status).toBe(400);
			expect(JSON.parse(wrongProtocol.body).code).toBe("EXECUTION_RPC_ENVELOPE_INVALID");
		} finally {
			await running.close();
		}
	});
});

describe("wasm control state store: controlRevision CAS and outbox", () => {
	test("an absent wasm file is uninitialized while celld files in the same directory stay untouched", () => {
		const directory = tempDirectory();
		const celldStore = new JsonStateStore(systemStateStoreIO, directory);
		celldStore.writeDesired({ version: 1, records: {} });
		writeFileSync(join(directory, "control-db.json"), JSON.stringify(emptyControlStateFile(), null, 2) + "\n", { mode: 0o600 });
		const desiredBefore = readFileSync(join(directory, "desired-state.json"), "utf8");
		const controlDbBefore = readFileSync(join(directory, "control-db.json"), "utf8");
		const store = new WasmControlStateStore(systemStateStoreIO, directory);
		const state = store.read();
		expect(state.controlRevision).toBe(0);
		expect(state.commandOutbox.length).toBe(0);
		expect(state.migration.status).toBe("not-started");
		// celld 文件字节不变，且 celld store 仍按原 parser 可读。
		expect(readFileSync(join(directory, "desired-state.json"), "utf8")).toBe(desiredBefore);
		expect(readFileSync(join(directory, "control-db.json"), "utf8")).toBe(controlDbBefore);
		expect(celldStore.readDesired()).toEqual({ version: 1, records: {} });
		expect(validateControlStateFile(JSON.parse(controlDbBefore))).toEqual(emptyControlStateFile());
	});

	test("outbox append commits at expectedControlRevision+1 and CAS conflicts write nothing", () => {
		const directory = tempDirectory();
		const store = new WasmControlStateStore(systemStateStoreIO, directory);
		const command = wasmCommand();
		const first = store.appendOutboxCommand(0, command, FIXED_NOW);
		expect(first.ok).toBe(true);
		if (first.ok) {
			expect(first.state.controlRevision).toBe(1);
			expect(first.state.commandOutbox[0]?.deliveryState).toBe("pending");
		}
		const bytesAfterFirst = readFileSync(controlPath(directory), "utf8");
		const other = wasmCommand({ commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abce" });
		const stale = store.appendOutboxCommand(0, other, FIXED_NOW);
		expect(stale.ok).toBe(false);
		if (!stale.ok) expect(stale.code).toBe(CONTROL_REVISION_CONFLICT);
		expect(readFileSync(controlPath(directory), "utf8")).toBe(bytesAfterFirst);
		// 用新 revision 重试不同命令成功；重复 commandId 即使 revision 正确也 fail-closed。
		const second = store.appendOutboxCommand(1, other, FIXED_NOW);
		expect(second.ok).toBe(true);
		const duplicate = store.appendOutboxCommand(2, command, FIXED_NOW);
		expect(duplicate.ok).toBe(false);
		if (!duplicate.ok) expect(duplicate.code).toBe(EXECUTION_OUTBOX_DUPLICATE_COMMAND);
		// u53 上限处的期望值同样零写入。
		const outOfRange = store.commit(9007199254740991, (current) => current);
		expect(outOfRange.ok).toBe(false);
	});

	test("acknowledgement projection is identity-checked, idempotent, and fails closed", () => {
		const directory = tempDirectory();
		const store = new WasmControlStateStore(systemStateStoreIO, directory);
		const command = wasmCommand();
		store.appendOutboxCommand(0, command, FIXED_NOW);
		const ack: ExecutionAcknowledgementV1 = {
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
			journalRevision: 2,
		};
		const projected = store.projectAcknowledgement(1, ack);
		expect(projected.ok).toBe(true);
		if (projected.ok) {
			expect(projected.state.controlRevision).toBe(2);
			expect(projected.state.commandOutbox[0]?.deliveryState).toBe("acknowledged");
		}
		// 幂等重投影（revision 未变）不再消耗 controlRevision。
		const again = store.projectAcknowledgement(2, ack);
		expect(again.ok).toBe(true);
		if (again.ok) expect(again.state.controlRevision).toBe(2);
		// 回显字段不匹配（packageDigest 被篡改）→ fail-closed 且零写入。
		const tampered: ExecutionAcknowledgementV1 = { ...ack, packageDigest: "e".repeat(64) };
		const mismatch = store.projectAcknowledgement(2, tampered);
		expect(mismatch.ok).toBe(false);
		if (!mismatch.ok) expect(mismatch.code).toBe("EXECUTION_ACK_PROJECTION_CONFLICT");
		// 未知 commandId → fail-closed。
		const unknown = store.projectAcknowledgement(2, { ...ack, commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abcf" });
		expect(unknown.ok).toBe(false);
		if (!unknown.ok) expect(unknown.code).toBe(EXECUTION_OUTBOX_COMMAND_UNKNOWN);
	});

	test("persistence is canonical JCS and non-canonical or celld-shaped bytes fail closed", () => {
		const directory = tempDirectory();
		const store = new WasmControlStateStore(systemStateStoreIO, directory);
		store.appendOutboxCommand(0, wasmCommand(), FIXED_NOW);
		const raw = readFileSync(controlPath(directory), "utf8");
		expect(raw).toBe(jcsBytesOf(JSON.parse(raw)).toString("utf8"));
		// 白空格偏差（非 JCS 字节）→ 读失败，文件不被重写。
		const pretty = JSON.stringify(JSON.parse(raw), null, 2) + "\n";
		writeFileSync(controlPath(directory), pretty, { mode: 0o600 });
		expect(() => store.read()).toThrow(WASM_CONTROL_STATE_CORRUPT);
		expect(readFileSync(controlPath(directory), "utf8")).toBe(pretty);
		// celld ControlStateFile 出现在 wasm 路径 → 按 wasm 解析失败（不降级、不迁移）。
		writeFileSync(controlPath(directory), JSON.stringify(emptyControlStateFile()), { mode: 0o600 });
		expect(() => store.read()).toThrow(WASM_CONTROL_STATE_CORRUPT);
	});
});

describe("celld/wasm parser isolation", () => {
	test("each parser rejects the other runtime kind's file shape", () => {
		// celld parser 拒绝 wasm v2 形状（无论是否伪装 version:1）。
		const wasmFile = exampleWasmControlStateFileV2();
		expect(validateControlStateFile(wasmFile)).toBeNull();
		expect(validateControlStateFile({ ...wasmFile, version: 1 })).toBeNull();
		// wasm parser 拒绝 celld version:1 形状。
		const celldFile = emptyControlStateFile();
		expect(validateControlStateFile(celldFile)).toEqual(celldFile);
		expect(validateWasmControlStateFileV2(celldFile).ok).toBe(false);
	});

	test("celld desired-state stays readable after wasm writes in the same directory", () => {
		const directory = tempDirectory();
		const celldStore = new JsonStateStore(systemStateStoreIO, directory);
		celldStore.writeDesired({ version: 1, records: {} });
		new WasmExecutionJournalStore(systemStateStoreIO, directory).appendReceived(0, wasmCommand(), FIXED_NOW);
		new WasmControlStateStore(systemStateStoreIO, directory).appendOutboxCommand(0, wasmCommand(), FIXED_NOW);
		expect(celldStore.readDesired()).toEqual({ version: 1, records: {} });
		// 三个物理文件并存、互不解析。
		expect(existsSync(join(directory, "desired-state.json"))).toBe(true);
		expect(existsSync(journalPath(directory))).toBe(true);
		expect(existsSync(controlPath(directory))).toBe(true);
	});
});

describe("execution journal service: idempotent command/query/replay", () => {
	test("a new command writes received then completed and answers with a correlated acknowledgement", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const command = wasmCommand();
		const result = await rpc.handle(commandEnvelope(command));
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("expected success");
		expect(result.body.kind).toBe("acknowledgement");
		expect(calls.length).toBe(1);
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory).read();
		expect(journal.journalRevision).toBe(2);
		expect(journal.entries.map((entry) => entry.kind)).toEqual(["command-received", "completed"]);
		expect(journal.entries[0]?.commandDigest).toBe(computeExecutionCommandDigestV1(command));
		// 幂等重投：返回存储的 ack，executor 不再被调用。
		const retry = await rpc.handle(commandEnvelope(command, "018f1e2c-3d4b-7c6d-8e9f-001122334456"));
		expect(retry.ok).toBe(true);
		expect(calls.length).toBe(1);
		if (retry.ok && result.ok && result.body.kind === "acknowledgement" && retry.body.kind === "acknowledgement") {
			expect(jcsBytesOf(retry.body.acknowledgement).equals(jcsBytesOf(result.body.acknowledgement))).toBe(true);
		}
	});

	test("query reports missing, received, and completed in order", async () => {
		const directory = tempDirectory();
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
		const rpc = handler(directory, countingExecutor().executor);
		const command = wasmCommand();
		const missing = await rpc.handle(queryEnvelope(command.commandId));
		expect(missing.ok).toBe(true);
		if (missing.ok && missing.body.kind === "query-result") expect(missing.body.status).toBe("missing");
		journal.appendReceived(0, command, FIXED_NOW);
		const received = await rpc.handle(queryEnvelope(command.commandId));
		if (received.ok && received.body.kind === "query-result") {
			expect(received.body.status).toBe("received");
			expect(received.body.received?.commandId).toBe(command.commandId);
		} else throw new Error("expected query-result");
		await rpc.handle(replayEnvelope(command));
		const completed = await rpc.handle(queryEnvelope(command.commandId));
		if (completed.ok && completed.body.kind === "query-result") {
			expect(completed.body.status).toBe("completed");
			expect(completed.body.acknowledgement?.journalRevision).toBe(2);
		} else throw new Error("expected query-result");
	});

	test("replay requires byte-identical commands and a known commandId", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const command = wasmCommand();
		const unknown = await rpc.handle(replayEnvelope(command));
		expect(unknown.ok).toBe(false);
		if (!unknown.ok) expect(unknown.code).toBe(EXECUTION_COMMAND_UNKNOWN);
		await rpc.handle(commandEnvelope(command));
		const differing = await rpc.handle(replayEnvelope(wasmCommand({ secretValuesDigest: "f".repeat(64) })));
		expect(differing.ok).toBe(false);
		if (!differing.ok) expect(differing.code).toBe(EXECUTION_COMMAND_ID_CONFLICT);
		const identical = await rpc.handle(replayEnvelope(command));
		expect(identical.ok).toBe(true);
		expect(calls.length).toBe(1);
	});

	test("expectedJournalRevision mismatches fail closed with zero journal writes", async () => {
		const directory = tempDirectory();
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const stale = await rpc.handle(commandEnvelope(wasmCommand({ expectedJournalRevision: 7 })));
		expect(stale.ok).toBe(false);
		if (!stale.ok) expect(stale.code).toBe(JOURNAL_REVISION_CONFLICT);
		expect(calls.length).toBe(0);
		expect(existsSync(journalPath(directory))).toBe(false);
		// 同一 expectedRevision 的两个不同命令：恰好一个 appended，另一个冲突。
		const winner = await rpc.handle(commandEnvelope(wasmCommand()));
		expect(winner.ok).toBe(true);
		const loser = await rpc.handle(commandEnvelope(wasmCommand({ commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abce" })));
		expect(loser.ok).toBe(false);
		if (!loser.ok) expect(loser.code).toBe(JOURNAL_REVISION_CONFLICT);
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory).read();
		expect(journal.entries.length).toBe(2);
	});

	test("journal persistence is canonical JCS and non-canonical bytes fail closed", () => {
		const directory = tempDirectory();
		const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
		journal.appendReceived(0, wasmCommand(), FIXED_NOW);
		const raw = readFileSync(journalPath(directory), "utf8");
		expect(raw).toBe(jcsBytesOf(JSON.parse(raw)).toString("utf8"));
		const pretty = JSON.stringify(JSON.parse(raw), null, 2) + "\n";
		writeFileSync(journalPath(directory), pretty, { mode: 0o600 });
		expect(() => journal.read()).toThrow(WASM_EXECUTION_JOURNAL_CORRUPT);
	});
});

describe("crash-point recovery has exactly one outcome", () => {
	const canonicalAckFor = (command: ExecutionCommandV1): ExecutionAcknowledgementV1 => ({
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
		journalRevision: 2,
	});

	test("state A: received but not executed — replay executes once and completes at revision 2", async () => {
		const directory = tempDirectory();
		const command = wasmCommand();
		new WasmExecutionJournalStore(systemStateStoreIO, directory).appendReceived(0, command, FIXED_NOW);
		// 模拟 supervisor 重启：新的 handler/executor 实例，只认磁盘 journal。
		const { executor, calls } = countingExecutor();
		const restarted = handler(directory, executor);
		const result = await restarted.handle(replayEnvelope(command));
		expect(result.ok).toBe(true);
		expect(calls.length).toBe(1);
		const query = await restarted.handle(queryEnvelope(command.commandId));
		if (query.ok && query.body.kind === "query-result") {
			expect(query.body.status).toBe("completed");
			const acknowledgement = query.body.acknowledgement;
			expect(acknowledgement).not.toBeNull();
			if (acknowledgement !== null) expect(jcsBytesOf(acknowledgement).equals(jcsBytesOf(canonicalAckFor(command)))).toBe(true);
		} else throw new Error("expected query-result");
		// 再次 replay 不再执行（副作用总数保持 1）。
		await restarted.handle(replayEnvelope(command));
		expect(calls.length).toBe(1);
	});

	test("state B: executed but not acknowledged — replay resumes idempotently with the same result", async () => {
		const directory = tempDirectory();
		const command = wasmCommand();
		new WasmExecutionJournalStore(systemStateStoreIO, directory).appendReceived(0, command, FIXED_NOW);
		// 模拟真实沙箱副作用跨进程持久（如 OCI 状态）：executor 以自身持久存储为幂等依据。
		const durableEffects = new Map<string, WasmExecutionOutcome>();
		const crashAfterEffect: WasmExecutionExecutor = {
			execute: async (received) => {
				durableEffects.set(computeExecutionCommandDigestV1(received), APPLIED);
				throw new Error("simulated crash after the side effect");
			},
		};
		const crashed = handler(directory, crashAfterEffect);
		const failure = await crashed.handle(commandEnvelope(command));
		expect(failure.ok).toBe(false);
		if (!failure.ok) expect(failure.code).toBe("EXECUTION_EXECUTOR_FAILED");
		// 崩溃后 journal 仍只有 received。
		const midJournal = new WasmExecutionJournalStore(systemStateStoreIO, directory).read();
		expect(midJournal.entries.map((entry) => entry.kind)).toEqual(["command-received"]);
		const resumeExecutor: WasmExecutionExecutor = {
			execute: async (received) => {
				const digest = computeExecutionCommandDigestV1(received);
				const recorded = durableEffects.get(digest);
				if (recorded !== undefined) return recorded;
				durableEffects.set(digest, APPLIED);
				return APPLIED;
			},
		};
		const restarted = handler(directory, resumeExecutor);
		const resumed = await restarted.handle(replayEnvelope(command));
		expect(resumed.ok).toBe(true);
		if (resumed.ok && resumed.body.kind === "acknowledgement") {
			expect(jcsBytesOf(resumed.body.acknowledgement).equals(jcsBytesOf(canonicalAckFor(command)))).toBe(true);
		}
		// 副作用只发生过一次（durableEffects 只有一项且未在恢复中重做）。
		expect(durableEffects.size).toBe(1);
	});

	test("state C: acknowledged in journal but not projected into the control outbox", async () => {
		const directory = tempDirectory();
		const command = wasmCommand();
		// Kernel 先以同一 controlRevision CAS 追加 outbox（双 CAS 第 1 步）。
		const control = new WasmControlStateStore(systemStateStoreIO, directory);
		control.appendOutboxCommand(0, command, FIXED_NOW);
		// supervisor 完整执行并落 completion（第 2 步），Kernel 投影前崩溃。
		const { executor, calls } = countingExecutor();
		const rpc = handler(directory, executor);
		const first = await rpc.handle(commandEnvelope(command));
		expect(first.ok).toBe(true);
		// 恢复：重新构造的 handler/executor 绝不重复执行，replay 返回存储的 ack。
		const restarted = handler(directory, { execute: async () => { throw new Error("must not execute a completed command"); } });
		const replayed = await restarted.handle(replayEnvelope(command));
		expect(replayed.ok).toBe(true);
		expect(calls.length).toBe(1);
		// Kernel 重启后按第 3 步 CAS 投影：outbox acknowledged、controlRevision 2。
		expect(control.findOutboxCommand(command.commandId)?.deliveryState).toBe("pending");
		if (replayed.ok && replayed.body.kind === "acknowledgement") {
			const projected = control.projectAcknowledgement(1, replayed.body.acknowledgement);
			expect(projected.ok).toBe(true);
			if (projected.ok) {
				expect(projected.state.controlRevision).toBe(2);
				expect(projected.state.commandOutbox[0]?.deliveryState).toBe("acknowledged");
			}
			const reprojection = control.projectAcknowledgement(2, replayed.body.acknowledgement);
			expect(reprojection.ok).toBe(true);
		}
	});
});
