// 用户原始需求（2026-08-26，add-wasm-runtime 任务 4.1）：engine metrics v1 wire 接进
//   supervisor → Kernel → monitor 链路——supervisor 侧从 executor 内部计数器喂 wire，
//   经固定只读采样端点暴露；Kernel 侧身份双端校验/单调窗口在 kernel-rs metrics.rs
//   （cargo 单测覆盖）；本文件锁 supervisor 侧链路段。
// 正交意图：payload 身份全部来自已接受 execution 记录（不采纳外部声明）；unknown
//   sandbox 一律拒绝（404，不合成载荷）；unavailable 唯一表示 engine:null；E 变更
//   才重置（新 tuple 重新归零）；运行中执行无 wasmd 读数时整体 unavailable（绝不
//   用 0 冒充 guest memory）；端点与 celld /v1/rpc 物理分离，无共享 parser。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WasmExecutionJournalStore } from "../supervisor/wasm-control.ts";
import {
	createWasmSupervisorExecutor,
	executorInternalEngineCounterSource,
	sampleWasmEngineMetrics,
	type WasmSupervisorExecutor,
} from "../supervisor/wasm-executor.ts";
import { startSupervisorServer } from "../supervisor/server.ts";
import { systemStateStoreIO } from "../supervisor/desired-state.ts";
import {
	exampleExecutionCommandV1,
	type ExecutionCommandV1,
	type ExecutionRpcRequestBodyV1,
} from "../packages/contracts/wasm-execution.ts";
import { validateWasmEngineMetricsV1 } from "../packages/contracts/wasm-health.ts";
import { createExecutionRpcHandler, type ExecutionRpcHandler } from "../supervisor/wasm-control.ts";

const REQUEST_ID = "018f1e2c-3d4b-7c6d-8e9f-001122334455";
const FIXED_NOW = "2026-08-26T00:00:00.000Z";

function tempDirectory(): string {
	return mkdtempSync(join(tmpdir(), "iweb-wasm-engine-metrics-"));
}

let commandCounter = 0;

function command(overrides: Partial<ExecutionCommandV1> = {}): ExecutionCommandV1 {
	commandCounter += 1;
	const base = exampleExecutionCommandV1();
	const sequence = commandCounter.toString(16).padStart(3, "0").slice(-3);
	return {
		...base,
		commandId: "018f1e2c-3d4b-7" + sequence + "-9e01-00112233445" + (commandCounter % 16).toString(16),
		expectedJournalRevision: 0,
		...overrides,
	};
}

function identityOf(preparationGeneration: number, executionGeneration: number, sandboxId = "sbx-vector") {
	return { ...exampleExecutionCommandV1().identity, sandboxId, preparationGeneration, executionGeneration };
}

interface Harness {
	readonly executor: WasmSupervisorExecutor;
	readonly handler: ExecutionRpcHandler;
	readonly deliver: (body: ExecutionRpcRequestBodyV1) => Promise<{ readonly ok: boolean; readonly code?: string }>;
}

function harness(): Harness {
	const directory = tempDirectory();
	const journal = new WasmExecutionJournalStore(systemStateStoreIO, directory);
	const executor = createWasmSupervisorExecutor({ journal });
	const handler = createExecutionRpcHandler({ journal, executor, now: () => FIXED_NOW });
	const deliver = async (body: ExecutionRpcRequestBodyV1) => {
		const result = await handler.handle({ protocol: "iweb-execution-rpc-v1", requestId: REQUEST_ID, body });
		return result.ok ? { ok: true } : { ok: false, code: result.code };
	};
	return { executor, handler, deliver };
}

function socketRequest(socketPath: string, path: string): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const value = request({ socketPath, method: "GET", path }, (response) => {
			let body = "";
			response.setEncoding("utf8");
			response.on("data", (chunk) => (body += chunk));
			response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
		});
		value.once("error", reject);
		value.end();
	});
}

describe("supervisor engine metrics sampler (4.1 wire feeding)", () => {
	test("an unstarted execution emits an available sample of proven zeros with fuel null", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		const payload = sampleWasmEngineMetrics(world.executor.fence, "sbx-vector", { now: () => FIXED_NOW });
		expect(payload).not.toBeNull();
		const validated = validateWasmEngineMetricsV1(payload);
		expect(validated.ok).toBe(true);
		if (!validated.ok) return;
		// 身份来自已接受 execution 记录（与命令同 tuple）。
		expect(validated.value.sandboxId).toBe("sbx-vector");
		expect(validated.value.preparationGeneration).toBe(1);
		expect(validated.value.executionGeneration).toBe(1);
		expect(validated.value.runtimeBinding).toEqual(exampleExecutionCommandV1().runtimeBinding);
		// prepared：无进程存活——instances/guestMemory 的零可证明；fuel 无法证明数值 → null。
		expect(validated.value.availability).toBe("available");
		expect(validated.value.engine).toEqual({
			fuelConsumedCumulative: null,
			epochTimeoutsCumulative: 0,
			instancesLiveInstant: 0,
			instancesHighWaterCumulative: 0,
			guestMemoryBytesInstant: 0,
		});
	});

	test("a running execution cannot prove guest memory: the whole sample is unavailable, never zero-filled", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 1), expectedJournalRevision: 2 }) });
		const payload = sampleWasmEngineMetrics(world.executor.fence, "sbx-vector", { now: () => FIXED_NOW });
		expect(payload).not.toBeNull();
		const validated = validateWasmEngineMetricsV1(payload);
		expect(validated.ok).toBe(true);
		if (!validated.ok) return;
		expect(validated.value.availability).toBe("unavailable");
		expect(validated.value.engine).toBeNull();
		// 停止后：实例高水位保留（该 E 曾运行），live/guestMemory 归零可证明。
		await world.executor.execute(command({ operation: "stop", identity: identityOf(1, 1) }));
		const stopped = sampleWasmEngineMetrics(world.executor.fence, "sbx-vector", { now: () => FIXED_NOW });
		const stoppedValidated = validateWasmEngineMetricsV1(stopped);
		expect(stoppedValidated.ok).toBe(true);
		if (!stoppedValidated.ok) return;
		expect(stoppedValidated.value.availability).toBe("available");
		expect(stoppedValidated.value.engine?.instancesHighWaterCumulative).toBe(1);
		expect(stoppedValidated.value.engine?.instancesLiveInstant).toBe(0);
		expect(stoppedValidated.value.engine?.guestMemoryBytesInstant).toBe(0);
	});

	test("epoch timeout counting is wired through the ledger and resets only on a new execution generation", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 1), expectedJournalRevision: 2 }) });
		world.executor.fence.noteEngineEpochTimeout(identityOf(1, 1));
		world.executor.fence.noteEngineEpochTimeout(identityOf(1, 1));
		await world.executor.execute(command({ operation: "stop", identity: identityOf(1, 1) }));
		const same = sampleWasmEngineMetrics(world.executor.fence, "sbx-vector", { now: () => FIXED_NOW });
		const sameValidated = validateWasmEngineMetricsV1(same);
		expect(sameValidated.ok && sameValidated.value.engine?.epochTimeoutsCumulative).toBe(2);
		// 新 execution generation（restart）：计数器随新 tuple 归零（E 变更才重置）。
		await world.deliver({ kind: "command", command: command({ operation: "start", identity: identityOf(1, 2), expectedJournalRevision: 4 }) });
		await world.executor.execute(command({ operation: "stop", identity: identityOf(1, 2) }));
		const next = sampleWasmEngineMetrics(world.executor.fence, "sbx-vector", { now: () => FIXED_NOW });
		const nextValidated = validateWasmEngineMetricsV1(next);
		expect(nextValidated.ok && nextValidated.value.executionGeneration).toBe(2);
		expect(nextValidated.ok && nextValidated.value.engine?.epochTimeoutsCumulative).toBe(0);
	});

	test("unknown sandbox is rejected without synthesizing a payload", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		expect(sampleWasmEngineMetrics(world.executor.fence, "sbx-none")).toBeNull();
		// 计数源产物非法（available 却缺 counters）时 fail-closed 降级为同身份 unavailable。
		const broken = sampleWasmEngineMetrics(world.executor.fence, "sbx-vector", {
			now: () => FIXED_NOW,
			counterSource: () => ({ available: true, engine: null }),
		});
		const validated = validateWasmEngineMetricsV1(broken);
		expect(validated.ok).toBe(true);
		if (validated.ok) {
			expect(validated.value.availability).toBe("unavailable");
			expect(validated.value.engine).toBeNull();
		}
	});

	test("the internal counter source stays injectable for the 5.x wasmd collection point", () => {
		const source = executorInternalEngineCounterSource();
		const record = {
			identity: identityOf(1, 1),
			packageDigest: exampleExecutionCommandV1().packageDigest,
			runtimeBinding: exampleExecutionCommandV1().runtimeBinding,
			capabilityRecordRevision: 5,
			capabilityRecordHash: "2".repeat(64),
			secretRevision: 3,
			secretSnapshotRef: "6".repeat(64),
			secretValuesDigest: "6".repeat(64),
			configRevision: 2,
			configSnapshotRef: "7".repeat(64),
			configValuesDigest: "8".repeat(64),
			substate: "running" as const,
			epochTimeoutsCumulative: 1,
			instancesHighWaterCumulative: 1,
		};
		expect(source(record)).toEqual({ available: false, engine: null });
		expect(source({ ...record, substate: "retiring" })).toEqual({ available: false, engine: null });
	});
});

describe("supervisor engine metrics endpoint (4.1 transport)", () => {
	test("GET /v1/execution-metrics/<sandboxId> serves the wire and rejects unknown sandboxes", async () => {
		const world = harness();
		await world.deliver({ kind: "command", command: command({ operation: "prepare", identity: identityOf(1, 1) }) });
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const running = await startSupervisorServer({
			socketPath,
			executionMetrics: (sandboxId) => sampleWasmEngineMetrics(world.executor.fence, sandboxId, { now: () => FIXED_NOW }),
		});
		try {
			const known = await socketRequest(socketPath, "/v1/execution-metrics/sbx-vector");
			expect(known.status).toBe(200);
			const payload = JSON.parse(known.body);
			const validated = validateWasmEngineMetricsV1(payload);
			expect(validated.ok).toBe(true);
			// 未知 sandbox：404，绝不合成载荷。
			const unknown = await socketRequest(socketPath, "/v1/execution-metrics/sbx-none");
			expect(unknown.status).toBe(404);
			expect(JSON.parse(unknown.body).code).toBe("EXECUTION_SANDBOX_UNKNOWN");
			// 非法 sandboxId 文法：先于 fence 查找拒绝（404）。
			const malformed = await socketRequest(socketPath, "/v1/execution-metrics/../etc");
			expect(malformed.status).toBe(404);
			// 其它方法/路径：未知路由。
			const wrongMethod = await socketRequest(socketPath, "/v1/execution-metrics/sbx-vector/list");
			expect(wrongMethod.status).toBe(404);
		} finally {
			await running.close();
		}
	});

	test("the endpoint fails closed (503) when the sampler is not configured; celld /v1/rpc stays separate", async () => {
		const directory = tempDirectory();
		const socketPath = join(directory, "supervisor.sock");
		const running = await startSupervisorServer({ socketPath });
		try {
			const unconfigured = await socketRequest(socketPath, "/v1/execution-metrics/sbx-vector");
			expect(unconfigured.status).toBe(503);
			expect(JSON.parse(unconfigured.body).code).toBe("EXECUTION_METRICS_NOT_CONFIGURED");
			// celld envelope 命中本路径不是 wasm wire：不进入 metrics 采样（404 路由层拒绝）。
			const celldEnvelope = await new Promise<{ status: number; body: string }>((resolve, reject) => {
				const value = request(
					{ socketPath, method: "POST", path: "/v1/execution-metrics/sbx-vector" },
					(response) => {
						let body = "";
						response.setEncoding("utf8");
						response.on("data", (chunk) => (body += chunk));
						response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
					},
				);
				value.once("error", reject);
				value.setHeader("content-type", "application/json");
				value.end(JSON.stringify({ version: 1, operation: "metrics", sandboxId: "sbx-vector" }));
			});
			expect(celldEnvelope.status).toBe(404);
		} finally {
			await running.close();
		}
	});
});
