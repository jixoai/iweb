// 用户原始需求（2026-08-28，add-wasm-host-services 第四轮复审 5.5/10 P1 缺口收尾）：
//   数据面不变量回归——KV/SQL/Logging 的 mutation 决策（contracts 纯函数：CAS 线性化、
//   写前配额、幂等 marker、SQL execute preflight、logging 环准入）在任意正/负路径上
//   都不得触碰控制态文件 wasm-control-state-v2.json 的任何字节。
// 正交意图：
//   1. 以真实磁盘控制态 store（supervisor/wasm-control.ts 的 WasmControlStateStore，
//      JCS 字节权威）落一份非平凡初始态（outbox 携带 V2 执行命令），mutation 批次
//      前后 readFileSync 逐字节对比（Buffer.compare === 0）——不是对象近似比较。
//   2. mutation 批次必须真实驱动三类后端的全部决策路径并断言各自结果（committed/
//      conflict/unavailable、allowed/quota-exceeded/unprovable、accepted/dropped/
//      limit-exceeded），防止「空转批次」让不变量测试空洞化。
//   3. 对照锚（方法学有效性）：一次真实的控制面 CAS（controlRevision 前进）必须改变
//      文件字节——证明字节对比具备检出能力，不变量测试不是恒真。
// 规范权威：openspec/changes/add-wasm-host-services/design.md——「an over-limit or
//   unprovable reservation changes no key, tombstone, SQL data or controlRevision」
//   （数据面变更永不携带 controlRevision）；specs/wasm-application-runtime/spec.md
//   「control state and data plane have explicit, separate authorities」。
// 边界备注：TS contracts 是 Rust 数据面（kernel-rs/wasmd）的镜像消费面——本测试钉死
//   「TS 决策链 + 控制态物理载体」的组合不变量；Rust 侧同款不变量由 kernel-rs/wasmd
//   批次的测试承载（跨实现语义由 host-services golden 向量互锁）。
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	WasmControlStateStore,
	WASM_CONTROL_STATE_FILENAME,
} from "../supervisor/wasm-control.ts";
import { systemStateStoreIO } from "../supervisor/wasm-shared.ts";
import { exampleExecutionCommand } from "../packages/contracts/wasm-execution.ts";
import {
	applyIwebKvCas,
	checkIwebKvWriteQuota,
	iwebKvConservativeReservedDeltaBytes,
	validateIwebKvMutationMarker,
} from "../packages/contracts/wasm-host-kv.ts";
import {
	IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS,
	validateIwebSqlExecuteRequest,
	validateIwebSqlResultWire,
} from "../packages/contracts/wasm-host-sql.ts";
import {
	createIwebLoggingRing,
	resetIwebLoggingRing,
	writeIwebLoggingEvent,
} from "../packages/contracts/wasm-host-logging.ts";

// ---------------------------------------------------------------------------
// 控制态世界：真实磁盘 + JCS 字节权威 + 非平凡初始态（V2 命令入 outbox）
// ---------------------------------------------------------------------------

interface ControlStateWorld {
	readonly store: WasmControlStateStore;
	readonly path: string;
	/** 初始态快照（mutation 批次前的完整读数与文件字节）。 */
	readonly initialState: ReturnType<WasmControlStateStore["read"]>;
	readonly initialBytes: Buffer;
}

function controlStateWorld(): ControlStateWorld {
	const directory = mkdtempSync(join(tmpdir(), "iweb-wasm-data-plane-"));
	const store = new WasmControlStateStore(systemStateStoreIO, directory);
	// 非平凡初始态：一次真实 CAS 把 V2 执行命令（数据面应用的 owner 命令）追加进 outbox。
	const appended = store.appendOutboxCommand(0, exampleExecutionCommand(), "2026-08-28T00:00:00Z");
	if (!appended.ok) throw new Error("fixture error: initial outbox append must commit");
	const initialState = store.read();
	if (initialState.controlRevision !== 1) throw new Error("fixture error: controlRevision must be 1 after the initial CAS");
	return {
		store,
		path: join(directory, WASM_CONTROL_STATE_FILENAME),
		initialState,
		initialBytes: readFileSync(join(directory, WASM_CONTROL_STATE_FILENAME)),
	};
}

// ---------------------------------------------------------------------------
// 数据面 mutation 批次：KV/SQL/Logging 的全部决策路径（contracts 纯函数构造）
// ---------------------------------------------------------------------------

interface MutationSummary {
	readonly kvCommitted: number;
	readonly kvConflicts: number;
	readonly kvUnavailable: number;
	readonly kvQuotaAllowed: number;
	readonly kvQuotaExceeded: number;
	readonly kvMarkersValid: number;
	readonly sqlAccepted: number;
	readonly sqlRejected: number;
	readonly sqlResultsValid: number;
	readonly loggingAccepted: number;
	readonly loggingDropped: number;
	readonly loggingRejected: number;
}

function runKvMutations(summary: { kvCommitted: number; kvConflicts: number; kvUnavailable: number; kvQuotaAllowed: number; kvQuotaExceeded: number; kvMarkersValid: number }): void {
	// CAS 线性化：创建（无条件写）→ 条件写命中 → stale writer 冲突 → 版本耗尽不可用。
	expect(applyIwebKvCas({ current: null, expected: null, nextVersion: 1 })).toEqual({ status: "committed", version: 1 });
	summary.kvCommitted += 1;
	expect(applyIwebKvCas({ current: { version: 1 }, expected: 1, nextVersion: 2 })).toEqual({ status: "committed", version: 2 });
	summary.kvCommitted += 1;
	expect(applyIwebKvCas({ current: { version: 2 }, expected: 1, nextVersion: 3 })).toEqual({ status: "conflict" });
	summary.kvConflicts += 1;
	expect(applyIwebKvCas({ current: { version: 4 }, expected: null, nextVersion: 4 })).toEqual({ status: "unavailable" });
	summary.kvUnavailable += 1;
	expect(applyIwebKvCas({ current: { version: Number.MAX_SAFE_INTEGER }, expected: null, nextVersion: Number.MAX_SAFE_INTEGER })).toEqual({ status: "unavailable" });
	summary.kvUnavailable += 1;

	// 写前配额：允许 / 超限 / 不可证明（任何非负 safe integer 缺一即坏 → 拒绝且零写入）。
	expect(checkIwebKvWriteQuota({ committedBytes: 100, outstandingReservedBytes: 0, reservedDeltaBytes: 50, aggregateEnvelopeBytes: 1000, kvCommittedBytes: 10, kvOutstandingReservedBytes: 0, kvServiceCapBytes: 200 })).toEqual({ status: "allowed", projectedBytes: 150 });
	summary.kvQuotaAllowed += 1;
	expect(checkIwebKvWriteQuota({ committedBytes: 100, outstandingReservedBytes: 0, reservedDeltaBytes: 1000, aggregateEnvelopeBytes: 1000 })).toEqual({ status: "quota-exceeded" });
	summary.kvQuotaExceeded += 1;
	expect(checkIwebKvWriteQuota({ committedBytes: -1, outstandingReservedBytes: 0, reservedDeltaBytes: 1, aggregateEnvelopeBytes: 1000 })).toEqual({ status: "quota-exceeded" });
	summary.kvQuotaExceeded += 1;

	// 保守预留公式 + 幂等 marker wire（spec「The backend marker includes the operationId,
	// reservationId and reservation proof」，重放返回原始 version）。
	expect(iwebKvConservativeReservedDeltaBytes({ keyBytes: 8, valueBytes: 100, entryOverheadBytes: 256 })).toBe(364);
	const marker = validateIwebKvMutationMarker({
		schemaVersion: 1,
		method: "set",
		key: "n.1",
		expectedVersion: null,
		assignedVersion: 1,
		operationId: "01890f2e-4a1e-7356-8f0c-6c2f11a7b901",
		reservationId: "01890f2e-4a1e-7456-9f0c-6c2f11a7b902",
		reservationProofDigest: "7".repeat(64),
	});
	expect(marker.ok).toBe(true);
	summary.kvMarkersValid += 1;
}

function runSqlMutations(summary: { sqlAccepted: number; sqlRejected: number; sqlResultsValid: number }): void {
	const limits = IWEB_SQL_MINIMAL_SQLITE_V1_LIMITS;
	// execute preflight：合法 insert（参数计数匹配）通过；超长语句在触碰任何后端前拒绝。
	const insert = validateIwebSqlExecuteRequest(
		"INSERT INTO notes (id, body) VALUES (?, ?)",
		[{ value: { kind: "integer", value: 1 } }, { value: { kind: "text", value: "hello" } }],
		limits,
	);
	expect(insert.ok).toBe(true);
	if (insert.ok) {
		expect(insert.value.kind).toBe("insert");
		expect(insert.value.parameterCount).toBe(2);
	}
	summary.sqlAccepted += 1;
	const oversized = validateIwebSqlExecuteRequest("S".repeat(limits.statementMaxBytes + 1), [], limits);
	expect(oversized.ok).toBe(false);
	if (!oversized.ok) expect(oversized.error.code).toBe("IWEB_SQL_STATEMENT_BYTES_EXCEEDED");
	summary.sqlRejected += 1;
	const countMismatch = validateIwebSqlExecuteRequest(
		"INSERT INTO notes (id) VALUES (?)",
		[],
		limits,
	);
	expect(countMismatch.ok).toBe(false);
	if (!countMismatch.ok) expect(countMismatch.error.code).toBe("IWEB_SQL_PARAMETER_COUNT_MISMATCH");
	summary.sqlRejected += 1;
	// 结果 wire：完整行集合法（截断/越限数据绝不包装成成功）。
	const result = validateIwebSqlResultWire(
		{ rows: [{ columns: [{ name: "id", value: { kind: "integer", value: 1 } }] }], affected: 0, lastInsertId: 1 },
		limits,
	);
	expect(result.ok).toBe(true);
	summary.sqlResultsValid += 1;
}

function runLoggingMutations(summary: { loggingAccepted: number; loggingDropped: number; loggingRejected: number }): void {
	const created = createIwebLoggingRing("notes-app", { maxEvents: 2, maxBytes: 4096 });
	expect(created.ok).toBe(true);
	if (!created.ok) return;
	let ring = created.value;
	const hostContext = (timestampUtc: string) => ({
		applicationId: "notes-app",
		versionId: "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1",
		preparationGeneration: 1,
		executionGeneration: 1,
		timestampUtc,
	});
	const event = (message: string) => ({ level: "info" as const, message, fields: [{ key: "code", value: "200" }] });
	// 环准入：accepted（两条）→ 满（drop-on-full，第三条 dropped）。
	for (let index = 0; index < 2; index += 1) {
		const written = writeIwebLoggingEvent(ring, hostContext("2026-08-28T00:00:0" + index + ".000Z"), event("accepted-" + index));
		expect(written.ok && written.outcome).toBe("accepted");
		summary.loggingAccepted += 1;
		if (written.ok) ring = written.ring;
	}
	const dropped = writeIwebLoggingEvent(ring, hostContext("2026-08-28T00:00:05.000Z"), event("dropped-by-full-ring"));
	expect(dropped.ok && dropped.outcome).toBe("dropped");
	summary.loggingDropped += 1;
	if (dropped.ok) ring = dropped.ring;
	expect(ring.droppedCount).toBe(1);
	// 超限事件（maxEventBytes 上界之下拒绝）：畸形 level 属 wire 拒绝（IWEB_LOG_INVALID_EVENT）。
	const rejected = writeIwebLoggingEvent(ring, hostContext("2026-08-28T00:00:06.000Z"), { level: "loud", message: "x", fields: [] });
	expect(rejected.ok).toBe(false);
	if (!rejected.ok) expect(rejected.code).toBe("IWEB_LOG_INVALID_EVENT");
	summary.loggingRejected += 1;
	// 生命周期重置（新执行代次开新环）：事件与 dropped 计数归零。
	const reset = resetIwebLoggingRing(ring);
	expect(reset.events).toHaveLength(0);
	expect(reset.droppedCount).toBe(0);
}

function runDataPlaneMutations(): MutationSummary {
	const summary: MutationSummary = {
		kvCommitted: 0,
		kvConflicts: 0,
		kvUnavailable: 0,
		kvQuotaAllowed: 0,
		kvQuotaExceeded: 0,
		kvMarkersValid: 0,
		sqlAccepted: 0,
		sqlRejected: 0,
		sqlResultsValid: 0,
		loggingAccepted: 0,
		loggingDropped: 0,
		loggingRejected: 0,
	};
	runKvMutations(summary);
	runSqlMutations(summary);
	runLoggingMutations(summary);
	return summary;
}

// ---------------------------------------------------------------------------
// 不变量：mutation 前后控制态文件字节不变（真实磁盘字节对比）
// ---------------------------------------------------------------------------

describe("host-services data plane leaves the control-state file byte-identical", () => {
	test("a full kv/sql/logging mutation batch changes no byte of wasm-control-state-v2.json", () => {
		const world = controlStateWorld();
		const bytesBefore = readFileSync(world.path);
		expect(Buffer.compare(bytesBefore, world.initialBytes)).toBe(0);
		const summary = runDataPlaneMutations();
		// 批次真实驱动了全部决策路径（防空转：任一路径缺失即测试失败）。
		expect(summary).toEqual({
			kvCommitted: 2,
			kvConflicts: 1,
			kvUnavailable: 2,
			kvQuotaAllowed: 1,
			kvQuotaExceeded: 2,
			kvMarkersValid: 1,
			sqlAccepted: 1,
			sqlRejected: 2,
			sqlResultsValid: 1,
			loggingAccepted: 2,
			loggingDropped: 1,
			loggingRejected: 1,
		});
		// 核心不变量：文件字节逐字节不变 + 读数（controlRevision/outbox）不变。
		const bytesAfter = readFileSync(world.path);
		expect(Buffer.compare(bytesAfter, bytesBefore)).toBe(0);
		const after = world.store.read();
		expect(after.controlRevision).toBe(world.initialState.controlRevision);
		expect(after.commandOutbox.length).toBe(world.initialState.commandOutbox.length);
		expect(JSON.stringify(after.commandOutbox)).toBe(JSON.stringify(world.initialState.commandOutbox));
	});

	test("interleaved reads during the batch stay byte-identical at every service boundary", () => {
		const world = controlStateWorld();
		const bytesBefore = readFileSync(world.path);
		const kvSummary = { kvCommitted: 0, kvConflicts: 0, kvUnavailable: 0, kvQuotaAllowed: 0, kvQuotaExceeded: 0, kvMarkersValid: 0 };
		runKvMutations(kvSummary);
		expect(Buffer.compare(readFileSync(world.path), bytesBefore)).toBe(0);
		const sqlSummary = { sqlAccepted: 0, sqlRejected: 0, sqlResultsValid: 0 };
		runSqlMutations(sqlSummary);
		expect(Buffer.compare(readFileSync(world.path), bytesBefore)).toBe(0);
		const loggingSummary = { loggingAccepted: 0, loggingDropped: 0, loggingRejected: 0 };
		runLoggingMutations(loggingSummary);
		expect(Buffer.compare(readFileSync(world.path), bytesBefore)).toBe(0);
	});

	test("method anchor: a real control-plane CAS does change the file bytes", () => {
		const world = controlStateWorld();
		const bytesBefore = readFileSync(world.path);
		// 对照锚：真正的控制面写（outbox CAS，controlRevision 1 → 2）必须被字节对比检出
		//——证明上面的不变量测试具备检出能力，不是恒真。
		const appended = world.store.appendOutboxCommand(
			1,
			{ ...exampleExecutionCommand(), commandId: "018f1e2c-3d4b-7a5e-9f01-23456789abce" },
			"2026-08-28T00:01:00Z",
		);
		expect(appended.ok).toBe(true);
		const bytesAfter = readFileSync(world.path);
		expect(Buffer.compare(bytesAfter, bytesBefore)).not.toBe(0);
		expect(world.store.read().controlRevision).toBe(2);
	});
});
