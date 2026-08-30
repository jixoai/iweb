// 用户原始需求（2026-08-14）：应用监控主表的行模型——逐应用实测内存与上限、显式 unavailable、节点总额标注。
// 正交意图：本文件是纯视图模型测试（bun/vitest 双跑）；DOM 渲染测试见 application-resource-table.svelte.test.ts。
// two-tier-runtime-trust（2026-08-30）：投影是路由派生 celld fleet（sandboxId 恒 null、无版本）；
// 新增「软上限」（看门狗软限）与「看门狗」（最近一次越限处决）列。
import { describe, expect, test } from "vitest";
import { applicationResourceRows, CELL_REASONS, formatBytesValue, formatWatchdogStamp } from "$lib/monitor/application-resource-table";
import type { ApplicationProjection, MonitorApp, WatchdogProjection } from "$lib/iweb/contracts";

function app(id: string, overrides: Partial<MonitorApp> = {}): MonitorApp {
	return {
		id,
		domains: [],
		deployed: true,
		system: false,
		requests: 12,
		errors: 1,
		inFlight: 0,
		averageLatencyMs: 8,
		lastRequestAt: null,
		...overrides,
	};
}

// 路由派生 celld fleet 投影：runtimeKind 恒 celld、无沙箱身份、无版本生命周期；
// resources 是该应用独立 celld 进程的采样（VmRSS / /proc stat 差分）。
function projection(id: string, overrides: Partial<ApplicationProjection> = {}): ApplicationProjection {
	return {
		id,
		runtimeKind: "celld",
		sandboxId: null,
		activeVersion: null,
		routeGeneration: 1,
		lifecycle: "active",
		versions: [],
		resources: {
			versionId: "celld-process",
			sampledAt: "2026-08-14T00:00:00.000Z",
			cpuMillis: { available: true, value: 1500 },
			memoryBytes: { available: true, value: 64 * 1024 * 1024 },
			pidCount: { available: true, value: 3 },
			terminated: { available: true, value: 0 },
			limits: { cpuMillis: null, memoryBytes: 128 * 1024 * 1024, pidLimit: null, storageBytes: null, enforcement: "watchdog-soft" },
		},
		...overrides,
	};
}

describe("application resource table row model (10.3)", () => {
	test("every visible application row carries measured memory, limit, requests, and lifecycle", () => {
		const rows = applicationResourceRows({
			apps: [app("notes")],
			applications: [projection("notes")],
		});
		expect(rows).toHaveLength(1);
		expect(rows[0].memory).toEqual({ kind: "value", text: "64.0 MiB" });
		expect(rows[0].memoryLimit).toEqual({ kind: "value", text: "128 MiB" });
		expect(rows[0].requests).toEqual({ kind: "value", text: "12" });
		expect(rows[0].lifecycle).toEqual({ kind: "value", text: "active" });
		expect(rows[0].terminated).toBe(false);
	});

	test("changing per-application usage changes the row, not the limit", () => {
		const first = applicationResourceRows({ apps: [app("notes")], applications: [projection("notes")] });
		const second = applicationResourceRows({
			apps: [app("notes")],
			applications: [projection("notes", { resources: { ...projection("notes").resources!, memoryBytes: { available: true, value: 32 * 1024 * 1024 }, terminated: { available: true, value: 1 } } })],
		});
		expect(first[0].memory.text).toBe("64.0 MiB");
		expect(second[0].memory.text).toBe("32.0 MiB");
		expect(second[0].memoryLimit.text).toBe("128 MiB");
		expect(second[0].terminated).toBe(true);
	});

	test("a process sample that cannot be read stays visible as an explicit unavailable state, never 0", () => {
		const rows = applicationResourceRows({
			apps: [app("notes")],
			applications: [projection("notes", { resources: { ...projection("notes").resources!, memoryBytes: { available: false } } })],
		});
		expect(rows[0].memory.kind).toBe("unavailable");
		expect(rows[0].memory.text).not.toContain("0");
		// a supervised-process row without a sample explains WHY (pidfile//proc unreadable)
		if (rows[0].memory.kind !== "value") expect(rows[0].memory.reason).toBe(CELL_REASONS.processNoSample);
		// the limit column survives a missing measurement
		expect(rows[0].memoryLimit.text).toBe("128 MiB");
	});

	test("a fleet app without any projection sample keeps explicit unavailable cells with intact columns", () => {
		const rows = applicationResourceRows({
			apps: [app("draft")],
			applications: [projection("draft", { lifecycle: "unavailable", resources: null })],
		});
		expect(rows).toHaveLength(1);
		expect(rows[0].memory).toEqual({ kind: "unavailable", text: "不可用", reason: CELL_REASONS.processNoSample });
		expect(rows[0].memoryLimit.kind).toBe("unavailable");
		if (rows[0].memoryLimit.kind !== "value") expect(rows[0].memoryLimit.reason).toBe(CELL_REASONS.processNoLimit);
		expect(rows[0].lifecycle.text).toBe("unavailable");
	});

	test("celld fleet apps show their own process RSS: a real per-app measurement (two-tier-runtime-trust)", () => {
		// each fleet app = exactly one supervised celld process; its RSS is real
		const rows = applicationResourceRows({
			apps: [app("admin", { system: true }), app("notes")],
			applications: [
				projection("admin", { resources: { ...projection("admin").resources!, memoryBytes: { available: true, value: 48 * 1024 * 1024 }, limits: null } }),
				projection("notes", { resources: { ...projection("notes").resources!, memoryBytes: { available: true, value: 30 * 1024 * 1024 } } }),
			],
		});
		expect(rows[0].memory).toEqual({ kind: "value", text: "48.0 MiB" });
		expect(rows[1].memory).toEqual({ kind: "value", text: "30.0 MiB" });
		// no enforced limit exists for a plain celld process: explicit, explained
		expect(rows[0].memoryLimit.kind).toBe("unavailable");
		if (rows[0].memoryLimit.kind !== "value") expect(rows[0].memoryLimit.reason).toBe(CELL_REASONS.processNoLimit);
		// a fleet app reporting its soft limit through the sample keeps the value
		expect(rows[1].memoryLimit).toEqual({ kind: "value", text: "128 MiB" });
	});

	test("an app whose process RSS cannot be read stays explicit, never 0 or node total", () => {
		const rows = applicationResourceRows({
			apps: [app("admin", { system: true })],
			applications: [projection("admin", { resources: null })],
		});
		expect(rows[0].memory.kind).toBe("unavailable");
		if (rows[0].memory.kind !== "value") expect(rows[0].memory.reason).toBe(CELL_REASONS.processNoSample);
	});

	test("monitor-frame app resources (process RSS) reach rows without any status projection (live path)", () => {
		const frameResources = {
			versionId: "celld-process",
			sampledAt: "2026-08-15T00:00:00.000Z",
			cpuMillis: { available: false },
			memoryBytes: { available: true, value: 80 * 1024 * 1024 },
			pidCount: { available: false },
			terminated: { available: false },
			limits: null,
		};
		const rows = applicationResourceRows({
			apps: [app("admin", { system: true, resources: frameResources } as Partial<MonitorApp>), app("mcp", { system: true, resources: { ...frameResources, memoryBytes: { available: true, value: 70 * 1024 * 1024 } } } as Partial<MonitorApp>)],
			applications: null,
		});
		expect(rows[0].memory).toEqual({ kind: "value", text: "80.0 MiB" });
		expect(rows[1].memory).toEqual({ kind: "value", text: "70.0 MiB" });
	});

	test("legacy sandboxed projections (old kernel frames) keep their sandbox semantics", () => {
		const rows = applicationResourceRows({
			apps: [app("legacy")],
			applications: [projection("legacy", { sandboxId: "sbx-legacy-1" })],
		});
		expect(rows[0].memory).toEqual({ kind: "value", text: "64.0 MiB" });
		const flaky = applicationResourceRows({
			apps: [app("legacy")],
			applications: [projection("legacy", { sandboxId: "sbx-legacy-1", resources: { ...projection("legacy").resources!, memoryBytes: { available: false } } })],
		});
		expect(flaky[0].memory.kind).toBe("unavailable");
		// sandbox rows keep the supervisor-unreachable reason, not the process-sampling one
		if (flaky[0].memory.kind !== "value") expect(flaky[0].memory.reason).toBe(CELL_REASONS.noSample);
	});

	test("the model structurally cannot copy the node cgroup total into an application row", () => {
		const nodeTotal = 900 * 1024 * 1024;
		const rows = applicationResourceRows({
			apps: [app("notes", { system: true })],
			applications: [projection("notes", { resources: null })],
		});
		// the API takes no node-memory input at all; no row text may equal the node total
		expect(applicationResourceRows.length).toBe(1);
		for (const row of rows) {
			expect(row.memory.text).not.toBe(formatBytesValue(nodeTotal));
			expect(row.memoryLimit.text).not.toBe(formatBytesValue(nodeTotal));
		}
	});
});

describe("watchdog soft-limit and kill-event columns (two-tier-runtime-trust)", () => {
	const watchdog = (overrides: Partial<WatchdogProjection> = {}): WatchdogProjection => ({
		intervalMs: 15000,
		defaultBytes: 512 * 1024 * 1024,
		apps: { notes: 256 * 1024 * 1024 },
		events: [
			{ applicationId: "notes", sampledBytes: 280 * 1024 * 1024, limitBytes: 256 * 1024 * 1024, terminatedAt: "2026-08-29T08:00:00.000Z" },
			{ applicationId: "notes", sampledBytes: 300 * 1024 * 1024, limitBytes: 256 * 1024 * 1024, terminatedAt: "2026-08-29T09:30:00.000Z" }
		],
		...overrides,
	});

	test("the soft-limit column shows the per-app override, falling back to the watchdog default", () => {
		const rows = applicationResourceRows({
			apps: [app("notes"), app("mcp")],
			applications: [projection("notes"), projection("mcp")],
			watchdog: watchdog(),
		});
		// apps[appId] 覆盖值；缺省应用回落 defaultBytes（512 MiB）。
		expect(rows[0].softLimit).toEqual({ kind: "value", text: "256 MiB" });
		expect(rows[1].softLimit).toEqual({ kind: "value", text: "512 MiB" });
	});

	test("without a watchdog projection the soft-limit column is explicit unavailable, never invented", () => {
		const rows = applicationResourceRows({
			apps: [app("notes")],
			applications: [projection("notes")],
			watchdog: null,
		});
		expect(rows[0].softLimit).toEqual({ kind: "unavailable", text: "不可用", reason: CELL_REASONS.watchdogNoProjection });
	});

	test("the watchdog column shows the most recent kill event (timestamp + sampled RSS)", () => {
		const rows = applicationResourceRows({
			apps: [app("notes")],
			applications: [projection("notes")],
			watchdog: watchdog(),
		});
		// 事件环无序保证：取 terminatedAt 最大者（09:30 的事件，采样 300 MiB）。
		expect(rows[0].watchdog).toEqual({
			kind: "value",
			text: formatWatchdogStamp("2026-08-29T09:30:00.000Z") + " · 300 MiB"
		});
	});

	test("an app without kill records renders an explicit dash, not a zero or a hidden cell", () => {
		const rows = applicationResourceRows({
			apps: [app("notes"), app("mcp")],
			applications: [projection("notes"), projection("mcp")],
			watchdog: watchdog(),
		});
		expect(rows[1].watchdog).toEqual({ kind: "not-applicable", text: "—", reason: CELL_REASONS.watchdogNoEvent });
	});
});

describe("wasm engine metrics projection rows (add-wasm-runtime 4.4)", () => {
	const engineProjection = (overrides: Partial<NonNullable<MonitorApp["engine"]>> = {}): NonNullable<MonitorApp["engine"]> => ({
		scope: "wasm-engine",
		sandboxId: "sbx-vector",
		versionId: "a".repeat(64) + "-1",
		preparationGeneration: 1,
		executionGeneration: 2,
		sampledAt: "2026-08-26T00:00:00Z",
		availability: "available",
		engine: {
			fuelConsumedCumulative: null,
			epochTimeoutsCumulative: 0,
			instancesLiveInstant: 1,
			instancesHighWaterCumulative: 1,
			guestMemoryBytesInstant: 4 * 1024 * 1024,
		},
		...overrides,
	});

	test("an available engine projection renders guest memory and live instances as a separately labeled scope", () => {
		const rows = applicationResourceRows({
			apps: [app("moonbit-demo", { engine: engineProjection() })],
			applications: [projection("moonbit-demo")],
		});
		expect(rows[0].engine).toEqual({ kind: "value", text: "4.0 MiB · 1 实例" });
		// engine 口径与进程口径并列互不换算：内存列仍是该应用进程的实测值。
		expect(rows[0].memory).toEqual({ kind: "value", text: "64.0 MiB" });
	});

	test("an unavailable engine projection stays explicit unavailable, never zero", () => {
		const rows = applicationResourceRows({
			apps: [app("moonbit-demo", { engine: engineProjection({ availability: "unavailable", engine: null, sampledAt: null }) })],
			applications: [projection("moonbit-demo")],
		});
		expect(rows[0].engine.kind).toBe("unavailable");
		if (rows[0].engine.kind === "unavailable") {
			expect(rows[0].engine.reason).toBe(CELL_REASONS.engineNoSample);
			expect(rows[0].engine.text).not.toContain("0");
		}
	});

	test("a non-wasm application renders an explicit not-applicable engine cell, distinct from a measurement failure", () => {
		const rows = applicationResourceRows({
			apps: [app("notes"), app("moonbit-demo", { engine: engineProjection() })],
			applications: [projection("notes"), projection("moonbit-demo")],
		});
		expect(rows[0].engine).toEqual({ kind: "not-applicable", text: "不适用", reason: CELL_REASONS.engineNotWasm });
		// 旧帧（不发射 engine 字段）与 null 投影同走「不适用」。
		const nullEngine = applicationResourceRows({
			apps: [app("notes", { engine: null })],
			applications: [projection("notes")],
		});
		expect(nullEngine[0].engine.kind).toBe("not-applicable");
	});

	test("a wasm row without a celld projection renders process-scope cells as not-applicable, not unavailable", () => {
		// wasm 应用不在 celld fleet 投影中：进程口径内存对它「不适用」（口径不同，
		// 不是测量失败）；wasm 数值由引擎列呈现。
		const rows = applicationResourceRows({
			apps: [app("moonbit-demo", { engine: engineProjection() })],
			applications: null,
		});
		expect(rows[0].memory).toEqual({ kind: "not-applicable", text: "不适用", reason: CELL_REASONS.processNotCelld });
		expect(rows[0].memoryLimit.kind).toBe("not-applicable");
		expect(rows[0].lifecycle.kind).toBe("not-applicable");
	});
});
describe("wasm host-services summary rows (add-wasm-host-services)", () => {
	const hostServicesProjection = (overrides: Partial<NonNullable<MonitorApp["hostServices"]>> = {}): NonNullable<MonitorApp["hostServices"]> => ({
		availability: "available",
		logging: {
			applicationId: "moonbit-demo",
			retainedEvents: 12,
			retainedBytes: 20480,
			droppedCount: 3,
			lastEventId: 15,
			capacity: { maxEvents: 256, maxBytes: 262144 },
		},
		...overrides,
	});

	test("an available host-services projection renders counts and status only — no bodies, no values", () => {
		const rows = applicationResourceRows({
			apps: [app("moonbit-demo", { hostServices: hostServicesProjection() })],
			applications: [projection("moonbit-demo")],
		});
		expect(rows[0].hostServices).toEqual({ kind: "value", text: "日志 12 · 丢弃 3" });
		// 摘要列绝不携带日志正文或字段值。
		expect(JSON.stringify(rows[0].hostServices)).not.toContain("message");
	});

	test("an unavailable host-services projection stays explicit unavailable, never zero", () => {
		const rows = applicationResourceRows({
			apps: [app("moonbit-demo", { hostServices: hostServicesProjection({ availability: "unavailable", logging: null }) })],
			applications: [projection("moonbit-demo")],
		});
		expect(rows[0].hostServices.kind).toBe("unavailable");
		if (rows[0].hostServices.kind === "unavailable") {
			expect(rows[0].hostServices.reason).toBe(CELL_REASONS.hostServicesNoSample);
			expect(rows[0].hostServices.text).not.toContain("0");
		}
	});

	test("an application without host services renders an explicit not-applicable cell", () => {
		const rows = applicationResourceRows({
			apps: [app("notes"), app("moonbit-demo", { hostServices: hostServicesProjection() })],
			applications: [projection("notes"), projection("moonbit-demo")],
		});
		expect(rows[0].hostServices).toEqual({ kind: "not-applicable", text: "不适用", reason: CELL_REASONS.hostServicesNotApplicable });
		// 与 engine 列独立：未启用宿主服务的 wasm 应用仍可有 engine 口径。
		expect(rows[0].hostServices.kind).toBe("not-applicable");
	});
});
