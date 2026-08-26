// 用户原始需求（2026-08-14）：应用监控主表的行模型——逐应用实测内存与强制上限、显式 unavailable、control-plane 节点开销标注。
// 正交意图：10.3/10.4；本文件是纯视图模型测试（bun/vitest 双跑）；DOM 渲染测试见 application-resource-table.svelte.test.ts。
import { describe, expect, test } from "vitest";
import { applicationResourceRows, CELL_REASONS, formatBytesValue } from "$lib/monitor/application-resource-table";
import type { ApplicationProjection, MonitorApp } from "$lib/iweb/contracts";

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

function projection(id: string, overrides: Partial<ApplicationProjection> = {}): ApplicationProjection {
	return {
		id,
		sandboxId: "sbx-" + id,
		activeVersion: { digest: "a".repeat(64), sequence: 1 },
		routeGeneration: 1,
		lifecycle: "active",
		versions: [],
		resources: {
			versionId: "v1",
			sampledAt: "2026-08-14T00:00:00.000Z",
			cpuMillis: { available: true, value: 1500 },
			memoryBytes: { available: true, value: 64 * 1024 * 1024 },
			pidCount: { available: true, value: 3 },
			terminated: { available: true, value: 0 },
			limits: { cpuMillis: 500, memoryBytes: 128 * 1024 * 1024, pidLimit: 128, storageBytes: 1024 ** 3 },
		},
		...overrides,
	};
}

describe("application resource table row model (10.3)", () => {
	test("every visible application row carries measured memory, enforced limit, requests, and lifecycle", () => {
		const rows = applicationResourceRows({
			apps: [app("notes")],
			sandboxes: [projection("notes")],
			applications: null,
		});
		expect(rows).toHaveLength(1);
		expect(rows[0].memory).toEqual({ kind: "value", text: "64.0 MiB" });
		expect(rows[0].memoryLimit).toEqual({ kind: "value", text: "128 MiB" });
		expect(rows[0].requests).toEqual({ kind: "value", text: "12" });
		expect(rows[0].lifecycle).toEqual({ kind: "value", text: "active" });
		expect(rows[0].terminated).toBe(false);
	});

	test("changing per-application usage changes the row, not the limit", () => {
		const first = applicationResourceRows({ apps: [app("notes")], sandboxes: [projection("notes")], applications: null });
		const second = applicationResourceRows({
			apps: [app("notes")],
			sandboxes: [projection("notes", { resources: { ...projection("notes").resources!, memoryBytes: { available: true, value: 32 * 1024 * 1024 }, terminated: { available: true, value: 1 } } })],
			applications: null,
		});
		expect(first[0].memory.text).toBe("64.0 MiB");
		expect(second[0].memory.text).toBe("32.0 MiB");
		expect(second[0].memoryLimit.text).toBe("128 MiB");
		expect(second[0].terminated).toBe(true);
	});

	test("a cgroup-unavailable sample stays visible as an explicit unavailable state, never 0", () => {
		const rows = applicationResourceRows({
			apps: [app("notes")],
			sandboxes: [projection("notes", { resources: { ...projection("notes").resources!, memoryBytes: { available: false } } })],
			applications: null,
		});
		expect(rows[0].memory.kind).toBe("unavailable");
		expect(rows[0].memory.text).not.toContain("0");
		// a sandboxed-but-unmeasured cell explains WHY (no sample this cycle)
		if (rows[0].memory.kind !== "value") expect(rows[0].memory.reason).toBe(CELL_REASONS.noSample);
		// the enforced limit column survives a missing measurement
		expect(rows[0].memoryLimit.text).toBe("128 MiB");
	});

	test("a not-yet-sandboxed application stays visible with an explicit not-sandboxed state and intact columns", () => {
		const rows = applicationResourceRows({
			apps: [app("draft")],
			sandboxes: null,
			applications: [projection("draft", { sandboxId: null, lifecycle: "admitted", resources: null })],
		});
		expect(rows).toHaveLength(1);
		expect(rows[0].memory).toEqual({ kind: "unavailable", text: "不可用（未沙箱化）", reason: CELL_REASONS.notSandboxed });
		expect(rows[0].memoryLimit.kind).toBe("unavailable");
		if (rows[0].memoryLimit.kind !== "value") expect(rows[0].memoryLimit.reason).toBe(CELL_REASONS.notSandboxed);
		expect(rows[0].lifecycle.text).toBe("admitted");
	});

	test("control-plane applications show their own celld process RSS: a real per-app measurement (2026-08-15 design)", () => {
		// each control-plane app = exactly one celld process; its RSS is real
		const processResources = {
			versionId: "celld-process",
			sampledAt: "2026-08-15T00:00:00.000Z",
			cpuMillis: { available: false as const },
			memoryBytes: { available: true as const, value: 48 * 1024 * 1024 },
			pidCount: { available: false as const },
			terminated: { available: false as const },
			limits: null,
		};
		const rows = applicationResourceRows({
			apps: [app("admin", { system: true }), app("mcp", { system: true })],
			sandboxes: [
				projection("admin", { sandboxId: null, resources: processResources }),
				projection("mcp", { sandboxId: null, resources: { ...processResources, memoryBytes: { available: true, value: 30 * 1024 * 1024 } } }),
			],
			applications: null,
		});
		expect(rows[0].memory).toEqual({ kind: "value", text: "48.0 MiB" });
		expect(rows[1].memory).toEqual({ kind: "value", text: "30.0 MiB" });
		// no enforced limit exists for a plain celld process: explicit, explained
		for (const row of rows) {
			expect(row.memoryLimit.kind).toBe("unavailable");
			if (row.memoryLimit.kind !== "value") expect(row.memoryLimit.reason).toBe(CELL_REASONS.controlPlaneNoLimit);
		}
	});

	test("a control-plane app whose process RSS cannot be read stays explicit, never 0 or node total", () => {
		const rows = applicationResourceRows({
			apps: [app("admin", { system: true })],
			sandboxes: [projection("admin", { sandboxId: null, resources: null })],
			applications: null,
		});
		expect(rows[0].memory.kind).toBe("unavailable");
		if (rows[0].memory.kind !== "value") expect(rows[0].memory.reason).toBe(CELL_REASONS.controlPlaneNoSample);
	});

	test("monitor-frame app resources (process RSS) reach control-plane rows without any control projection (live path)", () => {
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
			sandboxes: null,
			applications: null,
		});
		expect(rows[0].memory).toEqual({ kind: "value", text: "80.0 MiB" });
		expect(rows[1].memory).toEqual({ kind: "value", text: "70.0 MiB" });
	});

	test("the model structurally cannot copy the node cgroup total into an application row", () => {
		const nodeTotal = 900 * 1024 * 1024;
		const rows = applicationResourceRows({
			apps: [app("notes", { system: true })],
			sandboxes: [projection("notes", { sandboxId: null, resources: null })],
			applications: null,
		});
		// the API takes no node-memory input at all; no row text may equal the node total
		expect(applicationResourceRows.length).toBe(1);
		for (const row of rows) {
			expect(row.memory.text).not.toBe(formatBytesValue(nodeTotal));
			expect(row.memoryLimit.text).not.toBe(formatBytesValue(nodeTotal));
		}
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
			sandboxes: [projection("moonbit-demo")],
			applications: null,
		});
		expect(rows[0].engine).toEqual({ kind: "value", text: "4.0 MiB · 1 实例" });
		// engine 口径与 cgroup 口径并列互不换算：内存列仍是 cgroup 实测值。
		expect(rows[0].memory).toEqual({ kind: "value", text: "64.0 MiB" });
	});

	test("an unavailable engine projection stays explicit unavailable, never zero", () => {
		const rows = applicationResourceRows({
			apps: [app("moonbit-demo", { engine: engineProjection({ availability: "unavailable", engine: null, sampledAt: null }) })],
			sandboxes: [projection("moonbit-demo")],
			applications: null,
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
			sandboxes: [projection("notes"), projection("moonbit-demo")],
			applications: null,
		});
		expect(rows[0].engine).toEqual({ kind: "not-applicable", text: "不适用", reason: CELL_REASONS.engineNotWasm });
		// JS 参考内核帧（不发射 engine 字段）与 null 投影同走「不适用」。
		const nullEngine = applicationResourceRows({
			apps: [app("notes", { engine: null })],
			sandboxes: [projection("notes")],
			applications: null,
		});
		expect(nullEngine[0].engine.kind).toBe("not-applicable");
	});
});