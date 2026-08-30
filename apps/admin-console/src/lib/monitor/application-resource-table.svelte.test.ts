// 用户原始需求（2026-08-14）：Admin 组件测试必须是真实渲染断言，而不是源码字符串断言。
// 正交意图：10.4——真实挂载 Svelte 组件到 happy-dom，断言渲染出的表格行；在无法编译 .svelte 的运行器（纯 bun test）下显式跳过。
// two-tier-runtime-trust（2026-08-30）：断言「软上限」与「看门狗」两列的真实渲染。
import { describe, expect, test } from "vitest";
import type { ApplicationProjection, MonitorApp, WatchdogProjection } from "$lib/iweb/contracts";
import { formatWatchdogStamp } from "$lib/monitor/application-resource-table";

// Vitest compiles the .svelte module through the Svelte plugin and mounts it
// in happy-dom. A runner without the Svelte compiler (plain bun test discovery
// outside admin-console) cannot compile it; the suite then skips explicitly
// instead of failing the battery.
type ComponentModule = { default: new (options: { target: HTMLElement; props: Record<string, unknown> }) => Record<string, unknown> };
let component: ComponentModule["default"] | null = null;
let runtime: typeof import("svelte") | null = null;
try {
	component = ((await import("./application-resource-table.svelte")) as unknown as ComponentModule).default;
	// real component render in a real DOM: the components vitest project pins
	// the exact "svelte" specifier to the client entry so mount() exists
	runtime = await import("svelte");
} catch {
	component = null;
	runtime = null;
}
const ApplicationResourceTable = component;
// a runner without the Svelte compiler yields no callable component (and no
// DOM); those environments skip the DOM suite instead of failing
const domAvailable = typeof component === "function" && runtime !== null && typeof runtime.mount === "function" && typeof document !== "undefined";

function app(id: string, overrides: Partial<MonitorApp> = {}): MonitorApp {
	return { id, domains: [], deployed: true, system: false, requests: 5, errors: 0, inFlight: 0, averageLatencyMs: 7, lastRequestAt: null, ...overrides };
}

// 路由派生 celld fleet 投影：sandboxId 恒 null、无版本；resources 是进程采样。
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
			cpuMillis: { available: true, value: 1200 },
			memoryBytes: { available: true, value: 64 * 1024 * 1024 },
			pidCount: { available: true, value: 4 },
			terminated: { available: true, value: 0 },
			limits: { cpuMillis: null, memoryBytes: 128 * 1024 * 1024, pidLimit: null, storageBytes: null },
		},
		...overrides,
	};
}

function render(props: { apps: MonitorApp[]; applications: ApplicationProjection[] | null; watchdog?: WatchdogProjection | null }): HTMLElement {
	const svelte = runtime!;
	const target = document.createElement("div");
	document.body.appendChild(target);
	svelte.mount(ApplicationResourceTable as Parameters<typeof svelte.mount>[0], { target, props });
	svelte.flushSync();
	return target;
}

function cell(target: HTMLElement, appId: string, name: string): string {
	const row = target.querySelector('[data-app="' + appId + '"]');
	if (!row) throw new Error("missing row for " + appId);
	const cell = row.querySelector('[data-cell="' + name + '"]');
	if (!cell) throw new Error("missing cell " + name + " for " + appId);
	return (cell.textContent ?? "").trim();
}

function cellTitle(target: HTMLElement, appId: string, name: string): string {
	const row = target.querySelector('[data-app="' + appId + '"]');
	const cellElement = row?.querySelector('[data-cell="' + name + '"]');
	return cellElement?.getAttribute("title") ?? "";
}

describe.skipIf(!domAvailable)("ApplicationResourceTable rendered behavior (10.4)", () => {
	test("renders measured memory beside the limit, requests, and lifecycle", () => {
		const target = render({ apps: [app("notes")], applications: [projection("notes")] });
		expect(target.querySelector('[data-testid="application-resource-table"]')).not.toBeNull();
		expect(cell(target, "notes", "memory")).toBe("64.0 MiB");
		expect(cell(target, "notes", "memory-limit")).toBe("128 MiB");
		expect(target.querySelector('[data-app="notes"]')?.textContent).toContain("运行中");
		expect(target.querySelector('[data-app="notes"]')?.textContent).toContain("5");
	});

	test("changing usage re-renders the measured value; a limit termination shows the terminated badge", () => {
		const target = render({
			apps: [app("notes")],
			applications: [projection("notes", { resources: { ...projection("notes").resources!, memoryBytes: { available: true, value: 32 * 1024 * 1024 }, terminated: { available: true, value: 1 } } })],
		});
		expect(cell(target, "notes", "memory")).toBe("32.0 MiB");
		expect(cell(target, "notes", "memory-limit")).toBe("128 MiB");
		expect(target.querySelector('[data-app="notes"]')?.textContent).toContain("已终止");
	});

	test("unavailable rows keep every resource column visible with explicit states", () => {
		const target = render({
			apps: [app("flaky"), app("draft")],
			applications: [
				projection("flaky", { resources: { ...projection("flaky").resources!, memoryBytes: { available: false } } }),
				projection("draft", { lifecycle: "unavailable", resources: null }),
			],
		});
		expect(cell(target, "flaky", "memory")).toBe("不可用");
		expect(cell(target, "flaky", "memory-limit")).toBe("128 MiB");
		expect(cell(target, "draft", "memory")).toBe("不可用");
		expect(cell(target, "draft", "memory-limit")).toBe("不可用");
		// non-value cells explain themselves via tooltip reasons (10.4)
		expect(cellTitle(target, "flaky", "memory")).toContain("未能读取其进程采样");
		expect(cellTitle(target, "draft", "memory")).toContain("未能读取其进程采样");
		expect(cellTitle(target, "draft", "memory-limit")).toContain("未设置强制内存上限");
		// the columns exist for every row, never hidden by a missing sample
		for (const id of ["flaky", "draft"]) {
			expect(target.querySelector('[data-app="' + id + '"] [data-cell="memory"]')).not.toBeNull();
			expect(target.querySelector('[data-app="' + id + '"] [data-cell="memory-limit"]')).not.toBeNull();
			expect(target.querySelector('[data-app="' + id + '"] [data-cell="soft-limit"]')).not.toBeNull();
			expect(target.querySelector('[data-app="' + id + '"] [data-cell="watchdog"]')).not.toBeNull();
		}
		// the table carries an explanatory footnote so the empty-looking
		// resource columns never read as broken
		const note = target.querySelector('[data-testid="resource-table-note"]');
		expect(note?.textContent ?? "").toContain("独立的 celld 进程");
		expect(note?.textContent ?? "").toContain("不会用 0 代替");
	});

	test("celld process rows render their own process RSS (one supervised process per app)", () => {
		const nodeTotal = "879.9 MiB"; // a formatted node-total value that must never appear in a row
		const processResources = {
			versionId: "celld-process",
			sampledAt: "2026-08-15T00:00:00.000Z",
			cpuMillis: { available: false as const },
			memoryBytes: { available: true as const, value: 48 * 1024 * 1024 },
			pidCount: { available: false as const },
			terminated: { available: false as const },
			limits: null,
		};
		const target = render({
			apps: [app("admin", { system: true }), app("notes")],
			applications: [projection("admin", { resources: processResources }), projection("notes")],
		});
		expect(cell(target, "admin", "memory")).toBe("48.0 MiB");
		expect(cell(target, "admin", "memory-limit")).toBe("不可用");
		expect(cellTitle(target, "admin", "memory-limit")).toContain("未设置强制内存上限");
		expect(target.querySelector('[data-testid="application-resource-table"]')?.textContent).not.toContain(nodeTotal);
	});

	test("watchdog columns render the soft limit and the latest kill event; a dash when no record (two-tier-runtime-trust)", () => {
		const watchdog: WatchdogProjection = {
			intervalMs: 15000,
			defaultBytes: 512 * 1024 * 1024,
			apps: { notes: 256 * 1024 * 1024 },
			events: [
				{ applicationId: "notes", sampledBytes: 300 * 1024 * 1024, limitBytes: 256 * 1024 * 1024, terminatedAt: "2026-08-29T09:30:00.000Z" },
				{ applicationId: "mcp", sampledBytes: 600 * 1024 * 1024, limitBytes: 512 * 1024 * 1024, terminatedAt: "2026-08-29T10:00:00.000Z" }
			]
		};
		const target = render({
			apps: [app("notes"), app("mcp")],
			applications: [projection("notes"), projection("mcp")],
			watchdog
		});
		// 软上限：覆盖值 / 默认值；看门狗：最近一次越限处决（时间 + 采样值）。
		expect(cell(target, "notes", "soft-limit")).toBe("256 MiB");
		expect(cell(target, "mcp", "soft-limit")).toBe("512 MiB");
		expect(cell(target, "notes", "watchdog")).toBe(formatWatchdogStamp("2026-08-29T09:30:00.000Z") + " · 300 MiB");
		// 脚注交代软限语义：15 秒采样、越限 SIGKILL 单进程、entrypoint 退避重启。
		const note = target.querySelector('[data-testid="resource-table-note"]');
		expect(note?.textContent ?? "").toContain("15 秒采样");
		expect(note?.textContent ?? "").toContain("SIGKILL");
		// 无看门狗投影：软上限显式不可用（带原因）；无事件记录显式「—」。
		const bare = render({ apps: [app("notes")], applications: [projection("notes")] });
		expect(cell(bare, "notes", "soft-limit")).toBe("不可用");
		expect(cellTitle(bare, "notes", "soft-limit")).toContain("不会编造数值");
		expect(cell(bare, "notes", "watchdog")).toBe("—");
	});

	test("an empty application surface renders an explicit empty state, not a hidden table", () => {
		const target = render({ apps: [], applications: null });
		expect(target.querySelector('[data-testid="no-applications"]')).not.toBeNull();
	});

	test("wasm rows render the engine scope column; non-wasm rows render an explicit not-applicable cell (4.4)", () => {
		const engine = {
			scope: "wasm-engine" as const,
			sandboxId: "sbx-vector",
			versionId: "a".repeat(64) + "-1",
			preparationGeneration: 1,
			executionGeneration: 2,
			sampledAt: "2026-08-26T00:00:00Z",
			availability: "available" as const,
			engine: {
				fuelConsumedCumulative: null,
				epochTimeoutsCumulative: 0,
				instancesLiveInstant: 1,
				instancesHighWaterCumulative: 1,
				guestMemoryBytesInstant: 4 * 1024 * 1024,
			},
		};
		const unavailable = { ...engine, availability: "unavailable" as const, engine: null, sampledAt: null };
		const target = render({
			apps: [app("moonbit-demo", { engine }), app("warming", { engine: unavailable }), app("notes")],
			applications: [projection("moonbit-demo"), projection("warming"), projection("notes")],
		});
		expect(cell(target, "moonbit-demo", "engine")).toBe("4.0 MiB · 1 实例");
		expect(cell(target, "warming", "engine")).toBe("不可用");
		expect(cellTitle(target, "warming", "engine")).toContain("不会用 0 代替");
		expect(cell(target, "notes", "engine")).toBe("不适用");
		expect(cellTitle(target, "notes", "engine")).toContain("不是 wasm 运行时");
	});

	test("host-services rows render counts only; non-host-services rows render an explicit not-applicable cell (add-wasm-host-services)", () => {
		const hostServices = {
			availability: "available" as const,
			logging: {
				applicationId: "moonbit-demo",
				retainedEvents: 12,
				retainedBytes: 20480,
				droppedCount: 3,
				lastEventId: 15,
				capacity: { maxEvents: 256, maxBytes: 262144 },
			},
		};
		const unavailable = { availability: "unavailable" as const, logging: null };
		const target = render({
			apps: [app("moonbit-demo", { hostServices }), app("cooling", { hostServices: unavailable }), app("notes")],
			applications: [projection("moonbit-demo"), projection("cooling"), projection("notes")],
		});
		expect(cell(target, "moonbit-demo", "host-services")).toBe("日志 12 · 丢弃 3");
		expect(cell(target, "cooling", "host-services")).toBe("不可用");
		expect(cellTitle(target, "cooling", "host-services")).toContain("不会用 0 代替");
		expect(cell(target, "notes", "host-services")).toBe("不适用");
		expect(cellTitle(target, "notes", "host-services")).toContain("未启用 wasm 宿主服务");
		// 摘要列绝不渲染日志正文或字段值。
		expect(target.querySelector('[data-app="moonbit-demo"] [data-cell="host-services"]')?.textContent).not.toContain("message");
	});
});
