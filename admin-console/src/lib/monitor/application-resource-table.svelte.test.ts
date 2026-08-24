// 用户原始需求（2026-08-14）：Admin 组件测试必须是真实渲染断言，而不是源码字符串断言。
// 正交意图：10.4——真实挂载 Svelte 组件到 happy-dom，断言渲染出的表格行为；在无法编译 .svelte 的运行器（纯 bun test）下显式跳过。
import { describe, expect, test } from "vitest";
import type { ApplicationProjection, MonitorApp } from "$lib/iweb/contracts";

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
	return { id, sourcePath: "/" + id + "/app", domains: [], deployed: true, system: false, requests: 5, errors: 0, inFlight: 0, averageLatencyMs: 7, lastRequestAt: null, ...overrides };
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
			cpuMillis: { available: true, value: 1200 },
			memoryBytes: { available: true, value: 64 * 1024 * 1024 },
			pidCount: { available: true, value: 4 },
			terminated: { available: true, value: 0 },
			limits: { cpuMillis: 500, memoryBytes: 128 * 1024 * 1024, pidLimit: 128, storageBytes: 1024 ** 3 },
		},
		...overrides,
	};
}

function render(props: { apps: MonitorApp[]; sandboxes: ApplicationProjection[] | null; applications: ApplicationProjection[] | null }): HTMLElement {
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
	test("renders measured memory beside the enforced limit, requests, and lifecycle", () => {
		const target = render({ apps: [app("notes")], sandboxes: [projection("notes")], applications: null });
		expect(target.querySelector('[data-testid="application-resource-table"]')).not.toBeNull();
		expect(cell(target, "notes", "memory")).toBe("64.0 MiB");
		expect(cell(target, "notes", "memory-limit")).toBe("128 MiB");
		expect(target.querySelector('[data-app="notes"]')?.textContent).toContain("运行中");
		expect(target.querySelector('[data-app="notes"]')?.textContent).toContain("5");
	});

	test("changing usage re-renders the measured value; a limit termination shows the terminated badge", () => {
		const target = render({
			apps: [app("notes")],
			sandboxes: [projection("notes", { resources: { ...projection("notes").resources!, memoryBytes: { available: true, value: 32 * 1024 * 1024 }, terminated: { available: true, value: 1 } } })],
			applications: null,
		});
		expect(cell(target, "notes", "memory")).toBe("32.0 MiB");
		expect(cell(target, "notes", "memory-limit")).toBe("128 MiB");
		expect(target.querySelector('[data-app="notes"]')?.textContent).toContain("已终止");
	});

	test("unavailable and not-yet-sandboxed rows keep every resource column visible with explicit states", () => {
		const target = render({
			apps: [app("flaky"), app("draft")],
			sandboxes: [projection("flaky", { resources: { ...projection("flaky").resources!, memoryBytes: { available: false } } })],
			applications: [projection("draft", { sandboxId: null, lifecycle: "admitted", resources: null })],
		});
		expect(cell(target, "flaky", "memory")).toBe("不可用");
		expect(cell(target, "flaky", "memory-limit")).toBe("128 MiB");
		expect(cell(target, "draft", "memory")).toBe("不可用（未沙箱化）");
		expect(cell(target, "draft", "memory-limit")).toBe("不可用（未沙箱化）");
		// non-value cells explain themselves via tooltip reasons (10.4)
		expect(cellTitle(target, "flaky", "memory")).toContain("没有有效采样");
		expect(cellTitle(target, "draft", "memory")).toContain("尚未运行在独立沙箱");
		// the columns exist for every row, never hidden by a missing sample
		for (const id of ["flaky", "draft"]) {
			expect(target.querySelector('[data-app="' + id + '"] [data-cell="memory"]')).not.toBeNull();
			expect(target.querySelector('[data-app="' + id + '"] [data-cell="memory-limit"]')).not.toBeNull();
		}
		// the table carries an explanatory footnote so the empty-looking
		// resource columns never read as broken
		const note = target.querySelector('[data-testid="resource-table-note"]');
		expect(note?.textContent ?? "").toContain("独立的 celld 进程");
		expect(note?.textContent ?? "").toContain("不会用 0 代替");
	});

	test("control-plane rows render their own process RSS (one celld process per app)", () => {
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
			sandboxes: [projection("admin", { sandboxId: null, resources: processResources }), projection("notes")],
			applications: null,
		});
		expect(cell(target, "admin", "memory")).toBe("48.0 MiB");
		expect(cell(target, "admin", "memory-limit")).toBe("不可用");
		expect(cellTitle(target, "admin", "memory-limit")).toContain("未设置强制内存上限");
		expect(target.querySelector('[data-testid="application-resource-table"]')?.textContent).not.toContain(nodeTotal);
	});

	test("an empty application surface renders an explicit empty state, not a hidden table", () => {
		const target = render({ apps: [], sandboxes: null, applications: null });
		expect(target.querySelector('[data-testid="no-applications"]')).not.toBeNull();
	});
});