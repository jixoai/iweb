// 用户原始需求（2026-08-15）：admin/mcp 是普通 celld 应用（各自独立进程）；每个应用的内存必须可见——控制面应用显示其 celld 进程 RSS，沙箱化应用显示 cgroup 实测。
// 正交意图：纯视图模型——控制面应用有独立进程边界，RSS 是真实逐应用测量；未沙箱化应用保持可见并带显式 unavailable 与原因；节点 cgroup 总额不进入本模型。
// 4.4（2026-08-26）：wasm 应用行并列展示 engine（Wasmtime 引擎计数）口径——与
// cgroup/进程口径分开标注、互不换算；非 wasm 应用显式「不适用」而不是 unavailable。
import type { ApplicationProjection, MonitorApp } from "$lib/iweb/contracts";

export type CellText =
	| { readonly kind: "value"; readonly text: string }
	| { readonly kind: "unavailable"; readonly text: string; readonly reason: string }
	| { readonly kind: "not-applicable"; readonly text: string; readonly reason: string };

export interface ApplicationResourceRow {
	domains: string[];
	readonly id: string;
	readonly system: boolean;
	readonly requests: CellText;
	readonly errors: CellText;
	readonly latency: CellText;
	readonly lifecycle: CellText;
	readonly memory: CellText;
	readonly memoryLimit: CellText;
	readonly pid: CellText;
	readonly cpu: CellText;
	readonly terminated: boolean;
	readonly inFlight: number;
	/** wasm 引擎（Wasmtime）口径：guest memory 实测 + 存活实例；与 cgroup/进程口径分开。 */
	readonly engine: CellText;
}

export function formatBytesValue(bytes: number): string {
	if (bytes < 1024) return bytes + " B";
	const units = ["KiB", "MiB", "GiB", "TiB"];
	let value = bytes / 1024;
	let unit = 0;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit += 1;
	}
	return value.toFixed(value >= 100 ? 0 : 1) + " " + units[unit];
}

const UNAVAILABLE = "不可用";
const NOT_SANDBOXED = "不可用（未沙箱化）";
const NOT_APPLICABLE = "不适用";

// Why each non-value state exists. These strings are the UI's honesty layer:
// an empty-looking cell must explain itself instead of looking broken.
export const CELL_REASONS = {
	controlPlaneNoSample:
		"该应用拥有独立 celld 进程，但本周期未能读取其进程内存（pidfile 或 /proc 不可用）；不会用 0 代替。",
	controlPlaneNoLimit: "控制面 celld 进程未设置强制内存上限；沙箱化应用才有限额语义。",
	notSandboxed:
		"此应用尚未运行在独立沙箱中。沙箱化部署后，此处显示该沙箱 cgroup 的实测内存与强制上限。",
	noSample: "沙箱存在但本周期没有有效采样（supervisor 不可达或采样失败）；不会用 0 代替。",
	noLimit: "该沙箱未报告强制内存上限。",
	engineNoSample:
		"该 wasm 执行尚无首个可验证引擎样本，或本周期无法证明引擎度量（如进程内存无 wasmd 读数）；显示 unavailable，不会用 0 代替。",
	engineNotWasm:
		"该应用不是 wasm 运行时，没有 Wasmtime 引擎口径指标；其资源口径见「内存（实测）」列（celld 进程 RSS 或沙箱 cgroup）。",
} as const;

function measuredCell(measured: { available: boolean; value?: number } | null | undefined, formatter: (value: number) => string, unavailableReason: string = CELL_REASONS.noSample): CellText {
	// unavailable is an explicit state: a value we cannot prove never renders as 0
	return measured?.available === true && typeof measured.value === "number"
		? { kind: "value", text: formatter(measured.value) }
		: { kind: "unavailable", text: UNAVAILABLE, reason: unavailableReason };
}

// Builds the primary monitoring-table rows. Row authority is the application
// list (every visible application stays visible); resource and lifecycle data
// prefers the live monitor projection and falls back to the /v1/applications
// projection. The node cgroup total is deliberately NOT an input: it lives in
// its own separately labeled card and can never be copied into a row.
export function applicationResourceRows(input: {
	readonly apps: readonly MonitorApp[];
	readonly sandboxes: readonly ApplicationProjection[] | null;
	readonly applications: readonly ApplicationProjection[] | null;
}): ApplicationResourceRow[] {
	const live = new Map<string, ApplicationProjection>();
	for (const projection of input.sandboxes ?? []) live.set(projection.id, projection);
	for (const projection of input.applications ?? []) {
		if (!live.has(projection.id)) live.set(projection.id, projection);
	}
	const rows: ApplicationResourceRow[] = [];
	for (const app of input.apps) {
		const projection = live.get(app.id) ?? null;
		// 用户设计（2026-08-15）：admin/mcp 是普通 celld 应用（独立进程）。控制面应用
		// 的内存是其 celld 进程 RSS——真实、可归属的逐应用测量；沙箱化应用则取
		// cgroup 采样。两处都取不到时显式 unavailable，绝不补 0。
		const controlPlane = app.system === true && (projection?.sandboxId ?? null) === null;
		// 资源来源优先级：控制投影（沙箱 cgroup）→ 监控帧 app.resources（控制面进程 RSS）。
		const resources = projection?.resources ?? app.resources ?? null;
		const memory: CellText = controlPlane
			? measuredCell(resources?.memoryBytes, formatBytesValue, CELL_REASONS.controlPlaneNoSample)
			: projection === null || projection.sandboxId === null
				? { kind: "unavailable", text: NOT_SANDBOXED, reason: CELL_REASONS.notSandboxed }
				: measuredCell(resources?.memoryBytes, formatBytesValue);
		const memoryLimit: CellText = controlPlane
			? { kind: "unavailable", text: UNAVAILABLE, reason: CELL_REASONS.controlPlaneNoLimit }
			: projection === null || projection.sandboxId === null
				? { kind: "unavailable", text: NOT_SANDBOXED, reason: CELL_REASONS.notSandboxed }
				: resources?.limits && resources.limits.memoryBytes !== null && resources.limits.memoryBytes !== undefined
					? { kind: "value", text: formatBytesValue(resources.limits.memoryBytes) }
					: { kind: "unavailable", text: UNAVAILABLE, reason: CELL_REASONS.noLimit };
		// engine（Wasmtime）口径（4.4）：只认 Kernel 权威投影（app.engine）。
		// - 无投影（undefined/null）：非 wasm 应用或不适用 → 「不适用」，不是测量失败。
		// - 投影 unavailable / engine:null：显式 unavailable（无首样本或无法证明），
		//   绝不补零。
		// - 投影 available：guest memory 实测 + 存活实例数（与 cgroup/进程口径并列）。
		const engine: CellText =
			app.engine === undefined || app.engine === null
				? { kind: "not-applicable", text: NOT_APPLICABLE, reason: CELL_REASONS.engineNotWasm }
				: app.engine.availability === "available" && app.engine.engine !== null
					? {
							kind: "value",
							text: formatBytesValue(app.engine.engine.guestMemoryBytesInstant) + " · " + app.engine.engine.instancesLiveInstant + " 实例",
						}
					: { kind: "unavailable", text: UNAVAILABLE, reason: CELL_REASONS.engineNoSample };
		rows.push({
			id: app.id,
			domains: app.domains ?? [],
			system: app.system === true,
			requests: { kind: "value", text: String(app.requests) },
			errors: { kind: "value", text: String(app.errors) },
			latency: { kind: "value", text: app.averageLatencyMs + " ms" },
			lifecycle: projection
				? { kind: "value", text: projection.lifecycle }
				: { kind: "unavailable", text: NOT_SANDBOXED, reason: CELL_REASONS.notSandboxed },
			memory,
			memoryLimit,
			pid: measuredCell(resources?.pidCount, (value) => String(value)),
			cpu: measuredCell(resources?.cpuMillis, (value) => (value / 1000).toFixed(1) + " s"),
			terminated: resources?.terminated.available === true && resources.terminated.value === 1,
			inFlight: app.inFlight,
			engine,
		});
	}
	return rows;
}
