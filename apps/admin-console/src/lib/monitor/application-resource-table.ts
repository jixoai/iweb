// 用户原始需求（2026-08-15）：每个应用的内存必须可见——celld 应用显示其进程 RSS 实测。
// 正交意图：纯视图模型——每应用一个受监督 celld 进程，RSS 是真实逐应用测量；无采样
// 显式 unavailable 与原因；节点 cgroup 总额不进入本模型。
// 4.4（2026-08-26）：wasm 应用行并列展示 engine（Wasmtime 引擎计数）口径——与进程
// 口径分开标注、互不换算；非 wasm 应用显式「不适用」而不是 unavailable。
// add-wasm-host-services（2026-08-28）：wasm 应用行增加宿主服务摘要（仅计数/状态）。
// two-tier-runtime-trust（2026-08-30）：celld 层边界 = 每应用独立进程 + 看门狗软限——
// 新增「软上限」（watchdog.apps[appId] ?? defaultBytes）与「看门狗」（最近一次越限
// 处决：时间 + 处决时采样值）两列；投影是路由派生 fleet（无沙箱身份）。
import type { ApplicationProjection, MonitorApp, ResourceLimits, WatchdogEvent, WatchdogProjection } from "$lib/iweb/contracts";

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
	/** celld 看门狗软上限（apps 覆盖值 ?? 默认值）：采样 15s、越限 SIGKILL 单进程，非强制天花板。 */
	readonly softLimit: CellText;
	/** 看门狗最近一次越限处决（时间 + 处决时采样 RSS）；无记录显式「—」。 */
	readonly watchdog: CellText;
	readonly pid: CellText;
	readonly cpu: CellText;
	readonly terminated: boolean;
	readonly inFlight: number;
	/** wasm 引擎（Wasmtime）口径：guest memory 实测 + 存活实例；与进程口径分开。 */
	readonly engine: CellText;
	/** wasm 宿主服务（kv/sql/logging）摘要：仅计数/状态（保留事件、丢弃计数），无正文无值。 */
	readonly hostServices: CellText;
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

// 看门狗处决时间戳（本地时间，秒级）：处决事件必须可审计到具体时刻。
export function formatWatchdogStamp(iso: string): string {
	const date = new Date(iso);
	if (Number.isNaN(date.getTime())) return iso;
	const pad = (value: number): string => String(value).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

const UNAVAILABLE = "不可用";
const NOT_APPLICABLE = "不适用";
const WATCHDOG_NO_EVENT = "—";

// Why each non-value state exists. These strings are the UI's honesty layer:
// an empty-looking cell must explain itself instead of looking broken.
export const CELL_REASONS = {
	processNoSample:
		"该应用拥有独立 celld 进程，但本周期未能读取其进程采样（pidfile 或 /proc 不可用）；不会用 0 代替。",
	processNoLimit: "该 celld 进程未设置强制内存上限；看门狗软上限见「软上限」列。",
	processNotCelld:
		"该应用没有 celld 进程投影（wasm 应用经引擎执行，不在 celld fleet 投影中）；进程口径内存对它不适用，wasm 数值见「引擎（Wasmtime）」列。",
	noSample: "沙箱存在但本周期没有有效采样（supervisor 不可达或采样失败）；不会用 0 代替。",
	noLimit: "该沙箱未报告强制内存上限。",
	engineNoSample:
		"该 wasm 执行尚无首个可验证引擎样本，或本周期无法证明引擎度量（如进程内存无 wasmd 读数）；显示 unavailable，不会用 0 代替。",
	engineNotWasm:
		"该应用不是 wasm 运行时，没有 Wasmtime 引擎口径指标；其资源口径见「内存（实测）」列（celld 进程 RSS）。",
	hostServicesNotApplicable:
		"该应用未启用 wasm 宿主服务（KV/SQL/日志环），没有宿主服务摘要；启用后此处仅显示计数与状态，绝不显示日志正文或存储值。",
	hostServicesNoSample:
		"该 wasm 执行尚无宿主服务摘要投影（supervisor 未配置该面或本周期无法证明）；显示 unavailable，不会用 0 代替。",
	watchdogNoProjection:
		"本帧未携带看门狗策略投影（旧内核帧缺省或内核尚未实现）；软限与越限事件显式不可用，不会编造数值。",
	watchdogNoEvent:
		"有界事件环（最近 20 条）中没有该应用的越限处决记录：看门狗从未 SIGKILL 该进程，或记录已滚动出环。",
} as const;

function measuredCell(measured: { available: boolean; value?: number } | null | undefined, formatter: (value: number) => string, unavailableReason: string = CELL_REASONS.noSample): CellText {
	// unavailable is an explicit state: a value we cannot prove never renders as 0
	return measured?.available === true && typeof measured.value === "number"
		? { kind: "value", text: formatter(measured.value) }
		: { kind: "unavailable", text: UNAVAILABLE, reason: unavailableReason };
}

function memoryLimitCell(limits: ResourceLimits | null | undefined, noLimitReason: string): CellText {
	// 有上限才显示；上限缺失是显式状态，绝不以测量值或节点总额替代。
	return limits && limits.memoryBytes !== null && limits.memoryBytes !== undefined
		? { kind: "value", text: formatBytesValue(limits.memoryBytes) }
		: { kind: "unavailable", text: UNAVAILABLE, reason: noLimitReason };
}

// 看门狗事件环按应用取最近一次处决（terminatedAt 为 RFC3339，字典序即时间序）。
function latestWatchdogEvent(events: readonly WatchdogEvent[], applicationId: string): WatchdogEvent | null {
	let latest: WatchdogEvent | null = null;
	for (const event of events) {
		if (event.applicationId !== applicationId) continue;
		if (latest === null || event.terminatedAt > latest.terminatedAt) latest = event;
	}
	return latest;
}

// Builds the primary monitoring-table rows. Row authority is the application
// list (every visible application stays visible); resource data prefers the
// /v1/status celld fleet projection and falls back to the monitor frame's
// app.resources (process RSS). The node cgroup total is deliberately NOT an
// input: it lives in its own separately labeled card and can never be copied
// into a row.
export function applicationResourceRows(input: {
	readonly apps: readonly MonitorApp[];
	readonly applications: readonly ApplicationProjection[] | null;
	readonly watchdog?: WatchdogProjection | null;
}): ApplicationResourceRow[] {
	const live = new Map<string, ApplicationProjection>();
	for (const projection of input.applications ?? []) live.set(projection.id, projection);
	const rows: ApplicationResourceRow[] = [];
	for (const app of input.apps) {
		const projection = live.get(app.id) ?? null;
		// two-tier-runtime-trust：fleet 投影恒 sandboxId:null——每应用一个受监督 celld
		// 进程，内存是其 VmRSS 实测。无投影且非系统的行（wasm 应用）没有进程口径，
		// 「不适用」而非测量失败；旧帧里 sandboxId 非空的沙箱行仍按沙箱语义渲染。
		const celldProcessRow = projection !== null && projection.sandboxId === null;
		const legacySandboxRow = projection !== null && projection.sandboxId !== null;
		const processRow = celldProcessRow || (projection === null && app.system === true);
		const resources = projection?.resources ?? app.resources ?? null;
		const sampleReason = processRow ? CELL_REASONS.processNoSample : CELL_REASONS.noSample;
		const memory: CellText = processRow
			? measuredCell(resources?.memoryBytes, formatBytesValue, CELL_REASONS.processNoSample)
			: legacySandboxRow
				? measuredCell(resources?.memoryBytes, formatBytesValue)
				: { kind: "not-applicable", text: NOT_APPLICABLE, reason: CELL_REASONS.processNotCelld };
		const memoryLimit: CellText = processRow
			? memoryLimitCell(resources?.limits, CELL_REASONS.processNoLimit)
			: legacySandboxRow
				? memoryLimitCell(resources?.limits, CELL_REASONS.noLimit)
				: { kind: "not-applicable", text: NOT_APPLICABLE, reason: CELL_REASONS.processNotCelld };
		// 软上限（watchdog 软限）：apps 覆盖值 ?? 默认值；无投影显式不可用，不编造数值。
		const softLimit: CellText = input.watchdog
			? { kind: "value", text: formatBytesValue(input.watchdog.apps[app.id] ?? input.watchdog.defaultBytes) }
			: { kind: "unavailable", text: UNAVAILABLE, reason: CELL_REASONS.watchdogNoProjection };
		// 看门狗列：该应用最近一次越限处决（时间 + 处决时采样值）；无记录显式「—」。
		const lastKill = latestWatchdogEvent(input.watchdog?.events ?? [], app.id);
		const watchdogCell: CellText = lastKill
			? { kind: "value", text: formatWatchdogStamp(lastKill.terminatedAt) + " · " + formatBytesValue(lastKill.sampledBytes) }
			: { kind: "not-applicable", text: WATCHDOG_NO_EVENT, reason: CELL_REASONS.watchdogNoEvent };
		// engine（Wasmtime）口径（4.4）：只认 Kernel 权威投影（app.engine）。
		// - 无投影（undefined/null）：非 wasm 应用或不适用 → 「不适用」，不是测量失败。
		// - 投影 unavailable / engine:null：显式 unavailable（无首样本或无法证明），
		//   绝不补零。
		// - 投影 available：guest memory 实测 + 存活实例数（与进程口径并列）。
		const engine: CellText =
			app.engine === undefined || app.engine === null
				? { kind: "not-applicable", text: NOT_APPLICABLE, reason: CELL_REASONS.engineNotWasm }
				: app.engine.availability === "available" && app.engine.engine !== null
					? {
						kind: "value",
						text: formatBytesValue(app.engine.engine.guestMemoryBytesInstant) + " · " + app.engine.engine.instancesLiveInstant + " 实例",
					}
					: { kind: "unavailable", text: UNAVAILABLE, reason: CELL_REASONS.engineNoSample };
		// 宿主服务摘要（add-wasm-host-services）：只认 Kernel/supervisor 权威投影（app.hostServices）。
		// - 无投影（undefined/null）：未启用宿主服务的应用 → 「不适用」，不是测量失败。
		// - 投影 unavailable / logging:null：显式 unavailable（无首样本或无法证明），绝不补零。
		// - 投影 available：仅计数/状态（保留事件数 + 丢弃计数 + 环水位），无正文无值。
		const hostServices: CellText =
			app.hostServices === undefined || app.hostServices === null
				? { kind: "not-applicable", text: NOT_APPLICABLE, reason: CELL_REASONS.hostServicesNotApplicable }
				: app.hostServices.availability === "available" && app.hostServices.logging !== null
					? {
						kind: "value",
						text: "日志 " + app.hostServices.logging.retainedEvents + " · 丢弃 " + app.hostServices.logging.droppedCount,
					}
					: { kind: "unavailable", text: UNAVAILABLE, reason: CELL_REASONS.hostServicesNoSample };
		rows.push({
			id: app.id,
			domains: app.domains ?? [],
			system: app.system === true,
			requests: { kind: "value", text: String(app.requests) },
			errors: { kind: "value", text: String(app.errors) },
			latency: { kind: "value", text: app.averageLatencyMs + " ms" },
			lifecycle: projection
				? { kind: "value", text: projection.lifecycle }
				: { kind: "not-applicable", text: NOT_APPLICABLE, reason: CELL_REASONS.processNotCelld },
			memory,
			memoryLimit,
			softLimit,
			watchdog: watchdogCell,
			pid: measuredCell(resources?.pidCount, (value) => String(value), sampleReason),
			cpu: measuredCell(resources?.cpuMillis, (value) => (value / 1000).toFixed(1) + " s", sampleReason),
			terminated: resources?.terminated.available === true && resources.terminated.value === 1,
			inFlight: app.inFlight,
			engine,
			hostServices,
		});
	}
	return rows;
}
