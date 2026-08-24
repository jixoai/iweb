// 用户原始需求（2026-08-14）：逐应用 CPU/memory/PID/limits/termination 只能来自其 sandbox cgroup；无法证明则 unavailable，绝不估算、绝不代入零。
// 正交意图：可注入 reader；cgroup v2 文件；任一要素读不到即该要素 unavailable；zero 只出现在可证明的零值上。
import { type SandboxMetrics } from "./runtime.ts";

export interface MetricsReader {
	readFile(path: string): string | null;
}

export function parsePositiveInteger(value: string | null): number | null {
	if (value === null) return null;
	const trimmed = value.trim();
	if (trimmed === "max") return null;
	const parsed = Number.parseInt(trimmed, 10);
	return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

export function parseCpuUsageMicros(cpuStat: string | null): number | null {
	if (cpuStat === null) return null;
	const line = cpuStat.split("\n").find((entry) => entry.startsWith("usage_usec "));
	if (!line) return null;
	const raw = line.split(/\s+/)[1];
	const parsed = Number.parseInt(raw ?? "", 10);
	return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

// cpu.max is "quota period" (microseconds); quota "max" means no limit was
// enforced by this cgroup, so the limit stays unavailable.
export function parseCpuMaxMillis(cpuMax: string | null): number | null {
	if (cpuMax === null) return null;
	const parts = cpuMax.trim().split(/\s+/);
	if (parts.length !== 2) return null;
	if (parts[0] === "max") return null;
	const quota = Number.parseInt(parts[0], 10);
	const period = Number.parseInt(parts[1], 10);
	if (!Number.isSafeInteger(quota) || quota < 0) return null;
	if (!Number.isSafeInteger(period) || period <= 0) return null;
	return Math.floor((quota / period) * 1000);
}

export function parseOomKillCount(memoryEvents: string | null): number | null {
	if (memoryEvents === null) return null;
	const line = memoryEvents.split("\n").find((entry) => entry.startsWith("oom_kill "));
	if (!line) return null;
	const raw = line.split(/\s+/)[1];
	const parsed = Number.parseInt(raw ?? "", 10);
	return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

// Reads the sandbox cgroup files. Each measurement and each limit is provable
// on its own; anything unreadable stays null (unavailable) rather than zero.
export function readSandboxCgroupMetrics(reader: MetricsReader, cgroupPath: string, storageBytes: number | null, sampledAt: string): SandboxMetrics {
	const memory = parsePositiveInteger(reader.readFile(cgroupPath + "/memory.current"));
	const pids = parsePositiveInteger(reader.readFile(cgroupPath + "/pids.current"));
	const cpuMicros = parseCpuUsageMicros(reader.readFile(cgroupPath + "/cpu.stat"));
	const oomKills = parseOomKillCount(reader.readFile(cgroupPath + "/memory.events"));
	const memoryLimit = parsePositiveInteger(reader.readFile(cgroupPath + "/memory.max"));
	const pidLimit = parsePositiveInteger(reader.readFile(cgroupPath + "/pids.max"));
	const cpuLimitMillis = parseCpuMaxMillis(reader.readFile(cgroupPath + "/cpu.max"));

	const available = memory !== null && pids !== null && cpuMicros !== null;
	return {
		available,
		cpuMillis: cpuMicros === null ? null : Math.floor(cpuMicros / 1000),
		memoryBytes: memory,
		pidCount: pids,
		terminated: oomKills === null ? null : oomKills > 0,
		limits: { cpuMillis: cpuLimitMillis, memoryBytes: memoryLimit, pidLimit, storageBytes },
		sampledAt,
	};
}
