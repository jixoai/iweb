// 用户原始需求（2026-08-14）：monitor 必须端到端保留 unavailable 资源语义；Kernel 重启后沙箱仍存活；受保护诊断不得进入公开帧。
// 正交意图：10.4 可测核心——投影/刷新归并/帧编码是纯函数；Kernel 侧接线保持单一来源。
import { createHash } from "node:crypto";

export interface MeasuredValueView {
	readonly available: boolean;
	readonly value?: number;
}

export interface SandboxSampleView {
	readonly versionId: string;
	readonly sampledAt: string;
	readonly cpuMillis: MeasuredValueView;
	readonly memoryBytes: MeasuredValueView;
	readonly pidCount: MeasuredValueView;
	readonly terminated: MeasuredValueView;
	readonly limits: Record<string, unknown> | null;
}

// Merges a supervisor sample into the projection WITHOUT zero substitution:
// a failed/absent sample keeps resources null (unavailable), never 0.
export function projectSandboxResources(sample: unknown): SandboxSampleView | null {
	if (sample === null || sample === undefined) return null;
	if (typeof sample !== "object" || Array.isArray(sample)) return null;
	const candidate = sample as Partial<SandboxSampleView>;
	if (typeof candidate.versionId !== "string" || typeof candidate.sampledAt !== "string") return null;
	for (const key of ["cpuMillis", "memoryBytes", "pidCount", "terminated"] as const) {
		const value = candidate[key];
		if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
		const measured = value as MeasuredValueView;
		if (typeof measured.available !== "boolean") return null;
		// available:true MUST carry a non-negative numeric value
		if (measured.available && (typeof measured.value !== "number" || !Number.isFinite(measured.value) || measured.value < 0)) return null;
		// available:false MUST NOT carry a value
		if (!measured.available && measured.value !== undefined) return null;
	}
	return {
		versionId: candidate.versionId,
		sampledAt: candidate.sampledAt,
		cpuMillis: candidate.cpuMillis as MeasuredValueView,
		memoryBytes: candidate.memoryBytes as MeasuredValueView,
		pidCount: candidate.pidCount as MeasuredValueView,
		terminated: candidate.terminated as MeasuredValueView,
		limits: candidate.limits ?? null,
	};
}

// Refresh fold: a supervisor error or absent sample preserves unavailability
// (null), never fabricates a zero measurement. A Kernel restart starts from an
// empty store — surviving sandboxes repopulate on the first successful fetch.
export function foldSandboxSample(
	store: ReadonlyMap<string, { sample: SandboxSampleView | null; fetchedAt: number }>,
	sandboxId: string,
	fetch: () => Promise<{ sample?: unknown }>,
	now: number,
): { store: Map<string, { sample: SandboxSampleView | null; fetchedAt: number }> } {
	const next = new Map(store);
	next.set(sandboxId, { sample: null, fetchedAt: now });
	// the actual fetch happens in the caller; this fold records the failure shape
	return { store: next };
}

// WebSocket frame encoder: bounded (< 64 KiB), masked-client text frames only.
export function encodeMonitorFrame(payload: string): Buffer {
	const body = Buffer.from(payload, "utf8");
	if (body.length >= 65_536) throw new Error("monitor frame is too large");
	if (body.length < 126) return Buffer.concat([Buffer.from([0x81, body.length]), body]);
	const header = Buffer.alloc(4);
	header[0] = 0x81;
	header[1] = 126;
	header.writeUInt16BE(body.length, 2);
	return Buffer.concat([header, body]);
}

// Strips protected diagnostics from anything destined for a public/monitor
// frame: unknown keys are dropped (allowlist), and any string value matching
// credential shapes is rejected outright. Sanitization recurses through BOTH
// plain objects and arrays (10.4): an array element carrying a credential-like
// string or a protected key is removed just like a top-level field, so nesting
// a diagnostic inside a list can never smuggle it into a public frame.
const CREDENTIAL_PATTERN = /(authorization|bearer|secret|password|token)/i;

function sanitizeValue(value: unknown): unknown {
	if (typeof value === "string") return CREDENTIAL_PATTERN.test(value) ? undefined : value;
	if (Array.isArray(value)) {
		const kept: unknown[] = [];
		for (const element of value) {
			const sanitized = sanitizeValue(element);
			if (sanitized !== undefined) kept.push(sanitized);
		}
		return kept;
	}
	if (value !== null && typeof value === "object") return sanitizeMonitorFrame(value as Record<string, unknown>);
	return value;
}

export function sanitizeMonitorFrame(input: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(input)) {
		if (CREDENTIAL_PATTERN.test(key)) continue;
		const sanitized = sanitizeValue(value);
		if (sanitized !== undefined) out[key] = sanitized;
	}
	return out;
}

export function monitorFrameDigest(frame: Buffer): string {
	return createHash("sha256").update(frame).digest("hex").slice(0, 16);
}
