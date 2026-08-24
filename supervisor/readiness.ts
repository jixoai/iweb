// 用户原始需求（2026-08-14）：就绪探测必须用固定健康契约：唯一接受状态 200 + 候选 versionId/generation 相关；每次尝试有 deadline；总次数有界。
// 正交意图：401/404/429/hang/超时/陈旧响应都不能激活版本；失败只返回 generic unavailable。
import { READINESS_PATH } from "./sandbox-spec.ts";

export interface ReadinessProbeOptions {
	readonly fetch: (url: string, options: { readonly signal: AbortSignal }) => Promise<{ readonly status: number; readonly body: string }>;
	readonly baseUrl: string;
	readonly versionId: string;
	readonly generation?: number;
	readonly maxAttempts: number;
	readonly attemptTimeoutMs: number;
	readonly intervalMs: number;
	readonly sleep?: (ms: number) => Promise<void>;
}

export interface ReadinessResult {
	readonly ready: boolean;
	readonly attempts: number;
	readonly lastStatus: number | null;
	readonly mismatch: boolean;
	readonly timedOut: boolean;
}

export interface HealthPayload {
	readonly version: 1;
	readonly ok: boolean;
	readonly versionId: string;
	readonly generation: number;
}

const MAX_ATTEMPTS = 100;
const MAX_TIMEOUT_MS = 60_000;

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function readinessUrl(baseUrl: string, versionId: string, generation?: number): string {
	const query = "?versionId=" + encodeURIComponent(versionId) + (generation === undefined ? "" : "&generation=" + String(generation));
	return baseUrl + READINESS_PATH + query;
}

export function parseHealthPayload(body: string): HealthPayload | null {
	try {
		const parsed: unknown = JSON.parse(body);
		if (isRecord(parsed) && parsed.version === 1 && parsed.ok === true && typeof parsed.versionId === "string" && typeof parsed.generation === "number" && Number.isSafeInteger(parsed.generation)) {
			return { version: 1, ok: true, versionId: parsed.versionId, generation: parsed.generation };
		}
	} catch {
		// a malformed health payload is never readiness
	}
	return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Fixed health contract: only an exact 200 whose payload matches the expected
// candidate version identity (and optional generation) activates a version.
// Authorization failures, missing routes, throttling, hangs, timeouts, and
// stale responses are all not-ready and never expose upstream diagnostics.
export async function probeReadiness(options: ReadinessProbeOptions): Promise<ReadinessResult> {
	const sleep = options.sleep ?? defaultSleep;
	const maxAttempts = Math.min(Math.max(1, Math.floor(options.maxAttempts)), MAX_ATTEMPTS);
	const timeoutMs = Math.min(Math.max(100, Math.floor(options.attemptTimeoutMs)), MAX_TIMEOUT_MS);
	let lastStatus: number | null = null;
	let mismatch = false;
	let timedOut = false;

	for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const response = await options.fetch(readinessUrl(options.baseUrl, options.versionId, options.generation), { signal: controller.signal });
			lastStatus = response.status;
			if (response.status === 200) {
				const payload = parseHealthPayload(response.body);
				if (payload !== null && payload.versionId === options.versionId && (options.generation === undefined || payload.generation === options.generation)) {
					return { ready: true, attempts: attempt, lastStatus: 200, mismatch: false, timedOut: false };
				}
				mismatch = true;
			} else if (response.status === 409) {
				// The gateway answered with an explicit identity mismatch.
				mismatch = true;
			}
		} catch (error) {
			if (isAbortError(error)) timedOut = true;
			lastStatus = null;
		} finally {
			clearTimeout(timer);
		}
		if (attempt < maxAttempts) await sleep(options.intervalMs);
	}

	return { ready: false, attempts: maxAttempts, lastStatus, mismatch, timedOut };
}

function isAbortError(error: unknown): boolean {
	return typeof error === "object" && error !== null && (error as { readonly name?: unknown }).name === "AbortError";
}

// Generic public failure shaping: never expose sandbox/runtime diagnostics.
export function unavailableResponse(): { readonly status: 502; readonly body: string } {
	return { status: 502, body: JSON.stringify({ error: "application unavailable" }) + "\n" };
}
