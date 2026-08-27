// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：logging owner 面的接线证明——
//   drain/stream 端点（经 supervisor server 既有授权/token 面）、monitor summary 投影
//   （wasm-health executionMetrics 同款模式）、转发配置宿主装载（默认关 fail-closed）、
//   跨应用隔离违约拒绝（403，绝不部分返回）。
// 终审缺口修正（2026-08-28，双台账统一）后的形态：环唯一权威是 wasmd 进程内 ring；supervisor
//   面是拉取式投影（无本地台账）。本电池以 InMemoryWasmLoggingAuthority 作 wasmd 替身（契约
//   ring 纯函数承载，与 Rust LoggingRing::drain/monitor_summary 对位），证明：
//   正例（drain 分页/游标 stream、summary 仅计数）/负例（非法 wire、非法 JSON、content-type、
//   超限、未知应用、权威不可用/未接线 503、权威答案畸形 503 fail-closed 不部分返回）/
//   隔离（路径与 wire applicationId 不一致、redaction 边界违约）。
// 判定语义复用 packages/contracts/wasm-host-logging.ts 纯函数，不在测试里造第二套比对。
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	assembleWasmLoggingOwnerFace,
	createWasmLoggingOwnerFace,
	handleWasmLoggingDrainHttp,
	handleWasmLoggingSummaryHttp,
	InMemoryWasmLoggingAuthority,
	loadIwebLoggingForwardingConfig,
	WasmLoggingServeError,
	WASM_HOST_LOGGING_DRAIN_PATH,
	WASM_HOST_LOGGING_SUMMARY_PATH,
	WASM_LOG_APPLICATION_UNKNOWN,
	WASM_LOG_AUTHORITY_UNAVAILABLE,
	WASM_LOG_AUTHORITY_WIRE_INVALID,
	WASM_LOG_DRAIN_REQUEST_INVALID,
	WASM_LOG_FACE_NOT_CONFIGURED,
	WASM_LOG_FORWARDING_CONFIG_INVALID,
	IWEB_WASM_LOG_FORWARDING_FILE_ENV,
	validateIwebLoggingDrainResponseWireV1,
	type WasmLoggingOwnerFace,
	type WasmLoggingProjectionOutcome,
	type WasmLoggingProjectionSource,
} from "../supervisor/wasm-host-logging.ts";
import type { WasmServeIO } from "../supervisor/wasm-serve.ts";
import { startSupervisorServer } from "../supervisor/server.ts";
import {
	IWEB_LOG_FORWARDING_DEFAULT,
	type IwebLoggingDrainRequestV1,
	type IwebLoggingDrainResponseV1,
	type IwebLoggingHostContextV1,
	type IwebLoggingMonitorSummaryV1,
} from "../packages/contracts/wasm-host-logging.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";

const APPLICATION = "notes-app";
const OTHER_APPLICATION = "search-app";
const VERSION_ID = "a".repeat(64) + "-1";
const RING_CAPACITY = { maxEvents: 8, maxBytes: 65536 };

class MemoryIO implements WasmServeIO {
	readonly files = new Map<string, string>();
	write(path: string, content: string): void {
		this.files.set(path, content);
	}
	readFile(path: string): string | null {
		return this.files.get(path) ?? null;
	}
}

function jcsText(value: unknown): string {
	return Buffer.from(jcsCanonicalBytes(value)).toString("utf8");
}

function hostContext(applicationId: string, generation = 1): IwebLoggingHostContextV1 {
	return {
		applicationId,
		versionId: VERSION_ID,
		preparationGeneration: generation,
		executionGeneration: generation,
		timestampUtc: "2026-08-28T00:00:0" + (generation % 10) + "Z",
	};
}

/** 权威替身：事件只经权威自身的 write 进入（宿主上下文注入身份）。 */
function seededAuthority(): InMemoryWasmLoggingAuthority {
	const authority = new InMemoryWasmLoggingAuthority();
	authority.ensure(APPLICATION, RING_CAPACITY);
	for (let index = 0; index < 3; index++) {
		const result = authority.write(APPLICATION, hostContext(APPLICATION, index + 1), {
			level: "info",
			message: "event " + index,
			fields: [{ key: "ordinal", value: String(index) }],
		});
		if (!result.ok || result.outcome !== "accepted")
			throw new Error("fixture error: write must be accepted");
	}
	return authority;
}

function faceOf(authority: InMemoryWasmLoggingAuthority): WasmLoggingOwnerFace {
	return createWasmLoggingOwnerFace(authority, IWEB_LOG_FORWARDING_DEFAULT);
}

async function drain(
	face: WasmLoggingOwnerFace,
	applicationId: string,
	body: unknown,
	contentType = "application/json",
): Promise<{ readonly status: number; readonly body: string }> {
	return handleWasmLoggingDrainHttp(face, {
		method: "POST",
		path: WASM_HOST_LOGGING_DRAIN_PATH + "/" + applicationId,
		contentType,
		body: Buffer.from(JSON.stringify(body), "utf8"),
	});
}

async function drainRaw(
	face: WasmLoggingOwnerFace,
	applicationId: string,
	rawBody: string,
	contentType = "application/json",
): Promise<{ readonly status: number; readonly body: string }> {
	return handleWasmLoggingDrainHttp(face, {
		method: "POST",
		path: WASM_HOST_LOGGING_DRAIN_PATH + "/" + applicationId,
		contentType,
		body: Buffer.from(rawBody, "utf8"),
	});
}

async function summary(
	face: WasmLoggingOwnerFace,
	applicationId: string,
): Promise<{ readonly status: number; readonly body: string }> {
	return handleWasmLoggingSummaryHttp(
		face,
		"GET",
		WASM_HOST_LOGGING_SUMMARY_PATH + "/" + applicationId,
	);
}

/** 可编程权威：直接注入任意 drain/summary 答案（畸形 wire 与不可用性测试）。 */
class StubAuthority implements WasmLoggingProjectionSource {
	drainCalls = 0;
	summaryCalls = 0;
	constructor(
		private readonly drainOutcome: WasmLoggingProjectionOutcome<IwebLoggingDrainResponseV1>,
		private readonly summaryOutcome: WasmLoggingProjectionOutcome<IwebLoggingMonitorSummaryV1> = { ok: false, reason: "unknown-application" },
	) {}
	async drain(): Promise<WasmLoggingProjectionOutcome<IwebLoggingDrainResponseV1>> {
		this.drainCalls += 1;
		return this.drainOutcome;
	}
	async monitorSummary(): Promise<WasmLoggingProjectionOutcome<IwebLoggingMonitorSummaryV1>> {
		this.summaryCalls += 1;
		return this.summaryOutcome;
	}
}

// ---------------------------------------------------------------------------
// drain/stream：正例（分页 + 游标续流；全部来自权威）
// ---------------------------------------------------------------------------

describe("logging owner face: drain/stream positive paths (served from the authority)", () => {
	test("drain returns the application's bounded retained events with paging", async () => {
		const face = faceOf(seededAuthority());
		const result = await drain(face, APPLICATION, {
			schemaVersion: 1,
			applicationId: APPLICATION,
			afterEventId: 0,
			maxEvents: 2,
		});
		expect(result.status).toBe(200);
		const body = JSON.parse(result.body);
		expect(body.ok).toBe(true);
		expect(body.applicationId).toBe(APPLICATION);
		expect(body.events.map((event: { message: string }) => event.message)).toEqual([
			"event 0",
			"event 1",
		]);
		expect(body.hasMore).toBe(true);
		expect(body.lastEventId).toBe(3);
		expect(body.droppedCount).toBe(0);
	});

	test("stream continues from the cursor of the previous drain response", async () => {
		const face = faceOf(seededAuthority());
		const first = JSON.parse(
			(await drain(face, APPLICATION, {
				schemaVersion: 1,
				applicationId: APPLICATION,
				afterEventId: 0,
				maxEvents: 2,
			})).body,
		);
		const second = JSON.parse(
			(await drain(face, APPLICATION, {
				schemaVersion: 1,
				applicationId: APPLICATION,
				afterEventId: 2,
				maxEvents: 2,
			})).body,
		);
		expect(second.events.map((event: { message: string }) => event.message)).toEqual(["event 2"]);
		expect(second.hasMore).toBe(false);
		expect(first.lastEventId).toBe(second.lastEventId);
	});

	test("drain reports the dropped counter without evicting retained events", async () => {
		const authority = new InMemoryWasmLoggingAuthority();
		authority.ensure(APPLICATION, { maxEvents: 1, maxBytes: 65536 });
		const first = authority.write(APPLICATION, hostContext(APPLICATION), {
			level: "info",
			message: "kept",
			fields: [],
		});
		expect(first.ok && first.outcome).toBe("accepted");
		const second = authority.write(APPLICATION, hostContext(APPLICATION), {
			level: "warn",
			message: "dropped",
			fields: [],
		});
		expect(second.ok && second.outcome).toBe("dropped");
		const face = faceOf(authority);
		const result = JSON.parse(
			(await drain(face, APPLICATION, {
				schemaVersion: 1,
				applicationId: APPLICATION,
				afterEventId: 0,
				maxEvents: 10,
			})).body,
		);
		expect(result.events.map((event: { message: string }) => event.message)).toEqual(["kept"]);
		expect(result.droppedCount).toBe(1);
	});

	test("the face holds no local ledger: every drain consults the authority again", async () => {
		const authority = seededAuthority();
		const stub = new StubAuthority({ ok: true, value: { schemaVersion: 1, applicationId: APPLICATION, events: [], droppedCount: 0, hasMore: false, lastEventId: 0 } });
		const face = createWasmLoggingOwnerFace(authority, IWEB_LOG_FORWARDING_DEFAULT);
		await drain(face, APPLICATION, { schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 5 });
		const second = createWasmLoggingOwnerFace(stub, IWEB_LOG_FORWARDING_DEFAULT);
		await drain(second, APPLICATION, { schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 5 });
		expect(stub.drainCalls).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// drain/stream：负例（wire/传输级）与跨应用隔离违约
// ---------------------------------------------------------------------------

describe("logging owner face: drain negative and isolation paths", () => {
	test("an invalid drain wire is rejected with a stable code before the authority", async () => {
		const stub = new StubAuthority({ ok: true, value: { schemaVersion: 1, applicationId: APPLICATION, events: [], droppedCount: 0, hasMore: false, lastEventId: 0 } });
		const face = createWasmLoggingOwnerFace(stub, IWEB_LOG_FORWARDING_DEFAULT);
		for (const body of [
			{ schemaVersion: 2, applicationId: APPLICATION, afterEventId: 0, maxEvents: 1 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: -1, maxEvents: 1 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 0 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 1001 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 1, extra: true },
			{ schemaVersion: 1, applicationId: "NOT-LOWER", afterEventId: 0, maxEvents: 1 },
		]) {
			const result = await drain(face, APPLICATION, body);
			expect(result.status).toBe(400);
			expect(JSON.parse(result.body).code).toBe(WASM_LOG_DRAIN_REQUEST_INVALID);
		}
		expect(stub.drainCalls).toBe(0);
	});

	test("a drain request naming another application is a cross-application isolation violation (403)", async () => {
		const face = faceOf(seededAuthority());
		const result = await drain(face, APPLICATION, {
			schemaVersion: 1,
			applicationId: OTHER_APPLICATION,
			afterEventId: 0,
			maxEvents: 1,
		});
		expect(result.status).toBe(403);
		expect(JSON.parse(result.body).code).toBe("IWEB_LOG_APP_ISOLATION");
	});

	test("the authority reporting no ring for an application returns 404, never a synthesized payload", async () => {
		const face = faceOf(seededAuthority());
		const result = await drain(face, OTHER_APPLICATION, {
			schemaVersion: 1,
			applicationId: OTHER_APPLICATION,
			afterEventId: 0,
			maxEvents: 1,
		});
		expect(result.status).toBe(404);
		expect(JSON.parse(result.body).code).toBe(WASM_LOG_APPLICATION_UNKNOWN);
	});

	test("an unreachable authority is explicit 503 unavailability for both endpoints — never fabricated data", async () => {
		const unavailable = new StubAuthority({ ok: false, reason: "unavailable" }, { ok: false, reason: "unavailable" });
		const face = createWasmLoggingOwnerFace(unavailable, IWEB_LOG_FORWARDING_DEFAULT);
		const drained = await drain(face, APPLICATION, {
			schemaVersion: 1,
			applicationId: APPLICATION,
			afterEventId: 0,
			maxEvents: 1,
		});
		expect(drained.status).toBe(503);
		expect(JSON.parse(drained.body).code).toBe(WASM_LOG_AUTHORITY_UNAVAILABLE);
		const projected = await summary(face, APPLICATION);
		expect(projected.status).toBe(503);
		expect(JSON.parse(projected.body).code).toBe(WASM_LOG_AUTHORITY_UNAVAILABLE);
	});

	test("an unwired authority source (pre-wasmd-endpoint build) is 503 for every application", async () => {
		const face = createWasmLoggingOwnerFace(null, IWEB_LOG_FORWARDING_DEFAULT);
		const drained = await drain(face, APPLICATION, {
			schemaVersion: 1,
			applicationId: APPLICATION,
			afterEventId: 0,
			maxEvents: 1,
		});
		expect(drained.status).toBe(503);
		expect(JSON.parse(drained.body).code).toBe(WASM_LOG_AUTHORITY_UNAVAILABLE);
		const projected = await summary(face, APPLICATION);
		expect(projected.status).toBe(503);
		expect(JSON.parse(projected.body).code).toBe(WASM_LOG_AUTHORITY_UNAVAILABLE);
		// framing/隔离校验与权威无关，先于 503 判定。
		const crossApp = await drain(face, APPLICATION, {
			schemaVersion: 1,
			applicationId: OTHER_APPLICATION,
			afterEventId: 0,
			maxEvents: 1,
		});
		expect(crossApp.status).toBe(403);
	});

	test("a malformed authority projection is refused whole (503, no partial events)", async () => {
		const base = {
			schemaVersion: 1,
			applicationId: APPLICATION,
			droppedCount: 0,
			hasMore: false,
			lastEventId: 1,
		};
		const goodEvent = {
			eventId: 1,
			timestampUtc: "2026-08-28T00:00:00Z",
			applicationId: APPLICATION,
			versionId: VERSION_ID,
			preparationGeneration: 1,
			executionGeneration: 1,
			level: "info",
			message: "one",
			fields: [],
		};
		const cases: readonly unknown[] = [
			// 未知字段（response 与 record 两级）。
			{ ...base, events: [goodEvent], extra: true },
			{ ...base, events: [{ ...goodEvent, extra: true }] },
			// 归属违约：response/record 指向别的应用。
			{ ...base, applicationId: OTHER_APPLICATION, events: [goodEvent] },
			{ ...base, events: [{ ...goodEvent, applicationId: OTHER_APPLICATION }] },
			// redaction 边界违约：reserved key 携带未 redact 的原值。
			{ ...base, events: [{ ...goodEvent, fields: [{ key: "token", value: "leaked" }] }] },
			// 单调性/游标违约。
			{ ...base, events: [goodEvent, goodEvent] },
			{ ...base, events: [{ ...goodEvent, eventId: 0 }] },
			// 分页违约：超过请求 maxEvents。
			{ ...base, events: [goodEvent, { ...goodEvent, eventId: 2 }] },
		];
		for (const projection of cases) {
			const stub = new StubAuthority({ ok: true, value: projection as IwebLoggingDrainResponseV1 });
			const face = createWasmLoggingOwnerFace(stub, IWEB_LOG_FORWARDING_DEFAULT);
			const result = await drain(face, APPLICATION, {
				schemaVersion: 1,
				applicationId: APPLICATION,
				afterEventId: 0,
				maxEvents: 1,
			});
			expect(result.status).toBe(503);
			expect(JSON.parse(result.body).code).toBe(WASM_LOG_AUTHORITY_WIRE_INVALID);
			expect(result.body).not.toContain("event 0");
			expect(result.body).not.toContain("one");
		}
	});

	test("non-JSON bodies, wrong content types and oversized bodies are rejected before the face", async () => {
		const face = faceOf(seededAuthority());
		const invalidJson = await drainRaw(face, APPLICATION, "{not json");
		expect(invalidJson.status).toBe(400);
		expect(JSON.parse(invalidJson.body).code).toBe("INVALID_JSON");
		const wrongType = await drainRaw(face, APPLICATION, "{}", "text/plain");
		expect(wrongType.status).toBe(415);
		expect(JSON.parse(wrongType.body).code).toBe("UNSUPPORTED_CONTENT_TYPE");
		const oversized = await handleWasmLoggingDrainHttp(face, {
			method: "POST",
			path: WASM_HOST_LOGGING_DRAIN_PATH + "/" + APPLICATION,
			contentType: "application/json",
			body: Buffer.alloc(65 * 1024, 0x20),
		});
		expect(oversized.status).toBe(413);
	});

	test("the wire validator exposes its issues for diagnostics (cursor and paging invariants)", () => {
		const request: IwebLoggingDrainRequestV1 = {
			schemaVersion: 1,
			applicationId: APPLICATION,
			afterEventId: 5,
			maxEvents: 2,
		};
		const late = {
			schemaVersion: 1,
			applicationId: APPLICATION,
			events: [
				{
					eventId: 3,
					timestampUtc: "2026-08-28T00:00:00Z",
					applicationId: APPLICATION,
					versionId: VERSION_ID,
					preparationGeneration: 1,
					executionGeneration: 1,
					level: "info",
					message: "stale",
					fields: [],
				},
			],
			droppedCount: 0,
			hasMore: false,
			lastEventId: 3,
		};
		const outcome = validateIwebLoggingDrainResponseWireV1(late, request);
		expect(outcome.ok).toBe(false);
		if (!outcome.ok) {
			expect(outcome.issues.some((entry) => entry.code === WASM_LOG_AUTHORITY_WIRE_INVALID)).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// monitor summary 投影（wasm-health 模式：只读采样，仅计数/水位，无日志正文）
// ---------------------------------------------------------------------------

describe("logging owner face: monitor summary projection", () => {
	test("summary carries counts and capacity only — no message bodies or field values", async () => {
		const face = faceOf(seededAuthority());
		const result = await summary(face, APPLICATION);
		expect(result.status).toBe(200);
		const body = JSON.parse(result.body);
		expect(body).toEqual({
			applicationId: APPLICATION,
			retainedEvents: 3,
			retainedBytes: body.retainedBytes,
			droppedCount: 0,
			lastEventId: 3,
			capacity: RING_CAPACITY,
		});
		expect(JSON.stringify(body)).not.toContain("event 0");
		expect(JSON.stringify(body)).not.toContain("ordinal");
	});

	test("an unknown application summary returns 404, never zeros", async () => {
		const face = faceOf(seededAuthority());
		const result = await summary(face, OTHER_APPLICATION);
		expect(result.status).toBe(404);
		expect(JSON.parse(result.body).code).toBe(WASM_LOG_APPLICATION_UNKNOWN);
	});

	test("a malformed monitor summary is refused (503), not degraded to zeros", async () => {
		const stub = new StubAuthority(
			{ ok: false, reason: "unavailable" },
			{ ok: true, value: { applicationId: APPLICATION, retainedEvents: -1, retainedBytes: 0, droppedCount: 0, lastEventId: 0, capacity: RING_CAPACITY } as unknown as IwebLoggingMonitorSummaryV1 },
		);
		const face = createWasmLoggingOwnerFace(stub, IWEB_LOG_FORWARDING_DEFAULT);
		const result = await summary(face, APPLICATION);
		expect(result.status).toBe(503);
		expect(JSON.parse(result.body).code).toBe(WASM_LOG_AUTHORITY_WIRE_INVALID);
	});

	test("an authority lifecycle reset is observed on the next projection (no supervisor-side ledger)", async () => {
		const authority = seededAuthority();
		const face = faceOf(authority);
		const before = JSON.parse((await summary(face, APPLICATION)).body);
		expect(before.retainedEvents).toBe(3);
		authority.reset(APPLICATION);
		const after = JSON.parse((await summary(face, APPLICATION)).body);
		expect(after.retainedEvents).toBe(0);
		expect(after.droppedCount).toBe(0);
		expect(after.lastEventId).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// 转发配置宿主装载（默认关 fail-closed）
// ---------------------------------------------------------------------------

describe("logging forwarding config host loading (default off, fail-closed)", () => {
	test("an unset environment loads the default disabled config", () => {
		const io = new MemoryIO();
		expect(loadIwebLoggingForwardingConfig(io, {})).toEqual(IWEB_LOG_FORWARDING_DEFAULT);
		expect(
			loadIwebLoggingForwardingConfig(io, { [IWEB_WASM_LOG_FORWARDING_FILE_ENV]: "  " }),
		).toEqual(IWEB_LOG_FORWARDING_DEFAULT);
		// 默认关不触碰文件系统：即使路径被设置后文件存在也不读取。
		expect(io.files.size).toBe(0);
	});

	test("a valid owner-sealed file enables forwarding with the exact wire", () => {
		const io = new MemoryIO();
		io.write(
			"/etc/iweb/log-forwarding.json",
			jcsText({
				schemaVersion: 1,
				enabled: true,
				format: "json-lines",
				endpoint: "logs.example.com:5170",
			}),
		);
		const loaded = loadIwebLoggingForwardingConfig(io, {
			[IWEB_WASM_LOG_FORWARDING_FILE_ENV]: "/etc/iweb/log-forwarding.json",
		});
		expect(loaded).toEqual({
			schemaVersion: 1,
			enabled: true,
			format: "json-lines",
			endpoint: "logs.example.com:5170",
		});
	});

	test("a disabled config carrying format or endpoint leftovers fails closed", () => {
		const io = new MemoryIO();
		io.write(
			"/etc/iweb/log-forwarding.json",
			jcsText({ schemaVersion: 1, enabled: false, format: "json-lines", endpoint: null }),
		);
		expect(() =>
			loadIwebLoggingForwardingConfig(io, {
				[IWEB_WASM_LOG_FORWARDING_FILE_ENV]: "/etc/iweb/log-forwarding.json",
			}),
		).toThrow(WasmLoggingServeError);
	});

	test("an enabled config with an invalid endpoint fails closed", () => {
		const io = new MemoryIO();
		for (const endpoint of [
			"localhost:5170",
			"logs.example.com",
			"http://logs.example.com:5170",
			"logs.example.com:0",
			"logs.example.com:70000",
			"[::1]:5170",
			"user@logs.example.com:5170",
		]) {
			io.write(
				"/etc/iweb/log-forwarding.json",
				jcsText({ schemaVersion: 1, enabled: true, format: "syslog", endpoint }),
			);
			expect(() =>
				loadIwebLoggingForwardingConfig(io, {
					[IWEB_WASM_LOG_FORWARDING_FILE_ENV]: "/etc/iweb/log-forwarding.json",
				}),
			).toThrow(WasmLoggingServeError);
		}
	});

	test("missing files, non-canonical bytes and relative paths fail closed", () => {
		const io = new MemoryIO();
		expect(() =>
			loadIwebLoggingForwardingConfig(io, {
				[IWEB_WASM_LOG_FORWARDING_FILE_ENV]: "/etc/iweb/log-forwarding.json",
			}),
		).toThrow(WasmLoggingServeError);
		io.write(
			"/etc/iweb/log-forwarding.json",
			JSON.stringify({ enabled: false, schemaVersion: 1, format: null, endpoint: null }, null, 2),
		);
		try {
			loadIwebLoggingForwardingConfig(io, {
				[IWEB_WASM_LOG_FORWARDING_FILE_ENV]: "/etc/iweb/log-forwarding.json",
			});
			throw new Error("unreachable: non-canonical bytes must fail");
		} catch (error) {
			expect(error).toBeInstanceOf(WasmLoggingServeError);
			expect((error as WasmLoggingServeError).code).toBe(WASM_LOG_FORWARDING_CONFIG_INVALID);
		}
		expect(() =>
			loadIwebLoggingForwardingConfig(io, {
				[IWEB_WASM_LOG_FORWARDING_FILE_ENV]: "etc/iweb/log-forwarding.json",
			}),
		).toThrow(WasmLoggingServeError);
	});

	test("assembly without an authority source wires the face with explicit unavailability (default-off forwarding)", async () => {
		const assembled = assembleWasmLoggingOwnerFace({ environment: {}, io: new MemoryIO() });
		expect(assembled.enabled).toBe(true);
		expect(assembled.source).toBe(null);
		expect(assembled.forwardingConfig).toEqual(IWEB_LOG_FORWARDING_DEFAULT);
		const result = await summary(assembled.face, APPLICATION);
		expect(result.status).toBe(503);
		expect(JSON.parse(result.body).code).toBe(WASM_LOG_AUTHORITY_UNAVAILABLE);
	});

	test("assembly with an injected authority source serves its projections", async () => {
		const assembled = assembleWasmLoggingOwnerFace({
			environment: {},
			io: new MemoryIO(),
			source: seededAuthority(),
		});
		expect(assembled.source).not.toBe(null);
		const result = await summary(assembled.face, APPLICATION);
		expect(result.status).toBe(200);
		expect(JSON.parse(result.body).retainedEvents).toBe(3);
	});
});

// ---------------------------------------------------------------------------
// server 级接线：既有授权面之下的端点（未配置面 503；配置面 200）
// ---------------------------------------------------------------------------

function socketJsonRequest(
	socketPath: string,
	method: string,
	path: string,
	body?: string,
): Promise<{ readonly status: number; readonly body: string }> {
	return new Promise((resolve, reject) => {
		const value = request(
			{
				socketPath,
				method,
				path,
				headers: body === undefined ? {} : { "content-type": "application/json" },
			},
			(response) => {
				let payload = "";
				response.setEncoding("utf8");
				response.on("data", (chunk: string) => (payload += chunk));
				response.on("end", () => resolve({ status: response.statusCode ?? 0, body: payload }));
			},
		);
		value.once("error", reject);
		if (body !== undefined) value.write(body);
		value.end();
	});
}

describe("supervisor server wiring: logging owner face endpoints", () => {
	test("a source-backed face serves drain and summary over the authenticated supervisor socket", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-supervisor-log-"));
		const socketPath = join(directory, "supervisor.sock");
		const authority = new InMemoryWasmLoggingAuthority();
		authority.ensure(APPLICATION, RING_CAPACITY);
		const write = authority.write(APPLICATION, hostContext(APPLICATION), {
			level: "error",
			message: "boom",
			fields: [],
		});
		expect(write.ok && write.outcome).toBe("accepted");
		const running = await startSupervisorServer({
			socketPath,
			loggingFace: createWasmLoggingOwnerFace(authority, IWEB_LOG_FORWARDING_DEFAULT),
		});
		try {
			const drained = await socketJsonRequest(
				socketPath,
				"POST",
				WASM_HOST_LOGGING_DRAIN_PATH + "/" + APPLICATION,
				JSON.stringify({
					schemaVersion: 1,
					applicationId: APPLICATION,
					afterEventId: 0,
					maxEvents: 5,
				}),
			);
			expect(drained.status).toBe(200);
			expect(JSON.parse(drained.body).events).toHaveLength(1);
			const projected = await socketJsonRequest(
				socketPath,
				"GET",
				WASM_HOST_LOGGING_SUMMARY_PATH + "/" + APPLICATION,
			);
			expect(projected.status).toBe(200);
			expect(JSON.parse(projected.body).retainedEvents).toBe(1);
			const crossApp = await socketJsonRequest(
				socketPath,
				"POST",
				WASM_HOST_LOGGING_DRAIN_PATH + "/" + APPLICATION,
				JSON.stringify({
					schemaVersion: 1,
					applicationId: OTHER_APPLICATION,
					afterEventId: 0,
					maxEvents: 5,
				}),
			);
			expect(crossApp.status).toBe(403);
			const unknown = await socketJsonRequest(
				socketPath,
				"GET",
				WASM_HOST_LOGGING_SUMMARY_PATH + "/" + OTHER_APPLICATION,
			);
			expect(unknown.status).toBe(404);
		} finally {
			await running.close();
		}
	});

	test("an unconfigured face returns 503 for both logging endpoints (fail-closed)", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-supervisor-log-"));
		const socketPath = join(directory, "supervisor.sock");
		const running = await startSupervisorServer({ socketPath });
		try {
			const drained = await socketJsonRequest(
				socketPath,
				"POST",
				WASM_HOST_LOGGING_DRAIN_PATH + "/" + APPLICATION,
				JSON.stringify({
					schemaVersion: 1,
					applicationId: APPLICATION,
					afterEventId: 0,
					maxEvents: 5,
				}),
			);
			expect(drained.status).toBe(503);
			expect(JSON.parse(drained.body).code).toBe(WASM_LOG_FACE_NOT_CONFIGURED);
			const projected = await socketJsonRequest(
				socketPath,
				"GET",
				WASM_HOST_LOGGING_SUMMARY_PATH + "/" + APPLICATION,
			);
			expect(projected.status).toBe(503);
			expect(JSON.parse(projected.body).code).toBe(WASM_LOG_FACE_NOT_CONFIGURED);
		} finally {
			await running.close();
		}
	});

	test("a configured face without an authority source is explicitly unavailable over the socket", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-supervisor-log-"));
		const socketPath = join(directory, "supervisor.sock");
		const running = await startSupervisorServer({
			socketPath,
			loggingFace: createWasmLoggingOwnerFace(null, IWEB_LOG_FORWARDING_DEFAULT),
		});
		try {
			const drained = await socketJsonRequest(
				socketPath,
				"POST",
				WASM_HOST_LOGGING_DRAIN_PATH + "/" + APPLICATION,
				JSON.stringify({
					schemaVersion: 1,
					applicationId: APPLICATION,
					afterEventId: 0,
					maxEvents: 5,
				}),
			);
			expect(drained.status).toBe(503);
			expect(JSON.parse(drained.body).code).toBe(WASM_LOG_AUTHORITY_UNAVAILABLE);
		} finally {
			await running.close();
		}
	});
});
