// 用户原始需求（2026-08-28，add-wasm-host-services supervisor 接线层）：logging owner 面的接线证明——
//   drain/stream 端点（经 supervisor server 既有授权/token 面）、monitor summary 投影
//   （wasm-health executionMetrics 同款模式）、转发配置宿主装载（默认关 fail-closed）、
//   跨应用隔离违约拒绝（403，绝不部分返回）。
// 正交意图：正例（drain 分页/游标 stream、summary 仅计数）/负例（非法 wire、非法 JSON、
//   content-type、超限、未知应用、未配置面 503）/隔离（路径与 wire applicationId 不一致、
//   宿主上下文不属于环属主）/转发配置（默认关、合法开启、任何畸形 fail-closed）。
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
	loadIwebLoggingForwardingConfig,
	WasmLoggingRingStore,
	WasmLoggingServeError,
	WASM_HOST_LOGGING_DRAIN_PATH,
	WASM_HOST_LOGGING_SUMMARY_PATH,
	WASM_LOG_APPLICATION_UNKNOWN,
	WASM_LOG_DRAIN_REQUEST_INVALID,
	WASM_LOG_FACE_NOT_CONFIGURED,
	WASM_LOG_FORWARDING_CONFIG_INVALID,
	IWEB_WASM_LOG_FORWARDING_FILE_ENV,
	type WasmLoggingOwnerFace,
} from "../supervisor/wasm-host-logging.ts";
import type { WasmServeIO } from "../supervisor/wasm-serve.ts";
import { startSupervisorServer } from "../supervisor/server.ts";
import {
	IWEB_LOG_FORWARDING_DEFAULT,
	type IwebLoggingHostContextV1,
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

function seededStore(): WasmLoggingRingStore {
	const store = new WasmLoggingRingStore();
	store.ensure(APPLICATION, RING_CAPACITY);
	for (let index = 0; index < 3; index++) {
		const result = store.write(APPLICATION, hostContext(APPLICATION, index + 1), {
			level: "info",
			message: "event " + index,
			fields: [{ key: "ordinal", value: String(index) }],
		});
		if (!result.ok || result.outcome !== "accepted")
			throw new Error("fixture error: write must be accepted");
	}
	return store;
}

function faceOf(store: WasmLoggingRingStore): WasmLoggingOwnerFace {
	return createWasmLoggingOwnerFace(store, IWEB_LOG_FORWARDING_DEFAULT);
}

function drain(
	face: WasmLoggingOwnerFace,
	applicationId: string,
	body: unknown,
	contentType = "application/json",
): { readonly status: number; readonly body: string } {
	return handleWasmLoggingDrainHttp(face, {
		method: "POST",
		path: WASM_HOST_LOGGING_DRAIN_PATH + "/" + applicationId,
		contentType,
		body: Buffer.from(JSON.stringify(body), "utf8"),
	});
}

function drainRaw(
	face: WasmLoggingOwnerFace,
	applicationId: string,
	rawBody: string,
	contentType = "application/json",
): { readonly status: number; readonly body: string } {
	return handleWasmLoggingDrainHttp(face, {
		method: "POST",
		path: WASM_HOST_LOGGING_DRAIN_PATH + "/" + applicationId,
		contentType,
		body: Buffer.from(rawBody, "utf8"),
	});
}

function summary(
	face: WasmLoggingOwnerFace,
	applicationId: string,
): { readonly status: number; readonly body: string } {
	return handleWasmLoggingSummaryHttp(
		face,
		"GET",
		WASM_HOST_LOGGING_SUMMARY_PATH + "/" + applicationId,
	);
}

// ---------------------------------------------------------------------------
// drain/stream：正例（分页 + 游标续流）
// ---------------------------------------------------------------------------

describe("logging owner face: drain/stream positive paths", () => {
	test("drain returns the application's bounded retained events with paging", () => {
		const face = faceOf(seededStore());
		const result = drain(face, APPLICATION, {
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

	test("stream continues from the cursor of the previous drain response", () => {
		const face = faceOf(seededStore());
		const first = JSON.parse(
			drain(face, APPLICATION, {
				schemaVersion: 1,
				applicationId: APPLICATION,
				afterEventId: 0,
				maxEvents: 2,
			}).body,
		);
		const second = JSON.parse(
			drain(face, APPLICATION, {
				schemaVersion: 1,
				applicationId: APPLICATION,
				afterEventId: 2,
				maxEvents: 2,
			}).body,
		);
		expect(second.events.map((event: { message: string }) => event.message)).toEqual(["event 2"]);
		expect(second.hasMore).toBe(false);
		expect(first.lastEventId).toBe(second.lastEventId);
	});

	test("drain reports the dropped counter without evicting retained events", () => {
		const store = new WasmLoggingRingStore();
		store.ensure(APPLICATION, { maxEvents: 1, maxBytes: 65536 });
		const first = store.write(APPLICATION, hostContext(APPLICATION), {
			level: "info",
			message: "kept",
			fields: [],
		});
		expect(first.ok && first.outcome).toBe("accepted");
		const second = store.write(APPLICATION, hostContext(APPLICATION), {
			level: "warn",
			message: "dropped",
			fields: [],
		});
		expect(second.ok && second.outcome).toBe("dropped");
		const face = faceOf(store);
		const result = JSON.parse(
			drain(face, APPLICATION, {
				schemaVersion: 1,
				applicationId: APPLICATION,
				afterEventId: 0,
				maxEvents: 10,
			}).body,
		);
		expect(result.events.map((event: { message: string }) => event.message)).toEqual(["kept"]);
		expect(result.droppedCount).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// drain/stream：负例（wire/传输级）与跨应用隔离违约
// ---------------------------------------------------------------------------

describe("logging owner face: drain negative and isolation paths", () => {
	test("an invalid drain wire is rejected with a stable code", () => {
		const face = faceOf(seededStore());
		for (const body of [
			{ schemaVersion: 2, applicationId: APPLICATION, afterEventId: 0, maxEvents: 1 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: -1, maxEvents: 1 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 0 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 1001 },
			{ schemaVersion: 1, applicationId: APPLICATION, afterEventId: 0, maxEvents: 1, extra: true },
			{ schemaVersion: 1, applicationId: "NOT-LOWER", afterEventId: 0, maxEvents: 1 },
		]) {
			const result = drain(face, APPLICATION, body);
			expect(result.status).toBe(400);
			expect(JSON.parse(result.body).code).toBe(WASM_LOG_DRAIN_REQUEST_INVALID);
		}
	});

	test("a drain request naming another application is a cross-application isolation violation (403)", () => {
		const face = faceOf(seededStore());
		const result = drain(face, APPLICATION, {
			schemaVersion: 1,
			applicationId: OTHER_APPLICATION,
			afterEventId: 0,
			maxEvents: 1,
		});
		expect(result.status).toBe(403);
		expect(JSON.parse(result.body).code).toBe("IWEB_LOG_APP_ISOLATION");
	});

	test("draining an application with no ring returns 404, never a synthesized empty payload", () => {
		const face = faceOf(seededStore());
		const result = drain(face, OTHER_APPLICATION, {
			schemaVersion: 1,
			applicationId: OTHER_APPLICATION,
			afterEventId: 0,
			maxEvents: 1,
		});
		expect(result.status).toBe(404);
		expect(JSON.parse(result.body).code).toBe(WASM_LOG_APPLICATION_UNKNOWN);
	});

	test("non-JSON bodies, wrong content types and oversized bodies are rejected before the face", () => {
		const face = faceOf(seededStore());
		const invalidJson = drainRaw(face, APPLICATION, "{not json");
		expect(invalidJson.status).toBe(400);
		expect(JSON.parse(invalidJson.body).code).toBe("INVALID_JSON");
		const wrongType = drainRaw(face, APPLICATION, "{}", "text/plain");
		expect(wrongType.status).toBe(415);
		expect(JSON.parse(wrongType.body).code).toBe("UNSUPPORTED_CONTENT_TYPE");
		const oversized = handleWasmLoggingDrainHttp(face, {
			method: "POST",
			path: WASM_HOST_LOGGING_DRAIN_PATH + "/" + APPLICATION,
			contentType: "application/json",
			body: Buffer.alloc(65 * 1024, 0x20),
		});
		expect(oversized.status).toBe(413);
	});

	test("a host context that does not own the ring is rejected by the contract isolation rule", () => {
		const store = seededStore();
		const result = store.write(APPLICATION, hostContext(OTHER_APPLICATION), {
			level: "info",
			message: "forged",
			fields: [],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("IWEB_LOG_APP_ISOLATION");
		// 隔离违约零副作用：本应用已保留事件不被触碰。
		const drained = drain(faceOf(store), APPLICATION, {
			schemaVersion: 1,
			applicationId: APPLICATION,
			afterEventId: 0,
			maxEvents: 10,
		});
		expect(JSON.parse(drained.body).events).toHaveLength(3);
	});
});

// ---------------------------------------------------------------------------
// monitor summary 投影（wasm-health 模式：只读采样，仅计数/水位，无日志正文）
// ---------------------------------------------------------------------------

describe("logging owner face: monitor summary projection", () => {
	test("summary carries counts and capacity only — no message bodies or field values", () => {
		const face = faceOf(seededStore());
		const result = summary(face, APPLICATION);
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

	test("an unknown application summary returns 404, never zeros", () => {
		const face = faceOf(seededStore());
		const result = summary(face, OTHER_APPLICATION);
		expect(result.status).toBe(404);
		expect(JSON.parse(result.body).code).toBe(WASM_LOG_APPLICATION_UNKNOWN);
	});

	test("reset starts a new runtime lifecycle (no durability claim across restarts)", () => {
		const store = seededStore();
		store.reset(APPLICATION);
		const body = JSON.parse(summary(faceOf(store), APPLICATION).body);
		expect(body.retainedEvents).toBe(0);
		expect(body.droppedCount).toBe(0);
		expect(body.lastEventId).toBe(0);
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

	test("assembly wires the face with the loaded config (default off) and an empty transitional store", () => {
		const assembled = assembleWasmLoggingOwnerFace({ environment: {}, io: new MemoryIO() });
		expect(assembled.enabled).toBe(true);
		if (!assembled.enabled) throw new Error("unreachable");
		expect(assembled.forwardingConfig).toEqual(IWEB_LOG_FORWARDING_DEFAULT);
		const result = summary(assembled.face, APPLICATION);
		expect(result.status).toBe(404);
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
	test("configured face serves drain and summary over the authenticated supervisor socket", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-supervisor-log-"));
		const socketPath = join(directory, "supervisor.sock");
		const assembled = assembleWasmLoggingOwnerFace({ environment: {}, io: new MemoryIO() });
		assembled.store.ensure(APPLICATION, RING_CAPACITY);
		const write = assembled.store.write(APPLICATION, hostContext(APPLICATION), {
			level: "error",
			message: "boom",
			fields: [],
		});
		expect(write.ok && write.outcome).toBe("accepted");
		const running = await startSupervisorServer({ socketPath, loggingFace: assembled.face });
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
});
