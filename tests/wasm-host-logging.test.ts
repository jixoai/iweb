// 用户原始需求（2026-08-27，add-wasm-host-services 契约先行）：`iweb:logging@1.0.0` 的 WIT 文本、事件校验、
// 有界环 dropped 语义、redaction 先于大小计算、默认关的外部转发配置与 audit/stdio 隔离必须有正/负例。
// 正交意图：WIT↔spec 逐字一致性；事件 grammar/界与错误分类；redaction/环/单调 eventId/reset 纯函数；
// 转发配置与 drain 请求-响应 wire；audit/stdio 隔离闭集断言。
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	createIwebLoggingRing,
	drainIwebLoggingRing,
	IWEB_LOG_ALLOWED_SINKS,
	IWEB_LOG_EVENT_MAX_BYTES_DEFAULT,
	IWEB_LOG_FIELD_KEY_PATTERN,
	IWEB_LOG_FORWARDING_DEFAULT,
	IWEB_LOG_FORWARDING_FAILURE_WIRE_CODES,
	IWEB_LOG_FORWARDING_FORMATS,
	IWEB_LOG_LEVELS,
	IWEB_LOG_OUTCOME_CASES,
	IWEB_LOG_RESERVED_FIELD_KEYS,
	IWEB_LOG_REDACTED_VALUE,
	IWEB_LOG_RETAINED_RECORD_FIELDS,
	IWEB_LOG_RING_MAX_BYTES_DEFAULT,
	IWEB_LOG_RING_MAX_EVENTS_DEFAULT,
	IWEB_LOG_TRANSPORT_ERROR_CODES,
	IWEB_LOG_WIRE_ERROR_BY_CASE,
	IWEB_LOG_WIT_ERROR_CASES,
	iwebLoggingSinkErrorCode,
	iwebLoggingWitAdmissionErrorCode,
	isReservedIwebLoggingFieldKey,
	isValidIwebLoggingForwardingEndpoint,
	measureIwebLoggingEventBytes,
	projectIwebLoggingMonitorSummary,
	redactIwebLoggingFields,
	resetIwebLoggingRing,
	validateIwebLoggingEvent,
	validateIwebLoggingForwardingConfig,
	validateIwebLoggingHostContext,
	writeIwebLoggingEvent,
} from "../packages/contracts/wasm-host-logging.ts";

const repoRoot = join(import.meta.dir, "..");
// 变更进行中，规范权威在 change 目录；归档后需随 archive 把路径切到 openspec/specs/wasm-host-logging/spec.md。
const specText = readFileSync(join(repoRoot, "openspec/changes/add-wasm-host-services/specs/wasm-host-logging/spec.md"), "utf8");

function extractWitBlocks(text: string): string[] {
	const blocks: string[] = [];
	// change 目录的 delta spec 用 ~~~wit 围栏；归档主规范用 ```wit。两种围栏都识别。
	const pattern = /(?:```|~~~)wit\r?\n([\s\S]*?)(?:```|~~~)/g;
	let match: RegExpExecArray | null;
	while ((match = pattern.exec(text)) !== null) blocks.push(match[1]);
	return blocks;
}

// 逐字一致性口径：剥掉 `//` 行注释与行尾空白、去掉空行后必须与 spec 的 wit 代码块完全相等。
function normalizeWitText(text: string): string {
	return text
		.split(/\r?\n/)
		.map((line) => {
			const commentStart = line.indexOf("//");
			return (commentStart >= 0 ? line.slice(0, commentStart) : line).replace(/\s+$/, "");
		})
		.filter((line) => line.length > 0)
		.join("\n");
}

const HOST_CONTEXT = {
	applicationId: "notes-app",
	versionId: "a".repeat(64) + "-1",
	preparationGeneration: 3,
	executionGeneration: 2,
	timestampUtc: "2026-08-27T12:34:56.789Z",
};

function makeRing(applicationId = "notes-app", capacity = { maxEvents: IWEB_LOG_RING_MAX_EVENTS_DEFAULT, maxBytes: IWEB_LOG_RING_MAX_BYTES_DEFAULT }) {
	const ring = createIwebLoggingRing(applicationId, capacity);
	if (!ring.ok) throw new Error("fixture ring creation failed");
	return ring.value;
}

describe("iweb host logging WIT package", () => {
	const blocks = extractWitBlocks(specText);

	test("spec declares exactly the one iweb:logging WIT block", () => {
		expect(blocks.length).toBe(1);
	});

	test("iweb-logging.wit is byte-identical to the spec block and only imports logger", () => {
		const fileText = readFileSync(join(repoRoot, "packages/contracts/wit/iweb-logging.wit"), "utf8");
		const normalized = normalizeWitText(fileText);
		expect(normalized).toBe(normalizeWitText(blocks[0]));
		expect(normalized).toContain("package iweb:logging@1.0.0;");
		expect(normalized).toContain("enum level { trace, debug, info, warn, error }");
		expect(normalized).toContain("enum outcome { accepted, dropped }");
		expect(normalized).toContain("variant error { invalid-event, limit-exceeded, unavailable, internal }");
		expect(normalized).toContain("write: func(event: event) -> result<outcome, error>;");
		expect(normalized).toContain("world logging { import logger; }");
		expect(normalized).not.toMatch(/^\s*export\s/m);
	});

	test("exported logger or an unknown package patch is rejected before acceptance", () => {
		expect(iwebLoggingWitAdmissionErrorCode({ package: "iweb:logging@1.0.0", interface: "logger", direction: "export" })).toBe("IWEB_LOG_WIT_DIRECTION_INVALID");
		expect(iwebLoggingWitAdmissionErrorCode({ package: "iweb:logging@1.0.1", interface: "logger", direction: "import" })).toBe("IWEB_LOG_WIT_PACKAGE_INVALID");
		expect(iwebLoggingWitAdmissionErrorCode({ package: "iweb:logging@1.0.0", interface: "logger", direction: "import" })).toBe(null);
		// 非 logger 接口不属于本契约的方向法管辖。
		expect(iwebLoggingWitAdmissionErrorCode({ package: "iweb:logging@1.0.0", interface: "store", direction: "export" })).toBe(null);
	});

	test("level, outcome and error wire tables are the exact closed sets", () => {
		expect([...IWEB_LOG_LEVELS]).toEqual(["trace", "debug", "info", "warn", "error"]);
		expect([...IWEB_LOG_OUTCOME_CASES]).toEqual(["accepted", "dropped"]);
		expect([...IWEB_LOG_WIT_ERROR_CASES]).toEqual(["invalid-event", "limit-exceeded", "unavailable", "internal"]);
		expect(IWEB_LOG_WIRE_ERROR_BY_CASE["invalid-event"]).toBe("IWEB_LOG_INVALID_EVENT");
		expect(IWEB_LOG_WIRE_ERROR_BY_CASE["limit-exceeded"]).toBe("IWEB_LOG_LIMIT_EXCEEDED");
		expect(IWEB_LOG_WIRE_ERROR_BY_CASE.unavailable).toBe("IWEB_LOG_UNAVAILABLE");
		expect(IWEB_LOG_WIRE_ERROR_BY_CASE.internal).toBe("IWEB_LOG_INTERNAL");
		expect([...IWEB_LOG_TRANSPORT_ERROR_CODES]).toEqual(["IWEB_LOG_APP_ISOLATION"]);
	});
});

describe("iweb logging event validation", () => {
	test("accepts all levels with an empty message and empty fields", () => {
		for (const level of IWEB_LOG_LEVELS) {
			const result = validateIwebLoggingEvent({ level, message: "", fields: [] });
			expect(result.ok).toBe(true);
		}
	});

	test("accepts 32 unique grammar keys with multibyte values at the exact bounds", () => {
		const fields = Array.from({ length: 32 }, (_, index) => ({ key: "f" + index, value: "é".repeat(512) }));
		const result = validateIwebLoggingEvent({ level: "info", message: "é".repeat(2048), fields });
		expect(result.ok).toBe(true);
	});

	test("rejects unknown levels, non-strings, unknown fields and caller identity injection", () => {
		for (const level of ["verbose", "INFO", "", 7, null]) {
			expect(validateIwebLoggingEvent({ level, message: "m", fields: [] }).ok).toBe(false);
		}
		expect(validateIwebLoggingEvent({ level: "info", message: 7, fields: [] }).ok).toBe(false);
		expect(validateIwebLoggingEvent({ level: "info", message: "m", fields: "[]" }).ok).toBe(false);
		expect(validateIwebLoggingEvent("nope").ok).toBe(false);
		// caller timestamp / identity / eventId / owner credential 都是未知字段，fail-closed。
		for (const extra of [{ eventId: 1 }, { timestampUtc: "2026-08-27T00:00:00Z" }, { applicationId: "notes-app" }, { authorization: "Bearer x" }]) {
			const result = validateIwebLoggingEvent({ level: "info", message: "m", fields: [], ...extra });
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.errors.some((entry) => entry.code === "UNKNOWN_FIELD")).toBe(true);
		}
	});

	test("rejects over-bound message, values and field counts with limit-exceeded classification", () => {
		const overMessage = validateIwebLoggingEvent({ level: "info", message: "é".repeat(2049), fields: [] });
		expect(overMessage.ok).toBe(false);
		const overValue = validateIwebLoggingEvent({ level: "info", message: "m", fields: [{ key: "a", value: "é".repeat(513) }] });
		expect(overValue.ok).toBe(false);
		const overCount = validateIwebLoggingEvent({
			level: "info",
			message: "m",
			fields: Array.from({ length: 33 }, (_, index) => ({ key: "f" + index, value: "v" })),
		});
		expect(overCount.ok).toBe(false);
		for (const result of [overMessage, overValue, overCount]) {
			if (!result.ok) expect(result.errors.every((entry) => ["MESSAGE_TOO_LONG", "VALUE_TOO_LONG", "TOO_MANY_FIELDS"].includes(entry.code))).toBe(true);
		}
	});

	test("rejects duplicate keys, grammar violations and lone-surrogate (invalid UTF-8) text", () => {
		const duplicate = validateIwebLoggingEvent({ level: "info", message: "m", fields: [{ key: "a", value: "1" }, { key: "a", value: "2" }] });
		expect(duplicate.ok).toBe(false);
		if (!duplicate.ok) expect(duplicate.errors.some((entry) => entry.code === "DUPLICATE_KEY")).toBe(true);
		for (const key of ["", "A", "1a", "-a", "a b", "a/b", "é", "a".repeat(65)]) {
			expect(IWEB_LOG_FIELD_KEY_PATTERN.test(key)).toBe(false);
			expect(validateIwebLoggingEvent({ level: "info", message: "m", fields: [{ key, value: "v" }] }).ok).toBe(false);
		}
		expect(IWEB_LOG_FIELD_KEY_PATTERN.test("a".repeat(64))).toBe(true);
		expect(validateIwebLoggingEvent({ level: "info", message: "\uD800", fields: [] }).ok).toBe(false);
		expect(validateIwebLoggingEvent({ level: "info", message: "ok", fields: [{ key: "a", value: "\uDC00x" }] }).ok).toBe(false);
	});

	test("a disabled level is not accepted and classifies as invalid-event", () => {
		const result = validateIwebLoggingEvent({ level: "info", message: "m", fields: [] }, { enabledLevels: ["error"] });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.errors.some((entry) => entry.code === "LEVEL_DISABLED")).toBe(true);
		}
		const write = writeIwebLoggingEvent(makeRing(), HOST_CONTEXT, { level: "info", message: "m", fields: [] }, { enabledLevels: ["error"] });
		expect(write.ok).toBe(false);
		if (!write.ok) expect(write.code).toBe("IWEB_LOG_INVALID_EVENT");
	});

	test("host context requires UTC Z timestamps and wasm identity grammar", () => {
		expect(validateIwebLoggingHostContext(HOST_CONTEXT).ok).toBe(true);
		for (const bad of [
			{ ...HOST_CONTEXT, timestampUtc: "2026-08-27T12:34:56+02:00" },
			{ ...HOST_CONTEXT, timestampUtc: "2026-08-27 12:34:56Z" },
			{ ...HOST_CONTEXT, applicationId: "Notes_App" },
			{ ...HOST_CONTEXT, versionId: "not-a-version" },
			{ ...HOST_CONTEXT, preparationGeneration: -1 },
			{ ...HOST_CONTEXT, executionGeneration: 1.5 },
			{ ...HOST_CONTEXT, extra: true },
		]) {
			expect(validateIwebLoggingHostContext(bad).ok).toBe(false);
		}
	});
});

describe("iweb logging redaction boundary", () => {
	test("reserved keys are exactly the design list and only their values become [REDACTED]", () => {
		expect([...IWEB_LOG_RESERVED_FIELD_KEYS]).toEqual([
			"authorization",
			"cookie",
			"set-cookie",
			"x-api-key",
			"api-key",
			"token",
			"secret",
			"password",
			"credential",
			"request-body",
			"sql",
			"kv",
			"config",
			"owner-key",
		]);
		for (const key of IWEB_LOG_RESERVED_FIELD_KEYS) expect(isReservedIwebLoggingFieldKey(key)).toBe(true);
		expect(isReservedIwebLoggingFieldKey("note")).toBe(false);

		const original = "hunter2-value";
		const redacted = redactIwebLoggingFields([
			{ key: "token", value: original },
			{ key: "note", value: original },
		]);
		expect(redacted[0]).toEqual({ key: "token", value: IWEB_LOG_REDACTED_VALUE });
		expect(redacted[0]?.value).not.toBe(original);
		expect(redacted[1]).toEqual({ key: "note", value: original });
	});

	test("redaction happens before size accounting: an oversized reserved value still fits a small ring", () => {
		// 环只有 200 字节；token 原值 1000 字节放不下，redacted 后只占 [REDACTED] 的字节数。
		const ring = makeRing("notes-app", { maxEvents: 10, maxBytes: 200 });
		const result = writeIwebLoggingEvent(ring, HOST_CONTEXT, {
			level: "warn",
			message: "m",
			fields: [{ key: "token", value: "a".repeat(1000) }],
		});
		expect(result.ok).toBe(true);
		if (result.ok && result.outcome === "accepted") {
			expect(result.record.fields[0]?.value).toBe(IWEB_LOG_REDACTED_VALUE);
			expect(result.ring.retainedBytes).toBeLessThanOrEqual(200);
			expect(result.ring.droppedCount).toBe(0);
		}
		// 同一事件若按原值计量必然超环：直接用 measure 断言 redaction 先行。
		const redactedBytes = measureIwebLoggingEventBytes({ level: "warn", message: "m", fields: [{ key: "token", value: "a".repeat(1000) }] }, HOST_CONTEXT, 1);
		expect(redactedBytes).toBeLessThan(200);
	});

	test("an event whose redacted size still exceeds maxEventBytes fails with limit-exceeded, not dropped", () => {
		const ring = makeRing();
		const result = writeIwebLoggingEvent(
			ring,
			HOST_CONTEXT,
			{ level: "info", message: "m", fields: Array.from({ length: 10 }, (_, index) => ({ key: "f" + index, value: "a".repeat(1024) })) },
			{ maxEventBytes: IWEB_LOG_EVENT_MAX_BYTES_DEFAULT },
		);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("IWEB_LOG_LIMIT_EXCEEDED");
	});
});

describe("iweb logging bounded ring", () => {
	function event(message: string, value = "v") {
		return { level: "info" as const, message, fields: [{ key: "k", value }] };
	}

	test("event capacity reached: further writes return dropped, increment the counter and unblock", () => {
		const ring = makeRing("notes-app", { maxEvents: 2, maxBytes: 4096 });
		const first = writeIwebLoggingEvent(ring, HOST_CONTEXT, event("one"));
		const second = writeIwebLoggingEvent(first.ok ? first.ring : ring, HOST_CONTEXT, event("two"));
		expect(first.ok && first.outcome).toBe("accepted");
		expect(second.ok && second.outcome).toBe("accepted");
		const full = second.ok ? writeIwebLoggingEvent(second.ring, HOST_CONTEXT, event("three")) : null;
		expect(full?.ok && full.outcome).toBe("dropped");
		if (full?.ok && full.outcome === "dropped") {
			expect(full.ring.droppedCount).toBe(1);
			expect(full.ring.events.length).toBe(2);
			expect(full.ring.events.map((record) => record.message)).toEqual(["one", "two"]);
		}
		const again = full?.ok ? writeIwebLoggingEvent(full.ring, HOST_CONTEXT, event("four")) : null;
		expect(again?.ok && again.outcome).toBe("dropped");
		if (again?.ok && again.outcome === "dropped") expect(again.ring.droppedCount).toBe(2);
	});

	test("byte capacity reached drops without evicting retained events of this or another application", () => {
		const own = makeRing("notes-app", { maxEvents: 10, maxBytes: 300 });
		const other = makeRing("search-app", { maxEvents: 10, maxBytes: 300 });
		const first = writeIwebLoggingEvent(own, HOST_CONTEXT, event("one", "a".repeat(100)));
		expect(first.ok && first.outcome).toBe("accepted");
		const before = first.ok ? first.ring : own;
		const overflow = writeIwebLoggingEvent(before, HOST_CONTEXT, event("two", "a".repeat(1000)));
		expect(overflow.ok && overflow.outcome).toBe("dropped");
		if (overflow.ok && overflow.outcome === "dropped") {
			expect(overflow.ring.events.map((record) => record.message)).toEqual(["one"]);
			expect(overflow.ring.retainedBytes).toBe(before.retainedBytes);
		}
		// 他应用的事件不被触碰：自己的环溢出不影响邻居环。
		const neighbor = writeIwebLoggingEvent(other, { ...HOST_CONTEXT, applicationId: "search-app" }, event("neighbor"));
		expect(neighbor.ok && neighbor.outcome).toBe("accepted");
		expect(overflow.ok ? overflow.ring.events.length : 0).toBe(1);
	});

	test("event ids are contiguous and monotonic; dropped writes do not consume ids; write is immutable", () => {
		const ring = makeRing("notes-app", { maxEvents: 2, maxBytes: 4096 });
		let state = ring;
		for (const message of ["one", "two"]) {
			const result = writeIwebLoggingEvent(state, HOST_CONTEXT, event(message));
			expect(result.ok && result.outcome).toBe("accepted");
			if (result.ok && result.outcome === "accepted") state = result.ring;
		}
		expect(state.events.map((record) => record.eventId)).toEqual([1, 2]);
		expect(state.nextEventId).toBe(3);
		const dropped = writeIwebLoggingEvent(state, HOST_CONTEXT, event("three"));
		expect(dropped.ok && dropped.outcome).toBe("dropped");
		if (dropped.ok) {
			expect(dropped.ring.nextEventId).toBe(3);
			// 纯函数：输入 ring 不被修改。
			expect(state.events.length).toBe(2);
			expect(state.droppedCount).toBe(0);
		}
	});

	test("reset starts a new lifecycle with no durability claim", () => {
		const ring = makeRing("notes-app", { maxEvents: 2, maxBytes: 4096 });
		const first = writeIwebLoggingEvent(ring, HOST_CONTEXT, event("one"));
		const second = first.ok ? writeIwebLoggingEvent(first.ring, HOST_CONTEXT, event("two")) : null;
		const overflow = second?.ok ? writeIwebLoggingEvent(second.ring, HOST_CONTEXT, event("three")) : null;
		const before = overflow?.ok ? overflow.ring : ring;
		expect(before.events.length).toBe(2);
		expect(before.droppedCount).toBe(1);
		const after = resetIwebLoggingRing(before);
		expect(after.events).toEqual([]);
		expect(after.droppedCount).toBe(0);
		expect(after.retainedBytes).toBe(0);
		expect(after.nextEventId).toBe(1);
		expect(after.applicationId).toBe("notes-app");
		expect(after.capacity).toEqual({ maxEvents: 2, maxBytes: 4096 });
	});

	test("a host context that does not own the ring is an isolation violation", () => {
		const ring = makeRing("notes-app");
		const result = writeIwebLoggingEvent(ring, { ...HOST_CONTEXT, applicationId: "search-app" }, event("m"));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("IWEB_LOG_APP_ISOLATION");
	});

	test("invalid host context is an internal fault, never a component error", () => {
		const result = writeIwebLoggingEvent(makeRing(), { ...HOST_CONTEXT, timestampUtc: "not-a-timestamp" }, event("m"));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("IWEB_LOG_INTERNAL");
	});
});

describe("iweb logging drain and monitor projection", () => {
	function filledRing() {
		let state = makeRing();
		for (const message of ["one", "two", "three", "four", "five"]) {
			const result = writeIwebLoggingEvent(state, HOST_CONTEXT, { level: "info", message, fields: [] });
			if (result.ok && result.outcome === "accepted") state = result.ring;
			else throw new Error("fixture write failed");
		}
		return state;
	}

	test("drain returns a bounded cursor window for the owning application only", () => {
		const ring = filledRing();
		const page = drainIwebLoggingRing(ring, { schemaVersion: 1, applicationId: "notes-app", afterEventId: 2, maxEvents: 2 });
		expect(page.ok).toBe(true);
		if (page.ok) {
			expect(page.response.events.map((record) => record.eventId)).toEqual([3, 4]);
			expect(page.response.hasMore).toBe(true);
			expect(page.response.lastEventId).toBe(5);
			expect(page.response.droppedCount).toBe(0);
		}
		const all = drainIwebLoggingRing(ring, { schemaVersion: 1, applicationId: "notes-app", afterEventId: 0, maxEvents: 1000 });
		expect(all.ok).toBe(true);
		if (all.ok) {
			expect(all.response.events.length).toBe(5);
			expect(all.response.hasMore).toBe(false);
		}
	});

	test("drain request shapes are fail-closed and cross-application drains are rejected", () => {
		const ring = filledRing();
		for (const bad of [
			{ schemaVersion: 2, applicationId: "notes-app", afterEventId: 0, maxEvents: 10 },
			{ schemaVersion: 1, applicationId: "Notes_App", afterEventId: 0, maxEvents: 10 },
			{ schemaVersion: 1, applicationId: "notes-app", afterEventId: -1, maxEvents: 10 },
			{ schemaVersion: 1, applicationId: "notes-app", afterEventId: 0, maxEvents: 0 },
			{ schemaVersion: 1, applicationId: "notes-app", afterEventId: 0, maxEvents: 1001 },
			{ schemaVersion: 1, applicationId: "notes-app", afterEventId: 0, maxEvents: 10, extra: true },
			null,
		]) {
			expect(drainIwebLoggingRing(ring, bad).ok).toBe(false);
		}
		const cross = drainIwebLoggingRing(ring, { schemaVersion: 1, applicationId: "search-app", afterEventId: 0, maxEvents: 10 });
		expect(cross.ok).toBe(false);
		if (!cross.ok) expect(cross.code).toBe("IWEB_LOG_APP_ISOLATION");
	});

	test("retained records carry exactly the diagnostic field set; monitor summary carries no bodies", () => {
		const ring = filledRing();
		const drain = drainIwebLoggingRing(ring, { schemaVersion: 1, applicationId: "notes-app", afterEventId: 4, maxEvents: 10 });
		expect(drain.ok).toBe(true);
		if (drain.ok) {
			const record = drain.response.events[0];
			expect(record).toBeDefined();
			expect(Object.keys(record ?? {}).sort()).toEqual([...IWEB_LOG_RETAINED_RECORD_FIELDS].sort());
		}
		const summary = projectIwebLoggingMonitorSummary(ring);
		expect(Object.keys(summary).sort()).toEqual(["applicationId", "capacity", "droppedCount", "lastEventId", "retainedBytes", "retainedEvents"].sort());
		expect(summary.retainedEvents).toBe(5);
		expect(summary.lastEventId).toBe(5);
	});
});

describe("iweb logging forwarding config wire (owner authorized, default off)", () => {
	test("absent config and explicit disabled are the same default-off shape", () => {
		for (const input of [null, undefined, { schemaVersion: 1, enabled: false, format: null, endpoint: null }, { schemaVersion: 1, enabled: false }]) {
			const result = validateIwebLoggingForwardingConfig(input);
			expect(result.ok).toBe(true);
			if (result.ok) expect(result.value).toEqual(IWEB_LOG_FORWARDING_DEFAULT);
		}
		expect(IWEB_LOG_FORWARDING_DEFAULT.enabled).toBe(false);
	});

	test("enabled configs require a pinned format and a valid host:port endpoint", () => {
		expect(validateIwebLoggingForwardingConfig({ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "collector.internal:9000" }).ok).toBe(true);
		expect(validateIwebLoggingForwardingConfig({ schemaVersion: 1, enabled: true, format: "syslog", endpoint: "127.0.0.1:514" }).ok).toBe(true);
		expect(validateIwebLoggingForwardingConfig({ schemaVersion: 1, enabled: true, format: "syslog", endpoint: "collector.internal:65535" }).ok).toBe(true);
	});

	test("invalid formats, endpoints and shapes are rejected fail-closed", () => {
		for (const input of [
			{ schemaVersion: 1, enabled: true, format: "xml", endpoint: "collector.internal:9000" },
			{ schemaVersion: 1, enabled: true, endpoint: "collector.internal:9000" },
			{ schemaVersion: 1, enabled: true, format: "json-lines" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "http://collector.internal:9000" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "collector.internal:9000/path" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "user@collector.internal:9000" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "collector.internal:0" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "collector.internal:65536" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "collector.internal:99999" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "999.0.0.1:514" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "Collector.Internal:514" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "localhost:514" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: ":514" },
			{ schemaVersion: 1, enabled: true, format: "json-lines", endpoint: "collector.internal" },
			{ schemaVersion: 1, enabled: false, format: "json-lines", endpoint: "collector.internal:9000" },
			{ schemaVersion: 2, enabled: false },
			{ schemaVersion: 1, enabled: "on" },
			{ schemaVersion: 1, enabled: false, unknown: true },
			"off",
		]) {
			const result = validateIwebLoggingForwardingConfig(input);
			expect(result.ok).toBe(false);
		}
	});

	test("endpoint grammar rejects IPv6 brackets and userinfo outright", () => {
		expect(isValidIwebLoggingForwardingEndpoint("[::1]:514")).toBe(false);
		expect(isValidIwebLoggingForwardingEndpoint("collector.internal:0514")).toBe(true);
		expect(isValidIwebLoggingForwardingEndpoint("10.0.0.1:65_14")).toBe(false);
		expect([...IWEB_LOG_FORWARDING_FORMATS]).toEqual(["json-lines", "syslog"]);
	});
});

describe("iweb logging isolation from Kernel audit and stdio", () => {
	test("audit, stdio, unbounded files and implicit RustFS are forbidden sinks", () => {
		for (const sink of ["kernel-audit", "stdout", "stderr", "unbounded-file", "implicit-rustfs"]) {
			expect(iwebLoggingSinkErrorCode(sink)).toBe("IWEB_LOG_SINK_FORBIDDEN");
		}
		for (const sink of IWEB_LOG_ALLOWED_SINKS) expect(iwebLoggingSinkErrorCode(sink)).toBe(null);
		// 未知 sink 名不进入 allowed 闭集即可，但已知禁用名必须恒定拒绝。
		expect(iwebLoggingSinkErrorCode("kernel-audit")).toBe("IWEB_LOG_SINK_FORBIDDEN");
	});

	test("backend failure codes are exactly unavailable/internal; no stdio/audit fallback exists in the wire", () => {
		expect([...IWEB_LOG_FORWARDING_FAILURE_WIRE_CODES]).toEqual(["IWEB_LOG_UNAVAILABLE", "IWEB_LOG_INTERNAL"]);
		const codes = Object.values(IWEB_LOG_WIRE_ERROR_BY_CASE).concat([...IWEB_LOG_TRANSPORT_ERROR_CODES]);
		for (const forbidden of ["IWEB_LOG_STDOUT_FALLBACK", "IWEB_LOG_AUDIT_FALLBACK", "IWEB_LOG_FILE_FALLBACK"]) {
			expect(codes.includes(forbidden)).toBe(false);
		}
	});

	test("an accepted error event stays a diagnostic record: no audit-alias fields, redacted sensitive values", () => {
		const ring = makeRing();
		const result = writeIwebLoggingEvent(ring, HOST_CONTEXT, {
			level: "error",
			message: "boom",
			fields: [
				{ key: "sql", value: "SELECT * FROM secrets" },
				{ key: "request-id", value: "req-1" },
			],
		});
		expect(result.ok && result.outcome).toBe("accepted");
		if (result.ok && result.outcome === "accepted") {
			expect(Object.keys(result.record).sort()).toEqual([...IWEB_LOG_RETAINED_RECORD_FIELDS].sort());
			expect(result.record.fields.find((field) => field.key === "sql")?.value).toBe(IWEB_LOG_REDACTED_VALUE);
			expect(result.record.fields.find((field) => field.key === "request-id")?.value).toBe("req-1");
			// owner 诊断可定位执行身份；Kernel audit 与公开流量拿不到事件正文（无 audit 别名字段可承载）。
			expect(result.record.applicationId).toBe("notes-app");
			expect(result.record.preparationGeneration).toBe(3);
			expect(result.record.executionGeneration).toBe(2);
		}
	});
});
