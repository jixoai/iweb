// 用户原始需求（2026-08-14）：安装器不得覆盖或重叠宿主已有 subordinate ID 范围。
// 正交意图：验证解析；复用既有范围；跳过冲突；拒绝耗尽。
import { describe, expect, test } from "bun:test";
import { findAvailableSubordinateIdStart, parseSubordinateIdRanges } from "../supervisor/subordinate-ids.ts";

describe("subordinate ID allocation", () => {
	test("parses valid system ranges and ignores malformed records", () => {
		expect(parseSubordinateIdRanges("alice:100000:65536\nbroken\nbob:165536:65536:extra\nroot:-1:2\n")).toEqual([
			{ owner: "alice", start: 100000, count: 65536 }
		]);
	});

	test("uses the first gap after overlapping ranges", () => {
		const ranges = parseSubordinateIdRanges("alice:100000:65536\nbob:165536:65536\n");
		expect(findAvailableSubordinateIdStart(ranges, 65536)).toBe(231072);
	});

	test("keeps an available minimum when later ranges do not overlap", () => {
		const ranges = parseSubordinateIdRanges("alice:500000:65536\n");
		expect(findAvailableSubordinateIdStart(ranges, 65536)).toBe(100000);
	});

	test("rejects allocation when no complete range remains", () => {
		const ranges = parseSubordinateIdRanges("alice:100000:100000\n");
		expect(() => findAvailableSubordinateIdStart(ranges, 65536, 100000, 200000)).toThrow("no subordinate ID range");
	});
});
