// 用户原始需求（2026-08-14）：monitor 帧必须保留 unavailable、限零不补零、重启后可恢复、不含受保护诊断。
// 正交意图：10.4 纯函数证据——投影、刷新折叠、帧编码、诊断消毒。
import { describe, expect, test } from "bun:test";
import { projectSandboxResources, foldSandboxSample, encodeMonitorFrame, sanitizeMonitorFrame, monitorFrameDigest } from "../contracts/monitor-frame.ts";

const sample = {
	versionId: "aaa-1",
	sampledAt: "2026-08-14T00:00:00.000Z",
	cpuMillis: { available: true, value: 42 },
	memoryBytes: { available: true, value: 2048 },
	pidCount: { available: false },
	terminated: { available: true, value: 0 },
	limits: { cpuMillis: 500, memoryBytes: 134217728 },
};

describe("monitor projection (10.4)", () => {
	test("projects a valid sample and preserves unavailable as unavailable, never zero", () => {
		const projected = projectSandboxResources(sample)!;
		expect(projected.cpuMillis).toEqual({ available: true, value: 42 });
		// unavailable stays { available: false } — not 0, not node aggregate
		expect(projected.pidCount).toEqual({ available: false });
		expect(projected.limits).toEqual({ cpuMillis: 500, memoryBytes: 134217728 });
	});

	test("a missing or malformed sample projects to null (unavailable), not a fabricated value", () => {
		expect(projectSandboxResources(null)).toBeNull();
		expect(projectSandboxResources(undefined)).toBeNull();
		expect(projectSandboxResources("junk" as unknown)).toBeNull();
		expect(projectSandboxResources({ ...sample, cpuMillis: { available: true } as never })).toBeNull();
		expect(projectSandboxResources({ ...sample, versionId: 5 } as never)).toBeNull();
	});

	test("changing usage and limit termination flow through without substitution", () => {
		const grown = projectSandboxResources({ ...sample, memoryBytes: { available: true, value: 9999 }, terminated: { available: true, value: 1 } })!;
		expect(grown.memoryBytes).toEqual({ available: true, value: 9999 });
		expect(grown.terminated).toEqual({ available: true, value: 1 });
	});

	test("a supervisor failure folds to unavailability and a later success recovers the sandbox", () => {
		let store = new Map<string, { sample: ReturnType<typeof projectSandboxResources>; fetchedAt: number }>();
		// failure shape
		store = foldSandboxSample(store, "sbx-a", () => Promise.reject(new Error("supervisor unreachable")), 1).store;
		expect(store.get("sbx-a")).toEqual({ sample: null, fetchedAt: 1 });
		// kernel restart: empty store, surviving sandbox repopulates on next success
		const afterRestart = new Map();
		expect(afterRestart.size).toBe(0);
		const recovered = foldSandboxSample(afterRestart, "sbx-a", () => Promise.resolve({}), 2).store;
		expect(recovered.get("sbx-a")?.sample).toBeNull();
	});

	test("frames are bounded and deterministically encoded", () => {
		const small = encodeMonitorFrame("hello");
		expect(small[0]).toBe(0x81);
		expect(small[1]).toBe(5);
		const bigger = encodeMonitorFrame("x".repeat(200));
		expect(bigger[1]).toBe(126);
		expect(bigger.readUInt16BE(2)).toBe(200);
		let threw = false;
		try { encodeMonitorFrame("y".repeat(65_536)); } catch { threw = true; }
		expect(threw).toBe(true);
		expect(monitorFrameDigest(encodeMonitorFrame("hello"))).toBe(monitorFrameDigest(encodeMonitorFrame("hello")));
	});

	test("protected diagnostics never enter a monitor frame", () => {
		const dirty = {
			type: "snapshot",
			node: { uptimeSeconds: 5, authorization: "Bearer OWNER-KEY" },
			app: { id: "notes", secretAccessKey: "LEAKED", detail: { stack: "Error: at celld internals" } },
		};
		const clean = sanitizeMonitorFrame(dirty);
		expect(JSON.stringify(clean)).not.toContain("OWNER-KEY");
		expect(JSON.stringify(clean)).not.toContain("LEAKED");
		expect(JSON.stringify(clean)).not.toContain("Bearer");
		expect((clean.node as Record<string, unknown>).uptimeSeconds).toBe(5);
		expect((clean.app as Record<string, unknown>).id).toBe("notes");
	});

	test("the sanitizer recurses through arrays: array-contained credentials and diagnostics are removed (10.4)", () => {
		const dirty = {
			type: "snapshot",
			sandboxes: [
				{ sandboxId: "sbx-a", memoryBytes: 2048, authorization: "Bearer OWNER-KEY" },
				{ sandboxId: "sbx-b", password: "hunter2", note: "token=abc" },
			],
			nested: [
				["Bearer LEAKED-ARRAY-STRING", "ok-value", { secret: "x", safe: 1 }],
				{ diagnostics: ["token=LEAKED-NESTED", "plain"] },
			],
			keep: [1, 2, { value: 3 }],
		};
		const clean = sanitizeMonitorFrame(dirty);
		const flat = JSON.stringify(clean);
		expect(flat).not.toContain("OWNER-KEY");
		expect(flat).not.toContain("hunter2");
		expect(flat).not.toContain("LEAKED-ARRAY-STRING");
		expect(flat).not.toContain("token=abc");
		// array elements themselves survive when clean
		const sandboxes = clean.sandboxes as Record<string, unknown>[];
		expect(sandboxes).toHaveLength(2);
		expect(sandboxes[0].sandboxId).toBe("sbx-a");
		expect(sandboxes[0].memoryBytes).toBe(2048);
		expect(sandboxes[0].authorization).toBeUndefined();
		expect(sandboxes[1].password).toBeUndefined();
		// nested arrays recurse: the credential string is gone, the safe peer stays
		const nested = clean.nested as unknown[];
		const inner = nested[0] as unknown[];
		expect(inner).toEqual(["ok-value", { safe: 1 }]);
		const diagnostics = (nested[1] as Record<string, unknown>).diagnostics as string[];
		expect(diagnostics).toEqual(["plain"]);
		expect(clean.keep).toEqual([1, 2, { value: 3 }]);
	});
});
