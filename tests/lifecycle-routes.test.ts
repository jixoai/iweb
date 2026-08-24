// 用户原始需求（2026-08-14）：activate/rollback 端点必须返回已提交的 generation，而不是序列化的 Promise；drain 只在提交后运行。
// 正交意图：7.3/7.4/9.2 端点集成证据——真实 dispatcher + 串行化语义控制（延迟提交证明 await 顺序）。
import { describe, expect, test } from "bun:test";
import { handleVersionAction, type LifecycleControl } from "../contracts/lifecycle-routes.ts";

function makeControl(overrides: Partial<LifecycleControl> = {}): LifecycleControl & { calls: string[]; commitDelayMs: number } {
	const calls: string[] = [];
	const control = {
		calls,
		commitDelayMs: 20,
		inspectVersion: async () => ({ state: "ready" }),
		prepare: async () => ({ sandboxId: "sbx-x" }),
		probeReady: async () => ({ ready: true }),
		activate: async (_a: string, _v: string) => {
			// model the single-writer queue: the commit takes time
			await new Promise((r) => setTimeout(r, control.commitDelayMs));
			calls.push("activate-committed");
			return { generation: 7, retired: "sbx-old" };
		},
		rollback: async () => {
			await new Promise((r) => setTimeout(r, control.commitDelayMs));
			calls.push("rollback-committed");
			return { generation: 8, retired: "sbx-new" };
		},
		startVersion: async () => ({ sandboxId: "sbx-x" }),
		stopVersion: async () => ({ sandboxId: "sbx-x" }),
		drainRetired: async () => { calls.push("drain"); return ["sbx-old"]; },
		...overrides,
	};
	return control as never;
}

describe("lifecycle endpoint dispatcher (7.3/7.4/9.2)", () => {
	test("activate returns the COMMITTED generation, never a Promise", async () => {
		const control = makeControl();
		const outcome = await handleVersionAction(control, "notes", "a".repeat(64), "POST", "activate");
		expect(outcome.status).toBe(200);
		// the body is the resolved object: a serialized Promise would be {}
		expect(outcome.body).toEqual({ generation: 7, retired: "sbx-old" });
		expect((outcome.body as { generation: number }).generation).toBe(7);
		expect(outcome.drainAfterCommit).toBe(true);
	});

	test("rollback returns the committed result and flags drain-after-commit", async () => {
		const control = makeControl();
		const outcome = await handleVersionAction(control, "notes", "a".repeat(64), "POST", "rollback");
		expect(outcome.body).toEqual({ generation: 8, retired: "sbx-new" });
		expect(outcome.drainAfterCommit).toBe(true);
	});

	test("drain is NOT part of the dispatcher: callers drain only after the commit resolves", async () => {
		const control = makeControl();
		const pending = handleVersionAction(control, "notes", "a".repeat(64), "POST", "activate");
		// while the activation commit is still in flight, no drain may have run
		expect(control.calls).not.toContain("drain");
		expect(control.calls).not.toContain("activate-committed");
		const outcome = await pending;
		expect(control.calls).toContain("activate-committed");
		// the dispatcher never calls drain itself; the transport layer does afterwards
		expect(control.calls).not.toContain("drain");
		expect(outcome.drainAfterCommit).toBe(true);
	});

	test("every action maps to its status and awaits its payload", async () => {
		const control = makeControl();
		expect((await handleVersionAction(control, "n", "a".repeat(64), "GET", null)).status).toBe(200);
		expect((await handleVersionAction(control, "n", "a".repeat(64), "POST", "prepare")).status).toBe(201);
		expect((await handleVersionAction(control, "n", "a".repeat(64), "POST", "readiness")).status).toBe(200);
		expect((await handleVersionAction(control, "n", "a".repeat(64), "POST", "start")).status).toBe(200);
		expect((await handleVersionAction(control, "n", "a".repeat(64), "POST", "stop")).status).toBe(200);
		expect((await handleVersionAction(control, "n", "a".repeat(64), "DELETE", "activate")).status).toBe(405);
	});

	test("a commit failure propagates as a rejection, not a silent {}", async () => {
		const control = makeControl({ activate: async () => { throw Object.assign(new Error("no readiness lease"), { code: "ACTIVATION_REJECTED" }); } });
		let caught: unknown = null;
		try { await handleVersionAction(control, "notes", "a".repeat(64), "POST", "activate"); } catch (error) { caught = error; }
		expect((caught as { code?: string }).code).toBe("ACTIVATION_REJECTED");
	});
});
