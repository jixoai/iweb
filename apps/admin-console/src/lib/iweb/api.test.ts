// 用户原始需求（2026-08-12）：Admin 对外域名应从当前 admin 域名安全推导 API 域名。
// 正交意图：验证 admin 与 admin.app 两种入口；固定路由公开链接；避免为客户端注入部署期 token。
import { describe, expect, it } from "vitest";
import { apiOriginFromAdminOrigin, publicOrigin } from "$lib/iweb/api";

describe("apiOriginFromAdminOrigin", () => {
	it("maps the normal admin host to the reserved API host", () => {
		expect(apiOriginFromAdminOrigin(new URL("https://admin.family.iweb.xin"))).toBe(
			"https://api.family.iweb.xin"
		);
	});

	it("maps the replaceable admin application host to the reserved API host", () => {
		expect(apiOriginFromAdminOrigin(new URL("https://admin.app.test.iweb.localhost:19010"))).toBe(
			"https://api.test.iweb.localhost:19010"
		);
	});

	it("forms app hosts from the route registry without losing an explicit port", () => {
		expect(publicOrigin("test.iweb.localhost", "notes.app", "https:", "19010")).toBe(
			"https://notes.app.test.iweb.localhost:19010"
		);
	});
});

// --- KernelApiClient application projections（two-tier-runtime-trust：celld 版本
// 生命周期方法（admit/prepare/readiness/activate/rollback/start/stop/delete）已随
// 运行时准入永久删除；应用投影只剩只读列表与 /v1/status 派生两条路径） ---
import { KernelApiClient } from "$lib/iweb/api";

function mockFetch(handler: (url: string, init?: RequestInit) => { status: number; body: unknown }) {
	const original = globalThis.fetch;
	const calls: { url: string; method: string; body?: string }[] = [];
	globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
		calls.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : undefined });
		const { status, body } = handler(url, init);
		return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
	}) as typeof fetch;
	return {
		calls,
		restore: () => {
			globalThis.fetch = original;
		}
	};
}

describe("KernelApiClient application projections", () => {
	it("returns route-derived celld fleet projections and the watchdog from node status", async () => {
		// regression: the REAL /v1/status payload carries the status-only keys
		// (baseHost/runtime/routes/memory/sandboxSupervisor/watchdog); parsing it
		// with applicationsResponseSchema produced unrecognized_keys and broke the
		// admin console against a real node.
		const mock = mockFetch(() => ({
			status: 200,
			body: {
				baseHost: "test.iweb.localhost",
				runtime: "celld",
				routes: 6,
				memory: { usageBytes: 1000, limitBytes: null, usagePercent: null, kernelHeapUsedBytes: 500 },
				sandboxSupervisor: { configured: true, available: true, version: 1 },
				// regression: the live projection is GateSelectionResponseV1 (exact four
				// keys, no requested/accepted); drift here broke admin login sync.
				wasmPublication: { schemaVersion: 1, runtimeKind: "wasm", enabled: false, reasons: ["publication-not-requested", "sandbox-acceptance-missing"] },
				// two-tier-runtime-trust：celld fleet 投影（路由派生，无沙箱身份/版本）
				// + 看门狗投影（软限策略与最近越限事件环）。
				watchdog: {
					intervalMs: 15000,
					defaultBytes: 536870912,
					apps: { notes: 268435456 },
					events: [{ applicationId: "notes", sampledBytes: 314572800, limitBytes: 268435456, terminatedAt: "2026-08-29T08:00:00.000Z" }]
				},
				applications: [{ id: "notes", runtimeKind: "celld", sandboxId: null, activeVersion: null, routeGeneration: 3, lifecycle: "unavailable", versions: [], resources: { unavailable: true } }]
			}
		}));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const response = await client.statusApplications();
			expect(response.applications[0]?.runtimeKind).toBe("celld");
			expect(response.applications[0]?.lifecycle).toBe("unavailable");
			expect(response.applications[0]?.resources).toBeNull();
			expect(mock.calls[0]?.url).toBe("https://api.example.test/v1/status");
			const status = await client.status();
			expect(status.watchdog?.defaultBytes).toBe(536870912);
			expect(status.watchdog?.apps["notes"]).toBe(268435456);
			expect(status.watchdog?.events[0]?.sampledBytes).toBe(314572800);
		} finally {
			mock.restore();
		}
	});

	it("accepts a status frame without the optional watchdog projection (old kernel)", async () => {
		const mock = mockFetch(() => ({
			status: 200,
			body: {
				baseHost: "test.iweb.localhost",
				runtime: "celld",
				routes: 1,
				memory: { usageBytes: 1, limitBytes: 2, usagePercent: 50, kernelHeapUsedBytes: 3 },
				sandboxSupervisor: { configured: false, available: false, version: null },
				applications: []
			}
		}));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const status = await client.status();
			expect(status.watchdog).toBeUndefined();
			expect(status.applications).toEqual([]);
		} finally {
			mock.restore();
		}
	});

	it("propagates the bounded kernel error on failure", async () => {
		const mock = mockFetch(() => ({
			status: 503,
			body: { error: "kernel control plane temporarily unavailable", code: "KERNEL_UNAVAILABLE" }
		}));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			await expect(client.statusApplications()).rejects.toThrow("kernel control plane temporarily unavailable");
		} finally {
			mock.restore();
		}
	});

	it("credential absence: no owner token means no request leaves the client", async () => {
		const mock = mockFetch(() => ({ status: 200, body: {} }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "  ");
			await expect(client.statusApplications()).rejects.toMatchObject({ name: "KernelApiError", status: 401 });
			expect(mock.calls).toHaveLength(0);
		} finally {
			mock.restore();
		}
	});

	it("stale monitor data recovers: a later status fetch observes the new lifecycle", async () => {
		let lifecycle = "unavailable";
		const statusBody = () => ({
			baseHost: "example.test",
			runtime: "celld",
			routes: 1,
			memory: { usageBytes: 1, limitBytes: 2, usagePercent: 50, kernelHeapUsedBytes: 3 },
			sandboxSupervisor: { configured: true, available: true, version: 1 },
			watchdog: { intervalMs: 15000, defaultBytes: 536870912, apps: {}, events: [] },
			// fleet 投影：路由派生、runtimeKind 恒 celld、无沙箱身份、无版本。
			applications: [
				{ id: "notes", runtimeKind: "celld", sandboxId: null, activeVersion: null, routeGeneration: 1, lifecycle, versions: [], resources: null }
			]
		});
		const mock = mockFetch((url) => (url.endsWith("/v1/status") ? { status: 200, body: statusBody() } : { status: 200, body: {} }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const first = await client.statusApplications();
			expect(first.applications[0]?.lifecycle).toBe("unavailable");
			lifecycle = "active";
			const second = await client.statusApplications();
			expect(second.applications[0]?.lifecycle).toBe("active");
		} finally {
			mock.restore();
		}
	});
});
