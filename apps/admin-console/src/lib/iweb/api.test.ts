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

// --- KernelApiClient application lifecycle methods（任务 9.3-9.5） ---
import { KernelApiClient } from "$lib/iweb/api";

const hex64 = "a".repeat(64);

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

describe("KernelApiClient application lifecycle methods", () => {
	it("lists applications from /v1/applications", async () => {
		const mock = mockFetch(() => ({ status: 200, body: { applications: [] } }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const response = await client.listApplications();
			expect(response.applications).toEqual([]);
			expect(mock.calls[0]?.url).toBe("https://api.example.test/v1/applications");
			expect(mock.calls[0]?.method).toBe("GET");
		} finally {
			mock.restore();
		}
	});

	it("admits a version with an empty body (manifest is the policy authority)", async () => {
		const mock = mockFetch(() => ({
			status: 201,
			body: { versionId: hex64, identity: { applicationId: "notes", digest: hex64, sequence: 1 } }
		}));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const result = await client.admitApplication("notes");
			expect(result.versionId).toBe(hex64);
			expect(mock.calls[0]?.method).toBe("POST");
			expect(mock.calls[0]?.url).toBe("https://api.example.test/v1/applications/notes/versions");
			expect(JSON.parse(mock.calls[0]?.body ?? "{}")).toEqual({});
		} finally {
			mock.restore();
		}
	});

	it("admission never sends a policy override", async () => {
		const mock = mockFetch(() => ({ status: 201, body: { versionId: hex64, identity: {} } }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			await client.admitApplication("notes");
			expect(JSON.parse(mock.calls[0]?.body ?? "{}")).toEqual({});
		} finally {
			mock.restore();
		}
	});

	it("activates a version at the activate endpoint", async () => {
		const mock = mockFetch(() => ({ status: 200, body: { generation: 2, retired: null } }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const result = await client.activateVersion("notes", hex64);
			expect(result.generation).toBe(2);
			expect(mock.calls[0]?.method).toBe("POST");
			expect(mock.calls[0]?.url).toBe("https://api.example.test/v1/applications/notes/versions/" + hex64 + "/activate");
		} finally {
			mock.restore();
		}
	});

	it("parses readiness, rollback, start, stop and delete responses", async () => {
		const mock = mockFetch((url) => {
			if (url.endsWith("/readiness")) return { status: 200, body: { ready: true, attempts: 3, lastStatus: 200, mismatch: false, timedOut: false } };
			if (url.endsWith("/rollback")) return { status: 200, body: { generation: 1, retired: "sbx-notes-1" } };
			if (url.endsWith("/stop")) return { status: 200, body: { sandboxId: "sbx-notes-1" } };
			return { status: 200, body: { sandboxId: "sbx-notes-1" } };
		});
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const readiness = await client.probeReadiness("notes", hex64);
			expect(readiness.ready).toBe(true);
			const rollback = await client.rollbackVersion("notes", hex64);
			expect(rollback.generation).toBe(1);
			// 7.3 protocol union: rollback carries the retired sandbox id
			expect(rollback.retired).toBe("sbx-notes-1");
			const started = await client.startVersion("notes", hex64);
			expect(started.sandboxId).toBe("sbx-notes-1");
			const stopped = await client.stopVersion("notes", hex64);
			expect(stopped.sandboxId).toBe("sbx-notes-1");
			const prepared = await client.prepareVersion("notes", hex64);
			expect(prepared.sandboxId).toBe("sbx-notes-1");
			const deleted = await client.deleteVersion("notes", hex64);
			expect(deleted.sandboxId).toBe("sbx-notes-1");
		} finally {
			mock.restore();
		}
	});

	it("returns sandbox lifecycle projections from node status", async () => {
		// regression: the REAL /v1/status payload carries six status-only keys;
		// parsing it with applicationsResponseSchema produced unrecognized_keys
		const mock = mockFetch(() => ({
			status: 200,
			body: {
				baseHost: "test.iweb.localhost",
				runtime: "celld",
				routes: 6,
				memory: { usageBytes: 1000, limitBytes: null, usagePercent: null, kernelHeapUsedBytes: 500 },
				applicationPublication: { enabled: false, reasons: ["publication-not-requested", "sandbox-acceptance-missing"] },
				sandboxSupervisor: { configured: false, available: false, version: null },
				applications: [{ id: "notes", sandboxId: null, activeVersion: null, routeGeneration: 0, lifecycle: "unavailable", versions: [], resources: { unavailable: true } }]
			}
		}));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const response = await client.statusApplications();
			expect(response.applications[0]?.lifecycle).toBe("unavailable");
			expect(response.applications[0]?.resources).toBeNull();
			expect(mock.calls[0]?.url).toBe("https://api.example.test/v1/status");
		} finally {
			mock.restore();
		}
	});

	it("propagates the bounded kernel error on failure", async () => {
		const mock = mockFetch(() => ({
			status: 503,
			body: { error: "application publication is disabled until sandbox acceptance passes", code: "APPLICATION_PUBLICATION_DISABLED" }
		}));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			await expect(client.listApplications()).rejects.toThrow("application publication is disabled");
		} finally {
			mock.restore();
		}
	});
});

// --- 9.5 Admin publication/lifecycle contract coverage ---
describe("Admin application lifecycle contract (9.5)", () => {
	const applicationsBody = (lifecycle: string) => ({
		applications: [
			{
				id: "notes",
				sandboxId: "sbx-notes-1",
				activeVersion: lifecycle === "unavailable" ? null : { digest: hex64, sequence: 1 },
				routeGeneration: 1,
				lifecycle,
				versions: [{ versionId: hex64, sequence: 1, lifecycle, admittedAt: "2026-08-13T08:00:00.000Z", readinessExpiresAt: null }],
				resources: null
			}
		]
	});

	it("walks a successful publication flow: admit, prepare, readiness, activate", async () => {
		const mock = mockFetch((url) => {
			if (url.endsWith("/versions") ) return { status: 201, body: { versionId: hex64, identity: { applicationId: "notes", digest: hex64, sequence: 1 } } };
			if (url.endsWith("/prepare")) return { status: 201, body: { sandboxId: "sbx-notes-1" } };
			if (url.endsWith("/readiness")) return { status: 200, body: { ready: true, attempts: 1, lastStatus: 200, mismatch: false, timedOut: false } };
			if (url.endsWith("/activate")) return { status: 200, body: { generation: 1, retired: null } };
			return { status: 200, body: {} };
		});
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const admitted = await client.admitApplication("notes");
			expect(admitted.versionId).toBe(hex64);
			const prepared = await client.prepareVersion("notes", hex64);
			expect(prepared.sandboxId).toBe("sbx-notes-1");
			const readiness = await client.probeReadiness("notes", hex64);
			expect(readiness.ready).toBe(true);
			const activation = await client.activateVersion("notes", hex64);
			expect(activation).toEqual({ generation: 1, retired: null });
			expect(mock.calls.map((call) => call.method)).toEqual(["POST", "POST", "POST", "POST"]);
		} finally {
			mock.restore();
		}
	});

	it("surfaces a rejected package as a bounded KernelApiError without a stack", async () => {
		const mock = mockFetch(() => ({ status: 422, body: { error: "admission rejected: manifest policy is invalid (ADMISSION_REJECTED)" } }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			await expect(client.admitApplication("notes")).rejects.toMatchObject({ name: "KernelApiError", status: 422 });
		} finally {
			mock.restore();
		}
	});

	it("surfaces a failed readiness probe without inventing ready state", async () => {
		const mock = mockFetch(() => ({ status: 503, body: { error: "readiness probe failed: gateway did not answer" } }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			await expect(client.probeReadiness("notes", hex64)).rejects.toMatchObject({ status: 503 });
		} finally {
			mock.restore();
		}
	});

	it("stop/start and rollback keep the protocol shape (rollback names the retired sandbox)", async () => {
		const mock = mockFetch((url) => {
			if (url.endsWith("/stop") || url.endsWith("/start")) return { status: 200, body: { sandboxId: "sbx-notes-1" } };
			if (url.endsWith("/rollback")) return { status: 200, body: { generation: 2, retired: "sbx-notes-2" } };
			return { status: 200, body: {} };
		});
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			expect((await client.stopVersion("notes", hex64)).sandboxId).toBe("sbx-notes-1");
			expect((await client.startVersion("notes", hex64)).sandboxId).toBe("sbx-notes-1");
			const rollback = await client.rollbackVersion("notes", hex64);
			expect(rollback).toEqual({ generation: 2, retired: "sbx-notes-2" });
		} finally {
			mock.restore();
		}
	});

	it("protected routes: deleting the active version propagates the kernel's bounded rejection", async () => {
		const mock = mockFetch(() => ({ status: 409, body: { error: "ACTIVE_VERSION_PROTECTED: the active version cannot be deleted" } }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			await expect(client.deleteVersion("notes", hex64)).rejects.toMatchObject({ status: 409 });
		} finally {
			mock.restore();
		}
	});

	it("credential absence: no owner token means no request leaves the client", async () => {
		const mock = mockFetch(() => ({ status: 200, body: {} }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "  ");
			await expect(client.listApplications()).rejects.toMatchObject({ name: "KernelApiError", status: 401 });
			expect(mock.calls).toHaveLength(0);
		} finally {
			mock.restore();
		}
	});

	it("stale monitor data recovers: a later status fetch observes the new lifecycle", async () => {
		let lifecycle = "preparing";
		const statusBody = () => ({
			baseHost: "example.test",
			runtime: "celld",
			routes: 1,
			memory: { usageBytes: 1, limitBytes: 2, usagePercent: 50, kernelHeapUsedBytes: 3 },
			applicationPublication: { enabled: false, reasons: [] },
			sandboxSupervisor: { configured: true, available: true, version: 1 },
			applications: applicationsBody(lifecycle).applications
		});
		const mock = mockFetch((url) => (url.endsWith("/v1/status") ? { status: 200, body: statusBody() } : { status: 200, body: {} }));
		try {
			const client = new KernelApiClient("https://api.example.test", () => "owner-key");
			const first = await client.statusApplications();
			expect(first.applications[0]?.lifecycle).toBe("preparing");
			lifecycle = "active";
			const second = await client.statusApplications();
			expect(second.applications[0]?.lifecycle).toBe("active");
		} finally {
			mock.restore();
		}
	});
});
