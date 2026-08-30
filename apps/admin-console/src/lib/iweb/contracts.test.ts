// 用户原始需求（2026-08-13）：应用监控的应用副标题显示工作区文件夹路径。
// 正交意图：固定监控快照的路由派生字段契约；拒绝缺少必填域的坏快照。
// two-tier-runtime-trust（2026-08-30）：monitor 帧删除 celld sandboxes 数组，
// 新增可选看门狗投影（软限策略 + 最近越限事件环）。
import { describe, expect, it } from "vitest";
import {
	applicationProjectionSchema,
	monitorSnapshotSchema,
	routeSchema,
	routeStoreSchema,
	wasmStatusSchema
} from "$lib/iweb/contracts";

const snapshot = {
	type: "snapshot",
	emittedAt: "2026-08-13T08:00:00.000Z",
	node: {
		uptimeSeconds: 42,
		routeCount: 3,
		workspaceFileCount: 6,
		workspaceBytes: 1024,
		memory: {
			usageBytes: 256,
			limitBytes: 1024,
			usagePercent: 25,
			kernelHeapUsedBytes: 128
		}
	},
	apps: [
		{
			id: "notes",
			domains: ["notes.app"],
			deployed: true,
			system: false,
			requests: 12,
			errors: 0,
			inFlight: 1,
			averageLatencyMs: 4.2,
			lastRequestAt: "2026-08-13T08:00:00.000Z"
		}
	]
};

describe("monitorSnapshotSchema", () => {
	it("accepts route-derived domains for each monitored application", () => {
		expect(monitorSnapshotSchema.parse(snapshot).apps[0]?.id).toBe("notes");
	});

	it("rejects an application snapshot without route-derived domains", () => {
		const { domains: _domains, ...appWithoutDomains } = snapshot.apps[0];
		const result = monitorSnapshotSchema.safeParse({
			...snapshot,
			apps: [appWithoutDomains]
		});

		expect(result.success).toBe(false);
	});
});

// --- application sandbox projections（任务 9.3-9.5 / 10.3） ---
const hex64 = "a".repeat(64);

const validProjection = {
	id: "notes",
	runtimeKind: "celld",
	// two-tier-runtime-trust（9.6）：fleet 投影没有沙箱身份——契约恒 null。
	sandboxId: null,
	activeVersion: { digest: hex64, sequence: 2 },
	routeGeneration: 3,
	lifecycle: "active",
	versions: [
		{ versionId: hex64, sequence: 1, lifecycle: "retired", admittedAt: "2026-08-13T08:00:00.000Z", readinessExpiresAt: "2026-08-13T08:10:00.000Z" },
		{ versionId: hex64, sequence: 2, lifecycle: "active", admittedAt: "2026-08-13T08:05:00.000Z", readinessExpiresAt: null }
	],
	resources: {
		versionId: hex64,
		sampledAt: "2026-08-13T08:06:00.000Z",
		cpuMillis: { available: true, value: 1200 },
		memoryBytes: { available: true, value: 41943040 },
		pidCount: { available: true, value: 12 },
		terminated: { available: false },
		limits: { cpuMillis: 5000, memoryBytes: 134217728, pidLimit: 64, storageBytes: 104857600, enforcement: "watchdog-soft" }
	}
};

describe("applicationProjectionSchema", () => {
	it("accepts a valid application projection with a measured resource sample", () => {
		const parsed = applicationProjectionSchema.parse(validProjection);
		expect(parsed.runtimeKind).toBe("celld");
		expect(parsed.resources?.memoryBytes).toEqual({ available: true, value: 41943040 });
		expect(parsed.resources?.limits?.enforcement).toBe("watchdog-soft");
		expect(parsed.activeVersion?.digest).toBe(hex64);
		expect(parsed.versions).toHaveLength(2);
	});

	it("accepts an unavailable measurement { available: false }", () => {
		const parsed = applicationProjectionSchema.parse({
			...validProjection,
			resources: {
				versionId: hex64,
				sampledAt: "2026-08-13T08:06:00.000Z",
				cpuMillis: { available: false },
				memoryBytes: { available: false },
				pidCount: { available: false },
				terminated: { available: false },
				limits: null
			}
		});
		expect(parsed.resources?.memoryBytes).toEqual({ available: false });
	});

	it("rejects a value attached to an unavailable measurement", () => {
		const invalid = {
			...validProjection,
			resources: {
				...validProjection.resources,
				memoryBytes: { available: false, value: 42 }
			}
		};
		expect(applicationProjectionSchema.safeParse(invalid).success).toBe(false);
	});

	it("normalizes the kernel { unavailable: true } no-sample marker to null", () => {
		const parsed = applicationProjectionSchema.parse({ ...validProjection, resources: { unavailable: true } });
		expect(parsed.resources).toBeNull();
	});

	it("rejects a sandbox-era frame with a non-null sandboxId (two-tier fleet has no sandbox identity)", () => {
		const result = applicationProjectionSchema.safeParse({ ...validProjection, sandboxId: "sbx-notes-1" });
		expect(result.success).toBe(false);
	});
});

// two-tier-runtime-trust：celld 控制状态的 sandboxes 数组已从 monitor 帧删除——
// 快照携带它必须被 strict 契约拒收（不再是可忽略的旧键）。
describe("monitorSnapshotSchema sandboxes removal", () => {
	it("rejects a frame that still carries the deleted celld sandboxes array", () => {
		const result = monitorSnapshotSchema.safeParse({
			...snapshot,
			sandboxes: [validProjection]
		});
		expect(result.success).toBe(false);
	});
});

describe("monitorSnapshotSchema watchdog projection", () => {
	it("accepts a watchdog projection with per-app soft limits and a bounded kill-event ring", () => {
		const parsed = monitorSnapshotSchema.parse({
			...snapshot,
			watchdog: {
				intervalMs: 15000,
				defaultBytes: 536870912,
				apps: { notes: 268435456 },
				events: [{ applicationId: "notes", sampledBytes: 314572800, limitBytes: 268435456, terminatedAt: "2026-08-29T08:00:00.000Z" }]
			}
		});
		expect(parsed.watchdog?.apps["notes"]).toBe(268435456);
		expect(parsed.watchdog?.events[0]?.sampledBytes).toBe(314572800);
	});

	it("keeps the watchdog optional (old kernel frames omit it)", () => {
		const parsed = monitorSnapshotSchema.parse(snapshot);
		expect(parsed.watchdog).toBeUndefined();
	});

	it("rejects a kill event with a zero sampled value (zero must be proven, never invented)", () => {
		const result = monitorSnapshotSchema.safeParse({
			...snapshot,
			watchdog: {
				intervalMs: 15000,
				defaultBytes: 536870912,
				apps: {},
				events: [{ applicationId: "notes", sampledBytes: 0, limitBytes: 268435456, terminatedAt: "2026-08-29T08:00:00.000Z" }]
			}
		});
		expect(result.success).toBe(false);
	});
});

// --- two-tier-runtime-trust（9.6）：路由注册表 strict 双层 union ---
// 系统路由只能是镜像种子的 celld-app；用户路由只能是 sandbox（wasm 应用身份注册）。
// 用户 celld-app 路由在 Admin 即拒收——与 Kernel 供给法过滤（R2 9.9）双保险。
describe("routeSchema two-tier strict union", () => {
	const systemRoute = {
		hostId: "admin",
		target: { kind: "celld-app", appName: "admin" },
		system: true,
		enabled: true
	};
	const userRoute = {
		hostId: "notes.app",
		target: { kind: "sandbox", appName: "notes" },
		system: false,
		enabled: true
	};

	it("accepts a system celld-app route and a user sandbox route in one store", () => {
		const parsed = routeStoreSchema.parse({ version: 1, routes: [systemRoute, userRoute] });
		expect(parsed.routes).toHaveLength(2);
		expect(parsed.routes[0]?.target.kind).toBe("celld-app");
		expect(parsed.routes[1]?.target.kind).toBe("sandbox");
	});

	it("accepts a legacy user sandbox route that still carries a stale sandboxId (wire-compatible)", () => {
		const parsed = routeSchema.parse({
			hostId: "notes.app",
			target: { kind: "sandbox", appName: "notes", sandboxId: "sbx-stale" },
			system: false,
			enabled: true
		});
		expect(parsed.target.kind).toBe("sandbox");
		expect(parsed.target.sandboxId).toBe("sbx-stale");
	});

	it("rejects a user celld-app route (kernel filters them; Admin strict double insurance)", () => {
		const result = routeSchema.safeParse({
			hostId: "notes.app",
			target: { kind: "celld-app", appName: "notes" },
			system: false,
			enabled: true
		});
		expect(result.success).toBe(false);
	});

	it("rejects a system sandbox route (sandbox is the user-tier identity registration only)", () => {
		const result = routeSchema.safeParse({
			hostId: "admin",
			target: { kind: "sandbox", appName: "admin" },
			system: true,
			enabled: true
		});
		expect(result.success).toBe(false);
	});

	it("rejects unknown target kinds and unknown target keys", () => {
		expect(
			routeSchema.safeParse({ hostId: "x.app", target: { kind: "worker", appName: "x" }, system: false, enabled: true }).success
		).toBe(false);
		expect(
			routeSchema.safeParse({ hostId: "x.app", target: { kind: "sandbox", appName: "x", extra: 1 }, system: false, enabled: true }).success
		).toBe(false);
	});
});

// --- two-tier-runtime-trust（9.6）：/v1/wasm/status 投影（wasmStatusSchema） ---
describe("wasmStatusSchema", () => {
	const digest = hex64;
	const wasmStatus = {
		schemaVersion: 1,
		runtimeKind: "wasm",
		bootstrap: { state: "verified", claims: 3, source: "route-registry" },
		publicationGate: { schemaVersion: 1, runtimeKind: "wasm", enabled: false, reasons: ["publication-not-requested"] },
		applications: [
			{
				applicationId: "moonbit-demo",
				runtimeKind: "wasm",
				versions: [
					{
						versionId: digest + "-1",
						identity: { applicationId: "moonbit-demo", digest, sequence: 1 },
						lifecycle: "admitted"
					}
				],
				active: { versionId: digest + "-1", routeGeneration: 4 },
				routeGeneration: 4
			},
			{
				applicationId: "vector-search",
				runtimeKind: "wasm",
				versions: [],
				active: null,
				routeGeneration: 0
			}
		]
	};

	it("accepts the kernel status projection with active pointers and derives tiers per application", () => {
		const parsed = wasmStatusSchema.parse(wasmStatus);
		expect(parsed.applications[0]?.active?.versionId).toBe(digest + "-1");
		expect(parsed.applications[0]?.versions[0]?.identity.digest).toBe(digest);
		expect(parsed.applications[1]?.active).toBeNull();
	});

	it("strips the transitional servicePublicationGate key (R2 9.7 deletes it kernel-side)", () => {
		const parsed = wasmStatusSchema.parse({ ...wasmStatus, servicePublicationGate: wasmStatus.publicationGate });
		expect(parsed.applications).toHaveLength(2);
	});

	it("accepts the fail-closed bootstrap projection { state: unavailable, code, detail }", () => {
		const parsed = wasmStatusSchema.parse({
			...wasmStatus,
			bootstrap: { state: "unavailable", code: "WASM_STATE_UNAVAILABLE", detail: "control state file is corrupt" }
		});
		expect(parsed.bootstrap).toEqual({ state: "unavailable", code: "WASM_STATE_UNAVAILABLE", detail: "control state file is corrupt" });
	});

	it("rejects drift: wrong runtimeKind, malformed gate, and celld rows inside the wasm projection", () => {
		expect(wasmStatusSchema.safeParse({ ...wasmStatus, runtimeKind: "celld" }).success).toBe(false);
		expect(
			wasmStatusSchema.safeParse({ ...wasmStatus, publicationGate: { schemaVersion: 1, runtimeKind: "wasm", enabled: false } }).success
		).toBe(false);
		expect(
			wasmStatusSchema.safeParse({
				...wasmStatus,
				applications: [{ applicationId: "notes", runtimeKind: "celld", versions: [], active: null, routeGeneration: 0 }]
			}).success
		).toBe(false);
	});

	it("rejects a version row without the exact identity shape (applicationId/digest/sequence)", () => {
		const result = wasmStatusSchema.safeParse({
			...wasmStatus,
			applications: [
				{
					applicationId: "moonbit-demo",
					runtimeKind: "wasm",
					versions: [{ versionId: digest + "-1", identity: { digest, sequence: 1 }, lifecycle: "admitted" }],
					active: null,
					routeGeneration: 0
				}
			]
		});
		expect(result.success).toBe(false);
	});
});
