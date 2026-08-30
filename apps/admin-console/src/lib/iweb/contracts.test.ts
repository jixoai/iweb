// 用户原始需求（2026-08-13）：应用监控的应用副标题显示工作区文件夹路径。
// 正交意图：固定监控快照的路由派生字段契约；拒绝缺少必填域的坏快照。
// two-tier-runtime-trust（2026-08-30）：monitor 帧删除 celld sandboxes 数组，
// 新增可选看门狗投影（软限策略 + 最近越限事件环）。
import { describe, expect, it } from "vitest";
import { applicationProjectionSchema, monitorSnapshotSchema } from "$lib/iweb/contracts";

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
	sandboxId: "sbx-notes-1",
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
