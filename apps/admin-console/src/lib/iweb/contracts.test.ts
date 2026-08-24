// 用户原始需求（2026-08-13）：应用监控的应用副标题显示工作区文件夹路径。
// 正交意图：固定监控快照的路由派生字段契约；拒绝缺少必填域的坏快照。
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
	],
	sandboxes: []
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
		limits: { cpuMillis: 5000, memoryBytes: 134217728, pidLimit: 64, storageBytes: 104857600 }
	}
};

describe("applicationProjectionSchema", () => {
	it("accepts a valid application projection with a measured resource sample", () => {
		const parsed = applicationProjectionSchema.parse(validProjection);
		expect(parsed.resources?.memoryBytes).toEqual({ available: true, value: 41943040 });
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

describe("monitorSnapshotSchema sandboxes", () => {
	it("accepts sandbox projections inside the monitor snapshot", () => {
		const parsed = monitorSnapshotSchema.parse({
			...snapshot,
			sandboxes: [validProjection]
		});
		expect(parsed.sandboxes[0]?.id).toBe("notes");
	});
});
