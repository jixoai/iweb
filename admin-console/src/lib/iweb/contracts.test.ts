// 用户原始需求（2026-08-13）：应用监控的应用副标题显示工作区文件夹路径。
// 正交意图：固定监控快照的 sourcePath 契约；拒绝缺少应用路径的旧快照。
import { describe, expect, it } from "vitest";
import { monitorSnapshotSchema } from "$lib/iweb/contracts";

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
			sourcePath: "/notes/app/",
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
	it("accepts the workspace source path for each monitored application", () => {
		expect(monitorSnapshotSchema.parse(snapshot).apps[0]?.sourcePath).toBe("/notes/app/");
	});

	it("rejects an application snapshot without a workspace source path", () => {
		const { sourcePath: _sourcePath, ...appWithoutSourcePath } = snapshot.apps[0];
		const result = monitorSnapshotSchema.safeParse({
			...snapshot,
			apps: [appWithoutSourcePath]
		});

		expect(result.success).toBe(false);
	});
});
