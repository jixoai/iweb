// 任务 9.1/9.2/9.5：MCP 生命周期工具的契约测试。tools.js 必须是纯 ESM（无 Worker 全局）。
import { describe, expect, test } from "bun:test";
import { dispatchTool, tools } from "../worker/apps/mcp/app/tools.js";

const HEX64 = "a".repeat(64);

type KernelCall = { path: string; method: string; body?: string };

function recordingContext(handler?: (path: string, init: RequestInit) => Promise<unknown>) {
	const calls: KernelCall[] = [];
	return {
		calls,
		kernelFetch: async (path: string, init: RequestInit = {}) => {
			calls.push({ path, method: init.method ?? "GET", body: typeof init.body === "string" ? init.body : undefined });
			if (handler) return handler(path, init);
			return { ok: true };
		}
	};
}

const lifecycleToolNames = [
	"iweb_application_list",
	"iweb_application_admit",
	"iweb_application_prepare",
	"iweb_application_readiness",
	"iweb_application_activate",
	"iweb_application_start",
	"iweb_application_stop",
	"iweb_application_rollback",
	"iweb_application_delete_version",
	"iweb_application_metrics",
	"iweb_application_inspect",
	"iweb_application_versions",
	"iweb_application_delete_data"
];
// tools that identify only an application (no specific version)
const applicationOnlyTools = new Set(["iweb_application_list", "iweb_application_admit", "iweb_application_versions", "iweb_application_delete_data"]);

describe("MCP application tools", () => {
	test("every lifecycle tool is declared with required arguments and closed schemas", () => {
		for (const name of lifecycleToolNames) {
			const tool = tools.find((candidate) => candidate.name === name);
			expect(tool, name + " must be declared").toBeDefined();
			expect(tool!.inputSchema.additionalProperties).toBe(false);
			if (!applicationOnlyTools.has(name) || name !== "iweb_application_list") {
				expect(tool!.inputSchema.required).toContain("applicationId");
			}
			if (!applicationOnlyTools.has(name)) {
				expect(tool!.inputSchema.required).toContain("versionId");
			}
		}
	});

	test("existing workspace and domain tools remain declared", () => {
		for (const name of [
			"iweb_workspace_list",
			"iweb_workspace_read_text",
			"iweb_workspace_write_text",
			"iweb_workspace_delete",
			"iweb_domain_list",
			"iweb_domain_register"
		]) {
			expect(tools.some((tool) => tool.name === name)).toBe(true);
		}
	});

	test("dispatchTool rejects a malformed versionId without calling the kernel context", async () => {
		const context = recordingContext();
		await expect(dispatchTool("iweb_application_activate", { applicationId: "notes", versionId: "not-a-digest" }, context)).rejects.toThrow(
			"versionId must be a 64-character lowercase hex digest"
		);
		expect(context.calls).toHaveLength(0);
	});

	test("dispatchTool rejects a malformed applicationId without calling the kernel context", async () => {
		const context = recordingContext();
		await expect(dispatchTool("iweb_application_prepare", { applicationId: "Notes!", versionId: HEX64 }, context)).rejects.toThrow("applicationId");
		expect(context.calls).toHaveLength(0);
	});

	// 策略权威只有 workspace iweb.json（Kernel 校验 manifest 并推导 policy）；
	// admit 不接受 policy 覆盖。
	test("admit posts an empty body: the manifest is the sole policy authority", async () => {
		const context = recordingContext();
		const result = await dispatchTool("iweb_application_admit", { applicationId: "notes" }, context);
		expect(context.calls).toHaveLength(1);
		expect(context.calls[0]!.method).toBe("POST");
		expect(context.calls[0]!.path).toBe("/v1/applications/notes/versions");
		expect(context.calls[0]!.body).toBe("{}");
		expect(result).toHaveProperty("result");
	});

	test("admit rejects a malformed applicationId before calling the kernel context", async () => {
		const context = recordingContext();
		await expect(dispatchTool("iweb_application_admit", { applicationId: "Notes!" }, context)).rejects.toThrow("applicationId");
		expect(context.calls).toHaveLength(0);
	});

	test("activate posts to the version action endpoint", async () => {
		const context = recordingContext();
		await dispatchTool("iweb_application_activate", { applicationId: "notes", versionId: HEX64 }, context);
		expect(context.calls).toHaveLength(1);
		expect(context.calls[0]!.method).toBe("POST");
		expect(context.calls[0]!.path).toBe("/v1/applications/notes/versions/" + HEX64 + "/activate");
	});

	test("prepare, readiness, start, stop, rollback and delete map to their endpoints", async () => {
		const expectations: [string, string, string][] = [
			["iweb_application_prepare", "POST", "/v1/applications/notes/versions/" + HEX64 + "/prepare"],
			["iweb_application_readiness", "POST", "/v1/applications/notes/versions/" + HEX64 + "/readiness"],
			["iweb_application_start", "POST", "/v1/applications/notes/versions/" + HEX64 + "/start"],
			["iweb_application_stop", "POST", "/v1/applications/notes/versions/" + HEX64 + "/stop"],
			["iweb_application_rollback", "POST", "/v1/applications/notes/versions/" + HEX64 + "/rollback"],
		];
		for (const [name, method, path] of expectations) {
			const context = recordingContext();
			await dispatchTool(name, { applicationId: "notes", versionId: HEX64 }, context);
			expect(context.calls).toHaveLength(1);
			expect(context.calls[0]!.method).toBe(method);
			expect(context.calls[0]!.path).toBe(path);
		}
		// delete_version runs the active-version safety pre-flight first: a GET
		// of the application projection, then the DELETE itself
		const context = recordingContext();
		await dispatchTool("iweb_application_delete_version", { applicationId: "notes", versionId: HEX64 }, context);
		expect(context.calls).toHaveLength(2);
		expect(context.calls[0]!.method).toBe("GET");
		expect(context.calls[0]!.path).toBe("/v1/applications");
		expect(context.calls[1]!.method).toBe("DELETE");
		expect(context.calls[1]!.path).toBe("/v1/applications/notes/versions/" + HEX64);
	});

	test("metrics reads node status and picks the matching application projection", async () => {
		const projection = {
			id: "notes",
			sandboxId: "sbx-notes-1",
			activeVersion: { digest: HEX64, sequence: 2 },
			routeGeneration: 3,
			lifecycle: "active",
			versions: [],
			resources: null
		};
		const context = recordingContext(async (path) => (path === "/v1/status" ? { applications: [projection] } : { ok: true }));
		const result = await dispatchTool("iweb_application_metrics", { applicationId: "notes", versionId: HEX64 }, context);
		expect(context.calls).toHaveLength(1);
		expect(context.calls[0]!.path).toBe("/v1/status");
		expect(result).toEqual({ result: projection });
	});

	test("errors are bounded: kernel error text only, no stack trace", async () => {
		const context = recordingContext(async () => {
			throw new Error("application publication is disabled until sandbox acceptance passes\n    at kernel (index.js:99)");
		});
		try {
			await dispatchTool("iweb_application_activate", { applicationId: "notes", versionId: HEX64 }, context);
			throw new Error("expected rejection");
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			expect(message).toContain("application publication is disabled");
			expect(message).not.toContain("at kernel");
			expect(message).not.toContain("index.js");
		}
	});

	test("every dispatch result carries a stable result object", async () => {
		const projection = {
			id: "notes",
			sandboxId: null,
			activeVersion: null,
			routeGeneration: 0,
			lifecycle: "unavailable",
			versions: [],
			resources: null
		};
		const context = recordingContext(async () => ({ applications: [projection] }));
		for (const name of lifecycleToolNames) {
			const args =
				name === "iweb_application_list"
					? {}
					: applicationOnlyTools.has(name)
						? { applicationId: "notes" }
						: { applicationId: "notes", versionId: HEX64 };
			const result = await dispatchTool(name, args, context);
			expect(Object.keys(result)).toEqual(["result"]);
		}
	});
});

describe("MCP lifecycle contract (9.2/9.5)", () => {
	const HEX_A = "a".repeat(64);
	const HEX_B = "b".repeat(64);

	function applicationsHandler(applications: unknown[]) {
		return async (path: string) => {
			if (path === "/v1/applications") return { applications };
			return { ok: true };
		};
	}

	test("a full publication flow traverses admit -> prepare -> readiness -> activate in order", async () => {
		const calls: { path: string; method: string }[] = [];
		const context = recordingContext(async (path, init) => {
			calls.push({ path, method: (init.method ?? "GET") as string });
			if (path === "/v1/applications") return { applications: [] };
			if (path.endsWith("/versions") && (init.method ?? "GET") === "POST") return { versionId: HEX_A, identity: { applicationId: "notes", digest: HEX_A, sequence: 1 } };
			if (path.endsWith("/prepare")) return { sandboxId: "sbx-notes-1" };
			if (path.endsWith("/readiness")) return { ready: true };
			if (path.endsWith("/activate")) return { generation: 1, retired: null };
			return { ok: true };
		});
		const admitted = await dispatchTool("iweb_application_admit", { applicationId: "notes" }, context);
		expect(admitted.result).toMatchObject({ versionId: HEX_A });
		await dispatchTool("iweb_application_prepare", { applicationId: "notes", versionId: HEX_A }, context);
		await dispatchTool("iweb_application_readiness", { applicationId: "notes", versionId: HEX_A }, context);
		const activation = await dispatchTool("iweb_application_activate", { applicationId: "notes", versionId: HEX_A }, context);
		expect(activation.result).toEqual({ generation: 1, retired: null });
		expect(calls.map((call) => call.path)).toEqual([
			"/v1/applications/notes/versions",
			"/v1/applications/notes/versions/" + HEX_A + "/prepare",
			"/v1/applications/notes/versions/" + HEX_A + "/readiness",
			"/v1/applications/notes/versions/" + HEX_A + "/activate",
		]);
	});

	test("a rejected package propagates the kernel's bounded rejection text (9.5)", async () => {
		const context = recordingContext(async (path) => {
			if (path === "/v1/applications") return { applications: [] };
			throw new Error("admission rejected: manifest policy is invalid (code ADMISSION_REJECTED)");
		});
		await expect(dispatchTool("iweb_application_admit", { applicationId: "notes" }, context)).rejects.toThrow(/ADMISSION_REJECTED/);
	});

	test("a failed readiness probe surfaces the bounded failure without inventing ready state (9.5)", async () => {
		const context = recordingContext(async (path) => {
			if (path.endsWith("/readiness")) throw new Error("readiness probe failed: gateway did not answer the health contract");
			return { ok: true };
		});
		await expect(dispatchTool("iweb_application_readiness", { applicationId: "notes", versionId: HEX_A }, context)).rejects.toThrow(/health contract/);
	});

	test("stop/start round-trip and rollback map onto the version actions (9.5)", async () => {
		const context = recordingContext(async (path) => {
			if (path.endsWith("/rollback")) return { generation: 3, retired: "sbx-notes-2" };
			return { sandboxId: "sbx-notes-1" };
		});
		await dispatchTool("iweb_application_stop", { applicationId: "notes", versionId: HEX_A }, context);
		await dispatchTool("iweb_application_start", { applicationId: "notes", versionId: HEX_A }, context);
		const rollback = await dispatchTool("iweb_application_rollback", { applicationId: "notes", versionId: HEX_A }, context);
		expect(rollback.result).toEqual({ generation: 3, retired: "sbx-notes-2" });
	});

	test("retained-version listing and inspection are exposed for rollback planning (9.2)", async () => {
		const versions = [
			{ versionId: HEX_A, lifecycle: "retired", sequence: 1 },
			{ versionId: HEX_B, lifecycle: "active", sequence: 2 },
		];
		const context = recordingContext(applicationsHandler([{ id: "notes", activeVersion: { digest: HEX_B, sequence: 2 }, versions }]));
		const listing = await dispatchTool("iweb_application_versions", { applicationId: "notes" }, context);
		expect(listing.result).toEqual({ applicationId: "notes", active: { digest: HEX_B, sequence: 2 }, versions });
		await expect(dispatchTool("iweb_application_versions", { applicationId: "ghost" }, context)).rejects.toThrow(/no admitted versions/);
		const inspect = await dispatchTool("iweb_application_inspect", { applicationId: "notes", versionId: HEX_A }, recordingContext());
		expect(inspect).toHaveProperty("result");
	});

	test("the active version is protected from deletion by an MCP-side pre-flight (9.2/9.5)", async () => {
		const context = recordingContext(applicationsHandler([{ id: "notes", activeVersion: { digest: HEX_A, sequence: 1 }, versions: [{ versionId: HEX_A, lifecycle: "active", sequence: 1 }] }]));
		await expect(dispatchTool("iweb_application_delete_version", { applicationId: "notes", versionId: HEX_A }, context)).rejects.toThrow(/active version cannot be deleted/);
		// the destructive DELETE never ran: only the pre-flight GET was issued
		expect(context.calls).toHaveLength(1);
		expect(context.calls[0]!.method).toBe("GET");
	});

	test("separate persistent-data deletion is its own tool and endpoint, never implicit in version deletion (9.2)", async () => {
		const context = recordingContext();
		await dispatchTool("iweb_application_delete_data", { applicationId: "notes" }, context);
		expect(context.calls).toEqual([{ path: "/v1/applications/notes/data", method: "DELETE" }]);
		// version deletion never touches the data endpoint
		const versionContext = recordingContext(applicationsHandler([{ id: "notes", activeVersion: null, versions: [] }]));
		await dispatchTool("iweb_application_delete_version", { applicationId: "notes", versionId: HEX_B }, versionContext);
		expect(versionContext.calls.some((call) => call.path.includes("/data"))).toBe(false);
	});

	test("no tool definition or dispatch surface carries a credential (9.5)", () => {
		const flat = JSON.stringify(tools);
		expect(flat).not.toMatch(/bearer|authorization|secretAccessKey|IWEB_API_TOKEN/i);
		// the dispatch layer receives only a kernelFetch thunk: no env, no request
		for (const name of ["iweb_application_list", "iweb_application_versions", "iweb_application_delete_data"]) {
			const tool = tools.find((candidate) => candidate.name === name);
			expect(tool, name + " declared").toBeDefined();
			expect(JSON.stringify(tool!.inputSchema)).not.toMatch(/token|key|secret/i);
		}
	});

	test("stale monitor data is re-fetched: two metrics calls observe the live status each time (9.5)", async () => {
		let lifecycle = "preparing";
		const context = recordingContext(async () => ({ applications: [{ id: "notes", sandboxId: "sbx-notes-1", activeVersion: { digest: HEX_A, sequence: 1 }, routeGeneration: 1, lifecycle, versions: [], resources: null }] }));
		const first = await dispatchTool("iweb_application_metrics", { applicationId: "notes", versionId: HEX_A }, context);
		expect(first.result.lifecycle).toBe("preparing");
		lifecycle = "active";
		const second = await dispatchTool("iweb_application_metrics", { applicationId: "notes", versionId: HEX_A }, context);
		expect(second.result.lifecycle).toBe("active");
		expect(context.calls).toHaveLength(2);
	});
});
