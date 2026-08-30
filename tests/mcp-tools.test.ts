// two-tier-runtime-trust 7.1：MCP 工具面收窄 wasm-only 的契约测试。
// tools.ts 必须是纯 ESM（无 Worker 全局）。契约：
// - celld 运行时准入永久移除：退役生命周期工具只回 CELLD_IMAGE_ONLY 两层引导，零 kernel 调用；
// - 不存在任何指向已移除 celld 准入端点（/v1/applications*）的调用路径；
// - wasm 读面走 /v1/wasm/status 投影，发布走 /v1/wasm/admission 事务透传；
// - Kernel 终态 CELLD_ADMISSION_REMOVED 在 MCP 边界映射为有界引导呈现；
// - 工具描述（tools/list）携带两层引导文案。
import { describe, expect, test } from "bun:test";
import { dispatchTool, tools } from "../apps/workers/mcp/src/tools.ts";

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

const wasmStatusHandler = (applications: unknown[]) => async (path: string) => {
	if (path === "/v1/wasm/status") return { applications };
	return { ok: true };
};

const retiredToolNames = [
	"iweb_application_prepare",
	"iweb_application_readiness",
	"iweb_application_activate",
	"iweb_application_start",
	"iweb_application_stop",
	"iweb_application_rollback",
	"iweb_application_delete_version",
	"iweb_application_delete_data",
	"iweb_application_metrics"
];

const applicationToolNames = [
	"iweb_application_list",
	"iweb_application_admit",
	"iweb_application_inspect",
	"iweb_application_versions",
	...retiredToolNames
];

describe("MCP application tool declarations (two-tier trust)", () => {
	test("every application tool is declared with a closed schema", () => {
		for (const name of applicationToolNames) {
			const tool = tools.find((candidate) => candidate.name === name);
			expect(tool, name + " must be declared").toBeDefined();
			expect(tool!.inputSchema.additionalProperties, name).toBe(false);
			// admit 的身份在 transaction 内（applicationId 不是顶层参数）；list 是全局读。
			if (name !== "iweb_application_list" && name !== "iweb_application_admit") {
				expect(tool!.inputSchema.required, name).toContain("applicationId");
			}
		}
		const admit = tools.find((candidate) => candidate.name === "iweb_application_admit");
		expect(admit!.inputSchema.required).toEqual(["transaction"]);
	});

	test("every application tool description carries the two-layer deployment guidance", () => {
		for (const name of applicationToolNames) {
			const tool = tools.find((candidate) => candidate.name === name);
			expect(tool, name + " must be declared").toBeDefined();
			// 第一层：不可信代码 → wasi:http 组件经 wasm 准入（QuickJS/StarlingMonkey/MoonBit）。
			expect(tool!.description, name).toMatch(/wasi:http component/);
			expect(tool!.description, name).toMatch(/QuickJS or StarlingMonkey/);
			expect(tool!.description, name).toMatch(/MoonBit/);
			// 第二层：可信且需原生能力 → owner 节点镜像。
			expect(tool!.description, name).toMatch(/owner-built node image/);
		}
	});

	test("retired lifecycle tools are described as retired with the CELLD_IMAGE_ONLY code", () => {
		for (const name of retiredToolNames) {
			const tool = tools.find((candidate) => candidate.name === name);
			expect(tool!.description, name).toMatch(/Retired/);
			expect(tool!.description, name).toMatch(/CELLD_IMAGE_ONLY/);
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

	test("no tool definition or dispatch surface carries a credential", () => {
		const flat = JSON.stringify(tools);
		expect(flat).not.toMatch(/bearer|authorization|secretAccessKey|IWEB_API_TOKEN/i);
		// the dispatch layer receives only a kernelFetch thunk: no env, no request
		for (const name of applicationToolNames) {
			const tool = tools.find((candidate) => candidate.name === name);
			expect(tool, name + " declared").toBeDefined();
			expect(JSON.stringify(tool!.inputSchema), name).not.toMatch(/token|key|secret/i);
		}
	});
});

describe("MCP rejects celld targets with bounded two-layer guidance", () => {
	// celld fleet 应用（notes 是镜像种子的 celld 应用名）：对每个退役生命周期工具，
	// 拒绝文案必须携带 CELLD_IMAGE_ONLY 与两层引导，并且绝不发出任何 kernel 调用
	//（fleet 进程不受影响）。
	for (const name of retiredToolNames) {
		test(name + " returns the bounded image-only guidance without any kernel call", async () => {
			const context = recordingContext();
			const args = name === "iweb_application_delete_data" ? { applicationId: "notes" } : { applicationId: "notes", versionId: HEX64 };
			await expect(dispatchTool(name, args, context)).rejects.toThrow(/CELLD_IMAGE_ONLY/);
			try {
				await dispatchTool(name, args, context);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				expect(message).toContain("wasi:http component");
				expect(message).toContain("QuickJS or StarlingMonkey");
				expect(message).toContain("MoonBit");
				expect(message).toContain("owner-built node image");
				expect(message).toContain("retired");
			}
			expect(context.calls).toHaveLength(0);
		});
	}

	test("admit rejects an explicit celld kind before any kernel call", async () => {
		const context = recordingContext();
		await expect(
			dispatchTool("iweb_application_admit", { kind: "celld", transaction: { schemaVersion: 1, applicationId: "notes" } }, context)
		).rejects.toThrow(/CELLD_IMAGE_ONLY/);
		expect(context.calls).toHaveLength(0);
	});

	test("admit rejects a transaction whose runtimeBinding names celld before any kernel call", async () => {
		const context = recordingContext();
		await expect(
			dispatchTool(
				"iweb_application_admit",
				{ transaction: { schemaVersion: 1, applicationId: "notes", runtimeBinding: { kind: "celld" } } },
				context
			)
		).rejects.toThrow(/CELLD_IMAGE_ONLY/);
		expect(context.calls).toHaveLength(0);
	});

	test("retired tools keep the bounded input discipline: malformed ids reject locally", async () => {
		const context = recordingContext();
		await expect(dispatchTool("iweb_application_activate", { applicationId: "Notes!", versionId: HEX64 }, context)).rejects.toThrow("applicationId");
		await expect(dispatchTool("iweb_application_stop", { applicationId: "notes", versionId: "not-a-digest" }, context)).rejects.toThrow(
			"versionId must be a 64-character lowercase hex digest"
		);
		expect(context.calls).toHaveLength(0);
	});
});

describe("MCP wasm admission forwarding (the only publication path)", () => {
	const transaction = {
		schemaVersion: 1,
		applicationId: "vector",
		packageDigest: HEX64,
		normalizedPolicy: { schemaVersion: 1, name: "vector", runtime: { kind: "wasm", world: "wasi:http/proxy@0.2.8" } },
		runtimeBinding: { kind: "wasm", entryKey: "iweb-wasmd", world: "wasi:http/proxy@0.2.8", hostABI: "iweb-wasmd-abi@1.0.0" },
		capabilityRecordRevision: 9,
		capabilityRecordHash: "b".repeat(64),
		stagingTtlSeconds: 600,
		blobs: [{ digestHex: HEX64, base64: "AGJ5dGVz" }]
	};

	test("forwards the admission transaction verbatim and reports the Kernel's structured result", async () => {
		const admissionResult = { ok: true, admissionId: "adm-1", state: "visible", versionId: HEX64 + "-1" };
		const context = recordingContext(async (path) => (path === "/v1/wasm/admission" ? admissionResult : { ok: true }));
		const result = await dispatchTool("iweb_application_admit", { transaction }, context);
		expect(context.calls).toHaveLength(1);
		expect(context.calls[0]!.method).toBe("POST");
		expect(context.calls[0]!.path).toBe("/v1/wasm/admission");
		// 逐字透传：body 与调用方事务字节相等（Kernel 是包/策略/能力矩阵的唯一校验权威）。
		expect(context.calls[0]!.body).toBe(JSON.stringify(transaction));
		expect(result).toEqual({ result: admissionResult });
	});

	test("a kernel admission rejection propagates bounded text without a stack trace", async () => {
		const context = recordingContext(async () => {
			throw new Error("admission rejected: the capability matrix refuses this import (code WASM_ADMISSION_WIRE_INVALID)\n    at kernel (wasm_runtime.rs:99)");
		});
		try {
			await dispatchTool("iweb_application_admit", { transaction }, context);
			throw new Error("expected rejection");
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			expect(message).toContain("WASM_ADMISSION_WIRE_INVALID");
			expect(message).not.toContain("at kernel");
			expect(message).not.toContain("wasm_runtime.rs");
		}
	});

	test("a missing or non-object transaction rejects before any kernel call", async () => {
		const context = recordingContext();
		await expect(dispatchTool("iweb_application_admit", {}, context)).rejects.toThrow(/transaction must be the Kernel wasm admission transaction/);
		await expect(dispatchTool("iweb_application_admit", { transaction: "notes" }, context)).rejects.toThrow(/transaction must be the Kernel wasm admission transaction/);
		expect(context.calls).toHaveLength(0);
	});

	test("the Kernel's terminal CELLD_ADMISSION_REMOVED state is presented as bounded guidance, not raw endpoint semantics", async () => {
		const context = recordingContext(async () => {
			throw new Error("Kernel returned HTTP 410: celld admission removed [CELLD_ADMISSION_REMOVED]\n    at kernel (http.rs:42)");
		});
		try {
			await dispatchTool("iweb_application_admit", { transaction }, context);
			throw new Error("expected rejection");
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			expect(message).toContain("CELLD_ADMISSION_REMOVED");
			expect(message).toContain("CELLD_IMAGE_ONLY");
			expect(message).toContain("wasi:http component");
			expect(message).toContain("owner-built node image");
			// 有界呈现：不透传堆栈与原始内部文本形态。
			expect(message).not.toContain("at kernel");
			expect(message).not.toContain("http.rs");
		}
	});
});

describe("MCP wasm registry reads (Kernel /v1/wasm/status projection)", () => {
	const rows = [
		{
			applicationId: "vector",
			runtimeKind: "wasm",
			routeGeneration: 4,
			active: { versionId: HEX64 + "-2", routeGeneration: 4 },
			versions: [
				{ versionId: HEX64 + "-1", lifecycle: "retired", identity: { digest: HEX64, sequence: 1 } },
				{ versionId: HEX64 + "-2", lifecycle: "active", identity: { digest: HEX64, sequence: 2 } }
			]
		},
		{ applicationId: "sieve", runtimeKind: "wasm", routeGeneration: 0, active: null, versions: [] }
	];

	test("list reads the wasm status projection and reports only runtime-admitted applications", async () => {
		const context = recordingContext(wasmStatusHandler(rows));
		const result = await dispatchTool("iweb_application_list", {}, context);
		expect(context.calls).toEqual([{ path: "/v1/wasm/status", method: "GET" }]);
		expect(result).toEqual({ result: { applications: rows } });
	});

	test("versions lists retained admitted versions with the active pointer", async () => {
		const context = recordingContext(wasmStatusHandler(rows));
		const listing = await dispatchTool("iweb_application_versions", { applicationId: "vector" }, context);
		expect(listing).toEqual({
			result: { applicationId: "vector", runtimeKind: "wasm", active: rows[0]!.active, versions: rows[0]!.versions }
		});
	});

	test("inspect reports one application's runtime kind, versions, and lifecycle availability", async () => {
		const context = recordingContext(wasmStatusHandler(rows));
		const inspection = await dispatchTool("iweb_application_inspect", { applicationId: "vector" }, context);
		expect(inspection).toEqual({ result: rows[0] });
	});

	test("an unknown (or celld-seeded) application name gets the bounded image-only guidance", async () => {
		const context = recordingContext(wasmStatusHandler(rows));
		for (const tool of ["iweb_application_versions", "iweb_application_inspect"] as const) {
			await expect(dispatchTool(tool, { applicationId: "notes" }, context)).rejects.toThrow(/no admitted wasm versions/);
			try {
				await dispatchTool(tool, { applicationId: "notes" }, context);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				expect(message).toContain("CELLD_IMAGE_ONLY");
				expect(message).toContain("wasi:http component");
				expect(message).toContain("owner-built node image");
			}
		}
	});

	test("read tools reject a malformed applicationId without calling the kernel context", async () => {
		const context = recordingContext();
		await expect(dispatchTool("iweb_application_versions", { applicationId: "Notes!" }, context)).rejects.toThrow("applicationId");
		await expect(dispatchTool("iweb_application_inspect", { applicationId: "Notes!" }, context)).rejects.toThrow("applicationId");
		expect(context.calls).toHaveLength(0);
	});

	test("stale registry data is re-fetched: two versions calls observe the live projection each time", async () => {
		let lifecycle = "staging";
		const context = recordingContext(async () => ({
			applications: [{ applicationId: "vector", runtimeKind: "wasm", active: null, versions: [{ versionId: HEX64 + "-1", lifecycle }] }]
		}));
		const first = await dispatchTool("iweb_application_versions", { applicationId: "vector" }, context);
		expect(first.result.versions[0]!.lifecycle).toBe("staging");
		lifecycle = "active";
		const second = await dispatchTool("iweb_application_versions", { applicationId: "vector" }, context);
		expect(second.result.versions[0]!.lifecycle).toBe("active");
		expect(context.calls).toHaveLength(2);
	});

	test("every wasm-facing dispatch result carries a stable result object", async () => {
		const context = recordingContext(wasmStatusHandler(rows));
		expect(Object.keys(await dispatchTool("iweb_application_list", {}, context))).toEqual(["result"]);
		expect(Object.keys(await dispatchTool("iweb_application_versions", { applicationId: "vector" }, context))).toEqual(["result"]);
		expect(Object.keys(await dispatchTool("iweb_application_inspect", { applicationId: "vector" }, context))).toEqual(["result"]);
	});
});

describe("MCP never calls removed celld admission endpoints", () => {
	test("no dispatch path can reach a /v1/applications endpoint (deleted with the celld admission lifecycle)", async () => {
		// 对全部工具做一轮成功/失败混合调用：任何记录到的 kernel 调用都不得指向
		// 已移除的 celld 准入端点族。
		const context = recordingContext(async (path) => {
			if (path === "/v1/wasm/status") return { applications: [] };
			return { ok: true };
		});
		const attempts: Array<[string, Record<string, unknown>]> = [
			["iweb_workspace_list", {}],
			["iweb_workspace_read_text", { path: "a.txt" }],
			["iweb_workspace_write_text", { path: "a.txt", content: "x" }],
			["iweb_workspace_delete", { path: "a.txt" }],
			["iweb_domain_list", {}],
			["iweb_domain_register", { hostId: "notes", appName: "notes" }],
			["iweb_application_list", {}],
			["iweb_application_admit", { transaction: { schemaVersion: 1 } }],
			["iweb_application_versions", { applicationId: "ghost" }],
			["iweb_application_inspect", { applicationId: "ghost" }]
		];
		for (const [name, args] of attempts) {
			await dispatchTool(name, args, context).catch(() => undefined);
		}
		for (const retired of retiredToolNames) {
			const args = retired === "iweb_application_delete_data" ? { applicationId: "notes" } : { applicationId: "notes", versionId: HEX64 };
			await dispatchTool(retired, args, context).catch(() => undefined);
		}
		expect(context.calls.length).toBeGreaterThan(0);
		expect(context.calls.every((call) => !call.path.startsWith("/v1/applications"))).toBe(true);
	});
});
