// 用户原始需求（2026-08-14）：协议必须逐变体 round-trip，并在任何 OCI 副作用前拒绝 arbitrary image/command/host path/device/capability/network mode/socket/identifier。
// 正交意图：spy adapter 证明拒绝请求产生零 adapter 调用。
import { describe, expect, test } from "bun:test";
import { handleSupervisorRpc, type SupervisorAdapter } from "../packages/contracts/protocol-server.ts";
import { deriveSandboxId, validateSupervisorRequest, validateSupervisorResponse } from "../packages/contracts/protocol.ts";

const digestA = "a".repeat(64);
const digestB = "b".repeat(64);
const resources = { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 };

function validObject(): Record<string, unknown> {
	return { endpoint: "http://127.0.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTESTEXAMPLE", secretAccessKey: "SECRETTESTEXAMPLE123" };
}

function validPrepare(): Record<string, unknown> {
	return {
		version: 1,
		operation: "prepare",
		sandboxId: deriveSandboxId("app-a", digestB, 7),
		versionIdentity: { applicationId: "app-a", digest: digestB, sequence: 7 },
		packageDigest: digestA,
		policy: { resources, egress: { default: "deny", allow: [{ host: "api.example.com", port: 443 }] } },
		object: validObject(),
	};
}

function validSample(): Record<string, unknown> {
	return {
		versionId: "v1",
		sampledAt: "2026-08-14T00:00:00.000Z",
		cpuMillis: { available: true, value: 1 },
		memoryBytes: { available: true, value: 2 },
		pidCount: { available: true, value: 3 },
		terminated: { available: true, value: 0 },
		limits: resources,
	};
}

function spyAdapter(): { adapter: SupervisorAdapter; calls: string[] } {
	const calls: string[] = [];
	const adapter: SupervisorAdapter = {
		prepare: async (request) => { calls.push("prepare"); return { version: 1, operation: "prepare", status: "prepared", sandboxId: request.sandboxId }; },
		start: async (request) => { calls.push("start"); return { version: 1, operation: "start", status: "started", sandboxId: request.sandboxId }; },
		stop: async (request) => { calls.push("stop"); return { version: 1, operation: "stop", status: "stopped", sandboxId: request.sandboxId }; },
		inspect: async (request) => { calls.push("inspect"); return { version: 1, operation: "inspect", sandboxId: request.sandboxId, state: "ready" }; },
		metrics: async (request) => { calls.push("metrics"); return { version: 1, operation: "metrics", sandboxId: request.sandboxId, sample: { versionId: request.versionId, sampledAt: "2026-08-14T00:00:00.000Z", cpuMillis: { available: true, value: 1 }, memoryBytes: { available: true, value: 2 }, pidCount: { available: true, value: 3 }, terminated: { available: true, value: 0 }, limits: resources } }; },
		delete: async (request) => { calls.push("delete"); return { version: 1, operation: "delete", status: "deleted", sandboxId: request.sandboxId }; },
	};
	return { adapter, calls };
}

function rpc(body: unknown, overrides: { method?: string; path?: string; contentType?: string | null; rawBody?: string } = {}): Parameters<typeof handleSupervisorRpc>[1] {
	return {
		method: overrides.method ?? "POST",
		path: overrides.path ?? "/v1/rpc",
		contentType: overrides.contentType === undefined ? "application/json" : overrides.contentType,
		body: Buffer.from(overrides.rawBody ?? JSON.stringify(body), "utf8"),
	};
}

describe("supervisor protocol", () => {
	test("round-trips every request variant", () => {
		expect(validateSupervisorRequest(validPrepare()).ok).toBe(true);
			for (const operation of ["start", "stop", "inspect", "delete"] as const) {
				expect(validateSupervisorRequest({ version: 1, operation, sandboxId: validPrepare().sandboxId }).ok).toBe(true);
			}
			expect(validateSupervisorRequest({ version: 1, operation: "metrics", sandboxId: validPrepare().sandboxId, versionId: "version-a-7" }).ok).toBe(true);
	});

	test("prepare carries the optional application data-plane provisioning", () => {
		const withData = { ...validPrepare(), storageSecret: "s".repeat(48), data: validObject() };
		const result = validateSupervisorRequest(withData);
		expect(result.ok).toBe(true);
		if (result.ok) {
			const value = result.value as { storageSecret?: string; data?: { accessKeyId: string } };
			expect(value.storageSecret).toBe("s".repeat(48));
			expect(value.data?.accessKeyId).toBe("AKIDTESTEXAMPLE");
		}
		// a too-short storage secret is rejected before any adapter dispatch
		expect(validateSupervisorRequest({ ...validPrepare(), storageSecret: "short" }).ok).toBe(false);
	});

	test("round-trips every response variant", () => {
		expect(validateSupervisorResponse({ version: 1, operation: "prepare", status: "prepared", sandboxId: "s1" }).ok).toBe(true);
		expect(validateSupervisorResponse({ version: 1, operation: "start", status: "started", sandboxId: "s1" }).ok).toBe(true);
		expect(validateSupervisorResponse({ version: 1, operation: "stop", status: "stopped", sandboxId: "s1" }).ok).toBe(true);
		expect(validateSupervisorResponse({ version: 1, operation: "delete", status: "deleted", sandboxId: "s1" }).ok).toBe(true);
		expect(validateSupervisorResponse({ version: 1, operation: "inspect", sandboxId: "s1", state: "ready" }).ok).toBe(true);
		expect(validateSupervisorResponse({ version: 1, operation: "metrics", sandboxId: "s1", sample: validSample() }).ok).toBe(true);
	});

	test("rejects invalid object credentials before adapter dispatch", async () => {
		const { adapter, calls } = spyAdapter();
		const badCredentials: Record<string, unknown>[] = [
			{ endpoint: "http://127.0.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTESTEXAMPLE", secretAccessKey: "x\nsecret" },
			{ endpoint: "http://127.0.0.1:9000/path", region: "us-east-1", accessKeyId: "AKIDTESTEXAMPLE", secretAccessKey: "SECRETTESTEXAMPLE123" },
			{ endpoint: "file:///etc/passwd", region: "us-east-1", accessKeyId: "AKIDTESTEXAMPLE", secretAccessKey: "SECRETTESTEXAMPLE123" },
			{ endpoint: "http://127.0.0.1:9000", region: "US-EAST", accessKeyId: "AKIDTESTEXAMPLE", secretAccessKey: "SECRETTESTEXAMPLE123" },
		];
		for (const object of badCredentials) {
			const response = await handleSupervisorRpc(adapter, rpc({ ...validPrepare(), object }));
			expect(response.status).toBe(400);
			expect(JSON.parse(response.body).code).toBe("INVALID_REQUEST");
		}
		expect(calls).toEqual([]);
	});

	test("rejects arbitrary image, command, host path, device, capability, network mode, and socket fields", async () => {
		const { adapter, calls } = spyAdapter();
		const dangerousFields: Record<string, unknown>[] = [
			{ image: "alpine:latest" },
			{ command: ["sh", "-c", "id"] },
			{ hostPath: "/etc/passwd" },
			{ device: "/dev/sda" },
			{ capabilities: ["CAP_SYS_ADMIN"] },
			{ networkMode: "host" },
			{ socket: "/run/docker.sock" },
		];
		for (const field of dangerousFields) {
			const response = await handleSupervisorRpc(adapter, rpc({ ...validPrepare(), ...field }));
			expect(response.status).toBe(400);
			expect(JSON.parse(response.body).code).toBe("INVALID_REQUEST");
		}
		expect(calls).toEqual([]);
	});

	test("rejects an unsafe or reserved identifier before adapter dispatch", async () => {
		const { adapter, calls } = spyAdapter();
		const traversal = await handleSupervisorRpc(adapter, rpc({ ...validPrepare(), sandboxId: "../../etc/passwd" }));
		expect(traversal.status).toBe(400);
		const reserved = await handleSupervisorRpc(adapter, rpc({ ...validPrepare(), sandboxId: "kernel" }));
		expect(reserved.status).toBe(400);
		expect(JSON.parse(reserved.body).issues?.[0]?.code).toBe("RESERVED_IDENTIFIER");
		expect(calls).toEqual([]);
	});

	test("validates framing, body size, content type, and JSON before the adapter", async () => {
		const { adapter, calls } = spyAdapter();
		const wrongMethod = await handleSupervisorRpc(adapter, rpc(validPrepare(), { method: "GET" }));
		expect(wrongMethod.status).toBe(404);
		const wrongPath = await handleSupervisorRpc(adapter, rpc(validPrepare(), { path: "/v1/health" }));
		expect(wrongPath.status).toBe(404);
		const tooLarge = await handleSupervisorRpc(adapter, rpc({}, { rawBody: "x".repeat(70000) }));
		expect(tooLarge.status).toBe(413);
		const wrongType = await handleSupervisorRpc(adapter, rpc(validPrepare(), { contentType: "text/plain" }));
		expect(wrongType.status).toBe(415);
		const badJson = await handleSupervisorRpc(adapter, rpc({}, { rawBody: "not-json" }));
		expect(badJson.status).toBe(400);
		expect(calls).toEqual([]);
	});

	test("dispatches a valid request exactly once to the matching adapter method", async () => {
		const { adapter, calls } = spyAdapter();
		const response = await handleSupervisorRpc(adapter, rpc(validPrepare()));
		expect(response.status).toBe(200);
		expect(JSON.parse(response.body).operation).toBe("prepare");
		expect(calls).toEqual(["prepare"]);
	});
});


describe("adapter response validation and identity contract", () => {
	function adapterWith(overrides: Partial<SupervisorAdapter>): SupervisorAdapter {
		const { adapter } = spyAdapter();
		return { ...adapter, ...overrides };
	}

	test("returns a fixed 500 for an adapter response with the wrong status variant", async () => {
		const adapter = adapterWith({
			prepare: async (request) => ({ version: 1, operation: "prepare", status: "deleted", sandboxId: request.sandboxId } as never),
		});
		const response = await handleSupervisorRpc(adapter, rpc(validPrepare()));
		expect(response.status).toBe(500);
		expect(JSON.parse(response.body).code).toBe("ADAPTER_RESPONSE_INVALID");
		expect(response.body).not.toContain("deleted");
	});

	test("returns a fixed 500 for an adapter response with a mismatched sandbox identity", async () => {
		const adapter = adapterWith({
			prepare: async () => ({ version: 1, operation: "prepare", status: "prepared", sandboxId: "other-sandbox" }),
		});
		const response = await handleSupervisorRpc(adapter, rpc(validPrepare()));
		expect(response.status).toBe(500);
		expect(JSON.parse(response.body).code).toBe("ADAPTER_RESPONSE_INVALID");
	});

	test("does not reflect adapter exception text or secrets", async () => {
		const secret = "IWEB_API_TOKEN=super_secret_value";
		const adapter = adapterWith({
			prepare: async () => {
				throw new Error("boom " + secret);
			},
		});
		const response = await handleSupervisorRpc(adapter, rpc(validPrepare()));
		expect(response.status).toBe(500);
		expect(JSON.parse(response.body).code).toBe("ADAPTER_ERROR");
		expect(response.body).not.toContain(secret);
		expect(response.body).not.toContain("boom");
	});

	test("rejects a sandbox identity not derived from the version identity with zero adapter calls", async () => {
		const { adapter, calls } = spyAdapter();
		const mismatched = { ...validPrepare(), sandboxId: "app-a-v99" };
		const response = await handleSupervisorRpc(adapter, rpc(mismatched));
		expect(response.status).toBe(400);
		expect(JSON.parse(response.body).issues?.[0]?.code).toBe("IDENTITY_MISMATCH");
		expect(calls).toEqual([]);
	});

	test("derives distinct sandbox identities for conflicting immutable version digests", () => {
		expect(deriveSandboxId("app-a", digestA, 7)).not.toBe(deriveSandboxId("app-a", digestB, 7));
	});

	test("returns a fixed 500 when metrics identify a different version", async () => {
		const adapter = adapterWith({
			metrics: async (request) => ({ version: 1, operation: "metrics", sandboxId: request.sandboxId, sample: { ...validSample(), versionId: "other-version" } }),
		});
		const request = { version: 1, operation: "metrics", sandboxId: validPrepare().sandboxId, versionId: "version-a-7" };
		const response = await handleSupervisorRpc(adapter, rpc(request));
		expect(response.status).toBe(500);
		expect(JSON.parse(response.body).code).toBe("ADAPTER_RESPONSE_INVALID");
	});
});
