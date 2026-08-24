// 用户原始需求（2026-08-14）：activate/rollback 必须由真实 control object 提交：响应携带协议要求的 generation+retired，drain 只在指针落库后运行。
// 正交意图：7.3/7.4 生产控制对象证据——真实文件 ControlStore + 真实 createApplicationControl（而非 stubbed dispatcher 返回值），
// 经 kernel/index.js 使用的同一条路径（handleVersionAction dispatcher + applicationControl.activate/rollback）驱动完整生命周期。
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emptyControlStateFile, validateControlStateFile, type ControlStateFile } from "../packages/contracts/control-db.ts";
import { ControlStore, systemControlStoreIO } from "../packages/contracts/control-store.ts";
import { handleVersionAction } from "../packages/contracts/lifecycle-routes.ts";
import { createApplicationControl } from "../kernel/application-control.js";
import { memoryPackageStore } from "../kernel/package-store.js";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

const resources = { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 };
const policy = { resources, egress: { default: "deny" as const, allow: [] } };
const manifest = {
	schemaVersion: 1 as const,
	name: "notes",
	runtime: { kind: "celld" as const, celldVersion: "0.2.0", entrypoint: "index.js" },
	assets: { root: "app" },
	resources,
	storage: { persistent: false, requestBytes: 0 },
	egress: { default: "deny" as const, allow: [] },
};
const snapshotA = { path: "app/index.js", content: Buffer.from("export default {};\n") };
const snapshotB = { path: "app/index.js", content: Buffer.from("export default { v: 2 };\n") };
const digestA = packageFilesDigest([snapshotA]);
const digestB = packageFilesDigest([snapshotB]);

function productionControl() {
	const directory = mkdtempSync(join(tmpdir(), "iweb-lifecycle-prod-"));
	const controlPath = join(directory, "control.json");
	const secretsPath = join(directory, "control-secrets.json");
	const store = new ControlStore<ControlStateFile>({ io: systemControlStoreIO, path: controlPath, empty: emptyControlStateFile, parse: validateControlStateFile });
	const events: string[] = [];
	const stopped: string[] = [];
	const client = {
		prepare: async (_socket: string, request: Record<string, unknown>) => {
			events.push("prepare:" + request.sandboxId);
			return { version: 1, operation: "prepare", status: "prepared", sandboxId: request.sandboxId };
		},
		start: async (_socket: string, sandboxId: string) => { events.push("start:" + sandboxId); return { version: 1, operation: "start", status: "started", sandboxId }; },
		stop: async (_socket: string, sandboxId: string) => { events.push("stop:" + sandboxId); stopped.push(sandboxId); return { version: 1, operation: "stop", status: "stopped", sandboxId }; },
		inspect: async (_socket: string, sandboxId: string) => { events.push("inspect:" + sandboxId); return { version: 1, operation: "inspect", sandboxId, state: "ready" }; },
		metrics: async () => ({ version: 1, operation: "metrics", sandboxId: "sbx-x", sample: null }),
		remove: async (_socket: string, sandboxId: string) => { events.push("remove:" + sandboxId); return { version: 1, operation: "delete", status: "deleted", sandboxId }; },
		socketGet: async (_socketPath: string, path: string) => {
			const versionId = path.split("versionId=")[1]?.split("&")[0] ?? "";
			const generation = Number(path.split("generation=")[1]?.split("&")[0] ?? 0);
			return { status: 200, body: JSON.stringify({ version: 1, ok: true, versionId, generation }) };
		},
	};
	const instance = createApplicationControl({
		controlStore: store,
		secretsFile: secretsPath,
		supervisorSocket: join(directory, "supervisor.sock"),
		gatewayDirectory: join(directory, "gw"),
		objectEndpoint: "http://10.37.0.1:9000",
		rpcClient: client,
		issueObjectCredential: async (sandboxId: string) => ({
			object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKID-" + sandboxId, secretAccessKey: "SK-" + sandboxId },
			retire: { accessKey: "AKID-" + sandboxId, parentUser: "iweb-sandbox-issuer" },
		}),
		issueDataCredential: async () => ({ endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDDATA", secretAccessKey: "SECRETDATA" }),
		retireObjectCredential: async () => {},
		readiness: { maxAttempts: 2, attemptTimeoutMs: 1000, intervalMs: 0 },
		secretsIo: {
			readFile: (file: string) => { try { return readFileSync(file, "utf8"); } catch { return null; } },
			writeFileAtomic: (file: string, content: string) => { systemControlStoreIO.writeFileAtomic(file, content); },
		},
		packageStore: memoryPackageStore(),
		now: () => Date.now(),
	});
	return { instance, store, client, events, stopped, directory, controlPath };
}

describe("production control object lifecycle (7.3/7.4)", () => {
	test("activate and rollback commit through the REAL control object: the response satisfies the declared union and the pointer is durable before drain", async () => {
		const world = productionControl();
		const { instance, events, controlPath } = world;
		try {
			const first = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
			expect((await handleVersionAction(instance, "notes", first.versionId, "POST", "prepare")).status).toBe(201);
			expect((await handleVersionAction(instance, "notes", first.versionId, "POST", "readiness")).body).toMatchObject({ ready: true });
			const activation1 = await instance.activate("notes", first.versionId);
			expect(activation1).toEqual({ generation: 1, retired: null });

			const second = await instance.admit({ applicationId: "notes", packageDigest: digestB, manifest, policy, snapshotFiles: [snapshotB] });
			expect(second.identity.sequence).toBe(2);
			await handleVersionAction(instance, "notes", second.versionId, "POST", "prepare");
			await handleVersionAction(instance, "notes", second.versionId, "POST", "readiness");
			const activation2 = await instance.activate("notes", second.versionId);
			expect(activation2.generation).toBe(2);
			expect(activation2.retired).toMatch(/^sbx-/);
			const drained = await instance.drainRetired("notes");
			expect(drained).toEqual([activation2.retired]);
			expect(events[events.length - 1]).toBe("stop:" + activation2.retired);

			await instance.probeReady("notes", first.versionId);
			const rollback = await instance.rollback("notes", first.versionId);
			expect(rollback.generation).toBe(3);
			expect(rollback.retired).toMatch(/^sbx-/);
			expect(rollback.retired).not.toBe(activation1.retired ?? "");
			const onDisk = JSON.parse(readFileSync(controlPath, "utf8")) as { applications: Record<string, { active: { kind: string; version: { digest: string }; routeGeneration: number } }> };
			const active = onDisk.applications["notes"].active;
			expect(active.kind).toBe("active");
			expect(active.version.digest).toBe(first.versionId);
			expect(active.routeGeneration).toBe(3);
			const drained2 = await instance.drainRetired("notes");
			expect(drained2).toEqual([rollback.retired]);
		} finally {
			rmSync(world.directory, { recursive: true, force: true });
		}
	});

	test("negative paths: no readiness lease, unknown version, and unleased rollback are bounded coded failures", async () => {
		const world = productionControl();
		const { instance } = world;
		try {
			const first = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
			let caught: unknown = null;
			try { await instance.activate("notes", first.versionId); } catch (error) { caught = error; }
			expect((caught as { code?: string }).code).toBe("NOT_READY");
			caught = null;
			try { await instance.rollback("notes", "f".repeat(64)); } catch (error) { caught = error; }
			expect((caught as { code?: string }).code).toBe("UNKNOWN_VERSION");
			caught = null;
			try { await instance.prepare("notes", "f".repeat(64)); } catch (error) { caught = error; }
			expect((caught as { code?: string }).code).toBe("UNKNOWN_VERSION");
			caught = null;
			try { await instance.rollback("notes", first.versionId); } catch (error) { caught = error; }
			expect((caught as { code?: string }).code).toBe("NOT_READY");
			expect(instance.state().applications["notes"].active.kind).toBe("unavailable");
		} finally {
			rmSync(world.directory, { recursive: true, force: true });
		}
	});
});
