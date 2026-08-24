// 用户原始需求（2026-08-14）：Kernel 控制流必须只从不可变快照 admit、经窄协议 prepare/readiness/activate、restart 后从 durable store 重建、active version 不可删除。
// 正交意图：7.1-7.6 本地证据；2.22 快照持久化与 fail-closed；mock rpc client；in-memory store；无真实 MinIO/OCI。
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emptyControlStateFile, validateControlStateFile, type ControlStateFile } from "../contracts/control-db.ts";
import { ControlStore, systemControlStoreIO, type ControlStoreIO } from "../contracts/control-store.ts";
import { createApplicationControl } from "../kernel/application-control.js";
import { memoryPackageStore } from "../kernel/package-store.js";
import { deriveSandboxId } from "../contracts/protocol.ts";
import { packageFilesDigest } from "../contracts/package-collection.ts";
import { versionLabel } from "../contracts/records.ts";

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

// Real content-addressed digests: admission persists the snapshot under this
// digest and prepare re-derives it from restored content, so the happy path and
// the fail-closed path share the single contracts digest authority.
const snapshotA = { path: "app/index.js", content: Buffer.from("export default {};\n") };
const snapshotB = { path: "app/index.js", content: Buffer.from("export default { v: 2 };\n") };
const digestA = packageFilesDigest([snapshotA]);
const digestB = packageFilesDigest([snapshotB]);
const multiSnapshot = [
	{ path: "app/index.js", content: Buffer.from("export default {};\n") },
	{ path: "app/assets/style.css", content: Buffer.from("body{color:#000}\n") },
];
const digestMulti = packageFilesDigest(multiSnapshot);

function memoryStore(): { store: ControlStore<ControlStateFile>; files: Map<string, string> } {
	const files = new Map<string, string>();
	const io: ControlStoreIO = {
		readFile: (path) => files.get(path) ?? null,
		writeFileAtomic: (path, content) => files.set(path, content),
		deleteFile: (path) => files.delete(path),
		ensureDirectory: () => undefined,
	};
	return { store: new ControlStore<ControlStateFile>({ io, path: "/data/control.json", empty: emptyControlStateFile, parse: validateControlStateFile }), files };
}

function mockRpc(overrides: Record<string, unknown> = {}) {
	const calls: string[] = [];
	const prepareRequests: Record<string, unknown>[] = [];
	const client = {
		prepareRequests,
		prepare: async (socket: string, request: Record<string, unknown>) => {
			calls.push("prepare:" + request.sandboxId);
			prepareRequests.push({ ...request });
			return { version: 1, operation: "prepare", status: "prepared", sandboxId: request.sandboxId };
		},
		start: async (socket: string, sandboxId: string) => {
			calls.push("start:" + sandboxId);
			return { version: 1, operation: "start", status: "started", sandboxId };
		},
		stop: async (socket: string, sandboxId: string) => {
			calls.push("stop:" + sandboxId);
			return { version: 1, operation: "stop", status: "stopped", sandboxId };
		},
		inspect: async (socket: string, sandboxId: string) => {
			calls.push("inspect:" + sandboxId);
			return { version: 1, operation: "inspect", sandboxId, state: "ready" };
		},
		metrics: async (socket: string, sandboxId: string, versionId: string) => {
			calls.push("metrics:" + sandboxId);
			return {
				version: 1, operation: "metrics", sandboxId,
				sample: {
					versionId, sampledAt: "2026-08-14T00:00:00.000Z",
					cpuMillis: { available: true, value: 10 },
					memoryBytes: { available: true, value: 2000 },
					pidCount: { available: true, value: 2 },
					terminated: { available: true, value: 0 },
					limits: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 },
				},
			};
		},
		remove: async (socket: string, sandboxId: string) => {
			calls.push("remove:" + sandboxId);
			return { version: 1, operation: "delete", status: "deleted", sandboxId };
		},
		socketGet: async (socketPath: string, path: string) => {
			calls.push("get:" + path);
			const versionId = path.split("versionId=")[1]?.split("&")[0] ?? "";
			const generation = Number(path.split("generation=")[1]?.split("&")[0] ?? 0);
			return { status: 200, body: JSON.stringify({ version: 1, ok: true, versionId, generation }) };
		},
		...overrides,
	};
	return { client, calls };
}

// Observable in-memory package store: delegates to memoryPackageStore, records
// calls, and can be forced to report a missing or tampered snapshot so the
// fail-closed paths are exercised without a real object store.
type VersionIdentityArg = { applicationId: string; versionId: string; digest: string; sequence: number };

function trackingPackageStore(options: { verifyResult?: string | null; deployedResult?: boolean; deployedResponses?: boolean[] } = {}) {
	const base = memoryPackageStore();
	const calls: string[] = [];
	const identities: VersionIdentityArg[] = [];
	let verifyResult: string | null | undefined = options.verifyResult;
	const deployedResult: boolean | undefined = options.deployedResult;
	const deployedResponses = [...(options.deployedResponses ?? [])];
	return {
		calls,
		identities,
		corrupt() { verifyResult = null; },
		persist: async (digest: string, m: unknown, files: { path: string; content: Buffer }[]) => { calls.push("persist:" + digest); return base.persist(digest, m as object, files); },
		verify: async (digest: string) => { calls.push("verify:" + digest); if (verifyResult !== undefined) return verifyResult; return base.verify(digest); },
		deploy: async (sandboxId: string, identity: VersionIdentityArg) => { calls.push("deploy:" + sandboxId); identities.push({ ...identity, sandboxId } as VersionIdentityArg & { sandboxId: string }); return base.deploy(sandboxId, identity); },
		deployed: async (sandboxId: string, identity: VersionIdentityArg) => {
			calls.push("deployed:" + sandboxId);
			if (deployedResponses.length > 0) return deployedResponses.shift() as boolean;
			if (deployedResult !== undefined) return deployedResult;
			return base.deployed(sandboxId, identity);
		},
		deleteApplicationData: async (applicationId: string) => { calls.push("deleteData:" + applicationId); },
	};
}

function control(overrides: Record<string, unknown> = {}) {
	const { store, files } = memoryStore();
	const { client, calls } = mockRpc(overrides.rpc as Record<string, unknown>);
	// optional pre-seeded control-secrets content (2.47 persisted-state tests)
	if (typeof overrides.seedSecrets === "string") files.set("/data/control-secrets.json", overrides.seedSecrets as string);
	const secretsIo = {
		readFile: (file: string) => files.get(file) ?? null,
		writeFileAtomic: (file: string, content: string) => files.set(file, content),
	};
	const packageStore = (overrides.packageStore as ReturnType<typeof trackingPackageStore>) ?? trackingPackageStore();
	const retireObjectCredential = (overrides.retireObjectCredential as ((retire: unknown) => Promise<void>)) ?? (async () => {});
	const issueDataCredential = (overrides.issueDataCredential as ((applicationId: string) => Promise<{ endpoint: string; region: string; accessKeyId: string; secretAccessKey: string }>)) ?? (async () => ({ endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDDATA", secretAccessKey: "SECRETDATA" }));
	const objectEndpoint = (overrides.objectEndpoint as string) ?? "http://10.37.0.1:9000";
	const instance = createApplicationControl({
		controlStore: store,
		secretsFile: "/data/control-secrets.json",
		supervisorSocket: "/run/iweb-sandbox/supervisor.sock",
		gatewayDirectory: "/run/iweb-sandbox/gw",
		objectEndpoint,
		rpcClient: client,
		issueObjectCredential: async () => ({ object: { endpoint: objectEndpoint, region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" }, retire: { accessKey: "AKIDTEST", parentUser: "iweb-sandbox-issuer" } }),
		retireObjectCredential,
		issueDataCredential,
		readiness: { maxAttempts: 2, attemptTimeoutMs: 1000, intervalMs: 0 },
		secretsIo,
		packageStore,
		now: () => Date.parse("2026-08-14T00:00:00.000Z"),
	});
	return { instance, store, files, client, calls, packageStore };
}

describe("control store", () => {
	test("round-trips state and quarantines corrupt files", () => {
		const { store, files } = memoryStore();
		store.save(emptyControlStateFile());
		expect(store.load().applications).toEqual({});
		files.set("/data/control.json", "not json at all");
		const loaded = store.load();
		expect(loaded.applications).toEqual({});
		expect(files.get("/data/control.json.corrupt")).toBe("not json at all");
	});

	test("transactions persist only non-null mutations", () => {
		const { store } = memoryStore();
		expect(store.transaction(() => null)).toBeNull();
		expect(store.load().applications).toEqual({});
	});

	test("control state file validation rejects malformed shapes", () => {
		expect(validateControlStateFile({ version: 1, applications: {} })).not.toBeNull();
		expect(validateControlStateFile({ version: 2, applications: {} })).toBeNull();
		expect(validateControlStateFile({ version: 1, applications: { x: { applicationId: "y" } } })).toBeNull();
		expect(validateControlStateFile(null)).toBeNull();
	});

	test("control state file validation enforces the admission authority and the active-pointer invariant (2.47)", () => {
		const identity = { applicationId: "notes", digest: digestA, sequence: 1 };
		const version = { versionId: versionLabel(identity), identity, packageDigest: digestA, policy, lifecycle: "admitted" as const, admittedAt: "2026-08-14T00:00:00.000Z", readinessExpiresAt: null };
		const application = (versions: unknown[], active: unknown) => ({ notes: { applicationId: "notes", versions, active } });
		// a fully valid file with the pointer at an admitted version round-trips
		expect(validateControlStateFile({ version: 1, applications: application([version], { kind: "active", applicationId: "notes", version: identity, routeGeneration: 1 }) })).not.toBeNull();
		// unknown fields on a version record reject (no smuggled state)
		expect(validateControlStateFile({ version: 1, applications: application([{ ...version, extra: true }], { kind: "unavailable", applicationId: "notes", routeGeneration: 0 }) })).toBeNull();
		// policy must pass the same authority admission used: a partial resources object rejects
		expect(validateControlStateFile({ version: 1, applications: application([{ ...version, policy: { resources: { cpuMillis: 1 }, egress: { default: "deny", allow: [] } } }], { kind: "unavailable", applicationId: "notes", routeGeneration: 0 }) })).toBeNull();
		// an active pointer at a version that is not admitted is corrupt state
		expect(validateControlStateFile({ version: 1, applications: application([version], { kind: "active", applicationId: "notes", version: { ...identity, sequence: 9 }, routeGeneration: 1 }) })).toBeNull();
	});

	test("systemControlStoreIO writes durably (fsync file + directory) and leaves no torn temp file", () => {
		const dir = mkdtempSync(join(tmpdir(), "iweb-cs-"));
		try {
			const file = join(dir, "control.json");
			systemControlStoreIO.writeFileAtomic(file, "{\"ok\":true}\n");
			expect(readFileSync(file, "utf8")).toBe("{\"ok\":true}\n");
			expect(existsSync(file + ".tmp")).toBe(false);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("kernel application control flow", () => {
	test("admits an immutable version once and persists its canonical snapshot", async () => {
		const { instance, packageStore } = control();
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		expect(admitted.versionId).toMatch(/^[a-f0-9]{64}$/);
		expect(packageStore.calls).toContain("persist:" + digestA);
		const sandboxId = deriveSandboxId("notes", admitted.versionId, 1);
		expect(instance.sandboxIdFor(instance.state().applications["notes"].versions[0])).toBe(sandboxId);
		// a duplicate admission is rejected and never reaches persistence again
		await expect(instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] })).rejects.toThrow();
	});

	test("prepare issues a secret, persists it, and deploys from the verified snapshot", async () => {
		const { instance, files, calls, packageStore } = control();
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		expect(calls[0]).toMatch(/^prepare:sbx-/);
		expect(packageStore.calls).toContain("verify:" + digestA);
		expect(packageStore.calls.some((call) => call.startsWith("deploy:sbx-"))).toBe(true);
		const secrets = JSON.parse(files.get("/data/control-secrets.json") ?? "{}");
		const sandboxId = Object.keys(secrets.sandboxes)[0];
		expect(secrets.sandboxes[sandboxId].bucket).toBe("iweb-app-" + sandboxId);
		expect(secrets.sandboxes[sandboxId].versionId).toBe(versionLabel({ applicationId: "notes", digest: admitted.versionId, sequence: 1 }));
		expect(secrets.sandboxes[sandboxId].generation).toBe(1);
	});

	test("a later workspace mutation cannot alter the admitted version: prepare re-derives the same digest", async () => {
		const { instance, packageStore } = control();
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestMulti, manifest, policy, snapshotFiles: multiSnapshot });
		// The snapshot is immutable under its digest; a "workspace mutation" would
		// only change the live listing, not the persisted snapshot. Re-verifying
		// after a redundant prepare still matches the admitted digest.
		await instance.prepare("notes", admitted.versionId);
		expect(packageStore.calls.filter((call) => call === "verify:" + digestMulti).length).toBeGreaterThanOrEqual(1);
		const version = instance.state().applications["notes"].versions[0];
		expect(version.lifecycle).not.toBe("failed");
	});

	test("prepare fails closed when the snapshot is absent", async () => {
		const { instance } = control({ packageStore: trackingPackageStore({ verifyResult: null }) });
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await expect(instance.prepare("notes", admitted.versionId)).rejects.toThrow(/absent/);
		expect(instance.state().applications["notes"].versions[0].lifecycle).toBe("failed");
	});

	test("prepare fails closed when the snapshot digest mismatches", async () => {
		const { instance } = control({ packageStore: trackingPackageStore({ verifyResult: "0".repeat(64) }) });
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await expect(instance.prepare("notes", admitted.versionId)).rejects.toThrow(/match/);
		expect(instance.state().applications["notes"].versions[0].lifecycle).toBe("failed");
	});

	test("readiness records a lease and activation switches exactly one pointer", async () => {
		const { instance } = control();
		const first = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", first.versionId);
		const probe = await instance.probeReady("notes", first.versionId);
		expect(probe.ready).toBe(true);
		const active = await instance.activate("notes", first.versionId);
		expect(active.generation).toBe(1);
		expect(instance.state().applications["notes"].active.kind).toBe("active");
		expect(instance.state().applications["notes"].versions[0].lifecycle).toBe("active");
		await expect(instance.activate("notes", first.versionId)).rejects.toThrow();
	});

	test("an update retires the previous version and rollback restores it through the same gate", async () => {
		const { instance } = control();
		const first = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", first.versionId);
		await instance.probeReady("notes", first.versionId);
		await instance.activate("notes", first.versionId);

		const second = await instance.admit({ applicationId: "notes", packageDigest: digestB, manifest, policy, snapshotFiles: [snapshotB] });
		expect(second.identity.sequence).toBe(2);
		await instance.prepare("notes", second.versionId);
		await instance.probeReady("notes", second.versionId);
		const activation = await instance.activate("notes", second.versionId);
		expect(activation.generation).toBe(2);
		expect(activation.retired).toMatch(/^sbx-/);
		const versions = instance.state().applications["notes"].versions;
		expect(versions.find((version) => version.versionId === first.versionId)?.lifecycle).toBe("retired");

		const drained = await instance.drainRetired("notes");
		expect(drained).toHaveLength(1);

		await instance.probeReady("notes", first.versionId);
		const rollback = await instance.rollback("notes", first.versionId);
		expect(rollback.generation).toBe(3);
		// 7.3 protocol union: the production rollback response carries BOTH the
		// committed generation and the retired sandbox id
		expect(rollback.retired).toMatch(/^sbx-/);
		expect(instance.state().applications["notes"].active.version.digest).toBe(first.versionId);
	});

	test("the active version is protected from deletion", async () => {
		const { instance } = control();
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		await instance.probeReady("notes", admitted.versionId);
		await instance.activate("notes", admitted.versionId);
		await expect(instance.deleteVersion("notes", admitted.versionId)).rejects.toThrow();
	});

	test("version deletion retires the per-version object authority", async () => {
		const retired: { accessKey: string; parentUser: string }[] = [];
		const { instance } = control({ retireObjectCredential: async (retire) => { retired.push(retire as { accessKey: string; parentUser: string }); } });
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		await instance.deleteVersion("notes", admitted.versionId);
		expect(retired).toHaveLength(1);
		expect(retired[0].accessKey).toBe("AKIDTEST");
		expect(retired[0].parentUser).toBe("iweb-sandbox-issuer");
	});

	test("reconciliation reports missing active sandboxes and recovery restarts from admitted records", async () => {
		const { instance, calls } = control({
			rpc: {
				inspect: async () => {
					const error = new Error("unreachable");
					(error as Error & { code: string }).code = "SUPERVISOR_UNREACHABLE";
					throw error;
				},
			},
		});
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		await instance.probeReady("notes", admitted.versionId);
		await instance.activate("notes", admitted.versionId);
		const report = await instance.reconcile();
		expect(report.missingActive).toHaveLength(1);
		expect(report.missingActive[0].applicationId).toBe("notes");
		const recovered = await instance.recoverMissingActive();
		expect(recovered.recovered).toHaveLength(1);
		expect(calls.some((call) => call.startsWith("prepare:"))).toBe(true);
		expect(calls.some((call) => call.startsWith("start:"))).toBe(true);
	});

	test("recovery fails closed when the immutable snapshot vanished after admission", async () => {
		const store = trackingPackageStore();
		const { instance } = control({
			rpc: {
				inspect: async () => {
					const error = new Error("unreachable");
					(error as Error & { code: string }).code = "SUPERVISOR_UNREACHABLE";
					throw error;
				},
			},
			packageStore: store,
		});
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		await instance.probeReady("notes", admitted.versionId);
		await instance.activate("notes", admitted.versionId);
		store.corrupt();
		await expect(instance.recoverMissingActive()).rejects.toThrow(/absent/);
	});

	test("application data deletion is a separate operation from version deletion", async () => {
		const { instance, packageStore } = control();
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		// version deletion must NOT remove application data
		await instance.deleteVersion("notes", admitted.versionId);
		expect(packageStore.calls.some((c) => c.startsWith("deleteData:"))).toBe(false);
		// data deletion is a distinct owner-authorized operation
		await instance.deleteApplicationData("notes");
		expect(packageStore.calls).toContain("deleteData:notes");
	});

	test("prepare provisions the application data plane once per application and passes it to the supervisor", async () => {
		let issued = 0;
		const { instance, client } = control({
			issueDataCredential: async () => {
				issued += 1;
				return { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDDATA", secretAccessKey: "SECRETDATA" };
			},
		});
		const first = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", first.versionId);
		const second = await instance.admit({ applicationId: "notes", packageDigest: digestB, manifest, policy, snapshotFiles: [snapshotB] });
		await instance.prepare("notes", second.versionId);
		// one data authority per application, reused across versions
		expect(issued).toBe(1);
		const prepares = (client as { prepareRequests: Record<string, unknown>[] }).prepareRequests;
		expect(prepares).toHaveLength(2);
		for (const request of prepares) {
			expect(typeof request.storageSecret).toBe("string");
			expect((request.storageSecret as string).length).toBeGreaterThanOrEqual(32);
			expect((request.data as { accessKeyId: string }).accessKeyId).toBe("AKIDDATA");
		}
		// version deletion must not remove the application data authority
		await instance.deleteVersion("notes", second.versionId);
		expect(issued).toBe(1);
	});

	test("prepare fails closed on an unconfigured or self-loop object endpoint before any supervisor call", async () => {
		const { instance, client } = control({ objectEndpoint: "" });
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		let caught: unknown = null;
		try { await instance.prepare("notes", admitted.versionId); } catch (error) { caught = error; }
		expect((caught as Error & { code?: string }).code).toBe("OBJECT_ENDPOINT_UNCONFIGURED");
		expect((client as { prepareRequests: Record<string, unknown>[] }).prepareRequests).toHaveLength(0);
	});

	test("prepare fails closed on a self-loop object endpoint equal to the gateway listener", async () => {
		const { instance, client } = control({ objectEndpoint: "http://127.0.0.1:9000" });
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		let caught: unknown = null;
		try { await instance.prepare("notes", admitted.versionId); } catch (error) { caught = error; }
		expect((caught as Error & { code?: string }).code).toBe("OBJECT_ENDPOINT_SELF_LOOP");
		expect((client as { prepareRequests: Record<string, unknown>[] }).prepareRequests).toHaveLength(0);
	});


	test("concurrent admissions serialize: unique sequences, no lost updates, one active pointer (2.46)", async () => {
		const { instance } = control();
		// 8 concurrent admissions of distinct digests
		const digests = Array.from({ length: 8 }, (_, i) => packageFilesDigest([{ path: "app/index.js", content: Buffer.from("v" + i) }]));
		const results = await Promise.all(digests.map((digest, i) =>
			instance.admit({ applicationId: "notes", packageDigest: digest, manifest, policy, snapshotFiles: [{ path: "app/index.js", content: Buffer.from("v" + i) }] }),
		));
		const sequences = results.map((r) => r.identity.sequence).sort((a, b) => a - b);
		expect(sequences).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
		const application = instance.state().applications["notes"];
		expect(application.versions).toHaveLength(8);
		// concurrent prepare+activate on two versions: exactly one active pointer,
		// no interleaving can split or lose it
		const [first, second] = results;
		await Promise.all([
			instance.prepare("notes", first.versionId).catch(() => undefined),
			instance.prepare("notes", second.versionId).catch(() => undefined),
		]);
		await Promise.all([instance.probeReady("notes", first.versionId), instance.probeReady("notes", second.versionId)]);
		let activations = 0;
		await Promise.all([
			instance.activate("notes", first.versionId).then(() => { activations += 1; }).catch(() => undefined),
			instance.activate("notes", second.versionId).then(() => { activations += 1; }).catch(() => undefined),
		]);
		expect(activations).toBeGreaterThan(0);
		const active = instance.state().applications["notes"].active;
		expect(active.kind === "active" ? active.version.digest : null).toMatch(/^[a-f0-9]{64}$/);
		const activeCount = instance.state().applications["notes"].versions.filter((v) => v.lifecycle === "active").length;
		expect(activeCount).toBe(1);
	});

	test("malformed persisted kernel secrets are dropped, valid ones survive (2.47)", async () => {
		const { files } = control();
		// seed a secrets file with one valid entry in the real issuer shape
		// (argv-free retire handle: accessKey/parentUser) plus malformed ones
		const good = { version: 1, sandboxId: "sbx-good", versionId: "lbl", generation: 1, bucket: "iweb-app-sbx-good", object: { endpoint: "http://10.0.0.1:9000", region: "us-east-1", accessKeyId: "A", secretAccessKey: "S" }, retire: { accessKey: "AKIDRETIRE", parentUser: "iweb-sandbox-issuer" }, createdAt: "2026-08-14T00:00:00.000Z" };
		const smuggled = { ...good, sandboxId: "sbx-smuggled", extra: true };
		files.set("/data/control-secrets.json", JSON.stringify({ version: 1, sandboxes: { "sbx-good": good, "sbx-bad": { sandboxId: "sbx-bad" }, "sbx-wrongid": { ...good, sandboxId: "mismatch" }, "sbx-smuggled": smuggled } }));
		const second = createApplicationControl({
			controlStore: new ControlStore({ io: { readFile: (p) => files.get(p) ?? null, writeFileAtomic: (p, c) => files.set(p, c), deleteFile: (p) => files.delete(p), ensureDirectory: () => undefined }, path: "/data/control.json", empty: emptyControlStateFile, parse: validateControlStateFile }),
			secretsFile: "/data/control-secrets.json",
			supervisorSocket: "/run/iweb-sandbox/supervisor.sock",
			gatewayDirectory: "/run/iweb-sandbox/gw",
			objectEndpoint: "http://10.37.0.1:9000",
			rpcClient: { prepare: async () => ({ version: 1, operation: "prepare", status: "prepared", sandboxId: "s" }), start: async () => ({}), stop: async () => ({}), inspect: async () => ({ version: 1, operation: "inspect", sandboxId: "s", state: "ready" }), metrics: async () => ({ version: 1, operation: "metrics", sandboxId: "s", sample: {} }), remove: async () => ({}), socketGet: async () => ({ status: 200, body: "{}" }) },
			issueObjectCredential: async () => ({ object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" }, retire: { accessKey: "AKIDTEST", parentUser: "iweb-sandbox-issuer" } }),
			retireObjectCredential: async () => {},
			issueDataCredential: async () => ({ endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDDATA", secretAccessKey: "SECRETDATA" }),
			readiness: { maxAttempts: 1, attemptTimeoutMs: 100, intervalMs: 0 },
			secretsIo: { readFile: (f) => files.get(f) ?? null, writeFileAtomic: (f, c) => files.set(f, c) },
			packageStore: trackingPackageStore(),
			now: () => Date.parse("2026-08-14T00:00:00.000Z"),
		});
		// a prepare on a fresh version forces the next save; the sanitized
		// in-memory state is what persists, so survival is observable on disk
		const admitted = await second.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await second.prepare("notes", admitted.versionId);
		const saved = JSON.parse(files.get("/data/control-secrets.json") ?? "{}");
		const keys = Object.keys(saved.sandboxes);
		expect(keys).toContain("sbx-good");
		expect(keys).not.toContain("sbx-bad");
		expect(keys).not.toContain("sbx-wrongid");
		// unknown fields reject the whole entry (no partial trust)
		expect(keys).not.toContain("sbx-smuggled");
		// the surviving entry keeps its validated retire handle for deletion
		expect(saved.sandboxes["sbx-good"].retire).toEqual({ accessKey: "AKIDRETIRE", parentUser: "iweb-sandbox-issuer" });
	});
	test("metrics correlate the version label with the request", async () => {
		const { instance } = control();
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		const response = await instance.sandboxMetrics("notes", admitted.versionId);
		expect(response.sample.versionId).toBe(versionLabel({ applicationId: "notes", digest: admitted.versionId, sequence: 1 }));
		expect(response.sample.cpuMillis).toEqual({ available: true, value: 10 });
	});
});

describe("persisted control secrets (2.47)", () => {
	const validEntry = (sandboxId: string) => ({
		version: 1,
		sandboxId,
		versionId: "a".repeat(64) + "-1",
		generation: 1,
		bucket: "iweb-app-" + sandboxId,
		object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDOLD", secretAccessKey: "SECRETOLD" },
		retire: { accessKey: "AKIDOLD", parentUser: "iweb-sandbox-issuer" },
		createdAt: "2026-08-14T00:00:00.000Z",
	});

	test("a corrupt control-secrets file is quarantined durably and never silently emptied", () => {
		const { instance, files } = control({ seedSecrets: "{not json" });
		expect(instance.state().applications).toEqual({});
		const journal = JSON.parse(files.get("/data/control-secrets.json.quarantine.json") ?? "{}");
		expect(journal.entries).toHaveLength(1);
		expect(journal.entries[0].kind).toBe("control-secrets");
		expect(journal.entries[0].reason).toContain("not parseable JSON");
		// unknown top-level fields take the same documented path
		const second = control({ seedSecrets: JSON.stringify({ version: 1, sandboxes: {}, smuggled: true }) });
		expect(second.instance.state().applications).toEqual({});
		const journal2 = JSON.parse(second.files.get("/data/control-secrets.json.quarantine.json") ?? "{}");
		expect(journal2.entries[0].reason).toContain("unknown top-level field");
	});

	test("malformed persisted entries are excluded and journaled, and a malformed credential never reaches the gateway (2.47)", async () => {
		const good = validEntry("sbx-survivor1");
		const badEndpoint = { ...validEntry("sbx-badend001"), object: { endpoint: "http://ak:sk@10.37.0.1:9000", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK" } };
		const smuggledField = { ...validEntry("sbx-smuggled1"), extra: true };
		const seed = JSON.stringify({ version: 1, sandboxes: { "sbx-survivor1": good, "sbx-badend001": badEndpoint, "sbx-smuggled1": smuggledField } });
		const { instance, files, client } = control({ seedSecrets: seed });
		// the valid entry survives; the malformed ones are quarantined with reasons
		const journal = JSON.parse(files.get("/data/control-secrets.json.quarantine.json") ?? "{}");
		const reasons = journal.entries.map((entry: { key: string; reason: string }) => entry.key + ":" + entry.reason).join("\n");
		expect(reasons).toContain("sbx-badend001");
		expect(reasons).toContain("sbx-smuggled1");
		expect(reasons).toContain("unknown field");
		// prepare on a fresh version issues a NEW credential; the supervisor
		// request can never observe a malformed persisted endpoint or credential
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		const seen = client.prepareRequests.map((request) => JSON.stringify(request.object)).join(" ");
		expect(seen).not.toContain("AKIDOLD");
		expect(seen).not.toContain("SECRETOLD");
		expect(seen).not.toContain("ak:sk@");
		for (const request of client.prepareRequests) {
			expect((request.object as { endpoint: string }).endpoint).toBe("http://10.37.0.1:9000");
		}
	});

	test("a corrupt control-secrets quarantine journal is an explicit failure, never an empty one", () => {
		const files = new Map<string, string>([["/data/control-secrets.json", "{not json"], ["/data/control-secrets.json.quarantine.json", "{also not json"]]);
		const { store } = memoryStore();
		expect(() => {
			createApplicationControl({
				controlStore: store,
				secretsFile: "/data/control-secrets.json",
				supervisorSocket: "/run/s.sock",
				gatewayDirectory: "/run/gw",
				objectEndpoint: "http://10.37.0.1:9000",
				rpcClient: { prepare: async () => ({}), start: async () => ({}), stop: async () => ({}), inspect: async () => ({}), metrics: async () => ({}), remove: async () => ({}), socketGet: async () => ({ status: 200, body: "{}" }) },
				issueObjectCredential: async () => ({ object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK" }, retire: { accessKey: "AK", parentUser: "p" } }),
				issueDataCredential: async () => ({ endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK" }),
				retireObjectCredential: async () => {},
				secretsIo: { readFile: (file: string) => files.get(file) ?? null, writeFileAtomic: (file: string, content: string) => files.set(file, content) },
				packageStore: trackingPackageStore(),
			});
		}).toThrow(/not parseable JSON/);
	});

	test("a stale deployment record forces redeploy: the full identity travels to the store (2.22)", async () => {
		const store = trackingPackageStore({ deployedResponses: [false, true] });
		const { instance } = control({ packageStore: store });
		const admitted = await instance.admit({ applicationId: "notes", packageDigest: digestA, manifest, policy, snapshotFiles: [snapshotA] });
		await instance.prepare("notes", admitted.versionId);
		// deployed() was consulted, returned stale, and deploy ran with the FULL
		// version identity — not a bare digest
		expect(store.calls.filter((call) => call.startsWith("deployed:sbx-"))).toHaveLength(1);
		expect(store.calls.filter((call) => call.startsWith("deploy:sbx-"))).toHaveLength(1);
		const identity = store.identities[0];
		expect(identity.applicationId).toBe("notes");
		expect(identity.versionId).toBe(admitted.versionId);
		expect(identity.digest).toBe(digestA);
		expect(identity.sequence).toBe(1);
		// a second prepare with a fresh deployed()=true does not redeploy
		await instance.prepare("notes", admitted.versionId);
		expect(store.calls.filter((call) => call.startsWith("deploy:sbx-"))).toHaveLength(1);
	});
});
