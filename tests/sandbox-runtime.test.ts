// 用户原始需求（2026-08-14）：证明 sandbox spec 固定不可扩权、可执行权威唯一（镜像 ENTRYPOINT）、生命周期先验证完整 managed identity、desired state 落盘可重建、quarantine 持久且不采纳未知资源。
// 正交意图：2.12/2.14/2.15 的本地证据；assemble 后的 runtime command 由 scripted executor 逐 argv 检验。
import { describe, expect, test } from "bun:test";
import {
	appContainerName,
	buildAppContainerCreateArgs,
	buildNetworkCreateArgs,
	sandboxGatewayAddress,
	sandboxAppAddress,
	sandboxNetworkName,
	gatewayNetworkName,
	buildGatewayContainerCreateArgs,
	buildSandboxSpec,
	gatewayContainerName,
	IWEB_MANAGED_LABEL,
	isDigestPinnedImage,
	SECCOMP_PROFILE_HOST_PATH,
	versionLabel,
	type SandboxSpec,
	type SandboxSpecOptions,
} from "../supervisor/sandbox-spec.ts";
import { assertDigestPinnedOptions, createSandboxAdapter, lifecycleFromState, reconcileSandboxes } from "../supervisor/adapter.ts";
import { parseGatewayConfig } from "../supervisor/gateway.ts";
import { JsonStateStore, systemStateStoreIO, validateGatewaySecret, validateDesiredStateFile, validateQuarantineFile, type GatewaySecret, type StateStoreIO } from "../supervisor/desired-state.ts";
import { createQuarantineJournal } from "../packages/contracts/persisted-records.ts";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deriveSandboxId } from "../packages/contracts/protocol.ts";
import { PodmanRuntime, RuntimeFailure, unavailableMetrics, type OciRuntime, type RuntimeExecError, type SandboxListing, type SandboxMetrics, type SandboxState, type SandboxTopology } from "../supervisor/runtime.ts";

const digestA = "a".repeat(64);
const digestB = "b".repeat(64);
const policy = {
	resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 },
	egress: { default: "deny" as const, allow: [{ host: "api.example.com", port: 443 }] },
};
const versionIdentity = { applicationId: "app-a", digest: digestA, sequence: 3 };
const sandboxId = deriveSandboxId("app-a", digestA, 3);
const options: SandboxSpecOptions = {
	runtimeImage: "ghcr.io/denoland/celld@sha256:" + "c".repeat(64),
	gatewayImage: "localhost/iweb-sandbox-gateway@sha256:" + "d".repeat(64),
	stateDirectory: "/var/lib/iweb-sandbox",
	gatewayRuntimeDirectory: "/run/iweb-sandbox/gw",
	region: "us-east-1",
};

function memoryStore(): { store: JsonStateStore; files: Map<string, string> } {
	const files = new Map<string, string>();
	const io: StateStoreIO = {
		readFile: (path) => files.get(path) ?? null,
		writeFileAtomic: (path, content) => files.set(path, content),
		deleteFile: (path) => files.delete(path),
		ensureDirectory: () => undefined,
	};
	return { store: new JsonStateStore(io, "/state"), files };
}

describe("sandbox spec: single executable authority and fixed non-escalating args", () => {
	test("requires digest-pinned images and rejects floating tags", () => {
		expect(isDigestPinnedImage("ghcr.io/denoland/celld@sha256:" + "c".repeat(64))).toBe(true);
		expect(isDigestPinnedImage("localhost/iweb-gw@sha256:" + "d".repeat(64))).toBe(true);
		expect(isDigestPinnedImage("ghcr.io/denoland/celld:0.2.0")).toBe(false);
		expect(isDigestPinnedImage("celld")).toBe(false);
		expect(() => assertDigestPinnedOptions({ ...options, runtimeImage: "celld:latest" })).toThrow();
	});

	test("the command is arguments only; the image entrypoint is the sole executable authority", () => {
		const spec = buildSandboxSpec({ sandboxId, versionIdentity, packageDigest: digestB, policy, gatewayAddress: "10.200.3.2", subnetIndex: 3 }, options);
		expect(spec.command.join(" ")).not.toContain("celld");
		expect(spec.command[0]).toBe("--bucket");
		expect(spec.command.join(" ")).toContain("s3://iweb-app-" + sandboxId);
		expect(spec.command.join(" ")).toContain("--listen 127.0.0.1:8787");
		// the object endpoint is the in-pod gateway, never the host loopback MinIO
		expect(spec.command.join(" ")).toContain("--endpoint http://10.200.3.2:9000");
		expect(versionLabel(versionIdentity)).toBe(digestA + "-3");
	});

	test("network args are internal-only for the app and dual for the gateway (2.44)", () => {
		const spec = buildSandboxSpec({ sandboxId, versionIdentity, packageDigest: digestB, policy, gatewayAddress: "10.200.3.2", subnetIndex: 3 }, options);
		const internal = buildNetworkCreateArgs(sandboxId, true, 3);
		expect(internal.slice(0, 2)).toEqual(["network", "create"]);
		expect(internal.join(" ")).toContain("--internal");
		expect(internal.join(" ")).toContain("--subnet 10.200.3.0/24");
		const appArgs = buildAppContainerCreateArgs(spec, options);
		expect(appArgs).toContain(IWEB_MANAGED_LABEL);
		expect(appArgs).toContain("iweb.sandbox=" + sandboxId);
		expect(appArgs).toContain("iweb.version=" + versionLabel(versionIdentity));
		expect(appArgs.join(" ")).toContain("--network " + sandboxNetworkName(sandboxId));
		expect(appArgs.join(" ")).not.toContain(gatewayNetworkName(sandboxId));
		expect(appArgs.join(" ")).not.toContain("slirp4netns");
		expect(appArgs).toContain("--memory");
		expect(appArgs).toContain(String(128 * 2 ** 20));
		expect(appArgs).toContain("--pids-limit");
		for (const forbidden of ["--privileged", "--cap-add", "--device", "--entrypoint", "--volume", "--network host", "--network=host", "--pid=host", "--ipc=host", "--userns=host", "allow_host_loopback"]) {
			expect(appArgs.join(" ")).not.toContain(forbidden);
		}
	});

	test("gateway container mounts socket dir and read-only config; app container gets worker and bounded tmpfs only", () => {
		const spec = buildSandboxSpec({ sandboxId, versionIdentity, packageDigest: digestB, policy, gatewayAddress: "10.200.3.2", subnetIndex: 3 }, options);
		const gatewayArgs = buildGatewayContainerCreateArgs(spec, options);
		// dual-network join must pin the address per-interface: a global --ip is
		// rejected by podman ("--ip can only be set for a single network")
		expect(gatewayArgs.join(" ")).toContain("--network " + sandboxNetworkName(sandboxId) + ":ip=10.200.3.2," + gatewayNetworkName(sandboxId));
		expect(gatewayArgs).toContain(gatewayContainerName(sandboxId));
		expect(gatewayArgs.join(" ")).toContain("source=/run/iweb-sandbox/gw/" + sandboxId + ",target=/run/iweb");
		expect(gatewayArgs.join(" ")).toContain("source=/var/lib/iweb-sandbox/secrets/" + sandboxId + ".json,target=/etc/iweb-gateway/config.json,ro");
		expect(gatewayArgs).toContain("--cap-drop");
		expect(gatewayArgs.join(" ")).toContain("seccomp=" + SECCOMP_PROFILE_HOST_PATH);
		// credentials never enter argv
		expect(gatewayArgs.join(" ")).not.toContain("SECRET");
		const appArgs = buildAppContainerCreateArgs(spec, options);
		expect(appArgs).toContain(appContainerName(sandboxId));
		expect(appArgs.join(" ")).toContain("--read-only");
		expect(appArgs.join(" ")).toContain("noexec,nosuid");
		expect(appArgs.join(" ")).not.toContain("/run/iweb");
		// image is followed by the fixed argument list only
		const imageIndex = appArgs.indexOf(options.runtimeImage);
		expect(imageIndex).toBeGreaterThan(0);
		expect(appArgs.slice(imageIndex + 1)).toEqual([...spec.command]);
		// no argv element is the executable name; the image entrypoint is the authority
		expect(appArgs).not.toContain("celld");
		// outbound HTTP/HTTPS is forced through the pod-loopback egress proxy;
		// loopback (object proxy + ingress) bypasses egress so the worker fetch and
		// readiness probe never recurse through the egress proxy
		expect(appArgs.join(" ")).toContain("--env HTTP_PROXY=http://10.200.3.2:8081");
		expect(appArgs.join(" ")).toContain("--env HTTPS_PROXY=http://10.200.3.2:8081");
		expect(appArgs.join(" ")).toContain("--env NO_PROXY=10.200.3.2,127.0.0.1,localhost");
	});

	test("addresses are deterministic per subnet index and never collide between roles", () => {
		expect(sandboxGatewayAddress(3)).toBe("10.200.3.2");
		expect(sandboxAppAddress(3)).toBe("10.200.3.3");
		expect(sandboxGatewayAddress(3)).not.toBe(sandboxAppAddress(3));
	});
});

describe("scripted podman executor exercises the assembled invocation", () => {
	function scripted(handlers: Record<string, (args: string[]) => string>): { runtime: PodmanRuntime; calls: string[][] } {
		const calls: string[][] = [];
		const executor = (args: readonly string[]): string => {
			calls.push([...args]);
			const key = args.slice(0, 2).join(" ");
			const handler = handlers[key] ?? handlers["default"];
			if (handler) return handler([...args]);
			return "";
		};
		return { runtime: new PodmanRuntime({ executor }), calls };
	}

	// The new assembled shape: two networks then two containers, all with pinned
	// addresses from the subnet index; nothing is started during create.
	const gwInspect = JSON.stringify({ "iweb.managed": "1", "iweb.role": "gateway", "iweb.sandbox": sandboxId, "iweb.version": versionLabel(versionIdentity) });
	const appInspect = JSON.stringify({ "iweb.managed": "1", "iweb.role": "app", "iweb.sandbox": sandboxId, "iweb.version": versionLabel(versionIdentity) });
	const running = (labels: string) => "true|0|false|" + labels;

	test("create assembles both networks and both containers with no second celld authority", async () => {
		const { runtime, calls } = scripted({ default: () => "" });
		const spec = buildSandboxSpec({ sandboxId, versionIdentity, packageDigest: digestB, policy, gatewayAddress: "10.200.3.2", subnetIndex: 3 }, options);
		await runtime.create(spec, options);
		const networks = calls.filter((c) => c[0] === "network" && c[1] === "create");
		expect(networks).toHaveLength(2);
		expect(networks[0].join(" ")).toContain("--internal");
		const containerCreates = calls.filter((c) => c[0] === "create");
		expect(containerCreates).toHaveLength(2);
		const appCreate = containerCreates.find((c) => c.includes(options.runtimeImage))!;
		const imageIndex = appCreate.indexOf(options.runtimeImage);
		expect(appCreate.slice(imageIndex + 1)[0]).toBe("--bucket");
		expect(appCreate).not.toContain("celld");
	});

	test("create tolerates already-existing resources only when they carry the trusted identity", async () => {
		const { runtime } = scripted({
			"network create": () => { throw { stdout: "", stderr: "already exists" } as RuntimeExecError; },
			"create --name": () => { throw { stdout: "", stderr: "already exists" } as RuntimeExecError; },
			"inspect --format": (args: string[]) => args.includes(gatewayContainerName(sandboxId)) ? running(gwInspect) : running(appInspect),
			default: () => "",
		});
		const spec = buildSandboxSpec({ sandboxId, versionIdentity, packageDigest: digestB, policy, gatewayAddress: "10.200.3.2", subnetIndex: 3 }, options);
		await runtime.create(spec, options);
	});

	test("create rejects an existing container whose identity conflicts with the trusted record", async () => {
		const wrongVersion = versionLabel({ ...versionIdentity, sequence: 99 });
		const wrong = JSON.stringify({ "iweb.managed": "1", "iweb.role": "app", "iweb.sandbox": sandboxId, "iweb.version": wrongVersion });
		const { runtime } = scripted({
			"create --name": () => { throw { stdout: "", stderr: "already exists" } as RuntimeExecError; },
			"inspect --format": () => "true|0|false|" + wrong,
			default: () => "",
		});
		const spec = buildSandboxSpec({ sandboxId, versionIdentity, packageDigest: digestB, policy, gatewayAddress: "10.200.3.2", subnetIndex: 3 }, options);
		let caught: unknown = null;
		try { await runtime.create(spec, options); } catch (error) { caught = error; }
		expect(caught).toBeInstanceOf(RuntimeFailure);
		expect((caught as RuntimeFailure).kind).toBe("conflict");
	});

	test("topology classifies gateway and app nodes against the trusted record", async () => {
		const { runtime } = scripted({
			"inspect --format": (args: string[]) => args.includes(appContainerName(sandboxId)) ? "" : "true|0|false|" + gwInspect,
			default: () => "",
		});
		const topo = await runtime.topology(sandboxId, versionLabel(versionIdentity));
		expect(topo.gateway).toBe("present");
		expect(topo.app).toBe("absent");
	});

	test("start verifies both managed identities before acting", async () => {
		const { runtime, calls } = scripted({
			"inspect --format": (args: string[]) => args.includes(gatewayContainerName(sandboxId)) ? running(gwInspect) : running(appInspect),
			start: () => "",
			default: () => "",
		});
		await runtime.start(sandboxId);
		expect(calls.some((c) => c[0] === "start")).toBe(true);
	});

	test("start rejects a container whose labels do not prove the trusted identity", async () => {
		const wrongOwner = JSON.stringify({ "iweb.managed": "1", "iweb.role": "app", "iweb.sandbox": "other", "iweb.version": versionLabel(versionIdentity) });
		const { runtime, calls } = scripted({
			"inspect --format": () => "true|0|false|" + wrongOwner,
			default: () => "",
		});
		let caught: unknown = null;
		try { await runtime.start(sandboxId); } catch (error) { caught = error; }
		expect(caught).toBeInstanceOf(RuntimeFailure);
		expect((caught as RuntimeFailure).kind).toBe("conflict");
		expect(calls.some((c) => c[0] === "start")).toBe(false);
	});

	test("start on missing containers is an honest not-found failure", async () => {
		const { runtime } = scripted({
			"inspect --format": () => { throw { stdout: "", stderr: "no such container" } as RuntimeExecError; },
			default: () => "",
		});
		let caught: unknown = null;
		try { await runtime.start(sandboxId); } catch (error) { caught = error; }
		expect(caught).toBeInstanceOf(RuntimeFailure);
		expect((caught as RuntimeFailure).kind).toBe("not-found");
	});

	test("stop and delete are idempotent for recognized absent states and remove the networks", async () => {
		const { runtime, calls } = scripted({
			stop: () => { throw { stdout: "", stderr: "no such container" } as RuntimeExecError; },
			rm: () => { throw { stdout: "", stderr: "no such container" } as RuntimeExecError; },
			"network rm": () => { throw { stdout: "", stderr: "no such network" } as RuntimeExecError; },
			default: () => "",
		});
		await runtime.stop(sandboxId);
		await runtime.delete(sandboxId);
		expect(calls.some((c) => c[0] === "network" && c[1] === "rm")).toBe(true);
	});
});

describe("sandbox adapter with durable desired state", () => {
	class MockRuntime implements OciRuntime {
		created: SandboxSpec[] = [];
		started: string[] = [];
		stopped: string[] = [];
		deleted: string[] = [];
		quarantinedIds: string[] = [];
		states = new Map<string, SandboxState>();
		listings: SandboxListing[] = [];
		metricsResult: SandboxMetrics = unavailableMetrics("2026-08-14T00:00:00.000Z");

		async create(spec: SandboxSpec) { this.created.push(spec); this.states.set(spec.sandboxId, { exists: true, running: false, exitCode: null, oomKilled: false, labels: { managed: true, role: "sandbox", sandbox: spec.sandboxId, version: versionLabel(spec.versionIdentity) } }); }
		async start(id: string) { this.started.push(id); this.states.set(id, { exists: true, running: true, exitCode: null, oomKilled: false, labels: this.states.get(id)?.labels ?? null }); }
		async stop(id: string) { this.stopped.push(id); this.states.set(id, { exists: true, running: false, exitCode: null, oomKilled: false, labels: this.states.get(id)?.labels ?? null }); }
		async inspect(id: string) { return this.states.get(id) ?? { exists: false, running: false, exitCode: null, oomKilled: false, labels: null }; }
		async delete(id: string) { this.deleted.push(id); this.states.delete(id); }
		async list() { return this.listings; }
		async metrics() { return this.metricsResult; }
		async quarantine(id: string) { this.quarantinedIds.push(id); }
		async topology() { return { pod: "present", gateway: "present", app: "present" } as const; }
	}

	const prepareRequest = {
		version: 1 as const,
		operation: "prepare" as const,
		sandboxId,
		versionIdentity,
		packageDigest: digestB,
		policy,
		object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" },
		storageSecret: "d".repeat(64),
		data: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDDATA", secretAccessKey: "SECRETDATA" },
	};

	test("prepare fails closed when snapshot materialization fails, before any OCI resource is created", async () => {
		const { store } = memoryStore();
		const runtime = new MockRuntime();
		// a materializer whose MinIO store is empty -> snapshot missing
		const materializer: SnapshotMaterializerOptions = {
			exec: () => { throw new Error("mc: object not found"); },
		};
		const adapter = createSandboxAdapter(runtime, options, { state: store, materializer });
		let caught: unknown = null;
		try { await adapter.prepare(prepareRequest); } catch (error) { caught = error; }
		expect(caught).toBeInstanceOf(RuntimeFailure);
		// no OCI side effect: nothing was created
		expect(runtime.created).toHaveLength(0);
	});
	test("prepare persists desired state and gateway secret before creating OCI resources", async () => {
		const { store, files } = memoryStore();
		const runtime = new MockRuntime();
		const adapter = createSandboxAdapter(runtime, options, { state: store });
		const response = await adapter.prepare(prepareRequest);
		expect(response.status).toBe("prepared");
		expect(runtime.created).toHaveLength(1);
		const desired = JSON.parse(files.get("/state/desired-state.json") ?? "{}");
		expect(desired.records[sandboxId].packageDigest).toBe(digestB);
		const secret = JSON.parse(files.get("/state/secrets/" + sandboxId + ".json") ?? "{}") as GatewaySecret;
		expect(secret.versionId).toBe(versionLabel(versionIdentity));
		expect(secret.generation).toBe(3);
		expect(secret.bucket).toBe("iweb-app-" + sandboxId);
		// boot-required topology: the mounted secret must satisfy parseGatewayConfig
		expect(secret.ingressTarget).toBe("10.200.0.3:8787");
		expect(secret.socketDirectory).toBe("/run/iweb");
		expect(parseGatewayConfig(JSON.stringify(secret))).not.toBeNull();
		// the application persistent-data plane is provisioned into the gateway secret
		expect(secret.applicationId).toBe("app-a");
		expect(secret.storageSecret).toBe("d".repeat(64));
		expect(secret.data?.accessKeyId).toBe("AKIDDATA");
	});

	test("a restarted adapter rebuilds desired state from the durable store", async () => {
		const { store } = memoryStore();
		const runtime = new MockRuntime();
		const first = createSandboxAdapter(runtime, options, { state: store });
		await first.prepare(prepareRequest);
		const secondRuntime = new MockRuntime();
		secondRuntime.states.set(sandboxId, { exists: true, running: false, exitCode: null, oomKilled: false, labels: { managed: true, role: "sandbox", sandbox: sandboxId, version: versionLabel(versionIdentity) } });
		const second = createSandboxAdapter(secondRuntime, options, { state: store });
		// the rebuilt adapter still recognizes the sandbox and can drive it
		await second.start({ version: 1, operation: "start", sandboxId });
		expect(secondRuntime.started).toEqual([sandboxId]);
		// a sandbox never prepared is honestly rejected
		let caught: unknown = null;
		try {
			await second.start({ version: 1, operation: "start", sandboxId: "sbx-unknown" });
		} catch (error) {
			caught = error;
		}
		expect(caught).toBeInstanceOf(RuntimeFailure);
		expect((caught as RuntimeFailure).kind).toBe("not-found");
	});

	test("metrics preserve unavailable measurements and unknown limits without zero substitution", async () => {
		const { store } = memoryStore();
		const runtime = new MockRuntime();
		const adapter = createSandboxAdapter(runtime, options, { state: store });
		await adapter.prepare(prepareRequest);
		runtime.metricsResult = {
			available: false,
			cpuMillis: null,
			memoryBytes: null,
			pidCount: null,
			terminated: null,
			limits: { cpuMillis: null, memoryBytes: null, pidLimit: null, storageBytes: null },
			sampledAt: "2026-08-14T00:00:00.000Z",
		};
		const sample = await adapter.metrics({ version: 1, operation: "metrics", sandboxId, versionId: versionLabel(versionIdentity) });
		expect(sample.sample.cpuMillis).toEqual({ available: false });
		expect(sample.sample.memoryBytes).toEqual({ available: false });
		expect(sample.sample.limits).toBeNull();
		runtime.metricsResult = {
			available: true,
			cpuMillis: 12,
			memoryBytes: 3_000_000,
			pidCount: 4,
			terminated: false,
			limits: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 },
			sampledAt: "2026-08-14T00:00:01.000Z",
		};
		const available = await adapter.metrics({ version: 1, operation: "metrics", sandboxId, versionId: versionLabel(versionIdentity) });
		expect(available.sample.cpuMillis).toEqual({ available: true, value: 12 });
		expect(available.sample.terminated).toEqual({ available: true, value: 0 });
	});

	test("inspect conflicts when observed identity does not match the desired record", async () => {
		const { store } = memoryStore();
		const runtime = new MockRuntime();
		const adapter = createSandboxAdapter(runtime, options, { state: store });
		await adapter.prepare(prepareRequest);
		runtime.states.set(sandboxId, { exists: true, running: true, exitCode: null, oomKilled: false, labels: { managed: true, role: "sandbox", sandbox: sandboxId, version: digestB + "-9" } });
		let caught: unknown = null;
		try {
			await adapter.inspect({ version: 1, operation: "inspect", sandboxId });
		} catch (error) {
			caught = error;
		}
		expect(caught).toBeInstanceOf(RuntimeFailure);
		expect((caught as RuntimeFailure).kind).toBe("conflict");
	});

	test("delete removes the OCI resource, the desired record, and the secret", async () => {
		const { store, files } = memoryStore();
		const runtime = new MockRuntime();
		const adapter = createSandboxAdapter(runtime, options, { state: store });
		await adapter.prepare(prepareRequest);
		await adapter.delete({ version: 1, operation: "delete", sandboxId });
		expect(runtime.deleted).toEqual([sandboxId]);
		const desired = JSON.parse(files.get("/state/desired-state.json") ?? "{}");
		expect(desired.records[sandboxId]).toBeUndefined();
		expect(files.has("/state/secrets/" + sandboxId + ".json")).toBe(false);
	});
});
describe("sandbox isolation (3.5)", () => {
	class IsoRuntime implements OciRuntime {
		created: string[] = [];
		stopped: string[] = [];
		removed: string[] = [];
		// each sandbox answers with ITS OWN immutable identity (2.51)
		private identities = new Map<string, string>();
		async create(spec: SandboxSpec) { this.created.push(spec.sandboxId); this.identities.set(spec.sandboxId, versionLabel(spec.versionIdentity)); }
		async start() {}
		async stop(sandboxId: string) { this.stopped.push(sandboxId); }
		async inspect(sandboxId: string) { return { exists: !this.removed.includes(sandboxId), running: !this.removed.includes(sandboxId), exitCode: null, oomKilled: false, labels: { managed: true, role: "app", sandbox: sandboxId, version: this.identities.get(sandboxId) ?? versionLabel(versionIdentity) } }; }
		async delete(sandboxId: string) { this.removed.push(sandboxId); }
		async list() { return []; }
		async topology() { return { pod: "present" as const, gateway: "present" as const, app: "present" as const }; }
		async metrics() { return unavailableMetrics("2026-08-14T00:00:00.000Z"); }
		async quarantine() {}
	}
	test("a crashed sandbox reports failed while the survivor and control path remain usable (2.51)", async () => {
		const { store } = memoryStore();
		const runtime = new IsoRuntime();
		const adapter = createSandboxAdapter(runtime, options, { state: store });
		const baseRequest = {
			version: 1 as const,
			operation: "prepare" as const,
			sandboxId,
			versionIdentity,
			packageDigest: digestB,
			policy,
			object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" },
		};
		const digestTwo = "c".repeat(64);
		const identityTwo = { applicationId: "app-b", digest: digestTwo, sequence: 1 };
		const sandboxTwo = deriveSandboxId("app-b", digestTwo, 1);
		await adapter.prepare(baseRequest);
		await adapter.prepare({ ...baseRequest, sandboxId: sandboxTwo, versionIdentity: identityTwo, packageDigest: digestTwo });
		runtime.removed.push(sandboxId);
		const crashed = await adapter.inspect({ version: 1, operation: "inspect", sandboxId });
		expect(crashed.state).toBe("failed");
		const survivor = await adapter.inspect({ version: 1, operation: "inspect", sandboxId: sandboxTwo });
		expect(survivor.state).toBe("ready");
		const digestThree = "d".repeat(64);
		const identityThree = { applicationId: "app-c", digest: digestThree, sequence: 1 };
		const sandboxThree = deriveSandboxId("app-c", digestThree, 1);
		await adapter.prepare({ ...baseRequest, sandboxId: sandboxThree, versionIdentity: identityThree, packageDigest: digestThree });
		expect(runtime.created.length).toBeGreaterThanOrEqual(3);
	});

	test("resource exhaustion on one sandbox is reported honestly without zero substitution (2.51)", async () => {
		const { store } = memoryStore();
		class ExhaustingRuntime extends IsoRuntime {
			async metrics() { return unavailableMetrics("2026-08-14T00:00:00.000Z"); }
		}
		const runtime = new ExhaustingRuntime();
		const adapter = createSandboxAdapter(runtime, options, { state: store });
		const baseRequest = {
			version: 1 as const,
			operation: "prepare" as const,
			sandboxId,
			versionIdentity,
			packageDigest: digestB,
			policy,
			object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" },
		};
		await adapter.prepare(baseRequest);
		const metrics = await adapter.metrics({ version: 1, operation: "metrics", sandboxId, versionId: versionLabel(versionIdentity) });
		expect(metrics.sample.cpuMillis).toEqual({ available: false });
		expect(metrics.sample.memoryBytes).toEqual({ available: false });
		expect(metrics.sample.limits).toBeNull();
	});
	test("isolating one sandbox leaves another and the control plane operational", async () => {
		const { store } = memoryStore();
		const runtime = new IsoRuntime();
		const adapter = createSandboxAdapter(runtime, options, { state: store });
		const baseRequest = {
			version: 1 as const,
			operation: "prepare" as const,
			sandboxId,
			versionIdentity,
			packageDigest: digestB,
			policy,
			object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" },
		};
		const digestTwo = "c".repeat(64);
		const identityTwo = { applicationId: "app-b", digest: digestTwo, sequence: 1 };
		const sandboxTwo = deriveSandboxId("app-b", digestTwo, 1);
		await adapter.prepare(baseRequest);
		await adapter.prepare({ ...baseRequest, sandboxId: sandboxTwo, versionIdentity: identityTwo, packageDigest: digestTwo });
		await adapter.stop({ version: 1, operation: "stop", sandboxId });
		await adapter.delete({ version: 1, operation: "delete", sandboxId });
		const survivor = await adapter.inspect({ version: 1, operation: "inspect", sandboxId: sandboxTwo });
		expect(survivor.state).toBe("ready");
		const digestThree = "d".repeat(64);
		const identityThree = { applicationId: "app-c", digest: digestThree, sequence: 1 };
		const sandboxThree = deriveSandboxId("app-c", digestThree, 1);
		await adapter.prepare({ ...baseRequest, sandboxId: sandboxThree, versionIdentity: identityThree, packageDigest: digestThree });
		expect(runtime.created.length).toBeGreaterThanOrEqual(3);
	});
});

describe("sandbox reconciliation", () => {
	class ReconcileRuntime implements OciRuntime {
		stopped: string[] = [];
			removed: string[] = [];
			async create() {}
			async start() {}
			async stop() { this.stopped.push("x"); }
			async inspect(id: string) { return { exists: false, running: false, exitCode: null, oomKilled: false, labels: null }; }
			async delete() {}
			async list() { return [{ sandboxId: "known-a", running: true, role: "sandbox" }, { sandboxId: "unknown-b", running: true, role: "sandbox" }]; }
			async metrics() { return unavailableMetrics("2026-08-14T00:00:00.000Z"); }
			async quarantine(id: string) { this.removed.push(id); }
			async topology() { return { pod: "absent", gateway: "absent", app: "absent" } as const; }
		}
		test("quarantines unknown iweb-labeled resources, journals them durably, and reports missing desired sandboxes", async () => {
		const { store, files } = memoryStore();
		const runtime = new ReconcileRuntime();
		const result = await reconcileSandboxes(runtime, new Set(["known-a", "known-c"]), { state: store });
		expect(result.quarantined).toEqual(["unknown-b"]);
		expect(runtime.removed).toEqual(["unknown-b"]);
		expect(result.missing).toEqual(["known-c"]);
		const quarantine = JSON.parse(files.get("/state/quarantine.json") ?? "{}");
		expect(quarantine.entries).toEqual([{ sandboxId: "unknown-b", quarantinedAt: expect.any(String) }]);
	});

	test("reconcile reports partial and conflicting child topology on restart", async () => {
		class TopologyRuntime implements OciRuntime {
			topologyResult: SandboxTopology = { pod: "present", gateway: "present", app: "absent" };
			async create() {}
			async start() {}
			async stop() {}
			async inspect() { return { exists: true, running: true, exitCode: null, oomKilled: false, labels: null }; }
			async delete() {}
			async list() { return [{ sandboxId, running: true, role: "sandbox" }]; }
			async topology() { return this.topologyResult; }
			async metrics() { return unavailableMetrics("2026-08-14T00:00:00.000Z"); }
			async quarantine() {}
		}
		const { store } = memoryStore();
		store.writeDesired({ version: 1, records: { [sandboxId]: { sandboxId, packageDigest: digestB, versionIdentity, policy, createdAt: "2026-08-14T00:00:00.000Z", subnetIndex: 1 } } });
		const runtime = new TopologyRuntime();
		const partialResult = await reconcileSandboxes(runtime, new Set([sandboxId]), { state: store });
		expect(partialResult.partial).toEqual([sandboxId]);
		expect(partialResult.conflicting).toEqual([]);
		runtime.topologyResult = { pod: "present", gateway: "conflict", app: "present" };
		const conflictResult = await reconcileSandboxes(runtime, new Set([sandboxId]), { state: store });
		expect(conflictResult.conflicting).toEqual([sandboxId]);
	});
});

describe("lifecycle observation mapping", () => {
	test("maps missing and exited to failed, running to ready", () => {
		expect(lifecycleFromState({ exists: false, running: false, exitCode: null })).toBe("failed");
		expect(lifecycleFromState({ exists: true, running: true, exitCode: null })).toBe("ready");
		expect(lifecycleFromState({ exists: true, running: false, exitCode: 1 })).toBe("failed");
		expect(lifecycleFromState({ exists: true, running: false, exitCode: null })).toBe("stopped");
	});
});

describe("persisted gateway secret validation (2.28)", () => {
	const validSecret = {
		version: 1 as const, sandboxId: "sbx-test", versionId: "a".repeat(64) + "-1", generation: 1, bucket: "iweb-app-sbx-test",
		object: { endpoint: "http://127.0.0.1:9000", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK" },
		egress: { default: "deny" as const, allow: [] },
		ingressTarget: "127.0.0.1:8787",
		socketDirectory: "/run/iweb",
	};
	test("validateGatewaySecret accepts a well-formed record and rejects malformed, mismatched, or untyped fields", () => {
		expect(validateGatewaySecret(validSecret as Record<string, unknown>, "sbx-test")).not.toBeNull();
		expect(validateGatewaySecret({ ...validSecret, sandboxId: "other" } as Record<string, unknown>, "sbx-test")).toBeNull();
		expect(validateGatewaySecret({ ...validSecret, object: "not-a-record" } as Record<string, unknown>, "sbx-test")).toBeNull();
		expect(validateGatewaySecret({ ...validSecret, generation: 0 } as Record<string, unknown>, "sbx-test")).toBeNull();
		expect(validateGatewaySecret({ ...validSecret, egress: { default: "allow", allow: [] } } as Record<string, unknown>, "sbx-test")).toBeNull();
		// a secret missing the boot-required topology fields cannot start the gateway
		expect(validateGatewaySecret({ ...validSecret, ingressTarget: undefined } as Record<string, unknown>, "sbx-test")).toBeNull();
		expect(validateGatewaySecret({ ...validSecret, socketDirectory: "relative" } as Record<string, unknown>, "sbx-test")).toBeNull();
	});
	test("persisted desired/quarantine records are validated field by field, not cast", () => {
		// the persisted policy must pass the admission-time authority (all four
		// resource limits, bounded egress), never a looser persisted-only rule
		const validRecord = { sandboxId: "sbx-abc123", packageDigest: "a".repeat(64), versionIdentity: { applicationId: "app-a", digest: "a".repeat(64), sequence: 1 }, policy, createdAt: "2026-08-14T00:00:00.000Z", subnetIndex: 0 };
		const journal = createQuarantineJournal();
		validateDesiredStateFile({ version: 1, records: { "sbx-partial": { ...validRecord, sandboxId: "sbx-partial", policy: { resources: { cpuMillis: 500 }, egress: { default: "deny", allow: [] } } } } }, journal);
		expect(journal.entries()).toHaveLength(1);
		expect(journal.entries()[0].reason).toContain("policy");
		const good = validateDesiredStateFile({ version: 1, records: { "sbx-abc123": validRecord } });
		expect(good.records["sbx-abc123"]?.sandboxId).toBe("sbx-abc123");
		// malformed records are dropped, well-formed ones survive
		const mixed = validateDesiredStateFile({ version: 1, records: { "sbx-abc123": validRecord, "sbx-bad": { sandboxId: "sbx-bad", packageDigest: "not-a-digest" }, "sbx-collide": { ...validRecord, sandboxId: "sbx-other" } } });
		expect(Object.keys(mixed.records)).toEqual(["sbx-abc123"]);
		expect(validateDesiredStateFile({ version: 2, records: {} }).records).toEqual({});
		// a present-but-corrupt quarantine file is an EXPLICIT failure: invalid
		// entries, unknown top-level fields, and bad shapes throw instead of
		// silently dropping the rejection history (2.37)
		expect(validateQuarantineFile({ version: 1, entries: [{ sandboxId: "sbx-abc123", quarantinedAt: "t" }] }).entries).toEqual([{ sandboxId: "sbx-abc123", quarantinedAt: "t" }]);
		expect(() => validateQuarantineFile({ version: 1, entries: [{ sandboxId: "x", quarantinedAt: "t" }] })).toThrow(/QUARANTINE_FILE_CORRUPT/);
		expect(() => validateQuarantineFile({ version: 1, entries: [{ sandboxId: "sbx-abc123" }] })).toThrow(/QUARANTINE_FILE_CORRUPT/);
		expect(() => validateQuarantineFile({ version: 1, entries: [{ sandboxId: "sbx-abc123", quarantinedAt: "t", smuggled: 1 }] })).toThrow(/QUARANTINE_FILE_CORRUPT/);
		expect(() => validateQuarantineFile({ version: 2, entries: [] })).toThrow(/QUARANTINE_FILE_CORRUPT/);
	});

	test("nested GatewaySecret.data is validated through the shared authority, not a shallow string check (2.28/2.37)", () => {
		const dataTriple = { applicationId: "app-a", storageSecret: "e".repeat(64), data: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "AKIDDATA", secretAccessKey: "SECRETDATA" } };
		// the well-formed all-or-nothing triple passes
		expect(validateGatewaySecret({ ...validSecret, ...dataTriple } as Record<string, unknown>, "sbx-test")).not.toBeNull();
		// a smuggled field inside nested data rejects the whole secret
		expect(validateGatewaySecret({ ...validSecret, applicationId: "app-a", storageSecret: "e".repeat(64), data: { ...dataTriple.data, extra: "smuggled" } } as Record<string, unknown>, "sbx-test")).toBeNull();
		// a malformed nested endpoint (credentials embedded in the URL) rejects
		expect(validateGatewaySecret({ ...validSecret, applicationId: "app-a", storageSecret: "e".repeat(64), data: { ...dataTriple.data, endpoint: "http://ak:sk@10.37.0.1:9000" } } as Record<string, unknown>, "sbx-test")).toBeNull();
		// a partial triple is not accepted at all
		expect(validateGatewaySecret({ ...validSecret, applicationId: "app-a" } as Record<string, unknown>, "sbx-test")).toBeNull();
		expect(validateGatewaySecret({ ...validSecret, storageSecret: "e".repeat(64) } as Record<string, unknown>, "sbx-test")).toBeNull();
		// a storageSecret that is not the issued 64-hex form rejects
		expect(validateGatewaySecret({ ...validSecret, applicationId: "app-a", storageSecret: "not-hex-secret", data: dataTriple.data } as Record<string, unknown>, "sbx-test")).toBeNull();
		// an invalid applicationId shape rejects
		expect(validateGatewaySecret({ ...validSecret, applicationId: "Bad_Id", storageSecret: "e".repeat(64), data: dataTriple.data } as Record<string, unknown>, "sbx-test")).toBeNull();
	});

	test("an unknown top-level desired-state field quarantines durably, never silently empties (2.37)", () => {
		const { store, files } = memoryStore();
		files.set("/state/desired-state.json", JSON.stringify({ version: 1, records: {}, smuggled: true }));
		expect(store.readDesired().records).toEqual({});
		const journal: { entries: { sandboxId: string; kind: string; reason: string }[] } = JSON.parse(files.get("/state/quarantine.json") ?? "{}");
		expect(journal.entries).toHaveLength(1);
		expect(journal.entries[0].sandboxId).toBe("desired-state");
		expect(journal.entries[0].reason).toContain("unknown top-level field");
	});

	test("a corrupt quarantine file is an explicit failure, never an empty journal (2.37)", () => {
		const { store, files } = memoryStore();
		files.set("/state/quarantine.json", "{not json");
		expect(() => store.readQuarantine()).toThrow(/QUARANTINE_FILE_CORRUPT/);
		// and a corrupted journal wedges quarantine-appending loudly too
		files.set("/state/desired-state.json", "{not json");
		expect(() => store.readDesired()).toThrow(/QUARANTINE_FILE_CORRUPT/);
	});

	test("readSecret rejects a malformed persisted secret and accepts a valid one", () => {
		const { store, files } = memoryStore();
		const secretPath = store.secretPath(sandboxId);
		files.set(secretPath, JSON.stringify({ version: 1, sandboxId, object: "not-a-record" }));
		expect(store.readSecret(sandboxId)).toBeNull();
		files.set(secretPath, JSON.stringify({ ...validSecret, sandboxId }));
		expect(store.readSecret(sandboxId)?.bucket).toBe("iweb-app-sbx-test");
	});

	test("readDesired leaves a durable quarantine trail for malformed persisted records (2.37)", () => {
		const { store, files } = memoryStore();
		const good = { sandboxId: "sbx-abc123", packageDigest: "a".repeat(64), versionIdentity: { applicationId: "app-a", digest: "a".repeat(64), sequence: 1 }, policy, createdAt: "2026-08-14T00:00:00.000Z", subnetIndex: 0 };
		const badDigest = { ...good, sandboxId: "sbx-baddigest", packageDigest: "not-a-digest" };
		const smuggled = { ...good, sandboxId: "sbx-extra01", extra: true };
		files.set("/state/desired-state.json", JSON.stringify({ version: 1, records: { "sbx-abc123": good, "sbx-baddigest": badDigest, "sbx-extra01": smuggled } }));
		const loaded = store.readDesired();
		expect(Object.keys(loaded.records)).toEqual(["sbx-abc123"]);
		const journal: { entries: { sandboxId: string; kind: string; reason: string }[] } = JSON.parse(files.get("/state/quarantine.json") ?? "{}");
		expect(journal.entries).toHaveLength(2);
		expect(journal.entries[0]).toMatchObject({ sandboxId: "sbx-baddigest", kind: "desired-record" });
		expect(journal.entries[0].reason).toContain("packageDigest");
		expect(journal.entries[1].reason).toContain("unknown field");
		// the durable journal itself must validate back (kind/reason accepted)
		expect(validateQuarantineFile(journal as Record<string, unknown>).entries).toHaveLength(2);
		// a corrupt desired-state file is a file-scope quarantine event
		files.set("/state/desired-state.json", "{not json");
		expect(store.readDesired().records).toEqual({});
		const after: { entries: { sandboxId: string; kind: string; reason: string }[] } = JSON.parse(files.get("/state/quarantine.json") ?? "{}");
		const fileScope = after.entries.find((entry) => entry.sandboxId === "desired-state");
		expect(fileScope?.kind).toBe("desired-state");
		expect(fileScope?.reason).toContain("not parseable");
	});

	test("readSecret leaves a quarantine trail for a present-but-malformed secret (2.37)", () => {
		const { store, files } = memoryStore();
		files.set(store.secretPath("sbx-x"), JSON.stringify({ version: 1, sandboxId: "sbx-x" }));
		expect(store.readSecret("sbx-x")).toBeNull();
		const journal: { entries: { sandboxId: string; kind: string; reason: string }[] } = JSON.parse(files.get("/state/quarantine.json") ?? "{}");
		expect(journal.entries).toHaveLength(1);
		expect(journal.entries[0]).toMatchObject({ sandboxId: "sbx-x", kind: "gateway-secret" });
	});

	test("systemStateStoreIO distinguishes ENOENT from permission failures (2.37/2.47)", () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-state-"));
		try {
			expect(systemStateStoreIO.readFile(join(directory, "absent.json"))).toBeNull();
			const locked = join(directory, "locked.json");
			writeFileSync(locked, "{}");
			chmodSync(locked, 0o000);
			// a permission failure is an infrastructure error, never "absent"
			expect(() => systemStateStoreIO.readFile(locked)).toThrow();
		} finally {
			chmodSync(join(directory, "locked.json"), 0o644);
			rmSync(directory, { recursive: true, force: true });
		}
	});
});
