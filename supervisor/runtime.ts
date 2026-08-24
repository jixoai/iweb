// 用户原始需求（2026-08-14）：supervisor 通过不可扩权的 OCI 后端机械执行 sandbox 生命周期；每次操作先重建完整 managed identity；幂等只对明确已达成/不存在状态成立。
// 正交意图：2.44 双容器双网络拓扑——网络创建、gateway 先建、inspect 内网地址、app 后建；基础设施错误不吞掉；identity 校验贯穿。
import { execFileSync } from "node:child_process";
import {
	appContainerName,
	buildAppContainerCreateArgs,
	buildGatewayContainerCreateArgs,
	buildNetworkCreateArgs,
	buildNetworkRemoveArgs,
	gatewayContainerName,
	IWEB_MANAGED_LABEL,
	versionLabel,
	type SandboxSpec,
	type SandboxSpecOptions,
} from "./sandbox-spec.ts";
import { readSandboxCgroupMetrics, type MetricsReader } from "./metrics.ts";

export type RuntimeExecError = { readonly stdout: string; readonly stderr: string };
export type RuntimeExecutor = (args: readonly string[]) => string;

export type RuntimeFailureKind = "not-found" | "conflict" | "infrastructure";

export class RuntimeFailure extends Error {
	readonly kind: RuntimeFailureKind;
	constructor(kind: RuntimeFailureKind, message: string) {
		super(message);
		this.name = "RuntimeFailure";
		this.kind = kind;
	}
}

export interface PodLabels {
	readonly managed: boolean;
	readonly role: string | null;
	readonly sandbox: string | null;
	readonly version: string | null;
}

export interface SandboxState {
	readonly exists: boolean;
	readonly running: boolean;
	readonly exitCode: number | null;
	readonly oomKilled: boolean;
	readonly labels: PodLabels | null;
}

export interface SandboxLimits {
	readonly cpuMillis: number | null;
	readonly memoryBytes: number | null;
	readonly pidLimit: number | null;
	readonly storageBytes: number | null;
}

export interface SandboxMetrics {
	readonly available: boolean;
	readonly cpuMillis: number | null;
	readonly memoryBytes: number | null;
	readonly pidCount: number | null;
	readonly terminated: boolean | null;
	readonly limits: SandboxLimits;
	readonly sampledAt: string | null;
}

export interface SandboxListing {
	readonly sandboxId: string;
	readonly running: boolean;
	readonly role: string | null;
}

export type TopologyNode = "absent" | "present" | "conflict";

export interface SandboxTopology {
	readonly pod: TopologyNode;
	readonly gateway: TopologyNode;
	readonly app: TopologyNode;
}

export interface OciRuntime {
	// Two-phase create (2.44): networks + gateway first (returns the gateway's
	// address on the internal sandbox network), then the app container.
	createGateway(spec: SandboxSpec, options: SandboxSpecOptions): Promise<string>;
	createApp(spec: SandboxSpec, options: SandboxSpecOptions): Promise<void>;
	start(sandboxId: string): Promise<void>;
	stop(sandboxId: string): Promise<void>;
	inspect(sandboxId: string): Promise<SandboxState>;
	delete(sandboxId: string): Promise<void>;
	list(): Promise<SandboxListing[]>;
	topology(sandboxId: string, expectedVersion: string): Promise<SandboxTopology>;
	metrics(sandboxId: string): Promise<SandboxMetrics>;
	quarantine(sandboxId: string): Promise<void>;
}

export interface PodmanRuntimeOptions {
	readonly executor?: RuntimeExecutor;
	readonly metricsReader?: MetricsReader;
	readonly cgroupRoot?: string;
	readonly now?: () => number;
}

const NO_SUCH_RESOURCE_PATTERN = /no such (pod|container|network)|not found|does not exist|unrecognized/i;
const ALREADY_EXISTS_PATTERN = /already exists/i;
const NETWORK_ATTACH_CONFLICT = /network .* (not found|does not exist)/i;

function wrapExecFailure(error: unknown): RuntimeExecError {
	const candidate = error as { readonly stdout?: unknown; readonly stderr?: unknown };
	return { stdout: typeof candidate.stdout === "string" ? candidate.stdout : "", stderr: typeof candidate.stderr === "string" ? candidate.stderr : "" };
}

const defaultExecutor: RuntimeExecutor = (args) => {
	try {
		return execFileSync("podman", [...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
	} catch (error) {
		throw wrapExecFailure(error);
	}
};

function parseLabelsJson(raw: string): PodLabels {
	try {
		const labels = JSON.parse(raw) as Record<string, string>;
		return {
			managed: labels["iweb.managed"] === "1",
			role: labels["iweb.role"] ?? null,
			sandbox: labels["iweb.sandbox"] ?? null,
			version: labels["iweb.version"] ?? null,
		};
	} catch {
		return { managed: false, role: null, sandbox: null, version: null };
	}
}

export function emptyPodLabels(): PodLabels {
	return { managed: false, role: null, sandbox: null, version: null };
}

const MISSING_STATE: SandboxState = { exists: false, running: false, exitCode: null, oomKilled: false, labels: null };

function isInfrastructureText(stderr: string): boolean {
	return !NO_SUCH_RESOURCE_PATTERN.test(stderr) && !ALREADY_EXISTS_PATTERN.test(stderr);
}

export class PodmanRuntime implements OciRuntime {
	private readonly executor: RuntimeExecutor;
	private readonly metricsReader: MetricsReader;
	private readonly cgroupRoot: string;
	private readonly now: () => number;

	constructor(options: PodmanRuntimeOptions = {}) {
		this.executor = options.executor ?? defaultExecutor;
		this.metricsReader = options.metricsReader ?? { readFile: () => null };
		this.cgroupRoot = options.cgroupRoot ?? "/sys/fs/cgroup";
		this.now = options.now ?? (() => Date.now());
	}

	private labelsMatch(labels: PodLabels, sandboxId: string, expectedVersion: string | null, role: string): boolean {
		if (!labels.managed || labels.sandbox !== sandboxId || labels.role !== role) return false;
		return expectedVersion === null || labels.version === expectedVersion;
	}

	private requireManagedContainer(name: string, sandboxId: string, expectedVersion: string | null, role: string): Promise<SandboxState> {
		return this.inspectContainer(name, sandboxId, role).then((state) => {
			if (!state.exists) throw new RuntimeFailure("not-found", role + " container does not exist");
			if (state.labels === null || !this.labelsMatch(state.labels, sandboxId, expectedVersion, role)) {
				throw new RuntimeFailure("conflict", "existing " + role + " container does not carry the complete managed identity");
			}
			return state;
		});
	}

	private async inspectContainer(name: string, sandboxId: string, role: string): Promise<SandboxState> {
		let raw: string;
		try {
			raw = this.executor(["inspect", "--format", "{{.State.Running}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{json .Config.Labels}}", name]);
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (NO_SUCH_RESOURCE_PATTERN.test(failure.stderr)) return MISSING_STATE;
			throw new RuntimeFailure("infrastructure", "podman inspect failed for " + role);
		}
		const parts = raw.trim().split("|");
		if (parts.length < 4) return MISSING_STATE;
		const running = parts[0] === "true";
		const exitRaw = parts[1];
		const exitCode = exitRaw === "" || exitRaw === "-1" || running ? null : Number.isSafeInteger(Number(exitRaw)) ? Number(exitRaw) : null;
		return { exists: true, running, exitCode, oomKilled: parts[2] === "true", labels: parseLabelsJson(parts[3]) };
	}

	async create(spec: SandboxSpec, options: SandboxSpecOptions): Promise<void> {
		// Both networks and both containers in one phase: the spec's subnetIndex
		// pins every address, so the gateway secret (written earlier) already
		// carries the exact ingressTarget. Network creation is idempotent-by-error;
		// containers that already exist must carry the complete trusted identity.
		for (const internal of [true, false]) {
			try {
				this.executor(buildNetworkCreateArgs(spec.sandboxId, internal, spec.subnetIndex));
			} catch (error) {
				const failure = wrapExecFailure(error);
				if (!ALREADY_EXISTS_PATTERN.test(failure.stderr)) throw new RuntimeFailure("infrastructure", "podman network create failed (" + (internal ? "internal" : "gateway") + ")");
			}
		}
		try {
			this.executor(buildGatewayContainerCreateArgs(spec, options));
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (!ALREADY_EXISTS_PATTERN.test(failure.stderr)) throw new RuntimeFailure("infrastructure", "podman gateway container create failed");
			await this.requireManagedContainer(gatewayContainerName(spec.sandboxId), spec.sandboxId, versionLabel(spec.versionIdentity), "gateway");
		}
		try {
			this.executor(buildAppContainerCreateArgs(spec, options));
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (!ALREADY_EXISTS_PATTERN.test(failure.stderr)) throw new RuntimeFailure("infrastructure", "podman app container create failed");
			await this.requireManagedContainer(appContainerName(spec.sandboxId), spec.sandboxId, versionLabel(spec.versionIdentity), "app");
		}
	}

	async start(sandboxId: string): Promise<void> {
		await this.requireManagedContainer(appContainerName(sandboxId), sandboxId, null, "app");
		await this.requireManagedContainer(gatewayContainerName(sandboxId), sandboxId, null, "gateway");
		try {
			this.executor(["start", gatewayContainerName(sandboxId), appContainerName(sandboxId)]);
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (NO_SUCH_RESOURCE_PATTERN.test(failure.stderr)) throw new RuntimeFailure("not-found", "sandbox containers disappeared before start");
			throw new RuntimeFailure("infrastructure", "podman start failed");
		}
		const after = await this.inspectContainer(appContainerName(sandboxId), sandboxId, "app");
		if (!after.exists || !after.running) throw new RuntimeFailure("infrastructure", "podman start did not reach the running state");
	}

	async stop(sandboxId: string): Promise<void> {
		try {
			this.executor(["stop", appContainerName(sandboxId), gatewayContainerName(sandboxId)]);
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (NO_SUCH_RESOURCE_PATTERN.test(failure.stderr)) return;
			throw new RuntimeFailure("infrastructure", "podman stop failed");
		}
	}

	async inspect(sandboxId: string): Promise<SandboxState> {
		return this.inspectContainer(appContainerName(sandboxId), sandboxId, "app");
	}

	async delete(sandboxId: string): Promise<void> {
		try {
			this.executor(["rm", "-f", appContainerName(sandboxId), gatewayContainerName(sandboxId)]);
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (!NO_SUCH_RESOURCE_PATTERN.test(failure.stderr)) throw new RuntimeFailure("infrastructure", "podman rm failed");
		}
		try {
			this.executor(buildNetworkRemoveArgs(sandboxId));
		} catch (error) {
			const failure = wrapExecFailure(error);
			if (!NO_SUCH_RESOURCE_PATTERN.test(failure.stderr)) throw new RuntimeFailure("infrastructure", "podman network rm failed");
		}
	}

	async list(): Promise<SandboxListing[]> {
		const output = this.executor(["ps", "-a", "--filter", "label=" + IWEB_MANAGED_LABEL, "--filter", "label=iweb.role=app", "--format", "{{.Names}}|{{.State}}"]);
		const listings: SandboxListing[] = [];
		for (const line of output.split("\n")) {
			const trimmed = line.trim();
			if (trimmed === "") continue;
			const separator = trimmed.indexOf("|");
			if (separator < 0) continue;
			const name = trimmed.slice(0, separator);
			const state = trimmed.slice(separator + 1);
			const sandboxId = name.endsWith("-app") ? name.slice(0, -4) : name;
			listings.push({ sandboxId, running: state === "running", role: "app" });
		}
		return listings;
	}

	async topology(sandboxId: string, expectedVersion: string): Promise<SandboxTopology> {
		const node = async (name: string, role: string): Promise<TopologyNode> => {
			const state = await this.inspectContainer(name, sandboxId, role);
			if (!state.exists) return "absent";
			return this.labelsMatch(state.labels ?? emptyPodLabels(), sandboxId, expectedVersion, role) ? "present" : "conflict";
		};
		const gatewayNode = await node(gatewayContainerName(sandboxId), "gateway");
		const appNode = await node(appContainerName(sandboxId), "app");
		// the pod slot maps to the gateway (the sandbox's first-created resource)
		return { pod: gatewayNode, gateway: gatewayNode, app: appNode };
	}

	async quarantine(sandboxId: string): Promise<void> {
		try {
			this.executor(["stop", appContainerName(sandboxId), gatewayContainerName(sandboxId)]);
		} catch {
			// already stopped or absent needs no stop
		}
		await this.delete(sandboxId);
	}

	async metrics(sandboxId: string): Promise<SandboxMetrics> {
		const sampledAt = new Date(this.now()).toISOString();
		await this.requireManagedContainer(appContainerName(sandboxId), sandboxId, null, "app");
		let cgroupParent = "";
		try {
			cgroupParent = this.executor(["inspect", "--format", "{{.CgroupParent}}", appContainerName(sandboxId)]).trim();
		} catch {
			// fall through: no cgroup ownership can be proven
		}
		if (cgroupParent === "") return unavailableMetrics(sampledAt);
		const cgroupPath = this.cgroupRoot + "/" + cgroupParent.replace(/^\/+/, "");
		let storageBytes: number | null = null;
		try {
			const storageRaw = this.executor(["inspect", "--format", "{{.HostConfig.StorageOpt}}", appContainerName(sandboxId)]).trim();
			const match = /size:(\d+)/.exec(storageRaw);
			if (match) {
				const parsed = Number.parseInt(match[1], 10);
				if (Number.isSafeInteger(parsed) && parsed >= 0) storageBytes = parsed;
			}
		} catch {
			// storage limit remains unprovable
		}
		return readSandboxCgroupMetrics(this.metricsReader, cgroupPath, storageBytes, sampledAt);
	}
}

export function unavailableMetrics(sampledAt: string): SandboxMetrics {
	return {
		available: false,
		cpuMillis: null,
		memoryBytes: null,
		pidCount: null,
		terminated: null,
		limits: { cpuMillis: null, memoryBytes: null, pidLimit: null, storageBytes: null },
		sampledAt,
	};
}
