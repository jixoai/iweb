// 用户原始需求（2026-08-14）：supervisor 只能以固定、不可扩权的 OCI 参数创建沙箱；任意 image/command/host path/device/capability/network 都不得进入 spec。
// 正交意图：2.44 强制网络边界——Worker 仅挂 internal 网络（无外部路由），Gateway 双挂 internal+external；拒绝共享 netns 与共享 slirp（design.md 2A REJECTED A/B）。
import { type NormalizedPolicy, type VersionIdentity, versionLabel } from "../contracts/records.ts";

export interface SandboxMountSpec {
	readonly kind: "bind" | "tmpfs";
	readonly source: string;
	readonly target: string;
	readonly readOnly: boolean;
}

export interface SandboxSpec {
	readonly sandboxId: string;
	readonly versionIdentity: VersionIdentity;
	readonly runtimeImage: string;
	readonly gatewayImage: string;
	// Address of the gateway's object/egress/data proxies on the internal
	// sandbox network, discovered by inspecting the gateway container AFTER it is
	// created. The app container dials exactly this address.
	readonly gatewayAddress: string;
	readonly subnetIndex: number;
	readonly command: readonly string[];
	readonly environment: readonly string[];
	readonly mounts: readonly SandboxMountSpec[];
	readonly cpuMillis: number;
	readonly memoryBytes: number;
	readonly pidLimit: number;
	readonly storageBytes: number;
	readonly egress: NormalizedPolicy["egress"];
}

export interface SandboxSpecOptions {
	readonly runtimeImage: string;
	readonly gatewayImage: string;
	readonly stateDirectory: string;
	readonly gatewayRuntimeDirectory: string;
	readonly region: string;
}

export interface SandboxSpecInput {
	readonly sandboxId: string;
	readonly versionIdentity: VersionIdentity;
	readonly packageDigest: string;
	readonly policy: NormalizedPolicy;
	readonly gatewayAddress: string;
	readonly subnetIndex: number;
}

// Fixed platform constants. None of these are ever derived from request input.
export const IWEB_MANAGED_LABEL = "iweb.managed=1";
export const IWEB_ROLE_LABEL = "iweb.role=sandbox";
export const WORKER_MOUNT_TARGET = "/opt/iweb/worker";
export const SCRATCH_MOUNT_TARGET = "/tmp";
export const GATEWAY_SOCKET_MOUNT_TARGET = "/run/iweb";
export const GATEWAY_CONFIG_MOUNT_TARGET = "/etc/iweb-gateway/config.json";
export const SECCOMP_PROFILE_HOST_PATH = "/usr/local/libexec/iweb-sandbox/seccomp.json";
export const CELLD_LISTEN_ADDRESS = "127.0.0.1:8787";
// The gateway binds its app-facing proxies on every interface of its own netns:
// the internal sandbox network (app reach) and its external network. Only
// supervisor-created containers are ever attached to either network.
export const GATEWAY_BIND_HOST = "0.0.0.0";
export const GATEWAY_OBJECT_LISTEN = GATEWAY_BIND_HOST + ":9000";
export const GATEWAY_EGRESS_LISTEN = GATEWAY_BIND_HOST + ":8081";
export const GATEWAY_DATA_LISTEN = GATEWAY_BIND_HOST + ":8082";
export const READINESS_PATH = "/iweb-health";
export const GATEWAY_SUFFIX = "-gw";
export const APP_SUFFIX = "-app";
export const GATEWAY_INGRESS_SOCKET = "ingress.sock";
export const GATEWAY_SECRETS_DIR = "secrets";
export const GATEWAY_CONFIG_NAME = "gateway-config.json";

// --- Enforced network topology (2.44, design.md 2A) ---
// Worker and Gateway live in DIFFERENT network namespaces joined by exactly one
// internal network, so the Worker's only reachable peer is the Gateway:
//   iweb-sbx-<id> : --internal (no external route) — app + gateway
//   iweb-gw-<id>  : routable                   — gateway only (MinIO + egress)
// A raw socket from the app cannot reach the host, the Internet, Kernel, MinIO,
// the supervisor, or any peer sandbox: those all live beyond the internal
// network that has no default route. Proxy variables remain a cooperative hint
// for HTTP clients only — the boundary does not depend on them.
export function sandboxNetworkName(sandboxId: string): string {
	return "iweb-sbx-" + sandboxId;
}
export function gatewayNetworkName(sandboxId: string): string {
	return "iweb-gw-" + sandboxId;
}

// Deterministic per-sandbox /24 from a supervisor-allocated index. The index is
// persisted in the desired-state record so both IPs are known BEFORE any
// container exists: the gateway secret (ingressTarget) and the app's object
// endpoint are baked in one phase. 10.200.0.0/14 yields 1024 sandboxes.
export const SANDBOX_SUBNET_BASE = 200;
export const SANDBOX_SUBNET_MAX = 1023;
export function sandboxSubnetCidr(subnetIndex: number): string {
	if (!Number.isSafeInteger(subnetIndex) || subnetIndex < 0 || subnetIndex > SANDBOX_SUBNET_MAX) throw new Error("sandbox subnet index is out of range");
	const second = SANDBOX_SUBNET_BASE + Math.floor(subnetIndex / 256);
	const third = subnetIndex % 256;
	return "10." + second + "." + third + ".0/24";
}
export function sandboxGatewayAddress(subnetIndex: number): string {
	return "10." + (SANDBOX_SUBNET_BASE + Math.floor(subnetIndex / 256)) + "." + (subnetIndex % 256) + ".2";
}
export function sandboxAppAddress(subnetIndex: number): string {
	return "10." + (SANDBOX_SUBNET_BASE + Math.floor(subnetIndex / 256)) + "." + (subnetIndex % 256) + ".3";
}

const IMAGE_DIGEST_PATTERN = /^[a-z0-9._-]+(?:[/:][a-z0-9._-]+)+@sha256:[a-f0-9]{64}$/;

export function isDigestPinnedImage(value: string): boolean {
	return IMAGE_DIGEST_PATTERN.test(value);
}

export function packageSnapshotPath(stateDirectory: string, packageDigest: string): string {
	return stateDirectory + "/packages/" + packageDigest;
}

export function gatewaySocketDirectory(options: SandboxSpecOptions, sandboxId: string): string {
	return options.gatewayRuntimeDirectory + "/" + sandboxId;
}

export function gatewaySecretsPath(stateDirectory: string, sandboxId: string): string {
	return stateDirectory + "/" + GATEWAY_SECRETS_DIR + "/" + sandboxId + ".json";
}

export function gatewayContainerName(sandboxId: string): string {
	return sandboxId + GATEWAY_SUFFIX;
}

export function appContainerName(sandboxId: string): string {
	return sandboxId + APP_SUFFIX;
}

export function versionBucketName(sandboxId: string): string {
	return "iweb-app-" + sandboxId;
}

export { versionLabel };

export function buildSandboxSpec(input: SandboxSpecInput, options: SandboxSpecOptions): SandboxSpec {
	const bucket = versionBucketName(input.sandboxId);
	const gateway = input.gatewayAddress;
	return {
		sandboxId: input.sandboxId,
		versionIdentity: input.versionIdentity,
		runtimeImage: options.runtimeImage,
		gatewayImage: options.gatewayImage,
		gatewayAddress: gateway,
		subnetIndex: input.subnetIndex,
		// The executable authority is the runtime image ENTRYPOINT (celld). These
		// are arguments only; the name "celld" never appears here.
		command: [
			"--bucket", "s3://" + bucket,
			"--endpoint", "http://" + gateway + ":9000",
			"--region", options.region,
			"--listen", CELLD_LISTEN_ADDRESS,
		],
		environment: [
			"CELLD_NODE=" + input.sandboxId,
			// Cooperative hint ONLY (2.44): the enforced boundary is the internal
			// network; these variables make well-behaved HTTP clients use the
			// gateway without assuming they do.
			"HTTP_PROXY=http://" + gateway + ":8081",
			"HTTPS_PROXY=http://" + gateway + ":8081",
			"http_proxy=http://" + gateway + ":8081",
			"https_proxy=http://" + gateway + ":8081",
			"NO_PROXY=" + gateway + ",127.0.0.1,localhost",
			"no_proxy=" + gateway + ",127.0.0.1,localhost",
		],
		mounts: [
			{ kind: "bind", source: packageSnapshotPath(options.stateDirectory, input.packageDigest), target: WORKER_MOUNT_TARGET, readOnly: true },
			{ kind: "tmpfs", source: "tmpfs", target: SCRATCH_MOUNT_TARGET, readOnly: false },
		],
		cpuMillis: input.policy.resources.cpuMillis,
		memoryBytes: input.policy.resources.memoryBytes,
		pidLimit: input.policy.resources.pidLimit,
		storageBytes: input.policy.resources.storageBytes,
		egress: input.policy.egress,
	};
}

// --- assembled podman invocations (2.44 dual-network) ---

export function buildNetworkCreateArgs(sandboxId: string, internal: boolean, subnetIndex: number): string[] {
	const args = ["network", "create"];
	if (internal) args.push("--internal", "--subnet", sandboxSubnetCidr(subnetIndex));
	args.push(internal ? sandboxNetworkName(sandboxId) : gatewayNetworkName(sandboxId));
	return args;
}

// The gateway joins BOTH networks: the internal one (its only link to the app)
// and its own routable network (the only path to host MinIO and the Internet).
export function buildGatewayContainerCreateArgs(spec: SandboxSpec, options: SandboxSpecOptions): string[] {
	const socketDirectory = gatewaySocketDirectory(options, spec.sandboxId);
	const secretsPath = gatewaySecretsPath(options.stateDirectory, spec.sandboxId);
	return [
		"create",
		"--name", gatewayContainerName(spec.sandboxId),
		"--label", IWEB_MANAGED_LABEL,
		"--label", "iweb.sandbox=" + spec.sandboxId,
		"--label", "iweb.role=gateway",
		"--label", "iweb.version=" + versionLabel(spec.versionIdentity),
		// resource envelope lives with the app container (the workload); the
		// gateway is supervisor-owned tooling
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + SECCOMP_PROFILE_HOST_PATH,
		// The gateway joins TWO networks, so its pinned address must use the
		// per-network interface option (net:ip=<addr>). A global --ip is rejected
		// by podman ("--ip can only be set for a single network") — this was
		// exposed by the first real host lifecycle run.
		"--network", sandboxNetworkName(spec.sandboxId) + ":ip=" + sandboxGatewayAddress(spec.subnetIndex) + "," + gatewayNetworkName(spec.sandboxId),
		"--mount", "type=bind,source=" + socketDirectory + ",target=" + GATEWAY_SOCKET_MOUNT_TARGET,
		"--mount", "type=bind,source=" + secretsPath + ",target=" + GATEWAY_CONFIG_MOUNT_TARGET + ",ro",
		"--env", "IWEB_GATEWAY_CONFIG=" + GATEWAY_CONFIG_MOUNT_TARGET,
		"--env", "IWEB_GATEWAY_SOCKET_DIR=" + GATEWAY_SOCKET_MOUNT_TARGET,
		spec.gatewayImage,
	];
}

// The app joins ONLY the internal network: structurally no route to the host,
// the Internet, the supervisor, or any peer sandbox.
export function buildAppContainerCreateArgs(spec: SandboxSpec, options: SandboxSpecOptions): string[] {
	const args: string[] = [
		"create",
		"--name", appContainerName(spec.sandboxId),
		"--label", IWEB_MANAGED_LABEL,
		"--label", "iweb.sandbox=" + spec.sandboxId,
		"--label", "iweb.role=app",
		"--label", "iweb.version=" + versionLabel(spec.versionIdentity),
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + SECCOMP_PROFILE_HOST_PATH,
		"--network", sandboxNetworkName(spec.sandboxId),
		"--ip", sandboxAppAddress(spec.subnetIndex),
		"--cpus", String(spec.cpuMillis / 1000),
		"--memory", String(spec.memoryBytes),
		"--pids-limit", String(spec.pidLimit),
		"--storage-opt", "size=" + String(spec.storageBytes),
	];
	for (const mount of spec.mounts) {
		if (mount.kind === "bind") {
			args.push("--mount", "type=bind,source=" + mount.source + ",target=" + mount.target + (mount.readOnly ? ",ro" : ""));
		} else {
			args.push("--mount", "type=tmpfs,target=" + mount.target + ",tmpfs-mode=1777,noexec,nosuid,size=" + spec.storageBytes);
		}
	}
	for (const environment of spec.environment) {
		args.push("--env", environment);
	}
	args.push(spec.runtimeImage);
	args.push(...spec.command);
	return args;
}

export function buildNetworkRemoveArgs(sandboxId: string): string[] {
	return ["network", "rm", "-f", sandboxNetworkName(sandboxId), gatewayNetworkName(sandboxId)];
}
