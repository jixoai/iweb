// 用户原始需求（2026-08-14）：把窄 supervisor 协议机械映射到不可扩权的 OCI 生命周期；desired state 落盘并在重启后重建；metrics 无法证明即 unavailable。
// 正交意图：prepare 先持久化 desired state 与 gateway secret，再创建 OCI 资源；生命周期错误保留为基础设施失败；quarantine 持久且从不采纳或执行未知资源。
import type { SupervisorAdapter } from "../contracts/protocol-server.ts";
import type {
	DeleteRequest,
	InspectRequest,
	MetricsRequest,
	PrepareRequest,
	StartRequest,
	StopRequest,
} from "../contracts/protocol.ts";
import type { LifecycleState, ResourceSample } from "../contracts/records.ts";
import {
	buildSandboxSpec,
	CELLD_LISTEN_ADDRESS,
	GATEWAY_DATA_LISTEN,
	GATEWAY_OBJECT_LISTEN,
	GATEWAY_SOCKET_MOUNT_TARGET,
	isDigestPinnedImage,
	sandboxAppAddress,
	sandboxGatewayAddress,
	SANDBOX_SUBNET_MAX,
	versionBucketName,
	versionLabel,
	type SandboxSpec,
	type SandboxSpecOptions,
} from "./sandbox-spec.ts";
import { assertEndpointNotSelfLoop } from "./gateway.ts";
import { createSnapshotMaterializer, MaterializationFailure, type SnapshotMaterializerOptions } from "./snapshot-materialize.ts";
import { packageSnapshotPath } from "./sandbox-spec.ts";
import { JsonStateStore, type GatewaySecret } from "./desired-state.ts";
import { RuntimeFailure, type OciRuntime } from "./runtime.ts";

export function lifecycleFromState(state: { readonly exists: boolean; readonly running: boolean; readonly exitCode: number | null }): LifecycleState {
	if (!state.exists) return "failed";
	if (state.running) return "ready";
	if (state.exitCode !== null && state.exitCode !== 0) return "failed";
	return "stopped";
}

export interface SandboxAdapterStores {
	readonly state: JsonStateStore;
	/** Options for the snapshot materializer; omit `materializer` to disable
	 * materialization (tests) — production always materializes before create. */
	readonly materializer?: SnapshotMaterializerOptions;
}

// Fails closed: the supervisor refuses to serve when either platform image is
// not an immutable digest reference.
// Lowest free subnet index across all desired records; fails closed when the
// deterministic pool is exhausted (1024 concurrent sandboxes by design).
function allocateSubnetIndex(current: { records: Record<string, { subnetIndex?: unknown }> }): number {
	const used = new Set<number>();
	for (const record of Object.values(current.records)) {
		if (typeof record.subnetIndex === "number" && Number.isSafeInteger(record.subnetIndex)) used.add(record.subnetIndex);
	}
	for (let index = 0; index <= SANDBOX_SUBNET_MAX; index += 1) {
		if (!used.has(index)) return index;
	}
	throw new RuntimeFailure("conflict", "sandbox subnet pool is exhausted");
}

export function assertDigestPinnedOptions(options: SandboxSpecOptions): void {
	if (!isDigestPinnedImage(options.runtimeImage)) throw new Error("runtime image must be an immutable digest reference");
	if (!isDigestPinnedImage(options.gatewayImage)) throw new Error("gateway image must be an immutable digest reference");
}

export function createSandboxAdapter(runtime: OciRuntime, options: SandboxSpecOptions, stores: SandboxAdapterStores): SupervisorAdapter {
	assertDigestPinnedOptions(options);
	// Desired state is rebuilt from the durable store on every supervisor start,
	// so limits and version mapping never depend on mutable container labels.
	const desired = new Map<string, SandboxSpec>();
	const loaded = stores.state.readDesired();
	for (const [sandboxId, record] of Object.entries(loaded.records)) {
		try {
			const spec = buildSandboxSpec({ sandboxId: record.sandboxId, versionIdentity: record.versionIdentity, packageDigest: record.packageDigest, policy: record.policy, gatewayAddress: sandboxGatewayAddress(record.subnetIndex), subnetIndex: record.subnetIndex }, options);
			if (spec.sandboxId === sandboxId) desired.set(sandboxId, spec);
		} catch {
			// a corrupt desired record is skipped; the sandbox is treated as unknown
		}
	}

	const measuredValue = (value: number | null): ResourceSample["cpuMillis"] => (value === null ? { available: false } : { available: true, value });

	return {
		prepare: async (request: PrepareRequest) => {
			// Persist desired state (with a deterministic subnet allocation) before
			// any OCI side effect: if creation fails, restart reconciliation still
			// knows this sandbox was intended and can reuse its pinned addresses.
			const current = stores.state.readDesired();
			const existing = current.records[request.sandboxId];
			const subnetIndex = existing?.subnetIndex ?? allocateSubnetIndex(current);
			const spec = buildSandboxSpec({ sandboxId: request.sandboxId, versionIdentity: request.versionIdentity, packageDigest: request.packageDigest, policy: request.policy, gatewayAddress: sandboxGatewayAddress(subnetIndex), subnetIndex }, options);
			current.records[spec.sandboxId] = {
				sandboxId: spec.sandboxId,
				packageDigest: request.packageDigest,
				versionIdentity: request.versionIdentity,
				policy: request.policy,
				createdAt: existing?.createdAt ?? new Date().toISOString(),
				subnetIndex,
			};
			stores.state.writeDesired(current);
			const secret: GatewaySecret = {
				version: 1,
				sandboxId: spec.sandboxId,
				versionId: versionLabel(request.versionIdentity),
				generation: request.versionIdentity.sequence,
				bucket: versionBucketName(spec.sandboxId),
				object: request.object,
				egress: request.policy.egress,
				// Boot-required topology: the gateway dials the app's pinned address on
				// the internal sandbox network (celld listens on its container loopback
				// but is reached through its network interface), and the gateway
				// entrypoint validates both fields with parseGatewayConfig.
				ingressTarget: sandboxAppAddress(subnetIndex) + ":8787",
				socketDirectory: GATEWAY_SOCKET_MOUNT_TARGET,
				// Application persistent-data plane (2.27): provisioned by Kernel once
				// per application; the gateway enables the capability-verified data
				// proxy only when all three fields are present.
				applicationId: request.versionIdentity.applicationId,
				...(request.storageSecret !== undefined ? { storageSecret: request.storageSecret } : {}),
				...(request.data !== undefined ? { data: request.data } : {}),
			};
			stores.state.writeSecret(secret);
			// 2.33: materialize the immutable snapshot into the exact supervisor-owned
			// read-only mount the app container will bind, and verify it against the
			// single digest authority — BEFORE any OCI resource exists. A missing,
			// partial, or digest-mismatched snapshot fails closed here; the sandbox is
			// never created from (or without) unverified bytes.
			if (stores.materializer) {
				const materialize = createSnapshotMaterializer(options.stateDirectory, stores.materializer);
			try {
					await materialize(request.packageDigest, packageSnapshotPath(options.stateDirectory, request.packageDigest));
				} catch (error) {
					if (error instanceof MaterializationFailure) throw new RuntimeFailure("infrastructure", "snapshot materialization failed (" + error.kind + "): " + error.message);
					throw error;
				}
			}
			// Reject self-referential endpoint combinations BEFORE creating any pod:
			// a gateway whose object/data endpoint is its own listener cannot boot
			// and must never reach the OCI layer. The gateway re-checks at boot.
			assertEndpointNotSelfLoop(request.object.endpoint, GATEWAY_OBJECT_LISTEN, "object");
			if (request.data !== undefined) assertEndpointNotSelfLoop(request.data.endpoint, GATEWAY_DATA_LISTEN, "data");
			await runtime.create(spec, options);
			desired.set(spec.sandboxId, spec);
			return { version: 1, operation: "prepare", status: "prepared", sandboxId: request.sandboxId };
		},
		start: async (request: StartRequest) => {
			if (!desired.has(request.sandboxId)) throw new RuntimeFailure("not-found", "sandbox is not a desired sandbox");
			await runtime.start(request.sandboxId);
			return { version: 1, operation: "start", status: "started", sandboxId: request.sandboxId };
		},
		stop: async (request: StopRequest) => {
			if (!desired.has(request.sandboxId)) throw new RuntimeFailure("not-found", "sandbox is not a desired sandbox");
			await runtime.stop(request.sandboxId);
			return { version: 1, operation: "stop", status: "stopped", sandboxId: request.sandboxId };
		},
		inspect: async (request: InspectRequest) => {
			const state = await runtime.inspect(request.sandboxId);
			if (state.exists && state.labels !== null) {
				const expected = desired.get(request.sandboxId);
				if (expected !== undefined) {
					// the app container is the sandbox workload identity carrier (2.44):
				// role "app" + the trusted sandbox/version labels
				const matches = state.labels.managed && state.labels.role === "app" && state.labels.sandbox === request.sandboxId && state.labels.version === versionLabel(expected.versionIdentity);
					if (!matches) throw new RuntimeFailure("conflict", "observed sandbox identity does not match the desired record");
				}
			}
			return { version: 1, operation: "inspect", sandboxId: request.sandboxId, state: lifecycleFromState(state) };
		},
		metrics: async (request: MetricsRequest) => {
			const measurement = await runtime.metrics(request.sandboxId);
			const limits = measurement.limits;
			const anyLimit = limits.cpuMillis !== null || limits.memoryBytes !== null || limits.pidLimit !== null || limits.storageBytes !== null;
			const sample: ResourceSample = {
				versionId: request.versionId,
				sampledAt: measurement.sampledAt ?? new Date().toISOString(),
				cpuMillis: measuredValue(measurement.cpuMillis),
				memoryBytes: measuredValue(measurement.memoryBytes),
				pidCount: measuredValue(measurement.pidCount),
				terminated: measurement.terminated === null ? { available: false } : { available: true, value: measurement.terminated ? 1 : 0 },
				limits: anyLimit ? { ...limits } : null,
			};
			return { version: 1, operation: "metrics", sandboxId: request.sandboxId, sample };
		},
		delete: async (request: DeleteRequest) => {
			if (!desired.has(request.sandboxId)) throw new RuntimeFailure("not-found", "sandbox is not a desired sandbox");
			await runtime.delete(request.sandboxId);
			desired.delete(request.sandboxId);
			const current = stores.state.readDesired();
			delete current.records[request.sandboxId];
			stores.state.writeDesired(current);
			stores.state.deleteSecret(request.sandboxId);
			return { version: 1, operation: "delete", status: "deleted", sandboxId: request.sandboxId };
		},
	};
}

export interface ReconcileResult {
	readonly quarantined: readonly string[];
	readonly missing: readonly string[];
	readonly partial: readonly string[];
	readonly conflicting: readonly string[];
}

// Unknown iweb-labeled resources are stopped and removed (quarantined) and the
// quarantine is journaled durably. They are never adopted, started, or executed.
// Desired sandboxes with no observed pod are reported missing for Kernel-driven
// recovery; the supervisor never restarts them from mutable workspace content.
// For desired sandboxes whose pod IS observed, the complete child topology is
// verified on restart: a missing child is partial (rebuilt by recovery's create),
// a conflicting child is reported for quarantine. A sandbox is whole only when
// pod, gateway, and app all carry the trusted immutable identity.
export async function reconcileSandboxes(runtime: OciRuntime, knownSandboxIds: ReadonlySet<string>, stores: SandboxAdapterStores): Promise<ReconcileResult> {
	const listings = await runtime.list();
	const quarantined: string[] = [];
	const observed = new Set<string>();
	for (const item of listings) {
		observed.add(item.sandboxId);
		if (!knownSandboxIds.has(item.sandboxId)) {
			await runtime.quarantine(item.sandboxId);
			stores.state.appendQuarantine(item.sandboxId, new Date().toISOString());
			quarantined.push(item.sandboxId);
		}
	}
	const missing = [...knownSandboxIds].filter((sandboxId) => !observed.has(sandboxId));
	const desired = stores.state.readDesired().records;
	const partial: string[] = [];
	const conflicting: string[] = [];
	for (const sandboxId of knownSandboxIds) {
		if (!observed.has(sandboxId)) continue;
		const record = desired[sandboxId];
		if (!record) continue;
		const topology = await runtime.topology(sandboxId, versionLabel(record.versionIdentity));
		if (topology.pod === "conflict" || topology.gateway === "conflict" || topology.app === "conflict") conflicting.push(sandboxId);
		else if (topology.pod === "absent" || topology.gateway === "absent" || topology.app === "absent") partial.push(sandboxId);
	}
	return { quarantined, missing, partial, conflicting };
}
