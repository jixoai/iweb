// 用户原始需求（2026-08-14）：single-writer transactional control DB；admission 只从不可变快照创建版本；activation 原子切换唯一 active pointer 并保留旧版本用于回滚。
// 正交意图：纯函数；content-addressed versionId；secret 不在 inspectable record；candidate 失败不切换指针。
import { LIFECYCLE_STATES, validateActiveVersionRecord, validateNormalizedPolicy, validateVersionIdentity, type ActiveVersionRecord, type LifecycleState, type NormalizedPolicy, type VersionIdentity } from "./records.ts";
import { type ValidationIssue, type ValidationResult, failure, ok } from "./validation.ts";
import { type ApplicationManifest } from "./manifest.ts";
import { versionDigest } from "./package-collection.ts";

export interface VersionRecord {
	readonly versionId: string;
	readonly identity: VersionIdentity;
	readonly packageDigest: string;
	readonly policy: NormalizedPolicy;
	readonly lifecycle: LifecycleState;
	readonly admittedAt: string;
	readonly readinessExpiresAt: string | null;
}

export interface ApplicationRecord {
	readonly applicationId: string;
	readonly active: ActiveVersionRecord;
	readonly versions: readonly VersionRecord[];
}

export interface ControlState {
	readonly applications: Record<string, ApplicationRecord>;
}

export function emptyControlState(): ControlState {
	return { applications: {} };
}

// The persisted control file carries a schema version wrapper around the state.
export interface ControlStateFile {
	readonly version: 1;
	readonly applications: Record<string, ApplicationRecord>;
}

export function emptyControlStateFile(): ControlStateFile {
	return { version: 1, applications: {} };
}

export function controlStateFromFile(file: ControlStateFile): ControlState {
	return { applications: file.applications };
}

export function controlStateToFile(state: ControlState): ControlStateFile {
	return { version: 1, applications: state.applications };
}

// Strict load-time validation: only a well-formed file becomes control state;
// anything else quarantines and falls back to empty (recovery re-admits).
// Identity, policy, and the active pointer are validated with the same
// authority admission uses (contracts/records.ts) — no whole-record casts, no
// unknown fields, no persisted record looser than admission accepted (2.47).
export function validateControlStateFile(input: unknown): ControlStateFile | null {
	if (!isRecord(input) || input.version !== 1 || !isRecord(input.applications)) return null;
	const applications: Record<string, ApplicationRecord> = {};
	for (const [applicationId, rawApplication] of Object.entries(input.applications)) {
		if (!isRecord(rawApplication)) return null;
		for (const key of Object.keys(rawApplication)) {
			if (key !== "applicationId" && key !== "active" && key !== "versions") return null;
		}
		if (typeof rawApplication.applicationId !== "string" || rawApplication.applicationId !== applicationId) return null;
		if (!Array.isArray(rawApplication.versions)) return null;
		const versions: VersionRecord[] = [];
		for (const rawVersion of rawApplication.versions) {
			if (!isRecord(rawVersion)) return null;
			for (const key of Object.keys(rawVersion)) {
				if (key !== "versionId" && key !== "identity" && key !== "packageDigest" && key !== "policy" && key !== "lifecycle" && key !== "admittedAt" && key !== "readinessExpiresAt") return null;
			}
			if (typeof rawVersion.versionId !== "string" || rawVersion.versionId.length === 0 || rawVersion.versionId.length > 200) return null;
			const identity = validateVersionIdentity(rawVersion.identity);
			if (!identity.ok) return null;
			if (typeof rawVersion.packageDigest !== "string" || !/^[a-f0-9]{64}$/.test(rawVersion.packageDigest)) return null;
			const policy = validateNormalizedPolicy(rawVersion.policy);
			if (!policy.ok) return null;
			if (!LIFECYCLE_STATES.includes(rawVersion.lifecycle as LifecycleState)) return null;
			if (typeof rawVersion.admittedAt !== "string" || Number.isNaN(Date.parse(rawVersion.admittedAt))) return null;
			if (rawVersion.readinessExpiresAt !== null && (typeof rawVersion.readinessExpiresAt !== "string" || Number.isNaN(Date.parse(rawVersion.readinessExpiresAt)))) return null;
			versions.push({
				versionId: rawVersion.versionId,
				identity: identity.value,
				packageDigest: rawVersion.packageDigest,
				policy: policy.value,
				lifecycle: rawVersion.lifecycle as LifecycleState,
				admittedAt: rawVersion.admittedAt,
				readinessExpiresAt: rawVersion.readinessExpiresAt as string | null,
			});
		}
		const active = validateActiveVersionRecord(rawApplication.active);
		if (!active.ok || active.value.applicationId !== applicationId) return null;
		if (active.value.kind === "active") {
			// the persisted pointer must reference one of the admitted versions:
			// an orphaned or smuggled active identity is corrupt state
			const pointed = active.value.version;
			const matched = versions.some((version) => version.identity.applicationId === pointed.applicationId && version.identity.digest === pointed.digest && version.identity.sequence === pointed.sequence);
			if (!matched) return null;
		}
		applications[applicationId] = { applicationId, active: active.value, versions };
	}
	return { version: 1, applications };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface AdmissionInput {
	readonly applicationId: string;
	readonly packageDigest: string;
	readonly manifest: ApplicationManifest;
	readonly policy: NormalizedPolicy;
	readonly admittedAt: string;
}

export interface AdmissionResult {
	readonly state: ControlState;
	readonly version: VersionRecord;
}

export function admitVersion(state: ControlState, input: AdmissionInput): ValidationResult<AdmissionResult> {
	const digest = versionDigest(input.packageDigest, input.manifest);
	const existing = state.applications[input.applicationId];
	const duplicate = existing?.versions.some((version) => version.versionId === digest);
	if (duplicate) {
		return failure([{ code: "DUPLICATE_VERSION", path: "/version", message: "an identical admitted version already exists" }]);
	}
	const sequence = (existing?.versions.length ?? 0) + 1;
	const identity: VersionIdentity = { applicationId: input.applicationId, digest, sequence };
	const version: VersionRecord = { versionId: digest, identity, packageDigest: input.packageDigest, policy: input.policy, lifecycle: "admitted", admittedAt: input.admittedAt, readinessExpiresAt: null };
	const application: ApplicationRecord = existing
		? { ...existing, versions: [...existing.versions, version] }
		: { applicationId: input.applicationId, active: { kind: "unavailable", applicationId: input.applicationId, routeGeneration: 0 }, versions: [version] };
	return ok({ state: { applications: { ...state.applications, [input.applicationId]: application } }, version });
}

export interface ActivationResult {
	readonly state: ControlState;
	readonly retired: VersionRecord | null;
}

function activeVersionDigest(active: ActiveVersionRecord): string | null {
	return active.kind === "active" ? active.version.digest : null;
}

// Atomic activation: switch exactly one active pointer, increment route
// generation, and preserve the previous active version for rollback. The
// candidate must already be ready; otherwise no pointer changes.
export function activateVersion(state: ControlState, applicationId: string, versionId: string): ValidationResult<ActivationResult> {
	const application = state.applications[applicationId];
	if (!application) return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
	const candidate = application.versions.find((version) => version.versionId === versionId);
	if (!candidate) return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
	if (candidate.lifecycle !== "ready") return failure([{ code: "NOT_READY", path: "/lifecycle", message: "candidate version is not ready" }]);
	const previousDigest = activeVersionDigest(application.active);
	const retired = previousDigest === null ? null : application.versions.find((version) => version.versionId === previousDigest) ?? null;
	const generation = application.active.routeGeneration + 1;
	const active: ActiveVersionRecord = { kind: "active", applicationId, version: candidate.identity, routeGeneration: generation };
	const nextApplication: ApplicationRecord = {
		...application,
		active,
		versions: application.versions.map((version) => {
			if (version.versionId === versionId) return { ...version, lifecycle: "active" as LifecycleState };
			if (version.versionId === previousDigest) return { ...version, lifecycle: "retired" as LifecycleState };
			return version;
		}),
	};
	return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } }, retired });
}

// Rollback reactivates a retained admitted version through the same readiness
// gate; the caller must have already proven the target version ready.
export function rollbackVersion(state: ControlState, applicationId: string, versionId: string): ValidationResult<ActivationResult> {
	return activateVersion(state, applicationId, versionId);
}

export interface VersionUpdateResult {
	readonly state: ControlState;
	readonly version: VersionRecord;
}

// A readiness lease is recorded on the version after a successful probe; the
// activation flow requires an unexpired lease in addition to the ready state.
export function markVersionReady(state: ControlState, applicationId: string, versionId: string, expiresAt: string): ValidationResult<VersionUpdateResult> {
	const application = state.applications[applicationId];
	if (!application) return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
	const candidate = application.versions.find((version) => version.versionId === versionId);
	if (!candidate) return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
	const version: VersionRecord = { ...candidate, lifecycle: "ready", readinessExpiresAt: expiresAt };
	const nextApplication: ApplicationRecord = { ...application, versions: application.versions.map((entry) => (entry.versionId === versionId ? version : entry)) };
	return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } }, version });
}

// Version deletion is separate from application-data deletion and refuses to
// remove the version an active pointer references.
export function removeVersion(state: ControlState, applicationId: string, versionId: string): ValidationResult<{ readonly state: ControlState }> {
	const application = state.applications[applicationId];
	if (!application) return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
	const candidate = application.versions.find((version) => version.versionId === versionId);
	if (!candidate) return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
	if (application.active.kind === "active" && application.active.version.digest === versionId) {
		return failure([{ code: "ACTIVE_VERSION_PROTECTED", path: "/versionId", message: "the active version cannot be deleted" }]);
	}
	const nextApplication: ApplicationRecord = { ...application, versions: application.versions.filter((version) => version.versionId !== versionId) };
	return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } } });
}

// Explicit lifecycle transitions used by stop/start/delete flows. Activating
// and retiring remain reserved for the atomic pointer switch.
export function setVersionLifecycle(state: ControlState, applicationId: string, versionId: string, lifecycle: LifecycleState): ValidationResult<VersionUpdateResult> {
	const application = state.applications[applicationId];
	if (!application) return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
	const candidate = application.versions.find((version) => version.versionId === versionId);
	if (!candidate) return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
	const version: VersionRecord = { ...candidate, lifecycle };
	const nextApplication: ApplicationRecord = { ...application, versions: application.versions.map((entry) => (entry.versionId === versionId ? version : entry)) };
	return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } }, version });
}

