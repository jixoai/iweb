// 用户原始需求（2026-08-14）：应用身份、不可变版本、生命周期、归一化策略、就绪租约、失败类别与资源采样必须有稳定 typed 记录且不接收未经检查的外部输入。
// 正交意图：全部外部输入 runtime-validate；禁用 any/as any；记录可 round-trip。
import {
	failure,
	isRecord,
	issue,
	ok,
	rejectUnknownFields,
	validateInteger,
	validateOpaqueId,
	validateSha256,
	type ValidationIssue,
	type ValidationResult,
} from "./validation.ts";
import { validateEgress, validateResources, type ManifestEgress, type ManifestResources } from "./manifest.ts";

export interface ApplicationIdentity {
	readonly id: string;
}

export interface VersionIdentity {
	readonly applicationId: string;
	readonly digest: string;
	readonly sequence: number;
}

// The stable version label used across supervisor, gateway, and Kernel for
// identity correlation (protocol metrics, readiness, runtime labels).
export function versionLabel(identity: VersionIdentity): string {
	return identity.digest + "-" + identity.sequence;
}

export type LifecycleState = "admitted" | "preparing" | "ready" | "active" | "retired" | "stopped" | "failed";

export const LIFECYCLE_STATES: readonly LifecycleState[] = ["admitted", "preparing", "ready", "active", "retired", "stopped", "failed"];

export interface NormalizedPolicy {
	readonly resources: ManifestResources;
	readonly egress: ManifestEgress;
}

export interface ReadinessLease {
	readonly versionId: string;
	readonly expiresAt: string;
}

export type FailureCategory = "admission" | "preparation" | "readiness" | "activation" | "resource-limit" | "crash" | "unknown";

export const FAILURE_CATEGORIES: readonly FailureCategory[] = ["admission", "preparation", "readiness", "activation", "resource-limit", "crash", "unknown"];

// Limits are nullable per component: a limit that cannot be proven from the
// enforcing cgroup or storage driver remains null (unavailable), never zero.
export interface ResourceLimits {
	readonly cpuMillis: number | null;
	readonly memoryBytes: number | null;
	readonly pidLimit: number | null;
	readonly storageBytes: number | null;
}

// A measurement is available with a provable value, or unavailable. Zero is
// only emitted when the measured value is provably zero; missing cgroup
// ownership, unreadable files, or restart state are never converted to zero.
export type MeasuredValue =
	| { readonly available: false }
	| { readonly available: true; readonly value: number };

export interface ResourceSample {
	readonly versionId: string;
	readonly sampledAt: string;
	readonly cpuMillis: MeasuredValue;
	readonly memoryBytes: MeasuredValue;
	readonly pidCount: MeasuredValue;
	readonly terminated: MeasuredValue;
	readonly limits: ResourceLimits | null;
}

export function validateApplicationIdentity(input: unknown): ValidationResult<ApplicationIdentity> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "application identity must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["id"], errors);
	const id = validateOpaqueId(input.id, "/id", "id", errors);
	if (errors.length) return failure(errors);
	return ok({ id: id as string });
}

export function validateVersionIdentity(input: unknown): ValidationResult<VersionIdentity> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "version identity must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["applicationId", "digest", "sequence"], errors);
	const applicationId = validateOpaqueId(input.applicationId, "/applicationId", "applicationId", errors);
	const digest = validateSha256(input.digest, "/digest", "digest", errors);
	const sequence = validateInteger(input.sequence, "/sequence", "sequence", 1, Number.MAX_SAFE_INTEGER, errors);
	if (errors.length) return failure(errors);
	return ok({ applicationId: applicationId as string, digest: digest as string, sequence: sequence as number });
}

export function validateNormalizedPolicy(input: unknown): ValidationResult<NormalizedPolicy> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "policy must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["resources", "egress"], errors);
	const resources = validateResources(input.resources, "/resources");
	if (!resources.ok) errors.push(...resources.errors);
	const egress = validateEgress(input.egress, "/egress");
	if (!egress.ok) errors.push(...egress.errors);
	if (errors.length) return failure(errors);
	return ok({
		resources: (resources as { ok: true; value: ManifestResources }).value,
		egress: (egress as { ok: true; value: ManifestEgress }).value,
	});
}

export function validateReadinessLease(input: unknown): ValidationResult<ReadinessLease> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "readiness lease must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["versionId", "expiresAt"], errors);
	const versionId = validateOpaqueId(input.versionId, "/versionId", "versionId", errors);
	const expiresAt = typeof input.expiresAt === "string" && !Number.isNaN(Date.parse(input.expiresAt)) ? input.expiresAt : null;
	if (expiresAt === null) errors.push(issue("INVALID_TIMESTAMP", "/expiresAt", "expiresAt must be an ISO timestamp"));
	if (errors.length) return failure(errors);
	return ok({ versionId: versionId as string, expiresAt: expiresAt as string });
}

export function validateFailureCategory(input: unknown): ValidationResult<FailureCategory> {
	if (typeof input !== "string" || !FAILURE_CATEGORIES.includes(input as FailureCategory)) {
		return failure([issue("INVALID_FAILURE_CATEGORY", "", "failure category is not recognized")]);
	}
	return ok(input as FailureCategory);
}

export function validateLifecycleState(input: unknown): ValidationResult<LifecycleState> {
	if (typeof input !== "string" || !LIFECYCLE_STATES.includes(input as LifecycleState)) {
		return failure([issue("INVALID_LIFECYCLE_STATE", "", "lifecycle state is not recognized")]);
	}
	return ok(input as LifecycleState);
}

export function validateResourceLimits(input: unknown, path: string): ValidationResult<ResourceLimits> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", path, "limits must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, path, ["cpuMillis", "memoryBytes", "pidLimit", "storageBytes"], errors);
	const component = (value: unknown, field: string): number | null => {
		if (value === null) return null;
		const parsed = validateInteger(value, path + "/" + field, field, 0, Number.MAX_SAFE_INTEGER, errors);
		return parsed;
	};
	const cpuMillis = component(input.cpuMillis, "cpuMillis");
	const memoryBytes = component(input.memoryBytes, "memoryBytes");
	const pidLimit = component(input.pidLimit, "pidLimit");
	const storageBytes = component(input.storageBytes, "storageBytes");
	if (errors.length) return failure(errors);
	return ok({ cpuMillis, memoryBytes, pidLimit, storageBytes });
}

function validateMeasuredValue(input: unknown, path: string, fieldName: string, errors: ValidationIssue[]): MeasuredValue | null {
	if (!isRecord(input)) {
		errors.push(issue("TYPE_OBJECT", path, fieldName + " must be an object"));
		return null;
	}
	rejectUnknownFields(input, path, ["available", "value"], errors);
	if (input.available !== true && input.available !== false) {
		errors.push(issue("INVALID_AVAILABILITY", path + "/available", fieldName + " must carry an availability flag"));
		return null;
	}
	if (input.available === true) {
		const value = validateInteger(input.value, path + "/value", fieldName + " value", 0, Number.MAX_SAFE_INTEGER, errors);
		if (errors.length) return null;
		return { available: true, value: value as number };
	}
	if (input.value !== undefined) {
		errors.push(issue("UNEXPECTED_FIELD", path + "/value", fieldName + " unavailable must not carry a value"));
		return null;
	}
	return { available: false };
}

export function validateResourceSample(input: unknown): ValidationResult<ResourceSample> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "resource sample must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["versionId", "sampledAt", "cpuMillis", "memoryBytes", "pidCount", "terminated", "limits"], errors);
	const versionId = validateOpaqueId(input.versionId, "/versionId", "versionId", errors);
	const sampledAt = typeof input.sampledAt === "string" && !Number.isNaN(Date.parse(input.sampledAt)) ? input.sampledAt : null;
	if (sampledAt === null) errors.push(issue("INVALID_TIMESTAMP", "/sampledAt", "sampledAt must be an ISO timestamp"));
	const cpuMillis = validateMeasuredValue(input.cpuMillis, "/cpuMillis", "cpuMillis", errors);
	const memoryBytes = validateMeasuredValue(input.memoryBytes, "/memoryBytes", "memoryBytes", errors);
	const pidCount = validateMeasuredValue(input.pidCount, "/pidCount", "pidCount", errors);
	const terminated = validateMeasuredValue(input.terminated, "/terminated", "terminated", errors);
	let limits: ResourceLimits | null = null;
	if (input.limits !== null) {
		const validatedLimits = validateResourceLimits(input.limits, "/limits");
		if (!validatedLimits.ok) errors.push(...validatedLimits.errors);
		else limits = validatedLimits.value;
	}
	if (errors.length) return failure(errors);
	return ok({
		versionId: versionId as string,
		sampledAt: sampledAt as string,
		cpuMillis: cpuMillis as MeasuredValue,
		memoryBytes: memoryBytes as MeasuredValue,
		pidCount: pidCount as MeasuredValue,
		terminated: terminated as MeasuredValue,
		limits,
	});
}


// --- active-version pointer (task 2.8) ---

export type ActiveVersionRecord =
	| { readonly kind: "unavailable"; readonly applicationId: string; readonly routeGeneration: number }
	| { readonly kind: "active"; readonly applicationId: string; readonly version: VersionIdentity; readonly routeGeneration: number };

export function validateActiveVersionRecord(input: unknown): ValidationResult<ActiveVersionRecord> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "active-version record must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "", ["kind", "applicationId", "version", "routeGeneration"], errors);
	const applicationId = validateOpaqueId(input.applicationId, "/applicationId", "applicationId", errors);
	const routeGeneration = validateInteger(input.routeGeneration, "/routeGeneration", "routeGeneration", 0, Number.MAX_SAFE_INTEGER, errors);

	if (input.kind === "unavailable") {
		if (input.version !== undefined) errors.push(issue("UNEXPECTED_FIELD", "/version", "unavailable record must not carry a version"));
		if (errors.length) return failure(errors);
		return ok({ kind: "unavailable", applicationId: applicationId as string, routeGeneration: routeGeneration as number });
	}

	if (input.kind === "active") {
		const version = validateVersionIdentity(input.version);
		if (!version.ok) errors.push(...version.errors);
		else if (version.value.applicationId !== applicationId) {
			errors.push(issue("IDENTITY_MISMATCH", "/version/applicationId", "active version must belong to the same application"));
		}
		if (errors.length) return failure(errors);
		return ok({
			kind: "active",
			applicationId: applicationId as string,
			version: (version as { ok: true; value: VersionIdentity }).value,
			routeGeneration: routeGeneration as number,
		});
	}

	errors.push(issue("INVALID_KIND", "/kind", "kind must be unavailable or active"));
	return failure(errors);
}

