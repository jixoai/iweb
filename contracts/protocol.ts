// 用户原始需求（2026-08-14）：Kernel 与 supervisor 之间只允许窄版本化 prepare/start/stop/inspect/metrics/delete union。
// 正交意图：opaque ID；固定请求变体；任意 image/command/host path/device/capability/network mode/socket/identifier 均无表达面。
import { createHash } from "node:crypto";
import {
	failure,
	isRecord,
	issue,
	ok,
	rejectUnknownFields,
	validateOpaqueId,
	validateSha256,
	type ValidationIssue,
	type ValidationResult,
} from "./validation.ts";
import {
	validateNormalizedPolicy,
	validateResourceSample,
	validateVersionIdentity,
	type LifecycleState,
	type NormalizedPolicy,
	type ResourceSample,
	type VersionIdentity,
} from "./records.ts";

export const PROTOCOL_VERSION = 1;

export const RESERVED_SANDBOX_IDS: readonly string[] = ["supervisor", "kernel", "admin", "mcp", "api", "root", "host", "system", "control", "operator"];

export interface ObjectCredential {
	readonly endpoint: string;
	readonly region: string;
	readonly accessKeyId: string;
	readonly secretAccessKey: string;
}

export interface PrepareRequest {
	readonly version: 1;
	readonly operation: "prepare";
	readonly sandboxId: string;
	readonly versionIdentity: VersionIdentity;
	readonly packageDigest: string;
	readonly policy: NormalizedPolicy;
	// Version-scoped object credential. It is injected into the sandbox gateway
	// container only and never into the application container or any record.
	readonly object: ObjectCredential;
	// Optional application persistent-data plane provisioning (2.27): a shared
	// per-application storage secret and a data credential scoped to the
	// application's stable namespace. Both are gateway-only, like `object`.
	readonly storageSecret?: string;
	readonly data?: ObjectCredential;
}

export interface StartRequest {
	readonly version: 1;
	readonly operation: "start";
	readonly sandboxId: string;
}

export interface StopRequest {
	readonly version: 1;
	readonly operation: "stop";
	readonly sandboxId: string;
}

export interface InspectRequest {
	readonly version: 1;
	readonly operation: "inspect";
	readonly sandboxId: string;
}

export interface MetricsRequest {
	readonly version: 1;
	readonly operation: "metrics";
	readonly sandboxId: string;
	readonly versionId: string;
}

export interface DeleteRequest {
	readonly version: 1;
	readonly operation: "delete";
	readonly sandboxId: string;
}

export type SupervisorRequest = PrepareRequest | StartRequest | StopRequest | InspectRequest | MetricsRequest | DeleteRequest;

export interface PrepareResponse {
	readonly version: 1;
	readonly operation: "prepare";
	readonly status: "prepared";
	readonly sandboxId: string;
}

export interface StartResponse {
	readonly version: 1;
	readonly operation: "start";
	readonly status: "started";
	readonly sandboxId: string;
}

export interface StopResponse {
	readonly version: 1;
	readonly operation: "stop";
	readonly status: "stopped";
	readonly sandboxId: string;
}

export interface InspectResponse {
	readonly version: 1;
	readonly operation: "inspect";
	readonly sandboxId: string;
	readonly state: LifecycleState;
}

export interface MetricsResponse {
	readonly version: 1;
	readonly operation: "metrics";
	readonly sandboxId: string;
	readonly sample: ResourceSample;
}

export interface DeleteResponse {
	readonly version: 1;
	readonly operation: "delete";
	readonly status: "deleted";
	readonly sandboxId: string;
}

export type SupervisorResponse = PrepareResponse | StartResponse | StopResponse | InspectResponse | MetricsResponse | DeleteResponse;

export function isReservedSandboxId(value: string): boolean {
	return RESERVED_SANDBOX_IDS.includes(value);
}

export function validateSupervisorRequest(input: unknown): ValidationResult<SupervisorRequest> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "supervisor request must be an object")]);
	const errors: ValidationIssue[] = [];
	if (input.version !== PROTOCOL_VERSION) errors.push(issue("INVALID_VERSION", "/version", "protocol version must be " + PROTOCOL_VERSION));
	const operation = input.operation;
	if (operation !== "prepare" && operation !== "start" && operation !== "stop" && operation !== "inspect" && operation !== "metrics" && operation !== "delete") {
		errors.push(issue("INVALID_OPERATION", "/operation", "operation is not recognized"));
		return failure(errors);
	}
	switch (operation) {
		case "prepare": {
			rejectUnknownFields(input, "", ["version", "operation", "sandboxId", "versionIdentity", "packageDigest", "policy", "object", "storageSecret", "data"], errors);
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			const versionIdentity = validateVersionIdentity(input.versionIdentity);
			if (!versionIdentity.ok) errors.push(...versionIdentity.errors);
			const packageDigest = validateSha256(input.packageDigest, "/packageDigest", "packageDigest", errors);
			const policy = validateNormalizedPolicy(input.policy);
			if (!policy.ok) errors.push(...policy.errors);
			const object = validateObjectCredential(input.object);
			if (!object.ok) errors.push(...object.errors);
			const storageSecret = input.storageSecret === undefined ? undefined : validateBoundedSecret(input.storageSecret, "/storageSecret", "storageSecret", 32, 512, errors) ?? undefined;
			let data: ObjectCredential | undefined;
			if (input.data !== undefined) {
				const dataCredential = validateObjectCredential(input.data);
				if (!dataCredential.ok) errors.push(...dataCredential.errors);
				else data = (dataCredential as { ok: true; value: ObjectCredential }).value;
			}
			if (errors.length) return failure(errors);
			return ok({
				version: 1,
				operation: "prepare",
				sandboxId: sandboxId as string,
				versionIdentity: (versionIdentity as { ok: true; value: VersionIdentity }).value,
				packageDigest: packageDigest as string,
				policy: (policy as { ok: true; value: NormalizedPolicy }).value,
				object: (object as { ok: true; value: ObjectCredential }).value,
				...(storageSecret !== undefined ? { storageSecret } : {}),
				...(data !== undefined ? { data } : {}),
			});
		}
		case "start":
		case "stop":
		case "inspect":
		case "delete": {
			rejectUnknownFields(input, "", ["version", "operation", "sandboxId"], errors);
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation, sandboxId: sandboxId as string } as SupervisorRequest);
		}
		case "metrics": {
			rejectUnknownFields(input, "", ["version", "operation", "sandboxId", "versionId"], errors);
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			const versionId = validateOpaqueId(input.versionId, "/versionId", "versionId", errors);
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation: "metrics", sandboxId: sandboxId as string, versionId: versionId as string });
		}
		default:
			return failure([issue("INVALID_OPERATION", "/operation", "operation is not recognized")]);
	}
}

const PRINTABLE_SECRET_PATTERN = /^[\x20-\x7e]+$/;

function validateBoundedSecret(value: unknown, path: string, fieldName: string, minimum: number, maximum: number, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || value.length < minimum || value.length > maximum || !PRINTABLE_SECRET_PATTERN.test(value)) {
		errors.push(issue("INVALID_CREDENTIAL", path, fieldName + " must be printable text of bounded length"));
		return null;
	}
	return value;
}

// The object credential is narrowly scoped and validated before it can enter
// supervisor state. It never appears in logs, responses, or inspectable records.
export function validateObjectCredential(input: unknown): ValidationResult<ObjectCredential> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "/object", "object must be an object")]);
	const errors: ValidationIssue[] = [];
	rejectUnknownFields(input, "/object", ["endpoint", "region", "accessKeyId", "secretAccessKey"], errors);
	let endpoint: string | null = null;
	if (typeof input.endpoint !== "string" || input.endpoint.length > 256) {
		errors.push(issue("INVALID_ENDPOINT", "/object/endpoint", "endpoint must be a bounded URL"));
	} else {
		try {
			const parsed = new URL(input.endpoint);
			const allowed = parsed.protocol === "http:" || parsed.protocol === "https:";
			if (!allowed || parsed.username !== "" || parsed.password !== "" || (parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search !== "" || parsed.hash !== "") {
				errors.push(issue("INVALID_ENDPOINT", "/object/endpoint", "endpoint must be an http(s) origin"));
			} else {
				endpoint = input.endpoint;
			}
		} catch {
			errors.push(issue("INVALID_ENDPOINT", "/object/endpoint", "endpoint must be a parseable URL"));
		}
	}
	let region: string | null = null;
	if (typeof input.region !== "string" || !/^[a-z0-9-]{1,64}$/.test(input.region)) {
		errors.push(issue("INVALID_REGION", "/object/region", "region must be a bounded lowercase identifier"));
	} else {
		region = input.region;
	}
	const accessKeyId = validateBoundedSecret(input.accessKeyId, "/object/accessKeyId", "accessKeyId", 1, 256, errors);
	const secretAccessKey = validateBoundedSecret(input.secretAccessKey, "/object/secretAccessKey", "secretAccessKey", 1, 512, errors);
	if (errors.length) return failure(errors);
	return ok({ endpoint: endpoint as string, region: region as string, accessKeyId: accessKeyId as string, secretAccessKey: secretAccessKey as string });
}

export function deriveSandboxId(applicationId: string, versionDigest: string, sequence: number): string {
	const identity = applicationId + "\0" + versionDigest + "\0" + sequence;
	return "sbx-" + createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 40);
}

export function validateSemanticIdentity(request: SupervisorRequest): ValidationResult<SupervisorRequest> {
	const sandboxId = request.sandboxId;
	if (isReservedSandboxId(sandboxId)) {
		return failure([issue("RESERVED_IDENTIFIER", "/sandboxId", "sandbox identifier is reserved")]);
	}
	if (request.operation === "prepare") {
		const derived = deriveSandboxId(request.versionIdentity.applicationId, request.versionIdentity.digest, request.versionIdentity.sequence);
		if (sandboxId !== derived) {
			return failure([issue("IDENTITY_MISMATCH", "/sandboxId", "sandbox identifier must be derived from the application and version identity")]);
		}
	}
	return ok(request);
}

export function validateSupervisorResponse(input: unknown): ValidationResult<SupervisorResponse> {
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "supervisor response must be an object")]);
	const errors: ValidationIssue[] = [];
	if (input.version !== PROTOCOL_VERSION) errors.push(issue("INVALID_VERSION", "/version", "protocol version must be " + PROTOCOL_VERSION));
	const operation = input.operation;
	switch (operation) {
		case "prepare": {
			rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
			if (input.status !== "prepared") errors.push(issue("INVALID_STATUS", "/status", "prepare response status must be prepared"));
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation: "prepare", status: "prepared", sandboxId: sandboxId as string });
		}
		case "start": {
			rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
			if (input.status !== "started") errors.push(issue("INVALID_STATUS", "/status", "start response status must be started"));
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation: "start", status: "started", sandboxId: sandboxId as string });
		}
		case "stop": {
			rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
			if (input.status !== "stopped") errors.push(issue("INVALID_STATUS", "/status", "stop response status must be stopped"));
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation: "stop", status: "stopped", sandboxId: sandboxId as string });
		}
		case "delete": {
			rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
			if (input.status !== "deleted") errors.push(issue("INVALID_STATUS", "/status", "delete response status must be deleted"));
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation: "delete", status: "deleted", sandboxId: sandboxId as string });
		}
		case "inspect": {
			rejectUnknownFields(input, "", ["version", "operation", "sandboxId", "state"], errors);
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			const state = input.state;
			if (state !== "admitted" && state !== "preparing" && state !== "ready" && state !== "active" && state !== "retired" && state !== "stopped" && state !== "failed") {
				errors.push(issue("INVALID_LIFECYCLE_STATE", "/state", "lifecycle state is not recognized"));
			}
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation: "inspect", sandboxId: sandboxId as string, state: state as LifecycleState });
		}
		case "metrics": {
			rejectUnknownFields(input, "", ["version", "operation", "sandboxId", "sample"], errors);
			const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
			const sample = validateResourceSample(input.sample);
			if (!sample.ok) errors.push(...sample.errors);
			if (errors.length) return failure(errors);
			return ok({ version: 1, operation: "metrics", sandboxId: sandboxId as string, sample: (sample as { ok: true; value: ResourceSample }).value });
		}
		default:
			return failure([issue("INVALID_OPERATION", "/operation", "operation is not recognized")]);
	}
}

export function correlateResponse(request: SupervisorRequest, response: SupervisorResponse): ValidationResult<SupervisorResponse> {
	const errors: ValidationIssue[] = [];
	if (response.version !== PROTOCOL_VERSION) errors.push(issue("INVALID_VERSION", "/version", "protocol version must be " + PROTOCOL_VERSION));
	if (response.operation !== request.operation) errors.push(issue("OPERATION_MISMATCH", "/operation", "response operation does not match the request"));
	if (response.sandboxId !== request.sandboxId) errors.push(issue("SANDBOX_MISMATCH", "/sandboxId", "response sandbox identity does not match the request"));
	if (request.operation === "metrics" && response.operation === "metrics" && response.sample.versionId !== request.versionId) {
		errors.push(issue("VERSION_MISMATCH", "/sample/versionId", "metrics version identity does not match the requested sandbox version"));
	}
	if (errors.length) return failure(errors);
	return ok(response);
}
