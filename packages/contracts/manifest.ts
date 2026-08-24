// 用户原始需求（2026-08-14）：版本化 iweb.json 包 schema，固定 runtime/entrypoint、静态资源、有限资源与存储策略、默认拒绝 egress。
// 正交意图：拒绝 unknown field、绝对路径、..、symlink escape、shell command、arbitrary image 和无界资源。
import {
	failure,
	isRecord,
	issue,
	ok,
	rejectUnknownFields,
	validateDnsName,
	validateInteger,
	validateOpaqueId,
	validateSafeRelativePath,
	type ValidationIssue,
	type ValidationResult,
} from "./validation.ts";

export const MANIFEST_SCHEMA_VERSION = 1;
export const MAX_EGRESS_RULES = 256;

export const RESOURCE_BOUNDS = {
	cpuMillisMin: 1,
	cpuMillisMax: 1_000_000,
	memoryBytesMin: 1,
	memoryBytesMax: 64 * 2 ** 30,
	pidLimitMin: 1,
	pidLimitMax: 1_000_000,
	storageBytesMin: 0,
	storageBytesMax: 2 ** 40,
} as const;

const CELD_VERSION_PATTERN = /^\d+\.\d+\.\d+$/;

export interface ManifestRuntime {
	readonly kind: "celld";
	readonly celldVersion: string;
	readonly entrypoint: string;
}

export interface ManifestAssets {
	readonly root: string;
}

export interface ManifestResources {
	readonly cpuMillis: number;
	readonly memoryBytes: number;
	readonly pidLimit: number;
	readonly storageBytes: number;
}

export interface ManifestStorage {
	readonly persistent: boolean;
	readonly requestBytes: number;
}

export interface ManifestEgressRule {
	readonly host: string;
	readonly port: number;
}

export interface ManifestEgress {
	readonly default: "deny";
	readonly allow: readonly ManifestEgressRule[];
}

export interface ApplicationManifest {
	readonly schemaVersion: 1;
	readonly name: string;
	readonly runtime: ManifestRuntime;
	readonly assets: ManifestAssets;
	readonly resources: ManifestResources;
	readonly storage: ManifestStorage;
	readonly egress: ManifestEgress;
}

function validateRuntime(input: unknown, path: string): ValidationResult<ManifestRuntime> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", path, "runtime must be an object")]);
	rejectUnknownFields(input, path, ["kind", "celldVersion", "entrypoint"], errors);
	if (input.kind !== "celld") errors.push(issue("INVALID_RUNTIME", path + "/kind", "runtime kind must be celld"));
	const celldVersion = typeof input.celldVersion === "string" && CELD_VERSION_PATTERN.test(input.celldVersion) ? input.celldVersion : null;
	if (celldVersion === null) errors.push(issue("INVALID_VERSION", path + "/celldVersion", "celldVersion must be a pinned semver"));
	const entrypoint = typeof input.entrypoint === "string" ? input.entrypoint : null;
	if (entrypoint === null || !entrypoint.endsWith(".js")) errors.push(issue("INVALID_ENTRYPOINT", path + "/entrypoint", "entrypoint must be a .js module"));
	else validateSafeRelativePath(entrypoint, path + "/entrypoint", "entrypoint", errors);
	if (errors.length) return failure(errors);
	return ok({ kind: "celld", celldVersion: celldVersion as string, entrypoint: entrypoint as string });
}

function validateAssets(input: unknown, path: string): ValidationResult<ManifestAssets> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", path, "assets must be an object")]);
	rejectUnknownFields(input, path, ["root"], errors);
	const root = validateSafeRelativePath(input.root, path + "/root", "assets.root", errors);
	if (errors.length) return failure(errors);
	return ok({ root: root as string });
}

export function validateResources(input: unknown, path: string): ValidationResult<ManifestResources> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", path, "resources must be an object")]);
	rejectUnknownFields(input, path, ["cpuMillis", "memoryBytes", "pidLimit", "storageBytes"], errors);
	const cpuMillis = validateInteger(input.cpuMillis, path + "/cpuMillis", "cpuMillis", RESOURCE_BOUNDS.cpuMillisMin, RESOURCE_BOUNDS.cpuMillisMax, errors);
	const memoryBytes = validateInteger(input.memoryBytes, path + "/memoryBytes", "memoryBytes", RESOURCE_BOUNDS.memoryBytesMin, RESOURCE_BOUNDS.memoryBytesMax, errors);
	const pidLimit = validateInteger(input.pidLimit, path + "/pidLimit", "pidLimit", RESOURCE_BOUNDS.pidLimitMin, RESOURCE_BOUNDS.pidLimitMax, errors);
	const storageBytes = validateInteger(input.storageBytes, path + "/storageBytes", "storageBytes", RESOURCE_BOUNDS.storageBytesMin, RESOURCE_BOUNDS.storageBytesMax, errors);
	if (errors.length) return failure(errors);
	return ok({ cpuMillis: cpuMillis as number, memoryBytes: memoryBytes as number, pidLimit: pidLimit as number, storageBytes: storageBytes as number });
}

function validateStorage(input: unknown, path: string): ValidationResult<ManifestStorage> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", path, "storage must be an object")]);
	rejectUnknownFields(input, path, ["persistent", "requestBytes"], errors);
	if (typeof input.persistent !== "boolean") errors.push(issue("INVALID_BOOLEAN", path + "/persistent", "persistent must be a boolean"));
	const requestBytes = validateInteger(input.requestBytes, path + "/requestBytes", "requestBytes", RESOURCE_BOUNDS.storageBytesMin, RESOURCE_BOUNDS.storageBytesMax, errors);
	if (errors.length) return failure(errors);
	return ok({ persistent: input.persistent === true, requestBytes: requestBytes as number });
}

export function validateEgress(input: unknown, path: string): ValidationResult<ManifestEgress> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", path, "egress must be an object")]);
	rejectUnknownFields(input, path, ["default", "allow"], errors);
	if (input.default !== "deny") errors.push(issue("INVALID_EGRESS_DEFAULT", path + "/default", "egress default must be deny"));
	if (!Array.isArray(input.allow)) {
		errors.push(issue("INVALID_EGRESS", path + "/allow", "egress allow must be an array"));
		return failure(errors);
	}
	if (input.allow.length > MAX_EGRESS_RULES) {
		errors.push(issue("INVALID_EGRESS", path + "/allow", "egress allow list exceeds the maximum length"));
		return failure(errors);
	}
	const allow: ManifestEgressRule[] = [];
	input.allow.forEach((entry, index) => {
		if (!isRecord(entry)) {
			errors.push(issue("TYPE_OBJECT", path + "/allow/" + index, "egress rule must be an object"));
			return;
		}
		rejectUnknownFields(entry, path + "/allow/" + index, ["host", "port"], errors);
		const host = validateDnsName(entry.host, path + "/allow/" + index + "/host", "host", errors);
		const port = validateInteger(entry.port, path + "/allow/" + index + "/port", "port", 1, 65535, errors);
		if (host !== null && port !== null) allow.push({ host, port });
	});
	if (errors.length) return failure(errors);
	return ok({ default: "deny", allow });
}

export function validateApplicationManifest(input: unknown): ValidationResult<ApplicationManifest> {
	const errors: ValidationIssue[] = [];
	if (!isRecord(input)) return failure([issue("TYPE_OBJECT", "", "manifest must be an object")]);
	rejectUnknownFields(input, "", ["schemaVersion", "name", "runtime", "assets", "resources", "storage", "egress"], errors);

	if (input.schemaVersion !== MANIFEST_SCHEMA_VERSION) errors.push(issue("INVALID_VERSION", "/schemaVersion", "schemaVersion must be " + MANIFEST_SCHEMA_VERSION));
	const name = validateOpaqueId(input.name, "/name", "name", errors);

	const runtime = validateRuntime(input.runtime, "/runtime");
	if (!runtime.ok) errors.push(...runtime.errors);
	const assets = validateAssets(input.assets, "/assets");
	if (!assets.ok) errors.push(...assets.errors);
	const resources = validateResources(input.resources, "/resources");
	if (!resources.ok) errors.push(...resources.errors);
	const storage = validateStorage(input.storage, "/storage");
	if (!storage.ok) errors.push(...storage.errors);
	const egress = validateEgress(input.egress, "/egress");
	if (!egress.ok) errors.push(...egress.errors);

	// Semantic cross-check: a persistent-storage request cannot exceed the storage policy.
	if (storage.ok && resources.ok && storage.value.requestBytes > resources.value.storageBytes) {
		errors.push(issue("STORAGE_EXCEEDS_POLICY", "/storage/requestBytes", "storage request exceeds the declared storage policy"));
	}

	if (errors.length) return failure(errors);
	return ok({
		schemaVersion: MANIFEST_SCHEMA_VERSION,
		name: name as string,
		runtime: (runtime as { ok: true; value: ManifestRuntime }).value,
		assets: (assets as { ok: true; value: ManifestAssets }).value,
		resources: (resources as { ok: true; value: ManifestResources }).value,
		storage: (storage as { ok: true; value: ManifestStorage }).value,
		egress: (egress as { ok: true; value: ManifestEgress }).value,
	});
}

export function exampleManifest(): ApplicationManifest {
	return {
		schemaVersion: 1,
		name: "notes",
		runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint: "index.js" },
		assets: { root: "app" },
		resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 1024 * 2 ** 20 },
		storage: { persistent: true, requestBytes: 256 * 2 ** 20 },
		egress: { default: "deny", allow: [{ host: "api.example.com", port: 443 }] },
	};
}

export function serializeManifest(manifest: ApplicationManifest): string {
	return JSON.stringify(manifest, null, 2) + "\n";
}


