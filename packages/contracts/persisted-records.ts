// 用户原始需求（2026-08-14）：持久状态必须逐字段校验后才能进入运行时；malformed 记录要有明确 quarantine 边界；缺文件与 I/O 错误必须区分。
// 正交意图：2.28/2.37/2.47 的持久层单一校验权威。policy 与 version identity 的权威在 contracts/records.ts
// （admission 与持久读取共用同一套规则，不允许第二套更宽松的副本）；本模块只承载持久层专属校验：
// 对象 endpoint、bucket 名、credential 字符集、时间戳，以及 malformed 记录的 quarantine 日志。
// 读取侧铁律（由各 system IO 实现承担）：ENOENT → null（合法的不存在）；EACCES/EIO 等基础设施错误必须
// 向上抛出，绝不冒充 absent。
export interface PolicyValidationResult {
	readonly ok: boolean;
	readonly reason?: string;
}

// Object/data endpoints must be absolute http(s) URLs without credentials,
// fragments, or usernames, bounded in length.
export function validateObjectEndpoint(value: unknown): PolicyValidationResult {
	if (typeof value !== "string" || value.length === 0 || value.length > 2048) return { ok: false, reason: "endpoint is not a bounded string" };
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return { ok: false, reason: "endpoint is not an absolute URL" };
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, reason: "endpoint protocol must be http(s)" };
	if (url.username !== "" || url.password !== "") return { ok: false, reason: "endpoint must not embed credentials" };
	if (url.hash !== "") return { ok: false, reason: "endpoint must not carry a fragment" };
	return { ok: true };
}

// Bucket names: lowercase alnum with hyphens, bounded (S3-compatible).
export function validateBucketName(value: unknown): PolicyValidationResult {
	if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(value)) return { ok: false, reason: "bucket name is invalid" };
	return { ok: true };
}

// Credential strings: printable ASCII, bounded.
export function validateCredentialString(value: unknown, min: number, max: number): boolean {
	return typeof value === "string" && value.length >= min && value.length <= max && /^[\x20-\x7e]+$/.test(value);
}

// ISO timestamp, bounded.
export function validateTimestamp(value: unknown): boolean {
	return typeof value === "string" && value.length >= 10 && value.length <= 64 && !Number.isNaN(Date.parse(value));
}

// Application identifiers (shared with admission: lowercase DNS-label shape).
export function validateApplicationId(value: unknown): boolean {
	return typeof value === "string" && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value);
}

// sha-256 content digests.
export function validateSha256Digest(value: unknown): boolean {
	return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

// Gateway/application storage secrets are exactly 64 lowercase hex chars
// (randomBytes(32).toString("hex")); the persisted form may never be looser.
export function validateStorageSecret(value: unknown): boolean {
	return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

// A complete object/data-plane credential record: exactly the four known
// fields, endpoint/bucket/credential-string rules all applied. This is the
// single authority for persisted nested credential objects (GatewaySecret
// .object/.data, Kernel control secrets); unknown fields reject outright.
export interface ObjectCredentialValidation {
	readonly ok: boolean;
	readonly reason?: string;
	readonly value?: { readonly endpoint: string; readonly region: string; readonly accessKeyId: string; readonly secretAccessKey: string };
}

export function validateObjectCredentialRecord(value: unknown): ObjectCredentialValidation {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return { ok: false, reason: "credential is not a JSON object" };
	const record = value as Record<string, unknown>;
	const known = new Set(["endpoint", "region", "accessKeyId", "secretAccessKey"]);
	for (const key of Object.keys(record)) {
		if (!known.has(key)) return { ok: false, reason: "credential has unknown field " + key };
	}
	const endpoint = validateObjectEndpoint(record.endpoint);
	if (!endpoint.ok) return { ok: false, reason: endpoint.reason ?? "endpoint is invalid" };
	if (typeof record.region !== "string" || record.region.length === 0 || record.region.length > 64) return { ok: false, reason: "region is not a bounded string" };
	if (!validateCredentialString(record.accessKeyId, 1, 256)) return { ok: false, reason: "accessKeyId is not a bounded credential string" };
	if (!validateCredentialString(record.secretAccessKey, 1, 512)) return { ok: false, reason: "secretAccessKey is not a bounded credential string" };
	return { ok: true, value: { endpoint: record.endpoint as string, region: record.region, accessKeyId: record.accessKeyId as string, secretAccessKey: record.secretAccessKey as string } };
}

// Kernel-owned version-deployment record (deploy/version.json in the version
// bucket): the durable statement of WHICH application version a bucket's
// celld deployment belongs to. deploy() writes it after the pinned celld
// deploy; deployed() accepts a bucket as deployed only when this record
// field-matches the requested identity exactly (applicationId, versionId,
// digest, sequence) — a stale or partial record is never a deployment.
export interface VersionDeploymentRecord {
	readonly v: 1;
	readonly kind: "iweb-version-deployment";
	readonly sandboxId: string;
	readonly applicationId: string;
	readonly versionId: string;
	readonly digest: string;
	readonly sequence: number;
	readonly deployedAt: string;
}

export interface DeploymentRecordValidation {
	readonly ok: boolean;
	readonly reason?: string;
	readonly record?: VersionDeploymentRecord;
}

export function validateVersionDeploymentRecord(value: unknown): DeploymentRecordValidation {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return { ok: false, reason: "deployment record is not a JSON object" };
	const record = value as Record<string, unknown>;
	const known = new Set(["v", "kind", "sandboxId", "applicationId", "versionId", "digest", "sequence", "deployedAt"]);
	for (const key of Object.keys(record)) {
		if (!known.has(key)) return { ok: false, reason: "deployment record has unknown field " + key };
	}
	if (record.v !== 1) return { ok: false, reason: "deployment record v must be 1" };
	if (record.kind !== "iweb-version-deployment") return { ok: false, reason: "deployment record kind is wrong" };
	if (typeof record.sandboxId !== "string" || !record.sandboxId.startsWith("sbx-") || record.sandboxId.length < 8 || record.sandboxId.length > 128) return { ok: false, reason: "sandboxId is not an opaque sandbox id" };
	if (!validateApplicationId(record.applicationId)) return { ok: false, reason: "applicationId is invalid" };
	if (typeof record.versionId !== "string" || record.versionId.length < 64 || record.versionId.length > 200 || !/^[a-f0-9]{64}$/.test(record.versionId)) return { ok: false, reason: "versionId is not a version digest label" };
	if (!validateSha256Digest(record.digest)) return { ok: false, reason: "digest is not a sha-256 digest" };
	if (typeof record.sequence !== "number" || !Number.isSafeInteger(record.sequence) || record.sequence < 1) return { ok: false, reason: "sequence is not a positive safe integer" };
	if (!validateTimestamp(record.deployedAt)) return { ok: false, reason: "deployedAt is not a timestamp" };
	const { sandboxId, applicationId, versionId, digest, sequence, deployedAt } = record as {
		sandboxId: string; applicationId: string; versionId: string; digest: string; sequence: number; deployedAt: string;
	};
	return {
		ok: true,
		record: { v: 1, kind: "iweb-version-deployment", sandboxId, applicationId, versionId, digest, sequence, deployedAt },
	};
}

// Does a validated deployment record match the version being prepared?
// Every identity field must be equal; any drift (stale bucket content from an
// older version, partial write, tampering) is a mismatch, never a deployment.
export function deploymentRecordMatches(record: VersionDeploymentRecord, expected: { readonly sandboxId: string; readonly applicationId: string; readonly versionId: string; readonly digest: string; readonly sequence: number }): boolean {
	return (
		record.sandboxId === expected.sandboxId &&
		record.applicationId === expected.applicationId &&
		record.versionId === expected.versionId &&
		record.digest === expected.digest &&
		record.sequence === expected.sequence
	);
}

// Quarantine trail: a malformed persisted record is APPENDED to a journal with
// its reason, never silently dropped. The in-memory journal is drained by the
// caller into the durable quarantine file, so a rejection always leaves a trace.
export interface QuarantineJournal {
	append(kind: string, key: string, reason: string, at: string): void;
	entries(): readonly { kind: string; key: string; reason: string; at: string }[];
}

export function createQuarantineJournal(): QuarantineJournal {
	const list: { kind: string; key: string; reason: string; at: string }[] = [];
	return {
		append(kind, key, reason, at) { list.push({ kind, key, reason, at }); },
		entries: () => [...list],
	};
}
