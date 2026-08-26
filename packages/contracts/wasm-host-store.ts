// 用户原始需求（2026-08-25，add-wasm-runtime 任务 1.3 契约先行）：iweb 自有 WIT 宿主接口 `iweb:secrets@1.0.0` / `iweb:config@1.0.0` 必须以固定 WIT、key grammar 与 owner mutation 精确键集 wire 落入 contracts（owner 2026-08-26 终裁：值为 string、closed error variant、无 list/write/enumeration）。
// 正交意图：key/value grammar 与 bound；WIT 错误 variant ↔ wire 错误码映射（含方向错误码）；owner mutation keys/values 精确键集 fail-closed 校验。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md「The iweb secrets host interface is fixed and allowlisted」「The iweb config host interface is fixed and non-secret」。
// WIT 文本权威：./wit/iweb-secrets.wit 与 ./wit/iweb-config.wit（tests/wasm-host-store.test.ts 断言与 spec 逐字一致）。
// 快照记录（SnapshotRefV1/valuesDigest/raw-UDS handoff）属任务 6.1/7.3/7.4，不在本文件。
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "./validation.ts";

// ---------------------------------------------------------------------------
// key grammar 与值 bound（secrets 与 config 共用同一 owner 裁决）
// ---------------------------------------------------------------------------

export const IWEB_STORE_KEY_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
export const IWEB_STORE_KEY_MAX_BYTES = 128;
export const IWEB_STORE_VALUE_MAX_BYTES = 65536;
export const IWEB_STORE_ALLOWLIST_MAX_KEYS = 256;

// grammar 限定为小写 ASCII：字符数即 UTF-8 字节数（1..128），天然排除 slash、
// whitespace、colon、NUL、非规范化 UTF-8 与大小写变体（"a second encoding" 不存在）。
export function isValidIwebStoreKey(key: string): boolean {
	return typeof key === "string" && IWEB_STORE_KEY_PATTERN.test(key);
}

export function iwebUtf8ByteLength(value: string): number {
	let bytes = 0;
	for (const character of value) {
		const codePoint = character.codePointAt(0);
		if (codePoint === undefined) continue;
		if (codePoint <= 0x7f) bytes += 1;
		else if (codePoint <= 0x7ff) bytes += 2;
		else if (codePoint <= 0xffff) bytes += 3;
		else bytes += 4;
	}
	return bytes;
}

export function isValidIwebStoreValue(value: string): boolean {
	return typeof value === "string" && iwebUtf8ByteLength(value) <= IWEB_STORE_VALUE_MAX_BYTES;
}

// ---------------------------------------------------------------------------
// WIT 包/接口身份与方向法（import store 是唯一合法方向）
// ---------------------------------------------------------------------------

export const IWEB_SECRETS_WIT_PACKAGE = "iweb:secrets@1.0.0";
export const IWEB_SECRETS_WIT_WORLD = "secrets";
export const IWEB_CONFIG_WIT_PACKAGE = "iweb:config@1.0.0";
export const IWEB_CONFIG_WIT_WORLD = "config";
export const IWEB_STORE_INTERFACE = "store";

export type IwebStoreWitDirectionErrorCode = "IWEB_SECRET_WIT_DIRECTION_INVALID" | "IWEB_CONFIG_WIT_DIRECTION_INVALID";

// world/component 只能 import store；export store 一律在 OCI 物化前拒绝（spec 方向向量为 normative）。
export function iwebStoreWitDirectionErrorCode(id: { readonly package: string; readonly interface: string; readonly direction: string }): IwebStoreWitDirectionErrorCode | null {
	if (id.direction !== "export" || id.interface !== IWEB_STORE_INTERFACE) return null;
	if (id.package === IWEB_SECRETS_WIT_PACKAGE) return "IWEB_SECRET_WIT_DIRECTION_INVALID";
	if (id.package === IWEB_CONFIG_WIT_PACKAGE) return "IWEB_CONFIG_WIT_DIRECTION_INVALID";
	return null;
}

// ---------------------------------------------------------------------------
// WIT 调用错误 variant ↔ wire 错误码（closed set，不回显 key/value）
// ---------------------------------------------------------------------------

export const IWEB_STORE_WIT_ERROR_CASES = ["not-assigned", "denied", "snapshot-expired", "revision-stale", "internal"] as const;
export type IwebStoreWitErrorCase = (typeof IWEB_STORE_WIT_ERROR_CASES)[number];

export const IWEB_SECRET_WIRE_ERROR_BY_CASE: Readonly<Record<IwebStoreWitErrorCase, string>> = {
	"not-assigned": "IWEB_SECRET_NOT_ASSIGNED",
	denied: "IWEB_SECRET_DENIED",
	"snapshot-expired": "IWEB_SECRET_SNAPSHOT_EXPIRED",
	"revision-stale": "IWEB_SECRET_REVISION_STALE",
	internal: "IWEB_SECRET_INTERNAL",
};

export const IWEB_CONFIG_WIRE_ERROR_BY_CASE: Readonly<Record<IwebStoreWitErrorCase, string>> = {
	"not-assigned": "IWEB_CONFIG_NOT_ASSIGNED",
	denied: "IWEB_CONFIG_DENIED",
	"snapshot-expired": "IWEB_CONFIG_SNAPSHOT_EXPIRED",
	"revision-stale": "IWEB_CONFIG_REVISION_STALE",
	internal: "IWEB_CONFIG_INTERNAL",
};

// 传输层追加码：instantiate 前必需 raw-UDS descriptor 缺失/重复；不在 WIT variant 内。
export const IWEB_SECRET_TRANSPORT_ERROR_CODES = ["IWEB_SECRET_SNAPSHOT_FD_REQUIRED"] as const;
export const IWEB_CONFIG_TRANSPORT_ERROR_CODES = ["IWEB_CONFIG_FD_REQUIRED"] as const;

// owner CAS 冲突码（Kernel 提交路径使用；纯 wire 校验器不判定新旧 revision）。
export const SECRET_REVISION_CONFLICT = "SECRET_REVISION_CONFLICT";
export const CONFIG_REVISION_CONFLICT = "CONFIG_REVISION_CONFLICT";

// ---------------------------------------------------------------------------
// owner mutation wire：PUT /v1/applications/<applicationId>/{secret,config}-allowlist
// ---------------------------------------------------------------------------

export interface IwebSecretAllowlistMutationV1 {
	readonly schemaVersion: 1;
	readonly expectedSecretRevision: number;
	readonly keys: readonly string[];
	readonly values: Readonly<Record<string, string>>;
}

export interface IwebConfigAllowlistMutationV1 {
	readonly schemaVersion: 1;
	readonly expectedConfigRevision: number;
	readonly keys: readonly string[];
	readonly values: Readonly<Record<string, string>>;
}

interface OwnerMutationWire {
	readonly expectedRevision: number;
	readonly keys: readonly string[];
	readonly values: Readonly<Record<string, string>>;
}

interface OwnerMutationOptions {
	readonly revisionField: "expectedSecretRevision" | "expectedConfigRevision";
	// config：revision 0 + keys:[] 是唯一未分配态，任何 mutation 都提交 >= 1 的 revision，
	// 因此空 keys 拒绝；secrets：spec 明言 keys.length 为 0..256，允许清空式轮换。
	readonly minimumKeys: number;
	// config：spec 规定所有 wire 形状拒绝统一呈现为 IWEB_CONFIG_WIRE_INVALID（CAS 冲突另算）；
	// secrets：spec 未命名 mutation 形状错误码，沿用仓库细粒度 issue code。
	readonly uniformIssueCode: string | null;
	readonly noun: string;
}

function validateOwnerMutationWire(input: unknown, options: OwnerMutationOptions): ValidationResult<OwnerMutationWire> {
	const code = (granular: string): string => (options.uniformIssueCode ?? granular);
	if (!isRecord(input)) return failure([issue(code("TYPE_OBJECT"), "", options.noun + " must be an object")]);
	const errors: ValidationIssue[] = [];

	for (const field of Object.keys(input)) {
		if (field !== "schemaVersion" && field !== options.revisionField && field !== "keys" && field !== "values") {
			errors.push(issue(code("UNKNOWN_FIELD"), "/" + field, "unknown field is not allowed"));
		}
	}
	if (input.schemaVersion !== 1) {
		errors.push(issue(code("INVALID_SCHEMA_VERSION"), "/schemaVersion", "schemaVersion must be the literal 1"));
	}
	const expectedRevision = input[options.revisionField];
	if (typeof expectedRevision !== "number" || !Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
		errors.push(issue(code("INVALID_NUMBER"), "/" + options.revisionField, options.revisionField + " must be a non-negative safe integer"));
	}

	const keys: string[] = [];
	let keysValid = true;
	if (!Array.isArray(input.keys)) {
		errors.push(issue(code("TYPE_ARRAY"), "/keys", "keys must be an array"));
		keysValid = false;
	} else {
		if (input.keys.length < options.minimumKeys || input.keys.length > IWEB_STORE_ALLOWLIST_MAX_KEYS) {
			errors.push(issue(code("INVALID_KEY_COUNT"), "/keys", "keys length must be between " + options.minimumKeys + " and " + IWEB_STORE_ALLOWLIST_MAX_KEYS));
		}
		for (let i = 0; i < input.keys.length; i++) {
			const key = input.keys[i];
			if (typeof key !== "string" || !isValidIwebStoreKey(key)) {
				errors.push(issue(code("INVALID_KEY"), "/keys/" + i, "key must match ^[a-z][a-z0-9._-]{0,127}$"));
				keysValid = false;
				continue;
			}
			keys.push(key);
		}
		if (keysValid) {
			for (let i = 1; i < keys.length; i++) {
				// ASCII grammar 下 code-unit 序即 UTF-8 bytewise 序。
				if (keys[i - 1] === keys[i]) errors.push(issue(code("DUPLICATE_KEY"), "/keys", "keys must be unique"));
				else if (keys[i - 1] > keys[i]) errors.push(issue(code("UNSORTED_KEYS"), "/keys", "keys must be sorted in UTF-8 byte order"));
			}
		}
	}

	if (!isRecord(input.values)) {
		errors.push(issue(code("TYPE_OBJECT"), "/values", "values must be an object"));
	} else {
		const valueKeys = Object.keys(input.values);
		for (const key of valueKeys) {
			const value = input.values[key];
			if (typeof value !== "string") {
				errors.push(issue(code("INVALID_VALUE"), "/values/" + key, "value must be a string"));
				continue;
			}
			if (!isValidIwebStoreValue(value)) {
				errors.push(issue(code("INVALID_VALUE"), "/values/" + key, "value must be at most " + IWEB_STORE_VALUE_MAX_BYTES + " UTF-8 bytes"));
			}
		}
		if (keysValid) {
			// 键集 byte-for-byte 相等：无 missing、无 extra、无 prototype-like key
			//（grammar 决定 __proto__/constructor 之类不可能出现在 keys 内，extra 检查即兜底）。
			const keySet = new Set(keys);
			for (const key of valueKeys) {
				if (!keySet.has(key)) errors.push(issue(code("KEYS_VALUES_MISMATCH"), "/values/" + key, "values key is not present in keys"));
			}
			for (const key of keys) {
				if (!Object.prototype.hasOwnProperty.call(input.values, key)) {
					errors.push(issue(code("KEYS_VALUES_MISMATCH"), "/values/" + key, "keys entry is missing from values"));
				}
			}
		}
	}

	if (errors.length) return failure(errors);
	return ok({ expectedRevision: expectedRevision as number, keys, values: input.values as Record<string, string> });
}

export function validateIwebSecretAllowlistMutation(input: unknown): ValidationResult<IwebSecretAllowlistMutationV1> {
	const result = validateOwnerMutationWire(input, {
		revisionField: "expectedSecretRevision",
		minimumKeys: 0,
		uniformIssueCode: null,
		noun: "secret allowlist mutation",
	});
	if (!result.ok) return result;
	return ok({ schemaVersion: 1, expectedSecretRevision: result.value.expectedRevision, keys: result.value.keys, values: result.value.values });
}

export function validateIwebConfigAllowlistMutation(input: unknown): ValidationResult<IwebConfigAllowlistMutationV1> {
	const result = validateOwnerMutationWire(input, {
		revisionField: "expectedConfigRevision",
		minimumKeys: 1,
		uniformIssueCode: "IWEB_CONFIG_WIRE_INVALID",
		noun: "config allowlist mutation",
	});
	if (!result.ok) return result;
	return ok({ schemaVersion: 1, expectedConfigRevision: result.value.expectedRevision, keys: result.value.keys, values: result.value.values });
}
