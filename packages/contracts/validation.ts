// 用户原始需求（2026-08-14）：所有外部输入必须在任何 OCI 副作用前通过不可绕过的运行时验证。
// 正交意图：稳定、机器可读、长度有界、不回显 secret 或整份 hostile payload 的验证错误。
export interface ValidationIssue {
	readonly code: string;
	readonly path: string;
	readonly message: string;
}

export type ValidationResult<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly errors: readonly ValidationIssue[] };

export const MAX_VALIDATION_ERRORS = 50;

export const OPAQUE_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
export const SHA256_PATTERN = /^[a-f0-9]{64}$/;
export const DNS_NAME_PATTERN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
export const SAFE_RELATIVE_PATH_PATTERN = /^[A-Za-z0-9._@+=-]+(?:\/[A-Za-z0-9._@+=-]+)*$/;

export function ok<T>(value: T): ValidationResult<T> {
	return { ok: true, value };
}

export function failure<T>(issues: readonly ValidationIssue[]): ValidationResult<T> {
	return { ok: false, errors: issues.slice(0, MAX_VALIDATION_ERRORS) };
}

export function issue(code: string, path: string, message: string): ValidationIssue {
	return { code, path: boundedText(path, 200), message: boundedText(message, 200) };
}

export function boundedText(value: string, max = 200): string {
	return value
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function boundedKey(value: string, max = 40): string {
	return boundedText(value, max);
}

export function validateOpaqueId(value: unknown, path: string, fieldName: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !OPAQUE_ID_PATTERN.test(value)) {
		errors.push(issue("INVALID_IDENTIFIER", path, fieldName + " must be a lowercase opaque identifier"));
		return null;
	}
	return value;
}

export function validateSha256(value: unknown, path: string, fieldName: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
		errors.push(issue("INVALID_DIGEST", path, fieldName + " must be a 64-character lowercase hex digest"));
		return null;
	}
	return value;
}

export function validateInteger(value: unknown, path: string, fieldName: string, minimum: number, maximum: number, errors: ValidationIssue[]): number | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
		errors.push(issue("INVALID_NUMBER", path, fieldName + " must be an integer between " + minimum + " and " + maximum));
		return null;
	}
	return value;
}

export function validateDnsName(value: unknown, path: string, fieldName: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !DNS_NAME_PATTERN.test(value) || isIpLiteral(value)) {
		errors.push(issue("INVALID_HOST", path, fieldName + " must be a DNS name, not an address literal"));
		return null;
	}
	return value;
}

export function validateSafeRelativePath(value: unknown, path: string, fieldName: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !SAFE_RELATIVE_PATH_PATTERN.test(value) || value.length > 512) {
		errors.push(issue("INVALID_PATH", path, fieldName + " must be a bounded relative path without traversal"));
		return null;
	}
	if (value.startsWith("/") || value.split("/").some((segment) => segment === ".." || segment === "." || segment === "")) {
		errors.push(issue("INVALID_PATH", path, fieldName + " must not contain absolute or traversal segments"));
		return null;
	}
	return value;
}

export function rejectUnknownFields(input: Record<string, unknown>, path: string, allowed: readonly string[], errors: ValidationIssue[]): void {
	for (const key of Object.keys(input)) {
		if (!allowed.includes(key)) {
			errors.push(issue("UNKNOWN_FIELD", path + "/" + boundedKey(key), "unknown field is not allowed"));
		}
	}
}

function isIpLiteral(value: string): boolean {
	return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":") || value === "localhost";
}

