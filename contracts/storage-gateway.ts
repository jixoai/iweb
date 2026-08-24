// 用户原始需求（2026-08-14）：应用持久存储经短生命周期能力访问，能力映射到单一不透明应用身份；版本删除与数据删除分权。
// 正交意图：有界输入校验、HMAC 签名、到期、持久化 nonce 防重放；跨应用/复用/过期一律机器可读失败。
import * as nodeCrypto from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import {
	failure,
	isRecord,
	issue,
	ok,
	OPAQUE_ID_PATTERN,
	validateOpaqueId,
	type ValidationIssue,
	type ValidationResult,
} from "./validation.ts";

export interface IssuedCapability {
	readonly token: string;
	readonly applicationId: string;
	readonly expiresAt: number;
}

export type CapabilityFailureReason = "invalid" | "expired" | "reused" | "mismatch";

export interface CapabilityVerifyResult {
	readonly ok: boolean;
	readonly applicationId?: string;
	readonly reason?: CapabilityFailureReason;
}

export interface NonceReplayStore {
	consume(nonce: string): "fresh" | "replayed";
}

const MIN_SECRET_BYTES = 32;
const MAX_SECRET_BYTES = 512;
const MIN_TTL_MS = 1_000;
const MAX_TTL_MS = 86_400_000;
const MAX_TIMESTAMP_DRIFT_MS = 3_600_000;
const NONCE_PATTERN = /^[a-f0-9]{32}$/;
const MAX_TOKEN_LENGTH = 512;
const SIGNATURE_LENGTH = 43; // base64url encoding of a 32-byte HMAC-SHA256 digest

export function applicationDataPrefix(applicationId: string): string {
	return "iweb-apps/" + applicationId + "/data/";
}

export function applicationVersionPrefix(sandboxId: string): string {
	return "iweb-versions/" + sandboxId + "/";
}

function sign(secret: string, payload: string): string {
	return nodeCrypto.createHmac("sha256", secret).update(payload, "utf8").digest("base64url");
}

function hasValidSecretLength(secret: string): boolean {
	const bytes = Buffer.byteLength(secret, "utf8");
	return bytes >= MIN_SECRET_BYTES && bytes <= MAX_SECRET_BYTES;
}

export function issueStorageCapability(options: {
	readonly secret: string;
	readonly applicationId: string;
	readonly ttlMs: number;
	readonly now?: number;
	readonly nonce?: string;
}): ValidationResult<IssuedCapability> {
	const errors: ValidationIssue[] = [];
	const applicationId = validateOpaqueId(options.applicationId, "/applicationId", "applicationId", errors);
	if (typeof options.secret !== "string" || !hasValidSecretLength(options.secret)) {
		errors.push(issue("INVALID_SECRET", "/secret", "secret must be a string of 32 to 512 bytes"));
	}
	if (!Number.isSafeInteger(options.ttlMs) || options.ttlMs < MIN_TTL_MS || options.ttlMs > MAX_TTL_MS) {
		errors.push(issue("INVALID_TTL", "/ttlMs", "ttlMs must be an integer between 1000 and 86400000 milliseconds"));
	}
	let now = options.now;
	if (now === undefined) {
		now = Date.now();
	} else if (!Number.isSafeInteger(now) || Math.abs(now - Date.now()) > MAX_TIMESTAMP_DRIFT_MS) {
		errors.push(issue("INVALID_TIMESTAMP", "/now", "now must be a safe integer within 1 hour of the wall clock"));
	}
	let nonce = options.nonce;
	if (nonce === undefined) {
		nonce = nodeCrypto.randomBytes(16).toString("hex");
	} else if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) {
		errors.push(issue("INVALID_NONCE", "/nonce", "nonce must be 32 lowercase hexadecimal characters"));
	}
	if (errors.length || applicationId === null || now === undefined || nonce === undefined) return failure(errors);
	const expiresAt = now + options.ttlMs;
	const payload = applicationId + "." + expiresAt + "." + nonce;
	const token = payload + "." + sign(options.secret, payload);
	return ok({ token, applicationId, expiresAt });
}

export function verifyStorageCapability(options: {
	readonly secret: string;
	readonly token: string;
	readonly applicationId: string;
	readonly now?: number;
	readonly replay: NonceReplayStore;
}): CapabilityVerifyResult {
	if (typeof options.secret !== "string" || typeof options.token !== "string" || typeof options.applicationId !== "string") {
		return { ok: false, reason: "invalid" };
	}
	if (options.token.length > MAX_TOKEN_LENGTH) return { ok: false, reason: "invalid" };
	const parts = options.token.split(".");
	if (parts.length !== 4) return { ok: false, reason: "invalid" };
	const [applicationId, expiresAtText, nonce, signature] = parts;
	if (!OPAQUE_ID_PATTERN.test(applicationId)) return { ok: false, reason: "invalid" };
	if (applicationId !== options.applicationId) return { ok: false, reason: "mismatch" };
	const expiresAt = Number(expiresAtText);
	if (!Number.isSafeInteger(expiresAt)) return { ok: false, reason: "invalid" };
	if (expiresAt <= (options.now ?? Date.now())) return { ok: false, reason: "expired" };
	if (!NONCE_PATTERN.test(nonce)) return { ok: false, reason: "invalid" };
	if (signature.length !== SIGNATURE_LENGTH) return { ok: false, reason: "invalid" };
	const expected = sign(options.secret, applicationId + "." + expiresAtText + "." + nonce);
	const received = Buffer.from(signature);
	const wanted = Buffer.from(expected);
	if (!nodeCrypto.timingSafeEqual(received, wanted)) return { ok: false, reason: "invalid" };
	let fresh = false;
	try {
		fresh = options.replay.consume(nonce) === "fresh";
	} catch {
		// An unconsultable replay store must never become a throw; verification
		// fails closed with a machine-readable reason.
		return { ok: false, reason: "invalid" };
	}
	if (!fresh) return { ok: false, reason: "reused" };
	return { ok: true, applicationId };
}

export interface DurableNonceStoreOptions {
	readonly filePath: string;
	readonly readFile?: (path: string) => string | null;
	readonly appendFile?: (path: string, data: string) => void;
	readonly mkdir?: (path: string) => void;
}

function defaultReadFile(path: string): string | null {
	try {
		return readFileSync(path, "utf8");
	} catch (error: unknown) {
		if (isRecord(error) && error.code === "ENOENT") return null;
		throw error;
	}
}

function defaultAppendFile(path: string, data: string): void {
	appendFileSync(path, data, "utf8");
}

function defaultMkdir(path: string): void {
	mkdirSync(path, { recursive: true });
}

// Single-writer durable nonce store: one hex nonce per line. The Kernel is the
// only writer, so no cross-process locking is required here.
export class DurableNonceStore implements NonceReplayStore {
	private readonly filePath: string;
	private readonly readFile: (path: string) => string | null;
	private readonly appendFile: (path: string, data: string) => void;
	private readonly mkdir: (path: string) => void;

	constructor(options: DurableNonceStoreOptions) {
		this.filePath = options.filePath;
		this.readFile = options.readFile ?? defaultReadFile;
		this.appendFile = options.appendFile ?? defaultAppendFile;
		this.mkdir = options.mkdir ?? defaultMkdir;
		this.mkdir(dirname(this.filePath));
	}

	consume(nonce: string): "fresh" | "replayed" {
		const content = this.readFile(this.filePath);
		const present = content !== null && content.split("\n").some((line) => line === nonce);
		if (present) return "replayed";
		this.appendFile(this.filePath, nonce + "\n");
		return "fresh";
	}
}
