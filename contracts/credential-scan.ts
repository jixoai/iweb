// 用户原始需求（2026-08-14）：凭据扫描只报告位置类别与 clean/failed，绝不输出 secret 值或原始标签；位置以 kind + 标签哈希形式输出。
// 正交意图：12.3。
import { createHash } from "node:crypto";

// Caps keep the scan bounded against hostile package collections. Entries
// beyond the caps are ignored (never thrown); the caps are documented here so
// callers can size their projections accordingly.
export const MAX_SCAN_SECRETS = 256;
export const MAX_SCAN_LOCATIONS = 10_000;
export const LOCATION_DIGEST_LENGTH = 12;

export type ScanLocationKind =
	| "package"
	| "sandbox-fs"
	| "env-projection"
	| "object-store"
	| "admin-assets"
	| "log"
	| "monitor-frame"
	| "test-output"
	| "image-layer";

export interface ScanSecret {
	readonly value: string;
	readonly category: string;
}

export interface ScanLocation {
	readonly kind: ScanLocationKind;
	readonly label: string;
	readonly content: string;
}

export interface ScanFinding {
	// Always the sanitized form "<kind>:<first LOCATION_DIGEST_LENGTH hex chars
	// of sha256(label)>". Never the raw label, never derived from secret values.
	readonly location: string;
	readonly category: string;
}

export interface CredentialScanResult {
	readonly clean: boolean;
	readonly findings: readonly ScanFinding[];
}

// Defensive coercion so no plausible hostile runtime value can make the scan
// throw (the scan must never throw, per the 12.3 contract).
function asText(value: string): string {
	return typeof value === "string" ? value : String(value);
}

function sanitizeLocation(kind: ScanLocationKind, label: string): string {
	return kind + ":" + createHash("sha256").update(asText(label)).digest("hex").slice(0, LOCATION_DIGEST_LENGTH);
}

export function scanForSecrets(options: { readonly secrets: readonly ScanSecret[]; readonly locations: readonly ScanLocation[] }): CredentialScanResult {
	const findings = new Map<string, ScanFinding>();
	for (const location of options.locations.slice(0, MAX_SCAN_LOCATIONS)) {
		const foundCategories = new Set<string>();
		for (const secret of options.secrets.slice(0, MAX_SCAN_SECRETS)) {
			const value = asText(secret.value);
			if (value.length === 0) continue;
			if (asText(location.content).includes(value) || asText(location.label).includes(value)) {
				foundCategories.add(secret.category);
			}
		}
		if (foundCategories.size === 0) continue;
		const sanitized = sanitizeLocation(location.kind, asText(location.label));
		for (const category of foundCategories) {
			const finding: ScanFinding = { location: sanitized, category };
			findings.set(sanitized + "\u0000" + category, finding);
		}
	}
	const ordered = [...findings.values()].sort((a, b) => {
		if (a.location !== b.location) return a.location < b.location ? -1 : 1;
		if (a.category !== b.category) return a.category < b.category ? -1 : 1;
		return 0;
	});
	return { clean: ordered.length === 0, findings: ordered };
}

export const CREDENTIAL_PATTERNS: readonly { readonly id: string; readonly pattern: RegExp }[] = [
	{ id: "aws-access-key-id", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
	{ id: "private-key-block", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/ },
	{ id: "credential-url", pattern: /:\/\/[^\s/:@]+:[^\s/@]+@[^\s/"']+[:/]/ },
	{ id: "owner-token-assignment", pattern: /\bIWEB_API_TOKEN\b[^\n]{0,40}[:=][^\n]{0,4}["']?[^\s"']{8,}/ },
	{ id: "mc-host-secret", pattern: /\bMC_HOST[A-Z_]*=https?:\/\/[^\s@]+:[^\s@]+@/i },
];

export function scanForCredentialPatterns(locations: readonly ScanLocation[]): CredentialScanResult {
	const findings = new Map<string, ScanFinding>();
	for (const location of locations.slice(0, MAX_SCAN_LOCATIONS)) {
		const content = asText(location.content);
		const sanitized = sanitizeLocation(location.kind, asText(location.label));
		for (const detector of CREDENTIAL_PATTERNS) {
			if (detector.pattern.test(content)) {
				const finding: ScanFinding = { location: sanitized, category: detector.id };
				findings.set(sanitized + "\u0000" + detector.id, finding);
			}
		}
	}
	const ordered = [...findings.values()].sort((a, b) => {
		if (a.location !== b.location) return a.location < b.location ? -1 : 1;
		if (a.category !== b.category) return a.category < b.category ? -1 : 1;
		return 0;
	});
	return { clean: ordered.length === 0, findings: ordered };
}
