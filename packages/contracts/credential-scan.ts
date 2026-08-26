// 用户原始需求（2026-08-14）：凭据扫描只报告位置类别与 clean/failed，绝不输出 secret 值或原始标签；位置以 kind + 标签哈希形式输出。
// 正交意图：12.3；2026-08-26 评审固化两类误报区分规则（公开标识符精确等值豁免清单 + 纯 shell 参数展开值不算泄漏）。
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

// Exact-equality needle exemptions (2026-08-26 review follow-up). These
// identifiers are committed public text in this repository — S3 policy names
// and provisioning usernames used verbatim by scripts/iweb-entrypoint.sh — so
// a needle whose value is EXACTLY one of them carries no information beyond
// that public text: every occurrence in every surface is indistinguishable
// from the public constant itself. Exact equality only; any other value
// (superstring, substring, case variant) is still scanned normally.
export const PUBLIC_IDENTIFIER_EXEMPTIONS: readonly string[] = [
	"iweb-celld", // celld S3 policy name: entrypoint `mc admin policy create/attach local iweb-celld`
	"iweb-sandbox-issuer", // sandbox service-account issuer username: entrypoint `mc admin user add local iweb-sandbox-issuer`
];

export function isExemptPublicIdentifier(value: string): boolean {
	return PUBLIC_IDENTIFIER_EXEMPTIONS.includes(asText(value));
}

// A matched "value" that is nothing but a shell parameter expansion
// (`${VAR}` or `$VAR`, with at most one surrounding quote per side) re-exports
// the variable at exec time; it is not a literal assignment and cannot leak a
// secret value. Concatenation, prefixes, suffixes, and embedded expansions
// stay findings.
const PURE_PARAMETER_EXPANSION = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/;

export function isPureParameterExpansion(value: string): boolean {
	const text = asText(value).trim();
	if (text.length === 0) return false;
	const unquoted = text.replace(/^["']/, "").replace(/["']$/, "");
	return PURE_PARAMETER_EXPANSION.test(unquoted);
}

// The shell required-parameter assertion `: "${VAR:?VAR must be set}"` leaves
// a captured "value" of exactly `?VAR` — the `:?` operator residue plus the
// variable's own name. It asserts the variable is set and assigns nothing;
// the self-reference cannot be a literal secret. Any other residue (a
// different name, a longer message, a `:-` default) stays a finding.
export function isRequiredParameterAssertion(value: string, variableName: string): boolean {
	const text = asText(value).trim();
	if (text.length === 0) return false;
	const unquoted = text.replace(/^["']/, "").replace(/["']$/, "");
	return unquoted === "?" + asText(variableName);
}

export function scanForSecrets(options: { readonly secrets: readonly ScanSecret[]; readonly locations: readonly ScanLocation[] }): CredentialScanResult {
	const findings = new Map<string, ScanFinding>();
	for (const location of options.locations.slice(0, MAX_SCAN_LOCATIONS)) {
		const foundCategories = new Set<string>();
		for (const secret of options.secrets.slice(0, MAX_SCAN_SECRETS)) {
			const value = asText(secret.value);
			if (value.length === 0) continue;
			// documented false-positive class: value is exactly a repo-public
			// identifier (see PUBLIC_IDENTIFIER_EXEMPTIONS)
			if (isExemptPublicIdentifier(value)) continue;
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

export interface CredentialPattern {
	readonly id: string;
	readonly pattern: RegExp;
	// When true, a regex hit whose captured value (group 1) is a pure shell
	// parameter expansion is a documented non-leak re-export, e.g.
	// `IWEB_API_TOKEN="${IWEB_API_TOKEN}"` forwards the variable to a child
	// process instead of assigning a literal. Only the pure-expansion shape is
	// exempt; literal or concatenated values still report.
	readonly parameterExpansionValueExempt?: boolean;
}

export const CREDENTIAL_PATTERNS: readonly CredentialPattern[] = [
	{ id: "aws-access-key-id", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
	{ id: "private-key-block", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/ },
	{ id: "credential-url", pattern: /:\/\/[^\s/:@]+:[^\s/@]+@[^\s/"']+[:/]/ },
	{ id: "owner-token-assignment", pattern: /\bIWEB_API_TOKEN\b[^\n]{0,40}[:=]([^\n]{0,4}["']?[^\s"']{8,})/, parameterExpansionValueExempt: true },
	{ id: "mc-host-secret", pattern: /\bMC_HOST[A-Z_]*=https?:\/\/[^\s@]+:[^\s@]+@/i },
];

function reportsNonExemptMatch(detector: CredentialPattern, content: string): boolean {
	const global = new RegExp(detector.pattern.source, detector.pattern.flags.replace("g", "") + "g");
	for (let match = global.exec(content); match !== null; match = global.exec(content)) {
		if (match[0].length === 0) {
			global.lastIndex += 1;
			continue;
		}
		if (detector.parameterExpansionValueExempt === true) {
			const value = match[1] ?? match[0];
			// the variable name the assignment targets is the leading identifier
			// of the match (`IWEB_API_TOKEN...=value`)
			const variableName = /^[A-Za-z_][A-Za-z0-9_]*/.exec(match[0])?.[0] ?? "";
			if (isPureParameterExpansion(value)) continue;
			if (variableName !== "" && isRequiredParameterAssertion(value, variableName)) continue;
		}
		return true;
	}
	return false;
}

export function scanForCredentialPatterns(locations: readonly ScanLocation[]): CredentialScanResult {
	const findings = new Map<string, ScanFinding>();
	for (const location of locations.slice(0, MAX_SCAN_LOCATIONS)) {
		const content = asText(location.content);
		const sanitized = sanitizeLocation(location.kind, asText(location.label));
		for (const detector of CREDENTIAL_PATTERNS) {
			if (!reportsNonExemptMatch(detector, content)) continue;
			const finding: ScanFinding = { location: sanitized, category: detector.id };
			findings.set(sanitized + "\u0000" + detector.id, finding);
		}
	}
	const ordered = [...findings.values()].sort((a, b) => {
		if (a.location !== b.location) return a.location < b.location ? -1 : 1;
		if (a.category !== b.category) return a.category < b.category ? -1 : 1;
		return 0;
	});
	return { clean: ordered.length === 0, findings: ordered };
}
