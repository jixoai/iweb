// 用户原始需求（2026-08-14）：egress 默认拒绝；只编译 owner 授权的 DNS-name + port 规则；DNS 解析和每次 redirect 后都拒绝 loopback/link-local/metadata/private/internal/peer。
// 正交意图：纯策略编译与 IP/主机名拒绝判定，供 supervisor 网络边界复用。任务 2.19：规范化 IP/DNS 分类内核（纯字符串分类，不依赖 node:net/dns）。
import { type ManifestEgress } from "./manifest.ts";
import { DNS_NAME_PATTERN } from "./validation.ts";

export interface CompiledEgressRule {
	readonly host: string;
	readonly port: number;
}

export interface CompiledEgressPolicy {
	readonly defaultDeny: true;
	readonly allow: readonly CompiledEgressRule[];
}

export function compileEgressPolicy(egress: ManifestEgress): CompiledEgressPolicy {
	return { defaultDeny: true, allow: egress.allow.map((rule) => ({ host: rule.host, port: rule.port })) };
}

export const INTERNAL_HOSTNAMES: readonly string[] = ["kernel", "minio", "celld", "supervisor", "admin", "mcp", "api"];

export type AddressClass = "global-ipv4" | "global-ipv6" | "reserved" | "invalid";

// ---- hostname normalization -------------------------------------------------

// Normalize a destination host for allow-list matching: lowercase, strip a
// single trailing dot ("Api.Example.COM." → "api.example.com"), collapse
// nothing else. Rejects empty names, underscores (not DNS hostnames), IP
// literals (the caller classifies addresses separately), names longer than
// 253 chars, labels longer than 63 chars, and anything that does not match
// DNS_NAME_PATTERN. Returns null when the value must not be matched as a DNS
// hostname.
export function normalizeHostname(host: string): string | null {
	const lower = host.toLowerCase();
	const normalized = lower.endsWith(".") ? lower.slice(0, -1) : lower;
	if (normalized === "") return null;
	if (normalized.includes("_")) return null;
	if (normalized.length > 253) return null;
	if (isIpLiteralText(normalized)) return null;
	for (const label of normalized.split(".")) {
		if (label.length > 63) return null;
	}
	if (!DNS_NAME_PATTERN.test(normalized)) return null;
	return normalized;
}

function isIpLiteralText(value: string): boolean {
	return value.includes(":") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value);
}

// Internal hostnames (control-plane surfaces) are denied regardless of what an
// application resolves them to. Lowercasing and trailing-dot stripping happen
// inside normalizeHostname.
export function isInternalHostname(host: string): boolean {
	const normalized = normalizeHostname(host);
	if (normalized === null) return false;
	return INTERNAL_HOSTNAMES.includes(normalized) || normalized.endsWith(".local") || normalized.endsWith(".internal");
}

// ---- IPv4 classification ----------------------------------------------------

// Strict dotted-quad parse: exactly four decimal octets with no leading zeros
// ("01.2.3.4" is rejected), no whitespace, no hex/octal forms, each octet
// 0-255. Returns null for any other text.
function parseIpv4(value: string): number[] | null {
	const parts = value.split(".");
	if (parts.length !== 4) return null;
	const octets: number[] = [];
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return null;
		if (part.length > 1 && part.startsWith("0")) return null;
		const octet = Number(part);
		if (octet > 255) return null;
		octets.push(octet);
	}
	return octets;
}

// Every non-global IPv4 range (IANA special-purpose / RFC 6890): 0/8, 10/8,
// 100.64/10 (CGNAT), 127/8, 169.254/16, 172.16/12, 192.0.0.0/24,
// 192.0.2.0/24 (TEST-NET-1), 192.168/16, 198.18/15 (benchmarking),
// 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3), 224/4 (multicast),
// 240/4 (reserved, includes 255.255.255.255 limited broadcast).
function isReservedIpv4Octets(octets: readonly number[]): boolean {
	const [a, b, c] = octets;
	if (a === 0) return true; // 0.0.0.0/8 this network
	if (a === 10) return true; // 10.0.0.0/8 private
	if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
	if (a === 127) return true; // 127.0.0.0/8 loopback
	if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / metadata
	if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
	if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // 192.0.0.0/24 + TEST-NET-1 192.0.2.0/24
	if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
	if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
	if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 TEST-NET-2
	if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 TEST-NET-3
	if (a >= 224) return true; // 224/4 multicast + 240/4 reserved
	return false;
}

// ---- IPv6 classification ----------------------------------------------------

// Strict canonical IPv6 expander (no node:net/dns): lowercase, at most one
// "::", every group 1-4 hex digits, exactly 8 groups after expansion. Zone
// IDs ("%eth0") and whitespace are rejected. Embedded dotted-quad IPv4 text
// is only accepted as the final group and only for mapped/compatible forms.
// Returns null for invalid text; callers treat null as reserved (denied).
function expandIpv6(value: string): string[] | null {
	const lower = value.toLowerCase();
	if (lower.includes("%") || /\s/.test(lower)) return null;
	const parts = lower.split("::");
	if (parts.length > 2) return null;

	let usedDottedQuad = false;
	const parseGroups = (part: string): string[] | null => {
		if (part === "") return [];
		const tokens = part.split(":");
		const groups: string[] = [];
		for (let i = 0; i < tokens.length; i++) {
			const token = tokens[i];
			if (token.includes(".")) {
				if (i !== tokens.length - 1) return null; // dotted quad only as final token
				const octets = parseIpv4(token);
				if (octets === null) return null;
				usedDottedQuad = true;
				groups.push(((octets[0] << 8) | octets[1]).toString(16));
				groups.push(((octets[2] << 8) | octets[3]).toString(16));
			} else if (/^[0-9a-f]{1,4}$/.test(token)) {
				groups.push(token);
			} else {
				return null;
			}
		}
		return groups;
	};

	let explicit: string[];
	if (parts.length === 1) {
		const groups = parseGroups(parts[0]);
		if (groups === null) return null;
		if (groups.length !== 8) return null;
		explicit = groups;
	} else {
		const left = parseGroups(parts[0]);
		const right = parseGroups(parts[1]);
		if (left === null || right === null) return null;
		const total = left.length + right.length;
		if (total > 7) return null; // "::" must compress at least one zero group
		explicit = [...left, ...new Array<string>(8 - total).fill("0"), ...right];
	}

	const padded = explicit.map((group) => group.padStart(4, "0"));
	// Embedded dotted-quad IPv4 text is only accepted in mapped/compatible forms.
	if (usedDottedQuad && !(isIpv4Mapped(padded) || isIpv4Compatible(padded))) return null;
	return padded;
}

// ::ffff:0:0/96 — IPv4-mapped; the embedded IPv4 is classified by IPv4 rules.
function isIpv4Mapped(groups: readonly string[]): boolean {
	return groups[0] === "0000" && groups[1] === "0000" && groups[2] === "0000" && groups[3] === "0000" && groups[4] === "0000" && groups[5] === "ffff";
}

// ::0.0.0.0/96 — deprecated IPv4-compatible; always denied (covers :: and ::1).
function isIpv4Compatible(groups: readonly string[]): boolean {
	return groups[0] === "0000" && groups[1] === "0000" && groups[2] === "0000" && groups[3] === "0000" && groups[4] === "0000" && groups[5] === "0000";
}

function classifyEmbeddedIpv4(high: string, low: string): AddressClass {
	const octets = [
		parseInt(high.slice(0, 2), 16),
		parseInt(high.slice(2, 4), 16),
		parseInt(low.slice(0, 2), 16),
		parseInt(low.slice(2, 4), 16),
	];
	return isReservedIpv4Octets(octets) ? "reserved" : "global-ipv4";
}

// Non-global IPv6 ranges: ::/96 IPv4-compatible (covers :: and ::1),
// fe80::/10 link-local, fc00::/7 unique-local, ff00::/8 multicast,
// 64:ff9b::/96 NAT64 (RFC 6052), 64:ff9b:1::/48 local-use NAT64,
// 2001:db8::/32 documentation, 2001:10::/28 ORCHID, 2001::/32 Teredo,
// 2001:2::/48 benchmarking, 2002::/16 6to4, 5f00::/16 SRv6, 3fff::/20
// documentation, 100::/64 discard-only. Groups are zero-padded lowercase hex,
// so lexicographic comparison equals numeric comparison.
function isReservedIpv6Groups(groups: readonly string[]): boolean {
	const g0 = groups[0];
	const g1 = groups[1];
	if (g0 === "0000" && g1 === "0000" && groups[2] === "0000" && groups[3] === "0000" && groups[4] === "0000" && groups[5] === "0000") return true;
	if (g0 >= "fe80" && g0 <= "febf") return true; // fe80::/10 link-local
	if (g0 >= "fc00" && g0 <= "fdff") return true; // fc00::/7 unique-local
	if (g0 >= "ff00") return true; // ff00::/8 multicast
	if (g0 === "0064" && g1 === "ff9b" && groups[2] === "0000" && groups[3] === "0000" && groups[4] === "0000" && groups[5] === "0000") return true; // 64:ff9b::/96 NAT64
	if (g0 === "0064" && g1 === "ff9b" && groups[2] === "0001") return true; // 64:ff9b:1::/48 local-use NAT64
	if (g0 === "2001" && g1 === "0db8") return true; // 2001:db8::/32 documentation
	if (g0 === "2001" && g1 >= "0010" && g1 <= "001f") return true; // 2001:10::/28 ORCHID
	if (g0 === "2001" && g1 === "0000") return true; // 2001::/32 Teredo
	if (g0 === "2001" && g1 === "0002" && groups[2] === "0000") return true; // 2001:2::/48 benchmarking
	if (g0 === "2002") return true; // 2002::/16 6to4
	if (g0 === "5f00") return true; // 5f00::/16 SRv6
	if (g0 === "3fff" && g1 <= "0fff") return true; // 3fff::/20 documentation
	if (g0 === "0100" && g1 === "0000" && groups[2] === "0000" && groups[3] === "0000") return true; // 100::/64 discard-only
	return false;
}

// ---- address classification API --------------------------------------------

// Single classification entry point used by the supervisor egress gateway.
// "invalid" is reserved for values that are not address text at all (empty /
// whitespace-only); malformed address text is deliberately collapsed into
// "reserved" so every unparseable address-like string denies.
export function classifyAddress(value: string): AddressClass {
	const trimmed = value.trim();
	if (trimmed === "") return "invalid";
	if (trimmed.includes(":")) {
		const groups = expandIpv6(trimmed);
		if (groups === null) return "reserved"; // invalid IPv6 text → treated as reserved
		if (isIpv4Mapped(groups)) return classifyEmbeddedIpv4(groups[6], groups[7]);
		if (isReservedIpv6Groups(groups)) return "reserved";
		return "global-ipv6";
	}
	const octets = parseIpv4(trimmed);
	if (octets === null) return "reserved"; // invalid IPv4 text → treated as reserved
	if (isReservedIpv4Octets(octets)) return "reserved";
	return "global-ipv4";
}

export function isGlobalAddress(value: string): boolean {
	const cls = classifyAddress(value);
	return cls === "global-ipv4" || cls === "global-ipv6";
}

export function isReservedAddress(value: string): boolean {
	return !isGlobalAddress(value);
}

export function isReservedIpv4(value: string): boolean {
	const trimmed = value.trim();
	if (trimmed === "" || trimmed.includes(":")) return true; // not a global IPv4
	return classifyAddress(trimmed) !== "global-ipv4";
}

export function isReservedIpv6(value: string): boolean {
	const trimmed = value.trim();
	if (trimmed === "" || !trimmed.includes(":")) return false; // not IPv6-form
	const cls = classifyAddress(trimmed);
	if (cls === "global-ipv4") return false; // IPv4-mapped: reservation follows the embedded IPv4
	return cls !== "global-ipv6";
}

// A destination is denied when its host is invalid or internal, resolves to a
// reserved/invalid address (checked after every redirect), or its port is not
// in the allow list (default deny).
export function isDeniedEgressDestination(options: {
	readonly host: string;
	readonly resolvedAddresses: readonly string[];
	readonly port: number;
	readonly policy: CompiledEgressPolicy;
}): { readonly denied: boolean; readonly reason?: string } {
	const normalized = normalizeHostname(options.host);
	if (normalized === null) return { denied: true, reason: "invalid-host" };
	if (isInternalHostname(normalized)) return { denied: true, reason: "internal-hostname" };
	if (options.resolvedAddresses.length === 0) return { denied: true, reason: "unresolved" };
	if (options.resolvedAddresses.some((address) => !isGlobalAddress(address))) return { denied: true, reason: "reserved-address" };
	const allowed = options.policy.allow.find(
		(rule) => normalizeHostname(rule.host) === normalized && rule.port === options.port,
	);
	if (!allowed) return { denied: true, reason: "undeclared" };
	return { denied: false };
}
