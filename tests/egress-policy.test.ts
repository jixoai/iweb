// 用户原始需求（2026-08-14）：egress 默认拒绝；direct IP、DNS rebinding、redirect-to-private、undeclared、IPv6、internal hostname 全部拒绝。
// 正交意图：5.2/5.3/5.4。任务 2.19：用经过验证的规范化 IP/DNS 分类内核替代临时 egress 地址解析。
import { describe, expect, test } from "bun:test";
import {
	classifyAddress,
	compileEgressPolicy,
	isDeniedEgressDestination,
	isGlobalAddress,
	isInternalHostname,
	isReservedAddress,
	isReservedIpv4,
	isReservedIpv6,
	normalizeHostname,
} from "../contracts/egress-policy.ts";

const policy = compileEgressPolicy({ default: "deny", allow: [{ host: "api.example.com", port: 443 }] });

function verdict(host: string, resolvedAddresses: readonly string[], port = 443) {
	return isDeniedEgressDestination({ host, resolvedAddresses, port, policy });
}

describe("egress policy", () => {
	test("is deny-by-default and only allows declared host:port", () => {
		expect(policy.defaultDeny).toBe(true);
		expect(policy.allow).toEqual([{ host: "api.example.com", port: 443 }]);
		expect(isDeniedEgressDestination({ host: "api.example.com", resolvedAddresses: ["93.184.216.34"], port: 443, policy }).denied).toBe(false);
		expect(isDeniedEgressDestination({ host: "api.example.com", resolvedAddresses: ["93.184.216.34"], port: 80, policy }).reason).toBe("undeclared");
		expect(isDeniedEgressDestination({ host: "other.example.com", resolvedAddresses: ["93.184.216.34"], port: 443, policy }).reason).toBe("undeclared");
	});

	test("rejects direct private/reserved IP probes and IPv6 special ranges", () => {
		for (const ip of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.5", "192.168.1.1", "100.64.0.1", "224.0.0.1"]) {
			expect(isReservedAddress(ip)).toBe(true);
		}
		for (const ip of ["::1", "fe80::1", "fc00::1", "ff02::1"]) {
			expect(isReservedAddress(ip)).toBe(true);
		}
		expect(isReservedAddress("93.184.216.34")).toBe(false);
	});

	test("rejects DNS rebinding and redirect-to-private resolved addresses", () => {
		expect(isDeniedEgressDestination({ host: "api.example.com", resolvedAddresses: ["10.0.0.1"], port: 443, policy }).reason).toBe("reserved-address");
		expect(isDeniedEgressDestination({ host: "api.example.com", resolvedAddresses: ["169.254.169.254"], port: 443, policy }).reason).toBe("reserved-address");
	});

	test("rejects internal hostnames regardless of resolution", () => {
		for (const host of ["kernel", "minio", "celld", "supervisor", "admin", "mcp", "api", "kernel.local"]) {
			expect(isInternalHostname(host)).toBe(true);
		}
		expect(isDeniedEgressDestination({ host: "kernel", resolvedAddresses: ["93.184.216.34"], port: 443, policy }).reason).toBe("internal-hostname");
	});

	test("rejects unresolved destinations", () => {
		expect(isDeniedEgressDestination({ host: "api.example.com", resolvedAddresses: [], port: 443, policy }).reason).toBe("unresolved");
	});
});

describe("classifyAddress: reserved IPv4 ranges (every non-global range)", () => {
	const reservedIpv4: readonly (readonly [string, string])[] = [
		["0.0.0.0", "0/8 this network"],
		["0.255.255.255", "0/8 upper edge"],
		["10.0.0.1", "10/8 private"],
		["10.255.255.255", "10/8 upper edge"],
		["100.64.0.1", "100.64/10 CGNAT lower edge"],
		["100.127.255.255", "100.64/10 CGNAT upper edge"],
		["127.0.0.1", "127/8 loopback"],
		["127.255.255.254", "127/8 upper edge"],
		["169.254.0.1", "169.254/16 link-local lower edge"],
		["169.254.169.254", "169.254/16 metadata"],
		["169.254.255.254", "169.254/16 upper edge"],
		["172.16.0.0", "172.16/12 lower edge"],
		["172.31.255.255", "172.16/12 upper edge"],
		["192.0.0.1", "192.0.0.0/24"],
		["192.0.0.255", "192.0.0.0/24 upper edge"],
		["192.0.2.1", "TEST-NET-1 192.0.2.0/24"],
		["192.0.2.255", "TEST-NET-1 upper edge"],
		["192.168.0.1", "192.168/16 private"],
		["192.168.255.255", "192.168/16 upper edge"],
		["198.18.0.1", "198.18/15 benchmarking lower edge"],
		["198.19.255.255", "198.18/15 benchmarking upper edge"],
		["198.51.100.1", "TEST-NET-2 198.51.100.0/24"],
		["203.0.113.1", "TEST-NET-3 203.0.113.0/24"],
		["224.0.0.1", "224/4 multicast lower edge"],
		["239.255.255.255", "224/4 multicast upper edge"],
		["240.0.0.1", "240/4 reserved"],
		["255.255.255.255", "240/4 reserved limited broadcast"],
	];
	for (const [ip, note] of reservedIpv4) {
		test(`reserved IPv4 ${ip} (${note})`, () => {
			expect(classifyAddress(ip)).toBe("reserved");
			expect(isReservedAddress(ip)).toBe(true);
			expect(isReservedIpv4(ip)).toBe(true);
			expect(isGlobalAddress(ip)).toBe(false);
		});
	}
});

describe("classifyAddress: global IPv4", () => {
	const globalIpv4 = [
		"1.1.1.1",
		"8.8.8.8",
		"9.9.9.9",
		"93.184.216.34",
		"100.63.255.255", // just below CGNAT
		"100.128.0.1", // just above CGNAT
		"172.15.255.255", // just below 172.16/12
		"172.32.0.1", // just above 172.16/12
		"192.0.1.1", // outside 192.0.0.0/24 and TEST-NET-1
		"198.20.0.1", // outside 198.18/15
		"198.51.101.1", // outside TEST-NET-2
		"203.0.114.1", // outside TEST-NET-3
		"223.255.255.255", // just below 224/4
	];
	for (const ip of globalIpv4) {
		test(`global IPv4 ${ip}`, () => {
			expect(classifyAddress(ip)).toBe("global-ipv4");
			expect(isReservedAddress(ip)).toBe(false);
			expect(isReservedIpv4(ip)).toBe(false);
			expect(isGlobalAddress(ip)).toBe(true);
		});
	}
});

describe("classifyAddress: invalid IPv4 text is treated as reserved (denied)", () => {
	// 任务 2.19："01.2.3.4" 等非法文本必须按 reserved 处理；只有空/纯空白输入才是 "invalid"。
	const invalidIpv4 = [
		"01.2.3.4", // leading zero
		"1.02.3.4", // leading zero
		"1.2.3.04", // leading zero
		"1.2.3", // three octets
		"1.2.3.4.5", // five octets
		"0x1.2.3.4", // hex octet
		"1.2.3.0x4", // hex octet
		"1.2.3.300", // octet out of range
		"256.1.1.1", // octet out of range
		"1.2.3.999", // octet out of range
		"1.2.3.-4", // sign
		"1. 2.3.4", // embedded whitespace
		"1.2 .3.4", // embedded whitespace
		"1..2.3", // empty octet
		"1.2.3.4.5.6", // too many octets
		"1.2.3.4:80", // host:port is not an address
	];
	for (const ip of invalidIpv4) {
		test(`invalid IPv4 ${JSON.stringify(ip)}`, () => {
			expect(classifyAddress(ip)).toBe("reserved");
			expect(isReservedAddress(ip)).toBe(true);
			expect(isReservedIpv4(ip)).toBe(true);
			expect(isGlobalAddress(ip)).toBe(false);
		});
	}

	test("outer whitespace is trimmed before classification (embedded whitespace is not)", () => {
		expect(classifyAddress(" 93.184.216.34 ")).toBe("global-ipv4");
		expect(classifyAddress("1:2:3:4:5:6:7:8 ")).toBe("global-ipv6");
		expect(classifyAddress(" 10.0.0.1 ")).toBe("reserved");
	});

	test("empty / whitespace-only input classifies as invalid", () => {
		for (const value of ["", "   ", "\t"]) {
			expect(classifyAddress(value)).toBe("invalid");
			expect(isGlobalAddress(value)).toBe(false);
			expect(isReservedAddress(value)).toBe(true);
		}
	});
});

describe("classifyAddress: reserved IPv6 ranges", () => {
	const reservedIpv6: readonly (readonly [string, string])[] = [
		["::", "unspecified"],
		["::1", "loopback"],
		["fe80::1", "link-local"],
		["fe80:0:0:1::1", "link-local"],
		["febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::/10 upper edge"],
		["fc00::1", "unique-local"],
		["fd00::1", "unique-local"],
		["fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fc00::/7 upper edge"],
		["ff00::", "multicast"],
		["ff02::1", "multicast all-nodes"],
		["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "multicast upper edge"],
		["64:ff9b::1", "NAT64 well-known prefix (RFC 6052)"],
		["64:ff9b:1::1", "local-use NAT64"],
		["2001:db8::1", "documentation"],
		["2001:10::1", "ORCHID lower edge"],
		["2001:1f::1", "ORCHID upper edge"],
		["2001::1", "Teredo (tunneling bypass)"],
		["2001::4136:e378:8000:63bf:3fff:fdd2", "Teredo example"],
		["2001:2::1", "benchmarking"],
		["2002::1", "6to4"],
		["5f00::1", "SRv6"],
		["3fff::1", "new documentation"],
		["3fff:0fff::1", "3fff::/20 upper edge"],
		["100::1", "discard-only"],
		["::ffff:127.0.0.1", "IPv4-mapped loopback"],
		["::ffff:10.0.0.1", "IPv4-mapped private"],
		["::ffff:0:0", "IPv4-mapped 0.0.0.0"],
		["::127.0.0.1", "IPv4-compatible (deny regardless of embedded IPv4)"],
		["::93.184.216.34", "IPv4-compatible global-embedded (deny)"],
	];
	for (const [ip, note] of reservedIpv6) {
		test(`reserved IPv6 ${ip} (${note})`, () => {
			expect(classifyAddress(ip)).toBe("reserved");
			expect(isReservedAddress(ip)).toBe(true);
			expect(isReservedIpv6(ip)).toBe(true);
			expect(isGlobalAddress(ip)).toBe(false);
		});
	}
});

describe("classifyAddress: global IPv6", () => {
	const globalIpv6 = [
		"2606:4700:4700::1111", // Cloudflare DNS
		"2001:4860:4860::8888", // Google DNS
		"2a00:1450:4001:82f::200e", // google.com AAAA
		"2600:9000:5301::1", // Amazon
		"1:2:3:4:5:6:7:8", // full form, no compression
		"1:2:3:4:5:6:7::", // trailing :: compression
		"2001:db9::1", // just outside documentation 2001:db8::/32
		"2001:20::1", // just outside ORCHID 2001:10::/28
		"2001:3::1", // outside Teredo/benchmark/ORCHID/documentation
		"64:ff9c::1", // outside NAT64
		"3fff:1000::1", // just outside 3fff::/20
	];
	for (const ip of globalIpv6) {
		test(`global IPv6 ${ip}`, () => {
			expect(classifyAddress(ip)).toBe("global-ipv6");
			expect(isReservedAddress(ip)).toBe(false);
			expect(isReservedIpv6(ip)).toBe(false);
			expect(isGlobalAddress(ip)).toBe(true);
		});
	}
});

describe("classifyAddress: IPv4-mapped and IPv4-compatible", () => {
	test("IPv4-mapped addresses classify by the embedded IPv4", () => {
		expect(classifyAddress("::ffff:93.184.216.34")).toBe("global-ipv4");
		expect(isGlobalAddress("::ffff:93.184.216.34")).toBe(true);
		expect(isReservedAddress("::ffff:93.184.216.34")).toBe(false);
		expect(isReservedIpv6("::ffff:93.184.216.34")).toBe(false);
		expect(classifyAddress("::ffff:127.0.0.1")).toBe("reserved");
		expect(isReservedAddress("::ffff:127.0.0.1")).toBe(true);
		expect(isReservedIpv6("::ffff:127.0.0.1")).toBe(true);
		expect(classifyAddress("::FFFF:10.0.0.1")).toBe("reserved"); // case-insensitive
		expect(classifyAddress("0:0:0:0:0:ffff:5db8:d822")).toBe("global-ipv4"); // expanded hex form
	});

	test("IPv4-compatible ::/96 is always denied even with a global embedded IPv4", () => {
		expect(classifyAddress("::93.184.216.34")).toBe("reserved");
		expect(classifyAddress("::127.0.0.1")).toBe("reserved");
		expect(classifyAddress("::")).toBe("reserved");
		expect(classifyAddress("::1")).toBe("reserved");
	});
});

describe("classifyAddress: invalid IPv6 text is treated as reserved (denied)", () => {
	const invalidIpv6 = [
		"fe80::1%eth0", // zone id
		"::1%lo0", // zone id
		"1:2:3:4:5:6:7", // seven groups without ::
		"1:2:3:4:5:6:7:8:9", // nine groups
		"1::2::3", // two ::
		"1:::2", // empty group
		"12345::1", // group longer than 4 hex digits
		"gggg::1", // non-hex group
		"1.2.3.4:5", // dotted quad not in final position
		"2001:db8::1.2.3.4", // embedded IPv4 outside mapped/compatible forms
		"::ffff:1.2.3", // truncated embedded IPv4
		"::ffff:01.2.3.4", // leading-zero embedded IPv4
		"::ffff:1.2.3.300", // out-of-range embedded IPv4
		"::ffff:1.2.3.4.5", // five-octet embedded IPv4
		"1: 2:3:4:5:6:7:8", // embedded whitespace
		"1:2 :3:4:5:6:7:8", // embedded whitespace
		"fe80:: 1", // embedded whitespace
	];
	for (const ip of invalidIpv6) {
		test(`invalid IPv6 ${JSON.stringify(ip)}`, () => {
			expect(classifyAddress(ip)).toBe("reserved");
			expect(isReservedAddress(ip)).toBe(true);
			expect(isReservedIpv6(ip)).toBe(true);
			expect(isGlobalAddress(ip)).toBe(false);
		});
	}
});

describe("normalizeHostname", () => {
	test("lowercases and strips a single trailing dot", () => {
		expect(normalizeHostname("Api.Example.COM.")).toBe("api.example.com");
		expect(normalizeHostname("api.example.com")).toBe("api.example.com");
		expect(normalizeHostname("API.EXAMPLE.COM")).toBe("api.example.com");
		expect(normalizeHostname("Example.")).toBe("example");
		expect(normalizeHostname("example")).toBe("example");
	});

	test("rejects non-DNS hostnames and IP literals", () => {
		const bad = [
			"", // empty
			".", // empty after trailing-dot strip
			"..",
			"exa_mple.com", // underscore
			"_example.com", // leading underscore
			"example_.com", // trailing underscore
			"1.2.3.4", // IPv4 literal
			"192.168.1.1", // IPv4 literal
			"2001:db8::1", // IPv6 literal
			"::1", // IPv6 literal
			"fe80::1%eth0", // zone id / IPv6 literal
			"-example.com", // leading hyphen label
			"example-.com", // trailing hyphen label
			"exa mple.com", // whitespace
			"example..com", // empty label
			".example.com", // leading dot
		];
		for (const value of bad) {
			expect(normalizeHostname(value)).toBe(null);
		}
		// trailing dot is stripped, so a single trailing dot is fine
		expect(normalizeHostname("example.com.")).toBe("example.com");
	});

	test("enforces name and label length bounds", () => {
		const label63 = "a".repeat(63);
		expect(normalizeHostname(label63)).toBe(label63);
		expect(normalizeHostname("a".repeat(64))).toBe(null); // label > 63
		expect(normalizeHostname(label63 + ".com")).toBe(label63 + ".com");
		expect(normalizeHostname("a".repeat(64) + ".com")).toBe(null); // label > 63
		const name253 = "a".repeat(63) + "." + "a".repeat(63) + "." + "a".repeat(63) + "." + "a".repeat(61);
		expect(name253.length).toBe(253);
		expect(normalizeHostname(name253)).toBe(name253);
		expect(normalizeHostname(name253 + ".a")).toBe(null); // name > 253
	});
});

describe("isInternalHostname variants", () => {
	test("case and trailing dot do not bypass the internal check", () => {
		for (const host of ["kernel", "KERNEL", "kernel.", "Kernel.", "API", "api.", "SUPERVISOR", "minio.internal", "metadata.google.internal", "foo.local", "KERNEL.LOCAL"]) {
			expect(isInternalHostname(host)).toBe(true);
		}
		for (const host of ["example.com", "kernelx", "kernel.example", "api.example.com", "internally", "1.2.3.4"]) {
			expect(isInternalHostname(host)).toBe(false);
		}
	});
});

describe("isDeniedEgressDestination hardened flow", () => {
	test("allow matching is case- and trailing-dot-insensitive", () => {
		expect(verdict("API.EXAMPLE.COM.", ["93.184.216.34"], 443).denied).toBe(false);
		expect(verdict("api.example.com", ["93.184.216.34"], 443).denied).toBe(false);
		expect(verdict("API.EXAMPLE.COM", ["93.184.216.34"], 443).denied).toBe(false);
		expect(verdict("api.example.com.", ["93.184.216.34"], 443).denied).toBe(false);
	});

	test("invalid host text is denied as invalid-host", () => {
		// 旧行为：IP literal 作为 host 走 undeclared；2.19 起 normalizeHostname 返回 null → invalid-host。
		expect(verdict("not_a_host", ["93.184.216.34"], 443).reason).toBe("invalid-host");
		expect(verdict("1.2.3.4", ["93.184.216.34"], 443).reason).toBe("invalid-host"); // IP literal — classify separately
		expect(verdict("", ["93.184.216.34"], 443).reason).toBe("invalid-host");
	});

	test("undeclared port and undeclared host are denied", () => {
		expect(verdict("api.example.com", ["93.184.216.34"], 80).reason).toBe("undeclared");
		expect(verdict("other.example.com", ["93.184.216.34"], 443).reason).toBe("undeclared");
	});

	test("unresolved (empty address list) is denied", () => {
		expect(verdict("api.example.com", [], 443).reason).toBe("unresolved");
	});

	test("redirect re-check: any reserved/invalid address in the list denies", () => {
		// 首次解析为 global，redirect 后解析列表混入一个 reserved → 必须拒绝。
		expect(verdict("api.example.com", ["93.184.216.34", "10.0.0.1"], 443).reason).toBe("reserved-address");
		expect(verdict("api.example.com", ["93.184.216.34", "169.254.169.254", "8.8.8.8"], 443).reason).toBe("reserved-address");
		expect(verdict("api.example.com", ["93.184.216.34", "garbage"], 443).reason).toBe("reserved-address");
		expect(verdict("api.example.com", ["::ffff:127.0.0.1"], 443).reason).toBe("reserved-address");
		expect(verdict("api.example.com", ["::ffff:93.184.216.34"], 443).denied).toBe(false); // mapped global is allowed
		expect(verdict("api.example.com", ["2001:4860:4860::8888"], 443).denied).toBe(false); // global IPv6 is allowed
	});

	test("internal hostnames deny regardless of resolution and case", () => {
		for (const host of ["kernel", "minio", "celld", "supervisor", "admin", "mcp", "api", "kernel.local", "KERNEL.", "metadata.google.internal"]) {
			expect(verdict(host, ["93.184.216.34"], 443).reason).toBe("internal-hostname");
		}
	});
});