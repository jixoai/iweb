// 用户原始需求（2026-08-14）：Worker 与 Gateway 必须分处不同网络命名空间；Worker 的唯一可达对端是 Gateway。
// 正交意图：2.44 组装证据——internal 网络（无外部路由）只挂 app+gateway；--ip 钉死地址；NO_PROXY 仅内网地址。
import { describe, expect, test } from "bun:test";
import {
	buildSandboxSpec,
	buildGatewayContainerCreateArgs,
	buildAppContainerCreateArgs,
	buildNetworkCreateArgs,
	sandboxNetworkName,
	gatewayNetworkName,
	sandboxSubnetCidr,
	sandboxGatewayAddress,
	sandboxAppAddress,
	GATEWAY_SOCKET_MOUNT_TARGET,
} from "../supervisor/sandbox-spec.ts";

const policy = { resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 64, storageBytes: 2 ** 30 }, egress: { default: "deny" as const, allow: [] } };
const options = {
	runtimeImage: "ghcr.io/denoland/celld@sha256:" + "c".repeat(64),
	gatewayImage: "localhost/iweb-sandbox-gateway@sha256:" + "d".repeat(64),
	stateDirectory: "/var/lib/iweb-sandbox",
	gatewayRuntimeDirectory: "/run/iweb-sandbox/gw",
	region: "us-east-1",
};
const subnetIndex = 7;
const spec = buildSandboxSpec({ sandboxId: "sbx-topo", versionIdentity: { applicationId: "notes", digest: "a".repeat(64), sequence: 1 }, packageDigest: "a".repeat(64), policy, gatewayAddress: sandboxGatewayAddress(subnetIndex), subnetIndex }, options);

describe("enforced dual-network topology (2.44)", () => {
	test("the internal network is created without external routing and with the pinned subnet", () => {
		const internal = buildNetworkCreateArgs("sbx-topo", true, subnetIndex).join(" ");
		expect(internal).toContain("--internal");
		expect(internal).toContain("--subnet " + sandboxSubnetCidr(subnetIndex));
		expect(internal).toContain(sandboxNetworkName("sbx-topo"));
	});

	test("the gateway joins both networks and is pinned to the gateway address", () => {
		const gateway = buildGatewayContainerCreateArgs(spec, options).join(" ");
		const networks = "--network " + sandboxNetworkName("sbx-topo") + ":ip=" + sandboxGatewayAddress(subnetIndex) + "," + gatewayNetworkName("sbx-topo");
		expect(gateway).toContain(networks);
		expect(gateway).toContain("target=" + GATEWAY_SOCKET_MOUNT_TARGET);
		expect(gateway).not.toContain("docker.sock");
		expect(gateway).not.toContain("podman.sock");
	});

	test("the app joins ONLY the internal network: no route to host, Internet, or peers by construction", () => {
		const app = buildAppContainerCreateArgs(spec, options);
		const joined = app.join(" ");
		expect(joined).toContain("--network " + sandboxNetworkName("sbx-topo"));
		expect(joined).not.toContain(gatewayNetworkName("sbx-topo"));
		expect(joined).not.toMatch(/--network slirp/);
		expect(joined).not.toContain("10.0.2.2");
		expect(joined).toContain("--ip " + sandboxAppAddress(subnetIndex));
		// resource envelope + scratch + snapshot mount live on the app container
		expect(joined).toContain("--cpus");
		expect(joined).toContain("--memory");
		expect(joined).toContain("--pids-limit");
		expect(joined).toContain("noexec,nosuid");
		expect(joined).toContain("/var/lib/iweb-sandbox/packages/" + "a".repeat(64));
		expect(joined).not.toContain(GATEWAY_SOCKET_MOUNT_TARGET);
	});

	test("the app dials only the gateway: object endpoint and proxy variables point at the pinned gateway address", () => {
		const gatewayAddress = sandboxGatewayAddress(subnetIndex);
		expect(spec.command.join(" ")).toContain("--endpoint http://" + gatewayAddress + ":9000");
		const proxyEntries = spec.environment.filter((e) => e.startsWith("HTTP_PROXY=") || e.startsWith("http_proxy=") || e.startsWith("HTTPS_PROXY=") || e.startsWith("https_proxy="));
		expect(proxyEntries).toHaveLength(4);
		for (const entry of proxyEntries) expect(entry).toEndWith("http://" + gatewayAddress + ":8081");
		const noProxy = spec.environment.find((e) => e.startsWith("NO_PROXY=")) ?? "";
		expect(noProxy).toBe("NO_PROXY=" + gatewayAddress + ",127.0.0.1,localhost");
	});

	test("subnet math is deterministic and bounded", () => {
		expect(sandboxSubnetCidr(0)).toBe("10.200.0.0/24");
		expect(sandboxSubnetCidr(255)).toBe("10.200.255.0/24");
		expect(sandboxSubnetCidr(256)).toBe("10.201.0.0/24");
		expect(sandboxGatewayAddress(7)).toBe("10.200.7.2");
		expect(sandboxAppAddress(7)).toBe("10.200.7.3");
		expect(() => sandboxSubnetCidr(-1)).toThrow();
		expect(() => sandboxSubnetCidr(1024)).toThrow();
	});
});