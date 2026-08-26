// 用户原始需求（2026-08-26，add-wasm-runtime 镜像批次 supervisor 半边）：wasm kind 的
//   wasmd Podman argv——10 元素固定契约（对位 kernel-rs/wasmd/src/argv.rs parse_argv 的
//   fail-closed 语义）、manifest 可执行权威拒绝（WASM_MANIFEST_EXECUTABLE_AUTHORITY）、
//   digest-pinned runtime image、以及与 celld 沙箱同法（同网络/资源/降权段 + wasm 增量
//   --preserve-fds 2 与零 --env）的 create argv 组装。
// 正交意图：argv 的三个 JCS JSON 参数与 Rust 测试向量逐字节一致（跨实现锁）；未知/
//   缺失/多余参数、DNS/通配/零端口地址、非法架构、非 canonical JSON、未知身份字段各按
//   WASMD_ARGV_INVALID / WASMD_ARGV_WIRE_INVALID / WASM_IDENTITY_INCOMPLETE 分码拒绝。
import { describe, expect, test } from "bun:test";
import {
	buildWasmdAppContainerCreateArgs,
	buildWasmSandboxSpec,
	buildWasmdArgvV1,
	verifyWasmdArgvV1,
	wasmdIdentityOfCommand,
	WASMD_ARGV_ELEMENT_COUNT,
	WASMD_ARGV_INVALID,
	WASMD_ARGV_MARKER,
	WASMD_ARGV_PROGRAM,
	WASMD_ARGV_WIRE_INVALID,
	WASM_IDENTITY_INCOMPLETE,
	WASM_MANIFEST_EXECUTABLE_AUTHORITY,
	WASM_SPAWN_INVALID,
	wasmComponentSnapshotPath,
	wasmdIngressTarget,
	WASMD_CAPABILITY_RECORD_MOUNT_TARGET,
	WASMD_COMPONENT_MOUNT_TARGET,
} from "../supervisor/wasm-spawn.ts";
import { appContainerName, sandboxAppAddress, sandboxGatewayAddress, sandboxNetworkName, SECCOMP_PROFILE_HOST_PATH } from "../supervisor/sandbox-spec.ts";
import { exampleExecutionCommandV1, exampleNormalizedWasmManifestV1, type ExecutionCommandV1 } from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";

function startCommand(): ExecutionCommandV1 {
	// example 命令的身份/绑定与 Rust 向量同值（sbx-vector / a405...-1 / P=1,E=1）。
	return { ...exampleExecutionCommandV1(), operation: "start" };
}

// argv.rs / wire.rs 测试向量（Rust 侧同值向量；JCS 字节跨实现必须逐字节一致——binding/
// identity 以契约 JCS 序列化生成，与 Rust golden（wire.rs health 向量内嵌同一 binding）
// 锁定同一编码；resources 用手写向量字节）。
const VECTOR_BINDING_JSON = Buffer.from(jcsCanonicalBytes(startCommand().runtimeBinding)).toString("utf8");
const VECTOR_IDENTITY_JSON_VALID = Buffer.from(jcsCanonicalBytes(wasmdIdentityOfCommand(startCommand()))).toString("utf8");
// 未知字段注入（deny_unknown_fields 对位的负例：键序无关，出现即拒）。
const VECTOR_IDENTITY_JSON = VECTOR_IDENTITY_JSON_VALID.replace(/^\{/, '{"schemaVersion2Unused":null,');
const VECTOR_RESOURCES_JSON = '{"cpuMillis":500,"memoryBytes":268435456,"pidLimit":256,"storageBytes":1073741824}';

function vectorArgv(): string[] {
	return [
		WASMD_ARGV_PROGRAM,
		WASMD_ARGV_MARKER,
		"/run/iweb-sandbox/component.wasm",
		"127.0.0.1:8787",
		"10.88.0.1:8081",
		"/data/kernel/node-capability.json",
		"linux/arm64",
		VECTOR_BINDING_JSON,
		VECTOR_IDENTITY_JSON_VALID,
		VECTOR_RESOURCES_JSON,
	];
}

function spawnOptions(): Parameters<typeof buildWasmSandboxSpec>[1] {
	return {
		stateDirectory: "/var/lib/iweb-sandbox",
		runtimeImageRepository: "localhost/iweb-wasmd",
		architecture: "linux/arm64",
		capabilityRecordHostPath: "/var/lib/iweb-sandbox/node-capability.json",
		subnetIndex: 0,
	};
}

describe("wasmd argv v1: exact 10-element contract (argv.rs counterpart)", () => {
	test("the Rust vector parses and round-trips the marker/addresses/architecture", () => {
		const invocation = verifyWasmdArgvV1(vectorArgv());
		expect(invocation.ok).toBe(true);
		if (!invocation.ok) return;
		expect(invocation.value.componentPath).toBe("/run/iweb-sandbox/component.wasm");
		expect(invocation.value.listen).toBe("127.0.0.1:8787");
		expect(invocation.value.gateway).toBe("10.88.0.1:8081");
		expect(invocation.value.capabilityRecordPath).toBe("/data/kernel/node-capability.json");
		expect(invocation.value.architecture).toBe("linux/arm64");
		expect(invocation.value.identity.configRevision).toBe(2);
		expect(invocation.value.resources.memoryBytes).toBe(268435456);
	});

	test("the builder emits the vector JCS bytes for the example command", () => {
		const built = buildWasmdArgvV1({
			command: startCommand(),
			resources: { cpuMillis: 500, memoryBytes: 268435456, pidLimit: 256, storageBytes: 1073741824 },
			listen: "127.0.0.1:8787",
			gateway: "10.88.0.1:8081",
			componentPath: "/run/iweb-sandbox/component.wasm",
			capabilityRecordPath: "/data/kernel/node-capability.json",
			architecture: "linux/arm64",
		});
		expect(built.ok).toBe(true);
		if (!built.ok) return;
		const argv = [...built.value.argv];
		expect(argv.length).toBe(WASMD_ARGV_ELEMENT_COUNT);
		expect(argv[0]).toBe(WASMD_ARGV_PROGRAM);
		expect(argv[1]).toBe(WASMD_ARGV_MARKER);
		// 与 Rust 侧向量逐字节一致（binding/identity/resources 的 JCS 编码锁）。
		expect(argv[7]).toBe(VECTOR_BINDING_JSON);
		expect(argv[8]).toBe(VECTOR_IDENTITY_JSON_VALID);
		expect(argv[9]).toBe(VECTOR_RESOURCES_JSON);
	});

	test("unknown marker, extra and missing elements fail closed with WASMD_ARGV_INVALID", () => {
		const baseline = vectorArgv();
		const wrongMarker = verifyWasmdArgvV1([...baseline.slice(0, 1), "--iweb-wasmd-argv@2", ...baseline.slice(2)]);
		expect(wrongMarker.ok).toBe(false);
		if (!wrongMarker.ok) expect(wrongMarker.errors[0]?.code).toBe(WASMD_ARGV_INVALID);
		const extra = verifyWasmdArgvV1([...baseline, "--extra"]);
		expect(extra.ok).toBe(false);
		if (!extra.ok) expect(extra.errors[0]?.code).toBe(WASMD_ARGV_INVALID);
		const missing = verifyWasmdArgvV1(baseline.slice(0, -1));
		expect(missing.ok).toBe(false);
		if (!missing.ok) expect(missing.errors[0]?.code).toBe(WASMD_ARGV_INVALID);
	});

	test("DNS names, wildcard addresses, zero ports, relative paths, and bad architectures are rejected", () => {
		const baseline = vectorArgv();
		const cases: readonly [number, string][] = [
			[3, "0.0.0.0:8787"],
			[3, "127.0.0.1:0"],
			[3, "127.0.0.1:70000"],
			[4, "gateway.internal:8081"],
			[2, "component.wasm"],
			[5, "node-capability.json"],
			[6, "linux/riscv64"],
		];
		for (const [index, value] of cases) {
			const mutated = [...baseline];
			mutated[index] = value;
			const result = verifyWasmdArgvV1(mutated);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.errors[0]?.code).toBe(WASMD_ARGV_INVALID);
		}
	});

	test("non-canonical JSON, unknown identity fields, and dead generations are wire violations", () => {
		const baseline = vectorArgv();
		// 非 canonical（键序非 JCS）。
		const unsorted = [...baseline];
		unsorted[9] = '{"memoryBytes":268435456,"cpuMillis":500,"pidLimit":256,"storageBytes":1073741824}';
		let result = verifyWasmdArgvV1(unsorted);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors[0]?.code).toBe(WASMD_ARGV_WIRE_INVALID);
		// 未知身份字段（deny_unknown_fields 对位）。
		const unknownField = [...baseline];
		unknownField[8] = VECTOR_IDENTITY_JSON;
		result = verifyWasmdArgvV1(unknownField);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((error) => error.code === WASMD_ARGV_WIRE_INVALID)).toBe(true);
		// E=0 的身份（未分配 execution）→ WASM_IDENTITY_INCOMPLETE。
		const dead = [...baseline];
		dead[8] = VECTOR_IDENTITY_JSON_VALID.replace('"executionGeneration":1', '"executionGeneration":0');
		result = verifyWasmdArgvV1(dead);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((error) => error.code === WASM_IDENTITY_INCOMPLETE)).toBe(true);
		// 资源越界。
		const overBudget = [...baseline];
		overBudget[9] = '{"cpuMillis":1000001,"memoryBytes":268435456,"pidLimit":256,"storageBytes":1073741824}';
		result = verifyWasmdArgvV1(overBudget);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((error) => error.code === WASMD_ARGV_WIRE_INVALID)).toBe(true);
		// 重复键（strict parse 在覆盖前报错）。
		const duplicated = [...baseline];
		duplicated[9] = '{"cpuMillis":500,"cpuMillis":500,"memoryBytes":268435456,"pidLimit":256,"storageBytes":1073741824}';
		result = verifyWasmdArgvV1(duplicated);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors[0]?.code).toBe(WASMD_ARGV_WIRE_INVALID);
	});
});

describe("wasm sandbox spawn spec: executable authority stays with the supervisor", () => {
	test("the spec assembles pinned addresses, digest-pinned image, and the verified argv", () => {
		const spec = buildWasmSandboxSpec({ command: startCommand(), policy: exampleNormalizedWasmManifestV1() }, spawnOptions());
		expect(spec.ok).toBe(true);
		if (!spec.ok) return;
		// 同拓扑：app 挂 internal 网、gateway 拨 app 的 pinned 地址（与 celld ingressTarget 同端口）。
		expect(spec.value.listenAddress).toBe(wasmdIngressTarget(0));
		expect(spec.value.listenAddress).toBe(sandboxAppAddress(0) + ":8787");
		expect(spec.value.gatewayAddress).toBe(sandboxGatewayAddress(0) + ":8081");
		// image 权威只在 runtime binding 的 digest。
		expect(spec.value.runtimeImage).toBe("localhost/iweb-wasmd@sha256:" + "cd".repeat(32));
		// argv 已通过 10 元素契约复验，且身份/绑定来自命令。
		expect(spec.value.argv.length).toBe(WASMD_ARGV_ELEMENT_COUNT);
		expect(spec.value.argv[2]).toBe(WASMD_COMPONENT_MOUNT_TARGET);
		expect(spec.value.argv[5]).toBe(WASMD_CAPABILITY_RECORD_MOUNT_TARGET);
		expect(spec.value.argv[7]).toBe(VECTOR_BINDING_JSON);
		// 挂载：组件快照（entry layer digest 寻址）+ capability record，均只读。
		expect(spec.value.mounts.length).toBe(2);
		expect(spec.value.mounts[0]?.readOnly).toBe(true);
		expect(spec.value.mounts[0]?.source).toBe(wasmComponentSnapshotPath("/var/lib/iweb-sandbox", "sha256:" + "1".repeat(64)));
		expect(spec.value.mounts[1]?.source).toBe("/var/lib/iweb-sandbox/node-capability.json");
	});

	test("a manifest carrying image, command, mount, capability, socket, TLS, or env authority is rejected by name", () => {
		const authorityShapes: unknown[] = [
			{ ...exampleNormalizedWasmManifestV1(), image: "localhost/evil:latest" },
			{ ...exampleNormalizedWasmManifestV1(), entrypoint: ["/bin/sh"] },
			{ ...exampleNormalizedWasmManifestV1(), command: ["--privileged"] },
			{ ...exampleNormalizedWasmManifestV1(), mounts: [{ source: "/", target: "/host" }] },
			{ ...exampleNormalizedWasmManifestV1(), runtime: { ...exampleNormalizedWasmManifestV1().runtime, capability: "NET_ADMIN" } },
			{ ...exampleNormalizedWasmManifestV1(), runtime: { ...exampleNormalizedWasmManifestV1().runtime, socket: "tcp://0.0.0.0:9229" } },
			{ ...exampleNormalizedWasmManifestV1(), tls: { cert: "..." } },
			{ ...exampleNormalizedWasmManifestV1(), environment: { WASMD_ARGV: "override" } },
			{ ...exampleNormalizedWasmManifestV1(), resources: { cpuMillis: 1, memoryBytes: 2, pidLimit: 3, storageBytes: 4, env: ["X=1"] } },
		];
		for (const shape of authorityShapes) {
			const spec = buildWasmSandboxSpec({ command: startCommand(), policy: shape as never }, spawnOptions());
			expect(spec.ok).toBe(false);
			if (!spec.ok) expect(spec.errors[0]?.code).toBe(WASM_MANIFEST_EXECUTABLE_AUTHORITY);
		}
		// 非权威的未知字段仍由契约键集兜底拒绝（不落第二套语义）。
		const unknownField = { ...exampleNormalizedWasmManifestV1(), Surprise: 1 } as never;
		const spec = buildWasmSandboxSpec({ command: startCommand(), policy: unknownField }, spawnOptions());
		expect(spec.ok).toBe(false);
		if (!spec.ok) expect(spec.errors[0]?.code).toBe("WASM_MANIFEST_INVALID");
	});

	test("floating image references, bad subnets, and bad paths fail closed", () => {
		const input = { command: startCommand(), policy: exampleNormalizedWasmManifestV1() };
		const tagged = buildWasmSandboxSpec(input, { ...spawnOptions(), runtimeImageRepository: "localhost/iweb-wasmd:v1" });
		expect(tagged.ok).toBe(false);
		if (!tagged.ok) expect(tagged.errors[0]?.code).toBe(WASM_SPAWN_INVALID);
		const digested = buildWasmSandboxSpec(input, { ...spawnOptions(), runtimeImageRepository: "localhost/x@sha256:" + "0".repeat(64) });
		expect(digested.ok).toBe(false);
		const subnet = buildWasmSandboxSpec(input, { ...spawnOptions(), subnetIndex: 1024 });
		expect(subnet.ok).toBe(false);
		if (!subnet.ok) expect(subnet.errors[0]?.code).toBe(WASM_SPAWN_INVALID);
		const relative = buildWasmSandboxSpec(input, { ...spawnOptions(), capabilityRecordHostPath: "node-capability.json" });
		expect(relative.ok).toBe(false);
		// 命令本身未过契约（secretValuesDigest 非法）→ 拒绝。
		const tampered = buildWasmSandboxSpec({ command: { ...startCommand(), secretValuesDigest: "nothex" }, policy: exampleNormalizedWasmManifestV1() }, spawnOptions());
		expect(tampered.ok).toBe(false);
	});
});

describe("wasm app container create argv: same sandbox law, wasm deltas only", () => {
	test("the create argv keeps the celld conventions and adds --preserve-fds with zero env", () => {
		const spec = buildWasmSandboxSpec({ command: startCommand(), policy: exampleNormalizedWasmManifestV1() }, spawnOptions());
		expect(spec.ok).toBe(true);
		if (!spec.ok) return;
		const args = buildWasmdAppContainerCreateArgs(spec.value);
		const at = (flag: string): string => {
			const index = args.indexOf(flag);
			expect(index).toBeGreaterThan(-1);
			return args[index + 1] ?? "";
		};
		const valueOf = (flag: string): string => {
			// 成对查找（--security-opt 出现两次：no-new-privileges 与 seccomp=…）。
			const values: string[] = [];
			for (let index = args.indexOf(flag); index !== -1; index = args.indexOf(flag, index + 1)) values.push(args[index + 1] ?? "");
			return values.join("|");
		};
		// celld 同款段：managed 标签、只读根、降权、seccomp、internal 网络 + pinned IP、资源界。
		expect(args[0]).toBe("create");
		expect(at("--name")).toBe(appContainerName("sbx-vector"));
		expect(at("--label")).toContain("iweb.managed=1");
		expect(args).toContain("--read-only");
		expect(at("--cap-drop")).toBe("ALL");
		expect(valueOf("--security-opt")).toBe("no-new-privileges|seccomp=" + SECCOMP_PROFILE_HOST_PATH);
		expect(at("--network")).toBe(sandboxNetworkName("sbx-vector"));
		expect(at("--ip")).toBe(sandboxAppAddress(0));
		// example manifest 的资源界进入 cgroup 参数。
		expect(at("--cpus")).toBe("0.001");
		expect(at("--memory")).toBe("2");
		expect(at("--pids-limit")).toBe("3");
		expect(at("--storage-opt")).toBe("size=4");
		// wasm 增量：--preserve-fds 2（FD 3/4 的唯一进入路径）且零 --env。
		expect(at("--preserve-fds")).toBe("2");
		expect(args).not.toContain("--env");
		// 镜像是 digest-pinned 引用；尾部 command 恰好是 10 元素 argv。
		expect(args[args.length - WASMD_ARGV_ELEMENT_COUNT - 1]).toBe("localhost/iweb-wasmd@sha256:" + "cd".repeat(32));
		expect(args.slice(args.length - WASMD_ARGV_ELEMENT_COUNT)).toEqual([...spec.value.argv]);
	});
});
