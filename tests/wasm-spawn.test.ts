// 用户原始需求（2026-08-26，add-wasm-runtime 镜像批次 supervisor 半边；2026-08-29
//   simplify-wasm-host-services 单版本化）：wasm kind 的 wasmd Podman argv——argv@1 十元素
//   纯解析契约保留为 wire 对照（对位 kernel-rs/wasmd/src/argv.rs parse_argv 的 fail-closed
//   语义）；命令驱动的 spawn spec 恒为 argv@2（11 元素）。Rust kernel-rs 为 wire 权威，
//   TS 侧不再做跨实现逐字节 golden 锁。
// 正交意图：未知/缺失/多余参数、DNS/通配/零端口地址、非法架构、非 canonical JSON、
//   未知身份字段各按 WASMD_ARGV_INVALID / WASMD_ARGV_WIRE_INVALID / WASM_IDENTITY_INCOMPLETE
//   分码拒绝；manifest 可执行权威拒绝（WASM_MANIFEST_EXECUTABLE_AUTHORITY）。
import { describe, expect, test } from "bun:test";
import {
	buildWasmdAppContainerCreateArgs,
	buildWasmSandboxSpec,
	verifyWasmdArgvV1,
	WASMD_ARGV_ELEMENT_COUNT,
	WASMD_ARGV_INVALID,
	WASMD_ARGV_MARKER,
	WASMD_ARGV_PROGRAM,
	WASMD_ARGV_V2_ELEMENT_COUNT,
	WASMD_ARGV_WIRE_INVALID,
	WASM_IDENTITY_INCOMPLETE,
	WASM_MANIFEST_EXECUTABLE_AUTHORITY,
	WASM_SPAWN_INVALID,
	WASM_HOST_POLICY_DIGEST_MISMATCH,
	wasmApplicationDataPath,
	wasmComponentSnapshotPath,
	wasmdIngressTarget,
	WASMD_CAPABILITY_RECORD_MOUNT_TARGET,
	WASMD_COMPONENT_MOUNT_TARGET,
	WASMD_DATA_MOUNT_TARGET_ROOT,
} from "../supervisor/wasm-spawn.ts";
import { appContainerName, sandboxAppAddress, sandboxGatewayAddress, sandboxNetworkName, SECCOMP_PROFILE_HOST_PATH } from "../supervisor/sandbox-spec.ts";
import { exampleExecutionCommand, exampleNormalizedWasmManifestV1, exampleRuntimeBindingIdentityV1, type ExecutionCommand } from "../packages/contracts/wasm-execution.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";
import { sealWasmHostServicePolicyV2, WASM_EMPTY_HOST_SERVICE_POLICY_V2 } from "../packages/contracts/wasm-host-policy.ts";

// argv@1 十元素解析器保留为 wire 对照（无命令驱动构建；执行命令单一形态恒 argv@2）。
// 向量：admission 事实形 binding（ABI 1.0.0）+ 手拼 identity JSON。
const VECTOR_BINDING_JSON = Buffer.from(jcsCanonicalBytes(exampleRuntimeBindingIdentityV1())).toString("utf8");
const VECTOR_IDENTITY_JSON_VALID = Buffer.from(
	jcsCanonicalBytes({
		sandboxId: "sbx-vector",
		versionId: exampleExecutionCommand().identity.versionId,
		packageDigest: exampleExecutionCommand().packageDigest,
		runtimeBinding: exampleRuntimeBindingIdentityV1(),
		capabilityRecordRevision: 5,
		capabilityRecordHash: "2".repeat(64),
		secretRevision: 3,
		secretValuesDigest: "6".repeat(64),
		configRevision: 2,
		configSnapshotRef: "7".repeat(64),
		configValuesDigest: "8".repeat(64),
		preparationGeneration: 1,
		executionGeneration: 1,
	}),
).toString("utf8");

/** 单一命令形态 + logging-only 最小 policy（reserveBytes 1 < example manifest memoryBytes 2）。 */
const MINIMAL_POLICY = sealWasmHostServicePolicyV2({
	schemaVersion: 2,
	matrixRevision: 2,
	hostAbi: "iweb-wasmd-abi@1.1.0",
	hostServices: {
		kv: null,
		sql: null,
		logging: {
			profile: "bounded-memory-ring-v1",
			limits: { maxEventBytes: 256, ringMaxEvents: 8, ringMaxBytes: 2048 },
			consistency: "append-only-drop-on-full-v1",
			durability: "no-durable-claim-v1",
			retention: "runtime-lifecycle-only-v1",
		},
	},
	storageBytes: 4,
	reserveBytes: 1,
	dataDirectoryProfile: "per-app-sqlite-v1",
	durabilityProfile: "sqlite-full-fsync-v1",
});
if (!MINIMAL_POLICY.ok) throw new Error("fixture error: minimal policy must seal");

function startCommand(): ExecutionCommand {
	// example 命令的身份/绑定（sbx-vector / a405...-1 / P=1,E=1）+ fixture policy pin。
	return { ...exampleExecutionCommand(), operation: "start", hostServicePolicyDigest: MINIMAL_POLICY.value.policyDigest };
}

function specInput(command: ExecutionCommand = startCommand(), policy: Parameters<typeof buildWasmSandboxSpec>[0]["policy"] = exampleNormalizedWasmManifestV1()) {
	return { command, policy, hostServicePolicy: MINIMAL_POLICY.value };
}
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
	test("the spec assembles pinned addresses, digest-pinned image, and the verified argv@2", () => {
		const spec = buildWasmSandboxSpec(specInput(), spawnOptions());
		expect(spec.ok).toBe(true);
		if (!spec.ok) return;
		// 同拓扑：app 挂 internal 网、gateway 拨 app 的 pinned 地址（与 celld ingressTarget 同端口）。
		expect(spec.value.listenAddress).toBe(wasmdIngressTarget(0));
		expect(spec.value.listenAddress).toBe(sandboxAppAddress(0) + ":8787");
		expect(spec.value.gatewayAddress).toBe(sandboxGatewayAddress(0) + ":8081");
		// image 权威只在 runtime binding 的 digest。
		expect(spec.value.runtimeImage).toBe("localhost/iweb-wasmd@sha256:" + "cd".repeat(32));
		// argv@2 十一元素契约；身份/绑定来自命令（ABI 1.1.0 wire 形）。
		expect(spec.value.argv.length).toBe(WASMD_ARGV_V2_ELEMENT_COUNT);
		expect(spec.value.argv[2]).toBe(WASMD_COMPONENT_MOUNT_TARGET);
		expect(spec.value.argv[5]).toBe(WASMD_CAPABILITY_RECORD_MOUNT_TARGET);
		expect(spec.value.argv[7]).toBe(Buffer.from(jcsCanonicalBytes(startCommand().runtimeBinding)).toString("utf8"));
		// 挂载：组件快照（entry layer digest 寻址）+ capability record 只读 + per-app 数据目录读写。
		expect(spec.value.mounts.length).toBe(3);
		expect(spec.value.mounts[0]?.readOnly).toBe(true);
		expect(spec.value.mounts[0]?.source).toBe(wasmComponentSnapshotPath("/var/lib/iweb-sandbox", "sha256:" + "1".repeat(64)));
		expect(spec.value.mounts[1]?.source).toBe("/var/lib/iweb-sandbox/node-capability.json");
		const dataMount = spec.value.mounts[2];
		expect(dataMount?.kind === "bind" && dataMount.readOnly).toBe(false);
		expect(dataMount?.kind === "bind" && dataMount.source).toBe(wasmApplicationDataPath("/var/lib/iweb-sandbox", "vector"));
		expect(dataMount?.kind === "bind" && dataMount.target).toBe(WASMD_DATA_MOUNT_TARGET_ROOT + "/vector");
	});

	// simplify-wasm-host-services P0 空串闭环：空串 pin + 零值策略 → argv@2 第 11 元素
	// 携带 policyDigest "" 的 context；reserve 资源门对零值策略无语义（跳过而非 0 替换）。
	test("an empty policy pin builds the argv@2 with the zero-value host-services context", () => {
		const policyless = { ...startCommand(), hostServicePolicyDigest: "" };
		const spec = buildWasmSandboxSpec({ command: policyless, policy: exampleNormalizedWasmManifestV1(), hostServicePolicy: WASM_EMPTY_HOST_SERVICE_POLICY_V2 }, spawnOptions());
		expect(spec.ok).toBe(true);
		if (!spec.ok) return;
		expect(spec.value.argv.length).toBe(WASMD_ARGV_V2_ELEMENT_COUNT);
		const context = JSON.parse(spec.value.argv[10] ?? "{}") as { hostServicePolicy: { policyDigest: string; hostServices: Record<string, null> } };
		expect(context.hostServicePolicy.policyDigest).toBe("");
		expect(context.hostServicePolicy.hostServices).toEqual({ kv: null, sql: null, logging: null });
		// 空串 pin 与非零策略字节组合 → MISMATCH（fail-closed，绝不给空串 pin 携带 sealed policy）。
		const mismatch = buildWasmSandboxSpec({ command: policyless, policy: exampleNormalizedWasmManifestV1(), hostServicePolicy: MINIMAL_POLICY.value }, spawnOptions());
		expect(mismatch.ok).toBe(false);
		if (!mismatch.ok) expect(mismatch.errors[0]?.code).toBe(WASM_HOST_POLICY_DIGEST_MISMATCH);
		// 反向：hex pin 对零值策略同样 MISMATCH。
		const zeroWithHexPin = buildWasmSandboxSpec({ ...specInput(), hostServicePolicy: WASM_EMPTY_HOST_SERVICE_POLICY_V2 }, spawnOptions());
		expect(zeroWithHexPin.ok).toBe(false);
		if (!zeroWithHexPin.ok) expect(zeroWithHexPin.errors[0]?.code).toBe(WASM_HOST_POLICY_DIGEST_MISMATCH);
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
			const spec = buildWasmSandboxSpec(specInput(startCommand(), shape as never), spawnOptions());
			expect(spec.ok).toBe(false);
			if (!spec.ok) expect(spec.errors[0]?.code).toBe(WASM_MANIFEST_EXECUTABLE_AUTHORITY);
		}
		// 非权威的未知字段仍由契约键集兜底拒绝（不落第二套语义）。
		const unknownField = { ...exampleNormalizedWasmManifestV1(), Surprise: 1 } as never;
		const spec = buildWasmSandboxSpec(specInput(startCommand(), unknownField), spawnOptions());
		expect(spec.ok).toBe(false);
		if (!spec.ok) expect(spec.errors[0]?.code).toBe("WASM_MANIFEST_INVALID");
	});

	test("floating image references, bad subnets, and bad paths fail closed", () => {
		const input = specInput();
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
		const tampered = buildWasmSandboxSpec(specInput({ ...startCommand(), secretValuesDigest: "nothex" }), spawnOptions());
		expect(tampered.ok).toBe(false);
	});
});

describe("wasm app container create argv: same sandbox law, wasm deltas only", () => {
	test("the create argv keeps the celld conventions and adds --preserve-fds with zero env", () => {
		const spec = buildWasmSandboxSpec(specInput(), spawnOptions());
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
		// 镜像是 digest-pinned 引用；尾部 command 恰好是 11 元素 argv@2。
		expect(args[args.length - WASMD_ARGV_V2_ELEMENT_COUNT - 1]).toBe("localhost/iweb-wasmd@sha256:" + "cd".repeat(32));
		expect(args.slice(args.length - WASMD_ARGV_V2_ELEMENT_COUNT)).toEqual([...spec.value.argv]);
	});
});
