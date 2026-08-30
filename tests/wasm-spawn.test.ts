// 用户原始需求（2026-08-26，add-wasm-runtime 镜像批次 supervisor 半边；2026-08-29
//   simplify-wasm-host-services 单版本化；2026-08-30 two-tier-runtime-trust 去 Podman）：
//   wasm kind 的 wasmd argv——argv@1 十元素纯解析契约保留为 wire 对照（对位
//   kernel-rs/wasmd/src/argv.rs parse_argv 的 fail-closed 语义）；命令驱动的 spawn spec
//   恒为 argv@2（11 元素），进程口径（本地路径 + 回环监听 + launcher 脚本）。
// 正交意图：未知/缺失/多余参数、DNS/通配/零端口地址、非法架构、非 canonical JSON、
//   未知身份字段各按 WASMD_ARGV_INVALID / WASMD_ARGV_WIRE_INVALID / WASM_IDENTITY_INCOMPLETE
//   分码拒绝；manifest 可执行权威拒绝（WASM_MANIFEST_EXECUTABLE_AUTHORITY）。
import { describe, expect, test } from "bun:test";
import {
	buildWasmSandboxSpec,
	buildWasmdLauncherScript,
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
	wasmdPidFilePath,
	WASM_LISTEN_INDEX_MAX,
} from "../supervisor/wasm-spawn.ts";
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
		stateDirectory: "/data/kernel/wasm-supervisor",
		wasmdBinaryPath: "/opt/iweb/wasmd/iweb-wasmd",
		gatewayAddress: "127.0.0.1:8081",
		architecture: "linux/arm64",
		capabilityRecordHostPath: "/data/kernel/wasm/node-capability.json",
		pidDirectory: "/run/iweb-sandbox/wasmd",
		listenIndex: 0,
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

describe("wasm process spawn spec: executable authority stays with the supervisor", () => {
	test("the spec assembles the loopback listen literal, local paths, and the verified argv@2", () => {
		const spec = buildWasmSandboxSpec(specInput(), spawnOptions());
		expect(spec.ok).toBe(true);
		if (!spec.ok) return;
		// 容器内回环监听：supervisor 分配的唯一地址（127/8 确定性映射）+ 出网代理字面量。
		expect(spec.value.listenIndex).toBe(0);
		expect(spec.value.listenAddress).toBe(wasmdIngressTarget(0));
		expect(spec.value.listenAddress).toBe("127.200.0.3:8787");
		expect(wasmdIngressTarget(1)).toBe("127.200.1.3:8787");
		expect(wasmdIngressTarget(WASM_LISTEN_INDEX_MAX)).toBe("127.203.255.3:8787");
		expect(spec.value.gatewayAddress).toBe("127.0.0.1:8081");
		// argv@2 十一元素契约；身份/绑定来自命令（ABI 1.1.0 wire 形）。
		expect(spec.value.argv.length).toBe(WASMD_ARGV_V2_ELEMENT_COUNT);
		// 三组路径都是子进程可直接访问的本地路径（无挂载翻译）。
		expect(spec.value.componentPath).toBe(wasmComponentSnapshotPath("/data/kernel/wasm-supervisor", "sha256:" + "1".repeat(64)));
		expect(spec.value.argv[2]).toBe(spec.value.componentPath);
		expect(spec.value.capabilityRecordPath).toBe("/data/kernel/wasm/node-capability.json");
		expect(spec.value.argv[5]).toBe(spec.value.capabilityRecordPath);
		expect(spec.value.dataDirectoryPath).toBe(wasmApplicationDataPath("/data/kernel/wasm-supervisor", "vector"));
		expect(spec.value.pidFilePath).toBe(wasmdPidFilePath("/run/iweb-sandbox/wasmd", "sbx-vector"));
		expect(spec.value.argv[7]).toBe(Buffer.from(jcsCanonicalBytes(startCommand().runtimeBinding)).toString("utf8"));
		// 无 OCI 维度：spec 不携带镜像引用/挂载/cgroup 资源参数。
		expect("runtimeImage" in spec.value).toBe(false);
		expect("mounts" in spec.value).toBe(false);
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

	test("bad listen indexes and bad paths fail closed", () => {
		const input = specInput();
		const overflow = buildWasmSandboxSpec(input, { ...spawnOptions(), listenIndex: WASM_LISTEN_INDEX_MAX + 1 });
		expect(overflow.ok).toBe(false);
		if (!overflow.ok) expect(overflow.errors[0]?.code).toBe(WASM_SPAWN_INVALID);
		const negative = buildWasmSandboxSpec(input, { ...spawnOptions(), listenIndex: -1 });
		expect(negative.ok).toBe(false);
		if (!negative.ok) expect(negative.errors[0]?.code).toBe(WASM_SPAWN_INVALID);
		const relative = buildWasmSandboxSpec(input, { ...spawnOptions(), capabilityRecordHostPath: "node-capability.json" });
		expect(relative.ok).toBe(false);
		const relativeBin = buildWasmSandboxSpec(input, { ...spawnOptions(), wasmdBinaryPath: "iweb-wasmd" });
		expect(relativeBin.ok).toBe(false);
		// 命令本身未过契约（secretValuesDigest 非法）→ 拒绝。
		const tampered = buildWasmSandboxSpec(specInput({ ...startCommand(), secretValuesDigest: "nothex" }), spawnOptions());
		expect(tampered.ok).toBe(false);
	});
});

describe("wasmd launcher script: FD-injected exec payload (process-era)", () => {
	test("the launcher execs the pinned binary with argv@2 and writes the pidfile", () => {
		const spec = buildWasmSandboxSpec(specInput(), spawnOptions());
		expect(spec.ok).toBe(true);
		if (!spec.ok) return;
		const script = buildWasmdLauncherScript(spec.value);
		// 三段结构：建 pid 目录 → 后台启动 wasmd → 写 pidfile。
		const lines = script.split("\n").filter((line) => line.length > 0);
		expect(lines.length).toBe(3);
		expect(lines[0]).toContain("mkdir -p '/run/iweb-sandbox/wasmd'");
		// `wasmd &` 是简单命令后台化（$! 即 wasmd 本体 pid）：argv 元素逐字单引号引用，
		// 首个 token 是二进制路径，其后是 argv[1..10]（标记在位）。
		const launch = lines[1] ?? "";
		expect(launch.endsWith(" &")).toBe(true);
		expect(launch.startsWith("'/opt/iweb/wasmd/iweb-wasmd'")).toBe(true);
		expect(launch).toContain("'--iweb-wasmd-argv@2'");
		// JCS JSON 元素含空格/引号：必须以字面量进入脚本（单引号转义，不被 shell 再解释）。
		expect(launch).toContain("'" + spec.value.argv[7] + "'");
		expect(launch).toContain("'" + spec.value.argv[10] + "'");
		expect(lines[2]).toBe("echo $! > '/run/iweb-sandbox/wasmd/sbx-vector.pid'");
		// 零环境权威：launcher 不注入任何变量赋值或 export。
		expect(script.includes("export ") || /^[A-Z_]+=/m.test(script)).toBe(false);
		// 单引号转义正确性：JCS JSON 内的双引号不需要转义；恶意单引号会被安全转义。
		expect(buildWasmdLauncherScript({ ...spec.value, wasmdBinaryPath: "/opt/iweb/wasmd/iweb w'asmd" }).includes("'\\''")).toBe(true);
	});
});
