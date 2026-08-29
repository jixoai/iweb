// 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1 supervisor 半边）：wasm kind 复用
//   同一沙箱法——同一双网络拓扑（app 仅挂 internal 网）、同一 cgroup 资源界、同一只读
//   根/seccomp/no-new-privileges/cap-drop/cgroup 挂载惯例，仅 runtime image（catalog
//   digest-pinned wasmd）与容器 argv 不同；supervisor 独占生成 wasmd 的每一个 argv
//   元素（10 元素契约，逐字节对位 kernel-rs/wasmd/src/argv.rs 的 parse_argv）。
// 正交意图：
//   1. argv v1 精确形状（含 argv[0] 恰好 10 元素；无选项语法、无可选参数）：标记
//      `--iweb-wasmd-argv@1`、组件快照路径、listen/gateway ip:port 字面量、capability
//      record 路径、节点架构、binding/identity/resources 三个 JCS JSON——未知/缺失/多余
//      参数一律 fail-closed（WASMD_ARGV_INVALID / WASMD_ARGV_WIRE_INVALID，与 wasmd 同名）。
//   2. manifest 携带任意 image/command/mount/capability/socket/TLS/environment 可执行
//      权威 → WASM_MANIFEST_EXECUTABLE_AUTHORITY（spec "Wasmd has a fixed command and
//      host-mediated network contract" 已命名）；其余 manifest 校验复用
//      validateNormalizedWasmManifestV1 精确键集，不造第二套。
//   3. Podman argv 沿用 sandbox-spec.ts 的组装惯例（buildAppContainerCreateArgs 的标签/
//      只读/降权/网络/资源段），wasm 增量为 --preserve-fds=2（spec：FD 3 secret / FD 4
//      config 经 SCM_RIGHTS 唯一进入路径）与零 --env（无环境权威：记录值不得被环境变量
//      替代）。
// TODO(5.x Linux 实机 spawn)：本文件只生成并校验 argv/spec，不启动任何容器。真实
//   rootless Podman spawn（--preserve-fds 的 FD 3/4 CLOEXEC 清理、组件快照与 capability
//   record 的落地字节 digest 复验、网关 ingressTarget 接线、双容器 readiness 实测）归
//   5.x 镜像批次，规范条目：spec "Snapshot FD content is bound across Kernel, supervisor,
//   Podman, and wasmd"（三进程 FD 契约与 wasmd.readDigest 复验）、"Wasmd has a fixed
//   command and host-mediated network contract"（"A real dual-container readiness test is
//   required before an image/catalog entry is acceptance-gated"）。届时在 wasm-executor 的
//   start/prepare 副作用段消费本模块产物，fence 语义不变。
// 轮次注记（2026-08-28，add-wasm-host-services P0-3 supervisor 半边）：argv v2（11 元素，
//   对位 argv.rs @2 分支）——V2 binding（hostABI 1.1.0）生成 argv@2，第 11 元素为
//   host-services context JCS（{schemaVersion:2, applicationId, fenceNonce,
//   hostServicePolicy}，policy.rs WasmdHostServicesContextV2 对位），标记与 ABI 严格耦合
//   （@1 恒 1.0.0）；资源门 1 <= reserveBytes < memoryBytes 复用 contracts
//   checkWasmGuestMemoryReserve 谓词、wasmd 同名码 WASM_RESOURCE_RECORD_INVALID。本文件
//   P0-3（V2 wire 正式化）→ simplify-wasm-host-services（2026-08-29）：ExecutionCommand
//   已在 contracts 单版本化（原 V2 形态即唯一形态）；本文件的 supervisor 输入 seam 直接
//   消费 contracts 导入（校验/摘要唯一权威）。命令驱动的 argv@1 构建与 V1 spawn spec
//   组装已删除（无 V1 命令形态）；argv@1 纯解析器（verifyWasmdArgvV1）保留为 wire 对照。
import { isIP } from "node:net";
import {
	appContainerName,
	IWEB_MANAGED_LABEL,
	isDigestPinnedImage,
	SANDBOX_SUBNET_MAX,
	sandboxAppAddress,
	sandboxGatewayAddress,
	sandboxNetworkName,
	SCRATCH_MOUNT_TARGET,
	SECCOMP_PROFILE_HOST_PATH,
	type SandboxMountSpec,
} from "./sandbox-spec.ts";
import { failure, isRecord, issue, ok, type ValidationIssue, type ValidationResult } from "../packages/contracts/validation.ts";
import {
	jcsCanonicalBytes,
	parseStrictJson,
	validateNormalizedWasmManifestV1,
	WASM_APPLICATION_ID_PATTERN,
	WASM_OCI_SHA256_PATTERN,
	WASM_SHA256_HEX_PATTERN,
	WASM_U53_MAX,
	WASM_VERSION_ID_PATTERN,
	WASM_WORLD_LITERAL,
	type NormalizedWasmManifestV1,
	type WasmResourcesV1,
} from "../packages/contracts/wasm-package.ts";
import {
	computeExecutionCommandDigest,
	validateExecutionCommand,
	validateRuntimeBindingIdentityV1,
	validateRuntimeBindingIdentityV2,
	WASM_FENCE_NONCE_PATTERN,
	WASM_SANDBOX_ID_PATTERN,
	type ExecutionCommand,
	type RuntimeBindingIdentityV1,
	type RuntimeBindingIdentityV2,
} from "../packages/contracts/wasm-execution.ts";
import {
	checkWasmGuestMemoryReserve,
	isWasmHostServicePolicyV2Empty,
	validateWasmHostServicePolicyV2,
	type WasmHostServicePolicyV2,
} from "../packages/contracts/wasm-host-policy.ts";

// ---------------------------------------------------------------------------
// 稳定码与固定常量（与 kernel-rs/wasmd/src/argv.rs、wire.rs 的同名常量逐字对齐）
// ---------------------------------------------------------------------------

export const WASMD_ARGV_PROGRAM = "iweb-wasmd";
export const WASMD_ARGV_MARKER = "--iweb-wasmd-argv@1";
export const WASMD_ARGV_ELEMENT_COUNT = 10;
export const WASMD_ARGV_INVALID = "WASMD_ARGV_INVALID";
export const WASMD_ARGV_WIRE_INVALID = "WASMD_ARGV_WIRE_INVALID";
export const WASM_IDENTITY_INCOMPLETE = "WASM_IDENTITY_INCOMPLETE";
// spec 已命名：manifest 携带可执行权威的拒绝码。
export const WASM_MANIFEST_EXECUTABLE_AUTHORITY = "WASM_MANIFEST_EXECUTABLE_AUTHORITY";
// 宿主侧（spawn spec 组装层）补充码；spec 未命名，沿用 wasm 系命名风格。
export const WASM_SPAWN_INVALID = "WASM_SPAWN_INVALID";

// ---------------------------------------------------------------------------
// add-wasm-host-services argv v2（argv.rs ARGV_MARKER_V2/ARGV_V2_ELEMENT_COUNT 对位）：
// service-enabled 执行追加第 11 个元素 host-services context（JCS），标记与 ABI 严格耦合
//（@2 ⇔ binding.hostABI 1.1.0；@1 恒 1.0.0）。simplify-wasm-host-services 后无 service
// 的执行同为 argv@2：第 11 元素携带零值策略（policyDigest ""，全 null 服务）——V2 绝不
// 解释为 V1，反之亦然（wire.rs validate_with_host_abi 参数化的 TS 对位）。
// ---------------------------------------------------------------------------

export const WASMD_ARGV_MARKER_V2 = "--iweb-wasmd-argv@2";
export const WASMD_ARGV_V2_ELEMENT_COUNT = 11;
/** spec 已命名（Reserve is missing or consumes the total memory limit 场景；wasmd policy.rs cross_check 同名同语义）。 */
export const WASM_RESOURCE_RECORD_INVALID = "WASM_RESOURCE_RECORD_INVALID";
/** 命令 policy pin 与 resolved policy 字节不符（contracts validateWasmHostServicePolicyV2 同名同语义；契约未导出常量，此处镜像）。 */
export const WASM_HOST_POLICY_DIGEST_MISMATCH = "WASM_HOST_POLICY_DIGEST_MISMATCH";

export type WasmRuntimeArchitecture = "linux/amd64" | "linux/arm64";
export const WASMD_ARCHITECTURES: readonly WasmRuntimeArchitecture[] = ["linux/amd64", "linux/arm64"];

// wasmd 在沙箱内的组件快照挂载目标（argv[2] 的容器内路径；宿主源由 supervisor 物化）。
export const WASMD_COMPONENT_MOUNT_TARGET = "/opt/iweb/wasm/component.wasm";
// pinned NodeCapabilityRecordV1 的容器内路径（argv[5]；宿主上限唯一来源，只读挂载）。
export const WASMD_CAPABILITY_RECORD_MOUNT_TARGET = "/etc/iweb-wasmd/node-capability.json";
// V2（service-enabled）per-app 数据目录根（design §3 逐字：容器内
// /data/kernel/wasm-data/<applicationId>/，wasmd host_services HOST_SERVICES_DATA_ROOT
// 对位）。宿主源由 supervisor 状态目录派生；挂载为读写——kv/sql/quota 三个 SQLite
// 后端都要在目录内创建与提交（sqlite-full-fsync-v1 profile），只读挂载会让 provider
// open 即 fail-closed。
export const WASMD_DATA_MOUNT_TARGET_ROOT = "/data/kernel/wasm-data";

/** 宿主侧 per-app 数据目录（<stateDirectory>/wasm-data/<applicationId>；supervisor 物化，wasmd 以 0700/0600 加固）。 */
export function wasmApplicationDataPath(stateDirectory: string, applicationId: string): string {
	return stateDirectory + "/wasm-data/" + applicationId;
}
// gateway ingress 拨打沙箱内 wasmd 的端口：与 celld 沙箱的 ingressTarget 端口一致
//（adapter.ts 以 sandboxAppAddress(subnetIndex)+":8787" 为目标），同一拓扑不同 runtime。
export const WASMD_LISTEN_PORT = 8787;
// wasmd 唯一允许拨出的网关端口：gateway 的 egress 代理（sandbox-spec GATEWAY_EGRESS_LISTEN
// 的 8081；HTTP 与 HTTPS CONNECT 均经它，出网只拨固定网关 ip）。
export const WASMD_GATEWAY_EGRESS_PORT = 8081;

// ---------------------------------------------------------------------------
// WasmdIdentityV1：argv[8] 携带的身份 tuple（对位 wasmd/src/wire.rs；= health v2 的
// 13 个身份字段，含 capability pin、secret/config 快照 digest 与 P/E 双代次）。
// ---------------------------------------------------------------------------

export interface WasmdIdentityV1 {
	readonly sandboxId: string;
	readonly versionId: string;
	readonly packageDigest: string;
	readonly runtimeBinding: RuntimeBindingIdentityV1;
	readonly capabilityRecordRevision: number;
	readonly capabilityRecordHash: string;
	readonly secretRevision: number;
	readonly secretValuesDigest: string;
	readonly configRevision: number;
	readonly configSnapshotRef: string | null;
	readonly configValuesDigest: string | null;
	readonly preparationGeneration: number;
	readonly executionGeneration: number;
}

const WASMD_IDENTITY_KEYS: readonly string[] = [
	"sandboxId",
	"versionId",
	"packageDigest",
	"runtimeBinding",
	"capabilityRecordRevision",
	"capabilityRecordHash",
	"secretRevision",
	"secretValuesDigest",
	"configRevision",
	"configSnapshotRef",
	"configValuesDigest",
	"preparationGeneration",
	"executionGeneration",
];

function requireHex(value: unknown, path: string, fieldName: string, code: string, errors: ValidationIssue[]): string | null {
	if (typeof value !== "string" || !WASM_SHA256_HEX_PATTERN.test(value)) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be a 64-character lower-case hex digest"));
		return null;
	}
	return value;
}

function requireU53(value: unknown, path: string, fieldName: string, minimum: number, code: string, errors: ValidationIssue[]): number | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > WASM_U53_MAX) {
		errors.push(issue(code, path + "/" + fieldName, fieldName + " must be an integer between " + minimum + " and " + WASM_U53_MAX));
		return null;
	}
	return value;
}

// configRevision:0 ⇔ configSnapshotRef:null ⇔ configValuesDigest:null（wire.rs
// check_config_snapshot_coupling 对位；contracts 侧同款法则是模块私有，此处按镜像复述）。
// V1/V2 身份共用（只读三个 config 字段；WasmdIdentityV2 结构性满足同一约束）。
function checkIdentityConfigCoupling(identity: Readonly<Pick<WasmdIdentityV1, "configRevision" | "configSnapshotRef" | "configValuesDigest">>, path: string, errors: ValidationIssue[]): void {
	if (identity.configRevision === 0 && (identity.configSnapshotRef !== null || identity.configValuesDigest !== null)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/configSnapshotRef", "configRevision 0 requires both configSnapshotRef and configValuesDigest null"));
	}
	if (identity.configRevision > 0 && (identity.configSnapshotRef === null || identity.configValuesDigest === null)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/configSnapshotRef", "a non-zero configRevision requires both configSnapshotRef and configValuesDigest"));
	}
	if ((identity.configSnapshotRef === null) !== (identity.configValuesDigest === null)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/configValuesDigest", "configValuesDigest is null exactly when configSnapshotRef is null"));
	}
}

function requireWasmdIdentityV1(input: unknown, path: string, errors: ValidationIssue[]): WasmdIdentityV1 | null {
	if (!isRecord(input)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path, "identity-json must be an object"));
		return null;
	}
	for (const key of Object.keys(input)) {
		if (!WASMD_IDENTITY_KEYS.includes(key)) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/" + key, "unknown field is not allowed"));
	}
	for (const key of WASMD_IDENTITY_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/" + key, "required field is missing"));
	}
	if (typeof input.sandboxId !== "string" || !WASM_SANDBOX_ID_PATTERN.test(input.sandboxId)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/sandboxId", "sandboxId must be a lower-case sandbox identifier starting with a letter"));
	}
	if (typeof input.versionId !== "string" || !WASM_VERSION_ID_PATTERN.test(input.versionId)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/versionId", "versionId must be <64 lower-case hex>-<positive sequence without leading zero>"));
	}
	const packageDigest = requireHex(input.packageDigest, path, "packageDigest", WASMD_ARGV_WIRE_INVALID, errors);
	const capabilityRecordHash = requireHex(input.capabilityRecordHash, path, "capabilityRecordHash", WASMD_ARGV_WIRE_INVALID, errors);
	const secretValuesDigest = requireHex(input.secretValuesDigest, path, "secretValuesDigest", WASMD_ARGV_WIRE_INVALID, errors);
	const capabilityRecordRevision = requireU53(input.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASMD_ARGV_WIRE_INVALID, errors);
	const secretRevision = requireU53(input.secretRevision, path, "secretRevision", 0, WASMD_ARGV_WIRE_INVALID, errors);
	const configRevision = requireU53(input.configRevision, path, "configRevision", 0, WASMD_ARGV_WIRE_INVALID, errors);
	// 存活 execution 的双代次必须 >= 1（wire.rs：generation 下界以 WASM_IDENTITY_INCOMPLETE 报错）。
	const preparationGeneration = requireU53(input.preparationGeneration, path, "preparationGeneration", 1, WASM_IDENTITY_INCOMPLETE, errors);
	const executionGeneration = requireU53(input.executionGeneration, path, "executionGeneration", 1, WASM_IDENTITY_INCOMPLETE, errors);
	const binding = validateRuntimeBindingIdentityV1(input.runtimeBinding);
	if (!binding.ok) {
		for (const error of binding.errors) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/runtimeBinding", "runtime binding is invalid: " + error.message));
	}
	let configSnapshotRef: string | null = null;
	let configValuesDigest: string | null = null;
	if (input.configSnapshotRef !== null && input.configSnapshotRef !== undefined) {
		const ref = requireHex(input.configSnapshotRef, path, "configSnapshotRef", WASMD_ARGV_WIRE_INVALID, errors);
		if (ref !== null) configSnapshotRef = ref;
	} else if (input.configSnapshotRef === undefined) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/configSnapshotRef", "required field is missing"));
	}
	if (input.configValuesDigest !== null && input.configValuesDigest !== undefined) {
		const digest = requireHex(input.configValuesDigest, path, "configValuesDigest", WASMD_ARGV_WIRE_INVALID, errors);
		if (digest !== null) configValuesDigest = digest;
	} else if (input.configValuesDigest === undefined) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/configValuesDigest", "required field is missing"));
	}
	if (
		typeof input.sandboxId !== "string" ||
		typeof input.versionId !== "string" ||
		packageDigest === null ||
		capabilityRecordHash === null ||
		secretValuesDigest === null ||
		capabilityRecordRevision === null ||
		secretRevision === null ||
		configRevision === null ||
		preparationGeneration === null ||
		executionGeneration === null ||
		!binding.ok ||
		errors.length
	) {
		return null;
	}
	const identity: WasmdIdentityV1 = {
		sandboxId: input.sandboxId,
		versionId: input.versionId,
		packageDigest,
		runtimeBinding: binding.value,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
		preparationGeneration,
		executionGeneration,
	};
	checkIdentityConfigCoupling(identity, path, errors);
	if (errors.length) return null;
	return identity;
}

export function validateWasmdIdentityV1(input: unknown): ValidationResult<WasmdIdentityV1> {
	const errors: ValidationIssue[] = [];
	const value = requireWasmdIdentityV1(input, "", errors);
	if (value === null || errors.length) return failure(errors);
	return ok(value);
}

// ---------------------------------------------------------------------------
// argv v1：构建 + 校验（校验器是 argv.rs parse_argv 的 TS 对位；构建产物必须先过
// 校验器才允许返回——builder 与 parser 不允许漂移）
// ---------------------------------------------------------------------------

export interface WasmdInvocationV1 {
	readonly componentPath: string;
	readonly listen: string;
	readonly gateway: string;
	readonly capabilityRecordPath: string;
	readonly architecture: WasmRuntimeArchitecture;
	readonly binding: RuntimeBindingIdentityV1;
	readonly identity: WasmdIdentityV1;
	readonly resources: WasmResourcesV1;
}

function requireAbsolutePath(value: string, fieldName: string, errors: ValidationIssue[]): boolean {
	if (value.length === 0 || !value.startsWith("/")) {
		errors.push(issue(WASMD_ARGV_INVALID, "/" + fieldName, fieldName + " must be a non-empty absolute path"));
		return false;
	}
	return true;
}

// ip:port 字面量：拒绝 DNS 名、端口 0、通配/未指定地址（argv.rs parse_socket_address
// 对位——出网只拨固定网关 ip，不引入解析器）。
function requireSocketAddressLiteral(value: string, fieldName: string, errors: ValidationIssue[]): boolean {
	const separator = value.lastIndexOf(":");
	if (separator <= 0) {
		errors.push(issue(WASMD_ARGV_INVALID, "/" + fieldName, fieldName + " must be an ip:port literal (DNS names are not accepted)"));
		return false;
	}
	const host = value.slice(0, separator);
	const portText = value.slice(separator + 1);
	const port = /^[0-9]{1,5}$/.test(portText) ? Number(portText) : Number.NaN;
	if (isIP(host) === 0 || !Number.isSafeInteger(port)) {
		errors.push(issue(WASMD_ARGV_INVALID, "/" + fieldName, fieldName + " must be an ip:port literal (DNS names are not accepted)"));
		return false;
	}
	if (port === 0) {
		errors.push(issue(WASMD_ARGV_INVALID, "/" + fieldName, fieldName + " port must be non-zero"));
		return false;
	}
	if (port > 65535) {
		errors.push(issue(WASMD_ARGV_INVALID, "/" + fieldName, fieldName + " port must be within 1..65535"));
		return false;
	}
	if (host === "0.0.0.0" || host === "::") {
		errors.push(issue(WASMD_ARGV_INVALID, "/" + fieldName, fieldName + " must not use an unspecified/wildcard address"));
		return false;
	}
	return true;
}

// JCS 字节权威：原始字符串必须等于 JCS(strict-parse(value))——重复键、白空格、键序
// 偏差一律拒绝（parseStrictJson 在覆盖前检测重复成员名）。
function requireCanonicalJsonArg(value: string, fieldName: string, errors: ValidationIssue[]): unknown | null {
	const parsed = parseStrictJson(value);
	if (!parsed.ok) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName, fieldName + " must be canonical JCS JSON: " + parsed.error));
		return null;
	}
	if (Buffer.from(jcsCanonicalBytes(parsed.value)).toString("utf8") !== value) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName, fieldName + " bytes must equal JCS(parsed value); non-canonical JSON is rejected"));
		return null;
	}
	return parsed.value;
}

function requireResourcesArg(value: unknown, fieldName: string, errors: ValidationIssue[]): WasmResourcesV1 | null {
	if (!isRecord(value)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName, fieldName + " must be an object"));
		return null;
	}
	for (const key of Object.keys(value)) {
		if (key !== "cpuMillis" && key !== "memoryBytes" && key !== "pidLimit" && key !== "storageBytes") {
			errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName + "/" + key, "unknown field is not allowed"));
		}
	}
	for (const key of ["cpuMillis", "memoryBytes", "pidLimit", "storageBytes"] as const) {
		if (!Object.prototype.hasOwnProperty.call(value, key)) errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName + "/" + key, "required field is missing"));
	}
	const cpuMillis = requireU53(value.cpuMillis, "/" + fieldName, "cpuMillis", 1, WASMD_ARGV_WIRE_INVALID, errors);
	const memoryBytes = requireU53(value.memoryBytes, "/" + fieldName, "memoryBytes", 1, WASMD_ARGV_WIRE_INVALID, errors);
	const pidLimit = requireU53(value.pidLimit, "/" + fieldName, "pidLimit", 1, WASMD_ARGV_WIRE_INVALID, errors);
	const storageBytes = requireU53(value.storageBytes, "/" + fieldName, "storageBytes", 0, WASMD_ARGV_WIRE_INVALID, errors);
	if (cpuMillis === null || cpuMillis > 1000000) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName + "/cpuMillis", "cpuMillis must be an integer between 1 and 1000000"));
	}
	if (memoryBytes === null || memoryBytes > 68719476736) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName + "/memoryBytes", "memoryBytes must be an integer between 1 and 68719476736"));
	}
	if (pidLimit === null || pidLimit > 1000000) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName + "/pidLimit", "pidLimit must be an integer between 1 and 1000000"));
	}
	if (storageBytes === null || storageBytes > 1099511627776) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/" + fieldName + "/storageBytes", "storageBytes must be an integer between 0 and 1099511627776"));
	}
	if (errors.length || cpuMillis === null || memoryBytes === null || pidLimit === null || storageBytes === null) return null;
	return { cpuMillis, memoryBytes, pidLimit, storageBytes };
}

// argv.rs parse_argv 的 TS 对位：任何偏差 fail-closed（@1 十元素形状的纯解析器；
// 命令驱动的 @1 构建已随 ExecutionCommandV1 删除——执行命令单一形态恒 argv@2）。
export function verifyWasmdArgvV1(argv: readonly string[]): ValidationResult<WasmdInvocationV1> {
	const errors: ValidationIssue[] = [];
	if (argv.length !== WASMD_ARGV_ELEMENT_COUNT) {
		return failure([issue(WASMD_ARGV_INVALID, "", "argv must have exactly " + WASMD_ARGV_ELEMENT_COUNT + " elements including argv[0]; refusing len " + argv.length)]);
	}
	if (argv[1] !== WASMD_ARGV_MARKER) {
		return failure([issue(WASMD_ARGV_INVALID, "/1", "argv[1] must be the exact marker " + WASMD_ARGV_MARKER + "; refusing " + argv[1])]);
	}
	const componentPath = argv[2] ?? "";
	const capabilityRecordPath = argv[5] ?? "";
	const listen = argv[3] ?? "";
	const gateway = argv[4] ?? "";
	requireAbsolutePath(componentPath, "component path", errors);
	requireSocketAddressLiteral(listen, "listen address", errors);
	requireSocketAddressLiteral(gateway, "gateway address", errors);
	requireAbsolutePath(capabilityRecordPath, "capability record path", errors);
	const architecture = argv[6] ?? "";
	if (!WASMD_ARCHITECTURES.includes(architecture as WasmRuntimeArchitecture)) {
		errors.push(issue(WASMD_ARGV_INVALID, "/6", "architecture must be one of linux/amd64, linux/arm64"));
	}
	const bindingValue = requireCanonicalJsonArg(argv[7] ?? "", "binding-json", errors);
	const identityValue = requireCanonicalJsonArg(argv[8] ?? "", "identity-json", errors);
	const resourcesValue = requireCanonicalJsonArg(argv[9] ?? "", "resources-json", errors);
	let binding: RuntimeBindingIdentityV1 | null = null;
	if (bindingValue !== null) {
		const validated = validateRuntimeBindingIdentityV1(bindingValue);
		if (validated.ok) binding = validated.value;
		else for (const error of validated.errors) errors.push(issue(WASMD_ARGV_WIRE_INVALID, "/binding-json", "runtime binding is invalid: " + error.message));
	}
	const identity = identityValue === null ? null : requireWasmdIdentityV1(identityValue, "/identity-json", errors);
	const resources = resourcesValue === null ? null : requireResourcesArg(resourcesValue, "resources-json", errors);
	if (errors.length || binding === null || identity === null || resources === null) return failure(errors);
	return ok({
		componentPath,
		listen,
		gateway,
		capabilityRecordPath,
		architecture: architecture as WasmRuntimeArchitecture,
		binding,
		identity,
		resources,
	});
}

// ---------------------------------------------------------------------------
// add-wasm-host-services：execution 输入（argv@2，11 元素；单一命令形态）。
// simplify-wasm-host-services：ExecutionCommand 已在 contracts 单版本化
//（packages/contracts/wasm-execution.ts）；字段映射：runtimeBinding（ABI 1.1.0，
// argv[7] 权威）、applicationId/hostServicePolicyDigest（HostServiceIdentityV2 的
// supervisor 消费字段）、fenceNonce（ExecutionFenceV2）。无 V1 命令、无版本分派。
// ---------------------------------------------------------------------------

/** runtime binding：七字段，hostABI 钉 iweb-wasmd-abi@1.1.0（@2 标记耦合）。 */
export type { RuntimeBindingIdentityV2 };

/** 兼容再出口：ExecutionFenceV2.fenceNonce 文法（contracts WASM_FENCE_NONCE_PATTERN）。 */
export const WASMD_FENCE_NONCE_PATTERN = WASM_FENCE_NONCE_PATTERN;

/** executor/spawn 接受的执行命令（contracts ExecutionCommand 单一形态）。 */
export type SupervisorExecutionCommand = ExecutionCommand;

/**
 * 幂等摘要键：digestV2("iweb-wasm-execution-command-v2", JCS(command))（design 域表）。
 * 公式权威在 contracts（computeExecutionCommandDigest），此处零漂移转发。
 */
export function computeSupervisorExecutionCommandDigest(command: SupervisorExecutionCommand): string {
	return computeExecutionCommandDigest(command);
}

// V2 binding 校验（wire.rs validate_with_host_abi(expected_abi) 的 TS 对位）：
// 权威在 contracts validateRuntimeBindingIdentityV2；argv/identity 校验层以
// WASMD_ARGV_WIRE_INVALID 包装（与 V1 路径包装 validateRuntimeBindingIdentityV1 同款）。
function requireRuntimeBindingIdentityV2Arg(input: unknown, path: string, errors: ValidationIssue[]): RuntimeBindingIdentityV2 | null {
	const validated = validateRuntimeBindingIdentityV2(input);
	if (validated.ok) return validated.value;
	for (const error of validated.errors) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path, "runtime binding is invalid: " + error.message));
	return null;
}


// ---------------------------------------------------------------------------
// WasmdIdentityV2 与 argv@2 的 host-services context（policy.rs WasmdHostServicesContextV2 对位）
// ---------------------------------------------------------------------------

export interface WasmdIdentityV2 extends Omit<WasmdIdentityV1, "runtimeBinding"> {
	readonly runtimeBinding: RuntimeBindingIdentityV2;
}

function requireWasmdIdentityV2(input: unknown, path: string, errors: ValidationIssue[]): WasmdIdentityV2 | null {
	if (!isRecord(input)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path, "identity-json must be an object"));
		return null;
	}
	for (const key of Object.keys(input)) {
		if (!WASMD_IDENTITY_KEYS.includes(key)) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/" + key, "unknown field is not allowed"));
	}
	for (const key of WASMD_IDENTITY_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/" + key, "required field is missing"));
	}
	if (typeof input.sandboxId !== "string" || !WASM_SANDBOX_ID_PATTERN.test(input.sandboxId)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/sandboxId", "sandboxId must be a lower-case sandbox identifier starting with a letter"));
	}
	if (typeof input.versionId !== "string" || !WASM_VERSION_ID_PATTERN.test(input.versionId)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/versionId", "versionId must be <64 lower-case hex>-<positive sequence without leading zero>"));
	}
	const packageDigest = requireHex(input.packageDigest, path, "packageDigest", WASMD_ARGV_WIRE_INVALID, errors);
	const capabilityRecordHash = requireHex(input.capabilityRecordHash, path, "capabilityRecordHash", WASMD_ARGV_WIRE_INVALID, errors);
	const secretValuesDigest = requireHex(input.secretValuesDigest, path, "secretValuesDigest", WASMD_ARGV_WIRE_INVALID, errors);
	const capabilityRecordRevision = requireU53(input.capabilityRecordRevision, path, "capabilityRecordRevision", 1, WASMD_ARGV_WIRE_INVALID, errors);
	const secretRevision = requireU53(input.secretRevision, path, "secretRevision", 0, WASMD_ARGV_WIRE_INVALID, errors);
	const configRevision = requireU53(input.configRevision, path, "configRevision", 0, WASMD_ARGV_WIRE_INVALID, errors);
	const preparationGeneration = requireU53(input.preparationGeneration, path, "preparationGeneration", 1, WASM_IDENTITY_INCOMPLETE, errors);
	const executionGeneration = requireU53(input.executionGeneration, path, "executionGeneration", 1, WASM_IDENTITY_INCOMPLETE, errors);
	const binding = requireRuntimeBindingIdentityV2Arg(input.runtimeBinding, path + "/runtimeBinding", errors);
	let configSnapshotRef: string | null = null;
	let configValuesDigest: string | null = null;
	if (input.configSnapshotRef !== null && input.configSnapshotRef !== undefined) {
		const ref = requireHex(input.configSnapshotRef, path, "configSnapshotRef", WASMD_ARGV_WIRE_INVALID, errors);
		if (ref !== null) configSnapshotRef = ref;
	} else if (input.configSnapshotRef === undefined) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/configSnapshotRef", "required field is missing"));
	}
	if (input.configValuesDigest !== null && input.configValuesDigest !== undefined) {
		const digest = requireHex(input.configValuesDigest, path, "configValuesDigest", WASMD_ARGV_WIRE_INVALID, errors);
		if (digest !== null) configValuesDigest = digest;
	} else if (input.configValuesDigest === undefined) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/configValuesDigest", "required field is missing"));
	}
	if (
		typeof input.sandboxId !== "string" ||
		typeof input.versionId !== "string" ||
		packageDigest === null ||
		capabilityRecordHash === null ||
		secretValuesDigest === null ||
		capabilityRecordRevision === null ||
		secretRevision === null ||
		configRevision === null ||
		preparationGeneration === null ||
		executionGeneration === null ||
		binding === null ||
		errors.length
	) {
		return null;
	}
	const identity: WasmdIdentityV2 = {
		sandboxId: input.sandboxId,
		versionId: input.versionId,
		packageDigest,
		runtimeBinding: binding,
		capabilityRecordRevision,
		capabilityRecordHash,
		secretRevision,
		secretValuesDigest,
		configRevision,
		configSnapshotRef,
		configValuesDigest,
		preparationGeneration,
		executionGeneration,
	};
	checkIdentityConfigCoupling(identity, path, errors);
	if (errors.length) return null;
	return identity;
}

/** argv@2 追加元素：宿主注入的执行身份（applicationId/fenceNonce）+ 完整 sealed 策略。 */
export interface WasmdHostServicesContextV2 {
	readonly schemaVersion: 2;
	readonly applicationId: string;
	readonly fenceNonce: string;
	readonly hostServicePolicy: WasmHostServicePolicyV2;
}

const HOST_SERVICES_CONTEXT_KEYS: readonly string[] = ["schemaVersion", "applicationId", "fenceNonce", "hostServicePolicy"];

function requireHostServicesContextV2(input: unknown, path: string, errors: ValidationIssue[]): WasmdHostServicesContextV2 | null {
	if (!isRecord(input)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path, "host-services context must be an object"));
		return null;
	}
	for (const key of Object.keys(input)) {
		if (!HOST_SERVICES_CONTEXT_KEYS.includes(key)) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/" + key, "unknown field is not allowed"));
	}
	for (const key of HOST_SERVICES_CONTEXT_KEYS) {
		if (!Object.prototype.hasOwnProperty.call(input, key)) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/" + key, "required field is missing"));
	}
	if (input.schemaVersion !== 2) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/schemaVersion", "host-services context schemaVersion must be the literal 2"));
	}
	if (typeof input.applicationId !== "string" || !WASM_APPLICATION_ID_PATTERN.test(input.applicationId)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/applicationId", "applicationId must be a lower-case application identifier of at most 63 ASCII bytes"));
	}
	if (typeof input.fenceNonce !== "string" || !WASMD_FENCE_NONCE_PATTERN.test(input.fenceNonce)) {
		errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/fenceNonce", "fenceNonce must be 32 lower-case hex characters (16 host-issued bytes)"));
	}
	const policy = validateWasmHostServicePolicyV2(input.hostServicePolicy);
	if (!policy.ok) {
		for (const error of policy.errors) errors.push(issue(WASMD_ARGV_WIRE_INVALID, path + "/hostServicePolicy", "host service policy is invalid: " + error.message));
	}
	if (input.schemaVersion !== 2 || typeof input.applicationId !== "string" || typeof input.fenceNonce !== "string" || !policy.ok || errors.length) {
		return null;
	}
	return { schemaVersion: 2, applicationId: input.applicationId, fenceNonce: input.fenceNonce, hostServicePolicy: policy.value };
}

/**
 * design §3 资源门（policy.rs cross_check 对位）：1 <= reserveBytes <
 * resources.memoryBytes——缺失/零替换/越界一律 WASM_RESOURCE_RECORD_INVALID，
 * 绝不代默认值。谓词本身复用 contracts checkWasmGuestMemoryReserve（单一权威）。
 * 零值策略（simplify-wasm-host-services 空串 policyDigest）无 reserve 语义：三服务全
 * null、reserveBytes 0，资源门只对携带服务成员的策略生效（0 不满足 1<=reserve 下界，
 * 但零值本就不声明任何宿主服务预留）。
 */
function crossCheckHostServicesReserve(context: WasmdHostServicesContextV2, memoryBytes: number, path: string, errors: ValidationIssue[]): void {
	if (isWasmHostServicePolicyV2Empty(context.hostServicePolicy)) return;
	const gate = checkWasmGuestMemoryReserve(memoryBytes, context.hostServicePolicy.reserveBytes);
	if (!gate.ok) {
		errors.push(issue(WASM_RESOURCE_RECORD_INVALID, path, "policy reserveBytes must satisfy 1 <= reserveBytes < resources.memoryBytes; no zero/default reserve is substituted"));
	}
}

export interface WasmdInvocationV2 extends Omit<WasmdInvocationV1, "binding" | "identity"> {
	readonly binding: RuntimeBindingIdentityV2;
	readonly identity: WasmdIdentityV2;
	/** argv@2 携带的 host-service 执行上下文（argv@1 恒缺）；policyless 执行携带零值策略（policyDigest ""），绝不合成非零策略。 */
	readonly hostServices: WasmdHostServicesContextV2;
}

// argv.rs parse_argv（@2 分支）的 TS 对位：11 元素 + 标记/ABI 耦合 + context 资源门。
export function verifyWasmdArgvV2(argv: readonly string[]): ValidationResult<WasmdInvocationV2> {
	const errors: ValidationIssue[] = [];
	if (argv.length !== WASMD_ARGV_V2_ELEMENT_COUNT) {
		return failure([issue(WASMD_ARGV_INVALID, "", "argv must have exactly " + WASMD_ARGV_V2_ELEMENT_COUNT + " elements including argv[0] for marker " + WASMD_ARGV_MARKER_V2 + "; refusing len " + argv.length)]);
	}
	if (argv[1] !== WASMD_ARGV_MARKER_V2) {
		return failure([issue(WASMD_ARGV_INVALID, "/1", "argv[1] must be the exact marker " + WASMD_ARGV_MARKER_V2 + "; refusing " + argv[1])]);
	}
	const componentPath = argv[2] ?? "";
	const capabilityRecordPath = argv[5] ?? "";
	const listen = argv[3] ?? "";
	const gateway = argv[4] ?? "";
	requireAbsolutePath(componentPath, "component path", errors);
	requireSocketAddressLiteral(listen, "listen address", errors);
	requireSocketAddressLiteral(gateway, "gateway address", errors);
	requireAbsolutePath(capabilityRecordPath, "capability record path", errors);
	const architecture = argv[6] ?? "";
	if (!WASMD_ARCHITECTURES.includes(architecture as WasmRuntimeArchitecture)) {
		errors.push(issue(WASMD_ARGV_INVALID, "/6", "architecture must be one of linux/amd64, linux/arm64"));
	}
	const bindingValue = requireCanonicalJsonArg(argv[7] ?? "", "binding-json", errors);
	const identityValue = requireCanonicalJsonArg(argv[8] ?? "", "identity-json", errors);
	const resourcesValue = requireCanonicalJsonArg(argv[9] ?? "", "resources-json", errors);
	const contextValue = requireCanonicalJsonArg(argv[10] ?? "", "host-services-json", errors);
	let binding: RuntimeBindingIdentityV2 | null = null;
	if (bindingValue !== null) {
		binding = requireRuntimeBindingIdentityV2Arg(bindingValue, "/binding-json", errors);
	}
	const identity = identityValue === null ? null : requireWasmdIdentityV2(identityValue, "/identity-json", errors);
	const resources = resourcesValue === null ? null : requireResourcesArg(resourcesValue, "resources-json", errors);
	const hostServices = contextValue === null ? null : requireHostServicesContextV2(contextValue, "/host-services-json", errors);
	if (hostServices !== null && resources !== null) {
		crossCheckHostServicesReserve(hostServices, resources.memoryBytes, "/host-services-json", errors);
	}
	if (errors.length || binding === null || identity === null || resources === null || hostServices === null) return failure(errors);
	return ok({
		componentPath,
		listen,
		gateway,
		capabilityRecordPath,
		architecture: architecture as WasmRuntimeArchitecture,
		binding,
		identity,
		resources,
		hostServices,
	});
}

/** 命令 → 身份 tuple（binding 逐字保留 ABI 1.1.0）。 */
export function wasmdIdentityOfHostServiceCommandV2(command: ExecutionCommand): WasmdIdentityV2 {
	return {
		sandboxId: command.identity.sandboxId,
		versionId: command.identity.versionId,
		packageDigest: command.packageDigest,
		runtimeBinding: command.runtimeBinding,
		capabilityRecordRevision: command.capabilityRecordRevision,
		capabilityRecordHash: command.capabilityRecordHash,
		secretRevision: command.secretRevision,
		secretValuesDigest: command.secretValuesDigest,
		configRevision: command.configRevision,
		configSnapshotRef: command.configSnapshotRef,
		configValuesDigest: command.configValuesDigest,
		preparationGeneration: command.identity.preparationGeneration,
		executionGeneration: command.identity.executionGeneration,
	};
}

export interface WasmdArgvInputV2 {
	/** V2 seam 命令（身份/绑定/pin/快照 digest 的唯一来源；binding ABI 1.1.0）。 */
	readonly command: ExecutionCommand;
	/** admitted normalized manifest 的资源界（argv[9] 来源；reserve 门的对侧输入）。 */
	readonly resources: WasmResourcesV1;
	readonly listen: string;
	readonly gateway: string;
	readonly componentPath: string;
	readonly capabilityRecordPath: string;
	readonly architecture: WasmRuntimeArchitecture;
	/** sealed HostServicePolicyV2（argv@2 context 内嵌；policyDigest 由契约层复算）。 */
	readonly hostServicePolicy: WasmHostServicePolicyV2;
}

// argv@2 构建：前 10 元素与 v1 同构（binding/identity 换 ABI 1.1.0 投影），第 11 元素
// = JCS({schemaVersion:2, applicationId, fenceNonce, hostServicePolicy})；构建后立即以
// verifyWasmdArgvV2 复验（builder 与 parser 契约不得漂移）。
export function buildWasmdArgvV2(input: WasmdArgvInputV2): ValidationResult<{ readonly argv: readonly string[] }> {
	const command = validateExecutionCommand(input.command);
	if (!command.ok) return failure(command.errors);
	const context: WasmdHostServicesContextV2 = {
		schemaVersion: 2,
		applicationId: command.value.applicationId,
		fenceNonce: command.value.fenceNonce,
		hostServicePolicy: input.hostServicePolicy,
	};
	const argv: string[] = [
		WASMD_ARGV_PROGRAM,
		WASMD_ARGV_MARKER_V2,
		input.componentPath,
		input.listen,
		input.gateway,
		input.capabilityRecordPath,
		input.architecture,
		Buffer.from(jcsCanonicalBytes(command.value.runtimeBinding)).toString("utf8"),
		Buffer.from(jcsCanonicalBytes(wasmdIdentityOfHostServiceCommandV2(command.value))).toString("utf8"),
		Buffer.from(jcsCanonicalBytes(input.resources)).toString("utf8"),
		Buffer.from(jcsCanonicalBytes(context)).toString("utf8"),
	];
	const verified = verifyWasmdArgvV2(argv);
	if (!verified.ok) return failure(verified.errors);
	return ok({ argv });
}

// ---------------------------------------------------------------------------
// manifest 可执行权威拒绝（spec 已命名 WASM_MANIFEST_EXECUTABLE_AUTHORITY）
// ---------------------------------------------------------------------------

// wasm manifest 不存在的可执行权威字段名（spec：no assets/entrypoint/image/command/
// mount/socket/arbitrary environment；host capability/TLS 同列）。任意深度出现即拒绝。
const MANIFEST_EXECUTABLE_AUTHORITY_FIELDS: readonly string[] = [
	"assets",
	"capability",
	"capabilities",
	"command",
	"entrypoint",
	"env",
	"environment",
	"image",
	"mount",
	"mounts",
	"socket",
	"sockets",
	"tls",
];

function scanExecutableAuthority(value: unknown, found: string[]): void {
	if (Array.isArray(value)) {
		for (const item of value) scanExecutableAuthority(item, found);
		return;
	}
	if (!isRecord(value)) return;
	for (const key of Object.keys(value)) {
		if (MANIFEST_EXECUTABLE_AUTHORITY_FIELDS.includes(key)) found.push(key);
		scanExecutableAuthority(value[key], found);
	}
}

// 任意深度（含 runtime 嵌套）出现 image/command/mount/host capability/socket/TLS/
// environment 字段 → WASM_MANIFEST_EXECUTABLE_AUTHORITY。与 validateNormalizedWasmManifestV1
// 的精确键集（WASM_MANIFEST_INVALID）互补：前者点名 spec 拒绝码，后者兜底其余未知字段。
export function rejectWasmManifestExecutableAuthority(input: unknown): ValidationResult<true> {
	const found: string[] = [];
	scanExecutableAuthority(input, found);
	if (found.length) {
		const unique = [...new Set(found)].sort();
		return failure([issue(WASM_MANIFEST_EXECUTABLE_AUTHORITY, "", "an admission manifest carrying image, command, mount, host capability, socket, TLS, or arbitrary environment authority is rejected; found: " + unique.join(", "))]);
	}
	return ok(true);
}

// ---------------------------------------------------------------------------
// wasm 沙箱 spawn spec 与 Podman create argv（sandbox-spec.ts 惯例的 wasm 增量）
// ---------------------------------------------------------------------------

export interface WasmSandboxSpawnOptions {
	/** supervisor 状态目录（组件快照物化在其 wasm-components/ 下）。 */
	readonly stateDirectory: string;
	/** 固定 runtime image repo（无 tag/digest；与 binding.imageDigest 组装为 digest-pinned 引用）。 */
	readonly runtimeImageRepository: string;
	readonly architecture: WasmRuntimeArchitecture;
	/** 宿主侧 pinned NodeCapabilityRecordV1 文件（只读挂载进容器）。 */
	readonly capabilityRecordHostPath: string;
	readonly subnetIndex: number;
}

export interface WasmSandboxSpawnSpec {
	readonly sandboxId: string;
	readonly versionId: string;
	readonly subnetIndex: number;
	/** digest-pinned wasmd 镜像引用（repo@<binding.imageDigest>）。 */
	readonly runtimeImage: string;
	/** gateway ingress 拨打的 wasmd 监听地址（argv[3] 字面量）。 */
	readonly listenAddress: string;
	/** wasmd 唯一拨出的网关地址（argv[4] 字面量）。 */
	readonly gatewayAddress: string;
	/** wasmd argv（V1 binding = argv@1 恰好 10 元素；V2 binding = argv@2 恰好 11 元素）。 */
	readonly argv: readonly string[];
	readonly mounts: readonly SandboxMountSpec[];
	readonly cpuMillis: number;
	readonly memoryBytes: number;
	readonly pidLimit: number;
	readonly storageBytes: number;
}

// supervisor 物化的 entry layer 组件文件（宿主路径；materializer 接线属 5.x——落地字节
// 必须与 entryLayerDigest 复验后才允许挂载）。
export function wasmComponentSnapshotPath(stateDirectory: string, entryLayerDigest: string): string {
	return stateDirectory + "/wasm-components/" + entryLayerDigest.replace(/^sha256:/, "") + "/component.wasm";
}

// 网关 secret 的 wasm ingressTarget（与 celld 沙箱同拓扑：gateway 拨 app 的 pinned 地址）。
export function wasmdIngressTarget(subnetIndex: number): string {
	return sandboxAppAddress(subnetIndex) + ":" + WASMD_LISTEN_PORT;
}

function requireAbsoluteHostPath(value: string, fieldName: string, errors: ValidationIssue[]): void {
	if (value.length === 0 || !value.startsWith("/") || value.includes("\0")) {
		errors.push(issue(WASM_SPAWN_INVALID, "/" + fieldName, fieldName + " must be a non-empty absolute host path"));
	}
}

/**
 * spawn spec 组装（单一命令形态；原 buildWasmSandboxSpecV2）：同一沙箱法（manifest
 * 双闸、digest-pinned image、子网/绝对路径检查、mount 形状）+ host-service 增量——
 *   1. 命令复验 contracts validateExecutionCommand（binding ABI 1.1.0 + 身份增量）；
 *   2. 权限 pin：resolved policy 的 policyDigest 必须等于命令的 hostServicePolicyDigest
 *      （Kernel 只授权它准入过的策略字节；WASM_HOST_POLICY_DIGEST_MISMATCH）；
 *   3. argv@2（11 元素）：buildWasmdArgvV2 内嵌 host-services context，且复验
 *      1 <= reserveBytes < resources.memoryBytes（design §3 资源门，wasmd cross_check 对位）；
 *   4. per-app 数据目录挂载：宿主 <stateDirectory>/wasm-data/<applicationId>
 *      → 容器 /data/kernel/wasm-data/<applicationId>，读写（SQLite 后端需要写）。
 */
export function buildWasmSandboxSpec(input: {
	readonly command: ExecutionCommand;
	/** admitted normalized manifest（资源界 + entry layer；versionDigest 的同一绑定对象）。 */
	readonly policy: NormalizedWasmManifestV1;
	/** sealed HostServicePolicyV2（文件来源已验；本层重验 policyDigest 复算）。 */
	readonly hostServicePolicy: WasmHostServicePolicyV2;
}, options: WasmSandboxSpawnOptions): ValidationResult<WasmSandboxSpawnSpec> {
	const errors: ValidationIssue[] = [];
	// 命令复验（fail-closed：supervisor 不信任未经契约校验的命令字节）。
	const command = validateExecutionCommand(input.command);
	if (!command.ok) return failure(command.errors);
	// manifest 双闸：可执行权威点名拒绝 + 契约精确键集（与 V1 同款，不造第二套语义）。
	const authority = rejectWasmManifestExecutableAuthority(input.policy);
	if (!authority.ok) return failure(authority.errors);
	const policy = validateNormalizedWasmManifestV1(input.policy);
	if (!policy.ok) return failure(policy.errors);
	// sealed policy 重验 + 命令权限 pin（策略字节必须与命令 pin 精确相等）。
	const sealed = validateWasmHostServicePolicyV2(input.hostServicePolicy);
	if (!sealed.ok) return failure(sealed.errors);
	if (sealed.value.policyDigest !== command.value.hostServicePolicyDigest) {
		return failure([issue(WASM_HOST_POLICY_DIGEST_MISMATCH, "/hostServicePolicyDigest", "the resolved host service policy digest must equal the command pin hostServicePolicyDigest; Kernel authorized different policy bytes")]);
	}
	// image 权威只在 runtime binding：repo 名不得自带 tag/digest，引用必须 digest-pinned。
	if (options.runtimeImageRepository.includes("@") || options.runtimeImageRepository.includes(":")) {
		errors.push(issue(WASM_SPAWN_INVALID, "/runtimeImageRepository", "runtimeImageRepository must be a bare repository name; the digest comes only from the runtime binding"));
	}
	const runtimeImage = options.runtimeImageRepository + "@" + command.value.runtimeBinding.imageDigest;
	if (!isDigestPinnedImage(runtimeImage)) {
		errors.push(issue(WASM_SPAWN_INVALID, "/runtimeImage", "the runtime image reference must be digest-pinned (repo@sha256:<hex>)"));
	}
	if (!Number.isSafeInteger(options.subnetIndex) || options.subnetIndex < 0 || options.subnetIndex > SANDBOX_SUBNET_MAX) {
		errors.push(issue(WASM_SPAWN_INVALID, "/subnetIndex", "subnetIndex must be an integer between 0 and " + SANDBOX_SUBNET_MAX));
	}
	requireAbsoluteHostPath(options.stateDirectory, "stateDirectory", errors);
	requireAbsoluteHostPath(options.capabilityRecordHostPath, "capabilityRecordHostPath", errors);
	if (errors.length) return failure(errors);
	const listen = wasmdIngressTarget(options.subnetIndex);
	const gateway = sandboxGatewayAddress(options.subnetIndex) + ":" + WASMD_GATEWAY_EGRESS_PORT;
	const argv = buildWasmdArgvV2({
		command: command.value,
		resources: policy.value.resources,
		listen,
		gateway,
		componentPath: WASMD_COMPONENT_MOUNT_TARGET,
		capabilityRecordPath: WASMD_CAPABILITY_RECORD_MOUNT_TARGET,
		architecture: options.architecture,
		hostServicePolicy: sealed.value,
	});
	if (!argv.ok) return failure(argv.errors);
	// V2 增量挂载：per-app 数据目录（读写）——kv/sql/quota 的 SQLite 后端在容器内
	// /data/kernel/wasm-data/<applicationId>/ 落盘（provider open 创建 0700 目录与
	// 0600 文件）；宿主源挂到同形路径，跨应用隔离由「一应用一目录」+provider 身份门承担。
	const dataTarget = WASMD_DATA_MOUNT_TARGET_ROOT + "/" + command.value.applicationId;
	const mounts: SandboxMountSpec[] = [
		{ kind: "bind", source: wasmComponentSnapshotPath(options.stateDirectory, policy.value.runtime.entryLayerDigest), target: WASMD_COMPONENT_MOUNT_TARGET, readOnly: true },
		{ kind: "bind", source: options.capabilityRecordHostPath, target: WASMD_CAPABILITY_RECORD_MOUNT_TARGET, readOnly: true },
		{ kind: "bind", source: wasmApplicationDataPath(options.stateDirectory, command.value.applicationId), target: dataTarget, readOnly: false },
	];
	return ok({
		sandboxId: command.value.identity.sandboxId,
		versionId: command.value.identity.versionId,
		subnetIndex: options.subnetIndex,
		runtimeImage,
		listenAddress: listen,
		gatewayAddress: gateway,
		argv: argv.value.argv,
		mounts,
		cpuMillis: policy.value.resources.cpuMillis,
		memoryBytes: policy.value.resources.memoryBytes,
		pidLimit: policy.value.resources.pidLimit,
		storageBytes: policy.value.resources.storageBytes,
	});
}

// wasm app 容器的 Podman create argv：与 buildAppContainerCreateArgs 同一沙箱法（标签、
// 只读根、cap-drop ALL、no-new-privileges、seccomp、internal 网络 + pinned IP、cgroup
// 资源界、同款 tmpfs），wasm 增量只有三处：
//   1. --preserve-fds 2：FD 3（secret）/FD 4（config）经 SCM_RIGHTS 的唯一进入路径；
//   2. 零 --env：wasmd 只读 argv 与 FD，任何记录值不得被环境变量替代；
//   3. 镜像为 catalog digest-pinned wasmd，command 为 10 元素固定 argv（镜像 ENTRYPOINT
//      即 wasmd 本体，无任何 manifest 可执行权威）。
// 网关容器沿用 celld 沙箱的 buildGatewayContainerCreateArgs（同一拓扑、同一网关镜像；
// secret 的 ingressTarget 换为 wasmdIngressTarget）——接线属 5.x。
export function buildWasmdAppContainerCreateArgs(spec: WasmSandboxSpawnSpec): string[] {
	const args: string[] = [
		"create",
		"--name", appContainerName(spec.sandboxId),
		"--label", IWEB_MANAGED_LABEL,
		"--label", "iweb.sandbox=" + spec.sandboxId,
		"--label", "iweb.role=app",
		"--label", "iweb.version=" + spec.versionId,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + SECCOMP_PROFILE_HOST_PATH,
		"--network", sandboxNetworkName(spec.sandboxId),
		"--ip", sandboxAppAddress(spec.subnetIndex),
		"--cpus", String(spec.cpuMillis / 1000),
		"--memory", String(spec.memoryBytes),
		"--pids-limit", String(spec.pidLimit),
		"--storage-opt", "size=" + String(spec.storageBytes),
		"--preserve-fds", "2",
	];
	for (const mount of spec.mounts) {
		if (mount.kind === "bind") {
			args.push("--mount", "type=bind,source=" + mount.source + ",target=" + mount.target + (mount.readOnly ? ",ro" : ""));
		} else {
			args.push("--mount", "type=tmpfs,target=" + mount.target + ",tmpfs-mode=1777,noexec,nosuid,size=" + spec.storageBytes);
		}
	}
	args.push(spec.runtimeImage);
	args.push(...spec.argv);
	return args;
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. listen 地址取 sandboxAppAddress(subnetIndex):8787（gateway ingress 拨打的字面量），
//    而非 celld 的容器内 loopback：spec 要求 wasmd "listen only at the exact address
//    that the paired sandbox gateway ingress dials"，且 argv.rs 拒绝通配地址——绑定
//    pinned IP 是唯一同时满足两者的形态；Linux 实机双容器实测（5.x）复核。
// 2. identity-json 不携带 secretSnapshotRef（wire.rs 键集对位）：FD 内容以 valuesDigest
//    绑定，ref 是 Kernel 私有索引键，spec 明令 supervisor 把 ref 当 opaque。
// 3. WASMD_ARGV_INVALID / WASMD_ARGV_WIRE_INVALID / WASM_IDENTITY_INCOMPLETE 与
//    wasmd 侧稳定码同名同语义（argv 形状 vs wire 形状 vs 代次下界），跨实现不得改名。
// 4. manifest 可执行权威扫描是递归精确键名匹配（非子串）：normalized 契约的合法字段
//    （name/resources/storage/egress/runtime.* 等）不与权威字段名碰撞；深层嵌套的
//    image/command/mount 一律点名拒绝，其余未知字段仍由契约键集兜底拒绝。
