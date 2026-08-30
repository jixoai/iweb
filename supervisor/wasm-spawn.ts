// 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1 supervisor 半边；two-tier-runtime-trust
//   2026-08-30 去 Podman 修订）：supervisor 独占生成 wasmd 的每一个 argv 元素（11 元素
//   argv@2 契约，逐字节对位 kernel-rs/wasmd/src/argv.rs 的 parse_argv @2 分支）；执行
//   形态是节点容器内的受管子进程——无 OCI 参数、无 seccomp、无 Podman 网络，隔离由
//   Wasmtime 引擎结构强制（fuel/epoch/ResourceLimiter；spec two-tier 修订
//   "Wasm applications inherit the application sandbox law"）。
// 正交意图：
//   1. argv@2 精确形状（含 argv[0] 恰好 11 元素；无选项语法、无可选参数）：标记
//      `--iweb-wasmd-argv@2`、组件快照路径、listen/gateway ip:port 字面量、capability
//      record 路径、节点架构、binding/identity/resources/host-services 四个 JCS JSON——
//      未知/缺失/多余参数一律 fail-closed（WASMD_ARGV_INVALID / WASMD_ARGV_WIRE_INVALID，
//      与 wasmd 同名）。listen 是 supervisor 分配的唯一回环地址（127/8 内确定性映射），
//      gateway 是 supervisor 配置的唯一出网代理 ip:port 字面量。
//   2. manifest 携带任意 image/command/mount/capability/socket/TLS/environment 可执行
//      权威 → WASM_MANIFEST_EXECUTABLE_AUTHORITY（spec "Wasmd has a fixed command and
//      host-mediated network contract" 已命名）；其余 manifest 校验复用
//      validateNormalizedWasmManifestV1 精确键集，不造第二套。
//   3. 原 Podman 三组 bind mount 收敛为「子进程可直接访问的本地路径」：组件快照
//      （stateDirectory/wasm-components/...）、pinned capability record 宿主路径、
//      per-app wasm-data 目录——容器内同文件系统视角，无挂载翻译。
//   4. FD 3/4 直通：spec ADDED "Snapshot FD content is bound across Kernel, supervisor,
//      and wasmd"——描述符经 snapshot-fd relay 的注入型 exec 进入子进程（Node/Bun 无
//      SCM_RIGHTS 接收能力，relay 是唯一持有者），launcher 由本模块组装（见
//      buildWasmdLauncherScript；wasm-runtime.ts 消费）。
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

// wasmd 读取的组件快照文件（supervisor 物化的 entry layer 组件；子进程与本进程同
// 容器文件系统视角，argv[2] 即该本地路径——materializer 接线归 Kernel 投影批次）。
export function wasmComponentSnapshotPath(stateDirectory: string, entryLayerDigest: string): string {
	return stateDirectory + "/wasm-components/" + entryLayerDigest.replace(/^sha256:/, "") + "/component.wasm";
}

/** 宿主侧 per-app 数据目录（<stateDirectory>/wasm-data/<applicationId>；supervisor 物化，wasmd 以 0700/0600 加固）。 */
export function wasmApplicationDataPath(stateDirectory: string, applicationId: string): string {
	return stateDirectory + "/wasm-data/" + applicationId;
}

// ---------------------------------------------------------------------------
// 监听地址分配（容器内回环）：每 execution 一个确定性 127/8 回环地址 + 固定端口。
//   原 Podman 子网模型（10.200.<index>.0/24 的 .3 pinned IP）退役；Linux/macOS 都把
//   整个 127.0.0.0/8 路由到 loopback，按 index 映射 127.<200+hi>.<lo>.3 使各 execution
//   的 listener 互不冲突（同端口不同地址），且永远不与 127.0.0.1 上的节点控制面监听
//   （celld admin 8787 等）碰撞。spec 修订语："The runtime SHALL listen only at the
//   exact loopback address the supervisor assigned for that execution."
// ---------------------------------------------------------------------------

/** 每 sandbox 的确定性监听索引上界（含）；1024 个并发 execution 槽位。 */
export const WASM_LISTEN_INDEX_MAX = 1023;
const WASM_LISTEN_LOOPBACK_SECOND_BASE = 200;
/** wasmd 唯一 listener 的固定端口（与节点控制面共享端口空间但地址不同）。 */
export const WASMD_LISTEN_PORT = 8787;
/** 确定性回环监听地址（index → 127.<200+hi>.<lo>.3:8787）。 */
export function wasmdIngressTarget(listenIndex: number): string {
	return "127." + (WASM_LISTEN_LOOPBACK_SECOND_BASE + Math.floor(listenIndex / 256)) + "." + (listenIndex % 256) + ".3:" + WASMD_LISTEN_PORT;
}

// wasmd 唯一允许拨出的出网代理地址（argv[4] 字面量）：容器内 host-mediated 网关的
// 前向代理端点。默认值与部署一致（IWEB_SANDBOX_WASM_GATEWAY_ADDRESS 可覆盖；缺省
// 127.0.0.1:8081——容器内网关位）。组件无 socket 能力，出站 HTTP/HTTPS CONNECT 只经它。
export const DEFAULT_WASMD_GATEWAY_ADDRESS = "127.0.0.1:8081";

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
// wasm 进程 spawn spec 与 wasmd launcher（two-tier-runtime-trust：去 Podman）
// ---------------------------------------------------------------------------

export interface WasmSandboxSpawnOptions {
	/** supervisor 状态目录（组件快照物化在其 wasm-components/ 下；per-app 数据在其 wasm-data/ 下）。 */
	readonly stateDirectory: string;
	/** digest-pinned wasmd 二进制的容器内路径（IWEB_SANDBOX_WASM_BIN；镜像完整性检查由入口保证）。 */
	readonly wasmdBinaryPath: string;
	/** wasmd 唯一拨出的出网代理 ip:port 字面量（argv[4]）。 */
	readonly gatewayAddress: string;
	readonly architecture: WasmRuntimeArchitecture;
	/** pinned NodeCapabilityRecordV1 本地路径（argv[5]；宿主上限唯一来源，Kernel 投影只读目录内）。 */
	readonly capabilityRecordHostPath: string;
	/** launcher 写 pidfile 的目录（进程生命周期管理的地址权威；通常 /run/iweb-sandbox/wasmd）。 */
	readonly pidDirectory: string;
}

export interface WasmSandboxSpawnSpec {
	readonly sandboxId: string;
	readonly versionId: string;
	/** 本 execution 的确定性监听索引（记录于 fence，journal 重放按同序可得同值）。 */
	readonly listenIndex: number;
	/** wasmd 唯一 listener（argv[3] 字面量；supervisor 分配的回环地址）。 */
	readonly listenAddress: string;
	/** wasmd 唯一拨出的出网代理（argv[4] 字面量）。 */
	readonly gatewayAddress: string;
	/** wasmd argv（argv@2 恰好 11 元素；argv[0] 是契约程序名）。 */
	readonly argv: readonly string[];
	/** wasmd 二进制路径（launcher 的 exec 目标）。 */
	readonly wasmdBinaryPath: string;
	/** 组件快照本地路径（argv[2]；与 supervisor 同容器文件系统视角）。 */
	readonly componentPath: string;
	/** pinned capability record 本地路径（argv[5]）。 */
	readonly capabilityRecordPath: string;
	/** per-app 数据目录（子进程可写；kv/sql/quota 的 SQLite 后端在目录内落盘）。 */
	readonly dataDirectoryPath: string;
	/** 本 execution 的 pidfile（launcher 写入；stop/kill/isRunning 的进程地址）。 */
	readonly pidFilePath: string;
}

function requireAbsoluteHostPath(value: string, fieldName: string, errors: ValidationIssue[]): void {
	if (value.length === 0 || !value.startsWith("/") || value.includes("\0")) {
		errors.push(issue(WASM_SPAWN_INVALID, "/" + fieldName, fieldName + " must be a non-empty absolute host path"));
	}
}

/** wasmd execution 的 pidfile 路径（<pidDirectory>/<sandboxId>.pid）。 */
export function wasmdPidFilePath(pidDirectory: string, sandboxId: string): string {
	return pidDirectory + "/" + sandboxId + ".pid";
}

/**
 * spawn spec 组装（单一命令形态；原 buildWasmSandboxSpecV2）：命令/manifest/策略三闸 +
 *   进程口径增量——
 *   1. 命令复验 contracts validateExecutionCommand（binding ABI 1.1.0 + 身份增量）；
 *   2. 权限 pin：resolved policy 的 policyDigest 必须等于命令的 hostServicePolicyDigest
 *      （Kernel 只授权它准入过的策略字节；WASM_HOST_POLICY_DIGEST_MISMATCH）；
 *   3. argv@2（11 元素）：buildWasmdArgvV2 内嵌 host-services context，且复验
 *      1 <= reserveBytes < resources.memoryBytes（design §3 资源门，wasmd cross_check 对位）；
 *   4. 三组路径全部是子进程可直接访问的本地路径（组件快照、capability record、
 *      per-app wasm-data）——无挂载、无 OCI 参数；
 *   5. listen/gateway 都是 ip:port 字面量（verifyWasmdArgvV2 内的解析器复核）。
 */
export function buildWasmSandboxSpec(input: {
	readonly command: ExecutionCommand;
	/** admitted normalized manifest（资源界 + entry layer；versionDigest 的同一绑定对象）。 */
	readonly policy: NormalizedWasmManifestV1;
	/** sealed HostServicePolicyV2（文件来源已验；本层重验 policyDigest 复算）。 */
	readonly hostServicePolicy: WasmHostServicePolicyV2;
}, options: WasmSandboxSpawnOptions & { readonly listenIndex: number }): ValidationResult<WasmSandboxSpawnSpec> {
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
	if (!Number.isSafeInteger(options.listenIndex) || options.listenIndex < 0 || options.listenIndex > WASM_LISTEN_INDEX_MAX) {
		errors.push(issue(WASM_SPAWN_INVALID, "/listenIndex", "listenIndex must be an integer between 0 and " + WASM_LISTEN_INDEX_MAX));
	}
	requireAbsoluteHostPath(options.stateDirectory, "stateDirectory", errors);
	requireAbsoluteHostPath(options.capabilityRecordHostPath, "capabilityRecordHostPath", errors);
	requireAbsoluteHostPath(options.wasmdBinaryPath, "wasmdBinaryPath", errors);
	requireAbsoluteHostPath(options.pidDirectory, "pidDirectory", errors);
	if (errors.length) return failure(errors);
	const listen = wasmdIngressTarget(options.listenIndex);
	const gateway = options.gatewayAddress;
	const componentPath = wasmComponentSnapshotPath(options.stateDirectory, policy.value.runtime.entryLayerDigest);
	const capabilityRecordPath = options.capabilityRecordHostPath;
	const argv = buildWasmdArgvV2({
		command: command.value,
		resources: policy.value.resources,
		listen,
		gateway,
		componentPath,
		capabilityRecordPath,
		architecture: options.architecture,
		hostServicePolicy: sealed.value,
	});
	if (!argv.ok) return failure(argv.errors);
	return ok({
		sandboxId: command.value.identity.sandboxId,
		versionId: command.value.identity.versionId,
		listenIndex: options.listenIndex,
		listenAddress: listen,
		gatewayAddress: gateway,
		argv: argv.value.argv,
		wasmdBinaryPath: options.wasmdBinaryPath,
		componentPath,
		capabilityRecordPath,
		dataDirectoryPath: wasmApplicationDataPath(options.stateDirectory, command.value.applicationId),
		pidFilePath: wasmdPidFilePath(options.pidDirectory, command.value.identity.sandboxId),
	});
}

// ---------------------------------------------------------------------------
// wasmd launcher：relay 注入型 exec 的命令行（FD 3/4 直通的唯一进入路径）
// ---------------------------------------------------------------------------

/** POSIX 单引号转义（launcher 的每一个 argv 元素都以字面量进入子进程命令行）。 */
function shellQuoteLiteral(value: string): string {
	return "'" + value.replace(/'/g, "'\\''") + "'";
}

/**
 * wasmd launcher 脚本（sh -c 载荷；由 snapshot-fd relay 以 FD 3（secret）/FD 4（config，
 * 存在时）注入后 exec）：
 *   - relay 的注入型 exec 会 fork → dup2 到槽位 3/4（清 FD_CLOEXEC）→ 关闭其余继承
 *     描述符 → execv——这正是 spec ADDED "direct-process handoff" 的子进程形态；
 *   - launcher 只做三件事：建 pid 目录、以后台作业启动 wasmd（FD 3/4 原样继承）、把
 *     wasmd 的 pid 写入 pidfile 后退出（让 relay 的 waitpid 立即收敛，控制通道不被
 *     长驻进程占死——relay 控制 socket 是串行单线程，见 kernel-rs/snapshot-fd-relay）；
 *   - `wasmd &` 是简单命令后台化，$! 即 wasmd 本体的 pid（无子壳中间层）；
 *   - zero env：wasmd 只读 argv 与 FD（记录值不得被环境变量替代）。
 */
export function buildWasmdLauncherScript(spec: WasmSandboxSpawnSpec): string {
	const commandLine = [spec.wasmdBinaryPath, ...spec.argv.slice(1)].map(shellQuoteLiteral).join(" ");
	const pidDirectory = spec.pidFilePath.slice(0, spec.pidFilePath.lastIndexOf("/")) || "/";
	return "mkdir -p " + shellQuoteLiteral(pidDirectory) + "\n" + commandLine + " &\necho $! > " + shellQuoteLiteral(spec.pidFilePath) + "\n";
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. listen 地址是 supervisor 分配的 127/8 回环字面量（wasmdIngressTarget）：argv.rs 拒绝
//    通配地址，绑定唯一回环地址满足 spec "listen only at the exact loopback address the
//    supervisor assigned"；不同 execution 同端口不同地址，互不冲突且不与 127.0.0.1 上的
//    节点控制面监听碰撞。
// 2. identity-json 不携带 secretSnapshotRef（wire.rs 键集对位）：FD 内容以 valuesDigest
//    绑定，ref 是 Kernel 私有索引键，spec 明令 supervisor 把 ref 当 opaque。
// 3. WASMD_ARGV_INVALID / WASMD_ARGV_WIRE_INVALID / WASM_IDENTITY_INCOMPLETE 与
//    wasmd 侧稳定码同名同语义（argv 形状 vs wire 形状 vs 代次下界），跨实现不得改名。
// 4. manifest 可执行权威扫描是递归精确键名匹配（非子串）：normalized 契约的合法字段
//    （name/resources/storage/egress/runtime.* 等）不与权威字段名碰撞；深层嵌套的
//    image/command/mount 一律点名拒绝，其余未知字段仍由契约键集兜底拒绝。
// 5. launcher 以 /bin/sh 承载（relay 的 exec 目标；wasm-runtime.ts 固定传递）：FD 3/4
//    经后台作业原样继承（非交互 sh 不重定向额外描述符）；wasmd 的 argv[0] 因 exec 语法
//    取二进制路径——argv.rs 只校验元素数与 argv[1] 标记，argv[0] 内容非契约维度。
// 6. gateway 地址默认 127.0.0.1:8081（DEFAULT_WASMD_GATEWAY_ADDRESS）：容器内 host-
//    mediated 出网代理的部署位；端点由 Kernel/entrypoint 侧提供，缺位时组件出网按
//    连接失败 fail-closed（结构性出网边界不受影响）。

