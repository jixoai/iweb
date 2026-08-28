//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 2.1/2.2 + 7.6）：Kernel 侧 wasm
//! 执行命令权威——owner-authorized ExecutionCommandV1 生成（commandId、expected
//! control/journal revision、full tuple）、typed completion acknowledgement 投影、
//! query/replay 决策，以及双 generation fencing 的纯函数语义（单调
//! preparationGeneration/executionGeneration）。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//! "Kernel authorizes lifecycle while supervisor journals execution only"、
//! "Wasm control state has a revisioned outbox and isolated journal"、
//! "Every wasm execution uses a typed dual-generation fence"、
//! "Drain completion is a typed receipt before Kernel retirement"。
//! wire 权威：packages/contracts/wasm-execution.ts（命令/ack/身份/fence/receipt
//! 纯函数）——Rust 侧字节一致复算 commandDigest 与 receiptDigest，golden 向量以
//! bun 直读 contracts 的 oracle 产出。
//!
//! 正交意图：
//! 1. 纯函数层：typed wire 记录（精确键集）、commandDigest、双代次迁移、fence 比对；
//! 2. Kernel 命令生成：从 admission registry 行 + 控制态视图推导 expected revisions 与
//!    full tuple（prepare/start/drain/stop 各自的代次分配规则）；
//! 3. ack 投影状态机：supervisor journal 完成而 Kernel projection 失败时，只有
//!    query/replay 可推进，绝不先路由（本模块不存在任何 route-pointer 写入路径；
//!    route CAS 属任务 2.4）；
//! 4. 内存 CAS 载体（WasmCommandControlState）：controlRevision 每 mutation 恰好 +1，
//!    outbox 追加与 ack 投影共享同一 CAS 语义，供后续真实文件存储接线复用语义；
//! 5. DrainReceiptV1 wire 与退休投影（任务 7.6）：receiptDigest 复算/全字段校验、
//!    与 drain 命令及 retiring 记录的精确比对（stale/invalid 分码）；Kernel lifecycle
//!    的 `retired` 只在 receipt projection CAS 成功后写入，重复投影幂等不二次计数。
//!
//! 不可调和原因：命令生成与 ack 投影共享同一 identity fence 与 digest 公式，拆分会
//! 重引入 expected revision 与 tuple 的权威矛盾；双代次分配是命令生成的一部分，
//! 分离会让 fence 语义出现第二解释；receipt 投影与 ack 投影共享同一 controlRevision
//! CAS 载体与 retiring 判据，独立成模块会造出第二个 lifecycle 权威。

use crate::wasm_admission::{
    compose_wasm_version_id, jcs_bytes, parse_rfc3339_utc_millis, validate_runtime_binding,
    AdmissionError, RuntimeBindingIdentityV1, WASM_U53_MAX,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误码
// ---------------------------------------------------------------------------

pub const EXECUTION_COMMAND_DIGEST_DOMAIN: &str = "iweb-execution-command-v1";

/// ExecutionRpcEnvelopeV1.protocol 字面量（/v1/execution-rpc 专用；celld /v1/rpc 互斥）。
pub const EXECUTION_RPC_PROTOCOL_LITERAL: &str = "iweb-execution-rpc-v1";

// spec 已命名的稳定码。
pub const WASM_GENERATION_EXHAUSTED: &str = "WASM_GENERATION_EXHAUSTED";
pub const CONTROL_REVISION_CONFLICT: &str = "CONTROL_REVISION_CONFLICT";
pub const WASM_IDENTITY_INCOMPLETE: &str = "WASM_IDENTITY_INCOMPLETE";
// 对位 contracts/supervisor 已命名的传输/投影码。
pub const EXECUTION_COMMAND_ID_CONFLICT: &str = "EXECUTION_COMMAND_ID_CONFLICT";
pub const EXECUTION_OUTBOX_DUPLICATE_COMMAND: &str = "EXECUTION_OUTBOX_DUPLICATE_COMMAND";
pub const EXECUTION_OUTBOX_COMMAND_UNKNOWN: &str = "EXECUTION_OUTBOX_COMMAND_UNKNOWN";
pub const EXECUTION_ACK_PROJECTION_CONFLICT: &str = "EXECUTION_ACK_PROJECTION_CONFLICT";
// 本模块 fail-closed 补充码（spec 未命名；见文末歧义备注）。
pub const WASM_EXECUTION_IDENTITY_INVALID: &str = "WASM_EXECUTION_IDENTITY_INVALID";
pub const EXECUTION_COMMAND_INVALID: &str = "EXECUTION_COMMAND_INVALID";
pub const EXECUTION_ACKNOWLEDGEMENT_INVALID: &str = "EXECUTION_ACKNOWLEDGEMENT_INVALID";
pub const EXECUTION_QUERY_RESULT_INVALID: &str = "EXECUTION_QUERY_RESULT_INVALID";
pub const WASM_EXECUTION_FENCE_STALE: &str = "WASM_EXECUTION_FENCE_STALE";
pub const EXECUTION_ACK_STALE: &str = "EXECUTION_ACK_STALE";
pub const EXECUTION_OUTBOX_DEAD: &str = "EXECUTION_OUTBOX_DEAD";
// spec 已命名的 drain receipt 稳定码（任务 7.6）。
pub const DRAIN_RECEIPT_INVALID: &str = "DRAIN_RECEIPT_INVALID";
pub const DRAIN_RECEIPT_STALE: &str = "DRAIN_RECEIPT_STALE";
pub const DRAIN_RECEIPT_DIGEST_DOMAIN: &str = "iweb-drain-receipt-v1";

fn err(code: &'static str, detail: impl Into<String>) -> AdmissionError {
    AdmissionError::new(code, detail)
}

struct CommandRegexes {
    sandbox_id: regex::Regex,
    application_id: regex::Regex,
    sha256_hex: regex::Regex,
    uuid_v7: regex::Regex,
    failure_code: regex::Regex,
    entry_key: regex::Regex,
    oci_sha256: regex::Regex,
}

fn command_regexes() -> &'static CommandRegexes {
    static REGEXES: OnceLock<CommandRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| CommandRegexes {
        sandbox_id: regex::Regex::new(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$").expect("sandbox id regex"),
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        uuid_v7: regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").expect("uuid v7 regex"),
        failure_code: regex::Regex::new(r"^[A-Z][A-Z0-9_]{0,63}$").expect("failure code regex"),
        entry_key: regex::Regex::new(r"^[a-z][a-z0-9.-]{0,63}$").expect("entry key regex"),
        oci_sha256: regex::Regex::new(r"^sha256:[a-f0-9]{64}$").expect("oci sha256 regex"),
    })
}

fn validate_sandbox_id(value: &str) -> Result<(), AdmissionError> {
    if command_regexes().sandbox_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_EXECUTION_IDENTITY_INVALID, "sandboxId must start with a lower-case letter and span at most 63 ASCII bytes"))
    }
}

/// 对位 contracts WASM_APPLICATION_ID_PATTERN（同 wasm_activation 的应用 ID 文法）。
fn validate_application_id(value: &str) -> Result<(), AdmissionError> {
    if command_regexes().application_id.is_match(value) {
        Ok(())
    } else {
        Err(err(DRAIN_RECEIPT_INVALID, "applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"))
    }
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<(), AdmissionError> {
    if command_regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(EXECUTION_COMMAND_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

fn validate_uuid_v7(value: &str, field: &str) -> Result<(), AdmissionError> {
    if command_regexes().uuid_v7.is_match(value) {
        Ok(())
    } else {
        Err(err(EXECUTION_COMMAND_INVALID, format!("{field} must be a lower-case UUIDv7 (version nibble 7, RFC 9562 variant)")))
    }
}

fn require_u53(value: u64, minimum: u64, field: &str) -> Result<(), AdmissionError> {
    if value >= minimum && value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(EXECUTION_COMMAND_INVALID, format!("{field} must be an integer between {minimum} and the u53 maximum")))
    }
}

// configRevision:0 ⇔ configSnapshotRef:null ⇔ configValuesDigest:null；非零 revision
// 必须三者齐全（跨 command/ack 同一耦合律）。
fn check_config_snapshot_coupling(config_revision: u64, config_snapshot_ref: &Option<String>, config_values_digest: &Option<String>) -> Result<(), AdmissionError> {
    if config_revision == 0 && (config_snapshot_ref.is_some() || config_values_digest.is_some()) {
        return Err(err(EXECUTION_COMMAND_INVALID, "configRevision 0 requires configSnapshotRef null and configValuesDigest null"));
    }
    if config_revision > 0 && (config_snapshot_ref.is_none() || config_values_digest.is_none()) {
        return Err(err(EXECUTION_COMMAND_INVALID, "a non-zero configRevision requires both configSnapshotRef and configValuesDigest"));
    }
    if config_snapshot_ref.is_some() != config_values_digest.is_some() {
        return Err(err(EXECUTION_COMMAND_INVALID, "configValuesDigest is null exactly when configSnapshotRef is null"));
    }
    Ok(())
}

fn domain_digest(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// WasmExecutionIdentityV1（双 generation fence 的四元组）
// ---------------------------------------------------------------------------

/// (sandboxId, versionId, preparationGeneration, executionGeneration) 四元组；
/// 新分配的 sandbox 记录双代次均为 0，两值只增不减。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WasmExecutionIdentityV1 {
    #[serde(rename = "sandboxId")]
    pub sandbox_id: String,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    #[serde(rename = "executionGeneration")]
    pub execution_generation: u64,
}

pub fn validate_execution_identity(identity: &WasmExecutionIdentityV1) -> Result<(), AdmissionError> {
    validate_sandbox_id(&identity.sandbox_id)?;
    let (digest, sequence) = crate::wasm_admission::parse_wasm_version_id(&identity.version_id)
        .map_err(|e| err(WASM_EXECUTION_IDENTITY_INVALID, e.detail))?;
    if compose_wasm_version_id(&digest, sequence) != identity.version_id {
        return Err(err(WASM_EXECUTION_IDENTITY_INVALID, "versionId must round-trip its digest-sequence label"));
    }
    require_u53(identity.preparation_generation, 0, "/preparationGeneration")?;
    require_u53(identity.execution_generation, 0, "/executionGeneration")?;
    Ok(())
}

/// Kernel prepare CAS：(p,e) -> (p+1,e+1)（首次准备 (0,0)->(1,1)，重备/恢复也推进
/// preparation；到达 u53 上限 fail-closed，不回绕、不复用、不归零）。
pub fn prepare_generation_transition(current: &WasmExecutionIdentityV1) -> Result<WasmExecutionIdentityV1, AdmissionError> {
    if current.preparation_generation >= WASM_U53_MAX || current.execution_generation >= WASM_U53_MAX {
        return Err(err(WASM_GENERATION_EXHAUSTED, "generation space is exhausted; the Kernel does not wrap, reuse, or substitute zero"));
    }
    Ok(WasmExecutionIdentityV1 {
        sandbox_id: current.sandbox_id.clone(),
        version_id: current.version_id.clone(),
        preparation_generation: current.preparation_generation + 1,
        execution_generation: current.execution_generation + 1,
    })
}

/// 进程 spawn/restart/rebind 的 execution 分配：要求已有 preparation（P>=1），(p,e)->(p,e+1)。
pub fn execution_generation_transition(current: &WasmExecutionIdentityV1) -> Result<WasmExecutionIdentityV1, AdmissionError> {
    if current.preparation_generation < 1 {
        return Err(err(WASM_EXECUTION_IDENTITY_INVALID, "an execution allocation requires an existing preparation"));
    }
    if current.execution_generation >= WASM_U53_MAX {
        return Err(err(WASM_GENERATION_EXHAUSTED, "generation space is exhausted; the Kernel does not wrap, reuse, or substitute zero"));
    }
    Ok(WasmExecutionIdentityV1 {
        sandbox_id: current.sandbox_id.clone(),
        version_id: current.version_id.clone(),
        preparation_generation: current.preparation_generation,
        execution_generation: current.execution_generation + 1,
    })
}

/// 存活/报告健康与 metrics 的 execution 双代次必须 >= 1（E:0 只允许出现在首次分配前）。
pub fn is_alive_execution_identity(identity: &WasmExecutionIdentityV1) -> bool {
    identity.preparation_generation >= 1 && identity.execution_generation >= 1
}

/// 精确四元组比对：任一字段不同即 stale（不 coerce、不部分匹配）。
pub fn matches_execution_fence(expected: &WasmExecutionIdentityV1, reported: &WasmExecutionIdentityV1) -> bool {
    expected == reported
}

pub fn check_execution_fence(expected: &WasmExecutionIdentityV1, reported: &WasmExecutionIdentityV1) -> Result<(), AdmissionError> {
    if matches_execution_fence(expected, reported) {
        Ok(())
    } else {
        Err(err(WASM_EXECUTION_FENCE_STALE, "reported execution tuple differs from the fenced (sandboxId, versionId, preparationGeneration, executionGeneration) identity"))
    }
}

// ---------------------------------------------------------------------------
// ExecutionCommandV1 / ExecutionAcknowledgementV1（双 CAS fence + 快照 digest 绑定）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WasmExecutionOperation {
    Prepare,
    Start,
    Drain,
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCommandV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "commandId")]
    pub command_id: String,
    #[serde(rename = "expectedKernelControlRevision")]
    pub expected_kernel_control_revision: u64,
    #[serde(rename = "expectedJournalRevision")]
    pub expected_journal_revision: u64,
    pub operation: WasmExecutionOperation,
    pub identity: WasmExecutionIdentityV1,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "secretSnapshotRef")]
    pub secret_snapshot_ref: String,
    #[serde(rename = "secretValuesDigest")]
    pub secret_values_digest: String,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
    #[serde(rename = "configSnapshotRef")]
    pub config_snapshot_ref: Option<String>,
    #[serde(rename = "configValuesDigest")]
    pub config_values_digest: Option<String>,
}

pub fn validate_execution_command(command: &ExecutionCommandV1) -> Result<(), AdmissionError> {
    if command.schema_version != 1 {
        return Err(err(EXECUTION_COMMAND_INVALID, "schemaVersion must be exactly 1"));
    }
    validate_uuid_v7(&command.command_id, "commandId")?;
    require_u53(command.expected_kernel_control_revision, 0, "/expectedKernelControlRevision")?;
    require_u53(command.expected_journal_revision, 0, "/expectedJournalRevision")?;
    validate_execution_identity(&command.identity).map_err(|e| err(EXECUTION_COMMAND_INVALID, e.detail))?;
    validate_sha256_hex(&command.package_digest, "/packageDigest")?;
    validate_runtime_binding(&command.runtime_binding).map_err(|e| err(EXECUTION_COMMAND_INVALID, e.detail))?;
    require_u53(command.capability_record_revision, 1, "/capabilityRecordRevision")?;
    validate_sha256_hex(&command.capability_record_hash, "/capabilityRecordHash")?;
    require_u53(command.secret_revision, 0, "/secretRevision")?;
    validate_sha256_hex(&command.secret_snapshot_ref, "/secretSnapshotRef")?;
    validate_sha256_hex(&command.secret_values_digest, "/secretValuesDigest")?;
    require_u53(command.config_revision, 0, "/configRevision")?;
    if let Some(reference) = &command.config_snapshot_ref {
        validate_sha256_hex(reference, "/configSnapshotRef")?;
    }
    if let Some(digest) = &command.config_values_digest {
        validate_sha256_hex(digest, "/configValuesDigest")?;
    }
    check_config_snapshot_coupling(command.config_revision, &command.config_snapshot_ref, &command.config_values_digest)
}

/// commandDigest = hex(SHA-256(UTF8("iweb-execution-command-v1\n" || JCS(command))))；
/// 与 TS computeExecutionCommandDigestV1 字节一致（golden 向量锁定）。
pub fn execution_command_digest_v1(command: &ExecutionCommandV1) -> Result<String, AdmissionError> {
    let payload = jcs_bytes(command).map_err(|e| err(EXECUTION_COMMAND_INVALID, e.detail))?;
    Ok(domain_digest(EXECUTION_COMMAND_DIGEST_DOMAIN, &payload))
}

// ---------------------------------------------------------------------------
// ExecutionCommandV2（add-wasm-host-services P0-3：service-enabled 执行命令 wire）：
// V1 全字段 + runtimeBinding.hostABI 钉 iweb-wasmd-abi@1.1.0 + applicationId +
// matrixRevision:2 + hostServicePolicyDigest + fenceNonce（ExecutionFenceV2）。
// 摘要域 digestV2("iweb-wasm-execution-command-v2", JCS(command))——与 V1 "\n" 域
// 互不碰撞、互不解释；V1 解析器绝不消费 V2 wire，反之亦然（TS 对位：
// packages/contracts/wasm-execution.ts 的 validateExecutionCommandV2 /
// computeExecutionCommandDigestV2，wire 双向 golden 锁定）。
// ---------------------------------------------------------------------------

pub const EXECUTION_COMMAND_V2_INVALID: &str = "EXECUTION_COMMAND_V2_INVALID";
pub const EXECUTION_COMMAND_DIGEST_DOMAIN_V2: &str = "iweb-wasm-execution-command-v2";
/// ExecutionFenceV2.fenceNonce：16 宿主签发字节的 32 位小写十六进制渲染。
pub const WASM_FENCE_NONCE_PATTERN: &str = "^[a-f0-9]{32}$";

fn fence_nonce_regex() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| regex::Regex::new(WASM_FENCE_NONCE_PATTERN).expect("fence nonce regex"))
}

/// V2 runtime binding：与 V1 同形七字段，hostABI 钉 iweb-wasmd-abi@1.1.0
/// （argv@2 标记耦合；wire.rs validate_with_host_abi 的对位语义）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingIdentityV2 {
    pub kind: String,
    #[serde(rename = "catalogRevision")]
    pub catalog_revision: u64,
    #[serde(rename = "catalogHash")]
    pub catalog_hash: String,
    #[serde(rename = "entryKey")]
    pub entry_key: String,
    #[serde(rename = "imageDigest")]
    pub image_digest: String,
    #[serde(rename = "hostABI")]
    pub host_abi: String,
    pub world: String,
}

pub fn validate_runtime_binding_v2(binding: &RuntimeBindingIdentityV2) -> Result<(), AdmissionError> {
    if binding.kind != "wasm" {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/runtimeBinding/kind must be exactly \"wasm\""));
    }
    require_u53(binding.catalog_revision, 1, "/runtimeBinding/catalogRevision")
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    validate_sha256_hex(&binding.catalog_hash, "runtimeBinding/catalogHash").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    if !command_regexes().entry_key.is_match(&binding.entry_key) {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/runtimeBinding/entryKey must match ^[a-z][a-z0-9.-]{0,63}$"));
    }
    if !command_regexes().oci_sha256.is_match(&binding.image_digest) {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/runtimeBinding/imageDigest must be sha256: plus 64 lower-case hex characters"));
    }
    if binding.host_abi != crate::wasm_host_services::HOST_ABI_LITERAL_V2 {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/runtimeBinding/hostABI must be the exact V2 (service-enabled) ABI literal iweb-wasmd-abi@1.1.0"));
    }
    if binding.world != crate::wasm_admission::WASM_WORLD_LITERAL {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/runtimeBinding/world must be the exact matrix world literal"));
    }
    Ok(())
}

/// ExecutionCommandV2 精确键集（deny_unknown_fields + 结构校验；schemaVersion 恒 2）。
/// 第三轮复审（2026-08-28）字段重命名：expectedKernelControlRevision →
/// expectedControlRevision（V2 命令的期望 revision 即 wasm-control-state-v2 的单一
/// controlRevision CAS 计数器；V1 字段名与 V1 wire 一字不改）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCommandV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "commandId")]
    pub command_id: String,
    #[serde(rename = "expectedControlRevision")]
    pub expected_control_revision: u64,
    #[serde(rename = "expectedJournalRevision")]
    pub expected_journal_revision: u64,
    pub operation: WasmExecutionOperation,
    pub identity: WasmExecutionIdentityV1,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV2,
    #[serde(rename = "matrixRevision")]
    pub matrix_revision: u64,
    #[serde(rename = "hostServicePolicyDigest")]
    pub host_service_policy_digest: String,
    #[serde(rename = "fenceNonce")]
    pub fence_nonce: String,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "secretSnapshotRef")]
    pub secret_snapshot_ref: String,
    #[serde(rename = "secretValuesDigest")]
    pub secret_values_digest: String,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
    #[serde(rename = "configSnapshotRef")]
    pub config_snapshot_ref: Option<String>,
    #[serde(rename = "configValuesDigest")]
    pub config_values_digest: Option<String>,
}

pub fn validate_execution_command_v2(command: &ExecutionCommandV2) -> Result<(), AdmissionError> {
    if command.schema_version != 2 {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "schemaVersion must be exactly 2"));
    }
    validate_uuid_v7(&command.command_id, "commandId").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    require_u53(command.expected_control_revision, 0, "/expectedControlRevision")
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    require_u53(command.expected_journal_revision, 0, "/expectedJournalRevision")
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    validate_execution_identity(&command.identity).map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    if !command_regexes().application_id.is_match(&command.application_id) {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"));
    }
    validate_sha256_hex(&command.package_digest, "/packageDigest").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    validate_runtime_binding_v2(&command.runtime_binding).map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    if command.matrix_revision != crate::wasm_host_services::WASM_CAPABILITY_MATRIX_REVISION_2 {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "matrixRevision must be the literal 2 (service-enabled capability matrix)"));
    }
    validate_sha256_hex(&command.host_service_policy_digest, "/hostServicePolicyDigest")
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    if !fence_nonce_regex().is_match(&command.fence_nonce) {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/fenceNonce must be 32 lower-case hex characters (16 host-issued bytes)"));
    }
    require_u53(command.capability_record_revision, 1, "/capabilityRecordRevision")
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    validate_sha256_hex(&command.capability_record_hash, "/capabilityRecordHash").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    require_u53(command.secret_revision, 0, "/secretRevision").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    validate_sha256_hex(&command.secret_snapshot_ref, "/secretSnapshotRef").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    validate_sha256_hex(&command.secret_values_digest, "/secretValuesDigest").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    require_u53(command.config_revision, 0, "/configRevision").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    if let Some(reference) = &command.config_snapshot_ref {
        validate_sha256_hex(reference, "/configSnapshotRef").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    }
    if let Some(digest) = &command.config_values_digest {
        validate_sha256_hex(digest, "/configValuesDigest").map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    }
    check_config_snapshot_coupling(command.config_revision, &command.config_snapshot_ref, &command.config_values_digest)
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))
}

/// commandDigest(V2) = digestV2("iweb-wasm-execution-command-v2", JCS(command))；
/// 与 TS computeExecutionCommandDigestV2 字节一致（golden 向量锁定）。
pub fn execution_command_digest_v2(command: &ExecutionCommandV2) -> Result<String, AdmissionError> {
    let payload = jcs_bytes(command).map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    crate::wasm_host_services::digest_v2(EXECUTION_COMMAND_DIGEST_DOMAIN_V2, &payload)
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))
}

// ---------------------------------------------------------------------------
// 版本联合（第三轮复审，2026-08-28：V2 生产链贯穿）：outbox/journal/query-result 的
// 命令与 ack 按版本联合——判别式恒为 schemaVersion（deny_unknown_fields 使两版本 wire
// 互斥解析），digest/correlate/validate 全部随版本分派；跨版本组合一律拒绝。
// ---------------------------------------------------------------------------

/// 版本联合执行命令（untagged：V1/V2 键集互斥，deny_unknown_fields 保证无歧义）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ExecutionCommand {
    V1(ExecutionCommandV1),
    V2(ExecutionCommandV2),
}

impl ExecutionCommand {
    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }

    pub fn command_id(&self) -> &str {
        match self {
            Self::V1(command) => &command.command_id,
            Self::V2(command) => &command.command_id,
        }
    }

    pub fn operation(&self) -> WasmExecutionOperation {
        match self {
            Self::V1(command) => command.operation,
            Self::V2(command) => command.operation,
        }
    }

    pub fn identity(&self) -> &WasmExecutionIdentityV1 {
        match self {
            Self::V1(command) => &command.identity,
            Self::V2(command) => &command.identity,
        }
    }

    pub fn package_digest(&self) -> &str {
        match self {
            Self::V1(command) => &command.package_digest,
            Self::V2(command) => &command.package_digest,
        }
    }

    pub fn expected_journal_revision(&self) -> u64 {
        match self {
            Self::V1(command) => command.expected_journal_revision,
            Self::V2(command) => command.expected_journal_revision,
        }
    }

    pub fn secret_revision(&self) -> u64 {
        match self {
            Self::V1(command) => command.secret_revision,
            Self::V2(command) => command.secret_revision,
        }
    }

    pub fn secret_snapshot_ref(&self) -> &str {
        match self {
            Self::V1(command) => &command.secret_snapshot_ref,
            Self::V2(command) => &command.secret_snapshot_ref,
        }
    }

    pub fn secret_values_digest(&self) -> &str {
        match self {
            Self::V1(command) => &command.secret_values_digest,
            Self::V2(command) => &command.secret_values_digest,
        }
    }

    pub fn config_revision(&self) -> u64 {
        match self {
            Self::V1(command) => command.config_revision,
            Self::V2(command) => command.config_revision,
        }
    }

    pub fn config_snapshot_ref(&self) -> Option<&str> {
        match self {
            Self::V1(command) => command.config_snapshot_ref.as_deref(),
            Self::V2(command) => command.config_snapshot_ref.as_deref(),
        }
    }

    pub fn config_values_digest(&self) -> Option<&str> {
        match self {
            Self::V1(command) => command.config_values_digest.as_deref(),
            Self::V2(command) => command.config_values_digest.as_deref(),
        }
    }

    pub fn validate(&self) -> Result<(), AdmissionError> {
        match self {
            Self::V1(command) => validate_execution_command(command),
            Self::V2(command) => validate_execution_command_v2(command),
        }
    }
}

/// 版本联合摘要：V1 域一字不变；V2 命令用 digestV2 域（与 TS 双向 golden 锁定）。
pub fn execution_command_digest_versioned(command: &ExecutionCommand) -> Result<String, AdmissionError> {
    match command {
        ExecutionCommand::V1(inner) => execution_command_digest_v1(inner),
        ExecutionCommand::V2(inner) => execution_command_digest_v2(inner),
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AcknowledgementResult {
    Applied,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAcknowledgementV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "commandId")]
    pub command_id: String,
    pub operation: WasmExecutionOperation,
    pub identity: WasmExecutionIdentityV1,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "secretSnapshotRef")]
    pub secret_snapshot_ref: String,
    #[serde(rename = "secretValuesDigest")]
    pub secret_values_digest: String,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
    #[serde(rename = "configSnapshotRef")]
    pub config_snapshot_ref: Option<String>,
    #[serde(rename = "configValuesDigest")]
    pub config_values_digest: Option<String>,
    #[serde(rename = "drainReceiptDigest")]
    pub drain_receipt_digest: Option<String>,
    pub result: AcknowledgementResult,
    #[serde(rename = "failureCode")]
    pub failure_code: Option<String>,
    #[serde(rename = "journalRevision")]
    pub journal_revision: u64,
}

pub fn validate_execution_acknowledgement(ack: &ExecutionAcknowledgementV1) -> Result<(), AdmissionError> {
    if ack.schema_version != 1 {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_INVALID, "schemaVersion must be exactly 1"));
    }
    validate_uuid_v7(&ack.command_id, "commandId")?;
    validate_execution_identity(&ack.identity).map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_INVALID, e.detail))?;
    validate_sha256_hex(&ack.package_digest, "/packageDigest")?;
    validate_runtime_binding(&ack.runtime_binding).map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_INVALID, e.detail))?;
    require_u53(ack.capability_record_revision, 1, "/capabilityRecordRevision")?;
    validate_sha256_hex(&ack.capability_record_hash, "/capabilityRecordHash")?;
    require_u53(ack.secret_revision, 0, "/secretRevision")?;
    validate_sha256_hex(&ack.secret_snapshot_ref, "/secretSnapshotRef")?;
    validate_sha256_hex(&ack.secret_values_digest, "/secretValuesDigest")?;
    require_u53(ack.config_revision, 0, "/configRevision")?;
    if let Some(reference) = &ack.config_snapshot_ref {
        validate_sha256_hex(reference, "/configSnapshotRef")?;
    }
    if let Some(digest) = &ack.config_values_digest {
        validate_sha256_hex(digest, "/configValuesDigest")?;
    }
    if let Some(digest) = &ack.drain_receipt_digest {
        validate_sha256_hex(digest, "/drainReceiptDigest")?;
    }
    if let Some(code) = &ack.failure_code {
        if !command_regexes().failure_code.is_match(code) {
            return Err(err(EXECUTION_ACKNOWLEDGEMENT_INVALID, "failureCode must match ^[A-Z][A-Z0-9_]{0,63}$"));
        }
    }
    require_u53(ack.journal_revision, 0, "/journalRevision")?;
    check_config_snapshot_coupling(ack.config_revision, &ack.config_snapshot_ref, &ack.config_values_digest)?;
    // failureCode 为 null 当且仅当 result 为 applied。
    match (ack.result, &ack.failure_code) {
        (AcknowledgementResult::Applied, Some(_)) => Err(err(EXECUTION_ACKNOWLEDGEMENT_INVALID, "an applied acknowledgement must carry failureCode null")),
        (AcknowledgementResult::Rejected, None) => Err(err(EXECUTION_ACKNOWLEDGEMENT_INVALID, "a rejected acknowledgement must carry a bounded failureCode")),
        _ => Ok(()),
    }?;
    // drainReceiptDigest 仅在 operation:"drain" 且 result:"applied" 时非空。
    let applied_drain = ack.operation == WasmExecutionOperation::Drain && ack.result == AcknowledgementResult::Applied;
    if applied_drain && ack.drain_receipt_digest.is_none() {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_INVALID, "an applied drain acknowledgement must carry the DrainReceiptV1 digest"));
    }
    if !applied_drain && ack.drain_receipt_digest.is_some() {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_INVALID, "drainReceiptDigest is non-null only for operation drain with result applied"));
    }
    Ok(())
}

/// Kernel 只接受 commandId、全部回显命令字段仍然匹配的 acknowledgement；
/// 任一错配即 stale（绝不路由）。对位 TS correlateExecutionAcknowledgement。
pub fn correlate_acknowledgement(command: &ExecutionCommandV1, ack: &ExecutionAcknowledgementV1) -> Result<(), AdmissionError> {
    if ack.command_id != command.command_id {
        return Err(err("COMMAND_ID_MISMATCH", "acknowledgement command ID does not match the command"));
    }
    if ack.operation != command.operation {
        return Err(err("OPERATION_MISMATCH", "acknowledgement operation does not match the command"));
    }
    if ack.identity != command.identity {
        return Err(err("IDENTITY_MISMATCH", "acknowledgement execution identity does not match the command"));
    }
    if ack.package_digest != command.package_digest {
        return Err(err("PACKAGE_DIGEST_MISMATCH", "acknowledgement package digest does not match the command"));
    }
    if ack.runtime_binding != command.runtime_binding {
        return Err(err("RUNTIME_BINDING_MISMATCH", "acknowledgement runtime binding does not match the command"));
    }
    if ack.capability_record_revision != command.capability_record_revision || ack.capability_record_hash != command.capability_record_hash {
        return Err(err("CAPABILITY_RECORD_MISMATCH", "acknowledgement capability record pin does not match the command"));
    }
    if ack.secret_revision != command.secret_revision || ack.secret_snapshot_ref != command.secret_snapshot_ref || ack.secret_values_digest != command.secret_values_digest {
        return Err(err("SECRET_SNAPSHOT_MISMATCH", "acknowledgement secret snapshot fields do not match the command"));
    }
    if ack.config_revision != command.config_revision || ack.config_snapshot_ref != command.config_snapshot_ref || ack.config_values_digest != command.config_values_digest {
        return Err(err("CONFIG_SNAPSHOT_MISMATCH", "acknowledgement config snapshot fields do not match the command"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ExecutionAcknowledgementV2 + 版本联合（第三轮复审 2026-08-28，V2 生产链贯穿）：
// V2 命令的 ack 回执——V1 ack 全字段回显语义 + applicationId/matrixRevision:2/
// hostServicePolicyDigest/fenceNonce（HostServiceIdentityV2/ExecutionFenceV2 增量）+
// ABI 1.1.0 binding。V1 命令绝不产出 V2 ack，反之亦然。
// ---------------------------------------------------------------------------

pub const EXECUTION_ACKNOWLEDGEMENT_V2_INVALID: &str = "EXECUTION_ACKNOWLEDGEMENT_V2_INVALID";
pub const ACKNOWLEDGEMENT_VERSION_MISMATCH: &str = "ACKNOWLEDGEMENT_VERSION_MISMATCH";

/// ExecutionAcknowledgementV2 精确键集（schemaVersion 恒 2）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAcknowledgementV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "commandId")]
    pub command_id: String,
    pub operation: WasmExecutionOperation,
    pub identity: WasmExecutionIdentityV1,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV2,
    #[serde(rename = "matrixRevision")]
    pub matrix_revision: u64,
    #[serde(rename = "hostServicePolicyDigest")]
    pub host_service_policy_digest: String,
    #[serde(rename = "fenceNonce")]
    pub fence_nonce: String,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "secretSnapshotRef")]
    pub secret_snapshot_ref: String,
    #[serde(rename = "secretValuesDigest")]
    pub secret_values_digest: String,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
    #[serde(rename = "configSnapshotRef")]
    pub config_snapshot_ref: Option<String>,
    #[serde(rename = "configValuesDigest")]
    pub config_values_digest: Option<String>,
    #[serde(rename = "drainReceiptDigest")]
    pub drain_receipt_digest: Option<String>,
    pub result: AcknowledgementResult,
    #[serde(rename = "failureCode")]
    pub failure_code: Option<String>,
    #[serde(rename = "journalRevision")]
    pub journal_revision: u64,
}

pub fn validate_execution_acknowledgement_v2(ack: &ExecutionAcknowledgementV2) -> Result<(), AdmissionError> {
    let v2 = |result: Result<(), AdmissionError>| result.map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail));
    if ack.schema_version != 2 {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "schemaVersion must be exactly 2"));
    }
    validate_uuid_v7(&ack.command_id, "commandId").map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    v2(validate_execution_identity(&ack.identity))?;
    if !command_regexes().application_id.is_match(&ack.application_id) {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "/applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"));
    }
    validate_sha256_hex(&ack.package_digest, "/packageDigest").map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    v2(validate_runtime_binding_v2(&ack.runtime_binding))?;
    if ack.matrix_revision != crate::wasm_host_services::WASM_CAPABILITY_MATRIX_REVISION_2 {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "matrixRevision must be the literal 2 (service-enabled capability matrix)"));
    }
    validate_sha256_hex(&ack.host_service_policy_digest, "/hostServicePolicyDigest")
        .map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    if !fence_nonce_regex().is_match(&ack.fence_nonce) {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "/fenceNonce must be 32 lower-case hex characters (16 host-issued bytes)"));
    }
    require_u53(ack.capability_record_revision, 1, "/capabilityRecordRevision")
        .and_then(|_| validate_sha256_hex(&ack.capability_record_hash, "/capabilityRecordHash"))
        .map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    require_u53(ack.secret_revision, 0, "/secretRevision")
        .and_then(|_| validate_sha256_hex(&ack.secret_snapshot_ref, "/secretSnapshotRef"))
        .and_then(|_| validate_sha256_hex(&ack.secret_values_digest, "/secretValuesDigest"))
        .map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    require_u53(ack.config_revision, 0, "/configRevision").map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    if let Some(reference) = &ack.config_snapshot_ref {
        validate_sha256_hex(reference, "/configSnapshotRef").map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    }
    if let Some(digest) = &ack.config_values_digest {
        validate_sha256_hex(digest, "/configValuesDigest").map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    }
    if let Some(digest) = &ack.drain_receipt_digest {
        validate_sha256_hex(digest, "/drainReceiptDigest").map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    }
    if let Some(code) = &ack.failure_code {
        if !command_regexes().failure_code.is_match(code) {
            return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "failureCode must match ^[A-Z][A-Z0-9_]{0,63}$"));
        }
    }
    require_u53(ack.journal_revision, 0, "/journalRevision").map_err(|e| err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, e.detail))?;
    v2(check_config_snapshot_coupling(ack.config_revision, &ack.config_snapshot_ref, &ack.config_values_digest))?;
    match (ack.result, &ack.failure_code) {
        (AcknowledgementResult::Applied, Some(_)) => {
            return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "an applied acknowledgement must carry failureCode null"))
        }
        (AcknowledgementResult::Rejected, None) => {
            return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "a rejected acknowledgement must carry a bounded failureCode"))
        }
        _ => {}
    }
    let applied_drain = ack.operation == WasmExecutionOperation::Drain && ack.result == AcknowledgementResult::Applied;
    if applied_drain && ack.drain_receipt_digest.is_none() {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "an applied drain acknowledgement must carry the DrainReceiptV1 digest"));
    }
    if !applied_drain && ack.drain_receipt_digest.is_some() {
        return Err(err(EXECUTION_ACKNOWLEDGEMENT_V2_INVALID, "drainReceiptDigest is non-null only for operation drain with result applied"));
    }
    Ok(())
}

/// 版本联合 ack（untagged；schemaVersion 互斥）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ExecutionAcknowledgement {
    V1(ExecutionAcknowledgementV1),
    V2(ExecutionAcknowledgementV2),
}

impl ExecutionAcknowledgement {
    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }

    pub fn command_id(&self) -> &str {
        match self {
            Self::V1(ack) => &ack.command_id,
            Self::V2(ack) => &ack.command_id,
        }
    }

    pub fn journal_revision(&self) -> u64 {
        match self {
            Self::V1(ack) => ack.journal_revision,
            Self::V2(ack) => ack.journal_revision,
        }
    }

    pub fn validate(&self) -> Result<(), AdmissionError> {
        match self {
            Self::V1(ack) => validate_execution_acknowledgement(ack),
            Self::V2(ack) => validate_execution_acknowledgement_v2(ack),
        }
    }
}

/// V2 命令 ↔ V2 ack 的 echo 相关性（对位 correlate_acknowledgement + V2 增量字段）。
pub fn correlate_acknowledgement_v2(command: &ExecutionCommandV2, ack: &ExecutionAcknowledgementV2) -> Result<(), AdmissionError> {
    if ack.command_id != command.command_id {
        return Err(err("COMMAND_ID_MISMATCH", "acknowledgement command ID does not match the command"));
    }
    if ack.operation != command.operation {
        return Err(err("OPERATION_MISMATCH", "acknowledgement operation does not match the command"));
    }
    if ack.identity != command.identity {
        return Err(err("IDENTITY_MISMATCH", "acknowledgement execution identity does not match the command"));
    }
    if ack.application_id != command.application_id {
        return Err(err("IDENTITY_MISMATCH", "acknowledgement applicationId does not match the command"));
    }
    if ack.package_digest != command.package_digest {
        return Err(err("PACKAGE_DIGEST_MISMATCH", "acknowledgement package digest does not match the command"));
    }
    if ack.runtime_binding != command.runtime_binding {
        return Err(err("RUNTIME_BINDING_MISMATCH", "acknowledgement runtime binding does not match the command"));
    }
    if ack.matrix_revision != command.matrix_revision {
        return Err(err("IDENTITY_MISMATCH", "acknowledgement matrixRevision does not match the command"));
    }
    if ack.host_service_policy_digest != command.host_service_policy_digest {
        return Err(err("POLICY_MISMATCH", "acknowledgement hostServicePolicyDigest does not match the command"));
    }
    if ack.fence_nonce != command.fence_nonce {
        return Err(err("IDENTITY_MISMATCH", "acknowledgement fenceNonce does not match the command"));
    }
    if ack.capability_record_revision != command.capability_record_revision || ack.capability_record_hash != command.capability_record_hash {
        return Err(err("CAPABILITY_RECORD_MISMATCH", "acknowledgement capability record pin does not match the command"));
    }
    if ack.secret_revision != command.secret_revision || ack.secret_snapshot_ref != command.secret_snapshot_ref || ack.secret_values_digest != command.secret_values_digest {
        return Err(err("SECRET_SNAPSHOT_MISMATCH", "acknowledgement secret snapshot fields do not match the command"));
    }
    if ack.config_revision != command.config_revision || ack.config_snapshot_ref != command.config_snapshot_ref || ack.config_values_digest != command.config_values_digest {
        return Err(err("CONFIG_SNAPSHOT_MISMATCH", "acknowledgement config snapshot fields do not match the command"));
    }
    Ok(())
}

/// 版本联合 correlate：同版本逐字段 echo；跨版本一律 VERSION_MISMATCH（绝不跨版本解释）。
pub fn correlate_acknowledgement_versioned(command: &ExecutionCommand, ack: &ExecutionAcknowledgement) -> Result<(), AdmissionError> {
    match (command, ack) {
        (ExecutionCommand::V1(command), ExecutionAcknowledgement::V1(ack)) => correlate_acknowledgement(command, ack),
        (ExecutionCommand::V2(command), ExecutionAcknowledgement::V2(ack)) => correlate_acknowledgement_v2(command, ack),
        _ => Err(err(ACKNOWLEDGEMENT_VERSION_MISMATCH, "the acknowledgement schemaVersion must equal the command schemaVersion; cross-version echo is rejected")),
    }
}

// ---------------------------------------------------------------------------
// DrainReceiptV1（任务 7.6）：drain 完成的 typed receipt，Kernel retired 的唯一前置
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WasmDrainResult {
    Drained,
    ForcedKill,
}

/// DrainReceiptV1 精确键集；时间戳保留 RFC3339-UTC 原串（receiptDigest 字节保真）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DrainReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "commandId")]
    pub command_id: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub execution: WasmExecutionIdentityV1,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "routeGeneration")]
    pub route_generation: u64,
    #[serde(rename = "drainedRequestCount")]
    pub drained_request_count: u64,
    #[serde(rename = "deadlineAt")]
    pub deadline_at: String,
    #[serde(rename = "forcedKillAt")]
    pub forced_kill_at: Option<String>,
    pub result: WasmDrainResult,
    #[serde(rename = "completedAt")]
    pub completed_at: String,
    #[serde(rename = "journalRevision")]
    pub journal_revision: u64,
    #[serde(rename = "receiptDigest")]
    pub receipt_digest: String,
}

impl DrainReceiptV1 {
    pub fn deadline_at_epoch_millis(&self) -> Result<u64, AdmissionError> {
        parse_rfc3339_utc_millis(&self.deadline_at).map_err(|e| err(DRAIN_RECEIPT_INVALID, format!("/deadlineAt: {}", e.detail)))
    }

    pub fn forced_kill_at_epoch_millis(&self) -> Result<Option<u64>, AdmissionError> {
        self.forced_kill_at
            .as_deref()
            .map(parse_rfc3339_utc_millis)
            .transpose()
            .map_err(|e| err(DRAIN_RECEIPT_INVALID, format!("/forcedKillAt: {}", e.detail)))
    }

    pub fn completed_at_epoch_millis(&self) -> Result<u64, AdmissionError> {
        parse_rfc3339_utc_millis(&self.completed_at).map_err(|e| err(DRAIN_RECEIPT_INVALID, format!("/completedAt: {}", e.detail)))
    }
}

/// receiptDigest = hex(SHA-256(UTF8("iweb-drain-receipt-v1\n" ||
/// JCS(receipt with receiptDigest omitted))))；对位 TS computeDrainReceiptDigestV1
/// 字节一致（golden 向量锁定）。
pub fn drain_receipt_digest_v1(receipt: &DrainReceiptV1) -> Result<String, AdmissionError> {
    let mut value = serde_json::to_value(receipt).map_err(|e| err(DRAIN_RECEIPT_INVALID, format!("the drain receipt is not serializable as JSON: {e}")))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| err(DRAIN_RECEIPT_INVALID, "the drain receipt must serialize to a JSON object"))?;
    map.remove("receiptDigest");
    let payload = jcs_bytes(&value).map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    Ok(domain_digest(DRAIN_RECEIPT_DIGEST_DOMAIN, &payload))
}

/// 结构校验：精确字段域 + forcedKillAt 非空当且仅当 forced-kill 且不早于 deadline +
/// receiptDigest 必须可由其余字段精确复算（fail-closed）。
pub fn validate_drain_receipt(receipt: &DrainReceiptV1) -> Result<(), AdmissionError> {
    if receipt.schema_version != 1 {
        return Err(err(DRAIN_RECEIPT_INVALID, "schemaVersion must be exactly 1"));
    }
    validate_uuid_v7(&receipt.command_id, "commandId").map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    validate_application_id(&receipt.application_id)?;
    validate_execution_identity(&receipt.execution).map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    validate_sha256_hex(&receipt.package_digest, "/packageDigest").map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    validate_runtime_binding(&receipt.runtime_binding).map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    require_u53(receipt.route_generation, 0, "/routeGeneration").map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    require_u53(receipt.drained_request_count, 0, "/drainedRequestCount").map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    require_u53(receipt.journal_revision, 0, "/journalRevision").map_err(|e| err(DRAIN_RECEIPT_INVALID, e.detail))?;
    let deadline_at = receipt.deadline_at_epoch_millis()?;
    receipt.completed_at_epoch_millis()?;
    let forced_kill_at = receipt.forced_kill_at_epoch_millis()?;
    // forcedKillAt 非空当且仅当 result:"forced-kill"；非空时不早于 deadlineAt。
    match (receipt.result, forced_kill_at) {
        (WasmDrainResult::ForcedKill, None) => {
            return Err(err(DRAIN_RECEIPT_INVALID, "forcedKillAt is non-null if and only if result is forced-kill"));
        }
        (WasmDrainResult::Drained, Some(_)) => {
            return Err(err(DRAIN_RECEIPT_INVALID, "a normal drained receipt carries forcedKillAt null"));
        }
        (WasmDrainResult::ForcedKill, Some(at)) if at < deadline_at => {
            return Err(err(DRAIN_RECEIPT_INVALID, "forcedKillAt is at or after deadlineAt"));
        }
        _ => {}
    }
    let expected_digest = drain_receipt_digest_v1(receipt)?;
    if receipt.receipt_digest != expected_digest {
        return Err(err(DRAIN_RECEIPT_INVALID, "receiptDigest does not equal hex(SHA-256(UTF8(\"iweb-drain-receipt-v1\\n\" || JCS(receipt with receiptDigest omitted))))"));
    }
    Ok(())
}

/// receipt 与其 drain 命令的 echo 比对（commandId、完整 execution tuple、package、
/// binding；任一错配即 DRAIN_RECEIPT_INVALID——spec "mismatched identity" 条款）。
pub fn correlate_drain_receipt(command: &ExecutionCommandV1, receipt: &DrainReceiptV1) -> Result<(), AdmissionError> {
    if command.operation != WasmExecutionOperation::Drain {
        return Err(err(DRAIN_RECEIPT_INVALID, "a drain receipt correlates only with operation drain"));
    }
    if receipt.command_id != command.command_id {
        return Err(err(DRAIN_RECEIPT_INVALID, "the receipt commandId does not match the drain command"));
    }
    if receipt.execution != command.identity {
        return Err(err(DRAIN_RECEIPT_INVALID, "the receipt execution identity does not match the drain command"));
    }
    if receipt.package_digest != command.package_digest {
        return Err(err(DRAIN_RECEIPT_INVALID, "the receipt package digest does not match the drain command"));
    }
    if receipt.runtime_binding != command.runtime_binding {
        return Err(err(DRAIN_RECEIPT_INVALID, "the receipt runtime binding does not match the drain command"));
    }
    Ok(())
}

/// applied drain ack 与 receipt 的一致性：ack 的 drainReceiptDigest 是该 receipt 的
/// 精确 digest（spec ExecutionAcknowledgementV1 条款）。journalRevision 相等性不在此
/// 强制——receipt 与 ack 是否同一条 completion 落盘由 supervisor 生产布局决定（接线
/// 批次固定后可再收紧）。
pub fn correlate_drain_receipt_with_acknowledgement(ack: &ExecutionAcknowledgementV1, receipt: &DrainReceiptV1) -> Result<(), AdmissionError> {
    if ack.operation != WasmExecutionOperation::Drain || ack.result != AcknowledgementResult::Applied {
        return Err(err(DRAIN_RECEIPT_INVALID, "only an applied drain acknowledgement carries a drain receipt"));
    }
    if ack.drain_receipt_digest.as_deref() != Some(receipt.receipt_digest.as_str()) {
        return Err(err(DRAIN_RECEIPT_INVALID, "the receipt digest must equal the acknowledgement drainReceiptDigest"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// query-result（Kernel 读 supervisor journal 的唯一视图）
// ---------------------------------------------------------------------------

/// supervisor journal 的 received 条目（query-result 的 received 字段）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandReceivedV1 {
    pub kind: String,
    #[serde(rename = "commandId")]
    pub command_id: String,
    #[serde(rename = "commandDigest")]
    pub command_digest: String,
    /// 版本联合命令（V2 生产链）：V1/V2 wire 互斥解析；digest 复算随版本切域。
    pub command: ExecutionCommand,
    #[serde(rename = "snapshotHandoffDigest")]
    pub snapshot_handoff_digest: Option<String>,
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    #[serde(rename = "journalRevision")]
    pub journal_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandQueryResultV1 {
    pub kind: String,
    #[serde(rename = "commandId")]
    pub command_id: String,
    pub status: String,
    pub received: Option<CommandReceivedV1>,
    pub acknowledgement: Option<ExecutionAcknowledgement>,
}

/// 解析 {kind:"query-result",...} body 并做耦合校验（received 当且仅当非 missing；
/// acknowledgement 当且仅当 completed；received.commandDigest 必须可由其 command 复算）。
pub fn parse_command_query_result(bytes: &[u8]) -> Result<CommandQueryResultV1, AdmissionError> {
    let parsed: CommandQueryResultV1 = serde_json::from_slice(bytes)
        .map_err(|e| err(EXECUTION_QUERY_RESULT_INVALID, format!("query-result bytes do not parse as the typed record: {e}")))?;
    if parsed.kind != "query-result" {
        return Err(err(EXECUTION_QUERY_RESULT_INVALID, "kind must be exactly \"query-result\""));
    }
    validate_uuid_v7(&parsed.command_id, "commandId")?;
    match parsed.status.as_str() {
        "missing" => {
            if parsed.received.is_some() || parsed.acknowledgement.is_some() {
                return Err(err(EXECUTION_QUERY_RESULT_INVALID, "a missing command carries neither received nor acknowledgement"));
            }
        }
        "received" => {
            if parsed.received.is_none() {
                return Err(err(EXECUTION_QUERY_RESULT_INVALID, "received must be the exact CommandReceivedV1 when status is received"));
            }
            if parsed.acknowledgement.is_some() {
                return Err(err(EXECUTION_QUERY_RESULT_INVALID, "acknowledgement is non-null if and only if status is completed"));
            }
        }
        "completed" => {
            if parsed.received.is_none() {
                return Err(err(EXECUTION_QUERY_RESULT_INVALID, "received must be the exact CommandReceivedV1 when status is completed"));
            }
            if parsed.acknowledgement.is_none() {
                return Err(err(EXECUTION_QUERY_RESULT_INVALID, "acknowledgement must be non-null when status is completed"));
            }
        }
        other => return Err(err(EXECUTION_QUERY_RESULT_INVALID, format!("status must be missing, received, or completed (got {other})"))),
    }
    if let Some(received) = &parsed.received {
        if received.kind != "command-received" {
            return Err(err(EXECUTION_QUERY_RESULT_INVALID, "received kind must be exactly \"command-received\""));
        }
        if received.command_id != parsed.command_id {
            return Err(err(EXECUTION_QUERY_RESULT_INVALID, "received commandId must match the query-result commandId"));
        }
        let digest = execution_command_digest_versioned(&received.command)?;
        if digest != received.command_digest {
            return Err(err(EXECUTION_QUERY_RESULT_INVALID, "received commandDigest must equal the recomputed command digest"));
        }
        parse_rfc3339_utc_millis(&received.received_at).map_err(|e| err(EXECUTION_QUERY_RESULT_INVALID, e.detail))?;
        require_u53(received.journal_revision, 0, "/received/journalRevision")?;
    }
    if let Some(ack) = &parsed.acknowledgement {
        ack.validate().map_err(|e| err(EXECUTION_QUERY_RESULT_INVALID, e.detail))?;
        if ack.command_id() != parsed.command_id {
            return Err(err(EXECUTION_QUERY_RESULT_INVALID, "acknowledgement commandId must match the query-result commandId"));
        }
    }
    Ok(parsed)
}

/// Kernel 对单一 command 的 journal 观察（由 CommandQueryV1 的响应推导）。
#[derive(Debug, Clone)]
pub enum JournalObservation {
    Missing,
    ReceivedIncomplete,
    Completed(Box<ExecutionAcknowledgement>),
}

/// 从 query-result 推导 journal 观察，并对照 Kernel 自己授权的 outbox command：
/// received 条目的命令字节（以 digest 为准）必须与 outbox command 完全一致，
/// 否则是 EXECUTION_COMMAND_ID_CONFLICT（supervisor 侧 byte-identical replay 判据）。
/// 版本联合：digest 与 correlate 均按命令代际分派（V2 生产链）；跨版本 ack 在
/// correlate_acknowledgement_versioned 处 fail-closed。
pub fn journal_observation_from_query(outbox_command: &ExecutionCommand, query: &CommandQueryResultV1) -> Result<JournalObservation, AdmissionError> {
    if query.command_id != outbox_command.command_id() {
        return Err(err(EXECUTION_COMMAND_ID_CONFLICT, "query-result commandId does not match the authorized outbox command"));
    }
    let expected_digest = execution_command_digest_versioned(outbox_command)?;
    match query.status.as_str() {
        "missing" => Ok(JournalObservation::Missing),
        "received" => {
            let received = query.received.as_ref().ok_or_else(|| err(EXECUTION_QUERY_RESULT_INVALID, "status received requires the exact CommandReceivedV1"))?;
            if received.command_digest != expected_digest || &received.command != outbox_command {
                return Err(err(EXECUTION_COMMAND_ID_CONFLICT, "the journal received a differing command body for this commandId; no replay or projection occurs"));
            }
            Ok(JournalObservation::ReceivedIncomplete)
        }
        "completed" => {
            let received = query.received.as_ref().ok_or_else(|| err(EXECUTION_QUERY_RESULT_INVALID, "status completed requires the exact CommandReceivedV1"))?;
            if received.command_digest != expected_digest || &received.command != outbox_command {
                return Err(err(EXECUTION_COMMAND_ID_CONFLICT, "the journal completed a differing command body for this commandId; no replay or projection occurs"));
            }
            let ack = query.acknowledgement.as_ref().ok_or_else(|| err(EXECUTION_QUERY_RESULT_INVALID, "status completed requires the stored acknowledgement"))?;
            correlate_acknowledgement_versioned(outbox_command, ack)?;
            Ok(JournalObservation::Completed(Box::new(ack.clone())))
        }
        other => Err(err(EXECUTION_QUERY_RESULT_INVALID, format!("unknown query-result status: {other}"))),
    }
}

// ---------------------------------------------------------------------------
// Kernel 命令生成（从 admission registry + 控制态视图推导 expected revisions 与 tuple）
// ---------------------------------------------------------------------------

/// Kernel 生成一条 owner-authorized 命令所需的全部权威输入。
/// `control_revision` 是当前 wasm controlRevision（outbox 追加 CAS 以它为 expected）；
/// `journal_head` 是 Kernel 从 query/replay 得知的 supervisor journal 头（supervisor 侧
/// received CAS 以它为 expected）；两者是独立计数器，任何一方不得替代另一方。
pub struct KernelCommandPlanInput<'a> {
    pub command_id: &'a str,
    pub operation: WasmExecutionOperation,
    pub control_revision: u64,
    pub journal_head: u64,
    pub sandbox_id: &'a str,
    /// admission registry 的版本行（versionId/packageDigest/runtimeBinding 权威）。
    pub version_row: &'a crate::wasm_admission::WasmVersionRegistryRow,
    /// 产出该行的 AdmissionProofV1 的 capability pin（registry 行不重复承载）。
    pub capability_record_revision: u64,
    pub capability_record_hash: &'a str,
    pub secret_revision: u64,
    pub secret_snapshot_ref: &'a str,
    pub secret_values_digest: &'a str,
    pub config_revision: u64,
    pub config_snapshot_ref: Option<&'a str>,
    pub config_values_digest: Option<&'a str>,
    /// 本次分配前的当前 (P,E)（per-sandbox 双代次时钟）。
    pub current_generations: WasmExecutionIdentityV1,
}

#[derive(Debug)]
pub struct PlannedExecutionCommand {
    pub command: ExecutionCommandV1,
    /// 分配后的 (P,E)：prepare/start 推进；drain/stop 沿用目标 execution 的当前 tuple。
    pub next_generations: WasmExecutionIdentityV1,
    pub command_digest: String,
}

/// Kernel 侧命令生成器：按操作分配双代次、推导 expected revisions 与 full tuple，
/// 并复算 commandDigest。supervisor 只消费该命令——它不能铸 version、不能改 route
/// pointer（本函数不触碰 active pointer；激活属 2.4 的 route CAS）。
pub fn plan_execution_command(input: &KernelCommandPlanInput<'_>) -> Result<PlannedExecutionCommand, AdmissionError> {
    validate_uuid_v7(input.command_id, "commandId")?;
    validate_sandbox_id(input.sandbox_id)?;
    if input.current_generations.sandbox_id != input.sandbox_id || input.current_generations.version_id != input.version_row.version_id {
        return Err(err(WASM_EXECUTION_IDENTITY_INVALID, "the generation clock must belong to the same sandbox and registry version"));
    }
    if compose_wasm_version_id(&input.version_row.identity.digest, input.version_row.identity.sequence) != input.version_row.version_id {
        return Err(err(EXECUTION_COMMAND_INVALID, "registry row versionId must be its identity digest-sequence label"));
    }
    let next_generations = match input.operation {
        WasmExecutionOperation::Prepare => prepare_generation_transition(&input.current_generations)?,
        WasmExecutionOperation::Start => execution_generation_transition(&input.current_generations)?,
        WasmExecutionOperation::Drain | WasmExecutionOperation::Stop => {
            if !is_alive_execution_identity(&input.current_generations) {
                return Err(err(WASM_EXECUTION_FENCE_STALE, "drain and stop require an alive execution (both generations >= 1)"));
            }
            input.current_generations.clone()
        }
    };
    let command = ExecutionCommandV1 {
        schema_version: 1,
        command_id: input.command_id.to_string(),
        expected_kernel_control_revision: input.control_revision,
        expected_journal_revision: input.journal_head,
        operation: input.operation,
        identity: next_generations.clone(),
        package_digest: input.version_row.package_digest.clone(),
        runtime_binding: input.version_row.runtime_binding.clone(),
        capability_record_revision: input.capability_record_revision,
        capability_record_hash: input.capability_record_hash.to_string(),
        secret_revision: input.secret_revision,
        secret_snapshot_ref: input.secret_snapshot_ref.to_string(),
        secret_values_digest: input.secret_values_digest.to_string(),
        config_revision: input.config_revision,
        config_snapshot_ref: input.config_snapshot_ref.map(str::to_string),
        config_values_digest: input.config_values_digest.map(str::to_string),
    };
    validate_execution_command(&command)?;
    let command_digest = execution_command_digest_v1(&command)?;
    Ok(PlannedExecutionCommand { command, next_generations, command_digest })
}

/// V2（service-enabled）命令生成输入（第三轮复审 2026-08-28，V2 生产链）：
/// `base` 是同一 admission 行的 V1 规划输入（version_row/runtimeBinding 仍是 admission
/// 事实——binding.hostABI 在 admission 侧恒 1.0.0）；V2 增量由本结构显式携带。
pub struct KernelCommandPlanInputV2<'a> {
    pub base: KernelCommandPlanInput<'a>,
    /// HostServiceIdentityV2.applicationId（argv@2 context 的宿主注入身份）。
    pub application_id: &'a str,
    /// resolved HostServicePolicyV2 的 policyDigest（Kernel 只授权它准入过的策略字节）。
    pub host_service_policy_digest: &'a str,
}

#[derive(Debug)]
pub struct PlannedExecutionCommandV2 {
    pub command: ExecutionCommandV2,
    /// 分配后的 (P,E)（与 V1 同一双代次迁移；V2 只增身份面，不改代次语义）。
    pub next_generations: WasmExecutionIdentityV1,
    pub command_digest: String,
}

/// V2 runtime binding 推导：admission 的 V1 binding（ABI 1.0.0）+ V2 ABI 字面量
///（1.1.0）。除 hostABI 外逐字段保留 admission 事实；推导产物必须过
/// validate_runtime_binding_v2（fail-closed，绝不半推导）。
fn runtime_binding_v2_from_v1(binding: &RuntimeBindingIdentityV1) -> Result<RuntimeBindingIdentityV2, AdmissionError> {
    let derived = RuntimeBindingIdentityV2 {
        kind: binding.kind.clone(),
        catalog_revision: binding.catalog_revision,
        catalog_hash: binding.catalog_hash.clone(),
        entry_key: binding.entry_key.clone(),
        image_digest: binding.image_digest.clone(),
        host_abi: crate::wasm_host_services::HOST_ABI_LITERAL_V2.to_string(),
        world: binding.world.clone(),
    };
    validate_runtime_binding_v2(&derived)?;
    Ok(derived)
}

/// ExecutionFenceV2.fenceNonce 的 Kernel 派生：对 (applicationId, versionId, P, E) 的
/// 域分离 SHA-256 前 16 字节的 32 位小写十六进制渲染（host-issued；确定性保证 outbox
/// 重建/恢复推导出同一命令字节——outbox 持久化后优先复用已存命令，派生只是首次生成）。
pub fn plan_fence_nonce_v2(application_id: &str, version_id: &str, preparation: u64, execution: u64) -> String {
    let input = format!("iweb-wasm-fence-nonce-v2\n{application_id}\n{version_id}\n{preparation}\n{execution}");
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    };
    digest[..32].to_string()
}

/// Kernel 侧 V2 命令生成器：按 admission 行代际分选的另一支——V2 行（携带
/// host-service policy）生成 ExecutionCommandV2（ABI 1.1.0 binding + applicationId +
/// matrixRevision:2 + hostServicePolicyDigest + fenceNonce）；双代次分配、expected
/// revisions 推导与 digest 复算语义与 plan_execution_command 完全一致。
pub fn plan_execution_command_v2(input: &KernelCommandPlanInputV2<'_>) -> Result<PlannedExecutionCommandV2, AdmissionError> {
    let base = &input.base;
    // V1 层的全部结构性校验（命令 ID、sandbox/registry 行一致、versionId 复算、双代次
    // 迁移与存活判据）先行；失败码与 V1 逐字一致。
    validate_uuid_v7(base.command_id, "commandId")?;
    validate_sandbox_id(base.sandbox_id)?;
    if base.current_generations.sandbox_id != base.sandbox_id || base.current_generations.version_id != base.version_row.version_id {
        return Err(err(WASM_EXECUTION_IDENTITY_INVALID, "the generation clock must belong to the same sandbox and registry version"));
    }
    if compose_wasm_version_id(&base.version_row.identity.digest, base.version_row.identity.sequence) != base.version_row.version_id {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "registry row versionId must be its identity digest-sequence label"));
    }
    let next_generations = match base.operation {
        WasmExecutionOperation::Prepare => prepare_generation_transition(&base.current_generations)?,
        WasmExecutionOperation::Start => execution_generation_transition(&base.current_generations)?,
        WasmExecutionOperation::Drain | WasmExecutionOperation::Stop => {
            if !is_alive_execution_identity(&base.current_generations) {
                return Err(err(WASM_EXECUTION_FENCE_STALE, "drain and stop require an alive execution (both generations >= 1)"));
            }
            base.current_generations.clone()
        }
    };
    if !command_regexes().application_id.is_match(input.application_id) {
        return Err(err(EXECUTION_COMMAND_V2_INVALID, "/applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"));
    }
    validate_sha256_hex(input.host_service_policy_digest, "/hostServicePolicyDigest")
        .map_err(|e| err(EXECUTION_COMMAND_V2_INVALID, e.detail))?;
    let runtime_binding = runtime_binding_v2_from_v1(&base.version_row.runtime_binding)?;
    let command = ExecutionCommandV2 {
        schema_version: 2,
        command_id: base.command_id.to_string(),
        expected_control_revision: base.control_revision,
        expected_journal_revision: base.journal_head,
        operation: base.operation,
        identity: next_generations.clone(),
        application_id: input.application_id.to_string(),
        package_digest: base.version_row.package_digest.clone(),
        runtime_binding,
        matrix_revision: crate::wasm_host_services::WASM_CAPABILITY_MATRIX_REVISION_2,
        host_service_policy_digest: input.host_service_policy_digest.to_string(),
        fence_nonce: plan_fence_nonce_v2(
            input.application_id,
            &base.version_row.version_id,
            next_generations.preparation_generation,
            next_generations.execution_generation,
        ),
        capability_record_revision: base.capability_record_revision,
        capability_record_hash: base.capability_record_hash.to_string(),
        secret_revision: base.secret_revision,
        secret_snapshot_ref: base.secret_snapshot_ref.to_string(),
        secret_values_digest: base.secret_values_digest.to_string(),
        config_revision: base.config_revision,
        config_snapshot_ref: base.config_snapshot_ref.map(str::to_string),
        config_values_digest: base.config_values_digest.map(str::to_string),
    };
    validate_execution_command_v2(&command)?;
    let command_digest = execution_command_digest_v2(&command)?;
    Ok(PlannedExecutionCommandV2 { command, next_generations, command_digest })
}

// ---------------------------------------------------------------------------
// Kernel 侧内存 CAS 载体：controlRevision + command outbox（双 CAS 第 1/3 步）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutboxDeliveryState {
    Pending,
    Sent,
    Acknowledged,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandOutboxRecord {
    #[serde(rename = "commandId")]
    pub command_id: String,
    /// 版本联合命令（V2 生产链）：V2 行携带 ExecutionCommandV2；V1 wire 一字不变。
    pub command: ExecutionCommand,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "deliveryState")]
    pub delivery_state: OutboxDeliveryState,
    pub attempts: u64,
    #[serde(rename = "lastAttemptAt")]
    pub last_attempt_at: Option<String>,
}

/// controlRevision CAS 的内存载体：从 0 起步，每次已提交 Kernel mutation 恰好 +1；
/// 期望值不匹配零写入。真实文件存储（wasm-control-state-v2.json）接线属任务 7.2，
/// 本结构与 TS WasmControlStateStore 共享同一 CAS 语义。
#[derive(Debug, Clone, Default)]
pub struct WasmCommandControlState {
    pub control_revision: u64,
    pub command_outbox: Vec<CommandOutboxRecord>,
    /// retiring 记录（任务 7.6）：route 指针翻转时捕捉的 retired 判据；receipt
    /// projection CAS 成功前 lifecycle 绝不写 retired。
    pub retirements: Vec<RetiringExecutionRecord>,
}

/// 一次退休的 Kernel 侧判据（route 事件翻指针的同一时刻建档；peer 身份与
/// catalog retention/snapshot 释放均在 `retired` 投影之后由接线层执行）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RetiringExecutionRecord {
    /// 对应授权 drain 命令的 commandId（receipt 以它寻址）。
    #[serde(rename = "drainCommandId")]
    pub drain_command_id: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub execution: WasmExecutionIdentityV1,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    /// 指针翻转前捕捉的 retired route generation（receipt 必须精确相等）。
    #[serde(rename = "routeGeneration")]
    pub route_generation: u64,
    /// capability record 供给的精确 drain deadline（epoch 毫秒）。
    #[serde(rename = "deadlineAtEpochMillis")]
    pub deadline_at_epoch_millis: u64,
    /// route 指针翻转时刻（deadline 不得早于它）。
    #[serde(rename = "flipAtEpochMillis")]
    pub flip_at_epoch_millis: u64,
    /// Kernel lifecycle 投影：仅当 receipt projection CAS 成功才为 true。
    pub retired: bool,
    /// 已接受的 receipt digest（幂等重放比对；已接受后绝不改写）。
    #[serde(rename = "acceptedReceiptDigest")]
    pub accepted_receipt_digest: Option<String>,
}

#[derive(Debug)]
pub enum DrainRetirementProjection {
    /// 首次投影成功：retired 已写入，controlRevision 已 +1。
    Retired { control_revision: u64 },
    /// 幂等重投影：同一 receipt 已接受，不再消耗 revision、不二次计数。
    AlreadyRetired,
}

#[derive(Debug)]
pub enum AcknowledgementProjection {
    /// 投影成功：controlRevision 已 +1，outbox 条目置为 acknowledged。
    Projected { control_revision: u64 },
    /// 幂等重投影：同一 ack 已投影，不再消耗 revision。
    AlreadyAcknowledged,
}

impl WasmCommandControlState {
    /// 双 CAS 第 1 步：在授权该 command 的同一 controlRevision CAS 中追加 outbox。
    /// 版本联合（V2 生产链）：V1/V2 命令各自按其 schemaVersion 校验；V1 路径一字不变。
    pub fn authorize_command(&mut self, expected_control_revision: u64, command: ExecutionCommand, created_at: String) -> Result<(), AdmissionError> {
        if self.control_revision != expected_control_revision {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision CAS requires the current head; a mismatch writes nothing"));
        }
        if expected_control_revision >= WASM_U53_MAX {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
        }
        command.validate()?;
        parse_rfc3339_utc_millis(&created_at).map_err(|e| err(EXECUTION_COMMAND_INVALID, e.detail))?;
        if self.command_outbox.iter().any(|entry| entry.command_id == command.command_id()) {
            return Err(err(EXECUTION_OUTBOX_DUPLICATE_COMMAND, "outbox commandId must be unique; a duplicate append is fail-closed, never merged"));
        }
        self.command_outbox.push(CommandOutboxRecord {
            command_id: command.command_id().to_string(),
            command,
            created_at,
            delivery_state: OutboxDeliveryState::Pending,
            attempts: 0,
            last_attempt_at: None,
        });
        self.control_revision = expected_control_revision + 1;
        Ok(())
    }

    /// Route replacement binds its retiring execution to the authorized drain
    /// command in the same Kernel control-state CAS.  Splitting these writes
    /// would leave a visible pointer flip with an untracked drain window.
    pub fn authorize_drain_with_retirement(
        &mut self,
        expected_control_revision: u64,
        command: ExecutionCommandV1,
        created_at: String,
        record: RetiringExecutionRecord,
    ) -> Result<(), AdmissionError> {
        if self.control_revision != expected_control_revision {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision CAS requires the current head; a mismatch writes nothing"));
        }
        if expected_control_revision >= WASM_U53_MAX {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
        }
        if command.operation != WasmExecutionOperation::Drain {
            return Err(err(EXECUTION_COMMAND_INVALID, "a retiring execution may be authorized only with a drain command"));
        }
        validate_execution_command(&command)?;
        parse_rfc3339_utc_millis(&created_at).map_err(|e| err(EXECUTION_COMMAND_INVALID, e.detail))?;
        if record.drain_command_id != command.command_id
            || record.execution != command.identity
            || record.package_digest != command.package_digest
            || record.runtime_binding != command.runtime_binding
        {
            return Err(err(DRAIN_RECEIPT_INVALID, "the retiring execution must exactly echo its authorized drain command"));
        }
        validate_application_id(&record.application_id)?;
        validate_execution_identity(&record.execution)?;
        validate_sha256_hex(&record.package_digest, "/packageDigest")?;
        validate_runtime_binding(&record.runtime_binding)?;
        require_u53(record.route_generation, 0, "/routeGeneration")?;
        if record.deadline_at_epoch_millis < record.flip_at_epoch_millis {
            return Err(err(DRAIN_RECEIPT_INVALID, "the drain deadline supplied by the capability record must not precede the route flip"));
        }
        if record.retired || record.accepted_receipt_digest.is_some() {
            return Err(err(DRAIN_RECEIPT_INVALID, "a retiring record is created unretired; retirement is reachable only through receipt projection"));
        }
        if self.command_outbox.iter().any(|entry| entry.command_id == command.command_id)
            || self.retirements.iter().any(|entry| entry.drain_command_id == record.drain_command_id)
        {
            return Err(err(EXECUTION_OUTBOX_DUPLICATE_COMMAND, "a drain command and retiring execution are each recorded once"));
        }
        self.command_outbox.push(CommandOutboxRecord {
            command_id: command.command_id.clone(),
            command: ExecutionCommand::V1(command),
            created_at,
            delivery_state: OutboxDeliveryState::Pending,
            attempts: 0,
            last_attempt_at: None,
        });
        self.retirements.push(record);
        self.control_revision = expected_control_revision + 1;
        Ok(())
    }

    /// 双 CAS 第 3 步：投影 identity-checked acknowledgement。只有 echo 完全一致、
    /// journal revision 下界成立、且非 dead 终态的 ack 才能把 outbox 置为 acknowledged；
    /// 已 acknowledged 的重复投影幂等（不再消耗 revision）。版本联合：ack 与命令必须
    /// 同版本且逐字段 echo（跨版本在 correlate_acknowledgement_versioned 处拒绝）。
    pub fn project_acknowledgement(&mut self, expected_control_revision: u64, ack: &ExecutionAcknowledgement) -> Result<AcknowledgementProjection, AdmissionError> {
        if self.control_revision != expected_control_revision {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision CAS requires the current head; a mismatch writes nothing"));
        }
        ack.validate()?;
        let position = self
            .command_outbox
            .iter()
            .position(|entry| entry.command_id == ack.command_id())
            .ok_or_else(|| err(EXECUTION_OUTBOX_COMMAND_UNKNOWN, "the acknowledgement names no authorized outbox command"))?;
        let entry = &self.command_outbox[position];
        correlate_acknowledgement_versioned(&entry.command, ack)?;
        match entry.delivery_state {
            OutboxDeliveryState::Dead => Err(err(EXECUTION_ACK_PROJECTION_CONFLICT, "a dead outbox entry is never resurrected by an acknowledgement")),
            OutboxDeliveryState::Acknowledged => Ok(AcknowledgementProjection::AlreadyAcknowledged),
            OutboxDeliveryState::Pending | OutboxDeliveryState::Sent => {
                // fail-closed 下界：received 条目落在 expected+1，completion 只能在其后。
                if ack.journal_revision() < entry.command.expected_journal_revision().saturating_add(2) {
                    return Err(err(EXECUTION_ACK_STALE, "the acknowledgement journal revision cannot precede its received entry"));
                }
                if expected_control_revision >= WASM_U53_MAX {
                    return Err(err(CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
                }
                self.command_outbox[position].delivery_state = OutboxDeliveryState::Acknowledged;
                self.control_revision = expected_control_revision + 1;
                Ok(AcknowledgementProjection::Projected { control_revision: self.control_revision })
            }
        }
    }

    pub fn find_outbox(&self, command_id: &str) -> Option<&CommandOutboxRecord> {
        self.command_outbox.iter().find(|entry| entry.command_id == command_id)
    }

    /// 投递簿记（生产投递闭环）：pending/sent 条目记录一次投递尝试——attempts +1、
    /// lastAttemptAt 更新、pending → sent（advisory）。这也是一次已提交 Kernel
    /// mutation，与 outbox 追加/ack 投影共享同一 controlRevision CAS（每 mutation
    /// 恰 +1）；dead 绝不复活，acknowledged 的簿记是无写入的幂等 no-op。
    pub fn record_delivery_attempt(&mut self, expected_control_revision: u64, command_id: &str, at: String) -> Result<(), AdmissionError> {
        if self.control_revision != expected_control_revision {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision CAS requires the current head; a mismatch writes nothing"));
        }
        let position = self
            .command_outbox
            .iter()
            .position(|entry| entry.command_id == command_id)
            .ok_or_else(|| err(EXECUTION_OUTBOX_COMMAND_UNKNOWN, "delivery bookkeeping names no authorized outbox command"))?;
        parse_rfc3339_utc_millis(&at).map_err(|e| err(EXECUTION_COMMAND_INVALID, e.detail))?;
        let entry = &mut self.command_outbox[position];
        match entry.delivery_state {
            OutboxDeliveryState::Dead => Err(err(EXECUTION_OUTBOX_DEAD, "a dead outbox entry is owner-visible and never silently retried")),
            OutboxDeliveryState::Acknowledged => Ok(()),
            OutboxDeliveryState::Pending | OutboxDeliveryState::Sent => {
                if expected_control_revision >= WASM_U53_MAX {
                    return Err(err(CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
                }
                entry.delivery_state = OutboxDeliveryState::Sent;
                entry.attempts += 1;
                entry.last_attempt_at = Some(at);
                self.control_revision = expected_control_revision + 1;
                Ok(())
            }
        }
    }

    /// 任务 7.6 第 1 步：在 route 指针翻转的同一 controlRevision CAS 纪律下建档
    /// retiring 判据（真实接线把本调用与 wasm_activation 的指针 CAS 绑定到同一提交；
    /// 本模块只承诺判据形状与 CAS 语义）。deadline 早于翻转为结构性非法。
    pub fn authorize_retirement(&mut self, expected_control_revision: u64, record: RetiringExecutionRecord) -> Result<(), AdmissionError> {
        if self.control_revision != expected_control_revision {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision CAS requires the current head; a mismatch writes nothing"));
        }
        if expected_control_revision >= WASM_U53_MAX {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
        }
        validate_uuid_v7(&record.drain_command_id, "drainCommandId")?;
        validate_application_id(&record.application_id)?;
        validate_execution_identity(&record.execution)?;
        validate_sha256_hex(&record.package_digest, "/packageDigest")?;
        validate_runtime_binding(&record.runtime_binding)?;
        require_u53(record.route_generation, 0, "/routeGeneration")?;
        if record.deadline_at_epoch_millis < record.flip_at_epoch_millis {
            return Err(err(DRAIN_RECEIPT_INVALID, "the drain deadline supplied by the capability record must not precede the route flip"));
        }
        if record.retired || record.accepted_receipt_digest.is_some() {
            return Err(err(DRAIN_RECEIPT_INVALID, "a retiring record is created unretired; retirement is reachable only through receipt projection"));
        }
        if self.retirements.iter().any(|entry| entry.drain_command_id == record.drain_command_id) {
            return Err(err(EXECUTION_OUTBOX_DUPLICATE_COMMAND, "a retiring execution is recorded once per drain command"));
        }
        self.retirements.push(record);
        self.control_revision = expected_control_revision + 1;
        Ok(())
    }

    pub fn find_retirement(&self, drain_command_id: &str) -> Option<&RetiringExecutionRecord> {
        self.retirements.iter().find(|entry| entry.drain_command_id == drain_command_id)
    }

    /// 任务 7.6 第 2 步（Kernel retired 的唯一入口）：wire 校验 → 命令 echo →
    /// retiring 判据（stale/invalid 分码）→ 幂等/CAS。retired 只在此成功后写入；
    /// catalog retention 释放与 snapshot 删除均以此为前置（接线层消费 retired 标记）。
    pub fn project_drain_receipt(&mut self, expected_control_revision: u64, receipt: &DrainReceiptV1) -> Result<DrainRetirementProjection, AdmissionError> {
        if self.control_revision != expected_control_revision {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision CAS requires the current head; a mismatch writes nothing"));
        }
        validate_drain_receipt(receipt)?;
        let position = self
            .retirements
            .iter()
            .position(|entry| entry.drain_command_id == receipt.command_id)
            .ok_or_else(|| err(EXECUTION_OUTBOX_COMMAND_UNKNOWN, "the drain receipt names no retiring execution"))?;
        let retiring = &self.retirements[position];
        // receipt 必须寻址一条已授权的 drain 命令并与其 echo 一致（本批 drain 命令恒
        // V1——V2 行的 drain 规划在上层 fail-closed；防御性拒绝 V2 outbox 命令）。
        let outbox = self
            .find_outbox(&receipt.command_id)
            .ok_or_else(|| err(EXECUTION_OUTBOX_COMMAND_UNKNOWN, "the drain receipt names no authorized outbox command"))?;
        let drain_command = match &outbox.command {
            ExecutionCommand::V1(command) => command,
            ExecutionCommand::V2(_) => {
                return Err(err(DRAIN_RECEIPT_INVALID, "a V2 outbox command cannot correlate with a V1 drain receipt in this batch; V2 drain planning is fail-closed"))
            }
        };
        correlate_drain_receipt(drain_command, receipt)?;
        // stale：receipt 命名的 execution 代次/binding/route era 与 retiring 记录不同
        //（不写 retired、路由保持围栏，直至正确 receipt 或 owner 恢复决策）。
        if receipt.execution != retiring.execution || receipt.runtime_binding != retiring.runtime_binding {
            return Err(err(DRAIN_RECEIPT_STALE, "the receipt names an execution generation or binding different from the retiring route"));
        }
        if receipt.route_generation != retiring.route_generation {
            return Err(err(DRAIN_RECEIPT_STALE, "the receipt names a route generation different from the retiring route"));
        }
        if receipt.application_id != retiring.application_id || receipt.package_digest != retiring.package_digest {
            return Err(err(DRAIN_RECEIPT_STALE, "the receipt names an application or package different from the retiring route"));
        }
        // invalid：deadline 必须是 capability record 供给 Kernel 的精确值，且不早于翻转。
        if receipt.deadline_at_epoch_millis()? != retiring.deadline_at_epoch_millis {
            return Err(err(DRAIN_RECEIPT_INVALID, "deadlineAt must be the exact drain deadline supplied by the Kernel capability record"));
        }
        if retiring.deadline_at_epoch_millis < retiring.flip_at_epoch_millis {
            return Err(err(DRAIN_RECEIPT_INVALID, "deadline before route flip is invalid"));
        }
        // 幂等：同一 receipt 重放返回既有结果，不二次计数/杀；异 receipt 绝不改写。
        if retiring.retired {
            if retiring.accepted_receipt_digest.as_deref() == Some(receipt.receipt_digest.as_str()) {
                return Ok(DrainRetirementProjection::AlreadyRetired);
            }
            return Err(err(EXECUTION_ACK_PROJECTION_CONFLICT, "a projected retirement is never rewritten by another receipt"));
        }
        if expected_control_revision >= WASM_U53_MAX {
            return Err(err(CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
        }
        self.retirements[position].retired = true;
        self.retirements[position].accepted_receipt_digest = Some(receipt.receipt_digest.clone());
        self.control_revision = expected_control_revision + 1;
        Ok(DrainRetirementProjection::Retired { control_revision: self.control_revision })
    }
}

// ---------------------------------------------------------------------------
// query/replay 决策：journal 完成而 projection 失败时只有 replay 可推进、绝不先路由
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ReconciliationStep {
    /// journal 缺失：首次投递 outbox 命令（transport 属 7.1）。
    DeliverCommand,
    /// journal received-incomplete：byte-identical replay 在其存储 fence 下恢复执行。
    ReplayResume,
    /// journal 已完成且 ack 通过 echo 校验：执行 controlRevision 投影 CAS。
    /// 这是投影失败后唯一允许的推进；任何 route-pointer 变更仍需 2.4 的独立 CAS。
    ProjectAcknowledgement,
    /// outbox 已 acknowledged：终态，禁止删除直至 replay 保留时间戳落盘。
    AlreadyProjected,
}

/// 纯决策：给定 outbox 条目与 journal 观察，决定下一步。dead 条目 owner-visible、
/// 绝不静默重试；completed journal 的 ack 必须先通过 echo 校验才允许投影。
pub fn decide_reconciliation(outbox: &CommandOutboxRecord, journal: &JournalObservation) -> Result<ReconciliationStep, AdmissionError> {
    match outbox.delivery_state {
        OutboxDeliveryState::Dead => Err(err(EXECUTION_OUTBOX_DEAD, "a dead outbox entry is owner-visible and never silently retried")),
        OutboxDeliveryState::Acknowledged => Ok(ReconciliationStep::AlreadyProjected),
        OutboxDeliveryState::Pending | OutboxDeliveryState::Sent => match journal {
            JournalObservation::Missing => Ok(ReconciliationStep::DeliverCommand),
            JournalObservation::ReceivedIncomplete => Ok(ReconciliationStep::ReplayResume),
            JournalObservation::Completed(ack) => {
                correlate_acknowledgement_versioned(&outbox.command, ack)?;
                Ok(ReconciliationStep::ProjectAcknowledgement)
            }
        },
    }
}

#[derive(Debug)]
pub enum ReconciliationOutcome {
    DeliverCommand,
    ReplayResume,
    Projected { control_revision: u64 },
    AlreadyProjected,
}

/// 投影失败的唯一恢复路径：CONTROL_REVISION_CONFLICT 时状态零写入，调用方只能重新
/// query/replay（再次进入本函数）；本模块没有任何 route-pointer 写入 API——
/// "journal 完成而 Kernel projection 失败时只有 replay 可发生、绝不先路由"由
/// 类型层保证（route CAS 属任务 2.4 的独立授权）。
pub fn reconcile_projection(state: &mut WasmCommandControlState, command_id: &str, journal: &JournalObservation) -> Result<ReconciliationOutcome, AdmissionError> {
    let outbox = state
        .find_outbox(command_id)
        .ok_or_else(|| err(EXECUTION_OUTBOX_COMMAND_UNKNOWN, "reconciliation requires an authorized outbox command"))?;
    match decide_reconciliation(outbox, journal)? {
        ReconciliationStep::AlreadyProjected => Ok(ReconciliationOutcome::AlreadyProjected),
        ReconciliationStep::DeliverCommand => Ok(ReconciliationOutcome::DeliverCommand),
        ReconciliationStep::ReplayResume => Ok(ReconciliationOutcome::ReplayResume),
        ReconciliationStep::ProjectAcknowledgement => {
            let ack = match journal {
                JournalObservation::Completed(ack) => ack.as_ref(),
                _ => unreachable!("decide_reconciliation only projects completed observations"),
            };
            let head = state.control_revision;
            match state.project_acknowledgement(head, ack)? {
                AcknowledgementProjection::Projected { control_revision } => Ok(ReconciliationOutcome::Projected { control_revision }),
                AcknowledgementProjection::AlreadyAcknowledged => Ok(ReconciliationOutcome::AlreadyProjected),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_admission::{NormalizedWasmManifestV1, WasmVersionIdentity, WasmVersionRegistryRow};

    // -- golden 向量（bun oracle 直读 packages/contracts/wasm-execution.ts 于 2026-08-26 产出）：
    //    bun -e 'computeExecutionCommandDigestV1(exampleExecutionCommandV1())' 及其
    //    configRevision:0/start 变体；JCS 字节同步固定以锁定跨实现编码。 --

    const GOLDEN_PREPARE_DIGEST: &str = "ab9ec9e201fae1640606ac1374972ffb3438759528bd629daa1bb49fb70833fb";
    const GOLDEN_START_DIGEST: &str = "174fcd4f59071af40273517f7a23494ce6c6508ede63bf706c5b4e6cfb218c03";
    const VECTOR_VERSION_ID: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1";

    fn vector_binding() -> RuntimeBindingIdentityV1 {
        RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: crate::wasm_admission::WASM_HOST_ABI_LITERAL.into(),
            world: crate::wasm_admission::WASM_WORLD_LITERAL.into(),
        }
    }

    fn golden_prepare_command() -> ExecutionCommandV1 {
        ExecutionCommandV1 {
            schema_version: 1,
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into(),
            expected_kernel_control_revision: 12,
            expected_journal_revision: 4,
            operation: WasmExecutionOperation::Prepare,
            identity: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 1 },
            package_digest: "0".repeat(64),
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            secret_revision: 3,
            secret_snapshot_ref: "5".repeat(64),
            secret_values_digest: "6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some("7".repeat(64)),
            config_values_digest: Some("8".repeat(64)),
        }
    }

    fn golden_start_command() -> ExecutionCommandV1 {
        ExecutionCommandV1 {
            schema_version: 1,
            command_id: "018f1e2c-3d4b-7c6d-9e01-001122334455".into(),
            expected_kernel_control_revision: 13,
            expected_journal_revision: 6,
            operation: WasmExecutionOperation::Start,
            identity: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 2 },
            package_digest: "0".repeat(64),
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            secret_revision: 3,
            secret_snapshot_ref: "5".repeat(64),
            secret_values_digest: "6".repeat(64),
            config_revision: 0,
            config_snapshot_ref: None,
            config_values_digest: None,
        }
    }

    // 独立 oracle：手工拼 preimage 再单次 SHA-256（不复用被测实现）。
    fn oracle_domain_digest(domain: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(b"\n");
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

    #[test]
    fn golden_prepare_command_digest_matches_ts_oracle() {
        let command = golden_prepare_command();
        let jcs = jcs_bytes(&command).expect("command serializes as JCS");
        // JCS 关键序抽查：身份四元组与 config 耦合字段按 UTF-8 字节序出现。
        let text = String::from_utf8(jcs.clone()).expect("jcs is utf-8");
        assert!(text.contains(r#""configSnapshotRef":"777"#));
        assert!(text.contains(r#""preparationGeneration":1"#));
        assert_eq!(execution_command_digest_v1(&command).expect("digest computes"), GOLDEN_PREPARE_DIGEST);
        // 与实现无关的 oracle 复算（域前缀 + 单次 SHA-256）。
        assert_eq!(oracle_domain_digest(EXECUTION_COMMAND_DIGEST_DOMAIN, &jcs), GOLDEN_PREPARE_DIGEST);
        // 规范 JCS round-trip：原始字节等于 JCS(parse(bytes))。
        let parsed: ExecutionCommandV1 = serde_json::from_slice(&jcs).expect("golden jcs parses");
        assert_eq!(parsed, command);
    }

    #[test]
    fn golden_start_command_with_null_config_matches_ts_oracle() {
        let command = golden_start_command();
        let jcs = jcs_bytes(&command).expect("command serializes as JCS");
        let text = String::from_utf8(jcs.clone()).expect("jcs is utf-8");
        // Option<String> 必须序列化为显式 null（键不缺席），与 TS JCS 字节一致。
        assert!(text.contains(r#""configSnapshotRef":null"#));
        assert!(text.contains(r#""configValuesDigest":null"#));
        assert_eq!(execution_command_digest_v1(&command).expect("digest computes"), GOLDEN_START_DIGEST);
        assert_eq!(oracle_domain_digest(EXECUTION_COMMAND_DIGEST_DOMAIN, &jcs), GOLDEN_START_DIGEST);
    }

    // -- V2（service-enabled）golden 向量（bun oracle 直读 packages/contracts/
    //    wasm-execution.ts exampleExecutionCommandV2() 于 2026-08-28 产出）。 --
    const GOLDEN_V2_PREPARE_DIGEST: &str = "585870becc2cb26abff3e142e97b35b32a2eb69894f5d1c3976e1e981d6cb16d";

    fn vector_binding_v2() -> RuntimeBindingIdentityV2 {
        RuntimeBindingIdentityV2 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: crate::wasm_host_services::HOST_ABI_LITERAL_V2.into(),
            world: crate::wasm_admission::WASM_WORLD_LITERAL.into(),
        }
    }

    fn golden_v2_prepare_command() -> ExecutionCommandV2 {
        ExecutionCommandV2 {
            schema_version: 2,
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into(),
            expected_control_revision: 12,
            expected_journal_revision: 4,
            operation: WasmExecutionOperation::Prepare,
            identity: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 1 },
            application_id: "vector".into(),
            package_digest: "0".repeat(64),
            runtime_binding: vector_binding_v2(),
            matrix_revision: 2,
            host_service_policy_digest: "b21afb8e8cb4e6482b137ef5749ea2b9c39e4ef35619bfb079d4c83bd75bb665".into(),
            fence_nonce: "0f1e2d3c4b5a69788796a5b4c3d2e1f0".into(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            secret_revision: 3,
            secret_snapshot_ref: "5".repeat(64),
            secret_values_digest: "6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some("7".repeat(64)),
            config_values_digest: Some("8".repeat(64)),
        }
    }

    /// 独立 V2 oracle：domain || 0x00 || payload（单次 SHA-256，绝不二次 hash 十六进制文本）。
    fn oracle_domain_digest_v2(domain: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update([0x00]);
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

    #[test]
    fn golden_v2_command_digest_matches_ts_oracle_and_round_trips() {
        let command = golden_v2_prepare_command();
        assert!(validate_execution_command_v2(&command).is_ok());
        let jcs = jcs_bytes(&command).expect("command serializes as JCS");
        let text = String::from_utf8(jcs.clone()).expect("jcs is utf-8");
        // V2 增量键按 UTF-8 字节序出现（JCS 关键序抽查；复审重命名键固定在 golden 内）。
        assert!(text.contains(r#""hostABI":"iweb-wasmd-abi@1.1.0""#));
        assert!(text.contains(r#""matrixRevision":2"#));
        assert!(text.contains(r#""fenceNonce":"0f1e2d3c4b5a69788796a5b4c3d2e1f0""#));
        assert!(text.contains(r#""expectedControlRevision":12"#));
        assert!(!text.contains("expectedKernelControlRevision"));
        assert_eq!(execution_command_digest_v2(&command).expect("digest computes"), GOLDEN_V2_PREPARE_DIGEST);
        assert_eq!(oracle_domain_digest_v2(EXECUTION_COMMAND_DIGEST_DOMAIN_V2, &jcs), GOLDEN_V2_PREPARE_DIGEST);
        // V1/V2 域摘要互不碰撞：同一 payload 在 V1 "\n" 域下的摘要不同。
        assert_ne!(oracle_domain_digest(EXECUTION_COMMAND_DIGEST_DOMAIN, &jcs), GOLDEN_V2_PREPARE_DIGEST);
        // 规范 JCS round-trip：精确键集（deny_unknown_fields）保真。
        let parsed: ExecutionCommandV2 = serde_json::from_slice(&jcs).expect("golden jcs parses");
        assert_eq!(parsed, command);
    }

    #[test]
    fn v2_command_validation_pins_the_service_enabled_invariants() {
        let command = golden_v2_prepare_command();
        // schemaVersion 必须恒 2。
        let mut wrong_version = command.clone();
        wrong_version.schema_version = 1;
        assert_eq!(validate_execution_command_v2(&wrong_version).unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        // ABI 1.0.0 binding 不是 V2 wire。
        let mut v1_binding = command.clone();
        v1_binding.runtime_binding.host_abi = crate::wasm_admission::WASM_HOST_ABI_LITERAL.into();
        assert_eq!(validate_execution_command_v2(&v1_binding).unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        // matrixRevision 恒 2。
        let mut wrong_matrix = command.clone();
        wrong_matrix.matrix_revision = 1;
        assert_eq!(validate_execution_command_v2(&wrong_matrix).unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        // fenceNonce 文法（非 32 位小写十六进制）。
        let mut bad_nonce = command.clone();
        bad_nonce.fence_nonce = "0F1E2D3C4B5A69788796A5B4C3D2E1F0".into();
        assert_eq!(validate_execution_command_v2(&bad_nonce).unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        // policy digest 文法。
        let mut bad_policy = command.clone();
        bad_policy.host_service_policy_digest = "zz".into();
        assert_eq!(validate_execution_command_v2(&bad_policy).unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        // applicationId 文法。
        let mut bad_app = command.clone();
        bad_app.application_id = "Vector".into();
        assert_eq!(validate_execution_command_v2(&bad_app).unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        // config 耦合破坏。
        let mut broken_config = command.clone();
        broken_config.config_values_digest = None;
        assert_eq!(validate_execution_command_v2(&broken_config).unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        // 未知字段 → serde deny_unknown_fields 拒绝。
        let mut value = serde_json::to_value(&command).expect("serializes");
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ExecutionCommandV2>(value).is_err());
        // V1 解析器绝不消费 V2 wire（schemaVersion:2 被 V1 精确字面量拒绝）。
        let jcs = jcs_bytes(&command).expect("jcs");
        assert!(serde_json::from_slice::<ExecutionCommandV1>(&jcs).is_err());
    }

    #[test]
    fn versioned_command_union_parses_and_dispatches_by_schema_version() {
        // V1 wire → V1 变体；V2 wire → V2 变体（deny_unknown_fields 使两域互斥）。
        let v1_bytes = jcs_bytes(&golden_prepare_command()).expect("v1 jcs");
        let parsed_v1: ExecutionCommand = serde_json::from_slice(&v1_bytes).expect("v1 parses as union");
        assert_eq!(parsed_v1.schema_version(), 1);
        assert_eq!(execution_command_digest_versioned(&parsed_v1).expect("digest"), GOLDEN_PREPARE_DIGEST);
        let v2_bytes = jcs_bytes(&golden_v2_prepare_command()).expect("v2 jcs");
        let parsed_v2: ExecutionCommand = serde_json::from_slice(&v2_bytes).expect("v2 parses as union");
        assert_eq!(parsed_v2.schema_version(), 2);
        assert_eq!(parsed_v2.command_id(), "018f1e2c-3d4b-7a5e-9f01-23456789abcd");
        assert_eq!(parsed_v2.operation(), WasmExecutionOperation::Prepare);
        // 非 V1/V2 形状（缺 schemaVersion）fail-closed。
        let mut broken = serde_json::to_value(golden_v2_prepare_command()).expect("value");
        broken["schemaVersion"].take();
        assert!(serde_json::from_value::<ExecutionCommand>(broken).is_err());
    }

    #[test]
    fn plan_execution_command_v2_builds_service_enabled_command_from_v1_facts() {
        let row = vector_registry_row();
        let base = KernelCommandPlanInput {
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd",
            operation: WasmExecutionOperation::Prepare,
            control_revision: 12,
            journal_head: 4,
            sandbox_id: "sbx-vector",
            version_row: &row,
            capability_record_revision: 5,
            capability_record_hash: &"2".repeat(64),
            secret_revision: 3,
            secret_snapshot_ref: &"5".repeat(64),
            secret_values_digest: &"6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some(&"7".repeat(64)),
            config_values_digest: Some(&"8".repeat(64)),
            current_generations: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 0, execution_generation: 0 },
        };
        let planned = plan_execution_command_v2(&KernelCommandPlanInputV2 {
            base,
            application_id: "vector",
            host_service_policy_digest: "b21afb8e8cb4e6482b137ef5749ea2b9c39e4ef35619bfb079d4c83bd75bb665",
        })
        .expect("V2 plan derives a valid command");
        // 结构性事实：V2 增量 + V1 admission 事实保留（仅 hostABI 换 1.1.0 字面量）。
        assert_eq!(planned.command.application_id, "vector");
        assert_eq!(planned.command.matrix_revision, 2);
        assert_eq!(planned.command.expected_control_revision, 12);
        assert_eq!(planned.command.expected_journal_revision, 4);
        assert_eq!(planned.command.runtime_binding.host_abi, crate::wasm_host_services::HOST_ABI_LITERAL_V2);
        assert_eq!(planned.command.runtime_binding.catalog_revision, row.runtime_binding.catalog_revision);
        assert_eq!(planned.command.runtime_binding.catalog_hash, row.runtime_binding.catalog_hash);
        assert_eq!(planned.command.runtime_binding.entry_key, row.runtime_binding.entry_key);
        assert_eq!(planned.command.runtime_binding.image_digest, row.runtime_binding.image_digest);
        assert_eq!(planned.command.runtime_binding.world, row.runtime_binding.world);
        assert_eq!((planned.next_generations.preparation_generation, planned.next_generations.execution_generation), (1, 1));
        // fenceNonce：域分离确定性派生（同输入同 nonce；文法 32 位小写十六进制）。
        assert!(fence_nonce_regex().is_match(&planned.command.fence_nonce));
        assert_eq!(
            planned.command.fence_nonce,
            plan_fence_nonce_v2("vector", VECTOR_VERSION_ID, 1, 1),
            "the fence nonce derivation must be deterministic for the same identity tuple"
        );
        assert_ne!(plan_fence_nonce_v2("vector", VECTOR_VERSION_ID, 1, 2), planned.command.fence_nonce);
        // digest 复算与 oracle 域一致；V1 域摘要互不碰撞。
        let jcs = jcs_bytes(&planned.command).expect("jcs");
        assert_eq!(execution_command_digest_v2(&planned.command).expect("digest"), planned.command_digest);
        assert_eq!(oracle_domain_digest_v2(EXECUTION_COMMAND_DIGEST_DOMAIN_V2, &jcs), planned.command_digest);
        // 非法 policy digest / applicationId fail-closed。
        let capability_hash = "2".repeat(64);
        let secret_ref = "5".repeat(64);
        let secret_digest = "6".repeat(64);
        let config_ref = "7".repeat(64);
        let config_digest = "8".repeat(64);
        let make_base = || KernelCommandPlanInput {
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd",
            operation: WasmExecutionOperation::Prepare,
            control_revision: 12,
            journal_head: 4,
            sandbox_id: "sbx-vector",
            version_row: &row,
            capability_record_revision: 5,
            capability_record_hash: &capability_hash,
            secret_revision: 3,
            secret_snapshot_ref: &secret_ref,
            secret_values_digest: &secret_digest,
            config_revision: 2,
            config_snapshot_ref: Some(&config_ref),
            config_values_digest: Some(&config_digest),
            current_generations: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 0, execution_generation: 0 },
        };
        let bad_policy = plan_execution_command_v2(&KernelCommandPlanInputV2 { application_id: "vector", host_service_policy_digest: "zz", base: make_base() });
        assert_eq!(bad_policy.unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
        let bad_app = plan_execution_command_v2(&KernelCommandPlanInputV2 { application_id: "Vector", host_service_policy_digest: "b21afb8e8cb4e6482b137ef5749ea2b9c39e4ef35619bfb079d4c83bd75bb665", base: make_base() });
        assert_eq!(bad_app.unwrap_err().code, EXECUTION_COMMAND_V2_INVALID);
    }

    fn applied_ack_v2(command: &ExecutionCommandV2, journal_revision: u64) -> ExecutionAcknowledgementV2 {
        ExecutionAcknowledgementV2 {
            schema_version: 2,
            command_id: command.command_id.clone(),
            operation: command.operation,
            identity: command.identity.clone(),
            application_id: command.application_id.clone(),
            package_digest: command.package_digest.clone(),
            runtime_binding: command.runtime_binding.clone(),
            matrix_revision: command.matrix_revision,
            host_service_policy_digest: command.host_service_policy_digest.clone(),
            fence_nonce: command.fence_nonce.clone(),
            capability_record_revision: command.capability_record_revision,
            capability_record_hash: command.capability_record_hash.clone(),
            secret_revision: command.secret_revision,
            secret_snapshot_ref: command.secret_snapshot_ref.clone(),
            secret_values_digest: command.secret_values_digest.clone(),
            config_revision: command.config_revision,
            config_snapshot_ref: command.config_snapshot_ref.clone(),
            config_values_digest: command.config_values_digest.clone(),
            drain_receipt_digest: None,
            result: AcknowledgementResult::Applied,
            failure_code: None,
            journal_revision,
        }
    }

    #[test]
    fn v2_acknowledgement_validates_correlates_and_rejects_cross_version_echo() {
        let command = golden_v2_prepare_command();
        let ack = applied_ack_v2(&command, 6);
        assert!(validate_execution_acknowledgement_v2(&ack).is_ok());
        assert!(correlate_acknowledgement_v2(&command, &ack).is_ok());
        // V2 echo 增量字段的任一错配均拒绝。
        let mut wrong_policy = ack.clone();
        wrong_policy.host_service_policy_digest = "e".repeat(64);
        assert_eq!(correlate_acknowledgement_v2(&command, &wrong_policy).unwrap_err().code, "POLICY_MISMATCH");
        let mut wrong_nonce = ack.clone();
        wrong_nonce.fence_nonce = "f".repeat(32);
        assert_eq!(correlate_acknowledgement_v2(&command, &wrong_nonce).unwrap_err().code, "IDENTITY_MISMATCH");
        let mut wrong_app = ack.clone();
        wrong_app.application_id = "other".into();
        assert_eq!(correlate_acknowledgement_v2(&command, &wrong_app).unwrap_err().code, "IDENTITY_MISMATCH");
        let mut wrong_matrix = ack.clone();
        wrong_matrix.matrix_revision = 1;
        assert!(validate_execution_acknowledgement_v2(&wrong_matrix).is_err());
        // 跨版本 echo：V1 命令 × V2 ack（及反向）一律 VERSION_MISMATCH。
        assert_eq!(
            correlate_acknowledgement_versioned(&v1(golden_prepare_command()), &ExecutionAcknowledgement::V2(ack.clone())).unwrap_err().code,
            ACKNOWLEDGEMENT_VERSION_MISMATCH
        );
        assert_eq!(
            correlate_acknowledgement_versioned(&ExecutionCommand::V2(command.clone()), &ExecutionAcknowledgement::V1(ExecutionAcknowledgementV1 { schema_version: 1, ..applied_ack_v1_fields() })).unwrap_err().code,
            ACKNOWLEDGEMENT_VERSION_MISMATCH
        );
        // outbox/ack 全链：V2 命令授权 → V2 ack 投影 → 幂等。
        let mut state = WasmCommandControlState::default();
        state.authorize_command(0, ExecutionCommand::V2(command.clone()), "2026-08-28T00:00:00Z".into()).expect("authorize V2");
        match state.project_acknowledgement(1, &ExecutionAcknowledgement::V2(applied_ack_v2(&command, 6))).expect("V2 ack projects") {
            AcknowledgementProjection::Projected { control_revision } => assert_eq!(control_revision, 2),
            AcknowledgementProjection::AlreadyAcknowledged => panic!("first projection must consume a revision"),
        }
        match state.project_acknowledgement(2, &ExecutionAcknowledgement::V2(applied_ack_v2(&command, 6))).expect("reprojection") {
            AcknowledgementProjection::AlreadyAcknowledged => {}
            AcknowledgementProjection::Projected { .. } => panic!("reprojection must be idempotent"),
        }
        // V1 ack 不能投影 V2 outbox 条目（跨版本 fail-closed；commandId 命中才到达
        // correlate 的版本判定）。
        let mut fresh = WasmCommandControlState::default();
        let mut second = golden_v2_prepare_command();
        second.command_id = "018f1e2c-3d4b-7d6d-8e9f-001122334455".into();
        fresh.authorize_command(0, ExecutionCommand::V2(second.clone()), "2026-08-28T00:00:00Z".into()).expect("authorize");
        let mut v1_ack_of_v2 = applied_ack_v1_fields();
        v1_ack_of_v2.command_id = second.command_id.clone();
        assert_eq!(
            fresh.project_acknowledgement(1, &ExecutionAcknowledgement::V1(v1_ack_of_v2)).unwrap_err().code,
            ACKNOWLEDGEMENT_VERSION_MISMATCH
        );
    }

    fn applied_ack_v1_fields() -> ExecutionAcknowledgementV1 {
        let command = golden_start_command();
        ExecutionAcknowledgementV1 {
            schema_version: 1,
            command_id: command.command_id.clone(),
            operation: command.operation,
            identity: command.identity.clone(),
            package_digest: command.package_digest.clone(),
            runtime_binding: command.runtime_binding.clone(),
            capability_record_revision: command.capability_record_revision,
            capability_record_hash: command.capability_record_hash.clone(),
            secret_revision: command.secret_revision,
            secret_snapshot_ref: command.secret_snapshot_ref.clone(),
            secret_values_digest: command.secret_values_digest.clone(),
            config_revision: command.config_revision,
            config_snapshot_ref: command.config_snapshot_ref.clone(),
            config_values_digest: command.config_values_digest.clone(),
            drain_receipt_digest: None,
            result: AcknowledgementResult::Applied,
            failure_code: None,
            journal_revision: 6,
        }
    }

    #[test]
    fn dual_generation_transitions_are_monotonic_and_exhaustion_fenced() {
        let initial = WasmExecutionIdentityV1 { sandbox_id: "sbx".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 0, execution_generation: 0 };
        // 首次准备：(0,0) -> (1,1)（spec scenario "First preparation and later process restart"）。
        let first = prepare_generation_transition(&initial).expect("first prepare allocates (1,1)");
        assert_eq!((first.preparation_generation, first.execution_generation), (1, 1));
        assert!(is_alive_execution_identity(&first));
        // 进程重启：只推进 executionGeneration（严格更高）。
        let restart = execution_generation_transition(&first).expect("restart allocates a higher execution generation");
        assert_eq!((restart.preparation_generation, restart.execution_generation), (1, 2));
        // 恢复性重备：也分配严格更高的 preparation。
        let reprepare = prepare_generation_transition(&restart).expect("recovery prepare allocates a higher preparation");
        assert_eq!((reprepare.preparation_generation, reprepare.execution_generation), (2, 3));
        // 无 preparation 时不得分配 execution。
        let unprepared = WasmExecutionIdentityV1 { sandbox_id: "sbx".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 0, execution_generation: 0 };
        assert_eq!(execution_generation_transition(&unprepared).unwrap_err().code, WASM_EXECUTION_IDENTITY_INVALID);
        // u53 上限：分配失败 WASM_GENERATION_EXHAUSTED，不回绕、不复用、不归零。
        let exhausted = WasmExecutionIdentityV1 { sandbox_id: "sbx".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: WASM_U53_MAX, execution_generation: WASM_U53_MAX };
        assert_eq!(prepare_generation_transition(&exhausted).unwrap_err().code, WASM_GENERATION_EXHAUSTED);
        let execution_exhausted = WasmExecutionIdentityV1 { sandbox_id: "sbx".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: WASM_U53_MAX };
        assert_eq!(execution_generation_transition(&execution_exhausted).unwrap_err().code, WASM_GENERATION_EXHAUSTED);
        // 精确比对：任一字段不同即 stale。
        assert!(matches_execution_fence(&restart, &restart.clone()));
        assert!(!matches_execution_fence(&first, &restart));
        assert_eq!(check_execution_fence(&first, &restart).unwrap_err().code, WASM_EXECUTION_FENCE_STALE);
    }

    fn vector_registry_row() -> WasmVersionRegistryRow {
        let manifest: NormalizedWasmManifestV1 = serde_json::from_str(
            r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#,
        )
        .expect("vector manifest parses");
        WasmVersionRegistryRow {
            version_id: VECTOR_VERSION_ID.into(),
            identity: WasmVersionIdentity { application_id: "vector".into(), digest: "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532".into(), sequence: 1 },
            package_digest: "0".repeat(64),
            normalized_policy: manifest,
            lifecycle: "admitted".into(),
            runtime_binding: vector_binding(),
            admission_proof_ref: format!("admission-proof/vector/{VECTOR_VERSION_ID}"),
            admission_proof_digest: "4".repeat(64),
            host_service_policy_summary: None,
            readiness_lease_digest: None,
        }
    }

    #[test]
    fn plan_execution_command_derives_revisions_tuple_and_digest() {
        let row = vector_registry_row();
        // journal_head=4、control_revision=12、prepare：(0,0)->(1,1)，全字段来自 registry/证明。
        let plan = plan_execution_command(&KernelCommandPlanInput {
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd",
            operation: WasmExecutionOperation::Prepare,
            control_revision: 12,
            journal_head: 4,
            sandbox_id: "sbx-vector",
            version_row: &row,
            capability_record_revision: 5,
            capability_record_hash: &"2".repeat(64),
            secret_revision: 3,
            secret_snapshot_ref: &"5".repeat(64),
            secret_values_digest: &"6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some(&"7".repeat(64)),
            config_values_digest: Some(&"8".repeat(64)),
            current_generations: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 0, execution_generation: 0 },
        })
        .expect("plan derives a valid command");
        // 与 golden 向量完全一致的命令（同 registry 行、同快照输入、同 revisions）。
        assert_eq!(plan.command, golden_prepare_command());
        assert_eq!(plan.command_digest, GOLDEN_PREPARE_DIGEST);
        assert_eq!((plan.next_generations.preparation_generation, plan.next_generations.execution_generation), (1, 1));
        // drain/stop 要求存活 execution（双代次 >= 1）。
        let drain_error = plan_execution_command(&KernelCommandPlanInput {
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd",
            operation: WasmExecutionOperation::Drain,
            control_revision: 12,
            journal_head: 4,
            sandbox_id: "sbx-vector",
            version_row: &row,
            capability_record_revision: 5,
            capability_record_hash: &"2".repeat(64),
            secret_revision: 3,
            secret_snapshot_ref: &"5".repeat(64),
            secret_values_digest: &"6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some(&"7".repeat(64)),
            config_values_digest: Some(&"8".repeat(64)),
            current_generations: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 0, execution_generation: 0 },
        })
        .unwrap_err();
        assert_eq!(drain_error.code, WASM_EXECUTION_FENCE_STALE);
    }

    fn applied_ack(command: &ExecutionCommandV1, journal_revision: u64) -> ExecutionAcknowledgement {
        ExecutionAcknowledgement::V1(ExecutionAcknowledgementV1 {
            schema_version: 1,
            command_id: command.command_id.clone(),
            operation: command.operation,
            identity: command.identity.clone(),
            package_digest: command.package_digest.clone(),
            runtime_binding: command.runtime_binding.clone(),
            capability_record_revision: command.capability_record_revision,
            capability_record_hash: command.capability_record_hash.clone(),
            secret_revision: command.secret_revision,
            secret_snapshot_ref: command.secret_snapshot_ref.clone(),
            secret_values_digest: command.secret_values_digest.clone(),
            config_revision: command.config_revision,
            config_snapshot_ref: command.config_snapshot_ref.clone(),
            config_values_digest: command.config_values_digest.clone(),
            drain_receipt_digest: None,
            result: AcknowledgementResult::Applied,
            failure_code: None,
            journal_revision,
        })
    }

    /// V1 命令的枚举包装（outbox/投影面的版本联合入参）。
    fn v1(command: ExecutionCommandV1) -> ExecutionCommand {
        ExecutionCommand::V1(command)
    }

    #[test]
    fn double_cas_flow_authorizes_projects_and_is_idempotent() {
        let command = golden_prepare_command();
        let mut state = WasmCommandControlState::default();
        // 第 1 步：授权 CAS 追加 outbox，controlRevision 0 -> 1。
        state.authorize_command(0, v1(command.clone()), "2026-08-26T00:00:00Z".into()).expect("authorize appends the outbox");
        assert_eq!(state.control_revision, 1);
        assert_eq!(state.find_outbox(&command.command_id).expect("outbox entry exists").delivery_state, OutboxDeliveryState::Pending);
        // 重复 commandId fail-closed（零写入：revision 不变）。
        assert_eq!(state.authorize_command(1, v1(command.clone()), "2026-08-26T00:00:01Z".into()).unwrap_err().code, EXECUTION_OUTBOX_DUPLICATE_COMMAND);
        assert_eq!(state.control_revision, 1);
        // 第 3 步：completed journal（received 落在 expected+1=5，completion 落在 6）投影。
        let ack = applied_ack(&command, 6);
        match state.project_acknowledgement(1, &ack).expect("projection commits") {
            AcknowledgementProjection::Projected { control_revision } => assert_eq!(control_revision, 2),
            AcknowledgementProjection::AlreadyAcknowledged => panic!("first projection must consume a revision"),
        }
        assert_eq!(state.find_outbox(&command.command_id).unwrap().delivery_state, OutboxDeliveryState::Acknowledged);
        // 幂等重投影：不再消耗 revision。
        match state.project_acknowledgement(2, &ack).expect("reprojection is idempotent") {
            AcknowledgementProjection::AlreadyAcknowledged => {}
            AcknowledgementProjection::Projected { .. } => panic!("reprojection must not consume another revision"),
        }
        assert_eq!(state.control_revision, 2);
        // journal revision 下界：completion 不可能先于其 received 条目（expected+2）。
        // 用一条新命令验证下界（已 acknowledged 的条目走幂等分支，不再校验）。
        let mut fresh = WasmCommandControlState::default();
        let mut second = golden_start_command();
        second.command_id = "018f1e2c-3d4b-7d6d-8e9f-001122334455".into();
        fresh.authorize_command(0, v1(second.clone()), "2026-08-26T00:00:00Z".into()).expect("authorize");
        let early_ack = applied_ack(&second, second.expected_journal_revision + 1);
        assert_eq!(fresh.project_acknowledgement(1, &early_ack).unwrap_err().code, EXECUTION_ACK_STALE);
    }

    #[test]
    fn projection_failure_only_replay_advances_and_never_routes_first() {
        let command = golden_prepare_command();
        let mut state = WasmCommandControlState::default();
        state.authorize_command(0, v1(command.clone()), "2026-08-26T00:00:00Z".into()).expect("authorize");
        // 模拟：supervisor journal 已 received(5)+completed(6)，但 Kernel 在投影前崩溃/并发
        // 写入推进了 controlRevision（另一命令的授权 CAS）。
        let mut interleaved = golden_start_command();
        interleaved.command_id = "018f1e2c-3d4b-7d6d-8e9f-001122334455".into();
        interleaved.expected_kernel_control_revision = 1;
        state.authorize_command(1, v1(interleaved.clone()), "2026-08-26T00:00:01Z".into()).expect("interleaved authorize");
        assert_eq!(state.control_revision, 2);
        let ack = applied_ack(&command, 6);
        // 用过期 expected 投影：CONTROL_REVISION_CONFLICT，零写入。
        assert_eq!(state.project_acknowledgement(1, &ack).unwrap_err().code, CONTROL_REVISION_CONFLICT);
        assert_eq!(state.find_outbox(&command.command_id).unwrap().delivery_state, OutboxDeliveryState::Pending);
        assert_eq!(state.control_revision, 2);
        // 恢复路径只有 query/replay → reconcile：在当前 head 上投影成功。
        let observation = JournalObservation::Completed(Box::new(ack));
        match reconcile_projection(&mut state, &command.command_id, &observation).expect("replay reconciliation projects") {
            ReconciliationOutcome::Projected { control_revision } => assert_eq!(control_revision, 3),
            other => panic!("expected projection, got {other:?}"),
        }
        // 投影后再次 reconcile：终态 AlreadyProjected（outbox 删除仍被禁止直至保留时间戳）。
        match reconcile_projection(&mut state, &command.command_id, &observation).expect("terminal reconciliation") {
            ReconciliationOutcome::AlreadyProjected => {}
            other => panic!("expected terminal idempotence, got {other:?}"),
        }
        assert_eq!(state.control_revision, 3);
    }

    #[test]
    fn reconciliation_decision_matrix() {
        let command = golden_prepare_command();
        let outbox_with_state = |state: OutboxDeliveryState| CommandOutboxRecord {
            command_id: command.command_id.clone(),
            command: v1(command.clone()),
            created_at: "2026-08-26T00:00:00Z".into(),
            delivery_state: state,
            attempts: 0,
            last_attempt_at: None,
        };
        assert!(matches!(decide_reconciliation(&outbox_with_state(OutboxDeliveryState::Pending), &JournalObservation::Missing).unwrap(), ReconciliationStep::DeliverCommand));
        assert!(matches!(decide_reconciliation(&outbox_with_state(OutboxDeliveryState::Pending), &JournalObservation::ReceivedIncomplete).unwrap(), ReconciliationStep::ReplayResume));
        assert!(matches!(
            decide_reconciliation(&outbox_with_state(OutboxDeliveryState::Pending), &JournalObservation::Completed(Box::new(applied_ack(&command, 6)))).unwrap(),
            ReconciliationStep::ProjectAcknowledgement
        ));
        assert!(matches!(decide_reconciliation(&outbox_with_state(OutboxDeliveryState::Sent), &JournalObservation::ReceivedIncomplete).unwrap(), ReconciliationStep::ReplayResume));
        assert!(matches!(decide_reconciliation(&outbox_with_state(OutboxDeliveryState::Acknowledged), &JournalObservation::Missing).unwrap(), ReconciliationStep::AlreadyProjected));
        assert_eq!(decide_reconciliation(&outbox_with_state(OutboxDeliveryState::Dead), &JournalObservation::Missing).unwrap_err().code, EXECUTION_OUTBOX_DEAD);
        // journal 完成但 ack echo 错配 → 投影前拒绝，绝不路由。
        let mut tampered = match applied_ack(&command, 6) {
            ExecutionAcknowledgement::V1(ack) => ack,
            ExecutionAcknowledgement::V2(_) => panic!("V1 command must draft a V1 acknowledgement"),
        };
        tampered.identity.execution_generation = 9;
        assert_eq!(
            decide_reconciliation(&outbox_with_state(OutboxDeliveryState::Pending), &JournalObservation::Completed(Box::new(ExecutionAcknowledgement::V1(tampered)))).unwrap_err().code,
            "IDENTITY_MISMATCH"
        );
    }

    #[test]
    fn journal_observation_from_query_validates_byte_identical_replay() {
        let command = golden_prepare_command();
        let digest = execution_command_digest_v1(&command).expect("digest");
        let received = CommandReceivedV1 {
            kind: "command-received".into(),
            command_id: command.command_id.clone(),
            command_digest: digest.clone(),
            command: v1(command.clone()),
            snapshot_handoff_digest: None,
            received_at: "2026-08-26T00:00:00Z".into(),
            journal_revision: 5,
        };
        // status received：合法 received 条目 → ReceivedIncomplete。
        let received_body = serde_json::json!({
            "kind": "query-result",
            "commandId": command.command_id,
            "status": "received",
            "received": serde_json::to_value(&received).expect("received serializes"),
            "acknowledgement": null,
        });
        let query = parse_command_query_result(serde_json::to_vec(&received_body).expect("body serializes").as_slice()).expect("query-result parses");
        assert!(matches!(journal_observation_from_query(&v1(command.clone()), &query).unwrap(), JournalObservation::ReceivedIncomplete));
        // status completed：ack echo 校验通过 → Completed。
        let completed_body = serde_json::json!({
            "kind": "query-result",
            "commandId": command.command_id,
            "status": "completed",
            "received": serde_json::to_value(&received).expect("received serializes"),
            "acknowledgement": serde_json::to_value(applied_ack(&command, 6)).expect("ack serializes"),
        });
        let query = parse_command_query_result(serde_json::to_vec(&completed_body).expect("body serializes").as_slice()).expect("query-result parses");
        assert!(matches!(journal_observation_from_query(&v1(command.clone()), &query).unwrap(), JournalObservation::Completed(_)));
        // journal 里的命令字节与 outbox 不同 → EXECUTION_COMMAND_ID_CONFLICT（byte-identical
        // 判据：tampered command 自带其正确 digest，query-result 本身合法）。
        let mut other = command.clone();
        other.secret_revision = 4;
        let tampered_received = CommandReceivedV1 {
            command_digest: execution_command_digest_v1(&other).expect("tampered digest computes"),
            command: v1(other),
            ..received.clone()
        };
        let tampered_body = serde_json::json!({
            "kind": "query-result",
            "commandId": command.command_id,
            "status": "received",
            "received": serde_json::to_value(&tampered_received).expect("received serializes"),
            "acknowledgement": null,
        });
        let query = parse_command_query_result(serde_json::to_vec(&tampered_body).expect("body serializes").as_slice()).expect("query-result parses");
        assert_eq!(journal_observation_from_query(&v1(command.clone()), &query).unwrap_err().code, EXECUTION_COMMAND_ID_CONFLICT);
    }

    #[test]
    fn command_and_ack_validation_rejects_unknown_and_inconsistent_wire() {
        let command = golden_prepare_command();
        // 序列化含未知字段 → 拒绝（deny_unknown_fields）。
        let mut value = serde_json::to_value(&command).expect("serializes");
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ExecutionCommandV1>(value).is_err());
        // config 耦合破坏：非零 revision 缺 digest。
        let mut broken = command.clone();
        broken.config_values_digest = None;
        assert_eq!(validate_execution_command(&broken).unwrap_err().code, EXECUTION_COMMAND_INVALID);
        // ack：applied 必须 failureCode null；非 drain 不得携带 drainReceiptDigest。
        let unwrap_v1_ack = |ack: ExecutionAcknowledgement| match ack {
            ExecutionAcknowledgement::V1(ack) => ack,
            ExecutionAcknowledgement::V2(_) => panic!("V1 command must draft a V1 acknowledgement"),
        };
        let mut bad_ack = unwrap_v1_ack(applied_ack(&command, 6));
        bad_ack.failure_code = Some("X".into());
        assert_eq!(validate_execution_acknowledgement(&bad_ack).unwrap_err().code, EXECUTION_ACKNOWLEDGEMENT_INVALID);
        let mut drain_ack = unwrap_v1_ack(applied_ack(&command, 6));
        drain_ack.operation = WasmExecutionOperation::Drain;
        drain_ack.drain_receipt_digest = Some("9".repeat(64));
        assert!(validate_execution_acknowledgement(&drain_ack).is_ok());
        // rejected drain 必须 drainReceiptDigest:null 且 failureCode 有界。
        let mut rejected_drain = drain_ack.clone();
        rejected_drain.result = AcknowledgementResult::Rejected;
        rejected_drain.failure_code = Some("EXECUTION_DRAIN_RECEIPT_UNAVAILABLE".into());
        rejected_drain.drain_receipt_digest = None;
        assert!(validate_execution_acknowledgement(&rejected_drain).is_ok());
        // query-result 耦合破坏：completed 缺 acknowledgement。
        let bad_query = serde_json::json!({
            "kind": "query-result",
            "commandId": command.command_id,
            "status": "completed",
            "received": null,
            "acknowledgement": null,
        });
        assert!(parse_command_query_result(serde_json::to_vec(&bad_query).expect("serializes").as_slice()).is_err());
    }

    #[test]
    fn correlate_acknowledgement_rejects_every_echo_mismatch() {
        let command = golden_prepare_command();
        let base = match applied_ack(&command, 6) {
            ExecutionAcknowledgement::V1(ack) => ack,
            ExecutionAcknowledgement::V2(_) => panic!("V1 command must draft a V1 acknowledgement"),
        };
        assert!(correlate_acknowledgement(&command, &base).is_ok());
        let mut wrong_id = base.clone();
        wrong_id.command_id = "018f1e2c-3d4b-7a5e-9f01-23456789abce".into();
        assert_eq!(correlate_acknowledgement(&command, &wrong_id).unwrap_err().code, "COMMAND_ID_MISMATCH");
        let mut wrong_operation = base.clone();
        wrong_operation.operation = WasmExecutionOperation::Start;
        assert_eq!(correlate_acknowledgement(&command, &wrong_operation).unwrap_err().code, "OPERATION_MISMATCH");
        let mut wrong_binding = base.clone();
        wrong_binding.runtime_binding.catalog_revision = 10;
        assert_eq!(correlate_acknowledgement(&command, &wrong_binding).unwrap_err().code, "RUNTIME_BINDING_MISMATCH");
        let mut wrong_secret = base.clone();
        wrong_secret.secret_values_digest = "e".repeat(64);
        assert_eq!(correlate_acknowledgement(&command, &wrong_secret).unwrap_err().code, "SECRET_SNAPSHOT_MISMATCH");
        let mut wrong_config = base.clone();
        wrong_config.config_snapshot_ref = Some("f".repeat(64));
        assert_eq!(correlate_acknowledgement(&command, &wrong_config).unwrap_err().code, "CONFIG_SNAPSHOT_MISMATCH");
        let mut wrong_capability = base.clone();
        wrong_capability.capability_record_hash = "d".repeat(64);
        assert_eq!(correlate_acknowledgement(&command, &wrong_capability).unwrap_err().code, "CAPABILITY_RECORD_MISMATCH");
    }

    // -----------------------------------------------------------------------
    // 任务 7.6：DrainReceiptV1 wire + Kernel retired 投影
    // -----------------------------------------------------------------------

    // -- drain receipt golden 向量（bun oracle 直读 packages/contracts/
    //    wasm-execution.ts exampleDrainReceiptV1() 于 2026-08-26 产出）。 --
    const GOLDEN_DRAIN_RECEIPT_DIGEST: &str = "de4aee07e935f857d74f8204db46d5c2891e352af1c6212ee7c6b8fe0d7fcf13";

    fn golden_drain_receipt() -> DrainReceiptV1 {
        DrainReceiptV1 {
            schema_version: 1,
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into(),
            application_id: "vector".into(),
            execution: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 2 },
            package_digest: "0".repeat(64),
            runtime_binding: vector_binding(),
            route_generation: 4,
            drained_request_count: 2,
            deadline_at: "2026-08-26T00:00:30.000Z".into(),
            forced_kill_at: None,
            result: WasmDrainResult::Drained,
            completed_at: "2026-08-26T00:00:28.000Z".into(),
            journal_revision: 7,
            receipt_digest: GOLDEN_DRAIN_RECEIPT_DIGEST.into(),
        }
    }

    /// 变异后重封 receiptDigest（digest 公式忽略该字段自身，先算后赋总是自洽）。
    fn resealed(mut receipt: DrainReceiptV1) -> DrainReceiptV1 {
        receipt.receipt_digest = drain_receipt_digest_v1(&receipt).expect("digest recomputes");
        receipt
    }

    #[test]
    fn golden_drain_receipt_digest_matches_ts_oracle() {
        let receipt = golden_drain_receipt();
        assert!(validate_drain_receipt(&receipt).is_ok());
        assert_eq!(drain_receipt_digest_v1(&receipt).expect("digest computes"), GOLDEN_DRAIN_RECEIPT_DIGEST);
        // 与实现无关的 oracle 复算：序列化 → 去掉 receiptDigest → JCS → 域前缀单次 SHA-256。
        let mut value = serde_json::to_value(&receipt).expect("receipt serializes");
        value.as_object_mut().expect("object").remove("receiptDigest");
        let payload = jcs_bytes(&value).expect("jcs bytes");
        assert_eq!(oracle_domain_digest(DRAIN_RECEIPT_DIGEST_DOMAIN, &payload), GOLDEN_DRAIN_RECEIPT_DIGEST);
        // JCS round-trip：精确键集（deny_unknown_fields）保真。
        let bytes = jcs_bytes(&receipt).expect("receipt jcs");
        let parsed: DrainReceiptV1 = serde_json::from_slice(&bytes).expect("receipt parses");
        assert_eq!(parsed, receipt);
    }

    #[test]
    fn drain_receipt_validation_rejects_inconsistent_wire() {
        // digest 与字段不一致（改 drainedRequestCount 但保留旧 digest）。
        let mut wrong_count = golden_drain_receipt();
        wrong_count.drained_request_count = 3;
        assert_eq!(validate_drain_receipt(&wrong_count).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        // forced-kill 必须携带不早于 deadline 的 forcedKillAt。
        let mut missing_kill = golden_drain_receipt();
        missing_kill.result = WasmDrainResult::ForcedKill;
        missing_kill.receipt_digest = drain_receipt_digest_v1(&missing_kill).expect("reseal");
        assert_eq!(validate_drain_receipt(&missing_kill).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        let mut early_kill = golden_drain_receipt();
        early_kill.result = WasmDrainResult::ForcedKill;
        early_kill.forced_kill_at = Some("2026-08-26T00:00:29.999Z".into());
        assert_eq!(validate_drain_receipt(&resealed(early_kill)).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        // drained 不得携带 forcedKillAt。
        let mut killed_drained = golden_drain_receipt();
        killed_drained.forced_kill_at = Some("2026-08-26T00:00:30.000Z".into());
        assert_eq!(validate_drain_receipt(&resealed(killed_drained)).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        // forcedKillAt 恰等于 deadlineAt（at or after）合法。
        let mut at_deadline = golden_drain_receipt();
        at_deadline.result = WasmDrainResult::ForcedKill;
        at_deadline.forced_kill_at = Some("2026-08-26T00:00:30.000Z".into());
        at_deadline.completed_at = "2026-08-26T00:00:30.500Z".into();
        assert!(validate_drain_receipt(&resealed(at_deadline)).is_ok());
        // 结构非法：未知字段 / 坏 commandId / 坏 applicationId。
        let mut value = serde_json::to_value(golden_drain_receipt()).expect("serializes");
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<DrainReceiptV1>(value).is_err());
        let mut bad_id = golden_drain_receipt();
        bad_id.command_id = "not-a-uuid".into();
        assert_eq!(validate_drain_receipt(&bad_id).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        let mut bad_app = golden_drain_receipt();
        bad_app.application_id = "Vector".into();
        assert_eq!(validate_drain_receipt(&bad_app).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        // ack 一致性：drainReceiptDigest 必须等于 receipt 的精确 digest。
        let receipt = golden_drain_receipt();
        let drain_command = golden_start_command();
        let mut ack = match applied_ack(&drain_command, 7) {
            ExecutionAcknowledgement::V1(ack) => ack,
            ExecutionAcknowledgement::V2(_) => panic!("V1 command must draft a V1 acknowledgement"),
        };
        ack.operation = WasmExecutionOperation::Drain;
        ack.drain_receipt_digest = Some("9".repeat(64));
        assert_eq!(correlate_drain_receipt_with_acknowledgement(&ack, &receipt).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        ack.drain_receipt_digest = Some(receipt.receipt_digest.clone());
        assert!(correlate_drain_receipt_with_acknowledgement(&ack, &receipt).is_ok());
    }

    /// 投影世界：已授权 drain 命令（rev 1）+ retiring 记录（rev 2）。
    /// deadline 00:00:30 来自 capability record，翻转发生在 00:00:10，route era = 4。
    fn drain_projection_world() -> (WasmCommandControlState, ExecutionCommandV1) {
        let mut command = golden_start_command();
        command.command_id = "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into();
        command.operation = WasmExecutionOperation::Drain;
        command.expected_kernel_control_revision = 0;
        command.expected_journal_revision = 7;
        let mut state = WasmCommandControlState::default();
        state.authorize_command(0, v1(command.clone()), "2026-08-26T00:00:10.000Z".into()).expect("authorize drain command");
        state
            .authorize_retirement(
                1,
                RetiringExecutionRecord {
                    drain_command_id: command.command_id.clone(),
                    application_id: "vector".into(),
                    execution: command.identity.clone(),
                    package_digest: command.package_digest.clone(),
                    runtime_binding: command.runtime_binding.clone(),
                    route_generation: 4,
                    deadline_at_epoch_millis: parse_rfc3339_utc_millis("2026-08-26T00:00:30.000Z").expect("deadline parses"),
                    flip_at_epoch_millis: parse_rfc3339_utc_millis("2026-08-26T00:00:10.000Z").expect("flip parses"),
                    retired: false,
                    accepted_receipt_digest: None,
                },
            )
            .expect("authorize retirement");
        assert_eq!(state.control_revision, 2);
        (state, command)
    }

    /// stale 世界：retiring 记录按翻转时刻的判据建档，与随后授权的 drain 命令
    /// （及 echo 一致的 receipt）在 execution/binding/route era 上不同——receipt
    /// 通过命令 correlate，但与 retiring 记录不同（spec stale 场景的唯一可达路径）。
    fn drain_stale_world(retiring: RetiringExecutionRecord) -> (WasmCommandControlState, ExecutionCommandV1) {
        let mut command = golden_start_command();
        command.command_id = "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into();
        command.operation = WasmExecutionOperation::Drain;
        command.expected_kernel_control_revision = 0;
        command.expected_journal_revision = 7;
        let mut state = WasmCommandControlState::default();
        state.authorize_command(0, v1(command.clone()), "2026-08-26T00:00:10.000Z".into()).expect("authorize drain command");
        state.authorize_retirement(1, retiring).expect("authorize retirement");
        (state, command)
    }

    #[test]
    fn retired_is_written_only_by_receipt_projection_and_replay_never_counts_twice() {
        let (mut state, command) = drain_projection_world();
        let receipt = golden_drain_receipt();
        // 投影前：lifecycle 绝不是 retired（spec "MUST NOT write retired ... until"）。
        assert!(!state.find_retirement(&command.command_id).expect("retiring record").retired);
        // 投影前 CAS 冲突（模拟 receipt 已在 journal、Kernel 崩溃后 head 已被推进）：
        // 零写入、retired 保持 false——receipt 丢失只能重放，不能旁路。
        assert_eq!(state.project_drain_receipt(1, &receipt).unwrap_err().code, CONTROL_REVISION_CONFLICT);
        assert!(!state.find_retirement(&command.command_id).expect("retiring record").retired);
        assert_eq!(state.control_revision, 2);
        // 重放（当前 head）：投影成功，retired 与 accepted digest 同一 CAS 落盘。
        match state.project_drain_receipt(2, &receipt).expect("projection retires") {
            DrainRetirementProjection::Retired { control_revision } => assert_eq!(control_revision, 3),
            DrainRetirementProjection::AlreadyRetired => panic!("first projection must retire"),
        }
        let retired = state.find_retirement(&command.command_id).expect("retiring record");
        assert!(retired.retired);
        assert_eq!(retired.accepted_receipt_digest.as_deref(), Some(GOLDEN_DRAIN_RECEIPT_DIGEST));
        // 重复重放：同一 receipt 幂等返回，不二次递增（"never counts or kills twice"）。
        match state.project_drain_receipt(3, &receipt).expect("replay is idempotent") {
            DrainRetirementProjection::AlreadyRetired => {}
            DrainRetirementProjection::Retired { .. } => panic!("replay must not retire twice"),
        }
        assert_eq!(state.control_revision, 3);
        // 已接受后的异 receipt：fail-closed，绝不改写既有退休。
        let mut other = golden_drain_receipt();
        other.drained_request_count = 9;
        let other = resealed(other);
        assert_eq!(state.project_drain_receipt(3, &other).unwrap_err().code, EXECUTION_ACK_PROJECTION_CONFLICT);
        assert_eq!(state.control_revision, 3);
    }

    #[test]
    fn deadline_forced_kill_receipt_retires_after_validation() {
        let (mut state, _) = drain_projection_world();
        // deadline 时刻仍有 in-flight：计数 0、forcedKillAt == deadlineAt（at or after）。
        let mut forced = golden_drain_receipt();
        forced.result = WasmDrainResult::ForcedKill;
        forced.drained_request_count = 0;
        forced.forced_kill_at = Some("2026-08-26T00:00:30.000Z".into());
        forced.completed_at = "2026-08-26T00:00:30.500Z".into();
        let forced = resealed(forced);
        assert!(validate_drain_receipt(&forced).is_ok());
        match state.project_drain_receipt(2, &forced).expect("forced-kill receipt retires") {
            DrainRetirementProjection::Retired { control_revision } => assert_eq!(control_revision, 3),
            DrainRetirementProjection::AlreadyRetired => panic!("first projection must retire"),
        }
        assert!(state.find_retirement(&forced.command_id).expect("retiring record").retired);
    }

    #[test]
    fn stale_execution_receipt_keeps_route_fenced_without_retiring() {
        // 基准 retiring 判据（翻转时刻 (1,2)/binding9/era 4——与 drain 命令一致）。
        let base_retiring = |execution: WasmExecutionIdentityV1, catalog_revision: u64, route_generation: u64| RetiringExecutionRecord {
            drain_command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into(),
            application_id: "vector".into(),
            execution,
            package_digest: "0".repeat(64),
            runtime_binding: RuntimeBindingIdentityV1 { catalog_revision, ..vector_binding() },
            route_generation,
            deadline_at_epoch_millis: parse_rfc3339_utc_millis("2026-08-26T00:00:30.000Z").expect("deadline parses"),
            flip_at_epoch_millis: parse_rfc3339_utc_millis("2026-08-26T00:00:10.000Z").expect("flip parses"),
            retired: false,
            accepted_receipt_digest: None,
        };
        // retiring 记录的 execution generation 更高（3）：receipt（echo 一致，(1,2)）stale。
        let (mut state, _) = drain_stale_world(base_retiring(
            WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 3 },
            9,
            4,
        ));
        assert_eq!(state.project_drain_receipt(2, &golden_drain_receipt()).unwrap_err().code, DRAIN_RECEIPT_STALE);
        // retiring 记录的 binding 更新（catalog revision 10）。
        let (mut state, _) = drain_stale_world(base_retiring(
            WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 2 },
            10,
            4,
        ));
        assert_eq!(state.project_drain_receipt(2, &golden_drain_receipt()).unwrap_err().code, DRAIN_RECEIPT_STALE);
        // retiring 记录的 route era 不同（5）。
        let (mut state, _) = drain_stale_world(base_retiring(
            WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 2 },
            9,
            5,
        ));
        assert_eq!(state.project_drain_receipt(2, &golden_drain_receipt()).unwrap_err().code, DRAIN_RECEIPT_STALE);
        // 全部拒绝后：不写 retired、零 revision、路由保持围栏。
        let record = state.find_retirement("018f1e2c-3d4b-7a5e-9f01-23456789abcd").expect("retiring record");
        assert!(!record.retired);
        assert!(record.accepted_receipt_digest.is_none());
        assert_eq!(state.control_revision, 2);
    }

    #[test]
    fn invalid_deadline_and_unknown_command_fail_closed_without_retiring() {        let (mut state, _) = drain_projection_world();
        // deadline 与 capability record 供给的精确值不同。
        let mut wrong_deadline = golden_drain_receipt();
        wrong_deadline.deadline_at = "2026-08-26T00:00:29.000Z".into();
        assert_eq!(state.project_drain_receipt(2, &resealed(wrong_deadline)).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        // receipt 寻址不存在的 drain 命令。
        let mut unknown = golden_drain_receipt();
        unknown.command_id = "018f1e2c-3d4b-7b9d-8e01-001122334455".into();
        assert_eq!(state.project_drain_receipt(2, &resealed(unknown)).unwrap_err().code, EXECUTION_OUTBOX_COMMAND_UNKNOWN);
        // 命令 echo 错配（package digest）。
        let mut wrong_package = golden_drain_receipt();
        wrong_package.package_digest = "1".repeat(64);
        assert_eq!(state.project_drain_receipt(2, &resealed(wrong_package)).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        assert!(!state.find_retirement("018f1e2c-3d4b-7a5e-9f01-23456789abcd").expect("retiring record").retired);
        assert_eq!(state.control_revision, 2);
        // authorize_retirement 的结构性非法：deadline 早于翻转；重复建档。
        let mut duplicate = RetiringExecutionRecord {
            drain_command_id: "018f1e2c-3d4b-7c9d-8e01-001122334455".into(),
            application_id: "vector".into(),
            execution: WasmExecutionIdentityV1 { sandbox_id: "sbx-vector".into(), version_id: VECTOR_VERSION_ID.into(), preparation_generation: 1, execution_generation: 2 },
            package_digest: "0".repeat(64),
            runtime_binding: vector_binding(),
            route_generation: 4,
            deadline_at_epoch_millis: parse_rfc3339_utc_millis("2026-08-26T00:00:09.000Z").expect("deadline parses"),
            flip_at_epoch_millis: parse_rfc3339_utc_millis("2026-08-26T00:00:10.000Z").expect("flip parses"),
            retired: false,
            accepted_receipt_digest: None,
        };
        assert_eq!(state.authorize_retirement(2, duplicate.clone()).unwrap_err().code, DRAIN_RECEIPT_INVALID);
        duplicate.deadline_at_epoch_millis = parse_rfc3339_utc_millis("2026-08-26T00:00:30.000Z").expect("deadline parses");
        state.authorize_retirement(2, duplicate).expect("valid retirement records");
        // 同一 drain 命令重复建档 fail-closed（零写入）。
        let again = state.find_retirement("018f1e2c-3d4b-7c9d-8e01-001122334455").expect("just recorded").clone();
        assert_eq!(state.authorize_retirement(3, again).unwrap_err().code, EXECUTION_OUTBOX_DUPLICATE_COMMAND);
        assert_eq!(state.control_revision, 3);
    }
    #[test]
    fn delivery_attempt_bookkeeping_consumes_one_revision_and_is_idempotent_for_terminal_states() {
        let (mut state, command) = drain_projection_world();
        let head = state.control_revision;
        // pending → sent：attempts +1、lastAttemptAt 落盘、controlRevision 恰 +1。
        state.record_delivery_attempt(head, &command.command_id, "2026-08-26T00:00:11.000Z".into()).expect("first attempt records");
        let entry = state.find_outbox(&command.command_id).expect("outbox entry");
        assert_eq!(entry.delivery_state, OutboxDeliveryState::Sent);
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.last_attempt_at.as_deref(), Some("2026-08-26T00:00:11.000Z"));
        assert_eq!(state.control_revision, head + 1);
        // 重复簿记：仍是已提交 mutation（每次尝试都计数）。
        state.record_delivery_attempt(head + 1, &command.command_id, "2026-08-26T00:00:12.000Z".into()).expect("second attempt records");
        assert_eq!(state.find_outbox(&command.command_id).expect("entry").attempts, 2);
        assert_eq!(state.control_revision, head + 2);
        // 期望 revision 失配：零写入。
        assert_eq!(state.record_delivery_attempt(head, &command.command_id, "2026-08-26T00:00:13.000Z".into()).unwrap_err().code, CONTROL_REVISION_CONFLICT);
        assert_eq!(state.control_revision, head + 2);
        // 未知命令 / 非法时间戳 fail-closed。
        assert_eq!(state.record_delivery_attempt(head + 2, "018f1e2c-3d4b-7b9d-8e01-001122334455", "2026-08-26T00:00:13.000Z".into()).unwrap_err().code, EXECUTION_OUTBOX_COMMAND_UNKNOWN);
        assert_eq!(state.record_delivery_attempt(head + 2, &command.command_id, "not-a-timestamp".into()).unwrap_err().code, EXECUTION_COMMAND_INVALID);
        // acknowledged 的簿记是幂等 no-op（零 revision 消耗）。
        let ack = ExecutionAcknowledgement::V1(ExecutionAcknowledgementV1 {
            schema_version: 1,
            command_id: command.command_id.clone(),
            operation: command.operation,
            identity: command.identity.clone(),
            package_digest: command.package_digest.clone(),
            runtime_binding: command.runtime_binding.clone(),
            capability_record_revision: command.capability_record_revision,
            capability_record_hash: command.capability_record_hash.clone(),
            secret_revision: command.secret_revision,
            secret_snapshot_ref: command.secret_snapshot_ref.clone(),
            secret_values_digest: command.secret_values_digest.clone(),
            config_revision: command.config_revision,
            config_snapshot_ref: command.config_snapshot_ref.clone(),
            config_values_digest: command.config_values_digest.clone(),
            drain_receipt_digest: Some("9".repeat(64)),
            result: AcknowledgementResult::Applied,
            failure_code: None,
            journal_revision: command.expected_journal_revision + 2,
        });
        state.project_acknowledgement(head + 2, &ack).expect("ack projects");
        let head = state.control_revision;
        state.record_delivery_attempt(head, &command.command_id, "2026-08-26T00:00:14.000Z".into()).expect("acknowledged bookkeeping is a no-op");
        assert_eq!(state.control_revision, head, "no revision is consumed for an acknowledged entry");
    }
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. capabilityRecordRevision 在 command/ack 处取下界 1（与 contracts 同款取舍；
//    NodeCapabilityRecordV1/AdmissionProofV1/readiness 的 revision 均 >= 1）。
// 2. ack.journal_revision 下界 = command.expectedJournalRevision + 2：新命令的 received
//    条目必然落在 expected+1，completion 只能更晚（TS 契约层未做此检查，Kernel 投影层
//    fail-closed 收紧；interleaved 写入只会更大，不影响合法 ack）。
// 3. drain/stop 的代次语义：不分配新代次，命令携带目标 execution 的当前 tuple 且要求
//    双代次 >= 1（spec "for drain/stop, the command still carries the adopted snapshot
//    digests and they remain part of the identity fence"）。
// 4. reconcile_projection 在 CONTROL_REVISION_CONFLICT 时零写入返回错误；恢复的唯一
//    路径是重新 query/replay 再进入本函数（"只有 replay 可发生、绝不先路由"）。本模块
//    没有任何 route-pointer 写入 API——route CAS 是 2.4 的独立授权，类型层即无法从
//    journal/projection 状态直达路由。
// 5. journal_observation_from_query 以 commandDigest + 结构相等双判 byte-identical
//    replay（JCS 字节与 digest 一一对应；双保险不引入第二套相等语义）。
// 6. OutboxDeliveryState::Sent 与 Pending 在决策层等价（spec：sent is advisory and may
//    be replayed）；mark-sent 不消耗 controlRevision（mutation 清单未列入）。
// 7.（任务 7.6）receipt 判据分码：与 drain 命令的 echo 错配（identity/package/binding）
//    → DRAIN_RECEIPT_INVALID（spec INVALID 清单的 "mismatched identity"）；与 retiring
//    记录（翻转时刻捕捉的 execution/binding/route era）不同 → DRAIN_RECEIPT_STALE——
//    该路径仅在"记录判据与随后授权命令的 tuple 不同"时可达（如翻转后又有 restart 再
//    授权 drain），spec stale 场景的"generation or binding lower/different than the one
//    recorded for the retiring route"正指此层。deadline 与 capability record 精确值不符
//    → DRAIN_RECEIPT_INVALID（spec "the exact drain deadline supplied by the Kernel
//    capability record"）。retirements 记录只能以未退休态建档（authorize_retirement
//    拒绝 retired/accepted 预置），真实接线把它与 wasm_activation 的指针 CAS 绑定到
//    同一提交；supervisor 侧 receipt 的生产布局（与 ack 是否同一 completion 条目）由
//    后续接线任务固定后可再收紧 correlate_drain_receipt_with_acknowledgement 的
//    journalRevision 一致性。
