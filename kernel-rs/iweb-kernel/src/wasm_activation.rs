//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 2.4）：通用激活 gate——按
//! application-sandbox delta（O2 通用收紧），在 Kernel route CAS 事务内再次检查
//! readiness lease 未过期；rollback event 持久化目标 runtime binding identity。
//! 覆盖 lease 恰在 CAS 中过期（相等即过期）、candidate killed、route CAS
//! conflict 与旧 active 保留。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/application-sandbox/spec.md
//! "Version activation and rollback are atomic" + wasm-application-runtime spec.md
//! "Readiness leases use a nonce-bound canonical wire" / "Activation has a
//! replayable Kernel control wire"（RouteEventV1/LeaseConsumeRecordV1/恢复条款）。
//! 纯函数权威：packages/contracts/wasm-health.ts（checkReadinessLeaseExpiry 的
//! CAS 相等即过期、consumeReadinessLeaseV2 的 nonce 先于过期判定）。
//!
//! 正交意图：
//! 1. ReadinessLeaseV2 wire（nonce 文法、leaseDigest 公式复算、config 耦合、
//!    correlate 全字段一致）；
//! 2. 激活 CAS 事务 evaluate_activation_cas：单一线性化点上按固定顺序判定
//!    route conflict → candidate（registry/alive/secret 与 P fence/rollback
//!    retention）→ binding revoked → lease correlate → nonce 台账 → 过期
//!    （now == expiresAt 即过期，拒绝且不消费 nonce）；
//! 3. apply_activation 原子提交（指针翻转、nonce 消费、事件与 activationId
//!    记录同一提交；rejected 事件不消费 nonce）+ query/replay（同命令幂等、
//!    异命令 ACTIVATION_ID_CONFLICT）；
//! 4. rollback 走同一 gate，并把目标 runtime binding identity 持久化进
//!    RollbackRetentionRecord（含本事件）；
//! 5. 不确定提交恢复：指针已翻但事件缺失 → 从 pending 意图重建精确事件；
//!    消费标记无已提交路由 → 丢弃标记、租约回到未消费、按原
//!    expectedRouteGeneration 重放；无意图的翻指针 fail-closed。
//!
//! 不可调和原因：2/3/5 共享同一判定顺序与 pending 意图，拆分会重引入"CAS 内
//! 复查 lease"与恢复语义矛盾；1 是 2 的编码地基。
//!
//! 建模注记（接线批次映射，非语义变更）：eventId/activationId 由调用方提供
//!（生产为 UUIDv7）；ownerCommandId 采用 activationId 投影。
//!
//! 单版本化（2026-08-29，simplify-wasm-host-services）：V1/V2 双轨 wire 合并为
//! 单一形态——命令/事件/rollback/lease 各只有一个类型（原 V2 envelope 的字段
//! 集；capability_record_revision/hash 为必填；hostServicePolicyDigest 为必填
//! String，空串 = 该应用不获得 host services）。envelope 只有一个 protocol
//! 字面量 "iweb-wasm-activation"。删除跨版本分派与 ACTIVATION_VERSION_MISMATCH
//!（不存在第二版本可混入，deny_unknown_fields 仍拒绝任何未知键）。时间戳统一
//! RFC3339 原串（digest 字节保真）；三个 self-digest（commandDigest/eventDigest/
//! rollbackDigest）与 leaseDigest 复算 fail-closed 语义不变。TS 对位
//! packages/contracts/wasm-health.ts。

use crate::wasm_admission::{
    format_rfc3339_utc_millis, jcs_bytes, parse_rfc3339_utc_millis, parse_wasm_version_id,
    RuntimeBindingIdentityV1, WasmActivePointerV1, WasmVersionIdentity, WASM_U53_MAX,
};
use crate::wasm_commands::{runtime_binding_v2_from_v1, validate_runtime_binding_v2, RuntimeBindingIdentityV2};
use crate::wasm_secrets::matches_secret_revision_fence;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::Sha256;
#[cfg(test)]
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误码
// ---------------------------------------------------------------------------

/// spec 已命名的五个路由事件拒绝码。
pub const ACTIVATION_ROUTE_CONFLICT: &str = "ACTIVATION_ROUTE_CONFLICT";
pub const READINESS_LEASE_EXPIRED: &str = "READINESS_LEASE_EXPIRED";
pub const READINESS_LEASE_MISMATCH: &str = "READINESS_LEASE_MISMATCH";
pub const ACTIVATION_CANDIDATE_NOT_READY: &str = "ACTIVATION_CANDIDATE_NOT_READY";
pub const ACTIVATION_BINDING_REVOKED: &str = "ACTIVATION_BINDING_REVOKED";
/// envelope 级重放冲突（不产生 route event）。
pub const ACTIVATION_ID_CONFLICT: &str = "ACTIVATION_ID_CONFLICT";
/// 命令/候选/lease 的结构性非法（不产生 route event）。
pub const WASM_ACTIVATION_INVALID: &str = "WASM_ACTIVATION_INVALID";
/// 不一致状态需要 owner 修复。
pub const WASM_ACTIVATION_FAIL_CLOSED: &str = "WASM_ACTIVATION_FAIL_CLOSED";
/// 存在未完成恢复前拒绝新激活。
pub const WASM_ACTIVATION_REPAIR_REQUIRED: &str = "WASM_ACTIVATION_REPAIR_REQUIRED";
/// 崩溃注入标记（仅驱动测试用）。
pub const WASM_ACTIVATION_SIMULATED_CRASH: &str = "WASM_ACTIVATION_SIMULATED_CRASH";

/// V2（service-enabled）激活租约摘要域（design「Decisions 1」域表；
/// digestV2 的 0x00 分隔公式）。
pub const SERVICE_READINESS_LEASE_DIGEST_DOMAIN: &str = "iweb-wasm-readiness-v2";
/// V2 激活命令摘要域（spec 命名 "ActivationCommandV2 uses iweb-wasm-activation-v2"；
/// 16 域表内字面量，digest_v2 拒绝表外域）。
pub const ACTIVATION_COMMAND_DIGEST_DOMAIN_V2: &str = "iweb-wasm-activation-v2";
/// V2 路由事件摘要域（spec 命名 "RouteEventV2 uses iweb-wasm-route-event-v2"）。
pub const ROUTE_EVENT_DIGEST_DOMAIN_V2: &str = "iweb-wasm-route-event-v2";
/// V2 rollback 保留记录摘要域（design「Decisions 1」16 域表的 rollback 字面量）。
pub const ROLLBACK_RECORD_DIGEST_DOMAIN_V2: &str = "iweb-wasm-rollback-v2";

/// 结构化激活错误：code 为稳定 owner 可见码，detail 不含秘密。
#[derive(Debug, Clone, PartialEq)]
pub struct ActivationError {
    pub code: &'static str,
    pub detail: String,
}

impl ActivationError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ActivationError {}

fn err(code: &'static str, detail: impl Into<String>) -> ActivationError {
    ActivationError::new(code, detail)
}

fn lease_mismatch(detail: impl Into<String>) -> ActivationError {
    err(READINESS_LEASE_MISMATCH, detail)
}

// ---------------------------------------------------------------------------
// 文法
// ---------------------------------------------------------------------------

struct ActivationRegexes {
    application_id: regex::Regex,
    sandbox_id: regex::Regex,
    sha256_hex: regex::Regex,
    lease_nonce: regex::Regex,
    uuid_v7: regex::Regex,
}

fn regexes() -> &'static ActivationRegexes {
    static REGEXES: OnceLock<ActivationRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| ActivationRegexes {
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
        sandbox_id: regex::Regex::new(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$").expect("sandbox id regex"),
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        // 16 随机字节的 32 位小写十六进制；绝不从时间戳或 versionId 派生。
        lease_nonce: regex::Regex::new(r"^[a-f0-9]{32}$").expect("lease nonce regex"),
        uuid_v7: regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").expect("uuidv7 regex"),
    })
}

fn check_application_id(value: &str) -> Result<(), ActivationError> {
    if regexes().application_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_ACTIVATION_INVALID, "applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"))
    }
}

fn check_sandbox_id(value: &str) -> Result<(), ActivationError> {
    if regexes().sandbox_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_ACTIVATION_INVALID, "sandboxId must start with a lower-case letter and be at most 63 ASCII bytes"))
    }
}

fn check_sha256_hex(value: &str, field: &str) -> Result<(), ActivationError> {
    if regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_ACTIVATION_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

/// 单版本 policy 钉文法：空串（= 无 host services 的零值）或 64 位小写十六进制。
fn check_policy_digest(value: &str, field: &str) -> Result<(), ActivationError> {
    if value.is_empty() || regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_ACTIVATION_INVALID, format!("{field} must be empty or 64 lower-case hex characters")))
    }
}

fn check_uuid_v7(value: &str, field: &str) -> Result<(), ActivationError> {
    if regexes().uuid_v7.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_ACTIVATION_INVALID, format!("{field} must be a lower-case UUIDv7")))
    }
}

fn require_u53(value: u64, minimum: u64, maximum: u64, field: &str) -> Result<(), ActivationError> {
    if value >= minimum && value <= maximum && value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(WASM_ACTIVATION_INVALID, format!("{field} must be an integer between {minimum} and {maximum}")))
    }
}

/// configRevision 耦合：0 ⇔ 两个 config 字段为 null；非零 ⇒ 两者齐全。
fn check_config_coupling(config_revision: u64, config_snapshot_ref: &Option<String>, config_values_digest: &Option<String>, field: &str) -> Result<(), ActivationError> {
    let ref_present = config_snapshot_ref.is_some();
    let digest_present = config_values_digest.is_some();
    if ref_present != digest_present {
        return Err(err(WASM_ACTIVATION_INVALID, format!("{field}: configValuesDigest is null exactly when configSnapshotRef is null")));
    }
    if config_revision == 0 && ref_present {
        return Err(err(WASM_ACTIVATION_INVALID, format!("{field}: configRevision 0 requires configSnapshotRef null and configValuesDigest null")));
    }
    if config_revision > 0 && !ref_present {
        return Err(err(WASM_ACTIVATION_INVALID, format!("{field}: a non-zero configRevision requires both configSnapshotRef and configValuesDigest")));
    }
    Ok(())
}

/// 测试专用：golden JCS 指纹复算（sha256(JCS(bytes))）。
#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// ServiceReadinessLeaseV2（唯一激活租约形态；单版本化后不再有 V1 代际租约）
//
// 域 digestV2("iweb-wasm-readiness-v2", JCS(record with leaseDigest omitted))
// = SHA-256(ASCII(domain) || 0x00 || payload)。hostServicePolicyDigest 为必填
// String：空串 = 该应用不获得 host services（命令/registry 行同款空值语义，
// 三方 correlate 仍逐字节相等）。
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceReadinessLeaseV2 {
    pub schema_version: u64,
    pub lease_nonce: String,
    pub sandbox_id: String,
    pub version_id: String,
    pub package_digest: String,
    pub runtime_binding: RuntimeBindingIdentityV2,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    /// HostServicePolicyV2.policyDigest（64 位小写十六进制）；空串 = 无 host
    /// services（零值投影，不是缺键）。
    pub host_service_policy_digest: String,
    pub secret_revision: u64,
    pub secret_values_digest: String,
    pub config_revision: u64,
    pub config_snapshot_ref: Option<String>,
    pub config_values_digest: Option<String>,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    /// RFC3339-UTC 原串（digest 输入的字节保真）。
    pub issued_at: String,
    pub expires_at: String,
    pub lease_digest: String,
}

impl ServiceReadinessLeaseV2 {
    pub fn issued_at_epoch_millis(&self) -> Result<u64, ActivationError> {
        parse_rfc3339_utc_millis(&self.issued_at).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/issuedAt: {}", e.detail)))
    }

    pub fn expires_at_epoch_millis(&self) -> Result<u64, ActivationError> {
        parse_rfc3339_utc_millis(&self.expires_at).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/expiresAt: {}", e.detail)))
    }

    /// 结构校验（不含与候选的 correlate）：nonce 文法、能力钉、binding 钉、
    /// policy 空值或 64-hex、config 耦合、leaseDigest 复算一致。
    pub fn validate(&self) -> Result<(), ActivationError> {
        if self.schema_version != 2 {
            return Err(lease_mismatch("schemaVersion must be exactly 2 for a ServiceReadinessLeaseV2"));
        }
        if !regexes().lease_nonce.is_match(&self.lease_nonce) {
            return Err(lease_mismatch("leaseNonce must be 32 lower-case hex characters"));
        }
        check_sandbox_id(&self.sandbox_id).map_err(|e| lease_mismatch(e.detail))?;
        check_sha256_hex(&self.package_digest, "packageDigest").map_err(|e| lease_mismatch(e.detail))?;
        validate_runtime_binding_v2(&self.runtime_binding).map_err(|e| lease_mismatch(e.detail))?;
        require_u53(self.capability_record_revision, 1, WASM_U53_MAX, "capabilityRecordRevision").map_err(|e| lease_mismatch(e.detail))?;
        check_sha256_hex(&self.capability_record_hash, "capabilityRecordHash").map_err(|e| lease_mismatch(e.detail))?;
        check_policy_digest(&self.host_service_policy_digest, "hostServicePolicyDigest").map_err(|e| lease_mismatch(e.detail))?;
        require_u53(self.secret_revision, 0, WASM_U53_MAX, "secretRevision").map_err(|e| lease_mismatch(e.detail))?;
        check_sha256_hex(&self.secret_values_digest, "secretValuesDigest").map_err(|e| lease_mismatch(e.detail))?;
        require_u53(self.config_revision, 0, WASM_U53_MAX, "configRevision").map_err(|e| lease_mismatch(e.detail))?;
        if let Some(reference) = &self.config_snapshot_ref {
            check_sha256_hex(reference, "configSnapshotRef").map_err(|e| lease_mismatch(e.detail))?;
        }
        if let Some(digest) = &self.config_values_digest {
            check_sha256_hex(digest, "configValuesDigest").map_err(|e| lease_mismatch(e.detail))?;
        }
        check_config_coupling(self.config_revision, &self.config_snapshot_ref, &self.config_values_digest, "lease").map_err(|e| lease_mismatch(e.detail))?;
        require_u53(self.preparation_generation, 1, WASM_U53_MAX, "preparationGeneration").map_err(|e| lease_mismatch(e.detail))?;
        require_u53(self.execution_generation, 1, WASM_U53_MAX, "executionGeneration").map_err(|e| lease_mismatch(e.detail))?;
        if self.expires_at_epoch_millis().map_err(|e| lease_mismatch(e.detail))? <= self.issued_at_epoch_millis().map_err(|e| lease_mismatch(e.detail))? {
            return Err(lease_mismatch("expiresAt must be later than issuedAt"));
        }
        if self.lease_digest != compute_service_readiness_lease_digest(self).map_err(|e| lease_mismatch(e.detail))? {
            return Err(lease_mismatch("leaseDigest does not equal digestV2(\"iweb-wasm-readiness-v2\", JCS(record with leaseDigest omitted))"));
        }
        Ok(())
    }
}

/// leaseDigest = digestV2("iweb-wasm-readiness-v2", JCS(record with
/// leaseDigest omitted))——SHA-256(ASCII(domain) || 0x00 || payload)；与 TS
/// computeServiceReadinessLeaseDigestV2 字节一致（golden 向量锁定）。
pub fn compute_service_readiness_lease_digest(lease: &ServiceReadinessLeaseV2) -> Result<String, ActivationError> {
    let mut value = serde_json::to_value(lease).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("lease is not serializable as JSON: {e}")))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| err(WASM_ACTIVATION_INVALID, "the lease must serialize to a JSON object"))?;
    map.remove("leaseDigest");
    let bytes = serde_json::to_vec(&value).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("JCS serialization failed: {e}")))?;
    crate::wasm_host_services::digest_v2(SERVICE_READINESS_LEASE_DIGEST_DOMAIN, &bytes)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, e.detail))
}

/// CAS 线性化时刻的过期判定：单调时钟读数与 expiresAt 相等或更晚即过期
/// （对位 wasm-health.ts checkReadinessLeaseExpiry——相等即过期）。
pub fn check_readiness_lease_expiry_at_cas(now_epoch_millis: u64, expires_at_epoch_millis: u64) -> Result<(), ActivationError> {
    if now_epoch_millis >= expires_at_epoch_millis {
        return Err(err(
            READINESS_LEASE_EXPIRED,
            "the readiness lease expired at or before the CAS linearization instant; a fresh preparation plus exact health attestation is required",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ActivationCommand / 候选（candidate 子对象按 spec 精确键集；单 wire 形态）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationOperation {
    Activate,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivationCandidate {
    pub runtime_kind: String,
    pub sandbox_id: String,
    pub version_id: String,
    pub package_digest: String,
    pub runtime_binding: RuntimeBindingIdentityV2,
    pub admission_proof_ref: String,
    pub admission_proof_digest: String,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    pub secret_revision: u64,
    pub secret_values_digest: String,
    pub config_revision: u64,
    pub config_snapshot_ref: Option<String>,
    pub config_values_digest: Option<String>,
    pub lease_nonce: String,
    pub lease_digest: String,
}

impl ActivationCandidate {
    pub fn validate(&self, application_id: &str) -> Result<(), ActivationError> {
        if self.runtime_kind != "wasm" {
            return Err(err(WASM_ACTIVATION_INVALID, "candidate runtimeKind must be exactly \"wasm\""));
        }
        check_sandbox_id(&self.sandbox_id)?;
        check_sha256_hex(&self.package_digest, "packageDigest")?;
        let (digest, sequence) = parse_wasm_version_id(&self.version_id).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/versionId: {}", e.detail)))?;
        require_u53(sequence, 1, WASM_U53_MAX, "sequence")?;
        let _ = digest;
        validate_runtime_binding_v2(&self.runtime_binding).map_err(|e| err(WASM_ACTIVATION_INVALID, e.detail))?;
        let expected_proof_ref = format!("admission-proof/{application_id}/{}", self.version_id);
        if self.admission_proof_ref != expected_proof_ref {
            return Err(err(WASM_ACTIVATION_INVALID, "admissionProofRef must equal \"admission-proof/<applicationId>/<versionId>\""));
        }
        check_sha256_hex(&self.admission_proof_digest, "admissionProofDigest")?;
        require_u53(self.preparation_generation, 1, WASM_U53_MAX, "preparationGeneration")?;
        require_u53(self.execution_generation, 1, WASM_U53_MAX, "executionGeneration")?;
        require_u53(self.secret_revision, 0, WASM_U53_MAX, "secretRevision")?;
        check_sha256_hex(&self.secret_values_digest, "secretValuesDigest")?;
        require_u53(self.config_revision, 0, WASM_U53_MAX, "configRevision")?;
        if let Some(reference) = &self.config_snapshot_ref {
            check_sha256_hex(reference, "configSnapshotRef")?;
        }
        if let Some(digest) = &self.config_values_digest {
            check_sha256_hex(digest, "configValuesDigest")?;
        }
        check_config_coupling(self.config_revision, &self.config_snapshot_ref, &self.config_values_digest, "candidate")?;
        if !regexes().lease_nonce.is_match(&self.lease_nonce) {
            return Err(err(WASM_ACTIVATION_INVALID, "leaseNonce must be 32 lower-case hex characters"));
        }
        check_sha256_hex(&self.lease_digest, "leaseDigest")?;
        Ok(())
    }
}

/// 唯一激活命令形态（原 V2 envelope 字段集；capability pin 必填，
/// hostServicePolicyDigest 必填 String——空串 = 无 host services）。pure 与
/// wire 共用同一形状：requestedAt 保留 RFC3339 原串（commandDigest 必须覆盖
/// 命令自身的精确字节）。commandDigest 覆盖「完整对象、仅省 commandDigest」
/// 的 JCS 字节。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivationCommand {
    pub schema_version: u64,
    pub activation_id: String,
    pub application_id: String,
    pub operation: ActivationOperation,
    pub expected_route_generation: u64,
    /// 本命令 CAS 所关联的 v2 控制态 revision（wasm-control-state-v2 的单一
    /// controlRevision 计数器；u53）。
    pub expected_control_revision: u64,
    pub candidate: ActivationCandidate,
    /// service-enabled 版本的 HostServicePolicyV2.policyDigest；空串 = 无 host
    /// services。
    pub host_service_policy_digest: String,
    /// capability record pin 实值（admission capability record 的
    /// revision/hash，与 ServiceReadinessLeaseV2 同名钉同源）。
    pub capability_record_revision: u64,
    /// 见 capability_record_revision（64 位小写十六进制）。
    pub capability_record_hash: String,
    pub requested_at: String,
    /// digestV2("iweb-wasm-activation-v2", JCS(record with commandDigest omitted))。
    pub command_digest: String,
}

/// commandDigest = digestV2("iweb-wasm-activation-v2", JCS(command with
/// commandDigest omitted))；与 TS computeActivationCommandDigestV2 字节一致
///（golden 向量锁定）。digest_v2 的域表保证表外域 fail-closed。
pub fn compute_activation_command_digest(command: &ActivationCommand) -> Result<String, ActivationError> {
    let mut value = serde_json::to_value(command)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("the command is not serializable as JSON: {e}")))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| err(WASM_ACTIVATION_INVALID, "the activation command must serialize to a JSON object"))?;
    map.remove("commandDigest");
    let bytes = serde_json::to_vec(&value).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("JCS serialization failed: {e}")))?;
    crate::wasm_host_services::digest_v2(ACTIVATION_COMMAND_DIGEST_DOMAIN_V2, &bytes)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, e.detail))
}

impl ActivationCommand {
    pub fn validate(&self) -> Result<(), ActivationError> {
        if self.schema_version != 2 {
            return Err(err(WASM_ACTIVATION_INVALID, "schemaVersion must be exactly 2"));
        }
        check_uuid_v7(&self.activation_id, "activationId")?;
        check_application_id(&self.application_id)?;
        require_u53(self.expected_route_generation, 0, WASM_U53_MAX, "expectedRouteGeneration")?;
        require_u53(self.expected_control_revision, 0, WASM_U53_MAX, "expectedControlRevision")?;
        check_policy_digest(&self.host_service_policy_digest, "hostServicePolicyDigest")?;
        require_u53(self.capability_record_revision, 1, WASM_U53_MAX, "capabilityRecordRevision")?;
        check_sha256_hex(&self.capability_record_hash, "capabilityRecordHash")?;
        parse_rfc3339_utc_millis(&self.requested_at)
            .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/requestedAt: {}", e.detail)))?;
        check_sha256_hex(&self.command_digest, "commandDigest")?;
        self.candidate.validate(&self.application_id)?;
        // 摘要复算 fail-closed：任何被覆盖字段的篡改（含 policyDigest）在此暴露。
        let computed = compute_activation_command_digest(self)?;
        if computed != self.command_digest {
            return Err(err(
                WASM_ACTIVATION_INVALID,
                "commandDigest does not equal digestV2(\"iweb-wasm-activation-v2\", JCS(record with commandDigest omitted))",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LeaseConsumeRecord / RouteEvent / RollbackRecord（单版本；digest 承载记录的
// 时间戳保留 RFC3339 原串，Kernel 侧由 format_rfc3339_utc_millis 规范渲染，
// 因此 pure==wire）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseConsumeOutcome {
    Consumed,
    AlreadyConsumed,
    Rejected,
}

/// 事件内嵌的租约消费记录（wire 形；consumedAt RFC3339 原串进入 eventDigest
/// 覆盖面）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LeaseConsumeRecord {
    pub schema_version: u64,
    pub lease_nonce: String,
    pub lease_digest: String,
    pub activation_id: String,
    pub application_id: String,
    pub version_id: String,
    pub expected_route_generation: u64,
    pub consumed_at: String,
    pub outcome: LeaseConsumeOutcome,
    /// consumed 为新 generation；其余等于当前 generation。
    pub route_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteEventResult {
    Activated,
    Rejected,
}

/// 唯一路由事件形态。leaseConsume 为 wire 形（consumedAt RFC3339 原串）——
/// eventDigest 覆盖「完整对象、仅省 eventDigest」的 JCS 字节。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteEvent {
    pub schema_version: u64,
    pub event_id: String,
    pub activation_id: String,
    pub application_id: String,
    pub runtime_kind: String,
    pub operation: ActivationOperation,
    pub expected_route_generation: u64,
    pub previous: WasmActivePointerV1,
    pub next: WasmActivePointerV1,
    pub lease_consume: LeaseConsumeRecord,
    pub result: RouteEventResult,
    pub reason_code: Option<String>,
    /// 本次路由翻转绑定的 HostServicePolicyV2.policyDigest（空串 = 无 host
    /// services）。
    pub host_service_policy_digest: String,
    /// 事件持久化时的 v2 控制态 revision（本次 CAS 提交后的 revision）。
    pub control_revision: u64,
    pub route_generation: u64,
    pub created_at: String,
    /// digestV2("iweb-wasm-route-event-v2", JCS(record with eventDigest omitted))。
    pub event_digest: String,
}

/// eventDigest = digestV2("iweb-wasm-route-event-v2", JCS(event with
/// eventDigest omitted))；与 TS computeRouteEventDigestV2 字节一致（golden 锁定）。
pub fn compute_route_event_digest(event: &RouteEvent) -> Result<String, ActivationError> {
    let mut value = serde_json::to_value(event)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("the route event is not serializable as JSON: {e}")))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| err(WASM_ACTIVATION_INVALID, "the route event must serialize to a JSON object"))?;
    map.remove("eventDigest");
    let bytes = serde_json::to_vec(&value).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("JCS serialization failed: {e}")))?;
    crate::wasm_host_services::digest_v2(ROUTE_EVENT_DIGEST_DOMAIN_V2, &bytes)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, e.detail))
}

/// 构造面统一出口：先落全部事实字段（含 controlRevision 盖戳），最后计算
/// eventDigest——摘要覆盖对象其余全部键。
fn route_event_sealed(mut event: RouteEvent) -> Result<RouteEvent, ActivationError> {
    event.event_digest = compute_route_event_digest(&event)?;
    Ok(event)
}

fn check_reason_code(reason: &Option<String>) -> Result<(), ActivationError> {
    match reason {
        None => Ok(()),
        Some(code) => {
            // 与 wasm_commands failureCode 同款有界上划线码。
            let ok = !code.is_empty()
                && code.len() <= 64
                && code.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            if ok {
                Ok(())
            } else {
                Err(err(WASM_ACTIVATION_INVALID, "reasonCode must be null or a bounded upper-case code"))
            }
        }
    }
}

/// RouteEvent 结构校验（持久化/回读面）：result/reason/outcome/generation 四方
/// 耦合 + eventDigest 复算 fail-closed。
pub fn validate_route_event(event: &RouteEvent) -> Result<(), ActivationError> {
    if event.schema_version != 2 {
        return Err(err(WASM_ACTIVATION_INVALID, "schemaVersion must be exactly 2"));
    }
    check_uuid_v7(&event.event_id, "eventId")?;
    check_uuid_v7(&event.activation_id, "activationId")?;
    check_application_id(&event.application_id)?;
    if event.runtime_kind != "wasm" {
        return Err(err(WASM_ACTIVATION_INVALID, "runtimeKind must be exactly \"wasm\""));
    }
    require_u53(event.expected_route_generation, 0, WASM_U53_MAX, "expectedRouteGeneration")?;
    require_u53(event.control_revision, 0, WASM_U53_MAX, "controlRevision")?;
    require_u53(event.route_generation, 0, WASM_U53_MAX, "routeGeneration")?;
    parse_rfc3339_utc_millis(&event.created_at)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/createdAt: {}", e.detail)))?;
    check_policy_digest(&event.host_service_policy_digest, "hostServicePolicyDigest")?;
    check_sha256_hex(&event.event_digest, "eventDigest")?;
    check_reason_code(&event.reason_code)?;
    if event.lease_consume.schema_version != 1 {
        return Err(err(WASM_ACTIVATION_INVALID, "leaseConsume/schemaVersion must be exactly 1"));
    }
    if !regexes().lease_nonce.is_match(&event.lease_consume.lease_nonce) {
        return Err(err(WASM_ACTIVATION_INVALID, "leaseConsume/leaseNonce must be 32 lower-case hex characters"));
    }
    check_sha256_hex(&event.lease_consume.lease_digest, "leaseConsume/leaseDigest")?;
    parse_rfc3339_utc_millis(&event.lease_consume.consumed_at)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/leaseConsume/consumedAt: {}", e.detail)))?;
    match event.result {
        RouteEventResult::Activated => {
            if event.reason_code.is_some() {
                return Err(err(WASM_ACTIVATION_INVALID, "an activated event must carry reasonCode null"));
            }
            if event.lease_consume.outcome != LeaseConsumeOutcome::Consumed {
                return Err(err(WASM_ACTIVATION_INVALID, "an activated event must carry leaseConsume outcome consumed"));
            }
            if event.route_generation != event.expected_route_generation + 1 {
                return Err(err(WASM_ACTIVATION_INVALID, "an activated event must carry routeGeneration = expectedRouteGeneration + 1"));
            }
        }
        RouteEventResult::Rejected => {
            if event.reason_code.is_none() {
                return Err(err(WASM_ACTIVATION_INVALID, "a rejected event must carry a bounded reasonCode"));
            }
            if event.lease_consume.outcome == LeaseConsumeOutcome::Consumed {
                return Err(err(WASM_ACTIVATION_INVALID, "a rejected event must not consume the lease nonce"));
            }
            if event.next != event.previous {
                return Err(err(WASM_ACTIVATION_INVALID, "a rejected event must keep the previous route pointer"));
            }
        }
    }
    // 摘要复算 fail-closed：controlRevision/指针/租约消费/policy 钉任一被覆盖字段
    // 的篡改在此暴露。
    let computed = compute_route_event_digest(event)?;
    if computed != event.event_digest {
        return Err(err(
            WASM_ACTIVATION_INVALID,
            "eventDigest does not equal digestV2(\"iweb-wasm-route-event-v2\", JCS(record with eventDigest omitted))",
        ));
    }
    Ok(())
}

/// RollbackRecord.result：记录仅随成功提交的 rollback 写入（applied）；
/// rejected 形保留给显式拒绝回执（reasonCode 必填）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackRecordResult {
    Applied,
    Rejected,
}

/// 唯一 rollback 保留记录形态（完整 envelope）：schemaVersion:2 + rollbackId
///（rollback 命令 activationId 投影）+ expectedRouteGeneration/
/// expectedControlRevision（命令 CAS 关联）+ 内嵌 routeEvent（成功事件整体
/// 持久化；目标 binding 在 routeEvent.next.runtimeBinding，admission 事实形）+
/// reasonCode/result 耦合 + rollbackDigest。createdAt 保持持久化面 epoch 毫秒
///（TS 对位 createdAtEpochMillis）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RollbackRecord {
    pub schema_version: u64,
    pub rollback_id: String,
    pub application_id: String,
    /// previous 指针不可用时的空串投影。
    pub from_version_id: String,
    pub to_version_id: String,
    pub expected_route_generation: u64,
    pub expected_control_revision: u64,
    pub route_event: RouteEvent,
    /// 目标版本的 HostServicePolicyV2.policyDigest（policy 钉回显；空串 = 无
    /// host services）。
    pub host_service_policy_digest: String,
    /// applied 恒 null；rejected 必为有界上划线码（spec result/reason 耦合）。
    pub reason_code: Option<String>,
    pub result: RollbackRecordResult,
    pub created_at_epoch_millis: u64,
    /// digestV2("iweb-wasm-rollback-v2", JCS(record with rollbackDigest omitted))。
    pub rollback_digest: String,
}

/// rollbackDigest = digestV2("iweb-wasm-rollback-v2", JCS(record with
/// rollbackDigest omitted))；与 TS computeRollbackRecordDigestV2 字节一致。
pub fn compute_rollback_record_digest(record: &RollbackRecord) -> Result<String, ActivationError> {
    let mut value = serde_json::to_value(record)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("the rollback record is not serializable as JSON: {e}")))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| err(WASM_ACTIVATION_INVALID, "the rollback record must serialize to a JSON object"))?;
    map.remove("rollbackDigest");
    let bytes = serde_json::to_vec(&value).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("JCS serialization failed: {e}")))?;
    crate::wasm_host_services::digest_v2(ROLLBACK_RECORD_DIGEST_DOMAIN_V2, &bytes)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, e.detail))
}

/// RollbackRecord 结构校验（持久化/回读面）：result/reason 耦合 + 内嵌事件
/// 自洽 + rollbackDigest 复算 fail-closed。
pub fn validate_rollback_record(record: &RollbackRecord) -> Result<(), ActivationError> {
    if record.schema_version != 2 {
        return Err(err(WASM_ACTIVATION_INVALID, "schemaVersion must be exactly 2"));
    }
    check_uuid_v7(&record.rollback_id, "rollbackId")?;
    check_application_id(&record.application_id)?;
    if !record.from_version_id.is_empty() {
        let (digest, sequence) = parse_wasm_version_id(&record.from_version_id)
            .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/fromVersionId: {}", e.detail)))?;
        let _ = digest;
        require_u53(sequence, 1, WASM_U53_MAX, "fromVersionId/sequence")?;
    }
    let (digest, sequence) = parse_wasm_version_id(&record.to_version_id)
        .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/toVersionId: {}", e.detail)))?;
    let _ = digest;
    require_u53(sequence, 1, WASM_U53_MAX, "toVersionId/sequence")?;
    require_u53(record.expected_route_generation, 0, WASM_U53_MAX, "expectedRouteGeneration")?;
    require_u53(record.expected_control_revision, 0, WASM_U53_MAX, "expectedControlRevision")?;
    check_policy_digest(&record.host_service_policy_digest, "hostServicePolicyDigest")?;
    require_u53(record.created_at_epoch_millis, 0, u64::MAX, "createdAtEpochMillis")?;
    check_sha256_hex(&record.rollback_digest, "rollbackDigest")?;
    check_reason_code(&record.reason_code)?;
    match record.result {
        RollbackRecordResult::Applied => {
            if record.reason_code.is_some() {
                return Err(err(WASM_ACTIVATION_INVALID, "an applied rollback record must carry reasonCode null"));
            }
        }
        RollbackRecordResult::Rejected => {
            if record.reason_code.is_none() {
                return Err(err(WASM_ACTIVATION_INVALID, "a rejected rollback record must carry a bounded reasonCode"));
            }
        }
    }
    validate_route_event(&record.route_event)?;
    if record.route_event.operation != ActivationOperation::Rollback {
        return Err(err(WASM_ACTIVATION_INVALID, "the embedded route event must be a rollback operation"));
    }
    if record.route_event.application_id != record.application_id || record.route_event.activation_id != record.rollback_id {
        return Err(err(WASM_ACTIVATION_INVALID, "the embedded route event must agree with the rollback record identity"));
    }
    // 摘要复算 fail-closed。
    let computed = compute_rollback_record_digest(record)?;
    if computed != record.rollback_digest {
        return Err(err(
            WASM_ACTIVATION_INVALID,
            "rollbackDigest does not equal digestV2(\"iweb-wasm-rollback-v2\", JCS(record with rollbackDigest omitted))",
        ));
    }
    Ok(())
}

impl RollbackRecord {
    pub fn to_version_id(&self) -> &str {
        &self.to_version_id
    }

    /// 目标 binding：内嵌成功事件的 next 指针 binding（admission 事实形；事件
    /// 为 rejected 形或指针不可用时 None）。
    pub fn target_runtime_binding(&self) -> Option<&RuntimeBindingIdentityV1> {
        match &self.route_event.next {
            WasmActivePointerV1::Active { runtime_binding, .. } => Some(runtime_binding),
            WasmActivePointerV1::Unavailable { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// CAS 判据输入与 Kernel 状态
// ---------------------------------------------------------------------------

/// registry 行事实（Kernel 侧权威记录的投影；capability 钉来自 proof）。
/// host_service_policy_digest 为 proof 上 HostServicePolicyV2 的 policyDigest
///（None = 无 host services，与命令/lease 的空串零值同义）。
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryRowFacts {
    pub runtime_binding: RuntimeBindingIdentityV1,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    /// proof 携带 HostServicePolicyV2 时的 policyDigest（None = 无 host services）。
    pub host_service_policy_digest: Option<String>,
    /// lifecycle 是否处于可激活（ready/retained admitted）。
    pub lifecycle_ready: bool,
}

/// CAS 线性化点全部判据输入。
#[derive(Debug, Clone, PartialEq)]
pub struct ActivationCasFacts<'a> {
    /// CAS 线性化时刻的单调时钟读数（epoch 毫秒投影）。
    pub now_epoch_millis: u64,
    /// 本次 CAS 提交后的 v2 控制态 revision（事件的 controlRevision 盖戳值；
    /// store 提交面以 file.controlRevision + 1 覆盖，纯函数调用方显式给定）。
    pub control_revision: u64,
    /// 2.3 fence：当前 secret-store revision（候选必须相等）。
    pub current_secret_store_revision: u64,
    /// 2.3 fence：候选 preparationGeneration 必须等于当前 preparation。
    pub current_preparation_generation: u64,
    /// 候选执行是否存活（ready candidate 在 CAS 前死掉 → abort）。
    pub candidate_alive: bool,
    /// Kernel registry 行；None = 无业务记录（WASM_BUSINESS_RECORD_MISSING 投影为 NOT_READY）。
    pub registry_row: Option<&'a RegistryRowFacts>,
    /// 候选 binding 是否已被 catalog 撤销。
    pub binding_revoked: bool,
    /// rollback 目标的既有保留记录（activate 不需要）。
    pub rollback_retention: Option<&'a RollbackRecord>,
}

/// 一次 CAS 的写前意图（恢复的确定性输入；含 eventId、CAS 时刻与当时的
/// active 指针，使"指针已翻但事件缺失"能重建精确事件）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingActivationCas {
    pub command: ActivationCommand,
    pub lease: ServiceReadinessLeaseV2,
    pub event_id: String,
    pub cas_now_epoch_millis: u64,
    /// 本次 CAS 的目标控制态 revision（事件重建时的 controlRevision 盖戳值）。
    pub control_revision: u64,
    /// 意图写入时的 active 指针（= 事件的 previous）。
    pub previous_pointer: WasmActivePointerV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordedActivation {
    pub command: ActivationCommand,
    pub event: RouteEvent,
}

/// Kernel 激活状态（controlRevision CAS 的内存投影；同时是持久化载体的应用
/// 分区形状——serde camelCase 与 wire 键集一致）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KernelActivationState {
    pub application_id: String,
    pub route_generation: u64,
    pub active: WasmActivePointerV1,
    pub events: Vec<RouteEvent>,
    /// nonce -> 已消费 leaseDigest（consumed 只随成功提交写入）。
    pub nonce_ledger: BTreeMap<String, String>,
    /// nonce -> 原 activationId（already-consumed 按原始结果应答）。
    pub nonce_activation_index: BTreeMap<String, String>,
    /// activationId -> (命令, 事件)；query/replay 的 durable 记录。
    pub activation_records: BTreeMap<String, RecordedActivation>,
    /// rollback 保留记录（事件持久化的目标 binding）。
    pub rollback_retentions: Vec<RollbackRecord>,
    /// 最后一次 CAS 的写前意图；Some 即需要恢复后才能接受新激活。
    pub pending: Option<PendingActivationCas>,
}

impl KernelActivationState {
    pub fn new(application_id: &str) -> Result<Self, ActivationError> {
        check_application_id(application_id)?;
        Ok(Self {
            application_id: application_id.to_string(),
            route_generation: 0,
            active: WasmActivePointerV1::Unavailable { runtime_kind: "wasm".into(), application_id: application_id.to_string(), route_generation: 0 },
            events: Vec::new(),
            nonce_ledger: BTreeMap::new(),
            nonce_activation_index: BTreeMap::new(),
            activation_records: BTreeMap::new(),
            rollback_retentions: Vec::new(),
            pending: None,
        })
    }
}

// ---------------------------------------------------------------------------
// 激活 CAS 判定（纯；固定顺序，任一拒绝都保留旧 active）
// ---------------------------------------------------------------------------

pub enum ActivationCasDecision {
    /// 激活成功事件（routeGeneration = expected + 1；nonce 将被消费）。
    Activated(RouteEvent),
    /// 拒绝事件（next == previous；generation 不变；nonce 不消费）。
    Rejected(RouteEvent),
    /// nonce 已消费且 digest 相同：按 activationId 语义返回原始事件，
    /// 不产生第二个事件、不二次递增 generation。
    AlreadyConsumed(RouteEvent),
}

fn candidate_identity(command: &ActivationCommand) -> Result<WasmVersionIdentity, ActivationError> {
    let (digest, sequence) = parse_wasm_version_id(&command.candidate.version_id).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/versionId: {}", e.detail)))?;
    Ok(WasmVersionIdentity { application_id: command.application_id.clone(), digest, sequence })
}

#[allow(clippy::too_many_arguments)]
fn rejected_event(
    state: &KernelActivationState,
    command: &ActivationCommand,
    lease_nonce: &str,
    lease_digest: &str,
    reason: &'static str,
    now_epoch_millis: u64,
    control_revision: u64,
    event_id: &str,
) -> Result<RouteEvent, ActivationError> {
    route_event_sealed(RouteEvent {
        schema_version: 2,
        event_id: event_id.to_string(),
        activation_id: command.activation_id.clone(),
        application_id: command.application_id.clone(),
        runtime_kind: "wasm".into(),
        operation: command.operation,
        expected_route_generation: command.expected_route_generation,
        previous: state.active.clone(),
        next: state.active.clone(),
        lease_consume: LeaseConsumeRecord {
            schema_version: 1,
            lease_nonce: lease_nonce.to_string(),
            lease_digest: lease_digest.to_string(),
            activation_id: command.activation_id.clone(),
            application_id: command.application_id.clone(),
            version_id: command.candidate.version_id.clone(),
            expected_route_generation: command.expected_route_generation,
            consumed_at: format_rfc3339_utc_millis(now_epoch_millis),
            outcome: LeaseConsumeOutcome::Rejected,
            route_generation: state.route_generation,
        },
        result: RouteEventResult::Rejected,
        reason_code: Some(reason.to_string()),
        host_service_policy_digest: command.host_service_policy_digest.clone(),
        control_revision,
        route_generation: state.route_generation,
        created_at: format_rfc3339_utc_millis(now_epoch_millis),
        event_digest: String::new(),
    })
}

/// lease 与候选/registry 事实的全字段一致（任一错配 READINESS_LEASE_MISMATCH）：
/// 结构校验 + correlate（sandbox/version/package/binding/capability 钉/
/// hostServicePolicyDigest 三方钉（lease = 命令 = registry 行；registry None
/// 与空串同义）/secret/config/代次/lease nonce+digest）。registry 行存 admission
/// 事实形 binding，以 runtime_binding_v2_from_v1 归一比较。
fn correlate_readiness_lease(command: &ActivationCommand, lease: &ServiceReadinessLeaseV2, registry: &RegistryRowFacts) -> Result<(), ActivationError> {
    let candidate = &command.candidate;
    let mut mismatches = Vec::new();
    if lease.sandbox_id != candidate.sandbox_id {
        mismatches.push("sandboxId");
    }
    if lease.version_id != candidate.version_id {
        mismatches.push("versionId");
    }
    if lease.package_digest != candidate.package_digest {
        mismatches.push("packageDigest");
    }
    if lease.runtime_binding != candidate.runtime_binding {
        mismatches.push("runtimeBinding");
    }
    if lease.capability_record_revision != registry.capability_record_revision || lease.capability_record_hash != registry.capability_record_hash {
        mismatches.push("capabilityRecord pin");
    }
    if lease.host_service_policy_digest != command.host_service_policy_digest {
        mismatches.push("hostServicePolicyDigest (lease vs command)");
    }
    if registry.host_service_policy_digest.as_deref().unwrap_or("") != command.host_service_policy_digest.as_str() {
        mismatches.push("hostServicePolicyDigest (registry row)");
    }
    let registry_binding_v2 = runtime_binding_v2_from_v1(&registry.runtime_binding).map_err(|e| lease_mismatch(e.detail))?;
    if registry_binding_v2 != candidate.runtime_binding {
        mismatches.push("runtimeBinding (registry row)");
    }
    if lease.secret_revision != candidate.secret_revision || lease.secret_values_digest != candidate.secret_values_digest {
        mismatches.push("secret revision/values digest");
    }
    if lease.config_revision != candidate.config_revision || lease.config_snapshot_ref != candidate.config_snapshot_ref || lease.config_values_digest != candidate.config_values_digest {
        mismatches.push("config revision/reference/digest");
    }
    if lease.preparation_generation != candidate.preparation_generation || lease.execution_generation != candidate.execution_generation {
        mismatches.push("preparation/execution generations");
    }
    if lease.lease_digest != candidate.lease_digest || lease.lease_nonce != candidate.lease_nonce {
        mismatches.push("lease nonce/digest");
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(lease_mismatch(format!("lease disagrees with the activation candidate on: {}", mismatches.join(", "))))
    }
}

/// 单一 CAS 线性化点判定。固定顺序（确定且 fail-closed）：
/// 1. expectedRouteGeneration == 当前 route generation（否则 ACTIVATION_ROUTE_CONFLICT）；
/// 2. 候选可激活性：registry 行存在且 binding 一致、lifecycle ready、policy 钉
///    相等、候选存活、secret revision == 当前 secret-store revision（2.3 fence）、
///    preparationGeneration == 当前 preparation（2.3 fence）、rollback 目标保留
///    记录一致（否则 ACTIVATION_CANDIDATE_NOT_READY）；
/// 3. binding 未被撤销（否则 ACTIVATION_BINDING_REVOKED）；
/// 4. lease 结构与 digest 复算 + 与候选/registry 全字段一致（否则 READINESS_LEASE_MISMATCH）；
/// 5. nonce 台账：异 digest → READINESS_LEASE_MISMATCH；同 digest → AlreadyConsumed
///    （nonce 判定先于过期：重放场景返回原始结果，而非新的过期错误）；
/// 6. 过期复查：now >= expiresAt（相等即过期）→ READINESS_LEASE_EXPIRED，nonce 不消费。
///
/// 事件携带 hostServicePolicyDigest + controlRevision 盖戳 + eventDigest。
pub fn evaluate_activation_cas(
    state: &KernelActivationState,
    command: &ActivationCommand,
    lease: &ServiceReadinessLeaseV2,
    facts: &ActivationCasFacts<'_>,
    event_id: &str,
) -> Result<ActivationCasDecision, ActivationError> {
    command.validate()?;
    if command.application_id != state.application_id {
        return Err(err(WASM_ACTIVATION_INVALID, "the activation command must target this application state"));
    }
    let candidate = &command.candidate;
    // 1. route generation CAS。
    if command.expected_route_generation != state.route_generation {
        return Ok(ActivationCasDecision::Rejected(rejected_event(
            state,
            command,
            &lease.lease_nonce,
            &lease.lease_digest,
            ACTIVATION_ROUTE_CONFLICT,
            facts.now_epoch_millis,
            facts.control_revision,
            event_id,
        )?));
    }
    // 2. 候选可激活性：registry 行存在、binding/policy 钉一致、lifecycle ready、
    //    存活、2.3 fence、rollback 保留。
    let registry = match facts.registry_row {
        Some(row) => row,
        None => {
            return Ok(ActivationCasDecision::Rejected(rejected_event(
                state,
                command,
                &lease.lease_nonce,
                &lease.lease_digest,
                ACTIVATION_CANDIDATE_NOT_READY,
                facts.now_epoch_millis,
                facts.control_revision,
                event_id,
            )?))
        }
    };
    let candidate_not_ready = || {
        Ok(ActivationCasDecision::Rejected(rejected_event(
            state,
            command,
            &lease.lease_nonce,
            &lease.lease_digest,
            ACTIVATION_CANDIDATE_NOT_READY,
            facts.now_epoch_millis,
            facts.control_revision,
            event_id,
        )?))
    };
    // registry 行存 admission 事实形 binding（ABI 1.0.0），归一比较。
    let registry_binding_v2 = runtime_binding_v2_from_v1(&registry.runtime_binding).map_err(|e| err(WASM_ACTIVATION_INVALID, e.detail))?;
    if registry_binding_v2 != candidate.runtime_binding
        || !registry.lifecycle_ready
        || registry.host_service_policy_digest.as_deref().unwrap_or("") != command.host_service_policy_digest.as_str()
    {
        return candidate_not_ready();
    }
    if !facts.candidate_alive {
        return candidate_not_ready();
    }
    if !matches_secret_revision_fence(facts.current_secret_store_revision, candidate.secret_revision) {
        // 崩溃矩阵行 5：更新的已提交 revision 拒绝该候选，它永不激活。
        return candidate_not_ready();
    }
    if facts.current_preparation_generation != candidate.preparation_generation {
        return candidate_not_ready();
    }
    if command.operation == ActivationOperation::Rollback {
        // 保留记录是 Kernel 持久化面：先复算 rollbackDigest（fail-closed——持久层
        // 损坏不按业务 NOT_READY 解释），再校验目标/policy 钉与内嵌事件的 binding。
        if let Some(retention) = facts.rollback_retention {
            validate_rollback_record(retention).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, format!("the rollback retention record is invalid: {}", e.detail)))?;
            let retained_binding = match &retention.route_event.next {
                WasmActivePointerV1::Active { runtime_binding, .. } => runtime_binding,
                WasmActivePointerV1::Unavailable { .. } => return candidate_not_ready(),
            };
            if retention.to_version_id != candidate.version_id
                || retained_binding != &registry.runtime_binding
                || retention.host_service_policy_digest != command.host_service_policy_digest
            {
                return candidate_not_ready();
            }
        } else {
            return candidate_not_ready();
        }
    }
    // 3. binding 撤销。
    if facts.binding_revoked {
        return Ok(ActivationCasDecision::Rejected(rejected_event(
            state,
            command,
            &lease.lease_nonce,
            &lease.lease_digest,
            ACTIVATION_BINDING_REVOKED,
            facts.now_epoch_millis,
            facts.control_revision,
            event_id,
        )?));
    }
    // 4. lease 结构 + correlate（全字段 + policy 三方钉）。
    if lease.validate().and_then(|()| correlate_readiness_lease(command, lease, registry)).is_err() {
        return Ok(ActivationCasDecision::Rejected(rejected_event(
            state,
            command,
            &lease.lease_nonce,
            &lease.lease_digest,
            READINESS_LEASE_MISMATCH,
            facts.now_epoch_millis,
            facts.control_revision,
            event_id,
        )?));
    }
    // 5. nonce 台账（先于过期）。
    if let Some(recorded_digest) = state.nonce_ledger.get(&lease.lease_nonce) {
        if *recorded_digest != lease.lease_digest {
            return Ok(ActivationCasDecision::Rejected(rejected_event(
                state,
                command,
                &lease.lease_nonce,
                &lease.lease_digest,
                READINESS_LEASE_MISMATCH,
                facts.now_epoch_millis,
                facts.control_revision,
                event_id,
            )?));
        }
        let original_id = state
            .nonce_activation_index
            .get(&lease.lease_nonce)
            .ok_or_else(|| err(WASM_ACTIVATION_FAIL_CLOSED, "the nonce ledger and activation index disagree"))?;
        let original = state
            .activation_records
            .get(original_id)
            .ok_or_else(|| err(WASM_ACTIVATION_FAIL_CLOSED, "the consumed nonce has no durable activation record"))?;
        return Ok(ActivationCasDecision::AlreadyConsumed(original.event.clone()));
    }
    // 6. CAS 时刻过期复查（相等即过期）；validate 已证明时间戳可解析，
    //    此处解析失败仍按 MISMATCH fail-closed。
    let expires_at = lease.expires_at_epoch_millis().map_err(|e| lease_mismatch(e.detail))?;
    if let Err(expiry) = check_readiness_lease_expiry_at_cas(facts.now_epoch_millis, expires_at) {
        return Ok(ActivationCasDecision::Rejected(rejected_event(
            state,
            command,
            &lease.lease_nonce,
            &lease.lease_digest,
            expiry.code,
            facts.now_epoch_millis,
            facts.control_revision,
            event_id,
        )?));
    }
    // 激活：构造成功事件（consumed、generation+1、policy digest 随事件持久化、
    // controlRevision 盖戳 + eventDigest）。
    let next_generation = command.expected_route_generation + 1;
    let next_pointer = WasmActivePointerV1::Active {
        runtime_kind: "wasm".into(),
        application_id: command.application_id.clone(),
        version_id: candidate.version_id.clone(),
        identity: candidate_identity(command)?,
        runtime_binding: RuntimeBindingIdentityV1 {
            kind: candidate.runtime_binding.kind.clone(),
            catalog_revision: candidate.runtime_binding.catalog_revision,
            catalog_hash: candidate.runtime_binding.catalog_hash.clone(),
            entry_key: candidate.runtime_binding.entry_key.clone(),
            image_digest: candidate.runtime_binding.image_digest.clone(),
            host_abi: crate::wasm_admission::WASM_HOST_ABI_LITERAL.into(),
            world: candidate.runtime_binding.world.clone(),
        },
        admission_proof_ref: candidate.admission_proof_ref.clone(),
        admission_proof_digest: candidate.admission_proof_digest.clone(),
        route_generation: next_generation,
        host_service_policy_digest: (!command.host_service_policy_digest.is_empty())
            .then(|| command.host_service_policy_digest.clone()),
        preparation_generation: Some(candidate.preparation_generation),
        execution_generation: Some(candidate.execution_generation),
    };
    let event = route_event_sealed(RouteEvent {
        schema_version: 2,
        event_id: event_id.to_string(),
        activation_id: command.activation_id.clone(),
        application_id: command.application_id.clone(),
        runtime_kind: "wasm".into(),
        operation: command.operation,
        expected_route_generation: command.expected_route_generation,
        previous: state.active.clone(),
        next: next_pointer,
        lease_consume: LeaseConsumeRecord {
            schema_version: 1,
            lease_nonce: lease.lease_nonce.clone(),
            lease_digest: lease.lease_digest.clone(),
            activation_id: command.activation_id.clone(),
            application_id: command.application_id.clone(),
            version_id: candidate.version_id.clone(),
            expected_route_generation: command.expected_route_generation,
            consumed_at: format_rfc3339_utc_millis(facts.now_epoch_millis),
            outcome: LeaseConsumeOutcome::Consumed,
            route_generation: next_generation,
        },
        result: RouteEventResult::Activated,
        reason_code: None,
        host_service_policy_digest: command.host_service_policy_digest.clone(),
        control_revision: facts.control_revision,
        route_generation: next_generation,
        created_at: format_rfc3339_utc_millis(facts.now_epoch_millis),
        event_digest: String::new(),
    })?;
    Ok(ActivationCasDecision::Activated(event))
}

// ---------------------------------------------------------------------------
// 事务应用（原子提交 + query/replay + 崩溃注入）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationCrashPoint {
    /// 消费标记已写、指针/事件未提交（"consume 无 route"恢复输入）。
    AfterConsumeMarkerBeforePointerCas,
    /// 指针 CAS 已提交、事件/记录未写（"指针无事件"恢复输入）。
    AfterPointerCasBeforeEvent,
}

fn find_recorded<'a>(state: &'a KernelActivationState, activation_id: &str) -> Option<&'a RecordedActivation> {
    state.activation_records.get(activation_id)
}

/// apply 系列共享前置：validate → pending 修复门 → 同 activationId 幂等/冲突判定。
/// 返回 Some(event) 表示已有确定答案（幂等返回），None 表示可以继续判定。
fn activation_preamble(state: &KernelActivationState, command: &ActivationCommand) -> Result<Option<RouteEvent>, ActivationError> {
    command.validate()?;
    if state.pending.is_some() {
        return Err(err(WASM_ACTIVATION_REPAIR_REQUIRED, "an uncertain activation must be repaired before a new activation is accepted"));
    }
    if let Some(recorded) = find_recorded(state, &command.activation_id) {
        if &recorded.command == command {
            return Ok(Some(recorded.event.clone()));
        }
        return Err(err(ACTIVATION_ID_CONFLICT, "a known activationId with a different command returns ACTIVATION_ID_CONFLICT and never creates a route event"));
    }
    Ok(None)
}

/// 激活事务：写前意图 → 判定 → 原子提交（成功才翻指针/消费 nonce/写事件）。
/// - 同 activationId 同命令：幂等返回已存事件，不再 CAS、不二次递增；
/// - 同 activationId 异命令：ACTIVATION_ID_CONFLICT（envelope 级，无事件）；
/// - 拒绝：持久化 rejected 事件（nonce 不消费）；
/// - AlreadyConsumed：返回原始事件，不新增事件；
/// - rollback 成功：追加保留记录（完整 envelope：内嵌成功事件 + rollbackDigest）。
pub fn apply_activation(
    state: &mut KernelActivationState,
    command: &ActivationCommand,
    lease: &ServiceReadinessLeaseV2,
    facts: &ActivationCasFacts<'_>,
    event_id: &str,
    crash: Option<ActivationCrashPoint>,
) -> Result<RouteEvent, ActivationError> {
    check_uuid_v7(event_id, "eventId")?;
    if let Some(recorded_event) = activation_preamble(state, command)? {
        return Ok(recorded_event);
    }
    state.pending = Some(PendingActivationCas {
        command: command.clone(),
        lease: lease.clone(),
        event_id: event_id.to_string(),
        cas_now_epoch_millis: facts.now_epoch_millis,
        control_revision: facts.control_revision,
        previous_pointer: state.active.clone(),
    });
    let decision = match evaluate_activation_cas(state, command, lease, facts, event_id) {
        Ok(decision) => decision,
        // envelope 级失败（结构非法）：该 CAS 从未发生——清除写前意图，
        // 绝不留下需要"恢复"的假意图（pending Some 会阻塞后续激活）。
        Err(failure) => {
            state.pending = None;
            return Err(failure);
        }
    };
    match decision {
        ActivationCasDecision::Activated(event) => {
            // (a) 消费标记。
            state.nonce_ledger.insert(lease.lease_nonce.clone(), lease.lease_digest.clone());
            state.nonce_activation_index.insert(lease.lease_nonce.clone(), command.activation_id.clone());
            if crash == Some(ActivationCrashPoint::AfterConsumeMarkerBeforePointerCas) {
                return Err(err(WASM_ACTIVATION_SIMULATED_CRASH, "simulated crash after the consume marker, before the route pointer CAS"));
            }
            // (b) 指针 CAS。
            state.route_generation = event.route_generation;
            state.active = event.next.clone();
            if crash == Some(ActivationCrashPoint::AfterPointerCasBeforeEvent) {
                return Err(err(WASM_ACTIVATION_SIMULATED_CRASH, "simulated crash after the route pointer CAS, before the event append"));
            }
            // (c) 事件 + 记录（与指针同一 controlRevision 提交的投影面）。
            if command.operation == ActivationOperation::Rollback {
                let from_version_id = match &event.previous {
                    WasmActivePointerV1::Active { version_id, .. } => version_id.clone(),
                    WasmActivePointerV1::Unavailable { .. } => String::new(),
                };
                let mut record = RollbackRecord {
                    schema_version: 2,
                    rollback_id: command.activation_id.clone(),
                    application_id: command.application_id.clone(),
                    from_version_id,
                    to_version_id: command.candidate.version_id.clone(),
                    expected_route_generation: command.expected_route_generation,
                    expected_control_revision: command.expected_control_revision,
                    // 成功事件整体持久化；目标 binding = routeEvent.next（admission 事实形）。
                    route_event: event.clone(),
                    host_service_policy_digest: command.host_service_policy_digest.clone(),
                    reason_code: None,
                    result: RollbackRecordResult::Applied,
                    created_at_epoch_millis: facts.now_epoch_millis,
                    rollback_digest: String::new(),
                };
                record.rollback_digest = compute_rollback_record_digest(&record)?;
                state.rollback_retentions.push(record);
            }
            state.events.push(event.clone());
            state.activation_records.insert(command.activation_id.clone(), RecordedActivation { command: command.clone(), event: event.clone() });
            state.pending = None;
            Ok(event)
        }
        ActivationCasDecision::Rejected(event) => {
            state.events.push(event.clone());
            state.activation_records.insert(command.activation_id.clone(), RecordedActivation { command: command.clone(), event: event.clone() });
            state.pending = None;
            Ok(event)
        }
        ActivationCasDecision::AlreadyConsumed(original) => {
            state.pending = None;
            Ok(original)
        }
    }
}

/// lease 台账查无记录（候选声称的 nonce 无对应 Kernel lease 记录）：按 spec
/// "a lease with a missing nonce ... is rejected as READINESS_LEASE_MISMATCH" 的
/// 对偶面处理——无 lease 即无法 correlate，产出 rejected 事件（nonce 不消费、
/// 路由不动），幂等/冲突判定与 apply_activation 同一前置。
pub fn apply_activation_without_lease(
    state: &mut KernelActivationState,
    command: &ActivationCommand,
    now_epoch_millis: u64,
    // 本次拒绝事件持久化的目标控制态 revision（store 以 file.controlRevision + 1
    // 传入）。
    control_revision: u64,
    event_id: &str,
) -> Result<RouteEvent, ActivationError> {
    check_uuid_v7(event_id, "eventId")?;
    if let Some(recorded_event) = activation_preamble(state, command)? {
        return Ok(recorded_event);
    }
    let event = rejected_event(
        state,
        command,
        &command.candidate.lease_nonce,
        &command.candidate.lease_digest,
        READINESS_LEASE_MISMATCH,
        now_epoch_millis,
        control_revision,
        event_id,
    )?;
    state.events.push(event.clone());
    state.activation_records.insert(command.activation_id.clone(), RecordedActivation { command: command.clone(), event: event.clone() });
    Ok(event)
}

/// query：activationId 的 durable 结果（None = missing；received 未单独建模，
/// pending 意图即"received 未完成"）。
pub fn query_activation<'a>(state: &'a KernelActivationState, activation_id: &str) -> Option<&'a RouteEvent> {
    find_recorded(state, activation_id).map(|recorded| &recorded.event)
}

/// replay：仅接受字节等价（此处以命令结构等价建模）的重放；返回原始事件，
/// 不二次消费 nonce、不二次递增 route generation。
pub fn replay_activation(state: &KernelActivationState, command: &ActivationCommand) -> Result<RouteEvent, ActivationError> {
    match find_recorded(state, &command.activation_id) {
        Some(recorded) => {
            if &recorded.command == command {
                Ok(recorded.event.clone())
            } else {
                Err(err(ACTIVATION_ID_CONFLICT, "replay accepts only the byte-identical activation command"))
            }
        }
        None => Err(err(WASM_ACTIVATION_INVALID, "unknown activationId; send the command first")),
    }
}

// ---------------------------------------------------------------------------
// 不确定提交恢复
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ActivationRepairOutcome {
    /// 无需恢复（无 pending 意图且不变量成立）。
    NoRepairNeeded,
    /// 指针已翻但事件缺失：从 pending 意图重建精确事件并落记录（版本联合——
    /// 按意图命令代际重建同代事件）。
    /// 事件体盒装：低频控制面返回值，多数变体无载荷，不必内联 992+ 字节。
    RepairedEventFromPointerCas(Box<RouteEvent>),
    /// 消费标记存在但无已提交路由：丢弃标记，租约回到未消费，
    /// 可按原 expectedRouteGeneration 重放。
    DiscardedPartialConsume,
}

/// 不变量：每个 generation > 0 的指针翻转都有对应 consumed 事件；
/// nonce 台账与 activation 记录一致。
pub fn verify_activation_invariants(state: &KernelActivationState) -> Result<(), ActivationError> {
    if state.route_generation > 0 && !state
        .events
        .iter()
        .any(|event| event.lease_consume.outcome == LeaseConsumeOutcome::Consumed && event.route_generation == state.route_generation)
    {
        return Err(err(WASM_ACTIVATION_FAIL_CLOSED, "the route pointer carries a generation whose consuming event is missing"));
    }
    for (nonce, activation_id) in &state.nonce_activation_index {
        let recorded = state.activation_records.get(activation_id).ok_or_else(|| err(WASM_ACTIVATION_FAIL_CLOSED, "the nonce index names an unknown activation"))?;
        if recorded.event.lease_consume.lease_nonce != *nonce || !state.nonce_ledger.contains_key(nonce) {
            return Err(err(WASM_ACTIVATION_FAIL_CLOSED, "the nonce ledger, index, and activation record disagree"));
        }
    }
    Ok(())
}

/// 恢复：
/// - pending 存在且指针已按该命令翻转（generation == expected+1 且 active 命中
///   候选身份）→ 重建精确事件（同 eventId/CAS 时刻）；
/// - pending 存在、指针未翻、nonce 已被该意图消费 → 丢弃消费标记（租约
///   未消费），按原 expectedRouteGeneration 重放；
/// - pending 存在但什么都没发生 → 清除意图；
/// - pending 不存在而不变量破坏 → fail-closed（owner 修复）。
pub fn repair_uncertain_activation(state: &mut KernelActivationState) -> Result<ActivationRepairOutcome, ActivationError> {
    let Some(pending) = state.pending.clone() else {
        verify_activation_invariants(state)?;
        return Ok(ActivationRepairOutcome::NoRepairNeeded);
    };
    let flipped = state.route_generation == pending.command.expected_route_generation + 1
        && match &state.active {
            WasmActivePointerV1::Active { version_id, route_generation, .. } => {
                *version_id == pending.command.candidate.version_id && *route_generation == state.route_generation
            }
            WasmActivePointerV1::Unavailable { .. } => false,
        };
    if flipped {
        // 从指针 CAS 重建精确事件（确定性：同一命令/lease/eventId/CAS 时刻/
        // previous 指针——全部来自写前意图，恢复只补投影面）。
        let event = rebuild_activated_event_from_pending(&pending)?;
        if pending.command.operation == ActivationOperation::Rollback {
            let from_version_id = match &event.previous {
                WasmActivePointerV1::Active { version_id, .. } => version_id.clone(),
                WasmActivePointerV1::Unavailable { .. } => String::new(),
            };
            let mut record = RollbackRecord {
                schema_version: 2,
                rollback_id: pending.command.activation_id.clone(),
                application_id: pending.command.application_id.clone(),
                from_version_id,
                to_version_id: pending.command.candidate.version_id.clone(),
                expected_route_generation: pending.command.expected_route_generation,
                expected_control_revision: pending.command.expected_control_revision,
                route_event: event.clone(),
                host_service_policy_digest: pending.command.host_service_policy_digest.clone(),
                reason_code: None,
                result: RollbackRecordResult::Applied,
                created_at_epoch_millis: pending.cas_now_epoch_millis,
                rollback_digest: String::new(),
            };
            record.rollback_digest = compute_rollback_record_digest(&record)?;
            state.rollback_retentions.push(record);
        }
        state.events.push(event.clone());
        state.activation_records.insert(
            pending.command.activation_id.clone(),
            RecordedActivation { command: pending.command.clone(), event: event.clone() },
        );
        state.pending = None;
        verify_activation_invariants(state)?;
        return Ok(ActivationRepairOutcome::RepairedEventFromPointerCas(Box::new(event)));
    }
    // 消费标记无已提交路由：丢弃标记。
    if state.nonce_ledger.get(&pending.lease.lease_nonce).map(String::as_str) == Some(pending.lease.lease_digest.as_str())
        && state
            .nonce_activation_index
            .get(&pending.lease.lease_nonce)
            .map(String::as_str)
            == Some(pending.command.activation_id.as_str())
    {
        state.nonce_ledger.remove(&pending.lease.lease_nonce);
        state.nonce_activation_index.remove(&pending.lease.lease_nonce);
        state.pending = None;
        verify_activation_invariants(state)?;
        return Ok(ActivationRepairOutcome::DiscardedPartialConsume);
    }
    state.pending = None;
    verify_activation_invariants(state)?;
    Ok(ActivationRepairOutcome::NoRepairNeeded)
}

fn rebuild_activated_event_from_pending(pending: &PendingActivationCas) -> Result<RouteEvent, ActivationError> {
    let next_generation = pending.command.expected_route_generation + 1;
    let command = &pending.command;
    let lease = &pending.lease;
    let candidate = &command.candidate;
    let next_pointer = WasmActivePointerV1::Active {
        runtime_kind: "wasm".into(),
        application_id: command.application_id.clone(),
        version_id: candidate.version_id.clone(),
        identity: candidate_identity(command)?,
        runtime_binding: RuntimeBindingIdentityV1 {
            kind: candidate.runtime_binding.kind.clone(),
            catalog_revision: candidate.runtime_binding.catalog_revision,
            catalog_hash: candidate.runtime_binding.catalog_hash.clone(),
            entry_key: candidate.runtime_binding.entry_key.clone(),
            image_digest: candidate.runtime_binding.image_digest.clone(),
            host_abi: crate::wasm_admission::WASM_HOST_ABI_LITERAL.into(),
            world: candidate.runtime_binding.world.clone(),
        },
        admission_proof_ref: candidate.admission_proof_ref.clone(),
        admission_proof_digest: candidate.admission_proof_digest.clone(),
        route_generation: next_generation,
        host_service_policy_digest: (!command.host_service_policy_digest.is_empty())
            .then(|| command.host_service_policy_digest.clone()),
        preparation_generation: Some(candidate.preparation_generation),
        execution_generation: Some(candidate.execution_generation),
    };
    route_event_sealed(RouteEvent {
        schema_version: 2,
        event_id: pending.event_id.clone(),
        activation_id: command.activation_id.clone(),
        application_id: command.application_id.clone(),
        runtime_kind: "wasm".into(),
        operation: command.operation,
        expected_route_generation: command.expected_route_generation,
        previous: pending.previous_pointer.clone(),
        next: next_pointer,
        lease_consume: LeaseConsumeRecord {
            schema_version: 1,
            lease_nonce: lease.lease_nonce.clone(),
            lease_digest: lease.lease_digest.clone(),
            activation_id: command.activation_id.clone(),
            application_id: command.application_id.clone(),
            version_id: candidate.version_id.clone(),
            expected_route_generation: command.expected_route_generation,
            consumed_at: format_rfc3339_utc_millis(pending.cas_now_epoch_millis),
            outcome: LeaseConsumeOutcome::Consumed,
            route_generation: next_generation,
        },
        result: RouteEventResult::Activated,
        reason_code: None,
        host_service_policy_digest: command.host_service_policy_digest.clone(),
        control_revision: pending.control_revision,
        route_generation: next_generation,
        created_at: format_rfc3339_utc_millis(pending.cas_now_epoch_millis),
        event_digest: String::new(),
    })
}

// ---------------------------------------------------------------------------
// 任务 7.5：iweb-wasm-activation 传输接线（envelope / 存储 / 端点）
// ---------------------------------------------------------------------------

/// 唯一激活传输协议字面量（单 protocol；envelope 拒绝任何其它字面量）。
pub const ACTIVATION_RPC_PROTOCOL_LITERAL: &str = "iweb-wasm-activation";
/// spec 固定端点：owner-authorized Bearer 通道上的 Kernel 控制操作。
pub const ACTIVATION_RPC_PATH: &str = "/v1/wasm/activation-rpc";
pub const ACTIVATION_UNAUTHORIZED: &str = "ACTIVATION_UNAUTHORIZED";
pub const ACTIVATION_RPC_ENVELOPE_INVALID: &str = "ACTIVATION_RPC_ENVELOPE_INVALID";
/// Kernel 文本写入上限沿用 1 MiB（AGENTS 控制面法）。
pub const ACTIVATION_RPC_DEFAULT_MAX_BYTES: usize = 1_048_576;

/// UUIDv7（48-bit unix 毫秒 + 版本 7 + RFC 9562 variant；随机位来自 /dev/urandom）。
/// 生产 eventId 生成器；测试可用确定性来源替换（ActivationDeps.event_id）。
pub fn generate_uuid_v7(now_epoch_millis: u64) -> String {
    let mut random = [0u8; 10];
    {
        use std::io::Read as _;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut random))
            .expect("/dev/urandom");
    }
    let ms = now_epoch_millis.to_be_bytes(); // u64 → 8 字节，取后 6 字节为 48-bit 毫秒
    let mut bytes = [0u8; 16];
    bytes[0..6].copy_from_slice(&ms[2..8]);
    bytes[6] = 0x70 | (random[0] & 0x0f); // version 7
    bytes[7] = random[1];
    bytes[8] = 0x80 | (random[2] & 0x3f); // RFC 9562 variant 10xx
    bytes[9..16].copy_from_slice(&random[3..10]);
    let hex_text = hex::encode(bytes);
    format!("{}-{}-{}-{}-{}", &hex_text[0..8], &hex_text[8..12], &hex_text[12..16], &hex_text[16..20], &hex_text[20..32])
}

// ---------------------------------------------------------------------------
// envelope：{protocol, requestId, body: command | query | replay}——单 protocol
// 字面量 "iweb-wasm-activation"；命令 pure==wire（同一类型直传）。
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ActivationRpcRequestBody {
    /// ActivationCommand 精确键集，无 kind 成员（spec 未给命令体 kind 标签；
    /// fail-closed：携带 kind 的命令体按未知字段拒绝）。
    Command(ActivationCommand),
    Query { activation_id: String },
    Replay(ActivationCommand),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActivationRpcRequestEnvelope {
    pub request_id: String,
    pub body: ActivationRpcRequestBody,
}

fn ensure_exact_keys(value: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Result<(), ActivationError> {
    for key in value.keys() {
        if !keys.contains(&key.as_str()) {
            return Err(err(WASM_ACTIVATION_INVALID, format!("unknown field {key} is not allowed")));
        }
    }
    for key in keys {
        if !value.contains_key(*key) {
            return Err(err(WASM_ACTIVATION_INVALID, format!("required field {key} is missing")));
        }
    }
    Ok(())
}

fn parse_wire_command(value: &serde_json::Value) -> Result<ActivationCommand, ActivationError> {
    serde_json::from_value(value.clone()).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("activation command body is invalid: {e}")))
}

/// spec：raw body 是 JCS ActivationRpcEnvelope——字节必须等于 JCS(parse(bytes))，
/// 重复键/白空格/键序偏差与浮点数（u53 域外）一律在解析层拒绝。protocol 必须
/// 精确等于唯一字面量 "iweb-wasm-activation"。
pub fn parse_activation_rpc_envelope(bytes: &[u8]) -> Result<ActivationRpcRequestEnvelope, ActivationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| err(ACTIVATION_RPC_ENVELOPE_INVALID, format!("the activation rpc body must be JSON: {e}")))?;
    let canonical = jcs_bytes(&value).map_err(|e| err(ACTIVATION_RPC_ENVELOPE_INVALID, e.detail))?;
    if canonical != bytes {
        return Err(err(ACTIVATION_RPC_ENVELOPE_INVALID, "the raw activation rpc body must be canonical JCS bytes"));
    }
    let envelope = value
        .as_object()
        .ok_or_else(|| err(ACTIVATION_RPC_ENVELOPE_INVALID, "the activation rpc envelope must be an object"))?;
    ensure_exact_keys(envelope, &["protocol", "requestId", "body"])?;
    if envelope["protocol"].as_str() != Some(ACTIVATION_RPC_PROTOCOL_LITERAL) {
        return Err(err(
            ACTIVATION_RPC_ENVELOPE_INVALID,
            "protocol must be exactly \"iweb-wasm-activation\"",
        ));
    }
    let request_id = envelope["requestId"].as_str().unwrap_or_default().to_string();
    check_uuid_v7(&request_id, "requestId").map_err(|e| err(ACTIVATION_RPC_ENVELOPE_INVALID, e.detail))?;
    let body = envelope["body"]
        .as_object()
        .ok_or_else(|| err(ACTIVATION_RPC_ENVELOPE_INVALID, "the activation rpc body must be an object"))?;
    let parsed_body = if let Some(kind) = body.get("kind").and_then(serde_json::Value::as_str) {
        match kind {
            "query" => {
                ensure_exact_keys(body, &["kind", "activationId"])?;
                let activation_id = body["activationId"].as_str().unwrap_or_default().to_string();
                check_uuid_v7(&activation_id, "activationId").map_err(|e| err(ACTIVATION_RPC_ENVELOPE_INVALID, e.detail))?;
                ActivationRpcRequestBody::Query { activation_id }
            }
            "replay" => {
                ensure_exact_keys(body, &["kind", "command"])?;
                let command = parse_wire_command(&body["command"])?;
                ActivationRpcRequestBody::Replay(command)
            }
            _ => {
                return Err(err(
                    ACTIVATION_RPC_ENVELOPE_INVALID,
                    "kind must be \"query\" or \"replay\"; the ActivationCommand body carries no kind member",
                ))
            }
        }
    } else {
        let command = parse_wire_command(&envelope["body"])?;
        ActivationRpcRequestBody::Command(command)
    };
    Ok(ActivationRpcRequestEnvelope { request_id, body: parsed_body })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationStatus {
    Missing,
    Received,
    Activated,
    Rejected,
}

impl ActivationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ActivationStatus::Missing => "missing",
            ActivationStatus::Received => "received",
            ActivationStatus::Activated => "activated",
            ActivationStatus::Rejected => "rejected",
        }
    }
}

/// 响应 body：{kind:"result", activationId, status, event}；event 仅在
/// activated/rejected 非 null。
#[derive(Debug, Clone, PartialEq)]
pub struct ActivationResultBodyV1 {
    pub activation_id: String,
    pub status: ActivationStatus,
    pub event: Option<RouteEvent>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActivationRpcResponseEnvelopeV1 {
    pub request_id: String,
    pub body: ActivationResultBodyV1,
}

impl ActivationRpcResponseEnvelopeV1 {
    pub fn to_json(&self) -> Result<String, ActivationError> {
        let event = match &self.body.event {
            Some(event) => serde_json::to_value(event).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, format!("the route event is not serializable: {e}")))?,
            None => serde_json::Value::Null,
        };
        let value = serde_json::json!({
            "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
            "requestId": self.request_id,
            "body": {
                "kind": "result",
                "activationId": self.body.activation_id,
                "status": self.body.status.as_str(),
                "event": event,
            },
        });
        let bytes = jcs_bytes(&value).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, e.detail))?;
        String::from_utf8(bytes).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, format!("the response is not UTF-8: {e}")))
    }
}

// ---------------------------------------------------------------------------
// 存储接线：controlRevision CAS 载体（route 指针 + route 事件 + nonce 消费同一 CAS）
// ---------------------------------------------------------------------------

/// 持久化 IO 挂接点。生产接线把读写适配到 wasm 控制态的提交通道（与
/// wasm-control-state-v2.json 同一 fsync/rename 纪律）；测试用内存实现模拟
/// 跨重启持久性。物理载体由集成侧决定，本模块只承诺 JCS 字节权威与 CAS 语义。
pub trait ActivationStateIO: Send + Sync {
    fn read_activation_state(&self) -> std::io::Result<Option<Vec<u8>>>;
    fn write_activation_state(&self, bytes: &[u8]) -> std::io::Result<()>;
}

#[derive(Default)]
pub struct MemoryActivationStateIO {
    bytes: std::sync::Mutex<Option<Vec<u8>>>,
}

impl MemoryActivationStateIO {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ActivationStateIO for MemoryActivationStateIO {
    fn read_activation_state(&self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.bytes.lock().expect("activation state io lock").clone())
    }

    fn write_activation_state(&self, bytes: &[u8]) -> std::io::Result<()> {
        *self.bytes.lock().expect("activation state io lock") = Some(bytes.to_vec());
        Ok(())
    }
}

/// Kernel 侧激活控制态文件（JCS 字节权威；controlRevision 从 0 起，每次已提交
/// mutation 恰好 +1）。应用分区持有全部激活记录（事件、nonce 台账、activationId
/// 记录、rollback 保留与写前意图）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WasmActivationStateFileV1 {
    pub schema_version: u64,
    pub runtime_kind: String,
    pub control_revision: u64,
    pub applications: BTreeMap<String, KernelActivationState>,
}

impl WasmActivationStateFileV1 {
    pub fn empty() -> Self {
        Self { schema_version: 1, runtime_kind: "wasm".into(), control_revision: 0, applications: BTreeMap::new() }
    }
}

/// 存储层崩溃注入点（spec 恢复矩阵的持久化版）：
/// - AfterConsumeMarker：不确定中间态（消费标记已写、指针/事件未提交）以原
///   controlRevision 落盘——该 CAS 从未提交，不消耗 revision；
/// - AfterPointerCas：指针已翻、事件/记录缺失的撕裂提交以原 revision 落盘，
///   恢复以 pending 意图重建精确事件后才补记 revision +1。
pub use ActivationCrashPoint as StoreCrashPoint;

pub struct WasmActivationStore {
    io: Box<dyn ActivationStateIO>,
}

impl WasmActivationStore {
    pub fn new(io: Box<dyn ActivationStateIO>) -> Self {
        Self { io }
    }

    fn load(&self) -> Result<WasmActivationStateFileV1, ActivationError> {
        let bytes = self
            .io
            .read_activation_state()
            .map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, format!("the activation state cannot be read: {e}")))?;
        let Some(bytes) = bytes else {
            return Ok(WasmActivationStateFileV1::empty());
        };
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, format!("the activation state is not JSON: {e}")))?;
        let canonical = jcs_bytes(&value).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, e.detail))?;
        if canonical != bytes {
            return Err(err(WASM_ACTIVATION_FAIL_CLOSED, "the activation state file bytes are not canonical JCS"));
        }
        let file: WasmActivationStateFileV1 =
            serde_json::from_value(value).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, format!("the activation state file is invalid: {e}")))?;
        if file.schema_version != 1 || file.runtime_kind != "wasm" {
            return Err(err(WASM_ACTIVATION_FAIL_CLOSED, "the activation state file must be schemaVersion 1 with runtimeKind wasm"));
        }
        if file.control_revision > WASM_U53_MAX {
            return Err(err(WASM_ACTIVATION_FAIL_CLOSED, "controlRevision exceeds the u53 range"));
        }
        Ok(file)
    }

    fn persist(&self, file: &WasmActivationStateFileV1) -> Result<(), ActivationError> {
        let bytes = jcs_bytes(file).map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, e.detail))?;
        self.io
            .write_activation_state(&bytes)
            .map_err(|e| err(WASM_ACTIVATION_FAIL_CLOSED, format!("the activation state cannot be written: {e}")))
    }

    pub fn control_revision(&self) -> Result<u64, ActivationError> {
        Ok(self.load()?.control_revision)
    }

    pub fn application_state(&self, application_id: &str) -> Result<Option<KernelActivationState>, ActivationError> {
        Ok(self.load()?.applications.get(application_id).cloned())
    }

    /// 不确定提交恢复：每个 pending 意图按 repair_uncertain_activation 裁决。
    /// 撕裂提交的补全（RepairedEventFromPointerCas）记 revision +1（该 CAS 本次
    /// 才被记账）；丢弃消费标记/无事可修不消耗 revision。
    fn recover_file(file: &mut WasmActivationStateFileV1) -> Result<bool, ActivationError> {
        let mut changed = false;
        let application_ids: Vec<String> = file.applications.keys().cloned().collect();
        for application_id in application_ids {
            let Some(state) = file.applications.get_mut(&application_id) else { continue };
            if state.pending.is_none() {
                continue;
            }
            let outcome = repair_uncertain_activation(state)?;
            match outcome {
                ActivationRepairOutcome::NoRepairNeeded => {}
                ActivationRepairOutcome::RepairedEventFromPointerCas(_) => {
                    if file.control_revision >= WASM_U53_MAX {
                        return Err(err(crate::wasm_commands::CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
                    }
                    file.control_revision += 1;
                    changed = true;
                }
                ActivationRepairOutcome::DiscardedPartialConsume => {
                    changed = true;
                }
            }
        }
        Ok(changed)
    }

    pub fn recover(&mut self) -> Result<bool, ActivationError> {
        let mut file = self.load()?;
        let changed = Self::recover_file(&mut file)?;
        if changed {
            self.persist(&file)?;
        }
        Ok(changed)
    }

    /// route 指针 + route 事件 + nonce 消费在同一 controlRevision CAS 提交：
    /// 任一拒绝都不写盘；成功恰 +1。崩溃注入把不确定中间态以原 revision 落盘。
    /// 提交面以 file.controlRevision + 1 覆盖 facts.control_revision——事件的
    /// controlRevision 盖戳即「事件持久化时的 v2 控制态 revision」（恢复先于本
    /// 提交推进 revision，故覆盖必须发生在 recover 之后）。
    pub fn commit_activation(
        &mut self,
        command: &ActivationCommand,
        lease: &ServiceReadinessLeaseV2,
        facts: &OwnedActivationCasFacts,
        event_id: &str,
        crash: Option<ActivationCrashPoint>,
    ) -> Result<RouteEvent, ActivationError> {
        let mut file = self.load()?;
        if Self::recover_file(&mut file)? {
            self.persist(&file)?;
        }
        if file.control_revision >= WASM_U53_MAX {
            return Err(err(crate::wasm_commands::CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
        }
        let application_id = command.application_id.clone();
        let mut state = match file.applications.get(&application_id) {
            Some(state) => state.clone(),
            None => KernelActivationState::new(&application_id)?,
        };
        let before = state.clone();
        let mut facts = facts.clone();
        facts.control_revision = file.control_revision + 1;
        let facts_ref = facts.as_facts();
        match apply_activation(&mut state, command, lease, &facts_ref, event_id, crash) {
            Err(failure) => {
                if failure.code == WASM_ACTIVATION_SIMULATED_CRASH {
                    // 不确定中间态：该 CAS 未提交，原 revision 落盘供恢复裁决。
                    file.applications.insert(application_id, state);
                    self.persist(&file)?;
                }
                Err(failure)
            }
            Ok(event) => {
                if state != before {
                    if file.control_revision >= WASM_U53_MAX {
                        return Err(err(crate::wasm_commands::CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
                    }
                    file.control_revision += 1;
                    file.applications.insert(application_id, state);
                    self.persist(&file)?;
                }
                Ok(event)
            }
        }
    }

    /// lease 台账查无记录：仍要留下 rejected 事件（nonce 不消费、路由不动），
    /// 同一 CAS 纪律提交（事件追加即 mutation，恰 +1；幂等重放零写入；事件以
    /// file.controlRevision + 1 盖戳 controlRevision）。
    pub fn commit_missing_lease_rejection(
        &mut self,
        command: &ActivationCommand,
        now_epoch_millis: u64,
        event_id: &str,
    ) -> Result<RouteEvent, ActivationError> {
        let mut file = self.load()?;
        if Self::recover_file(&mut file)? {
            self.persist(&file)?;
        }
        if file.control_revision >= WASM_U53_MAX {
            return Err(err(crate::wasm_commands::CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
        }
        let application_id = command.application_id.clone();
        let mut state = match file.applications.get(&application_id) {
            Some(state) => state.clone(),
            None => KernelActivationState::new(&application_id)?,
        };
        let before = state.clone();
        let event = apply_activation_without_lease(&mut state, command, now_epoch_millis, file.control_revision + 1, event_id)?;
        if state != before {
            if file.control_revision >= WASM_U53_MAX {
                return Err(err(crate::wasm_commands::CONTROL_REVISION_CONFLICT, "control revision space is exhausted"));
            }
            file.control_revision += 1;
            file.applications.insert(application_id, state);
            self.persist(&file)?;
        }
        Ok(event)
    }

    /// activationId 的 durable 结果（命令 + 事件；None = 无记录）。
    pub fn recorded_activation(&self, activation_id: &str) -> Result<Option<(ActivationCommand, RouteEvent)>, ActivationError> {
        let file = self.load()?;
        for state in file.applications.values() {
            if let Some(recorded) = state.activation_records.get(activation_id) {
                return Ok(Some((recorded.command.clone(), recorded.event.clone())));
            }
        }
        Ok(None)
    }

    /// 该 activationId 是否存在未裁决的写前意图（query 的 received 状态）。
    pub fn pending_activation(&self, activation_id: &str) -> Result<bool, ActivationError> {
        let file = self.load()?;
        Ok(file.applications.values().any(|state| state.pending.as_ref().is_some_and(|pending| pending.command.activation_id == activation_id)))
    }
}

// ---------------------------------------------------------------------------
// 端点服务：query/replay/命令 → result body；HTTP 封装挂接 Bearer 通道
// ---------------------------------------------------------------------------

/// CAS 判据的自有版本（宿主回调提供；借用视图给纯函数层）。control_revision 为
/// 调用方初值——store 提交面以 file.controlRevision + 1 覆盖（事件盖戳权威在
/// 持久化边界，宿主回调无法提前知道恢复后的 revision）。
#[derive(Debug, Clone, PartialEq)]
pub struct OwnedActivationCasFacts {
    pub now_epoch_millis: u64,
    pub control_revision: u64,
    pub current_secret_store_revision: u64,
    pub current_preparation_generation: u64,
    pub candidate_alive: bool,
    pub registry_row: Option<RegistryRowFacts>,
    pub binding_revoked: bool,
    pub rollback_retention: Option<RollbackRecord>,
}

impl OwnedActivationCasFacts {
    pub fn as_facts(&self) -> ActivationCasFacts<'_> {
        ActivationCasFacts {
            now_epoch_millis: self.now_epoch_millis,
            control_revision: self.control_revision,
            current_secret_store_revision: self.current_secret_store_revision,
            current_preparation_generation: self.current_preparation_generation,
            candidate_alive: self.candidate_alive,
            registry_row: self.registry_row.as_ref(),
            binding_revoked: self.binding_revoked,
            rollback_retention: self.rollback_retention.as_ref(),
        }
    }
}

/// 宿主依赖挂接点：时钟、owner Bearer 校验、lease 台账查找、CAS 判据、eventId 源。
/// 真实 Kernel 部署把这些接到控制面权威（owner key 校验、readiness lease 记录、
/// wasm 业务 registry 投影）；本模块只消费它们，绝不自行解释秘密或业务状态。
pub struct ActivationDeps<'a> {
    pub now_epoch_millis: &'a dyn Fn() -> u64,
    pub verify_bearer: &'a dyn Fn(Option<&str>) -> bool,
    pub lease_lookup: &'a dyn Fn(&str) -> Option<ServiceReadinessLeaseV2>,
    pub facts: &'a dyn Fn(&str) -> OwnedActivationCasFacts,
    pub event_id: &'a dyn Fn() -> String,
}

pub struct ActivationHttpFailure {
    pub status: u16,
    pub code: String,
    pub message: String,
}

fn activation_failure(failure: ActivationError) -> ActivationHttpFailure {
    let status = match failure.code {
        ACTIVATION_ID_CONFLICT | WASM_ACTIVATION_REPAIR_REQUIRED => 409,
        WASM_ACTIVATION_FAIL_CLOSED => 500,
        _ => 400,
    };
    ActivationHttpFailure { status, code: failure.code.into(), message: failure.detail }
}

fn result_body(activation_id: &str, event: &RouteEvent) -> Result<ActivationResultBodyV1, ActivationHttpFailure> {
    let status = match event.result {
        RouteEventResult::Activated => ActivationStatus::Activated,
        RouteEventResult::Rejected => ActivationStatus::Rejected,
    };
    Ok(ActivationResultBodyV1 { activation_id: activation_id.to_string(), status, event: Some(event.clone()) })
}

fn submit_command(
    store: &mut WasmActivationStore,
    command: &ActivationCommand,
    deps: &ActivationDeps<'_>,
) -> Result<ActivationResultBodyV1, ActivationHttpFailure> {
    let event_id = (deps.event_id)();
    let lease_nonce = command.candidate.lease_nonce.clone();
    let event = match (deps.lease_lookup)(&lease_nonce) {
        Some(lease) => {
            let facts = (deps.facts)(&command.application_id);
            store.commit_activation(command, &lease, &facts, &event_id, None).map_err(activation_failure)?
        }
        None => store.commit_missing_lease_rejection(command, (deps.now_epoch_millis)(), &event_id).map_err(activation_failure)?,
    };
    result_body(&command.activation_id, &event)
}

/// envelope 级处理（无 HTTP framing）：query 只读；replay 对已知 activationId
/// 要求字节等价命令，对未裁决意图重放同一 CAS；command 走提交路径。
pub fn handle_activation_rpc_envelope(
    store: &mut WasmActivationStore,
    envelope: &ActivationRpcRequestEnvelope,
    deps: &ActivationDeps<'_>,
) -> Result<ActivationRpcResponseEnvelopeV1, ActivationHttpFailure> {
    let body = match &envelope.body {
        ActivationRpcRequestBody::Command(command) => return Ok(ActivationRpcResponseEnvelopeV1 {
            request_id: envelope.request_id.clone(),
            body: submit_command(store, command, deps)?,
        }),
        ActivationRpcRequestBody::Query { activation_id } => {
            match store.recorded_activation(activation_id).map_err(activation_failure)? {
                Some((_, event)) => result_body(activation_id, &event)?,
                None => {
                    let status = if store.pending_activation(activation_id).map_err(activation_failure)? {
                        ActivationStatus::Received
                    } else {
                        ActivationStatus::Missing
                    };
                    ActivationResultBodyV1 { activation_id: activation_id.clone(), status, event: None }
                }
            }
        }
        ActivationRpcRequestBody::Replay(command) => match store.recorded_activation(&command.activation_id).map_err(activation_failure)? {
            Some((recorded_command, event)) => {
                if recorded_command != *command {
                    return Err(ActivationHttpFailure {
                        status: 409,
                        code: ACTIVATION_ID_CONFLICT.into(),
                        message: "replay accepts only the byte-identical activation command; no route event is created".into(),
                    });
                }
                result_body(&command.activation_id, &event)?
            }
            None => {
                if store.pending_activation(&command.activation_id).map_err(activation_failure)? {
                    // "received" 且无事件：重放同一 CAS（store 先恢复不确定提交）。
                    submit_command(store, command, deps)?
                } else {
                    return Err(ActivationHttpFailure {
                        status: 404,
                        code: WASM_ACTIVATION_INVALID.into(),
                        message: "unknown activationId; send the command first".into(),
                    });
                }
            }
        },
    };
    Ok(ActivationRpcResponseEnvelopeV1 { request_id: envelope.request_id.clone(), body })
}

/// HTTP 请求描述（挂接点：真实部署把 axum 提取值适配到这里）。
pub struct ActivationHttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub authorization: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActivationHttpResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ActivationHttpOptions {
    pub max_request_bytes: usize,
}

impl Default for ActivationHttpOptions {
    fn default() -> Self {
        Self { max_request_bytes: ACTIVATION_RPC_DEFAULT_MAX_BYTES }
    }
}

fn activation_http_error(status: u16, code: &str, message: &str) -> ActivationHttpResponse {
    ActivationHttpResponse { status, body: serde_json::json!({ "ok": false, "code": code, "message": message }).to_string() + "\n" }
}

fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| value.split(';').next().is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json")))
}

/// POST /v1/wasm/activation-rpc 的六步 framing：方法/路径 → body 上限 →
/// content type → owner Bearer（挂接点）→ JCS envelope → 服务处理。
pub fn handle_activation_rpc_http(
    store: &mut WasmActivationStore,
    deps: &ActivationDeps<'_>,
    request: ActivationHttpRequest<'_>,
    options: ActivationHttpOptions,
) -> ActivationHttpResponse {
    if request.method != "POST" || request.path != ACTIVATION_RPC_PATH {
        return activation_http_error(404, "UNKNOWN_ROUTE", "unknown kernel activation route");
    }
    if request.body.len() > options.max_request_bytes {
        return activation_http_error(413, "BODY_TOO_LARGE", "activation rpc request is too large");
    }
    if !is_json_content_type(request.content_type) {
        return activation_http_error(415, "UNSUPPORTED_CONTENT_TYPE", "activation rpc expects application/json");
    }
    if !(deps.verify_bearer)(request.authorization) {
        return activation_http_error(401, ACTIVATION_UNAUTHORIZED, "activation requires the owner bearer credential");
    }
    let envelope = match parse_activation_rpc_envelope(request.body) {
        Ok(envelope) => envelope,
        Err(failure) => return activation_http_error(400, ACTIVATION_RPC_ENVELOPE_INVALID, &failure.detail),
    };
    match handle_activation_rpc_envelope(store, &envelope, deps) {
        Ok(response) => match response.to_json() {
            Ok(body) => ActivationHttpResponse { status: 200, body: body + "\n" },
            Err(failure) => activation_http_error(500, failure.code, &failure.detail),
        },
        Err(failure) => activation_http_error(failure.status, &failure.code, &failure.message),
    }
}

// ---------------------------------------------------------------------------
// tests：lease digest 跨语言 golden、CAS 门全场景、恢复、rollback binding 持久化
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// tests：lease digest 跨语言 golden、CAS 门全场景、恢复、rollback binding 持久化
//（单版本 wire：fixture 统一 ServiceReadinessLeaseV2 + ActivationCommand）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "shop";
    const VERSION_ID: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1";
    const ROLLBACK_VERSION_ID: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1";
    const LEASE_NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const SEED_NONCE: &str = "99999999999999999999999999999999";
    /// TS exampleServiceReadinessLeaseV2 的 leaseDigest（digestV2 0x00 域）。
    const GOLDEN_V2_LEASE_DIGEST: &str = "517d4d1986ec6961e51e59a5c5e6dda19e56f68301729aa86c2350309c876065";
    /// TS exampleActivationCommandV2 镜像（携带必填 capability pin）的 wire JCS
    /// 指纹（sha256(JCS(bytes))）与 commandDigest（单版本化后由本地 oracle 复算）。
    const GOLDEN_COMMAND_JCS_SHA256: &str = "2a50437a594d72504a4f8562de504d3b050a2719233f16a5301edb3ad912519b";
    const GOLDEN_COMMAND_DIGEST: &str = "105f0db95eef20e13c9500136c466fb7b0af671c68ba18f85bee58db7f2e2edf";
    const GOLDEN_EVENT_JCS_SHA256: &str = "5e90ab4cc88a8c0fcb1c12ad01a76ec0b684c112fc38872ba0471fc49454da92";
    const GOLDEN_EVENT_DIGEST: &str = "d01134b92d038b7d8deade898b5f09765245095e1e072741befbb6233221b7e0";
    const GOLDEN_ROLLBACK_JCS_SHA256: &str = "d38cc62b566d11c86769c4d8d917c9b1e6633f78dd733b1e5fa7327fd1f8e482";
    const GOLDEN_ROLLBACK_DIGEST: &str = "96d90caf50cf20f8b5adede62953afded515cf9ade582662e0fbead803a888cb";
    const V2_VECTOR_VERSION_ID: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1";
    const EXAMPLE_V2_POLICY_DIGEST: &str = "b21afb8e8cb4e6482b137ef5749ea2b9c39e4ef35619bfb079d4c83bd75bb665";
    /// 基准时刻：lease 签发于 1_800_000_000_000，默认 60s 窗口。
    const CAS_NOW: u64 = 1_800_000_000_000;
    const SECRET_REVISION: u64 = 3;
    /// 新候选的 preparation/execution 代次（seed 激活用 1，新准备推进到 2）。
    const GENERATION: u64 = 2;
    const CAPABILITY_REVISION: u64 = 5;
    const CAPABILITY_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn binding_v1() -> RuntimeBindingIdentityV1 {
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

    fn binding() -> RuntimeBindingIdentityV2 {
        runtime_binding_v2_from_v1(&binding_v1()).expect("binding derives")
    }

    /// packages/contracts/wasm-health.ts exampleServiceReadinessLeaseV2 的跨语言
    /// golden 同值镜像。
    fn vector_lease() -> ServiceReadinessLeaseV2 {
        ServiceReadinessLeaseV2 {
            schema_version: 2,
            lease_nonce: LEASE_NONCE.into(),
            sandbox_id: "sbx-vector".into(),
            version_id: VERSION_ID.into(),
            package_digest: "0".repeat(64),
            runtime_binding: binding(),
            host_service_policy_digest: EXAMPLE_V2_POLICY_DIGEST.into(),
            capability_record_revision: CAPABILITY_REVISION,
            capability_record_hash: CAPABILITY_HASH.into(),
            secret_revision: 3,
            secret_values_digest: "6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some("7".repeat(64)),
            config_values_digest: Some("8".repeat(64)),
            preparation_generation: 1,
            execution_generation: 1,
            issued_at: "2026-08-26T00:00:00Z".into(),
            expires_at: "2026-08-26T00:10:00Z".into(),
            lease_digest: GOLDEN_V2_LEASE_DIGEST.into(),
        }
    }

    fn lease_for(candidate: &ActivationCandidate, window_millis: u64) -> ServiceReadinessLeaseV2 {
        let issued = CAS_NOW;
        let base = ServiceReadinessLeaseV2 {
            schema_version: 2,
            lease_nonce: candidate.lease_nonce.clone(),
            sandbox_id: candidate.sandbox_id.clone(),
            version_id: candidate.version_id.clone(),
            package_digest: candidate.package_digest.clone(),
            runtime_binding: candidate.runtime_binding.clone(),
            host_service_policy_digest: String::new(),
            capability_record_revision: CAPABILITY_REVISION,
            capability_record_hash: CAPABILITY_HASH.into(),
            secret_revision: candidate.secret_revision,
            secret_values_digest: candidate.secret_values_digest.clone(),
            config_revision: candidate.config_revision,
            config_snapshot_ref: candidate.config_snapshot_ref.clone(),
            config_values_digest: candidate.config_values_digest.clone(),
            preparation_generation: candidate.preparation_generation,
            execution_generation: candidate.execution_generation,
            issued_at: crate::wasm_admission::format_rfc3339_utc_millis(issued),
            expires_at: crate::wasm_admission::format_rfc3339_utc_millis(issued + window_millis),
            lease_digest: String::new(),
        };
        let digest = compute_service_readiness_lease_digest(&base).expect("lease digest");
        ServiceReadinessLeaseV2 { lease_digest: digest, ..base }
    }

    fn make_candidate(version_id: &str, nonce: &str, secret_revision: u64, generation: u64) -> ActivationCandidate {
        let probe = ActivationCandidate {
            runtime_kind: "wasm".into(),
            sandbox_id: "sbx-candidate".into(),
            version_id: version_id.into(),
            package_digest: "0".repeat(64),
            runtime_binding: binding(),
            admission_proof_ref: format!("admission-proof/{APP}/{version_id}"),
            admission_proof_digest: "3".repeat(64),
            preparation_generation: generation,
            execution_generation: generation,
            secret_revision,
            secret_values_digest: "6".repeat(64),
            config_revision: 0,
            config_snapshot_ref: None,
            config_values_digest: None,
            lease_nonce: nonce.into(),
            lease_digest: String::new(),
        };
        let lease = lease_for(&probe, 60_000);
        ActivationCandidate { lease_digest: lease.lease_digest, ..probe }
    }

    /// 测试工具：命令任意字段变异后重算 commandDigest（合法命令面）。
    fn seal_command(mut command: ActivationCommand) -> ActivationCommand {
        command.command_digest = compute_activation_command_digest(&command).expect("command digest");
        command
    }

    fn make_command(activation_id: &str, candidate: ActivationCandidate, expected: u64) -> ActivationCommand {
        seal_command(ActivationCommand {
            schema_version: 2,
            activation_id: activation_id.into(),
            application_id: APP.into(),
            operation: ActivationOperation::Activate,
            expected_route_generation: expected,
            expected_control_revision: 0,
            candidate,
            host_service_policy_digest: String::new(),
            capability_record_revision: CAPABILITY_REVISION,
            capability_record_hash: CAPABILITY_HASH.into(),
            requested_at: crate::wasm_admission::format_rfc3339_utc_millis(CAS_NOW),
            command_digest: String::new(),
        })
    }

    fn registry_row() -> RegistryRowFacts {
        RegistryRowFacts { runtime_binding: binding_v1(), capability_record_revision: CAPABILITY_REVISION, capability_record_hash: CAPABILITY_HASH.into(), host_service_policy_digest: None, lifecycle_ready: true }
    }

    /// rollback 保留记录 fixture：围绕 (to_version_id, target_binding) 构造一份
    /// 自洽的完整 envelope（内嵌 sealed rollback 事件 + rollbackDigest）。
    fn retention_for(to_version_id: &str, target_binding: RuntimeBindingIdentityV1) -> RollbackRecord {
        let rollback_id = "01892555-0000-7000-8000-0000000000fe".to_string();
        let candidate = make_candidate(to_version_id, "a".repeat(32).as_str(), SECRET_REVISION, GENERATION);
        let mut command = make_command(&rollback_id, candidate, 1);
        command.operation = ActivationOperation::Rollback;
        let command = seal_command(command);
        let next_pointer = WasmActivePointerV1::Active {
            runtime_kind: "wasm".into(),
            application_id: APP.into(),
            version_id: to_version_id.into(),
            identity: candidate_identity(&command).expect("identity"),
            runtime_binding: target_binding,
            admission_proof_ref: command.candidate.admission_proof_ref.clone(),
            admission_proof_digest: command.candidate.admission_proof_digest.clone(),
            route_generation: 2,
            host_service_policy_digest: None,
            preparation_generation: Some(GENERATION),
            execution_generation: Some(GENERATION),
        };
        let event = route_event_sealed(RouteEvent {
            schema_version: 2,
            event_id: "01892555-0000-7000-8000-0000000000fd".into(),
            activation_id: rollback_id.clone(),
            application_id: APP.into(),
            runtime_kind: "wasm".into(),
            operation: ActivationOperation::Rollback,
            expected_route_generation: 1,
            previous: WasmActivePointerV1::Unavailable { runtime_kind: "wasm".into(), application_id: APP.into(), route_generation: 0 },
            next: next_pointer,
            lease_consume: LeaseConsumeRecord {
                schema_version: 1,
                lease_nonce: command.candidate.lease_nonce.clone(),
                lease_digest: command.candidate.lease_digest.clone(),
                activation_id: rollback_id.clone(),
                application_id: APP.into(),
                version_id: to_version_id.into(),
                expected_route_generation: 1,
                consumed_at: crate::wasm_admission::format_rfc3339_utc_millis(CAS_NOW),
                outcome: LeaseConsumeOutcome::Consumed,
                route_generation: 2,
            },
            result: RouteEventResult::Activated,
            reason_code: None,
            host_service_policy_digest: String::new(),
            control_revision: 1,
            route_generation: 2,
            created_at: crate::wasm_admission::format_rfc3339_utc_millis(CAS_NOW),
            event_digest: String::new(),
        })
        .expect("event seals");
        let mut record = RollbackRecord {
            schema_version: 2,
            rollback_id,
            application_id: APP.into(),
            from_version_id: String::new(),
            to_version_id: to_version_id.into(),
            expected_route_generation: 1,
            expected_control_revision: 0,
            route_event: event,
            host_service_policy_digest: String::new(),
            reason_code: None,
            result: RollbackRecordResult::Applied,
            created_at_epoch_millis: CAS_NOW,
            rollback_digest: String::new(),
        };
        record.rollback_digest = compute_rollback_record_digest(&record).expect("rollback digest");
        record
    }

    fn make_facts<'a>(now: u64, secret_revision: u64, generation: u64, registry: Option<&'a RegistryRowFacts>) -> ActivationCasFacts<'a> {
        ActivationCasFacts {
            now_epoch_millis: now,
            control_revision: 0,
            current_secret_store_revision: secret_revision,
            current_preparation_generation: generation,
            candidate_alive: true,
            registry_row: registry,
            binding_revoked: false,
            rollback_retention: None,
        }
    }

    /// 用一次真实激活制造历史：旧版本 b*..-1 持有 route generation 1；
    /// 新候选以 preparation/execution 代次 2 出现。
    fn seeded_state() -> KernelActivationState {
        let mut state = KernelActivationState::new(APP).expect("state");
        let previous_version_id = format!("{}-1", "b".repeat(64));
        let previous_candidate = make_candidate(&previous_version_id, SEED_NONCE, SECRET_REVISION, 1);
        // make_candidate 以默认 60s 窗口预烧 lease digest；seed lease 必须用同一窗口。
        let previous_lease = lease_for(&previous_candidate, 60_000);
        let previous_command = make_command("01892555-0000-7000-8000-000000000000", previous_candidate, 0);
        let row = registry_row();
        let facts = make_facts(CAS_NOW, SECRET_REVISION, 1, Some(&row));
        apply_activation(&mut state, &previous_command, &previous_lease, &facts, "01892555-0000-7000-8000-0000000000ed", None).expect("seed activation");
        assert_eq!(state.route_generation, 1);
        state
    }

    #[test]
    fn lease_digest_matches_ts_golden_vector() {
        let lease = vector_lease();
        assert_eq!(compute_service_readiness_lease_digest(&lease).unwrap(), GOLDEN_V2_LEASE_DIGEST);
        assert!(lease.validate().is_ok());
    }

    #[test]
    fn lease_validation_rejects_bad_shape_and_digest() {
        let mut lease = vector_lease();
        lease.lease_nonce = "not-hex!".into();
        assert_eq!(lease.validate().unwrap_err().code, READINESS_LEASE_MISMATCH);
        let mut lease = vector_lease();
        lease.lease_digest = "0".repeat(64);
        assert_eq!(lease.validate().unwrap_err().code, READINESS_LEASE_MISMATCH);
        let mut lease = vector_lease();
        lease.expires_at = lease.issued_at.clone();
        assert_eq!(lease.validate().unwrap_err().code, READINESS_LEASE_MISMATCH);
        // configRevision:0 与非空 ref 矛盾。
        let mut lease = vector_lease();
        lease.config_revision = 0;
        assert_eq!(lease.validate().unwrap_err().code, READINESS_LEASE_MISMATCH);
        // policy digest 文法：非空即必须 64 位小写十六进制；空串（无 host services）
        // 合法。
        let mut lease = vector_lease();
        lease.host_service_policy_digest = "zz".into();
        assert!(lease.validate().is_err());
        let mut lease = vector_lease();
        lease.host_service_policy_digest = String::new();
        lease.lease_digest = compute_service_readiness_lease_digest(&lease).unwrap();
        assert!(lease.validate().is_ok());
    }

    #[test]
    fn cas_lease_expiry_equal_means_expired() {
        let lease = vector_lease();
        let expires_at = lease.expires_at_epoch_millis().unwrap();
        assert!(check_readiness_lease_expiry_at_cas(expires_at - 1, expires_at).is_ok());
        // 相等即过期。
        assert_eq!(check_readiness_lease_expiry_at_cas(expires_at, expires_at).unwrap_err().code, READINESS_LEASE_EXPIRED);
        assert_eq!(check_readiness_lease_expiry_at_cas(expires_at + 1, expires_at).unwrap_err().code, READINESS_LEASE_EXPIRED);
    }

    #[test]
    fn happy_activation_consumes_nonce_and_increments_generation() {
        let mut state = seeded_state();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let command = make_command("01892555-0000-7000-8000-000000000001", candidate, 1);
        let row = registry_row();
        let facts = make_facts(CAS_NOW + 1_000, SECRET_REVISION, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000aaaa", None).expect("activation");
        assert_eq!(event.result, RouteEventResult::Activated);
        assert_eq!(event.route_generation, 2);
        assert_eq!(event.lease_consume.outcome, LeaseConsumeOutcome::Consumed);
        assert_eq!(event.host_service_policy_digest, "");
        assert!(validate_route_event(&event).is_ok());
        assert_eq!(state.route_generation, 2);
        assert!(state.nonce_ledger.contains_key(LEASE_NONCE));
        assert!(matches!(&state.active, WasmActivePointerV1::Active { version_id, .. } if version_id == VERSION_ID));
        // 指针携带候选代次；无 policy 的应用 policy 钉为 None。
        assert!(matches!(&state.active, WasmActivePointerV1::Active { preparation_generation, execution_generation, host_service_policy_digest: None, .. } if *preparation_generation == Some(GENERATION) && *execution_generation == Some(GENERATION)));
        // previous 保留旧 active。
        assert!(matches!(&event.previous, WasmActivePointerV1::Active { version_id, .. } if *version_id != VERSION_ID));
    }

    #[test]
    fn lease_expires_exactly_at_cas_keeps_old_active() {
        let mut state = seeded_state();
        let row = registry_row();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let expires_at = lease.expires_at_epoch_millis().unwrap();
        let command = make_command("01892555-0000-7000-8000-000000000002", candidate, 1);
        // CAS 恰在 expiresAt 线性化：相等即过期。
        let facts = make_facts(expires_at, SECRET_REVISION, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000bbbb", None).expect("rejected event");
        assert_eq!(event.result, RouteEventResult::Rejected);
        assert_eq!(event.reason_code.as_deref(), Some(READINESS_LEASE_EXPIRED));
        assert_eq!(event.next, event.previous);
        assert_eq!(event.route_generation, 1);
        assert_eq!(state.route_generation, 1);
        // 拒绝不消费 nonce。
        assert!(!state.nonce_ledger.contains_key(LEASE_NONCE));
        // 过期前 1ms 仍可激活（spec：先 fresh preparation + health，再 CAS）。
        let candidate2 = make_candidate(VERSION_ID, &"f".repeat(32), SECRET_REVISION, GENERATION);
        let lease2 = lease_for(&candidate2, 60_000);
        let command2 = make_command("01892555-0000-7000-8000-000000000012", candidate2, 1);
        let facts2 = make_facts(expires_at - 1, SECRET_REVISION, GENERATION, Some(&row));
        let event2 = apply_activation(&mut state, &command2, &lease2, &facts2, "01892555-0000-7000-8000-00000000ccc1", None).expect("activation");
        assert_eq!(event2.result, RouteEventResult::Activated);
        assert_eq!(state.route_generation, 2);
    }

    #[test]
    fn candidate_killed_keeps_previous_active() {
        let mut state = seeded_state();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let command = make_command("01892555-0000-7000-8000-000000000003", candidate, 1);
        let row = registry_row();
        let mut facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        facts.candidate_alive = false;
        let event = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000cccc", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        assert_eq!(event.next, event.previous);
        assert_eq!(state.route_generation, 1);
        assert!(!state.nonce_ledger.contains_key(LEASE_NONCE));
    }

    #[test]
    fn route_cas_conflict_keeps_old_active() {
        let mut state = seeded_state();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        // stale expected generation（当前为 1，提交 0）。
        let command = make_command("01892555-0000-7000-8000-000000000004", candidate, 0);
        let row = registry_row();
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000dddd", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_ROUTE_CONFLICT));
        assert_eq!(event.next, event.previous);
        assert_eq!(state.route_generation, 1);
        assert!(!state.nonce_ledger.contains_key(LEASE_NONCE));
    }

    #[test]
    fn lease_for_another_tuple_and_revoked_binding_reject() {
        let mut state = seeded_state();
        let row = registry_row();
        // 内部自洽但指向另一 tuple 的 lease（digest 自洽）：correlate 拒绝。
        let other_tuple_probe = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION + 1, GENERATION);
        let other_tuple_lease = lease_for(&other_tuple_probe, 60_000);
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let command = make_command("01892555-0000-7000-8000-000000000005", candidate, 1);
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &command, &other_tuple_lease, &facts, "01892555-0000-7000-8000-00000000eeee", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(READINESS_LEASE_MISMATCH));
        assert_eq!(state.route_generation, 1);
        // binding 撤销 → ACTIVATION_BINDING_REVOKED。
        let candidate = make_candidate(VERSION_ID, &"e".repeat(32), SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let command = make_command("01892555-0000-7000-8000-000000000006", candidate, 1);
        let mut facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        facts.binding_revoked = true;
        let event = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000ffff", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_BINDING_REVOKED));
    }

    #[test]
    fn stale_secret_revision_candidate_never_activates() {
        let mut state = seeded_state();
        let row = registry_row();
        // 候选 snapshot revision 7，secret-store 已提交 8（2.3 fence）。
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, 7, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let command = make_command("01892555-0000-7000-8000-000000000007", candidate, 1);
        let facts = make_facts(CAS_NOW, 8, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000abba", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        assert_eq!(state.route_generation, 1);
        assert!(!state.nonce_ledger.contains_key(LEASE_NONCE));
    }

    #[test]
    fn nonce_replay_returns_original_event_without_second_consume() {
        let mut state = seeded_state();
        let row = registry_row();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let activation_id = "01892555-0000-7000-8000-000000000008";
        let command = make_command(activation_id, candidate, 1);
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        let original = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000c0de", None).expect("activation");
        // 同 activationId 同命令：幂等（query/replay 语义）。
        let replayed = replay_activation(&state, &command).expect("replay");
        assert_eq!(replayed, original);
        let replayed_again = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000c0df", None).expect("idempotent");
        assert_eq!(replayed_again, original);
        assert_eq!(state.route_generation, 2);
        // 同 activationId 异命令 → ACTIVATION_ID_CONFLICT。
        let mut conflicting = command.clone();
        conflicting.expected_route_generation = 2;
        let conflicting = seal_command(conflicting);
        assert_eq!(apply_activation(&mut state, &conflicting, &lease, &facts, "01892555-0000-7000-8000-00000000c0e0", None).unwrap_err().code, ACTIVATION_ID_CONFLICT);
        // 异 activationId 复用同 nonce 同 digest：AlreadyConsumed——返回原始事件，
        // 不产生第二个事件、不递增 generation（expected 取翻转后的当前值）。
        let replay_command = make_command("01892555-0000-7000-8000-000000000009", command.candidate.clone(), 2);
        let answered = apply_activation(&mut state, &replay_command, &lease, &facts, "01892555-0000-7000-8000-00000000c0e1", None).expect("original result");
        assert_eq!(answered, original);
        assert_eq!(state.route_generation, 2);
        // seed 事件 + 本次激活事件，恰两条。
        assert_eq!(state.events.len(), 2);
    }

    #[test]
    fn duplicate_nonce_for_another_tuple_rejects() {
        let mut state = seeded_state();
        let row = registry_row();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let command = make_command("01892555-0000-7000-8000-000000000010", candidate, 1);
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000d001", None).expect("activation");
        // 同 nonce、不同 digest（另一 tuple 的自洽 lease）→ MISMATCH。
        let candidate2 = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION + 1, GENERATION);
        let lease2 = lease_for(&candidate2, 60_000);
        let command2 = make_command("01892555-0000-7000-8000-000000000011", candidate2, 2);
        let facts2 = make_facts(CAS_NOW, SECRET_REVISION + 1, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &command2, &lease2, &facts2, "01892555-0000-7000-8000-00000000d002", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(READINESS_LEASE_MISMATCH));
        assert_eq!(state.route_generation, 2);
    }

    #[test]
    fn rollback_uses_same_gate_and_persists_target_binding() {
        let mut state = seeded_state();
        let row = registry_row();
        let candidate = make_candidate(ROLLBACK_VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let mut no_retention = make_command("01892555-0000-7000-8000-000000000012", candidate.clone(), 1);
        no_retention.operation = ActivationOperation::Rollback;
        let no_retention = seal_command(no_retention);
        // 无保留记录 → NOT_READY（fail-closed）。
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &no_retention, &lease, &facts, "01892555-0000-7000-8000-00000000e0f1", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        // 保留记录 binding 与候选不一致 → NOT_READY（独立 activationId）。
        let mut mismatched_binding = binding_v1();
        mismatched_binding.catalog_revision = 77;
        let mismatched = retention_for(ROLLBACK_VERSION_ID, mismatched_binding);
        let mut mismatched_command = make_command("01892555-0000-7000-8000-000000000013", candidate.clone(), 1);
        mismatched_command.operation = ActivationOperation::Rollback;
        let mismatched_command = seal_command(mismatched_command);
        let mut facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        facts.rollback_retention = Some(&mismatched);
        let event = apply_activation(&mut state, &mismatched_command, &lease, &facts, "01892555-0000-7000-8000-00000000e0f2", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        // 一致的保留记录 → 同一 gate 放行，事件持久化目标 binding。
        let retention = retention_for(ROLLBACK_VERSION_ID, binding_v1());
        let mut rollback_command = make_command("01892555-0000-7000-8000-000000000014", candidate, 1);
        rollback_command.operation = ActivationOperation::Rollback;
        let rollback_command = seal_command(rollback_command);
        let mut facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        facts.rollback_retention = Some(&retention);
        let event = apply_activation(&mut state, &rollback_command, &lease, &facts, "01892555-0000-7000-8000-00000000e0f3", None).expect("rollback activation");
        assert_eq!(event.result, RouteEventResult::Activated);
        assert_eq!(event.operation, ActivationOperation::Rollback);
        let persisted = state.rollback_retentions.last().expect("rollback retention persisted");
        assert_eq!(persisted.to_version_id, ROLLBACK_VERSION_ID);
        assert_eq!(persisted.rollback_id, rollback_command.activation_id);
        assert_eq!(persisted.route_event, event);
        assert_eq!(persisted.route_event.route_generation, 2);
        assert!(validate_rollback_record(persisted).is_ok());
        assert_eq!(persisted.from_version_id, format!("{}-1", "b".repeat(64)));
    }

    #[test]
    fn repair_pointer_without_event_writes_exact_event() {
        // 完整跑一遍拿基准事件；再以崩溃注入跑一遍，修复后必须重建同一事件。
        let row = registry_row();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let command = make_command("01892555-0000-7000-8000-000000000015", candidate, 1);
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        let mut complete = seeded_state();
        let expected = apply_activation(&mut complete, &command, &lease, &facts, "01892555-0000-7000-8000-00000000f0a1", None).expect("activation");

        let mut crashed = seeded_state();
        let failure = apply_activation(&mut crashed, &command, &lease, &facts, "01892555-0000-7000-8000-00000000f0a1", Some(ActivationCrashPoint::AfterPointerCasBeforeEvent)).unwrap_err();
        assert_eq!(failure.code, WASM_ACTIVATION_SIMULATED_CRASH);
        assert_eq!(crashed.route_generation, 2);
        assert_eq!(crashed.events.len(), 1); // 仅 seed 事件。
        // 恢复前拒绝新激活。
        assert_eq!(apply_activation(&mut crashed, &command, &lease, &facts, "01892555-0000-7000-8000-00000000f0a2", None).unwrap_err().code, WASM_ACTIVATION_REPAIR_REQUIRED);
        let outcome = repair_uncertain_activation(&mut crashed).expect("repair");
        let ActivationRepairOutcome::RepairedEventFromPointerCas(event) = outcome else {
            panic!("expected RepairedEventFromPointerCas, got {outcome:?}");
        };
        assert_eq!(*event, expected);
        // replay 返回同一事件；不再递增。
        assert_eq!(replay_activation(&crashed, &command).unwrap(), expected);
        assert_eq!(crashed.route_generation, 2);
        assert_eq!(crashed.pending, None);
    }

    #[test]
    fn repair_partial_consume_discards_marker_and_replay_succeeds() {
        let row = registry_row();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let lease = lease_for(&candidate, 60_000);
        let command = make_command("01892555-0000-7000-8000-000000000016", candidate, 1);
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        let mut state = seeded_state();
        let failure = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000f0b1", Some(ActivationCrashPoint::AfterConsumeMarkerBeforePointerCas)).unwrap_err();
        assert_eq!(failure.code, WASM_ACTIVATION_SIMULATED_CRASH);
        // 指针未翻；消费标记存在。
        assert_eq!(state.route_generation, 1);
        assert!(state.nonce_ledger.contains_key(LEASE_NONCE));
        let outcome = repair_uncertain_activation(&mut state).expect("repair");
        assert_eq!(outcome, ActivationRepairOutcome::DiscardedPartialConsume);
        // 租约回到未消费；按原 expectedRouteGeneration 重放成功。
        assert!(!state.nonce_ledger.contains_key(LEASE_NONCE));
        let event = apply_activation(&mut state, &command, &lease, &facts, "01892555-0000-7000-8000-00000000f0b2", None).expect("replay activates");
        assert_eq!(event.result, RouteEventResult::Activated);
        assert_eq!(state.route_generation, 2);
    }

    #[test]
    fn repair_fail_closed_without_intent() {
        let mut state = seeded_state();
        // 伪造：指针翻到 generation 2 但无事件、无 pending（意图丢失）。
        state.route_generation = 2;
        let outcome = repair_uncertain_activation(&mut state).expect_err("fail closed");
        assert_eq!(outcome.code, WASM_ACTIVATION_FAIL_CLOSED);
    }

    #[test]
    fn query_missing_returns_none() {
        let state = seeded_state();
        assert!(query_activation(&state, "01892555-0000-7000-8000-0000000000ff").is_none());
    }

    // -----------------------------------------------------------------------
    // 任务 7.5：envelope / 存储 / 端点 接线测试
    // -----------------------------------------------------------------------

    const OWNER_BEARER: &str = "Bearer owner-key";

    fn owned_facts(now: u64, secret_revision: u64, generation: u64, registry: Option<RegistryRowFacts>) -> OwnedActivationCasFacts {
        OwnedActivationCasFacts {
            now_epoch_millis: now,
            // store 提交面覆盖；直接调用纯函数的用例另行显式给定。
            control_revision: 0,
            current_secret_store_revision: secret_revision,
            current_preparation_generation: generation,
            candidate_alive: true,
            registry_row: registry,
            binding_revoked: false,
            rollback_retention: None,
        }
    }

    /// 测试世界：内存 IO + lease 台账 + facts + 确定性 eventId/时钟。lease 与
    /// facts 的语义与纯函数测试一致（60s 窗口签发于 CAS_NOW）。
    struct TestWorld {
        store: WasmActivationStore,
        leases: BTreeMap<String, ServiceReadinessLeaseV2>,
        facts: BTreeMap<String, OwnedActivationCasFacts>,
        event_counter: std::cell::Cell<u64>,
    }

    /// 共享内存 IO 适配器：让测试在 store 之外直接读原始落盘字节。
    struct SharedActivationIO(std::sync::Arc<MemoryActivationStateIO>);

    impl ActivationStateIO for SharedActivationIO {
        fn read_activation_state(&self) -> std::io::Result<Option<Vec<u8>>> {
            self.0.read_activation_state()
        }

        fn write_activation_state(&self, bytes: &[u8]) -> std::io::Result<()> {
            self.0.write_activation_state(bytes)
        }
    }

    impl TestWorld {
        fn new() -> Self {
            Self::with_io(std::sync::Arc::new(MemoryActivationStateIO::new()))
        }

        fn with_io(io: std::sync::Arc<MemoryActivationStateIO>) -> Self {
            Self { store: WasmActivationStore::new(Box::new(SharedActivationIO(io))), leases: BTreeMap::new(), facts: BTreeMap::new(), event_counter: std::cell::Cell::new(0) }
        }

        /// 用一次真实提交制造历史：旧版本 b*..-1 持有 generation 1。
        fn seed(&mut self) {
            let previous_version_id = format!("{}-1", "b".repeat(64));
            let candidate = make_candidate(&previous_version_id, SEED_NONCE, SECRET_REVISION, 1);
            let lease = lease_for(&candidate, 60_000);
            self.leases.insert(SEED_NONCE.into(), lease.clone());
            self.facts.insert(
                APP.into(),
                owned_facts(CAS_NOW, SECRET_REVISION, 1, Some(registry_row())),
            );
            let command = make_command("01892555-0000-7000-8000-000000000000", candidate, 0);
            let event = self.commit(&command, None).expect("seed activation");
            assert_eq!(event.route_generation, 1);
            // seed 后新准备的当前 preparation 推进到 2。
            self.facts.insert(
                APP.into(),
                owned_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(registry_row())),
            );
        }

        fn commit(&mut self, command: &ActivationCommand, crash: Option<ActivationCrashPoint>) -> Result<RouteEvent, ActivationError> {
            let lease = self.leases.get(&command.candidate.lease_nonce).expect("lease registered").clone();
            let facts = self.facts.get(&command.application_id).expect("facts registered").clone();
            let event_id = self.next_event_id();
            self.store.commit_activation(command, &lease, &facts, &event_id, crash)
        }

        fn next_event_id(&self) -> String {
            let n = self.event_counter.get() + 1;
            self.event_counter.set(n);
            counter_uuid(n)
        }

        /// 通用请求入口：依赖闭包只捕获本函数的局部克隆，避免与 &mut store 的
        /// 借用冲突；事件计数在调用后写回。
        fn request(
            &mut self,
            method: &str,
            path: &str,
            authorization: Option<&str>,
            content_type: Option<&str>,
            body: &[u8],
            options: ActivationHttpOptions,
        ) -> ActivationHttpResponse {
            let leases = self.leases.clone();
            let facts = self.facts.clone();
            let counter = std::cell::Cell::new(self.event_counter.get());
            let now = || CAS_NOW;
            let verify = |authorization: Option<&str>| authorization == Some(OWNER_BEARER);
            let missing_facts = owned_facts(CAS_NOW, SECRET_REVISION, GENERATION, None);
            let deps = ActivationDeps {
                now_epoch_millis: &now,
                verify_bearer: &verify,
                lease_lookup: &|nonce: &str| leases.get(nonce).cloned(),
                facts: &|application: &str| facts.get(application).cloned().unwrap_or_else(|| missing_facts.clone()),
                event_id: &|| {
                    let n = counter.get() + 1;
                    counter.set(n);
                    counter_uuid(n)
                },
            };
            let response = handle_activation_rpc_http(
                &mut self.store,
                &deps,
                ActivationHttpRequest { method, path, authorization, content_type, body },
                options,
            );
            self.event_counter.set(counter.get());
            response
        }

        fn post(&mut self, body: Vec<u8>) -> ActivationHttpResponse {
            self.request("POST", ACTIVATION_RPC_PATH, Some(OWNER_BEARER), Some("application/json"), &body, ActivationHttpOptions::default())
        }
    }

    fn counter_uuid(n: u64) -> String {
        format!("01892555-{:04}-7{:03}-8{:03}-{:012}", n, n, n, n)
    }

    fn command_envelope_body(command: &ActivationCommand) -> serde_json::Value {
        serde_json::json!({
            "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
            "requestId": "01892555-0000-7000-8000-0000000000e0",
            "body": serde_json::to_value(command).expect("command serializes"),
        })
    }

    fn command_envelope_bytes(command: &ActivationCommand) -> Vec<u8> {
        jcs_bytes(&command_envelope_body(command)).expect("canonical envelope bytes")
    }

    fn query_envelope_bytes(activation_id: &str) -> Vec<u8> {
        jcs_bytes(&serde_json::json!({
            "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
            "requestId": "01892555-0000-7000-8000-0000000000e1",
            "body": { "kind": "query", "activationId": activation_id },
        }))
        .expect("canonical query bytes")
    }

    fn replay_envelope_bytes(command: &ActivationCommand) -> Vec<u8> {
        jcs_bytes(&serde_json::json!({
            "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
            "requestId": "01892555-0000-7000-8000-0000000000e2",
            "body": { "kind": "replay", "command": serde_json::to_value(command).expect("command serializes") },
        }))
        .expect("canonical replay bytes")
    }

    fn parse_response(response: &ActivationHttpResponse) -> serde_json::Value {
        serde_json::from_str(response.body.trim_end()).expect("response is JSON")
    }

    #[test]
    fn uuid_v7_generator_matches_grammar() {
        let id = generate_uuid_v7(1_800_000_000_000);
        assert!(regexes().uuid_v7.is_match(&id), "generated id {id} must be a lower-case UUIDv7");
        assert_ne!(id, generate_uuid_v7(1_800_000_000_000), "random bits must differ between calls");
    }

    #[test]
    fn envelope_parsing_requires_canonical_jcs_and_exact_shapes() {
        let command = make_command("01892555-0000-7000-8000-000000000101", make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION), 1);
        // 合法命令 envelope（无 kind 成员）。
        let bytes = command_envelope_bytes(&command);
        let envelope = parse_activation_rpc_envelope(&bytes).expect("canonical command envelope parses");
        match &envelope.body {
            ActivationRpcRequestBody::Command(wire) => assert_eq!(*wire, command),
            other => panic!("expected command body, got {other:?}"),
        }
        // query / replay 形状。
        let query = parse_activation_rpc_envelope(&query_envelope_bytes(&command.activation_id)).expect("query parses");
        assert_eq!(query.body, ActivationRpcRequestBody::Query { activation_id: command.activation_id.clone() });
        let replay = parse_activation_rpc_envelope(&replay_envelope_bytes(&command)).expect("replay parses");
        assert!(matches!(replay.body, ActivationRpcRequestBody::Replay(_)));
        // 非 JCS 字节（键序/白空格）拒绝。
        let non_canonical = String::from_utf8(command_envelope_bytes(&command)).unwrap().replacen("\"protocol\"", "  \"protocol\"", 1);
        assert_eq!(parse_activation_rpc_envelope(non_canonical.as_bytes()).unwrap_err().code, ACTIVATION_RPC_ENVELOPE_INVALID);
        // 浮点（u53 域外）：canonical 化即失败——传输层不可能为浮点 body 产出
        // 合法 JCS 字节，等价于解析层拒绝。
        let mut float_body = command_envelope_body(&command);
        float_body["body"]["expectedRouteGeneration"] = serde_json::json!(1.5);
        assert!(jcs_bytes(&float_body).is_err());
        // 协议字面量错误（含历史 -v1/-v2 变体）拒绝。
        for wrong in ["iweb-execution-rpc-v1", "iweb-wasm-activation-v1", "iweb-wasm-activation-v2"] {
            let mut wrong_protocol = command_envelope_body(&command);
            wrong_protocol["protocol"] = serde_json::json!(wrong);
            let wrong_bytes = jcs_bytes(&wrong_protocol).expect("canonical");
            assert_eq!(parse_activation_rpc_envelope(&wrong_bytes).unwrap_err().code, ACTIVATION_RPC_ENVELOPE_INVALID);
        }
        // spec 无 {kind:"command"} 形状：命令体携带 kind 一律拒绝（fail-closed）。
        let mut kind_command = command_envelope_body(&command);
        kind_command["body"] = serde_json::json!({ "kind": "command", "command": kind_command["body"].clone() });
        let kind_bytes = jcs_bytes(&kind_command).expect("canonical");
        assert_eq!(parse_activation_rpc_envelope(&kind_bytes).unwrap_err().code, ACTIVATION_RPC_ENVELOPE_INVALID);
        // 未知字段拒绝（deny_unknown_fields）。
        let mut extra = command_envelope_body(&command);
        extra["body"]["extra"] = serde_json::json!(1);
        let extra_bytes = jcs_bytes(&extra).expect("canonical");
        assert!(parse_activation_rpc_envelope(&extra_bytes).is_err());
    }

    #[test]
    fn http_framing_and_bearer_are_enforced() {
        let mut world = TestWorld::new();
        world.seed();
        let command = make_command("01892555-0000-7000-8000-000000000102", make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION), 1);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&command.candidate, 60_000));
        let body = command_envelope_bytes(&command);
        // 方法/路径。
        let wrong_method = world.request("GET", ACTIVATION_RPC_PATH, Some(OWNER_BEARER), Some("application/json"), &body, ActivationHttpOptions::default());
        assert_eq!(wrong_method.status, 404);
        // body 上限。
        let too_large = world.request("POST", ACTIVATION_RPC_PATH, Some(OWNER_BEARER), Some("application/json"), &body, ActivationHttpOptions { max_request_bytes: 8 });
        assert_eq!(too_large.status, 413);
        // content type。
        let wrong_type = world.request("POST", ACTIVATION_RPC_PATH, Some(OWNER_BEARER), Some("text/plain"), &body, ActivationHttpOptions::default());
        assert_eq!(wrong_type.status, 415);
        // owner Bearer。
        let unauthenticated = world.request("POST", ACTIVATION_RPC_PATH, None, Some("application/json"), &body, ActivationHttpOptions::default());
        assert_eq!(unauthenticated.status, 401);
        assert!(unauthenticated.body.contains(ACTIVATION_UNAUTHORIZED));
        // 非 JSON。
        let invalid_json = world.post(b"{not json".to_vec());
        assert_eq!(invalid_json.status, 400);
        // 零副作用：四次拒绝后 revision 仍为 seed 后的 1。
        assert_eq!(world.store.control_revision().unwrap(), 1);
    }

    #[test]
    fn endpoint_activates_and_lost_response_query_replays_original_event() {
        let mut world = TestWorld::new();
        world.seed();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let command = make_command("01892555-0000-7000-8000-000000000110", candidate, 1);
        let first = world.post(command_envelope_bytes(&command));
        assert_eq!(first.status, 200);
        let parsed = parse_response(&first);
        assert_eq!(parsed["body"]["status"], "activated");
        assert_eq!(parsed["body"]["activationId"], command.activation_id);
        assert_eq!(parsed["protocol"], ACTIVATION_RPC_PROTOCOL_LITERAL);
        assert_eq!(parsed["requestId"], "01892555-0000-7000-8000-0000000000e0");
        assert_eq!(parsed["body"]["event"]["schemaVersion"], 2);
        assert_eq!(parsed["body"]["event"]["routeGeneration"], 2);
        assert_eq!(parsed["body"]["event"]["leaseConsume"]["outcome"], "consumed");
        assert_eq!(world.store.control_revision().unwrap(), 2);

        // response lost：客户端重发同命令（或 query/replay）得到原始事件，
        // 不二次消费 nonce、不二次递增 generation/revision。
        let retry = world.post(command_envelope_bytes(&command));
        assert_eq!(retry.status, 200);
        assert_eq!(parse_response(&retry)["body"]["event"], parsed["body"]["event"]);
        let query = world.post(query_envelope_bytes(&command.activation_id));
        assert_eq!(parse_response(&query)["body"]["event"], parsed["body"]["event"]);
        assert_eq!(parse_response(&query)["body"]["status"], "activated");
        let replay = world.post(replay_envelope_bytes(&command));
        assert_eq!(parse_response(&replay)["body"]["event"], parsed["body"]["event"]);
        assert_eq!(world.store.control_revision().unwrap(), 2);
        let state = world.store.application_state(APP).unwrap().expect("state");
        assert_eq!(state.route_generation, 2);
        assert_eq!(state.events.len(), 2);
        // 未知 activationId → missing。
        let missing = world.post(query_envelope_bytes("01892555-0000-7000-8000-0000000000ff"));
        assert_eq!(parse_response(&missing)["body"]["status"], "missing");
        assert!(parse_response(&missing)["body"]["event"].is_null());
        // 同 activationId 异命令重放 → envelope 级 409，无新事件。
        let mut conflicting = command.clone();
        conflicting.expected_route_generation = 2;
        let conflicting = seal_command(conflicting);
        let conflict = world.post(replay_envelope_bytes(&conflicting));
        assert_eq!(conflict.status, 409);
        assert!(conflict.body.contains(ACTIVATION_ID_CONFLICT));
        // 未知 activationId 重放 → 404。
        let unknown = world.post(replay_envelope_bytes(&make_command("01892555-0000-7000-8000-0000000000fe", make_candidate(VERSION_ID, &"a".repeat(32), SECRET_REVISION, GENERATION), 2)));
        assert_eq!(unknown.status, 404);
        assert_eq!(world.store.control_revision().unwrap(), 2);
    }

    #[test]
    fn stale_nonce_envelope_rejected_event_keeps_route() {
        let mut world = TestWorld::new();
        world.seed();
        // 第一个命令消费 nonce。
        let first_candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&first_candidate, 60_000));
        let first_command = make_command("01892555-0000-7000-8000-000000000120", first_candidate, 1);
        let first = world.post(command_envelope_bytes(&first_command));
        assert_eq!(parse_response(&first)["body"]["status"], "activated");
        // 同 nonce、另一 tuple 的自洽 lease → envelope 级 rejected 事件（MISMATCH）。
        let stale_candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION + 1, GENERATION);
        let stale_lease = lease_for(&stale_candidate, 60_000);
        world.leases.insert(LEASE_NONCE.into(), stale_lease);
        world.facts.insert(APP.into(), owned_facts(CAS_NOW, SECRET_REVISION + 1, GENERATION, Some(registry_row())));
        let stale_command = make_command("01892555-0000-7000-8000-000000000121", stale_candidate, 2);
        let stale = world.post(command_envelope_bytes(&stale_command));
        assert_eq!(stale.status, 200);
        let parsed = parse_response(&stale);
        assert_eq!(parsed["body"]["status"], "rejected");
        assert_eq!(parsed["body"]["event"]["reasonCode"], READINESS_LEASE_MISMATCH);
        assert_eq!(parsed["body"]["event"]["routeGeneration"], 2);
        let state = world.store.application_state(APP).unwrap().expect("state");
        assert_eq!(state.route_generation, 2);
        // rejected 事件是 committed mutation：revision +1；nonce 台账无第二 tuple。
        assert_eq!(world.store.control_revision().unwrap(), 3);
        // 该 rejected 结果同样可 query/replay 幂等返回。
        let query = world.post(query_envelope_bytes(&stale_command.activation_id));
        assert_eq!(parse_response(&query)["body"]["event"], parsed["body"]["event"]);
    }

    #[test]
    fn partial_lease_marker_crash_discards_and_replays_same_cas() {
        let mut world = TestWorld::new();
        world.seed();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let command = make_command("01892555-0000-7000-8000-000000000130", candidate, 1);
        // 崩溃：消费标记已写、指针/事件未提交。不确定中间态以原 revision 落盘。
        let failure = world.commit(&command, Some(ActivationCrashPoint::AfterConsumeMarkerBeforePointerCas)).expect_err("simulated crash");
        assert_eq!(failure.code, WASM_ACTIVATION_SIMULATED_CRASH);
        assert_eq!(world.store.control_revision().unwrap(), 1);
        let uncertain = world.store.application_state(APP).unwrap().expect("state");
        assert!(uncertain.nonce_ledger.contains_key(LEASE_NONCE));
        assert_eq!(uncertain.route_generation, 1);
        // 显式恢复：丢弃消费标记（租约回到未消费），不消耗 revision。
        assert!(world.store.recover().expect("repair ok"));
        let repaired = world.store.application_state(APP).unwrap().expect("state");
        assert!(!repaired.nonce_ledger.contains_key(LEASE_NONCE));
        assert_eq!(repaired.route_generation, 1);
        assert_eq!(world.store.control_revision().unwrap(), 1);
        // 按原 expectedRouteGeneration 重放成功：指针/事件/消费同一 CAS（恰 +1）。
        let event = world.commit(&command, None).expect("replay activates");
        assert_eq!(event.result, RouteEventResult::Activated);
        assert_eq!(event.route_generation, 2);
        assert_eq!(world.store.control_revision().unwrap(), 2);
    }

    #[test]
    fn pointer_flip_without_event_is_repaired_from_pending_intent() {
        // 基准：无崩溃的完整结果。
        let mut reference = TestWorld::new();
        reference.seed();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        reference.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let command = make_command("01892555-0000-7000-8000-000000000140", candidate, 1);
        let expected = reference.commit(&command, None).expect("activation");

        // 崩溃注入：指针已翻、事件缺失，以原 revision 落盘（撕裂提交）。
        let mut world = TestWorld::new();
        world.seed();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let command = make_command("01892555-0000-7000-8000-000000000140", candidate, 1);
        let failure = world.commit(&command, Some(ActivationCrashPoint::AfterPointerCasBeforeEvent)).expect_err("simulated crash");
        assert_eq!(failure.code, WASM_ACTIVATION_SIMULATED_CRASH);
        assert_eq!(world.store.control_revision().unwrap(), 1);
        // query 在未裁决意图上只读：status received、event null。
        let query = world.post(query_envelope_bytes(&command.activation_id));
        assert_eq!(parse_response(&query)["body"]["status"], "received");
        assert!(parse_response(&query)["body"]["event"].is_null());
        // replay：先修复（从 pending 意图重建精确事件并补记 revision），再幂等返回。
        let replay = world.post(replay_envelope_bytes(&command));
        assert_eq!(replay.status, 200);
        let parsed = parse_response(&replay);
        assert_eq!(parsed["body"]["status"], "activated");
        assert_eq!(world.store.control_revision().unwrap(), 2);
        let state = world.store.application_state(APP).unwrap().expect("state");
        assert_eq!(state.events.len(), 2);
        // 与无崩溃基准的事件逐字段一致（同 eventId/CAS 时刻/previous）。
        assert_eq!(state.events.last().unwrap(), &expected);
        // 再次 replay：不再递增。
        let again = world.post(replay_envelope_bytes(&command));
        assert_eq!(parse_response(&again)["body"]["event"], parsed["body"]["event"]);
        assert_eq!(world.store.control_revision().unwrap(), 2);
        assert_eq!(state.route_generation, 2);
    }

    #[test]
    fn rollback_envelope_persists_retention_and_duplicate_never_increments() {
        let mut world = TestWorld::new();
        world.seed();
        let candidate = make_candidate(ROLLBACK_VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let mut facts = owned_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(registry_row()));
        facts.rollback_retention = Some(retention_for(ROLLBACK_VERSION_ID, binding_v1()));
        world.facts.insert(APP.into(), facts);
        let mut command = make_command("01892555-0000-7000-8000-000000000150", candidate, 1);
        command.operation = ActivationOperation::Rollback;
        let command = seal_command(command);
        let response = world.post(command_envelope_bytes(&command));
        assert_eq!(parse_response(&response)["body"]["status"], "activated");
        let state = world.store.application_state(APP).unwrap().expect("state");
        let persisted = state.rollback_retentions.last().expect("rollback retention persisted");
        assert_eq!(persisted.to_version_id, ROLLBACK_VERSION_ID);
        assert_eq!(persisted.rollback_id, command.activation_id);
        assert!(validate_rollback_record(persisted).is_ok());
        // 重复 activation（同 activationId 同命令）：幂等，不递增 generation/revision。
        let revision_after_rollback = world.store.control_revision().unwrap();
        let duplicate = world.post(command_envelope_bytes(&command));
        assert_eq!(parse_response(&duplicate)["body"]["status"], "activated");
        assert_eq!(parse_response(&duplicate)["body"]["event"], parse_response(&response)["body"]["event"]);
        assert_eq!(world.store.control_revision().unwrap(), revision_after_rollback);
        let state = world.store.application_state(APP).unwrap().expect("state");
        assert_eq!(state.route_generation, 2);
        assert_eq!(state.rollback_retentions.len(), 1);
    }

    #[test]
    fn missing_lease_record_rejects_without_consuming_nonce() {
        let mut world = TestWorld::new();
        world.seed();
        // 候选 nonce 无 lease 台账记录：rejected 事件（MISMATCH），路由不动。
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        let command = make_command("01892555-0000-7000-8000-000000000160", candidate.clone(), 1);
        let response = world.post(command_envelope_bytes(&command));
        assert_eq!(parse_response(&response)["body"]["status"], "rejected");
        assert_eq!(parse_response(&response)["body"]["event"]["reasonCode"], READINESS_LEASE_MISMATCH);
        let state = world.store.application_state(APP).unwrap().expect("state");
        assert_eq!(state.route_generation, 1);
        assert!(!state.nonce_ledger.contains_key(LEASE_NONCE));
        assert_eq!(world.store.control_revision().unwrap(), 2);
        // 补上 lease 记录后同一候选可正常激活（新 activationId）。
        world.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let command = make_command("01892555-0000-7000-8000-000000000161", candidate, 1);
        let activated = world.post(command_envelope_bytes(&command));
        assert_eq!(parse_response(&activated)["body"]["status"], "activated");
        assert_eq!(world.store.control_revision().unwrap(), 3);
    }

    #[test]
    fn store_file_is_canonical_jcs_and_roundtrips() {
        let io = std::sync::Arc::new(MemoryActivationStateIO::new());
        let mut world = TestWorld::with_io(io.clone());
        world.seed();
        let candidate = make_candidate(VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let command = make_command("01892555-0000-7000-8000-000000000170", candidate, 1);
        world.commit(&command, None).expect("activation");
        // 落盘字节 = JCS(parse(bytes))；文件 round-trip 保真。
        let bytes = io.read_activation_state().expect("io read").expect("state persisted");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("file is JSON");
        assert_eq!(jcs_bytes(&value).unwrap(), bytes);
        let file: WasmActivationStateFileV1 = serde_json::from_value(value).expect("file round-trips");
        assert_eq!(file.control_revision, 2);
        assert_eq!(file.applications.len(), 1);
        // 命令 pure==wire：requestedAt RFC3339 原串保真。
        assert!(command.requested_at.ends_with('Z'));
    }

    // -----------------------------------------------------------------------
    // golden 向量（单版本 wire；TS example* 同值镜像 + 必填 capability pin）+
    // CAS 正/负、持久化/回放。
    // -----------------------------------------------------------------------

    fn vector_binding_v2() -> RuntimeBindingIdentityV2 {
        binding()
    }

    /// TS exampleActivationCommandV2 同值镜像 + 必填 capability pin（单版本化后
    /// 键恒在场）。
    fn golden_wire_command() -> ActivationCommand {
        let lease = vector_lease();
        seal_command(ActivationCommand {
            schema_version: 2,
            activation_id: "018f1e2c-3d4b-7a5e-9f01-23456789abe1".into(),
            application_id: "vector".into(),
            operation: ActivationOperation::Activate,
            expected_route_generation: 0,
            expected_control_revision: 0,
            candidate: ActivationCandidate {
                runtime_kind: "wasm".into(),
                sandbox_id: "sbx-vector".into(),
                version_id: V2_VECTOR_VERSION_ID.into(),
                package_digest: "0".repeat(64),
                runtime_binding: vector_binding_v2(),
                admission_proof_ref: format!("admission-proof/vector/{V2_VECTOR_VERSION_ID}"),
                admission_proof_digest: "3".repeat(64),
                preparation_generation: 1,
                execution_generation: 1,
                secret_revision: 3,
                secret_values_digest: "6".repeat(64),
                config_revision: 2,
                config_snapshot_ref: Some("7".repeat(64)),
                config_values_digest: Some("8".repeat(64)),
                lease_nonce: lease.lease_nonce.clone(),
                lease_digest: lease.lease_digest.clone(),
            },
            host_service_policy_digest: EXAMPLE_V2_POLICY_DIGEST.into(),
            capability_record_revision: CAPABILITY_REVISION,
            capability_record_hash: CAPABILITY_HASH.into(),
            requested_at: "2026-08-28T00:00:00Z".into(),
            command_digest: String::new(),
        })
    }

    /// 测试工具：事件任意字段变异后重算 eventDigest（合法事件面）。
    fn seal_event(mut event: RouteEvent) -> RouteEvent {
        event.event_digest = compute_route_event_digest(&event).expect("event digest");
        event
    }

    /// TS exampleRouteEventV2 同值镜像（controlRevision = 首次提交的控制态
    /// revision 1；时间为 Kernel 规范 ".000Z" 渲染；指针携带 policy 钉与代次）。
    fn golden_wire_event() -> RouteEvent {
        let command = golden_wire_command();
        let mut event = RouteEvent {
            schema_version: 2,
            event_id: "018f1e2c-3d4b-7a5e-9f01-23456789abe2".into(),
            activation_id: command.activation_id.clone(),
            application_id: command.application_id.clone(),
            runtime_kind: "wasm".into(),
            operation: command.operation,
            expected_route_generation: command.expected_route_generation,
            previous: WasmActivePointerV1::Unavailable { runtime_kind: "wasm".into(), application_id: command.application_id.clone(), route_generation: 0 },
            next: WasmActivePointerV1::Active {
                runtime_kind: "wasm".into(),
                application_id: command.application_id.clone(),
                version_id: command.candidate.version_id.clone(),
                identity: WasmVersionIdentity { application_id: command.application_id.clone(), digest: "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532".into(), sequence: 1 },
                runtime_binding: RuntimeBindingIdentityV1 {
                    kind: "wasm".into(),
                    catalog_revision: 9,
                    catalog_hash: "ab".repeat(32),
                    entry_key: "iweb-wasmd".into(),
                    image_digest: format!("sha256:{}", "cd".repeat(32)),
                    host_abi: crate::wasm_admission::WASM_HOST_ABI_LITERAL.into(),
                    world: crate::wasm_admission::WASM_WORLD_LITERAL.into(),
                },
                admission_proof_ref: command.candidate.admission_proof_ref.clone(),
                admission_proof_digest: command.candidate.admission_proof_digest.clone(),
                route_generation: 1,
                host_service_policy_digest: Some(EXAMPLE_V2_POLICY_DIGEST.into()),
                preparation_generation: Some(1),
                execution_generation: Some(1),
            },
            lease_consume: LeaseConsumeRecord {
                schema_version: 1,
                lease_nonce: command.candidate.lease_nonce.clone(),
                lease_digest: command.candidate.lease_digest.clone(),
                activation_id: command.activation_id.clone(),
                application_id: command.application_id.clone(),
                version_id: command.candidate.version_id.clone(),
                expected_route_generation: command.expected_route_generation,
                consumed_at: "2026-08-28T00:00:01.000Z".into(),
                outcome: LeaseConsumeOutcome::Consumed,
                route_generation: 1,
            },
            result: RouteEventResult::Activated,
            reason_code: None,
            host_service_policy_digest: command.host_service_policy_digest.clone(),
            control_revision: 1,
            route_generation: 1,
            created_at: "2026-08-28T00:00:01.000Z".into(),
            event_digest: String::new(),
        };
        event.event_digest = compute_route_event_digest(&event).expect("event digest");
        event
    }

    /// TS exampleRollbackRecordV2 同值镜像（完整 envelope；持久化面 epoch 毫秒；
    /// 内嵌事件为 rollback 形态——activationId = rollbackId、operation = rollback）。
    fn golden_rollback_record() -> RollbackRecord {
        let command = golden_wire_command();
        let rollback_id = "018f1e2c-3d4b-7a5e-9f01-23456789abe4".to_string();
        let mut embedded = golden_wire_event();
        embedded.event_id = "018f1e2c-3d4b-7a5e-9f01-23456789abe3".into();
        embedded.activation_id = rollback_id.clone();
        embedded.operation = ActivationOperation::Rollback;
        embedded = seal_event(embedded);
        let mut record = RollbackRecord {
            schema_version: 2,
            rollback_id,
            application_id: command.application_id.clone(),
            from_version_id: format!("{}-1", "b".repeat(64)),
            to_version_id: command.candidate.version_id.clone(),
            expected_route_generation: command.expected_route_generation,
            expected_control_revision: command.expected_control_revision,
            route_event: embedded,
            host_service_policy_digest: command.host_service_policy_digest.clone(),
            reason_code: None,
            result: RollbackRecordResult::Applied,
            created_at_epoch_millis: parse_rfc3339_utc_millis("2026-08-28T00:00:02Z").unwrap(),
            rollback_digest: String::new(),
        };
        record.rollback_digest = compute_rollback_record_digest(&record).expect("rollback digest");
        record
    }

    /// V2 向量 lease 的签发时刻 +60s（CAS 落在租约窗口内；CAS_NOW 基准晚于窗口）。
    fn v2_cas_now() -> u64 {
        vector_lease().issued_at_epoch_millis().unwrap() + 60_000
    }

    fn v2_registry_row() -> RegistryRowFacts {
        RegistryRowFacts {
            runtime_binding: binding_v1(),
            capability_record_revision: CAPABILITY_REVISION,
            capability_record_hash: CAPABILITY_HASH.into(),
            host_service_policy_digest: Some(EXAMPLE_V2_POLICY_DIGEST.into()),
            lifecycle_ready: true,
        }
    }

    #[test]
    fn command_golden_jcs_round_trips() {
        let wire = golden_wire_command();
        assert!(wire.validate().is_ok());
        let jcs = jcs_bytes(&wire).expect("wire JCS");
        assert_eq!(sha256_hex(&jcs), GOLDEN_COMMAND_JCS_SHA256);
        assert_eq!(wire.command_digest, GOLDEN_COMMAND_DIGEST);
        // 精确键集 round-trip（deny_unknown_fields 保真）。
        let parsed: ActivationCommand = serde_json::from_slice(&jcs).expect("command parses");
        assert_eq!(parsed, wire);
        // 负向量：schemaVersion 钳 2、policy digest 文法（空串合法/垃圾非法）、
        // 未知字段、ABI 1.0.0 binding、expectedControlRevision 超 u53、
        // commandDigest 篡改（复算 fail-closed）、被覆盖字段篡改。
        let mut wrong_version = wire.clone();
        wrong_version.schema_version = 1;
        assert_eq!(wrong_version.validate().unwrap_err().code, WASM_ACTIVATION_INVALID);
        let mut bad_policy = wire.clone();
        bad_policy.host_service_policy_digest = "zz".into();
        assert!(bad_policy.validate().is_err());
        let mut empty_policy = wire.clone();
        empty_policy.host_service_policy_digest = String::new();
        let empty_policy = seal_command(empty_policy);
        assert!(empty_policy.validate().is_ok());
        let mut v1_binding = wire.clone();
        v1_binding.candidate.runtime_binding.host_abi = crate::wasm_admission::WASM_HOST_ABI_LITERAL.into();
        assert!(v1_binding.validate().is_err());
        let mut bad_revision = wire.clone();
        bad_revision.expected_control_revision = WASM_U53_MAX + 1;
        assert!(bad_revision.validate().is_err());
        let mut tampered_digest = wire.clone();
        tampered_digest.command_digest = "0".repeat(64);
        let failure = tampered_digest.validate().unwrap_err();
        assert_eq!(failure.code, WASM_ACTIVATION_INVALID);
        assert!(failure.detail.contains("commandDigest"));
        // 被覆盖字段篡改（policy digest）而摘要未重算 → 复算失败。
        let mut tampered_policy = wire.clone();
        tampered_policy.host_service_policy_digest = "9".repeat(64);
        assert!(tampered_policy.validate().is_err());
        let mut value = serde_json::to_value(&wire).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ActivationCommand>(value).is_err());
    }

    #[test]
    fn event_golden_jcs_and_structural_validation() {
        let wire_event = golden_wire_event();
        let jcs = jcs_bytes(&wire_event).expect("event JCS");
        assert_eq!(sha256_hex(&jcs), GOLDEN_EVENT_JCS_SHA256);
        assert_eq!(wire_event.event_digest, GOLDEN_EVENT_DIGEST);
        assert_eq!(wire_event.control_revision, 1);
        // pure==wire：结构校验（activated 四方耦合 + eventDigest 复算）直接通过。
        assert!(validate_route_event(&wire_event).is_ok());
        // 负向量：activated 带 reasonCode / 拒绝形态带 consumed outcome / 拒绝翻指针 /
        // 错误 schemaVersion / 未知字段 / eventDigest 篡改。
        let mut bad_reason = wire_event.clone();
        bad_reason.reason_code = Some("NOPE".into());
        bad_reason = seal_event(bad_reason);
        assert!(validate_route_event(&bad_reason).is_err());
        let mut bad_rejected = wire_event.clone();
        bad_rejected.result = RouteEventResult::Rejected;
        bad_rejected = seal_event(bad_rejected);
        assert!(validate_route_event(&bad_rejected).is_err());
        let mut bad_pointer = wire_event.clone();
        bad_pointer.next = bad_pointer.previous.clone();
        bad_pointer.route_generation = 5;
        bad_pointer = seal_event(bad_pointer);
        assert!(validate_route_event(&bad_pointer).is_err());
        // schemaVersion 钳 2：摘要按变异后记录自洽，仍必须因 schemaVersion 拒绝。
        let wrong_version = seal_event({
            let mut event = wire_event.clone();
            event.schema_version = 1;
            event
        });
        assert!(validate_route_event(&wrong_version).is_err());
        let mut tampered_digest = wire_event.clone();
        tampered_digest.event_digest = "0".repeat(64);
        let failure = validate_route_event(&tampered_digest).unwrap_err();
        assert_eq!(failure.code, WASM_ACTIVATION_INVALID);
        assert!(failure.detail.contains("eventDigest"));
        // 被覆盖字段篡改（controlRevision）而摘要未重算 → 复算失败。
        let mut tampered_revision = wire_event;
        tampered_revision.control_revision = 7;
        assert!(validate_route_event(&tampered_revision).is_err());
    }

    #[test]
    fn rollback_record_golden_envelope_and_digest_recompute() {
        let record = golden_rollback_record();
        let jcs = jcs_bytes(&record).expect("rollback record JCS");
        assert_eq!(sha256_hex(&jcs), GOLDEN_ROLLBACK_JCS_SHA256);
        assert_eq!(record.rollback_digest, GOLDEN_ROLLBACK_DIGEST);
        assert!(validate_rollback_record(&record).is_ok());
        // 负例：rollbackDigest 篡改 / 被覆盖字段（expectedControlRevision）篡改 /
        // applied 带 reasonCode（重算摘要后仍拒绝——reason/result 耦合）/ 未知字段。
        let mut tampered = record.clone();
        tampered.rollback_digest = "0".repeat(64);
        let failure = validate_rollback_record(&tampered).unwrap_err();
        assert_eq!(failure.code, WASM_ACTIVATION_INVALID);
        assert!(failure.detail.contains("rollbackDigest"));
        let mut covered = record.clone();
        covered.expected_control_revision += 1;
        assert!(validate_rollback_record(&covered).is_err());
        let mut bad_reason = record.clone();
        bad_reason.reason_code = Some("NOPE".into());
        bad_reason.rollback_digest = compute_rollback_record_digest(&bad_reason).unwrap();
        assert!(validate_rollback_record(&bad_reason).is_err());
        let mut value = serde_json::to_value(&record).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<RollbackRecord>(value).is_err());
    }

    #[test]
    fn activation_cas_positive_and_negative() {
        let mut state = KernelActivationState::new("vector").expect("state");
        let lease = vector_lease();
        let command = golden_wire_command();
        let row = v2_registry_row();
        // facts 显式给定 controlRevision 盖戳值 1（首提交的故事位：file rev 0 → 1）。
        let facts = ActivationCasFacts { control_revision: 1, ..make_facts(v2_cas_now(), 3, 1, Some(&row)) };
        // 正向量：命令 + lease → 事件（policy digest + controlRevision 盖戳 +
        // eventDigest 随事件持久化；指针投影 policy 钉与候选代次）。
        let event = apply_activation(&mut state, &command, &lease, &facts, "018f1e2c-3d4b-7a5e-9f01-23456789abe2", None).expect("activation");
        assert_eq!(event.result, RouteEventResult::Activated);
        assert_eq!(event.route_generation, 1);
        assert_eq!(event.host_service_policy_digest, EXAMPLE_V2_POLICY_DIGEST);
        assert_eq!(event.control_revision, 1);
        assert_eq!(event.event_digest, compute_route_event_digest(&event).unwrap());
        assert!(validate_route_event(&event).is_ok());
        assert_eq!(state.route_generation, 1);
        assert!(state.nonce_ledger.contains_key(LEASE_NONCE));
        assert!(matches!(&state.active, WasmActivePointerV1::Active { host_service_policy_digest: Some(digest), preparation_generation: Some(1), execution_generation: Some(1), .. } if digest == EXAMPLE_V2_POLICY_DIGEST));

        // 负向量：registry 行无 policy 钉（None ↔ 命令空串语义不同）→ NOT_READY。
        let mut fresh = KernelActivationState::new("vector").unwrap();
        let mut no_policy_row = v2_registry_row();
        no_policy_row.host_service_policy_digest = None;
        let no_policy_facts = make_facts(v2_cas_now(), 3, 1, Some(&no_policy_row));
        let bad_command = seal_command({
            let mut bad = command.clone();
            bad.activation_id = "018f1e2c-3d4b-7a5e-9f01-23456789abe4".into();
            bad.candidate.lease_nonce = "e".repeat(32);
            bad
        });
        let mut bad_lease = lease.clone();
        bad_lease.lease_nonce = "e".repeat(32);
        bad_lease.lease_digest = String::new();
        bad_lease.lease_digest = compute_service_readiness_lease_digest(&bad_lease).unwrap();
        let bad_command = seal_command({
            let mut bad = bad_command;
            bad.candidate.lease_digest = bad_lease.lease_digest.clone();
            bad
        });
        let event = apply_activation(&mut fresh, &bad_command, &bad_lease, &no_policy_facts, "018f1e2c-3d4b-7a5e-9f01-23456789abe5", None).expect("rejected event");
        assert_eq!(event.result, RouteEventResult::Rejected);
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        assert!(validate_route_event(&event).is_ok());
        // registry policy 钉不等 → NOT_READY。
        let mut wrong_policy_row = v2_registry_row();
        wrong_policy_row.host_service_policy_digest = Some("9".repeat(64));
        let wrong_policy_facts = make_facts(v2_cas_now(), 3, 1, Some(&wrong_policy_row));
        let mut fresh2 = KernelActivationState::new("vector").unwrap();
        let event = apply_activation(&mut fresh2, &bad_command, &bad_lease, &wrong_policy_facts, "018f1e2c-3d4b-7a5e-9f01-23456789abe6", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        // lease policy ≠ 命令 policy → READINESS_LEASE_MISMATCH（自洽 lease）。
        let mut other_policy_lease = lease.clone();
        other_policy_lease.lease_nonce = "d".repeat(32);
        other_policy_lease.host_service_policy_digest = "9".repeat(64);
        other_policy_lease.lease_digest = compute_service_readiness_lease_digest(&other_policy_lease).unwrap();
        let mismatch_command = seal_command({
            let mut mismatch = command.clone();
            mismatch.activation_id = "018f1e2c-3d4b-7a5e-9f01-23456789abe7".into();
            mismatch.candidate.lease_nonce = other_policy_lease.lease_nonce.clone();
            mismatch.candidate.lease_digest = other_policy_lease.lease_digest.clone();
            mismatch
        });
        let mut fresh3 = KernelActivationState::new("vector").unwrap();
        let event = apply_activation(&mut fresh3, &mismatch_command, &other_policy_lease, &facts, "018f1e2c-3d4b-7a5e-9f01-23456789abe8", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(READINESS_LEASE_MISMATCH));

        // rollback 保留记录摘要被篡改（持久层损坏）→ fail-closed（不按业务
        // NOT_READY 解释）。
        let mut tampered_retention = golden_rollback_record();
        tampered_retention.rollback_digest = "0".repeat(64);
        let mut tampered_facts = make_facts(v2_cas_now(), 3, 1, Some(&row));
        tampered_facts.rollback_retention = Some(&tampered_retention);
        let mut fresh5 = KernelActivationState::new("vector").unwrap();
        let rollback_probe = seal_command({
            let mut probe = command.clone();
            probe.activation_id = "018f1e2c-3d4b-7a5e-9f01-23456789abf6".into();
            probe.operation = ActivationOperation::Rollback;
            probe.candidate.lease_nonce = "f".repeat(32);
            probe
        });
        let mut probe_lease = lease.clone();
        probe_lease.lease_nonce = rollback_probe.candidate.lease_nonce.clone();
        probe_lease.lease_digest = compute_service_readiness_lease_digest(&probe_lease).unwrap();
        let rollback_probe = seal_command({
            let mut probe = rollback_probe;
            probe.candidate.lease_digest = probe_lease.lease_digest.clone();
            probe
        });
        let failure = apply_activation(&mut fresh5, &rollback_probe, &probe_lease, &tampered_facts, "018f1e2c-3d4b-7a5e-9f01-23456789abf7", None).unwrap_err();
        assert_eq!(failure.code, WASM_ACTIVATION_FAIL_CLOSED);
    }

    #[test]
    fn route_event_persists_replays_and_rollback_record() {
        let mut world = TestWorld::new();
        // 世界：lease 台账 + registry facts（service-enabled 行）。
        world.leases.insert(LEASE_NONCE.into(), vector_lease());
        let mut facts = owned_facts(v2_cas_now(), 3, 1, Some(v2_registry_row()));
        world.facts.insert("vector".into(), facts.clone());
        // store 提交：事件持久化；store 提交面以 file.controlRevision + 1 盖戳
        //（首提交 → 1）。
        let wire = golden_wire_command();
        let event = world
            .store
            .commit_activation(&wire, &vector_lease(), &facts, "018f1e2c-3d4b-7a5e-9f01-23456789abeb", None)
            .expect("commit");
        assert_eq!(event.control_revision, 1, "the store stamps the post-commit control revision");
        assert!(validate_route_event(&event).is_ok());
        assert_eq!(world.store.control_revision().unwrap(), 1);
        let state = world.store.application_state("vector").unwrap().expect("state");
        assert_eq!(state.route_generation, 1);
        // 幂等重放：同命令返回原始事件，不二次递增。
        let replayed = world
            .store
            .commit_activation(&wire, &vector_lease(), &facts, "018f1e2c-3d4b-7a5e-9f01-23456789abec", None)
            .expect("idempotent replay");
        assert_eq!(replayed, event);
        assert_eq!(world.store.control_revision().unwrap(), 1);
        // durable 记录：recorded_activation 返回命令 + 事件。
        let (recorded_command, recorded_event) = world.store.recorded_activation(&wire.activation_id).unwrap().expect("recorded");
        assert_eq!(recorded_command, wire);
        assert_eq!(recorded_event, event);

        // rollback：既有保留记录（完整 envelope + 有效摘要）→ 新 rollback 提交
        // 追加 RollbackRecord（内嵌成功事件 + rollbackDigest）。
        let rollback_wire = seal_command(ActivationCommand {
            activation_id: "018f1e2c-3d4b-7a5e-9f01-23456789abed".into(),
            operation: ActivationOperation::Rollback,
            expected_route_generation: 1,
            candidate: ActivationCandidate {
                lease_nonce: "b".repeat(32),
                lease_digest: String::new(),
                ..wire.candidate.clone()
            },
            ..wire.clone()
        });
        let mut rollback_lease = vector_lease();
        rollback_lease.lease_nonce = rollback_wire.candidate.lease_nonce.clone();
        rollback_lease.lease_digest = compute_service_readiness_lease_digest(&rollback_lease).unwrap();
        let rollback_wire = seal_command(ActivationCommand { candidate: ActivationCandidate { lease_digest: rollback_lease.lease_digest.clone(), ..rollback_wire.candidate.clone() }, ..rollback_wire });
        facts.rollback_retention = Some(golden_rollback_record());
        world.facts.insert("vector".into(), facts.clone());
        let event = world
            .store
            .commit_activation(&rollback_wire, &rollback_lease, &facts, "018f1e2c-3d4b-7a5e-9f01-23456789abee", None)
            .expect("rollback");
        assert_eq!(event.operation, ActivationOperation::Rollback);
        assert_eq!(event.route_generation, 2);
        assert_eq!(event.control_revision, 2, "the second commit stamps revision 2");
        let state = world.store.application_state("vector").unwrap().expect("state");
        let retention = state.rollback_retentions.last().expect("retention");
        assert_eq!(retention.host_service_policy_digest, EXAMPLE_V2_POLICY_DIGEST);
        assert_eq!(retention.rollback_id, "018f1e2c-3d4b-7a5e-9f01-23456789abed");
        assert_eq!(retention.expected_control_revision, rollback_wire.expected_control_revision);
        assert_eq!(retention.route_event, event);
        assert_eq!(retention.result, RollbackRecordResult::Applied);
        assert!(validate_rollback_record(retention).is_ok());
        assert_eq!(retention.rollback_digest, compute_rollback_record_digest(retention).unwrap());
        // 落盘字节仍是规范 JCS。
        assert_eq!(world.store.control_revision().unwrap(), 2);
    }
}
