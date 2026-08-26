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
//! 建模注记（接线批次映射，非语义变更）：时间用 epoch 毫秒 u64（wire 侧
//! RFC3339-UTC 由 wasm_admission 转换，lease 记录本身保留 RFC3339 原串以
//! 保证 leaseDigest 字节精确）；eventId/activationId 由调用方提供（生产为
//! UUIDv7）；ownerCommandId 采用 activationId 投影（ActivationCommandV1 不含
//! 独立 owner 命令 ID，见歧义报告）。

use crate::wasm_admission::{
    format_rfc3339_utc_millis, jcs_bytes, parse_rfc3339_utc_millis, parse_wasm_version_id, validate_runtime_binding,
    RuntimeBindingIdentityV1, WasmActivePointerV1, WasmVersionIdentity, WASM_U53_MAX,
};
use crate::wasm_secrets::matches_secret_revision_fence;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误码
// ---------------------------------------------------------------------------

/// spec 已命名的五个 RouteEventV1 拒绝码。
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

pub const READINESS_LEASE_DIGEST_DOMAIN: &str = "iweb-readiness-lease-v2";

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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// ReadinessLeaseV2（nonce 绑定 canonical wire；保留 RFC3339 原串保证字节精确）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadinessLeaseV2 {
    pub schema_version: u64,
    pub lease_nonce: String,
    pub sandbox_id: String,
    pub version_id: String,
    pub package_digest: String,
    pub runtime_binding: RuntimeBindingIdentityV1,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    pub secret_revision: u64,
    pub secret_values_digest: String,
    pub config_revision: u64,
    /// null 恰当对应 configRevision:0；serde 默认序列化为显式 null（键不省略）。
    pub config_snapshot_ref: Option<String>,
    pub config_values_digest: Option<String>,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    /// RFC3339-UTC 原串（digest 输入的字节保真）。
    pub issued_at: String,
    pub expires_at: String,
    pub lease_digest: String,
}

impl ReadinessLeaseV2 {
    pub fn issued_at_epoch_millis(&self) -> Result<u64, ActivationError> {
        parse_rfc3339_utc_millis(&self.issued_at).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/issuedAt: {}", e.detail)))
    }

    pub fn expires_at_epoch_millis(&self) -> Result<u64, ActivationError> {
        parse_rfc3339_utc_millis(&self.expires_at).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/expiresAt: {}", e.detail)))
    }

    /// 结构校验（不含与候选的 correlate）：nonce 文法、能力钉、config 耦合、
    /// expiresAt > issuedAt、leaseDigest 复算一致。
    pub fn validate(&self) -> Result<(), ActivationError> {
        if self.schema_version != 2 {
            return Err(lease_mismatch("schemaVersion must be exactly 2 for a ReadinessLeaseV2"));
        }
        if !regexes().lease_nonce.is_match(&self.lease_nonce) {
            return Err(lease_mismatch("leaseNonce must be 32 lower-case hex characters"));
        }
        check_sandbox_id(&self.sandbox_id).map_err(|e| lease_mismatch(e.detail))?;
        check_sha256_hex(&self.package_digest, "packageDigest").map_err(|e| lease_mismatch(e.detail))?;
        validate_runtime_binding(&self.runtime_binding).map_err(|e| lease_mismatch(e.detail))?;
        require_u53(self.capability_record_revision, 1, WASM_U53_MAX, "capabilityRecordRevision").map_err(|e| lease_mismatch(e.detail))?;
        check_sha256_hex(&self.capability_record_hash, "capabilityRecordHash").map_err(|e| lease_mismatch(e.detail))?;
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
        if self.lease_digest != compute_readiness_lease_digest(self).map_err(|e| lease_mismatch(e.detail))? {
            return Err(lease_mismatch("leaseDigest does not equal hex(SHA-256(UTF8(\"iweb-readiness-lease-v2\\n\" || JCS(record with leaseDigest omitted))))"));
        }
        Ok(())
    }
}

/// leaseDigest = hex(SHA-256(UTF8("iweb-readiness-lease-v2\n" ||
/// JCS(record with leaseDigest omitted))))；单次域前缀 SHA-256，不二次哈希 hex 串。
pub fn compute_readiness_lease_digest(lease: &ReadinessLeaseV2) -> Result<String, ActivationError> {
    let mut value = serde_json::to_value(lease).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("lease is not serializable as JSON: {e}")))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| err(WASM_ACTIVATION_INVALID, "the lease must serialize to a JSON object"))?;
    map.remove("leaseDigest");
    let bytes = serde_json::to_vec(&value).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("JCS serialization failed: {e}")))?;
    let mut preimage = Vec::with_capacity(READINESS_LEASE_DIGEST_DOMAIN.len() + 1 + bytes.len());
    preimage.extend_from_slice(READINESS_LEASE_DIGEST_DOMAIN.as_bytes());
    preimage.push(b'\n');
    preimage.extend_from_slice(&bytes);
    Ok(sha256_hex(&preimage))
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
// ActivationCommandV1 / 候选（candidate 子对象按 spec 精确键集）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationOperation {
    Activate,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivationCandidateV1 {
    pub runtime_kind: String,
    pub sandbox_id: String,
    pub version_id: String,
    pub package_digest: String,
    pub runtime_binding: RuntimeBindingIdentityV1,
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

impl ActivationCandidateV1 {
    pub fn validate(&self, application_id: &str) -> Result<(), ActivationError> {
        if self.runtime_kind != "wasm" {
            return Err(err(WASM_ACTIVATION_INVALID, "candidate runtimeKind must be exactly \"wasm\""));
        }
        check_sandbox_id(&self.sandbox_id)?;
        check_sha256_hex(&self.package_digest, "packageDigest")?;
        let (digest, sequence) = parse_wasm_version_id(&self.version_id).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/versionId: {}", e.detail)))?;
        require_u53(sequence, 1, WASM_U53_MAX, "sequence")?;
        let _ = digest;
        validate_runtime_binding(&self.runtime_binding).map_err(|e| err(WASM_ACTIVATION_INVALID, e.detail))?;
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivationCommandV1 {
    pub schema_version: u64,
    pub activation_id: String,
    pub application_id: String,
    pub operation: ActivationOperation,
    pub expected_route_generation: u64,
    pub candidate: ActivationCandidateV1,
    pub requested_at_epoch_millis: u64,
}

impl ActivationCommandV1 {
    pub fn validate(&self) -> Result<(), ActivationError> {
        if self.schema_version != 1 {
            return Err(err(WASM_ACTIVATION_INVALID, "schemaVersion must be exactly 1"));
        }
        check_uuid_v7(&self.activation_id, "activationId")?;
        check_application_id(&self.application_id)?;
        require_u53(self.expected_route_generation, 0, WASM_U53_MAX, "expectedRouteGeneration")?;
        require_u53(self.requested_at_epoch_millis, 0, u64::MAX, "requestedAt")?;
        self.candidate.validate(&self.application_id)
    }
}

// ---------------------------------------------------------------------------
// LeaseConsumeRecordV1 / RouteEventV1 / RollbackRetentionRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseConsumeOutcome {
    Consumed,
    AlreadyConsumed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LeaseConsumeRecordV1 {
    pub schema_version: u64,
    pub lease_nonce: String,
    pub lease_digest: String,
    pub activation_id: String,
    pub application_id: String,
    pub version_id: String,
    pub expected_route_generation: u64,
    pub consumed_at_epoch_millis: u64,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteEventV1 {
    pub schema_version: u64,
    pub event_id: String,
    pub activation_id: String,
    pub application_id: String,
    pub runtime_kind: String,
    pub operation: ActivationOperation,
    pub expected_route_generation: u64,
    pub previous: WasmActivePointerV1,
    pub next: WasmActivePointerV1,
    pub lease_consume: LeaseConsumeRecordV1,
    pub result: RouteEventResult,
    pub reason_code: Option<String>,
    pub route_generation: u64,
    pub created_at_epoch_millis: u64,
}

/// spec catalog 法的 rollback 记录精确七字段：目标 binding 随事件持久化。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RollbackRetentionRecord {
    pub application_id: String,
    pub from_version_id: String,
    pub to_version_id: String,
    pub target_runtime_binding: RuntimeBindingIdentityV1,
    pub route_generation: u64,
    pub created_at_epoch_millis: u64,
    pub owner_command_id: String,
}

// ---------------------------------------------------------------------------
// CAS 判据输入与 Kernel 状态
// ---------------------------------------------------------------------------

/// registry 行事实（Kernel 侧权威记录的投影；capability 钉来自 proof）。
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryRowFacts {
    pub runtime_binding: RuntimeBindingIdentityV1,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    /// lifecycle 是否处于可激活（ready/retained admitted）。
    pub lifecycle_ready: bool,
}

/// CAS 线性化点全部判据输入。
#[derive(Debug, Clone, PartialEq)]
pub struct ActivationCasFacts<'a> {
    /// CAS 线性化时刻的单调时钟读数（epoch 毫秒投影）。
    pub now_epoch_millis: u64,
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
    pub rollback_retention: Option<&'a RollbackRetentionRecord>,
}

/// 一次 CAS 的写前意图（恢复的确定性输入；含 eventId、CAS 时刻与当时的
/// active 指针，使"指针已翻但事件缺失"能重建精确事件）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingActivationCas {
    pub command: ActivationCommandV1,
    pub lease: ReadinessLeaseV2,
    pub event_id: String,
    pub cas_now_epoch_millis: u64,
    /// 意图写入时的 active 指针（= 事件的 previous）。
    pub previous_pointer: WasmActivePointerV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordedActivation {
    pub command: ActivationCommandV1,
    pub event: RouteEventV1,
}

/// Kernel 激活状态（controlRevision CAS 的内存投影；7.5 起同时是持久化载体
/// 的应用分区形状——serde camelCase 与 wire 键集一致）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KernelActivationState {
    pub application_id: String,
    pub route_generation: u64,
    pub active: WasmActivePointerV1,
    pub events: Vec<RouteEventV1>,
    /// nonce -> 已消费 leaseDigest（consumed 只随成功提交写入）。
    pub nonce_ledger: BTreeMap<String, String>,
    /// nonce -> 原 activationId（already-consumed 按原始结果应答）。
    pub nonce_activation_index: BTreeMap<String, String>,
    /// activationId -> (命令, 事件)；query/replay 的 durable 记录。
    pub activation_records: BTreeMap<String, RecordedActivation>,
    /// rollback 保留记录（事件持久化的目标 binding）。
    pub rollback_retentions: Vec<RollbackRetentionRecord>,
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
    Activated(RouteEventV1),
    /// 拒绝事件（next == previous；generation 不变；nonce 不消费）。
    Rejected(RouteEventV1),
    /// nonce 已消费且 digest 相同：按 activationId 语义返回原始事件，
    /// 不产生第二个事件、不二次递增 generation。
    AlreadyConsumed(RouteEventV1),
}

fn candidate_identity(command: &ActivationCommandV1) -> Result<WasmVersionIdentity, ActivationError> {
    let (digest, sequence) = parse_wasm_version_id(&command.candidate.version_id).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/versionId: {}", e.detail)))?;
    Ok(WasmVersionIdentity { application_id: command.application_id.clone(), digest, sequence })
}

fn rejected_event(state: &KernelActivationState, command: &ActivationCommandV1, lease_nonce: &str, lease_digest: &str, reason: &'static str, now_epoch_millis: u64, event_id: &str) -> RouteEventV1 {
    RouteEventV1 {
        schema_version: 1,
        event_id: event_id.to_string(),
        activation_id: command.activation_id.clone(),
        application_id: command.application_id.clone(),
        runtime_kind: "wasm".into(),
        operation: command.operation,
        expected_route_generation: command.expected_route_generation,
        previous: state.active.clone(),
        next: state.active.clone(),
        lease_consume: LeaseConsumeRecordV1 {
            schema_version: 1,
            lease_nonce: lease_nonce.to_string(),
            lease_digest: lease_digest.to_string(),
            activation_id: command.activation_id.clone(),
            application_id: command.application_id.clone(),
            version_id: command.candidate.version_id.clone(),
            expected_route_generation: command.expected_route_generation,
            consumed_at_epoch_millis: now_epoch_millis,
            outcome: LeaseConsumeOutcome::Rejected,
            route_generation: state.route_generation,
        },
        result: RouteEventResult::Rejected,
        reason_code: Some(reason.to_string()),
        route_generation: state.route_generation,
        created_at_epoch_millis: now_epoch_millis,
    }
}

/// lease 与候选/registry 事实的全字段一致（任一错配 READINESS_LEASE_MISMATCH）。
fn correlate_readiness_lease(command: &ActivationCommandV1, lease: &ReadinessLeaseV2, registry: &RegistryRowFacts) -> Result<(), ActivationError> {
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
/// 2. 候选可激活性：registry 行存在且 binding 一致、lifecycle ready、候选存活、
///    secret revision == 当前 secret-store revision（2.3 fence）、
///    preparationGeneration == 当前 preparation（2.3 fence）、
///    rollback 目标保留记录一致（否则 ACTIVATION_CANDIDATE_NOT_READY）；
/// 3. binding 未被撤销（否则 ACTIVATION_BINDING_REVOKED）；
/// 4. lease 结构与 digest 复算 + 与候选/registry 全字段一致（否则 READINESS_LEASE_MISMATCH）；
/// 5. nonce 台账：异 digest → READINESS_LEASE_MISMATCH；同 digest → AlreadyConsumed
///    （nonce 判定先于过期：重放场景返回原始结果，而非新的过期错误）；
/// 6. 过期复查：now >= expiresAt（相等即过期）→ READINESS_LEASE_EXPIRED，nonce 不消费。
pub fn evaluate_activation_cas(
    state: &KernelActivationState,
    command: &ActivationCommandV1,
    lease: &ReadinessLeaseV2,
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
            event_id,
        )));
    }
    // 2. 候选可激活性（registry/存活/2.3 fence/rollback 保留）。
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
                event_id,
            )))
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
            event_id,
        )))
    };
    if registry.runtime_binding != candidate.runtime_binding || !registry.lifecycle_ready {
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
        match facts.rollback_retention {
            Some(retention) => {
                if retention.to_version_id != candidate.version_id || retention.target_runtime_binding != candidate.runtime_binding {
                    return candidate_not_ready();
                }
            }
            None => return candidate_not_ready(),
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
            event_id,
        )));
    }
    // 4. lease 结构 + correlate：任一失败都是 READINESS_LEASE_MISMATCH 的拒绝
    //    事件（spec：celld v1 lease、缺 nonce、跨 tuple nonce、config 耦合矛盾、
    //    与记录不一致的 payload 一律按此码拒绝，而非 envelope 错误）。
    if lease.validate().and_then(|()| correlate_readiness_lease(command, lease, registry)).is_err() {
        return Ok(ActivationCasDecision::Rejected(rejected_event(
            state,
            command,
            &lease.lease_nonce,
            &lease.lease_digest,
            READINESS_LEASE_MISMATCH,
            facts.now_epoch_millis,
            event_id,
        )));
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
                event_id,
            )));
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
            event_id,
        )));
    }
    // 激活：构造成功事件（consumed、generation+1）。
    let next_generation = command.expected_route_generation + 1;
    let next_pointer = WasmActivePointerV1::Active {
        runtime_kind: "wasm".into(),
        application_id: command.application_id.clone(),
        version_id: candidate.version_id.clone(),
        identity: candidate_identity(command)?,
        runtime_binding: candidate.runtime_binding.clone(),
        admission_proof_ref: candidate.admission_proof_ref.clone(),
        admission_proof_digest: candidate.admission_proof_digest.clone(),
        route_generation: next_generation,
    };
    let event = RouteEventV1 {
        schema_version: 1,
        event_id: event_id.to_string(),
        activation_id: command.activation_id.clone(),
        application_id: command.application_id.clone(),
        runtime_kind: "wasm".into(),
        operation: command.operation,
        expected_route_generation: command.expected_route_generation,
        previous: state.active.clone(),
        next: next_pointer,
        lease_consume: LeaseConsumeRecordV1 {
            schema_version: 1,
            lease_nonce: lease.lease_nonce.clone(),
            lease_digest: lease.lease_digest.clone(),
            activation_id: command.activation_id.clone(),
            application_id: command.application_id.clone(),
            version_id: candidate.version_id.clone(),
            expected_route_generation: command.expected_route_generation,
            consumed_at_epoch_millis: facts.now_epoch_millis,
            outcome: LeaseConsumeOutcome::Consumed,
            route_generation: next_generation,
        },
        result: RouteEventResult::Activated,
        reason_code: None,
        route_generation: next_generation,
        created_at_epoch_millis: facts.now_epoch_millis,
    };
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
fn activation_preamble(state: &KernelActivationState, command: &ActivationCommandV1) -> Result<Option<RouteEventV1>, ActivationError> {
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
/// - rollback 成功：追加 RollbackRetentionRecord（目标 binding 持久化）。
pub fn apply_activation(
    state: &mut KernelActivationState,
    command: &ActivationCommandV1,
    lease: &ReadinessLeaseV2,
    facts: &ActivationCasFacts<'_>,
    event_id: &str,
    crash: Option<ActivationCrashPoint>,
) -> Result<RouteEventV1, ActivationError> {
    check_uuid_v7(event_id, "eventId")?;
    if let Some(recorded_event) = activation_preamble(state, command)? {
        return Ok(recorded_event);
    }
    state.pending = Some(PendingActivationCas {
        command: command.clone(),
        lease: lease.clone(),
        event_id: event_id.to_string(),
        cas_now_epoch_millis: facts.now_epoch_millis,
        previous_pointer: state.active.clone(),
    });
    let decision = evaluate_activation_cas(state, command, lease, facts, event_id)?;
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
                state.rollback_retentions.push(RollbackRetentionRecord {
                    application_id: command.application_id.clone(),
                    from_version_id,
                    to_version_id: command.candidate.version_id.clone(),
                    target_runtime_binding: command.candidate.runtime_binding.clone(),
                    route_generation: event.route_generation,
                    created_at_epoch_millis: facts.now_epoch_millis,
                    owner_command_id: command.activation_id.clone(),
                });
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
    command: &ActivationCommandV1,
    now_epoch_millis: u64,
    event_id: &str,
) -> Result<RouteEventV1, ActivationError> {
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
        event_id,
    );
    state.events.push(event.clone());
    state.activation_records.insert(command.activation_id.clone(), RecordedActivation { command: command.clone(), event: event.clone() });
    Ok(event)
}

/// query：activationId 的 durable 结果（None = missing；received 未单独建模，
/// pending 意图即"received 未完成"）。
pub fn query_activation<'a>(state: &'a KernelActivationState, activation_id: &str) -> Option<&'a RouteEventV1> {
    find_recorded(state, activation_id).map(|recorded| &recorded.event)
}

/// replay：仅接受字节等价（此处以命令结构等价建模）的重放；返回原始事件，
/// 不二次消费 nonce、不二次递增 route generation。
pub fn replay_activation(state: &KernelActivationState, command: &ActivationCommandV1) -> Result<RouteEventV1, ActivationError> {
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
    /// 指针已翻但事件缺失：从 pending 意图重建精确事件并落记录。
    /// 事件体盒装：低频控制面返回值，多数变体无载荷，不必内联 992+ 字节。
    RepairedEventFromPointerCas(Box<RouteEventV1>),
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
        if &recorded.event.lease_consume.lease_nonce != nonce || !state.nonce_ledger.contains_key(nonce) {
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
            state.rollback_retentions.push(RollbackRetentionRecord {
                application_id: pending.command.application_id.clone(),
                from_version_id,
                to_version_id: pending.command.candidate.version_id.clone(),
                target_runtime_binding: pending.command.candidate.runtime_binding.clone(),
                route_generation: event.route_generation,
                created_at_epoch_millis: pending.cas_now_epoch_millis,
                owner_command_id: pending.command.activation_id.clone(),
            });
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
    if state.nonce_ledger.get(&pending.lease.lease_nonce) == Some(&pending.lease.lease_digest)
        && state.nonce_activation_index.get(&pending.lease.lease_nonce) == Some(&pending.command.activation_id)
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

fn rebuild_activated_event_from_pending(pending: &PendingActivationCas) -> Result<RouteEventV1, ActivationError> {
    let candidate = &pending.command.candidate;
    let next_generation = pending.command.expected_route_generation + 1;
    let next_pointer = WasmActivePointerV1::Active {
        runtime_kind: "wasm".into(),
        application_id: pending.command.application_id.clone(),
        version_id: candidate.version_id.clone(),
        identity: candidate_identity(&pending.command)?,
        runtime_binding: candidate.runtime_binding.clone(),
        admission_proof_ref: candidate.admission_proof_ref.clone(),
        admission_proof_digest: candidate.admission_proof_digest.clone(),
        route_generation: next_generation,
    };
    Ok(RouteEventV1 {
        schema_version: 1,
        event_id: pending.event_id.clone(),
        activation_id: pending.command.activation_id.clone(),
        application_id: pending.command.application_id.clone(),
        runtime_kind: "wasm".into(),
        operation: pending.command.operation,
        expected_route_generation: pending.command.expected_route_generation,
        previous: pending.previous_pointer.clone(),
        next: next_pointer,
        lease_consume: LeaseConsumeRecordV1 {
            schema_version: 1,
            lease_nonce: pending.lease.lease_nonce.clone(),
            lease_digest: pending.lease.lease_digest.clone(),
            activation_id: pending.command.activation_id.clone(),
            application_id: pending.command.application_id.clone(),
            version_id: candidate.version_id.clone(),
            expected_route_generation: pending.command.expected_route_generation,
            consumed_at_epoch_millis: pending.cas_now_epoch_millis,
            outcome: LeaseConsumeOutcome::Consumed,
            route_generation: next_generation,
        },
        result: RouteEventResult::Activated,
        reason_code: None,
        route_generation: next_generation,
        created_at_epoch_millis: pending.cas_now_epoch_millis,
    })
}

// ---------------------------------------------------------------------------
// 任务 7.5：iweb-wasm-activation-v1 传输接线（envelope / 存储 / 端点）
// ---------------------------------------------------------------------------

pub const ACTIVATION_RPC_PROTOCOL_LITERAL: &str = "iweb-wasm-activation-v1";
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
// wire 记录：时间戳为 RFC3339-UTC 原串（digest/JCS 字节保真），与纯函数层的
// epoch 毫秒投影互转
// ---------------------------------------------------------------------------

/// ActivationCommandV1 的 wire 形状（requestedAt 为 RFC3339-UTC；无 kind 成员）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireActivationCommandV1 {
    pub schema_version: u64,
    pub activation_id: String,
    pub application_id: String,
    pub operation: ActivationOperation,
    pub expected_route_generation: u64,
    pub candidate: ActivationCandidateV1,
    pub requested_at: String,
}

impl WireActivationCommandV1 {
    pub fn to_pure(&self) -> Result<ActivationCommandV1, ActivationError> {
        let requested_at_epoch_millis = parse_rfc3339_utc_millis(&self.requested_at)
            .map_err(|e| err(WASM_ACTIVATION_INVALID, format!("/requestedAt: {}", e.detail)))?;
        Ok(ActivationCommandV1 {
            schema_version: self.schema_version,
            activation_id: self.activation_id.clone(),
            application_id: self.application_id.clone(),
            operation: self.operation,
            expected_route_generation: self.expected_route_generation,
            candidate: self.candidate.clone(),
            requested_at_epoch_millis,
        })
    }

    pub fn from_pure(command: &ActivationCommandV1) -> Result<Self, ActivationError> {
        Ok(Self {
            schema_version: command.schema_version,
            activation_id: command.activation_id.clone(),
            application_id: command.application_id.clone(),
            operation: command.operation,
            expected_route_generation: command.expected_route_generation,
            candidate: command.candidate.clone(),
            requested_at: format_rfc3339_utc_millis(command.requested_at_epoch_millis),
        })
    }
}

/// LeaseConsumeRecordV1 的 wire 形状（consumedAt RFC3339）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireLeaseConsumeRecordV1 {
    pub schema_version: u64,
    pub lease_nonce: String,
    pub lease_digest: String,
    pub activation_id: String,
    pub application_id: String,
    pub version_id: String,
    pub expected_route_generation: u64,
    pub consumed_at: String,
    pub outcome: LeaseConsumeOutcome,
    pub route_generation: u64,
}

impl WireLeaseConsumeRecordV1 {
    pub fn from_pure(record: &LeaseConsumeRecordV1) -> Result<Self, ActivationError> {
        Ok(Self {
            schema_version: record.schema_version,
            lease_nonce: record.lease_nonce.clone(),
            lease_digest: record.lease_digest.clone(),
            activation_id: record.activation_id.clone(),
            application_id: record.application_id.clone(),
            version_id: record.version_id.clone(),
            expected_route_generation: record.expected_route_generation,
            consumed_at: format_rfc3339_utc_millis(record.consumed_at_epoch_millis),
            outcome: record.outcome,
            route_generation: record.route_generation,
        })
    }
}

/// RouteEventV1 的 wire 形状（createdAt RFC3339）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireRouteEventV1 {
    pub schema_version: u64,
    pub event_id: String,
    pub activation_id: String,
    pub application_id: String,
    pub runtime_kind: String,
    pub operation: ActivationOperation,
    pub expected_route_generation: u64,
    pub previous: WasmActivePointerV1,
    pub next: WasmActivePointerV1,
    pub lease_consume: WireLeaseConsumeRecordV1,
    pub result: RouteEventResult,
    pub reason_code: Option<String>,
    pub route_generation: u64,
    pub created_at: String,
}

impl WireRouteEventV1 {
    pub fn from_pure(event: &RouteEventV1) -> Result<Self, ActivationError> {
        Ok(Self {
            schema_version: event.schema_version,
            event_id: event.event_id.clone(),
            activation_id: event.activation_id.clone(),
            application_id: event.application_id.clone(),
            runtime_kind: event.runtime_kind.clone(),
            operation: event.operation,
            expected_route_generation: event.expected_route_generation,
            previous: event.previous.clone(),
            next: event.next.clone(),
            lease_consume: WireLeaseConsumeRecordV1::from_pure(&event.lease_consume)?,
            result: event.result,
            reason_code: event.reason_code.clone(),
            route_generation: event.route_generation,
            created_at: format_rfc3339_utc_millis(event.created_at_epoch_millis),
        })
    }
}

// ---------------------------------------------------------------------------
// envelope：{protocol, requestId, body: command | query | replay}
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ActivationRpcRequestBodyV1 {
    /// ActivationCommandV1 精确键集，无 kind 成员（spec 未给命令体 kind 标签；
    /// fail-closed：携带 kind 的命令体按未知字段拒绝，见文末歧义备注）。
    Command(WireActivationCommandV1),
    Query { activation_id: String },
    Replay(WireActivationCommandV1),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActivationRpcRequestEnvelopeV1 {
    pub protocol: String,
    pub request_id: String,
    pub body: ActivationRpcRequestBodyV1,
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

fn parse_wire_command(value: &serde_json::Value) -> Result<WireActivationCommandV1, ActivationError> {
    serde_json::from_value(value.clone()).map_err(|e| err(WASM_ACTIVATION_INVALID, format!("activation command body is invalid: {e}")))
}

/// spec：raw body 是 JCS ActivationRpcEnvelopeV1——字节必须等于 JCS(parse(bytes))，
/// 重复键/白空格/键序偏差与浮点数（u53 域外）一律在解析层拒绝。
pub fn parse_activation_rpc_envelope(bytes: &[u8]) -> Result<ActivationRpcRequestEnvelopeV1, ActivationError> {
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
        return Err(err(ACTIVATION_RPC_ENVELOPE_INVALID, "protocol must be exactly \"iweb-wasm-activation-v1\""));
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
                ActivationRpcRequestBodyV1::Query { activation_id }
            }
            "replay" => {
                ensure_exact_keys(body, &["kind", "command"])?;
                ActivationRpcRequestBodyV1::Replay(parse_wire_command(&body["command"])?)
            }
            _ => {
                return Err(err(
                    ACTIVATION_RPC_ENVELOPE_INVALID,
                    "kind must be \"query\" or \"replay\"; the ActivationCommandV1 body carries no kind member",
                ))
            }
        }
    } else {
        ActivationRpcRequestBodyV1::Command(parse_wire_command(&envelope["body"])?)
    };
    Ok(ActivationRpcRequestEnvelopeV1 { protocol: ACTIVATION_RPC_PROTOCOL_LITERAL.into(), request_id, body: parsed_body })
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
    pub event: Option<WireRouteEventV1>,
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
    pub fn commit_activation(
        &mut self,
        command: &WireActivationCommandV1,
        lease: &ReadinessLeaseV2,
        facts: &OwnedActivationCasFacts,
        event_id: &str,
        crash: Option<ActivationCrashPoint>,
    ) -> Result<RouteEventV1, ActivationError> {
        let pure = command.to_pure()?;
        let mut file = self.load()?;
        if Self::recover_file(&mut file)? {
            self.persist(&file)?;
        }
        let application_id = pure.application_id.clone();
        let mut state = match file.applications.get(&application_id) {
            Some(state) => state.clone(),
            None => KernelActivationState::new(&application_id)?,
        };
        let before = state.clone();
        let facts_ref = facts.as_facts();
        match apply_activation(&mut state, &pure, lease, &facts_ref, event_id, crash) {
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
    /// 同一 CAS 纪律提交（事件追加即 mutation，恰 +1；幂等重放零写入）。
    pub fn commit_missing_lease_rejection(
        &mut self,
        command: &WireActivationCommandV1,
        now_epoch_millis: u64,
        event_id: &str,
    ) -> Result<RouteEventV1, ActivationError> {
        let pure = command.to_pure()?;
        let mut file = self.load()?;
        if Self::recover_file(&mut file)? {
            self.persist(&file)?;
        }
        let application_id = pure.application_id.clone();
        let mut state = match file.applications.get(&application_id) {
            Some(state) => state.clone(),
            None => KernelActivationState::new(&application_id)?,
        };
        let before = state.clone();
        let event = apply_activation_without_lease(&mut state, &pure, now_epoch_millis, event_id)?;
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
    pub fn recorded_activation(&self, activation_id: &str) -> Result<Option<(ActivationCommandV1, RouteEventV1)>, ActivationError> {
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

/// CAS 判据的自有版本（宿主回调提供；借用视图给纯函数层）。
#[derive(Debug, Clone, PartialEq)]
pub struct OwnedActivationCasFacts {
    pub now_epoch_millis: u64,
    pub current_secret_store_revision: u64,
    pub current_preparation_generation: u64,
    pub candidate_alive: bool,
    pub registry_row: Option<RegistryRowFacts>,
    pub binding_revoked: bool,
    pub rollback_retention: Option<RollbackRetentionRecord>,
}

impl OwnedActivationCasFacts {
    pub fn as_facts(&self) -> ActivationCasFacts<'_> {
        ActivationCasFacts {
            now_epoch_millis: self.now_epoch_millis,
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
    pub lease_lookup: &'a dyn Fn(&str) -> Option<ReadinessLeaseV2>,
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

fn result_body(activation_id: &str, event: &RouteEventV1) -> Result<ActivationResultBodyV1, ActivationHttpFailure> {
    let status = match event.result {
        RouteEventResult::Activated => ActivationStatus::Activated,
        RouteEventResult::Rejected => ActivationStatus::Rejected,
    };
    let wire_event = WireRouteEventV1::from_pure(event).map_err(activation_failure)?;
    Ok(ActivationResultBodyV1 { activation_id: activation_id.to_string(), status, event: Some(wire_event) })
}

fn submit_command(
    store: &mut WasmActivationStore,
    command: &WireActivationCommandV1,
    deps: &ActivationDeps<'_>,
) -> Result<ActivationResultBodyV1, ActivationHttpFailure> {
    let event_id = (deps.event_id)();
    let event = match (deps.lease_lookup)(&command.candidate.lease_nonce) {
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
    envelope: &ActivationRpcRequestEnvelopeV1,
    deps: &ActivationDeps<'_>,
) -> Result<ActivationRpcResponseEnvelopeV1, ActivationHttpFailure> {
    let body = match &envelope.body {
        ActivationRpcRequestBodyV1::Command(command) => return Ok(ActivationRpcResponseEnvelopeV1 {
            request_id: envelope.request_id.clone(),
            body: submit_command(store, command, deps)?,
        }),
        ActivationRpcRequestBodyV1::Query { activation_id } => {
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
        ActivationRpcRequestBodyV1::Replay(command) => match store.recorded_activation(&command.activation_id).map_err(activation_failure)? {
            Some((recorded_command, event)) => {
                let pure = command.to_pure().map_err(activation_failure)?;
                if recorded_command != pure {
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

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "shop";
    const VERSION_ID: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1";
    const ROLLBACK_VERSION_ID: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1";
    const LEASE_NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const SEED_NONCE: &str = "99999999999999999999999999999999";
    const GOLDEN_LEASE_DIGEST: &str = "858b284bdcac15f6d131bea4797299741d91a6783c39da75bd105783f6e0cf6e";
    /// 基准时刻：lease 签发于 1_800_000_000_000，默认 60s 窗口。
    const CAS_NOW: u64 = 1_800_000_000_000;
    const SECRET_REVISION: u64 = 3;
    /// 新候选的 preparation/execution 代次（seed 激活用 1，新准备推进到 2）。
    const GENERATION: u64 = 2;

    fn binding() -> RuntimeBindingIdentityV1 {
        RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: "iweb-wasmd-abi@1.0.0".into(),
            world: "wasi:http/proxy@0.2.8".into(),
        }
    }

    /// packages/contracts/wasm-health.ts exampleReadinessLeaseV2 的跨语言 golden。
    fn vector_lease() -> ReadinessLeaseV2 {
        ReadinessLeaseV2 {
            schema_version: 2,
            lease_nonce: LEASE_NONCE.into(),
            sandbox_id: "sbx-vector".into(),
            version_id: VERSION_ID.into(),
            package_digest: "0".repeat(64),
            runtime_binding: binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            secret_revision: 3,
            secret_values_digest: "6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some("7".repeat(64)),
            config_values_digest: Some("8".repeat(64)),
            preparation_generation: 1,
            execution_generation: 1,
            issued_at: "2026-08-26T00:00:00Z".into(),
            expires_at: "2026-08-26T00:10:00Z".into(),
            lease_digest: GOLDEN_LEASE_DIGEST.into(),
        }
    }

    fn lease_for(candidate: &ActivationCandidateV1, window_millis: u64) -> ReadinessLeaseV2 {
        let issued = CAS_NOW;
        let base = ReadinessLeaseV2 {
            schema_version: 2,
            lease_nonce: candidate.lease_nonce.clone(),
            sandbox_id: candidate.sandbox_id.clone(),
            version_id: candidate.version_id.clone(),
            package_digest: candidate.package_digest.clone(),
            runtime_binding: candidate.runtime_binding.clone(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
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
        let digest = compute_readiness_lease_digest(&base).expect("lease digest");
        ReadinessLeaseV2 { lease_digest: digest, ..base }
    }

    fn make_candidate(version_id: &str, nonce: &str, secret_revision: u64, generation: u64) -> ActivationCandidateV1 {
        let probe = ActivationCandidateV1 {
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
        ActivationCandidateV1 { lease_digest: lease.lease_digest, ..probe }
    }

    fn make_command(activation_id: &str, candidate: ActivationCandidateV1, expected: u64) -> ActivationCommandV1 {
        ActivationCommandV1 {
            schema_version: 1,
            activation_id: activation_id.into(),
            application_id: APP.into(),
            operation: ActivationOperation::Activate,
            expected_route_generation: expected,
            candidate,
            requested_at_epoch_millis: CAS_NOW,
        }
    }

    fn registry_row() -> RegistryRowFacts {
        RegistryRowFacts { runtime_binding: binding(), capability_record_revision: 5, capability_record_hash: "2".repeat(64), lifecycle_ready: true }
    }

    fn retention_for(to_version_id: &str, target_binding: RuntimeBindingIdentityV1) -> RollbackRetentionRecord {
        RollbackRetentionRecord {
            application_id: APP.into(),
            from_version_id: format!("admission-proof/{APP}/").len().to_string(),
            to_version_id: to_version_id.into(),
            target_runtime_binding: target_binding,
            route_generation: 1,
            created_at_epoch_millis: CAS_NOW,
            owner_command_id: "01892555-0000-7000-8000-0000000000fe".into(),
        }
    }

    fn make_facts<'a>(now: u64, secret_revision: u64, generation: u64, registry: Option<&'a RegistryRowFacts>) -> ActivationCasFacts<'a> {
        ActivationCasFacts {
            now_epoch_millis: now,
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
        assert_eq!(compute_readiness_lease_digest(&lease).unwrap(), GOLDEN_LEASE_DIGEST);
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
        assert_eq!(state.route_generation, 2);
        assert!(state.nonce_ledger.contains_key(LEASE_NONCE));
        assert!(matches!(&state.active, WasmActivePointerV1::Active { version_id, .. } if version_id == VERSION_ID));
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
        // 无保留记录 → NOT_READY（fail-closed）。
        let facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        let event = apply_activation(&mut state, &no_retention, &lease, &facts, "01892555-0000-7000-8000-00000000e0f1", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        // 保留记录 binding 与候选不一致 → NOT_READY（独立 activationId）。
        let mut mismatched_binding = binding();
        mismatched_binding.catalog_revision = 77;
        let mismatched = retention_for(ROLLBACK_VERSION_ID, mismatched_binding);
        let mut mismatched_command = make_command("01892555-0000-7000-8000-000000000013", candidate.clone(), 1);
        mismatched_command.operation = ActivationOperation::Rollback;
        let mut facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        facts.rollback_retention = Some(&mismatched);
        let event = apply_activation(&mut state, &mismatched_command, &lease, &facts, "01892555-0000-7000-8000-00000000e0f2", None).expect("rejected event");
        assert_eq!(event.reason_code.as_deref(), Some(ACTIVATION_CANDIDATE_NOT_READY));
        // 一致的保留记录 → 同一 gate 放行，事件持久化目标 binding。
        let retention = retention_for(ROLLBACK_VERSION_ID, binding());
        let mut rollback_command = make_command("01892555-0000-7000-8000-000000000014", candidate, 1);
        rollback_command.operation = ActivationOperation::Rollback;
        let mut facts = make_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(&row));
        facts.rollback_retention = Some(&retention);
        let event = apply_activation(&mut state, &rollback_command, &lease, &facts, "01892555-0000-7000-8000-00000000e0f3", None).expect("rollback activation");
        assert_eq!(event.result, RouteEventResult::Activated);
        assert_eq!(event.operation, ActivationOperation::Rollback);
        let persisted = state.rollback_retentions.last().expect("rollback retention persisted");
        assert_eq!(persisted.to_version_id, ROLLBACK_VERSION_ID);
        assert_eq!(persisted.target_runtime_binding, binding());
        assert_eq!(persisted.route_generation, 2);
        assert_eq!(persisted.owner_command_id, rollback_command.activation_id);
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
        leases: BTreeMap<String, ReadinessLeaseV2>,
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

        fn commit(&mut self, command: &ActivationCommandV1, crash: Option<ActivationCrashPoint>) -> Result<RouteEventV1, ActivationError> {
            let wire = WireActivationCommandV1::from_pure(command)?;
            let lease = self.leases.get(&command.candidate.lease_nonce).expect("lease registered");
            let facts = self.facts.get(&command.application_id).expect("facts registered").clone();
            let event_id = self.next_event_id();
            self.store.commit_activation(&wire, lease, &facts, &event_id, crash)
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

    fn command_envelope_body(command: &ActivationCommandV1) -> serde_json::Value {
        serde_json::json!({
            "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
            "requestId": "01892555-0000-7000-8000-0000000000e0",
            "body": serde_json::to_value(WireActivationCommandV1::from_pure(command).expect("wire command")).expect("command serializes"),
        })
    }

    fn command_envelope_bytes(command: &ActivationCommandV1) -> Vec<u8> {
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

    fn replay_envelope_bytes(command: &ActivationCommandV1) -> Vec<u8> {
        jcs_bytes(&serde_json::json!({
            "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
            "requestId": "01892555-0000-7000-8000-0000000000e2",
            "body": { "kind": "replay", "command": serde_json::to_value(WireActivationCommandV1::from_pure(command).expect("wire command")).expect("command serializes") },
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
            ActivationRpcRequestBodyV1::Command(wire) => assert_eq!(wire.to_pure().unwrap(), command),
            other => panic!("expected command body, got {other:?}"),
        }
        // query / replay 形状。
        let query = parse_activation_rpc_envelope(&query_envelope_bytes(&command.activation_id)).expect("query parses");
        assert_eq!(query.body, ActivationRpcRequestBodyV1::Query { activation_id: command.activation_id.clone() });
        let replay = parse_activation_rpc_envelope(&replay_envelope_bytes(&command)).expect("replay parses");
        assert!(matches!(replay.body, ActivationRpcRequestBodyV1::Replay(_)));
        // 非 JCS 字节（键序/白空格）拒绝。
        let non_canonical = String::from_utf8(command_envelope_bytes(&command)).unwrap().replacen("\"protocol\"", "  \"protocol\"", 1);
        assert_eq!(parse_activation_rpc_envelope(non_canonical.as_bytes()).unwrap_err().code, ACTIVATION_RPC_ENVELOPE_INVALID);
        // 浮点（u53 域外）：canonical 化即失败——传输层不可能为浮点 body 产出
        // 合法 JCS 字节，等价于解析层拒绝。
        let mut float_body = command_envelope_body(&command);
        float_body["body"]["expectedRouteGeneration"] = serde_json::json!(1.5);
        assert!(jcs_bytes(&float_body).is_err());
        // 协议字面量错误。
        let mut wrong_protocol = command_envelope_body(&command);
        wrong_protocol["protocol"] = serde_json::json!("iweb-execution-rpc-v1");
        let wrong_bytes = jcs_bytes(&wrong_protocol).expect("canonical");
        assert_eq!(parse_activation_rpc_envelope(&wrong_bytes).unwrap_err().code, ACTIVATION_RPC_ENVELOPE_INVALID);
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
    fn rollback_envelope_persists_target_binding_and_duplicate_never_increments() {
        let mut world = TestWorld::new();
        world.seed();
        let candidate = make_candidate(ROLLBACK_VERSION_ID, LEASE_NONCE, SECRET_REVISION, GENERATION);
        world.leases.insert(LEASE_NONCE.into(), lease_for(&candidate, 60_000));
        let mut facts = owned_facts(CAS_NOW, SECRET_REVISION, GENERATION, Some(registry_row()));
        facts.rollback_retention = Some(retention_for(ROLLBACK_VERSION_ID, binding()));
        world.facts.insert(APP.into(), facts);
        let mut command = make_command("01892555-0000-7000-8000-000000000150", candidate, 1);
        command.operation = ActivationOperation::Rollback;
        let response = world.post(command_envelope_bytes(&command));
        assert_eq!(parse_response(&response)["body"]["status"], "activated");
        let state = world.store.application_state(APP).unwrap().expect("state");
        let persisted = state.rollback_retentions.last().expect("rollback retention persisted");
        assert_eq!(persisted.to_version_id, ROLLBACK_VERSION_ID);
        assert_eq!(persisted.target_runtime_binding, binding());
        assert_eq!(persisted.owner_command_id, command.activation_id);
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
        // wire↔pure round-trip（requestedAt RFC3339 ↔ epoch 毫秒）。
        let wire = WireActivationCommandV1::from_pure(&command).unwrap();
        assert_eq!(wire.to_pure().unwrap(), command);
        assert_eq!(wire.requested_at, format_rfc3339_utc_millis(command.requested_at_epoch_millis));
    }
}
