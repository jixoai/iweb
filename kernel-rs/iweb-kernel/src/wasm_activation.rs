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
    parse_rfc3339_utc_millis, parse_wasm_version_id, validate_runtime_binding, RuntimeBindingIdentityV1,
    WasmActivePointerV1, WasmVersionIdentity, WASM_U53_MAX,
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
#[derive(Debug, Clone, PartialEq)]
pub struct PendingActivationCas {
    pub command: ActivationCommandV1,
    pub lease: ReadinessLeaseV2,
    pub event_id: String,
    pub cas_now_epoch_millis: u64,
    /// 意图写入时的 active 指针（= 事件的 previous）。
    pub previous_pointer: WasmActivePointerV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordedActivation {
    pub command: ActivationCommandV1,
    pub event: RouteEventV1,
}

/// Kernel 激活状态（controlRevision CAS 的内存投影）。
#[derive(Debug, Clone, PartialEq)]
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

fn rejected_event(state: &KernelActivationState, command: &ActivationCommandV1, lease: &ReadinessLeaseV2, reason: &'static str, now_epoch_millis: u64, event_id: &str) -> RouteEventV1 {
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
            lease_nonce: lease.lease_nonce.clone(),
            lease_digest: lease.lease_digest.clone(),
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
            lease,
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
                lease,
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
            lease,
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
            lease,
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
            lease,
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
                lease,
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
            lease,
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
    command.validate()?;
    check_uuid_v7(event_id, "eventId")?;
    if state.pending.is_some() {
        return Err(err(WASM_ACTIVATION_REPAIR_REQUIRED, "an uncertain activation must be repaired before a new activation is accepted"));
    }
    if let Some(recorded) = find_recorded(state, &command.activation_id) {
        if &recorded.command == command {
            return Ok(recorded.event.clone());
        }
        return Err(err(ACTIVATION_ID_CONFLICT, "a known activationId with a different command returns ACTIVATION_ID_CONFLICT and never creates a route event"));
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
// tests：lease digest 跨语言 golden、CAS 门全场景、恢复、rollback binding 持久化
// ---------------------------------------------------------------------------

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
}
