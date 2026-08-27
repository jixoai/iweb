//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 7.2 Kernel 侧）：按 runtime kind
//! 隔离 Kernel 业务记录——严格 per-kind `WasmKernelRouteRegistryV1`、全局 kind-claim
//! CAS 索引、带 source/target application ID 的 `MigrationRecordV1`/receipt、以及升级
//! 节点的 `KindClaimBootstrapV1` 一次性 celld 引导。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/application-sandbox/spec.md
//! "Kernel business records are isolated by runtime kind"（含 bootstrap 段与全部场景）
//! 及 wasm-application-runtime/spec.md 的 MigrationRecordV1/MigrationReceiptV1 精确形状。
//! wire 权威：packages/contracts/wasm-execution.ts（binding/bootstrap digest 公式与
//! 校验器），Rust 侧字节一致复算；行/指针/proof 形状复用 wasm_admission.rs。
//!
//! 正交意图：
//! 1. digest 纯函数（kind binding digest、bootstrap completion receipt digest）——
//!    与 TS 向量 golden 对齐（测试内再配独立 preimage oracle 双保险）；
//! 2. 全局 kind-claim CAS（applicationId 终身绑定一个 runtime kind；先取全局 claim
//!    CAS 再写 kind-specific registry，绝不反序；APPLICATION_RUNTIME_KIND_CONFLICT /
//!    APPLICATION_KIND_SPLIT_BRAIN fail-closed）；
//! 3. KindClaimBootstrapV1（现行 celld ControlStateFile 无 controlRevision，故
//!    sourceRevision:0；controlStateRawDigest 变化强制重推导；崩溃幂等重放；验证
//!    通过前 wasm 写路径以 WASM_KIND_BOOTSTRAP_PENDING 关闭）；
//! 4. MigrationRecordV1/MigrationReceiptV1（跨 kind 必须换 applicationId、source
//!    digest/revision 绑定、幂等 replay 返回原 receipt、失败 target quarantine 且
//!    active 指针不变）。
//!
//! 接线备注（本文件不改 lib.rs，由编排者注册）：在 lib.rs 的 `pub mod wasm_admission;`
//! 之后追加一行 `pub mod wasm_kind_registry;`。启动序契约：先
//! `bootstrap_from_celld_raw`（或 bootstrap_from_celld）完成/验证引导，再开放 wasm
//! 写路径与 `recover`；celld 控制态每次变更后调用 `celld_control_state_changed`
//! 失效旧验证（digest 不匹配即重新关闭 wasm 写路径）。

use crate::wasm_admission::{
    format_rfc3339_utc_millis, jcs_bytes, verify_admission_proof, AdmissionError, AdmissionProofV1,
    WasmKernelRouteRegistry, WASM_U53_MAX, WasmVersionRegistryRow,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误码（spec 已命名码优先；补充码沿用 contracts 命名风格）
// ---------------------------------------------------------------------------

pub const KIND_CLAIM_BINDING_DIGEST_DOMAIN: &str = "iweb-application-kind-binding-v1";
pub const KIND_CLAIM_BOOTSTRAP_DIGEST_DOMAIN: &str = "iweb-kind-claim-bootstrap-v1";

pub const RUNTIME_KIND_CELLD: &str = "celld";
pub const RUNTIME_KIND_WASM: &str = "wasm";

// spec 已命名的稳定码。
pub const APPLICATION_RUNTIME_KIND_CONFLICT: &str = "APPLICATION_RUNTIME_KIND_CONFLICT";
pub const APPLICATION_KIND_SPLIT_BRAIN: &str = "APPLICATION_KIND_SPLIT_BRAIN";
pub const WASM_KIND_BOOTSTRAP_PENDING: &str = "WASM_KIND_BOOTSTRAP_PENDING";
pub const WASM_BUSINESS_RECORD_MISSING: &str = "WASM_BUSINESS_RECORD_MISSING";
pub const MIGRATION_SOURCE_CONFLICT: &str = "MIGRATION_SOURCE_CONFLICT";

// contracts 已命名的补充码（TS KIND_CLAIM_CODE 与两个 digest mismatch 码）。
pub const WASM_KIND_CLAIM_INVALID: &str = "WASM_KIND_CLAIM_INVALID";
pub const KIND_CLAIM_BINDING_DIGEST_MISMATCH: &str = "KIND_CLAIM_BINDING_DIGEST_MISMATCH";
pub const KIND_CLAIM_DIGEST_MISMATCH: &str = "KIND_CLAIM_DIGEST_MISMATCH";

// spec 未命名的补充 fail-closed 码（不覆盖 spec 已命名码）。
pub const KIND_REGISTRY_REVISION_CONFLICT: &str = "KIND_REGISTRY_REVISION_CONFLICT";
pub const KIND_REGISTRY_STORE_IO: &str = "KIND_REGISTRY_STORE_IO";
pub const MIGRATION_RECORD_INVALID: &str = "MIGRATION_RECORD_INVALID";
pub const MIGRATION_CROSS_KIND_IDENTITY_INVALID: &str = "MIGRATION_CROSS_KIND_IDENTITY_INVALID";
pub const MIGRATION_TARGET_INVALID: &str = "MIGRATION_TARGET_INVALID";
pub const MIGRATION_TARGET_WRITE_FAILED: &str = "MIGRATION_TARGET_WRITE_FAILED";
pub const MIGRATION_TARGET_DIGEST_MISMATCH: &str = "MIGRATION_TARGET_DIGEST_MISMATCH";
pub const MIGRATION_TERMINAL_ROLLED_BACK: &str = "MIGRATION_TERMINAL_ROLLED_BACK";

// MigrationRecordV1 的固定字面量（spec 精确形状）：celld 源与 wasm 目标各只有一条
// 合法路径；本实现不接受任何其它 path/kind 组合。
const MIGRATION_SOURCE_KIND: &str = "celld";
const MIGRATION_TARGET_KIND: &str = "wasm";
pub const MIGRATION_SOURCE_PATH: &str = "/data/kernel/control-db.json";
pub const MIGRATION_TARGET_PATH: &str = "/data/kernel/wasm-control-state-v2.json";

/// 结构化错误：code 为稳定 owner 可见码，detail 携带路径/上下文，不含秘密。
#[derive(Debug, Clone, PartialEq)]
pub struct KindRegistryError {
    pub code: &'static str,
    pub detail: String,
}

impl KindRegistryError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for KindRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for KindRegistryError {}

/// wasm_admission 侧错误的透传映射（code 原样保留，保持稳定码语义）。
fn aerr(error: AdmissionError) -> KindRegistryError {
    KindRegistryError { code: error.code, detail: error.detail }
}

fn err(code: &'static str, detail: impl Into<String>) -> KindRegistryError {
    KindRegistryError::new(code, detail)
}

fn kind_regexes() -> &'static KindRegexes {
    static REGEXES: OnceLock<KindRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| KindRegexes {
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        uuid_v7: regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").expect("uuid v7 regex"),
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
    })
}

struct KindRegexes {
    sha256_hex: regex::Regex,
    uuid_v7: regex::Regex,
    application_id: regex::Regex,
}

/// applicationId 文法（与 contracts WASM_APPLICATION_ID_PATTERN / wasm_admission 同款；
/// 那边的校验器是模块私有，这里独立设防避免改动共享文件）。
fn validate_kind_application_id(value: &str) -> Result<(), KindRegistryError> {
    if kind_regexes().application_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_KIND_CLAIM_INVALID, format!("applicationId must match ^[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?$: {value}")))
    }
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<(), KindRegistryError> {
    if kind_regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_KIND_CLAIM_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

fn validate_uuid_v7(value: &str, field: &str) -> Result<(), KindRegistryError> {
    if kind_regexes().uuid_v7.is_match(value) {
        Ok(())
    } else {
        Err(err(MIGRATION_RECORD_INVALID, format!("{field} must be a lower-case UUIDv7")))
    }
}

fn require_u53(value: u64, minimum: u64, field: &str) -> Result<(), KindRegistryError> {
    if value >= minimum && value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(WASM_KIND_CLAIM_INVALID, format!("{field} must be an integer between {minimum} and the u53 maximum")))
    }
}

fn require_rfc3339_utc(value: &str, field: &str, code: &'static str) -> Result<(), KindRegistryError> {
    crate::wasm_admission::parse_rfc3339_utc_millis(value)
        .map(|_| ())
        .map_err(|e| err(code, format!("{field} must be an RFC3339 UTC timestamp: {}", e.detail)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn domain_digest(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// 从原始字节解析 typed 记录：serde derive 自带 duplicate-member 检测 +
/// deny_unknown_fields 精确键集；原始字节必须等于 JCS(解析值)（对位 TS
/// parseStrictJson + jcsCanonicalBytes 比对，不接受"解析后等价"）。
fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8], code: &'static str, noun: &str) -> Result<T, KindRegistryError> {
    let parsed: T = serde_json::from_slice(bytes).map_err(|e| err(code, format!("{noun} bytes do not parse as the typed record: {e}")))?;
    let canonical = jcs_bytes(&parsed).map_err(aerr)?;
    if canonical != bytes {
        return Err(err(code, format!("{noun} bytes must equal JCS(parse(bytes))")));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// digest 纯函数（逐字对照 contracts wasm-execution.ts；域前缀 + 单次 SHA-256）
// ---------------------------------------------------------------------------

/// binding digest 的 JCS preimage：{schemaVersion:1, applicationId, runtimeKind,
/// bindingRevision}（camelCase 键；BTreeMap 序即 RFC 8785 序）。
#[derive(Serialize)]
struct BindingDigestPreimage {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "applicationId")]
    application_id: String,
    #[serde(rename = "runtimeKind")]
    runtime_kind: String,
    #[serde(rename = "bindingRevision")]
    binding_revision: u64,
}

/// bindingDigest = hex(SHA-256(UTF8("iweb-application-kind-binding-v1\n" ||
///   JCS({schemaVersion:1, applicationId, runtimeKind, bindingRevision})))。
pub fn kind_binding_digest(application_id: &str, runtime_kind: &str, binding_revision: u64) -> Result<String, KindRegistryError> {
    let preimage = BindingDigestPreimage {
        schema_version: 1,
        application_id: application_id.to_string(),
        runtime_kind: runtime_kind.to_string(),
        binding_revision,
    };
    let bytes = jcs_bytes(&preimage).map_err(aerr)?;
    Ok(domain_digest(KIND_CLAIM_BINDING_DIGEST_DOMAIN, &bytes))
}

/// bootstrap completion receipt digest 的 JCS preimage（completionReceiptDigest 省略）。
#[derive(Serialize)]
struct BootstrapDigestPreimage<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "bootstrapRevision")]
    bootstrap_revision: u64,
    #[serde(rename = "sourceKind")]
    source_kind: &'a str,
    #[serde(rename = "controlStateRawDigest")]
    control_state_raw_digest: &'a str,
    #[serde(rename = "sourceRevision")]
    source_revision: u64,
    #[serde(rename = "sortedClaims")]
    sorted_claims: &'a [RuntimeKindClaimV1],
}

/// completionReceiptDigest = hex(SHA-256(UTF8("iweb-kind-claim-bootstrap-v1\n" ||
///   JCS(record with completionReceiptDigest omitted))))。
pub fn kind_claim_bootstrap_digest(record: &KindClaimBootstrapV1) -> Result<String, KindRegistryError> {
    let preimage = BootstrapDigestPreimage {
        schema_version: record.schema_version,
        bootstrap_revision: record.bootstrap_revision,
        source_kind: &record.source_kind,
        control_state_raw_digest: &record.control_state_raw_digest,
        source_revision: record.source_revision,
        sorted_claims: &record.sorted_claims,
    };
    let bytes = jcs_bytes(&preimage).map_err(aerr)?;
    Ok(domain_digest(KIND_CLAIM_BOOTSTRAP_DIGEST_DOMAIN, &bytes))
}

// ---------------------------------------------------------------------------
// typed wire 记录（精确键集；camelCase 对位 contracts/spec）
// ---------------------------------------------------------------------------

/// RuntimeKindClaimV1 / ApplicationRuntimeKindBindingV1 的 claim 形状。
/// bindingRevision 从 1 起且永不改变；本实现值域内唯一合法值是 1。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeKindClaimV1 {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "bindingRevision")]
    pub binding_revision: u64,
    #[serde(rename = "bindingDigest")]
    pub binding_digest: String,
}

/// `ApplicationRuntimeKindBindingV1`：/data/kernel/application-kind-registry-v1/
/// &lt;applicationId&gt;.json 的完整记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KindClaimBindingV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "bindingRevision")]
    pub binding_revision: u64,
    #[serde(rename = "bindingDigest")]
    pub binding_digest: String,
}

/// 共享 CAS 索引：/data/kernel/application-kind-registry-v1/index.json。
/// 空索引 revision 0；每次 claim 变更恰好 +1；claims 按 applicationId 字节序严格排序。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KindClaimIndexV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "registryRevision")]
    pub registry_revision: u64,
    pub claims: Vec<RuntimeKindClaimV1>,
}

impl Default for KindClaimIndexV1 {
    fn default() -> Self {
        // 空索引从 revision 0 起步，但 schemaVersion 恒为 1（不能 derive：会把 1 也归零）。
        Self { schema_version: 1, registry_revision: 0, claims: Vec::new() }
    }
}

/// KindClaimBootstrapV1（spec 精确七字段；sortedClaims 只含 celld claim）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KindClaimBootstrapV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "bootstrapRevision")]
    pub bootstrap_revision: u64,
    #[serde(rename = "sourceKind")]
    pub source_kind: String,
    #[serde(rename = "controlStateRawDigest")]
    pub control_state_raw_digest: String,
    #[serde(rename = "sourceRevision")]
    pub source_revision: u64,
    #[serde(rename = "sortedClaims")]
    pub sorted_claims: Vec<RuntimeKindClaimV1>,
    #[serde(rename = "completionReceiptDigest")]
    pub completion_receipt_digest: String,
}

/// MigrationRecordV1（wasm-application-runtime spec 的精确形状）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MigrationRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "migrationId")]
    pub migration_id: String,
    #[serde(rename = "sourceKind")]
    pub source_kind: String,
    #[serde(rename = "sourceApplicationId")]
    pub source_application_id: String,
    #[serde(rename = "sourcePath")]
    pub source_path: String,
    #[serde(rename = "sourceRevision")]
    pub source_revision: u64,
    #[serde(rename = "sourceDigest")]
    pub source_digest: String,
    #[serde(rename = "targetKind")]
    pub target_kind: String,
    #[serde(rename = "targetApplicationId")]
    pub target_application_id: String,
    #[serde(rename = "targetPath")]
    pub target_path: String,
    #[serde(rename = "targetDigest")]
    pub target_digest: String,
    pub status: String,
    #[serde(rename = "receiptRef")]
    pub receipt_ref: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: Option<String>,
}

/// MigrationReceiptV1（spec 精确形状；只在 committed 时写一次）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "migrationId")]
    pub migration_id: String,
    #[serde(rename = "sourceKind")]
    pub source_kind: String,
    #[serde(rename = "sourceApplicationId")]
    pub source_application_id: String,
    #[serde(rename = "sourceRevision")]
    pub source_revision: u64,
    #[serde(rename = "sourceDigest")]
    pub source_digest: String,
    #[serde(rename = "targetKind")]
    pub target_kind: String,
    #[serde(rename = "targetApplicationId")]
    pub target_application_id: String,
    #[serde(rename = "targetRevision")]
    pub target_revision: u64,
    #[serde(rename = "targetDigest")]
    pub target_digest: String,
    #[serde(rename = "completedAt")]
    pub completed_at: String,
}

// ---------------------------------------------------------------------------
// 记录校验（fail-closed；对位 contracts validator 语义）
// ---------------------------------------------------------------------------

fn sort_claims(claims: &mut [RuntimeKindClaimV1]) {
    claims.sort_by(|a, b| a.application_id.as_bytes().cmp(b.application_id.as_bytes()));
}

fn claims_strictly_sorted(claims: &[RuntimeKindClaimV1]) -> bool {
    claims.windows(2).all(|pair| pair[0].application_id.as_bytes() < pair[1].application_id.as_bytes())
}

/// 单条 claim 校验。`require_celld` 为 true 时只接受 celld claim（bootstrap 只从
/// celld 控制态推导；wasm claim 属于越权写入，必须拒绝——对位 TS requireRuntimeKindClaim）。
fn validate_runtime_kind_claim(claim: &RuntimeKindClaimV1, require_celld: bool) -> Result<(), KindRegistryError> {
    validate_kind_application_id(&claim.application_id)?;
    if require_celld {
        if claim.runtime_kind != RUNTIME_KIND_CELLD {
            return Err(err(WASM_KIND_CLAIM_INVALID, "/runtimeKind must be exactly \"celld\" in a bootstrap claim set"));
        }
    } else if claim.runtime_kind != RUNTIME_KIND_CELLD && claim.runtime_kind != RUNTIME_KIND_WASM {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/runtimeKind must be one of: celld, wasm"));
    }
    // bindingRevision 从 1 起且永不改变；本实现唯一合法值 1。
    if claim.binding_revision != 1 {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/bindingRevision must be exactly 1 (it starts at 1 and never changes)"));
    }
    validate_sha256_hex(&claim.binding_digest, "bindingDigest")?;
    let recomputed = kind_binding_digest(&claim.application_id, &claim.runtime_kind, claim.binding_revision)?;
    if recomputed != claim.binding_digest {
        return Err(err(KIND_CLAIM_BINDING_DIGEST_MISMATCH, "bindingDigest must equal the application-kind-binding-v1 domain digest of the claim"));
    }
    Ok(())
}

pub fn validate_kind_claim_index(index: &KindClaimIndexV1) -> Result<(), KindRegistryError> {
    if index.schema_version != 1 {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/schemaVersion must be 1"));
    }
    require_u53(index.registry_revision, 0, "registryRevision")?;
    for claim in &index.claims {
        validate_runtime_kind_claim(claim, false)?;
    }
    if !claims_strictly_sorted(&index.claims) {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/claims must be bytewise sorted by unique applicationId"));
    }
    Ok(())
}

pub fn validate_kind_claim_bootstrap(record: &KindClaimBootstrapV1) -> Result<(), KindRegistryError> {
    if record.schema_version != 1 {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/schemaVersion must be 1"));
    }
    require_u53(record.bootstrap_revision, 0, "bootstrapRevision")?;
    if record.source_kind != RUNTIME_KIND_CELLD {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/sourceKind must be exactly \"celld\""));
    }
    validate_sha256_hex(&record.control_state_raw_digest, "controlStateRawDigest")?;
    require_u53(record.source_revision, 0, "sourceRevision")?;
    for claim in &record.sorted_claims {
        validate_runtime_kind_claim(claim, true)?;
    }
    if !claims_strictly_sorted(&record.sorted_claims) {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/sortedClaims must be bytewise sorted by unique applicationId"));
    }
    validate_sha256_hex(&record.completion_receipt_digest, "completionReceiptDigest")?;
    let recomputed = kind_claim_bootstrap_digest(record)?;
    if recomputed != record.completion_receipt_digest {
        return Err(err(KIND_CLAIM_DIGEST_MISMATCH, "completionReceiptDigest must equal the kind-claim-bootstrap-v1 domain digest of the record"));
    }
    Ok(())
}

pub fn validate_migration_record(record: &MigrationRecordV1) -> Result<(), KindRegistryError> {
    if record.schema_version != 1 {
        return Err(err(MIGRATION_RECORD_INVALID, "/schemaVersion must be 1"));
    }
    validate_uuid_v7(&record.migration_id, "migrationId")?;
    if record.source_kind != MIGRATION_SOURCE_KIND || record.target_kind != MIGRATION_TARGET_KIND {
        return Err(err(MIGRATION_RECORD_INVALID, "sourceKind must be \"celld\" and targetKind must be \"wasm\""));
    }
    validate_kind_application_id(&record.source_application_id)
        .map_err(|e| err(MIGRATION_RECORD_INVALID, e.detail))?;
    validate_kind_application_id(&record.target_application_id)
        .map_err(|e| err(MIGRATION_RECORD_INVALID, e.detail))?;
    // 跨 kind 断言：sourceKind != targetKind 恒成立（固定字面量），故两个 ID 必须不同。
    if record.source_application_id == record.target_application_id {
        return Err(err(MIGRATION_CROSS_KIND_IDENTITY_INVALID, "a cross-kind migration must prove sourceApplicationId != targetApplicationId"));
    }
    if record.source_path != MIGRATION_SOURCE_PATH || record.target_path != MIGRATION_TARGET_PATH {
        return Err(err(MIGRATION_RECORD_INVALID, "sourcePath/targetPath must be the exact spec literals"));
    }
    require_u53_migration(record.source_revision, "sourceRevision")?;
    validate_migration_sha256(&record.source_digest, "sourceDigest")?;
    validate_migration_sha256(&record.target_digest, "targetDigest")?;
    if record.receipt_ref != format!("migration-receipt/{}", record.migration_id) {
        return Err(err(MIGRATION_RECORD_INVALID, "receiptRef must equal \"migration-receipt/<migrationId>\""));
    }
    require_rfc3339_utc(&record.started_at, "startedAt", MIGRATION_RECORD_INVALID)?;
    if !matches!(record.status.as_str(), "started" | "committed" | "rolled-back") {
        return Err(err(MIGRATION_RECORD_INVALID, "/status must be one of: started, committed, rolled-back"));
    }
    match (&record.completed_at, record.status.as_str()) {
        (None, "started") => Ok(()),
        (Some(completed_at), "committed") | (Some(completed_at), "rolled-back") => {
            require_rfc3339_utc(completed_at, "completedAt", MIGRATION_RECORD_INVALID)
        }
        (None, _) => Err(err(MIGRATION_RECORD_INVALID, "a committed or rolled-back migration must carry completedAt")),
        (Some(_), _) => Err(err(MIGRATION_RECORD_INVALID, "a started migration must not carry completedAt")),
    }
}

fn require_u53_migration(value: u64, field: &str) -> Result<(), KindRegistryError> {
    if value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(MIGRATION_RECORD_INVALID, format!("{field} must be a u53 integer")))
    }
}

fn validate_migration_sha256(value: &str, field: &str) -> Result<(), KindRegistryError> {
    if kind_regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(MIGRATION_RECORD_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

pub fn validate_migration_receipt(receipt: &MigrationReceiptV1) -> Result<(), KindRegistryError> {
    if receipt.schema_version != 1 {
        return Err(err(MIGRATION_RECORD_INVALID, "/schemaVersion must be 1"));
    }
    validate_uuid_v7(&receipt.migration_id, "migrationId")?;
    if receipt.source_kind != MIGRATION_SOURCE_KIND || receipt.target_kind != MIGRATION_TARGET_KIND {
        return Err(err(MIGRATION_RECORD_INVALID, "sourceKind must be \"celld\" and targetKind must be \"wasm\""));
    }
    validate_kind_application_id(&receipt.source_application_id)
        .map_err(|e| err(MIGRATION_RECORD_INVALID, e.detail))?;
    validate_kind_application_id(&receipt.target_application_id)
        .map_err(|e| err(MIGRATION_RECORD_INVALID, e.detail))?;
    if receipt.source_application_id == receipt.target_application_id {
        return Err(err(MIGRATION_CROSS_KIND_IDENTITY_INVALID, "a cross-kind migration must prove sourceApplicationId != targetApplicationId"));
    }
    require_u53_migration(receipt.source_revision, "sourceRevision")?;
    require_u53_migration(receipt.target_revision, "targetRevision")?;
    validate_migration_sha256(&receipt.source_digest, "sourceDigest")?;
    validate_migration_sha256(&receipt.target_digest, "targetDigest")?;
    require_rfc3339_utc(&receipt.completed_at, "completedAt", MIGRATION_RECORD_INVALID)
}

/// receipt 与其 migration record 的关联校验（targetRevision 不在 record 内，由
/// 字节一致重放请求双方携带）。
fn correlate_receipt(receipt: &MigrationReceiptV1, record: &MigrationRecordV1) -> Result<(), KindRegistryError> {
    let mismatch = |field: &str| err(MIGRATION_RECORD_INVALID, format!("receipt {field} does not match the migration record"));
    if receipt.migration_id != record.migration_id {
        return Err(mismatch("migrationId"));
    }
    if receipt.source_kind != record.source_kind || receipt.target_kind != record.target_kind {
        return Err(mismatch("kind"));
    }
    if receipt.source_application_id != record.source_application_id || receipt.target_application_id != record.target_application_id {
        return Err(mismatch("applicationId"));
    }
    if receipt.source_revision != record.source_revision {
        return Err(mismatch("sourceRevision"));
    }
    if receipt.source_digest != record.source_digest || receipt.target_digest != record.target_digest {
        return Err(mismatch("digest"));
    }
    match &record.completed_at {
        Some(completed_at) if &receipt.completed_at == completed_at => Ok(()),
        Some(_) => Err(mismatch("completedAt")),
        None => Err(mismatch("completedAt (record is not committed)")),
    }
}

// ---------------------------------------------------------------------------
// 存储抽象（kind-registry / migration；JCS 字节读写，文件层 tmp+rename 原子落盘）
// ---------------------------------------------------------------------------

pub trait KindRegistryStore {
    /// index.json 原始 JCS 字节（不存在 = 空索引 revision 0）。
    fn index_bytes(&self) -> Option<Vec<u8>>;
    fn write_index(&mut self, bytes: &[u8]) -> Result<(), KindRegistryError>;
    /// <applicationId>.json 原始 JCS 字节。
    fn binding_bytes(&self, application_id: &str) -> Option<Vec<u8>>;
    fn write_binding(&mut self, application_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError>;
    /// 全部 bootstrap 记录（按 bootstrapRevision 升序）。
    fn bootstrap_records(&self) -> Vec<Vec<u8>>;
    fn write_bootstrap(&mut self, bootstrap_revision: u64, bytes: &[u8]) -> Result<(), KindRegistryError>;
}

pub trait MigrationStore {
    fn migration_bytes_all(&self) -> Vec<Vec<u8>>;
    fn write_migration(&mut self, migration_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError>;
    fn receipt_bytes(&self, migration_id: &str) -> Option<Vec<u8>>;
    fn write_receipt(&mut self, migration_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError>;
    /// 已落盘且未被隔离的目标文件原始字节。
    fn committed_target_bytes(&self, target_path: &str) -> Option<Vec<u8>>;
    fn write_target(&mut self, target_path: &str, bytes: &[u8]) -> Result<(), KindRegistryError>;
    /// 隔离目标：移出可路由位置，绝不删除（等 owner 修复/审计）。
    fn quarantine_target(&mut self, target_path: &str) -> Result<(), KindRegistryError>;
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), KindRegistryError> {
    let temporary = path.with_extension(format!("tmp-{}", crate::monitor::now_millis()));
    std::fs::write(&temporary, bytes).map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot write {}: {e}", temporary.display())))?;
    std::fs::rename(&temporary, path).map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot rename into {}: {e}", path.display())))
}

/// kind-registry 目录存储：root = /data/kernel/application-kind-registry-v1。
/// 布局：index.json、<applicationId>.json、bootstrap/<bootstrapRevision>.json。
/// bootstrap 保留全部历史记录（双记录分歧 split-brain 检测需要）。
#[derive(Debug, Clone)]
pub struct KindRegistryStoreDir {
    root: PathBuf,
}

impl KindRegistryStoreDir {
    pub fn open(root: &Path) -> Result<Self, KindRegistryError> {
        std::fs::create_dir_all(root.join("bootstrap"))
            .map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot create kind registry root {}: {e}", root.display())))?;
        Ok(Self { root: root.to_path_buf() })
    }
}

impl KindRegistryStore for KindRegistryStoreDir {
    fn index_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.root.join("index.json")).ok()
    }

    fn write_index(&mut self, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(&self.root.join("index.json"), bytes)
    }

    fn binding_bytes(&self, application_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.join(format!("{application_id}.json"))).ok()
    }

    fn write_binding(&mut self, application_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(&self.root.join(format!("{application_id}.json")), bytes)
    }

    fn bootstrap_records(&self) -> Vec<Vec<u8>> {
        let Ok(entries) = std::fs::read_dir(self.root.join("bootstrap")) else {
            return Vec::new();
        };
        let mut revisions: Vec<(u64, PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                if name.contains(".tmp-") {
                    return None;
                }
                let revision = name.strip_suffix(".json")?.parse::<u64>().ok()?;
                Some((revision, entry.path()))
            })
            .collect();
        revisions.sort_by_key(|(revision, _)| *revision);
        revisions.into_iter().filter_map(|(_, path)| std::fs::read(path).ok()).collect()
    }

    fn write_bootstrap(&mut self, bootstrap_revision: u64, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(&self.root.join("bootstrap").join(format!("{bootstrap_revision}.json")), bytes)
    }
}

/// migration 目录存储：migrations/<migrationId>.json、migration-receipt/<migrationId>.json；
/// 目标文件按其绝对路径直接读写，quarantine 以改名实现（绝不删除）。
#[derive(Debug, Clone)]
pub struct MigrationStoreDir {
    root: PathBuf,
}

impl MigrationStoreDir {
    pub fn open(root: &Path) -> Result<Self, KindRegistryError> {
        std::fs::create_dir_all(root.join("migrations"))
            .map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot create migration root {}: {e}", root.display())))?;
        std::fs::create_dir_all(root.join("migration-receipt"))
            .map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot create migration receipt root {}: {e}", root.display())))?;
        Ok(Self { root: root.to_path_buf() })
    }
}

impl MigrationStore for MigrationStoreDir {
    fn migration_bytes_all(&self) -> Vec<Vec<u8>> {
        let Ok(entries) = std::fs::read_dir(self.root.join("migrations")) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| !path.file_name().is_some_and(|name| name.to_string_lossy().contains(".tmp-")))
            .collect();
        paths.sort();
        paths.into_iter().filter_map(|path| std::fs::read(path).ok()).collect()
    }

    fn write_migration(&mut self, migration_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(&self.root.join("migrations").join(format!("{migration_id}.json")), bytes)
    }

    fn receipt_bytes(&self, migration_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.join("migration-receipt").join(format!("{migration_id}.json"))).ok()
    }

    fn write_receipt(&mut self, migration_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(&self.root.join("migration-receipt").join(format!("{migration_id}.json")), bytes)
    }

    fn committed_target_bytes(&self, target_path: &str) -> Option<Vec<u8>> {
        std::fs::read(target_path).ok()
    }

    fn write_target(&mut self, target_path: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(Path::new(target_path), bytes)
    }

    fn quarantine_target(&mut self, target_path: &str) -> Result<(), KindRegistryError> {
        let path = Path::new(target_path);
        if !path.exists() {
            return Ok(());
        }
        let quarantined = PathBuf::from(format!("{}.quarantined-{}", target_path, crate::monitor::now_millis()));
        std::fs::rename(path, &quarantined)
            .map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot quarantine target {}: {e}", quarantined.display())))
    }
}

// ---------------------------------------------------------------------------
// WasmKernelRouteRegistryV1：per-kind wasm registry + 全局 kind-claim CAS + bootstrap
// ---------------------------------------------------------------------------

/// 中断的 kind 事务重放句柄：byte-identical owner 事务（同 proof + 同
/// expectedKindRegistryRevision），恢复时幂等补全 claim+row。
#[derive(Debug, Clone)]
pub struct PendingKindTransaction {
    pub expected_kind_registry_revision: u64,
    pub proof: AdmissionProofV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KindClaimOutcome {
    /// true = 本次调用创建了 claim（revision +1）；false = 同 kind 幂等重试（零写入）。
    pub created: bool,
    pub claim: RuntimeKindClaimV1,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct KindRecoveryReport {
    /// 重放补全的 applicationId（claim 与 row 都已落位）。
    pub replayed: Vec<String>,
    /// 孤儿 claim（全局 claim 存在、kind-specific row 缺失）→ quarantine。
    pub quarantined_claims: Vec<String>,
    /// 孤儿 row（kind-specific row 存在、全局 claim 缺失）→ quarantine。
    pub quarantined_rows: Vec<String>,
}

/// Kernel 拥有的严格 per-kind wasm registry（V1）：
/// - `records` 只承载 runtimeKind:"wasm" 的业务行/指针（复用 wasm_admission 的形状，
///   与 celld ControlStateFile/VersionRecord 物理隔离，绝不互相解析）；
/// - `index` 是 celld/wasm 共享的全局 kind-claim CAS 索引（applicationId 终身
///   绑定一个 runtime kind）；
/// - `bootstrap` 为已对当前 celld 控制态验证过的引导记录（None = wasm 写路径关闭）；
/// - `quarantined` 是恢复期隔离的 applicationId（fence，等 owner 修复 CAS）。
#[derive(Debug, Clone, Default)]
pub struct WasmKernelRouteRegistryV1 {
    index: KindClaimIndexV1,
    records: WasmKernelRouteRegistry,
    bootstrap: Option<KindClaimBootstrapV1>,
    bootstrap_history: Vec<KindClaimBootstrapV1>,
    quarantined: BTreeMap<String, &'static str>,
}

impl WasmKernelRouteRegistryV1 {
    pub fn empty() -> Self {
        Self::default()
    }

    /// 从持久存储重建（index + bootstrap 历史全部校验）。bootstrap 只加载历史，
    /// 不设为已验证——启动序必须先跑 bootstrap_from_celld(_raw) 对当前 celld
    /// 控制态验证/重推导后，wasm 写路径才打开。
    pub fn load(store: &dyn KindRegistryStore) -> Result<Self, KindRegistryError> {
        let index = match store.index_bytes() {
            Some(bytes) => {
                let parsed: KindClaimIndexV1 = parse_canonical(&bytes, WASM_KIND_CLAIM_INVALID, "kind claim index")?;
                validate_kind_claim_index(&parsed)?;
                parsed
            }
            None => KindClaimIndexV1::default(),
        };
        let mut bootstrap_history = Vec::new();
        for bytes in store.bootstrap_records() {
            let record: KindClaimBootstrapV1 = parse_canonical(&bytes, WASM_KIND_CLAIM_INVALID, "kind claim bootstrap record")?;
            validate_kind_claim_bootstrap(&record)?;
            bootstrap_history.push(record);
        }
        bootstrap_history.sort_by_key(|record| record.bootstrap_revision);
        Self::cross_check_bootstrap_history(&bootstrap_history)?;
        Ok(Self { index, records: WasmKernelRouteRegistry::default(), bootstrap: None, bootstrap_history, quarantined: BTreeMap::new() })
    }

    /// 双 bootstrap 记录分歧：同 controlStateRawDigest 的记录 claim 集必须字节一致、
    /// bootstrapRevision 必须唯一；否则 APPLICATION_KIND_SPLIT_BRAIN fail-closed。
    fn cross_check_bootstrap_history(history: &[KindClaimBootstrapV1]) -> Result<(), KindRegistryError> {
        let mut seen_revisions = BTreeSet::new();
        for record in history {
            if !seen_revisions.insert(record.bootstrap_revision) {
                return Err(err(APPLICATION_KIND_SPLIT_BRAIN, format!("two bootstrap records share bootstrapRevision {}", record.bootstrap_revision)));
            }
        }
        for (i, earlier) in history.iter().enumerate() {
            for later in &history[i + 1..] {
                if earlier.control_state_raw_digest == later.control_state_raw_digest && earlier.sorted_claims != later.sorted_claims {
                    return Err(err(APPLICATION_KIND_SPLIT_BRAIN, "two bootstrap records exist for the same source digest with different claim sets"));
                }
            }
        }
        Ok(())
    }

    pub fn index(&self) -> &KindClaimIndexV1 {
        &self.index
    }

    pub fn registry_revision(&self) -> u64 {
        self.index.registry_revision
    }

    pub fn records(&self) -> &WasmKernelRouteRegistry {
        &self.records
    }

    pub fn claim(&self, application_id: &str) -> Option<&RuntimeKindClaimV1> {
        self.index.claims.iter().find(|claim| claim.application_id == application_id)
    }

    pub fn bootstrap_record(&self) -> Option<&KindClaimBootstrapV1> {
        self.bootstrap.as_ref()
    }

    pub fn is_quarantined(&self, application_id: &str) -> Option<&'static str> {
        self.quarantined.get(application_id).copied()
    }

    /// wasm 写路径门：没有"已对当前 celld 控制态验证过"的 bootstrap 记录即
    /// WASM_KIND_BOOTSTRAP_PENDING（不分配任何 wasm 身份或 claim）。
    pub fn wasm_write_gate(&self) -> Result<(), KindRegistryError> {
        if self.bootstrap.is_some() {
            Ok(())
        } else {
            Err(err(WASM_KIND_BOOTSTRAP_PENDING, "no kind-claim bootstrap record verifies against the current celld control state; the wasm write path stays closed"))
        }
    }

    /// celld 控制态变更通知：raw digest 与已验证 bootstrap 记录不一致时失效验证，
    /// 强制在下次 wasm 写之前重新 bootstrap（返回是否发生了失效）。
    pub fn celld_control_state_changed(&mut self, celld_control_state_raw: &[u8]) -> bool {
        let digest = sha256_hex(celld_control_state_raw);
        if self.bootstrap.as_ref().is_some_and(|record| record.control_state_raw_digest != digest) {
            self.bootstrap = None;
            true
        } else {
            false
        }
    }

    fn ensure_not_quarantined(&self, application_id: &str) -> Result<(), KindRegistryError> {
        match self.quarantined.get(application_id) {
            Some(reason) => Err(err(APPLICATION_KIND_SPLIT_BRAIN, format!("applicationId {application_id} is fenced ({reason}) and waits for an owner repair CAS"))),
            None => Ok(()),
        }
    }

    /// 全局 kind-claim CAS。写序恒为：全局 claim（binding + index）→ kind-specific
    /// registry 写，绝不反序。同 kind 重试幂等（零写入零 revision 变更）；不同 kind
    /// 返回 APPLICATION_RUNTIME_KIND_CONFLICT 且不触碰任何 registry；期望 revision
    /// 不匹配返回 KIND_REGISTRY_REVISION_CONFLICT 且不写任何东西。wasm kind 额外
    /// 受 bootstrap 门约束。
    pub fn claim_runtime_kind(
        &mut self,
        store: &mut dyn KindRegistryStore,
        application_id: &str,
        runtime_kind: &str,
        expected_kind_registry_revision: u64,
    ) -> Result<KindClaimOutcome, KindRegistryError> {
        if runtime_kind != RUNTIME_KIND_CELLD && runtime_kind != RUNTIME_KIND_WASM {
            return Err(err(WASM_KIND_CLAIM_INVALID, "runtimeKind must be one of: celld, wasm"));
        }
        if runtime_kind == RUNTIME_KIND_WASM {
            self.wasm_write_gate()?;
        }
        self.ensure_not_quarantined(application_id)?;
        validate_kind_application_id(application_id)?;
        if let Some(existing) = self.claim(application_id) {
            if existing.runtime_kind == runtime_kind {
                return Ok(KindClaimOutcome { created: false, claim: existing.clone() });
            }
            return Err(err(
                APPLICATION_RUNTIME_KIND_CONFLICT,
                format!("applicationId {application_id} is permanently {}-bound; changing runtime kind requires a new applicationId", existing.runtime_kind),
            ));
        }
        if expected_kind_registry_revision != self.index.registry_revision {
            return Err(err(
                KIND_REGISTRY_REVISION_CONFLICT,
                format!("expectedKindRegistryRevision {expected_kind_registry_revision} != current {}; the claim CAS writes nothing on mismatch", self.index.registry_revision),
            ));
        }
        let binding_digest = kind_binding_digest(application_id, runtime_kind, 1)?;
        let claim = RuntimeKindClaimV1 { application_id: application_id.to_string(), runtime_kind: runtime_kind.to_string(), binding_revision: 1, binding_digest: binding_digest.clone() };
        let binding = KindClaimBindingV1 { schema_version: 1, application_id: claim.application_id.clone(), runtime_kind: claim.runtime_kind.clone(), binding_revision: 1, binding_digest };
        let mut next = self.index.clone();
        next.registry_revision += 1;
        next.claims.push(claim.clone());
        sort_claims(&mut next.claims);
        validate_kind_claim_index(&next)?;
        // 持久先于内存：任一写失败时内存索引不变，重试幂等重放同一步。
        store.write_binding(application_id, &jcs_bytes(&binding).map_err(aerr)?)?;
        store.write_index(&jcs_bytes(&next).map_err(aerr)?)?;
        self.index = next;
        Ok(KindClaimOutcome { created: true, claim })
    }

    /// 单个 kind 事务的统一路径：先全局 claim CAS，再 kind-specific row 插入
    /// （幂等）。恢复重放与正常注册共用，保证字节一致语义。
    fn apply_kind_transaction(&mut self, store: &mut dyn KindRegistryStore, transaction: &PendingKindTransaction) -> Result<WasmVersionRegistryRow, KindRegistryError> {
        verify_admission_proof(&transaction.proof).map_err(aerr)?;
        let application_id = transaction.proof.application_id.clone();
        self.claim_runtime_kind(store, &application_id, RUNTIME_KIND_WASM, transaction.expected_kind_registry_revision)?;
        self.records.insert_admitted(&transaction.proof).map_err(aerr)
    }

    /// 注册（投影）一条 wasm 准入记录：kind claim CAS 成功后才写 wasm registry 行。
    /// 同 kind 幂等；celld-bound ID 冲突；bootstrap 未验证前整体关闭。
    pub fn register_wasm_admission(
        &mut self,
        store: &mut dyn KindRegistryStore,
        expected_kind_registry_revision: u64,
        proof: &AdmissionProofV1,
    ) -> Result<WasmVersionRegistryRow, KindRegistryError> {
        self.apply_kind_transaction(store, &PendingKindTransaction { expected_kind_registry_revision, proof: proof.clone() })
    }

    /// supervisor/gateway 投影一致性检查：上报的 wasm version/binding 缺少 Kernel
    /// registry 记录或缺 admission-proof 引用时拒绝（WASM_BUSINESS_RECORD_MISSING），
    /// 既有 active 指针保持不变（纯读路径，无任何 mutation）。
    pub fn check_wasm_route_projection(&self, application_id: &str, version_id: &str, admission_proof_ref: Option<&str>) -> Result<(), KindRegistryError> {
        let application = self
            .records
            .applications
            .get(application_id)
            .ok_or_else(|| err(WASM_BUSINESS_RECORD_MISSING, format!("applicationId {application_id} has no Kernel wasm registry record")))?;
        let row = application
            .versions
            .iter()
            .find(|row| row.version_id == version_id)
            .ok_or_else(|| err(WASM_BUSINESS_RECORD_MISSING, format!("version {version_id} is absent from the Kernel wasm registry")))?;
        let expected_ref = format!("admission-proof/{application_id}/{version_id}");
        if row.admission_proof_ref != expected_ref || admission_proof_ref != Some(row.admission_proof_ref.as_str()) {
            return Err(err(WASM_BUSINESS_RECORD_MISSING, "the projected version lacks its admission-proof reference"));
        }
        Ok(())
    }

    /// 恢复：重放中断的 owner kind 事务 → split-brain 检测（fail-closed，绝不按
    /// 时间戳/journal 序启发式选边）→ binding/index 一致性 → 孤儿 quarantine。
    pub fn recover(
        &mut self,
        store: &mut dyn KindRegistryStore,
        celld_application_ids: &[String],
        pending: &[PendingKindTransaction],
    ) -> Result<KindRecoveryReport, KindRegistryError> {
        let mut report = KindRecoveryReport::default();
        for transaction in pending {
            self.apply_kind_transaction(store, transaction)?;
            report.replayed.push(transaction.proof.application_id.clone());
        }
        let wasm_rows: Vec<String> = self.records.applications.keys().cloned().collect();
        let wasm_claims: Vec<String> = self
            .index
            .claims
            .iter()
            .filter(|claim| claim.runtime_kind == RUNTIME_KIND_WASM)
            .map(|claim| claim.application_id.clone())
            .collect();
        // 两个 kind registry 同时主张同一 applicationId（含双 active 指针的上位情形）。
        for celld_id in celld_application_ids {
            if wasm_rows.iter().any(|id| id == celld_id) || wasm_claims.iter().any(|id| id == celld_id) {
                return Err(err(
                    APPLICATION_KIND_SPLIT_BRAIN,
                    format!("both celld and wasm registries claim applicationId {celld_id}; all traffic for it is fenced pending an owner repair receipt"),
                ));
            }
        }
        // binding/index 一致性：被索引引用的 binding 必须逐字段一致；缺失则按 claim
        // 确定性重建（binding digest 是纯函数）。
        for claim in &self.index.claims {
            match store.binding_bytes(&claim.application_id) {
                Some(bytes) => {
                    let binding: KindClaimBindingV1 = parse_canonical(&bytes, WASM_KIND_CLAIM_INVALID, "kind binding record")?;
                    if binding.schema_version != 1
                        || binding.application_id != claim.application_id
                        || binding.runtime_kind != claim.runtime_kind
                        || binding.binding_revision != claim.binding_revision
                        || binding.binding_digest != claim.binding_digest
                    {
                        return Err(err(
                            APPLICATION_KIND_SPLIT_BRAIN,
                            format!("the binding record and the shared kind index disagree on applicationId {}", claim.application_id),
                        ));
                    }
                }
                None => {
                    let binding = binding_from_claim(claim);
                    store.write_binding(&claim.application_id, &jcs_bytes(&binding).map_err(aerr)?)?;
                }
            }
        }
        // 孤儿：claim 无 row / row 无 claim。不得成为 active；等 owner 重放或修复。
        for id in &wasm_claims {
            if !self.records.applications.contains_key(id) {
                self.quarantined.insert(id.clone(), "wasm kind claim without its kind-specific registry row");
                report.quarantined_claims.push(id.clone());
            }
        }
        for id in &wasm_rows {
            if !self.index.claims.iter().any(|claim| claim.application_id == *id && claim.runtime_kind == RUNTIME_KIND_WASM) {
                self.quarantined.insert(id.clone(), "wasm registry row without its global kind claim");
                report.quarantined_rows.push(id.clone());
            }
        }
        Ok(report)
    }

    /// 从当前 celld 控制态推导（或验证）一次 kind-claim bootstrap：
    /// - 已有记录且 controlStateRawDigest 匹配：校验 derived 集与 index 一致后直接
    ///   视为验证通过（幂等重放）；
    /// - 无记录或 digest 变化：逐 claim 提交进共享 index（每次变更 revision +1，
    ///   中途崩溃重放幂等），最后持久化新 bootstrap 记录（revision 递增）。
    pub fn bootstrap_from_celld(
        &mut self,
        store: &mut dyn KindRegistryStore,
        celld_control_state_raw: &[u8],
        celld_application_ids: &[String],
    ) -> Result<KindClaimBootstrapV1, KindRegistryError> {
        let derived = derive_celld_claims(celld_application_ids)?;
        let raw_digest = sha256_hex(celld_control_state_raw);
        Self::cross_check_bootstrap_history(&self.bootstrap_history)?;
        let latest = self.bootstrap_history.last().cloned();
        if let Some(record) = &latest {
            if record.control_state_raw_digest == raw_digest {
                // 记录 verifies：derived 集必须与记录一致（celld registry entry 不得
                // 缺席已验证 claim 集），index 必须逐条包含记录的 claim。
                if record.sorted_claims != derived {
                    return Err(err(APPLICATION_KIND_SPLIT_BRAIN, "a celld registry entry is absent from the verified claim set"));
                }
                for claim in &derived {
                    if !self.index.claims.contains(claim) {
                        return Err(err(APPLICATION_KIND_SPLIT_BRAIN, "the shared kind index no longer contains a bootstrap claim"));
                    }
                }
                self.bootstrap = Some(record.clone());
                return Ok(record.clone());
            }
        }
        // 首次或 digest 变化 → 重推导提交（幂等：已存在的字节一致 claim 直接跳过）。
        for claim in &derived {
            // position() 先结算借用，None 分支才能安全改写 self.index。
            let found = self.index.claims.iter().position(|existing| existing.application_id == claim.application_id);
            match found {
                Some(index) if &self.index.claims[index] == claim => {}
                Some(index) if self.index.claims[index].runtime_kind == RUNTIME_KIND_WASM => {
                    return Err(err(APPLICATION_KIND_SPLIT_BRAIN, format!("bootstrap must not overwrite the wasm kind claim on applicationId {}", claim.application_id)));
                }
                Some(_) => {
                    return Err(err(APPLICATION_KIND_SPLIT_BRAIN, format!("the index claim on applicationId {} disagrees with the deterministic celld derivation", claim.application_id)));
                }
                None => {
                    let mut next = self.index.clone();
                    next.registry_revision += 1;
                    next.claims.push(claim.clone());
                    sort_claims(&mut next.claims);
                    validate_kind_claim_index(&next)?;
                    let binding = binding_from_claim(claim);
                    store.write_binding(&claim.application_id, &jcs_bytes(&binding).map_err(aerr)?)?;
                    store.write_index(&jcs_bytes(&next).map_err(aerr)?)?;
                    self.index = next;
                }
            }
        }
        // 现行 celld ControlStateFile 无 controlRevision 字段 → sourceRevision 恒为
        // 显式快照 revision 0（绝不由 versions 数量推断；将来带 revision 的源用其精确值）。
        let bootstrap_revision = latest.as_ref().map(|record| record.bootstrap_revision + 1).unwrap_or(1);
        let mut record = KindClaimBootstrapV1 {
            schema_version: 1,
            bootstrap_revision,
            source_kind: RUNTIME_KIND_CELLD.to_string(),
            control_state_raw_digest: raw_digest,
            source_revision: 0,
            sorted_claims: derived,
            completion_receipt_digest: String::new(),
        };
        record.completion_receipt_digest = kind_claim_bootstrap_digest(&record)?;
        validate_kind_claim_bootstrap(&record)?;
        let bytes = jcs_bytes(&record).map_err(aerr)?;
        store.write_bootstrap(record.bootstrap_revision, &bytes)?;
        self.bootstrap_history.push(record.clone());
        Self::cross_check_bootstrap_history(&self.bootstrap_history)?;
        self.bootstrap = Some(record.clone());
        Ok(record)
    }

    /// 便捷入口：从 celld 控制态原始字节解析（严格 v1 legacy 形状，绝不解析 wasm
    /// 身份）后执行 bootstrap。wasm v2 控制态在此 fail-closed（parser 隔离）。
    pub fn bootstrap_from_celld_raw(&mut self, store: &mut dyn KindRegistryStore, celld_control_state_raw: &[u8]) -> Result<KindClaimBootstrapV1, KindRegistryError> {
        let state: crate::control::ControlStateFile = serde_json::from_slice(celld_control_state_raw)
            .map_err(|e| err(WASM_KIND_CLAIM_INVALID, format!("the celld control state does not parse as the legacy v1 shape: {e}")))?;
        if state.version != 1 {
            return Err(err(WASM_KIND_CLAIM_INVALID, "the celld control state must be the legacy version 1 shape"));
        }
        let ids = celld_application_ids(&state);
        self.bootstrap_from_celld(store, celld_control_state_raw, &ids)
    }

    // -- celld → wasm 迁移（MigrationRecordV1 / MigrationReceiptV1） --

    /// owner 授权的单向快照迁移。幂等键 (sourceKind, sourceApplicationId,
    /// sourceRevision, sourceDigest, targetKind, targetApplicationId)：字节一致重放
    /// 返回原 receipt；同源 revision 换 digest/目标 ID 返回 MIGRATION_SOURCE_CONFLICT
    /// 并隔离任何未完成 target。跨 kind 必须换 applicationId；target 已 celld-bound
    /// 或 source 已 wasm-bound 均为 APPLICATION_RUNTIME_KIND_CONFLICT（不写任何
    /// registry/指针）。目标校验失败或 digest 不匹配：target quarantine、记录
    /// rolled-back、active 指针不变。
    pub fn commit_migration(&self, store: &mut dyn MigrationStore, request: &MigrationRequestV1) -> Result<MigrationReceiptV1, KindRegistryError> {
        validate_uuid_v7(&request.migration_id, "migrationId")?;
        validate_kind_application_id(&request.source_application_id)
            .map_err(|e| err(MIGRATION_RECORD_INVALID, e.detail))?;
        validate_kind_application_id(&request.target_application_id)
            .map_err(|e| err(MIGRATION_RECORD_INVALID, e.detail))?;
        require_u53_migration(request.source_revision, "sourceRevision")?;
        require_u53_migration(request.target_revision, "targetRevision")?;
        if request.source_application_id == request.target_application_id {
            return Err(err(MIGRATION_CROSS_KIND_IDENTITY_INVALID, "a cross-kind migration must prove sourceApplicationId != targetApplicationId"));
        }
        if let Some(claim) = self.claim(&request.target_application_id) {
            if claim.runtime_kind == RUNTIME_KIND_CELLD {
                return Err(err(APPLICATION_RUNTIME_KIND_CONFLICT, format!("target applicationId {} is celld-bound; changing runtime kind requires a new applicationId", request.target_application_id)));
            }
        }
        if let Some(claim) = self.claim(&request.source_application_id) {
            if claim.runtime_kind == RUNTIME_KIND_WASM {
                return Err(err(APPLICATION_RUNTIME_KIND_CONFLICT, format!("celld source applicationId {} is wasm-bound; runtime kind is permanent per applicationId", request.source_application_id)));
            }
        }
        let source_digest = sha256_hex(&request.source_snapshot);
        let mut existing: Vec<MigrationRecordV1> = Vec::new();
        for bytes in store.migration_bytes_all() {
            existing.push(parse_canonical(&bytes, MIGRATION_RECORD_INVALID, "migration record")?);
        }
        let mut conflict = false;
        for record in &existing {
            let same_source_tuple = record.source_kind == MIGRATION_SOURCE_KIND
                && record.source_application_id == request.source_application_id
                && record.source_revision == request.source_revision;
            if !same_source_tuple {
                continue;
            }
            if record.source_digest != source_digest || record.target_application_id != request.target_application_id {
                // 同源 revision 换 digest / 换目标 ID：隔离任何未完成 target 后拒绝。
                conflict = true;
                if record.status != "committed" {
                    store.quarantine_target(MIGRATION_TARGET_PATH)?;
                    let rolled = rolled_back(record, request.now_epoch_millis)?;
                    store.write_migration(&record.migration_id, &jcs_bytes(&rolled).map_err(aerr)?)?;
                }
                continue;
            }
            match record.status.as_str() {
                "committed" => {
                    if let Some(receipt_bytes) = store.receipt_bytes(&record.migration_id) {
                        let receipt: MigrationReceiptV1 = parse_canonical(&receipt_bytes, MIGRATION_RECORD_INVALID, "migration receipt")?;
                        validate_migration_receipt(&receipt)?;
                        correlate_receipt(&receipt, record)?;
                        return Ok(receipt);
                    }
                    // crash-after-target：重算 target digest，匹配则补写唯一 receipt。
                    let committed = store
                        .committed_target_bytes(MIGRATION_TARGET_PATH)
                        .ok_or_else(|| err(MIGRATION_TARGET_DIGEST_MISMATCH, "the committed target file is missing during receipt recovery"))?;
                    if sha256_hex(&committed) != record.target_digest {
                        store.quarantine_target(MIGRATION_TARGET_PATH)?;
                        let rolled = rolled_back(record, request.now_epoch_millis)?;
                        store.write_migration(&record.migration_id, &jcs_bytes(&rolled).map_err(aerr)?)?;
                        return Err(err(MIGRATION_TARGET_DIGEST_MISMATCH, "the committed target digest no longer matches the migration record"));
                    }
                    let receipt = receipt_from_record(record, request.target_revision)?;
                    store.write_receipt(&receipt.migration_id, &jcs_bytes(&receipt).map_err(aerr)?)?;
                    return Ok(receipt);
                }
                "rolled-back" => {
                    if record.migration_id == request.migration_id {
                        return Err(err(MIGRATION_TERMINAL_ROLLED_BACK, "a rolled-back migrationId is terminal; the owner must issue a new migrationId"));
                    }
                    // 同元组、新 migrationId：owner 修复后重新驱动（历史 rolled-back 记录保留）。
                }
                "started" => {
                    if record.migration_id != request.migration_id {
                        return Err(err(MIGRATION_SOURCE_CONFLICT, "another in-flight migration already owns this source tuple"));
                    }
                    // 同 ID 续跑（crash before target commit：源未被触碰，重试同 ID）。
                }
                _ => return Err(err(MIGRATION_RECORD_INVALID, "unknown migration status")),
            }
        }
        if conflict {
            return Err(err(MIGRATION_SOURCE_CONFLICT, "a migration retry sees the same source revision with a different source digest or target applicationId"));
        }
        let target_digest = sha256_hex(&request.target_bytes);
        let record = MigrationRecordV1 {
            schema_version: 1,
            migration_id: request.migration_id.clone(),
            source_kind: MIGRATION_SOURCE_KIND.to_string(),
            source_application_id: request.source_application_id.clone(),
            source_path: MIGRATION_SOURCE_PATH.to_string(),
            source_revision: request.source_revision,
            source_digest: source_digest.clone(),
            target_kind: MIGRATION_TARGET_KIND.to_string(),
            target_application_id: request.target_application_id.clone(),
            target_path: MIGRATION_TARGET_PATH.to_string(),
            target_digest: target_digest.clone(),
            status: "started".to_string(),
            receipt_ref: format!("migration-receipt/{}", request.migration_id),
            started_at: format_rfc3339_utc_millis(request.now_epoch_millis),
            completed_at: None,
        };
        validate_migration_record(&record)?;
        store.write_migration(&record.migration_id, &jcs_bytes(&record).map_err(aerr)?)?;
        if let Err(problem) = validate_target_shape(&request.target_bytes, request.target_revision) {
            store.quarantine_target(MIGRATION_TARGET_PATH)?;
            let rolled = rolled_back(&record, request.now_epoch_millis)?;
            store.write_migration(&record.migration_id, &jcs_bytes(&rolled).map_err(aerr)?)?;
            return Err(problem);
        }
        if let Err(problem) = store.write_target(MIGRATION_TARGET_PATH, &request.target_bytes) {
            let rolled = rolled_back(&record, request.now_epoch_millis)?;
            store.write_migration(&record.migration_id, &jcs_bytes(&rolled).map_err(aerr)?)?;
            return Err(problem);
        }
        let mut committed_record = record.clone();
        committed_record.status = "committed".to_string();
        committed_record.completed_at = Some(format_rfc3339_utc_millis(request.now_epoch_millis));
        validate_migration_record(&committed_record)?;
        store.write_migration(&committed_record.migration_id, &jcs_bytes(&committed_record).map_err(aerr)?)?;
        let receipt = receipt_from_record(&committed_record, request.target_revision)?;
        store.write_receipt(&receipt.migration_id, &jcs_bytes(&receipt).map_err(aerr)?)?;
        Ok(receipt)
    }
}

fn binding_from_claim(claim: &RuntimeKindClaimV1) -> KindClaimBindingV1 {
    KindClaimBindingV1 {
        schema_version: 1,
        application_id: claim.application_id.clone(),
        runtime_kind: claim.runtime_kind.clone(),
        binding_revision: claim.binding_revision,
        binding_digest: claim.binding_digest.clone(),
    }
}

/// 从 celld application ID 集推导 bytewise 排序的 claim 集（runtimeKind 恒 celld、
/// bindingRevision 恒 1、digest 按公式复算）。
pub fn derive_celld_claims(celld_application_ids: &[String]) -> Result<Vec<RuntimeKindClaimV1>, KindRegistryError> {
    let mut seen = BTreeSet::new();
    let mut claims = Vec::new();
    for id in celld_application_ids {
        validate_kind_application_id(id).map_err(|e| err(WASM_KIND_CLAIM_INVALID, format!("celld application id: {}", e.detail)))?;
        if !seen.insert(id.clone()) {
            return Err(err(WASM_KIND_CLAIM_INVALID, format!("duplicate celld applicationId {id}")));
        }
        claims.push(RuntimeKindClaimV1 {
            application_id: id.clone(),
            runtime_kind: RUNTIME_KIND_CELLD.to_string(),
            binding_revision: 1,
            binding_digest: kind_binding_digest(id, RUNTIME_KIND_CELLD, 1)?,
        });
    }
    sort_claims(&mut claims);
    Ok(claims)
}

/// 现行 celld ControlStateFile 的 applicationId 键集。
pub fn celld_application_ids(state: &crate::control::ControlStateFile) -> Vec<String> {
    state.applications.keys().cloned().collect()
}

/// 迁移请求：source 快照与 target 完整 JCS 文件由 owner 准备；driver 负责校验、
/// 幂等、receipt 与 quarantine。
#[derive(Debug, Clone)]
pub struct MigrationRequestV1 {
    pub migration_id: String,
    pub source_application_id: String,
    /// 原始规范源快照字节（sourceDigest = SHA-256(本字节)，绝不信任声明值）。
    pub source_snapshot: Vec<u8>,
    /// 现行 celld ControlStateFile 无 revision → 0（显式快照 revision）。
    pub source_revision: u64,
    pub target_application_id: String,
    /// 完整 target JCS 文件字节（含 controlRevision）。
    pub target_bytes: Vec<u8>,
    /// 已提交 target 的 controlRevision（与 target_bytes 内字段必须一致）。
    pub target_revision: u64,
    pub now_epoch_millis: u64,
}

fn rolled_back(record: &MigrationRecordV1, now_epoch_millis: u64) -> Result<MigrationRecordV1, KindRegistryError> {
    let mut next = record.clone();
    next.status = "rolled-back".to_string();
    next.completed_at = Some(format_rfc3339_utc_millis(now_epoch_millis));
    validate_migration_record(&next)?;
    Ok(next)
}

fn receipt_from_record(record: &MigrationRecordV1, target_revision: u64) -> Result<MigrationReceiptV1, KindRegistryError> {
    let completed_at = record
        .completed_at
        .clone()
        .ok_or_else(|| err(MIGRATION_RECORD_INVALID, "a committed migration must carry completedAt"))?;
    let receipt = MigrationReceiptV1 {
        schema_version: 1,
        migration_id: record.migration_id.clone(),
        source_kind: record.source_kind.clone(),
        source_application_id: record.source_application_id.clone(),
        source_revision: record.source_revision,
        source_digest: record.source_digest.clone(),
        target_kind: record.target_kind.clone(),
        target_application_id: record.target_application_id.clone(),
        target_revision,
        target_digest: record.target_digest.clone(),
        completed_at,
    };
    validate_migration_receipt(&receipt)?;
    Ok(receipt)
}

/// target 形状校验：必须已是 JCS 字节，且 schemaVersion=2、runtimeKind="wasm"、
/// controlRevision 与请求一致（完整 WasmControlStateFileV2 校验属 wasm 控制态任务）。
fn validate_target_shape(target_bytes: &[u8], expected_revision: u64) -> Result<(), KindRegistryError> {
    let value: serde_json::Value = serde_json::from_slice(target_bytes)
        .map_err(|e| err(MIGRATION_TARGET_INVALID, format!("target bytes do not parse as JSON: {e}")))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|e| err(MIGRATION_TARGET_INVALID, format!("target re-serialization failed: {e}")))?;
    if canonical != target_bytes {
        return Err(err(MIGRATION_TARGET_INVALID, "target bytes must already be JCS canonical"));
    }
    let invalid = |detail: &str| err(MIGRATION_TARGET_INVALID, detail.to_string());
    let Some(object) = value.as_object() else {
        return Err(invalid("target must be a JSON object"));
    };
    match object.get("schemaVersion").and_then(serde_json::Value::as_u64) {
        Some(2) => {}
        _ => return Err(invalid("target schemaVersion must be 2")),
    }
    if object.get("runtimeKind").and_then(serde_json::Value::as_str) != Some(RUNTIME_KIND_WASM) {
        return Err(invalid("target runtimeKind must be \"wasm\""));
    }
    match object.get("controlRevision").and_then(serde_json::Value::as_u64) {
        Some(revision) if revision == expected_revision => Ok(()),
        _ => Err(invalid("target controlRevision must equal the request targetRevision")),
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_admission::{
        wasm_version_digest_v1, LifecycleAdmissionRecord, NormalizedWasmManifestV1, RuntimeBindingIdentityV1, WasmActivePointerV1,
        WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL,
    };

    // -- golden 向量（TS 权威 packages/contracts/wasm-execution.ts 于 2026-08-26
    //    经 bun 直读产出；值写死，改公式必须先改契约再重算） --

    const GOLDEN_BINDING_CELLD_ADMIN: &str = "d7a016dab24dfebcb8e12b4156e8b1fd6d70a9d32918fa17f901281527690600";
    const GOLDEN_BINDING_CELLD_NOTES: &str = "c467357ac32bd89a2e9cdde3bf96f78957825df97ca34ba82ee9ce552e46263d";
    const GOLDEN_BINDING_CELLD_MCP: &str = "26c7ea53f6067d7f01a075061539a15d06cf7b924a627159dd244499fe5ad112";
    const GOLDEN_BINDING_WASM_VECTOR: &str = "5cdbc1c45afc1242f171b295ce70a6058cf982d51da1bd952b16db9be9a73664";
    // 对位 contracts exampleKindClaimBootstrapV1()：bootstrapRevision 1、
    // controlStateRawDigest "9"*64、sourceRevision 0、claims [admin, notes]。
    const GOLDEN_BOOTSTRAP_EXAMPLE: &str = "ddaaf30e6621ed126cd6cfe686f4f48912e2ac57c4b2ab35e51814fc3c25a92a";

    const T0: u64 = 1_800_000_000_000;

    // 独立 oracle：手工拼 preimage 再单次 SHA-256（不复用被测实现）。
    fn oracle_sha256_hex(parts: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hex::encode(hasher.finalize())
    }

    fn vector_manifest() -> NormalizedWasmManifestV1 {
        serde_json::from_str(
            r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#,
        )
        .expect("vector manifest parses")
    }

    fn vector_binding() -> RuntimeBindingIdentityV1 {
        RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: WASM_HOST_ABI_LITERAL.into(),
            world: WASM_WORLD_LITERAL.into(),
        }
    }

    fn proof_for(application_id: &str) -> AdmissionProofV1 {
        let mut manifest = vector_manifest();
        manifest.name = application_id.to_string();
        let manifest_jcs = jcs_bytes(&manifest).expect("manifest jcs");
        let package_digest = "0".repeat(64);
        let version_digest = wasm_version_digest_v1(&package_digest, &manifest_jcs);
        AdmissionProofV1 {
            schema_version: 1,
            application_id: application_id.to_string(),
            package_digest,
            version_digest: version_digest.clone(),
            sequence: 1,
            version_id: format!("{version_digest}-1"),
            normalized_policy: manifest,
            lifecycle_admission_record: LifecycleAdmissionRecord {
                schema_version: 1,
                state: "admitted".into(),
                admitted_at: "2026-08-26T00:00:00Z".into(),
                admission_journal_revision: 0,
            },
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            commit_token_hash: "4".repeat(64),
            host_service_policy: None,
        }
    }

    /// 现行 celld ControlStateFile 形状（version:1，无 controlRevision）的原始字节。
    fn celld_state_raw(ids: &[&str]) -> Vec<u8> {
        let mut applications = serde_json::Map::new();
        for id in ids {
            applications.insert(
                (*id).to_string(),
                serde_json::json!({ "applicationId": id, "active": { "kind": "none" }, "versions": [] }),
            );
        }
        serde_json::to_vec(&serde_json::json!({ "version": 1, "applications": applications })).expect("celld state serializes")
    }

    // -- 内存 mock 存储与故障注入 --

    #[derive(Default)]
    struct MockKindStore {
        index: Option<Vec<u8>>,
        bindings: BTreeMap<String, Vec<u8>>,
        bootstraps: BTreeMap<u64, Vec<u8>>,
        index_writes: usize,
        /// 崩溃注入：第 n 次 index 写成功后，后续 index 写失败（模拟中途掉电）。
        fail_index_after: Option<usize>,
    }

    impl MockKindStore {
        fn maybe_fail_index(&mut self) -> Result<(), KindRegistryError> {
            self.index_writes += 1;
            if self.fail_index_after.is_some_and(|limit| self.index_writes > limit) {
                return Err(err(KIND_REGISTRY_STORE_IO, "injected crash: index write lost"));
            }
            Ok(())
        }
    }

    impl KindRegistryStore for MockKindStore {
        fn index_bytes(&self) -> Option<Vec<u8>> {
            self.index.clone()
        }
        fn write_index(&mut self, bytes: &[u8]) -> Result<(), KindRegistryError> {
            self.maybe_fail_index()?;
            self.index = Some(bytes.to_vec());
            Ok(())
        }
        fn binding_bytes(&self, application_id: &str) -> Option<Vec<u8>> {
            self.bindings.get(application_id).cloned()
        }
        fn write_binding(&mut self, application_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
            self.bindings.insert(application_id.to_string(), bytes.to_vec());
            Ok(())
        }
        fn bootstrap_records(&self) -> Vec<Vec<u8>> {
            self.bootstraps.values().cloned().collect()
        }
        fn write_bootstrap(&mut self, bootstrap_revision: u64, bytes: &[u8]) -> Result<(), KindRegistryError> {
            self.bootstraps.insert(bootstrap_revision, bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockMigrationStore {
        migrations: BTreeMap<String, Vec<u8>>,
        receipts: BTreeMap<String, Vec<u8>>,
        targets: BTreeMap<String, Vec<u8>>,
        quarantined: BTreeSet<String>,
        fail_target_write: bool,
        fail_receipt_write: bool,
    }

    impl MockMigrationStore {
        fn record(&self, migration_id: &str) -> Option<MigrationRecordV1> {
            self.migrations
                .get(migration_id)
                .and_then(|bytes| parse_canonical::<MigrationRecordV1>(bytes, MIGRATION_RECORD_INVALID, "migration record").ok())
        }
    }

    impl MigrationStore for MockMigrationStore {
        fn migration_bytes_all(&self) -> Vec<Vec<u8>> {
            self.migrations.values().cloned().collect()
        }
        fn write_migration(&mut self, migration_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
            self.migrations.insert(migration_id.to_string(), bytes.to_vec());
            Ok(())
        }
        fn receipt_bytes(&self, migration_id: &str) -> Option<Vec<u8>> {
            self.receipts.get(migration_id).cloned()
        }
        fn write_receipt(&mut self, migration_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
            if self.fail_receipt_write {
                return Err(err(KIND_REGISTRY_STORE_IO, "injected receipt write failure"));
            }
            self.receipts.insert(migration_id.to_string(), bytes.to_vec());
            Ok(())
        }
        fn committed_target_bytes(&self, target_path: &str) -> Option<Vec<u8>> {
            if self.quarantined.contains(target_path) {
                return None;
            }
            self.targets.get(target_path).cloned()
        }
        fn write_target(&mut self, target_path: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
            if self.fail_target_write {
                return Err(err(MIGRATION_TARGET_WRITE_FAILED, "injected target write failure"));
            }
            self.targets.insert(target_path.to_string(), bytes.to_vec());
            Ok(())
        }
        fn quarantine_target(&mut self, target_path: &str) -> Result<(), KindRegistryError> {
            self.targets.remove(target_path);
            self.quarantined.insert(target_path.to_string());
            Ok(())
        }
    }

    fn migration_request() -> MigrationRequestV1 {
        MigrationRequestV1 {
            migration_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into(),
            source_application_id: "legacy-notes".into(),
            source_snapshot: celld_state_raw(&["legacy-notes"]),
            source_revision: 0,
            target_application_id: "wasm-notes".into(),
            target_bytes: br#"{"controlRevision":7,"runtimeKind":"wasm","schemaVersion":2}"#.to_vec(),
            target_revision: 7,
            now_epoch_millis: T0,
        }
    }

    // -- digest/记录 golden 对齐 --

    #[test]
    fn binding_digests_match_ts_vectors() {
        assert_eq!(kind_binding_digest("admin", RUNTIME_KIND_CELLD, 1).unwrap(), GOLDEN_BINDING_CELLD_ADMIN);
        assert_eq!(kind_binding_digest("notes", RUNTIME_KIND_CELLD, 1).unwrap(), GOLDEN_BINDING_CELLD_NOTES);
        assert_eq!(kind_binding_digest("mcp", RUNTIME_KIND_CELLD, 1).unwrap(), GOLDEN_BINDING_CELLD_MCP);
        assert_eq!(kind_binding_digest("vector", RUNTIME_KIND_WASM, 1).unwrap(), GOLDEN_BINDING_WASM_VECTOR);
        // 独立 oracle：域前缀 + 手工 preimage 单次 SHA-256。
        let preimage = br#"{"applicationId":"admin","bindingRevision":1,"runtimeKind":"celld","schemaVersion":1}"#;
        let oracle = oracle_sha256_hex(&[b"iweb-application-kind-binding-v1\n", preimage]);
        assert_eq!(kind_binding_digest("admin", RUNTIME_KIND_CELLD, 1).unwrap(), oracle);
        assert_eq!(oracle, GOLDEN_BINDING_CELLD_ADMIN);
    }

    #[test]
    fn bootstrap_digest_matches_ts_example_vector() {
        let claims = derive_celld_claims(&["notes".to_string(), "admin".to_string()]).expect("derive");
        let mut record = KindClaimBootstrapV1 {
            schema_version: 1,
            bootstrap_revision: 1,
            source_kind: RUNTIME_KIND_CELLD.to_string(),
            control_state_raw_digest: "9".repeat(64),
            source_revision: 0,
            sorted_claims: claims,
            completion_receipt_digest: String::new(),
        };
        record.completion_receipt_digest = kind_claim_bootstrap_digest(&record).unwrap();
        assert_eq!(record.completion_receipt_digest, GOLDEN_BOOTSTRAP_EXAMPLE);
        validate_kind_claim_bootstrap(&record).expect("example record self-validates");
        // 独立 oracle：手工拼 JCS preimage（含两条 claim 的完整字节）复算。
        let admin = format!(
            r#"{{"applicationId":"admin","bindingDigest":"{GOLDEN_BINDING_CELLD_ADMIN}","bindingRevision":1,"runtimeKind":"celld"}}"#
        );
        let notes = format!(
            r#"{{"applicationId":"notes","bindingDigest":"{GOLDEN_BINDING_CELLD_NOTES}","bindingRevision":1,"runtimeKind":"celld"}}"#
        );
        let preimage = format!(
            r#"{{"bootstrapRevision":1,"controlStateRawDigest":"{}","schemaVersion":1,"sortedClaims":[{admin},{notes}],"sourceKind":"celld","sourceRevision":0}}"#,
            "9".repeat(64)
        );
        let oracle = oracle_sha256_hex(&[b"iweb-kind-claim-bootstrap-v1\n", preimage.as_bytes()]);
        assert_eq!(record.completion_receipt_digest, oracle);
        // 任何字段扰动都必须改变 receipt digest。
        record.bootstrap_revision += 1;
        assert_ne!(kind_claim_bootstrap_digest(&record).unwrap(), GOLDEN_BOOTSTRAP_EXAMPLE);
    }

    #[test]
    fn claim_validation_recomputes_digests_and_rejects_divergence() {
        let mut claim = derive_celld_claims(&["admin".to_string()]).unwrap().remove(0);
        validate_runtime_kind_claim(&claim, false).expect("valid celld claim");
        validate_runtime_kind_claim(&claim, true).expect("valid bootstrap claim");
        let mut wasm_variant = claim.clone();
        wasm_variant.runtime_kind = RUNTIME_KIND_WASM.into();
        wasm_variant.binding_digest = kind_binding_digest("admin", RUNTIME_KIND_WASM, 1).unwrap();
        assert_eq!(validate_runtime_kind_claim(&wasm_variant, true).unwrap_err().code, WASM_KIND_CLAIM_INVALID);
        claim.binding_digest = "0".repeat(64);
        assert_eq!(validate_runtime_kind_claim(&claim, false).unwrap_err().code, KIND_CLAIM_BINDING_DIGEST_MISMATCH);
        claim.binding_revision = 2;
        assert_eq!(validate_runtime_kind_claim(&claim, false).unwrap_err().code, WASM_KIND_CLAIM_INVALID);
        // index：乱序/重复 applicationId 拒绝（derive 会排序，这里显式构造乱序）。
        let mut claims = derive_celld_claims(&["admin".to_string(), "notes".to_string()]).unwrap();
        claims.reverse();
        let mut index = KindClaimIndexV1 { schema_version: 1, registry_revision: 2, claims };
        assert_eq!(validate_kind_claim_index(&index).unwrap_err().code, WASM_KIND_CLAIM_INVALID, "乱序 claim 集必须拒绝");
        index.claims.push(index.claims[0].clone());
        sort_claims(&mut index.claims);
        assert_eq!(validate_kind_claim_index(&index).unwrap_err().code, WASM_KIND_CLAIM_INVALID, "重复 applicationId 必须拒绝");
    }

    // -- bootstrap：门、幂等、崩溃重放、重推导、冲突 --

    #[test]
    fn wasm_write_path_closed_before_bootstrap() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        assert_eq!(registry.wasm_write_gate().unwrap_err().code, WASM_KIND_BOOTSTRAP_PENDING);
        let rejected = registry.register_wasm_admission(&mut store, 0, &proof_for("vector"));
        assert_eq!(rejected.unwrap_err().code, WASM_KIND_BOOTSTRAP_PENDING);
        // 未分配任何 wasm 身份或 claim：index/store 均为空。
        assert_eq!(registry.registry_revision(), 0);
        assert!(store.index_bytes().is_none());
        assert!(store.bindings.is_empty());
        assert!(store.bootstraps.is_empty());
    }

    #[test]
    fn bootstrap_commits_sorted_claims_and_is_idempotent() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let raw = celld_state_raw(&["notes", "admin"]);
        let record = registry.bootstrap_from_celld_raw(&mut store, &raw).unwrap();
        assert_eq!(record.schema_version, 1);
        assert_eq!(record.bootstrap_revision, 1);
        assert_eq!(record.source_kind, "celld");
        assert_eq!(record.source_revision, 0, "现行 celld ControlStateFile 无 controlRevision，sourceRevision 恒 0");
        assert_eq!(record.control_state_raw_digest, sha256_hex(&raw));
        assert_eq!(record.sorted_claims.len(), 2);
        assert_eq!(record.sorted_claims[0].application_id, "admin", "claim 集 bytewise 排序");
        assert_eq!(record.sorted_claims[1].application_id, "notes");
        // 两条 claim 变更 → revision 恰好 0→2（每次 mutation +1）。
        assert_eq!(registry.registry_revision(), 2);
        assert!(store.index_bytes().is_some());
        assert_eq!(store.bindings.len(), 2);
        registry.wasm_write_gate().expect("bootstrap verified opens the wasm path");
        // 幂等重放：同 raw digest 再引导不产生新记录/新 revision。
        let replay = registry.bootstrap_from_celld_raw(&mut store, &raw).unwrap();
        assert_eq!(replay, record);
        assert_eq!(registry.registry_revision(), 2);
        assert_eq!(store.bootstraps.len(), 1);
    }

    #[test]
    fn bootstrap_crash_replays_identical_claim_set() {
        let mut store = MockKindStore { fail_index_after: Some(1), ..Default::default() };
        let raw = celld_state_raw(&["admin", "notes"]);
        {
            let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
            let interrupted = registry.bootstrap_from_celld_raw(&mut store, &raw);
            assert_eq!(interrupted.unwrap_err().code, KIND_REGISTRY_STORE_IO);
            // 中断后 index 部分提交（admin 在，notes 缺）且 bootstrap 记录未写：
            // 从持久层重建的视图必须仍然关闭 wasm 写路径。
        }
        {
            let partial = WasmKernelRouteRegistryV1::load(&store).unwrap();
            assert_eq!(partial.wasm_write_gate().unwrap_err().code, WASM_KIND_BOOTSTRAP_PENDING);
            let index: KindClaimIndexV1 = serde_json::from_slice(&store.index_bytes().unwrap()).unwrap();
            assert_eq!(index.registry_revision, 1, "部分索引：只有第一个 claim 提交");
            assert_eq!(index.claims.len(), 1);
        }
        // 重启后重放：同一 source digest 推导同一 claim 集，补齐并落记录。
        store.fail_index_after = None;
        let mut recovered = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let record = recovered.bootstrap_from_celld_raw(&mut store, &raw).unwrap();
        assert_eq!(record.sorted_claims.len(), 2);
        assert_eq!(recovered.registry_revision(), 2);
        recovered.wasm_write_gate().expect("replay completes the identical claim set");
        // 与无崩溃路径结果完全一致。
        let mut clean_store = MockKindStore::default();
        let mut clean = WasmKernelRouteRegistryV1::load(&clean_store).unwrap();
        let clean_record = clean.bootstrap_from_celld_raw(&mut clean_store, &raw).unwrap();
        assert_eq!(record, clean_record);
    }

    #[test]
    fn celld_digest_change_forces_rederivation() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let raw_a = celld_state_raw(&["admin", "notes"]);
        registry.bootstrap_from_celld_raw(&mut store, &raw_a).unwrap();
        let raw_b = celld_state_raw(&["admin", "notes", "mcp"]);
        // 控制态变化：已验证记录失效，wasm 写路径重新关闭。
        assert!(registry.celld_control_state_changed(&raw_b));
        assert_eq!(registry.wasm_write_gate().unwrap_err().code, WASM_KIND_BOOTSTRAP_PENDING);
        let rejected = registry.register_wasm_admission(&mut store, 2, &proof_for("vector"));
        assert_eq!(rejected.unwrap_err().code, WASM_KIND_BOOTSTRAP_PENDING);
        // 重推导：bootstrapRevision +1、既有 claim 幂等跳过、新 claim 提交。
        let rederived = registry.bootstrap_from_celld_raw(&mut store, &raw_b).unwrap();
        assert_eq!(rederived.bootstrap_revision, 2);
        assert_eq!(rederived.sorted_claims.len(), 3);
        assert_eq!(registry.registry_revision(), 3, "只对新 mcp claim +1");
        assert_eq!(store.bootstraps.len(), 2);
        registry.wasm_write_gate().expect("re-derivation reopens the wasm path");
        // 同 digest 的重复 bootstrap 记录（同 claim 集）不构成分歧。
        WasmKernelRouteRegistryV1::load(&store).unwrap();
    }

    #[test]
    fn same_name_wasm_admission_after_bootstrap_rejected() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["admin"])).unwrap();
        let rejected = registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof_for("admin"));
        assert_eq!(rejected.unwrap_err().code, APPLICATION_RUNTIME_KIND_CONFLICT);
        // celld 绑定原样保留：claim/digest/revision 均未动，wasm registry 无行。
        let claim = registry.claim("admin").unwrap().clone();
        assert_eq!(claim.runtime_kind, "celld");
        assert_eq!(claim.binding_digest, GOLDEN_BINDING_CELLD_ADMIN);
        assert_eq!(registry.registry_revision(), 1);
        assert!(registry.records().applications.is_empty());
    }

    #[test]
    fn bootstrap_records_disagree_enter_split_brain() {
        let mut store = MockKindStore::default();
        // 两条同 source digest、不同 claim 集的自洽记录（digest 各自复算通过）。
        for (revision, ids) in [(1u64, &["admin"][..]), (2u64, &["admin", "notes"][..])] {
            let mut record = KindClaimBootstrapV1 {
                schema_version: 1,
                bootstrap_revision: revision,
                source_kind: RUNTIME_KIND_CELLD.to_string(),
                control_state_raw_digest: "9".repeat(64),
                source_revision: 0,
                sorted_claims: derive_celld_claims(&ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()).unwrap(),
                completion_receipt_digest: String::new(),
            };
            record.completion_receipt_digest = kind_claim_bootstrap_digest(&record).unwrap();
            store.write_bootstrap(revision, &jcs_bytes(&record).unwrap()).unwrap();
        }
        let error = WasmKernelRouteRegistryV1::load(&store).unwrap_err();
        assert_eq!(error.code, APPLICATION_KIND_SPLIT_BRAIN);
    }

    #[test]
    fn bootstrap_rejects_index_tampering_and_missing_entries() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let raw = celld_state_raw(&["admin", "notes"]);
        registry.bootstrap_from_celld_raw(&mut store, &raw).unwrap();
        // 场景 A：已验证记录对应的 index 缺 claim（celld registry entry 缺席）→ split-brain。
        let mut tampered: KindClaimIndexV1 = serde_json::from_slice(&store.index_bytes().unwrap()).unwrap();
        tampered.claims.truncate(1);
        store.write_index(&jcs_bytes(&tampered).unwrap()).unwrap();
        let mut reloaded = WasmKernelRouteRegistryV1::load(&store).unwrap();
        assert_eq!(reloaded.bootstrap_from_celld_raw(&mut store, &raw).unwrap_err().code, APPLICATION_KIND_SPLIT_BRAIN);
        // 场景 B：index 已对某 app 写入 wasm claim 后，bootstrap 又要从 celld 推导
        // 同名 claim → 绝不覆盖 → split-brain。
        let mut store_b = MockKindStore::default();
        let mut registry_b = WasmKernelRouteRegistryV1::load(&store_b).unwrap();
        registry_b.bootstrap_from_celld_raw(&mut store_b, &celld_state_raw(&["admin"])).unwrap();
        registry_b.claim_runtime_kind(&mut store_b, "vector", RUNTIME_KIND_WASM, 1).unwrap();
        let raw_c = celld_state_raw(&["admin", "vector"]);
        let mut registry_c = WasmKernelRouteRegistryV1::load(&store_b).unwrap();
        let error = registry_c.bootstrap_from_celld(&mut store_b, &raw_c, &["admin".to_string(), "vector".to_string()]).unwrap_err();
        assert_eq!(error.code, APPLICATION_KIND_SPLIT_BRAIN);
    }

    // -- kind-claim CAS：幂等、CAS 冲突、kind 终身绑定 --

    #[test]
    fn kind_claim_cas_conflict_and_idempotent_retry() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["admin"])).unwrap();
        let base = registry.registry_revision();
        // 期望 revision 过期 → CAS 拒绝且零写入。
        let stale = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, base - 1);
        assert_eq!(stale.unwrap_err().code, KIND_REGISTRY_REVISION_CONFLICT);
        assert_eq!(registry.registry_revision(), base);
        assert!(registry.claim("vector").is_none());
        // 正确期望 → 创建（revision 恰好 +1）。
        let created = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, base).unwrap();
        assert!(created.created);
        assert_eq!(registry.registry_revision(), base + 1);
        assert_eq!(created.claim.binding_digest, GOLDEN_BINDING_WASM_VECTOR);
        // 同 kind 幂等重试（即使带旧期望值）：零写入零 revision 变更。
        let retry = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, base).unwrap();
        assert!(!retry.created);
        assert_eq!(retry.claim, created.claim);
        assert_eq!(registry.registry_revision(), base + 1);
        // 反向：wasm-bound ID 提交给 celld → 冲突，绑定不变。
        let reverse = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_CELLD, base + 1);
        assert_eq!(reverse.unwrap_err().code, APPLICATION_RUNTIME_KIND_CONFLICT);
        assert_eq!(registry.claim("vector").unwrap().runtime_kind, "wasm");
        // register 全路径幂等：claim + row 重复注册返回同一行。
        let proof = proof_for("vector");
        let row = registry.register_wasm_admission(&mut store, base, &proof).unwrap();
        let again = registry.register_wasm_admission(&mut store, base, &proof).unwrap();
        assert_eq!(row, again);
        assert_eq!(registry.records().applications["vector"].versions.len(), 1);
        assert_eq!(registry.registry_revision(), base + 1);
    }

    // -- 恢复：中断重放、孤儿 quarantine、split-brain --

    #[test]
    fn interrupted_claim_without_row_replays_byte_identical_transaction() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["admin"])).unwrap();
        let expected = registry.registry_revision();
        let proof = proof_for("vector");
        // 模拟崩溃：claim 已提交、kind-specific row 未写。
        registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, expected).unwrap();
        assert!(registry.records().applications.is_empty());
        // 恢复：byte-identical owner 事务（同 proof + 同 expected revision）幂等补全。
        let pending = vec![PendingKindTransaction { expected_kind_registry_revision: expected, proof: proof.clone() }];
        let report = registry.recover(&mut store, &[], &pending).unwrap();
        assert_eq!(report.replayed, vec!["vector".to_string()]);
        assert!(report.quarantined_claims.is_empty() && report.quarantined_rows.is_empty());
        assert_eq!(registry.records().applications["vector"].versions[0].version_id, proof.version_id);
        assert!(matches!(registry.records().applications["vector"].active, WasmActivePointerV1::Unavailable { .. }));
    }

    #[test]
    fn orphan_claim_and_orphan_row_are_quarantined() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["admin"])).unwrap();
        // 孤儿 claim（无 row、无 pending 事务）：quarantine，不得成为 active。
        registry.claim_runtime_kind(&mut store, "orphan-claim", RUNTIME_KIND_WASM, registry.registry_revision()).unwrap();
        // 孤儿 row（直接投影，无全局 claim——模拟跨层泄漏）。
        registry.records.insert_admitted(&proof_for("orphan-row")).unwrap();
        let report = registry.recover(&mut store, &[], &[]).unwrap();
        assert_eq!(report.quarantined_claims, vec!["orphan-claim".to_string()]);
        assert_eq!(report.quarantined_rows, vec!["orphan-row".to_string()]);
        // 隔离后任何写路径 fail-closed，等 owner 修复。
        assert_eq!(registry.claim_runtime_kind(&mut store, "orphan-claim", RUNTIME_KIND_WASM, registry.registry_revision()).unwrap_err().code, APPLICATION_KIND_SPLIT_BRAIN);
        assert_eq!(registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof_for("orphan-row")).unwrap_err().code, APPLICATION_KIND_SPLIT_BRAIN);
        assert!(registry.is_quarantined("orphan-claim").is_some());
    }

    #[test]
    fn two_registries_claim_same_id_after_recovery_split_brain() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["admin"])).unwrap();
        // wasm registry 出现与 celld 同名 "admin" 的行（模拟崩溃后两 registry 都主张）。
        registry.records.insert_admitted(&proof_for("admin")).unwrap();
        let before = registry.index().clone();
        let error = registry.recover(&mut store, &["admin".to_string()], &[]).unwrap_err();
        assert_eq!(error.code, APPLICATION_KIND_SPLIT_BRAIN);
        // 绝不启发式选边：索引与记录状态原样保留，只 fence 流量。
        assert_eq!(registry.index().clone(), before);
        assert!(registry.records().applications.contains_key("admin"));
    }

    #[test]
    fn binding_index_disagreement_split_brain() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["admin"])).unwrap();
        // 篡改 binding 文件（合法 JCS 但 revision 与 index 分歧）。
        let mut binding: KindClaimBindingV1 = serde_json::from_slice(&store.binding_bytes("admin").unwrap()).unwrap();
        binding.binding_revision = 3;
        store.write_binding("admin", &jcs_bytes(&binding).unwrap()).unwrap();
        let error = registry.recover(&mut store, &[], &[]).unwrap_err();
        assert_eq!(error.code, APPLICATION_KIND_SPLIT_BRAIN);
        // 缺失 binding 文件则按 claim 确定性重建（digest 是纯函数）。
        store.bindings.remove("admin");
        registry.recover(&mut store, &[], &[]).unwrap();
        let rebuilt: KindClaimBindingV1 = serde_json::from_slice(&store.binding_bytes("admin").unwrap()).unwrap();
        assert_eq!(rebuilt.binding_digest, GOLDEN_BINDING_CELLD_ADMIN);
    }

    #[test]
    fn supervisor_projection_missing_record_rejected_and_pointer_retained() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["admin"])).unwrap();
        let proof = proof_for("vector");
        registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof).unwrap();
        let pointer_before = registry.records().applications["vector"].active.clone();
        // 未知版本 → 拒绝。
        let unknown = registry.check_wasm_route_projection("vector", &format!("{}-9", "b".repeat(64)), None);
        assert_eq!(unknown.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        // 已知版本但缺 admission-proof 引用 → 拒绝。
        let missing_ref = registry.check_wasm_route_projection("vector", &proof.version_id, None);
        assert_eq!(missing_ref.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        let wrong_ref = registry.check_wasm_route_projection("vector", &proof.version_id, Some("admission-proof/other/x"));
        assert_eq!(wrong_ref.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        // 未知应用 → 拒绝。
        let unknown_app = registry.check_wasm_route_projection("ghost", &proof.version_id, None);
        assert_eq!(unknown_app.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        // 完整引用 → 通过；active 指针全程未变。
        registry.check_wasm_route_projection("vector", &proof.version_id, Some(&format!("admission-proof/vector/{}", proof.version_id))).unwrap();
        assert_eq!(registry.records().applications["vector"].active, pointer_before);
    }

    // -- migration：happy、幂等、冲突、崩溃、quarantine --

    fn bootstrapped_registry() -> (MockKindStore, WasmKernelRouteRegistryV1) {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.bootstrap_from_celld_raw(&mut store, &celld_state_raw(&["legacy-notes", "admin"])).unwrap();
        (store, registry)
    }

    #[test]
    fn migration_commits_with_receipt_and_replays_idempotently() {
        let (_kind_store, registry) = bootstrapped_registry();
        let mut store = MockMigrationStore::default();
        let receipt = registry.commit_migration(&mut store, &migration_request()).unwrap();
        assert_eq!(receipt.schema_version, 1);
        assert_eq!(receipt.migration_id, "018f1e2c-3d4b-7a5e-9f01-23456789abcd");
        assert_eq!(receipt.source_kind, "celld");
        assert_eq!(receipt.target_kind, "wasm");
        assert_eq!(receipt.source_application_id, "legacy-notes");
        assert_eq!(receipt.target_application_id, "wasm-notes", "跨 kind 迁移必须换 applicationId");
        assert_eq!(receipt.source_revision, 0, "现行 celld ControlStateFile 无 revision → sourceRevision 0");
        assert_eq!(receipt.source_digest, sha256_hex(&celld_state_raw(&["legacy-notes"])));
        assert_eq!(receipt.target_revision, 7);
        assert_eq!(receipt.target_digest, sha256_hex(&migration_request().target_bytes));
        let record = store.record(&receipt.migration_id).unwrap();
        assert_eq!(record.status, "committed");
        assert_eq!(record.receipt_ref, format!("migration-receipt/{}", receipt.migration_id));
        assert_eq!(store.receipts.len(), 1);
        // 字节一致重放：返回原 receipt，不写第二份。
        let replay = registry.commit_migration(&mut store, &migration_request()).unwrap();
        assert_eq!(replay, receipt);
        assert_eq!(store.receipts.len(), 1);
        // 幂等零残留：kind 索引/registry 不被迁移触碰。
        assert_eq!(registry.claim("wasm-notes"), None);
        assert!(registry.records().applications.is_empty());
    }

    #[test]
    fn migration_cross_kind_same_id_and_celld_bound_target_rejected() {
        let (_kind_store, registry) = bootstrapped_registry();
        let mut store = MockMigrationStore::default();
        let mut same_id = migration_request();
        same_id.target_application_id = same_id.source_application_id.clone();
        let rejected = registry.commit_migration(&mut store, &same_id);
        assert_eq!(rejected.unwrap_err().code, MIGRATION_CROSS_KIND_IDENTITY_INVALID);
        // target 已 celld-bound：不写 target registry 也不写 active 指针。
        let mut celld_target = migration_request();
        celld_target.source_application_id = "beta".into();
        celld_target.source_snapshot = celld_state_raw(&["beta"]);
        celld_target.target_application_id = "admin".into();
        let conflict = registry.commit_migration(&mut store, &celld_target);
        assert_eq!(conflict.unwrap_err().code, APPLICATION_RUNTIME_KIND_CONFLICT);
        assert!(store.migrations.is_empty());
        assert!(store.targets.is_empty());
        assert!(registry.records().applications.is_empty());
    }

    #[test]
    fn migration_source_conflict_quarantines_and_preserves_routes() {
        let (_kind_store, registry) = bootstrapped_registry();
        let mut store = MockMigrationStore::default();
        // 既有同源 (kind, app, revision) 的在途记录，source digest 不同。
        let request = migration_request();
        let stale = MigrationRecordV1 {
            schema_version: 1,
            migration_id: "018f1e2c-3d4b-7a5e-9f01-23456789ffff".into(),
            source_kind: "celld".into(),
            source_application_id: request.source_application_id.clone(),
            source_path: MIGRATION_SOURCE_PATH.into(),
            source_revision: request.source_revision,
            source_digest: "1".repeat(64),
            target_kind: "wasm".into(),
            target_application_id: request.target_application_id.clone(),
            target_path: MIGRATION_TARGET_PATH.into(),
            target_digest: "2".repeat(64),
            status: "started".into(),
            receipt_ref: "migration-receipt/018f1e2c-3d4b-7a5e-9f01-23456789ffff".into(),
            started_at: format_rfc3339_utc_millis(T0 - 1_000),
            completed_at: None,
        };
        store.write_migration(&stale.migration_id, &jcs_bytes(&stale).unwrap()).unwrap();
        store.write_target(MIGRATION_TARGET_PATH, b"partial").unwrap();
        let conflict = registry.commit_migration(&mut store, &request);
        assert_eq!(conflict.unwrap_err().code, MIGRATION_SOURCE_CONFLICT);
        // 任何 target 被隔离；在途记录改写为 rolled-back；active 指针不变。
        assert!(store.quarantined.contains(MIGRATION_TARGET_PATH));
        assert_eq!(store.record(&stale.migration_id).unwrap().status, "rolled-back");
        assert!(registry.records().applications.is_empty());
        // 同 revision 不同目标 ID 同样冲突。
        let mut other_target = migration_request();
        other_target.migration_id = "018f1e2c-3d4b-7a5e-9f01-23456789eeee".into();
        other_target.target_application_id = "wasm-other".into();
        let committed_first = registry.commit_migration(&mut store, &other_target);
        // 源 digest 未变、目标不同 → 仍按 source conflict 处理（本测试里源 digest 一致，
        // 目标不同）。
        assert_eq!(committed_first.unwrap_err().code, MIGRATION_SOURCE_CONFLICT);
    }

    #[test]
    fn migration_crash_after_target_completes_the_one_receipt() {
        let (_kind_store, registry) = bootstrapped_registry();
        let mut store = MockMigrationStore::default();
        let request = migration_request();
        // 注入 receipt 写失败：target 已落、记录 committed、receipt 缺失。
        store.fail_receipt_write = true;
        let first = registry.commit_migration(&mut store, &request);
        assert_eq!(first.unwrap_err().code, KIND_REGISTRY_STORE_IO);
        assert_eq!(store.record(&request.migration_id).unwrap().status, "committed");
        assert!(store.receipt_bytes(&request.migration_id).is_none());
        // 重试：重算 target digest 匹配 → 补写唯一 receipt（字节一致）。
        store.fail_receipt_write = false;
        let recovered = registry.commit_migration(&mut store, &request).unwrap();
        assert_eq!(store.receipts.len(), 1);
        // 再重放一次：直接返回该 receipt（幂等键不含 receipt 本身）。
        let replay = registry.commit_migration(&mut store, &request).unwrap();
        assert_eq!(recovered, replay);
        // receipt 丢失后的重试同样收敛。
        store.receipts.remove(&request.migration_id);
        let again = registry.commit_migration(&mut store, &request).unwrap();
        assert_eq!(again, recovered);
    }

    #[test]
    fn migration_target_digest_mismatch_quarantines_target() {
        let (_kind_store, registry) = bootstrapped_registry();
        let mut store = MockMigrationStore::default();
        let request = migration_request();
        registry.commit_migration(&mut store, &request).unwrap();
        // 模拟落盘后 target 被篡改 + receipt 丢失：恢复重算 digest 不匹配 → quarantine。
        store.targets.insert(MIGRATION_TARGET_PATH.to_string(), br#"{"controlRevision":8,"runtimeKind":"wasm","schemaVersion":2}"#.to_vec());
        store.receipts.remove(&request.migration_id);
        let mismatch = registry.commit_migration(&mut store, &request);
        assert_eq!(mismatch.unwrap_err().code, MIGRATION_TARGET_DIGEST_MISMATCH);
        assert!(store.quarantined.contains(MIGRATION_TARGET_PATH));
        assert_eq!(store.record(&request.migration_id).unwrap().status, "rolled-back");
        assert!(store.receipt_bytes(&request.migration_id).is_none());
        // active 指针不变（迁移从不触碰任何 active 指针）。
        assert!(registry.records().applications.is_empty());
    }

    #[test]
    fn migration_invalid_target_rolls_back_without_writing() {
        let (_kind_store, registry) = bootstrapped_registry();
        let mut store = MockMigrationStore::default();
        let mut request = migration_request();
        // 非 JCS 字节（多余空格）→ 形状校验失败：rolled-back、无 target。
        request.target_bytes = br#"{ "controlRevision":7, "runtimeKind":"wasm", "schemaVersion":2 }"#.to_vec();
        let invalid = registry.commit_migration(&mut store, &request);
        assert_eq!(invalid.unwrap_err().code, MIGRATION_TARGET_INVALID);
        assert_eq!(store.record(&request.migration_id).unwrap().status, "rolled-back");
        assert!(store.targets.is_empty());
        // controlRevision 与请求不一致 → 同样拒绝（换新 migrationId 重试）。
        let mut request2 = migration_request();
        request2.migration_id = "018f1e2c-3d4b-7a5e-9f01-23456789dddd".into();
        request2.target_bytes = br#"{"controlRevision":8,"runtimeKind":"wasm","schemaVersion":2}"#.to_vec();
        let mismatched = registry.commit_migration(&mut store, &request2);
        assert_eq!(mismatched.unwrap_err().code, MIGRATION_TARGET_INVALID);
    }

    #[test]
    fn migration_target_write_failure_leaves_source_untouched() {
        let (_kind_store, registry) = bootstrapped_registry();
        let mut store = MockMigrationStore { fail_target_write: true, ..Default::default() };
        let request = migration_request();
        let failed = registry.commit_migration(&mut store, &request);
        assert_eq!(failed.unwrap_err().code, MIGRATION_TARGET_WRITE_FAILED);
        assert_eq!(store.record(&request.migration_id).unwrap().status, "rolled-back");
        assert!(store.committed_target_bytes(MIGRATION_TARGET_PATH).is_none());
        // 同 migrationId 重试：rolled-back 是终态，owner 必须换新 ID。
        store.fail_target_write = false;
        let retry = registry.commit_migration(&mut store, &request);
        assert_eq!(retry.unwrap_err().code, MIGRATION_TERMINAL_ROLLED_BACK);
        // 新 ID 从零完成（源快照未被触碰）。
        let mut fresh = migration_request();
        fresh.migration_id = "018f1e2c-3d4b-7a5e-9f01-23456789bbbb".into();
        registry.commit_migration(&mut store, &fresh).unwrap();
    }

    // -- parser 隔离（celld v1 形状与 wasm v2 形状互不解析） --

    #[test]
    fn celld_parser_and_bootstrap_reject_wasm_control_state() {
        let wasm_v2 = br#"{"schemaVersion":2,"runtimeKind":"wasm","controlRevision":0,"applications":{},"commandOutbox":[],"migration":{"source":"celld-control-state-v1","status":"not-started","sourceDigest":null,"completedAt":null}}"#;
        assert!(serde_json::from_slice::<crate::control::ControlStateFile>(wasm_v2).is_err(), "celld parser 必须拒绝 wasm v2 形状");
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let rejected = registry.bootstrap_from_celld_raw(&mut store, wasm_v2);
        assert_eq!(rejected.unwrap_err().code, WASM_KIND_CLAIM_INVALID);
        // celld v1 形状可解析（无 controlRevision 字段），bootstrap sourceRevision 恒 0。
        let raw = celld_state_raw(&["admin"]);
        assert!(serde_json::from_slice::<crate::control::ControlStateFile>(&raw).is_ok());
        let record = registry.bootstrap_from_celld_raw(&mut store, &raw).unwrap();
        assert_eq!(record.source_revision, 0);
    }

    // -- 文件持久化存储（kind-registry / migration 目录） --

    #[test]
    fn file_stores_round_trip_kind_registry_and_bootstrap() {
        let dir = std::env::temp_dir().join("iweb-kernel-wasm-kind-registry-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.join("application-kind-registry-v1");
        let raw = celld_state_raw(&["notes", "admin"]);
        let expected_record;
        {
            let mut store = KindRegistryStoreDir::open(&root).unwrap();
            let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
            expected_record = registry.bootstrap_from_celld_raw(&mut store, &raw).unwrap();
            let proof = proof_for("vector");
            registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof).unwrap();
        }
        {
            let mut store = KindRegistryStoreDir::open(&root).unwrap();
            let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
            // 重启后 bootstrap 需重新验证（load 不自动放行 wasm 写路径）。
            assert_eq!(registry.wasm_write_gate().unwrap_err().code, WASM_KIND_BOOTSTRAP_PENDING);
            let replay = registry.bootstrap_from_celld_raw(&mut store, &raw).unwrap();
            assert_eq!(replay, expected_record, "崩溃/重启后幂等重放同一条 bootstrap 记录");
            assert_eq!(registry.registry_revision(), 3);
            assert_eq!(registry.claim("vector").unwrap().runtime_kind, "wasm");
            let index: KindClaimIndexV1 = serde_json::from_slice(&store.index_bytes().unwrap()).unwrap();
            assert_eq!(index.claims.len(), 3);
            assert_eq!(index.claims[0].application_id, "admin");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_migration_store_round_trip_and_quarantine() {
        let dir = std::env::temp_dir().join("iweb-kernel-wasm-kind-migration-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = MigrationStoreDir::open(&dir).unwrap();
        let target_path = dir.join("wasm-control-state-v2.json").to_string_lossy().into_owned();
        let bytes = br#"{"controlRevision":7,"runtimeKind":"wasm","schemaVersion":2}"#.to_vec();
        store.write_target(&target_path, &bytes).unwrap();
        assert_eq!(store.committed_target_bytes(&target_path).unwrap(), bytes);
        store.quarantine_target(&target_path).unwrap();
        assert!(store.committed_target_bytes(&target_path).is_none(), "隔离后目标不可再读");
        let quarantined = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .find(|entry| entry.file_name().to_string_lossy().contains(".quarantined-"));
        assert!(quarantined.is_some(), "隔离即改名移出可路由位置，绝不删除原始字节");
        // migration 记录与 receipt 的文件往返。
        let receipt = receipt_from_record(
            &MigrationRecordV1 {
                schema_version: 1,
                migration_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".into(),
                source_kind: "celld".into(),
                source_application_id: "legacy-notes".into(),
                source_path: MIGRATION_SOURCE_PATH.into(),
                source_revision: 0,
                source_digest: "0".repeat(64),
                target_kind: "wasm".into(),
                target_application_id: "wasm-notes".into(),
                target_path: MIGRATION_TARGET_PATH.into(),
                target_digest: "1".repeat(64),
                status: "committed".into(),
                receipt_ref: "migration-receipt/018f1e2c-3d4b-7a5e-9f01-23456789abcd".into(),
                started_at: format_rfc3339_utc_millis(T0),
                completed_at: Some(format_rfc3339_utc_millis(T0 + 1)),
            },
            7,
        )
        .unwrap();
        store.write_receipt(&receipt.migration_id, &jcs_bytes(&receipt).unwrap()).unwrap();
        let round_trip: MigrationReceiptV1 =
            parse_canonical(&store.receipt_bytes(&receipt.migration_id).unwrap(), MIGRATION_RECORD_INVALID, "migration receipt").unwrap();
        assert_eq!(round_trip, receipt);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
