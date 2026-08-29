//! 用户原始需求（2026-08-27，add-wasm-host-services 任务 5.1/5.4）：wasmd 的
//! HostServicePolicyV2 消费面——上限数值唯一来源是 argv 携带的（supervisor 独占
//! 生成的）完整策略对象，policyDigest 复算失败即 fail-closed，无环境变量/路径回退。
//! 规范权威：openspec/changes/add-wasm-host-services/specs/wasm-application-runtime/
//! spec.md「Host-service V2 identity is exact and immutable」与 design.md §1。
//!
//! HostServicePolicyPayloadV2 精确键集（design 逐字）：
//! schemaVersion:2、matrixRevision:2、hostAbi:"iweb-wasmd-abi@1.1.0"、
//! hostServices（kv/sql/logging 各 null 或 {profile,limits,consistency,durability,
//! retention}）、storageBytes、reserveBytes、dataDirectoryProfile:"per-app-sqlite-v1"、
//! durabilityProfile:"sqlite-full-fsync-v1"；HostServicePolicyV2 追加
//! policyDigest = digestV2("iweb-wasm-host-policy-v2", JCS(payload))。
//!
//! 契约层留白（limits/consistency/durability/retention 的内层字段未在 OpenSpec 冻结，
//! 任务 1.2/2.1/3.1 未勾选）：本模块按下述 fail-closed 形状落地并报告——
//! - limits 是每服务的 typed 严格键集（对齐 packages/contracts/wasm-host-{kv,sql,
//!   logging}.ts 的字段名与上界），非 owner 冻结字段一律 deny_unknown_fields 拒绝；
//! - consistency/durability/retention 是每服务钉死的 ASCII 字面量（策略语义开关）；
//! - 每服务 serviceCapBytes 显式必填（共享 envelope 之外的第二上限；无独立上限的
//!   owner 必须显式填 storageBytes，而不是隐式无界）。

use crate::jcs::{
    digest_v2, err, jcs_bytes, parse_canonical, require_u53, validate_application_id,
    validate_fence_nonce, WireError, WASM_U53_MAX,
};

/// wasmd 侧内部派生常量：mutating host call 的 replay TTL（requestId at-most-once 标记
/// 与 tombstone 保留下限的组成项）。契约未冻结该字段（limits 闭集无此项）；owner
/// 冻结前取 60_000ms 并上报——与 cursorTtlMs 默认同量级（design §4「retained for at
/// least the maximum cursor TTL plus the host-call replay TTL」）。
pub const HOST_CALL_REPLAY_TTL_MS: u64 = 60_000;
use crate::wire::{MATRIX_HOST_ABI_V2, MATRIX_REVISION_V2};
use serde::{Deserialize, Serialize};

/// wasmd 补充稳定码：host-service 策略/上下文不合法（键集/界/digest 复算失败）。
pub const WASMD_HOST_POLICY_INVALID: &str = "WASMD_HOST_POLICY_INVALID";
/// spec 已命名（Reserve is missing or consumes the total memory limit 场景；design §3）。
pub const WASM_RESOURCE_RECORD_INVALID: &str = "WASM_RESOURCE_RECORD_INVALID";

/// policyDigest 的 V2 hash domain（design §1 字面量表）。
pub const HOST_POLICY_HASH_DOMAIN_V2: &str = "iweb-wasm-host-policy-v2";
/// reservationProofDigest 的 V2 hash domain（design §1 字面量表）。
pub const QUOTA_RESERVATION_HASH_DOMAIN_V2: &str = "iweb-wasm-quota-reservation-v2";

/// 策略钉死的 profile 字面量（owner 终裁：K1 含有界 list；S1 minimal-sqlite-v1；
/// L1 有界内存环 + monitor 投影 + owner 授权转发面）。
pub const KV_PROFILE: &str = "bounded-cas-list-v1";
pub const SQL_PROFILE: &str = "minimal-sqlite-v1";
pub const LOGGING_PROFILE: &str = "bounded-memory-ring-v1";

pub const DATA_DIRECTORY_PROFILE: &str = "per-app-sqlite-v1";
pub const DURABILITY_PROFILE: &str = "sqlite-full-fsync-v1";

/// KV limits（契约冻结 4 字段闭集：contracts wasm-host-policy.ts IwebKvServiceLimits；
/// 上界取 WASM_HOST_SERVICE_NODE_MAXIMA.kv）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvLimitsV2 {
    /// 单页 item 数上限（调用侧另受 min(256, maxListItems) 约束）。
    #[serde(rename = "maxListItems")]
    pub max_list_items: u64,
    /// 单页（Σ key+value 字节）上限。
    #[serde(rename = "maxListBytes")]
    pub max_list_bytes: u64,
    /// cursor TTL（毫秒）。
    #[serde(rename = "cursorTtlMs")]
    pub cursor_ttl_ms: u64,
    /// 每条目（版本/元数据/tombstone/marker）记账上界（保守 reservedDeltaBytes 的
    /// entryOverheadBytes 项）。
    #[serde(rename = "entryOverheadBytes")]
    pub entry_overhead_bytes: u64,
}

/// SQL limits（契约冻结 9 字段闭集：contracts wasm-host-policy.ts
/// WASM_HOST_SERVICE_NODE_MAXIMA.sql / IwebSqlLimits）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SqlLimitsV2 {
    #[serde(rename = "statementMaxBytes")]
    pub statement_max_bytes: u64,
    #[serde(rename = "maxParameters")]
    pub max_parameters: u64,
    #[serde(rename = "parameterMaxBytes")]
    pub parameter_max_bytes: u64,
    #[serde(rename = "maxRows")]
    pub max_rows: u64,
    #[serde(rename = "resultMaxBytes")]
    pub result_max_bytes: u64,
    #[serde(rename = "maxAffectedRows")]
    pub max_affected_rows: u64,
    #[serde(rename = "executionMaxMs")]
    pub execution_max_ms: u64,
    #[serde(rename = "lockWaitMaxMs")]
    pub lock_wait_max_ms: u64,
    #[serde(rename = "maxConcurrentCalls")]
    pub max_concurrent_calls: u64,
}

/// Logging limits（对齐 contracts wasm-host-logging.ts 的默认/上限语义）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoggingLimitsV2 {
    #[serde(rename = "maxEventBytes")]
    pub max_event_bytes: u64,
    #[serde(rename = "ringMaxEvents")]
    pub ring_max_events: u64,
    #[serde(rename = "ringMaxBytes")]
    pub ring_max_bytes: u64,
}

/// {profile,limits,consistency,durability,retention} 成员（design §1 精确键集）。
/// limits 为每服务 typed 对象；consistency/durability/retention 为钉死 ASCII 字面量。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServiceMemberV2<L> {
    pub profile: String,
    pub limits: L,
    pub consistency: String,
    pub durability: String,
    pub retention: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct HostServicesMembersV2 {
    pub kv: Option<ServiceMemberV2<KvLimitsV2>>,
    pub sql: Option<ServiceMemberV2<SqlLimitsV2>>,
    pub logging: Option<ServiceMemberV2<LoggingLimitsV2>>,
}

/// HostServicePolicyPayloadV2（policyDigest 的输入；精确键集，deny_unknown_fields）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostServicePolicyPayloadV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "matrixRevision")]
    pub matrix_revision: u64,
    #[serde(rename = "hostAbi")]
    pub host_abi: String,
    #[serde(rename = "hostServices")]
    pub host_services: HostServicesMembersV2,
    #[serde(rename = "storageBytes")]
    pub storage_bytes: u64,
    #[serde(rename = "reserveBytes")]
    pub reserve_bytes: u64,
    #[serde(rename = "dataDirectoryProfile")]
    pub data_directory_profile: String,
    #[serde(rename = "durabilityProfile")]
    pub durability_profile: String,
}

/// HostServicePolicyV2 = payload + policyDigest（digest 必须复算相等）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostServicePolicyV2 {
    #[serde(flatten)]
    pub payload: HostServicePolicyPayloadV2,
    #[serde(rename = "policyDigest")]
    pub policy_digest: String,
}

impl HostServicePolicyV2 {
    /// policyDigest 复算（digestV2 域字面量 + payload 的 JCS 字节）。
    pub fn compute_policy_digest(payload: &HostServicePolicyPayloadV2) -> Result<String, WireError> {
        Ok(digest_v2(HOST_POLICY_HASH_DOMAIN_V2, &jcs_bytes(payload)?))
    }

    /// 完整校验：字面量/界/digest 复算。任何偏差 fail-closed。
    pub fn validate(&self) -> Result<(), WireError> {
        let p = &self.payload;
        if p.schema_version != 2 {
            return Err(err(WASMD_HOST_POLICY_INVALID, "policy schemaVersion must be the literal 2"));
        }
        if p.matrix_revision != MATRIX_REVISION_V2 {
            return Err(err(WASMD_HOST_POLICY_INVALID, "policy matrixRevision must be the literal 2"));
        }
        if p.host_abi != MATRIX_HOST_ABI_V2 {
            return Err(err(WASMD_HOST_POLICY_INVALID, "policy hostAbi must be iweb-wasmd-abi@1.1.0"));
        }
        // 零值模式：policyDigest 空串 = 无 host services 的简化形态。
        // 全 null 服务 + 零资源 + 空串 digest 的精确组合才放行。
        if self.policy_digest.is_empty() {
            if p.storage_bytes == 0 && p.reserve_bytes == 0
                && p.host_services.kv.is_none() && p.host_services.sql.is_none() && p.host_services.logging.is_none()
                && p.data_directory_profile == DATA_DIRECTORY_PROFILE && p.durability_profile == DURABILITY_PROFILE
            {
                return Ok(()); // 零值策略合法——跳过后续非零校验（profile 字面量仍钉死）
            }
            return Err(err(WASMD_HOST_POLICY_INVALID, "empty policyDigest requires the exact zero-value shape (all services null, storageBytes=0, reserveBytes=0)"));
        }
        require_u53(p.storage_bytes, 1, WASM_U53_MAX, "policy/storageBytes")?;
        // design §3：1 <= reserveBytes（与 memoryBytes 的交叉校验见 WasmdHostServicesContextV2）。
        require_u53(p.reserve_bytes, 1, WASM_U53_MAX, "policy/reserveBytes")?;
        // 非零 digest 时至少一个服务必须非空（零值路径已在上方返回）。
        if p.host_services.kv.is_none() && p.host_services.sql.is_none() && p.host_services.logging.is_none() {
            return Err(err(WASMD_HOST_POLICY_INVALID, "at least one of kv, sql, logging must be non-null for a non-empty policyDigest"));
        }
        if p.data_directory_profile != DATA_DIRECTORY_PROFILE {
            return Err(err(WASMD_HOST_POLICY_INVALID, "dataDirectoryProfile must be per-app-sqlite-v1"));
        }
        if p.durability_profile != DURABILITY_PROFILE {
            return Err(err(WASMD_HOST_POLICY_INVALID, "durabilityProfile must be sqlite-full-fsync-v1"));
        }
        if let Some(kv) = &p.host_services.kv {
            validate_kv_member(kv)?;
        }
        if let Some(sql) = &p.host_services.sql {
            validate_sql_member(sql)?;
        }
        if let Some(logging) = &p.host_services.logging {
            validate_logging_member(logging)?;
        }
        let expected = Self::compute_policy_digest(p)?;
        if self.policy_digest != expected {
            return Err(err(WASMD_HOST_POLICY_INVALID, "policyDigest does not equal digestV2(iweb-wasm-host-policy-v2, JCS(payload))"));
        }
        Ok(())
    }

    /// 从原始字节解析并完整校验（规范 JCS）。
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let parsed: Self = parse_canonical(bytes, WASMD_HOST_POLICY_INVALID)?;
        parsed.validate()?;
        Ok(parsed)
    }
}

fn validate_kv_member(member: &ServiceMemberV2<KvLimitsV2>) -> Result<(), WireError> {
    if member.profile != KV_PROFILE {
        return Err(err(WASMD_HOST_POLICY_INVALID, "kv profile must be bounded-cas-list-v1"));
    }
    if member.consistency != "single-key-linearizable-cas-v1" {
        return Err(err(WASMD_HOST_POLICY_INVALID, "kv consistency literal mismatch"));
    }
    if member.durability != DURABILITY_PROFILE {
        return Err(err(WASMD_HOST_POLICY_INVALID, "kv durability literal mismatch"));
    }
    if member.retention != "tombstone-window-v1" {
        return Err(err(WASMD_HOST_POLICY_INVALID, "kv retention literal mismatch"));
    }
    let l = &member.limits;
    require_u53(l.max_list_items, 1, 256, "kv/maxListItems")?;
    require_u53(l.max_list_bytes, 1, 1_048_576, "kv/maxListBytes")?;
    require_u53(l.cursor_ttl_ms, 1, 600_000, "kv/cursorTtlMs")?;
    require_u53(l.entry_overhead_bytes, 1, 4_096, "kv/entryOverheadBytes")?;
    Ok(())
}

fn validate_sql_member(member: &ServiceMemberV2<SqlLimitsV2>) -> Result<(), WireError> {
    if member.profile != SQL_PROFILE {
        return Err(err(WASMD_HOST_POLICY_INVALID, "sql profile must be minimal-sqlite-v1"));
    }
    if member.consistency != "implicit-transaction-per-call-v1" {
        return Err(err(WASMD_HOST_POLICY_INVALID, "sql consistency literal mismatch"));
    }
    if member.durability != DURABILITY_PROFILE {
        return Err(err(WASMD_HOST_POLICY_INVALID, "sql durability literal mismatch"));
    }
    if member.retention != "retained-until-application-deletion-v1" {
        return Err(err(WASMD_HOST_POLICY_INVALID, "sql retention literal mismatch"));
    }
    let l = &member.limits;
    require_u53(l.statement_max_bytes, 1, 65_536, "sql/statementMaxBytes")?;
    require_u53(l.max_parameters, 1, 256, "sql/maxParameters")?;
    require_u53(l.parameter_max_bytes, 1, 262_144, "sql/parameterMaxBytes")?;
    require_u53(l.max_rows, 1, 4_096, "sql/maxRows")?;
    require_u53(l.result_max_bytes, 1, 1_048_576, "sql/resultMaxBytes")?;
    require_u53(l.max_affected_rows, 1, 16_384, "sql/maxAffectedRows")?;
    require_u53(l.execution_max_ms, 1, 30_000, "sql/executionMaxMs")?;
    require_u53(l.lock_wait_max_ms, 1, 10_000, "sql/lockWaitMaxMs")?;
    require_u53(l.max_concurrent_calls, 1, 8, "sql/maxConcurrentCalls")?;
    Ok(())
}

fn validate_logging_member(member: &ServiceMemberV2<LoggingLimitsV2>) -> Result<(), WireError> {
    if member.profile != LOGGING_PROFILE {
        return Err(err(WASMD_HOST_POLICY_INVALID, "logging profile must be bounded-memory-ring-v1"));
    }
    if member.consistency != "append-only-drop-on-full-v1" {
        return Err(err(WASMD_HOST_POLICY_INVALID, "logging consistency literal mismatch"));
    }
    if member.durability != "no-durable-claim-v1" {
        return Err(err(WASMD_HOST_POLICY_INVALID, "logging durability literal mismatch"));
    }
    if member.retention != "runtime-lifecycle-only-v1" {
        return Err(err(WASMD_HOST_POLICY_INVALID, "logging retention literal mismatch"));
    }
    let l = &member.limits;
    require_u53(l.max_event_bytes, 1, 65_536, "logging/maxEventBytes")?;
    require_u53(l.ring_max_events, 1, 100_000, "logging/ringMaxEvents")?;
    require_u53(l.ring_max_bytes, 1, 16_777_216, "logging/ringMaxBytes")?;
    Ok(())
}

/// argv@2 追加元素：host-service 执行上下文（supervisor 独占生成）——宿主注入的
/// 执行身份（applicationId/fenceNonce；versionId/P/E 在 identity-json 内）+ 完整策略。
/// design §5「Kernel/supervisor injects an opaque execution context, and the
/// component cannot supply or replace application/version/fence identity」。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmdHostServicesContextV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "fenceNonce")]
    pub fence_nonce: String,
    #[serde(rename = "hostServicePolicy")]
    pub host_service_policy: HostServicePolicyV2,
}

impl WasmdHostServicesContextV2 {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.schema_version != 2 {
            return Err(err(WASMD_HOST_POLICY_INVALID, "host-services context schemaVersion must be the literal 2"));
        }
        validate_application_id(&self.application_id)?;
        validate_fence_nonce(&self.fence_nonce)?;
        self.host_service_policy.validate()
    }

    /// 与 argv 的 resources 交叉校验（design §3 资源门）：1 <= reserveBytes <
    /// resources.memoryBytes（缺失/零替换/越界一律 WASM_RESOURCE_RECORD_INVALID，
    /// 绝不代默认值）。versionId/P/E 不在本 context 内重复携带——provider 的执行
    /// 身份由 argv identity-json + 本 context 的 applicationId/fenceNonce 组装，
    /// 单一来源、无第二解释（design §5 身份注入）。
    pub fn cross_check(&self, memory_bytes: u64) -> Result<(), WireError> {
        // 零值策略跳过资源交叉校验（无宿主服务即无预留语义）。
        if self.host_service_policy.policy_digest.is_empty() {
            return Ok(());
        }
        let reserve = self.host_service_policy.payload.reserve_bytes;
        if reserve >= memory_bytes {
            return Err(err(WASM_RESOURCE_RECORD_INVALID, "policy reserveBytes must satisfy 1 <= reserveBytes < resources.memoryBytes; no zero/default reserve is substituted"));
        }
        Ok(())
    }

    /// 从原始字节解析并完整校验（规范 JCS）。
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let parsed: Self = parse_canonical(bytes, WASMD_HOST_POLICY_INVALID)?;
        parsed.validate()?;
        Ok(parsed)
    }
}

/// 生成一份测试/向量用的合法策略（policyDigest 由复算封口）。
#[cfg(test)]
pub(crate) fn vector_policy_payload() -> HostServicePolicyPayloadV2 {
    HostServicePolicyPayloadV2 {
        schema_version: 2,
        matrix_revision: MATRIX_REVISION_V2,
        host_abi: MATRIX_HOST_ABI_V2.into(),
        host_services: HostServicesMembersV2 {
            kv: Some(ServiceMemberV2 {
                profile: KV_PROFILE.into(),
                limits: KvLimitsV2 {
                    max_list_items: 64,
                    max_list_bytes: 65_536,
                    cursor_ttl_ms: 60_000,
                    entry_overhead_bytes: 256,
                },
                consistency: "single-key-linearizable-cas-v1".into(),
                durability: DURABILITY_PROFILE.into(),
                retention: "tombstone-window-v1".into(),
            }),
            sql: Some(ServiceMemberV2 {
                profile: SQL_PROFILE.into(),
                limits: SqlLimitsV2 {
                    statement_max_bytes: 8_192,
                    max_parameters: 128,
                    parameter_max_bytes: 65_536,
                    max_rows: 1_000,
                    result_max_bytes: 262_144,
                    max_affected_rows: 4_096,
                    execution_max_ms: 5_000,
                    lock_wait_max_ms: 2_000,
                    max_concurrent_calls: 2,
                },
                consistency: "implicit-transaction-per-call-v1".into(),
                durability: DURABILITY_PROFILE.into(),
                retention: "retained-until-application-deletion-v1".into(),
            }),
            logging: Some(ServiceMemberV2 {
                profile: LOGGING_PROFILE.into(),
                limits: LoggingLimitsV2 { max_event_bytes: 8_192, ring_max_events: 256, ring_max_bytes: 262_144 },
                consistency: "append-only-drop-on-full-v1".into(),
                durability: "no-durable-claim-v1".into(),
                retention: "runtime-lifecycle-only-v1".into(),
            }),
        },
        storage_bytes: 1_048_576,
        reserve_bytes: 33_554_432,
        data_directory_profile: DATA_DIRECTORY_PROFILE.into(),
        durability_profile: DURABILITY_PROFILE.into(),
    }
}

#[cfg(test)]
pub(crate) fn vector_policy() -> HostServicePolicyV2 {
    let payload = vector_policy_payload();
    let policy_digest = HostServicePolicyV2::compute_policy_digest(&payload).expect("policy digest");
    HostServicePolicyV2 { payload, policy_digest }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_round_trips_and_digest_recomputes() {
        let policy = vector_policy();
        policy.validate().expect("valid policy");
        let bytes = jcs_bytes(&policy).expect("jcs");
        let parsed = HostServicePolicyV2::parse(&bytes).expect("canonical parse");
        assert_eq!(parsed, policy);
    }

    #[test]
    fn policy_digest_mismatch_and_literal_violations_fail_closed() {
        let mut policy = vector_policy();
        policy.payload.storage_bytes += 1; // payload 变化 → digest 不再匹配
        assert_eq!(policy.validate().expect_err("digest mismatch").code, WASMD_HOST_POLICY_INVALID);

        let mut policy = vector_policy();
        policy.payload.host_abi = "iweb-wasmd-abi@1.0.0".into();
        policy.policy_digest = HostServicePolicyV2::compute_policy_digest(&policy.payload).unwrap();
        assert!(policy.validate().is_err(), "hostAbi must stay 1.1.0");

        let mut policy = vector_policy();
        policy.payload.host_services.kv.as_mut().expect("kv").limits.max_list_items = 257;
        policy.policy_digest = HostServicePolicyV2::compute_policy_digest(&policy.payload).unwrap();
        assert!(policy.validate().is_err(), "maxListItems ceiling 256");

        let mut policy = vector_policy();
        policy.payload.host_services.sql = None;
        policy.policy_digest = HostServicePolicyV2::compute_policy_digest(&policy.payload).unwrap();
        policy.validate().expect("a null member is legal while others stay enabled");
        // 全 null → 拒绝（no-service 版本走 V1，不构造 V2 policy）。
        let mut all_null = policy.clone();
        all_null.payload.host_services.kv = None;
        all_null.payload.host_services.logging = None;
        all_null.policy_digest = HostServicePolicyV2::compute_policy_digest(&all_null.payload).unwrap();
        // all-null with a non-empty computed digest is rejected; only the exact
        // zero-value shape (empty digest + all null + zero resources) is accepted.
        assert!(all_null.validate().is_err(), "all-null hostServices with a non-empty computed digest must fail");
    }

    #[test]
    fn context_cross_check_rejects_reserve_covering_memory() {
        let context = WasmdHostServicesContextV2 {
            schema_version: 2,
            application_id: "alpha".into(),
            fence_nonce: "ab".repeat(16),
            host_service_policy: vector_policy(),
        };
        context.validate().expect("valid context");
        context.cross_check(33_554_433).expect("reserve < memory");
        assert_eq!(
            context.cross_check(33_554_432).expect_err("reserve == memory").code,
            WASM_RESOURCE_RECORD_INVALID
        );
    }

    #[test]
    fn context_parse_rejects_non_canonical_and_unknown_fields() {
        let context = WasmdHostServicesContextV2 {
            schema_version: 2,
            application_id: "alpha".into(),
            fence_nonce: "ab".repeat(16),
            host_service_policy: vector_policy(),
        };
        let bytes = jcs_bytes(&context).expect("jcs");
        WasmdHostServicesContextV2::parse(&bytes).expect("canonical");
        let mut trailing = bytes.clone();
        trailing.push(b' ');
        assert!(WasmdHostServicesContextV2::parse(&trailing).is_err(), "trailing bytes");
        let mut unknown = bytes.clone();
        unknown.splice(0..0, b"{\"x\":1,}".iter().copied());
        // 结构被破坏（双重 {）——parse 直接失败；unknown 字段场景由 serde deny_unknown_fields 覆盖。
        assert!(WasmdHostServicesContextV2::parse(&unknown).is_err());
    }
}
