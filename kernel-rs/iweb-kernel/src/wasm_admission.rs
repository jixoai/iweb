//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.5）：Kernel 侧 wasm 准入事务——
//! 单点提交、AdmittedVisible 谓词、admission journal、opaque commit token、
//! AdmissionProofV1、幂等 materializer receipt 与每个中断点的唯一恢复结果。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//! "Kernel-owned admission uses one visible-state predicate" 及 application-sandbox delta。
//! wire 权威：packages/contracts/wasm-package.ts / wasm-execution.ts（digest/JCS/proof 公式），
//! Rust 侧字节一致复算——JCS 按 RFC 8785（本模块值域内整数+ASCII 键），域前缀单次 SHA-256。
//!
//! 正交意图：
//! 1. digest/proof 纯函数（wasmVersionDigestV1、commitTokenHash、admissionProofDigest、
//!    materializationTarget）——与 TS 向量 golden 对齐；
//! 2. admission journal（追加式、崩溃可重放、状态机 + lease + 显式 sequence 分配器）；
//! 3. 准入事务驱动与恢复（staging→…→visible 唯一结果、fail-closed）；
//! 4. AdmittedVisible 三段一致谓词 + witness 读写抽象（object/DB/materializer trait）；
//! 5. 到 wasm 独立 registry（WasmKernelRouteRegistryV1 投影）——与 celld
//!    ControlState/VersionRecord 物理隔离，绝不写 celld 路径。
//!
//! 不可调和原因：2/3 共享同一状态机与恢复表，拆分会重引入中断点语义矛盾；
//! 1 是 2/3 的编码地基，同文件保证公式与事务不漂移。
//!
//! P0-3（add-wasm-host-services Kernel 半边，2026-08-28）：AdmissionRequest/Proof 携带
//! 可选 `hostServicePolicy`（完整 HostServicePolicyV2）——在场即 V2（service-enabled）
//! 准入：policy digest 绑定进 proof 与 materializer receipt，versionDigest 走
//! HostServiceIdentityV2 的 versionDigestV2 公式，`AdmittedVisible` 谓词要求 V2 policy
//! 在场且 digest 复算匹配（V1 证明的 JCS 字节形状不变；join 校验含 policy 全等）。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::wasm_host_services::{
    check_wasm_guest_memory_reserve, wasm_host_service_version_digest_v2, HostServiceError,
    HostServicePolicyV2,
};

// ---------------------------------------------------------------------------
// 常量、错误与名称文法（spec "Normative Encoding and Names"）
// ---------------------------------------------------------------------------

/// u53 安全整数上界（spec：0..9007199254740991，不接受浮点/负数/指数/字符串数字）。
pub const WASM_U53_MAX: u64 = 9_007_199_254_740_991;
pub const WASM_WORLD_LITERAL: &str = "wasi:http/proxy@0.2.8";
pub const WASM_HOST_ABI_LITERAL: &str = "iweb-wasmd-abi@1.0.0";
pub const WASM_MAX_EGRESS_RULES: usize = 256;

const VERSION_DIGEST_DOMAIN: &str = "iweb-wasm-version-digest-v1";
const ADMISSION_PROOF_DOMAIN: &str = "iweb-admission-proof-v1";
const COMMIT_TOKEN_DOMAIN: &str = "iweb-wasm-admission-token-v1";
const MATERIALIZER_TARGET_DOMAIN: &str = "iweb-wasm-materializer-target-v1";

/// 结构化准入错误：code 为稳定 owner 可见码（对位 contracts 的 ValidationIssue.code），
/// detail 携带路径/上下文，不包含任何秘密值。
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionError {
    pub code: &'static str,
    pub detail: String,
}

impl AdmissionError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for AdmissionError {}

// 稳定错误码（沿用 contracts 命名风格；不覆盖 spec 已命名码）。
pub const WASM_APPLICATION_ID_INVALID: &str = "WASM_APPLICATION_ID_INVALID";
pub const WASM_MANIFEST_INVALID: &str = "WASM_MANIFEST_INVALID";
pub const WASM_BINDING_INVALID: &str = "WASM_BINDING_INVALID";
pub const WASM_VERSION_ID_INVALID: &str = "WASM_VERSION_ID_INVALID";
pub const WASM_VERSION_DIGEST_MISMATCH: &str = "WASM_VERSION_DIGEST_MISMATCH";
pub const WASM_APPLICATION_ID_MISMATCH: &str = "WASM_APPLICATION_ID_MISMATCH";
pub const WASM_ADMISSION_PROOF_INVALID: &str = "WASM_ADMISSION_PROOF_INVALID";
pub const WASM_ADMISSION_JOURNAL_INVALID: &str = "WASM_ADMISSION_JOURNAL_INVALID";
pub const WASM_ADMISSION_STATE_INVALID: &str = "WASM_ADMISSION_STATE_INVALID";
pub const WASM_ADMISSION_LEASE_EXPIRED: &str = "WASM_ADMISSION_LEASE_EXPIRED";
pub const WASM_ADMISSION_PROOF_MISMATCH: &str = "WASM_ADMISSION_PROOF_MISMATCH";
pub const WASM_ADMISSION_DB_CONFLICT: &str = "WASM_ADMISSION_DB_CONFLICT";
pub const WASM_ADMISSION_RECEIPT_MISMATCH: &str = "WASM_ADMISSION_RECEIPT_MISMATCH";
pub const WASM_ADMISSION_OBJECT_CORRUPT: &str = "WASM_ADMISSION_OBJECT_CORRUPT";
pub const WASM_ADMISSION_OBJECT_WRITE_FAILED: &str = "WASM_ADMISSION_OBJECT_WRITE_FAILED";
pub const WASM_ADMISSION_DB_WRITE_FAILED: &str = "WASM_ADMISSION_DB_WRITE_FAILED";
pub const WASM_ADMISSION_HANDOFF_FAILED: &str = "WASM_ADMISSION_HANDOFF_FAILED";
pub const WASM_ADMISSION_TERMINAL_FAILED: &str = "WASM_ADMISSION_TERMINAL_FAILED";
pub const WASM_ADMISSION_IN_FLIGHT: &str = "WASM_ADMISSION_IN_FLIGHT";
pub const WASM_ADMISSION_RESUME_NEEDS_REQUEST: &str = "WASM_ADMISSION_RESUME_NEEDS_REQUEST";
pub const WASM_ADMISSION_FAIL_CLOSED: &str = "WASM_ADMISSION_FAIL_CLOSED";
pub const WASM_ADMISSION_TOKEN_UNAVAILABLE: &str = "WASM_ADMISSION_TOKEN_UNAVAILABLE";
pub const WASM_REGISTRY_CONFLICT: &str = "WASM_REGISTRY_CONFLICT";
/// spec 场景「Declared and discovered imports differ」的稳定码（V2 policy 成员与
/// normalizedPolicy.declaredHostImports 的 import 集不一致时 fail-closed）。
pub const WASM_DECLARATION_MISMATCH: &str = "WASM_DECLARATION_MISMATCH";

fn regexes() -> &'static Regexes {
    static REGEXES: OnceLock<Regexes> = OnceLock::new();
    REGEXES.get_or_init(|| Regexes {
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        oci_sha256: regex::Regex::new(r"^sha256:[a-f0-9]{64}$").expect("oci sha256 regex"),
        version_id: regex::Regex::new(r"^[a-f0-9]{64}-[1-9][0-9]{0,15}$").expect("version id regex"),
        wit_package: regex::Regex::new(r"^[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*:[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*@(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$").expect("wit package regex"),
        wit_interface: regex::Regex::new(r"^[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*$").expect("wit interface regex"),
        entry_key: regex::Regex::new(r"^[a-z][a-z0-9.-]{0,63}$").expect("entry key regex"),
        dns_label: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("dns label regex"),
        ipv4: regex::Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$").expect("ipv4 regex"),
        rfc3339_utc: regex::Regex::new(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.(\d{1,9}))?Z$").expect("rfc3339 regex"),
    })
}

struct Regexes {
    application_id: regex::Regex,
    sha256_hex: regex::Regex,
    oci_sha256: regex::Regex,
    version_id: regex::Regex,
    wit_package: regex::Regex,
    wit_interface: regex::Regex,
    entry_key: regex::Regex,
    dns_label: regex::Regex,
    ipv4: regex::Regex,
    rfc3339_utc: regex::Regex,
}

fn err(code: &'static str, detail: impl Into<String>) -> AdmissionError {
    AdmissionError::new(code, detail)
}

fn validate_application_id(value: &str) -> Result<(), AdmissionError> {
    if regexes().application_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_APPLICATION_ID_INVALID, format!("applicationId must match ^[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?$: {value}")))
    }
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<(), AdmissionError> {
    if regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err("INVALID_DIGEST", format!("{field} must be 64 lower-case hex characters")))
    }
}

fn validate_oci_sha256(value: &str, field: &str) -> Result<(), AdmissionError> {
    if regexes().oci_sha256.is_match(value) {
        Ok(())
    } else {
        Err(err("INVALID_DIGEST", format!("{field} must be sha256: plus 64 lower-case hex characters")))
    }
}

/// 校验 versionId 文法并拆出 (versionDigest, sequence)；sequence 必须是 u53 正整数。
pub fn parse_wasm_version_id(version_id: &str) -> Result<(String, u64), AdmissionError> {
    if !regexes().version_id.is_match(version_id) {
        return Err(err(WASM_VERSION_ID_INVALID, "versionId must be <64 hex>-<positive sequence without leading zero>"));
    }
    let (digest, sequence) = version_id.split_once('-').ok_or_else(|| err(WASM_VERSION_ID_INVALID, "versionId must contain one dash"))?;
    let sequence: u64 = sequence.parse().map_err(|_| err(WASM_VERSION_ID_INVALID, "versionId sequence must be a positive u53 integer"))?;
    if sequence == 0 || sequence > WASM_U53_MAX {
        return Err(err(WASM_VERSION_ID_INVALID, "versionId sequence must be within 1..=u53 max"));
    }
    Ok((digest.to_string(), sequence))
}

pub fn compose_wasm_version_id(version_digest: &str, sequence: u64) -> String {
    format!("{version_digest}-{sequence}")
}

// ---------------------------------------------------------------------------
// RFC3339-UTC（无 chrono 依赖；Howard Hinnant civil-days 算法，毫秒精度）
// ---------------------------------------------------------------------------

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// epoch 毫秒 → "YYYY-MM-DDTHH:MM:SS.mmmZ"（TS 侧 /^\d{4}-..T..:..:..(\.\d+)?Z$/ 接受）。
pub fn format_rfc3339_utc_millis(epoch_millis: u64) -> String {
    let secs = (epoch_millis / 1000) as i64;
    let millis = epoch_millis % 1000;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// 解析 RFC3339-UTC（Z 结尾，可选 1..9 位小数，取前 3 位毫秒）→ epoch 毫秒。
pub fn parse_rfc3339_utc_millis(value: &str) -> Result<u64, AdmissionError> {
    let captures = regexes().rfc3339_utc.captures(value).ok_or_else(|| err(WASM_ADMISSION_PROOF_INVALID, "timestamp must be RFC3339 UTC ending in Z"))?;
    let year: i64 = captures[1].parse().map_err(|_| err(WASM_ADMISSION_PROOF_INVALID, "invalid year"))?;
    let month: u32 = captures[2].parse().map_err(|_| err(WASM_ADMISSION_PROOF_INVALID, "invalid month"))?;
    let day: u32 = captures[3].parse().map_err(|_| err(WASM_ADMISSION_PROOF_INVALID, "invalid day"))?;
    let hour: u32 = captures[4].parse().map_err(|_| err(WASM_ADMISSION_PROOF_INVALID, "invalid hour"))?;
    let minute: u32 = captures[5].parse().map_err(|_| err(WASM_ADMISSION_PROOF_INVALID, "invalid minute"))?;
    let second: u32 = captures[6].parse().map_err(|_| err(WASM_ADMISSION_PROOF_INVALID, "invalid second"))?;
    let millis = captures.get(8).map(|m| {
        let digits = m.as_str();
        let padded = format!("{digits:0<3}");
        padded[..3].parse::<u64>()
    }).transpose().map_err(|_| err(WASM_ADMISSION_PROOF_INVALID, "invalid fraction"))?.unwrap_or(0);
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return Err(err(WASM_ADMISSION_PROOF_INVALID, "timestamp component out of range"));
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_len = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(err(WASM_ADMISSION_PROOF_INVALID, "invalid month")),
    };
    if day > month_len {
        return Err(err(WASM_ADMISSION_PROOF_INVALID, "day exceeds month length"));
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    if secs < 0 {
        return Err(err(WASM_ADMISSION_PROOF_INVALID, "timestamps before 1970 are not accepted"));
    }
    Ok(secs as u64 * 1000 + millis)
}

// ---------------------------------------------------------------------------
// JCS（RFC 8785，本 capability 值域：整数 ≤ u53、ASCII 键、字符串、布尔、null、数组、对象）
// ---------------------------------------------------------------------------

/// 序列化为 JCS 字节。serde_json 默认 Map=BTreeMap（键按 UTF-8 字节序），
/// 值域内与 RFC 8785 字节一致；浮点/非 ASCII 键在 validate_jcs_domain 中 fail-closed。
pub fn jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AdmissionError> {
    let parsed = serde_json::to_value(value).map_err(|e| err(WASM_ADMISSION_PROOF_INVALID, format!("value is not serializable as JSON: {e}")))?;
    validate_jcs_domain(&parsed)?;
    serde_json::to_vec(&parsed).map_err(|e| err(WASM_ADMISSION_PROOF_INVALID, format!("JCS serialization failed: {e}")))
}

fn validate_jcs_domain(value: &serde_json::Value) -> Result<(), AdmissionError> {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) => Ok(()),
        serde_json::Value::Number(n) => {
            // RFC 8785 数值跟随 ECMAScript Number::toString；本域只允许 u53 整数，
            // 浮点（含 JSON 指数形式解析结果）一律拒绝，避免两套序列化语义分歧。
            if let Some(u) = n.as_u64() {
                if u <= WASM_U53_MAX {
                    Ok(())
                } else {
                    Err(err(WASM_ADMISSION_PROOF_INVALID, "integer exceeds the u53 JSON safe-integer domain"))
                }
            } else {
                Err(err(WASM_ADMISSION_PROOF_INVALID, "floating-point values are not part of the canonical JSON domain"))
            }
        }
        serde_json::Value::String(s) => {
            // 键与字符串值只接受 ASCII：UTF-16 code-unit（RFC 8785）与 UTF-8 字节序
            // 仅在非 ASCII（尤其增补平面）处分歧；文法层已限 ASCII，这里再独立设防。
            if s.is_ascii() {
                Ok(())
            } else {
                Err(err(WASM_ADMISSION_PROOF_INVALID, "non-ASCII strings are outside the canonical ASCII-only domain"))
            }
        }
        serde_json::Value::Array(items) => {
            items.iter().try_for_each(validate_jcs_domain)
        }
        serde_json::Value::Object(map) => {
            for (key, member) in map {
                if !key.is_ascii() {
                    return Err(err(WASM_ADMISSION_PROOF_INVALID, "non-ASCII object keys are outside the canonical ASCII-only domain"));
                }
                validate_jcs_domain(member)?;
            }
            Ok(())
        }
    }
}

/// 从原始字节解析 typed witness：serde derive 自带 duplicate-member 检测 +
/// deny_unknown_fields 精确键集（对位 TS parseStrictJson 的"覆盖前检测重复"）。
fn parse_canonical_witness<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8]) -> Result<T, AdmissionError> {
    let parsed: T = serde_json::from_slice(bytes).map_err(|e| err(WASM_ADMISSION_JOURNAL_INVALID, format!("witness bytes do not parse as the typed record: {e}")))?;
    // 规范 JCS 检查：原始字节必须等于 JCS(解析值)，而不是"解析后等价"。
    let canonical = jcs_bytes(&parsed)?;
    if canonical != bytes {
        return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "witness bytes must equal JCS(parse(bytes))"));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// digest 纯函数（逐字对照 spec；域前缀 + 单次 SHA-256，绝不二次 hash 十六进制串）
// ---------------------------------------------------------------------------

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

/// wasmVersionDigestV1 = sha256hex("iweb-wasm-version-digest-v1\n" ||
///   "package " || packageDigest || "\n" || "admission-manifest " || dec(len) || "\n" || A)。
pub fn wasm_version_digest_v1(package_digest: &str, admission_manifest_jcs: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(VERSION_DIGEST_DOMAIN.as_bytes());
    hasher.update(b"\n");
    hasher.update(format!("package {package_digest}\n").as_bytes());
    hasher.update(format!("admission-manifest {}\n", admission_manifest_jcs.len()).as_bytes());
    hasher.update(admission_manifest_jcs);
    hex::encode(hasher.finalize())
}

/// commitTokenHash = hex(SHA-256(UTF8("iweb-wasm-admission-token-v1\n" || tokenBytes)))。
/// token 是 Kernel 生成的 256 随机位，绝不接受包方提供；仅以 hash 形式持久化。
pub fn commit_token_hash(token_bytes: &[u8; 32]) -> String {
    domain_digest(COMMIT_TOKEN_DOMAIN, token_bytes)
}

/// admissionProofDigest = hex(SHA-256(UTF8("iweb-admission-proof-v1\n" || JCS(proof))))。
pub fn admission_proof_digest(proof_jcs: &[u8]) -> String {
    domain_digest(ADMISSION_PROOF_DOMAIN, proof_jcs)
}

/// materializationTarget = "mat-" + sha256("iweb-wasm-materializer-target-v1\n" || JCS(proof)) 前 40 hex。
pub fn materialization_target(proof_jcs: &[u8]) -> String {
    let digest = domain_digest(MATERIALIZER_TARGET_DOMAIN, proof_jcs);
    format!("mat-{}", &digest[..40])
}

// ---------------------------------------------------------------------------
// V2（service-enabled）policy 绑定与 generation 感知的 versionDigest
// ---------------------------------------------------------------------------

fn host_service_error(error: HostServiceError) -> AdmissionError {
    AdmissionError { code: error.code, detail: error.detail }
}

/// V2 policy 与 normalizedPolicy 的绑定校验（admission 请求与 proof 共用）：
/// 1. policy 自身完整校验（字面量/limits 上界/policyDigest 复算/至少一个服务启用）；
/// 2. 声明一致（spec「Declared and discovered imports differ」）：policy 成员非 null ⇔
///    declaredHostImports 含对应精确 import，否则 WASM_DECLARATION_MISMATCH；
/// 3. reserve 交叉校验（TS checkWasmGuestMemoryReserve 对位）：
///    1 <= reserveBytes < resources.memoryBytes，缺失/越界 fail-closed。
pub fn verify_host_service_policy_binding(
    policy: &HostServicePolicyV2,
    manifest: &NormalizedWasmManifestV1,
) -> Result<(), AdmissionError> {
    policy.validate().map_err(host_service_error)?;
    let imports = &manifest.runtime.declared_host_imports;
    let declared = |package: &str, interface: &str| {
        imports
            .iter()
            .any(|entry| entry.package == package && entry.interface == interface && entry.direction == "import")
    };
    let members = [
        ("kv", policy.host_services.kv.is_some(), "iweb:kv@1.0.0", "store"),
        ("sql", policy.host_services.sql.is_some(), "iweb:sql@1.0.0", "store"),
        ("logging", policy.host_services.logging.is_some(), "iweb:logging@1.0.0", "logger"),
    ];
    for (kind, enabled, package, interface) in members {
        if enabled && !declared(package, interface) {
            return Err(err(
                WASM_DECLARATION_MISMATCH,
                format!("hostServices.{kind} is enabled but normalizedPolicy declares no {package}/{interface} import"),
            ));
        }
        if !enabled && declared(package, interface) {
            return Err(err(
                WASM_DECLARATION_MISMATCH,
                format!("normalizedPolicy declares {package}/{interface} but hostServices.{kind} is null; the version must use the V2 policy"),
            ));
        }
    }
    check_wasm_guest_memory_reserve(manifest.resources.memory_bytes, policy.reserve_bytes).map_err(host_service_error)?;
    Ok(())
}

/// generation 感知的 versionDigest：无 policy → wasmVersionDigestV1；有 policy →
/// HostServiceIdentityV2 的 versionDigestV2（iweb-wasm-host-identity-v2 domain）。
/// V2 输入的 normalizedPolicy 直接取 admission manifest 的 JCS 字节解析值，
/// 保证嵌入 digest 的对象与 wasmVersionDigestV1 输入逐字节同源。
fn admission_version_digest(
    package_digest: &str,
    admission_manifest_jcs: &[u8],
    host_service_policy: Option<&HostServicePolicyV2>,
) -> Result<String, AdmissionError> {
    match host_service_policy {
        None => Ok(wasm_version_digest_v1(package_digest, admission_manifest_jcs)),
        Some(policy) => {
            let manifest_value = serde_json::from_slice::<serde_json::Value>(admission_manifest_jcs)
                .map_err(|e| err(WASM_ADMISSION_PROOF_INVALID, format!("the admission manifest JCS does not parse: {e}")))?;
            wasm_host_service_version_digest_v2(package_digest, &manifest_value, &policy.policy_digest).map_err(host_service_error)
        }
    }
}

// ---------------------------------------------------------------------------
// typed wire 记录（精确键集；camelCase 对位 contracts）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmImportCapability {
    pub package: String,
    pub interface: String,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmRuntimeV1 {
    pub kind: String,
    #[serde(rename = "entryLayerDigest")]
    pub entry_layer_digest: String,
    pub world: String,
    #[serde(rename = "hostABI")]
    pub host_abi: String,
    #[serde(rename = "declaredHostImports")]
    pub declared_host_imports: Vec<WasmImportCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmResourcesV1 {
    #[serde(rename = "cpuMillis")]
    pub cpu_millis: u64,
    #[serde(rename = "memoryBytes")]
    pub memory_bytes: u64,
    #[serde(rename = "pidLimit")]
    pub pid_limit: u64,
    #[serde(rename = "storageBytes")]
    pub storage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmStorageV1 {
    pub persistent: bool,
    #[serde(rename = "requestBytes")]
    pub request_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmEgressRuleV1 {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmEgressV1 {
    pub default: String,
    pub allow: Vec<WasmEgressRuleV1>,
}

/// NormalizedWasmManifestV1（wasmVersionDigestV1 的哈希对象；精确键集）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedWasmManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub name: String,
    pub runtime: WasmRuntimeV1,
    pub resources: WasmResourcesV1,
    pub storage: WasmStorageV1,
    pub egress: WasmEgressV1,
}

/// RuntimeBindingIdentityV1（七字段完整绑定；不得以 image digest / catalog revision 子集替代）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingIdentityV1 {
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

/// 准入时刻的不可变 lifecycle 投影（registry 行由它创建；没有后续 lifecycle 状态）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleAdmissionRecord {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub state: String,
    #[serde(rename = "admittedAt")]
    pub admitted_at: String,
    #[serde(rename = "admissionJournalRevision")]
    pub admission_journal_revision: u64,
}

/// AdmissionProofV1：所有 durable admission witness 共享的精确 JCS 对象。
/// P0-3（add-wasm-host-services）：可选 `hostServicePolicy` 成员在场即 V2
/// （service-enabled）证明——versionDigest 改用 HostServiceIdentityV2 的
/// versionDigestV2 公式；不在场即 V1，versionDigest 保持 wasmVersionDigestV1。
/// V1 证明的字节形状不变（skip_serializing_if 保证 V1 不携带该键）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProofV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "versionDigest")]
    pub version_digest: String,
    pub sequence: u64,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "normalizedPolicy")]
    pub normalized_policy: NormalizedWasmManifestV1,
    #[serde(rename = "lifecycleAdmissionRecord")]
    pub lifecycle_admission_record: LifecycleAdmissionRecord,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "commitTokenHash")]
    pub commit_token_hash: String,
    /// V2（service-enabled）证明携带完整 HostServicePolicyV2；policy digest 由此绑定
    /// 进 proof/receipt/registry/控制态（AdmissionProofV2 的 Kernel 半边落点）。
    #[serde(rename = "hostServicePolicy", skip_serializing_if = "Option::is_none")]
    pub host_service_policy: Option<HostServicePolicyV2>,
}

/// 对象完成 marker：恰好 {schemaVersion, proof}。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompletionMarker {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub proof: AdmissionProofV1,
}

/// Kernel DB 行：恰好 {schemaVersion, proof, visibility}。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDbRow {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub proof: AdmissionProofV1,
    pub visibility: String,
}

/// materializer receipt：恰好 {schemaVersion, proof, materializationTarget}
/// （V1）；V2 证明追加显式 `hostServicePolicyDigest`（P0-3：receipt 携带 policy
/// digest；V1 receipt 字节形状不变）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MaterializerReceipt {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub proof: AdmissionProofV1,
    #[serde(rename = "materializationTarget")]
    pub materialization_target: String,
    #[serde(rename = "hostServicePolicyDigest", skip_serializing_if = "Option::is_none")]
    pub host_service_policy_digest: Option<String>,
}

/// journal 的 durable 对象：恰好 {schemaVersion, proof, state, journalRevision, leaseExpiresAt}。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionJournalRow {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub proof: AdmissionProofV1,
    pub state: AdmissionState,
    #[serde(rename = "journalRevision")]
    pub journal_revision: u64,
    #[serde(rename = "leaseExpiresAt")]
    pub lease_expires_at: Option<String>,
}

/// journal 状态机：正常路径 staging→validated→object-complete→db-hidden→
/// materializer-acknowledged→visible；visible/failed/collected 为终态；
/// 非终态→failed、failed→collected 是仅有的额外合法迁移，绝无回退。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionState {
    Staging,
    Validated,
    ObjectComplete,
    DbHidden,
    MaterializerAcknowledged,
    Visible,
    Failed,
    Collected,
}

impl AdmissionState {
    pub fn is_terminal(self) -> bool {
        matches!(self, AdmissionState::Visible | AdmissionState::Failed | AdmissionState::Collected)
    }

    fn transition_allowed(from: AdmissionState, to: AdmissionState) -> bool {
        use AdmissionState::*;
        if from == to {
            return false;
        }
        matches!(
            (from, to),
            (Staging, Validated)
                | (Validated, ObjectComplete)
                | (ObjectComplete, DbHidden)
                | (DbHidden, MaterializerAcknowledged)
                | (MaterializerAcknowledged, Visible)
                | (Staging | Validated | ObjectComplete | DbHidden | MaterializerAcknowledged, Failed)
                | (Failed, Collected)
        )
    }
}

// ---------------------------------------------------------------------------
// manifest / binding / proof 校验（fail-closed；对位 contracts validator 语义）
// ---------------------------------------------------------------------------

fn require_u53(value: u64, minimum: u64, maximum: u64, field: &str) -> Result<(), AdmissionError> {
    if value >= minimum && value <= maximum && value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(WASM_MANIFEST_INVALID, format!("{field} must be an integer between {minimum} and {maximum}")))
    }
}

fn validate_dns_name(host: &str) -> Result<(), AdmissionError> {
    if host.len() > 253 || host.is_empty() {
        return Err(err(WASM_MANIFEST_INVALID, "egress host must be a DNS name of at most 253 bytes"));
    }
    if !host.split('.').all(|label| regexes().dns_label.is_match(label)) {
        return Err(err(WASM_MANIFEST_INVALID, "egress host must be a lower-case DNS name"));
    }
    // 地址字面量（IPv4 点分、任何含冒号的 IPv6、localhost）不是 DNS name，拒绝。
    if regexes().ipv4.is_match(host) || host.contains(':') || host == "localhost" {
        return Err(err(WASM_MANIFEST_INVALID, "egress host must be a DNS name, not an address literal"));
    }
    Ok(())
}

/// NormalizedWasmManifestV1 全字段校验（含排序/去重/跨字段约束）。
pub fn validate_normalized_manifest(manifest: &NormalizedWasmManifestV1) -> Result<(), AdmissionError> {
    require_u53(manifest.schema_version, 1, 1, "/schemaVersion")?;
    validate_application_id(&manifest.name).map_err(|e| err(WASM_MANIFEST_INVALID, format!("/name: {}", e.detail)))?;
    let runtime = &manifest.runtime;
    if runtime.kind != "wasm" {
        return Err(err(WASM_MANIFEST_INVALID, "/runtime/kind must be exactly \"wasm\""));
    }
    validate_oci_sha256(&runtime.entry_layer_digest, "/runtime/entryLayerDigest")
        .map_err(|e| err(WASM_MANIFEST_INVALID, e.detail))?;
    if runtime.world != WASM_WORLD_LITERAL {
        return Err(err(WASM_MANIFEST_INVALID, "/runtime/world must be the exact matrix world literal"));
    }
    if runtime.host_abi != WASM_HOST_ABI_LITERAL {
        return Err(err(WASM_MANIFEST_INVALID, "/runtime/hostABI must be the exact matrix ABI literal"));
    }
    validate_import_capabilities(&runtime.declared_host_imports)?;
    let resources = &manifest.resources;
    require_u53(resources.cpu_millis, 1, 1_000_000, "/resources/cpuMillis")?;
    require_u53(resources.memory_bytes, 1, 68_719_476_736, "/resources/memoryBytes")?;
    require_u53(resources.pid_limit, 1, 1_000_000, "/resources/pidLimit")?;
    require_u53(resources.storage_bytes, 0, 1_099_511_627_776, "/resources/storageBytes")?;
    let storage = &manifest.storage;
    require_u53(storage.request_bytes, 0, 1_099_511_627_776, "/storage/requestBytes")?;
    if storage.request_bytes > resources.storage_bytes {
        return Err(err(WASM_MANIFEST_INVALID, "/storage/requestBytes must be <= resources/storageBytes"));
    }
    let egress = &manifest.egress;
    if egress.default != "deny" {
        return Err(err(WASM_MANIFEST_INVALID, "/egress/default must be exactly \"deny\""));
    }
    if egress.allow.len() > WASM_MAX_EGRESS_RULES {
        return Err(err(WASM_MANIFEST_INVALID, format!("/egress/allow must have at most {WASM_MAX_EGRESS_RULES} items")));
    }
    for rule in &egress.allow {
        validate_dns_name(&rule.host)?;
        require_u53(rule.port as u64, 1, 65_535, "/egress/allow/port")?;
    }
    for pair in egress.allow.windows(2) {
        let (previous, current) = (&pair[0], &pair[1]);
        let by_host = previous.host.as_bytes().cmp(current.host.as_bytes());
        if by_host != std::cmp::Ordering::Less {
            let code = if by_host == std::cmp::Ordering::Equal && previous.port < current.port {
                "must be sorted by (host, port)"
            } else {
                "contains a duplicate (host, port) pair"
            };
            return Err(err(WASM_MANIFEST_INVALID, format!("/egress/allow {code}")));
        }
        if by_host == std::cmp::Ordering::Equal && previous.port >= current.port {
            return Err(err(WASM_MANIFEST_INVALID, "/egress/allow contains a duplicate (host, port) pair"));
        }
    }
    Ok(())
}

/// 排序键：(package, interface, direction) 的 UTF-8 字节序。
fn import_capability_sort_key(entry: &WasmImportCapability) -> (&[u8], &[u8], &[u8]) {
    (entry.package.as_bytes(), entry.interface.as_bytes(), entry.direction.as_bytes())
}

fn validate_import_capabilities(imports: &[WasmImportCapability]) -> Result<(), AdmissionError> {
    for entry in imports {
        if !regexes().wit_package.is_match(&entry.package) {
            return Err(err(WASM_MANIFEST_INVALID, "declaredHostImports package must be a lower-case WIT namespace:name@major.minor.patch identity"));
        }
        if !regexes().wit_interface.is_match(&entry.interface) {
            return Err(err(WASM_MANIFEST_INVALID, "declaredHostImports interface must be a lower-case WIT interface identifier"));
        }
        // declaredHostImports 只接受 direction:"import"；根导出是另一个 typed 形状。
        if entry.direction != "import" {
            return Err(err(WASM_MANIFEST_INVALID, "declaredHostImports direction must be the literal \"import\""));
        }
    }
    for pair in imports.windows(2) {
        let (previous, current) = (&pair[0], &pair[1]);
        match import_capability_sort_key(previous).cmp(&import_capability_sort_key(current)) {
            std::cmp::Ordering::Greater => {
                return Err(err(WASM_MANIFEST_INVALID, "declaredHostImports must be sorted by (package, interface, direction) in UTF-8 byte order"));
            }
            std::cmp::Ordering::Equal => {
                return Err(err(WASM_MANIFEST_INVALID, "declaredHostImports duplicate (package, interface, direction) key is rejected"));
            }
            std::cmp::Ordering::Less => {}
        }
    }
    Ok(())
}

/// RuntimeBindingIdentityV1 校验。
pub fn validate_runtime_binding(binding: &RuntimeBindingIdentityV1) -> Result<(), AdmissionError> {
    if binding.kind != "wasm" {
        return Err(err(WASM_BINDING_INVALID, "/kind must be exactly \"wasm\""));
    }
    require_u53(binding.catalog_revision, 1, WASM_U53_MAX, "/catalogRevision")
        .map_err(|e| err(WASM_BINDING_INVALID, e.detail))?;
    validate_sha256_hex(&binding.catalog_hash, "catalogHash").map_err(|e| err(WASM_BINDING_INVALID, e.detail))?;
    if !regexes().entry_key.is_match(&binding.entry_key) {
        return Err(err(WASM_BINDING_INVALID, "/entryKey must match ^[a-z][a-z0-9.-]{0,63}$"));
    }
    validate_oci_sha256(&binding.image_digest, "imageDigest").map_err(|e| err(WASM_BINDING_INVALID, e.detail))?;
    if binding.host_abi != WASM_HOST_ABI_LITERAL {
        return Err(err(WASM_BINDING_INVALID, "/hostABI must be the exact matrix ABI literal"));
    }
    if binding.world != WASM_WORLD_LITERAL {
        return Err(err(WASM_BINDING_INVALID, "/world must be the exact matrix world literal"));
    }
    Ok(())
}

/// AdmissionProofV1 完整自洽校验：形状、文法、name=applicationId、
/// versionId=versionDigest+"-"+sequence、versionDigest 等于按 generation 选择的公式
/// （V1：wasmVersionDigestV1；V2：HostServiceIdentityV2 的 versionDigestV2，
/// 且 policy 绑定校验必须通过）。
/// 返回 admission manifest JCS 字节（供上层复用）。
pub fn verify_admission_proof(proof: &AdmissionProofV1) -> Result<Vec<u8>, AdmissionError> {
    if proof.schema_version != 1 {
        return Err(err(WASM_ADMISSION_PROOF_INVALID, "/schemaVersion must be 1"));
    }
    validate_application_id(&proof.application_id)?;
    validate_sha256_hex(&proof.package_digest, "packageDigest")?;
    validate_sha256_hex(&proof.version_digest, "versionDigest")?;
    require_u53(proof.sequence, 1, WASM_U53_MAX, "/sequence")?;
    parse_wasm_version_id(&proof.version_id)?;
    let composed = compose_wasm_version_id(&proof.version_digest, proof.sequence);
    if proof.version_id != composed {
        return Err(err(WASM_VERSION_ID_INVALID, "versionId must be versionDigest + '-' + decimal(sequence)"));
    }
    validate_normalized_manifest(&proof.normalized_policy)?;
    if proof.normalized_policy.name != proof.application_id {
        return Err(err(WASM_APPLICATION_ID_MISMATCH, "normalizedPolicy.name must exactly equal applicationId"));
    }
    let record = &proof.lifecycle_admission_record;
    if record.schema_version != 1 {
        return Err(err(WASM_ADMISSION_PROOF_INVALID, "/lifecycleAdmissionRecord/schemaVersion must be 1"));
    }
    if record.state != "admitted" {
        return Err(err(WASM_ADMISSION_PROOF_INVALID, "/lifecycleAdmissionRecord/state must be \"admitted\""));
    }
    parse_rfc3339_utc_millis(&record.admitted_at)?;
    require_u53(record.admission_journal_revision, 0, WASM_U53_MAX, "/lifecycleAdmissionRecord/admissionJournalRevision")?;
    validate_runtime_binding(&proof.runtime_binding)?;
    require_u53(proof.capability_record_revision, 1, WASM_U53_MAX, "/capabilityRecordRevision")?;
    validate_sha256_hex(&proof.capability_record_hash, "capabilityRecordHash")?;
    validate_sha256_hex(&proof.commit_token_hash, "commitTokenHash")?;
    let admission_manifest = jcs_bytes(&proof.normalized_policy)?;
    if let Some(policy) = &proof.host_service_policy {
        // V2（service-enabled）：policy 绑定（digest/声明/reserve）先行，
        // versionDigest 再按 HostServiceIdentityV2 公式复算。
        verify_host_service_policy_binding(policy, &proof.normalized_policy)?;
    }
    let recomputed = admission_version_digest(&proof.package_digest, &admission_manifest, proof.host_service_policy.as_ref())?;
    if recomputed != proof.version_digest {
        return Err(err(
            WASM_VERSION_DIGEST_MISMATCH,
            "versionDigest must equal the generation-selected digest formula (wasmVersionDigestV1 without a host service policy; HostServiceIdentityV2 versionDigestV2 with one)",
        ));
    }
    Ok(admission_manifest)
}

/// proof 的 JCS 字节 + admissionProofDigest（registry 投影与 witness 比对共用）。
pub fn proof_jcs_bytes(proof: &AdmissionProofV1) -> Result<Vec<u8>, AdmissionError> {
    jcs_bytes(proof)
}

// ---------------------------------------------------------------------------
// commit token 源（Kernel 生成 256 随机位；绝不由包方提供）
// ---------------------------------------------------------------------------

pub trait TokenSource {
    fn generate(&mut self) -> Result<[u8; 32], AdmissionError>;
}

/// 生产源：/dev/urandom。不可读即 fail-closed（绝不退回确定性值）。
pub struct OsRandomTokenSource;

impl TokenSource for OsRandomTokenSource {
    fn generate(&mut self) -> Result<[u8; 32], AdmissionError> {
        use std::io::Read;
        let mut token = [0u8; 32];
        let mut file = std::fs::File::open("/dev/urandom").map_err(|e| err(WASM_ADMISSION_TOKEN_UNAVAILABLE, format!("cannot open /dev/urandom: {e}")))?;
        file.read_exact(&mut token).map_err(|e| err(WASM_ADMISSION_TOKEN_UNAVAILABLE, format!("cannot read 256 random bits: {e}")))?;
        Ok(token)
    }
}

// ---------------------------------------------------------------------------
// witness 存储抽象（对象前缀 / 控制库行 / materializer receipt）
// ---------------------------------------------------------------------------

/// 版本键：(applicationId, versionId)——proof 的完整版本身份。
pub type VersionKey = (String, String);

fn version_prefix(proof: &AdmissionProofV1) -> String {
    format!("admission-object/{}/{}", proof.application_id, proof.version_id)
}

/// 对象存储：内容寻址 blob + 完成_marker。前缀内 blob 文件名必须等于其内容的 sha256 hex。
pub trait AdmissionObjectStore {
    /// 写入一个内容寻址 blob；digest_hex 与内容不符即 WASM_ADMISSION_OBJECT_CORRUPT。
    fn write_blob(&mut self, prefix: &str, digest_hex: &str, bytes: &[u8]) -> Result<(), AdmissionError>;
    /// 写入完成 marker（JCS 字节）。
    fn write_completion_marker(&mut self, prefix: &str, marker_bytes: &[u8]) -> Result<(), AdmissionError>;
    /// 验证前缀：≥1 个 blob、每个 blob 文件名==sha256(内容)、marker 存在。
    fn verify_prefix(&self, prefix: &str) -> Result<(), AdmissionError>;
    /// marker 原始字节（谓词读取）。
    fn completion_marker_bytes(&self, prefix: &str) -> Option<Vec<u8>>;
    /// GC：删除前缀全部对象（仅 failed→collected 路径调用）。
    fn remove_prefix(&mut self, prefix: &str) -> Result<(), AdmissionError>;
}

/// Kernel 控制库行（hidden/visible CAS）。
pub trait AdmissionControlDb {
    /// 幂等插入 hidden 行：不存在则插入；存在且 proof JCS 相同且仍 hidden 则 Ok；
    /// 存在但 proof 不同 → WASM_ADMISSION_DB_CONFLICT；已 visible 且 proof 相同 → Ok（重放）。
    fn insert_hidden_row(&mut self, key: &VersionKey, row_bytes: &[u8], proof_jcs: &[u8]) -> Result<(), AdmissionError>;
    /// hidden→visible CAS：成功翻转 Ok(true)；已 visible 且 proof 相同 Ok(false)；
    /// 行缺失或 proof 不同 → 结构化错误。
    fn flip_hidden_to_visible(&mut self, key: &VersionKey, proof_jcs: &[u8]) -> Result<bool, AdmissionError>;
    /// 行原始字节（谓词读取）。
    fn row_bytes(&self, key: &VersionKey) -> Option<Vec<u8>>;
    /// GC：删除行（仅 failed→collected 路径调用；visible 行不可删）。
    fn remove_row(&mut self, key: &VersionKey) -> Result<(), AdmissionError>;
    /// 遍历全部行键（恢复期 fail-closed 扫描用）。
    fn keys(&self) -> Vec<VersionKey>;
}

/// materializer：接收幂等 handoff，落 durable receipt；绝不启动执行（hidden 行不可执行）。
pub trait AdmissionMaterializer {
    fn handoff(&mut self, key: &VersionKey, receipt_bytes: &[u8], target: &str) -> Result<(), AdmissionError>;
    fn receipt_bytes(&self, key: &VersionKey) -> Option<Vec<u8>>;
    fn remove_receipt(&mut self, key: &VersionKey) -> Result<(), AdmissionError>;
}

/// 事务可用的四类存储句柄。
pub struct AdmissionStores<'a> {
    pub journal: &'a mut dyn AdmissionJournal,
    pub objects: &'a mut dyn AdmissionObjectStore,
    pub db: &'a mut dyn AdmissionControlDb,
    pub materializer: &'a mut dyn AdmissionMaterializer,
}

// ---------------------------------------------------------------------------
// admission journal（追加式、崩溃可重放）
// ---------------------------------------------------------------------------

pub trait AdmissionJournal {
    /// create-or-join：同一 (applicationId, versionDigest) 的重试 join 既有 proof 与
    /// token hash；仅获胜 insert 生成 256 位 token。sequence 由显式分配器 CAS 分配，
    /// 绝不从数组长度推断。
    fn create_or_join(&mut self, request: &AdmissionRequest, token: &mut dyn TokenSource, now_epoch_millis: u64) -> Result<CreateOrJoin, AdmissionError>;
    /// 合法迁移 + journalRevision +1；非终态前进要求 lease 未过期。
    fn transition(&mut self, key: &VersionKey, to: AdmissionState, now_epoch_millis: u64) -> Result<AdmissionJournalRow, AdmissionError>;
    /// lease 续期：仅在过期前以成功 CAS（revision+1）允许。
    fn extend_lease(&mut self, key: &VersionKey, now_epoch_millis: u64, ttl_seconds: u64) -> Result<AdmissionJournalRow, AdmissionError>;
    fn row(&self, key: &VersionKey) -> Option<AdmissionJournalRow>;
    fn keys(&self) -> Vec<VersionKey>;
}

#[derive(Debug, Clone)]
pub struct CreateOrJoin {
    pub proof: AdmissionProofV1,
    pub key: VersionKey,
    pub created: bool,
    pub state: AdmissionState,
    pub journal_revision: u64,
}

/// 内存 journal 核心；文件持久化由 WasmAdmissionJournalFile 包装（同一 trait）。
#[derive(Debug, Default)]
pub struct WasmAdmissionJournal {
    rows: BTreeMap<VersionKey, AdmissionJournalRow>,
    /// (applicationId, versionDigest) → 该 digest 的全部 versionId（创建序）。
    by_content: BTreeMap<VersionKey, Vec<String>>,
    /// applicationId → 下一个可分配 sequence（显式分配器，绝不由 versions.len() 推断）。
    next_sequence: BTreeMap<String, u64>,
}

impl WasmAdmissionJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// 重放一条 journal 记录（完整 row 快照）。首条必须是 staging/revision 0；
    /// 后续必须是合法迁移或 lease 续期且 revision 恰好 +1。重建分配器与内容索引。
    pub fn replay_row(&mut self, row: AdmissionJournalRow) -> Result<(), AdmissionError> {
        if row.schema_version != 1 {
            return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "journal row schemaVersion must be 1"));
        }
        let key: VersionKey = (row.proof.application_id.clone(), row.proof.version_id.clone());
        match self.rows.get(&key) {
            None => {
                if row.state != AdmissionState::Staging || row.journal_revision != 0 || row.lease_expires_at.is_none() {
                    return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "first journal record for a version must be staging/revision 0 with a lease"));
                }
                verify_admission_proof(&row.proof)?;
                let sequence = row.proof.sequence;
                self.rows.insert(key.clone(), row);
                self.by_content.entry((key.0.clone(), row_proof_digest(&self.rows[&key]).to_string())).or_default().push(key.1.clone());
                let next = self.next_sequence.get(&key.0).copied().unwrap_or(1);
                if sequence >= next {
                    self.next_sequence.insert(key.0.clone(), sequence + 1);
                }
                Ok(())
            }
            Some(previous) => {
                if row.journal_revision != previous.journal_revision + 1 {
                    return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "journal revision must increase by exactly one"));
                }
                if row.proof != previous.proof {
                    return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "the proof of a journal row is immutable"));
                }
                let extended = row.state == previous.state;
                if extended {
                    // lease 续期：状态不变，仅 lease 前移且必须仍非终态。
                    if row.state.is_terminal() {
                        return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "terminal rows carry a null lease and cannot extend"));
                    }
                    let previous_lease = previous.lease_expires_at.clone().ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "nonterminal row must carry a lease"))?;
                    let new_lease = row.lease_expires_at.clone().ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "lease extension must carry a new lease"))?;
                    if parse_rfc3339_utc_millis(&new_lease)? < parse_rfc3339_utc_millis(&previous_lease)? {
                        return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "lease extension must not move the lease backwards"));
                    }
                } else {
                    if !AdmissionState::transition_allowed(previous.state, row.state) {
                        return Err(err(WASM_ADMISSION_JOURNAL_INVALID, format!("illegal transition {:?} -> {:?}", previous.state, row.state)));
                    }
                    if row.state.is_terminal() && row.lease_expires_at.is_some() {
                        return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "terminal rows must carry a null lease"));
                    }
                    if !row.state.is_terminal() && row.lease_expires_at.is_none() {
                        return Err(err(WASM_ADMISSION_JOURNAL_INVALID, "nonterminal rows must carry a lease"));
                    }
                }
                self.rows.insert(key, row);
                Ok(())
            }
        }
    }

    fn allocate_sequence(&mut self, application_id: &str) -> u64 {
        let next = self.next_sequence.entry(application_id.to_string()).or_insert(1);
        let sequence = *next;
        *next += 1;
        sequence
    }

    fn lease_from_ttl(now_epoch_millis: u64, ttl_seconds: u64) -> Result<String, AdmissionError> {
        if ttl_seconds == 0 || ttl_seconds > 3600 {
            return Err(err(WASM_ADMISSION_PROOF_INVALID, "stagingTtlSeconds must be within 1..=3600 (proof-pinned admission bound)"));
        }
        Ok(format_rfc3339_utc_millis(now_epoch_millis + ttl_seconds * 1000))
    }
}

fn row_proof_digest(row: &AdmissionJournalRow) -> &str {
    &row.proof.version_digest
}

impl AdmissionJournal for WasmAdmissionJournal {
    fn create_or_join(&mut self, request: &AdmissionRequest, token: &mut dyn TokenSource, now_epoch_millis: u64) -> Result<CreateOrJoin, AdmissionError> {
        validate_application_id(&request.application_id)?;
        validate_sha256_hex(&request.package_digest, "packageDigest")?;
        validate_normalized_manifest(&request.normalized_policy)?;
        if request.normalized_policy.name != request.application_id {
            return Err(err(WASM_APPLICATION_ID_MISMATCH, "normalizedPolicy.name must exactly equal applicationId"));
        }
        validate_runtime_binding(&request.runtime_binding)?;
        require_u53(request.capability_record_revision, 1, WASM_U53_MAX, "capabilityRecordRevision")?;
        validate_sha256_hex(&request.capability_record_hash, "capabilityRecordHash")?;
        // V2（service-enabled）policy 绑定先行（digest/声明/reserve fail-closed）。
        if let Some(policy) = &request.host_service_policy {
            verify_host_service_policy_binding(policy, &request.normalized_policy)?;
        }
        let admission_manifest = jcs_bytes(&request.normalized_policy)?;
        let version_digest = admission_version_digest(
            &request.package_digest,
            &admission_manifest,
            request.host_service_policy.as_ref(),
        )?;

        let content_key: VersionKey = (request.application_id.clone(), version_digest.clone());
        if let Some(joined) = self.find_join_candidate(request, &content_key, &admission_manifest)? {
            return Ok(joined);
        }

        // 获胜 insert：此刻才生成 256 位 token（失败路径绝不落盘 token）。
        let token = token.generate()?;
        let commit_token_hash = commit_token_hash(&token);
        let sequence = self.allocate_sequence(&request.application_id);
        let version_id = compose_wasm_version_id(&version_digest, sequence);
        let proof = AdmissionProofV1 {
            schema_version: 1,
            application_id: request.application_id.clone(),
            package_digest: request.package_digest.clone(),
            version_digest,
            sequence,
            version_id: version_id.clone(),
            normalized_policy: request.normalized_policy.clone(),
            lifecycle_admission_record: LifecycleAdmissionRecord {
                schema_version: 1,
                state: "admitted".into(),
                admitted_at: format_rfc3339_utc_millis(now_epoch_millis),
                admission_journal_revision: 0,
            },
            runtime_binding: request.runtime_binding.clone(),
            capability_record_revision: request.capability_record_revision,
            capability_record_hash: request.capability_record_hash.clone(),
            commit_token_hash,
            host_service_policy: request.host_service_policy.clone(),
        };
        verify_admission_proof(&proof)?;
        let row = AdmissionJournalRow {
            schema_version: 1,
            state: AdmissionState::Staging,
            journal_revision: 0,
            lease_expires_at: Some(Self::lease_from_ttl(now_epoch_millis, request.staging_ttl_seconds)?),
            proof,
        };
        let key: VersionKey = (request.application_id.clone(), version_id.clone());
        self.rows.insert(key.clone(), row.clone());
        self.by_content.entry(content_key).or_default().push(version_id);
        Ok(CreateOrJoin { proof: row.proof, key, created: true, state: row.state, journal_revision: row.journal_revision })
    }

    fn transition(&mut self, key: &VersionKey, to: AdmissionState, now_epoch_millis: u64) -> Result<AdmissionJournalRow, AdmissionError> {
        let previous = self.rows.get(key).cloned().ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "unknown journal row"))?;
        if !AdmissionState::transition_allowed(previous.state, to) {
            return Err(err(WASM_ADMISSION_STATE_INVALID, format!("illegal transition {:?} -> {:?}", previous.state, to)));
        }
        let mut next = previous.clone();
        next.journal_revision = previous.journal_revision + 1;
        next.state = to;
        if to.is_terminal() {
            next.lease_expires_at = None;
        } else {
            // 过期的非终态行只允许转 failed，绝不允许继续走向 visible。
            let lease = previous.lease_expires_at.as_deref().ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "nonterminal row must carry a lease"))?;
            if parse_rfc3339_utc_millis(lease)? <= now_epoch_millis {
                return Err(err(WASM_ADMISSION_LEASE_EXPIRED, "an expired nonterminal row may only transition to failed"));
            }
        }
        self.rows.insert(key.clone(), next.clone());
        Ok(next)
    }

    fn extend_lease(&mut self, key: &VersionKey, now_epoch_millis: u64, ttl_seconds: u64) -> Result<AdmissionJournalRow, AdmissionError> {
        let previous = self.rows.get(key).cloned().ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "unknown journal row"))?;
        if previous.state.is_terminal() {
            return Err(err(WASM_ADMISSION_STATE_INVALID, "a terminal row cannot extend its lease"));
        }
        let lease = previous.lease_expires_at.as_deref().ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "nonterminal row must carry a lease"))?;
        if parse_rfc3339_utc_millis(lease)? <= now_epoch_millis {
            return Err(err(WASM_ADMISSION_LEASE_EXPIRED, "lease extension requires the current lease to be unexpired"));
        }
        let mut next = previous;
        next.journal_revision += 1;
        next.lease_expires_at = Some(Self::lease_from_ttl(now_epoch_millis, ttl_seconds)?);
        self.rows.insert(key.clone(), next.clone());
        Ok(next)
    }

    fn row(&self, key: &VersionKey) -> Option<AdmissionJournalRow> {
        self.rows.get(key).cloned()
    }

    fn keys(&self) -> Vec<VersionKey> {
        self.rows.keys().cloned().collect()
    }
}

/// 文件持久化 journal：追加式 JSONL（每行一个完整 row 快照的 JCS 字节）。
/// 崩溃重放：完整行全部校验后重建；尾部残行（无换行的部分写）丢弃；
/// 中部损坏行 fail-closed 返回错误。
#[derive(Debug)]
pub struct WasmAdmissionJournalFile {
    path: PathBuf,
    journal: WasmAdmissionJournal,
}

impl WasmAdmissionJournalFile {
    pub fn open(path: &Path) -> Result<Self, AdmissionError> {
        let mut journal = WasmAdmissionJournal::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for (index, line) in text.split('\n').enumerate() {
                if line.is_empty() {
                    continue;
                }
                let row: AdmissionJournalRow = match serde_json::from_str(line) {
                    Ok(row) => row,
                    Err(parse_error) => {
                        // 只有最后一行可能是崩溃残留的部分写；中部损坏必须 fail-closed。
                        let is_tail = line.is_empty() || index + 1 >= text.split('\n').count();
                        if is_tail && !text.ends_with('\n') {
                            break;
                        }
                        return Err(err(WASM_ADMISSION_JOURNAL_INVALID, format!("journal line {} is corrupt: {parse_error}", index + 1)));
                    }
                };
                journal.replay_row(row).map_err(|e| err(WASM_ADMISSION_JOURNAL_INVALID, format!("journal line {} replay failed: {}", index + 1, e.detail)))?;
            }
        }
        Ok(Self { path: path.to_path_buf(), journal })
    }

    fn append(&mut self, row: &AdmissionJournalRow) -> Result<(), AdmissionError> {
        let mut line = jcs_bytes(row)?;
        line.push(b'\n');
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)
            .map_err(|e| err(WASM_ADMISSION_JOURNAL_INVALID, format!("cannot open admission journal {}: {e}", self.path.display())))?;
        file.write_all(&line).map_err(|e| err(WASM_ADMISSION_JOURNAL_INVALID, format!("cannot append admission journal: {e}")))?;
        Ok(())
    }

    /// 内部统一路径：先改内存状态，再追加持久行；追加失败时返回错误，
    /// 进程重启后从文件重放重建（内存态不再被使用）。
    fn mutate<F>(&mut self, mutate: F) -> Result<AdmissionJournalRow, AdmissionError>
    where
        F: FnOnce(&mut WasmAdmissionJournal) -> Result<AdmissionJournalRow, AdmissionError>,
    {
        let next = mutate(&mut self.journal)?;
        self.append(&next)?;
        Ok(next)
    }
}

impl AdmissionJournal for WasmAdmissionJournalFile {
    fn create_or_join(&mut self, request: &AdmissionRequest, token: &mut dyn TokenSource, now_epoch_millis: u64) -> Result<CreateOrJoin, AdmissionError> {
        // join 是纯读路径（幂等，不产生新行，含与内存版完全一致的 mismatch 校验）；
        // create 才追加首行。
        let joined = {
            let admission_manifest = jcs_bytes(&request.normalized_policy)?;
            let version_digest = admission_version_digest(
                &request.package_digest,
                &admission_manifest,
                request.host_service_policy.as_ref(),
            )?;
            self.journal.find_join_candidate(request, &(request.application_id.clone(), version_digest), &admission_manifest)?
        };
        if let Some(create_or_join) = joined {
            return Ok(create_or_join);
        }
        let create_or_join = self.journal.create_or_join(request, token, now_epoch_millis)?;
        if create_or_join.created {
            let row = self.journal.row(&create_or_join.key).ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "created row is missing"))?;
            self.append(&row)?;
        }
        Ok(create_or_join)
    }

    fn transition(&mut self, key: &VersionKey, to: AdmissionState, now_epoch_millis: u64) -> Result<AdmissionJournalRow, AdmissionError> {
        self.mutate(|journal| journal.transition(key, to, now_epoch_millis))
    }

    fn extend_lease(&mut self, key: &VersionKey, now_epoch_millis: u64, ttl_seconds: u64) -> Result<AdmissionJournalRow, AdmissionError> {
        self.mutate(|journal| journal.extend_lease(key, now_epoch_millis, ttl_seconds))
    }

    fn row(&self, key: &VersionKey) -> Option<AdmissionJournalRow> {
        self.journal.row(key)
    }

    fn keys(&self) -> Vec<VersionKey> {
        self.journal.keys()
    }
}

impl WasmAdmissionJournal {
    /// join 判定（内存与文件持久化两个实现共用，语义必须完全一致）：
    /// 同 (applicationId, versionDigest) 已有事务时——普通重试 join 既有 proof
    /// （caller 可推导字段必须逐项一致）；显式 resequence 要求旧事务已终态；
    /// 多个非终态同 content 事务 fail-closed。返回 None 表示需要创建新事务。
    fn find_join_candidate(&mut self, request: &AdmissionRequest, content_key: &VersionKey, admission_manifest: &[u8]) -> Result<Option<CreateOrJoin>, AdmissionError> {
        let candidates = self.by_content.get(content_key).cloned().unwrap_or_default();
        if candidates.is_empty() {
            return Ok(None);
        }
        let nonterminal: Vec<String> = candidates.iter().filter(|version_id| {
            self.rows.get(&(request.application_id.clone(), (*version_id).clone())).is_some_and(|row| !row.state.is_terminal())
        }).cloned().collect();
        if nonterminal.len() > 1 {
            return Err(err(WASM_ADMISSION_IN_FLIGHT, "multiple nonterminal admissions exist for the same content identity; fail closed"));
        }
        if !request.allow_resequence {
            let chosen = nonterminal.first().cloned().unwrap_or_else(|| candidates[candidates.len() - 1].clone());
            let key: VersionKey = (request.application_id.clone(), chosen);
            let row = self.rows.get(&key).cloned().ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "content index points at a missing journal row"))?;
            // join 校验：请求必须与持久 proof 的全部 caller 可推导字段一致
            //（V2 场景含完整 hostServicePolicy——policy digest 是不可变身份的一部分）。
            if row.proof.package_digest != request.package_digest
                || row.proof.runtime_binding != request.runtime_binding
                || row.proof.capability_record_revision != request.capability_record_revision
                || row.proof.capability_record_hash != request.capability_record_hash
                || row.proof.host_service_policy != request.host_service_policy
                || jcs_bytes(&row.proof.normalized_policy)? != admission_manifest
            {
                return Err(err(WASM_ADMISSION_PROOF_MISMATCH, "a retry must join the exact persisted proof; binding/capacity/policy divergence is rejected"));
            }
            return Ok(Some(CreateOrJoin { proof: row.proof.clone(), key, created: false, state: row.state, journal_revision: row.journal_revision }));
        }
        if !nonterminal.is_empty() {
            return Err(err(WASM_ADMISSION_IN_FLIGHT, "re-sequencing requires the previous admission of the same digest to reach a terminal state"));
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// 准入事务请求与驱动（durable sequence + 中断点恢复的唯一结果）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    pub application_id: String,
    /// 已由制品校验产出的 wasmPackageDigestV1（本模块不重新解析 OCI 布局）。
    pub package_digest: String,
    pub normalized_policy: NormalizedWasmManifestV1,
    pub runtime_binding: RuntimeBindingIdentityV1,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    /// V2（service-enabled）准入携带完整 HostServicePolicyV2（含 policyDigest）；
    /// None 即 V1。policy 在场即绑定进 proof（versionDigestV2 公式）与后续 V2 投影。
    pub host_service_policy: Option<HostServicePolicyV2>,
    /// proof-pinned 的 admission.stagingTtlSeconds（NodeCapabilityRecordV1）。
    pub staging_ttl_seconds: u64,
    /// staging 已校验的 blob 集（digest hex → bytes）；事务负责内容寻址落盘。
    pub blobs: Vec<(String, Vec<u8>)>,
    /// 显式 owner 再准入：同 digest 分配更高 sequence；默认 false（同 digest 一律 join）。
    pub allow_resequence: bool,
}

#[derive(Debug, Clone)]
pub struct AdmissionOutcome {
    pub proof: AdmissionProofV1,
    pub key: VersionKey,
    pub created: bool,
    pub journal_revision: u64,
    pub state: AdmissionState,
}

#[derive(Debug, Clone, Default)]
pub struct RecoveryReport {
    pub completed: Vec<VersionKey>,
    pub failed: Vec<VersionKey>,
    pub pending: Vec<VersionKey>,
    /// visible 行 witness 失一致 → fail-closed 隔离（脱离路由资格，等 owner 恢复）。
    pub quarantined: Vec<VersionKey>,
}

fn lease_expired(row: &AdmissionJournalRow, now_epoch_millis: u64) -> Result<bool, AdmissionError> {
    match row.lease_expires_at.as_deref() {
        None => Ok(false), // 终态行无 lease。
        Some(lease) => Ok(parse_rfc3339_utc_millis(lease)? <= now_epoch_millis),
    }
}

/// 完整准入事务：create-or-join → validated → blobs+marker（object-complete）→
/// hidden DB 行（db-hidden）→ 幂等 handoff+receipt（materializer-acknowledged）→
/// DB CAS visible → journal visible。任何一步失败返回结构化错误并停在当前
/// journal 状态；重试/恢复从此处继续并收敛到同一结果（proof/token/revision 确定）。
pub fn commit_wasm_admission(
    stores: &mut AdmissionStores<'_>,
    request: &AdmissionRequest,
    token: &mut dyn TokenSource,
    now_epoch_millis: u64,
) -> Result<AdmissionOutcome, AdmissionError> {
    let joined = stores.journal.create_or_join(request, token, now_epoch_millis)?;
    let outcome = drive_to_visible(stores, &joined.key, Some(request), joined.created, now_epoch_millis)?;
    Ok(outcome)
}

/// 恢复驱动：journal 里每个非终态（及 materializer-acknowledged 之后被中断的）
/// 行推进到唯一终态；无请求可推进 object-complete 之后的全部步骤（blob 无法
/// 重写，需 owner 带原始请求重试；此处停在 pending 而不是伪造失败）。
pub fn recover_wasm_admission(stores: &mut AdmissionStores<'_>, now_epoch_millis: u64) -> Result<RecoveryReport, AdmissionError> {
    let mut report = RecoveryReport::default();
    for key in stores.journal.keys() {
        let Some(row) = stores.journal.row(&key) else { continue };
        if row.state.is_terminal() {
            continue;
        }
        if lease_expired(&row, now_epoch_millis)? {
            // 过期非终态行唯一去向是 failed（然后 GC）。
            stores.journal.transition(&key, AdmissionState::Failed, now_epoch_millis)?;
            report.failed.push(key);
            continue;
        }
        match drive_to_visible(stores, &key, None, false, now_epoch_millis) {
            Ok(_) => report.completed.push(key),
            Err(failure) => {
                // 驱动已把完整性破坏记录为 failed → 汇报为 failed（唯一终态），
                // 而不是把它当作恢复进程自身的致命错误。
                let now_failed = stores.journal.row(&key).is_some_and(|row| row.state == AdmissionState::Failed);
                if now_failed {
                    report.failed.push(key);
                } else if failure.code == WASM_ADMISSION_RESUME_NEEDS_REQUEST || failure.code == WASM_ADMISSION_TERMINAL_FAILED {
                    report.pending.push(key);
                } else {
                    return Err(failure);
                }
            }
        }
    }
    // 恢复期 fail-closed 扫描：visible DB 行的 witness 三段必须一致。
    for key in stores.db.keys() {
        let row_bytes = stores.db.row_bytes(&key).unwrap_or_default();
        if row_bytes.is_empty() {
            continue;
        }
        let db_row: AdmissionDbRow = parse_canonical_witness(&row_bytes)?;
        if db_row.visibility == "visible" && admitted_visible(stores.objects, stores.db, stores.materializer, &key.0, &key.1).is_err() {
            report.quarantined.push(key);
        }
    }
    Ok(report)
}

/// GC：仅 failed → collected；删除其对象前缀/DB 行/receipt。
/// 调用方必须先证明 retention 窗口已过且引用已检查（spec GC 条款）。
pub fn collect_failed_admission(stores: &mut AdmissionStores<'_>, key: &VersionKey, now_epoch_millis: u64) -> Result<AdmissionJournalRow, AdmissionError> {
    let row = stores.journal.row(key).ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "unknown journal row"))?;
    if row.state != AdmissionState::Failed {
        return Err(err(WASM_ADMISSION_STATE_INVALID, "only a failed admission may be collected"));
    }
    // collected 是幂等终态：重复收集直接返回现状。
    if row.state == AdmissionState::Collected {
        return Ok(row);
    }
    let prefix = version_prefix(&row.proof);
    stores.objects.remove_prefix(&prefix)?;
    stores.db.remove_row(key)?;
    stores.materializer.remove_receipt(key)?;
    stores.journal.transition(key, AdmissionState::Collected, now_epoch_millis)
}

fn integrity_failure(code: &str) -> bool {
    matches!(
        code,
        WASM_ADMISSION_OBJECT_CORRUPT | WASM_ADMISSION_DB_CONFLICT | WASM_ADMISSION_RECEIPT_MISMATCH | WASM_ADMISSION_FAIL_CLOSED
    )
}

fn drive_to_visible(
    stores: &mut AdmissionStores<'_>,
    key: &VersionKey,
    request: Option<&AdmissionRequest>,
    created: bool,
    now_epoch_millis: u64,
) -> Result<AdmissionOutcome, AdmissionError> {
    let mut row = stores.journal.row(key).ok_or_else(|| err(WASM_ADMISSION_JOURNAL_INVALID, "unknown journal row"))?;
    if row.state == AdmissionState::Visible {
        return Ok(AdmissionOutcome { proof: row.proof, key: key.clone(), created: false, journal_revision: row.journal_revision, state: row.state });
    }
    if row.state.is_terminal() {
        return Err(err(WASM_ADMISSION_TERMINAL_FAILED, "this admission has already reached a terminal failed/collected state"));
    }
    if lease_expired(&row, now_epoch_millis)? {
        stores.journal.transition(key, AdmissionState::Failed, now_epoch_millis)?;
        return Err(err(WASM_ADMISSION_LEASE_EXPIRED, "the admission lease expired; the row can only become failed and then collected"));
    }
    let proof_jcs = proof_jcs_bytes(&row.proof)?;
    let prefix = version_prefix(&row.proof);

    if row.state == AdmissionState::Staging {
        row = stores.journal.transition(key, AdmissionState::Validated, now_epoch_millis)?;
    }
    if row.state == AdmissionState::Validated {
        let Some(request) = request else {
            return Err(err(WASM_ADMISSION_RESUME_NEEDS_REQUEST, "resuming from staging/validated requires the owner to retry with the original package bytes"));
        };
        // join 重试的 blob 集必须与 staging 验证过的集合一致（digest 已被 proof 绑定）。
        if request.application_id != row.proof.application_id || request.package_digest != row.proof.package_digest {
            return Err(err(WASM_ADMISSION_PROOF_MISMATCH, "retry request does not match the joined journal proof"));
        }
        for (digest_hex, bytes) in &request.blobs {
            if sha256_hex(bytes) != *digest_hex {
                return Err(err(WASM_ADMISSION_OBJECT_CORRUPT, format!("blob {digest_hex} does not hash to its content address")));
            }
            stores.objects.write_blob(&prefix, digest_hex, bytes).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
        }
        if request.blobs.is_empty() {
            return Err(err(WASM_ADMISSION_OBJECT_CORRUPT, "a wasm package must carry at least one blob"));
        }
        let marker = CompletionMarker { schema_version: 1, proof: row.proof.clone() };
        let marker_bytes = jcs_bytes(&marker)?;
        stores.objects.write_completion_marker(&prefix, &marker_bytes).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
        stores.objects.verify_prefix(&prefix).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
        row = stores.journal.transition(key, AdmissionState::ObjectComplete, now_epoch_millis)?;
    }
    if matches!(row.state, AdmissionState::ObjectComplete | AdmissionState::DbHidden | AdmissionState::MaterializerAcknowledged) {
        // hidden 及之后：对象缺失/损坏即标 failed（spec 恢复表第 3 行）。
        stores.objects.verify_prefix(&prefix).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
    }
    if row.state == AdmissionState::ObjectComplete {
        let db_row = AdmissionDbRow { schema_version: 1, proof: row.proof.clone(), visibility: "hidden".into() };
        let db_bytes = jcs_bytes(&db_row)?;
        stores.db.insert_hidden_row(key, &db_bytes, &proof_jcs).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
        row = stores.journal.transition(key, AdmissionState::DbHidden, now_epoch_millis)?;
    }
    if row.state == AdmissionState::DbHidden {
        // 幂等 handoff：同 (key, target) 重发不产生第二份 receipt 或所有权。
        // V2 证明：receipt 显式携带 policy digest（P0-3）。
        let receipt = MaterializerReceipt {
            schema_version: 1,
            proof: row.proof.clone(),
            materialization_target: materialization_target(&proof_jcs),
            host_service_policy_digest: row.proof.host_service_policy.as_ref().map(|policy| policy.policy_digest.clone()),
        };
        let receipt_bytes = jcs_bytes(&receipt)?;
        stores.materializer.handoff(key, &receipt_bytes, &receipt.materialization_target).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
        row = stores.journal.transition(key, AdmissionState::MaterializerAcknowledged, now_epoch_millis)?;
    }
    if row.state == AdmissionState::MaterializerAcknowledged {
        // receipt 必须仍然 durable 且与 proof 三段一致（ack 丢失/重启后的重放检查）。
        verify_receipt_durable(stores.materializer, key, &row.proof, &proof_jcs).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
        // 只重试 DB hidden→visible CAS；成功前 materialized 字节不可执行。
        stores.db.flip_hidden_to_visible(key, &proof_jcs).map_err(|e| fail_row(stores, key, &e, now_epoch_millis))?;
        row = stores.journal.transition(key, AdmissionState::Visible, now_epoch_millis)?;
    }
    Ok(AdmissionOutcome { proof: row.proof, key: key.clone(), created, journal_revision: row.journal_revision, state: row.state })
}

fn fail_row(stores: &mut AdmissionStores<'_>, key: &VersionKey, failure: &AdmissionError, now_epoch_millis: u64) -> AdmissionError {
    if integrity_failure(failure.code) {
        let _ = stores.journal.transition(key, AdmissionState::Failed, now_epoch_millis);
    }
    failure.clone()
}

fn verify_receipt_durable(materializer: &dyn AdmissionMaterializer, key: &VersionKey, proof: &AdmissionProofV1, proof_jcs: &[u8]) -> Result<(), AdmissionError> {
    let bytes = materializer.receipt_bytes(key).ok_or_else(|| err(WASM_ADMISSION_RECEIPT_MISMATCH, "the materializer receipt is not durable"))?;
    let receipt: MaterializerReceipt = parse_canonical_witness(&bytes)?;
    if receipt.schema_version != 1 || receipt.proof != *proof {
        return Err(err(WASM_ADMISSION_RECEIPT_MISMATCH, "the durable receipt must carry the byte-identical proof"));
    }
    if receipt.materialization_target != materialization_target(proof_jcs) {
        return Err(err(WASM_ADMISSION_RECEIPT_MISMATCH, "materializationTarget must equal the domain digest formula of the proof"));
    }
    // V2：receipt 必须显式携带 proof 的 policy digest；V1 receipt 必须不携带
    //（policy digest 绑定不得从 receipt 缺席或被跨 generation 移植）。
    let expected_digest = proof.host_service_policy.as_ref().map(|policy| policy.policy_digest.clone());
    if receipt.host_service_policy_digest != expected_digest {
        return Err(err(WASM_ADMISSION_RECEIPT_MISMATCH, "the receipt hostServicePolicyDigest must carry exactly the proof's host service policy digest"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AdmittedVisible 谓词（唯一可见性判据）
// ---------------------------------------------------------------------------

/// AdmittedVisible(version)：当且仅当以下四条同时成立才为 true：
/// 四条同时成立才为 true：
/// 1. verified content-addressed object + 匹配 completion marker 存在；
/// 2. 恰好一条 Kernel 控制库行以 visibility "visible" 提交；
/// 3. 恰好一条 durable materializer receipt 存在；
/// 4. 完整 AdmissionProofV1（含 versionId/sequence/normalizedPolicy）在三段记录中字节一致。
///
/// P0-3 扩展：V2（service-enabled）证明要求 hostServicePolicy 在场且其 policyDigest
/// 复算匹配（verify_admission_proof 内绑定校验），并且 receipt 显式携带同一 policy
/// digest；V1 证明要求 receipt 不携带 policy digest（互不伪装）。
///
/// 返回 Ok(None)=不可见（hidden/缺失，无完整性破坏）；Err=WASM_ADMISSION_FAIL_CLOSED
/// （visible 行的 witness 失一致：脱离路由资格，等 owner 恢复，绝不从可变字节重建）。
pub fn admitted_visible(
    objects: &dyn AdmissionObjectStore,
    db: &dyn AdmissionControlDb,
    materializer: &dyn AdmissionMaterializer,
    application_id: &str,
    version_id: &str,
) -> Result<Option<AdmissionProofV1>, AdmissionError> {
    let key: VersionKey = (application_id.to_string(), version_id.to_string());
    let Some(row_bytes) = db.row_bytes(&key) else {
        return Ok(None);
    };
    let db_row: AdmissionDbRow = parse_canonical_witness(&row_bytes)?;
    if db_row.schema_version != 1 || (db_row.visibility != "hidden" && db_row.visibility != "visible") {
        return Err(err(WASM_ADMISSION_FAIL_CLOSED, "the control-db row must be a typed hidden/visible admission row"));
    }
    if db_row.visibility != "visible" {
        return Ok(None);
    }
    let proof_jcs = proof_jcs_bytes(&db_row.proof)?;
    let prefix = version_prefix(&db_row.proof);
    let fail_closed = |detail: &str| err(WASM_ADMISSION_FAIL_CLOSED, format!("visible version failed witness verification: {detail}"));
    // 1. 对象与 marker。
    let Some(marker_bytes) = objects.completion_marker_bytes(&prefix) else {
        return Err(fail_closed("the completion marker is missing"));
    };
    let marker: CompletionMarker = parse_canonical_witness(&marker_bytes).map_err(|e| fail_closed(&e.detail))?;
    if marker.schema_version != 1 || marker.proof != db_row.proof {
        return Err(fail_closed("the completion marker proof differs from the control-db row"));
    }
    objects.verify_prefix(&prefix).map_err(|e| fail_closed(&e.detail))?;
    // 2+3. receipt。
    let Some(receipt_bytes) = materializer.receipt_bytes(&key) else {
        return Err(fail_closed("the materializer receipt is missing"));
    };
    let receipt: MaterializerReceipt = parse_canonical_witness(&receipt_bytes).map_err(|e| fail_closed(&e.detail))?;
    if receipt.schema_version != 1 || receipt.proof != db_row.proof {
        return Err(fail_closed("the receipt proof differs from the control-db row"));
    }
    if receipt.materialization_target != materialization_target(&proof_jcs) {
        return Err(fail_closed("materializationTarget does not match the proof formula"));
    }
    let expected_policy_digest = db_row.proof.host_service_policy.as_ref().map(|policy| policy.policy_digest.clone());
    if receipt.host_service_policy_digest != expected_policy_digest {
        return Err(fail_closed("the receipt must carry exactly the proof's hostServicePolicyDigest (present for V2, absent for V1)"));
    }
    // 4. proof 内部自洽（versionId/sequence/normalizedPolicy/versionDigest/policy 绑定）。
    verify_admission_proof(&db_row.proof).map_err(|e| fail_closed(&e.detail))?;
    Ok(Some(db_row.proof))
}

// ---------------------------------------------------------------------------
// 到 Kernel wasm registry 的投影（与 celld ControlState/VersionRecord 物理隔离）
// ---------------------------------------------------------------------------

/// wasm 版本身份投影（celld VersionIdentity 的结构等价物；独立数据结构）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmVersionIdentity {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub digest: String,
    pub sequence: u64,
}

/// WasmKernelRouteRegistryV1 的版本行（admission 之后的 lifecycle 由后续任务推进；
/// 本模块只创建 lifecycle="admitted" 的行）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmVersionRegistryRow {
    #[serde(rename = "versionId")]
    pub version_id: String,
    pub identity: WasmVersionIdentity,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "normalizedPolicy")]
    pub normalized_policy: NormalizedWasmManifestV1,
    pub lifecycle: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "admissionProofRef")]
    pub admission_proof_ref: String,
    #[serde(rename = "admissionProofDigest")]
    pub admission_proof_digest: String,
    /// V2（service-enabled）行携带 hostServicePolicyDigest 静态摘要
    ///（policy digest + envelope + profile 字面量 + 启用服务；无动态用量——
    /// 控制态与数据面的结构隔离不变）。V1 行不携带该键。
    #[serde(rename = "hostServicePolicySummary", skip_serializing_if = "Option::is_none")]
    pub host_service_policy_summary: Option<crate::wasm_host_services::ControlStateServicePolicySummaryV2>,
    #[serde(rename = "readinessLeaseDigest", skip_serializing_if = "Option::is_none")]
    pub readiness_lease_digest: Option<String>,
}

/// wasm active pointer（激活由 readiness gate + route CAS 决定；准入绝不翻指针，
/// 因此本模块创建的记录恒为 unavailable）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
// wire 形状优先：Active 变体直接持有 identity/binding/proof 引用以保证 JCS 字节
// 精确；该枚举是低频控制面记录而非热路径数据，体积差不构成装箱理由。
#[allow(clippy::large_enum_variant)]
#[serde(tag = "kind")]
pub enum WasmActivePointerV1 {
    #[serde(rename = "active")]
    Active {
        #[serde(rename = "runtimeKind")]
        runtime_kind: String,
        #[serde(rename = "applicationId")]
        application_id: String,
        #[serde(rename = "versionId")]
        version_id: String,
        identity: WasmVersionIdentity,
        #[serde(rename = "runtimeBinding")]
        runtime_binding: RuntimeBindingIdentityV1,
        #[serde(rename = "admissionProofRef")]
        admission_proof_ref: String,
        #[serde(rename = "admissionProofDigest")]
        admission_proof_digest: String,
        #[serde(rename = "routeGeneration")]
        route_generation: u64,
        /// V2-ness marker：service-enabled 执行的 policyDigest（V1 指针 None/缺失，
        /// 字节形状不变）。完整 V2 identity 通过 admissionProofDigest + 此字段绑定。
        #[serde(rename = "hostServicePolicyDigest", skip_serializing_if = "Option::is_none", default)]
        host_service_policy_digest: Option<String>,
    },
    #[serde(rename = "unavailable")]
    Unavailable {
        #[serde(rename = "runtimeKind")]
        runtime_kind: String,
        #[serde(rename = "applicationId")]
        application_id: String,
        #[serde(rename = "routeGeneration")]
        route_generation: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmApplicationRegistryRecord {
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub versions: Vec<WasmVersionRegistryRow>,
    pub active: WasmActivePointerV1,
    #[serde(rename = "routeGeneration")]
    pub route_generation: u64,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
}

/// Kernel 拥有的 wasm 业务 registry（/data/kernel/wasm-control-state-v2.json 的
/// 内存形态）。与 celld crate::control::ControlState 物理隔离：不同文件、不同
/// 结构、不同 sequence 分配器；绝不把 wasm 记录投影进 celld VersionRecord，
/// 也绝不用 celld versionId=digest 表示法（spec "Kernel business authority is
/// partitioned by runtime kind"）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmKernelRouteRegistry {
    pub applications: BTreeMap<String, WasmApplicationRegistryRecord>,
}

/// proof → registry 行投影：identity={applicationId,digest,sequence}、
/// admissionProofRef="admission-proof/<app>/<versionId>"、
/// admissionProofDigest=hex(SHA-256("iweb-admission-proof-v1\n"||JCS(proof)))、
/// lifecycle="admitted"、readinessLeaseDigest=null（ready/active 才需要）；
/// V2 证明额外投影 hostServicePolicySummary（policy digest 静态摘要）。
pub fn project_registry_row(proof: &AdmissionProofV1) -> Result<WasmVersionRegistryRow, AdmissionError> {
    let proof_jcs = proof_jcs_bytes(proof)?;
    Ok(WasmVersionRegistryRow {
        version_id: proof.version_id.clone(),
        identity: WasmVersionIdentity { application_id: proof.application_id.clone(), digest: proof.version_digest.clone(), sequence: proof.sequence },
        package_digest: proof.package_digest.clone(),
        normalized_policy: proof.normalized_policy.clone(),
        lifecycle: "admitted".into(),
        runtime_binding: proof.runtime_binding.clone(),
        admission_proof_ref: format!("admission-proof/{}/{}", proof.application_id, proof.version_id),
        admission_proof_digest: admission_proof_digest(&proof_jcs),
        host_service_policy_summary: proof.host_service_policy.as_ref().map(|policy| policy.static_summary()),
        readiness_lease_digest: None,
    })
}

impl WasmKernelRouteRegistry {
    /// 幂等插入 admitted 行（同 versionId 重复投影返回既有行；同 versionId 不同内容
    /// fail-closed）。准入只创建 admitted 行与 unavailable 指针；绝不翻 active。
    pub fn insert_admitted(&mut self, proof: &AdmissionProofV1) -> Result<WasmVersionRegistryRow, AdmissionError> {
        let row = project_registry_row(proof)?;
        let application = self.applications.entry(proof.application_id.clone()).or_insert_with(|| WasmApplicationRegistryRecord {
            runtime_kind: "wasm".into(),
            application_id: proof.application_id.clone(),
            versions: Vec::new(),
            active: WasmActivePointerV1::Unavailable { runtime_kind: "wasm".into(), application_id: proof.application_id.clone(), route_generation: 0 },
            route_generation: 0,
            secret_revision: 0,
            config_revision: 0,
        });
        if let Some(existing) = application.versions.iter().find(|candidate| candidate.version_id == row.version_id) {
            if *existing == row {
                return Ok(existing.clone());
            }
            return Err(err(WASM_REGISTRY_CONFLICT, "the same versionId already projects to a different registry row"));
        }
        application.versions.push(row.clone());
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // -- golden 向量（TS 权威 packages/contracts 于 2026-08-26 产出） --

    const SPEC_VECTOR_MANIFEST: &str = r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#;
    const SPEC_VECTOR_PACKAGE_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const SPEC_VECTOR_VERSION_DIGEST: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";
    const GOLDEN_COMMIT_TOKEN: [u8; 32] = [0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef];
    const GOLDEN_COMMIT_TOKEN_HASH: &str = "af8f000697558656f805d09b826276d91661e2ccde22d6242c2ab6236d7f51a0";
    const GOLDEN_ADMISSION_PROOF_DIGEST: &str = "1dd357867fb385f557e1b4a9412cab01ecd004447cda836984b5c7f4fc278f63";
    const GOLDEN_MATERIALIZATION_TARGET: &str = "mat-02bfd0e5931b9a319f36f5ec8cb3ac37dc744ded";
    const GOLDEN_PROOF_JCS: &str = r#"{"applicationId":"vector","capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"commitTokenHash":"af8f000697558656f805d09b826276d91661e2ccde22d6242c2ab6236d7f51a0","lifecycleAdmissionRecord":{"admissionJournalRevision":0,"admittedAt":"2026-08-26T00:00:00Z","schemaVersion":1,"state":"admitted"},"normalizedPolicy":{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}},"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"sequence":1,"versionDigest":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}"#;

    fn vector_manifest() -> NormalizedWasmManifestV1 {
        serde_json::from_str(SPEC_VECTOR_MANIFEST).expect("spec vector manifest parses")
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

    fn vector_proof() -> AdmissionProofV1 {
        AdmissionProofV1 {
            schema_version: 1,
            application_id: "vector".into(),
            package_digest: SPEC_VECTOR_PACKAGE_DIGEST.into(),
            version_digest: SPEC_VECTOR_VERSION_DIGEST.into(),
            sequence: 1,
            version_id: format!("{SPEC_VECTOR_VERSION_DIGEST}-1"),
            normalized_policy: vector_manifest(),
            lifecycle_admission_record: LifecycleAdmissionRecord {
                schema_version: 1,
                state: "admitted".into(),
                admitted_at: "2026-08-26T00:00:00Z".into(),
                admission_journal_revision: 0,
            },
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            commit_token_hash: GOLDEN_COMMIT_TOKEN_HASH.into(),
            host_service_policy: None,
        }
    }

    // 独立 oracle：手工拼 preimage 再单次 SHA-256（不复用被测实现）。
    fn oracle_sha256_hex(parts: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hex::encode(hasher.finalize())
    }

    // -- 内存 mock 存储与故障注入 --

    #[derive(Default)]
    struct MockObjects {
        prefixes: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
        markers: BTreeMap<String, Vec<u8>>,
        fail_blob: bool,
        fail_marker: bool,
    }

    impl AdmissionObjectStore for MockObjects {
        fn write_blob(&mut self, prefix: &str, digest_hex: &str, bytes: &[u8]) -> Result<(), AdmissionError> {
            if self.fail_blob {
                return Err(err(WASM_ADMISSION_OBJECT_WRITE_FAILED, "injected blob write failure"));
            }
            if sha256_hex(bytes) != digest_hex {
                return Err(err(WASM_ADMISSION_OBJECT_CORRUPT, "blob name must equal sha256 of content"));
            }
            self.prefixes.entry(prefix.to_string()).or_default().insert(digest_hex.to_string(), bytes.to_vec());
            Ok(())
        }
        fn write_completion_marker(&mut self, prefix: &str, marker_bytes: &[u8]) -> Result<(), AdmissionError> {
            if self.fail_marker {
                return Err(err(WASM_ADMISSION_OBJECT_WRITE_FAILED, "injected marker write failure"));
            }
            self.markers.insert(prefix.to_string(), marker_bytes.to_vec());
            Ok(())
        }
        fn verify_prefix(&self, prefix: &str) -> Result<(), AdmissionError> {
            let blobs = self.prefixes.get(prefix).ok_or_else(|| err(WASM_ADMISSION_OBJECT_CORRUPT, "object prefix is missing"))?;
            if blobs.is_empty() {
                return Err(err(WASM_ADMISSION_OBJECT_CORRUPT, "object prefix has no content-addressed blobs"));
            }
            for (name, bytes) in blobs {
                if sha256_hex(bytes) != *name {
                    return Err(err(WASM_ADMISSION_OBJECT_CORRUPT, "a stored blob no longer hashes to its address"));
                }
            }
            if !self.markers.contains_key(prefix) {
                return Err(err(WASM_ADMISSION_OBJECT_CORRUPT, "the completion marker is missing"));
            }
            Ok(())
        }
        fn completion_marker_bytes(&self, prefix: &str) -> Option<Vec<u8>> {
            self.markers.get(prefix).cloned()
        }
        fn remove_prefix(&mut self, prefix: &str) -> Result<(), AdmissionError> {
            self.prefixes.remove(prefix);
            self.markers.remove(prefix);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockDb {
        rows: BTreeMap<VersionKey, Vec<u8>>,
        fail_insert: bool,
        fail_flip: bool,
    }

    impl AdmissionControlDb for MockDb {
        fn insert_hidden_row(&mut self, key: &VersionKey, row_bytes: &[u8], proof_jcs: &[u8]) -> Result<(), AdmissionError> {
            if self.fail_insert {
                return Err(err(WASM_ADMISSION_DB_WRITE_FAILED, "injected db insert failure"));
            }
            if let Some(existing) = self.rows.get(key) {
                let existing_row: AdmissionDbRow = parse_canonical_witness(existing)?;
                if existing_row.visibility == "visible" {
                    if existing == row_bytes {
                        return Ok(());
                    }
                    return Err(err(WASM_ADMISSION_DB_CONFLICT, "a visible row cannot be rewritten"));
                }
                if existing != row_bytes {
                    return Err(err(WASM_ADMISSION_DB_CONFLICT, "the hidden row already exists with a different proof"));
                }
                return Ok(());
            }
            let row: AdmissionDbRow = parse_canonical_witness(row_bytes)?;
            if row.visibility != "hidden" {
                return Err(err(WASM_ADMISSION_DB_CONFLICT, "insert must write a hidden row"));
            }
            // 行的 proof JCS 必须与调用方绑定的 proof 一致（proof-bound insert）。
            if jcs_bytes(&row.proof)? != proof_jcs {
                return Err(err(WASM_ADMISSION_DB_CONFLICT, "the hidden row proof does not match the transaction proof"));
            }
            self.rows.insert(key.clone(), row_bytes.to_vec());
            Ok(())
        }
        fn flip_hidden_to_visible(&mut self, key: &VersionKey, proof_jcs: &[u8]) -> Result<bool, AdmissionError> {
            if self.fail_flip {
                return Err(err(WASM_ADMISSION_DB_WRITE_FAILED, "injected db flip failure"));
            }
            let existing = self.rows.get(key).ok_or_else(|| err(WASM_ADMISSION_FAIL_CLOSED, "the control-db row is missing"))?;
            let row: AdmissionDbRow = parse_canonical_witness(existing)?;
            let current_proof_jcs = jcs_bytes(&row.proof)?;
            if current_proof_jcs != proof_jcs {
                return Err(err(WASM_ADMISSION_DB_CONFLICT, "the row carries a different proof"));
            }
            match row.visibility.as_str() {
                "visible" => Ok(false),
                "hidden" => {
                    let flipped = AdmissionDbRow { schema_version: 1, proof: row.proof, visibility: "visible".into() };
                    self.rows.insert(key.clone(), jcs_bytes(&flipped)?);
                    Ok(true)
                }
                _ => Err(err(WASM_ADMISSION_DB_CONFLICT, "unknown visibility")),
            }
        }
        fn row_bytes(&self, key: &VersionKey) -> Option<Vec<u8>> {
            self.rows.get(key).cloned()
        }
        fn remove_row(&mut self, key: &VersionKey) -> Result<(), AdmissionError> {
            self.rows.remove(key);
            Ok(())
        }
        fn keys(&self) -> Vec<VersionKey> {
            self.rows.keys().cloned().collect()
        }
    }

    #[derive(Default)]
    struct MockMaterializer {
        receipts: BTreeMap<VersionKey, Vec<u8>>,
        fail_handoff: bool,
    }

    impl AdmissionMaterializer for MockMaterializer {
        fn handoff(&mut self, key: &VersionKey, receipt_bytes: &[u8], target: &str) -> Result<(), AdmissionError> {
            if self.fail_handoff {
                return Err(err(WASM_ADMISSION_HANDOFF_FAILED, "injected handoff failure"));
            }
            if let Some(existing) = self.receipts.get(key) {
                let existing_receipt: MaterializerReceipt = parse_canonical_witness(existing)?;
                let incoming: MaterializerReceipt = parse_canonical_witness(receipt_bytes)?;
                if existing_receipt.materialization_target != incoming.materialization_target || existing_receipt.proof != incoming.proof {
                    return Err(err(WASM_ADMISSION_RECEIPT_MISMATCH, "a different receipt already exists for this version"));
                }
                return Ok(());
            }
            let receipt: MaterializerReceipt = parse_canonical_witness(receipt_bytes)?;
            if receipt.materialization_target != target {
                return Err(err(WASM_ADMISSION_RECEIPT_MISMATCH, "receipt target disagrees with the handoff target"));
            }
            self.receipts.insert(key.clone(), receipt_bytes.to_vec());
            Ok(())
        }
        fn receipt_bytes(&self, key: &VersionKey) -> Option<Vec<u8>> {
            self.receipts.get(key).cloned()
        }
        fn remove_receipt(&mut self, key: &VersionKey) -> Result<(), AdmissionError> {
            self.receipts.remove(key);
            Ok(())
        }
    }

    /// 可共享的 mock 集合（并发同 proof 测试要分两组句柄交替推进）。
    #[derive(Default)]
    struct MockWorld {
        journal: WasmAdmissionJournal,
        objects: MockObjects,
        db: MockDb,
        materializer: MockMaterializer,
    }

    impl MockWorld {
        fn stores(&mut self) -> AdmissionStores<'_> {
            AdmissionStores { journal: &mut self.journal, objects: &mut self.objects, db: &mut self.db, materializer: &mut self.materializer }
        }
    }

    struct CountingTokenSource {
        counter: u64,
    }

    impl CountingTokenSource {
        fn new() -> Self {
            Self { counter: 0 }
        }
    }

    impl TokenSource for CountingTokenSource {
        fn generate(&mut self) -> Result<[u8; 32], AdmissionError> {
            let mut token = [0u8; 32];
            token[0] = (self.counter >> 24) as u8;
            token[1] = (self.counter >> 16) as u8;
            token[2] = (self.counter >> 8) as u8;
            token[3] = self.counter as u8;
            self.counter += 1;
            Ok(token)
        }
    }

    const T0: u64 = 1_800_000_000_000; // 2027-01-15T08:00:00.000Z，测试固定时钟。

    fn request() -> AdmissionRequest {
        // staging 已校验的内容寻址 blob 集：名称 = sha256(内容)。
        let layer = b"layer-bytes".to_vec();
        let layer_digest = sha256_hex(&layer);
        AdmissionRequest {
            application_id: "vector".into(),
            package_digest: SPEC_VECTOR_PACKAGE_DIGEST.into(),
            normalized_policy: vector_manifest(),
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            host_service_policy: None,
            staging_ttl_seconds: 600,
            blobs: vec![(layer_digest, layer)],
            allow_resequence: false,
        }
    }

    // -- digest/proof golden 对齐 --

    #[test]
    fn version_digest_matches_published_spec_vector() {
        let manifest_bytes = jcs_bytes(&vector_manifest()).expect("jcs");
        assert_eq!(manifest_bytes.len(), 405, "JCS bytes must be the published 405-byte vector");
        assert_eq!(std::str::from_utf8(&manifest_bytes).unwrap(), SPEC_VECTOR_MANIFEST, "JCS bytes must be byte-identical to the spec vector");
        let digest = wasm_version_digest_v1(SPEC_VECTOR_PACKAGE_DIGEST, &manifest_bytes);
        assert_eq!(digest, SPEC_VECTOR_VERSION_DIGEST);
        // 独立 oracle：手工 preimage 单次 SHA-256。
        let preimage = format!("iweb-wasm-version-digest-v1\npackage {SPEC_VECTOR_PACKAGE_DIGEST}\nadmission-manifest 405\n");
        let oracle = oracle_sha256_hex(&[preimage.as_bytes(), &manifest_bytes]);
        assert_eq!(digest, oracle);
    }

    #[test]
    fn proof_jcs_and_domain_digests_match_ts_vectors() {
        let proof = vector_proof();
        let proof_jcs = jcs_bytes(&proof).expect("jcs");
        assert_eq!(std::str::from_utf8(&proof_jcs).unwrap(), GOLDEN_PROOF_JCS, "proof JCS must be byte-identical to the TS authority vector");
        assert_eq!(proof_jcs.len(), 1375);
        assert_eq!(admission_proof_digest(&proof_jcs), GOLDEN_ADMISSION_PROOF_DIGEST);
        assert_eq!(materialization_target(&proof_jcs), GOLDEN_MATERIALIZATION_TARGET);
        // token hash 绑定 token 字节本身（域前缀 + 单次 SHA-256）。
        assert_eq!(commit_token_hash(&GOLDEN_COMMIT_TOKEN), GOLDEN_COMMIT_TOKEN_HASH);
        let mut other = [0u8; 32];
        other[0] = 0x01;
        assert_eq!(commit_token_hash(&other), "1407deb08292288a2f45b1b249b5d28792e1322ee8a9acb32570cca495189e59");
        // 独立 oracle 复算 proof digest。
        let oracle = oracle_sha256_hex(&[b"iweb-admission-proof-v1\n", &proof_jcs]);
        assert_eq!(admission_proof_digest(&proof_jcs), oracle);
        // round-trip：typed 解析 golden JCS 再序列化保持字节一致。
        let parsed: AdmissionProofV1 = serde_json::from_str(GOLDEN_PROOF_JCS).expect("golden proof parses");
        assert_eq!(jcs_bytes(&parsed).unwrap(), proof_jcs);
    }

    #[test]
    fn verify_admission_proof_rejects_every_divergence() {
        let proof = vector_proof();
        verify_admission_proof(&proof).expect("vector proof is internally consistent");
        let mut wrong_version_digest = proof.clone();
        wrong_version_digest.version_digest = "e".repeat(64);
        wrong_version_digest.version_id = format!("{}-1", "e".repeat(64));
        assert_eq!(verify_admission_proof(&wrong_version_digest).unwrap_err().code, WASM_VERSION_DIGEST_MISMATCH);
        let mut wrong_composition = proof.clone();
        wrong_composition.version_id = format!("{SPEC_VECTOR_VERSION_DIGEST}-2");
        assert_eq!(verify_admission_proof(&wrong_composition).unwrap_err().code, WASM_VERSION_ID_INVALID);
        let mut wrong_name = proof.clone();
        wrong_name.application_id = "other".into();
        assert_eq!(verify_admission_proof(&wrong_name).unwrap_err().code, WASM_APPLICATION_ID_MISMATCH);
        let mut wrong_token_hash = proof.clone();
        wrong_token_hash.commit_token_hash = "F".repeat(64);
        assert_eq!(verify_admission_proof(&wrong_token_hash).unwrap_err().code, "INVALID_DIGEST");
        let mut wrong_world = proof.clone();
        wrong_world.normalized_policy.runtime.world = "wasi:http/proxy@0.2.7".into();
        assert_eq!(verify_admission_proof(&wrong_world).unwrap_err().code, WASM_MANIFEST_INVALID);
    }

    #[test]
    fn manifest_typed_parse_rejects_duplicates_unknown_floats_and_exponents() {
        assert!(serde_json::from_str::<NormalizedWasmManifestV1>(SPEC_VECTOR_MANIFEST).is_ok());
        // 重复成员名：serde derive 在覆盖前检测（对位 TS parseStrictJson）。
        let duplicated = SPEC_VECTOR_MANIFEST.replace(r#""name":"vector""#, r#""name":"vector","name":"vector""#);
        assert!(serde_json::from_str::<NormalizedWasmManifestV1>(&duplicated).is_err());
        // 未知字段。
        let unknown = SPEC_VECTOR_MANIFEST.replace(r#""schemaVersion":1,"storage""#, r#""schemaVersion":1,"entrypoint":"x","storage""#);
        assert!(serde_json::from_str::<NormalizedWasmManifestV1>(&unknown).is_err());
        // 浮点与指数形式数值。
        let floating = SPEC_VECTOR_MANIFEST.replace(r#""cpuMillis":1"#, r#""cpuMillis":1.5"#);
        assert!(serde_json::from_str::<NormalizedWasmManifestV1>(&floating).is_err());
        let exponent = SPEC_VECTOR_MANIFEST.replace(r#""memoryBytes":2"#, r#""memoryBytes":2e0"#);
        assert!(serde_json::from_str::<NormalizedWasmManifestV1>(&exponent).is_err());
        // requestBytes > storageBytes。
        let oversubscribed = SPEC_VECTOR_MANIFEST.replace(r#""requestBytes":0"#, r#""requestBytes":5"#);
        let parsed = serde_json::from_str::<NormalizedWasmManifestV1>(&oversubscribed).expect("shape ok");
        assert_eq!(validate_normalized_manifest(&parsed).unwrap_err().code, WASM_MANIFEST_INVALID);
    }

    #[test]
    fn version_id_grammar_negative_vectors() {
        assert!(parse_wasm_version_id(&format!("{}-1", "a".repeat(64))).is_ok());
        assert_eq!(parse_wasm_version_id(&format!("{}-01", "a".repeat(64))).unwrap_err().code, WASM_VERSION_ID_INVALID);
        assert_eq!(parse_wasm_version_id(&format!("{}-0", "a".repeat(64))).unwrap_err().code, WASM_VERSION_ID_INVALID);
        assert_eq!(parse_wasm_version_id(&format!("{}-{}", "a".repeat(64), "9".repeat(17))).unwrap_err().code, WASM_VERSION_ID_INVALID);
        assert_eq!(parse_wasm_version_id(&format!("{}-1", "A".repeat(64))).unwrap_err().code, WASM_VERSION_ID_INVALID);
    }

    #[test]
    fn rfc3339_round_trip_is_exact() {
        let formatted = format_rfc3339_utc_millis(T0);
        assert_eq!(formatted, "2027-01-15T08:00:00.000Z");
        assert_eq!(parse_rfc3339_utc_millis(&formatted).unwrap(), T0);
        assert_eq!(parse_rfc3339_utc_millis("2026-08-26T00:00:00Z").unwrap(), 1_787_702_400_000);
        assert_eq!(format_rfc3339_utc_millis(1_787_702_400_000), "2026-08-26T00:00:00.000Z");
        assert!(parse_rfc3339_utc_millis("2026-08-26T00:00:00+01:00").is_err());
        assert!(parse_rfc3339_utc_millis("2026-13-01T00:00:00Z").is_err());
        assert!(parse_rfc3339_utc_millis("2026-02-30T00:00:00Z").is_err());
        assert!(parse_rfc3339_utc_millis("2026-08-26T24:00:00Z").is_err());
    }

    // -- 事务：happy path 与每个中断点 --

    #[test]
    fn happy_path_commits_to_visible_with_unique_result() {
        let mut world = MockWorld::default();
        let mut token = CountingTokenSource::new();
        let outcome = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).expect("commit");
        assert_eq!(outcome.state, AdmissionState::Visible);
        assert!(outcome.created);
        assert_eq!(outcome.journal_revision, 5, "creation=revision 0，validated→object-complete→db-hidden→acknowledged→visible 共 5 次迁移");
        let key = outcome.key.clone();
        assert_eq!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).expect("predicate ok").map(|p| p.version_id), Some(outcome.proof.version_id.clone()));
        // 幂等重放：同请求再提交，不产生新版本/新 token/新 target。
        let replay = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0 + 1_000).expect("replay");
        assert!(!replay.created);
        assert_eq!(replay.proof, outcome.proof);
        assert_eq!(world.journal.keys().len(), 1);
        assert_eq!(world.materializer.receipts.len(), 1);
    }

    #[test]
    fn interruption_marker_without_db_row_recovers_uniquely() {
        let mut world = MockWorld::default();
        world.db.fail_insert = true;
        let mut token = CountingTokenSource::new();
        let failed = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0);
        assert_eq!(failed.unwrap_err().code, WASM_ADMISSION_DB_WRITE_FAILED);
        let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
        // 中断点现状：marker 持久、DB 无行 → 不可见。
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_none());
        // 恢复（无请求也可推进：object-complete 之后的所有步骤只依赖 proof）。
        world.db.fail_insert = false;
        let report = recover_wasm_admission(&mut world.stores(), T0 + 1_000).expect("recover");
        assert_eq!(report.completed, vec![key.clone()]);
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_some());
        // 再恢复一次：唯一结果，无新迁移。
        let again = recover_wasm_admission(&mut world.stores(), T0 + 2_000).expect("recover again");
        assert!(again.completed.is_empty() && again.failed.is_empty() && again.quarantined.is_empty());
        let row = world.journal.row(&key).unwrap();
        assert_eq!(row.state, AdmissionState::Visible);
        assert_eq!(row.journal_revision, 5);
    }

    #[test]
    fn interruption_db_committed_but_handoff_lost_recovers_by_resend() {
        let mut world = MockWorld::default();
        world.materializer.fail_handoff = true;
        let mut token = CountingTokenSource::new();
        let failed = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0);
        assert_eq!(failed.unwrap_err().code, WASM_ADMISSION_HANDOFF_FAILED);
        let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
        // hidden 行绝不可见、绝不可执行，即使对象与 marker 已就绪。
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_none());
        world.materializer.fail_handoff = false;
        let report = recover_wasm_admission(&mut world.stores(), T0 + 1_000).expect("recover");
        assert_eq!(report.completed, vec![key.clone()]);
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_some());
    }

    #[test]
    fn interruption_receipt_ok_but_final_flip_fails_retries_only_flip() {
        let mut world = MockWorld::default();
        world.db.fail_flip = true;
        let mut token = CountingTokenSource::new();
        let failed = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0);
        assert_eq!(failed.unwrap_err().code, WASM_ADMISSION_DB_WRITE_FAILED);
        let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
        // receipt 已 durable、DB 仍 hidden：materialized 字段不可执行。
        assert!(world.materializer.receipt_bytes(&key).is_some());
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_none());
        world.db.fail_flip = false;
        let report = recover_wasm_admission(&mut world.stores(), T0 + 1_000).expect("recover");
        assert_eq!(report.completed, vec![key.clone()]);
        // 只重试了 flip：receipt 没有第二份，marker 没有重写。
        assert_eq!(world.materializer.receipts.len(), 1);
    }

    #[test]
    fn interruption_client_response_lost_query_returns_one_outcome() {
        let mut world = MockWorld::default();
        let mut token = CountingTokenSource::new();
        // 响应丢失 = 调用方丢弃 outcome；世界状态已经推进。
        let dropped = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).expect("commit");
        let key = dropped.key.clone();
        let queried = world.journal.row(&key).expect("journal outcome");
        assert_eq!(queried.state, AdmissionState::Visible);
        // 带同 proof 的重试不能创建另一个版本或 materializer target。
        let retry = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0 + 5_000).expect("retry");
        assert_eq!(retry.proof, dropped.proof);
        assert_eq!(world.journal.keys().len(), 1);
        assert_eq!(world.materializer.receipts.len(), 1);
    }

    #[test]
    fn interruption_partial_blob_write_fails_without_marker() {
        let mut world = MockWorld::default();
        world.objects.fail_blob = true;
        let mut token = CountingTokenSource::new();
        let failed = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0);
        assert_eq!(failed.unwrap_err().code, WASM_ADMISSION_OBJECT_WRITE_FAILED);
        let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
        let row = world.journal.row(&key).unwrap();
        assert_eq!(row.state, AdmissionState::Validated, "blob 写失败停在 validated，不伪造 object-complete");
        // 带原始请求的重试恢复。
        world.objects.fail_blob = false;
        let outcome = commit_wasm_admission(&mut world.stores(), &request(), &mut CountingTokenSource::new(), T0 + 1_000).expect("resume");
        assert_eq!(outcome.state, AdmissionState::Visible);
        assert!(!outcome.created, "重试 join 既有事务，不分配新 sequence");
    }

    #[test]
    fn concurrent_same_proof_converges_on_one_transaction() {
        let shared = Rc::new(RefCell::new(MockWorld::default()));
        let mut first = CountingTokenSource::new();
        let mut second = CountingTokenSource::new();
        // 两个并发调用者先后 create-or-join（交错推进），同一 proof 只有一个事务。
        let first_join = shared.borrow_mut().journal.create_or_join(&request(), &mut first, T0).expect("join1");
        let second_join = shared.borrow_mut().journal.create_or_join(&request(), &mut second, T0).expect("join2");
        assert!(first_join.created);
        assert!(!second_join.created, "第二个调用者 join 同一 (applicationId, versionId)");
        assert_eq!(first_join.proof, second_join.proof, "并发重试收到同一持久 proof 与 token hash");
        assert_eq!(first.token_count(), 1, "只获胜 insert 生成一次 token");
        // 交替推进到 visible：两个调用者最终看到同一 journal 结果。
        let a = {
            let mut world = shared.borrow_mut();
            commit_wasm_admission(&mut world.stores(), &request(), &mut second, T0 + 1)
        };
        let b = {
            let mut world = shared.borrow_mut();
            commit_wasm_admission(&mut world.stores(), &request(), &mut first, T0 + 2)
        };
        let (a, b) = (a.expect("a commits"), b.expect("b commits"));
        assert_eq!(a.proof, b.proof);
        assert_eq!(a.journal_revision, b.journal_revision);
        assert_eq!(shared.borrow().journal.keys().len(), 1);
        assert_eq!(shared.borrow().materializer.receipts.len(), 1);
    }

    #[test]
    fn lease_expiry_forces_failed_and_never_visible() {
        let mut world = MockWorld::default();
        world.db.fail_insert = true;
        let mut token = CountingTokenSource::new();
        commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).unwrap_err();
        let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
        // 越过 lease（stagingTtlSeconds=600）再恢复：唯一去向是 failed。
        let report = recover_wasm_admission(&mut world.stores(), T0 + 601_000).expect("recover");
        assert_eq!(report.failed, vec![key.clone()]);
        assert_eq!(world.journal.row(&key).unwrap().state, AdmissionState::Failed);
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_none());
        // 过期后重试也绝不能继续走向 visible。
        let retry = commit_wasm_admission(&mut world.stores(), &request(), &mut CountingTokenSource::new(), T0 + 602_000);
        assert_eq!(retry.unwrap_err().code, WASM_ADMISSION_TERMINAL_FAILED);
        // GC：failed → collected（调用方已证明 retention 窗口）。
        world.db.fail_insert = false;
        let collected = collect_failed_admission(&mut world.stores(), &key, T0 + 900_000).expect("collect");
        assert_eq!(collected.state, AdmissionState::Collected);
        assert!(world.db.row_bytes(&key).is_none());
        assert!(world.materializer.receipt_bytes(&key).is_none());
    }

    #[test]
    fn visible_row_with_missing_marker_fails_closed() {
        let mut world = MockWorld::default();
        let mut token = CountingTokenSource::new();
        let outcome = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).expect("commit");
        let key = outcome.key.clone();
        // 模拟 marker 损毁（例如对象层损坏）。
        world.objects.markers.remove(&version_prefix(&outcome.proof)).unwrap();
        let visible = admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1);
        assert_eq!(visible.unwrap_err().code, WASM_ADMISSION_FAIL_CLOSED);
        // 恢复扫描也把它隔离（脱离路由资格），绝不从可变工作区字节重建。
        let report = recover_wasm_admission(&mut world.stores(), T0 + 1_000).expect("recover");
        assert_eq!(report.quarantined, vec![key.clone()]);
    }

    #[test]
    fn visible_row_with_missing_receipt_fails_closed() {
        let mut world = MockWorld::default();
        let mut token = CountingTokenSource::new();
        let outcome = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).expect("commit");
        let key = outcome.key.clone();
        world.materializer.receipts.remove(&key).unwrap();
        assert_eq!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap_err().code, WASM_ADMISSION_FAIL_CLOSED);
    }

    #[test]
    fn receipt_with_tampered_proof_fails_predicate() {
        let mut world = MockWorld::default();
        let mut token = CountingTokenSource::new();
        let outcome = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).expect("commit");
        let key = outcome.key.clone();
        // 篡改 receipt 的 proof（换 capabilityRecordHash）后回写非规范字节也应被 typed+JCS 检查拦下。
        let mut tampered = world.materializer.receipt_bytes(&key).unwrap();
        tampered[10] = b'3';
        world.materializer.receipts.insert(key.clone(), tampered);
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).is_err());
    }

    #[test]
    fn hidden_row_with_marker_and_receipt_is_not_visible() {
        let mut world = MockWorld::default();
        world.db.fail_flip = true;
        let mut token = CountingTokenSource::new();
        let outcome = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0);
        outcome.unwrap_err();
        let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
        // marker+receipt 俱全、DB 行 hidden：谓词必须 false（不得把任何中间态当版本）。
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_none());
    }

    #[test]
    fn corrupt_object_after_db_hidden_marks_failed() {
        let mut world = MockWorld::default();
        world.db.fail_flip = true;
        let mut token = CountingTokenSource::new();
        commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).unwrap_err();
        let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
        // 对象损坏（blob 内容与地址不符）→ hidden 行标 failed，等待 GC。
        let prefix = version_prefix(&world.journal.row(&key).unwrap().proof);
        world.objects.prefixes.get_mut(&prefix).unwrap().insert("1".repeat(64), b"tampered".to_vec());
        world.db.fail_flip = false;
        let report = recover_wasm_admission(&mut world.stores(), T0 + 1_000).expect("recover");
        assert_eq!(report.failed, vec![key.clone()]);
        assert_eq!(world.journal.row(&key).unwrap().state, AdmissionState::Failed);
    }

    // -- sequence / 再准入语义 --

    #[test]
    fn later_owner_admission_of_same_digest_allocates_higher_sequence() {
        let mut world = MockWorld::default();
        let mut token = CountingTokenSource::new();
        let first = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).expect("first");
        assert_eq!(first.proof.sequence, 1);
        let mut resequence = request();
        resequence.allow_resequence = true;
        let second = commit_wasm_admission(&mut world.stores(), &resequence, &mut token, T0 + 1_000).expect("second");
        assert_eq!(second.proof.sequence, 2, "同 digest 的后续 owner 准入分配更高 sequence");
        assert_ne!(second.proof.version_id, first.proof.version_id);
        assert_ne!(second.proof.commit_token_hash, first.proof.commit_token_hash, "不同 versionId 各自生成独立 token");
        // journal 内两行都在，各自可见。
        for key in [first.key.clone(), second.key.clone()] {
            assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_some());
        }
    }

    #[test]
    fn resequence_rejected_while_previous_is_in_flight() {
        let mut world = MockWorld::default();
        world.db.fail_insert = true;
        let mut token = CountingTokenSource::new();
        commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).unwrap_err();
        let mut resequence = request();
        resequence.allow_resequence = true;
        let rejected = commit_wasm_admission(&mut world.stores(), &resequence, &mut CountingTokenSource::new(), T0 + 1_000);
        assert_eq!(rejected.unwrap_err().code, WASM_ADMISSION_IN_FLIGHT);
    }

    #[test]
    fn retry_with_divergent_binding_fails_closed() {
        let mut world = MockWorld::default();
        world.db.fail_insert = true;
        let mut token = CountingTokenSource::new();
        commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0).unwrap_err();
        let mut divergent = request();
        divergent.runtime_binding.catalog_revision = 10;
        let rejected = commit_wasm_admission(&mut world.stores(), &divergent, &mut CountingTokenSource::new(), T0 + 1_000);
        assert_eq!(rejected.unwrap_err().code, WASM_ADMISSION_PROOF_MISMATCH);
        // 文件持久化 journal 的 join 路径必须执行同一 mismatch 校验（实现统一性）。
        let dir = std::env::temp_dir().join("iweb-kernel-wasm-admission-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal-c.jsonl");
        let _ = std::fs::remove_file(&path);
        {
            let mut journal = WasmAdmissionJournalFile::open(&path).unwrap();
            journal.create_or_join(&request(), &mut CountingTokenSource::new(), T0).expect("create");
        }
        {
            let mut journal = WasmAdmissionJournalFile::open(&path).unwrap();
            let rejected = journal.create_or_join(&divergent, &mut CountingTokenSource::new(), T0 + 1_000);
            assert_eq!(rejected.unwrap_err().code, WASM_ADMISSION_PROOF_MISMATCH);
        }
        let _ = std::fs::remove_file(&path);
    }

    // -- journal 文件持久化与重放 --

    #[test]
    fn file_journal_replays_state_and_discards_torn_tail() {
        let dir = std::env::temp_dir().join("iweb-kernel-wasm-admission-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal-a.jsonl");
        let _ = std::fs::remove_file(&path);
        let key;
        {
            let mut journal = WasmAdmissionJournalFile::open(&path).unwrap();
            let mut token = CountingTokenSource::new();
            let joined = journal.create_or_join(&request(), &mut token, T0).expect("create");
            key = joined.key.clone();
            journal.transition(&key, AdmissionState::Validated, T0).unwrap();
            journal.transition(&key, AdmissionState::ObjectComplete, T0).unwrap();
        }
        // 正常重放：崩溃后从文件重建到 object-complete。
        {
            let journal = WasmAdmissionJournalFile::open(&path).unwrap();
            assert_eq!(journal.row(&key).unwrap().state, AdmissionState::ObjectComplete);
            assert_eq!(journal.row(&key).unwrap().journal_revision, 2);
            // sequence 分配器重建：下一个准入不得复用 sequence 1。
        }
        // 尾部残行（无换行的部分写）被丢弃。
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(br#"{"schemaVersion":1,"proof":{"applicationId":"vec"#).unwrap();
        }
        {
            let journal = WasmAdmissionJournalFile::open(&path).unwrap();
            assert_eq!(journal.row(&key).unwrap().state, AdmissionState::ObjectComplete, "残行不破坏已提交状态");
        }
        // 中部损坏行 fail-closed。
        {
            let text = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<&str> = text.split('\n').collect();
            lines[1] = r#"{"broken":"record"}"#;
            std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        }
        assert_eq!(WasmAdmissionJournalFile::open(&path).unwrap_err().code, WASM_ADMISSION_JOURNAL_INVALID);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_journal_replay_continues_end_to_end_after_reopen() {
        let dir = std::env::temp_dir().join("iweb-kernel-wasm-admission-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("journal-b.jsonl");
        let _ = std::fs::remove_file(&path);
        let key;
        {
            let mut journal = WasmAdmissionJournalFile::open(&path).unwrap();
            let mut token = CountingTokenSource::new();
            let joined = journal.create_or_join(&request(), &mut token, T0).expect("create");
            key = joined.key.clone();
            journal.transition(&key, AdmissionState::Validated, T0).unwrap();
        }
        // 崩溃后重开：继续推进到 visible，且 token/proof 不变。
        let mut world = MockWorld::default();
        {
            let mut journal = WasmAdmissionJournalFile::open(&path).unwrap();
            let proof_before = journal.row(&key).unwrap().proof.clone();
            let mut stores = AdmissionStores { journal: &mut journal, objects: &mut world.objects, db: &mut world.db, materializer: &mut world.materializer };
            let outcome = commit_wasm_admission(&mut stores, &request(), &mut CountingTokenSource::new(), T0 + 1_000).expect("resume to visible");
            assert_eq!(outcome.state, AdmissionState::Visible);
            assert_eq!(outcome.proof, proof_before, "重放沿用持久 token hash，不重新生成");
            assert!(!outcome.created);
        }
        assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_some());
        // sequence 不复用：再准入同 digest 分配 sequence 2。
        {
            let mut journal = WasmAdmissionJournalFile::open(&path).unwrap();
            let mut resequence = request();
            resequence.allow_resequence = true;
            let joined = journal.create_or_join(&resequence, &mut CountingTokenSource::new(), T0 + 2_000).expect("resequence");
            assert_eq!(joined.proof.sequence, 2);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn journal_replay_rejects_regression_and_revision_skips() {
        let mut journal = WasmAdmissionJournal::new();
        let mut token = CountingTokenSource::new();
        let joined = journal.create_or_join(&request(), &mut token, T0).expect("create");
        let key = joined.key.clone();
        // 直接重放 visible（跳过中间态）→ 拒绝。
        let mut skip = journal.row(&key).unwrap();
        skip.state = AdmissionState::Visible;
        skip.journal_revision = 1;
        skip.lease_expires_at = None;
        assert_eq!(journal.replay_row(skip).unwrap_err().code, WASM_ADMISSION_JOURNAL_INVALID);
        // 回退（visible→db-hidden）→ 拒绝。
        journal.transition(&key, AdmissionState::Validated, T0).unwrap();
        let mut regression = journal.row(&key).unwrap();
        regression.state = AdmissionState::Staging;
        regression.journal_revision = 3;
        assert_eq!(journal.replay_row(regression).unwrap_err().code, WASM_ADMISSION_JOURNAL_INVALID);
        // proof 突变 → 拒绝。
        let mut mutated = journal.row(&key).unwrap();
        mutated.journal_revision += 1;
        mutated.proof.commit_token_hash = "9".repeat(64);
        assert_eq!(journal.replay_row(mutated).unwrap_err().code, WASM_ADMISSION_JOURNAL_INVALID);
    }

    // -- registry 投影 --

    #[test]
    fn registry_projection_is_exact_and_idempotent() {
        let proof = vector_proof();
        let row = project_registry_row(&proof).expect("project");
        assert_eq!(row.version_id, proof.version_id);
        assert_eq!(row.identity.application_id, "vector");
        assert_eq!(row.identity.digest, SPEC_VECTOR_VERSION_DIGEST);
        assert_eq!(row.identity.sequence, 1);
        assert_eq!(row.admission_proof_ref, format!("admission-proof/vector/{}", proof.version_id));
        assert_eq!(row.admission_proof_digest, GOLDEN_ADMISSION_PROOF_DIGEST);
        assert_eq!(row.lifecycle, "admitted");
        assert!(row.readiness_lease_digest.is_none());
        let mut registry = WasmKernelRouteRegistry::default();
        let inserted = registry.insert_admitted(&proof).expect("insert");
        assert_eq!(inserted, row);
        let again = registry.insert_admitted(&proof).expect("idempotent insert");
        assert_eq!(again, row);
        assert_eq!(registry.applications["vector"].versions.len(), 1);
        // 准入绝不翻 active 指针：恒 unavailable。
        assert!(matches!(registry.applications["vector"].active, WasmActivePointerV1::Unavailable { .. }));
        // 同 versionId 不同内容 → fail-closed。
        let mut conflicting = row.clone();
        conflicting.package_digest = "3".repeat(64);
        registry.applications.get_mut("vector").unwrap().versions[0] = conflicting;
        assert_eq!(registry.insert_admitted(&proof).unwrap_err().code, WASM_REGISTRY_CONFLICT);
    }

    // -- 恢复唯一性矩阵：每个中断点恢复两次结果一致 --

    #[test]
    fn every_interruption_point_recovers_deterministically() {
        // 中断点枚举：blob 写失败 / marker 写失败 / DB 插入失败 / handoff 失败 / flip 失败。
        for injection in [Injection::Blob, Injection::Marker, Injection::DbInsert, Injection::Handoff, Injection::Flip] {
            let mut world = MockWorld::default();
            injection.apply(&mut world);
            let mut token = CountingTokenSource::new();
            let first = commit_wasm_admission(&mut world.stores(), &request(), &mut token, T0);
            if first.is_ok() {
                panic!("injection {injection:?} must interrupt the first commit");
            }
            injection.clear(&mut world);
            // 恢复两次：结果唯一且稳定——要么一次完成（第二次 no-op），
            // 要么停在 pending 等待带原始请求的 owner 重试（第二次仍报同一 pending）。
            let report_one = recover_wasm_admission(&mut world.stores(), T0 + 1_000).expect("recover one");
            let report_two = recover_wasm_admission(&mut world.stores(), T0 + 2_000).expect("recover two");
            assert!(report_one.completed.len() + report_one.pending.len() == 1, "injection {injection:?}: one decided outcome");
            if report_one.completed.is_empty() {
                assert_eq!(report_two.pending, report_one.pending, "injection {injection:?}: pending is the stable unique outcome");
                assert!(report_two.completed.is_empty() && report_two.failed.is_empty());
            } else {
                assert!(report_two.completed.is_empty() && report_two.failed.is_empty() && report_two.pending.is_empty(), "injection {injection:?}: second recovery is a no-op");
            }
            let key = ("vector".to_string(), format!("{SPEC_VECTOR_VERSION_DIGEST}-1"));
            let row = world.journal.row(&key).unwrap();
            if report_one.completed.contains(&key) {
                assert_eq!(row.state, AdmissionState::Visible);
                assert_eq!(row.journal_revision, 5);
                assert!(admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap().is_some());
            } else {
                // blob/marker 失败停在 validated（需带原始请求重试），等待 lease 决定。
                assert_eq!(row.state, AdmissionState::Validated);
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Injection {
        Blob,
        Marker,
        DbInsert,
        Handoff,
        Flip,
    }

    impl Injection {
        fn apply(self, world: &mut MockWorld) {
            match self {
                Injection::Blob => world.objects.fail_blob = true,
                Injection::Marker => world.objects.fail_marker = true,
                Injection::DbInsert => world.db.fail_insert = true,
                Injection::Handoff => world.materializer.fail_handoff = true,
                Injection::Flip => world.db.fail_flip = true,
            }
        }
        fn clear(self, world: &mut MockWorld) {
            match self {
                Injection::Blob => world.objects.fail_blob = false,
                Injection::Marker => world.objects.fail_marker = false,
                Injection::DbInsert => world.db.fail_insert = false,
                Injection::Handoff => world.materializer.fail_handoff = false,
                Injection::Flip => world.db.fail_flip = false,
            }
        }
    }

    // -- OsRandomTokenSource 冒烟（只在能读 /dev/urandom 的平台） --

    #[test]
    fn os_token_source_produces_distinct_tokens() {
        let mut source = OsRandomTokenSource;
        let a = source.generate().expect("urandom");
        let b = source.generate().expect("urandom");
        assert_ne!(a, b);
    }

    impl CountingTokenSource {
        fn token_count(&self) -> u64 {
            self.counter
        }
    }

    // -- P0-3：V2（service-enabled）admission 的 policy digest 绑定正/负路径 --

    /// V2 测试 manifest：声明 iweb:kv@1.0.0/store import，memoryBytes 256MiB
    ///（> reserve 32MiB），其余与 spec vector 同形状。
    const SPEC_VECTOR_V2_MANIFEST: &str = r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":268435456,"pidLimit":3,"storageBytes":1048576},"runtime":{"declaredHostImports":[{"direction":"import","interface":"store","package":"iweb:kv@1.0.0"}],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#;

    /// golden fixture 的 kv-only policy（policyDigest 与 TS contracts 逐字一致）。
    fn vector_policy() -> HostServicePolicyV2 {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/wasm/host-services-golden-vectors.json");
        let bytes = std::fs::read(&path).expect("golden vectors fixture");
        let vectors: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture parses");
        let entry = vectors["policyDigest"]
            .as_array()
            .expect("policyDigest vectors")
            .iter()
            .find(|entry| entry["name"] == "kv-only")
            .expect("kv-only vector");
        let payload: crate::wasm_host_services::HostServicePolicyPayloadV2 =
            serde_json::from_value(entry["payload"].clone()).expect("payload parses");
        HostServicePolicyV2::seal(&payload).expect("policy seals")
    }

    /// all-three-services 向量的 sql 成员（构造 sql-only 反向声明失配用例）。
    fn sql_member_from_fixture() -> crate::wasm_host_services::ServiceMemberV2<crate::wasm_host_services::SqlLimitsV2> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/wasm/host-services-golden-vectors.json");
        let bytes = std::fs::read(&path).expect("golden vectors fixture");
        let vectors: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture parses");
        let entry = vectors["policyDigest"]
            .as_array()
            .expect("policyDigest vectors")
            .iter()
            .find(|entry| entry["name"] == "all-three-services")
            .expect("all-three-services vector");
        serde_json::from_value(entry["payload"]["hostServices"]["sql"].clone()).expect("sql member parses")
    }

    fn v2_request() -> AdmissionRequest {
        let layer = b"layer-v2-bytes".to_vec();
        let layer_digest = sha256_hex(&layer);
        AdmissionRequest {
            application_id: "vector".into(),
            package_digest: SPEC_VECTOR_PACKAGE_DIGEST.into(),
            normalized_policy: serde_json::from_str(SPEC_VECTOR_V2_MANIFEST).expect("v2 manifest"),
            runtime_binding: vector_binding(),
            capability_record_revision: 2,
            capability_record_hash: "2".repeat(64),
            host_service_policy: Some(vector_policy()),
            staging_ttl_seconds: 600,
            blobs: vec![(layer_digest, layer)],
            allow_resequence: false,
        }
    }

    #[test]
    fn v2_admission_binds_the_policy_digest_end_to_end() {
        let mut world = MockWorld::default();
        let mut token = CountingTokenSource::new();
        let outcome = commit_wasm_admission(&mut world.stores(), &v2_request(), &mut token, T0).expect("v2 commit");
        assert_eq!(outcome.state, AdmissionState::Visible);
        // proof 携带完整 policy；versionDigest 走 HostServiceIdentityV2 公式。
        let policy = outcome.proof.host_service_policy.as_ref().expect("proof binds the policy");
        let manifest_value: serde_json::Value = serde_json::from_str(SPEC_VECTOR_V2_MANIFEST).unwrap();
        let expected_digest = crate::wasm_host_services::wasm_host_service_version_digest_v2(
            SPEC_VECTOR_PACKAGE_DIGEST,
            &manifest_value,
            &policy.policy_digest,
        )
        .expect("oracle digest");
        assert_eq!(outcome.proof.version_digest, expected_digest);
        assert_eq!(outcome.proof.version_id, format!("{expected_digest}-1"));
        // 与 V1 公式互不解释。
        assert_ne!(
            outcome.proof.version_digest,
            wasm_version_digest_v1(SPEC_VECTOR_PACKAGE_DIGEST, &jcs_bytes(&outcome.proof.normalized_policy).unwrap())
        );
        // materializer receipt 显式携带 policy digest。
        let receipt_bytes = world.materializer.receipt_bytes(&outcome.key).expect("receipt durable");
        let receipt: MaterializerReceipt = parse_canonical_witness(&receipt_bytes).expect("receipt parses");
        assert_eq!(receipt.host_service_policy_digest.as_deref(), Some(policy.policy_digest.as_str()));
        // AdmittedVisible 扩展：V2 policy 在场且 digest 匹配才可见。
        let visible = admitted_visible(&world.objects, &world.db, &world.materializer, &outcome.key.0, &outcome.key.1)
            .expect("predicate ok")
            .expect("visible");
        assert_eq!(visible.host_service_policy.as_ref().map(|p| p.policy_digest.clone()), Some(policy.policy_digest.clone()));
        // registry 行携带 hostServicePolicyDigest 静态摘要（无动态用量）。
        let row = project_registry_row(&visible).expect("row projects");
        let summary = row.host_service_policy_summary.expect("static summary present");
        assert_eq!(summary.policy_digest, policy.policy_digest);
        assert_eq!(summary.host_services.kv.as_deref(), Some("bounded-cas-list-v1"));
        assert!(summary.host_services.sql.is_none() && summary.host_services.logging.is_none());
        // 幂等重放 join 同一 V2 proof。
        let replay = commit_wasm_admission(&mut world.stores(), &v2_request(), &mut token, T0 + 1_000).expect("replay");
        assert!(!replay.created);
        assert_eq!(replay.proof, outcome.proof);
        assert_eq!(world.journal.keys().len(), 1);
    }

    #[test]
    fn v2_admission_rejects_a_tampered_policy_digest() {
        let mut request = v2_request();
        let policy = request.host_service_policy.as_mut().expect("policy");
        policy.policy_digest = "0".repeat(64);
        let mut world = MockWorld::default();
        let failure = commit_wasm_admission(&mut world.stores(), &request, &mut CountingTokenSource::new(), T0).unwrap_err();
        assert_eq!(failure.code, crate::wasm_host_services::WASM_HOST_POLICY_DIGEST_MISMATCH);
        assert!(world.journal.keys().is_empty(), "失败路径不落任何 journal 行");
    }

    #[test]
    fn v2_admission_rejects_declared_import_divergence_both_ways() {
        // policy 启用 kv 但 manifest 未声明 import。
        let mut request = v2_request();
        request.normalized_policy.runtime.declared_host_imports.clear();
        let failure = commit_wasm_admission(&mut MockWorld::default().stores(), &request, &mut CountingTokenSource::new(), T0).unwrap_err();
        assert_eq!(failure.code, WASM_DECLARATION_MISMATCH);
        // 反向：manifest 声明 kv+sql import，但 policy 只启用 sql（kv 为 null）→ 同码拒绝。
        //（policy 不能全 null：无任何新 import 的版本是 V1 版本，policy 本身即拒绝。）
        let mut request = v2_request();
        request.normalized_policy.runtime.declared_host_imports = vec![
            crate::wasm_admission::WasmImportCapability {
                package: "iweb:kv@1.0.0".into(),
                interface: "store".into(),
                direction: "import".into(),
            },
            crate::wasm_admission::WasmImportCapability {
                package: "iweb:sql@1.0.0".into(),
                interface: "store".into(),
                direction: "import".into(),
            },
        ];
        if let Some(policy) = request.host_service_policy.as_mut() {
            policy.host_services.kv = None;
            policy.host_services.sql = Some(sql_member_from_fixture());
            policy.policy_digest = HostServicePolicyV2::compute_policy_digest(&policy.payload()).unwrap();
        }
        let failure = commit_wasm_admission(&mut MockWorld::default().stores(), &request, &mut CountingTokenSource::new(), T0).unwrap_err();
        assert_eq!(failure.code, WASM_DECLARATION_MISMATCH);
    }

    #[test]
    fn v2_admission_rejects_reserve_covering_or_missing_against_memory() {
        // reserveBytes >= resources.memoryBytes：fail-closed，绝不代默认。
        let mut request = v2_request();
        let policy = request.host_service_policy.as_mut().expect("policy");
        policy.reserve_bytes = request.normalized_policy.resources.memory_bytes;
        policy.policy_digest = HostServicePolicyV2::compute_policy_digest(&policy.payload()).unwrap();
        let failure = commit_wasm_admission(&mut MockWorld::default().stores(), &request, &mut CountingTokenSource::new(), T0).unwrap_err();
        assert_eq!(failure.code, crate::wasm_host_services::WASM_GUEST_MEMORY_RESERVE_INVALID);
        // reserveBytes = 0 在 policy 校验层即拒绝（reserve >= 1 是 policy 不变式）。
        let mut request = v2_request();
        let policy = request.host_service_policy.as_mut().expect("policy");
        policy.reserve_bytes = 0;
        policy.policy_digest = HostServicePolicyV2::compute_policy_digest(&policy.payload()).unwrap();
        let failure = commit_wasm_admission(&mut MockWorld::default().stores(), &request, &mut CountingTokenSource::new(), T0).unwrap_err();
        assert_eq!(failure.code, crate::wasm_host_services::WASM_HOST_POLICY_INVALID);
    }

    #[test]
    fn v2_visible_predicate_fails_closed_when_the_receipt_drops_the_policy_digest() {
        let mut world = MockWorld::default();
        let outcome = commit_wasm_admission(&mut world.stores(), &v2_request(), &mut CountingTokenSource::new(), T0).expect("commit");
        let key = outcome.key.clone();
        // 篡改 durable receipt：剥掉显式 hostServicePolicyDigest 成员。
        let bytes = world.materializer.receipt_bytes(&key).expect("receipt");
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        let policy = outcome.proof.host_service_policy.as_ref().expect("policy");
        // receipt JCS 键序：hostServicePolicyDigest 是首个键（尾随逗号形式）。
        let member = format!(r#""hostServicePolicyDigest":"{}","#, policy.policy_digest);
        assert!(text.contains(&member), "receipt carries the digest member: {text}");
        let stripped = text.replace(&member, "").into_bytes();
        world.materializer.receipts.insert(key.clone(), stripped);
        let failure = admitted_visible(&world.objects, &world.db, &world.materializer, &key.0, &key.1).unwrap_err();
        assert_eq!(failure.code, WASM_ADMISSION_FAIL_CLOSED);
    }

    #[test]
    fn v1_and_v2_proofs_cannot_swap_generations() {
        // V1 proof 伪装 V2：换上与 policy 绑定一致的 V2 manifest，但保留 V1 公式的
        // versionDigest → 绑定校验通过、digest 公式复算拒绝。
        let mut proof = vector_proof();
        proof.normalized_policy = serde_json::from_str(SPEC_VECTOR_V2_MANIFEST).expect("v2 manifest");
        proof.host_service_policy = Some(vector_policy());
        assert_eq!(verify_admission_proof(&proof).unwrap_err().code, WASM_VERSION_DIGEST_MISMATCH);
        // V2 proof 剥掉 policy（versionDigest 仍是 V2 公式）→ 同样拒绝。
        let mut world = MockWorld::default();
        let outcome = commit_wasm_admission(&mut world.stores(), &v2_request(), &mut CountingTokenSource::new(), T0).expect("commit");
        let mut stripped = outcome.proof.clone();
        stripped.host_service_policy = None;
        assert_eq!(verify_admission_proof(&stripped).unwrap_err().code, WASM_VERSION_DIGEST_MISMATCH);
    }
}
