//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1-3.4）：iweb-wasmd 是内嵌
//! Wasmtime 的 wasm 应用执行进程；其身份/绑定/上限全部来自 supervisor 生成的固定
//! argv 与 pinned node capability record，任何自解析输入都 fail-closed。
//! 本模块是 wasmd 自包含的 canonical JSON（RFC 8785 JCS 子集）与域前缀 digest 工具。
//!
//! 编码语义唯一权威：packages/contracts/wasm-package.ts 的 jcsCanonicalBytes 与
//! kernel-rs/iweb-kernel/src/wasm_admission.rs 的 jcs_bytes——本模块逐字对齐同一值域
//! （整数 ≤ u53、ASCII 键与字符串、布尔、null、数组、对象；浮点/非 ASCII 一律拒绝），
//! 不定义第二套解释。wasmd 独立成 crate（不依赖 iweb-kernel lib），因此携带自有副本。

use serde::Serialize;
use sha2::{Digest, Sha256};

/// u53 上界（spec Normative Encoding：0..9007199254740991）。
pub const WASM_U53_MAX: u64 = 9_007_199_254_740_991;

/// 结构化 wire 错误：code 为稳定 owner 可见码；detail 不含任何秘密值。
#[derive(Debug, Clone, PartialEq)]
pub struct WireError {
    pub code: &'static str,
    pub detail: String,
}

impl WireError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for WireError {}

pub fn err(code: &'static str, detail: impl Into<String>) -> WireError {
    WireError::new(code, detail)
}

/// sha256 的单次小写十六进制渲染（绝不二次 hash 十六进制串）。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// 域前缀单次 SHA-256：hex(SHA-256(UTF8(domain || "\n" || payload)))。
pub fn domain_digest(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// digestV2（add-wasm-host-services design §1）：hex(SHA-256(ASCII(domain) || 0x00 || payload))。
/// 与 V1 domain_digest（0x0A 分隔）刻意不同式：V2 hash domain 逐字规定 NUL 分隔，
/// 两套公式绝不互换（unknown hash domain 一律 fail-closed，不猜测）。
pub fn digest_v2(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0x00]);
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// 序列化为 JCS 字节（serde_json 默认 Map=BTreeMap，键按 UTF-8 字节序；值域内与
/// RFC 8785 字节一致）。浮点与非 ASCII 一律 fail-closed。
pub fn jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let parsed = serde_json::to_value(value)
        .map_err(|e| err(WIRE_JCS_INVALID, format!("value is not serializable as JSON: {e}")))?;
    validate_jcs_domain(&parsed)?;
    serde_json::to_vec(&parsed)
        .map_err(|e| err(WIRE_JCS_INVALID, format!("JCS serialization failed: {e}")))
}

fn validate_jcs_domain(value: &serde_json::Value) -> Result<(), WireError> {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) => Ok(()),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u <= WASM_U53_MAX {
                    Ok(())
                } else {
                    Err(err(WIRE_JCS_INVALID, "integer exceeds the u53 JSON safe-integer domain"))
                }
            } else {
                Err(err(WIRE_JCS_INVALID, "floating-point values are not part of the canonical JSON domain"))
            }
        }
        serde_json::Value::String(s) => {
            if s.is_ascii() {
                Ok(())
            } else {
                Err(err(WIRE_JCS_INVALID, "non-ASCII strings are outside the canonical ASCII-only domain"))
            }
        }
        serde_json::Value::Array(items) => items.iter().try_for_each(validate_jcs_domain),
        serde_json::Value::Object(map) => {
            for (key, member) in map {
                if !key.is_ascii() {
                    return Err(err(WIRE_JCS_INVALID, "non-ASCII object keys are outside the canonical ASCII-only domain"));
                }
                validate_jcs_domain(member)?;
            }
            Ok(())
        }
    }
}

/// 从原始字节解析 typed wire：serde derive 自带 duplicate-member 检测 +
/// deny_unknown_fields 精确键集；并要求原始字节等于 JCS(解析值)（规范 JCS，
/// 而不是“解析后等价”）。
pub fn parse_canonical<T>(bytes: &[u8], code: &'static str) -> Result<T, WireError>
where
    T: for<'de> serde::Deserialize<'de> + Serialize,
{
    let parsed: T = serde_json::from_slice(bytes)
        .map_err(|e| err(code, format!("bytes do not parse as the typed record: {e}")))?;
    let canonical = jcs_bytes(&parsed)?;
    if canonical != bytes {
        return Err(err(code, "wire bytes must equal JCS(parse(bytes))"));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// 名称文法（与 contracts/kernel 同一正则；OnceLock 缓存）
// ---------------------------------------------------------------------------

struct WireRegexes {
    sha256_hex: regex::Regex,
    oci_sha256: regex::Regex,
    sandbox_id: regex::Regex,
    version_id: regex::Regex,
    application_key: regex::Regex,
    entry_key: regex::Regex,
    architecture: regex::Regex,
    application_id: regex::Regex,
    uuid_v7: regex::Regex,
    fence_nonce: regex::Regex,
}

fn regexes() -> &'static WireRegexes {
    static REGEXES: std::sync::OnceLock<WireRegexes> = std::sync::OnceLock::new();
    REGEXES.get_or_init(|| WireRegexes {
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        oci_sha256: regex::Regex::new(r"^sha256:[a-f0-9]{64}$").expect("oci sha256 regex"),
        sandbox_id: regex::Regex::new(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$").expect("sandbox id regex"),
        version_id: regex::Regex::new(r"^[a-f0-9]{64}-[1-9][0-9]{0,15}$").expect("version id regex"),
        // iweb:config/secrets 的 key 文法：^[a-z][a-z0-9._-]{0,127}$（1..128 字节）。
        application_key: regex::Regex::new(r"^[a-z][a-z0-9._-]{0,127}$").expect("application key regex"),
        entry_key: regex::Regex::new(r"^[a-z][a-z0-9.-]{0,63}$").expect("entry key regex"),
        architecture: regex::Regex::new(r"^linux/(amd64|arm64)$").expect("architecture regex"),
        // applicationId（contracts validation.ts OPAQUE_ID_PATTERN）。
        application_id: regex::Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$").expect("application id regex"),
        // UUIDv7（contracts wasm-execution.ts WASM_UUIDV7_PATTERN：小写、版本 7、变体 89ab）。
        uuid_v7: regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").expect("uuid v7 regex"),
        // fenceNonce：宿主签发 16 字节的 32 个小写十六进制字符渲染（design ExecutionFenceV2）。
        fence_nonce: regex::Regex::new(r"^[a-f0-9]{32}$").expect("fence nonce regex"),
    })
}

pub fn validate_sha256_hex(value: &str, field: &str) -> Result<(), WireError> {
    if regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

pub fn validate_oci_sha256(value: &str, field: &str) -> Result<(), WireError> {
    if regexes().oci_sha256.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, format!("{field} must be sha256: plus 64 lower-case hex characters")))
    }
}

pub fn validate_sandbox_id(value: &str) -> Result<(), WireError> {
    if regexes().sandbox_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, "sandboxId must match ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"))
    }
}

pub fn validate_version_id(value: &str) -> Result<(), WireError> {
    if !regexes().version_id.is_match(value) {
        return Err(err(WIRE_GRAMMAR_INVALID, "versionId must match ^[a-f0-9]{64}-[1-9][0-9]{0,15}$"));
    }
    // sequence 为正 u53 十进制（无前导零已由文法保证）。
    let sequence: u128 = value[65..].parse().map_err(|_| err(WIRE_GRAMMAR_INVALID, "versionId sequence must be a decimal integer"))?;
    if sequence > WASM_U53_MAX as u128 {
        return Err(err(WIRE_GRAMMAR_INVALID, "versionId sequence exceeds u53"));
    }
    Ok(())
}

pub fn validate_application_key(value: &str) -> Result<(), WireError> {
    if regexes().application_key.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, "key must match ^[a-z][a-z0-9._-]{0,127}$"))
    }
}

pub fn validate_entry_key(value: &str) -> Result<(), WireError> {
    if regexes().entry_key.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, "entryKey must match ^[a-z][a-z0-9.-]{0,63}$"))
    }
}

pub fn validate_architecture(value: &str) -> Result<(), WireError> {
    if regexes().architecture.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, "architecture must be linux/amd64 or linux/arm64"))
    }
}

/// applicationId 文法（^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$；contracts OPAQUE_ID_PATTERN）。
pub fn validate_application_id(value: &str) -> Result<(), WireError> {
    if regexes().application_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, "applicationId must match ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$"))
    }
}

/// UUIDv7 文法（contracts WASM_UUIDV7_PATTERN；小写、版本 nibble 7、变体 89ab）。
pub fn validate_uuid_v7(value: &str) -> Result<(), WireError> {
    if regexes().uuid_v7.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, "identifier must be a lower-case UUIDv7"))
    }
}

/// fenceNonce 文法：16 宿主签发字节的 32 小写十六进制字符渲染。
pub fn validate_fence_nonce(value: &str) -> Result<(), WireError> {
    if regexes().fence_nonce.is_match(value) {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, "fenceNonce must be 32 lower-case hex characters"))
    }
}

/// u53 界检查（含最小值/最大值；全部含端点）。
pub fn require_u53(value: u64, minimum: u64, maximum: u64, field: &str) -> Result<(), WireError> {
    if value >= minimum && value <= maximum && value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(WIRE_GRAMMAR_INVALID, format!("{field} must be an integer between {minimum} and {maximum}")))
    }
}

/// 稳定错误码（沿 contracts/kernel 命名风格；本 crate 补充码不覆盖 spec 已命名码）。
pub const WIRE_JCS_INVALID: &str = "WASMD_WIRE_JCS_INVALID";
pub const WIRE_GRAMMAR_INVALID: &str = "WASMD_WIRE_GRAMMAR_INVALID";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jcs_orders_keys_bytewise_and_matches_contracts_domain() {
        // 与 TS jcsCanonicalBytes 相同值域的排序语义：键按 UTF-8 字节序、无空白。
        let value = serde_json::json!({"b": 1, "a": [true, null, "x"]});
        assert_eq!(jcs_bytes(&value).expect("jcs"), br#"{"a":[true,null,"x"],"b":1}"#);
    }

    #[test]
    fn jcs_rejects_float_and_non_ascii() {
        let value = serde_json::json!({"a": 1.5});
        assert_eq!(jcs_bytes(&value).expect_err("float rejected").code, WIRE_JCS_INVALID);
        let value = serde_json::json!({"键": 1});
        assert_eq!(jcs_bytes(&value).expect_err("non-ascii rejected").code, WIRE_JCS_INVALID);
        let value = serde_json::json!({"a": u64::MAX});
        assert!(jcs_bytes(&value).is_err());
    }

    #[test]
    fn domain_digest_is_single_prefixed_sha256() {
        // 域前缀 + 单次 SHA-256：与 kernel domain_digest 同式，可用独立 oracle 复算。
        let out = domain_digest("iweb-wasmd-test", b"payload");
        let mut hasher = Sha256::new();
        hasher.update(b"iweb-wasmd-test\npayload");
        assert_eq!(out, hex::encode(hasher.finalize()));
    }

    #[test]
    fn digest_v2_uses_nul_separator_and_never_equals_v1() {
        // digestV2 = SHA-256(domain || 0x00 || payload)（design §1 逐字）；与 V1 的
        // 0x0A 分隔输出必然不同（域与 payload 相同也不可碰撞互换）。
        let out = digest_v2("iweb-wasmd-test", b"payload");
        let mut hasher = Sha256::new();
        hasher.update(b"iweb-wasmd-test\0payload");
        assert_eq!(out, hex::encode(hasher.finalize()));
        assert_ne!(out, domain_digest("iweb-wasmd-test", b"payload"));
    }

    #[test]
    fn application_id_uuid_v7_and_fence_nonce_grammars() {
        assert!(validate_application_id("alpha").is_ok());
        assert!(validate_application_id("app-1").is_ok());
        assert!(validate_application_id("-bad").is_err());
        assert!(validate_application_id("Bad").is_err());
        assert!(validate_uuid_v7("018f6b1e-5c0a-7740-afbc-57a9016f2085").is_ok());
        assert!(validate_uuid_v7("018f6b1e-5c0a-4740-afbc-57a9016f2085").is_err(), "version nibble must be 7");
        assert!(validate_uuid_v7("018F6B1E-5C0A-7740-AFBC-57A9016F2085").is_err(), "lower-case only");
        assert!(validate_fence_nonce(&"ab".repeat(16)).is_ok());
        assert!(validate_fence_nonce(&"ab".repeat(15)).is_err());
        assert!(validate_fence_nonce(&"AB".repeat(16)).is_err());
    }

    #[test]
    fn grammar_vectors() {
        assert!(validate_sandbox_id("sbx-vector").is_ok());
        assert!(validate_sandbox_id("1bad").is_err());
        assert!(validate_version_id(&format!("{}-1", "a".repeat(64))).is_ok());
        assert!(validate_version_id(&format!("{}-01", "a".repeat(64))).is_err());
        assert!(validate_version_id(&format!("{}-{}", "a".repeat(64), u64::MAX)).is_err());
        assert!(validate_oci_sha256(&format!("sha256:{}", "0".repeat(64)), "field").is_ok());
        assert!(validate_application_key("a.b-c_d").is_ok());
        assert!(validate_application_key("A/b").is_err());
        assert!(validate_architecture("linux/arm64").is_ok());
        assert!(validate_architecture("linux/riscv64").is_err());
    }
}

/// Constant-time byte-slice equality to prevent timing attacks on token comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
