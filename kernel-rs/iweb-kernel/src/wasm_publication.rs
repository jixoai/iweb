//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 4.3 + 7.8 Kernel 侧）：发布门 v2 与双
//! runtime gate——wasm 发布必须先有不可变信任 Kernel release 在固定路径
//! `/opt/iweb/release/wasm-sandbox-acceptance.json` 的 canonical kind-bound acceptance
//! record v2；celld v1 与 wasm v2 两 gate 并行评估、按 runtime kind 精确选择、互不启用、
//! 无 fallback，环境变量不得重定向任一记录路径。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//! "Wasm publication requires a canonical kind-bound acceptance record" 与
//! "Runtime-kind publication gate selection is a dual-gate wire"（含全部场景）。
//! JS 对位实现：kernel/application-publication-gate.js（celld adapter + wasm v2 adapter，
//! 双实现同套断言见 tests/wasm-publication-gate.test.ts）。
//!
//! 正交意图：
//! 1. acceptance record v2 校验器（deny_unknown_fields 精确键集 + serde 重复成员检测 +
//!    JCS 字节相等 + recordDigest 域前缀单次 SHA-256 复算 + 全部身份字段文法）；
//! 2. gate 评估纯函数（记录字节 + 当前节点 catalog/capability/arch pin + 双开关 →
//!    开/关 + reasons wire；reasons 去重且按 spec 列出的稳定顺序）；
//! 3. PublicationGateSetV1（celld v1 与 wasm v2 并行评估；runtime-kind 精确选择；
//!    未知 kind 返回 RUNTIME_KIND_UNSUPPORTED typed error；跨 kind 喂结果得到
//!    runtime-kind-mismatch 的关闭结果，绝不调用另一个 parser 作 fallback）；
//! 4. 固定路径读取（两个路径常量是唯一会交给 reader 的路径；wasm 侧检测到重定向
//!    环境变量即 fail-closed，且不再读任何文件）。
//!
//! 接线备注（本文件不改 lib.rs，由编排者注册）：在 lib.rs 的 `pub mod wasm_kind_registry;`
//! 之后追加一行 `pub mod wasm_publication;`。启动序契约（spec「The v2 gate is connected at
//! startup in this order」）：(1) 先评 celld gate；(2) 独立读取并校验固定 wasm 验收记录；
//! (3) 发布不可变 PublicationGateSetV1 给 runtime selector；(4) 每个发布请求按 Kernel
//! 业务记录的 runtimeKind 精确选择一个结果并要求 enabled。
//!
//! 歧义备注（保守 fail-closed 取舍，供 review 对照）：
//! 1. spec 说 wasm gate「requires only IWEB_WASM_PUBLICATION_ENABLED=1 plus the
//!    application switch」：application switch 即现行 `IWEB_APPLICATION_PUBLICATION_ENABLED`。
//!    取双开关同时为 1 才 requested（fail-closed：wasm 发布是应用发布的一种）。
//! 2. reasons 中 `unsupported-architecture` 的触发面：记录 arch 本身不是两个合法字面量时
//!    属 schema 校验（wasm-acceptance-invalid）；`unsupported-architecture` 承担
//!    「节点 arch 不受支持」与「记录 arch 与节点 arch 不相等」两种情况（spec 的
//!    identity-mismatch 场景三分支未点名 arch，且否则该码没有触发面）。
//! 3. spec 未列举重定向环境变量名；对 wasm 侧两个直觉命名
//!    （IWEB_WASM_SANDBOX_ACCEPTANCE_FILE / IWEB_WASM_ACCEPTANCE_FILE）出现非空值即
//!    fail-closed（wasm-acceptance-invalid），并且不读任何文件。celld 侧保持 v1 行为
//!    完全不变（忽略重定向变量——现有 tests/application-publication-gate.test.ts 断言）。
//! 4. 未提供节点 pin（catalog/capability/arch 尚未加载）时 wasm gate 以
//!    wasm-identity-mismatch + capability-record-mismatch + catalog-mismatch 关闭，
//!    不推断默认 pin。
//! 5. `sandbox-acceptance-missing`（wasm 文件缺失/不可读）与 `wasm-acceptance-invalid`
//!    （可读但校验失败）分开：前者与 celld v1 的缺文件语义对齐。

use crate::wasm_admission::{jcs_bytes, WASM_HOST_ABI_LITERAL, WASM_U53_MAX, WASM_WORLD_LITERAL};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误/原因码
// ---------------------------------------------------------------------------

/// `recordDigest = hex(SHA-256(UTF8("iweb-wasm-acceptance-record-v2\n" || JCS(record with recordDigest omitted))))`。
pub const WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN: &str = "iweb-wasm-acceptance-record-v2";

/// celld v1 验收记录固定路径（现行 kernel/application-publication-gate.js 同一常量）。
pub const CELLD_ACCEPTANCE_FILE: &str = "/opt/iweb/release/sandbox-acceptance.json";
/// wasm v2 验收记录固定 Kernel-owned 路径（spec 逐字）。
pub const WASM_ACCEPTANCE_FILE: &str = "/opt/iweb/release/wasm-sandbox-acceptance.json";

pub const ENV_APPLICATION_PUBLICATION_ENABLED: &str = "IWEB_APPLICATION_PUBLICATION_ENABLED";
pub const ENV_WASM_PUBLICATION_ENABLED: &str = "IWEB_WASM_PUBLICATION_ENABLED";
/// 尝试重定向 wasm 验收记录路径的环境变量名（补充 fail-closed 名单；spec 未列举名字）。
pub const ENV_WASM_ACCEPTANCE_PATH_REDIRECTS: &[&str] =
    &["IWEB_WASM_SANDBOX_ACCEPTANCE_FILE", "IWEB_WASM_ACCEPTANCE_FILE"];

pub const RUNTIME_KIND_CELLD: &str = "celld";
pub const RUNTIME_KIND_WASM: &str = "wasm";

/// runtime-kind 选择入口的 typed error（spec 命名：`RUNTIME_KIND_UNSUPPORTED`）。
pub const RUNTIME_KIND_UNSUPPORTED: &str = "RUNTIME_KIND_UNSUPPORTED";

// spec GateResultV1.reasons 的稳定顺序（duplicate-free，成功 gate 为空数组）。
pub const REASON_PUBLICATION_NOT_REQUESTED: &str = "publication-not-requested";
pub const REASON_SANDBOX_ACCEPTANCE_MISSING: &str = "sandbox-acceptance-missing";
pub const REASON_WASM_ACCEPTANCE_INVALID: &str = "wasm-acceptance-invalid";
pub const REASON_WASM_IDENTITY_MISMATCH: &str = "wasm-identity-mismatch";
pub const REASON_RUNTIME_KIND_MISMATCH: &str = "runtime-kind-mismatch";
pub const REASON_CAPABILITY_RECORD_MISMATCH: &str = "capability-record-mismatch";
pub const REASON_CATALOG_MISMATCH: &str = "catalog-mismatch";
pub const REASON_UNSUPPORTED_ARCHITECTURE: &str = "unsupported-architecture";

/// spec 列出的 reasons 稳定顺序（评估端插入与跨 kind 合并共用同一排序）。
pub const GATE_REASON_ORDER: [&str; 8] = [
    REASON_PUBLICATION_NOT_REQUESTED,
    REASON_SANDBOX_ACCEPTANCE_MISSING,
    REASON_WASM_ACCEPTANCE_INVALID,
    REASON_WASM_IDENTITY_MISMATCH,
    REASON_RUNTIME_KIND_MISMATCH,
    REASON_CAPABILITY_RECORD_MISMATCH,
    REASON_CATALOG_MISMATCH,
    REASON_UNSUPPORTED_ARCHITECTURE,
];

pub const WASM_RUNTIME_ARCHITECTURES: [&str; 2] = ["linux/amd64", "linux/arm64"];

// 结构性拒绝码（沿用 contracts 命名风格；不覆盖 spec 已命名码）。
pub const WASM_ACCEPTANCE_RECORD_INVALID: &str = "WASM_ACCEPTANCE_RECORD_INVALID";
pub const WASM_ACCEPTANCE_RECORD_DIGEST_MISMATCH: &str = "WASM_ACCEPTANCE_RECORD_DIGEST_MISMATCH";
pub const WASM_PUBLICATION_GATE_INVALID: &str = "WASM_PUBLICATION_GATE_INVALID";

/// 结构化错误：code 为稳定 owner 可见码，detail 携带路径/上下文，不含秘密。
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationGateError {
    pub code: &'static str,
    pub detail: String,
}

impl PublicationGateError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for PublicationGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for PublicationGateError {}

fn err(code: &'static str, detail: impl Into<String>) -> PublicationGateError {
    PublicationGateError::new(code, detail)
}

fn publication_regexes() -> &'static PublicationRegexes {
    static REGEXES: OnceLock<PublicationRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| PublicationRegexes {
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        oci_sha256: regex::Regex::new(r"^sha256:[a-f0-9]{64}$").expect("oci sha256 regex"),
        // spec：`catalogEntryKey: /^[a-z][a-z0-9.-]{0,63}$/`。
        catalog_entry_key: regex::Regex::new(r"^[a-z][a-z0-9.-]{0,63}$").expect("catalog entry key regex"),
    })
}

struct PublicationRegexes {
    sha256_hex: regex::Regex,
    oci_sha256: regex::Regex,
    catalog_entry_key: regex::Regex,
}

// ---------------------------------------------------------------------------
// acceptance record v2：typed wire 记录（精确键集；camelCase 对位 spec/contracts）
// ---------------------------------------------------------------------------

/// recordDigest 的输入对象：record 去掉 recordDigest 本身（spec 逐字；键名 camelCase 对位 wire）。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct WasmAcceptanceRecordPayloadV2 {
    pub version: u64,
    pub result: String,
    pub gate: String,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "runtimeImageDigest")]
    pub runtime_image_digest: String,
    #[serde(rename = "hostABI")]
    pub host_abi: String,
    pub world: String,
    pub arch: String,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "catalogRevision")]
    pub catalog_revision: u64,
    #[serde(rename = "catalogHash")]
    pub catalog_hash: String,
    #[serde(rename = "catalogEntryKey")]
    pub catalog_entry_key: String,
    #[serde(rename = "evidenceDigest")]
    pub evidence_digest: String,
}

/// 完整 v2 验收记录（serde derive 自带重复成员检测 + deny_unknown_fields 精确键集）。
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmAcceptanceRecordV2 {
    pub version: u64,
    pub result: String,
    pub gate: String,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "runtimeImageDigest")]
    pub runtime_image_digest: String,
    #[serde(rename = "hostABI")]
    pub host_abi: String,
    pub world: String,
    pub arch: String,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "catalogRevision")]
    pub catalog_revision: u64,
    #[serde(rename = "catalogHash")]
    pub catalog_hash: String,
    #[serde(rename = "catalogEntryKey")]
    pub catalog_entry_key: String,
    #[serde(rename = "evidenceDigest")]
    pub evidence_digest: String,
    #[serde(rename = "recordDigest")]
    pub record_digest: String,
}

impl WasmAcceptanceRecordV2 {
    /// 去 recordDigest 的 digest 输入对象。
    pub fn payload(&self) -> WasmAcceptanceRecordPayloadV2 {
        WasmAcceptanceRecordPayloadV2 {
            version: self.version,
            result: self.result.clone(),
            gate: self.gate.clone(),
            runtime_kind: self.runtime_kind.clone(),
            runtime_image_digest: self.runtime_image_digest.clone(),
            host_abi: self.host_abi.clone(),
            world: self.world.clone(),
            arch: self.arch.clone(),
            capability_record_revision: self.capability_record_revision,
            capability_record_hash: self.capability_record_hash.clone(),
            catalog_revision: self.catalog_revision,
            catalog_hash: self.catalog_hash.clone(),
            catalog_entry_key: self.catalog_entry_key.clone(),
            evidence_digest: self.evidence_digest.clone(),
        }
    }
}

fn require_sha256_hex(value: &str, field: &str) -> Result<(), PublicationGateError> {
    if publication_regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_ACCEPTANCE_RECORD_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

fn require_u53_minimum_1(value: u64, field: &str) -> Result<(), PublicationGateError> {
    if (1..=WASM_U53_MAX).contains(&value) {
        Ok(())
    } else {
        Err(err(WASM_ACCEPTANCE_RECORD_INVALID, format!("{field} must be a u53 integer >= 1")))
    }
}

/// 全部身份字段文法校验（结构解析后、JCS/digest 复算前）。
pub fn validate_wasm_acceptance_record_v2(record: &WasmAcceptanceRecordV2) -> Result<(), PublicationGateError> {
    if record.version != 2 {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "version must be the literal 2"));
    }
    if record.result != "passed" {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "result must be exactly \"passed\""));
    }
    if record.gate != "application-sandbox" {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "gate must be exactly \"application-sandbox\""));
    }
    if record.runtime_kind != RUNTIME_KIND_WASM {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "runtimeKind must be exactly \"wasm\""));
    }
    if !publication_regexes().oci_sha256.is_match(&record.runtime_image_digest) {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "runtimeImageDigest must be sha256: plus 64 lower-case hex characters"));
    }
    if record.host_abi != WASM_HOST_ABI_LITERAL {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "hostABI must be exactly the matrix ABI literal"));
    }
    if record.world != WASM_WORLD_LITERAL {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "world must be exactly the matrix world literal"));
    }
    if !WASM_RUNTIME_ARCHITECTURES.contains(&record.arch.as_str()) {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "arch must be one of linux/amd64 or linux/arm64"));
    }
    require_u53_minimum_1(record.capability_record_revision, "capabilityRecordRevision")?;
    require_sha256_hex(&record.capability_record_hash, "capabilityRecordHash")?;
    require_u53_minimum_1(record.catalog_revision, "catalogRevision")?;
    require_sha256_hex(&record.catalog_hash, "catalogHash")?;
    if !publication_regexes().catalog_entry_key.is_match(&record.catalog_entry_key) {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "catalogEntryKey must match ^[a-z][a-z0-9.-]{0,63}$"));
    }
    require_sha256_hex(&record.evidence_digest, "evidenceDigest")?;
    require_sha256_hex(&record.record_digest, "recordDigest")?;
    Ok(())
}

/// `recordDigest`（域前缀单次 SHA-256；输入必须是已通过结构校验的 payload）。
pub fn compute_wasm_acceptance_record_digest_v2(payload: &WasmAcceptanceRecordPayloadV2) -> Result<String, PublicationGateError> {
    let jcs = jcs_bytes(payload).map_err(|e| err(WASM_ACCEPTANCE_RECORD_INVALID, format!("payload is outside the canonical JSON domain: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN.as_bytes());
    hasher.update(b"\n");
    hasher.update(&jcs);
    Ok(hex::encode(hasher.finalize()))
}

/// 完整 v2 校验：typed 解析（未知/缺失/重复成员拒绝）→ 字段文法 → 原始字节等于
/// JCS(parse(bytes))（不是「解析后等价」）→ recordDigest 复算。
pub fn verify_wasm_acceptance_record_v2(bytes: &[u8]) -> Result<WasmAcceptanceRecordV2, PublicationGateError> {
    let parsed: WasmAcceptanceRecordV2 = serde_json::from_slice(bytes)
        .map_err(|e| err(WASM_ACCEPTANCE_RECORD_INVALID, format!("record bytes do not parse as the typed v2 record: {e}")))?;
    validate_wasm_acceptance_record_v2(&parsed)?;
    // 规范 JCS 检查：先取 payload JCS（也会做 canonical domain 校验），再与完整记录字节比对。
    let payload_jcs = jcs_bytes(&parsed.payload())
        .map_err(|e| err(WASM_ACCEPTANCE_RECORD_INVALID, format!("record is outside the canonical JSON domain: {e}")))?;
    // 完整记录的 JCS = payload JCS 按 key 序插入 "recordDigest":"<hex>"；直接复算完整对象
    // 需要完整记录可序列化——用拼装方式保持单一权威（payload JCS 已含 14 个键）。
    let expected_full = insert_record_digest_member(&payload_jcs, &parsed.record_digest);
    if expected_full != bytes {
        return Err(err(WASM_ACCEPTANCE_RECORD_INVALID, "record bytes must equal JCS(parse(bytes)); non-JCS form is not valid"));
    }
    let expected_digest = compute_wasm_acceptance_record_digest_v2(&parsed.payload())?;
    if expected_digest != parsed.record_digest {
        return Err(err(WASM_ACCEPTANCE_RECORD_DIGEST_MISMATCH, "recordDigest must equal hex(SHA-256(UTF8(\"iweb-wasm-acceptance-record-v2\\n\" || JCS(record with recordDigest omitted))))"));
    }
    Ok(parsed)
}

/// 在 payload JCS 的键序里插入 `"recordDigest":"<hex>"`（"recordDigest" 排在 "result"
/// 之前、"hostABI" 之后；全 ASCII 域内 bytewise 序稳定）。这是 JCS 字节相等的实现细节，
/// 不是第二套编码语义。
fn insert_record_digest_member(payload_jcs: &[u8], record_digest: &str) -> Vec<u8> {
    let text = std::str::from_utf8(payload_jcs).expect("payload JCS is ASCII-domain UTF-8");
    // 插入成员 = "recordDigest":"<hex>" + ','；payload[..at] 已以前一成员的分隔逗号结尾。
    let member = format!(r#""recordDigest":"{record_digest}","#);
    let insertion = "\"result\":"; // bytewise：recordDigest < result（'c' < 's'）
    match text.find(insertion) {
        Some(at) => {
            let mut out = Vec::with_capacity(payload_jcs.len() + member.len());
            out.extend_from_slice(&payload_jcs[..at]);
            out.extend_from_slice(member.as_bytes());
            out.extend_from_slice(&payload_jcs[at..]);
            out
        }
        None => {
            // 理论不可达：payload JCS 必含 "result" 键；fail-closed 返回不匹配的字节。
            let mut out = payload_jcs.to_vec();
            out.extend_from_slice(member.as_bytes());
            out
        }
    }
}

// ---------------------------------------------------------------------------
// GateResultV1 / PublicationGateSetV1：reasons wire 与双 gate 选择
// ---------------------------------------------------------------------------

/// spec GateResultV1（精确六键；reasons duplicate-free 且按稳定顺序）。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GateResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    pub enabled: bool,
    pub requested: bool,
    pub accepted: bool,
    pub reasons: Vec<&'static str>,
}

/// spec PublicationGateSetV1（启动时并行评估两个 runtime kind 的不可变结果集）。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PublicationGateSetV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub celld: GateResultV1,
    pub wasm: GateResultV1,
}

/// Kernel 内部入口的 gate selection response：`{schemaVersion:1,runtimeKind,enabled,reasons}`。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GateSelectionResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    pub enabled: bool,
    pub reasons: Vec<&'static str>,
}

fn push_reason_stable(reasons: &mut Vec<&'static str>, reason: &'static str) {
    if reasons.contains(&reason) {
        return; // duplicate-free
    }
    let position = GATE_REASON_ORDER.iter().position(|candidate| *candidate == reason).expect("reason must be part of the stable order");
    // 插在第一个稳定序大于新 reason 的现有成员之前；否则追加。
    let insert_at = reasons
        .iter()
        .position(|existing| GATE_REASON_ORDER.iter().position(|candidate| candidate == existing).expect("existing reason must be part of the stable order") > position)
        .unwrap_or(reasons.len());
    reasons.insert(insert_at, reason);
}

fn gate_result(runtime_kind: &'static str, enabled: bool, requested: bool, accepted: bool, reasons: Vec<&'static str>) -> GateResultV1 {
    GateResultV1 { schema_version: 1, runtime_kind: runtime_kind.to_string(), enabled, requested, accepted, reasons }
}

/// 跨 kind 守卫：把一个 gate 的结果喂给另一个 runtime kind 时，返回 disabled 结果并
/// 合并 runtime-kind-mismatch（spec 场景「The old single gate is asked to publish wasm」；
/// 绝不调用另一个 parser 作 fallback）。
pub fn gate_result_for_runtime_kind(gate: &GateResultV1, runtime_kind: &str) -> GateResultV1 {
    if gate.runtime_kind == runtime_kind {
        return gate.clone();
    }
    let mut reasons = gate.reasons.clone();
    push_reason_stable(&mut reasons, REASON_RUNTIME_KIND_MISMATCH);
    GateResultV1 {
        schema_version: 1,
        runtime_kind: runtime_kind.to_string(),
        enabled: false,
        requested: gate.requested,
        accepted: gate.accepted,
        reasons,
    }
}

fn selection_response(gate: &GateResultV1) -> GateSelectionResponseV1 {
    GateSelectionResponseV1 { schema_version: 1, runtime_kind: gate.runtime_kind.clone(), enabled: gate.enabled, reasons: gate.reasons.clone() }
}

/// `selectPublicationGate(runtimeKind, PublicationGateSetV1)`：`"celld"` 返回现行 v1 gate
/// 契约结果，`"wasm"` 返回 v2 validator 结果，其它值返回 RUNTIME_KIND_UNSUPPORTED typed
/// error，且不尝试任何一个 parser。
pub fn select_publication_gate(runtime_kind: &str, set: &PublicationGateSetV1) -> Result<GateSelectionResponseV1, PublicationGateError> {
    match runtime_kind {
        RUNTIME_KIND_CELLD => Ok(selection_response(&set.celld)),
        RUNTIME_KIND_WASM => Ok(selection_response(&set.wasm)),
        other => Err(err(RUNTIME_KIND_UNSUPPORTED, format!("runtime kind \"{other}\" has no publication gate; no parser is tried"))),
    }
}

// ---------------------------------------------------------------------------
// 节点 pin 与开关视图
// ---------------------------------------------------------------------------

/// 当前节点选定的 catalog entry/binding pin（与记录逐字段相等比较）。
#[derive(Debug, Clone, PartialEq)]
pub struct WasmGateCatalogEntryPin {
    pub entry_key: String,
    pub image_digest: String,
    pub host_abi: String,
    pub world: String,
}

/// 当前节点身份 pin：catalog revision/hash、capability record revision/hash、架构。
#[derive(Debug, Clone, PartialEq)]
pub struct WasmGateNodeIdentity {
    pub architecture: String,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    pub catalog_revision: u64,
    pub catalog_hash: String,
    pub catalog_entry: WasmGateCatalogEntryPin,
}

/// 双开关视图（application switch + wasm switch）与 wasm 路径重定向检测。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GateEnvironmentView {
    pub application_publication_enabled: bool,
    pub wasm_publication_enabled: bool,
    /// 检测到重定向 wasm 验收路径的环境变量（变量名）；Some 即 fail-closed。
    pub wasm_acceptance_path_redirect: Option<String>,
}

impl GateEnvironmentView {
    /// 从任意环境查询构造（测试与宿主接线共用语义）。
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let application_publication_enabled = lookup(ENV_APPLICATION_PUBLICATION_ENABLED).as_deref() == Some("1");
        let wasm_publication_enabled = lookup(ENV_WASM_PUBLICATION_ENABLED).as_deref() == Some("1");
        let wasm_acceptance_path_redirect = ENV_WASM_ACCEPTANCE_PATH_REDIRECTS
            .iter()
            .find(|name| lookup(name).as_deref().is_some_and(|value| !value.is_empty()))
            .map(|name| (*name).to_string());
        Self { application_publication_enabled, wasm_publication_enabled, wasm_acceptance_path_redirect }
    }

    /// 从进程环境构造。
    pub fn from_process_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
}

// ---------------------------------------------------------------------------
// gate 评估纯函数
// ---------------------------------------------------------------------------

/// wasm 验收记录输入的三态：重定向 / 不可读 / 可读字节。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WasmAcceptanceInput<'a> {
    /// 环境变量尝试重定向固定路径（不读任何文件）。
    Redirected,
    /// 固定路径缺失或不可读。
    Unavailable,
    /// 固定路径的原始字节。
    Bytes(&'a [u8]),
}

/// celld v1 记录判定（语义与 kernel/application-publication-gate.js 逐字一致：
/// JSON.parse 宽松格式 + 四字段判定；不要求 JCS）。
fn celld_v1_record_accepted(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    // JS 侧 `value.version !== 1` 对 1.0 视为相等（Number 语义）；此处以 f64 对齐。
    if object.get("version").and_then(serde_json::Value::as_f64) != Some(1.0) {
        return false;
    }
    if object.get("result").and_then(serde_json::Value::as_str) != Some("passed") {
        return false;
    }
    if object.get("gate").and_then(serde_json::Value::as_str) != Some("application-sandbox") {
        return false;
    }
    match object.get("evidenceDigest").and_then(serde_json::Value::as_str) {
        Some(digest) => publication_regexes().sha256_hex.is_match(digest),
        None => false,
    }
}

/// celld v1 gate：保持现行 `evaluateApplicationPublicationGate` 契约
/// （requested=IWEB_APPLICATION_PUBLICATION_ENABLED=1；accepted=v1 记录有效；
/// reasons 取 publication-not-requested / sandbox-acceptance-missing）。
pub fn evaluate_celld_publication_gate_v1(record_bytes: Option<&[u8]>, application_switch: bool) -> GateResultV1 {
    let requested = application_switch;
    let accepted = record_bytes.is_some_and(celld_v1_record_accepted);
    let mut reasons = Vec::new();
    if !requested {
        push_reason_stable(&mut reasons, REASON_PUBLICATION_NOT_REQUESTED);
    }
    if !accepted {
        push_reason_stable(&mut reasons, REASON_SANDBOX_ACCEPTANCE_MISSING);
    }
    gate_result(RUNTIME_KIND_CELLD, requested && accepted, requested, accepted, reasons)
}

/// wasm v2 gate 纯函数：记录输入 + 节点 pin + 双开关 → GateResultV1。
pub fn evaluate_wasm_publication_gate_v2(
    input: WasmAcceptanceInput<'_>,
    node: Option<&WasmGateNodeIdentity>,
    switches: &GateEnvironmentView,
) -> GateResultV1 {
    // 双开关（见歧义备注 1）：wasm 发布同时要求 application switch 与 wasm switch。
    let requested = switches.application_publication_enabled && switches.wasm_publication_enabled;
    let mut reasons: Vec<&'static str> = Vec::new();
    if !requested {
        push_reason_stable(&mut reasons, REASON_PUBLICATION_NOT_REQUESTED);
    }
    let mut accepted = false;
    let mut identity_ok = true;
    match input {
        WasmAcceptanceInput::Redirected => {
            // fail-closed：固定路径不可被环境变量重定向，检测到尝试即拒绝且不读任何文件。
            push_reason_stable(&mut reasons, REASON_WASM_ACCEPTANCE_INVALID);
        }
        WasmAcceptanceInput::Unavailable => {
            push_reason_stable(&mut reasons, REASON_SANDBOX_ACCEPTANCE_MISSING);
        }
        WasmAcceptanceInput::Bytes(bytes) => match verify_wasm_acceptance_record_v2(bytes) {
            Err(_) => push_reason_stable(&mut reasons, REASON_WASM_ACCEPTANCE_INVALID),
            Ok(record) => {
                accepted = true;
                match node {
                    None => {
                        // 未加载节点 pin：三项 pin 比较全部按失配关闭，不推断默认值。
                        push_reason_stable(&mut reasons, REASON_WASM_IDENTITY_MISMATCH);
                        push_reason_stable(&mut reasons, REASON_CAPABILITY_RECORD_MISMATCH);
                        push_reason_stable(&mut reasons, REASON_CATALOG_MISMATCH);
                        identity_ok = false;
                    }
                    Some(node) => {
                        // 记录 arch 与节点 arch 逐字相等；节点 arch 本身必须受支持。
                        if !WASM_RUNTIME_ARCHITECTURES.contains(&node.architecture.as_str()) || record.arch != node.architecture {
                            push_reason_stable(&mut reasons, REASON_UNSUPPORTED_ARCHITECTURE);
                            identity_ok = false;
                        }
                        if record.capability_record_revision != node.capability_record_revision
                            || record.capability_record_hash != node.capability_record_hash
                        {
                            push_reason_stable(&mut reasons, REASON_CAPABILITY_RECORD_MISMATCH);
                            identity_ok = false;
                        }
                        if record.catalog_revision != node.catalog_revision || record.catalog_hash != node.catalog_hash {
                            push_reason_stable(&mut reasons, REASON_CATALOG_MISMATCH);
                            identity_ok = false;
                        }
                        let entry = &node.catalog_entry;
                        if record.catalog_entry_key != entry.entry_key
                            || record.runtime_image_digest != entry.image_digest
                            || record.host_abi != entry.host_abi
                            || record.world != entry.world
                        {
                            push_reason_stable(&mut reasons, REASON_WASM_IDENTITY_MISMATCH);
                            identity_ok = false;
                        }
                    }
                }
            }
        },
    }
    let enabled = requested && accepted && identity_ok;
    gate_result(RUNTIME_KIND_WASM, enabled, requested, accepted, reasons)
}

/// 启动时并行评估两个 runtime kind。`read_bytes` 只会被以两个固定路径常量调用
/// （重定向检测命中时 wasm 侧不读任何文件）；两个 gate 互不启用、无 fallback。
pub fn evaluate_publication_gate_set_v1(
    read_bytes: &dyn Fn(&str) -> std::io::Result<Vec<u8>>,
    switches: &GateEnvironmentView,
    node: Option<&WasmGateNodeIdentity>,
) -> PublicationGateSetV1 {
    // (1) 现行 celld gate：保留 enabled/requested/accepted/reasons 语义。
    let celld_record = read_bytes(CELLD_ACCEPTANCE_FILE).ok();
    let celld = evaluate_celld_publication_gate_v1(celld_record.as_deref(), switches.application_publication_enabled);
    // (2) 独立读取并校验固定 wasm 验收记录（重定向检测命中时不读任何文件）。
    let wasm = match &switches.wasm_acceptance_path_redirect {
        Some(_) => evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Redirected, node, switches),
        None => match read_bytes(WASM_ACCEPTANCE_FILE) {
            Ok(bytes) => evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(&bytes), node, switches),
            Err(_) => evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Unavailable, node, switches),
        },
    };
    // (3) 发布不可变 PublicationGateSetV1。
    PublicationGateSetV1 { schema_version: 1, celld, wasm }
}

/// 发布守卫（对位 JS requireApplicationPublication 的 wasm 版）：门未开即抛稳定码。
pub fn require_wasm_publication(gate: &GateResultV1) -> Result<(), PublicationGateError> {
    if gate.runtime_kind != RUNTIME_KIND_WASM {
        return Err(err(WASM_PUBLICATION_GATE_INVALID, "the gate result was not produced by the wasm v2 validator"));
    }
    if !gate.enabled {
        return Err(err(WASM_PUBLICATION_GATE_INVALID, "wasm publication is disabled until the v2 acceptance record passes"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 测试：golden 向量（bun oracle 2026-08-26 按公式手工 preimage 产出）+ 拒绝面
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // bun oracle（独立按公式拼 preimage，不复用本实现）：
    //   preimage = "iweb-wasm-acceptance-record-v2\n" ||
    //     JCS({arch, capabilityRecordHash, capabilityRecordRevision, catalogEntryKey,
    //          catalogHash, catalogRevision, evidenceDigest, gate, hostABI, result,
    //          runtimeImageDigest, runtimeKind, version, world})
    //   sha256(preimage) = 69f0125fdd737b9b6f662fabd2c3cd52a3d0d93b82835ee9c10f19de7c2eea1f
    const GOLDEN_RECORD_DIGEST: &str = "69f0125fdd737b9b6f662fabd2c3cd52a3d0d93b82835ee9c10f19de7c2eea1f";
    const GOLDEN_RECORD_JCS: &str = r#"{"arch":"linux/amd64","capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"catalogEntryKey":"iweb-wasmd","catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"evidenceDigest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","gate":"application-sandbox","hostABI":"iweb-wasmd-abi@1.0.0","recordDigest":"69f0125fdd737b9b6f662fabd2c3cd52a3d0d93b82835ee9c10f19de7c2eea1f","result":"passed","runtimeImageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","runtimeKind":"wasm","version":2,"world":"wasi:http/proxy@0.2.8"}"#;

    fn golden_payload() -> WasmAcceptanceRecordPayloadV2 {
        WasmAcceptanceRecordPayloadV2 {
            version: 2,
            result: "passed".into(),
            gate: "application-sandbox".into(),
            runtime_kind: "wasm".into(),
            runtime_image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: WASM_HOST_ABI_LITERAL.into(),
            world: WASM_WORLD_LITERAL.into(),
            arch: "linux/amd64".into(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            catalog_entry_key: "iweb-wasmd".into(),
            evidence_digest: "e".repeat(64),
        }
    }

    fn golden_record_bytes() -> Vec<u8> {
        GOLDEN_RECORD_JCS.as_bytes().to_vec()
    }

    fn node_identity() -> WasmGateNodeIdentity {
        WasmGateNodeIdentity {
            architecture: "linux/amd64".into(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            catalog_entry: WasmGateCatalogEntryPin {
                entry_key: "iweb-wasmd".into(),
                image_digest: format!("sha256:{}", "cd".repeat(32)),
                host_abi: WASM_HOST_ABI_LITERAL.into(),
                world: WASM_WORLD_LITERAL.into(),
            },
        }
    }

    fn all_on_switches() -> GateEnvironmentView {
        GateEnvironmentView { application_publication_enabled: true, wasm_publication_enabled: true, wasm_acceptance_path_redirect: None }
    }

    // 独立 oracle：手工拼 preimage 再单次 SHA-256（不复用被测实现）。
    fn oracle_domain_digest(domain: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(b"\n");
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

    // oracle 的手工 payload JCS（与 bun 产出逐字一致）。
    fn oracle_payload_jcs() -> String {
        r#"{"arch":"linux/amd64","capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"catalogEntryKey":"iweb-wasmd","catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"evidenceDigest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","gate":"application-sandbox","hostABI":"iweb-wasmd-abi@1.0.0","result":"passed","runtimeImageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","runtimeKind":"wasm","version":2,"world":"wasi:http/proxy@0.2.8"}"#.to_string()
    }

    #[test]
    fn golden_record_digest_matches_bun_oracle() {
        let computed = compute_wasm_acceptance_record_digest_v2(&golden_payload()).expect("digest computes");
        assert_eq!(computed, GOLDEN_RECORD_DIGEST);
        // 与实现无关的 oracle 复算（域前缀 + 单次 SHA-256，绝不对 hex 串二次 hash）。
        assert_eq!(oracle_domain_digest(WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN, oracle_payload_jcs().as_bytes()), GOLDEN_RECORD_DIGEST);
    }

    #[test]
    fn golden_record_verifies_and_round_trips() {
        let record = verify_wasm_acceptance_record_v2(&golden_record_bytes()).expect("golden record verifies");
        assert_eq!(record.record_digest, GOLDEN_RECORD_DIGEST);
        assert_eq!(record.payload(), golden_payload());
    }

    #[test]
    fn unknown_field_is_rejected_before_enablement() {
        // 带 extra 字段的记录，且 recordDigest 是对「另一字段集」（改 evidenceDigest）计算的：
        // spec 场景「an extra field or a digest computed over a different field set」。
        let mut payload = golden_payload();
        payload.evidence_digest = "f".repeat(64); // 改字段同时保证「digest 对另一字段集计算」场景
        let digest = compute_wasm_acceptance_record_digest_v2(&payload).unwrap();
        let image_digest = format!("sha256:{}", "cd".repeat(32));
        let forged = format!(
            r#"{{"arch":"linux/amd64","capabilityRecordHash":"{}","capabilityRecordRevision":5,"catalogEntryKey":"iweb-wasmd","catalogHash":"{}","catalogRevision":9,"evidenceDigest":"{}","extra":true,"gate":"application-sandbox","hostABI":"{}","recordDigest":"{}","result":"passed","runtimeImageDigest":"{}","runtimeKind":"wasm","version":2,"world":"{}"}}"#,
            "2".repeat(64),
            "ab".repeat(32),
            "f".repeat(64),
            WASM_HOST_ABI_LITERAL,
            digest,
            image_digest,
            WASM_WORLD_LITERAL,
        );
        let error = verify_wasm_acceptance_record_v2(forged.as_bytes()).expect_err("unknown field must be rejected");
        assert_eq!(error.code, WASM_ACCEPTANCE_RECORD_INVALID);
        // gate 层面：enabling 条件下仍关闭。
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(forged.as_bytes()), Some(&node_identity()), &all_on_switches());
        assert!(!gate.enabled);
        assert_eq!(gate.reasons, vec![REASON_WASM_ACCEPTANCE_INVALID]);
    }

    #[test]
    fn missing_field_is_rejected() {
        // 从合法 JCS 里删掉 "evidenceDigest" 成员。
        let text = String::from_utf8(golden_record_bytes()).unwrap();
        let without = text.replace(&format!(r#","evidenceDigest":"{}""#, "e".repeat(64)), "");
        let error = verify_wasm_acceptance_record_v2(without.as_bytes()).expect_err("missing field must be rejected");
        assert_eq!(error.code, WASM_ACCEPTANCE_RECORD_INVALID);
    }

    #[test]
    fn digest_mismatch_is_rejected_with_stable_code() {
        let mut text = String::from_utf8(golden_record_bytes()).unwrap();
        let bad = "0".repeat(64);
        text = text.replace(&format!(r#""recordDigest":"{}""#, GOLDEN_RECORD_DIGEST), &format!(r#""recordDigest":"{bad}""#));
        let error = verify_wasm_acceptance_record_v2(text.as_bytes()).expect_err("digest mismatch must be rejected");
        assert_eq!(error.code, WASM_ACCEPTANCE_RECORD_DIGEST_MISMATCH);
    }

    #[test]
    fn non_jcs_bytes_are_rejected() {
        // 同字段、不同键序（version 提前）：解析等价但不是 JCS。
        let reordered = format!(
            concat!(
                r#"{{"version":2,"result":"passed","gate":"application-sandbox","runtimeKind":"wasm","runtimeImageDigest":"sha256:{img}","hostABI":"{abi}","world":"{world}","arch":"linux/amd64","capabilityRecordRevision":5,"capabilityRecordHash":"{cap}","catalogRevision":9,"catalogHash":"{cat}","catalogEntryKey":"iweb-wasmd","evidenceDigest":"{ev}","recordDigest":"{digest}"}}"#
            ),
            img = "cd".repeat(32),
            abi = WASM_HOST_ABI_LITERAL,
            world = WASM_WORLD_LITERAL,
            cap = "2".repeat(64),
            cat = "ab".repeat(32),
            ev = "e".repeat(64),
            digest = GOLDEN_RECORD_DIGEST,
        );
        let error = verify_wasm_acceptance_record_v2(reordered.as_bytes()).expect_err("non-JCS form must be rejected");
        assert_eq!(error.code, WASM_ACCEPTANCE_RECORD_INVALID);
    }

    #[test]
    fn duplicate_member_is_rejected() {
        // 同名成员重复出现：必须在「最后值覆盖」之前被检测（serde derive 的重复字段检测）。
        let explicit = format!(
            r#"{{"arch":"linux/amd64","arch":"linux/arm64","capabilityRecordHash":"{}","capabilityRecordRevision":5,"catalogEntryKey":"iweb-wasmd","catalogHash":"{}","catalogRevision":9,"evidenceDigest":"{}","gate":"application-sandbox","hostABI":"{}","recordDigest":"{}","result":"passed","runtimeImageDigest":"sha256:{}","runtimeKind":"wasm","version":2,"world":"{}"}}"#,
            "2".repeat(64),
            "ab".repeat(32),
            "e".repeat(64),
            WASM_HOST_ABI_LITERAL,
            GOLDEN_RECORD_DIGEST,
            "cd".repeat(32),
            WASM_WORLD_LITERAL,
        );
        let error = verify_wasm_acceptance_record_v2(explicit.as_bytes()).expect_err("duplicate member must be rejected before last-value override");
        assert_eq!(error.code, WASM_ACCEPTANCE_RECORD_INVALID);
    }

    #[test]
    fn malformed_json_is_rejected() {
        let error = verify_wasm_acceptance_record_v2(b"{ not json").expect_err("malformed JSON must be rejected");
        assert_eq!(error.code, WASM_ACCEPTANCE_RECORD_INVALID);
    }

    #[test]
    fn v1_record_cannot_open_wasm() {
        // 现行 celld v1 记录（合法）喂给 wasm validator：缺少 v2 字段 → 拒绝。
        let v1 = br#"{"version":1,"gate":"application-sandbox","result":"passed","evidenceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let error = verify_wasm_acceptance_record_v2(v1).expect_err("v1 record must not validate as v2");
        assert_eq!(error.code, WASM_ACCEPTANCE_RECORD_INVALID);
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(v1), Some(&node_identity()), &all_on_switches());
        assert!(!gate.enabled);
        assert_eq!(gate.reasons, vec![REASON_WASM_ACCEPTANCE_INVALID]);
        // 只有 application switch（没有 wasm switch）同样不开 wasm。
        let switches = GateEnvironmentView { application_publication_enabled: true, wasm_publication_enabled: false, wasm_acceptance_path_redirect: None };
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(&golden_record_bytes()), Some(&node_identity()), &switches);
        assert!(!gate.enabled);
        assert_eq!(gate.reasons, vec![REASON_PUBLICATION_NOT_REQUESTED]);
        // 把 v1 gate 的结果跨 kind 喂给 wasm：runtime-kind-mismatch，且不触发 celld parser fallback。
        let set_celld_only = PublicationGateSetV1 {
            schema_version: 1,
            celld: evaluate_celld_publication_gate_v1(Some(v1.as_slice()), true),
            wasm: evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Unavailable, None, &all_on_switches()),
        };
        let cross = gate_result_for_runtime_kind(&set_celld_only.celld, RUNTIME_KIND_WASM);
        assert_eq!(cross.runtime_kind, RUNTIME_KIND_WASM);
        assert!(!cross.enabled);
        assert_eq!(cross.reasons, vec![REASON_RUNTIME_KIND_MISMATCH]);
    }

    #[test]
    fn v2_record_cannot_open_celld() {
        // celld v1 validator 对 v2 记录：version!==1 → 不接受。
        assert!(!celld_v1_record_accepted(&golden_record_bytes()));
        // set 层面：wasm 全开 + celld 缺记录 → 只有 wasm 开。
        let set = evaluate_publication_gate_set_v1(
            &|path| {
                if path == WASM_ACCEPTANCE_FILE {
                    Ok(golden_record_bytes())
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
                }
            },
            &all_on_switches(),
            Some(&node_identity()),
        );
        assert!(set.wasm.enabled);
        assert!(!set.celld.enabled);
        assert_eq!(set.celld.reasons, vec![REASON_SANDBOX_ACCEPTANCE_MISSING]);
        let selection = select_publication_gate(RUNTIME_KIND_CELLD, &set).expect("celld selection is exact");
        assert!(!selection.enabled);
        assert_eq!(selection.reasons, vec![REASON_SANDBOX_ACCEPTANCE_MISSING]);
    }

    #[test]
    fn identity_mismatch_returns_exact_reason_codes_in_stable_order() {
        // 构造对另一节点身份的合法自 digest 记录（catalog/capability/arch/image 各失配）。
        let mut payload = golden_payload();
        payload.catalog_revision = 10;
        payload.capability_record_hash = "3".repeat(64);
        payload.arch = "linux/arm64".into();
        payload.runtime_image_digest = format!("sha256:{}", "ce".repeat(32));
        let digest = compute_wasm_acceptance_record_digest_v2(&payload).unwrap();
        let text = format!(
            concat!(
                r#"{{"arch":"{arch}","capabilityRecordHash":"{cap}","capabilityRecordRevision":{caprev},"catalogEntryKey":"{key}","catalogHash":"{cat}","catalogRevision":{catrev},"evidenceDigest":"{ev}","gate":"application-sandbox","hostABI":"{abi}","recordDigest":"{digest}","result":"passed","runtimeImageDigest":"{img}","runtimeKind":"wasm","version":2,"world":"{world}"}}"#
            ),
            arch = payload.arch,
            cap = payload.capability_record_hash,
            caprev = payload.capability_record_revision,
            key = payload.catalog_entry_key,
            cat = payload.catalog_hash,
            catrev = payload.catalog_revision,
            ev = payload.evidence_digest,
            abi = payload.host_abi,
            digest = digest,
            img = payload.runtime_image_digest,
            world = payload.world,
        );
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(text.as_bytes()), Some(&node_identity()), &all_on_switches());
        assert!(!gate.enabled);
        // 稳定顺序：identity(4) < capability(6) < catalog(7) < unsupported-arch(8)。
        assert_eq!(
            gate.reasons,
            vec![REASON_WASM_IDENTITY_MISMATCH, REASON_CAPABILITY_RECORD_MISMATCH, REASON_CATALOG_MISMATCH, REASON_UNSUPPORTED_ARCHITECTURE]
        );
        // 单项失配：capability revision 不等 → 仅 capability-record-mismatch。
        let mut other = node_identity();
        other.capability_record_revision = 6;
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(&golden_record_bytes()), Some(&other), &all_on_switches());
        assert_eq!(gate.reasons, vec![REASON_CAPABILITY_RECORD_MISMATCH]);
        // 单项失配：catalog hash 不等 → 仅 catalog-mismatch。
        let mut other = node_identity();
        other.catalog_hash = "ac".repeat(32);
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(&golden_record_bytes()), Some(&other), &all_on_switches());
        assert_eq!(gate.reasons, vec![REASON_CATALOG_MISMATCH]);
        // 单项失配：entry key 不等 → 仅 wasm-identity-mismatch。
        let mut other = node_identity();
        other.catalog_entry.entry_key = "other-wasmd".into();
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(&golden_record_bytes()), Some(&other), &all_on_switches());
        assert_eq!(gate.reasons, vec![REASON_WASM_IDENTITY_MISMATCH]);
        // 节点 arch 不受支持（如开发机 darwin/arm64）→ unsupported-architecture。
        let mut other = node_identity();
        other.architecture = "darwin/arm64".into();
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(&golden_record_bytes()), Some(&other), &all_on_switches());
        assert_eq!(gate.reasons, vec![REASON_UNSUPPORTED_ARCHITECTURE]);
    }

    #[test]
    fn missing_node_pins_fail_closed() {
        let gate = evaluate_wasm_publication_gate_v2(WasmAcceptanceInput::Bytes(&golden_record_bytes()), None, &all_on_switches());
        assert!(!gate.enabled);
        assert!(gate.accepted, "record itself is valid; only pins are missing");
        assert_eq!(gate.reasons, vec![REASON_WASM_IDENTITY_MISMATCH, REASON_CAPABILITY_RECORD_MISMATCH, REASON_CATALOG_MISMATCH]);
    }

    #[test]
    fn dual_gates_evaluate_independently_without_fallback() {
        let celld_ok: &[u8] = br#"{"version":1,"gate":"application-sandbox","result":"passed","evidenceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        // celld 记录有效 + wasm 记录损坏：wasm 关、celld 开。
        let set = evaluate_publication_gate_set_v1(
            &|path| {
                if path == CELLD_ACCEPTANCE_FILE {
                    Ok(celld_ok.to_vec())
                } else if path == WASM_ACCEPTANCE_FILE {
                    Ok(b"{ broken".to_vec())
                } else {
                    panic!("reader must only be called with the two fixed paths, got {path}");
                }
            },
            &all_on_switches(),
            Some(&node_identity()),
        );
        assert!(set.celld.enabled);
        assert!(!set.wasm.enabled);
        assert_eq!(set.wasm.reasons, vec![REASON_WASM_ACCEPTANCE_INVALID]);
        // 双开。
        let set = evaluate_publication_gate_set_v1(
            &|path| {
                if path == CELLD_ACCEPTANCE_FILE {
                    Ok(celld_ok.to_vec())
                } else if path == WASM_ACCEPTANCE_FILE {
                    Ok(golden_record_bytes())
                } else {
                    panic!("unexpected path {path}");
                }
            },
            &all_on_switches(),
            Some(&node_identity()),
        );
        assert!(set.celld.enabled && set.wasm.enabled);
        let celld_selection = select_publication_gate("celld", &set).expect("celld selects");
        let wasm_selection = select_publication_gate("wasm", &set).expect("wasm selects");
        assert!(celld_selection.enabled && wasm_selection.enabled);
        assert_eq!(celld_selection.reasons, Vec::<&str>::new());
        assert_eq!(wasm_selection.reasons, Vec::<&str>::new());
        assert!(require_wasm_publication(&set.wasm).is_ok());
    }

    #[test]
    fn unknown_runtime_kind_is_a_typed_selection_error() {
        let set = evaluate_publication_gate_set_v1(&|_| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")), &all_on_switches(), Some(&node_identity()));
        let error = select_publication_gate("deno", &set).expect_err("unknown kind must be a typed error");
        assert_eq!(error.code, RUNTIME_KIND_UNSUPPORTED);
    }

    #[test]
    fn path_redirection_is_rejected_without_reading_any_file() {
        let read_paths = std::cell::RefCell::new(Vec::new());
        let switches = GateEnvironmentView {
            application_publication_enabled: true,
            wasm_publication_enabled: true,
            wasm_acceptance_path_redirect: Some("IWEB_WASM_SANDBOX_ACCEPTANCE_FILE".into()),
        };
        let set = evaluate_publication_gate_set_v1(
            &|path| {
                read_paths.borrow_mut().push(path.to_string());
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
            },
            &switches,
            Some(&node_identity()),
        );
        // wasm 侧不读任何文件（重定向即拒绝）；celld 侧仍只读自己的固定路径。
        assert_eq!(*read_paths.borrow(), vec![CELLD_ACCEPTANCE_FILE.to_string()]);
        assert!(!set.wasm.enabled);
        assert_eq!(set.wasm.reasons, vec![REASON_WASM_ACCEPTANCE_INVALID]);
        // 环境视图：非空重定向值命中；空字符串不视为重定向（与「未设置」一致）。
        let view = GateEnvironmentView::from_lookup(|name| (name == "IWEB_WASM_ACCEPTANCE_FILE").then_some("/tmp/forged.json".to_string()));
        assert_eq!(view.wasm_acceptance_path_redirect.as_deref(), Some("IWEB_WASM_ACCEPTANCE_FILE"));
        let view = GateEnvironmentView::from_lookup(|name| (name == "IWEB_WASM_ACCEPTANCE_FILE").then_some(String::new()));
        assert_eq!(view.wasm_acceptance_path_redirect, None);
    }

    #[test]
    fn celld_gate_semantics_match_the_js_contract() {
        let record: &[u8] = br#"{"version":1,"gate":"application-sandbox","result":"passed","evidenceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        // 默认关：无开关 + 缺记录。
        let gate = evaluate_celld_publication_gate_v1(None, false);
        assert_eq!((gate.enabled, gate.requested, gate.accepted), (false, false, false));
        assert_eq!(gate.reasons, vec![REASON_PUBLICATION_NOT_REQUESTED, REASON_SANDBOX_ACCEPTANCE_MISSING]);
        // 只有开关：不开。
        let gate = evaluate_celld_publication_gate_v1(None, true);
        assert_eq!((gate.enabled, gate.requested, gate.accepted), (false, true, false));
        // 只有记录：不开。
        let gate = evaluate_celld_publication_gate_v1(Some(record), false);
        assert_eq!((gate.enabled, gate.requested, gate.accepted), (false, false, true));
        // 双条件：开（宽松 JSON 格式也接受——v1 契约）。
        let spaced = b"  { \"version\" : 1.0 , \"result\": \"passed\",  \"gate\":\"application-sandbox\", \"evidenceDigest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" }  ";
        let gate = evaluate_celld_publication_gate_v1(Some(spaced), true);
        assert_eq!((gate.enabled, gate.requested, gate.accepted), (true, true, true));
        assert_eq!(gate.reasons, Vec::<&str>::new());
        // 坏记录（digest 大写）：不开。
        let upper: &[u8] = br#"{"version":1,"gate":"application-sandbox","result":"passed","evidenceDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let gate = evaluate_celld_publication_gate_v1(Some(upper), true);
        assert!(!gate.accepted);
        assert_eq!(gate.reasons, vec![REASON_SANDBOX_ACCEPTANCE_MISSING]);
    }

    #[test]
    fn gate_selection_wire_shape_is_exact() {
        let set = evaluate_publication_gate_set_v1(
            &|path| (path == WASM_ACCEPTANCE_FILE).then(golden_record_bytes).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
            &all_on_switches(),
            Some(&node_identity()),
        );
        let wire = serde_json::to_value(&set).expect("set serializes");
        assert_eq!(wire["schemaVersion"], serde_json::json!(1));
        assert_eq!(wire["celld"]["runtimeKind"], serde_json::json!("celld"));
        assert_eq!(wire["wasm"]["runtimeKind"], serde_json::json!("wasm"));
        let selection = select_publication_gate("wasm", &set).expect("wasm selects");
        let selection_wire = serde_json::to_value(&selection).expect("selection serializes");
        // 内部入口响应精确四键：schemaVersion/runtimeKind/enabled/reasons。
        assert_eq!(selection_wire, serde_json::json!({"schemaVersion":1,"runtimeKind":"wasm","enabled":true,"reasons":[]}));
    }
}
