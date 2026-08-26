//! 用户原始需求（2026-08-26，add-wasm-runtime J 批次 Kernel 启动/HTTP 接线）：把
//! wasm_admission / wasm_kind_registry / wasm_activation / wasm_publication /
//! wasm_commands 状态机接进 Kernel 生产路径——启动序（双 gate 并行评估 → celld
//! kind-claim bootstrap 验证/引导 → admission/activation 恢复）、owner 控制端点
//! （admission 提交、activation-rpc、wasm 状态投影）与 retired 投影。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//! （"Runtime-kind publication gate selection is a dual-gate wire"、"Activation has a
//! replayable Kernel control wire"、"Drain completion is a typed receipt before Kernel
//! retirement"）与 specs/application-sandbox/spec.md delta（单点 AdmittedVisible、
//! kind-claim CAS 与 bootstrap 启动门、激活 route CAS 与 lease 门）。
//!
//! 接线取舍（保守 fail-closed，供 review 对照）：
//! 1. celld 现行路径零改动：本模块只新增 /v1/wasm/* 端点与启动评估；
//!    /v1/applications 503 gate 与 /v1/status.applicationPublication 语义保持原样。
//! 2. 未启用开关（或验收记录无效、节点 pin 缺失）时 wasm 路径一律 503
//!    WASM_PUBLICATION_DISABLED，对齐现行发布门 fail-closed 语义。
//! 3. 节点 pin（catalog/capability/arch）来源：Kernel 拥有的固定路径
//!    `<wasm-root>/gate-node-identity.json`（canonical JCS；缺失/损坏 → node=None →
//!    gate 以 identity/capability/catalog mismatch 关闭，绝不推断默认 pin）。真正的
//!    NodeCapabilityRecordV1 / RuntimeCatalogV1 Rust 加载器落地后由其替换该投影文件。
//! 4. 激活 CAS 判据（current preparation/secret revision、candidate 存活、lifecycle
//!    ready）与 readiness lease 台账来自 Kernel 拥有的 `<wasm-root>/wasm-fences.json`
//!    与 `<wasm-root>/readiness-leases.json`——执行流（supervisor 执行命令通道，独立
//!    J 批次）是唯一写者；本模块只读。文件缺失/损坏 → 判据 fail-closed（激活被拒），
//!    绝不伪造 ready。
//! 5. wasm 业务记录持久化：`<wasm-root>/wasm-route-registry.json` 保存 AdmissionProofV1
//!    集合 + lifecycle 覆盖表（admitted/active/retired 由本接线维护；行形状由
//!    project_registry_row 从 proof 确定投影）。完整 wasm-control-state-v2.json
//!    （含 commandOutbox/migration）属于执行命令通道接线，本文件不越权写它。
//! 6. drain receipt 的 owner-HTTP 入口不存在（spec：receipt 来自 supervisor 通道）；
//!    本模块暴露 project_drain_receipt 供执行流接线/测试驱动 retired 投影。
//! 7. celld 控制态缺失按空状态引导（空字节 digest）；文件出现后 digest 变化强制
//!    重推导（celld_control_state_changed 语义），wasm 写路径在重验证前保持关闭。

use crate::wasm_activation::{
    generate_uuid_v7, handle_activation_rpc_http, ActivationDeps, ActivationHttpRequest,
    ActivationHttpOptions, ActivationStateIO, KernelActivationState, OwnedActivationCasFacts,
    ReadinessLeaseV2, RegistryRowFacts, WasmActivationStore, ACTIVATION_RPC_DEFAULT_MAX_BYTES,
    ACTIVATION_RPC_PATH,
};
use crate::wasm_admission::{
    admitted_visible, commit_wasm_admission, jcs_bytes, project_registry_row,
    recover_wasm_admission, verify_admission_proof, AdmissionControlDb, AdmissionError,
    AdmissionMaterializer, AdmissionObjectStore, AdmissionProofV1, AdmissionRequest,
    AdmissionState, AdmissionStores, NormalizedWasmManifestV1, OsRandomTokenSource,
    RuntimeBindingIdentityV1, WasmActivePointerV1, WasmAdmissionJournalFile,
    WasmVersionRegistryRow,
};
use crate::wasm_commands::{
    DrainReceiptV1, DrainRetirementProjection, ExecutionCommandV1, RetiringExecutionRecord,
    WasmCommandControlState, WasmExecutionIdentityV1, WasmExecutionOperation,
};
use crate::wasm_kind_registry::{
    KindClaimBootstrapV1, KindRegistryStoreDir, WasmKernelRouteRegistryV1,
    APPLICATION_RUNTIME_KIND_CONFLICT, WASM_KIND_BOOTSTRAP_PENDING, RUNTIME_KIND_WASM,
};
use crate::wasm_publication::{
    evaluate_publication_gate_set_v1, require_wasm_publication, select_publication_gate,
    GateEnvironmentView, GateSelectionResponseV1, PublicationGateSetV1,
    WasmGateCatalogEntryPin, WasmGateNodeIdentity, RUNTIME_KIND_CELLD,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// 常量与稳定错误码（spec 已命名码优先；补充码沿用 contracts 命名风格）
// ---------------------------------------------------------------------------

/// wasm 状态根目录覆盖变量（缺省从 IWEB_CONTROL_DB_FILE 的父目录派生 `<dir>/wasm`）。
pub const ENV_WASM_STATE_ROOT: &str = "IWEB_WASM_STATE_ROOT";

/// owner 控制端点（activation-rpc 的路径常量由 wasm_activation 持有）。
pub const WASM_ADMISSION_SUBMIT_PATH: &str = "/v1/wasm/admission";
pub const WASM_STATUS_PATH: &str = "/v1/wasm/status";

pub const WASM_PUBLICATION_DISABLED: &str = "WASM_PUBLICATION_DISABLED";
pub const WASM_STATE_UNAVAILABLE: &str = "WASM_STATE_UNAVAILABLE";
pub const WASM_ADMISSION_WIRE_INVALID: &str = "WASM_ADMISSION_WIRE_INVALID";
pub const WASM_RUNTIME_IO: &str = "WASM_RUNTIME_IO";
pub const WASM_UNAUTHORIZED: &str = "WASM_UNAUTHORIZED";

/// admission 提交的传输层 body 上限（blob 以 base64 携带；admission.maxPackageBytes
/// 由上游制品校验器执行，本上限只防控制面滥用）。
pub const ADMISSION_SUBMIT_MAX_BYTES: usize = 68 * 1024 * 1024;

/// 结构化控制面失败：code 为稳定 owner 可见码，detail 不含秘密。
#[derive(Debug, Clone, PartialEq)]
pub struct WasmControlFailure {
    pub code: &'static str,
    pub detail: String,
}

impl WasmControlFailure {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

/// 控制面处理结果（http.rs 适配为 axum Response；模块级测试直接消费）。
#[derive(Debug, Clone, PartialEq)]
pub struct WasmHttpResponse {
    pub status: u16,
    pub body: String,
}

fn ok_json(status: u16, body: serde_json::Value) -> WasmHttpResponse {
    WasmHttpResponse { status, body: format!("{body}\n") }
}

fn err_json(status: u16, code: &str, detail: &str) -> WasmHttpResponse {
    ok_json(status, json!({ "ok": false, "code": code, "message": detail }))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn regex_sha256_hex() -> &'static regex::Regex {
    static SHA256_HEX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SHA256_HEX.get_or_init(|| regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"))
}

/// 文件层原子落盘（tmp + rename；对位现有 control/routes 的写纪律）。
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), WasmControlFailure> {
    let temporary = path.with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
    std::fs::write(&temporary, bytes)
        .map_err(|e| WasmControlFailure::new(WASM_RUNTIME_IO, format!("cannot write {}: {e}", temporary.display())))?;
    std::fs::rename(&temporary, path)
        .map_err(|e| WasmControlFailure::new(WASM_RUNTIME_IO, format!("cannot rename into {}: {e}", path.display())))
}

/// 从原始字节解析 typed 记录：serde derive 自带重复成员检测 + deny_unknown_fields
/// 精确键集；原始字节必须等于 JCS(parse(bytes))（不接受「解析后等价」）。
fn parse_canonical<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8], code: &'static str, noun: &str) -> Result<T, WasmControlFailure> {
    let parsed: T = serde_json::from_slice(bytes)
        .map_err(|e| WasmControlFailure::new(code, format!("{noun} bytes do not parse as the typed record: {e}")))?;
    let canonical = jcs_bytes(&parsed)
        .map_err(|e| WasmControlFailure::new(code, format!("{noun} is outside the canonical JSON domain: {}", e.detail)))?;
    if canonical != bytes {
        return Err(WasmControlFailure::new(code, format!("{noun} bytes must equal JCS(parse(bytes))")));
    }
    Ok(parsed)
}

fn write_canonical<T: Serialize>(path: &Path, record: &T) -> Result<(), WasmControlFailure> {
    let bytes = jcs_bytes(record)
        .map_err(|e| WasmControlFailure::new(WASM_RUNTIME_IO, format!("record is outside the canonical JSON domain: {}", e.detail)))?;
    atomic_write(path, &bytes)
}

fn map_admission_error(error: AdmissionError) -> WasmControlFailure {
    WasmControlFailure::new(error.code, error.detail)
}

/// wasm_admission 侧错误的 HTTP 投影：结构性拒绝 → 400；环境/IO 类 → 503。
fn admission_failure_http(error: &AdmissionError) -> WasmHttpResponse {
    let structural = matches!(
        error.code,
        crate::wasm_admission::WASM_APPLICATION_ID_INVALID
            | crate::wasm_admission::WASM_MANIFEST_INVALID
            | crate::wasm_admission::WASM_BINDING_INVALID
            | crate::wasm_admission::WASM_VERSION_ID_INVALID
            | crate::wasm_admission::WASM_VERSION_DIGEST_MISMATCH
            | crate::wasm_admission::WASM_APPLICATION_ID_MISMATCH
            | crate::wasm_admission::WASM_ADMISSION_PROOF_INVALID
            | crate::wasm_admission::WASM_ADMISSION_JOURNAL_INVALID
            | crate::wasm_admission::WASM_ADMISSION_STATE_INVALID
            | crate::wasm_admission::WASM_ADMISSION_LEASE_EXPIRED
            | crate::wasm_admission::WASM_ADMISSION_PROOF_MISMATCH
            | crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT
            | crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH
            | crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT
            | crate::wasm_admission::WASM_ADMISSION_TERMINAL_FAILED
            | crate::wasm_admission::WASM_ADMISSION_IN_FLIGHT
            | crate::wasm_admission::WASM_REGISTRY_CONFLICT
    );
    let status = if structural { 400 } else { 503 };
    err_json(status, error.code, &error.detail)
}

fn admission_state_label(state: AdmissionState) -> &'static str {
    match state {
        AdmissionState::Staging => "staging",
        AdmissionState::Validated => "validated",
        AdmissionState::ObjectComplete => "object-complete",
        AdmissionState::DbHidden => "db-hidden",
        AdmissionState::MaterializerAcknowledged => "materializer-acknowledged",
        AdmissionState::Visible => "visible",
        AdmissionState::Failed => "failed",
        AdmissionState::Collected => "collected",
    }
}

// ---------------------------------------------------------------------------
// 状态根目录与文件布局
// ---------------------------------------------------------------------------

/// wasm 控制面文件集（全部 Kernel 拥有；JCS 字节权威 + tmp/rename 原子落盘）。
#[derive(Debug, Clone)]
pub struct WasmRuntimePaths {
    /// wasm 状态根（默认 `<control-db 目录>/wasm`）。
    pub root: PathBuf,
    /// celld 控制态原始文件（bootstrap 的 digest 源；只读）。
    pub celld_control_db: PathBuf,
}

impl WasmRuntimePaths {
    /// 生产解析：IWEB_WASM_STATE_ROOT 显式优先；否则从控制库路径派生；再退
    /// /data/kernel/wasm。celld 控制态路径缺失按空文件处理（不阻断 celld 服务）。
    pub fn resolve(control_db: &str) -> Self {
        let root = std::env::var(ENV_WASM_STATE_ROOT)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                if control_db.is_empty() {
                    None
                } else {
                    Path::new(control_db).parent().map(|parent| {
                        if parent.as_os_str().is_empty() {
                            PathBuf::from(".").join("wasm")
                        } else {
                            parent.join("wasm")
                        }
                    })
                }
            })
            .unwrap_or_else(|| PathBuf::from("/data/kernel/wasm"));
        let celld_control_db = if control_db.is_empty() {
            PathBuf::from("/data/kernel/control-db.json")
        } else {
            PathBuf::from(control_db)
        };
        Self { root, celld_control_db }
    }

    fn admission_journal(&self) -> PathBuf {
        self.root.join("admission-journal.jsonl")
    }
    fn admission_objects(&self) -> PathBuf {
        self.root.join("admission-objects")
    }
    fn admission_db(&self) -> PathBuf {
        self.root.join("admission-db.json")
    }
    fn admission_receipts(&self) -> PathBuf {
        self.root.join("admission-receipts.json")
    }
    fn kind_registry(&self) -> PathBuf {
        self.root.join("kind-registry")
    }
    fn activation_state(&self) -> PathBuf {
        self.root.join("activation-state.json")
    }
    fn route_registry(&self) -> PathBuf {
        self.root.join("wasm-route-registry.json")
    }
    fn command_control(&self) -> PathBuf {
        self.root.join("wasm-command-control.json")
    }
    fn readiness_leases(&self) -> PathBuf {
        self.root.join("readiness-leases.json")
    }
    fn fences(&self) -> PathBuf {
        self.root.join("wasm-fences.json")
    }
    fn gate_node_identity(&self) -> PathBuf {
        self.root.join("gate-node-identity.json")
    }
}

// ---------------------------------------------------------------------------
// 文件存储适配：admission witness 三件套（objects / db / materializer）
// ---------------------------------------------------------------------------

/// 对象前缀安全检查：前缀由 proof 派生（applicationId/versionId 文法已验证），
/// 防御性拒绝路径分隔符，绝不拼接出根外路径。
fn safe_prefix(root: &Path, prefix: &str) -> Result<PathBuf, AdmissionError> {
    let invalid = prefix.is_empty()
        || prefix.starts_with('/')
        || prefix.contains("..")
        || prefix.split('/').any(|segment| segment.is_empty() || segment.contains('\\') || segment.contains(':'));
    if invalid {
        return Err(AdmissionError::new(
            crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
            format!("object prefix {prefix} is not a safe admission-object prefix"),
        ));
    }
    Ok(root.join(prefix))
}

fn admission_io_error(detail: String) -> AdmissionError {
    AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_OBJECT_WRITE_FAILED, detail)
}

/// 内容寻址对象存储：`<objects>/<prefix>/blobs/<hex>` + `<objects>/<prefix>/completion-marker.json`。
pub struct FileAdmissionObjects {
    root: PathBuf,
}

impl FileAdmissionObjects {
    pub fn open(root: &Path) -> Self {
        Self { root: root.to_path_buf() }
    }
}

impl AdmissionObjectStore for FileAdmissionObjects {
    fn write_blob(&mut self, prefix: &str, digest_hex: &str, bytes: &[u8]) -> Result<(), AdmissionError> {
        // 内容寻址防御：文件名必须等于内容的 sha256（trait 契约；事务层已验）。
        if sha256_hex(bytes) != digest_hex {
            return Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
                format!("blob {digest_hex} does not hash to its content address"),
            ));
        }
        let directory = safe_prefix(&self.root, prefix)?.join("blobs");
        std::fs::create_dir_all(&directory).map_err(|e| admission_io_error(format!("cannot create {}: {e}", directory.display())))?;
        let target = directory.join(digest_hex);
        let temporary = directory.join(format!("{digest_hex}.tmp-{}", crate::monitor::now_millis() % 1_000_000));
        std::fs::write(&temporary, bytes).map_err(|e| admission_io_error(format!("cannot write blob: {e}")))?;
        std::fs::rename(&temporary, &target).map_err(|e| admission_io_error(format!("cannot store blob {digest_hex}: {e}")))
    }

    fn write_completion_marker(&mut self, prefix: &str, marker_bytes: &[u8]) -> Result<(), AdmissionError> {
        let directory = safe_prefix(&self.root, prefix)?;
        std::fs::create_dir_all(&directory).map_err(|e| admission_io_error(format!("cannot create {}: {e}", directory.display())))?;
        let target = directory.join("completion-marker.json");
        let temporary = directory.join(format!("completion-marker.json.tmp-{}", crate::monitor::now_millis() % 1_000_000));
        std::fs::write(&temporary, marker_bytes).map_err(|e| admission_io_error(format!("cannot write completion marker: {e}")))?;
        std::fs::rename(&temporary, &target).map_err(|e| admission_io_error(format!("cannot store completion marker: {e}")))
    }

    fn verify_prefix(&self, prefix: &str) -> Result<(), AdmissionError> {
        let directory = safe_prefix(&self.root, prefix)?;
        if !directory.join("completion-marker.json").is_file() {
            return Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
                "the completion marker is missing from the object prefix",
            ));
        }
        let blobs = directory.join("blobs");
        let mut entries = std::fs::read_dir(&blobs)
            .map_err(|e| admission_io_error(format!("cannot list {}: {e}", blobs.display())))?
            .flatten()
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
                "the object prefix carries no blob",
            ));
        }
        entries.sort();
        for path in entries {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
            if name.contains(".tmp-") {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
                    format!("residual temporary blob {name} in the object prefix"),
                ));
            }
            let bytes = std::fs::read(&path).map_err(|e| admission_io_error(format!("cannot read blob {name}: {e}")))?;
            if sha256_hex(&bytes) != name {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
                    format!("blob {name} does not hash to its file name"),
                ));
            }
        }
        Ok(())
    }

    fn completion_marker_bytes(&self, prefix: &str) -> Option<Vec<u8>> {
        safe_prefix(&self.root, prefix).ok().and_then(|directory| std::fs::read(directory.join("completion-marker.json")).ok())
    }

    fn remove_prefix(&mut self, prefix: &str) -> Result<(), AdmissionError> {
        let directory = safe_prefix(&self.root, prefix)?;
        if directory.exists() {
            std::fs::remove_dir_all(&directory).map_err(|e| admission_io_error(format!("cannot remove {}: {e}", directory.display())))?;
        }
        Ok(())
    }
}

/// VersionKey ↔ 文件 map 键：applicationId 文法不含 ':'，':' 分隔无歧义。
fn key_to_string(key: &(String, String)) -> Result<String, AdmissionError> {
    if key.0.contains(':') || key.1.contains(':') || key.0.is_empty() || key.1.is_empty() {
        return Err(AdmissionError::new(
            crate::wasm_admission::WASM_ADMISSION_DB_WRITE_FAILED,
            "the admission version key is not addressable",
        ));
    }
    Ok(format!("{}:{}", key.0, key.1))
}

fn decode_stored_bytes(encoded: &str, code: &'static str, noun: &str) -> Result<Vec<u8>, AdmissionError> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| AdmissionError::new(code, format!("{noun} bytes are not valid base64: {e}")))
}

/// 控制库行文件：`{schemaVersion:1, rows:{"<app>:<versionId>":"<base64 row JCS>"}}`。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AdmissionDbFile {
    schema_version: u64,
    #[serde(default)]
    rows: BTreeMap<String, String>,
}

pub struct FileAdmissionDb {
    path: PathBuf,
    file: AdmissionDbFile,
}

impl FileAdmissionDb {
    pub fn open(path: &Path) -> Result<Self, AdmissionError> {
        let file = match std::fs::read(path) {
            Ok(bytes) if bytes.is_empty() => AdmissionDbFile { schema_version: 1, rows: BTreeMap::new() },
            Ok(bytes) => {
                let parsed: AdmissionDbFile = serde_json::from_slice(&bytes)
                    .map_err(|e| AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_DB_WRITE_FAILED, format!("the admission db file does not parse: {e}")))?;
                if parsed.schema_version != 1 {
                    return Err(AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_DB_WRITE_FAILED, "the admission db file must be schemaVersion 1"));
                }
                parsed
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AdmissionDbFile { schema_version: 1, rows: BTreeMap::new() },
            Err(e) => {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_DB_WRITE_FAILED,
                    format!("cannot read the admission db file {}: {e}", path.display()),
                ))
            }
        };
        Ok(Self { path: path.to_path_buf(), file })
    }

    fn persist(&self) -> Result<(), AdmissionError> {
        let bytes = jcs_bytes(&self.file)?;
        let temporary = self.path.with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
        std::fs::write(&temporary, &bytes).map_err(|e| admission_io_error(format!("cannot write the admission db file: {e}")))?;
        std::fs::rename(&temporary, &self.path).map_err(|e| admission_io_error(format!("cannot store the admission db file: {e}")))
    }
}

impl AdmissionControlDb for FileAdmissionDb {
    fn insert_hidden_row(&mut self, key: &(String, String), row_bytes: &[u8], proof_jcs: &[u8]) -> Result<(), AdmissionError> {
        let stored = key_to_string(key)?;
        if let Some(encoded) = self.file.rows.get(&stored).cloned() {
            let existing = decode_stored_bytes(&encoded, crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT, "the admission db row")?;
            let parsed: crate::wasm_admission::AdmissionDbRow = serde_json::from_slice(&existing)
                .map_err(|e| AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT, format!("the stored admission db row does not parse: {e}")))?;
            let existing_proof_jcs = crate::wasm_admission::proof_jcs_bytes(&parsed.proof)?;
            if existing_proof_jcs != proof_jcs || existing != row_bytes {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                    "the admission db row already exists with a different proof or bytes",
                ));
            }
            if parsed.visibility != "hidden" && parsed.visibility != "visible" {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                    "the stored admission db row carries an unknown visibility",
                ));
            }
            return Ok(());
        }
        self.file.rows.insert(stored, base64::engine::general_purpose::STANDARD.encode(row_bytes));
        self.persist()
    }

    fn flip_hidden_to_visible(&mut self, key: &(String, String), proof_jcs: &[u8]) -> Result<bool, AdmissionError> {
        let stored = key_to_string(key)?;
        let encoded = self.file.rows.get(&stored).cloned().ok_or_else(|| {
            AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT, "the admission db row is missing during the visibility CAS")
        })?;
        let existing = decode_stored_bytes(&encoded, crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT, "the admission db row")?;
        let mut parsed: crate::wasm_admission::AdmissionDbRow = serde_json::from_slice(&existing)
            .map_err(|e| AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT, format!("the stored admission db row does not parse: {e}")))?;
        let existing_proof_jcs = crate::wasm_admission::proof_jcs_bytes(&parsed.proof)?;
        if existing_proof_jcs != proof_jcs {
            return Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                "the visibility CAS names a different proof",
            ));
        }
        match parsed.visibility.as_str() {
            "visible" => Ok(false),
            "hidden" => {
                parsed.visibility = "visible".into();
                let bytes = jcs_bytes(&parsed)?;
                self.file.rows.insert(stored, base64::engine::general_purpose::STANDARD.encode(&bytes));
                self.persist()?;
                Ok(true)
            }
            _ => Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                "the stored admission db row carries an unknown visibility",
            )),
        }
    }

    fn row_bytes(&self, key: &(String, String)) -> Option<Vec<u8>> {
        let stored = key_to_string(key).ok()?;
        self.file
            .rows
            .get(&stored)
            .and_then(|encoded| decode_stored_bytes(encoded, crate::wasm_admission::WASM_ADMISSION_FAIL_CLOSED, "the admission db row").ok())
    }

    fn remove_row(&mut self, key: &(String, String)) -> Result<(), AdmissionError> {
        let stored = key_to_string(key)?;
        self.file.rows.remove(&stored);
        self.persist()
    }

    fn keys(&self) -> Vec<(String, String)> {
        self.file
            .rows
            .keys()
            .filter_map(|stored| stored.split_once(':').map(|(app, version)| (app.to_string(), version.to_string())))
            .collect()
    }
}

/// materializer receipt 文件：`{schemaVersion:1, receipts:{"<app>:<versionId>":"<base64 receipt JCS>"}}`。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AdmissionReceiptsFile {
    schema_version: u64,
    #[serde(default)]
    receipts: BTreeMap<String, String>,
}

pub struct FileAdmissionMaterializer {
    path: PathBuf,
    file: AdmissionReceiptsFile,
}

impl FileAdmissionMaterializer {
    pub fn open(path: &Path) -> Result<Self, AdmissionError> {
        let file = match std::fs::read(path) {
            Ok(bytes) if bytes.is_empty() => AdmissionReceiptsFile { schema_version: 1, receipts: BTreeMap::new() },
            Ok(bytes) => {
                let parsed: AdmissionReceiptsFile = serde_json::from_slice(&bytes)
                    .map_err(|e| AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_HANDOFF_FAILED, format!("the admission receipt file does not parse: {e}")))?;
                if parsed.schema_version != 1 {
                    return Err(AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_HANDOFF_FAILED, "the admission receipt file must be schemaVersion 1"));
                }
                parsed
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AdmissionReceiptsFile { schema_version: 1, receipts: BTreeMap::new() },
            Err(e) => {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_HANDOFF_FAILED,
                    format!("cannot read the admission receipt file {}: {e}", path.display()),
                ))
            }
        };
        Ok(Self { path: path.to_path_buf(), file })
    }

    fn persist(&self) -> Result<(), AdmissionError> {
        let bytes = jcs_bytes(&self.file)?;
        let temporary = self.path.with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
        std::fs::write(&temporary, &bytes).map_err(|e| admission_io_error(format!("cannot write the admission receipt file: {e}")))?;
        std::fs::rename(&temporary, &self.path).map_err(|e| admission_io_error(format!("cannot store the admission receipt file: {e}")))
    }
}

impl AdmissionMaterializer for FileAdmissionMaterializer {
    fn handoff(&mut self, key: &(String, String), receipt_bytes: &[u8], target: &str) -> Result<(), AdmissionError> {
        // 防御：receipt 必须解析为 typed 记录且 materializationTarget 等于 proof 公式。
        let parsed: crate::wasm_admission::MaterializerReceipt = serde_json::from_slice(receipt_bytes)
            .map_err(|e| AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH, format!("the materializer receipt does not parse: {e}")))?;
        let proof_jcs = crate::wasm_admission::proof_jcs_bytes(&parsed.proof)?;
        if parsed.schema_version != 1 || parsed.materialization_target != crate::wasm_admission::materialization_target(&proof_jcs) || parsed.materialization_target != target {
            return Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH,
                "the materializer receipt does not match the proof-derived materialization target",
            ));
        }
        let stored = key_to_string(key)?;
        if let Some(encoded) = self.file.receipts.get(&stored).cloned() {
            let existing = decode_stored_bytes(&encoded, crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH, "the materializer receipt")?;
            if existing != receipt_bytes {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH,
                    "a different receipt already exists for this version",
                ));
            }
            return Ok(());
        }
        self.file.receipts.insert(stored, base64::engine::general_purpose::STANDARD.encode(receipt_bytes));
        self.persist()
    }

    fn receipt_bytes(&self, key: &(String, String)) -> Option<Vec<u8>> {
        let stored = key_to_string(key).ok()?;
        self.file
            .receipts
            .get(&stored)
            .and_then(|encoded| decode_stored_bytes(encoded, crate::wasm_admission::WASM_ADMISSION_FAIL_CLOSED, "the materializer receipt").ok())
    }

    fn remove_receipt(&mut self, key: &(String, String)) -> Result<(), AdmissionError> {
        self.file.receipts.remove(&key_to_string(key)?);
        self.persist()
    }
}

// ---------------------------------------------------------------------------
// 文件存储适配：activation 控制态（ActivationStateIO）
// ---------------------------------------------------------------------------

pub struct FileActivationStateIO {
    path: PathBuf,
}

impl FileActivationStateIO {
    pub fn open(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }
}

impl ActivationStateIO for FileActivationStateIO {
    fn read_activation_state(&self) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_activation_state(&self, bytes: &[u8]) -> std::io::Result<()> {
        let temporary = self.path.with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
        std::fs::write(&temporary, bytes)?;
        std::fs::rename(&temporary, &self.path)
    }
}

// ---------------------------------------------------------------------------
// wire 记录：执行 fence / readiness lease 台账 / gate 节点 pin / 业务 registry /
// command control（全部 canonical JCS + deny_unknown_fields）
// ---------------------------------------------------------------------------

/// 每版本执行 fence（Kernel 权威判据；执行流通道是唯一写者，本模块只读）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WasmFenceRecordV1 {
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "sandboxId")]
    pub sandbox_id: String,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    #[serde(rename = "executionGeneration")]
    pub execution_generation: u64,
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
    /// 执行是否存活（candidate 死亡 → CAS abort）。
    pub alive: bool,
    /// Kernel 侧 lifecycle 判据（ready/active 才可激活）。
    pub lifecycle: String,
    /// catalog 撤销围栏（revocation 执行面落地前的显式 owner/流围栏位）。
    #[serde(rename = "bindingRevoked")]
    pub binding_revoked: bool,
    /// capability record 供给的精确 drain deadline（epoch 毫秒）；缺省（null）→
    /// 激活替换时不建档 retiring（retired 投影等执行流补 deadline 后驱动）。
    /// 与 configSnapshotRef/configValuesDigest 一致采用显式 null（文件是执行流
    /// 批次的固定契约：14 键恒在，canonical round-trip 无歧义）。
    #[serde(rename = "drainDeadlineEpochMillis")]
    pub drain_deadline_epoch_millis: Option<u64>,
}

/// 每应用 fence 视图：current 指针（CAS 判据）+ 逐版本记录（retiring 判据保留
/// 被替换版本的最后 fence）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WasmApplicationFenceV1 {
    #[serde(rename = "currentVersionId")]
    pub current_version_id: String,
    #[serde(default)]
    pub records: BTreeMap<String, WasmFenceRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct WasmFencesFileV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "runtimeKind")]
    runtime_kind: String,
    applications: BTreeMap<String, WasmApplicationFenceV1>,
}

impl WasmFencesFileV1 {
    #[cfg(test)]
    fn empty() -> Self {
        Self { schema_version: 1, runtime_kind: RUNTIME_KIND_WASM.into(), applications: BTreeMap::new() }
    }
}

/// readiness lease 台账（gateway v2 探针是唯一写者；本模块只读 + 结构校验）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReadinessLeasesFileV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "runtimeKind")]
    runtime_kind: String,
    leases: BTreeMap<String, ReadinessLeaseV2>,
}

impl ReadinessLeasesFileV1 {
    #[cfg(test)]
    fn empty() -> Self {
        Self { schema_version: 1, runtime_kind: RUNTIME_KIND_WASM.into(), leases: BTreeMap::new() }
    }
}

/// gate 节点 pin 投影（owner 安装；catalog/capability 加载器落地前的固定路径权威）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct GateNodeIdentityFileV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "runtimeKind")]
    runtime_kind: String,
    architecture: String,
    #[serde(rename = "capabilityRecordRevision")]
    capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    capability_record_hash: String,
    #[serde(rename = "catalogRevision")]
    catalog_revision: u64,
    #[serde(rename = "catalogHash")]
    catalog_hash: String,
    #[serde(rename = "catalogEntry")]
    catalog_entry: GateNodeIdentityEntryFileV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct GateNodeIdentityEntryFileV1 {
    #[serde(rename = "entryKey")]
    entry_key: String,
    #[serde(rename = "imageDigest")]
    image_digest: String,
    #[serde(rename = "hostABI")]
    host_abi: String,
    world: String,
}

impl TryFrom<GateNodeIdentityFileV1> for WasmGateNodeIdentity {
    type Error = WasmControlFailure;

    fn try_from(value: GateNodeIdentityFileV1) -> Result<Self, Self::Error> {
        let sha256_ok = |text: &str| regex_sha256_hex().is_match(text);
        if value.schema_version != 1 || value.runtime_kind != RUNTIME_KIND_WASM {
            return Err(WasmControlFailure::new(WASM_STATE_UNAVAILABLE, "the gate node identity file must be schemaVersion 1 with runtimeKind wasm"));
        }
        if !crate::wasm_publication::WASM_RUNTIME_ARCHITECTURES.contains(&value.architecture.as_str()) {
            return Err(WasmControlFailure::new(WASM_STATE_UNAVAILABLE, "the gate node identity architecture must be linux/amd64 or linux/arm64"));
        }
        if value.capability_record_revision == 0 || value.capability_record_revision > crate::wasm_admission::WASM_U53_MAX {
            return Err(WasmControlFailure::new(WASM_STATE_UNAVAILABLE, "the gate node identity capabilityRecordRevision must be a u53 >= 1"));
        }
        if value.catalog_revision == 0 || value.catalog_revision > crate::wasm_admission::WASM_U53_MAX {
            return Err(WasmControlFailure::new(WASM_STATE_UNAVAILABLE, "the gate node identity catalogRevision must be a u53 >= 1"));
        }
        if !sha256_ok(&value.capability_record_hash) || !sha256_ok(&value.catalog_hash) {
            return Err(WasmControlFailure::new(WASM_STATE_UNAVAILABLE, "the gate node identity hashes must be 64 lower-case hex characters"));
        }
        let image_hex = value.catalog_entry.image_digest.strip_prefix("sha256:").unwrap_or("");
        if !value.catalog_entry.image_digest.starts_with("sha256:") || !sha256_ok(image_hex) {
            return Err(WasmControlFailure::new(WASM_STATE_UNAVAILABLE, "the gate node identity imageDigest must be sha256: plus 64 lower-case hex characters"));
        }
        Ok(WasmGateNodeIdentity {
            architecture: value.architecture,
            capability_record_revision: value.capability_record_revision,
            capability_record_hash: value.capability_record_hash,
            catalog_revision: value.catalog_revision,
            catalog_hash: value.catalog_hash,
            catalog_entry: WasmGateCatalogEntryPin {
                entry_key: value.catalog_entry.entry_key,
                image_digest: value.catalog_entry.image_digest,
                host_abi: value.catalog_entry.host_abi,
                world: value.catalog_entry.world,
            },
        })
    }
}

/// wasm 业务 registry 持久化（proof 集合 + lifecycle 覆盖表；行由纯函数投影）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmRouteRegistryFileV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    /// 已注册的 AdmissionProofV1（canonical；行形状 project_registry_row 确定）。
    #[serde(default)]
    pub proofs: Vec<AdmissionProofV1>,
    /// versionId → lifecycle 覆盖（admitted/active/retired；本接线唯一写者）。
    #[serde(default)]
    pub lifecycles: BTreeMap<String, String>,
}

impl WasmRouteRegistryFileV1 {
    fn fresh() -> Self {
        Self { schema_version: 1, runtime_kind: RUNTIME_KIND_WASM.into(), proofs: Vec::new(), lifecycles: BTreeMap::new() }
    }
}

/// wasm 命令控制态持久化（controlRevision CAS + outbox + retirements）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmCommandControlFileV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "runtimeKind")]
    runtime_kind: String,
    #[serde(rename = "controlRevision")]
    control_revision: u64,
    #[serde(default)]
    command_outbox: Vec<crate::wasm_commands::CommandOutboxRecord>,
    #[serde(default)]
    retirements: Vec<RetiringExecutionRecord>,
}

impl WasmCommandControlFileV1 {
    fn fresh() -> Self {
        Self { schema_version: 1, runtime_kind: RUNTIME_KIND_WASM.into(), control_revision: 0, command_outbox: Vec::new(), retirements: Vec::new() }
    }

    fn to_state(&self) -> WasmCommandControlState {
        WasmCommandControlState {
            control_revision: self.control_revision,
            command_outbox: self.command_outbox.clone(),
            retirements: self.retirements.clone(),
        }
    }

    fn from_state(state: &WasmCommandControlState) -> Self {
        Self {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: state.control_revision,
            command_outbox: state.command_outbox.clone(),
            retirements: state.retirements.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// 运行时主体：启动序 + 控制面端点
// ---------------------------------------------------------------------------

/// 启动序产物：双 gate 集（不可变）+ bootstrap 状态 + 失败围栏。
pub struct WasmRuntime {
    paths: WasmRuntimePaths,
    gates: PublicationGateSetV1,
    /// 最近一次成功验证的 bootstrap 记录（None = wasm 写路径保持关闭）。
    bootstrap_verified: Option<KindClaimBootstrapV1>,
    /// bootstrap 失败记录（owner 可见 code + detail；不含秘密）。
    bootstrap_failure: Option<WasmControlFailure>,
    /// 状态不可用围栏（目录/文件损坏 → wasm 路径 503，celld 不受影响）。
    state_failure: Option<WasmControlFailure>,
}

impl WasmRuntime {
    /// 启动序（spec「The v2 gate is connected at startup in this order」+
    /// application-sandbox bootstrap 启动门）：
    /// (1) 评估 celld v1 gate（保留现行语义）；(2) 独立读取并校验固定 wasm 验收记录，
    /// 与 celld 并行评估出不可变 PublicationGateSetV1；(3) 创建状态根；
    /// (4) celld kind-claim bootstrap 验证/引导（wasm 写路径在完成前保持关闭）；
    /// (5) 重放已持久化 proof（幂等注册 + 恢复一致性扫描）；(6) activation 恢复；
    /// (7) admission journal 恢复驱动。
    pub fn startup(
        paths: WasmRuntimePaths,
        read_bytes: &dyn Fn(&str) -> std::io::Result<Vec<u8>>,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        // 节点 pin：Kernel 拥有的固定路径投影；缺失/损坏 → None（gate fail-closed）。
        let node_pin = std::fs::read(paths.gate_node_identity())
            .ok()
            .and_then(|bytes| parse_canonical::<GateNodeIdentityFileV1>(&bytes, WASM_STATE_UNAVAILABLE, "gate node identity").ok())
            .and_then(|file| WasmGateNodeIdentity::try_from(file).ok());
        let switches = GateEnvironmentView::from_lookup(env_lookup);
        let gates = evaluate_publication_gate_set_v1(read_bytes, &switches, node_pin.as_ref());
        let mut runtime = Self { paths, gates, bootstrap_verified: None, bootstrap_failure: None, state_failure: None };
        // 状态根创建失败 → 围栏（不终止进程：celld 控制面必须继续服务）。
        if let Err(failure) = std::fs::create_dir_all(&runtime.paths.root) {
            runtime.state_failure = Some(WasmControlFailure::new(
                WASM_STATE_UNAVAILABLE,
                format!("cannot create the wasm state root {}: {failure}", runtime.paths.root.display()),
            ));
            return runtime;
        }
        // bootstrap + 幂等重放 + 恢复扫描（任一失败 → 记录围栏，wasm 写路径保持关闭）。
        if let Err(failure) = runtime.run_bootstrap_and_recover() {
            runtime.bootstrap_failure = Some(failure);
        }
        // activation 恢复：不确定提交按 repair_uncertain_activation 裁决。
        if runtime.state_failure.is_none() {
            let io = FileActivationStateIO::open(&runtime.paths.activation_state());
            if let Err(failure) = WasmActivationStore::new(Box::new(io)).recover() {
                runtime.state_failure = Some(WasmControlFailure::new(failure.code, failure.detail));
            }
        }
        // admission 恢复：journal 非终态行推进 + visible 行 witness 一致性扫描。
        if runtime.state_failure.is_none() {
            if let Err(failure) = run_admission_recovery(&runtime.paths, now_millis_u64()) {
                runtime.state_failure = Some(failure);
            }
        }
        runtime
    }

    /// 双 gate 集（不可变引用；status 投影与端点选择共用）。
    pub fn gates(&self) -> &PublicationGateSetV1 {
        &self.gates
    }

    /// wasm gate 的选择响应（/v1/status.wasmPublication 投影同一形状）。
    /// select_publication_gate 对 "wasm" 恒成功；Err 分支仅类型完备（保持关闭）。
    pub fn wasm_gate_selection(&self) -> GateSelectionResponseV1 {
        select_publication_gate(RUNTIME_KIND_WASM, &self.gates).unwrap_or(GateSelectionResponseV1 {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            enabled: false,
            reasons: Vec::new(),
        })
    }

    /// 读 celld 控制态原始字节（缺失 → 空字节；引导按空状态，文件出现后强制重推导）。
    fn celld_raw(&self) -> Vec<u8> {
        std::fs::read(&self.paths.celld_control_db).unwrap_or_default()
    }

    /// bootstrap + 已持久化 proof 幂等重放 + 恢复一致性扫描（启动与 digest 变化重推导共用）。
    fn run_bootstrap_and_recover(&mut self) -> Result<(), WasmControlFailure> {
        let mut store = KindRegistryStoreDir::open(&self.paths.kind_registry()).map_err(map_kind_error)?;
        let mut registry = WasmKernelRouteRegistryV1::load(&store).map_err(map_kind_error)?;
        let raw = self.celld_raw();
        if raw.is_empty() {
            registry.bootstrap_from_celld(&mut store, &[], &[]).map_err(map_kind_error)?;
        } else {
            registry.bootstrap_from_celld_raw(&mut store, &raw).map_err(map_kind_error)?;
        }
        // 幂等重放已持久化 proof（claim 已存在时零写入），再跑恢复一致性扫描
        //（孤儿 claim/row quarantine；split-brain fail-closed）。
        let registry_file = self.load_route_registry()?;
        for proof in &registry_file.proofs {
            registry
                .register_wasm_admission(&mut store, registry.registry_revision(), proof)
                .map_err(map_kind_error)?;
        }
        let celld_ids = celld_ids_from_raw(&raw);
        registry.recover(&mut store, &celld_ids, &[]).map_err(map_kind_error)?;
        self.bootstrap_verified = registry.bootstrap_record().cloned();
        self.bootstrap_failure = None;
        Ok(())
    }

    /// 每次 wasm 写前验证 bootstrap 对当前 celld 控制态仍然有效：digest 变化 → 重推导。
    fn ensure_bootstrap_current(&mut self) -> Result<(), WasmControlFailure> {
        if let Some(failure) = &self.state_failure {
            return Err(failure.clone());
        }
        let digest = sha256_hex(&self.celld_raw());
        if self.bootstrap_verified.as_ref().is_some_and(|record| record.control_state_raw_digest == digest) {
            return Ok(());
        }
        self.run_bootstrap_and_recover()
    }

    fn load_route_registry(&self) -> Result<WasmRouteRegistryFileV1, WasmControlFailure> {
        match std::fs::read(self.paths.route_registry()) {
            Ok(bytes) if bytes.is_empty() => Ok(WasmRouteRegistryFileV1::fresh()),
            Ok(bytes) => {
                let parsed = parse_canonical::<WasmRouteRegistryFileV1>(&bytes, WASM_RUNTIME_IO, "wasm route registry")?;
                if parsed.schema_version != 1 || parsed.runtime_kind != RUNTIME_KIND_WASM {
                    return Err(WasmControlFailure::new(WASM_RUNTIME_IO, "the wasm route registry must be schemaVersion 1 with runtimeKind wasm"));
                }
                for proof in &parsed.proofs {
                    verify_admission_proof(proof)
                        .map_err(|e| WasmControlFailure::new(e.code, format!("a persisted admission proof is invalid: {}", e.detail)))?;
                }
                Ok(parsed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(WasmRouteRegistryFileV1::fresh()),
            Err(e) => Err(WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!("cannot read the wasm route registry {}: {e}", self.paths.route_registry().display()),
            )),
        }
    }

    fn save_route_registry(&self, file: &WasmRouteRegistryFileV1) -> Result<(), WasmControlFailure> {
        write_canonical(&self.paths.route_registry(), file)
    }

    fn load_command_control(&self) -> Result<WasmCommandControlFileV1, WasmControlFailure> {
        match std::fs::read(self.paths.command_control()) {
            Ok(bytes) if bytes.is_empty() => Ok(WasmCommandControlFileV1::fresh()),
            Ok(bytes) => {
                let parsed = parse_canonical::<WasmCommandControlFileV1>(&bytes, WASM_RUNTIME_IO, "wasm command control state")?;
                if parsed.schema_version != 1 || parsed.runtime_kind != RUNTIME_KIND_WASM {
                    return Err(WasmControlFailure::new(WASM_RUNTIME_IO, "the wasm command control state must be schemaVersion 1 with runtimeKind wasm"));
                }
                Ok(parsed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(WasmCommandControlFileV1::fresh()),
            Err(e) => Err(WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!("cannot read the wasm command control state {}: {e}", self.paths.command_control().display()),
            )),
        }
    }

    fn load_fences(&self) -> BTreeMap<String, WasmApplicationFenceV1> {
        // fence 台账损坏 → 视为无 fence（激活判据 fail-closed），不阻断其它路径。
        std::fs::read(self.paths.fences())
            .ok()
            .and_then(|bytes| parse_canonical::<WasmFencesFileV1>(&bytes, WASM_RUNTIME_IO, "wasm fences").ok())
            .map(|file| file.applications)
            .unwrap_or_default()
    }

    fn load_leases(&self) -> BTreeMap<String, ReadinessLeaseV2> {
        std::fs::read(self.paths.readiness_leases())
            .ok()
            .and_then(|bytes| parse_canonical::<ReadinessLeasesFileV1>(&bytes, WASM_RUNTIME_IO, "readiness leases").ok())
            .map(|file| file.leases)
            .unwrap_or_default()
    }

    /// 激活控制态（typed 全量；facts 与 lifecycle 同步共用）。
    fn load_activation_states(&self) -> BTreeMap<String, KernelActivationState> {
        std::fs::read(self.paths.activation_state())
            .ok()
            .and_then(|bytes| parse_canonical::<crate::wasm_activation::WasmActivationStateFileV1>(&bytes, WASM_RUNTIME_IO, "activation state").ok())
            .map(|file| file.applications)
            .unwrap_or_default()
    }

    /// 结构化 gate 前置：选择 wasm gate 并要求 enabled（spec 启动序第 4 步）。
    fn require_wasm_gate_enabled(&self) -> Result<(), WasmHttpResponse> {
        let selection = self.wasm_gate_selection();
        if let Err(failure) = require_wasm_publication(&self.gates.wasm) {
            return Err(err_json(
                503,
                WASM_PUBLICATION_DISABLED,
                &format!("{}; reasons: {:?}", failure.detail, selection.reasons),
            ));
        }
        Ok(())
    }

    /// POST /v1/wasm/admission：owner 授权的 wasm 准入提交。
    /// 事务序：发布门 → bootstrap 门 → kind-claim 冲突预检 → wasm_admission 事务
    /// （create-or-join → … → visible）→ wasm kind registry 注册（claim + 行投影）。
    pub fn handle_admission_submit(
        &mut self,
        authorized: bool,
        content_type: Option<&str>,
        body: &[u8],
        now_epoch_millis: u64,
    ) -> WasmHttpResponse {
        if !authorized {
            return err_json(401, WASM_UNAUTHORIZED, "wasm admission requires the owner bearer credential");
        }
        if let Some(failure) = &self.state_failure {
            return err_json(503, failure.code, &failure.detail);
        }
        if body.len() > ADMISSION_SUBMIT_MAX_BYTES {
            return err_json(413, "BODY_TOO_LARGE", "wasm admission request is too large");
        }
        let json_type = content_type.is_some_and(|value| value.split(';').next().is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json")));
        if !json_type {
            return err_json(415, "UNSUPPORTED_CONTENT_TYPE", "wasm admission expects application/json");
        }
        if let Err(response) = self.require_wasm_gate_enabled() {
            return response;
        }
        // bootstrap 门：对当前 celld 控制态验证/重推导（digest 变化即重引导）。
        if let Err(failure) = self.ensure_bootstrap_current() {
            return err_json(
                503,
                WASM_KIND_BOOTSTRAP_PENDING,
                &format!("the wasm write path stays closed: [{}] {}", failure.code, failure.detail),
            );
        }
        let request = match parse_admission_submit(body) {
            Ok(request) => request,
            Err(failure) => return err_json(400, failure.code, &failure.detail),
        };
        // kind-claim 预检 + 注册实例（bootstrap 在该实例内验证后才可 claim/register）。
        let mut kind_store = match KindRegistryStoreDir::open(&self.paths.kind_registry()) {
            Ok(store) => store,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        let mut registry = match WasmKernelRouteRegistryV1::load(&kind_store) {
            Ok(registry) => registry,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        let raw = self.celld_raw();
        let bootstrap_result = if raw.is_empty() {
            registry.bootstrap_from_celld(&mut kind_store, &[], &[])
        } else {
            registry.bootstrap_from_celld_raw(&mut kind_store, &raw)
        };
        if let Err(failure) = bootstrap_result {
            return err_json(
                503,
                WASM_KIND_BOOTSTRAP_PENDING,
                &format!("the wasm write path stays closed: [{}] {}", failure.code, failure.detail),
            );
        }
        if let Some(claim) = registry.claim(&request.application_id) {
            if claim.runtime_kind != RUNTIME_KIND_WASM {
                return err_json(
                    409,
                    APPLICATION_RUNTIME_KIND_CONFLICT,
                    &format!(
                        "applicationId {} is permanently {}-bound; changing runtime kind requires a new applicationId",
                        request.application_id, claim.runtime_kind
                    ),
                );
            }
        }
        // 准入事务（文件 witness 三件套 + journal）。
        let outcome = {
            let mut journal = match WasmAdmissionJournalFile::open(&self.paths.admission_journal()) {
                Ok(journal) => journal,
                Err(failure) => return err_json(503, failure.code, &failure.detail),
            };
            let mut objects = FileAdmissionObjects::open(&self.paths.admission_objects());
            let mut db = match FileAdmissionDb::open(&self.paths.admission_db()) {
                Ok(db) => db,
                Err(failure) => return err_json(503, failure.code, &failure.detail),
            };
            let mut materializer = match FileAdmissionMaterializer::open(&self.paths.admission_receipts()) {
                Ok(materializer) => materializer,
                Err(failure) => return err_json(503, failure.code, &failure.detail),
            };
            let mut token = OsRandomTokenSource;
            let mut stores = AdmissionStores { journal: &mut journal, objects: &mut objects, db: &mut db, materializer: &mut materializer };
            match commit_wasm_admission(&mut stores, &request, &mut token, now_epoch_millis) {
                Ok(outcome) => outcome,
                Err(failure) => return admission_failure_http(&failure),
            }
        };
        // kind registry 注册（claim CAS + 行投影；同 kind 幂等）。
        if let Err(failure) = registry.register_wasm_admission(&mut kind_store, registry.registry_revision(), &outcome.proof) {
            return err_json(
                if failure.code == APPLICATION_RUNTIME_KIND_CONFLICT { 409 } else { 503 },
                failure.code,
                &failure.detail,
            );
        }
        self.bootstrap_verified = registry.bootstrap_record().cloned();
        // 持久化业务记录（proof 集合 + lifecycle 覆盖）。
        let mut registry_file = match self.load_route_registry() {
            Ok(file) => file,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        if outcome.created && !registry_file.proofs.iter().any(|proof| proof.version_id == outcome.proof.version_id) {
            registry_file.proofs.push(outcome.proof.clone());
            registry_file.lifecycles.entry(outcome.proof.version_id.clone()).or_insert_with(|| "admitted".into());
            if let Err(failure) = self.save_route_registry(&registry_file) {
                return err_json(503, failure.code, &failure.detail);
            }
        }
        ok_json(
            201,
            json!({
                "schemaVersion": 1,
                "applicationId": outcome.proof.application_id,
                "versionId": outcome.proof.version_id,
                "identity": {
                    "applicationId": outcome.proof.application_id,
                    "digest": outcome.proof.version_digest,
                    "sequence": outcome.proof.sequence,
                },
                "state": admission_state_label(outcome.state),
                "created": outcome.created,
            }),
        )
    }

    /// POST /v1/wasm/activation-rpc：owner Bearer + JCS envelope（wasm_activation
    /// 的完整六步 framing）；CAS 判据接线 Kernel 权威文件（fence/lease/registry）。
    pub fn handle_activation_rpc(
        &mut self,
        authorization: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
        verify_bearer: &dyn Fn(Option<&str>) -> bool,
    ) -> WasmHttpResponse {
        if let Some(failure) = &self.state_failure {
            return err_json(503, failure.code, &failure.detail);
        }
        // 发布门同样围栏 activation（路由翻转是发布面的一部分；未启用即 503）。
        if let Err(response) = self.require_wasm_gate_enabled() {
            return response;
        }
        let fences = self.load_fences();
        let leases = self.load_leases();
        let registry_file = self.load_route_registry().unwrap_or_else(|_| WasmRouteRegistryFileV1::fresh());
        let activation_states = self.load_activation_states();
        let now_epoch_millis = now_millis_u64();
        let mut store = WasmActivationStore::new(Box::new(FileActivationStateIO::open(&self.paths.activation_state())));
        let deps = ActivationDeps {
            now_epoch_millis: &|| now_epoch_millis,
            verify_bearer,
            lease_lookup: &|nonce: &str| leases.get(nonce).filter(|lease| lease.validate().is_ok()).cloned(),
            facts: &|application_id: &str| {
                activation_facts(&fences, &registry_file, &activation_states, application_id, now_epoch_millis)
            },
            event_id: &|| generate_uuid_v7(now_epoch_millis),
        };
        let request = ActivationHttpRequest { method: "POST", path: ACTIVATION_RPC_PATH, authorization, content_type, body };
        let options = ActivationHttpOptions { max_request_bytes: ACTIVATION_RPC_DEFAULT_MAX_BYTES };
        let response = handle_activation_rpc_http(&mut store, &deps, request, options);
        let outcome = WasmHttpResponse { status: response.status, body: response.body };
        // 激活成功后同步业务 lifecycle 投影（active 覆盖 + retiring 建档）；同步失败
        // 有界上报（route CAS 已提交，投影可由下次激活/恢复收敛）。
        if outcome.status == 200 {
            if let Err(failure) = self.sync_lifecycle_after_activation(now_epoch_millis) {
                return err_json(503, failure.code, &format!("the route CAS committed but the lifecycle projection failed: {}", failure.detail));
            }
        }
        outcome
    }

    /// GET /v1/wasm/status：bootstrap 状态 + 双 gate 选择 + 业务 registry 投影。
    pub fn status_projection(&self) -> serde_json::Value {
        let bootstrap = match (&self.bootstrap_verified, &self.bootstrap_failure, &self.state_failure) {
            (Some(record), _, _) => json!({
                "state": "verified",
                "bootstrapRevision": record.bootstrap_revision,
                "controlStateRawDigest": record.control_state_raw_digest,
                "sourceRevision": record.source_revision,
                "claims": record.sorted_claims.len(),
            }),
            (None, Some(failure), _) => json!({ "state": "pending", "code": failure.code, "detail": failure.detail }),
            (None, None, Some(failure)) => json!({ "state": "unavailable", "code": failure.code, "detail": failure.detail }),
            (None, None, None) => json!({ "state": "pending", "code": WASM_KIND_BOOTSTRAP_PENDING, "detail": "no kind-claim bootstrap record verifies against the current celld control state" }),
        };
        let wasm_selection = serde_json::to_value(self.wasm_gate_selection()).unwrap_or(serde_json::Value::Null);
        let celld_selection = match select_publication_gate(RUNTIME_KIND_CELLD, &self.gates) {
            Ok(selection) => serde_json::to_value(selection).unwrap_or(serde_json::Value::Null),
            Err(failure) => json!({ "schemaVersion": 1, "runtimeKind": RUNTIME_KIND_CELLD, "enabled": false, "reasons": [failure.code] }),
        };
        let registry_file = self.load_route_registry().unwrap_or_else(|_| WasmRouteRegistryFileV1::fresh());
        let activation_states = self.load_activation_states();
        let mut applications: Vec<serde_json::Value> = Vec::new();
        for proof in &registry_file.proofs {
            let Some(state) = activation_states.get(&proof.application_id) else { continue };
            let versions: Vec<serde_json::Value> = registry_file
                .proofs
                .iter()
                .filter(|candidate| candidate.application_id == proof.application_id)
                .map(|candidate| {
                    let lifecycle = registry_file
                        .lifecycles
                        .get(&candidate.version_id)
                        .cloned()
                        .unwrap_or_else(|| "admitted".into());
                    json!({
                        "versionId": candidate.version_id,
                        "identity": {
                            "applicationId": candidate.application_id,
                            "digest": candidate.version_digest,
                            "sequence": candidate.sequence,
                        },
                        "lifecycle": lifecycle,
                    })
                })
                .collect();
            let active = match &state.active {
                WasmActivePointerV1::Active { version_id, route_generation, .. } => {
                    json!({ "versionId": version_id, "routeGeneration": route_generation })
                }
                WasmActivePointerV1::Unavailable { .. } => serde_json::Value::Null,
            };
            applications.push(json!({
                "applicationId": proof.application_id,
                "runtimeKind": RUNTIME_KIND_WASM,
                "versions": versions,
                "active": active,
                "routeGeneration": state.route_generation,
            }));
        }
        json!({
            "schemaVersion": 1,
            "runtimeKind": RUNTIME_KIND_WASM,
            "bootstrap": bootstrap,
            "publicationGate": wasm_selection,
            "celldPublicationGate": celld_selection,
            "applications": applications,
        })
    }

    /// proof 集 → 确定性行投影（按 applicationId 分组 + lifecycle 覆盖）。
    pub fn project_registry_rows(&self) -> BTreeMap<String, Vec<WasmVersionRegistryRow>> {
        let file = self.load_route_registry().unwrap_or_else(|_| WasmRouteRegistryFileV1::fresh());
        let mut grouped: BTreeMap<String, Vec<WasmVersionRegistryRow>> = BTreeMap::new();
        for proof in &file.proofs {
            if let Ok(mut row) = project_registry_row(proof) {
                if let Some(lifecycle) = file.lifecycles.get(&row.version_id) {
                    row.lifecycle = lifecycle.clone();
                }
                grouped.entry(proof.application_id.clone()).or_default().push(row);
            }
        }
        grouped
    }

    /// 激活成功后的 lifecycle 同步：新 active 版本 → "active"；被替换版本在
    /// fence 携带精确 drain deadline 时建档 retiring（drain 命令 + 判据），
    /// retired 仍只由 project_drain_receipt 写入（spec 退休门）。
    fn sync_lifecycle_after_activation(&mut self, now_epoch_millis: u64) -> Result<(), WasmControlFailure> {
        let mut registry_file = self.load_route_registry()?;
        let fences = self.load_fences();
        let activation_states = self.load_activation_states();
        let mut command_file = self.load_command_control()?;
        let mut command_state = command_file.to_state();
        let mut command_dirty = false;
        let application_ids: Vec<String> = registry_file.proofs.iter().map(|proof| proof.application_id.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        for application_id in &application_ids {
            let Some(state) = activation_states.get(application_id) else { continue };
            let WasmActivePointerV1::Active { version_id, .. } = &state.active else { continue };
            let Some(proof) = registry_file.proofs.iter().find(|proof| &proof.version_id == version_id) else { continue };
            registry_file.lifecycles.insert(version_id.clone(), "active".into());
            // 最后一次成功事件的 previous 指针 → 被替换版本（retiring 建档对象）；
            // 其 fence 记录按 versionId 保留（current 指针此时已指向新候选）。
            let Some(last_event) = state.events.iter().rev().find(|event| event.result == crate::wasm_activation::RouteEventResult::Activated) else { continue };
            let WasmActivePointerV1::Active { version_id: previous_version_id, route_generation: previous_generation, .. } = &last_event.previous else { continue };
            let Some(previous_fence) = fences
                .get(application_id)
                .and_then(|application| application.records.get(previous_version_id))
            else { continue };
            let Some(deadline) = previous_fence.drain_deadline_epoch_millis else {
                // 无精确 deadline → 不建档（capability record 缺席时绝不发明默认值）。
                continue;
            };
            if command_state.retirements.iter().any(|record| record.execution.version_id == *previous_version_id) {
                continue;
            }
            let identity = WasmExecutionIdentityV1 {
                sandbox_id: previous_fence.sandbox_id.clone(),
                version_id: previous_version_id.clone(),
                preparation_generation: previous_fence.preparation_generation,
                execution_generation: previous_fence.execution_generation,
            };
            let command = ExecutionCommandV1 {
                schema_version: 1,
                command_id: generate_uuid_v7(now_epoch_millis),
                expected_kernel_control_revision: command_state.control_revision,
                expected_journal_revision: 0,
                operation: WasmExecutionOperation::Drain,
                identity: identity.clone(),
                package_digest: proof.package_digest.clone(),
                runtime_binding: proof.runtime_binding.clone(),
                capability_record_revision: proof.capability_record_revision,
                capability_record_hash: proof.capability_record_hash.clone(),
                secret_revision: previous_fence.secret_revision,
                secret_snapshot_ref: previous_fence.secret_snapshot_ref.clone(),
                secret_values_digest: previous_fence.secret_values_digest.clone(),
                config_revision: previous_fence.config_revision,
                config_snapshot_ref: previous_fence.config_snapshot_ref.clone(),
                config_values_digest: previous_fence.config_values_digest.clone(),
            };
            let created_at = crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis);
            let drain_command_id = command.command_id.clone();
            command_state
                .authorize_command(command_state.control_revision, command, created_at)
                .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
            command_state
                .authorize_retirement(
                    command_state.control_revision,
                    RetiringExecutionRecord {
                        drain_command_id,
                        application_id: application_id.clone(),
                        execution: identity,
                        package_digest: proof.package_digest.clone(),
                        runtime_binding: proof.runtime_binding.clone(),
                        route_generation: *previous_generation,
                        deadline_at_epoch_millis: deadline,
                        flip_at_epoch_millis: now_epoch_millis,
                        retired: false,
                        accepted_receipt_digest: None,
                    },
                )
                .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
            command_dirty = true;
        }
        if command_dirty {
            command_file = WasmCommandControlFileV1::from_state(&command_state);
            write_canonical(&self.paths.command_control(), &command_file)?;
        }
        self.save_route_registry(&registry_file)
    }

    /// drain receipt 投影（retired 的唯一入口；执行流通道/测试驱动）：CAS 成功后
    /// 才把被替换版本的 lifecycle 写为 "retired"。
    pub fn project_drain_receipt(&mut self, receipt: &DrainReceiptV1) -> Result<DrainRetirementProjection, WasmControlFailure> {
        let mut command_file = self.load_command_control()?;
        let mut command_state = command_file.to_state();
        let expected = command_state.control_revision;
        let projection = command_state
            .project_drain_receipt(expected, receipt)
            .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
        if let DrainRetirementProjection::Retired { .. } = projection {
            let mut registry_file = self.load_route_registry()?;
            registry_file.lifecycles.insert(receipt.execution.version_id.clone(), "retired".into());
            self.save_route_registry(&registry_file)?;
        }
        command_file = WasmCommandControlFileV1::from_state(&command_state);
        write_canonical(&self.paths.command_control(), &command_file)?;
        Ok(projection)
    }

    /// 已建档的 retiring 判据（执行流取 drain 命令寻址；测试/状态投影用）。
    pub fn retiring_records(&self) -> Vec<RetiringExecutionRecord> {
        self.load_command_control().map(|file| file.to_state().retirements).unwrap_or_default()
    }

    /// AdmittedVisible 谓词直通（owner 诊断/测试：三段 witness 一致性）。
    pub fn admitted_visible(&self, application_id: &str, version_id: &str) -> Result<Option<AdmissionProofV1>, WasmControlFailure> {
        let objects = FileAdmissionObjects::open(&self.paths.admission_objects());
        let db = FileAdmissionDb::open(&self.paths.admission_db()).map_err(map_admission_error)?;
        let materializer = FileAdmissionMaterializer::open(&self.paths.admission_receipts()).map_err(map_admission_error)?;
        admitted_visible(&objects, &db, &materializer, application_id, version_id).map_err(map_admission_error)
    }
}

fn map_kind_error(error: crate::wasm_kind_registry::KindRegistryError) -> WasmControlFailure {
    WasmControlFailure::new(error.code, error.detail)
}

/// admission journal 恢复驱动（启动序第 7 步；文件 witness 全套接线）。
fn run_admission_recovery(paths: &WasmRuntimePaths, now_epoch_millis: u64) -> Result<(), WasmControlFailure> {
    let mut journal = WasmAdmissionJournalFile::open(&paths.admission_journal()).map_err(map_admission_error)?;
    let mut objects = FileAdmissionObjects::open(&paths.admission_objects());
    let mut db = FileAdmissionDb::open(&paths.admission_db()).map_err(map_admission_error)?;
    let mut materializer = FileAdmissionMaterializer::open(&paths.admission_receipts()).map_err(map_admission_error)?;
    let mut stores = AdmissionStores { journal: &mut journal, objects: &mut objects, db: &mut db, materializer: &mut materializer };
    recover_wasm_admission(&mut stores, now_epoch_millis).map_err(map_admission_error)?;
    Ok(())
}

fn celld_ids_from_raw(raw: &[u8]) -> Vec<String> {
    if raw.is_empty() {
        return Vec::new();
    }
    serde_json::from_slice::<crate::control::ControlStateFile>(raw)
        .ok()
        .map(|state| crate::wasm_kind_registry::celld_application_ids(&state))
        .unwrap_or_default()
}

fn now_millis_u64() -> u64 {
    u64::try_from(crate::monitor::now_millis()).unwrap_or(u64::MAX)
}

/// 激活 CAS 判据（Kernel 权威）：当前 fence（准备/秘密代次、存活、lifecycle）+
/// proof（binding/capability 钉）+ activation 控制态（rollback 保留）。
/// RegistryRowFacts 的 capability 钉来自 AdmissionProofV1（业务行不重复携带）。
fn activation_facts(
    fences: &BTreeMap<String, WasmApplicationFenceV1>,
    registry_file: &WasmRouteRegistryFileV1,
    activation_states: &BTreeMap<String, KernelActivationState>,
    application_id: &str,
    now_epoch_millis: u64,
) -> OwnedActivationCasFacts {
    // 当前候选 fence = 应用的 current 指针指向的版本记录。
    let fence = fences
        .get(application_id)
        .and_then(|application| application.records.get(&application.current_version_id));
    let registry_row = fence.and_then(|fence| {
        registry_file
            .proofs
            .iter()
            .find(|proof| proof.application_id == application_id && proof.version_id == fence.version_id)
            .filter(|_| matches!(fence.lifecycle.as_str(), "ready" | "active"))
            .map(|proof| RegistryRowFacts {
                runtime_binding: proof.runtime_binding.clone(),
                capability_record_revision: proof.capability_record_revision,
                capability_record_hash: proof.capability_record_hash.clone(),
                lifecycle_ready: true,
            })
    });
    OwnedActivationCasFacts {
        now_epoch_millis,
        current_secret_store_revision: fence.map(|fence| fence.secret_revision).unwrap_or(0),
        current_preparation_generation: fence.map(|fence| fence.preparation_generation).unwrap_or(0),
        candidate_alive: fence.is_some_and(|fence| fence.alive),
        registry_row,
        binding_revoked: fence.is_some_and(|fence| fence.binding_revoked),
        rollback_retention: activation_states
            .get(application_id)
            .and_then(|state| state.rollback_retentions.first().cloned()),
    }
}

// ---------------------------------------------------------------------------
// admission 提交 wire（owner 通道；严格键集 + base64 blob）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionBlobWireV1 {
    #[serde(rename = "digestHex")]
    digest_hex: String,
    base64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSubmitWireV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "applicationId")]
    application_id: String,
    #[serde(rename = "packageDigest")]
    package_digest: String,
    #[serde(rename = "normalizedPolicy")]
    normalized_policy: NormalizedWasmManifestV1,
    #[serde(rename = "runtimeBinding")]
    runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "capabilityRecordRevision")]
    capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    capability_record_hash: String,
    #[serde(rename = "stagingTtlSeconds")]
    staging_ttl_seconds: u64,
    blobs: Vec<AdmissionBlobWireV1>,
    #[serde(rename = "allowResequence", default)]
    allow_resequence: bool,
}

/// 严格解析 admission 提交：schemaVersion 恰 1、blob 非空、digest 去重、base64 可解码。
fn parse_admission_submit(body: &[u8]) -> Result<AdmissionRequest, WasmControlFailure> {
    let invalid = |detail: String| WasmControlFailure::new(WASM_ADMISSION_WIRE_INVALID, detail);
    let wire: AdmissionSubmitWireV1 = serde_json::from_slice(body)
        .map_err(|e| invalid(format!("the admission submit body does not parse: {e}")))?;
    if wire.schema_version != 1 {
        return Err(invalid("schemaVersion must be exactly 1".into()));
    }
    if wire.blobs.is_empty() {
        return Err(invalid("a wasm admission must carry at least one blob".into()));
    }
    let mut seen = BTreeSet::new();
    let mut blobs = Vec::with_capacity(wire.blobs.len());
    for blob in &wire.blobs {
        if !seen.insert(blob.digest_hex.clone()) {
            return Err(invalid(format!("duplicate blob digest {} in the admission submit", blob.digest_hex)));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&blob.base64)
            .map_err(|e| invalid(format!("blob {} is not valid base64: {e}", blob.digest_hex)))?;
        blobs.push((blob.digest_hex.clone(), bytes));
    }
    Ok(AdmissionRequest {
        application_id: wire.application_id,
        package_digest: wire.package_digest,
        normalized_policy: wire.normalized_policy,
        runtime_binding: wire.runtime_binding,
        capability_record_revision: wire.capability_record_revision,
        capability_record_hash: wire.capability_record_hash,
        staging_ttl_seconds: wire.staging_ttl_seconds,
        blobs,
        allow_resequence: wire.allow_resequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_and_lease_file_shapes_are_canonical() {
        // wire 形状哨兵：空文件序列化为 canonical JCS 且 deny_unknown_fields 生效。
        let fences = WasmFencesFileV1::empty();
        let bytes = jcs_bytes(&fences).expect("jcs");
        assert_eq!(String::from_utf8(bytes.clone()).expect("utf8"), r#"{"applications":{},"runtimeKind":"wasm","schemaVersion":1}"#);
        assert!(parse_canonical::<WasmFencesFileV1>(&bytes, WASM_RUNTIME_IO, "wasm fences").is_ok());
        let leases = ReadinessLeasesFileV1::empty();
        let bytes = jcs_bytes(&leases).expect("jcs");
        assert_eq!(String::from_utf8(bytes.clone()).expect("utf8"), r#"{"leases":{},"runtimeKind":"wasm","schemaVersion":1}"#);
        let with_unknown = bytes.clone();
        let mut corrupted = String::from_utf8(with_unknown.clone()).expect("utf8");
        corrupted.pop();
        corrupted.push_str(r#","surplus":true}"#);
        assert!(parse_canonical::<WasmFencesFileV1>(corrupted.as_bytes(), WASM_RUNTIME_IO, "wasm fences").is_err());
    }

    #[test]
    fn admission_submit_wire_rejects_unknown_and_duplicate_blobs() {
        assert!(parse_admission_submit(b"{ not json").is_err());
        assert!(parse_admission_submit(br#"{"schemaVersion":2}"#).is_err());
        // 正常最小形状（manifest/binding 交由上层校验；此处只验 wire 解析面）。
        let manifest = serde_json::from_str::<NormalizedWasmManifestV1>(SPEC_VECTOR_MANIFEST).expect("manifest");
        let binding = serde_json::to_value(vector_binding()).expect("binding");
        let body = json!({
            "schemaVersion": 1,
            "applicationId": "vector",
            "packageDigest": "0".repeat(64),
            "normalizedPolicy": manifest,
            "runtimeBinding": binding,
            "capabilityRecordRevision": 5,
            "capabilityRecordHash": "2".repeat(64),
            "stagingTtlSeconds": 60,
            "blobs": [
                { "digestHex": "1".repeat(64), "base64": base64::engine::general_purpose::STANDARD.encode(b"payload-a") },
                { "digestHex": "1".repeat(64), "base64": base64::engine::general_purpose::STANDARD.encode(b"payload-b") },
            ],
        });
        let failure = parse_admission_submit(jcs_bytes(&body).expect("jcs").as_slice()).expect_err("duplicate digest must be rejected");
        assert_eq!(failure.code, WASM_ADMISSION_WIRE_INVALID);
        let mut unique = body.clone();
        unique["blobs"][1]["digestHex"] = json!("2".repeat(64));
        let request = parse_admission_submit(jcs_bytes(&unique).expect("jcs").as_slice()).expect("parses");
        assert_eq!(request.blobs.len(), 2);
        assert_eq!(request.blobs[0].1, b"payload-a".to_vec());
        let mut unknown = unique.clone();
        unknown["surplus"] = json!(true);
        assert!(parse_admission_submit(jcs_bytes(&unknown).expect("jcs").as_slice()).is_err());
    }

    const SPEC_VECTOR_MANIFEST: &str = r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#;

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
}
