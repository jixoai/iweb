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
    recover_wasm_admission, verify_admission_proof, AdmissionControlDb, AdmissionDbRow,
    AdmissionError, AdmissionMaterializer, AdmissionObjectStore, AdmissionProofV1,
    AdmissionRequest, AdmissionState, AdmissionStores, NormalizedWasmManifestV1,
    OsRandomTokenSource, RuntimeBindingIdentityV1, WasmActivePointerV1,
    WasmAdmissionJournalFile, WasmVersionRegistryRow,
};
use crate::wasm_commands::{
    decide_reconciliation, parse_command_query_result,
    plan_execution_command, validate_execution_acknowledgement, correlate_acknowledgement,
    DrainReceiptV1, DrainRetirementProjection, ExecutionAcknowledgementV1, ExecutionCommandV1,
    JournalObservation, KernelCommandPlanInput, OutboxDeliveryState, ReconciliationStep,
    RetiringExecutionRecord, WasmCommandControlState, WasmExecutionIdentityV1,
    WasmExecutionOperation, EXECUTION_RPC_PROTOCOL_LITERAL,
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
/// 规范控制态文件结构性失败（P0-6：wasm-control-state-v2.json 校验 fail-closed 码）。
pub const WASM_CONTROL_STATE_INVALID: &str = "WASM_CONTROL_STATE_INVALID";
/// 准入身份绑定失败（P0-4：binding/capability/catalog pin 与当前节点逐字段不等）。
pub const WASM_ADMISSION_NODE_PIN_MISMATCH: &str = "WASM_ADMISSION_NODE_PIN_MISMATCH";

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
    /// 规范控制态文件（P0-6：wasm-control-state-v2.json；migration 语义 not-started 起步）。
    fn control_state(&self) -> PathBuf {
        self.root.join("wasm-control-state-v2.json")
    }
    /// 旧 schema-1 命令控制文件（只作迁移源读取；不再写出）。
    fn legacy_command_control(&self) -> PathBuf {
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
/// schema 2（P0-5/P0-1 批次）：追加 Kernel 拥有的投递侧状态——retirements 判据与
/// supervisor journal head 提示（spec 的 WasmControlStateFileV2 精确键集不含这些
/// Kernel 内部派生状态，故独立于规范文件落在本业务文件；v1 文件按 default 兼容读）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmRouteRegistryFile {
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
    /// Kernel 侧退休判据（drain 命令寻址；与 outbox 同批写入）。
    #[serde(default)]
    pub retirements: Vec<RetiringExecutionRecord>,
    /// Kernel 已知的 supervisor journal 头提示（新命令的 expectedJournalRevision）。
    #[serde(default)]
    pub journal_head_hint: u64,
}

impl WasmRouteRegistryFile {
    fn fresh() -> Self {
        Self { schema_version: ROUTE_REGISTRY_SCHEMA_VERSION, runtime_kind: RUNTIME_KIND_WASM.into(), proofs: Vec::new(), lifecycles: BTreeMap::new(), retirements: Vec::new(), journal_head_hint: 0 }
    }
}

/// 业务 registry 文件当前写出的 schema 版本（读取兼容 1/2）。
pub const ROUTE_REGISTRY_SCHEMA_VERSION: u64 = 2;

// ---------------------------------------------------------------------------
// wasm-control-state-v2.json：规范形状（schema 2 + migration/outbox/controlRevision CAS）
// 对位 packages/contracts/wasm-execution.ts WasmControlStateFileV2 与 TS store。
// ---------------------------------------------------------------------------

/// `migration` 分区：source 恒为 celld-control-state-v1；not-started 携带空 digest/
/// completedAt（契约语义：迁移交易未开始时 wasm 状态自成一体的空起点）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmControlMigrationStateV1 {
    pub source: String,
    pub status: String,
    #[serde(rename = "sourceDigest")]
    pub source_digest: Option<String>,
    #[serde(rename = "completedAt")]
    pub completed_at: Option<String>,
}

impl WasmControlMigrationStateV1 {
    pub fn not_started() -> Self {
        Self { source: WASM_CONTROL_MIGRATION_SOURCE.into(), status: "not-started".into(), source_digest: None, completed_at: None }
    }

    fn validate(&self) -> Result<(), WasmControlFailure> {
        let invalid = || WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, "the wasm control migration state is invalid");
        if self.source != WASM_CONTROL_MIGRATION_SOURCE {
            return Err(invalid());
        }
        match self.status.as_str() {
            "not-started" => {
                if self.completed_at.is_some() {
                    return Err(invalid());
                }
            }
            "in-progress" | "complete" => {
                if self.status == "complete" && self.completed_at.is_none() {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        if let Some(digest) = &self.source_digest {
            if !regex_sha256_hex().is_match(digest) {
                return Err(invalid());
            }
        }
        if let Some(at) = &self.completed_at {
            if crate::wasm_admission::parse_rfc3339_utc_millis(at).is_err() {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// migration.source 的固定字面量（TS requireStringLiteral 对位）。
pub const WASM_CONTROL_MIGRATION_SOURCE: &str = "celld-control-state-v1";

/// 旧 schema-1 命令控制文件（J 批次 `wasm-command-control.json`；只读迁移源）。
/// 键名按 J 批次实际落盘形状（`command_outbox` 为 snake_case；alias 兼容 camelCase）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LegacyCommandControlFileV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "controlRevision")]
    pub control_revision: u64,
    #[serde(default, alias = "commandOutbox")]
    pub command_outbox: Vec<crate::wasm_commands::CommandOutboxRecord>,
    #[serde(default)]
    pub retirements: Vec<RetiringExecutionRecord>,
}

/// 规范文件的版本行 wire（readinessLeaseDigest 显式 null——与 TS 精确键集一致；
/// WasmVersionRegistryRow 的 skip_serializing_if 形状只用于业务内存行）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmControlVersionRowV1 {
    #[serde(rename = "versionId")]
    pub version_id: String,
    pub identity: crate::wasm_admission::WasmVersionIdentity,
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
    #[serde(rename = "readinessLeaseDigest")]
    pub readiness_lease_digest: Option<String>,
}

impl From<&WasmVersionRegistryRow> for WasmControlVersionRowV1 {
    fn from(row: &WasmVersionRegistryRow) -> Self {
        Self {
            version_id: row.version_id.clone(),
            identity: row.identity.clone(),
            package_digest: row.package_digest.clone(),
            normalized_policy: row.normalized_policy.clone(),
            lifecycle: row.lifecycle.clone(),
            runtime_binding: row.runtime_binding.clone(),
            admission_proof_ref: row.admission_proof_ref.clone(),
            admission_proof_digest: row.admission_proof_digest.clone(),
            readiness_lease_digest: row.readiness_lease_digest.clone(),
        }
    }
}

/// 规范文件的应用控制记录（WasmApplicationControlRecordV1）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmApplicationControlRecordV1 {
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub versions: Vec<WasmControlVersionRowV1>,
    pub active: WasmActivePointerV1,
    #[serde(rename = "routeGeneration")]
    pub route_generation: u64,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
}

/// 规范控制态文件（wasm-control-state-v2.json 精确键集）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmControlStateFileV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "controlRevision")]
    pub control_revision: u64,
    pub applications: BTreeMap<String, WasmApplicationControlRecordV1>,
    #[serde(rename = "commandOutbox")]
    pub command_outbox: Vec<crate::wasm_commands::CommandOutboxRecord>,
    pub migration: WasmControlMigrationStateV1,
}

impl WasmControlStateFileV2 {
    pub fn empty() -> Self {
        Self {
            schema_version: 2,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: 0,
            applications: BTreeMap::new(),
            command_outbox: Vec::new(),
            migration: WasmControlMigrationStateV1::not_started(),
        }
    }

    /// 结构 + 跨字段校验（TS validateWasmControlStateFileV2 的 Kernel 侧对位：
    /// 精确键集由 serde deny_unknown_fields 承担；这里做行/指针/outbox 耦合律）。
    pub fn validate(&self) -> Result<(), WasmControlFailure> {
        let invalid = |detail: String| WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, detail);
        if self.schema_version != 2 || self.runtime_kind != RUNTIME_KIND_WASM {
            return Err(invalid("the wasm control state must be schemaVersion 2 with runtimeKind wasm".into()));
        }
        if self.control_revision > crate::wasm_admission::WASM_U53_MAX {
            return Err(invalid("controlRevision must be a u53 integer".into()));
        }
        self.migration.validate()?;
        let application_pattern = regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex");
        for (key, record) in &self.applications {
            if !application_pattern.is_match(key) || record.application_id != *key || record.runtime_kind != RUNTIME_KIND_WASM {
                return Err(invalid(format!("application record {key} must be keyed by its wasm applicationId")));
            }
            let mut seen = BTreeSet::new();
            for row in &record.versions {
                if !seen.insert(row.version_id.clone()) {
                    return Err(invalid(format!("application {key} carries duplicate versionId {}", row.version_id)));
                }
                if crate::wasm_admission::compose_wasm_version_id(&row.identity.digest, row.identity.sequence) != row.version_id {
                    return Err(invalid(format!("versionId {} must be the proof's complete digest-sequence label", row.version_id)));
                }
                if row.identity.application_id != *key {
                    return Err(invalid(format!("version {}/identity must belong to the same application", row.version_id)));
                }
                if row.admission_proof_ref != format!("admission-proof/{key}/{}", row.version_id) {
                    return Err(invalid(format!("version {} carries a wrong admissionProofRef", row.version_id)));
                }
                if row.normalized_policy.name != *key {
                    return Err(invalid(format!("version {} normalizedPolicy.name must equal the record applicationId", row.version_id)));
                }
                if matches!(row.lifecycle.as_str(), "ready" | "active") && row.readiness_lease_digest.is_none() {
                    return Err(invalid(format!("a ready or active candidate ({}) must carry a readiness lease digest", row.version_id)));
                }
            }
            match &record.active {
                WasmActivePointerV1::Active { application_id, version_id, identity, runtime_binding, admission_proof_ref, admission_proof_digest, route_generation, .. } => {
                    if application_id != key {
                        return Err(invalid(format!("application {key} active pointer belongs to another application")));
                    }
                    if *route_generation != record.route_generation {
                        return Err(invalid(format!("application {key} active pointer route generation must equal the record's current route generation")));
                    }
                    let Some(row) = record.versions.iter().find(|row| &row.version_id == version_id) else {
                        return Err(invalid(format!("application {key} active pointer names no registry version")));
                    };
                    if row.identity != *identity || row.runtime_binding != *runtime_binding || row.admission_proof_ref != *admission_proof_ref || row.admission_proof_digest != *admission_proof_digest {
                        return Err(invalid(format!("application {key} active pointer identity, binding, and proof reference must match the registry version")));
                    }
                }
                WasmActivePointerV1::Unavailable { application_id, route_generation, .. } => {
                    if application_id != key {
                        return Err(invalid(format!("application {key} unavailable pointer belongs to another application")));
                    }
                    if *route_generation != record.route_generation {
                        return Err(invalid(format!("application {key} active pointer route generation must equal the record's current route generation")));
                    }
                }
            }
        }
        let mut command_ids = BTreeSet::new();
        for entry in &self.command_outbox {
            if !command_ids.insert(entry.command_id.clone()) {
                return Err(invalid(format!("outbox commandId {} must be unique", entry.command_id)));
            }
            if entry.command_id != entry.command.command_id {
                return Err(invalid(format!("outbox commandId {} must match the wrapped command", entry.command_id)));
            }
        }
        Ok(())
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
    /// supervisor 执行通道 socket（IWEB_SANDBOX_SOCKET；投递闭环的传输端点）。
    execution_socket: Option<String>,
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
        let execution_socket = env_lookup(crate::supervisor::SUPERVISOR_SOCKET_ENV).filter(|value| !value.trim().is_empty());
        let mut runtime = Self { paths, gates, bootstrap_verified: None, bootstrap_failure: None, state_failure: None, execution_socket };
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
        // P0-6：schema-1 命令控制文件 → 规范 wasm-control-state-v2.json 一次性物化
        //（V2 已存在时零写入；迁移语义按契约 migration not-started 起步）。
        if runtime.state_failure.is_none() {
            if let Err(failure) = runtime.materialize_legacy_command_control() {
                eprintln!("iweb-kernel: wasm legacy control state migration failed: [{}] {}", failure.code, failure.detail);
                runtime.state_failure = Some(failure);
            }
        }
        // P0-1：outbox 投递闭环（query → deliver/replay → ack 投影）。supervisor 不可达
        // 不是 wasm 控制面失败——命令留待重试，只记录 owner 日志。
        if runtime.state_failure.is_none() {
            let socket = runtime.execution_socket.clone();
            runtime.deliver_pending_execution_commands(socket.as_deref(), now_millis_u64());
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
        // P0-5 跨存储恢复窗口收敛：admission DB 的 visible 行是 witness 权威——
        // witness→kind registry→route registry 任一步此前中断时，启动从这里幂等
        // 补写到完成（registry 文件缺行则补行 + kind claim；已齐则零写入）。
        self.converge_route_registry_from_admission(&mut store, &mut registry)?;
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

    /// P0-5：扫描 admission DB 的 visible 行，把缺失的 proof 收敛进 route registry
    /// 文件与 kind registry（任何中间态 → 完整态；幂等，不产生重复行/claim）。
    fn converge_route_registry_from_admission(
        &self,
        store: &mut KindRegistryStoreDir,
        registry: &mut WasmKernelRouteRegistryV1,
    ) -> Result<(), WasmControlFailure> {
        let db = FileAdmissionDb::open(&self.paths.admission_db()).map_err(map_admission_error)?;
        let mut registry_file = self.load_route_registry()?;
        let mut dirty = false;
        for key in db.keys() {
            let Some(row_bytes) = db.row_bytes(&key) else { continue };
            if row_bytes.is_empty() {
                continue;
            }
            let row: AdmissionDbRow = serde_json::from_slice(&row_bytes)
                .map_err(|e| map_admission_error(AdmissionError::new(crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT, format!("a stored admission db row does not parse: {e}"))))?;
            if row.visibility != "visible" {
                continue;
            }
            verify_admission_proof(&row.proof)
                .map_err(|e| WasmControlFailure::new(e.code, format!("a visible admission db row carries an invalid proof: {}", e.detail)))?;
            // kind registry 注册幂等（claim 已存在且同 kind 时零写入）。
            registry
                .register_wasm_admission(store, registry.registry_revision(), &row.proof)
                .map_err(map_kind_error)?;
            if !registry_file.proofs.iter().any(|proof| proof.version_id == row.proof.version_id) {
                registry_file.proofs.push(row.proof.clone());
                registry_file.lifecycles.entry(row.proof.version_id.clone()).or_insert_with(|| "admitted".into());
                dirty = true;
            }
        }
        if dirty {
            self.save_route_registry(&registry_file)?;
        }
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

    fn load_route_registry(&self) -> Result<WasmRouteRegistryFile, WasmControlFailure> {
        match std::fs::read(self.paths.route_registry()) {
            Ok(bytes) if bytes.is_empty() => Ok(WasmRouteRegistryFile::fresh()),
            Ok(bytes) => {
                let parsed = parse_canonical::<WasmRouteRegistryFile>(&bytes, WASM_RUNTIME_IO, "wasm route registry")?;
                if parsed.schema_version == 1 {
                    // v1 兼容读（无 retirements/journal_head_hint；下次写入升级为 v2）。
                    if parsed.runtime_kind != RUNTIME_KIND_WASM {
                        return Err(WasmControlFailure::new(WASM_RUNTIME_IO, "the wasm route registry must carry runtimeKind wasm"));
                    }
                    return Ok(WasmRouteRegistryFile { schema_version: ROUTE_REGISTRY_SCHEMA_VERSION, runtime_kind: parsed.runtime_kind, proofs: parsed.proofs, lifecycles: parsed.lifecycles, retirements: Vec::new(), journal_head_hint: 0 });
                }
                if parsed.schema_version != ROUTE_REGISTRY_SCHEMA_VERSION || parsed.runtime_kind != RUNTIME_KIND_WASM {
                    return Err(WasmControlFailure::new(WASM_RUNTIME_IO, "the wasm route registry must be schemaVersion 1 or 2 with runtimeKind wasm"));
                }
                for proof in &parsed.proofs {
                    verify_admission_proof(proof)
                        .map_err(|e| WasmControlFailure::new(e.code, format!("a persisted admission proof is invalid: {}", e.detail)))?;
                }
                Ok(parsed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(WasmRouteRegistryFile::fresh()),
            Err(e) => Err(WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!("cannot read the wasm route registry {}: {e}", self.paths.route_registry().display()),
            )),
        }
    }

    fn save_route_registry(&self, file: &WasmRouteRegistryFile) -> Result<(), WasmControlFailure> {
        write_canonical(&self.paths.route_registry(), file)
    }

    /// P0-6 控制态装载：规范 V2 文件优先；旧 schema-1 文件按迁移源并入（carry
    /// controlRevision/outbox；retirements 并入业务 registry 文件）。两者皆缺 →
    /// 空状态（migration not-started）。返回 (内存 CAS 载体, migration 分区,
    /// 业务 registry 文件)——retirements/journal head 提示在业务文件侧维护。
    fn load_control_state(&self) -> Result<(WasmCommandControlState, WasmControlMigrationStateV1, WasmRouteRegistryFile), WasmControlFailure> {
        let mut registry_file = self.load_route_registry()?;
        match std::fs::read(self.paths.control_state()) {
            Ok(bytes) if bytes.is_empty() => Ok((WasmCommandControlState::default(), WasmControlMigrationStateV1::not_started(), registry_file)),
            Ok(bytes) => {
                let parsed = parse_canonical::<WasmControlStateFileV2>(&bytes, WASM_CONTROL_STATE_INVALID, "wasm control state")?;
                parsed.validate()?;
                Ok((
                    WasmCommandControlState { control_revision: parsed.control_revision, command_outbox: parsed.command_outbox.clone(), retirements: registry_file.retirements.clone() },
                    parsed.migration,
                    registry_file,
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // 迁移源：schema-1 命令控制文件（J 批次布局）。carry 语义数据，规范
                // migration 分区按 not-started 起步（该文件从不承载 celld 业务迁移）。
                match std::fs::read(self.paths.legacy_command_control()) {
                    Ok(bytes) if !bytes.is_empty() => {
                        let legacy = parse_canonical::<LegacyCommandControlFileV1>(&bytes, WASM_CONTROL_STATE_INVALID, "legacy wasm command control state")?;
                        if legacy.schema_version != 1 || legacy.runtime_kind != RUNTIME_KIND_WASM {
                            return Err(WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, "the legacy wasm command control state must be schemaVersion 1 with runtimeKind wasm"));
                        }
                        registry_file.retirements = legacy.retirements.clone();
                        registry_file.journal_head_hint = 0;
                        Ok((
                            WasmCommandControlState { control_revision: legacy.control_revision, command_outbox: legacy.command_outbox.clone(), retirements: legacy.retirements.clone() },
                            WasmControlMigrationStateV1::not_started(),
                            registry_file,
                        ))
                    }
                    _ => Ok((WasmCommandControlState::default(), WasmControlMigrationStateV1::not_started(), registry_file)),
                }
            }
            Err(e) => Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                format!("cannot read the wasm control state {}: {e}", self.paths.control_state().display()),
            )),
        }
    }

    /// P0-6 控制态持久化：规范 V2 文件（精确键集：controlRevision/outbox/migration/
    /// applications 投影）+ 业务 registry 文件（retirements/journal head 提示）同批
    /// 落盘。V2 先写（CAS 权威），业务文件随后；中间窗口崩溃由装载侧 fail-closed
    /// 校验兜底（retirement 引用的 drain 命令必须仍在 outbox）。
    fn save_control_state(&self, state: &WasmCommandControlState, migration: &WasmControlMigrationStateV1, registry_file: &WasmRouteRegistryFile) -> Result<(), WasmControlFailure> {
        let applications = self.project_control_applications(registry_file);
        let file = WasmControlStateFileV2 {
            schema_version: 2,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: state.control_revision,
            applications,
            command_outbox: state.command_outbox.clone(),
            migration: migration.clone(),
        };
        file.validate().map_err(|e| WasmControlFailure::new(e.code, format!("the projected wasm control state is invalid: {}", e.detail)))?;
        write_canonical(&self.paths.control_state(), &file)?;
        let mut registry = registry_file.clone();
        registry.retirements = state.retirements.clone();
        self.save_route_registry(&registry)
    }

    /// 业务状态 → V2 applications 投影（proof/lifecycle 行 + activation 指针 +
    /// fence 的 secret/config 代次 + lease 台账的就绪 digest）。
    fn project_control_applications(&self, registry_file: &WasmRouteRegistryFile) -> BTreeMap<String, WasmApplicationControlRecordV1> {
        let fences = self.load_fences();
        let leases = self.load_leases();
        let activation_states = self.load_activation_states();
        let mut applications: BTreeMap<String, WasmApplicationControlRecordV1> = BTreeMap::new();
        for proof in &registry_file.proofs {
            let Ok(mut row) = project_registry_row(proof) else { continue };
            if let Some(lifecycle) = registry_file.lifecycles.get(&row.version_id) {
                row.lifecycle = lifecycle.clone();
            }
            // ready/active 行必须携带就绪租约 digest：优先激活事件消费记录，其次
            // lease 台账扫描；两者皆缺（激活态文件丢失的恢复窗口）→ 投影降级为
            // admitted（指针此时必然 unavailable，路由保持关闭，不伪造就绪证据）。
            if matches!(row.lifecycle.as_str(), "ready" | "active") {
                let event_version = |pointer: &WasmActivePointerV1| match pointer {
                    WasmActivePointerV1::Active { version_id, .. } => Some(version_id.clone()),
                    WasmActivePointerV1::Unavailable { .. } => None,
                };
                let from_event = activation_states
                    .get(&proof.application_id)
                    .and_then(|state| {
                        state
                            .events
                            .iter()
                            .rev()
                            .find(|event| event.result == crate::wasm_activation::RouteEventResult::Activated && event_version(&event.next) == Some(row.version_id.clone()))
                            .map(|event| event.lease_consume.lease_digest.clone())
                    });
                let from_ledger = leases.values().find(|lease| lease.version_id == row.version_id && lease.validate().is_ok()).map(|lease| lease.lease_digest.clone());
                match from_event.or(from_ledger) {
                    Some(digest) => row.readiness_lease_digest = Some(digest),
                    None => {
                        eprintln!("iweb-kernel: wasm version {} is {} without a discoverable readiness lease digest; the control-state projection keeps it admitted", row.version_id, row.lifecycle);
                        row.lifecycle = "admitted".into();
                    }
                }
            }
            let entry = applications.entry(proof.application_id.clone()).or_insert_with(|| {
                let (route_generation, active) = match activation_states.get(&proof.application_id) {
                    Some(state) => (
                        state.route_generation,
                        state.active.clone(),
                    ),
                    None => (0, WasmActivePointerV1::Unavailable { runtime_kind: RUNTIME_KIND_WASM.into(), application_id: proof.application_id.clone(), route_generation: 0 }),
                };
                let fence = fences.get(&proof.application_id).and_then(|application| application.records.get(&application.current_version_id));
                WasmApplicationControlRecordV1 {
                    runtime_kind: RUNTIME_KIND_WASM.into(),
                    application_id: proof.application_id.clone(),
                    versions: Vec::new(),
                    active,
                    route_generation,
                    secret_revision: fence.map(|fence| fence.secret_revision).unwrap_or(0),
                    config_revision: fence.map(|fence| fence.config_revision).unwrap_or(0),
                }
            });
            entry.versions.push(WasmControlVersionRowV1::from(&row));
        }
        // active 指针指向的行缺失（业务 registry 与激活态的恢复窗口）→ 指针降级为
        // unavailable（当前 generation 保持），绝不让规范文件携带悬空 active。
        for (application_id, record) in applications.iter_mut() {
            if let WasmActivePointerV1::Active { version_id, .. } = &record.active {
                if !record.versions.iter().any(|row| &row.version_id == version_id) {
                    eprintln!("iweb-kernel: wasm application {application_id} active pointer names version {version_id} with no registry row; the projection falls back to unavailable");
                    record.active = WasmActivePointerV1::Unavailable { runtime_kind: RUNTIME_KIND_WASM.into(), application_id: application_id.clone(), route_generation: record.route_generation };
                }
            }
        }
        applications
    }

    /// P0-6：一次性把旧 schema-1 命令控制文件物化为规范 V2 布局（V2 已存在时零写入）。
    fn materialize_legacy_command_control(&mut self) -> Result<(), WasmControlFailure> {
        if self.paths.control_state().is_file() {
            return Ok(());
        }
        if !self.paths.legacy_command_control().is_file() {
            return Ok(());
        }
        let (state, migration, registry_file) = self.load_control_state()?;
        self.save_control_state(&state, &migration, &registry_file)
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

    /// P0-4：admission 的 runtimeBinding/capability pin 与当前节点身份逐字段相等校验。
    /// 节点 pin 权威是 Kernel 拥有的固定路径 gate-node-identity.json；缺失/损坏/
    /// 任一字段不等（catalog revision/hash、entry key、image digest、host ABI、
    /// world、capability record revision/hash）→ 结构化 fail-closed 拒绝（400），
    /// 绝不推断默认 pin 或部分匹配。
    fn verify_admission_node_identity(&self, request: &AdmissionRequest) -> Result<(), WasmHttpResponse> {
        let mismatch = |detail: String| err_json(400, WASM_ADMISSION_NODE_PIN_MISMATCH, &detail);
        let pin = match std::fs::read(self.paths.gate_node_identity()) {
            Ok(bytes) => match parse_canonical::<GateNodeIdentityFileV1>(&bytes, WASM_STATE_UNAVAILABLE, "gate node identity") {
                Ok(file) => match WasmGateNodeIdentity::try_from(file) {
                    Ok(pin) => pin,
                    Err(failure) => return Err(mismatch(format!("the gate node identity is unusable: [{}] {}", failure.code, failure.detail))),
                },
                Err(failure) => return Err(mismatch(format!("the gate node identity is not canonical: [{}] {}", failure.code, failure.detail))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(mismatch("no gate node identity is installed; wasm admission cannot bind to this node".into()));
            }
            Err(e) => return Err(mismatch(format!("cannot read the gate node identity: {e}"))),
        };
        let binding = &request.runtime_binding;
        let mut fields = Vec::new();
        if binding.catalog_revision != pin.catalog_revision {
            fields.push("runtimeBinding.catalogRevision");
        }
        if binding.catalog_hash != pin.catalog_hash {
            fields.push("runtimeBinding.catalogHash");
        }
        if binding.entry_key != pin.catalog_entry.entry_key {
            fields.push("runtimeBinding.entryKey");
        }
        if binding.image_digest != pin.catalog_entry.image_digest {
            fields.push("runtimeBinding.imageDigest");
        }
        if binding.host_abi != pin.catalog_entry.host_abi {
            fields.push("runtimeBinding.hostABI");
        }
        if binding.world != pin.catalog_entry.world {
            fields.push("runtimeBinding.world");
        }
        if request.capability_record_revision != pin.capability_record_revision {
            fields.push("capabilityRecordRevision");
        }
        if request.capability_record_hash != pin.capability_record_hash {
            fields.push("capabilityRecordHash");
        }
        if fields.is_empty() {
            Ok(())
        } else {
            Err(mismatch(format!(
                "the admission identity pins do not equal the current node identity: {}",
                fields.join(", ")
            )))
        }
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
        // P0-4 准入身份绑定：runtimeBinding/capability pin/catalog revision+hash 与当前
        // 节点 gate-node-identity 逐字段相等；缺失/不相等 → 结构化 fail-closed 拒绝。
        if let Err(response) = self.verify_admission_node_identity(&request) {
            return response;
        }
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
        // 持久化业务记录（proof 集合 + lifecycle 覆盖）。P0-5：join 重试（created=false）
        // 不跳过——witness 事务已提交而本步此前失败时，重试必须幂等补写到完成。
        let mut registry_file = match self.load_route_registry() {
            Ok(file) => file,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        if !registry_file.proofs.iter().any(|proof| proof.version_id == outcome.proof.version_id) {
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
        let registry_file = self.load_route_registry().unwrap_or_else(|_| WasmRouteRegistryFile::fresh());
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
        let registry_file = self.load_route_registry().unwrap_or_else(|_| WasmRouteRegistryFile::fresh());
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
        let file = self.load_route_registry().unwrap_or_else(|_| WasmRouteRegistryFile::fresh());
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
    /// fence 携带精确 drain deadline 时经 plan_execution_command 生成 drain 命令并
    /// 建档 retiring（P0-1：expected revisions 由控制态/ journal head 提示推导），
    /// retired 仍只由 project_drain_receipt 写入（spec 退休门）。
    fn sync_lifecycle_after_activation(&mut self, now_epoch_millis: u64) -> Result<(), WasmControlFailure> {
        let mut registry_file = self.load_route_registry()?;
        let fences = self.load_fences();
        let activation_states = self.load_activation_states();
        let (mut command_state, migration, _) = self.load_control_state()?;
        let journal_head_hint = registry_file.journal_head_hint;
        let mut command_dirty = false;
        let application_ids: Vec<String> = registry_file.proofs.iter().map(|proof| proof.application_id.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        for application_id in &application_ids {
            let Some(state) = activation_states.get(application_id) else { continue };
            let WasmActivePointerV1::Active { version_id, .. } = &state.active else { continue };
            if !registry_file.proofs.iter().any(|proof| &proof.version_id == version_id) {
                continue;
            }
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
            // P0-1：drain 命令从纯函数生成器产出（expected control revision = 当前头、
            // expected journal revision = Kernel 已知 supervisor journal 头提示）。
            // 行权威是被替换（retiring）版本自己的 proof——命令身份/fence 与其执行
            // 的版本一致，而非新激活版本。
            let Some(previous_proof) = registry_file.proofs.iter().find(|proof| proof.version_id == *previous_version_id) else { continue };
            let row = project_registry_row(previous_proof).map_err(map_admission_error)?;
            let planned = plan_execution_command(&KernelCommandPlanInput {
                command_id: &generate_uuid_v7(now_epoch_millis),
                operation: WasmExecutionOperation::Drain,
                control_revision: command_state.control_revision,
                journal_head: journal_head_hint,
                sandbox_id: &previous_fence.sandbox_id,
                version_row: &row,
                capability_record_revision: previous_proof.capability_record_revision,
                capability_record_hash: &previous_proof.capability_record_hash,
                secret_revision: previous_fence.secret_revision,
                secret_snapshot_ref: &previous_fence.secret_snapshot_ref,
                secret_values_digest: &previous_fence.secret_values_digest,
                config_revision: previous_fence.config_revision,
                config_snapshot_ref: previous_fence.config_snapshot_ref.as_deref(),
                config_values_digest: previous_fence.config_values_digest.as_deref(),
                current_generations: WasmExecutionIdentityV1 {
                    sandbox_id: previous_fence.sandbox_id.clone(),
                    version_id: previous_version_id.clone(),
                    preparation_generation: previous_fence.preparation_generation,
                    execution_generation: previous_fence.execution_generation,
                },
            })
            .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
            let identity = planned.next_generations;
            let command = planned.command;
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
                        package_digest: previous_proof.package_digest.clone(),
                        runtime_binding: previous_proof.runtime_binding.clone(),
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
            self.save_control_state(&command_state, &migration, &registry_file)?;
        } else {
            self.save_route_registry(&registry_file)?;
        }
        // P0-1：授权即投递（best-effort；supervisor 不可达/不确定结果留待
        // query/replay 重试，绝不阻塞激活响应）。
        let socket = self.execution_socket.clone();
        self.deliver_pending_execution_commands(socket.as_deref(), now_epoch_millis);
        Ok(())
    }

    /// drain receipt 投影（retired 的唯一入口；执行流通道/测试驱动）：CAS 成功后
    /// 才把被替换版本的 lifecycle 写为 "retired"。
    pub fn project_drain_receipt(&mut self, receipt: &DrainReceiptV1) -> Result<DrainRetirementProjection, WasmControlFailure> {
        let (mut command_state, migration, mut registry_file) = self.load_control_state()?;
        let expected = command_state.control_revision;
        let projection = command_state
            .project_drain_receipt(expected, receipt)
            .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
        if let DrainRetirementProjection::Retired { .. } = projection {
            registry_file.lifecycles.insert(receipt.execution.version_id.clone(), "retired".into());
        }
        self.save_control_state(&command_state, &migration, &registry_file)?;
        Ok(projection)
    }

    /// 已建档的 retiring 判据（执行流取 drain 命令寻址；测试/状态投影用）。
    pub fn retiring_records(&self) -> Vec<RetiringExecutionRecord> {
        self.load_control_state().map(|(state, _, _)| state.retirements).unwrap_or_default()
    }

    /// 规范控制态文件的只读投影（owner 诊断/测试对位 WasmControlStateFileV2）。
    pub fn control_state_projection(&self) -> Result<WasmControlStateFileV2, WasmControlFailure> {
        let (state, migration, registry_file) = self.load_control_state()?;
        let applications = self.project_control_applications(&registry_file);
        Ok(WasmControlStateFileV2 {
            schema_version: 2,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: state.control_revision,
            applications,
            command_outbox: state.command_outbox,
            migration,
        })
    }

    /// P0-1 生产投递闭环：对每个 pending/sent outbox 条目执行
    /// query → decide_reconciliation → deliver/replay/project-ack，并把 journal
    /// head 提示收敛到观察到的最大 revision。supervisor 不可达/响应不确定时命令
    /// 保持 sent（advisory），只能经 query/replay 推进——绝不重发 command 语义。
    pub fn deliver_pending_execution_commands(&mut self, socket_path: Option<&str>, now_epoch_millis: u64) -> WasmDeliveryReport {
        let Some(socket) = socket_path else {
            return WasmDeliveryReport::default();
        };
        match self.run_outbox_delivery(socket, now_epoch_millis) {
            Ok(report) => report,
            Err(failure) => {
                eprintln!("iweb-kernel: wasm outbox delivery stopped: [{}] {}", failure.code, failure.detail);
                let mut report = WasmDeliveryReport::default();
                report.failures.push(format!("[{}] {}", failure.code, failure.detail));
                report
            }
        }
    }

    fn run_outbox_delivery(&mut self, socket: &str, now_epoch_millis: u64) -> Result<WasmDeliveryReport, WasmControlFailure> {
        let (mut state, migration, mut registry_file) = self.load_control_state()?;
        let mut report = WasmDeliveryReport::default();
        let mut journal_head_hint = registry_file.journal_head_hint;
        let mut dirty = false;
        let command_ids: Vec<String> = state
            .command_outbox
            .iter()
            .filter(|entry| matches!(entry.delivery_state, OutboxDeliveryState::Pending | OutboxDeliveryState::Sent))
            .map(|entry| entry.command_id.clone())
            .collect();
        for command_id in command_ids {
            let Some(outbox) = state.find_outbox(&command_id).cloned() else { continue };
            // 第 1 步：query（journal 观察是唯一推进依据）。
            let request_id = generate_uuid_v7(now_epoch_millis);
            let observation = match self.post_execution_rpc(socket, &request_id, json!({ "kind": "query", "commandId": command_id })) {
                Ok(body) => match parse_query_result_envelope(&request_id, &body) {
                    Ok(query) => {
                        // journal head 提示按观察收敛（received/completion 的最大 revision）。
                        if let Some(received) = &query.received {
                            journal_head_hint = journal_head_hint.max(received.journal_revision);
                        }
                        if let Some(ack) = &query.acknowledgement {
                            journal_head_hint = journal_head_hint.max(ack.journal_revision);
                        }
                        match crate::wasm_commands::journal_observation_from_query(&outbox.command, &query) {
                            Ok(observation) => Some(observation),
                            Err(failure) => {
                                report.failures.push(format!("[{}] {}", failure.code, failure.detail));
                                None
                            }
                        }
                    }
                    Err(failure) => {
                        report.failures.push(format!("[{}] {}", failure.code, failure.detail));
                        None
                    }
                },
                Err(failure) => {
                    report.failures.push(format!("[{}] {}", failure.code, failure.detail));
                    None
                }
            };
            let Some(observation) = observation else {
                // 观察失败（传输/畸形/命令冲突）：记录一次投递尝试，命令保持原态。
                let head = state.control_revision;
                if state.record_delivery_attempt(head, &command_id, crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis)).is_ok() {
                    dirty = true;
                }
                report.attempted += 1;
                continue;
            };
            match decide_reconciliation(&outbox, &observation) {
                Ok(ReconciliationStep::AlreadyProjected) => report.already_projected += 1,
                Ok(ReconciliationStep::ProjectAcknowledgement) => {
                    let JournalObservation::Completed(ack) = &observation else { unreachable!("decide_reconciliation projects completed observations only") };
                    let head = state.control_revision;
                    match state.project_acknowledgement(head, ack) {
                        Ok(crate::wasm_commands::AcknowledgementProjection::Projected { .. }) => {
                            report.projected += 1;
                            dirty = true;
                        }
                        Ok(crate::wasm_commands::AcknowledgementProjection::AlreadyAcknowledged) => report.already_projected += 1,
                        Err(failure) => report.failures.push(format!("[{}] {}", failure.code, failure.detail)),
                    }
                }
                Ok(step) => {
                    // 第 2 步：deliver（missing）或 byte-identical replay（received-incomplete）。
                    let kind = match step {
                        ReconciliationStep::DeliverCommand => {
                            report.attempted += 1;
                            "command"
                        }
                        _ => {
                            report.replayed += 1;
                            "replay"
                        }
                    };
                    let request_id = generate_uuid_v7(now_epoch_millis);
                    let command_value = serde_json::to_value(&outbox.command).expect("command serializes");
                    let delivered = self.post_execution_rpc(socket, &request_id, json!({ "kind": kind, "command": command_value }));
                    let outcome = delivered.and_then(|body| parse_acknowledgement_envelope(&request_id, &body, &outbox.command));
                    match outcome {
                        Ok(ack) => {
                            journal_head_hint = journal_head_hint.max(ack.journal_revision);
                            let head = state.control_revision;
                            match state.project_acknowledgement(head, &ack) {
                                Ok(crate::wasm_commands::AcknowledgementProjection::Projected { .. }) => {
                                    report.projected += 1;
                                    report.delivered += 1;
                                    dirty = true;
                                }
                                Ok(crate::wasm_commands::AcknowledgementProjection::AlreadyAcknowledged) => report.already_projected += 1,
                                Err(failure) => report.failures.push(format!("[{}] {}", failure.code, failure.detail)),
                            }
                        }
                        Err(failure) => {
                            // 不确定结果（response lost/传输失败/echo 拒绝）：留待 query/replay。
                            report.failures.push(format!("[{}] {}", failure.code, failure.detail));
                            let head = state.control_revision;
                            if state.record_delivery_attempt(head, &command_id, crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis)).is_ok() {
                                dirty = true;
                            }
                        }
                    }
                }
                Err(failure) => report.failures.push(format!("[{}] {}", failure.code, failure.detail)),
            }
        }
        if dirty || journal_head_hint != registry_file.journal_head_hint {
            registry_file.journal_head_hint = journal_head_hint;
            self.save_control_state(&state, &migration, &registry_file)?;
        }
        Ok(report)
    }

    /// POST /v1/execution-rpc（envelope 用既有契约；成功返回响应 body 字节）。
    fn post_execution_rpc(&self, socket: &str, request_id: &str, body: serde_json::Value) -> Result<Vec<u8>, WasmControlFailure> {
        let envelope = json!({
            "protocol": EXECUTION_RPC_PROTOCOL_LITERAL,
            "requestId": request_id,
            "body": body,
        });
        let bytes = jcs_bytes(&envelope).map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
        match crate::supervisor::execution_rpc_blocking(socket, &bytes, EXECUTION_RPC_TIMEOUT_MS) {
            Some((200, response)) => Ok(response),
            Some((status, response)) => {
                let detail = String::from_utf8_lossy(&response).trim().to_string();
                Err(WasmControlFailure::new(WASM_EXECUTION_DELIVERY_UNCERTAIN, format!("supervisor returned HTTP {status}: {detail}")))
            }
            None => Err(WasmControlFailure::new(WASM_EXECUTION_DELIVERY_UNCERTAIN, "the execution rpc response is uncertain (transport failure or timeout); only query/replay may advance the command")),
        }
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

// ---------------------------------------------------------------------------
// P0-1 投递闭环的 wire/报告辅助
// ---------------------------------------------------------------------------

/// 投递不确定码（传输失败/超时/非 200——唯一推进路径是 query/replay）。
pub const WASM_EXECUTION_DELIVERY_UNCERTAIN: &str = "WASM_EXECUTION_DELIVERY_UNCERTAIN";
/// 单次 /v1/execution-rpc 调用的阻塞上界（本地 UDS；控制面在锁内串行）。
pub const EXECUTION_RPC_TIMEOUT_MS: u64 = 2_000;

/// 一轮 outbox 投递的 owner 可见报告（无秘密；failures 是稳定码 + 摘要）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WasmDeliveryReport {
    pub attempted: usize,
    pub delivered: usize,
    pub replayed: usize,
    pub projected: usize,
    pub already_projected: usize,
    pub failures: Vec<String>,
}

/// 响应 envelope 头（{protocol,requestId,body}；protocol/requestId 必须回显）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRpcEnvelopeResponseHead {
    protocol: String,
    #[serde(rename = "requestId")]
    request_id: String,
    body: serde_json::Value,
}

fn parse_envelope_head(request_id: &str, bytes: &[u8]) -> Result<serde_json::Value, WasmControlFailure> {
    let head: ExecutionRpcEnvelopeResponseHead = serde_json::from_slice(bytes)
        .map_err(|e| WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, format!("the execution rpc response does not parse as the envelope: {e}")))?;
    if head.protocol != EXECUTION_RPC_PROTOCOL_LITERAL {
        return Err(WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, "the execution rpc response protocol does not echo the request literal"));
    }
    if head.request_id != request_id {
        return Err(WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, "the execution rpc response requestId does not echo the request"));
    }
    Ok(head.body)
}

/// 响应 envelope 码（spec 未命名 HTTP 错误 envelope 之外的 Kernel 侧结构码）。
pub const EXECUTION_RPC_RESPONSE_INVALID: &str = "EXECUTION_RPC_RESPONSE_INVALID";

fn parse_query_result_envelope(request_id: &str, bytes: &[u8]) -> Result<crate::wasm_commands::CommandQueryResultV1, WasmControlFailure> {
    let body = parse_envelope_head(request_id, bytes)?;
    if body.get("kind").and_then(serde_json::Value::as_str) != Some("query-result") {
        return Err(WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, "a query must answer with a query-result body"));
    }
    let body_bytes = serde_json::to_vec(&body).map_err(|e| WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, format!("the query-result body is not serializable: {e}")))?;
    parse_command_query_result(&body_bytes).map_err(|e| WasmControlFailure::new(e.code, e.detail))
}

fn parse_acknowledgement_envelope(request_id: &str, bytes: &[u8], command: &ExecutionCommandV1) -> Result<ExecutionAcknowledgementV1, WasmControlFailure> {
    let body = parse_envelope_head(request_id, bytes)?;
    if body.get("kind").and_then(serde_json::Value::as_str) != Some("acknowledgement") {
        return Err(WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, "a delivered command must answer with an acknowledgement body"));
    }
    let Some(ack_value) = body.get("acknowledgement") else {
        return Err(WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, "the acknowledgement body is missing its acknowledgement member"));
    };
    let ack: ExecutionAcknowledgementV1 = serde_json::from_value(ack_value.clone())
        .map_err(|e| WasmControlFailure::new(EXECUTION_RPC_RESPONSE_INVALID, format!("the acknowledgement does not parse as the typed record: {e}")))?;
    validate_execution_acknowledgement(&ack).map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
    correlate_acknowledgement(command, &ack).map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
    Ok(ack)
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
    registry_file: &WasmRouteRegistryFile,
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

    /// TS exampleWasmControlStateFileV2 的 canonical JCS（bun oracle 于 2026-08-27
    /// 产出；3889 字节）——跨实现形状/键序锁定向量。
    const GOLDEN_CONTROL_STATE_V2_JCS: &str = r#"{"applications":{"vector":{"active":{"admissionProofDigest":"4444444444444444444444444444444444444444444444444444444444444444","admissionProofRef":"admission-proof/vector/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1","applicationId":"vector","identity":{"applicationId":"vector","digest":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532","sequence":1},"kind":"active","routeGeneration":4,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"runtimeKind":"wasm","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"},"applicationId":"vector","configRevision":2,"routeGeneration":4,"runtimeKind":"wasm","secretRevision":3,"versions":[{"admissionProofDigest":"4444444444444444444444444444444444444444444444444444444444444444","admissionProofRef":"admission-proof/vector/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1","identity":{"applicationId":"vector","digest":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532","sequence":1},"lifecycle":"active","normalizedPolicy":{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}},"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","readinessLeaseDigest":"3333333333333333333333333333333333333333333333333333333333333333","runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}]}},"commandOutbox":[{"attempts":1,"command":{"capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abcd","configRevision":2,"configSnapshotRef":"7777777777777777777777777777777777777777777777777777777777777777","configValuesDigest":"8888888888888888888888888888888888888888888888888888888888888888","expectedJournalRevision":4,"expectedKernelControlRevision":12,"identity":{"executionGeneration":1,"preparationGeneration":1,"sandboxId":"sbx-vector","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"},"operation":"prepare","packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"secretRevision":3,"secretSnapshotRef":"5555555555555555555555555555555555555555555555555555555555555555","secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666"},"commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abcd","createdAt":"2026-08-26T00:00:00Z","deliveryState":"sent","lastAttemptAt":"2026-08-26T00:00:01Z"}],"controlRevision":12,"migration":{"completedAt":null,"source":"celld-control-state-v1","sourceDigest":null,"status":"not-started"},"runtimeKind":"wasm","schemaVersion":2}"#;

    #[test]
    fn control_state_v2_golden_round_trips_the_ts_vector() {
        let bytes = GOLDEN_CONTROL_STATE_V2_JCS.as_bytes().to_vec();
        let parsed = parse_canonical::<WasmControlStateFileV2>(&bytes, WASM_CONTROL_STATE_INVALID, "wasm control state").expect("golden parses canonically");
        parsed.validate().expect("golden validates");
        assert_eq!(parsed.control_revision, 12);
        assert_eq!(parsed.applications.len(), 1);
        assert_eq!(parsed.migration.status, "not-started");
        assert_eq!(parsed.command_outbox.len(), 1);
        // JCS round-trip：原始字节等于 JCS(parse(bytes))（含显式 null 键）。
        let reencoded = jcs_bytes(&parsed).expect("re-encode");
        assert_eq!(String::from_utf8(reencoded).expect("utf8"), GOLDEN_CONTROL_STATE_V2_JCS);
        // 空文件：not-started 起步 + 显式 null 迁移字段。
        let empty = WasmControlStateFileV2::empty();
        empty.validate().expect("empty validates");
        let encoded = jcs_bytes(&empty).expect("empty jcs");
        assert_eq!(
            String::from_utf8(encoded).expect("utf8"),
            r#"{"applications":{},"commandOutbox":[],"controlRevision":0,"migration":{"completedAt":null,"source":"celld-control-state-v1","sourceDigest":null,"status":"not-started"},"runtimeKind":"wasm","schemaVersion":2}"#
        );
    }

    #[test]
    fn control_state_v2_rejects_structural_and_cross_field_violations() {
        let replace = |from: &str, to: &str| GOLDEN_CONTROL_STATE_V2_JCS.replacen(from, to, 1).into_bytes();
        // schemaVersion 篡改（schema 1 不得被 wasm v2 语义接受：解析可行、校验拒绝）。
        let celld_shape = replace(r#""runtimeKind":"wasm","schemaVersion":2}"#, r#""runtimeKind":"wasm","schemaVersion":1}"#);
        let parsed = parse_canonical::<WasmControlStateFileV2>(&celld_shape, WASM_CONTROL_STATE_INVALID, "x").expect("parses as JSON");
        assert!(parsed.validate().is_err());
        // 未知顶层键。
        let mut surplus = GOLDEN_CONTROL_STATE_V2_JCS.to_string();
        surplus.insert_str(1, r#""surplus":true,"#);
        assert!(parse_canonical::<WasmControlStateFileV2>(surplus.as_bytes(), WASM_CONTROL_STATE_INVALID, "x").is_err());
        // active 行缺 readinessLeaseDigest（显式 null 键缺席即拒绝）。
        let missing_lease = replace(r#""readinessLeaseDigest":"3333333333333333333333333333333333333333333333333333333333333333","runtimeBinding""#, r#""runtimeBinding""#);
        assert!(parse_canonical::<WasmControlStateFileV2>(&missing_lease, WASM_CONTROL_STATE_INVALID, "x").is_err());
        // 跨字段：active 指针 routeGeneration 与记录不一致。
        let mismatched = replace(r#""routeGeneration":4,"runtimeKind":"wasm","secretRevision":3"#, r#""routeGeneration":5,"runtimeKind":"wasm","secretRevision":3"#);
        let parsed = parse_canonical::<WasmControlStateFileV2>(&mismatched, WASM_CONTROL_STATE_INVALID, "x").expect("parses");
        assert!(parsed.validate().is_err());
        // 跨字段：admissionProofRef 公式破坏（active 指针侧首个出现即触发指针↔行比对）。
        let wrong_ref = replace(r#"admission-proof/vector/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"#, r#"admission-proof/wrong/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"#);
        let parsed = parse_canonical::<WasmControlStateFileV2>(&wrong_ref, WASM_CONTROL_STATE_INVALID, "x").expect("parses");
        assert!(parsed.validate().is_err());
        // migration：complete 缺 completedAt。
        let bad_migration = GOLDEN_CONTROL_STATE_V2_JCS.replacen(r#""status":"not-started""#, r#""status":"complete""#, 1);
        let parsed = parse_canonical::<WasmControlStateFileV2>(bad_migration.as_bytes(), WASM_CONTROL_STATE_INVALID, "x").expect("parses");
        assert!(parsed.validate().is_err());
        // outbox：commandId 与包装命令不一致。
        let mismatched_outbox = replace(r#""commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abcd","createdAt""#, r#""commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abce","createdAt""#);
        let parsed = parse_canonical::<WasmControlStateFileV2>(&mismatched_outbox, WASM_CONTROL_STATE_INVALID, "x").expect("parses");
        assert!(parsed.validate().is_err());
    }

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
