//! 用户原始需求（two-tier-runtime-trust，2026-08-30）：把 wasm_admission /
//! wasm_kind_registry / wasm_activation / wasm_publication / wasm_commands 状态机
//! 接进 Kernel 生产路径——启动序（wasm 单 gate 评估 → 路由注册表 kind-claim 派生 →
//! admission/activation 恢复）、owner 控制端点（admission 提交、activation-rpc、
//! wasm 状态投影）与 retired 投影。celld 运行时准入已永久移除：无 celld gate、
//! 无 celld 控制态、无 WASM_KIND_BOOTSTRAP_PENDING——终身 celld claims 从路由注册表
//! 确定性派生，路由文件不可解析即节点启动失败。
//! 规范权威：openspec/changes/two-tier-runtime-trust/specs/wasm-application-runtime/spec.md
//! （"Wasm publication gate selection is a wasm-only wire"、"Kernel business authority
//! is a wasm-only registry"、"Activation has a replayable Kernel control wire"、
//! "Drain completion is a typed receipt before Kernel retirement"）。
//!
//! 接线取舍（保守 fail-closed，供 review 对照）：
//! 1. 未启用开关（或验收记录无效、节点 pin 缺失）时 wasm 路径一律 503
//!    WASM_PUBLICATION_DISABLED，对齐发布门 fail-closed 语义（单开关
//!    IWEB_WASM_PUBLICATION_ENABLED）。
//! 2. 节点 pin（catalog/capability/arch）来源：Kernel 拥有的固定路径
//!    `<wasm-root>/gate-node-identity.json`（canonical JCS；缺失/损坏 → node=None →
//!    gate 以 identity/capability/catalog mismatch 关闭，绝不推断默认 pin）。真正的
//!    NodeCapabilityRecordV1 / RuntimeCatalogV1 Rust 加载器落地后由其替换该投影文件。
//! 3. 激活 CAS 判据（current preparation/secret revision、candidate 存活、lifecycle
//!    ready）与 readiness lease 台账来自 Kernel 拥有的 `<wasm-root>/wasm-fences.json`
//!    与 `<wasm-root>/readiness-leases.json`——执行流（supervisor 执行命令通道，独立
//!    J 批次）是唯一写者；本模块只读。文件缺失/损坏 → 判据 fail-closed（激活被拒），
//!    绝不伪造 ready。
//! 4. `wasm-control-state-v2.json` 是 wasm 的唯一控制权威：admission/version 行、
//!    active pointer、route generation、revision 与 command outbox 均在同一 CAS
//!    载体中持久化。`wasm-route-registry.json` 只保留 proof 与 lifecycle 审计投影，
//!    不得再反向重建 v2 applications。
//! 5. drain receipt 的 owner-HTTP 入口不存在（spec：receipt 来自 supervisor 通道）；
//!    本模块暴露 project_drain_receipt 供执行流接线/测试驱动 retired 投影。
//! 6. kind claims：启动时从路由注册表（镜像种子 + owner 写入的唯一应用身份权威）
//!    读取所有 `celld-app` 目标的应用名作为终身 celld claim，与持久 wasm claims
//!    合并。无 pending 失败模式：路由文件不可解析 → RouteStore::load panic →
//!    节点启动失败。
//!
//! P0-3（add-wasm-host-services Kernel 半边，2026-08-28；R2 修复轮 9.7 单 gate 收敛）：
//! - admission 提交 wire 携带可选 `hostServicePolicy`（V2/service-enabled）；
//! - 发布门是单一 wasm gate（固定路径的 v2/v3 一代记录，启动评估一次）；
//!   service-enabled 请求额外与 gate 携带的已验证 v3 记录逐字段绑定
//!   （policy/binding/capability pins；v2 记录安装时结构性关闭 service 面）；
//! - preparation gate 对 V2 证明执行 reserve 交叉校验（TS checkWasmGuestMemoryReserve
//!   对位；缺失/零替换/越界 fail-closed，绝不代默认）；
//! - wasm-control-state-v2 的 V2 版本行携带 hostServicePolicyDigest 静态摘要
//!   （policy digest + envelope + profile 字面量 + 启用服务；控制态与数据面结构隔离不变）。

use crate::wasm_activation::{
    generate_uuid_v7, handle_activation_rpc_http, ActivationCommand, ActivationDeps,
    ActivationHttpOptions, ActivationHttpRequest, ActivationStateIO,
    KernelActivationState, OwnedActivationCasFacts, RegistryRowFacts, RouteEvent,
    ServiceReadinessLeaseV2, WasmActivationStore, ACTIVATION_RPC_DEFAULT_MAX_BYTES,
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
    decide_reconciliation, parse_command_query_result, plan_execution_command,
    validate_execution_acknowledgement, DrainReceiptV1, DrainRetirementProjection,
    ExecutionAcknowledgement, ExecutionCommand, JournalObservation, KernelCommandPlanInput,
    OutboxDeliveryState, ReconciliationStep, RetiringExecutionRecord, WasmCommandControlState,
    WasmExecutionIdentityV1, WasmExecutionOperation, EXECUTION_RPC_PROTOCOL_LITERAL,
};
use crate::wasm_kind_registry::{
    derive_celld_claims_from_routes, KindRegistryStoreDir, RuntimeKindClaimV1,
    WasmKernelRouteRegistryV1, APPLICATION_RUNTIME_KIND_CONFLICT,
    KIND_CLAIM_SOURCE_ROUTE_REGISTRY, RUNTIME_KIND_WASM,
};
use crate::wasm_publication::{
    evaluate_wasm_publication_gate_from_reader, require_wasm_publication, select_publication_gate,
    GateEnvironmentView, GateResultV1, GateSelectionResponseV1, VerifiedWasmAcceptanceRecord,
    WasmGateCatalogEntryPin, WasmGateNodeIdentity, WasmPublicationGateState,
};
use crate::wasm_snapshot_fd::{
    compute_snapshot_fd_digest, deliver_snapshot_handoff, ConfigSnapshotFdHandoffV1,
    SecretSnapshotFdHandoffV1, SnapshotDeliveryOutcome, SnapshotFdError, SnapshotFrameKind,
    SnapshotHandoffDelivery, SnapshotHandoffPayload, SnapshotSocketPeer, SNAPSHOT_FD_SOCKET_PATH,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// 常量与稳定错误码（spec 已命名码优先；补充码沿用 contracts 命名风格）
// ---------------------------------------------------------------------------

/// wasm 状态根目录覆盖变量（缺省从 IWEB_ROUTES_FILE 的父目录派生 `<dir>/wasm`）。
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
/// R2 修复轮 9.9b：用户路由 sandbox 目标指向未准入 wasm 应用（409 有界码）。
pub const WASM_APPLICATION_NOT_ADMITTED: &str = "WASM_APPLICATION_NOT_ADMITTED";
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
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// 控制面处理结果（http.rs 适配为 axum Response；模块级测试直接消费）。
#[derive(Debug, Clone, PartialEq)]
pub struct WasmHttpResponse {
    pub status: u16,
    pub body: String,
}

fn ok_json(status: u16, body: serde_json::Value) -> WasmHttpResponse {
    WasmHttpResponse {
        status,
        body: format!("{body}\n"),
    }
}

fn err_json(status: u16, code: &str, detail: &str) -> WasmHttpResponse {
    ok_json(
        status,
        json!({ "ok": false, "code": code, "message": detail }),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn domain_sha256_hex(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn regex_sha256_hex() -> &'static regex::Regex {
    static SHA256_HEX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SHA256_HEX.get_or_init(|| regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"))
}

/// 文件层原子落盘（tmp + rename；对位现有 control/routes 的写纪律）。
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), WasmControlFailure> {
    let temporary =
        path.with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
    std::fs::write(&temporary, bytes).map_err(|e| {
        WasmControlFailure::new(
            WASM_RUNTIME_IO,
            format!("cannot write {}: {e}", temporary.display()),
        )
    })?;
    std::fs::rename(&temporary, path).map_err(|e| {
        WasmControlFailure::new(
            WASM_RUNTIME_IO,
            format!("cannot rename into {}: {e}", path.display()),
        )
    })
}

/// 从原始字节解析 typed 记录：serde derive 自带重复成员检测 + deny_unknown_fields
/// 精确键集；原始字节必须等于 JCS(parse(bytes))（不接受「解析后等价」）。
fn parse_canonical<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    code: &'static str,
    noun: &str,
) -> Result<T, WasmControlFailure> {
    let parsed: T = serde_json::from_slice(bytes).map_err(|e| {
        WasmControlFailure::new(
            code,
            format!("{noun} bytes do not parse as the typed record: {e}"),
        )
    })?;
    let canonical = jcs_bytes(&parsed).map_err(|e| {
        WasmControlFailure::new(
            code,
            format!("{noun} is outside the canonical JSON domain: {}", e.detail),
        )
    })?;
    if canonical != bytes {
        return Err(WasmControlFailure::new(
            code,
            format!("{noun} bytes must equal JCS(parse(bytes))"),
        ));
    }
    Ok(parsed)
}

fn write_canonical<T: Serialize>(path: &Path, record: &T) -> Result<(), WasmControlFailure> {
    let bytes = jcs_bytes(record).map_err(|e| {
        WasmControlFailure::new(
            WASM_RUNTIME_IO,
            format!("record is outside the canonical JSON domain: {}", e.detail),
        )
    })?;
    atomic_write(path, &bytes)
}

fn map_admission_error(error: AdmissionError) -> WasmControlFailure {
    WasmControlFailure::new(error.code, error.detail)
}

/// v2 中不附带业务字段的控制变更仍须经过同一 controlRevision CAS。命令 outbox
/// 使用 wasm_commands 内的专用变更器；admission/route 投影使用这个窄 helper。
fn advance_control_revision(state: &mut WasmCommandControlState) -> Result<(), WasmControlFailure> {
    if state.control_revision >= crate::wasm_admission::WASM_U53_MAX {
        return Err(WasmControlFailure::new(
            WASM_CONTROL_STATE_INVALID,
            "the wasm control revision space is exhausted",
        ));
    }
    state.control_revision += 1;
    Ok(())
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
            | crate::wasm_admission::WASM_DECLARATION_MISMATCH
            | crate::wasm_host_services::WASM_HOST_POLICY_INVALID
            | crate::wasm_host_services::WASM_HOST_POLICY_DIGEST_MISMATCH
            | crate::wasm_host_services::WASM_HOST_IDENTITY_INVALID
            | crate::wasm_host_services::WASM_GUEST_MEMORY_RESERVE_INVALID
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
    /// wasm 状态根（默认 `<路由注册表目录>/wasm`）。
    pub root: PathBuf,
    /// 路由注册表文件（kind-claim 派生源；None = 未配置路由存储，派生空 claim 集）。
    /// Some 且文件不可解析时 RouteStore::load panic-fail-closed（节点启动失败）。
    pub routes_registry: Option<PathBuf>,
}

impl WasmRuntimePaths {
    /// 生产解析：IWEB_WASM_STATE_ROOT 显式优先；否则从路由注册表路径派生；再退
    /// /data/kernel/wasm。
    pub fn resolve(routes_file: Option<&str>) -> Self {
        let routes_registry = routes_file
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let root = std::env::var(ENV_WASM_STATE_ROOT)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                routes_registry
                    .as_ref()
                    .and_then(|path| path.parent())
                    .map(|parent| {
                        if parent.as_os_str().is_empty() {
                            PathBuf::from(".").join("wasm")
                        } else {
                            parent.join("wasm")
                        }
                    })
            })
            .unwrap_or_else(|| PathBuf::from("/data/kernel/wasm"));
        Self { root, routes_registry }
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
    /// 规范控制态文件（P0-6：wasm-control-state-v2.json）。
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
    /// supervisor 读取的 admitted policy 目录。它与 Kernel 的默认 wasm root 同属
    /// `/data/kernel`，而不是 supervisor 私有 stateDirectory。
    fn admission_policy_directory(&self) -> PathBuf {
        self.root.join("admission")
    }
    fn retirements(&self) -> PathBuf {
        self.root.join("retirements.json")
    }
    fn data_root(&self) -> PathBuf {
        self.root.parent().unwrap_or(&self.root).to_path_buf()
    }
    fn secret_snapshots(&self) -> PathBuf {
        self.data_root().join("secrets").join("snapshots")
    }
    fn secret_snapshot_index(&self) -> PathBuf {
        self.data_root().join("secrets").join("snapshot-index-v1")
    }
    fn config_snapshots(&self) -> PathBuf {
        self.data_root().join("config").join("snapshots")
    }
    fn config_snapshot_index(&self) -> PathBuf {
        self.data_root().join("config").join("snapshot-index-v1")
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
        || prefix
            .split('/')
            .any(|segment| segment.is_empty() || segment.contains('\\') || segment.contains(':'));
    if invalid {
        return Err(AdmissionError::new(
            crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
            format!("object prefix {prefix} is not a safe admission-object prefix"),
        ));
    }
    Ok(root.join(prefix))
}

fn admission_io_error(detail: String) -> AdmissionError {
    AdmissionError::new(
        crate::wasm_admission::WASM_ADMISSION_OBJECT_WRITE_FAILED,
        detail,
    )
}

/// 内容寻址对象存储：`<objects>/<prefix>/blobs/<hex>` + `<objects>/<prefix>/completion-marker.json`。
pub struct FileAdmissionObjects {
    root: PathBuf,
}

impl FileAdmissionObjects {
    pub fn open(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
}

impl AdmissionObjectStore for FileAdmissionObjects {
    fn write_blob(
        &mut self,
        prefix: &str,
        digest_hex: &str,
        bytes: &[u8],
    ) -> Result<(), AdmissionError> {
        // 内容寻址防御：文件名必须等于内容的 sha256（trait 契约；事务层已验）。
        if sha256_hex(bytes) != digest_hex {
            return Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
                format!("blob {digest_hex} does not hash to its content address"),
            ));
        }
        let directory = safe_prefix(&self.root, prefix)?.join("blobs");
        std::fs::create_dir_all(&directory).map_err(|e| {
            admission_io_error(format!("cannot create {}: {e}", directory.display()))
        })?;
        let target = directory.join(digest_hex);
        let temporary = directory.join(format!(
            "{digest_hex}.tmp-{}",
            crate::monitor::now_millis() % 1_000_000
        ));
        std::fs::write(&temporary, bytes)
            .map_err(|e| admission_io_error(format!("cannot write blob: {e}")))?;
        std::fs::rename(&temporary, &target)
            .map_err(|e| admission_io_error(format!("cannot store blob {digest_hex}: {e}")))
    }

    fn write_completion_marker(
        &mut self,
        prefix: &str,
        marker_bytes: &[u8],
    ) -> Result<(), AdmissionError> {
        let directory = safe_prefix(&self.root, prefix)?;
        std::fs::create_dir_all(&directory).map_err(|e| {
            admission_io_error(format!("cannot create {}: {e}", directory.display()))
        })?;
        let target = directory.join("completion-marker.json");
        let temporary = directory.join(format!(
            "completion-marker.json.tmp-{}",
            crate::monitor::now_millis() % 1_000_000
        ));
        std::fs::write(&temporary, marker_bytes)
            .map_err(|e| admission_io_error(format!("cannot write completion marker: {e}")))?;
        std::fs::rename(&temporary, &target)
            .map_err(|e| admission_io_error(format!("cannot store completion marker: {e}")))
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
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            if name.contains(".tmp-") {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_OBJECT_CORRUPT,
                    format!("residual temporary blob {name} in the object prefix"),
                ));
            }
            let bytes = std::fs::read(&path)
                .map_err(|e| admission_io_error(format!("cannot read blob {name}: {e}")))?;
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
        safe_prefix(&self.root, prefix)
            .ok()
            .and_then(|directory| std::fs::read(directory.join("completion-marker.json")).ok())
    }

    fn remove_prefix(&mut self, prefix: &str) -> Result<(), AdmissionError> {
        let directory = safe_prefix(&self.root, prefix)?;
        if directory.exists() {
            std::fs::remove_dir_all(&directory).map_err(|e| {
                admission_io_error(format!("cannot remove {}: {e}", directory.display()))
            })?;
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

fn decode_stored_bytes(
    encoded: &str,
    code: &'static str,
    noun: &str,
) -> Result<Vec<u8>, AdmissionError> {
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
            Ok(bytes) if bytes.is_empty() => AdmissionDbFile {
                schema_version: 1,
                rows: BTreeMap::new(),
            },
            Ok(bytes) => {
                let parsed: AdmissionDbFile = serde_json::from_slice(&bytes).map_err(|e| {
                    AdmissionError::new(
                        crate::wasm_admission::WASM_ADMISSION_DB_WRITE_FAILED,
                        format!("the admission db file does not parse: {e}"),
                    )
                })?;
                if parsed.schema_version != 1 {
                    return Err(AdmissionError::new(
                        crate::wasm_admission::WASM_ADMISSION_DB_WRITE_FAILED,
                        "the admission db file must be schemaVersion 1",
                    ));
                }
                parsed
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AdmissionDbFile {
                schema_version: 1,
                rows: BTreeMap::new(),
            },
            Err(e) => {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_DB_WRITE_FAILED,
                    format!("cannot read the admission db file {}: {e}", path.display()),
                ))
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    fn persist(&self) -> Result<(), AdmissionError> {
        let bytes = jcs_bytes(&self.file)?;
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
        std::fs::write(&temporary, &bytes)
            .map_err(|e| admission_io_error(format!("cannot write the admission db file: {e}")))?;
        std::fs::rename(&temporary, &self.path)
            .map_err(|e| admission_io_error(format!("cannot store the admission db file: {e}")))
    }
}

impl AdmissionControlDb for FileAdmissionDb {
    fn insert_hidden_row(
        &mut self,
        key: &(String, String),
        row_bytes: &[u8],
        proof_jcs: &[u8],
    ) -> Result<(), AdmissionError> {
        let stored = key_to_string(key)?;
        if let Some(encoded) = self.file.rows.get(&stored).cloned() {
            let existing = decode_stored_bytes(
                &encoded,
                crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                "the admission db row",
            )?;
            let parsed: crate::wasm_admission::AdmissionDbRow = serde_json::from_slice(&existing)
                .map_err(|e| {
                AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                    format!("the stored admission db row does not parse: {e}"),
                )
            })?;
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
        self.file.rows.insert(
            stored,
            base64::engine::general_purpose::STANDARD.encode(row_bytes),
        );
        self.persist()
    }

    fn flip_hidden_to_visible(
        &mut self,
        key: &(String, String),
        proof_jcs: &[u8],
    ) -> Result<bool, AdmissionError> {
        let stored = key_to_string(key)?;
        let encoded = self.file.rows.get(&stored).cloned().ok_or_else(|| {
            AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                "the admission db row is missing during the visibility CAS",
            )
        })?;
        let existing = decode_stored_bytes(
            &encoded,
            crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
            "the admission db row",
        )?;
        let mut parsed: crate::wasm_admission::AdmissionDbRow = serde_json::from_slice(&existing)
            .map_err(|e| {
            AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_DB_CONFLICT,
                format!("the stored admission db row does not parse: {e}"),
            )
        })?;
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
                self.file.rows.insert(
                    stored,
                    base64::engine::general_purpose::STANDARD.encode(&bytes),
                );
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
        self.file.rows.get(&stored).and_then(|encoded| {
            decode_stored_bytes(
                encoded,
                crate::wasm_admission::WASM_ADMISSION_FAIL_CLOSED,
                "the admission db row",
            )
            .ok()
        })
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
            .filter_map(|stored| {
                stored
                    .split_once(':')
                    .map(|(app, version)| (app.to_string(), version.to_string()))
            })
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
            Ok(bytes) if bytes.is_empty() => AdmissionReceiptsFile {
                schema_version: 1,
                receipts: BTreeMap::new(),
            },
            Ok(bytes) => {
                let parsed: AdmissionReceiptsFile =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        AdmissionError::new(
                            crate::wasm_admission::WASM_ADMISSION_HANDOFF_FAILED,
                            format!("the admission receipt file does not parse: {e}"),
                        )
                    })?;
                if parsed.schema_version != 1 {
                    return Err(AdmissionError::new(
                        crate::wasm_admission::WASM_ADMISSION_HANDOFF_FAILED,
                        "the admission receipt file must be schemaVersion 1",
                    ));
                }
                parsed
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AdmissionReceiptsFile {
                schema_version: 1,
                receipts: BTreeMap::new(),
            },
            Err(e) => {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_HANDOFF_FAILED,
                    format!(
                        "cannot read the admission receipt file {}: {e}",
                        path.display()
                    ),
                ))
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    fn persist(&self) -> Result<(), AdmissionError> {
        let bytes = jcs_bytes(&self.file)?;
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
        std::fs::write(&temporary, &bytes).map_err(|e| {
            admission_io_error(format!("cannot write the admission receipt file: {e}"))
        })?;
        std::fs::rename(&temporary, &self.path).map_err(|e| {
            admission_io_error(format!("cannot store the admission receipt file: {e}"))
        })
    }
}

impl AdmissionMaterializer for FileAdmissionMaterializer {
    fn handoff(
        &mut self,
        key: &(String, String),
        receipt_bytes: &[u8],
        target: &str,
    ) -> Result<(), AdmissionError> {
        // 防御：receipt 必须解析为 typed 记录且 materializationTarget 等于 proof 公式。
        let parsed: crate::wasm_admission::MaterializerReceipt =
            serde_json::from_slice(receipt_bytes).map_err(|e| {
                AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH,
                    format!("the materializer receipt does not parse: {e}"),
                )
            })?;
        let proof_jcs = crate::wasm_admission::proof_jcs_bytes(&parsed.proof)?;
        if parsed.schema_version != 1
            || parsed.materialization_target
                != crate::wasm_admission::materialization_target(&proof_jcs)
            || parsed.materialization_target != target
        {
            return Err(AdmissionError::new(
                crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH,
                "the materializer receipt does not match the proof-derived materialization target",
            ));
        }
        let stored = key_to_string(key)?;
        if let Some(encoded) = self.file.receipts.get(&stored).cloned() {
            let existing = decode_stored_bytes(
                &encoded,
                crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH,
                "the materializer receipt",
            )?;
            if existing != receipt_bytes {
                return Err(AdmissionError::new(
                    crate::wasm_admission::WASM_ADMISSION_RECEIPT_MISMATCH,
                    "a different receipt already exists for this version",
                ));
            }
            return Ok(());
        }
        self.file.receipts.insert(
            stored,
            base64::engine::general_purpose::STANDARD.encode(receipt_bytes),
        );
        self.persist()
    }

    fn receipt_bytes(&self, key: &(String, String)) -> Option<Vec<u8>> {
        let stored = key_to_string(key).ok()?;
        self.file.receipts.get(&stored).and_then(|encoded| {
            decode_stored_bytes(
                encoded,
                crate::wasm_admission::WASM_ADMISSION_FAIL_CLOSED,
                "the materializer receipt",
            )
            .ok()
        })
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
        Self {
            path: path.to_path_buf(),
        }
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
        let temporary = self
            .path
            .with_extension(format!("tmp-{}", crate::monitor::now_millis() % 1_000_000));
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
        Self {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            applications: BTreeMap::new(),
        }
    }
}

/// 一个 preparation 的 secret values FD 内容。值仅存于 Kernel 私有 source 文件；
/// 该 shape 没有 `schemaVersion`，因为它就是规范定义的 digest-input payload。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct SecretSnapshotValuesPayloadV1 {
    #[serde(rename = "applicationId")]
    application_id: String,
    #[serde(rename = "versionId")]
    version_id: String,
    #[serde(rename = "preparationGeneration")]
    preparation_generation: u64,
    #[serde(rename = "secretRevision")]
    secret_revision: u64,
    keys: Vec<String>,
    values: BTreeMap<String, String>,
}

/// 公开于 raw handoff 前的 opaque ref index。source bytes 的路径由 ref 派生，不进入
/// supervisor command；index 与 source 都只由 Kernel 解析和写入。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct SecretSnapshotRefV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    kind: String,
    #[serde(rename = "ref")]
    reference: String,
    #[serde(rename = "applicationId")]
    application_id: String,
    #[serde(rename = "versionId")]
    version_id: String,
    #[serde(rename = "preparationGeneration")]
    preparation_generation: u64,
    #[serde(rename = "secretRevision")]
    secret_revision: u64,
    #[serde(rename = "valuesDigest")]
    values_digest: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct SecretSnapshotRefPreimageV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    kind: String,
    #[serde(rename = "applicationId")]
    application_id: String,
    #[serde(rename = "versionId")]
    version_id: String,
    #[serde(rename = "preparationGeneration")]
    preparation_generation: u64,
    #[serde(rename = "secretRevision")]
    secret_revision: u64,
    #[serde(rename = "valuesDigest")]
    values_digest: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ConfigSnapshotRefV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    kind: String,
    #[serde(rename = "ref")]
    reference: String,
    #[serde(rename = "applicationId")]
    application_id: String,
    #[serde(rename = "versionId")]
    version_id: String,
    #[serde(rename = "preparationGeneration")]
    preparation_generation: u64,
    #[serde(rename = "configRevision")]
    config_revision: u64,
    #[serde(rename = "valuesDigest")]
    values_digest: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

/// Snapshot FD 是短时交接权，而不是 version 生命周期 TTL。当前 capability record
/// 未在 Kernel 装载时暴露 preparation lease，因此这个上限仅用于 handoff/replay；
/// activation 仍需自己的 readiness lease CAS。
const SNAPSHOT_HANDOFF_TTL_MILLIS: u64 = 300_000;

/// readiness lease 台账（gateway v2 探针是唯一写者；本模块只读 + 结构校验）。
/// 第四轮复审：值为版本联合租约（V1 字节形状不变；V2/service-enabled 行携带
/// hostServicePolicyDigest 的 ServiceReadinessLeaseV2）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReadinessLeasesFileV1 {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "runtimeKind")]
    runtime_kind: String,
    leases: BTreeMap<String, ServiceReadinessLeaseV2>,
}

impl ReadinessLeasesFileV1 {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            leases: BTreeMap::new(),
        }
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
            return Err(WasmControlFailure::new(
                WASM_STATE_UNAVAILABLE,
                "the gate node identity file must be schemaVersion 1 with runtimeKind wasm",
            ));
        }
        if !crate::wasm_publication::WASM_RUNTIME_ARCHITECTURES
            .contains(&value.architecture.as_str())
        {
            return Err(WasmControlFailure::new(
                WASM_STATE_UNAVAILABLE,
                "the gate node identity architecture must be linux/amd64 or linux/arm64",
            ));
        }
        if value.capability_record_revision == 0
            || value.capability_record_revision > crate::wasm_admission::WASM_U53_MAX
        {
            return Err(WasmControlFailure::new(
                WASM_STATE_UNAVAILABLE,
                "the gate node identity capabilityRecordRevision must be a u53 >= 1",
            ));
        }
        if value.catalog_revision == 0
            || value.catalog_revision > crate::wasm_admission::WASM_U53_MAX
        {
            return Err(WasmControlFailure::new(
                WASM_STATE_UNAVAILABLE,
                "the gate node identity catalogRevision must be a u53 >= 1",
            ));
        }
        if !sha256_ok(&value.capability_record_hash) || !sha256_ok(&value.catalog_hash) {
            return Err(WasmControlFailure::new(
                WASM_STATE_UNAVAILABLE,
                "the gate node identity hashes must be 64 lower-case hex characters",
            ));
        }
        let image_hex = value
            .catalog_entry
            .image_digest
            .strip_prefix("sha256:")
            .unwrap_or("");
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
        Self {
            schema_version: ROUTE_REGISTRY_SCHEMA_VERSION,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            proofs: Vec::new(),
            lifecycles: BTreeMap::new(),
            retirements: Vec::new(),
            journal_head_hint: 0,
        }
    }
}

/// 业务 registry 文件当前写出的 schema 版本（读取兼容 1/2）。
pub const ROUTE_REGISTRY_SCHEMA_VERSION: u64 = 2;

// ---------------------------------------------------------------------------
// wasm-control-state-v2.json：规范形状（schema 2 + outbox/controlRevision CAS；
// two-tier-runtime-trust：celld-control-state-v1 migration 分区已删除）
// 对位 packages/contracts/wasm-execution.ts WasmControlStateFileV2 与 TS store。
// ---------------------------------------------------------------------------

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
/// P0-3：V2（service-enabled）版本行携带 hostServicePolicyDigest 静态摘要
///（policy digest + envelope + profile 字面量 + 启用服务）；V1 行不携带该键
///（skip_serializing_if 保证 V1 字节形状不变）。
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
    #[serde(rename = "hostServicePolicySummary", skip_serializing_if = "Option::is_none")]
    pub host_service_policy_summary: Option<crate::wasm_host_services::ControlStateServicePolicySummaryV2>,
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
            host_service_policy_summary: row.host_service_policy_summary.clone(),
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
}

impl WasmControlStateFileV2 {
    pub fn empty() -> Self {
        Self {
            schema_version: 2,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: 0,
            applications: BTreeMap::new(),
            command_outbox: Vec::new(),
        }
    }

    /// 结构 + 跨字段校验（TS validateWasmControlStateFileV2 的 Kernel 侧对位：
    /// 精确键集由 serde deny_unknown_fields 承担；这里做行/指针/outbox 耦合律）。
    pub fn validate(&self) -> Result<(), WasmControlFailure> {
        let invalid = |detail: String| WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, detail);
        if self.schema_version != 2 || self.runtime_kind != RUNTIME_KIND_WASM {
            return Err(invalid(
                "the wasm control state must be schemaVersion 2 with runtimeKind wasm".into(),
            ));
        }
        if self.control_revision > crate::wasm_admission::WASM_U53_MAX {
            return Err(invalid("controlRevision must be a u53 integer".into()));
        }
        let application_pattern = regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
            .expect("application id regex");
        for (key, record) in &self.applications {
            if !application_pattern.is_match(key)
                || record.application_id != *key
                || record.runtime_kind != RUNTIME_KIND_WASM
            {
                return Err(invalid(format!(
                    "application record {key} must be keyed by its wasm applicationId"
                )));
            }
            let mut seen = BTreeSet::new();
            for row in &record.versions {
                if !seen.insert(row.version_id.clone()) {
                    return Err(invalid(format!(
                        "application {key} carries duplicate versionId {}",
                        row.version_id
                    )));
                }
                if crate::wasm_admission::compose_wasm_version_id(
                    &row.identity.digest,
                    row.identity.sequence,
                ) != row.version_id
                {
                    return Err(invalid(format!(
                        "versionId {} must be the proof's complete digest-sequence label",
                        row.version_id
                    )));
                }
                if row.identity.application_id != *key {
                    return Err(invalid(format!(
                        "version {}/identity must belong to the same application",
                        row.version_id
                    )));
                }
                if row.admission_proof_ref != format!("admission-proof/{key}/{}", row.version_id) {
                    return Err(invalid(format!(
                        "version {} carries a wrong admissionProofRef",
                        row.version_id
                    )));
                }
                if row.normalized_policy.name != *key {
                    return Err(invalid(format!(
                        "version {} normalizedPolicy.name must equal the record applicationId",
                        row.version_id
                    )));
                }
                // P0-3：V2 版本行的 hostServicePolicyDigest 静态摘要结构校验
                //（policy digest hex、profile 字面量、至少一个启用服务）。
                if let Some(summary) = &row.host_service_policy_summary {
                    summary.validate().map_err(|failure| {
                        invalid(format!(
                            "version {} hostServicePolicySummary is invalid: {}",
                            row.version_id, failure
                        ))
                    })?;
                }
                if matches!(row.lifecycle.as_str(), "ready" | "active")
                    && row.readiness_lease_digest.is_none()
                {
                    return Err(invalid(format!(
                        "a ready or active candidate ({}) must carry a readiness lease digest",
                        row.version_id
                    )));
                }
            }
            match &record.active {
                WasmActivePointerV1::Active {
                    application_id,
                    version_id,
                    identity,
                    runtime_binding,
                    admission_proof_ref,
                    admission_proof_digest,
                    route_generation,
                    ..
                } => {
                    if application_id != key {
                        return Err(invalid(format!(
                            "application {key} active pointer belongs to another application"
                        )));
                    }
                    if *route_generation != record.route_generation {
                        return Err(invalid(format!("application {key} active pointer route generation must equal the record's current route generation")));
                    }
                    let Some(row) = record
                        .versions
                        .iter()
                        .find(|row| &row.version_id == version_id)
                    else {
                        return Err(invalid(format!(
                            "application {key} active pointer names no registry version"
                        )));
                    };
                    if row.identity != *identity
                        || row.runtime_binding != *runtime_binding
                        || row.admission_proof_ref != *admission_proof_ref
                        || row.admission_proof_digest != *admission_proof_digest
                    {
                        return Err(invalid(format!("application {key} active pointer identity, binding, and proof reference must match the registry version")));
                    }
                }
                WasmActivePointerV1::Unavailable {
                    application_id,
                    route_generation,
                    ..
                } => {
                    if application_id != key {
                        return Err(invalid(format!(
                            "application {key} unavailable pointer belongs to another application"
                        )));
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
                return Err(invalid(format!(
                    "outbox commandId {} must be unique",
                    entry.command_id
                )));
            }
            if entry.command_id != entry.command.command_id {
                return Err(invalid(format!(
                    "outbox commandId {} must match the wrapped command",
                    entry.command_id
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 运行时主体：启动序 + 控制面端点
// ---------------------------------------------------------------------------

/// 启动序产物：wasm 单 gate（不可变；R2 修复轮 9.7：一次评估，全准入/生命周期
/// 共用）+ 路由派生 kind-claim 状态 + 失败围栏。
pub struct WasmRuntime {
    paths: WasmRuntimePaths,
    /// wasm 单 gate 的不可变启动评估结果与已验证验收记录（v2 或 v3 一代）。
    wasm_gate: WasmPublicationGateState,
    /// 路由注册表派生的终身 celld claims（内存快照；admission 冲突预检用）。
    route_celld_claims: Vec<RuntimeKindClaimV1>,
    /// 状态不可用围栏（目录/文件损坏 → wasm 路径 503，celld 不受影响）。
    state_failure: Option<WasmControlFailure>,
    /// supervisor 执行通道 socket（IWEB_SANDBOX_SOCKET；投递闭环的传输端点）。
    execution_socket: Option<String>,
}

/// Public ingress may use only this Kernel-resolved projection.  The route
/// registry contributes an application identity, while the canonical v2
/// pointer and its live execution fence select the concrete sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmIngressTarget {
    pub application_id: String,
    pub sandbox_id: String,
    pub version_id: String,
    pub route_generation: u64,
    pub preparation_generation: u64,
    pub execution_generation: u64,
}

/// `activation-state.json` is a replay journal, never a routing authority.
/// These outcomes distinguish a single legal v2 pointer advance from an
/// already-projected event and an older journal record that v2 must ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationJournalProjection {
    Advanced,
    Settled,
    Stale,
}

impl WasmRuntime {
    /// 启动序（spec「The gate is connected at startup in this order」+
    /// 路由派生 kind claims）：
    /// (1) 独立读取并校验固定 wasm 验收记录，评估不可变 wasm 单 gate；
    /// (2) 创建状态根；(3) admission journal recovery；(4) 路由注册表 kind-claim
    /// 派生（Some 且不可解析 → RouteStore panic，节点启动失败）+ route-registry
    /// converge；(5) 一次性 v2 物化与 visible admission reconcile；(6) activation
    /// replay。该顺序保证本轮恢复推进的 visible 行无需第二次重启才能进入控制态。
    pub fn startup(
        paths: WasmRuntimePaths,
        read_bytes: &dyn Fn(&str) -> std::io::Result<Vec<u8>>,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        // 节点 pin：Kernel 拥有的固定路径投影；缺失/损坏 → None（gate fail-closed）。
        let node_pin = std::fs::read(paths.gate_node_identity())
            .ok()
            .and_then(|bytes| {
                parse_canonical::<GateNodeIdentityFileV1>(
                    &bytes,
                    WASM_STATE_UNAVAILABLE,
                    "gate node identity",
                )
                .ok()
            })
            .and_then(|file| WasmGateNodeIdentity::try_from(file).ok());
        let switches = GateEnvironmentView::from_lookup(env_lookup);
        // R2 修复轮 9.7：启动只评估一次 wasm 单 gate（固定路径的 v2/v3 一代记录）；
        // 所有 wasm 准入/生命周期共用该结果，无代际分选。
        let wasm_gate = evaluate_wasm_publication_gate_from_reader(read_bytes, &switches, node_pin.as_ref());
        let execution_socket = crate::supervisor::fixed_supervisor_socket_path(
            env_lookup(crate::supervisor::SUPERVISOR_SOCKET_ENV).as_deref(),
        );
        let execution_socket_failure = execution_socket.as_ref().err().cloned();
        let execution_socket = execution_socket.ok().map(str::to_owned);
        let mut runtime = Self {
            paths,
            wasm_gate,
            route_celld_claims: Vec::new(),
            state_failure: None,
            execution_socket,
        };
        if let Some(detail) = execution_socket_failure {
            runtime.state_failure = Some(WasmControlFailure::new(
                crate::supervisor::SUPERVISOR_SOCKET_PATH_REJECTED,
                detail,
            ));
            return runtime;
        }
        // 状态根创建失败 → 围栏（不终止进程：celld 控制面必须继续服务）。
        if let Err(failure) = std::fs::create_dir_all(&runtime.paths.root) {
            runtime.state_failure = Some(WasmControlFailure::new(
                WASM_STATE_UNAVAILABLE,
                format!(
                    "cannot create the wasm state root {}: {failure}",
                    runtime.paths.root.display()
                ),
            ));
            return runtime;
        }
        // admission 必须先恢复。随后 route registry 才能在同一启动轮看到所有 visible
        // witness，避免过去的「恢复后还需重启一次」窗口。
        if runtime.state_failure.is_none() {
            if let Err(failure) = run_admission_recovery(&runtime.paths, now_millis_u64()) {
                runtime.state_failure = Some(failure);
            }
        }
        // 路由派生 kind claims + 幂等重放 + visible witness 的 route-registry converge。
        // 路由文件不可解析时 RouteStore::load panic（节点启动失败；无 pending 模式）。
        if runtime.state_failure.is_none() {
            if let Err(failure) = runtime.run_route_claim_derivation() {
                runtime.state_failure = Some(failure);
            }
        }
        // P0-6：schema-1 命令控制文件 → 规范 wasm-control-state-v2.json 一次性物化
        //（V2 已存在时零写入；迁移语义按契约 migration not-started 起步）。
        if runtime.state_failure.is_none() {
            if let Err(failure) = runtime.materialize_legacy_command_control() {
                eprintln!(
                    "iweb-kernel: wasm legacy control state migration failed: [{}] {}",
                    failure.code, failure.detail
                );
                runtime.state_failure = Some(failure);
            }
        }
        if runtime.state_failure.is_none() {
            if let Err(failure) = runtime.materialize_control_state_if_missing() {
                runtime.state_failure = Some(failure);
            }
        }
        if runtime.state_failure.is_none() {
            if let Err(failure) = runtime.reconcile_visible_admissions_into_control_state() {
                runtime.state_failure = Some(failure);
            }
        }
        if runtime.state_failure.is_none() {
            if let Err(failure) = runtime.reconcile_visible_execution_state(now_millis_u64()) {
                runtime.state_failure = Some(failure);
            }
        }
        // activation recovery：不确定提交按 repair_uncertain_activation 裁决。随后把
        // 已修复的 route event 投影进同一 v2 CAS 载体，令本轮恢复即可打开有效路由。
        if runtime.state_failure.is_none() {
            let io = FileActivationStateIO::open(&runtime.paths.activation_state());
            if let Err(failure) = WasmActivationStore::new(Box::new(io)).recover() {
                runtime.state_failure = Some(WasmControlFailure::new(failure.code, failure.detail));
            }
        }
        if runtime.state_failure.is_none() {
            if let Err(failure) = runtime.sync_lifecycle_after_activation(now_millis_u64()) {
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

    /// wasm gate 的不可变启动评估结果（status 投影与端点选择共用；R2 修复轮 9.7：
    /// 单 gate，全准入/生命周期共用）。
    pub fn wasm_gate(&self) -> &GateResultV1 {
        &self.wasm_gate.result
    }

    /// 已验证的验收记录（admission 提交侧与请求 pin 逐字段绑定的权威输入）。
    pub fn verified_acceptance_record(&self) -> Option<&VerifiedWasmAcceptanceRecord> {
        self.wasm_gate.record.as_ref()
    }

    /// wasm gate 的选择响应（/v1/status.wasmPublication 投影同一形状）。
    /// select_publication_gate 对 "wasm" 恒成功；Err 分支仅类型完备（保持关闭）。
    pub fn wasm_gate_selection(&self) -> GateSelectionResponseV1 {
        select_publication_gate(RUNTIME_KIND_WASM, &self.wasm_gate.result).unwrap_or(GateSelectionResponseV1 {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            enabled: false,
            reasons: Vec::new(),
        })
    }

    /// 路由注册表派生的终身 celld claims（只读投影；冲突预检与 status 投影用）。
    pub fn route_celld_claims(&self) -> &[RuntimeKindClaimV1] {
        &self.route_celld_claims
    }

    /// R2 修复轮 9.9b：用户路由 sandbox 目标法——appName 必须是规范控制态
    /// （wasm-control-state-v2）中已存在（admitted 过）的 applicationId。
    /// Err = wasm 状态围栏/控制态不可读（调用方 503，无法证明准入事实）；
    /// Ok(false) = 未准入（调用方 409 WASM_APPLICATION_NOT_ADMITTED）。
    pub fn require_admitted_application(&self, application_id: &str) -> Result<bool, WasmControlFailure> {
        if let Some(failure) = &self.state_failure {
            return Err(failure.clone());
        }
        let (.., applications) = self.load_control_state()?;
        Ok(applications.contains_key(application_id))
    }

    /// 路由派生 kind claims + 已持久化 proof 幂等重放 + 恢复一致性扫描（启动期一次）。
    /// 无 digest 重验证链：celld-app 路由是镜像种子，运行期不可变更。
    fn run_route_claim_derivation(&mut self) -> Result<(), WasmControlFailure> {
        let derived = derive_route_celld_claims(&self.paths)?;
        let mut store =
            KindRegistryStoreDir::open(&self.paths.kind_registry()).map_err(map_kind_error)?;
        let mut registry = WasmKernelRouteRegistryV1::load(&store).map_err(map_kind_error)?;
        registry
            .merge_route_derived_claims(&mut store, &derived)
            .map_err(map_kind_error)?;
        // P0-5 跨存储恢复窗口收敛：admission DB 的 visible 行是 witness 权威——
        // witness→kind registry→route registry 任一步此前中断时，启动从这里幂等
        // 补写到完成（registry 文件缺行则补行 + kind claim；已齐则零写入）。
        self.converge_route_registry_from_admission(&mut store, &mut registry)?;
        // 幂等重放已持久化 proof（claim 已存在时零写入），再跑恢复一致性扫描
        //（孤儿 claim/row quarantine；split-brain fail-closed）。
        for proof in &self.load_admitted_visible_proofs()? {
            registry
                .register_wasm_admission(&mut store, registry.registry_revision(), proof)
                .map_err(map_kind_error)?;
        }
        let celld_ids: Vec<String> = derived
            .iter()
            .map(|claim| claim.application_id.clone())
            .collect();
        registry
            .recover(&mut store, &celld_ids, &[])
            .map_err(map_kind_error)?;
        self.route_celld_claims = derived;
        Ok(())
    }

    /// P0-5：只扫描完整 `AdmittedVisible` witness，把缺失 proof 收敛进 route
    /// registry 文件与 kind registry。DB 的 `visibility:"visible"` 本身不足以
    /// 赋予 route 资格；任何缺 marker/receipt/byte identity 的行均 fail-closed。
    fn converge_route_registry_from_admission(
        &self,
        store: &mut KindRegistryStoreDir,
        registry: &mut WasmKernelRouteRegistryV1,
    ) -> Result<(), WasmControlFailure> {
        let mut registry_file = self.load_route_registry()?;
        let mut dirty = false;
        for proof in &self.load_admitted_visible_proofs()? {
            // kind registry 注册幂等（claim 已存在且同 kind 时零写入）。
            registry
                .register_wasm_admission(store, registry.registry_revision(), proof)
                .map_err(map_kind_error)?;
            if !registry_file
                .proofs
                .iter()
                .any(|candidate| candidate.version_id == proof.version_id)
            {
                registry_file.proofs.push(proof.clone());
                registry_file
                    .lifecycles
                    .entry(proof.version_id.clone())
                    .or_insert_with(|| "admitted".into());
                dirty = true;
            }
        }
        if dirty {
            self.save_route_registry(&registry_file)?;
        }
        Ok(())
    }

    fn load_route_registry(&self) -> Result<WasmRouteRegistryFile, WasmControlFailure> {
        match std::fs::read(self.paths.route_registry()) {
            Ok(bytes) if bytes.is_empty() => Ok(WasmRouteRegistryFile::fresh()),
            Ok(bytes) => {
                let parsed = parse_canonical::<WasmRouteRegistryFile>(
                    &bytes,
                    WASM_RUNTIME_IO,
                    "wasm route registry",
                )?;
                if parsed.schema_version == 1 {
                    // v1 兼容读（无 retirements/journal_head_hint；下次写入升级为 v2）。
                    if parsed.runtime_kind != RUNTIME_KIND_WASM {
                        return Err(WasmControlFailure::new(
                            WASM_RUNTIME_IO,
                            "the wasm route registry must carry runtimeKind wasm",
                        ));
                    }
                    return Ok(WasmRouteRegistryFile {
                        schema_version: ROUTE_REGISTRY_SCHEMA_VERSION,
                        runtime_kind: parsed.runtime_kind,
                        proofs: parsed.proofs,
                        lifecycles: parsed.lifecycles,
                        retirements: Vec::new(),
                        journal_head_hint: 0,
                    });
                }
                if parsed.schema_version != ROUTE_REGISTRY_SCHEMA_VERSION
                    || parsed.runtime_kind != RUNTIME_KIND_WASM
                {
                    return Err(WasmControlFailure::new(WASM_RUNTIME_IO, "the wasm route registry must be schemaVersion 1 or 2 with runtimeKind wasm"));
                }
                for proof in &parsed.proofs {
                    verify_admission_proof(proof).map_err(|e| {
                        WasmControlFailure::new(
                            e.code,
                            format!("a persisted admission proof is invalid: {}", e.detail),
                        )
                    })?;
                }
                Ok(parsed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(WasmRouteRegistryFile::fresh())
            }
            Err(e) => Err(WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!(
                    "cannot read the wasm route registry {}: {e}",
                    self.paths.route_registry().display()
                ),
            )),
        }
    }

    fn save_route_registry(&self, file: &WasmRouteRegistryFile) -> Result<(), WasmControlFailure> {
        write_canonical(&self.paths.route_registry(), file)
    }

    /// P0-6 控制态装载：v2 文件存在时 applications 是唯一控制权威，绝不再由
    /// registry / activation / fence side files 反向派生。只有 v2 尚未存在的升级
    /// 窗口才允许一次 legacy 投影，随后由 materialize_control_state_if_missing 固化。
    fn load_control_state(
        &self,
    ) -> Result<
        (
            WasmCommandControlState,
            WasmRouteRegistryFile,
            BTreeMap<String, WasmApplicationControlRecordV1>,
        ),
        WasmControlFailure,
    > {
        let mut registry_file = self.load_route_registry()?;
        match std::fs::read(self.paths.control_state()) {
            Ok(bytes) if bytes.is_empty() => Ok((
                WasmCommandControlState::default(),
                registry_file.clone(),
                self.project_visible_admission_applications()?,
            )),
            Ok(bytes) => {
                let parsed = parse_canonical::<WasmControlStateFileV2>(
                    &bytes,
                    WASM_CONTROL_STATE_INVALID,
                    "wasm control state",
                )?;
                parsed.validate()?;
                Ok((
                    WasmCommandControlState {
                        control_revision: parsed.control_revision,
                        command_outbox: parsed.command_outbox.clone(),
                        retirements: registry_file.retirements.clone(),
                    },
                    registry_file,
                    parsed.applications,
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // 迁移源：schema-1 命令控制文件（J 批次布局）。carry 语义数据
                //（celld-control-state-v1 migration 分区已删除，不再写出）。
                match std::fs::read(self.paths.legacy_command_control()) {
                    Ok(bytes) if !bytes.is_empty() => {
                        let legacy = parse_canonical::<LegacyCommandControlFileV1>(
                            &bytes,
                            WASM_CONTROL_STATE_INVALID,
                            "legacy wasm command control state",
                        )?;
                        if legacy.schema_version != 1 || legacy.runtime_kind != RUNTIME_KIND_WASM {
                            return Err(WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, "the legacy wasm command control state must be schemaVersion 1 with runtimeKind wasm"));
                        }
                        registry_file.retirements = legacy.retirements.clone();
                        registry_file.journal_head_hint = 0;
                        Ok((
                            WasmCommandControlState {
                                control_revision: legacy.control_revision,
                                command_outbox: legacy.command_outbox.clone(),
                                retirements: legacy.retirements.clone(),
                            },
                            registry_file.clone(),
                            self.project_visible_admission_applications()?,
                        ))
                    }
                    _ => Ok((
                        WasmCommandControlState::default(),
                        registry_file.clone(),
                        self.project_visible_admission_applications()?,
                    )),
                }
            }
            Err(e) => Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                format!(
                    "cannot read the wasm control state {}: {e}",
                    self.paths.control_state().display()
                ),
            )),
        }
    }

    /// 取得跨进程 control-state 写锁。进程内 HTTP state mutex 只串行单个 Kernel，
    /// 不能保护 restart overlap 或 maintenance writer；revision 比较必须在这个锁内
    /// 完成，避免两个旧快照先后 rename 而发生静默覆盖。
    fn lock_control_state(&self) -> Result<File, WasmControlFailure> {
        std::fs::create_dir_all(&self.paths.root).map_err(|error| {
            WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!("cannot create the wasm state root for the control-state lock: {error}"),
            )
        })?;
        let lock_path = self.paths.root.join("wasm-control-state-v2.lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| {
                WasmControlFailure::new(
                    WASM_RUNTIME_IO,
                    format!(
                        "cannot open wasm control-state lock {}: {error}",
                        lock_path.display()
                    ),
                )
            })?;
        // The Kernel targets Unix hosts; LOCK_EX blocks instead of turning a legitimate
        // concurrent writer into a dropped mutation. File is released automatically on drop.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!(
                    "cannot lock wasm control state {}: {}",
                    lock_path.display(),
                    std::io::Error::last_os_error()
                ),
            ));
        }
        Ok(lock)
    }

    /// 控制态持久化：applications 从调用方的 v2 CAS 载体原样写入；registry 只接收
    /// lifecycle 审计投影，不能影响 v2 的任何字段。`expected_control_revision` 是
    /// mutation 开始时读到的磁盘头；`None` 只允许首次物化时文件确实不存在/为空。
    fn save_control_state(
        &self,
        expected_control_revision: Option<u64>,
        state: &WasmCommandControlState,
        registry_file: &WasmRouteRegistryFile,
        applications: &BTreeMap<String, WasmApplicationControlRecordV1>,
    ) -> Result<(), WasmControlFailure> {
        let file = WasmControlStateFileV2 {
            schema_version: 2,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: state.control_revision,
            applications: applications.clone(),
            command_outbox: state.command_outbox.clone(),
        };
        file.validate().map_err(|e| {
            WasmControlFailure::new(
                e.code,
                format!("the projected wasm control state is invalid: {}", e.detail),
            )
        })?;
        let _lock = self.lock_control_state()?;
        let actual_control_revision = match std::fs::read(self.paths.control_state()) {
            Ok(bytes) if bytes.is_empty() => None,
            Ok(bytes) => {
                let current = parse_canonical::<WasmControlStateFileV2>(
                    &bytes,
                    WASM_CONTROL_STATE_INVALID,
                    "wasm control state",
                )?;
                current.validate()?;
                Some(current.control_revision)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(WasmControlFailure::new(
                    WASM_RUNTIME_IO,
                    format!("cannot read the wasm control state for revision CAS: {error}"),
                ));
            }
        };
        if actual_control_revision != expected_control_revision {
            return Err(WasmControlFailure::new(
                crate::wasm_commands::CONTROL_REVISION_CONFLICT,
                format!(
                    "wasm control-state revision CAS expected {:?}, found {:?}; no bytes were written",
                    expected_control_revision, actual_control_revision
                ),
            ));
        }
        write_canonical(&self.paths.control_state(), &file)?;
        let mut registry = registry_file.clone();
        registry.retirements = state.retirements.clone();
        for record in applications.values() {
            for version in &record.versions {
                registry
                    .lifecycles
                    .insert(version.version_id.clone(), version.lifecycle.clone());
            }
        }
        self.save_route_registry(&registry)?;
        // supervisor 的 drain receipt 判据只读这个 Kernel 投影；它不携带控制态、
        // snapshot values 或 owner credential。每次 v2 CAS 后重写整个 canonical 数组，
        // 防止 supervisor 观察到过期的 retiring 事实。
        let retirement_bytes = jcs_bytes(&state.retirements)
            .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
        atomic_write(&self.paths.retirements(), &retirement_bytes)
    }

    /// 首次 v2 物化唯一允许的输入：三段 admission witness 共同证明的
    /// `AdmittedVisible` proof。route registry、activation state 与 fence 都是
    /// 下游审计/执行事实，绝不能反向铸造可见版本或 active pointer。
    fn load_admitted_visible_proofs(&self) -> Result<Vec<AdmissionProofV1>, WasmControlFailure> {
        let objects = FileAdmissionObjects::open(&self.paths.admission_objects());
        let db = FileAdmissionDb::open(&self.paths.admission_db()).map_err(map_admission_error)?;
        let materializer = FileAdmissionMaterializer::open(&self.paths.admission_receipts())
            .map_err(map_admission_error)?;
        let mut proofs = Vec::new();
        for (application_id, version_id) in db.keys() {
            if let Some(proof) =
                admitted_visible(&objects, &db, &materializer, &application_id, &version_id)
                    .map_err(map_admission_error)?
            {
                proofs.push(proof);
            }
        }
        proofs.sort_by(|left, right| left.version_id.cmp(&right.version_id));
        let mut seen = BTreeSet::new();
        for proof in &proofs {
            if !seen.insert(proof.version_id.clone()) {
                return Err(WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    format!(
                        "the admission witness set contains duplicate visible version {}",
                        proof.version_id
                    ),
                ));
            }
        }
        Ok(proofs)
    }

    fn project_visible_admission_applications(
        &self,
    ) -> Result<BTreeMap<String, WasmApplicationControlRecordV1>, WasmControlFailure> {
        let proofs = self.load_admitted_visible_proofs()?;
        let mut applications: BTreeMap<String, WasmApplicationControlRecordV1> = BTreeMap::new();
        for proof in &proofs {
            let row = project_registry_row(proof).map_err(map_admission_error)?;
            let entry = applications
                .entry(proof.application_id.clone())
                .or_insert_with(|| WasmApplicationControlRecordV1 {
                    runtime_kind: RUNTIME_KIND_WASM.into(),
                    application_id: proof.application_id.clone(),
                    versions: Vec::new(),
                    active: WasmActivePointerV1::Unavailable {
                        runtime_kind: RUNTIME_KIND_WASM.into(),
                        application_id: proof.application_id.clone(),
                        route_generation: 0,
                    },
                    route_generation: 0,
                    secret_revision: 0,
                    config_revision: 0,
                });
            entry.versions.push(WasmControlVersionRowV1::from(&row));
        }
        Ok(applications)
    }

    /// 首次落盘前把一次性的 legacy 投影固化为 v2。调用点位于 admission recovery
    /// 之后，保证同一启动轮已经变为 visible 的版本也会被纳入权威状态。
    fn materialize_control_state_if_missing(&mut self) -> Result<(), WasmControlFailure> {
        if self.paths.control_state().is_file() {
            return Ok(());
        }
        let (state, registry_file, applications) = self.load_control_state()?;
        self.save_control_state(None, &state, &registry_file, &applications)
    }

    /// 把一个已达 AdmittedVisible 的 proof 写进 v2。它不分配 execution identity；
    /// 该部分由 prepare/start reconciler 完成。相同 proof 的 retry 零写入，任何
    /// 已有 versionId 的不可变身份分歧均 fail-closed。
    fn upsert_visible_admission(
        &self,
        applications: &mut BTreeMap<String, WasmApplicationControlRecordV1>,
        proof: &AdmissionProofV1,
    ) -> Result<bool, WasmControlFailure> {
        let candidate = WasmControlVersionRowV1::from(
            &project_registry_row(proof).map_err(map_admission_error)?,
        );
        let record = applications
            .entry(proof.application_id.clone())
            .or_insert_with(|| WasmApplicationControlRecordV1 {
                runtime_kind: RUNTIME_KIND_WASM.into(),
                application_id: proof.application_id.clone(),
                versions: Vec::new(),
                active: WasmActivePointerV1::Unavailable {
                    runtime_kind: RUNTIME_KIND_WASM.into(),
                    application_id: proof.application_id.clone(),
                    route_generation: 0,
                },
                route_generation: 0,
                secret_revision: 0,
                config_revision: 0,
            });
        if record.runtime_kind != RUNTIME_KIND_WASM || record.application_id != proof.application_id
        {
            return Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "an existing v2 application record does not match the admitted wasm application",
            ));
        }
        if let Some(existing) = record
            .versions
            .iter()
            .find(|version| version.version_id == candidate.version_id)
        {
            let immutable_match = existing.identity == candidate.identity
                && existing.package_digest == candidate.package_digest
                && existing.normalized_policy == candidate.normalized_policy
                && existing.runtime_binding == candidate.runtime_binding
                && existing.admission_proof_ref == candidate.admission_proof_ref
                && existing.admission_proof_digest == candidate.admission_proof_digest
                && existing.host_service_policy_summary == candidate.host_service_policy_summary;
            if !immutable_match {
                return Err(WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "a v2 version row with the same versionId has different immutable admission facts",
                ));
            }
            return Ok(false);
        }
        record.versions.push(candidate);
        record
            .versions
            .sort_by(|left, right| left.version_id.cmp(&right.version_id));
        Ok(true)
    }

    /// v2 是控制权威，admission witness 是它唯一允许的外部补充来源。这个 reconciler
    /// 仅追加尚未出现的 immutable version 行，绝不从 registry 覆盖 lifecycle、pointer
    /// 或 generation；因此可以在启动和 admission join retry 中安全重复执行。
    fn reconcile_visible_admissions_into_control_state(&self) -> Result<(), WasmControlFailure> {
        let (mut state, registry_file, mut applications) = self.load_control_state()?;
        let expected_control_revision = state.control_revision;
        let mut changed = false;
        for proof in &self.load_admitted_visible_proofs()? {
            changed |= self.upsert_visible_admission(&mut applications, proof)?;
        }
        if changed {
            advance_control_revision(&mut state)?;
            self.save_control_state(
                Some(expected_control_revision),
                &state,
                &registry_file,
                &applications,
            )?;
        }
        Ok(())
    }

    fn load_fences_file(&self) -> Result<WasmFencesFileV1, WasmControlFailure> {
        match std::fs::read(self.paths.fences()) {
            Ok(bytes) if bytes.is_empty() => Ok(WasmFencesFileV1 {
                schema_version: 1,
                runtime_kind: RUNTIME_KIND_WASM.into(),
                applications: BTreeMap::new(),
            }),
            Ok(bytes) => {
                let parsed = parse_canonical::<WasmFencesFileV1>(
                    &bytes,
                    WASM_CONTROL_STATE_INVALID,
                    "wasm fences",
                )?;
                if parsed.schema_version != 1 || parsed.runtime_kind != RUNTIME_KIND_WASM {
                    return Err(WasmControlFailure::new(
                        WASM_CONTROL_STATE_INVALID,
                        "the wasm fences file must be schemaVersion 1 with runtimeKind wasm",
                    ));
                }
                for (application_id, fence) in &parsed.applications {
                    let current =
                        fence
                            .records
                            .get(&fence.current_version_id)
                            .ok_or_else(|| {
                                WasmControlFailure::new(
                                WASM_CONTROL_STATE_INVALID,
                                "each wasm application fence must name a current version record",
                            )
                            })?;
                    if current.version_id != fence.current_version_id || application_id.is_empty() {
                        return Err(WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, "a wasm fence record is inconsistent with its application currentVersionId"));
                    }
                    if fence
                        .records
                        .iter()
                        .any(|(version_id, record)| version_id != &record.version_id)
                    {
                        return Err(WasmControlFailure::new(
                            WASM_CONTROL_STATE_INVALID,
                            "a wasm fence record key must equal its versionId",
                        ));
                    }
                }
                Ok(parsed)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(WasmFencesFileV1 {
                schema_version: 1,
                runtime_kind: RUNTIME_KIND_WASM.into(),
                applications: BTreeMap::new(),
            }),
            Err(error) => Err(WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!("cannot read wasm fences: {error}"),
            )),
        }
    }

    fn save_fences_file(&self, file: &WasmFencesFileV1) -> Result<(), WasmControlFailure> {
        std::fs::create_dir_all(&self.paths.root).map_err(|error| {
            WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!("cannot create wasm state root for fences: {error}"),
            )
        })?;
        write_canonical(&self.paths.fences(), file)
    }

    fn persist_admission_policy(&self, proof: &AdmissionProofV1) -> Result<(), WasmControlFailure> {
        let directory = self.paths.admission_policy_directory();
        std::fs::create_dir_all(&directory).map_err(|error| {
            WasmControlFailure::new(
                WASM_RUNTIME_IO,
                format!("cannot create wasm admission policy directory: {error}"),
            )
        })?;
        let bytes = jcs_bytes(&proof.normalized_policy)
            .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
        let path = directory.join(format!("{}.json", proof.version_id));
        match std::fs::read(&path) {
            Ok(existing) if existing == bytes => Ok(()),
            Ok(_) => Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "an admitted policy file already exists with bytes different from the immutable normalized policy",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => atomic_write(&path, &bytes),
            Err(error) => Err(WasmControlFailure::new(WASM_RUNTIME_IO, format!("cannot read admitted policy file: {error}"))),
        }
    }

    fn deterministic_sandbox_id(proof: &AdmissionProofV1) -> String {
        let digest = domain_sha256_hex("iweb-wasm-sandbox-v1", proof.version_id.as_bytes());
        format!("sbx-{}", &digest[..24])
    }

    fn ensure_initial_secret_snapshot(
        &self,
        proof: &AdmissionProofV1,
        preparation_generation: u64,
        now_epoch_millis: u64,
    ) -> Result<SecretSnapshotRefV1, WasmControlFailure> {
        let values = SecretSnapshotValuesPayloadV1 {
            application_id: proof.application_id.clone(),
            version_id: proof.version_id.clone(),
            preparation_generation,
            secret_revision: 0,
            keys: Vec::new(),
            values: BTreeMap::new(),
        };
        let values_bytes = jcs_bytes(&values)
            .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
        let values_digest =
            compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &values_bytes)
                .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
        let expires_at_epoch_millis = now_epoch_millis
            .checked_add(SNAPSHOT_HANDOFF_TTL_MILLIS)
            .ok_or_else(|| {
                WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "the snapshot handoff expiry overflows epoch milliseconds",
                )
            })?;
        let expires_at = crate::wasm_admission::format_rfc3339_utc_millis(expires_at_epoch_millis);
        let preimage = SecretSnapshotRefPreimageV1 {
            schema_version: 1,
            kind: "iweb-secret-snapshot".into(),
            application_id: proof.application_id.clone(),
            version_id: proof.version_id.clone(),
            preparation_generation,
            secret_revision: 0,
            values_digest: values_digest.clone(),
            expires_at: expires_at.clone(),
        };
        let reference = domain_sha256_hex(
            "iweb-secret-snapshot-ref-v1",
            &jcs_bytes(&preimage)
                .map_err(|error| WasmControlFailure::new(error.code, error.detail))?,
        );
        let index = SecretSnapshotRefV1 {
            schema_version: 1,
            kind: "iweb-secret-snapshot".into(),
            reference: reference.clone(),
            application_id: proof.application_id.clone(),
            version_id: proof.version_id.clone(),
            preparation_generation,
            secret_revision: 0,
            values_digest,
            expires_at,
        };
        let index_directory = self.paths.secret_snapshot_index();
        let source_directory = self.paths.secret_snapshots();
        std::fs::create_dir_all(&index_directory)
            .and_then(|_| std::fs::create_dir_all(&source_directory))
            .map_err(|error| {
                WasmControlFailure::new(
                    WASM_RUNTIME_IO,
                    format!("cannot create secret snapshot directories: {error}"),
                )
            })?;
        let index_path = index_directory.join(format!("{}.json", reference));
        let source_path = source_directory.join(format!("{}.json", reference));
        match std::fs::read(&index_path) {
            Ok(existing) => {
                let parsed = parse_canonical::<SecretSnapshotRefV1>(
                    &existing,
                    WASM_CONTROL_STATE_INVALID,
                    "secret snapshot index",
                )?;
                if parsed != index {
                    return Err(WasmControlFailure::new(
                        WASM_CONTROL_STATE_INVALID,
                        "a secret snapshot ref already names different immutable facts",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_canonical(&index_path, &index)?
            }
            Err(error) => {
                return Err(WasmControlFailure::new(
                    WASM_RUNTIME_IO,
                    format!("cannot read secret snapshot index: {error}"),
                ))
            }
        }
        match std::fs::read(&source_path) {
            Ok(existing) if existing == values_bytes => {}
            Ok(_) => {
                return Err(WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "a secret snapshot source already contains different values payload bytes",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_write(&source_path, &values_bytes)?
            }
            Err(error) => {
                return Err(WasmControlFailure::new(
                    WASM_RUNTIME_IO,
                    format!("cannot read secret snapshot source: {error}"),
                ))
            }
        }
        Ok(index)
    }

    fn fence_from_planned_start(
        command: &ExecutionCommand,
        lifecycle: &str,
    ) -> WasmFenceRecordV1 {
        WasmFenceRecordV1 {
            version_id: command.identity.version_id.clone(),
            sandbox_id: command.identity.sandbox_id.clone(),
            preparation_generation: command.identity.preparation_generation,
            execution_generation: command.identity.execution_generation,
            secret_revision: command.secret_revision,
            secret_snapshot_ref: command.secret_snapshot_ref.clone(),
            secret_values_digest: command.secret_values_digest.clone(),
            config_revision: command.config_revision,
            config_snapshot_ref: command.config_snapshot_ref.clone(),
            config_values_digest: command.config_values_digest.as_deref().map(str::to_string),
            alive: false,
            lifecycle: lifecycle.into(),
            binding_revoked: false,
            drain_deadline_epoch_millis: None,
        }
    }

    /// admission visible 后的生产 execution materialization。每个新 version 获得
    /// policy、revision-0 secret snapshot、P/E fence 和严格有序的 Prepare/Start
    /// outbox。outbox 先于 HTTP 投递落盘；crash 后可由 command identity 重建 fence。
    /// P0-3 preparation gate：V2（service-enabled）证明的 reserve 交叉校验
    ///（TS checkWasmGuestMemoryReserve 对位）：guestMemoryBytes =
    /// resources.memoryBytes - reserveBytes；缺失/零替换/越界一律 fail-closed，
    /// 绝不代默认 reserve，也绝不规划 Prepare/Start。
    fn preparation_reserve_gate(proof: &AdmissionProofV1) -> Result<(), WasmControlFailure> {
        if let Some(policy) = &proof.host_service_policy {
            crate::wasm_host_services::check_wasm_guest_memory_reserve(
                proof.normalized_policy.resources.memory_bytes,
                policy.reserve_bytes,
            )
            .map_err(|failure| WasmControlFailure::new(failure.code, failure.detail))?;
        }
        Ok(())
    }

    fn reconcile_visible_execution_state(
        &mut self,
        now_epoch_millis: u64,
    ) -> Result<(), WasmControlFailure> {
        let (mut command_state, registry_file, mut applications) =
            self.load_control_state()?;
        let mut fences = self.load_fences_file()?;
        let mut fences_dirty = false;
        // Execution is downstream of visibility: route-registry proof rows are an
        // audit projection only and cannot manufacture Prepare/Start work.
        for proof in &self.load_admitted_visible_proofs()? {
            self.persist_admission_policy(proof)?;
            Self::preparation_reserve_gate(proof)?;
            let Some(application) = applications.get(&proof.application_id) else {
                return Err(WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "a visible admission is absent from canonical v2 control state",
                ));
            };
            if !application
                .versions
                .iter()
                .any(|version| version.version_id == proof.version_id)
            {
                return Err(WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "a visible admission version is absent from canonical v2 control state",
                ));
            }
            let has_fence = fences
                .applications
                .get(&proof.application_id)
                .and_then(|application| application.records.get(&proof.version_id))
                .is_some();
            if has_fence {
                continue;
            }
            // Every outbox append is its own persisted controlRevision CAS.  A
            // crash can therefore leave only Prepare or both entries durable;
            // recovery completes the missing successor rather than recreating
            // an earlier command with a new identity.
            // 第三轮复审（2026-08-28，V2 生产链）：outbox 的既有命令按版本联合扫描；
            // 命令生成按 admission 行代际分选——V2 行（proof.host_service_policy 存在）
            // 生成统一命令（带 hostServicePolicyDigest；无 policy 行为空串零值）。
            let command_matches = |entry: &&crate::wasm_commands::CommandOutboxRecord, operation: WasmExecutionOperation| {
                entry.command.operation == operation
                    && entry.command.identity.version_id == proof.version_id
                    && entry.command.package_digest == proof.package_digest
            };
            let existing_start = command_state
                .command_outbox
                .iter()
                .find(|entry| command_matches(entry, WasmExecutionOperation::Start))
                .map(|entry| entry.command.clone());
            let existing_prepare = command_state
                .command_outbox
                .iter()
                .find(|entry| command_matches(entry, WasmExecutionOperation::Prepare))
                .map(|entry| entry.command.clone());
            let fence = if let Some(start) = existing_start {
                Self::fence_from_planned_start(&start, "preparing")
            } else {
                let sandbox_id = Self::deterministic_sandbox_id(proof);
                let version_row = project_registry_row(proof).map_err(map_admission_error)?;
                // 单版本命令生成：不按 admission 行代际分选——policy 在 proof 上则携带
                // 其 digest，否则 policy 钉为空串（命令仍生成，只是不获得 host services）。
                // 同一 proof 的代际恒定（admission 行不可变）。
                let plan_uniform = |input: KernelCommandPlanInput<'_>| -> Result<ExecutionCommand, WasmControlFailure> {
                    let planned = plan_execution_command(&input)
                        .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
                    Ok(planned.command)
                };
                let prepare = if let Some(existing) = existing_prepare {
                    existing
                } else {
                    let expected = command_state.control_revision;
                    let command_time = now_epoch_millis.saturating_add(expected);
                    let snapshot =
                        self.ensure_initial_secret_snapshot(proof, 1, now_epoch_millis)?;
                    let planned = plan_uniform(
                        KernelCommandPlanInput {
                            command_id: &generate_uuid_v7(command_time),
                            operation: WasmExecutionOperation::Prepare,
                            control_revision: expected,
                            journal_head: registry_file.journal_head_hint,
                            sandbox_id: &sandbox_id,
                            application_id: &proof.application_id,
                            host_service_policy_digest: proof
                                .host_service_policy
                                .as_ref()
                                .map(|policy| policy.policy_digest.as_str()),
                            version_row: &version_row,
                            capability_record_revision: proof.capability_record_revision,
                            capability_record_hash: &proof.capability_record_hash,
                            secret_revision: snapshot.secret_revision,
                            secret_snapshot_ref: &snapshot.reference,
                            secret_values_digest: &snapshot.values_digest,
                            config_revision: 0,
                            config_snapshot_ref: None,
                            config_values_digest: None,
                            current_generations: WasmExecutionIdentityV1 {
                                sandbox_id: sandbox_id.clone(),
                                version_id: proof.version_id.clone(),
                                preparation_generation: 0,
                                execution_generation: 0,
                            },
                        },
                    )?;
                    command_state
                        .authorize_command(
                            expected,
                            planned,
                            crate::wasm_admission::format_rfc3339_utc_millis(command_time),
                        )
                        .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
                    self.save_control_state(
                        Some(expected),
                        &command_state,
                        &registry_file,
                        &applications,
                    )?;
                    command_state
                        .command_outbox
                        .last()
                        .expect("authorize_command appended the prepare entry")
                        .command
                        .clone()
                };
                let start_journal_head = registry_file
                    .journal_head_hint
                    .checked_add(2)
                    .filter(|value| *value <= crate::wasm_admission::WASM_U53_MAX)
                    .ok_or_else(|| WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, "the supervisor journal revision space is exhausted before Start planning"))?;
                let expected = command_state.control_revision;
                let command_time = now_epoch_millis.saturating_add(expected);
                // Start 沿用 prepare 的 adopted snapshot 字段（版本联合访问器；V2 命令
                // 携带同一 snapshot 面 + V2 身份增量）。
                let start = plan_uniform(
                    KernelCommandPlanInput {
                        command_id: &generate_uuid_v7(command_time),
                        operation: WasmExecutionOperation::Start,
                        control_revision: expected,
                        journal_head: start_journal_head,
                        sandbox_id: &prepare.identity.sandbox_id,
                        application_id: &proof.application_id,
                        host_service_policy_digest: proof
                            .host_service_policy
                            .as_ref()
                            .map(|policy| policy.policy_digest.as_str()),
                        version_row: &version_row,
                        capability_record_revision: proof.capability_record_revision,
                        capability_record_hash: &proof.capability_record_hash,
                        secret_revision: prepare.secret_revision,
                        secret_snapshot_ref: &prepare.secret_snapshot_ref,
                        secret_values_digest: &prepare.secret_values_digest,
                        config_revision: prepare.config_revision,
                        config_snapshot_ref: prepare.config_snapshot_ref.as_deref(),
                        config_values_digest: prepare.config_values_digest.as_deref(),
                        current_generations: prepare.identity.clone(),
                    },
                )?;
                command_state
                    .authorize_command(
                        expected,
                        start.clone(),
                        crate::wasm_admission::format_rfc3339_utc_millis(command_time),
                    )
                    .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
                if let Some(application) = applications.get_mut(&proof.application_id) {
                    if let Some(version) = application
                        .versions
                        .iter_mut()
                        .find(|version| version.version_id == proof.version_id)
                    {
                        // Start authorization and the preparing lifecycle become one
                        // control-state mutation; no virtual revision increment.
                        version.lifecycle = "preparing".into();
                    }
                }
                self.save_control_state(
                    Some(expected),
                    &command_state,
                    &registry_file,
                    &applications,
                )?;
                Self::fence_from_planned_start(&start, "preparing")
            };
            let application_fence = fences
                .applications
                .entry(proof.application_id.clone())
                .or_insert_with(|| WasmApplicationFenceV1 {
                    current_version_id: proof.version_id.clone(),
                    records: BTreeMap::new(),
                });
            application_fence.current_version_id = proof.version_id.clone();
            application_fence
                .records
                .insert(proof.version_id.clone(), fence);
            if let Some(application) = applications.get_mut(&proof.application_id) {
                if let Some(version) = application
                    .versions
                    .iter_mut()
                    .find(|version| version.version_id == proof.version_id)
                {
                    if version.lifecycle != "preparing" {
                        version.lifecycle = "preparing".into();
                        // A lifecycle projection after a Start-only crash is its own
                        // committed control mutation.
                        let expected = command_state.control_revision;
                        advance_control_revision(&mut command_state)?;
                        self.save_control_state(
                            Some(expected),
                            &command_state,
                            &registry_file,
                            &applications,
                        )?;
                    }
                }
            }
            fences_dirty = true;
        }
        if fences_dirty {
            self.save_fences_file(&fences)?;
        }
        Ok(())
    }

    fn resolve_secret_snapshot(
        &self,
        command: &ExecutionCommand,
        application_id: &str,
        now_epoch_millis: u64,
    ) -> Result<(SecretSnapshotRefV1, PathBuf), WasmControlFailure> {
        let index_path = self
            .paths
            .secret_snapshot_index()
            .join(format!("{}.json", command.secret_snapshot_ref));
        let source_path = self
            .paths
            .secret_snapshots()
            .join(format!("{}.json", command.secret_snapshot_ref));
        let bytes = std::fs::read(&index_path).map_err(|_| {
            WasmControlFailure::new(
                crate::wasm_secrets::WASM_SECRET_SNAPSHOT_REF_INVALID,
                "the command secret snapshot ref has no Kernel index record",
            )
        })?;
        let index = parse_canonical::<SecretSnapshotRefV1>(
            &bytes,
            crate::wasm_secrets::WASM_SECRET_SNAPSHOT_REF_INVALID,
            "secret snapshot index",
        )?;
        let expires_at = crate::wasm_admission::parse_rfc3339_utc_millis(&index.expires_at)
            .map_err(|_| {
                WasmControlFailure::new(
                    crate::wasm_secrets::WASM_SECRET_SNAPSHOT_REF_INVALID,
                    "the command secret snapshot ref has an invalid expiry",
                )
            })?;
        if now_epoch_millis >= expires_at {
            return Err(WasmControlFailure::new(
                "IWEB_SECRET_SNAPSHOT_EXPIRED",
                "the command secret snapshot has expired before FD handoff",
            ));
        }
        let matches = index.schema_version == 1
            && index.kind == "iweb-secret-snapshot"
            && index.reference == command.secret_snapshot_ref
            && index.application_id == application_id
            && index.version_id == command.identity.version_id
            && index.preparation_generation == command.identity.preparation_generation
            && index.secret_revision == command.secret_revision
            && index.values_digest == command.secret_values_digest;
        if !matches {
            return Err(WasmControlFailure::new(
                crate::wasm_secrets::WASM_SECRET_SNAPSHOT_REF_INVALID,
                "the command secret snapshot ref does not bind its execution tuple",
            ));
        }
        let source = std::fs::read(&source_path).map_err(|_| {
            WasmControlFailure::new(
                crate::wasm_secrets::WASM_SECRET_SNAPSHOT_REF_INVALID,
                "the command secret snapshot source is unavailable",
            )
        })?;
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &source)
            .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
        if digest != index.values_digest {
            return Err(WasmControlFailure::new(
                "SNAPSHOT_VALUES_DIGEST_MISMATCH",
                "the Kernel secret snapshot source bytes do not match the indexed values digest",
            ));
        }
        Ok((index, source_path))
    }

    fn resolve_config_snapshot(
        &self,
        command: &ExecutionCommand,
        application_id: &str,
        now_epoch_millis: u64,
    ) -> Result<Option<(ConfigSnapshotRefV1, PathBuf)>, WasmControlFailure> {
        if command.config_revision == 0 {
            return Ok(None);
        }
        let reference = command.config_snapshot_ref.as_deref().ok_or_else(|| {
            WasmControlFailure::new(
                "IWEB_CONFIG_WIRE_INVALID",
                "a non-zero config revision requires a snapshot ref before FD handoff",
            )
        })?;
        let values_digest = command.config_values_digest.as_deref().ok_or_else(|| {
            WasmControlFailure::new(
                "IWEB_CONFIG_WIRE_INVALID",
                "a non-zero config revision requires a values digest before FD handoff",
            )
        })?;
        let index_path = self
            .paths
            .config_snapshot_index()
            .join(format!("{}.json", reference));
        let source_path = self
            .paths
            .config_snapshots()
            .join(format!("{}.json", reference));
        let bytes = std::fs::read(&index_path).map_err(|_| {
            WasmControlFailure::new(
                "IWEB_CONFIG_WIRE_INVALID",
                "the command config snapshot ref has no Kernel index record",
            )
        })?;
        let index = parse_canonical::<ConfigSnapshotRefV1>(
            &bytes,
            "IWEB_CONFIG_WIRE_INVALID",
            "config snapshot index",
        )?;
        let expires_at = crate::wasm_admission::parse_rfc3339_utc_millis(&index.expires_at)
            .map_err(|_| {
                WasmControlFailure::new(
                    "IWEB_CONFIG_WIRE_INVALID",
                    "the command config snapshot ref has an invalid expiry",
                )
            })?;
        if now_epoch_millis >= expires_at {
            return Err(WasmControlFailure::new(
                "IWEB_CONFIG_SNAPSHOT_EXPIRED",
                "the command config snapshot has expired before FD handoff",
            ));
        }
        let matches = index.schema_version == 1
            && index.kind == "iweb-config-snapshot"
            && index.reference == reference
            && index.application_id == application_id
            && index.version_id == command.identity.version_id
            && index.preparation_generation == command.identity.preparation_generation
            && index.config_revision == command.config_revision
            && index.values_digest == values_digest;
        if !matches {
            return Err(WasmControlFailure::new(
                "IWEB_CONFIG_WIRE_INVALID",
                "the command config snapshot ref does not bind its execution tuple",
            ));
        }
        let source = std::fs::read(&source_path).map_err(|_| {
            WasmControlFailure::new(
                "IWEB_CONFIG_WIRE_INVALID",
                "the command config snapshot source is unavailable",
            )
        })?;
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::ConfigRequest, &source)
            .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
        if digest != index.values_digest {
            return Err(WasmControlFailure::new(
                "SNAPSHOT_VALUES_DIGEST_MISMATCH",
                "the Kernel config snapshot source bytes do not match the indexed values digest",
            ));
        }
        Ok(Some((index, source_path)))
    }

    fn resolved_supervisor_peer() -> Result<SnapshotSocketPeer, WasmControlFailure> {
        let peer = crate::supervisor::resolve_supervisor_socket_peer()
            .map_err(|error| WasmControlFailure::new(error.code, error.to_string()))?;
        Ok(SnapshotSocketPeer { uid: peer.uid, gid: peer.gid })
    }

    /// Raw FD handoff is a hard predecessor of the execution HTTP envelope. It is intentionally
    /// called for both normal delivery and replay: an accepted supervisor handoff is idempotent,
    /// while a missing/restarted relay receives the same command-bound bytes before HTTP resumes.
    fn deliver_snapshots_before_execution_with_transport(
        &self,
        command: &ExecutionCommand,
        now_epoch_millis: u64,
        peer_resolver: SnapshotPeerResolver,
        snapshot_transport: SnapshotHandoffTransport,
    ) -> Result<(), WasmControlFailure> {
        if !matches!(
            command.operation,
            WasmExecutionOperation::Prepare | WasmExecutionOperation::Start
        ) {
            return Ok(());
        }
        let visible_proofs = self.load_admitted_visible_proofs()?;
        let proof = visible_proofs
            .iter()
            .find(|proof| {
                proof.version_id == command.identity.version_id
                    && proof.package_digest == command.package_digest
            })
            .ok_or_else(|| {
                WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "an execution command names no admitted proof for snapshot handoff",
                )
            })?;
        let peer = peer_resolver()?;
        let command_digest = crate::wasm_commands::execution_command_digest(command)
            .map_err(|error| WasmControlFailure::new(error.code, error.detail))?;
        let (secret, secret_source) =
            self.resolve_secret_snapshot(command, &proof.application_id, now_epoch_millis)?;
        let secret_handoff = SnapshotHandoffPayload::Secret(SecretSnapshotFdHandoffV1 {
            schema_version: 1,
            kind: "secret".into(),
            command_id: command.command_id.clone(),
            command_digest: command_digest.clone(),
            reference: secret.reference.clone(),
            application_id: proof.application_id.clone(),
            version_id: command.identity.version_id.clone(),
            preparation_generation: command.identity.preparation_generation,
            secret_revision: command.secret_revision,
            values_digest: secret.values_digest.clone(),
            fd_digest: secret.values_digest.clone(),
            expires_at: secret.expires_at.clone(),
        });
        let secret_delivery = SnapshotHandoffDelivery {
            socket_path: Path::new(SNAPSHOT_FD_SOCKET_PATH),
            expected_owner: peer,
            handoff: secret_handoff,
            snapshot_path: &secret_source,
        };
        match snapshot_transport(&secret_delivery) {
            Ok(SnapshotDeliveryOutcome::Accepted(_)) => {}
            Ok(SnapshotDeliveryOutcome::RejectedBySupervisor(ack)) => {
                return Err(WasmControlFailure::new(
                    WASM_EXECUTION_DELIVERY_UNCERTAIN,
                    format!(
                        "the supervisor rejected the secret snapshot handoff: {}",
                        ack.failure_code
                            .unwrap_or_else(|| "SNAPSHOT_HANDOFF_REJECTED".into())
                    ),
                ));
            }
            Err(error) => return Err(WasmControlFailure::new(error.code, error.detail)),
        }
        if let Some((config, config_source)) =
            self.resolve_config_snapshot(command, &proof.application_id, now_epoch_millis)?
        {
            let config_handoff = SnapshotHandoffPayload::Config(ConfigSnapshotFdHandoffV1 {
                schema_version: 1,
                kind: "config".into(),
                command_id: command.command_id.clone(),
                command_digest,
                reference: config.reference.clone(),
                application_id: proof.application_id.clone(),
                version_id: command.identity.version_id.clone(),
                preparation_generation: command.identity.preparation_generation,
                config_revision: command.config_revision,
                values_digest: config.values_digest.clone(),
                fd_digest: config.values_digest.clone(),
                expires_at: config.expires_at.clone(),
            });
            let config_delivery = SnapshotHandoffDelivery {
                socket_path: Path::new(SNAPSHOT_FD_SOCKET_PATH),
                expected_owner: peer,
                handoff: config_handoff,
                snapshot_path: &config_source,
            };
            match snapshot_transport(&config_delivery) {
                Ok(SnapshotDeliveryOutcome::Accepted(_)) => {}
                Ok(SnapshotDeliveryOutcome::RejectedBySupervisor(ack)) => {
                    return Err(WasmControlFailure::new(
                        WASM_EXECUTION_DELIVERY_UNCERTAIN,
                        format!(
                            "the supervisor rejected the config snapshot handoff: {}",
                            ack.failure_code
                                .unwrap_or_else(|| "SNAPSHOT_HANDOFF_REJECTED".into())
                        ),
                    ));
                }
                Err(error) => return Err(WasmControlFailure::new(error.code, error.detail)),
            }
        }
        Ok(())
    }

    /// P0-6：一次性把旧 schema-1 命令控制文件物化为规范 V2 布局（V2 已存在时零写入）。
    fn materialize_legacy_command_control(&mut self) -> Result<(), WasmControlFailure> {
        if self.paths.control_state().is_file() {
            return Ok(());
        }
        if !self.paths.legacy_command_control().is_file() {
            return Ok(());
        }
        let (state, registry_file, applications) = self.load_control_state()?;
        self.save_control_state(None, &state, &registry_file, &applications)
    }

    fn load_fences(&self) -> BTreeMap<String, WasmApplicationFenceV1> {
        // fence 台账损坏 → 视为无 fence（激活判据 fail-closed），不阻断其它路径。
        std::fs::read(self.paths.fences())
            .ok()
            .and_then(|bytes| {
                parse_canonical::<WasmFencesFileV1>(&bytes, WASM_RUNTIME_IO, "wasm fences").ok()
            })
            .map(|file| file.applications)
            .unwrap_or_default()
    }

    fn load_leases(&self) -> BTreeMap<String, ServiceReadinessLeaseV2> {
        std::fs::read(self.paths.readiness_leases())
            .ok()
            .and_then(|bytes| {
                parse_canonical::<ReadinessLeasesFileV1>(
                    &bytes,
                    WASM_RUNTIME_IO,
                    "readiness leases",
                )
                .ok()
            })
            .map(|file| file.leases)
            .unwrap_or_default()
    }

    /// 激活控制态（typed 全量；facts 与 lifecycle 同步共用）。
    fn load_activation_states(&self) -> BTreeMap<String, KernelActivationState> {
        std::fs::read(self.paths.activation_state())
            .ok()
            .and_then(|bytes| {
                parse_canonical::<crate::wasm_activation::WasmActivationStateFileV1>(
                    &bytes,
                    WASM_RUNTIME_IO,
                    "activation state",
                )
                .ok()
            })
            .map(|file| file.applications)
            .unwrap_or_default()
    }

    /// 结构化 gate 前置：要求单一 wasm gate enabled（spec 启动序第 4 步；R2 修复轮
    /// 9.7：所有 wasm 准入/生命周期共用同一 gate，无代际分选）。
    fn require_wasm_gate_enabled(&self) -> Result<(), WasmHttpResponse> {
        let selection = self.wasm_gate_selection();
        if let Err(failure) = require_wasm_publication(&self.wasm_gate) {
            return Err(err_json(
                503,
                WASM_PUBLICATION_DISABLED,
                &format!("{}; reasons: {:?}", failure.detail, selection.reasons),
            ));
        }
        Ok(())
    }

    /// admission 的发布门（单 gate）+ service-enabled 请求的记录 pin 绑定：
    /// - 先要求单一 wasm gate enabled（所有请求同一门）；
    /// - V2（service-enabled）请求还必须与 gate 携带的已验证记录逐字段相等
    ///   （hostServicePolicyDigest、capability record revision/hash、catalog
    ///   revision/hash/entry key、image digest、world；matrixRevision=2 与
    ///   hostABI=1.1.0 由 v3 记录 validator 钉死）。安装的是 v2 记录（无
    ///   host-service pin）时结构性地拒绝——绝不放行未由记录证明的 service 面。
    ///
    /// 任一失配 → 结构化 fail-closed 拒绝（503 门未开 / 400 pin 失配），绝不 fallback。
    fn require_admission_publication_gate(&self, request: &AdmissionRequest) -> Result<(), WasmHttpResponse> {
        self.require_wasm_gate_enabled()?;
        let Some(policy) = request.host_service_policy.as_ref() else {
            return Ok(()); // V1 请求：无 host-service pin 需要与记录绑定
        };
        let Some(record) = self.verified_acceptance_record() else {
            return Err(err_json(
                503,
                WASM_PUBLICATION_DISABLED,
                "an enabled gate must carry the verified acceptance record",
            ));
        };
        let VerifiedWasmAcceptanceRecord::V3(record) = record else {
            return Err(err_json(
                503,
                WASM_PUBLICATION_DISABLED,
                "the installed acceptance record is not service-enabled; service-enabled admission requires the v3 record",
            ));
        };
        let mismatch = |detail: String| err_json(400, WASM_ADMISSION_NODE_PIN_MISMATCH, &detail);
        let binding = &request.runtime_binding;
        let mut fields = Vec::new();
        if record.host_service_policy_digest != policy.policy_digest {
            fields.push("hostServicePolicyDigest");
        }
        if record.capability_record_revision != request.capability_record_revision {
            fields.push("capabilityRecordRevision");
        }
        if record.capability_record_hash != request.capability_record_hash {
            fields.push("capabilityRecordHash");
        }
        if record.catalog_revision != binding.catalog_revision {
            fields.push("runtimeBinding.catalogRevision");
        }
        if record.catalog_hash != binding.catalog_hash {
            fields.push("runtimeBinding.catalogHash");
        }
        if record.catalog_entry_key != binding.entry_key {
            fields.push("runtimeBinding.entryKey");
        }
        if record.runtime_image_digest != binding.image_digest {
            fields.push("runtimeBinding.imageDigest");
        }
        if record.world != binding.world {
            fields.push("runtimeBinding.world");
        }
        if fields.is_empty() {
            Ok(())
        } else {
            Err(mismatch(format!(
                "the v3 acceptance record does not bind this service-enabled admission identity: {}",
                fields.join(", ")
            )))
        }
    }

    /// P0-4：admission 的 runtimeBinding/capability pin 与当前节点身份逐字段相等校验。
    /// 节点 pin 权威是 Kernel 拥有的固定路径 gate-node-identity.json；缺失/损坏/
    /// 任一字段不等（catalog revision/hash、entry key、image digest、host ABI、
    /// world、capability record revision/hash）→ 结构化 fail-closed 拒绝（400），
    /// 绝不推断默认 pin 或部分匹配。
    fn verify_admission_node_identity(
        &self,
        request: &AdmissionRequest,
    ) -> Result<(), WasmHttpResponse> {
        let mismatch = |detail: String| err_json(400, WASM_ADMISSION_NODE_PIN_MISMATCH, &detail);
        let pin = match std::fs::read(self.paths.gate_node_identity()) {
            Ok(bytes) => match parse_canonical::<GateNodeIdentityFileV1>(
                &bytes,
                WASM_STATE_UNAVAILABLE,
                "gate node identity",
            ) {
                Ok(file) => match WasmGateNodeIdentity::try_from(file) {
                    Ok(pin) => pin,
                    Err(failure) => {
                        return Err(mismatch(format!(
                            "the gate node identity is unusable: [{}] {}",
                            failure.code, failure.detail
                        )))
                    }
                },
                Err(failure) => {
                    return Err(mismatch(format!(
                        "the gate node identity is not canonical: [{}] {}",
                        failure.code, failure.detail
                    )))
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(mismatch(
                    "no gate node identity is installed; wasm admission cannot bind to this node"
                        .into(),
                ));
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
            return err_json(
                401,
                WASM_UNAUTHORIZED,
                "wasm admission requires the owner bearer credential",
            );
        }
        if let Some(failure) = &self.state_failure {
            return err_json(503, failure.code, &failure.detail);
        }
        if body.len() > ADMISSION_SUBMIT_MAX_BYTES {
            return err_json(413, "BODY_TOO_LARGE", "wasm admission request is too large");
        }
        let json_type = content_type.is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json"))
        });
        if !json_type {
            return err_json(
                415,
                "UNSUPPORTED_CONTENT_TYPE",
                "wasm admission expects application/json",
            );
        }
        // 先解析 wire：发布门按应用代际选择（V1 → v2 记录 gate；
        // V2 service-enabled → v3 记录 gate + 逐字段 pin 绑定）。
        let request = match parse_admission_submit(body) {
            Ok(request) => request,
            Err(failure) => return err_json(400, failure.code, &failure.detail),
        };
        if let Err(response) = self.require_admission_publication_gate(&request) {
            return response;
        }
        // P0-4 准入身份绑定：runtimeBinding/capability pin/catalog revision+hash 与当前
        // 节点 gate-node-identity 逐字段相等；缺失/不相等 → 结构化 fail-closed 拒绝。
        if let Err(response) = self.verify_admission_node_identity(&request) {
            return response;
        }
        // 路由派生 kind-claim 预检：celld-app 路由目标的 applicationId 终身 celld-bound。
        if self
            .route_celld_claims
            .iter()
            .any(|claim| claim.application_id == request.application_id)
        {
            return err_json(
                409,
                APPLICATION_RUNTIME_KIND_CONFLICT,
                &format!(
                    "applicationId {} is permanently celld-bound by the route registry; changing runtime kind requires a new applicationId",
                    request.application_id
                ),
            );
        }
        // kind-claim 预检 + 注册实例（持久 wasm claim 的冲突在 CAS 内裁决）。
        let mut kind_store = match KindRegistryStoreDir::open(&self.paths.kind_registry()) {
            Ok(store) => store,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        let mut registry = match WasmKernelRouteRegistryV1::load(&kind_store) {
            Ok(registry) => registry,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
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
            let mut journal = match WasmAdmissionJournalFile::open(&self.paths.admission_journal())
            {
                Ok(journal) => journal,
                Err(failure) => return err_json(503, failure.code, &failure.detail),
            };
            let mut objects = FileAdmissionObjects::open(&self.paths.admission_objects());
            let mut db = match FileAdmissionDb::open(&self.paths.admission_db()) {
                Ok(db) => db,
                Err(failure) => return err_json(503, failure.code, &failure.detail),
            };
            let mut materializer =
                match FileAdmissionMaterializer::open(&self.paths.admission_receipts()) {
                    Ok(materializer) => materializer,
                    Err(failure) => return err_json(503, failure.code, &failure.detail),
                };
            let mut token = OsRandomTokenSource;
            let mut stores = AdmissionStores {
                journal: &mut journal,
                objects: &mut objects,
                db: &mut db,
                materializer: &mut materializer,
            };
            match commit_wasm_admission(&mut stores, &request, &mut token, now_epoch_millis) {
                Ok(outcome) => outcome,
                Err(failure) => return admission_failure_http(&failure),
            }
        };
        // kind registry 注册（claim CAS + 行投影；同 kind 幂等）。
        if let Err(failure) = registry.register_wasm_admission(
            &mut kind_store,
            registry.registry_revision(),
            &outcome.proof,
        ) {
            return err_json(
                if failure.code == APPLICATION_RUNTIME_KIND_CONFLICT {
                    409
                } else {
                    503
                },
                failure.code,
                &failure.detail,
            );
        }
        // 持久化业务记录（proof 集合 + lifecycle 覆盖）。P0-5：join 重试（created=false）
        // 不跳过——witness 事务已提交而本步此前失败时，重试必须幂等补写到完成。
        let mut registry_file = match self.load_route_registry() {
            Ok(file) => file,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        if !registry_file
            .proofs
            .iter()
            .any(|proof| proof.version_id == outcome.proof.version_id)
        {
            registry_file.proofs.push(outcome.proof.clone());
            registry_file
                .lifecycles
                .entry(outcome.proof.version_id.clone())
                .or_insert_with(|| "admitted".into());
            if let Err(failure) = self.save_route_registry(&registry_file) {
                return err_json(503, failure.code, &failure.detail);
            }
        }
        // v2 admission 行与一次 controlRevision CAS 同步写入。registry 已经是审计
        // 投影；若此处失败，下一次 startup/join retry 会从 visible witness 收敛，且
        // 在 v2 落盘之前公开 wasm 路由不会读取 registry 作为权威。
        let v2_present = self.paths.control_state().is_file();
        let (mut command_state, _, mut applications) = match self.load_control_state() {
            Ok(loaded) => loaded,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        let expected_control_revision = command_state.control_revision;
        let changed = match self.upsert_visible_admission(&mut applications, &outcome.proof) {
            Ok(changed) => changed,
            Err(failure) => return err_json(503, failure.code, &failure.detail),
        };
        if changed {
            if let Err(failure) = advance_control_revision(&mut command_state).and_then(|_| {
                self.save_control_state(
                    Some(expected_control_revision),
                    &command_state,
                    &registry_file,
                    &applications,
                )
            }) {
                return err_json(503, failure.code, &failure.detail);
            }
        } else if !v2_present {
            if let Err(failure) = self.save_control_state(
                None,
                &command_state,
                &registry_file,
                &applications,
            ) {
                return err_json(503, failure.code, &failure.detail);
            }
        }
        if let Err(failure) = self.reconcile_visible_execution_state(now_epoch_millis) {
            return err_json(503, failure.code, &failure.detail);
        }
        let socket = self.execution_socket.clone();
        self.deliver_pending_execution_commands(socket.as_deref(), now_epoch_millis);
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
        // R2 修复轮 9.7：单 gate——无候选版本代际分选，与 admission 同一门。
        if let Err(response) = self.require_wasm_gate_enabled() {
            return response;
        }
        // A replay journal may be durable while a prior process died before
        // its v2 projection.  Reconcile it before accepting a new route CAS so
        // activation-state can never advance independently of controlRevision.
        let now_epoch_millis = now_millis_u64();
        if let Err(failure) = self.sync_lifecycle_after_activation(now_epoch_millis) {
            return err_json(
                503,
                failure.code,
                &format!("the activation replay journal cannot converge into canonical v2 control state: {}", failure.detail),
            );
        }
        let fences = self.load_fences();
        let leases = self.load_leases();
        let registry_file = self
            .load_route_registry()
            .unwrap_or_else(|_| WasmRouteRegistryFile::fresh());
        let activation_states = self.load_activation_states();
        let mut store = WasmActivationStore::new(Box::new(FileActivationStateIO::open(
            &self.paths.activation_state(),
        )));
        let deps = ActivationDeps {
            now_epoch_millis: &|| now_epoch_millis,
            verify_bearer,
            lease_lookup: &|nonce: &str| {
                leases
                    .get(nonce)
                    .filter(|lease| lease.validate().is_ok())
                    .cloned()
            },
            facts: &|application_id: &str| {
                activation_facts(
                    &fences,
                    &registry_file,
                    &activation_states,
                    application_id,
                    now_epoch_millis,
                )
            },
            event_id: &|| generate_uuid_v7(now_epoch_millis),
        };
        let request = ActivationHttpRequest {
            method: "POST",
            path: ACTIVATION_RPC_PATH,
            authorization,
            content_type,
            body,
        };
        let options = ActivationHttpOptions {
            max_request_bytes: ACTIVATION_RPC_DEFAULT_MAX_BYTES,
        };
        let response = handle_activation_rpc_http(&mut store, &deps, request, options);
        let outcome = WasmHttpResponse {
            status: response.status,
            body: response.body,
        };
        // 激活成功后同步业务 lifecycle 投影（active 覆盖 + retiring 建档）；同步失败
        // 有界上报（route CAS 已提交，投影可由下次激活/恢复收敛）。
        if outcome.status == 200 {
            if let Err(failure) = self.sync_lifecycle_after_activation(now_epoch_millis) {
                return err_json(
                    503,
                    failure.code,
                    &format!(
                        "the route CAS committed but the lifecycle projection failed: {}",
                        failure.detail
                    ),
                );
            }
        }
        outcome
    }

    /// GET /v1/wasm/status：kind-claim 派生状态 + wasm gate 选择 + 业务 registry 投影。
    pub fn status_projection(&self) -> serde_json::Value {
        let bootstrap = match &self.state_failure {
            None => json!({
                "state": "verified",
                "claims": self.route_celld_claims.len(),
                "source": KIND_CLAIM_SOURCE_ROUTE_REGISTRY,
            }),
            Some(failure) => {
                json!({ "state": "unavailable", "code": failure.code, "detail": failure.detail })
            }
        };
        let wasm_selection =
            serde_json::to_value(self.wasm_gate_selection()).unwrap_or(serde_json::Value::Null);
        let mut applications: Vec<serde_json::Value> = Vec::new();
        if let Ok(state) = self.control_state_projection() {
            for application in state.applications.values() {
                let versions: Vec<serde_json::Value> = application
                    .versions
                    .iter()
                    .map(|version| {
                        json!({
                            "versionId": version.version_id,
                            "identity": version.identity,
                            "lifecycle": version.lifecycle,
                        })
                    })
                    .collect();
                let active = match &application.active {
                    WasmActivePointerV1::Active {
                        version_id,
                        route_generation,
                        ..
                    } => {
                        json!({ "versionId": version_id, "routeGeneration": route_generation })
                    }
                    WasmActivePointerV1::Unavailable { .. } => serde_json::Value::Null,
                };
                applications.push(json!({
                    "applicationId": application.application_id,
                    "runtimeKind": RUNTIME_KIND_WASM,
                    "versions": versions,
                    "active": active,
                    "routeGeneration": application.route_generation,
                }));
            }
        }
        json!({
            "schemaVersion": 1,
            "runtimeKind": RUNTIME_KIND_WASM,
            "bootstrap": bootstrap,
            "publicationGate": wasm_selection,
            "applications": applications,
        })
    }

    /// proof 集 → 确定性行投影（按 applicationId 分组 + lifecycle 覆盖）。
    pub fn project_registry_rows(&self) -> BTreeMap<String, Vec<WasmVersionRegistryRow>> {
        let file = self
            .load_route_registry()
            .unwrap_or_else(|_| WasmRouteRegistryFile::fresh());
        let mut grouped: BTreeMap<String, Vec<WasmVersionRegistryRow>> = BTreeMap::new();
        for proof in &file.proofs {
            if let Ok(mut row) = project_registry_row(proof) {
                if let Some(lifecycle) = file.lifecycles.get(&row.version_id) {
                    row.lifecycle = lifecycle.clone();
                }
                grouped
                    .entry(proof.application_id.clone())
                    .or_default()
                    .push(row);
            }
        }
        grouped
    }

    /// Projects one replay-journal event into the canonical v2 control state.
    /// The journal can prove a prior owner-authorized CAS, but it cannot skip a
    /// v2 generation, replace a same-generation pointer, or manufacture an
    /// application/version row.  That makes activation-state explicitly
    /// subordinate to `wasm-control-state-v2.json`.
    /// 事件持久化后同一投影面；候选以
    /// 归一视图比较（V2 binding ABI 1.1.0 → admission 事实形，其余字段同名同型）。
    fn project_activation_event_into_v2(
        &mut self,
        application_id: &str,
        journal: &KernelActivationState,
        event: &RouteEvent,
        fences: &BTreeMap<String, WasmApplicationFenceV1>,
        now_epoch_millis: u64,
    ) -> Result<ActivationJournalProjection, WasmControlFailure> {
        let (mut command_state, registry_file, mut applications) =
            self.load_control_state()?;
        let expected_control_revision = command_state.control_revision;
        let application = applications.get_mut(application_id).ok_or_else(|| {
            WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "the activation replay journal names an application missing from canonical v2 control state",
            )
        })?;

        if application.route_generation > event.route_generation {
            return Ok(ActivationJournalProjection::Stale);
        }
        let pointer_is_current = application.route_generation == event.route_generation
            && application.active == event.next;
        let pointer_is_next = application.route_generation == event.expected_route_generation
            && application.active == event.previous;
        if !pointer_is_current && !pointer_is_next {
            return Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "the activation replay journal is not the current v2 pointer or its single legal predecessor",
            ));
        }
        if event.result != crate::wasm_activation::RouteEventResult::Activated
            || event.route_generation != event.expected_route_generation.saturating_add(1)
            || event.lease_consume.outcome != crate::wasm_activation::LeaseConsumeOutcome::Consumed
        {
            return Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "the activation replay journal carries an invalid successful route event",
            ));
        }
        let recorded = journal
            .activation_records
            .get(&event.activation_id)
            .ok_or_else(|| {
                WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "the activation event has no matching durable command record",
                )
            })?;
        if &recorded.event != event
            || recorded.command.application_id != application_id
            || recorded.command.expected_route_generation != event.expected_route_generation
        {
            return Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "the activation replay journal command and event disagree",
            ));
        }
        let candidate = projected_activation_candidate(&recorded.command)?;
        let candidate_matches_event = match &event.next {
            WasmActivePointerV1::Active {
                runtime_kind,
                application_id: pointer_application_id,
                version_id,
                runtime_binding,
                admission_proof_ref,
                admission_proof_digest,
                route_generation,
                ..
            } => {
                runtime_kind == RUNTIME_KIND_WASM
                    && pointer_application_id == application_id
                    && version_id == candidate.version_id
                    && runtime_binding == &candidate.runtime_binding
                    && admission_proof_ref == candidate.admission_proof_ref
                    && admission_proof_digest == candidate.admission_proof_digest
                    && *route_generation == event.route_generation
            }
            WasmActivePointerV1::Unavailable { .. } => false,
        };
        if !candidate_matches_event
            || candidate.lease_nonce != event.lease_consume.lease_nonce
            || candidate.lease_digest != event.lease_consume.lease_digest
            || event.lease_consume.application_id != application_id
            || event.lease_consume.version_id != candidate.version_id
        {
            return Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "the activation candidate, consumed lease, and route event do not bind the same immutable facts",
            ));
        }
        let active_fence = fences
            .get(application_id)
            .and_then(|fence| fence.records.get(candidate.version_id))
            .ok_or_else(|| {
                WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "the activation replay journal has no candidate execution fence",
                )
            })?;
        let fence_matches_candidate = active_fence.sandbox_id == candidate.sandbox_id
            && active_fence.preparation_generation == candidate.preparation_generation
            && active_fence.execution_generation == candidate.execution_generation
            && active_fence.secret_revision == candidate.secret_revision
            && active_fence.secret_values_digest == candidate.secret_values_digest
            && active_fence.config_revision == candidate.config_revision
            && active_fence.config_snapshot_ref.as_deref() == candidate.config_snapshot_ref
            && active_fence.config_values_digest.as_deref() == candidate.config_values_digest
            && active_fence.alive
            && !active_fence.binding_revoked
            && matches!(active_fence.lifecycle.as_str(), "ready" | "active");
        if !fence_matches_candidate {
            return Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "the activation replay journal candidate no longer matches its live execution fence",
            ));
        }

        let mut v2_mutated = pointer_is_next;
        if pointer_is_next {
            application.active = event.next.clone();
            application.route_generation = event.route_generation;
        }
        let active_version = application
            .versions
            .iter_mut()
            .find(|version| version.version_id == candidate.version_id)
            .ok_or_else(|| WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, "the activation replay journal names a version missing from canonical v2 control state"))?;
        if active_version.identity.application_id != application_id
            || active_version.package_digest != candidate.package_digest
            || active_version.runtime_binding != candidate.runtime_binding
            || active_version.admission_proof_ref != candidate.admission_proof_ref
            || active_version.admission_proof_digest != candidate.admission_proof_digest
        {
            return Err(WasmControlFailure::new(
                WASM_CONTROL_STATE_INVALID,
                "the activation replay journal candidate disagrees with immutable v2 admission facts",
            ));
        }
        match &active_version.readiness_lease_digest {
            Some(digest) if digest != candidate.lease_digest => {
                return Err(WasmControlFailure::new(
                    WASM_CONTROL_STATE_INVALID,
                    "the active v2 version carries a different readiness lease digest",
                ));
            }
            Some(_) => {}
            None => {
                active_version.readiness_lease_digest = Some(candidate.lease_digest.to_string());
                v2_mutated = true;
            }
        }
        if active_version.lifecycle != "active" {
            active_version.lifecycle = "active".into();
            v2_mutated = true;
        }
        if application.secret_revision != candidate.secret_revision {
            application.secret_revision = candidate.secret_revision;
            v2_mutated = true;
        }
        if application.config_revision != candidate.config_revision {
            application.config_revision = candidate.config_revision;
            v2_mutated = true;
        }

        // A replacement's drain command and retiring record are part of the
        // same v2 mutation as the pointer flip.  They are not reconstructed
        // from a future static route record.
        let mut retirement_added = false;
        if let WasmActivePointerV1::Active {
            version_id: previous_version_id,
            route_generation: previous_generation,
            ..
        } = &event.previous
        {
            if previous_version_id != candidate.version_id
                && !command_state.retirements.iter().any(|record| {
                    record.application_id == application_id
                        && record.execution.version_id == *previous_version_id
                })
            {
                if let Some(previous_fence) = fences
                    .get(application_id)
                    .and_then(|fence| fence.records.get(previous_version_id))
                {
                    if let Some(deadline) = previous_fence.drain_deadline_epoch_millis {
                        let previous_proof = registry_file
                            .proofs
                            .iter()
                            .find(|proof| proof.application_id == application_id && proof.version_id == *previous_version_id)
                            .ok_or_else(|| WasmControlFailure::new(WASM_CONTROL_STATE_INVALID, "the retired activation pointer has no immutable admission proof"))?;
                        let row =
                            project_registry_row(previous_proof).map_err(map_admission_error)?;
                        let command_time =
                            now_epoch_millis.saturating_add(expected_control_revision);
                        // 单版本 drain 规划：与 prepare/start 同一 wire；retiring 记录/receipt
                        // 仍存 admission 事实形（binding 以 runtime_binding_v2_from_v1 归一
                        // echo，见 wasm_commands）。
                        let planned = plan_execution_command(&KernelCommandPlanInput {
                            command_id: &generate_uuid_v7(command_time),
                            operation: WasmExecutionOperation::Drain,
                            control_revision: expected_control_revision,
                            journal_head: registry_file.journal_head_hint,
                            sandbox_id: &previous_fence.sandbox_id,
                            application_id: &previous_proof.application_id,
                            host_service_policy_digest: previous_proof
                                .host_service_policy
                                .as_ref()
                                .map(|policy| policy.policy_digest.as_str()),
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
                        .map_err(|failure| WasmControlFailure::new(failure.code, failure.detail))?;
                        let command = planned.command;
                        let retirement = RetiringExecutionRecord {
                            drain_command_id: command.command_id.clone(),
                            application_id: application_id.into(),
                            execution: planned.next_generations,
                            package_digest: previous_proof.package_digest.clone(),
                            runtime_binding: previous_proof.runtime_binding.clone(),
                            route_generation: *previous_generation,
                            deadline_at_epoch_millis: deadline,
                            flip_at_epoch_millis: now_epoch_millis,
                            retired: false,
                            accepted_receipt_digest: None,
                        };
                        command_state
                            .authorize_drain_with_retirement(
                                expected_control_revision,
                                command,
                                crate::wasm_admission::format_rfc3339_utc_millis(command_time),
                                retirement,
                            )
                            .map_err(|failure| {
                                WasmControlFailure::new(failure.code, failure.detail)
                            })?;
                        retirement_added = true;
                        v2_mutated = true;
                    }
                }
            }
        }
        if !v2_mutated {
            return Ok(ActivationJournalProjection::Settled);
        }
        if !retirement_added {
            advance_control_revision(&mut command_state)?;
        }
        self.save_control_state(
            Some(expected_control_revision),
            &command_state,
            &registry_file,
            &applications,
        )?;
        Ok(if pointer_is_next {
            ActivationJournalProjection::Advanced
        } else {
            ActivationJournalProjection::Settled
        })
    }

    /// Activation state is retained for request query/replay and crash repair,
    /// while v2 remains the route authority.  This reconciler walks journal
    /// events in route-generation order so a recovery that has several durable
    /// events converges in one startup rather than requiring another restart.
    fn sync_lifecycle_after_activation(
        &mut self,
        now_epoch_millis: u64,
    ) -> Result<(), WasmControlFailure> {
        let fences = self.load_fences();
        let activation_states = self.load_activation_states();
        for (application_id, journal) in activation_states {
            let activated_events: Vec<&RouteEvent> = journal
                .events
                .iter()
                .filter(|event| event.result == crate::wasm_activation::RouteEventResult::Activated)
                .collect();
            if activated_events.is_empty() {
                continue;
            }
            loop {
                let control = self.control_state_projection()?;
                let application = control.applications.get(&application_id).ok_or_else(|| {
                    WasmControlFailure::new(
                        WASM_CONTROL_STATE_INVALID,
                        "the activation replay journal names no canonical v2 application",
                    )
                })?;
                if let Some(next) = activated_events.iter().copied().find(|event| {
                    event.expected_route_generation == application.route_generation
                        && event.previous == application.active
                }) {
                    match self.project_activation_event_into_v2(
                        &application_id,
                        &journal,
                        next,
                        &fences,
                        now_epoch_millis,
                    )? {
                        ActivationJournalProjection::Advanced => continue,
                        ActivationJournalProjection::Settled
                        | ActivationJournalProjection::Stale => break,
                    }
                }
                if let Some(current) = activated_events.iter().copied().find(|event| {
                    event.route_generation == application.route_generation
                        && event.next == application.active
                }) {
                    let _ = self.project_activation_event_into_v2(
                        &application_id,
                        &journal,
                        current,
                        &fences,
                        now_epoch_millis,
                    )?;
                    break;
                }
                if journal.route_generation > application.route_generation {
                    return Err(WasmControlFailure::new(
                        WASM_CONTROL_STATE_INVALID,
                        "the activation replay journal skips the canonical v2 route generation",
                    ));
                }
                // A v2 generation ahead of this journal is safe to route: the
                // journal is a subordinate replay aid and cannot roll it back.
                break;
            }
        }
        // Authorization is now durably represented in v2. Delivery remains
        // best-effort; query/replay is the only path that may later advance it.
        let socket = self.execution_socket.clone();
        self.deliver_pending_execution_commands(socket.as_deref(), now_epoch_millis);
        Ok(())
    }

    /// drain receipt 投影（retired 的唯一入口；执行流通道/测试驱动）：CAS 成功后
    /// 才把被替换版本的 lifecycle 写为 "retired"。
    pub fn project_drain_receipt(
        &mut self,
        receipt: &DrainReceiptV1,
    ) -> Result<DrainRetirementProjection, WasmControlFailure> {
        let (mut command_state, mut registry_file, mut applications) =
            self.load_control_state()?;
        let expected = command_state.control_revision;
        let projection = command_state
            .project_drain_receipt(expected, receipt)
            .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
        if let DrainRetirementProjection::Retired { .. } = projection {
            registry_file
                .lifecycles
                .insert(receipt.execution.version_id.clone(), "retired".into());
            if let Some(application) = applications.get_mut(&receipt.application_id) {
                if let Some(version) = application
                    .versions
                    .iter_mut()
                    .find(|version| version.version_id == receipt.execution.version_id)
                {
                    version.lifecycle = "retired".into();
                }
            }
        }
        self.save_control_state(
            Some(expected),
            &command_state,
            &registry_file,
            &applications,
        )?;
        Ok(projection)
    }

    /// 已建档的 retiring 判据（执行流取 drain 命令寻址；测试/状态投影用）。
    pub fn retiring_records(&self) -> Vec<RetiringExecutionRecord> {
        self.load_control_state()
            .map(|(state, _, _)| state.retirements)
            .unwrap_or_default()
    }

    /// 规范控制态文件的只读投影（owner 诊断/测试对位 WasmControlStateFileV2）。
    pub fn control_state_projection(&self) -> Result<WasmControlStateFileV2, WasmControlFailure> {
        let (state, _, applications) = self.load_control_state()?;
        Ok(WasmControlStateFileV2 {
            schema_version: 2,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: state.control_revision,
            applications,
            command_outbox: state.command_outbox,
        })
    }

    /// Resolves a public wasm route from the canonical v2 pointer and the
    /// current execution fence.  Static RouteTarget.sandboxId is deliberately
    /// absent from this path: a stale route record can never select traffic.
    pub fn resolve_active_ingress(&self, application_id: &str) -> Option<WasmIngressTarget> {
        if self.state_failure.is_some() {
            return None;
        }
        let (_, _, applications) = match self.load_control_state() {
            Ok(loaded) => loaded,
            Err(failure) => {
                eprintln!(
                    "iweb-kernel: wasm public route unavailable because v2 control state cannot be read: [{}] {}",
                    failure.code, failure.detail
                );
                return None;
            }
        };
        let fences = match self.load_fences_file() {
            Ok(fences) => fences,
            Err(failure) => {
                eprintln!(
                    "iweb-kernel: wasm public route unavailable because execution fences cannot be read: [{}] {}",
                    failure.code, failure.detail
                );
                return None;
            }
        };
        resolve_active_ingress_from_records(application_id, &applications, &fences)
    }
}

fn resolve_active_ingress_from_records(
    application_id: &str,
    applications: &BTreeMap<String, WasmApplicationControlRecordV1>,
    fences: &WasmFencesFileV1,
) -> Option<WasmIngressTarget> {
    let application = applications.get(application_id)?;
    if application.runtime_kind != RUNTIME_KIND_WASM || application.application_id != application_id
    {
        return None;
    }
    let WasmActivePointerV1::Active {
        runtime_kind,
        application_id: pointer_application_id,
        version_id,
        identity,
        runtime_binding,
        admission_proof_ref,
        admission_proof_digest,
        route_generation,
        host_service_policy_digest: _,
        preparation_generation: _,
        execution_generation: _,
    } = &application.active
    else {
        return None;
    };
    if runtime_kind != RUNTIME_KIND_WASM
        || pointer_application_id != application_id
        || *route_generation != application.route_generation
    {
        return None;
    }
    let version = application
        .versions
        .iter()
        .find(|version| version.version_id == *version_id)?;
    if version.lifecycle != "active"
        || version.readiness_lease_digest.is_none()
        || version.identity != *identity
        || version.runtime_binding != *runtime_binding
        || version.admission_proof_ref != *admission_proof_ref
        || version.admission_proof_digest != *admission_proof_digest
    {
        return None;
    }
    let application_fence = fences.applications.get(application_id)?;
    if application_fence.current_version_id != *version_id {
        return None;
    }
    let fence = application_fence.records.get(version_id)?;
    if fence.version_id != *version_id
        || !fence.alive
        || fence.binding_revoked
        || !matches!(fence.lifecycle.as_str(), "ready" | "active")
        || fence.preparation_generation == 0
        || fence.execution_generation == 0
        || application.secret_revision != fence.secret_revision
        || application.config_revision != fence.config_revision
    {
        return None;
    }
    Some(WasmIngressTarget {
        application_id: application_id.into(),
        sandbox_id: fence.sandbox_id.clone(),
        version_id: version_id.clone(),
        route_generation: *route_generation,
        preparation_generation: fence.preparation_generation,
        execution_generation: fence.execution_generation,
    })
}

impl WasmRuntime {
    /// P0-1 生产投递闭环：对每个 pending/sent outbox 条目执行
    /// query → decide_reconciliation → deliver/replay/project-ack，并把 journal
    /// head 提示收敛到观察到的最大 revision。supervisor 不可达/响应不确定时命令
    /// 保持 sent（advisory），只能经 query/replay 推进——绝不重发 command 语义。
    pub fn deliver_pending_execution_commands(
        &mut self,
        socket_path: Option<&str>,
        now_epoch_millis: u64,
    ) -> WasmDeliveryReport {
        self.deliver_pending_execution_commands_with_transports(
            socket_path,
            now_epoch_millis,
            crate::supervisor::execution_rpc_blocking,
            Self::resolved_supervisor_peer,
            deliver_snapshot_handoff,
        )
    }

    /// Narrow test seam for a local execution-RPC responder. Production callers
    /// must use `deliver_pending_execution_commands`, which keeps the fixed
    /// supervisor socket policy in `execution_rpc_blocking`.
    #[doc(hidden)]
    pub fn deliver_pending_execution_commands_with_transport(
        &mut self,
        socket_path: Option<&str>,
        now_epoch_millis: u64,
        transport: ExecutionRpcTransport,
    ) -> WasmDeliveryReport {
        self.deliver_pending_execution_commands_with_transports(
            socket_path,
            now_epoch_millis,
            transport,
            Self::resolved_supervisor_peer,
            deliver_snapshot_handoff,
        )
    }

    /// Narrow test seam for an in-process snapshot relay. Production callers
    /// must use `deliver_pending_execution_commands`, which supplies both fixed
    /// socket transports and the deployed supervisor-account resolver.
    #[doc(hidden)]
    pub fn deliver_pending_execution_commands_with_transports(
        &mut self,
        socket_path: Option<&str>,
        now_epoch_millis: u64,
        transport: ExecutionRpcTransport,
        peer_resolver: SnapshotPeerResolver,
        snapshot_transport: SnapshotHandoffTransport,
    ) -> WasmDeliveryReport {
        let Some(socket) = socket_path else {
            return WasmDeliveryReport::default();
        };
        match self.run_outbox_delivery(
            socket,
            now_epoch_millis,
            transport,
            peer_resolver,
            snapshot_transport,
        ) {
            Ok(report) => report,
            Err(failure) => {
                eprintln!(
                    "iweb-kernel: wasm outbox delivery stopped: [{}] {}",
                    failure.code, failure.detail
                );
                let mut report = WasmDeliveryReport::default();
                report
                    .failures
                    .push(format!("[{}] {}", failure.code, failure.detail));
                report
            }
        }
    }

    /// `attempt` 与 acknowledgement projection 都是规范定义的单次 v2 mutation。
    /// 不能把一轮投递中的多个 mutation 堆在内存后只写一次：那会让磁盘
    /// `controlRevision` 跳号，并在中途崩溃时丢失已发生的投递事实。
    fn persist_outbox_delivery_mutation(
        &self,
        expected_control_revision: u64,
        state: &WasmCommandControlState,
        registry_file: &mut WasmRouteRegistryFile,
        applications: &BTreeMap<String, WasmApplicationControlRecordV1>,
        journal_head_hint: u64,
    ) -> Result<(), WasmControlFailure> {
        registry_file.journal_head_hint = journal_head_hint;
        self.save_control_state(
            Some(expected_control_revision),
            state,
            registry_file,
            applications,
        )
    }

    fn run_outbox_delivery(
        &mut self,
        socket: &str,
        now_epoch_millis: u64,
        transport: ExecutionRpcTransport,
        peer_resolver: SnapshotPeerResolver,
        snapshot_transport: SnapshotHandoffTransport,
    ) -> Result<WasmDeliveryReport, WasmControlFailure> {
        let (mut state, mut registry_file, applications) = self.load_control_state()?;
        let mut report = WasmDeliveryReport::default();
        let mut journal_head_hint = registry_file.journal_head_hint;
        let command_ids: Vec<String> = state
            .command_outbox
            .iter()
            .filter(|entry| {
                matches!(
                    entry.delivery_state,
                    OutboxDeliveryState::Pending | OutboxDeliveryState::Sent
                )
            })
            .map(|entry| entry.command_id.clone())
            .collect();
        for command_id in command_ids {
            let Some(outbox) = state.find_outbox(&command_id).cloned() else {
                continue;
            };
            // 第 1 步：query（journal 观察是唯一推进依据）。
            let request_id = generate_uuid_v7(now_epoch_millis);
            let observation = match self.post_execution_rpc(
                socket,
                &request_id,
                json!({ "kind": "query", "commandId": command_id }),
                transport,
            ) {
                Ok(body) => match parse_query_result_envelope(&request_id, &body) {
                    Ok(query) => {
                        // journal head 提示按观察收敛（received/completion 的最大 revision）。
                        if let Some(received) = &query.received {
                            journal_head_hint = journal_head_hint.max(received.journal_revision);
                        }
                        if let Some(ack) = &query.acknowledgement {
                            journal_head_hint = journal_head_hint.max(ack.journal_revision);
                        }
                        match crate::wasm_commands::journal_observation_from_query(
                            &outbox.command,
                            &query,
                        ) {
                            Ok(observation) => Some(observation),
                            Err(failure) => {
                                report
                                    .failures
                                    .push(format!("[{}] {}", failure.code, failure.detail));
                                None
                            }
                        }
                    }
                    Err(failure) => {
                        report
                            .failures
                            .push(format!("[{}] {}", failure.code, failure.detail));
                        None
                    }
                },
                Err(failure) => {
                    report
                        .failures
                        .push(format!("[{}] {}", failure.code, failure.detail));
                    None
                }
            };
            let Some(observation) = observation else {
                // 观察失败（传输/畸形/命令冲突）：记录一次投递尝试，命令保持原态。
                let head = state.control_revision;
                match state.record_delivery_attempt(
                    head,
                    &command_id,
                    crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis),
                ) {
                    Ok(()) if state.control_revision != head => self
                        .persist_outbox_delivery_mutation(
                            head,
                            &state,
                            &mut registry_file,
                            &applications,
                            journal_head_hint,
                        )?,
                    Ok(()) => {}
                    Err(failure) => report
                        .failures
                        .push(format!("[{}] {}", failure.code, failure.detail)),
                }
                report.attempted += 1;
                continue;
            };
            match decide_reconciliation(&outbox, &observation) {
                Ok(ReconciliationStep::AlreadyProjected) => report.already_projected += 1,
                Ok(ReconciliationStep::ProjectAcknowledgement) => {
                    let JournalObservation::Completed(ack) = &observation else {
                        unreachable!("decide_reconciliation projects completed observations only")
                    };
                    let head = state.control_revision;
                    match state.project_acknowledgement(head, ack) {
                        Ok(crate::wasm_commands::AcknowledgementProjection::Projected {
                            ..
                        }) => {
                            self.persist_outbox_delivery_mutation(
                                head,
                                &state,
                                &mut registry_file,
                                &applications,
                                journal_head_hint,
                            )?;
                            report.projected += 1;
                        }
                        Ok(
                            crate::wasm_commands::AcknowledgementProjection::AlreadyAcknowledged,
                        ) => report.already_projected += 1,
                        Err(failure) => report
                            .failures
                            .push(format!("[{}] {}", failure.code, failure.detail)),
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
                    // Snapshot FD 是 Prepare/Start HTTP envelope 的硬前置条件。handoff
                    // 失败时不触碰 supervisor execution journal；保留 outbox 供下一轮
                    // query/replay，避免「Start 已到而 relay 未收到快照」的半配置执行。
                    if let Err(failure) = self.deliver_snapshots_before_execution_with_transport(
                        &outbox.command,
                        now_epoch_millis,
                        peer_resolver,
                        snapshot_transport,
                    ) {
                        report
                            .failures
                            .push(format!("[{}] {}", failure.code, failure.detail));
                        let head = state.control_revision;
                        match state.record_delivery_attempt(
                            head,
                            &command_id,
                            crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis),
                        ) {
                            Ok(()) if state.control_revision != head => self
                                .persist_outbox_delivery_mutation(
                                    head,
                                    &state,
                                    &mut registry_file,
                                    &applications,
                                    journal_head_hint,
                                )?,
                            Ok(()) => {}
                            Err(failure) => report
                                .failures
                                .push(format!("[{}] {}", failure.code, failure.detail)),
                        }
                        continue;
                    }
                    let request_id = generate_uuid_v7(now_epoch_millis);
                    let command_value =
                        serde_json::to_value(&outbox.command).expect("command serializes");
                    let delivered = self.post_execution_rpc(
                        socket,
                        &request_id,
                        json!({ "kind": kind, "command": command_value }),
                        transport,
                    );
                    let outcome = delivered.and_then(|body| {
                        parse_acknowledgement_envelope(&request_id, &body, &outbox.command)
                    });
                    match outcome {
                        Ok(ack) => {
                            journal_head_hint = journal_head_hint.max(ack.journal_revision);
                            let head = state.control_revision;
                            match state.project_acknowledgement(head, &ack) {
                                Ok(crate::wasm_commands::AcknowledgementProjection::Projected { .. }) => {
                                    self.persist_outbox_delivery_mutation(
                                        head,
                                        &state,
                                        &mut registry_file,
                                        &applications,
                                        journal_head_hint,
                                    )?;
                                    report.projected += 1;
                                    report.delivered += 1;
                                }
                                Ok(crate::wasm_commands::AcknowledgementProjection::AlreadyAcknowledged) => report.already_projected += 1,
                                Err(failure) => report.failures.push(format!("[{}] {}", failure.code, failure.detail)),
                            }
                        }
                        Err(failure) => {
                            // 不确定结果（response lost/传输失败/echo 拒绝）：留待 query/replay。
                            report
                                .failures
                                .push(format!("[{}] {}", failure.code, failure.detail));
                            let head = state.control_revision;
                            match state.record_delivery_attempt(
                                head,
                                &command_id,
                                crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis),
                            ) {
                                Ok(()) if state.control_revision != head => self
                                    .persist_outbox_delivery_mutation(
                                        head,
                                        &state,
                                        &mut registry_file,
                                        &applications,
                                        journal_head_hint,
                                    )?,
                                Ok(()) => {}
                                Err(failure) => report
                                    .failures
                                    .push(format!("[{}] {}", failure.code, failure.detail)),
                            }
                        }
                    }
                }
                Err(failure) => report
                    .failures
                    .push(format!("[{}] {}", failure.code, failure.detail)),
            }
        }
        if journal_head_hint != registry_file.journal_head_hint {
            registry_file.journal_head_hint = journal_head_hint;
            self.save_route_registry(&registry_file)?;
        }
        Ok(report)
    }

    /// POST /v1/execution-rpc（envelope 用既有契约；成功返回响应 body 字节）。
    fn post_execution_rpc(
        &self,
        socket: &str,
        request_id: &str,
        body: serde_json::Value,
        transport: ExecutionRpcTransport,
    ) -> Result<Vec<u8>, WasmControlFailure> {
        let envelope = json!({
            "protocol": EXECUTION_RPC_PROTOCOL_LITERAL,
            "requestId": request_id,
            "body": body,
        });
        let bytes = jcs_bytes(&envelope).map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
        match transport(socket, &bytes, EXECUTION_RPC_TIMEOUT_MS) {
            Some((200, response)) => Ok(response),
            Some((status, response)) => {
                let detail = String::from_utf8_lossy(&response).trim().to_string();
                Err(WasmControlFailure::new(WASM_EXECUTION_DELIVERY_UNCERTAIN, format!("supervisor returned HTTP {status}: {detail}")))
            }
            None => Err(WasmControlFailure::new(WASM_EXECUTION_DELIVERY_UNCERTAIN, "the execution rpc response is uncertain (transport failure or timeout); only query/replay may advance the command")),
        }
    }

    /// AdmittedVisible 谓词直通（owner 诊断/测试：三段 witness 一致性）。
    pub fn admitted_visible(
        &self,
        application_id: &str,
        version_id: &str,
    ) -> Result<Option<AdmissionProofV1>, WasmControlFailure> {
        let objects = FileAdmissionObjects::open(&self.paths.admission_objects());
        let db = FileAdmissionDb::open(&self.paths.admission_db()).map_err(map_admission_error)?;
        let materializer = FileAdmissionMaterializer::open(&self.paths.admission_receipts())
            .map_err(map_admission_error)?;
        admitted_visible(&objects, &db, &materializer, application_id, version_id)
            .map_err(map_admission_error)
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

/// Trusted in-process transport used only by integration tests. The production
/// delivery method always supplies the fixed-socket transport above.
pub type ExecutionRpcTransport = fn(&str, &[u8], u64) -> Option<(u16, Vec<u8>)>;

/// Trusted in-process snapshot hooks used only by integration tests. Production
/// delivery always resolves `iweb-sandbox` and sends on the fixed raw-UDS path.
pub type SnapshotPeerResolver = fn() -> Result<SnapshotSocketPeer, WasmControlFailure>;
pub type SnapshotHandoffTransport =
    for<'a> fn(&SnapshotHandoffDelivery<'a>) -> Result<SnapshotDeliveryOutcome, SnapshotFdError>;

/// 响应 envelope 头（{protocol,requestId,body}；protocol/requestId 必须回显）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRpcEnvelopeResponseHead {
    protocol: String,
    #[serde(rename = "requestId")]
    request_id: String,
    body: serde_json::Value,
}

fn parse_envelope_head(
    request_id: &str,
    bytes: &[u8],
) -> Result<serde_json::Value, WasmControlFailure> {
    let head: ExecutionRpcEnvelopeResponseHead = serde_json::from_slice(bytes).map_err(|e| {
        WasmControlFailure::new(
            EXECUTION_RPC_RESPONSE_INVALID,
            format!("the execution rpc response does not parse as the envelope: {e}"),
        )
    })?;
    if head.protocol != EXECUTION_RPC_PROTOCOL_LITERAL {
        return Err(WasmControlFailure::new(
            EXECUTION_RPC_RESPONSE_INVALID,
            "the execution rpc response protocol does not echo the request literal",
        ));
    }
    if head.request_id != request_id {
        return Err(WasmControlFailure::new(
            EXECUTION_RPC_RESPONSE_INVALID,
            "the execution rpc response requestId does not echo the request",
        ));
    }
    Ok(head.body)
}

/// 响应 envelope 码（spec 未命名 HTTP 错误 envelope 之外的 Kernel 侧结构码）。
pub const EXECUTION_RPC_RESPONSE_INVALID: &str = "EXECUTION_RPC_RESPONSE_INVALID";

fn parse_query_result_envelope(
    request_id: &str,
    bytes: &[u8],
) -> Result<crate::wasm_commands::CommandQueryResultV1, WasmControlFailure> {
    let body = parse_envelope_head(request_id, bytes)?;
    if body.get("kind").and_then(serde_json::Value::as_str) != Some("query-result") {
        return Err(WasmControlFailure::new(
            EXECUTION_RPC_RESPONSE_INVALID,
            "a query must answer with a query-result body",
        ));
    }
    let body_bytes = serde_json::to_vec(&body).map_err(|e| {
        WasmControlFailure::new(
            EXECUTION_RPC_RESPONSE_INVALID,
            format!("the query-result body is not serializable: {e}"),
        )
    })?;
    parse_command_query_result(&body_bytes).map_err(|e| WasmControlFailure::new(e.code, e.detail))
}

fn parse_acknowledgement_envelope(
    request_id: &str,
    bytes: &[u8],
    command: &ExecutionCommand,
) -> Result<ExecutionAcknowledgement, WasmControlFailure> {
    let body = parse_envelope_head(request_id, bytes)?;
    if body.get("kind").and_then(serde_json::Value::as_str) != Some("acknowledgement") {
        return Err(WasmControlFailure::new(
            EXECUTION_RPC_RESPONSE_INVALID,
            "a delivered command must answer with an acknowledgement body",
        ));
    }
    let Some(ack_value) = body.get("acknowledgement") else {
        return Err(WasmControlFailure::new(
            EXECUTION_RPC_RESPONSE_INVALID,
            "the acknowledgement body is missing its acknowledgement member",
        ));
    };
    // 版本联合 ack：schemaVersion 互斥解析（V1 命令绝不消费 V2 ack，反之亦然）。
    let ack: ExecutionAcknowledgement =
        serde_json::from_value(ack_value.clone()).map_err(|e| {
            WasmControlFailure::new(
                EXECUTION_RPC_RESPONSE_INVALID,
                format!("the acknowledgement does not parse as the typed record: {e}"),
            )
        })?;
    validate_execution_acknowledgement(&ack)
        .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
    crate::wasm_commands::correlate_acknowledgement(command, &ack)
        .map_err(|e| WasmControlFailure::new(e.code, e.detail))?;
    Ok(ack)
}

/// admission journal 恢复驱动（启动序第 7 步；文件 witness 全套接线）。
fn run_admission_recovery(
    paths: &WasmRuntimePaths,
    now_epoch_millis: u64,
) -> Result<(), WasmControlFailure> {
    let mut journal =
        WasmAdmissionJournalFile::open(&paths.admission_journal()).map_err(map_admission_error)?;
    let mut objects = FileAdmissionObjects::open(&paths.admission_objects());
    let mut db = FileAdmissionDb::open(&paths.admission_db()).map_err(map_admission_error)?;
    let mut materializer = FileAdmissionMaterializer::open(&paths.admission_receipts())
        .map_err(map_admission_error)?;
    let mut stores = AdmissionStores {
        journal: &mut journal,
        objects: &mut objects,
        db: &mut db,
        materializer: &mut materializer,
    };
    recover_wasm_admission(&mut stores, now_epoch_millis).map_err(map_admission_error)?;
    Ok(())
}

/// 启动期从路由注册表读取并派生终身 celld claims。Some 且文件不可解析时
/// RouteStore::load panic-fail-closed（spec「Route registry is unreadable at startup」
/// → 节点启动失败，无 partial-admission/pending 模式）；None（未配置路由存储）
/// 派生空 claim 集。
fn derive_route_celld_claims(paths: &WasmRuntimePaths) -> Result<Vec<RuntimeKindClaimV1>, WasmControlFailure> {
    let routes = match &paths.routes_registry {
        Some(path) => crate::routes::RouteStore::load(path).snapshot(),
        None => Vec::new(),
    };
    derive_celld_claims_from_routes(&routes)
        .map_err(|failure| WasmControlFailure::new(failure.code, failure.detail))
}

fn now_millis_u64() -> u64 {
    u64::try_from(crate::monitor::now_millis()).unwrap_or(u64::MAX)
}

/// 版本联合激活候选的归一视图（project_activation_event_into_v2 专用）：
/// 两代候选字段同名同型，唯 binding 带代际（V2 ABI 1.1.0）；此处归一到
/// admission 事实形（V1 binding），与 v2 控制态行/指针同基比较。
struct ProjectedActivationCandidate<'a> {
    version_id: &'a str,
    sandbox_id: &'a str,
    package_digest: &'a str,
    runtime_binding: RuntimeBindingIdentityV1,
    admission_proof_ref: &'a str,
    admission_proof_digest: &'a str,
    preparation_generation: u64,
    execution_generation: u64,
    secret_revision: u64,
    secret_values_digest: &'a str,
    config_revision: u64,
    config_snapshot_ref: Option<&'a str>,
    config_values_digest: Option<&'a str>,
    lease_nonce: &'a str,
    lease_digest: &'a str,
}

fn projected_activation_candidate<'a>(
    command: &'a ActivationCommand,
) -> Result<ProjectedActivationCandidate<'a>, WasmControlFailure> {
    let candidate = &command.candidate;
    // 命令 binding 为单版本 wire 形（ABI 1.1.0）→ admission 事实形（ABI 1.0.0
    // 字面量互换），与 v2 控制态行/指针同基比较。
    let runtime_binding = RuntimeBindingIdentityV1 {
        kind: candidate.runtime_binding.kind.clone(),
        catalog_revision: candidate.runtime_binding.catalog_revision,
        catalog_hash: candidate.runtime_binding.catalog_hash.clone(),
        entry_key: candidate.runtime_binding.entry_key.clone(),
        image_digest: candidate.runtime_binding.image_digest.clone(),
        host_abi: crate::wasm_admission::WASM_HOST_ABI_LITERAL.into(),
        world: candidate.runtime_binding.world.clone(),
    };
    Ok(ProjectedActivationCandidate {
        version_id: &candidate.version_id,
        sandbox_id: &candidate.sandbox_id,
        package_digest: &candidate.package_digest,
        runtime_binding,
        admission_proof_ref: &candidate.admission_proof_ref,
        admission_proof_digest: &candidate.admission_proof_digest,
        preparation_generation: candidate.preparation_generation,
        execution_generation: candidate.execution_generation,
        secret_revision: candidate.secret_revision,
        secret_values_digest: &candidate.secret_values_digest,
        config_revision: candidate.config_revision,
        config_snapshot_ref: candidate.config_snapshot_ref.as_deref(),
        config_values_digest: candidate.config_values_digest.as_deref(),
        lease_nonce: &candidate.lease_nonce,
        lease_digest: &candidate.lease_digest,
    })
}

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
            .find(|proof| {
                proof.application_id == application_id && proof.version_id == fence.version_id
            })
            .filter(|_| matches!(fence.lifecycle.as_str(), "ready" | "active"))
            .map(|proof| RegistryRowFacts {
                runtime_binding: proof.runtime_binding.clone(),
                capability_record_revision: proof.capability_record_revision,
                capability_record_hash: proof.capability_record_hash.clone(),
                // V2（service-enabled）行：proof 携带完整 policy → 投影 digest。
                host_service_policy_digest: proof
                    .host_service_policy
                    .as_ref()
                    .map(|policy| policy.policy_digest.clone()),
                lifecycle_ready: true,
            })
    });
    OwnedActivationCasFacts {
        now_epoch_millis,
        // controlRevision 盖戳初值：store 提交面以 file.controlRevision + 1 覆盖
        //（第五轮复审：V2 事件盖戳权威在持久化边界，本回调无法预知恢复后的 revision）。
        control_revision: 0,
        current_secret_store_revision: fence.map(|fence| fence.secret_revision).unwrap_or(0),
        current_preparation_generation: fence
            .map(|fence| fence.preparation_generation)
            .unwrap_or(0),
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
    /// V2（service-enabled）准入的完整 HostServicePolicyV2（含 policyDigest）；
    /// 不在场即 V1 请求（绝不由缺失字段推断 V2）。
    #[serde(rename = "hostServicePolicy", default)]
    host_service_policy: Option<crate::wasm_host_services::HostServicePolicyV2>,
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
        return Err(invalid(
            "a wasm admission must carry at least one blob".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut blobs = Vec::with_capacity(wire.blobs.len());
    for blob in &wire.blobs {
        if !seen.insert(blob.digest_hex.clone()) {
            return Err(invalid(format!(
                "duplicate blob digest {} in the admission submit",
                blob.digest_hex
            )));
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
        host_service_policy: wire.host_service_policy,
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
    const GOLDEN_CONTROL_STATE_V2_JCS: &str = r#"{"applications":{"vector":{"active":{"admissionProofDigest":"4444444444444444444444444444444444444444444444444444444444444444","admissionProofRef":"admission-proof/vector/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1","applicationId":"vector","identity":{"applicationId":"vector","digest":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532","sequence":1},"kind":"active","routeGeneration":4,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"runtimeKind":"wasm","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"},"applicationId":"vector","configRevision":2,"routeGeneration":4,"runtimeKind":"wasm","secretRevision":3,"versions":[{"admissionProofDigest":"4444444444444444444444444444444444444444444444444444444444444444","admissionProofRef":"admission-proof/vector/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1","identity":{"applicationId":"vector","digest":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532","sequence":1},"lifecycle":"active","normalizedPolicy":{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}},"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","readinessLeaseDigest":"3333333333333333333333333333333333333333333333333333333333333333","runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}]}},"commandOutbox":[{"attempts":1,"command":{"applicationId":"vector","capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abcd","configRevision":2,"configSnapshotRef":"7777777777777777777777777777777777777777777777777777777777777777","configValuesDigest":"8888888888888888888888888888888888888888888888888888888888888888","expectedControlRevision":12,"expectedJournalRevision":4,"fenceNonce":"0f1e2d3c4b5a69788796a5b4c3d2e1f0","hostServicePolicyDigest":"","identity":{"executionGeneration":1,"preparationGeneration":1,"sandboxId":"sbx-vector","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"},"matrixRevision":2,"operation":"prepare","packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.1.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":2,"secretRevision":3,"secretSnapshotRef":"5555555555555555555555555555555555555555555555555555555555555555","secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666"},"commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abcd","createdAt":"2026-08-26T00:00:00Z","deliveryState":"sent","lastAttemptAt":"2026-08-26T00:00:01Z"}],"controlRevision":12,"runtimeKind":"wasm","schemaVersion":2}"#;

    #[test]
    fn control_state_v2_golden_round_trips_the_ts_vector() {
        let bytes = GOLDEN_CONTROL_STATE_V2_JCS.as_bytes().to_vec();
        let parsed = parse_canonical::<WasmControlStateFileV2>(
            &bytes,
            WASM_CONTROL_STATE_INVALID,
            "wasm control state",
        )
        .expect("golden parses canonically");
        parsed.validate().expect("golden validates");
        assert_eq!(parsed.control_revision, 12);
        assert_eq!(parsed.applications.len(), 1);
        assert_eq!(parsed.command_outbox.len(), 1);
        // JCS round-trip：原始字节等于 JCS(parse(bytes))（含显式 null 键）。
        let reencoded = jcs_bytes(&parsed).expect("re-encode");
        assert_eq!(
            String::from_utf8(reencoded).expect("utf8"),
            GOLDEN_CONTROL_STATE_V2_JCS
        );
        // 空文件：无 migration 分区（celld-control-state-v1 迁移源已删除）。
        let empty = WasmControlStateFileV2::empty();
        empty.validate().expect("empty validates");
        let encoded = jcs_bytes(&empty).expect("empty jcs");
        assert_eq!(
            String::from_utf8(encoded).expect("utf8"),
            r#"{"applications":{},"commandOutbox":[],"controlRevision":0,"runtimeKind":"wasm","schemaVersion":2}"#
        );
    }

    #[test]
    fn control_state_v2_rejects_structural_and_cross_field_violations() {
        let replace = |from: &str, to: &str| {
            GOLDEN_CONTROL_STATE_V2_JCS
                .replacen(from, to, 1)
                .into_bytes()
        };
        // schemaVersion 篡改（schema 1 不得被 wasm v2 语义接受：解析可行、校验拒绝）。
        let celld_shape = replace(
            r#""runtimeKind":"wasm","schemaVersion":2}"#,
            r#""runtimeKind":"wasm","schemaVersion":1}"#,
        );
        let parsed = parse_canonical::<WasmControlStateFileV2>(
            &celld_shape,
            WASM_CONTROL_STATE_INVALID,
            "x",
        )
        .expect("parses as JSON");
        assert!(parsed.validate().is_err());
        // 未知顶层键。
        let mut surplus = GOLDEN_CONTROL_STATE_V2_JCS.to_string();
        surplus.insert_str(1, r#""surplus":true,"#);
        assert!(parse_canonical::<WasmControlStateFileV2>(
            surplus.as_bytes(),
            WASM_CONTROL_STATE_INVALID,
            "x"
        )
        .is_err());
        // active 行缺 readinessLeaseDigest（显式 null 键缺席即拒绝）。
        let missing_lease = replace(
            r#""readinessLeaseDigest":"3333333333333333333333333333333333333333333333333333333333333333","runtimeBinding""#,
            r#""runtimeBinding""#,
        );
        assert!(parse_canonical::<WasmControlStateFileV2>(
            &missing_lease,
            WASM_CONTROL_STATE_INVALID,
            "x"
        )
        .is_err());
        // 跨字段：active 指针 routeGeneration 与记录不一致。
        let mismatched = replace(
            r#""routeGeneration":4,"runtimeKind":"wasm","secretRevision":3"#,
            r#""routeGeneration":5,"runtimeKind":"wasm","secretRevision":3"#,
        );
        let parsed =
            parse_canonical::<WasmControlStateFileV2>(&mismatched, WASM_CONTROL_STATE_INVALID, "x")
                .expect("parses");
        assert!(parsed.validate().is_err());
        // 跨字段：admissionProofRef 公式破坏（active 指针侧首个出现即触发指针↔行比对）。
        let wrong_ref = replace(
            r#"admission-proof/vector/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"#,
            r#"admission-proof/wrong/a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"#,
        );
        let parsed =
            parse_canonical::<WasmControlStateFileV2>(&wrong_ref, WASM_CONTROL_STATE_INVALID, "x")
                .expect("parses");
        assert!(parsed.validate().is_err());
        // 旧 migration 分区（celld-control-state-v1）现在是未知键 → 拒绝。
        let legacy_migration = GOLDEN_CONTROL_STATE_V2_JCS.replacen(
            r#""controlRevision":12,"runtimeKind""#,
            r#""controlRevision":12,"migration":{"completedAt":null,"source":"celld-control-state-v1","sourceDigest":null,"status":"not-started"},"runtimeKind""#,
            1,
        );
        assert!(parse_canonical::<WasmControlStateFileV2>(
            legacy_migration.as_bytes(),
            WASM_CONTROL_STATE_INVALID,
            "x",
        )
        .is_err());
        // outbox：commandId 与包装命令不一致。
        let mismatched_outbox = replace(
            r#""commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abcd","createdAt""#,
            r#""commandId":"018f1e2c-3d4b-7a5e-9f01-23456789abce","createdAt""#,
        );
        let parsed = parse_canonical::<WasmControlStateFileV2>(
            &mismatched_outbox,
            WASM_CONTROL_STATE_INVALID,
            "x",
        )
        .expect("parses");
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn fence_and_lease_file_shapes_are_canonical() {
        // wire 形状哨兵：空文件序列化为 canonical JCS 且 deny_unknown_fields 生效。
        let fences = WasmFencesFileV1::empty();
        let bytes = jcs_bytes(&fences).expect("jcs");
        assert_eq!(
            String::from_utf8(bytes.clone()).expect("utf8"),
            r#"{"applications":{},"runtimeKind":"wasm","schemaVersion":1}"#
        );
        assert!(
            parse_canonical::<WasmFencesFileV1>(&bytes, WASM_RUNTIME_IO, "wasm fences").is_ok()
        );
        let leases = ReadinessLeasesFileV1::empty();
        let bytes = jcs_bytes(&leases).expect("jcs");
        assert_eq!(
            String::from_utf8(bytes.clone()).expect("utf8"),
            r#"{"leases":{},"runtimeKind":"wasm","schemaVersion":1}"#
        );
        let with_unknown = bytes.clone();
        let mut corrupted = String::from_utf8(with_unknown.clone()).expect("utf8");
        corrupted.pop();
        corrupted.push_str(r#","surplus":true}"#);
        assert!(parse_canonical::<WasmFencesFileV1>(
            corrupted.as_bytes(),
            WASM_RUNTIME_IO,
            "wasm fences"
        )
        .is_err());
    }

    #[test]
    fn v2_active_pointer_and_live_fence_are_the_only_wasm_ingress_authority() {
        let parsed = parse_canonical::<WasmControlStateFileV2>(
            GOLDEN_CONTROL_STATE_V2_JCS.as_bytes(),
            WASM_CONTROL_STATE_INVALID,
            "wasm control state",
        )
        .expect("golden control state parses");
        let application = parsed
            .applications
            .get("vector")
            .expect("vector application");
        let version = application.versions.first().expect("version row");
        let mut fences = WasmFencesFileV1 {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            applications: BTreeMap::from([(
                "vector".into(),
                WasmApplicationFenceV1 {
                    current_version_id: version.version_id.clone(),
                    records: BTreeMap::from([(
                        version.version_id.clone(),
                        WasmFenceRecordV1 {
                            version_id: version.version_id.clone(),
                            sandbox_id: "sbx-current".into(),
                            preparation_generation: 7,
                            execution_generation: 9,
                            secret_revision: application.secret_revision,
                            secret_snapshot_ref: "5".repeat(64),
                            secret_values_digest: "6".repeat(64),
                            config_revision: application.config_revision,
                            config_snapshot_ref: Some("7".repeat(64)),
                            config_values_digest: Some("8".repeat(64)),
                            alive: true,
                            lifecycle: "active".into(),
                            binding_revoked: false,
                            drain_deadline_epoch_millis: None,
                        },
                    )]),
                },
            )]),
        };
        let selected = resolve_active_ingress_from_records("vector", &parsed.applications, &fences)
            .expect("the current active pointer may route");
        assert_eq!(selected.sandbox_id, "sbx-current");
        assert_eq!(
            (
                selected.preparation_generation,
                selected.execution_generation
            ),
            (7, 9)
        );

        // A dead or stale fence cannot keep the active pointer routable.
        fences
            .applications
            .get_mut("vector")
            .expect("vector fence")
            .records
            .get_mut(&version.version_id)
            .expect("current fence")
            .alive = false;
        assert!(
            resolve_active_ingress_from_records("vector", &parsed.applications, &fences).is_none()
        );

        // A pointer whose generation no longer equals the v2 record is equally closed.
        fences
            .applications
            .get_mut("vector")
            .expect("vector fence")
            .records
            .get_mut(&version.version_id)
            .expect("current fence")
            .alive = true;
        let mut stale_pointer = parsed.applications.clone();
        stale_pointer
            .get_mut("vector")
            .expect("vector application")
            .route_generation += 1;
        assert!(resolve_active_ingress_from_records("vector", &stale_pointer, &fences).is_none());
    }

    #[test]
    fn v2_control_revision_is_monotonic_for_kernel_only_projections() {
        let mut state = WasmCommandControlState::default();
        advance_control_revision(&mut state)
            .expect("visible-admission projection advances the CAS revision");
        let after_visible_admission = state.control_revision;
        advance_control_revision(&mut state)
            .expect("route-pointer projection advances the same CAS revision");
        assert_eq!(after_visible_admission, 1);
        assert_eq!(state.control_revision, 2);
    }

    #[test]
    fn control_state_file_cas_rejects_a_stale_snapshot_without_overwriting_bytes() {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-control-cas-{}-{}",
            std::process::id(),
            crate::monitor::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = WasmRuntimePaths { root: root.join("wasm"), routes_registry: None };
        let runtime = WasmRuntime::startup(
            paths.clone(),
            &|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test gate record absent",
                ))
            },
            &|_| None,
        );
        let (mut state, registry, applications) = runtime
            .load_control_state()
            .expect("initial v2 control state");
        let expected = state.control_revision;
        advance_control_revision(&mut state).expect("first mutation advances the revision");
        runtime
            .save_control_state(Some(expected), &state, &registry, &applications)
            .expect("the current revision may commit");
        let committed = std::fs::read(paths.control_state()).expect("committed bytes");

        let mut stale = state.clone();
        advance_control_revision(&mut stale).expect("stale candidate remains structurally valid");
        let stale_error = runtime
            .save_control_state(Some(expected), &stale, &registry, &applications)
            .expect_err("an old expected revision must not overwrite the newer file");
        assert_eq!(
            stale_error.code,
            crate::wasm_commands::CONTROL_REVISION_CONFLICT
        );
        assert_eq!(
            std::fs::read(paths.control_state()).expect("stale write leaves bytes intact"),
            committed
        );

        let materialize_error = runtime
            .save_control_state(None, &stale, &registry, &applications)
            .expect_err("first-materialization CAS must not replace an existing v2 file");
        assert_eq!(
            materialize_error.code,
            crate::wasm_commands::CONTROL_REVISION_CONFLICT
        );
        assert_eq!(
            std::fs::read(paths.control_state()).expect("materialization race leaves bytes intact"),
            committed
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn first_v2_materialization_ignores_registry_and_fence_without_admitted_visible_witness() {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-v2-witness-only-{}-{}",
            std::process::id(),
            crate::monitor::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = WasmRuntimePaths { root: root.join("wasm"), routes_registry: None };
        std::fs::create_dir_all(&paths.root).expect("state root");
        let proof = unmaterialized_vector_proof();
        write_canonical(
            &paths.route_registry(),
            &WasmRouteRegistryFile {
                schema_version: ROUTE_REGISTRY_SCHEMA_VERSION,
                runtime_kind: RUNTIME_KIND_WASM.into(),
                proofs: vec![proof.clone()],
                lifecycles: BTreeMap::from([(proof.version_id.clone(), "active".into())]),
                retirements: Vec::new(),
                journal_head_hint: 0,
            },
        )
        .expect("rogue audit projection writes");
        write_canonical(
            &paths.fences(),
            &WasmFencesFileV1 {
                schema_version: 1,
                runtime_kind: RUNTIME_KIND_WASM.into(),
                applications: BTreeMap::from([(
                    proof.application_id.clone(),
                    WasmApplicationFenceV1 {
                        current_version_id: proof.version_id.clone(),
                        records: BTreeMap::from([(
                            proof.version_id.clone(),
                            WasmFenceRecordV1 {
                                version_id: proof.version_id.clone(),
                                sandbox_id: "sbx-rogue".into(),
                                preparation_generation: 1,
                                execution_generation: 1,
                                secret_revision: 0,
                                secret_snapshot_ref: "5".repeat(64),
                                secret_values_digest: "6".repeat(64),
                                config_revision: 0,
                                config_snapshot_ref: None,
                                config_values_digest: None,
                                alive: true,
                                lifecycle: "active".into(),
                                binding_revoked: false,
                                drain_deadline_epoch_millis: None,
                            },
                        )]),
                    },
                )]),
            },
        )
        .expect("rogue fence projection writes");

        let runtime = WasmRuntime::startup(
            paths.clone(),
            &|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test gate record absent",
                ))
            },
            &|_| None,
        );
        let state = runtime.control_state_projection().expect("v2 projection");
        assert!(state.applications.is_empty(), "only the admission objects + visible DB row + receipt predicate may materialize v2 versions");
        assert!(runtime
            .resolve_active_ingress(&proof.application_id)
            .is_none());
        let _ = std::fs::remove_dir_all(root);
    }


    // -----------------------------------------------------------------------
    // 命令生成不按 admission 行代际分选（单版本化）：policy 在 proof 上则携带其
    // digest，否则 policy 钉为空串（命令仍生成，只是不获得 host services）。
    // -----------------------------------------------------------------------

    /// 在独立状态根上提交一条 admission（文件 witness 三件套 + journal）并 startup
    /// runtime（startup 序含 reconcile_visible_* 两步）。
    fn commit_admission_and_open_runtime(tag: &str, request: &AdmissionRequest) -> WasmRuntime {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-command-generation-{}-{}-{}",
            tag,
            std::process::id(),
            crate::monitor::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = WasmRuntimePaths { root: root.join("wasm"), routes_registry: None };
        std::fs::create_dir_all(&paths.root).expect("state root");
        let mut journal =
            WasmAdmissionJournalFile::open(&paths.admission_journal()).expect("admission journal opens");
        let mut objects = FileAdmissionObjects::open(&paths.admission_objects());
        let mut db = FileAdmissionDb::open(&paths.admission_db()).expect("admission db opens");
        let mut materializer =
            FileAdmissionMaterializer::open(&paths.admission_receipts()).expect("materializer opens");
        let mut token = OsRandomTokenSource;
        let mut stores = AdmissionStores {
            journal: &mut journal,
            objects: &mut objects,
            db: &mut db,
            materializer: &mut materializer,
        };
        // fixture 自洽：blob 名必须是内容的 sha256（commit 按内容寻址复验）。
        let mut request = request.clone();
        let blob_digest = {
            use sha2::Digest as _;
            let mut hasher = Sha256::new();
            hasher.update(b"layer");
            hex::encode(hasher.finalize())
        };
        request.blobs = vec![(blob_digest, b"layer".to_vec())];
        commit_wasm_admission(&mut stores, &request, &mut token, 1_000).expect("admission commits");
        WasmRuntime::startup(
            paths.clone(),
            &|_| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "test gate record absent")),
            &|_| None,
        )
    }

    #[test]
    fn service_admission_row_generates_policy_pinned_commands_in_reconcile() {
        let runtime = commit_admission_and_open_runtime("v2-row", &v2_service_admission_request());
        let state = runtime.control_state_projection().expect("v2 projection");
        let policy_digest = KV_ONLY_POLICY_DIGEST.to_string();
        for operation in [WasmExecutionOperation::Prepare, WasmExecutionOperation::Start] {
            let entry = state
                .command_outbox
                .iter()
                .find(|entry| entry.command.operation == operation)
                .unwrap_or_else(|| panic!("{operation:?} command authorized"));
            let command = &entry.command;
            // 身份增量：applicationId/matrixRevision/policyDigest/fenceNonce + ABI 1.1.0。
            assert_eq!(command.application_id, "vector");
            assert_eq!(command.matrix_revision, crate::wasm_host_services::WASM_CAPABILITY_MATRIX_REVISION_2);
            assert_eq!(command.host_service_policy_digest, policy_digest);
            assert!(
                command.fence_nonce.len() == 32 && command.fence_nonce.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "fenceNonce must be 32 lower-case hex characters"
            );
            assert_eq!(command.runtime_binding.host_abi, crate::wasm_host_services::HOST_ABI_LITERAL_V2);
            // admission 事实保留（catalog/capability pin 逐字段来自 proof binding）。
            assert_eq!(command.runtime_binding.catalog_revision, 9);
            assert_eq!(command.runtime_binding.catalog_hash, "ab".repeat(32));
            assert_eq!(command.capability_record_revision, 2);
            assert_eq!(command.capability_record_hash, "2".repeat(64));
            // 命令自洽：完整校验 + 域摘要可复算（64 位小写十六进制）。
            assert!(crate::wasm_commands::validate_execution_command(command).is_ok());
            let digest = crate::wasm_commands::execution_command_digest(command).expect("digest");
            assert!(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        }
    }

    #[test]
    fn policyless_admission_row_keeps_uniform_commands_with_empty_policy() {
        // 同一 fixture 去 policy（V1 manifest + host_service_policy:none）：命令仍是
        // 唯一 wire，policy 钉为空串（无 host services）。
        let mut request = v2_service_admission_request();
        request.host_service_policy = None;
        request.normalized_policy = serde_json::from_str(SPEC_VECTOR_MANIFEST).expect("v1 manifest");
        let runtime = commit_admission_and_open_runtime("v1-row", &request);
        let state = runtime.control_state_projection().expect("v2 projection");
        assert!(
            state
                .command_outbox
                .iter()
                .all(|entry| crate::wasm_commands::validate_execution_command(&entry.command).is_ok()
                    && entry.command.host_service_policy_digest.is_empty()
                    && entry.command.runtime_binding.host_abi == crate::wasm_host_services::HOST_ABI_LITERAL_V2),
            "a non-service admission row keeps the uniform command wire with an empty policy pin"
        );
        assert!(
            state
                .command_outbox
                .iter()
                .any(|entry| entry.command.operation == WasmExecutionOperation::Prepare)
                && state
                    .command_outbox
                    .iter()
                    .any(|entry| entry.command.operation == WasmExecutionOperation::Start),
            "both Prepare and Start are authorized for the visible V1 row"
        );
    }

    // -----------------------------------------------------------------------
    // Kernel activation 入口集成测试（单版本 wire）：gate 按目标版本行分选
    // （service-enabled 行 → v3 记录门；否则 v2 记录门）→ 命令/lease/gate →
    // 路由事件持久化 + v2 控制态投影。
    // -----------------------------------------------------------------------

    /// 提交 admission 后以（可选）v3 验收记录 + 双开关启动 runtime。
    fn commit_admission_and_open_service_runtime(tag: &str, request: &AdmissionRequest, record: Option<Vec<u8>>) -> (WasmRuntime, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-v2-activation-{}-{}-{}",
            tag,
            std::process::id(),
            crate::monitor::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = WasmRuntimePaths { root: root.join("wasm"), routes_registry: None };
        std::fs::create_dir_all(&paths.root).expect("state root");
        let mut journal =
            WasmAdmissionJournalFile::open(&paths.admission_journal()).expect("admission journal opens");
        let mut objects = FileAdmissionObjects::open(&paths.admission_objects());
        let mut db = FileAdmissionDb::open(&paths.admission_db()).expect("admission db opens");
        let mut materializer =
            FileAdmissionMaterializer::open(&paths.admission_receipts()).expect("materializer opens");
        let mut token = OsRandomTokenSource;
        let mut stores = AdmissionStores {
            journal: &mut journal,
            objects: &mut objects,
            db: &mut db,
            materializer: &mut materializer,
        };
        let mut request = request.clone();
        let blob_digest = {
            use sha2::Digest as _;
            let mut hasher = Sha256::new();
            hasher.update(b"layer");
            hex::encode(hasher.finalize())
        };
        request.blobs = vec![(blob_digest, b"layer".to_vec())];
        commit_wasm_admission(&mut stores, &request, &mut token, 1_000).expect("admission commits");
        if record.is_some() {
            write_v2_gate_node_identity(&paths);
        }
        let runtime = WasmRuntime::startup(
            paths,
            &|path| {
                if path == crate::wasm_publication::WASM_ACCEPTANCE_FILE {
                    record
                        .clone()
                        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
                }
            },
            &|name| (name == crate::wasm_publication::ENV_WASM_PUBLICATION_ENABLED).then(|| "1".to_string()),
        );
        (runtime, root)
    }

    /// V2 激活 fixture：从 v2 控制态行推导 V2 命令 + V2 lease，并播种 fence 文件。
    fn activation_fixture(
        runtime: &WasmRuntime,
        now_epoch_millis: u64,
    ) -> crate::wasm_activation::ActivationCommand {
        let state = runtime.control_state_projection().expect("v2 projection");
        let application = &state.applications["vector"];
        let version = &application.versions[0];
        let binding_v2 =
            crate::wasm_commands::runtime_binding_v2_from_v1(&version.runtime_binding).expect("binding derives");
        // V2 lease（激活面）：admission 事实 + policy digest + digestV2 域摘要。
        let mut lease = crate::wasm_activation::ServiceReadinessLeaseV2 {
            schema_version: 2,
            lease_nonce: "0f1e2d3c4b5a69788796a5b4c3d2e1f0".into(),
            sandbox_id: "sbx-vector".into(),
            version_id: version.version_id.clone(),
            package_digest: version.package_digest.clone(),
            runtime_binding: binding_v2.clone(),
            host_service_policy_digest: KV_ONLY_POLICY_DIGEST.into(),
            capability_record_revision: 2,
            capability_record_hash: "2".repeat(64),
            secret_revision: 3,
            secret_values_digest: "6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some("7".repeat(64)),
            config_values_digest: Some("8".repeat(64)),
            preparation_generation: 1,
            execution_generation: 1,
            issued_at: crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis),
            expires_at: crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis + 600_000),
            lease_digest: String::new(),
        };
        lease.lease_digest =
            crate::wasm_activation::compute_service_readiness_lease_digest(&lease).expect("lease digest");
        assert!(lease.validate().is_ok());
        // 播种 fence（激活判据的 Kernel 权威文件契约）。
        let fences = WasmFencesFileV1 {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            applications: BTreeMap::from([(
                "vector".into(),
                WasmApplicationFenceV1 {
                    current_version_id: version.version_id.clone(),
                    records: BTreeMap::from([(
                        version.version_id.clone(),
                        WasmFenceRecordV1 {
                            version_id: version.version_id.clone(),
                            sandbox_id: "sbx-vector".into(),
                            preparation_generation: 1,
                            execution_generation: 1,
                            secret_revision: 3,
                            secret_snapshot_ref: "5".repeat(64),
                            secret_values_digest: "6".repeat(64),
                            config_revision: 2,
                            config_snapshot_ref: Some("7".repeat(64)),
                            config_values_digest: Some("8".repeat(64)),
                            alive: true,
                            lifecycle: "ready".into(),
                            binding_revoked: false,
                            drain_deadline_epoch_millis: None,
                        },
                    )]),
                },
            )]),
        };
        write_canonical(&runtime.paths.fences(), &fences).expect("fences seed");
        // 播种 V2 lease 台账（gateway v2 探针文件契约；本测试直接落盘）。
        let leases = ReadinessLeasesFileV1 {
            schema_version: 1,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            leases: BTreeMap::from([(lease.lease_nonce.clone(), (lease.clone()))]),
        };
        write_canonical(&runtime.paths.readiness_leases(), &leases).expect("leases seed");
        // 第五轮复审：命令携带与 v2 控制态 CAS 关联的 expectedControlRevision（以
        // 当前激活控制态文件的 revision 为准；空文件 = 0）+ commandDigest 复算。
        let expected_control_revision = std::fs::read(runtime.paths.activation_state())
            .ok()
            .and_then(|bytes| {
                parse_canonical::<crate::wasm_activation::WasmActivationStateFileV1>(
                    &bytes,
                    WASM_RUNTIME_IO,
                    "activation state",
                )
                .ok()
            })
            .map(|file| file.control_revision)
            .unwrap_or(0);
        let command = crate::wasm_activation::ActivationCommand {
            schema_version: 2,
            activation_id: generate_uuid_v7(now_epoch_millis),
            application_id: "vector".into(),
            operation: crate::wasm_activation::ActivationOperation::Activate,
            expected_route_generation: 0,
            expected_control_revision,
            candidate: crate::wasm_activation::ActivationCandidate {
                runtime_kind: "wasm".into(),
                sandbox_id: "sbx-vector".into(),
                version_id: version.version_id.clone(),
                package_digest: version.package_digest.clone(),
                runtime_binding: binding_v2,
                admission_proof_ref: version.admission_proof_ref.clone(),
                admission_proof_digest: version.admission_proof_digest.clone(),
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
            host_service_policy_digest: KV_ONLY_POLICY_DIGEST.into(),
            // capability record pin 实值（必填，经 commandDigest 覆盖）。
            capability_record_revision: 2,
            capability_record_hash: "4".repeat(64),
            requested_at: crate::wasm_admission::format_rfc3339_utc_millis(now_epoch_millis),
            command_digest: String::new(),
        };
        let command_digest =
            crate::wasm_activation::compute_activation_command_digest(&command).expect("command digest");
        crate::wasm_activation::ActivationCommand { command_digest, ..command }
    }

    fn service_activation_envelope(
        command: &crate::wasm_activation::ActivationCommand,
        now_epoch_millis: u64,
    ) -> Vec<u8> {
        let envelope = serde_json::json!({
            "protocol": crate::wasm_activation::ACTIVATION_RPC_PROTOCOL_LITERAL,
            "requestId": generate_uuid_v7(now_epoch_millis + 1),
            "body": serde_json::to_value(command).expect("command value"),
        });
        jcs_bytes(&envelope).expect("envelope JCS")
    }

    fn call_activation(runtime: &mut WasmRuntime, envelope: &[u8]) -> (u16, serde_json::Value) {
        let response = runtime.handle_activation_rpc(
            Some("Bearer owner"),
            Some("application/json"),
            envelope,
            &|bearer| bearer == Some("Bearer owner"),
        );
        let parsed: serde_json::Value =
            serde_json::from_str(response.body.trim()).expect("response JSON");
        (response.status, parsed)
    }

    #[test]
    fn activation_rpc_dispatches_gate_by_target_row_and_persists_route_event() {
        let now = now_millis_u64();
        // (a) service gate 关（无 v3 记录）：V2 envelope → 503，绝不落 V1 门。
        let (mut runtime, root) =
            commit_admission_and_open_service_runtime("gate-closed", &v2_service_admission_request(), None);
        let command = activation_fixture(&runtime, now);
        let (status, body) = call_activation(&mut runtime, &service_activation_envelope(&command, now));
        assert_eq!(status, 503, "body: {body}");
        assert_eq!(body["code"], json!("WASM_PUBLICATION_DISABLED"));
        let _ = std::fs::remove_dir_all(&root);

        // (b) v3 记录 + 双开关：service-enabled 目标行 → activated（事件持久化 + 投影）。
        let (mut runtime, root) = commit_admission_and_open_service_runtime(
            "happy",
            &v2_service_admission_request(),
            Some(v3_acceptance_record_bytes()),
        );
        let command = activation_fixture(&runtime, now);
        let (status, body) = call_activation(&mut runtime, &service_activation_envelope(&command, now));
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(
            body["protocol"],
            json!(crate::wasm_activation::ACTIVATION_RPC_PROTOCOL_LITERAL)
        );
        assert_eq!(body["body"]["status"], json!("activated"));
        assert_eq!(body["body"]["event"]["schemaVersion"], json!(2));
        assert_eq!(body["body"]["event"]["hostServicePolicyDigest"], json!(KV_ONLY_POLICY_DIGEST));
        assert_eq!(body["body"]["event"]["routeGeneration"], json!(1));
        assert_eq!(
            body["body"]["event"]["next"]["runtimeBinding"]["hostABI"],
            json!("iweb-wasmd-abi@1.0.0"),
            "the route pointer keeps the admission-fact binding"
        );
        // 指针携带候选代次（单版本化后指针仅有的三个可选增量之一）。
        assert_eq!(body["body"]["event"]["next"]["preparationGeneration"], json!(1));
        assert_eq!(body["body"]["event"]["next"]["executionGeneration"], json!(1));
        // v2 控制态投影：V2 事件经同一 projection 面（union）翻转 active 指针。
        let control = runtime.control_state_projection().expect("projection");
        let application = &control.applications["vector"];
        assert_eq!(application.route_generation, 1);
        assert!(
            matches!(&application.active, WasmActivePointerV1::Active { version_id, route_generation, .. }
                if version_id == &command.candidate.version_id && *route_generation == 1)
        );
        assert_eq!(
            application
                .versions
                .iter()
                .find(|row| row.version_id == command.candidate.version_id)
                .expect("row")
                .lifecycle,
            "active"
        );
        // 激活控制态：路由事件持久化 + nonce 消费。
        let activation_state = runtime
            .load_activation_states()
            .get("vector")
            .cloned()
            .expect("activation state");
        assert_eq!(activation_state.route_generation, 1);
        assert!(activation_state.events.last().is_some());
        // byte-identical replay：同命令返回原始 V2 事件，无二次递增（路由代次/nonce/
        // 事件清单不变；controlRevision 的 outbox delivery 记账与路由 CAS 幂等正交）。
        let (status, replay_body) = call_activation(&mut runtime, &service_activation_envelope(&command, now));
        assert_eq!(status, 200);
        assert_eq!(replay_body["body"]["event"], body["body"]["event"]);
        let control = runtime.control_state_projection().expect("projection");
        assert_eq!(control.applications["vector"].route_generation, 1);
        let replayed_state = runtime
            .load_activation_states()
            .get("vector")
            .cloned()
            .expect("activation state");
        assert_eq!(replayed_state.events.len(), activation_state.events.len());
        assert_eq!(replayed_state.nonce_ledger.len(), 1);
        assert_eq!(replayed_state.route_generation, 1);
        let _ = std::fs::remove_dir_all(&root);

        // (c) 非 service 行目标：R2 修复轮 9.7 单 gate——不再按目标行代际分选；
        // v3 记录开同一 gate，V1 行目标同样过门（admission 时的 pin 绑定已约束该行，
        // 激活门只看发布开关；本 fixture 的 CAS 判据齐备 → activated）。
        let mut v1_request = v2_service_admission_request();
        v1_request.host_service_policy = None;
        v1_request.normalized_policy = serde_json::from_str(SPEC_VECTOR_MANIFEST).expect("v1 manifest");
        let (mut runtime, root) = commit_admission_and_open_service_runtime(
            "v1-row-target",
            &v1_request,
            Some(v3_acceptance_record_bytes()),
        );
        let command = activation_fixture(&runtime, now);
        let (status, body) = call_activation(&mut runtime, &service_activation_envelope(&command, now));
        // 单 gate 开 → 不再被发布门 503 围栏；请求进入正常 CAS 判定（本 fixture 的
        // service 形 envelope 对 V1 行给出 typed 拒绝——那是激活面语义，不是门语义）。
        assert_eq!(status, 200, "body: {body}");
        assert_ne!(body["code"], json!("WASM_PUBLICATION_DISABLED"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn admission_submit_wire_rejects_unknown_and_duplicate_blobs() {
        assert!(parse_admission_submit(b"{ not json").is_err());
        assert!(parse_admission_submit(br#"{"schemaVersion":2}"#).is_err());
        // 正常最小形状（manifest/binding 交由上层校验；此处只验 wire 解析面）。
        let manifest = serde_json::from_str::<NormalizedWasmManifestV1>(SPEC_VECTOR_MANIFEST)
            .expect("manifest");
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
        let failure = parse_admission_submit(jcs_bytes(&body).expect("jcs").as_slice())
            .expect_err("duplicate digest must be rejected");
        assert_eq!(failure.code, WASM_ADMISSION_WIRE_INVALID);
        let mut unique = body.clone();
        unique["blobs"][1]["digestHex"] = json!("2".repeat(64));
        let request =
            parse_admission_submit(jcs_bytes(&unique).expect("jcs").as_slice()).expect("parses");
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

    fn unmaterialized_vector_proof() -> AdmissionProofV1 {
        let normalized_policy =
            serde_json::from_str::<NormalizedWasmManifestV1>(SPEC_VECTOR_MANIFEST)
                .expect("vector manifest");
        let package_digest = "0".repeat(64);
        let version_digest = crate::wasm_admission::wasm_version_digest_v1(
            &package_digest,
            &jcs_bytes(&normalized_policy).expect("manifest JCS"),
        );
        AdmissionProofV1 {
            schema_version: 1,
            application_id: "vector".into(),
            package_digest,
            version_id: crate::wasm_admission::compose_wasm_version_id(&version_digest, 1),
            version_digest,
            sequence: 1,
            normalized_policy,
            lifecycle_admission_record: crate::wasm_admission::LifecycleAdmissionRecord {
                schema_version: 1,
                state: "admitted".into(),
                admitted_at: "2026-08-26T00:00:00Z".into(),
                admission_journal_revision: 0,
            },
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            commit_token_hash: "3".repeat(64),
            host_service_policy: None,
        }
    }

    // ------------------------------------------------------------------
    // P0-3（add-wasm-host-services Kernel 半边）：V2 admission wire、代际发布门、
    // preparation reserve 交叉校验与控制态静态摘要
    // ------------------------------------------------------------------

    const SPEC_VECTOR_V2_MANIFEST: &str = r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":268435456,"pidLimit":3,"storageBytes":1048576},"runtime":{"declaredHostImports":[{"direction":"import","interface":"store","package":"iweb:kv@1.0.0"}],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#;
    const KV_ONLY_POLICY_DIGEST: &str = "b21afb8e8cb4e6482b137ef5749ea2b9c39e4ef35619bfb079d4c83bd75bb665";

    fn kv_only_policy() -> crate::wasm_host_services::HostServicePolicyV2 {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/wasm/host-services-golden-vectors.json");
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
        crate::wasm_host_services::HostServicePolicyV2::seal(&payload).expect("policy seals")
    }

    fn v2_manifest() -> NormalizedWasmManifestV1 {
        serde_json::from_str(SPEC_VECTOR_V2_MANIFEST).expect("v2 manifest")
    }

    /// V2 proof（直接构造，digest 公式与 create_or_join 相同）。
    fn v2_vector_proof(reserve_override: Option<u64>) -> AdmissionProofV1 {
        let normalized_policy = v2_manifest();
        let mut policy = kv_only_policy();
        if let Some(reserve) = reserve_override {
            policy.reserve_bytes = reserve;
            policy.policy_digest =
                crate::wasm_host_services::HostServicePolicyV2::compute_policy_digest(&policy.payload())
                    .expect("digest reseals");
        }
        let package_digest = "0".repeat(64);
        let manifest_value: serde_json::Value = serde_json::from_str(SPEC_VECTOR_V2_MANIFEST).unwrap();
        let version_digest = crate::wasm_host_services::wasm_host_service_version_digest_v2(
            &package_digest,
            &manifest_value,
            &policy.policy_digest,
        )
        .expect("v2 digest");
        AdmissionProofV1 {
            schema_version: 1,
            application_id: "vector".into(),
            package_digest,
            version_id: crate::wasm_admission::compose_wasm_version_id(&version_digest, 1),
            version_digest,
            sequence: 1,
            normalized_policy,
            lifecycle_admission_record: crate::wasm_admission::LifecycleAdmissionRecord {
                schema_version: 1,
                state: "admitted".into(),
                admitted_at: "2026-08-26T00:00:00Z".into(),
                admission_journal_revision: 0,
            },
            runtime_binding: vector_binding(),
            capability_record_revision: 2,
            capability_record_hash: "2".repeat(64),
            commit_token_hash: "3".repeat(64),
            host_service_policy: Some(policy),
        }
    }

    /// 合法自 digest 的 V3 验收记录 JCS（值与 wasm_publication 测试同源）。
    fn v3_acceptance_record_bytes() -> Vec<u8> {
        let payload = crate::wasm_publication::WasmAcceptanceRecordPayloadV3 {
            version: 3,
            matrix_revision: 2,
            result: "passed".into(),
            gate: "application-sandbox".into(),
            runtime_kind: "wasm".into(),
            runtime_image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: crate::wasm_publication::WASM_HOST_ABI_LITERAL_V2.into(),
            world: crate::wasm_admission::WASM_WORLD_LITERAL.into(),
            arch: "linux/amd64".into(),
            capability_record_revision: 2,
            capability_record_hash: "2".repeat(64),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            catalog_entry_key: "iweb-wasmd".into(),
            host_service_policy_digest: KV_ONLY_POLICY_DIGEST.into(),
            evidence_digest: "e".repeat(64),
        };
        let digest = crate::wasm_publication::compute_wasm_acceptance_record_digest_v3(&payload)
            .expect("record digest");
        let full = serde_json::json!({
            "arch": payload.arch,
            "capabilityRecordHash": payload.capability_record_hash,
            "capabilityRecordRevision": payload.capability_record_revision,
            "catalogEntryKey": payload.catalog_entry_key,
            "catalogHash": payload.catalog_hash,
            "catalogRevision": payload.catalog_revision,
            "evidenceDigest": payload.evidence_digest,
            "gate": payload.gate,
            "hostABI": payload.host_abi,
            "hostServicePolicyDigest": payload.host_service_policy_digest,
            "matrixRevision": payload.matrix_revision,
            "recordDigest": digest,
            "result": payload.result,
            "runtimeImageDigest": payload.runtime_image_digest,
            "runtimeKind": payload.runtime_kind,
            "version": payload.version,
            "world": payload.world,
        });
        jcs_bytes(&full).expect("record JCS")
    }

    fn v2_service_admission_request() -> AdmissionRequest {
        AdmissionRequest {
            application_id: "vector".into(),
            package_digest: "0".repeat(64),
            normalized_policy: v2_manifest(),
            runtime_binding: vector_binding(),
            capability_record_revision: 2,
            capability_record_hash: "2".repeat(64),
            host_service_policy: Some(kv_only_policy()),
            staging_ttl_seconds: 600,
            blobs: vec![("1".repeat(64), b"layer".to_vec())],
            allow_resequence: false,
        }
    }

    /// V2 节点身份 pin 文件（capability record revision 2 / hostABI 1.1.0）。
    fn write_v2_gate_node_identity(paths: &WasmRuntimePaths) {
        write_canonical(
            &paths.gate_node_identity(),
            &GateNodeIdentityFileV1 {
                schema_version: 1,
                runtime_kind: RUNTIME_KIND_WASM.into(),
                architecture: "linux/amd64".into(),
                capability_record_revision: 2,
                capability_record_hash: "2".repeat(64),
                catalog_revision: 9,
                catalog_hash: "ab".repeat(32),
                catalog_entry: GateNodeIdentityEntryFileV1 {
                    entry_key: "iweb-wasmd".into(),
                    image_digest: format!("sha256:{}", "cd".repeat(32)),
                    host_abi: crate::wasm_publication::WASM_HOST_ABI_LITERAL_V2.into(),
                    world: crate::wasm_admission::WASM_WORLD_LITERAL.into(),
                },
            },
        )
        .expect("gate node identity writes");
    }



    /// V1 代际节点身份（hostABI 1.0.0；与 v2 记录 gate 的正向配对）。
    fn write_v1_gate_node_identity(paths: &WasmRuntimePaths) {
        write_canonical(
            &paths.gate_node_identity(),
            &GateNodeIdentityFileV1 {
                schema_version: 1,
                runtime_kind: RUNTIME_KIND_WASM.into(),
                architecture: "linux/amd64".into(),
                capability_record_revision: 2,
                capability_record_hash: "2".repeat(64),
                catalog_revision: 9,
                catalog_hash: "ab".repeat(32),
                catalog_entry: GateNodeIdentityEntryFileV1 {
                    entry_key: "iweb-wasmd".into(),
                    image_digest: format!("sha256:{}", "cd".repeat(32)),
                    host_abi: crate::wasm_admission::WASM_HOST_ABI_LITERAL.into(),
                    world: crate::wasm_admission::WASM_WORLD_LITERAL.into(),
                },
            },
        )
        .expect("gate node identity writes");
    }

    /// v2 记录节点（V1 代际身份）上的单 gate 运行时。
    fn v2_record_runtime(record: Vec<u8>) -> WasmRuntime {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-v2-record-gate-{}-{}",
            std::process::id(),
            crate::monitor::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = WasmRuntimePaths { root: root.join("wasm"), routes_registry: None };
        std::fs::create_dir_all(&paths.root).expect("state root");
        write_v1_gate_node_identity(&paths);
        WasmRuntime::startup(
            paths,
            &|path| {
                if path == crate::wasm_publication::WASM_ACCEPTANCE_FILE {
                    Ok(record.clone())
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
                }
            },
            &|name| (name == crate::wasm_publication::ENV_WASM_PUBLICATION_ENABLED).then(|| "1".to_string()),
        )
    }

    fn service_runtime(record: Vec<u8>) -> WasmRuntime {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-service-gate-{}-{}",
            std::process::id(),
            crate::monitor::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let paths = WasmRuntimePaths { root: root.join("wasm"), routes_registry: None };
        std::fs::create_dir_all(&paths.root).expect("state root");
        write_v2_gate_node_identity(&paths);
        let runtime = WasmRuntime::startup(
            paths,
            &|path| {
                if path == crate::wasm_publication::WASM_ACCEPTANCE_FILE {
                    Ok(record.clone())
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
                }
            },
            &|name| (name == crate::wasm_publication::ENV_WASM_PUBLICATION_ENABLED).then(|| "1".to_string()),
        );
        // startup 内部临时根由測試持有；返回前登记清理路径由用例自行删除。
        runtime
    }

    #[test]
    fn admission_submit_wire_parses_the_v2_host_service_policy() {
        let manifest = serde_json::from_str::<NormalizedWasmManifestV1>(SPEC_VECTOR_V2_MANIFEST)
            .expect("v2 manifest");
        let policy = serde_json::to_value(kv_only_policy()).expect("policy value");
        let body = json!({
            "schemaVersion": 1,
            "applicationId": "vector",
            "packageDigest": "0".repeat(64),
            "normalizedPolicy": manifest,
            "runtimeBinding": serde_json::to_value(vector_binding()).expect("binding"),
            "capabilityRecordRevision": 2,
            "capabilityRecordHash": "2".repeat(64),
            "hostServicePolicy": policy,
            "stagingTtlSeconds": 60,
            "blobs": [
                { "digestHex": "1".repeat(64), "base64": base64::engine::general_purpose::STANDARD.encode(b"payload-a") },
            ],
        });
        let request = parse_admission_submit(jcs_bytes(&body).expect("jcs").as_slice()).expect("parses");
        let policy = request.host_service_policy.expect("wire policy lands in the request");
        assert_eq!(policy.policy_digest, KV_ONLY_POLICY_DIGEST);
        // policy 内未知成员：deny_unknown_fields 在 wire 层拒绝。
        let mut unknown = body.clone();
        unknown["hostServicePolicy"]["extra"] = json!(true);
        assert!(parse_admission_submit(jcs_bytes(&unknown).expect("jcs").as_slice()).is_err());
        // V1 wire（无 hostServicePolicy）依旧解析为 None。
        let mut v1 = body;
        as_object_remove(&mut v1, "hostServicePolicy");
        let request = parse_admission_submit(jcs_bytes(&v1).expect("jcs").as_slice()).expect("v1 parses");
        assert!(request.host_service_policy.is_none());
    }

    fn response_code(response: &WasmHttpResponse) -> String {
        let body: serde_json::Value = serde_json::from_str(&response.body).expect("response body is JSON");
        body["code"].as_str().expect("code member").to_string()
    }

    fn as_object_remove(value: &mut serde_json::Value, key: &str) {
        if let serde_json::Value::Object(map) = value {
            map.remove(key);
        }
    }

    #[test]
    fn admitted_application_check_backs_the_user_route_law() {
        // R2 修复轮 9.9b：require_admitted_application——已提交 admission 的应用为
        // true；未知名为 false；状态围栏（坏 socket 路径）为 Err。
        let (runtime, root) =
            commit_admission_and_open_service_runtime("route-law", &v2_service_admission_request(), Some(v3_acceptance_record_bytes()));
        assert!(runtime.require_admitted_application("vector").expect("control state is readable"));
        assert!(!runtime.require_admitted_application("notes").expect("unknown app is not admitted"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn service_enabled_gate_binds_the_v3_record_pins_to_the_admission_request() {
        let runtime = service_runtime(v3_acceptance_record_bytes());
        // 匹配的 V2 请求：单 gate 开 + 记录 pin 绑定通过。
        runtime
            .require_admission_publication_gate(&v2_service_admission_request())
            .expect("matching v2 request passes the single gate and record binding");
        // policy digest 失配：结构化 400（WASM_ADMISSION_NODE_PIN_MISMATCH）。
        let mut request = v2_service_admission_request();
        let policy = request.host_service_policy.as_mut().expect("policy");
        policy.policy_digest = "0".repeat(64);
        let response = runtime
            .require_admission_publication_gate(&request)
            .expect_err("policy digest mismatch must fail");
        assert_eq!(response.status, 400);
        assert_eq!(response_code(&response), WASM_ADMISSION_NODE_PIN_MISMATCH);
        // capability revision 失配（请求 3 ≠ 记录 2）。
        let mut request = v2_service_admission_request();
        request.capability_record_revision = 3;
        let response = runtime
            .require_admission_publication_gate(&request)
            .expect_err("capability pin mismatch must fail");
        assert_eq!(response.status, 400);
        // V1 请求在 v3 记录节点上：单 gate 开 → 通过（R2 修复轮 9.7：无代际分选；
        // V1 请求不携带 host-service pin，无需与记录绑定）。
        let mut v1_request = v2_service_admission_request();
        v1_request.host_service_policy = None;
        runtime
            .require_admission_publication_gate(&v1_request)
            .expect("a v1 request passes the single wasm gate");
        let _ = std::fs::remove_dir_all(runtime.paths.root.parent().expect("temp root"));
    }

    #[test]
    fn v2_request_on_a_v2_record_node_stays_service_closed() {
        // 文件承载 v2 记录：单 gate 开（v2 记录合法），但 service-enabled 请求要求
        // gate 携带 v3 记录的 host-service pin → 结构性 503（fail-closed，不猜 pin）。
        let golden_v2_record = {
            // 与 wasm_publication 测试同值的合法 v2 记录。
            let payload = crate::wasm_publication::WasmAcceptanceRecordPayloadV2 {
                version: 2,
                result: "passed".into(),
                gate: "application-sandbox".into(),
                runtime_kind: "wasm".into(),
                runtime_image_digest: format!("sha256:{}", "cd".repeat(32)),
                host_abi: crate::wasm_admission::WASM_HOST_ABI_LITERAL.into(),
                world: crate::wasm_admission::WASM_WORLD_LITERAL.into(),
                arch: "linux/amd64".into(),
                capability_record_revision: 2,
                capability_record_hash: "2".repeat(64),
                catalog_revision: 9,
                catalog_hash: "ab".repeat(32),
                catalog_entry_key: "iweb-wasmd".into(),
                evidence_digest: "e".repeat(64),
            };
            let digest = crate::wasm_publication::compute_wasm_acceptance_record_digest_v2(&payload)
                .expect("v2 digest");
            let full = serde_json::json!({
                "arch": payload.arch,
                "capabilityRecordHash": payload.capability_record_hash,
                "capabilityRecordRevision": payload.capability_record_revision,
                "catalogEntryKey": payload.catalog_entry_key,
                "catalogHash": payload.catalog_hash,
                "catalogRevision": payload.catalog_revision,
                "evidenceDigest": payload.evidence_digest,
                "gate": payload.gate,
                "hostABI": payload.host_abi,
                "recordDigest": digest,
                "result": payload.result,
                "runtimeImageDigest": payload.runtime_image_digest,
                "runtimeKind": payload.runtime_kind,
                "version": payload.version,
                "world": payload.world,
            });
            jcs_bytes(&full).expect("record JCS")
        };
        let runtime = v2_record_runtime(golden_v2_record);
        let response = runtime
            .require_admission_publication_gate(&v2_service_admission_request())
            .expect_err("a v2 record can never bind the service-enabled admission identity");
        assert_eq!(response.status, 503);
        assert_eq!(response_code(&response), WASM_PUBLICATION_DISABLED);
        // 同一节点：V1 请求通过（单 gate 由 v2 记录 + V1 代际身份打开）。
        let mut v1_request = v2_service_admission_request();
        v1_request.host_service_policy = None;
        runtime
            .require_admission_publication_gate(&v1_request)
            .expect("a v1 request passes behind the v2 record gate");
        let _ = std::fs::remove_dir_all(runtime.paths.root.parent().expect("temp root"));
    }

    #[test]
    fn preparation_reserve_gate_enforces_the_ts_reserve_formula() {
        // 合法 V2 proof（reserve 32MiB < memory 256MiB）：通过。
        WasmRuntime::preparation_reserve_gate(&v2_vector_proof(None)).expect("valid reserve passes");
        // reserve == memory：fail-closed，绝不代默认（构造时 digest 重封保持自洽）。
        let bad = v2_vector_proof(Some(268_435_456));
        let failure = WasmRuntime::preparation_reserve_gate(&bad).expect_err("reserve >= memory must fail closed");
        assert_eq!(
            failure.code,
            crate::wasm_host_services::WASM_GUEST_MEMORY_RESERVE_INVALID
        );
        // V1 proof 无 reserve 概念：永远通过（V1 路径不交叉解释）。
        WasmRuntime::preparation_reserve_gate(&unmaterialized_vector_proof()).expect("v1 proof passes");
    }





    #[test]
    fn control_state_v2_version_rows_carry_the_static_policy_summary() {
        let proof = v2_vector_proof(None);
        let row = project_registry_row(&proof).expect("row projects");
        let summary = row.host_service_policy_summary.as_ref().expect("summary present");
        assert_eq!(summary.policy_digest, KV_ONLY_POLICY_DIGEST);
        let control_row = WasmControlVersionRowV1::from(&row);
        assert_eq!(control_row.host_service_policy_summary.as_ref(), Some(summary));
        // 合成一份控制态：V2 行校验通过；摘要 profile 字面量漂移 → validate 拒绝。
        let state = WasmControlStateFileV2 {
            schema_version: 2,
            runtime_kind: RUNTIME_KIND_WASM.into(),
            control_revision: 0,
            applications: BTreeMap::from([(
                "vector".to_string(),
                WasmApplicationControlRecordV1 {
                    runtime_kind: RUNTIME_KIND_WASM.into(),
                    application_id: "vector".into(),
                    versions: vec![control_row.clone()],
                    active: WasmActivePointerV1::Unavailable {
                        runtime_kind: RUNTIME_KIND_WASM.into(),
                        application_id: "vector".into(),
                        route_generation: 0,
                    },
                    route_generation: 0,
                    secret_revision: 0,
                    config_revision: 0,
                },
            )]),
            command_outbox: Vec::new(),
        };
        state.validate().expect("v2 row with a static summary validates");
        let mut corrupted = state.clone();
        corrupted
            .applications
            .get_mut("vector")
            .expect("application")
            .versions[0]
            .host_service_policy_summary
            .as_mut()
            .expect("summary")
            .host_services
            .kv = Some("unknown-profile".into());
        assert!(corrupted.validate().is_err());
        // V1 行不携带摘要键（序列化字节无该成员）。
        let v1_row = WasmControlVersionRowV1::from(&project_registry_row(&unmaterialized_vector_proof()).unwrap());
        let v1_wire = serde_json::to_value(&v1_row).expect("v1 row wire");
        assert!(v1_wire.get("hostServicePolicySummary").is_none());
    }
}
