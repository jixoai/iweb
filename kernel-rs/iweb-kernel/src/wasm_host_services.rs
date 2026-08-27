//! 用户原始需求（2026-08-27，add-wasm-host-services Kernel 数据面权威批次）：Kernel 必须先有
//! per-app 宿主服务数据面的权威层——KV/SQL 后端目录与文件的派生/属主/preparation 生命周期、
//! 单一 quota ledger 的 reservation→commit/rollback→finalize 与崩溃恢复矩阵、以及「数据面 mutation
//! 永不推进 controlRevision」的结构保证；实现落在本模块（纯函数 + 本机 preparation），SQLite 执行
//! 属 wasmd 内嵌 provider（另一批次）。
//! 正交意图：(1) digestV2(0x00 分隔) 与 quota reservation proof；(2) per-app 数据目录/文件派生与
//! 0700/0600 preparation（创建失败 → not ready，绝不动旧 active 执行）；(3) quota ledger 写前原子
//! 不等式、finalize/release、崩溃恢复计划与跨后端串行证明；(4) 数据面/控制面 CAS 域隔离的结构证明；
//! (5) 备份/恢复身份校验与 quiesce 顺序纯函数层。
//! 规范权威：openspec/changes/add-wasm-host-services/design.md「Decisions 3/4」与
//! specs/wasm-application-runtime/spec.md「Host-service data uses one data-plane quota authority
//! outside control CAS」「Resource, directory, durability and failure boundaries are explicit」。
//! fail-closed 裁决（spec 未逐字规定处，已在子代理报告上报）：
//!   1) BackendOperationMarkerV2 的精确键集：design 只固定 marker「包含 reservation/proof/operation
//!      IDs」；本模块补 committedBytes/backendCommittedBytes（恢复 finalize 需要测量值），schemaVersion=2；
//!   2) reservedDeltaBytes >= 1：保守上界为 0 的写不构成可证明的 mutation 预留；
//!   3) committed 行无 marker = 不可证明状态 → owner recovery（与「marker 无行」相反方向 fail-closed）；
//!   4) reservation 行在 reserve 之后除 state 外不可变：proof 覆盖含 ledgerRevision 在内的全部
//!      字段，状态迁移（committed/released）不得改写 proof 覆盖字段而破坏 durable proof；
//!      ledger 写序推进只体现在 usage 快照的 ledgerRevision（每次 ledger 写恰好 +1）；
//!   5) 恢复 fold 只用 marker 携带的测量值，绝不从 released 行扣减其它 operation 的用量；
//!   6) restore 集内零长度成员拒绝（空文件不是合法 SQLite/ledger 镜像，宁可拒绝不可静默空替）。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::wasm_admission::{jcs_bytes, AdmissionError, WASM_U53_MAX};

// ---------------------------------------------------------------------------
// 稳定错误码与错误类型（owner 可见；public traffic 只见 generic unavailability）
// ---------------------------------------------------------------------------

pub const WASM_HOST_SERVICE_ID_INVALID: &str = "WASM_HOST_SERVICE_ID_INVALID";
pub const WASM_HOST_SERVICE_PATH_INVALID: &str = "WASM_HOST_SERVICE_PATH_INVALID";
pub const WASM_HOST_SERVICE_PREPARATION_NOT_READY: &str = "WASM_HOST_SERVICE_PREPARATION_NOT_READY";
pub const WASM_HOST_SERVICE_CANONICAL_INVALID: &str = "WASM_HOST_SERVICE_CANONICAL_INVALID";
pub const WASM_HOST_SERVICE_QUOTA_EXCEEDED: &str = "WASM_HOST_SERVICE_QUOTA_EXCEEDED";
pub const WASM_HOST_SERVICE_LEDGER_INVALID: &str = "WASM_HOST_SERVICE_LEDGER_INVALID";
pub const WASM_HOST_SERVICE_LEDGER_STALE: &str = "WASM_HOST_SERVICE_LEDGER_STALE";
pub const WASM_HOST_SERVICE_RESERVATION_PROOF_MISMATCH: &str = "WASM_HOST_SERVICE_RESERVATION_PROOF_MISMATCH";
pub const WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH: &str = "WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH";
pub const WASM_HOST_SERVICE_RECOVERY_REQUIRED: &str = "WASM_HOST_SERVICE_RECOVERY_REQUIRED";
pub const WASM_HOST_SERVICE_OWNER_RECOVERY_REQUIRED: &str = "WASM_HOST_SERVICE_OWNER_RECOVERY_REQUIRED";
pub const WASM_HOST_SERVICE_BACKUP_INVALID: &str = "WASM_HOST_SERVICE_BACKUP_INVALID";
pub const WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED: &str = "WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED";

/// 结构化宿主服务数据面错误：code 为稳定 owner 可见码，detail 不含 KV/SQL payload、路径或凭证。
#[derive(Debug, Clone, PartialEq)]
pub struct HostServiceError {
    pub code: &'static str,
    pub detail: String,
}

impl HostServiceError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for HostServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for HostServiceError {}

fn err(code: &'static str, detail: impl Into<String>) -> HostServiceError {
    HostServiceError::new(code, detail)
}

fn jcs_error(error: &AdmissionError) -> HostServiceError {
    err(WASM_HOST_SERVICE_CANONICAL_INVALID, format!("record is outside the canonical JSON domain: {}", error.detail))
}

// ---------------------------------------------------------------------------
// digestV2：SHA-256(ASCII(domain) || 0x00 || payload)——与 V1 系 "\n" 域互不解释
// ---------------------------------------------------------------------------

/// design.md「Decisions 1」的 16 个 V2 hash domain（ASCII literal）。
pub const WASM_DIGEST_V2_DOMAINS: &[&str] = &[
    "iweb-wasm-host-policy-v2",
    "iweb-wasm-host-identity-v2",
    "iweb-wasm-capability-record-v2",
    "iweb-wasm-acceptance-record-v3",
    "iweb-wasm-admission-proof-v2",
    "iweb-wasm-catalog-binding-v2",
    "iweb-wasm-control-state-v2",
    "iweb-wasm-execution-command-v2",
    "iweb-wasm-execution-ack-v2",
    "iweb-wasm-readiness-v2",
    "iweb-wasm-metrics-v2",
    "iweb-wasm-activation-v2",
    "iweb-wasm-route-event-v2",
    "iweb-wasm-rollback-v2",
    "iweb-wasm-host-call-v2",
    "iweb-wasm-quota-reservation-v2",
];

pub const QUOTA_RESERVATION_DIGEST_DOMAIN: &str = "iweb-wasm-quota-reservation-v2";

/// digestV2(domain,payloadBytes) = hex(SHA-256(ASCII(domain) || 0x00 || payloadBytes))。
/// domain 必须属于 V2 domain 表（防拼错/混用）；payload 是原始 JCS 字节，绝不做 hex 二次摘要。
pub fn digest_v2(domain: &str, payload: &[u8]) -> Result<String, HostServiceError> {
    if !WASM_DIGEST_V2_DOMAINS.contains(&domain) {
        return Err(err(WASM_HOST_SERVICE_CANONICAL_INVALID, format!("unknown V2 hash domain: {domain}")));
    }
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0x00]);
    hasher.update(payload);
    Ok(hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// 本地文法（applicationId 与 revision-1 内核文法一致；UUIDv7 与 wasm-execution.ts 同文）
// ---------------------------------------------------------------------------

fn host_service_regexes() -> &'static HostServiceRegexes {
    static REGEXES: std::sync::OnceLock<HostServiceRegexes> = std::sync::OnceLock::new();
    REGEXES.get_or_init(|| HostServiceRegexes {
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        uuidv7: regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").expect("uuidv7 regex"),
    })
}

struct HostServiceRegexes {
    application_id: regex::Regex,
    sha256_hex: regex::Regex,
    uuidv7: regex::Regex,
}

fn require_application_id(application_id: &str) -> Result<(), HostServiceError> {
    if host_service_regexes().application_id.is_match(application_id) {
        Ok(())
    } else {
        Err(err(WASM_HOST_SERVICE_ID_INVALID, "applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"))
    }
}

fn require_sha256_hex(value: &str, field: &str) -> Result<(), HostServiceError> {
    if host_service_regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

fn require_uuidv7(value: &str, field: &str) -> Result<(), HostServiceError> {
    if host_service_regexes().uuidv7.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, format!("{field} must be a lower-case UUIDv7")))
    }
}

fn require_u53(value: u64, field: &str) -> Result<(), HostServiceError> {
    if value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, format!("{field} must be a u53 safe integer")))
    }
}

// ---------------------------------------------------------------------------
// per-app 数据目录与文件派生（design「Decisions 3」：/data/kernel/wasm-data/<applicationId>/
// ---------------------------------------------------------------------------

pub const WASM_HOST_DATA_ROOT: &str = "/data/kernel/wasm-data";
pub const KV_SQLITE_FILE: &str = "kv.sqlite3";
pub const SQL_SQLITE_FILE: &str = "sql.sqlite3";
pub const QUOTA_LEDGER_FILE: &str = "quota.sqlite3";
/// 目录 0700、宿主文件 0600；组件只能拿到 WIT imports，永远拿不到路径。
pub const DATA_DIRECTORY_MODE: u32 = 0o700;
pub const SQLITE_FILE_MODE: u32 = 0o600;

/// 一个应用的三个宿主数据文件路径。派生自 applicationId，含恰好一层目录分量。
#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationDataPaths {
    pub directory: PathBuf,
    pub kv: PathBuf,
    pub sql: PathBuf,
    pub quota: PathBuf,
}

impl ApplicationDataPaths {
    pub fn files(&self) -> [(&'static str, &Path); 3] {
        [("kv", self.kv.as_path()), ("sql", self.sql.as_path()), ("quota", self.quota.as_path())]
    }
}

/// 从 root（部署注入的 wasm-data 根）与 applicationId 派生数据目录与三文件路径。
/// id 文法（小写 DNS-label 风格）先拒绝一切穿越成分：slash、`..`、`.`、绝对路径、NUL、大小写变体。
pub fn derive_application_data_paths(root: &Path, application_id: &str) -> Result<ApplicationDataPaths, HostServiceError> {
    require_application_id(application_id)?;
    if application_id.contains('/') || application_id.contains('\\') || application_id.contains('\0') {
        return Err(err(WASM_HOST_SERVICE_PATH_INVALID, "applicationId must not contain path separators"));
    }
    let directory = root.join(application_id);
    // 结构双保险：目录分量必须恰好是 applicationId（root 不含 `..` 成分）。
    let tail = directory.file_name().and_then(|name| name.to_str()).expect("applicationId is valid UTF-8");
    if tail != application_id {
        return Err(err(WASM_HOST_SERVICE_PATH_INVALID, "derived directory must end with exactly the applicationId"));
    }
    for component in directory.components() {
        if matches!(component, std::path::Component::ParentDir | std::path::Component::CurDir) {
            return Err(err(WASM_HOST_SERVICE_PATH_INVALID, "derived path must not contain . or .. components"));
        }
    }
    Ok(ApplicationDataPaths {
        kv: directory.join(KV_SQLITE_FILE),
        sql: directory.join(SQL_SQLITE_FILE),
        quota: directory.join(QUOTA_LEDGER_FILE),
        directory,
    })
}

// ---------------------------------------------------------------------------
// preparation 生命周期：创建失败 → not ready，不扰动旧 active 执行、绝不静默空替
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct PreparedBackends {
    pub paths: ApplicationDataPaths,
    /// 本次调用新创建的文件（已存在且校验通过的文件不列入）。
    pub created: Vec<&'static str>,
}

/// 首次 service-enabled preparation 时由宿主创建 per-app 目录与空 SQLite 文件：
/// 目录 0700、文件 0600、no-symlink、创建后 fsync（sqlite-full-fsync-v1 的文件级前提）。
/// 任何失败返回 `WASM_HOST_SERVICE_PREPARATION_NOT_READY`：不删除、不截断、不重建任何既有文件，
/// 老 active 执行与既有数据保持原样（design「Migration Plan 3」）。
pub fn prepare_application_backends(root: &Path, application_id: &str) -> Result<PreparedBackends, HostServiceError> {
    let paths = derive_application_data_paths(root, application_id)?;

    // 目录：已存在则必须是普通目录（非 symlink）且 0700；否则以 0700 创建并 fsync。
    match std::fs::symlink_metadata(&paths.directory) {
        Ok(meta) => {
            require_host_directory(&meta, &paths.directory)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_data_directory(&paths.directory)?;
        }
        Err(error) => {
            return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot inspect the application data directory: {error}")));
        }
    }

    let mut created = Vec::new();
    for (kind, path) in paths.files() {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                // 既有文件只做校验：symlink/非普通文件/权限漂移一律 not ready，绝不截断重写。
                require_host_sqlite_file(&meta, path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_host_sqlite_file(path)?;
                created.push(match kind {
                    "kv" => KV_SQLITE_FILE,
                    "sql" => SQL_SQLITE_FILE,
                    _ => QUOTA_LEDGER_FILE,
                });
            }
            Err(error) => {
                return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot inspect {kind} backend file: {error}")));
            }
        }
    }
    Ok(PreparedBackends { paths, created })
}

fn require_host_directory(metadata: &std::fs::Metadata, path: &Path) -> Result<(), HostServiceError> {
    if metadata.file_type().is_symlink() {
        return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("{} must not be a symlink", path.display())));
    }
    if !metadata.is_dir() {
        return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("{} must be a directory", path.display())));
    }
    #[cfg(unix)]
    {
        let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
        if mode & 0o7777 != DATA_DIRECTORY_MODE {
            return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("{} must have mode 0700", path.display())));
        }
    }
    Ok(())
}

fn require_host_sqlite_file(metadata: &std::fs::Metadata, path: &Path) -> Result<(), HostServiceError> {
    if metadata.file_type().is_symlink() {
        return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("{} must not be a symlink", path.display())));
    }
    if !metadata.is_file() {
        return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("{} must be a regular file", path.display())));
    }
    #[cfg(unix)]
    {
        let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
        if mode & 0o7777 != SQLITE_FILE_MODE {
            return Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("{} must have mode 0600", path.display())));
        }
    }
    Ok(())
}

fn create_data_directory(directory: &Path) -> Result<(), HostServiceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(DATA_DIRECTORY_MODE);
        builder.create(directory).map_err(|error| err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot create the application data directory: {error}")))?;
        // umask 修正 + 目录条目落盘。
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(DATA_DIRECTORY_MODE))
            .map_err(|error| err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot enforce mode 0700 on the data directory: {error}")))?;
        let handle = std::fs::File::open(directory).map_err(|error| err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot fsync the data directory: {error}")))?;
        handle.sync_all().map_err(|error| err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot fsync the data directory: {error}")))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, "per-app sqlite data directories require a unix host"))
    }
}

fn create_host_sqlite_file(path: &Path) -> Result<(), HostServiceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let handle = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SQLITE_FILE_MODE)
            .open(path)
            .map_err(|error| err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot create {}: {error}", path.display())))?;
        // umask 修正 + 空文件落盘。
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(SQLITE_FILE_MODE))
            .map_err(|error| err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot enforce mode 0600 on {}: {error}", path.display())))?;
        handle.sync_all().map_err(|error| err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, format!("cannot fsync {}: {error}", path.display())))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(err(WASM_HOST_SERVICE_PREPARATION_NOT_READY, "per-app sqlite files require a unix host"))
    }
}

// ---------------------------------------------------------------------------
// 控制态静态摘要与「数据面不推进 controlRevision」的结构保证
// ---------------------------------------------------------------------------

/// 控制态只保存静态策略摘要（policy digest、envelope、profile 字面量与启用服务），
/// 不含动态用量、reservation、WAL 页数或日志正文（spec「one data-plane quota authority」）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ControlStateServicePolicySummaryV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "policyDigest")]
    pub policy_digest: String,
    #[serde(rename = "storageBytes")]
    pub storage_bytes: u64,
    #[serde(rename = "dataDirectoryProfile")]
    pub data_directory_profile: String,
    #[serde(rename = "durabilityProfile")]
    pub durability_profile: String,
    /// 启用服务 → profile 字面量；未启用为 null。不含 limits 数值副本（policy digest 已绑定）。
    #[serde(rename = "hostServices")]
    pub host_services: HostServicesEnabledV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostServicesEnabledV2 {
    pub kv: Option<String>,
    pub sql: Option<String>,
    pub logging: Option<String>,
}

/// 控制面权威字段（CAS 域）：数据面记录（reservation/marker/usage/backup 摘要）一律不得携带。
pub const CONTROL_AUTHORITY_FIELD_NAMES: &[&str] = &[
    "controlRevision",
    "expectedControlRevision",
    "routeGeneration",
    "expectedRouteGeneration",
    "admissionSequence",
    "journalRevision",
    "leaseNonce",
    "fenceNonce",
];

/// 结构证明：canonical JSON 记录（任意嵌套）不含任何控制面权威字段。
pub fn record_is_control_authority_free(canonical: &[u8]) -> bool {
    let value: serde_json::Value = match serde_json::from_slice(canonical) {
        Ok(value) => value,
        Err(_) => return false,
    };
    value_control_free(&value)
}

fn value_control_free(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.keys().all(|key| !CONTROL_AUTHORITY_FIELD_NAMES.contains(&key.as_str())) && map.values().all(value_control_free)
        }
        serde_json::Value::Array(items) => items.iter().all(value_control_free),
        _ => true,
    }
}

/// 结构证明：数据面文件与控制态文件是独立文件/独立 CAS 域——控制态路径不在数据目录内，
/// 数据文件也不与控制态路径重合。
pub fn assert_independent_cas_domains(paths: &ApplicationDataPaths, control_state_path: &Path) -> Result<(), HostServiceError> {
    if control_state_path.starts_with(&paths.directory) || control_state_path == paths.directory {
        return Err(err(WASM_HOST_SERVICE_PATH_INVALID, "the control-state file must not live inside the application data directory"));
    }
    for (_, file) in paths.files() {
        if file == control_state_path {
            return Err(err(WASM_HOST_SERVICE_PATH_INVALID, "a data-plane file must not be the control-state file"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// quota ledger：QuotaReservationV2、usage 快照、envelope 与 reservation proof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum QuotaBackend {
    Kv,
    Sql,
}

impl QuotaBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            QuotaBackend::Kv => "kv",
            QuotaBackend::Sql => "sql",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ReservationState {
    Reserved,
    Committed,
    Released,
}

impl ReservationState {
    pub fn as_str(self) -> &'static str {
        match self {
            ReservationState::Reserved => "reserved",
            ReservationState::Committed => "committed",
            ReservationState::Released => "released",
        }
    }
}

/// design「Decisions 4」的 QuotaReservationV2（13 键精确集合，camelCase）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuotaReservationV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "reservationId")]
    pub reservation_id: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub backend: QuotaBackend,
    #[serde(rename = "ledgerRevision")]
    pub ledger_revision: u64,
    #[serde(rename = "expectedUsageRevision")]
    pub expected_usage_revision: u64,
    #[serde(rename = "baseCommittedBytes")]
    pub base_committed_bytes: u64,
    #[serde(rename = "reservedDeltaBytes")]
    pub reserved_delta_bytes: u64,
    #[serde(rename = "projectedCommittedBytes")]
    pub projected_committed_bytes: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    pub state: ReservationState,
    #[serde(rename = "reservationProofDigest")]
    pub reservation_proof_digest: String,
}

impl QuotaReservationV2 {
    /// 校验字段文法（不含 proof 复算；proof 由 verify_reservation_proof 单独把关）。
    pub fn validate(&self) -> Result<(), HostServiceError> {
        if self.schema_version != 2 {
            return Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, "reservation schemaVersion must be the literal 2"));
        }
        require_uuidv7(&self.reservation_id, "reservationId")?;
        require_uuidv7(&self.operation_id, "operationId")?;
        require_application_id(&self.application_id)?;
        require_u53(self.ledger_revision, "ledgerRevision")?;
        require_u53(self.expected_usage_revision, "expectedUsageRevision")?;
        require_u53(self.base_committed_bytes, "baseCommittedBytes")?;
        require_u53(self.reserved_delta_bytes, "reservedDeltaBytes")?;
        require_u53(self.projected_committed_bytes, "projectedCommittedBytes")?;
        require_u53(self.expires_at, "expiresAt")?;
        if self.reserved_delta_bytes < 1 {
            return Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, "reservedDeltaBytes must be at least 1 (a provable conservative bound)"));
        }
        require_sha256_hex(&self.reservation_proof_digest, "reservationProofDigest")?;
        Ok(())
    }

    /// proof 输入：同记录但 state 固定 "reserved" 且省略 proof（design 逐字）。
    fn proof_payload(&self) -> QuotaReservationV2 {
        let mut payload = self.clone();
        payload.state = ReservationState::Reserved;
        payload.reservation_proof_digest = String::new();
        payload
    }
}

/// reservationProofDigest = digestV2("iweb-wasm-quota-reservation-v2",
/// JCS(reservation with state:"reserved" and the proof omitted))。
pub fn compute_reservation_proof_digest(reservation: &QuotaReservationV2) -> Result<String, HostServiceError> {
    let payload = reservation.proof_payload();
    let mut value = serde_json::to_value(&payload)
        .map_err(|error| err(WASM_HOST_SERVICE_CANONICAL_INVALID, format!("reservation is not serializable as JSON: {error}")))?;
    strip_proof_member(&mut value);
    let payload_jcs = jcs_bytes(&value).map_err(|e| jcs_error(&e))?;
    digest_v2(QUOTA_RESERVATION_DIGEST_DOMAIN, &payload_jcs)
}

fn strip_proof_member(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        map.remove("reservationProofDigest");
    }
}

/// durable proof 复算（provider 在任何后端写之前必须通过）。
pub fn verify_reservation_proof(reservation: &QuotaReservationV2) -> Result<(), HostServiceError> {
    reservation.validate()?;
    let expected = compute_reservation_proof_digest(reservation)?;
    if expected == reservation.reservation_proof_digest {
        Ok(())
    } else {
        Err(err(WASM_HOST_SERVICE_RESERVATION_PROOF_MISMATCH, "reservationProofDigest does not match the reserved-state proof"))
    }
}

/// ledger 动态用量快照（数据面内部状态；不进控制态 digest）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LedgerUsageV2 {
    #[serde(rename = "ledgerRevision")]
    pub ledger_revision: u64,
    #[serde(rename = "usageRevision")]
    pub usage_revision: u64,
    #[serde(rename = "committedBytes")]
    pub committed_bytes: u64,
    #[serde(rename = "outstandingReservedBytes")]
    pub outstanding_reserved_bytes: u64,
    #[serde(rename = "kvCommittedBytes")]
    pub kv_committed_bytes: u64,
    #[serde(rename = "kvOutstandingReservedBytes")]
    pub kv_outstanding_reserved_bytes: u64,
    #[serde(rename = "sqlCommittedBytes")]
    pub sql_committed_bytes: u64,
    #[serde(rename = "sqlOutstandingReservedBytes")]
    pub sql_outstanding_reserved_bytes: u64,
}

impl LedgerUsageV2 {
    pub fn initial() -> Self {
        Self {
            ledger_revision: 0,
            usage_revision: 0,
            committed_bytes: 0,
            outstanding_reserved_bytes: 0,
            kv_committed_bytes: 0,
            kv_outstanding_reserved_bytes: 0,
            sql_committed_bytes: 0,
            sql_outstanding_reserved_bytes: 0,
        }
    }

    fn validate(&self) -> Result<(), HostServiceError> {
        require_u53(self.ledger_revision, "ledgerRevision")?;
        require_u53(self.usage_revision, "usageRevision")?;
        for (field, value) in [
            ("committedBytes", self.committed_bytes),
            ("outstandingReservedBytes", self.outstanding_reserved_bytes),
            ("kvCommittedBytes", self.kv_committed_bytes),
            ("kvOutstandingReservedBytes", self.kv_outstanding_reserved_bytes),
            ("sqlCommittedBytes", self.sql_committed_bytes),
            ("sqlOutstandingReservedBytes", self.sql_outstanding_reserved_bytes),
        ] {
            require_u53(value, field)?;
        }
        Ok(())
    }

    fn backend_committed(&self, backend: QuotaBackend) -> u64 {
        match backend {
            QuotaBackend::Kv => self.kv_committed_bytes,
            QuotaBackend::Sql => self.sql_committed_bytes,
        }
    }

    fn backend_outstanding(&self, backend: QuotaBackend) -> u64 {
        match backend {
            QuotaBackend::Kv => self.kv_outstanding_reserved_bytes,
            QuotaBackend::Sql => self.sql_outstanding_reserved_bytes,
        }
    }
}

/// 共享 envelope 与服务 cap（来自静态 HostServicePolicyV2；本模块不重算 policy digest）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuotaEnvelopeV2 {
    #[serde(rename = "aggregateStorageBytes")]
    pub aggregate_storage_bytes: u64,
    #[serde(rename = "kvServiceCapBytes")]
    pub kv_service_cap_bytes: u64,
    #[serde(rename = "sqlServiceCapBytes")]
    pub sql_service_cap_bytes: u64,
}

impl QuotaEnvelopeV2 {
    fn validate(&self) -> Result<(), HostServiceError> {
        require_u53(self.aggregate_storage_bytes, "aggregateStorageBytes")?;
        require_u53(self.kv_service_cap_bytes, "kvServiceCapBytes")?;
        require_u53(self.sql_service_cap_bytes, "sqlServiceCapBytes")?;
        if self.kv_service_cap_bytes > self.aggregate_storage_bytes || self.sql_service_cap_bytes > self.aggregate_storage_bytes {
            return Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, "service caps must not exceed the aggregate envelope"));
        }
        Ok(())
    }

    fn service_cap(&self, backend: QuotaBackend) -> u64 {
        match backend {
            QuotaBackend::Kv => self.kv_service_cap_bytes,
            QuotaBackend::Sql => self.sql_service_cap_bytes,
        }
    }
}

pub struct ReserveQuotaInput<'a> {
    pub application_id: &'a str,
    pub backend: QuotaBackend,
    pub reservation_id: &'a str,
    pub operation_id: &'a str,
    pub reserved_delta_bytes: u64,
    pub expires_at_ms: u64,
    pub now_ms: u64,
}

/// 串行化 reserve 事务：先验证 committedBytes + outstandingReservedBytes + delta <= aggregateEnvelope
/// 与服务 cap（溢出与不可证明输入同样 fail-closed），再原子写 `reserved` 并产出 durable proof。
/// 任何拒绝都不触碰任何后端，也不推进任何 CAS。
pub fn reserve_quota(usage: &LedgerUsageV2, envelope: &QuotaEnvelopeV2, input: &ReserveQuotaInput<'_>) -> Result<(QuotaReservationV2, LedgerUsageV2), HostServiceError> {
    usage.validate()?;
    envelope.validate()?;
    require_application_id(input.application_id)?;
    require_uuidv7(input.reservation_id, "reservationId")?;
    require_uuidv7(input.operation_id, "operationId")?;
    require_u53(input.reserved_delta_bytes, "reservedDeltaBytes")?;
    require_u53(input.expires_at_ms, "expiresAt")?;
    require_u53(input.now_ms, "nowMs")?;
    if input.reserved_delta_bytes < 1 {
        return Err(err(WASM_HOST_SERVICE_QUOTA_EXCEEDED, "reservedDeltaBytes must be a provable conservative bound >= 1"));
    }
    if input.now_ms >= input.expires_at_ms {
        return Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, "reservation must not be created already expired"));
    }

    let projected = usage
        .committed_bytes
        .checked_add(usage.outstanding_reserved_bytes)
        .and_then(|sum| sum.checked_add(input.reserved_delta_bytes))
        .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "quota arithmetic overflow"))?;
    let service_projected = usage
        .backend_committed(input.backend)
        .checked_add(usage.backend_outstanding(input.backend))
        .and_then(|sum| sum.checked_add(input.reserved_delta_bytes))
        .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "service quota arithmetic overflow"))?;
    if projected > envelope.aggregate_storage_bytes || service_projected > envelope.service_cap(input.backend) {
        return Err(err(WASM_HOST_SERVICE_QUOTA_EXCEEDED, "committed + outstanding + delta exceeds the aggregate envelope or service cap"));
    }

    let mut reservation = QuotaReservationV2 {
        schema_version: 2,
        reservation_id: input.reservation_id.to_string(),
        operation_id: input.operation_id.to_string(),
        application_id: input.application_id.to_string(),
        backend: input.backend,
        ledger_revision: usage.ledger_revision + 1,
        expected_usage_revision: usage.usage_revision,
        base_committed_bytes: usage.committed_bytes,
        reserved_delta_bytes: input.reserved_delta_bytes,
        projected_committed_bytes: projected,
        expires_at: input.expires_at_ms,
        state: ReservationState::Reserved,
        reservation_proof_digest: String::new(),
    };
    reservation.reservation_proof_digest = compute_reservation_proof_digest(&reservation)?;
    verify_reservation_proof(&reservation)?;

    let mut next = usage.clone();
    next.ledger_revision = usage.ledger_revision + 1;
    next.outstanding_reserved_bytes = usage.outstanding_reserved_bytes + input.reserved_delta_bytes;
    match input.backend {
        QuotaBackend::Kv => next.kv_outstanding_reserved_bytes = usage.kv_outstanding_reserved_bytes + input.reserved_delta_bytes,
        QuotaBackend::Sql => next.sql_outstanding_reserved_bytes = usage.sql_outstanding_reserved_bytes + input.reserved_delta_bytes,
    }
    Ok((reservation, next))
}

/// 后端幂等 marker（design：包含 reservation/proof/operation IDs；裁决 1 补测量字节）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackendOperationMarkerV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub backend: QuotaBackend,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    #[serde(rename = "reservationId")]
    pub reservation_id: String,
    #[serde(rename = "reservationProofDigest")]
    pub reservation_proof_digest: String,
    /// 后端事务提交后测得的 committed 总量（恢复 finalize 的权威输入）。
    #[serde(rename = "committedBytes")]
    pub committed_bytes: u64,
    /// 同一次测得的该后端 committed 量。
    #[serde(rename = "backendCommittedBytes")]
    pub backend_committed_bytes: u64,
}

impl BackendOperationMarkerV2 {
    pub fn validate(&self) -> Result<(), HostServiceError> {
        if self.schema_version != 2 {
            return Err(err(WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH, "marker schemaVersion must be the literal 2"));
        }
        require_application_id(&self.application_id)?;
        require_uuidv7(&self.operation_id, "operationId")?;
        require_uuidv7(&self.reservation_id, "reservationId")?;
        require_sha256_hex(&self.reservation_proof_digest, "reservationProofDigest")?;
        require_u53(self.committed_bytes, "committedBytes")?;
        require_u53(self.backend_committed_bytes, "backendCommittedBytes")?;
        Ok(())
    }
}

/// provider 后端写闸门：无 durable ledger 行、identity/proof/backend/usage revision 不匹配即拒绝。
pub fn verify_backend_write_authority(
    marker: &BackendOperationMarkerV2,
    reservation: &QuotaReservationV2,
    application_id: &str,
    expected_usage_revision: u64,
) -> Result<(), HostServiceError> {
    marker.validate()?;
    if marker.application_id != application_id || reservation.application_id != application_id {
        return Err(err(WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH, "marker and reservation must belong to the target application"));
    }
    if marker.backend != reservation.backend
        || marker.operation_id != reservation.operation_id
        || marker.reservation_id != reservation.reservation_id
        || marker.reservation_proof_digest != reservation.reservation_proof_digest
    {
        return Err(err(WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH, "marker must carry the same reservation, proof and operation identities"));
    }
    verify_reservation_proof(reservation)?;
    if reservation.state != ReservationState::Reserved {
        return Err(err(WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH, "only a reserved reservation authorizes a backend write"));
    }
    if reservation.expected_usage_revision != expected_usage_revision {
        return Err(err(WASM_HOST_SERVICE_LEDGER_STALE, "reservation expectedUsageRevision does not match the ledger usage revision"));
    }
    Ok(())
}

pub struct FinalizeReservationInput {
    /// 后端 commit + durability 成功后测得的 committed 总量。
    pub measured_committed_bytes: u64,
    /// 同一次测得的该后端 committed 量。
    pub measured_backend_committed_bytes: u64,
}

/// 后端事务 + sqlite-full-fsync-v1 成功后的 ledger finalize（唯一 committed 写入点）：
/// committed 行幂等重放返回原状（不二次扣减）；测量超 envelope → quarantine 码；
/// backend 失败路径走 release_reservation，不走这里。
pub fn finalize_reservation(
    usage: &LedgerUsageV2,
    envelope: &QuotaEnvelopeV2,
    reservation: &QuotaReservationV2,
    input: &FinalizeReservationInput,
) -> Result<(QuotaReservationV2, LedgerUsageV2), HostServiceError> {
    usage.validate()?;
    envelope.validate()?;
    verify_reservation_proof(reservation)?;
    require_u53(input.measured_committed_bytes, "measuredCommittedBytes")?;
    require_u53(input.measured_backend_committed_bytes, "measuredBackendCommittedBytes")?;
    if reservation.state == ReservationState::Committed {
        // committed, marker present → 幂等重放：返回存储结果，不再有任何副作用。
        return Ok((reservation.clone(), usage.clone()));
    }
    if reservation.state != ReservationState::Reserved {
        return Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, "only a reserved reservation can finalize"));
    }
    if input.measured_committed_bytes > envelope.aggregate_storage_bytes
        || input.measured_backend_committed_bytes > envelope.service_cap(reservation.backend)
    {
        return Err(err(WASM_HOST_SERVICE_RECOVERY_REQUIRED, "post-commit measurement exceeds the envelope; the backend must be quarantined"));
    }

    let mut next_row = reservation.clone();
    next_row.state = ReservationState::Committed;

    let mut next = usage.clone();
    next.ledger_revision = usage.ledger_revision + 1;
    next.usage_revision = usage.usage_revision + 1;
    next.committed_bytes = input.measured_committed_bytes;
    next.outstanding_reserved_bytes = usage
        .outstanding_reserved_bytes
        .checked_sub(reservation.reserved_delta_bytes)
        .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "outstanding reserved bytes underflow; ledger state is impossible"))?;
    match reservation.backend {
        QuotaBackend::Kv => {
            next.kv_committed_bytes = input.measured_backend_committed_bytes;
            next.kv_outstanding_reserved_bytes = usage
                .kv_outstanding_reserved_bytes
                .checked_sub(reservation.reserved_delta_bytes)
                .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "kv outstanding reserved bytes underflow"))?;
        }
        QuotaBackend::Sql => {
            next.sql_committed_bytes = input.measured_backend_committed_bytes;
            next.sql_outstanding_reserved_bytes = usage
                .sql_outstanding_reserved_bytes
                .checked_sub(reservation.reserved_delta_bytes)
                .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "sql outstanding reserved bytes underflow"))?;
        }
    }
    verify_reservation_proof(&next_row)?;
    Ok((next_row, next))
}

/// 后端事务失败路径：释放 reservation（released 行幂等）；usage 只减 outstanding，不碰 committed。
pub fn release_reservation(usage: &LedgerUsageV2, reservation: &QuotaReservationV2) -> Result<(QuotaReservationV2, LedgerUsageV2), HostServiceError> {
    usage.validate()?;
    verify_reservation_proof(reservation)?;
    if reservation.state == ReservationState::Released {
        return Ok((reservation.clone(), usage.clone()));
    }
    if reservation.state != ReservationState::Reserved {
        return Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, "only a reserved or released reservation can be released"));
    }

    let mut next_row = reservation.clone();
    next_row.state = ReservationState::Released;

    let mut next = usage.clone();
    next.ledger_revision = usage.ledger_revision + 1;
    next.outstanding_reserved_bytes = usage
        .outstanding_reserved_bytes
        .checked_sub(reservation.reserved_delta_bytes)
        .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "outstanding reserved bytes underflow on release"))?;
    match reservation.backend {
        QuotaBackend::Kv => {
            next.kv_outstanding_reserved_bytes = usage
                .kv_outstanding_reserved_bytes
                .checked_sub(reservation.reserved_delta_bytes)
                .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "kv outstanding reserved bytes underflow on release"))?;
        }
        QuotaBackend::Sql => {
            next.sql_outstanding_reserved_bytes = usage
                .sql_outstanding_reserved_bytes
                .checked_sub(reservation.reserved_delta_bytes)
                .ok_or_else(|| err(WASM_HOST_SERVICE_LEDGER_INVALID, "sql outstanding reserved bytes underflow on release"))?;
        }
    }
    Ok((next_row, next))
}

// ---------------------------------------------------------------------------
// 崩溃恢复计划（design「Decisions 4」恢复表逐行）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryActionV2 {
    /// reserved 且无后端 marker：释放（expired 预留从不计入 committed）。
    ReleaseReservation { reservation_id: String, ledger_revision: u64 },
    /// reserved 且 marker 在场 / marker 无行（重建后）：用 marker 测量值精确 finalize 一次。
    /// （Box 消除 variant 尺寸差；不动语义。）
    FinalizeFromMarker {
        reservation: Box<QuotaReservationV2>,
        marker: Box<BackendOperationMarkerV2>,
        ledger_revision: u64,
    },
    /// 该后端隔离直到 owner 处置（绝不猜测用量、绝不静默空替）。
    QuarantineBackend { backend: QuotaBackend },
    /// 不可证明状态：owner recovery（released 行带 committed marker、revision 回退、committed 行无 marker 等）。
    OwnerRecoveryRequired { reason: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LedgerRecoveryStatus {
    Healthy,
    Recovering,
    Quarantined,
    OwnerRecoveryRequired,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryPlanV2 {
    pub status: LedgerRecoveryStatus,
    pub actions: Vec<RecoveryActionV2>,
    /// 依序应用 actions 后的用量快照（纯 fold；owner-recovery 时不具权威性，仅投影）。
    pub resulting_usage: LedgerUsageV2,
}

pub struct LedgerRecoveryInput<'a> {
    pub application_id: &'a str,
    pub usage: &'a LedgerUsageV2,
    pub envelope: &'a QuotaEnvelopeV2,
    pub reservations: &'a [QuotaReservationV2],
    pub markers: &'a [BackendOperationMarkerV2],
}

/// 确定性恢复计划（先做不可能态检查，再按行匹配 marker）：
///
/// | durable state              | recovery                                   |
/// |---------------------------|--------------------------------------------|
/// | reserved, no marker       | release（expired 不计费）                   |
/// | reserved, marker          | 用 marker 测量值 finalize 恰好一次           |
/// | marker, no ledger row     | quarantine + 重建 reservation + finalize    |
/// | committed, marker         | 幂等重放（无动作）                           |
/// | released + committed marker / revision 回退 | unavailable + owner recovery |
pub fn plan_ledger_recovery(input: &LedgerRecoveryInput<'_>) -> Result<RecoveryPlanV2, HostServiceError> {
    input.usage.validate()?;
    input.envelope.validate()?;
    for row in input.reservations {
        row.validate()?;
        if row.application_id != input.application_id {
            return Err(err(WASM_HOST_SERVICE_LEDGER_INVALID, "ledger row belongs to another application"));
        }
    }
    for marker in input.markers {
        marker.validate()?;
        if marker.application_id != input.application_id {
            return Err(err(WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH, "backend marker belongs to another application"));
        }
    }

    // 不可能态：ledger revision 必须唯一且不超前快照；usage revision 不得回退。
    let mut seen_revisions: HashSet<u64> = HashSet::new();
    for row in input.reservations {
        if !seen_revisions.insert(row.ledger_revision) {
            return Ok(owner_plan(input.usage, "duplicate ledger revision across reservations"));
        }
        if row.ledger_revision > input.usage.ledger_revision {
            return Ok(owner_plan(input.usage, "reservation ledger revision is ahead of the ledger snapshot"));
        }
        if row.state == ReservationState::Committed && row.expected_usage_revision >= input.usage.usage_revision {
            return Ok(owner_plan(input.usage, "committed reservation implies an impossible usage revision"));
        }
    }
    let mut seen_marker_keys: HashSet<(QuotaBackend, String)> = HashSet::new();
    for marker in input.markers {
        if !seen_marker_keys.insert((marker.backend, marker.operation_id.clone())) {
            return Ok(owner_plan(input.usage, "duplicate backend operation marker"));
        }
    }

    let mut actions: Vec<RecoveryActionV2> = Vec::new();
    let mut usage = input.usage.clone();
    let mut matched_markers: HashSet<(QuotaBackend, String)> = HashSet::new();

    for row in input.reservations {
        let marker = input
            .markers
            .iter()
            .find(|marker| marker.backend == row.backend && marker.operation_id == row.operation_id && marker.reservation_id == row.reservation_id);
        match (row.state, marker) {
            (ReservationState::Reserved, None) => {
                // release after checking the operation was not committed（marker 即提交证据）。
                let ledger_revision = usage.ledger_revision + 1;
                let (next_row, next_usage) = release_reservation(&usage, row)?;
                usage = next_usage;
                actions.push(RecoveryActionV2::ReleaseReservation { reservation_id: next_row.reservation_id, ledger_revision });
            }
            (ReservationState::Reserved, Some(marker)) => {
                let ledger_revision = usage.ledger_revision + 1;
                let (next_row, next_usage) = finalize_reservation(
                    &usage,
                    input.envelope,
                    row,
                    &FinalizeReservationInput {
                        measured_committed_bytes: marker.committed_bytes,
                        measured_backend_committed_bytes: marker.backend_committed_bytes,
                    },
                )?;
                usage = next_usage;
                matched_markers.insert((marker.backend, marker.operation_id.clone()));
                actions.push(RecoveryActionV2::FinalizeFromMarker { reservation: Box::new(next_row), marker: Box::new(marker.clone()), ledger_revision });
            }
            (ReservationState::Committed, Some(marker)) => {
                // committed, marker present → 幂等重放存储结果。
                matched_markers.insert((marker.backend, marker.operation_id.clone()));
            }
            (ReservationState::Committed, None) => {
                return Ok(owner_plan(input.usage, "committed reservation without a durable backend marker is unprovable"));
            }
            (ReservationState::Released, Some(marker)) => {
                // released 行带 committed marker：绝不扣减其它 operation 的用量，服务不可用。
                actions.push(RecoveryActionV2::QuarantineBackend { backend: marker.backend });
                actions.push(RecoveryActionV2::OwnerRecoveryRequired { reason: "released reservation carries a committed backend marker".into() });
                matched_markers.insert((marker.backend, marker.operation_id.clone()));
                usage = input.usage.clone();
            }
            (ReservationState::Released, None) => {
                // 已释放且无提交证据：终态，无动作。
            }
        }
    }

    // 孤立 marker：quarantine + 从 marker 重建 reservation，然后 finalize（不暴露部分成功）。
    for marker in input.markers {
        if matched_markers.contains(&(marker.backend, marker.operation_id.clone())) {
            continue;
        }
        let reconstructed = QuotaReservationV2 {
            schema_version: 2,
            reservation_id: marker.reservation_id.clone(),
            operation_id: marker.operation_id.clone(),
            application_id: marker.application_id.clone(),
            backend: marker.backend,
            // 重建行没有 ledger 写序：以 marker 自身可证明字段为准，进入 quarantine 处置。
            ledger_revision: 0,
            expected_usage_revision: 0,
            base_committed_bytes: 0,
            reserved_delta_bytes: 1,
            projected_committed_bytes: marker.committed_bytes,
            expires_at: 0,
            state: ReservationState::Reserved,
            reservation_proof_digest: marker.reservation_proof_digest.clone(),
        };
        actions.push(RecoveryActionV2::QuarantineBackend { backend: marker.backend });
        actions.push(RecoveryActionV2::FinalizeFromMarker { reservation: Box::new(reconstructed), marker: Box::new(marker.clone()), ledger_revision: usage.ledger_revision + 1 });
    }

    let status = if actions
        .iter()
        .any(|action| matches!(action, RecoveryActionV2::OwnerRecoveryRequired { .. }))
    {
        LedgerRecoveryStatus::OwnerRecoveryRequired
    } else if actions.iter().any(|action| matches!(action, RecoveryActionV2::QuarantineBackend { .. })) {
        LedgerRecoveryStatus::Quarantined
    } else if actions.is_empty() {
        LedgerRecoveryStatus::Healthy
    } else {
        LedgerRecoveryStatus::Recovering
    };
    Ok(RecoveryPlanV2 { status, actions, resulting_usage: usage })
}

fn owner_plan(usage: &LedgerUsageV2, reason: &str) -> RecoveryPlanV2 {
    RecoveryPlanV2 {
        status: LedgerRecoveryStatus::OwnerRecoveryRequired,
        actions: vec![RecoveryActionV2::OwnerRecoveryRequired { reason: reason.to_string() }],
        resulting_usage: usage.clone(),
    }
}

// ---------------------------------------------------------------------------
// 备份/恢复：quiesce 顺序计划 + 身份/完整性校验（纯函数层）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackupFileKind {
    Kv,
    Sql,
    Quota,
}

impl BackupFileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BackupFileKind::Kv => KV_SQLITE_FILE,
            BackupFileKind::Sql => SQL_SQLITE_FILE,
            BackupFileKind::Quota => QUOTA_LEDGER_FILE,
        }
    }
}

/// 备份固定顺序（spec「Backup/restore quiesces the application...」）：
/// 先 drain 在飞 host-call，再清空 outstanding reservations（或完成恢复），
/// 冻结 ledger revision，fsync 三个后端文件，最后捕获身份与文件集。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupStepV2 {
    DrainHostCalls,
    SettleReservations,
    FreezeLedger,
    FsyncBackends,
    CaptureIdentityAndFiles,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackupQuiesceStateV2 {
    #[serde(rename = "outstandingReservedBytes")]
    pub outstanding_reserved_bytes: u64,
    pub recovery_status: LedgerRecoveryStatus,
    #[serde(rename = "ledgerRevision")]
    pub ledger_revision: u64,
    #[serde(rename = "frozenLedgerRevision")]
    pub frozen_ledger_revision: Option<u64>,
}

/// quiesce 前置检查 + 固定顺序：outstanding reservations 未清零、恢复未到 Healthy、
/// 或冻结 revision 与当前 ledger revision 不一致时拒绝（fail-closed，绝不在活动写入时捕获）。
pub fn plan_backup_quiesce(state: &BackupQuiesceStateV2) -> Result<Vec<BackupStepV2>, HostServiceError> {
    require_u53(state.outstanding_reserved_bytes, "outstandingReservedBytes")?;
    require_u53(state.ledger_revision, "ledgerRevision")?;
    if state.outstanding_reserved_bytes > 0 {
        return Err(err(WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED, "outstanding reservations must settle before backup capture"));
    }
    if state.recovery_status != LedgerRecoveryStatus::Healthy {
        return Err(err(WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED, "ledger recovery must complete (healthy) before backup capture"));
    }
    if state.frozen_ledger_revision != Some(state.ledger_revision) {
        return Err(err(WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED, "the frozen ledger revision must equal the current ledger revision"));
    }
    Ok(vec![
        BackupStepV2::DrainHostCalls,
        BackupStepV2::SettleReservations,
        BackupStepV2::FreezeLedger,
        BackupStepV2::FsyncBackends,
        BackupStepV2::CaptureIdentityAndFiles,
    ])
}

/// 备份文件条目（kind/长度/内容摘要/权限/symlink 位；内容校验在恢复侧复算）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackupFileEntryV2 {
    pub kind: BackupFileKind,
    #[serde(rename = "byteLen")]
    pub byte_len: u64,
    pub sha256: String,
    pub mode: u32,
    pub symlink: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackupSetDescriptorV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "hostServicePolicyDigest")]
    pub host_service_policy_digest: String,
    #[serde(rename = "ledgerRevision")]
    pub ledger_revision: u64,
    #[serde(rename = "usageRevision")]
    pub usage_revision: u64,
    pub quiesced: bool,
    pub files: Vec<BackupFileEntryV2>,
}

impl BackupSetDescriptorV2 {
    /// 备份集完整性：恰好三个成员、无 symlink、0600、摘要为 64-hex、身份与 policy digest 匹配、quiesced。
    pub fn validate(&self, expected_application_id: &str, expected_policy_digest: &str) -> Result<(), HostServiceError> {
        self.validate_common(expected_application_id, expected_policy_digest)?;
        if self.files.iter().any(|entry| entry.byte_len == 0) {
            return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "a zero-length member cannot be a valid sqlite/ledger image"));
        }
        Ok(())
    }

    fn validate_common(&self, expected_application_id: &str, expected_policy_digest: &str) -> Result<(), HostServiceError> {
        if self.schema_version != 2 {
            return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup descriptor schemaVersion must be the literal 2"));
        }
        require_application_id(&self.application_id)?;
        require_sha256_hex(&self.host_service_policy_digest, "hostServicePolicyDigest")?;
        require_u53(self.ledger_revision, "ledgerRevision")?;
        require_u53(self.usage_revision, "usageRevision")?;
        if self.application_id != expected_application_id {
            return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup set belongs to another application"));
        }
        if self.host_service_policy_digest != expected_policy_digest {
            return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup set policy digest does not match the application"));
        }
        if !self.quiesced {
            return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup set must be captured under quiesce"));
        }
        if self.files.len() != 3 {
            return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup set must contain exactly kv, sql and quota members"));
        }
        let mut kinds: HashSet<String> = HashSet::new();
        for entry in &self.files {
            if !kinds.insert(entry.kind.as_str().to_string()) {
                return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup set has a duplicate member kind"));
            }
            require_u53(entry.byte_len, "byteLen")?;
            require_sha256_hex(&entry.sha256, "sha256")?;
            if entry.symlink {
                return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "a symlinked member is refused"));
            }
            if entry.mode & 0o7777 != SQLITE_FILE_MODE {
                return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup members must carry mode 0600"));
            }
        }
        for expected in [BackupFileKind::Kv, BackupFileKind::Sql, BackupFileKind::Quota] {
            if !kinds.contains(expected.as_str()) {
                return Err(err(WASM_HOST_SERVICE_BACKUP_INVALID, "backup set is missing a member"));
            }
        }
        Ok(())
    }
}

/// 恢复侧校验：与备份相同的完整性 + 身份校验；任何失败都不得静默创建空替身（由调用方保证不落地）。
/// 与 validate 的差别：restore 额外拒绝零长度成员（空文件不是合法 SQLite/ledger 镜像，裁决 6）。
pub fn validate_restore_set(descriptor: &BackupSetDescriptorV2, expected_application_id: &str, expected_policy_digest: &str) -> Result<(), HostServiceError> {
    descriptor.validate(expected_application_id, expected_policy_digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    fn uuidv7(seed: u8) -> String {
        // 合法 UUIDv7 形状（版本 7 + variant 8/9/a/b）；种子只影响尾部，保持确定性。
        format!("01890f2e-4a1e-7{seed:01x}56-8f0c-6c2f11a7b9{seed:02x}")
    }

    fn envelope() -> QuotaEnvelopeV2 {
        QuotaEnvelopeV2 {
            aggregate_storage_bytes: 1000,
            kv_service_cap_bytes: 600,
            sql_service_cap_bytes: 600,
        }
    }

    fn reserve(usage: &LedgerUsageV2, backend: QuotaBackend, delta: u64, tag: u8) -> (QuotaReservationV2, LedgerUsageV2) {
        reserve_quota(
            usage,
            &envelope(),
            &ReserveQuotaInput {
                application_id: "notes-app",
                backend,
                reservation_id: &uuidv7(tag),
                operation_id: &uuidv7(tag),
                reserved_delta_bytes: delta,
                expires_at_ms: 10_000,
                now_ms: 1_000,
            },
        )
        .expect("reserve must succeed in test fixture")
    }

    fn marker_for(reservation: &QuotaReservationV2, committed: u64, backend_committed: u64) -> BackendOperationMarkerV2 {
        BackendOperationMarkerV2 {
            schema_version: 2,
            application_id: reservation.application_id.clone(),
            backend: reservation.backend,
            operation_id: reservation.operation_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            reservation_proof_digest: reservation.reservation_proof_digest.clone(),
            committed_bytes: committed,
            backend_committed_bytes: backend_committed,
        }
    }

    fn temp_root(tag: &str) -> PathBuf {
        // 部署层保证 wasm-data 根存在；测试自建根目录。
        let root = std::env::temp_dir().join(format!("iweb-wasm-host-services-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        root
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::symlink_metadata(path).expect("metadata").permissions().mode() & 0o7777
    }

    // ------------------------------------------------------------------
    // digestV2
    // ------------------------------------------------------------------

    #[test]
    fn digest_v2_frames_domain_with_single_nul_separator() {
        let payload = br#"{"a":1}"#;
        let mut oracle = Sha256::new();
        oracle.update(b"iweb-wasm-quota-reservation-v2");
        oracle.update([0x00]);
        oracle.update(payload);
        assert_eq!(digest_v2(QUOTA_RESERVATION_DIGEST_DOMAIN, payload).unwrap(), hex::encode(oracle.finalize()));
    }

    #[test]
    fn digest_v2_rejects_unknown_domains_and_is_not_v1_newline_convention() {
        assert!(digest_v2("iweb-wasm-host-policy-v3", b"x").is_err());
        let payload = br#"{"schemaVersion":2}"#;
        let v2 = digest_v2("iweb-wasm-host-policy-v2", payload).unwrap();
        let mut v1_style = Sha256::new();
        v1_style.update(b"iweb-wasm-host-policy-v2\n");
        v1_style.update(payload);
        assert_ne!(v2, hex::encode(v1_style.finalize()));
        assert_eq!(WASM_DIGEST_V2_DOMAINS.len(), 16);
    }

    // ------------------------------------------------------------------
    // path derivation（负例矩阵）
    // ------------------------------------------------------------------

    #[test]
    fn derives_exactly_one_directory_component() {
        let root = Path::new("/data/kernel/wasm-data");
        let paths = derive_application_data_paths(root, "notes-app").unwrap();
        assert_eq!(paths.directory, root.join("notes-app"));
        assert_eq!(paths.kv, root.join("notes-app").join("kv.sqlite3"));
        assert_eq!(paths.sql, root.join("notes-app").join("sql.sqlite3"));
        assert_eq!(paths.quota, root.join("notes-app").join("quota.sqlite3"));
    }

    #[test]
    fn rejects_path_escape_and_malformed_ids() {
        let root = Path::new("/data/kernel/wasm-data");
        for bad in [
            "", ".", "..", "a/b", "a\\b", "/abs", "A", "Notes", "-ab", "ab-", "a b", "a..b\0x", "a?b", "a_b!",
        ] {
            assert!(derive_application_data_paths(root, bad).is_err(), "id {bad:?} must be rejected");
        }
        let too_long = "a".repeat(64);
        assert!(derive_application_data_paths(root, &too_long).is_err());
        // root 自身带 .. 也必须拒绝（结构双保险）。
        assert!(derive_application_data_paths(Path::new("/data/../kernel"), "app").is_err());
    }

    // ------------------------------------------------------------------
    // preparation 生命周期（真实文件系统；创建失败 → not ready 且不扰动旧状态）
    // ------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn prepare_creates_0700_directory_and_0600_files_idempotently() {
        let root = temp_root("prepare-ok");
        let prepared = prepare_application_backends(&root, "notes-app").unwrap();
        assert_eq!(prepared.created.len(), 3);
        assert_eq!(mode_of(&prepared.paths.directory), 0o700);
        for (_, file) in prepared.paths.files() {
            assert_eq!(mode_of(file), 0o600);
            assert!(file.symlink_metadata().unwrap().is_file());
        }
        // 幂等：第二次全部走既有校验，不新建。
        let again = prepare_application_backends(&root, "notes-app").unwrap();
        assert!(again.created.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_fails_not_ready_on_symlink_or_wrong_mode_and_never_touches_siblings() {
        let root = temp_root("prepare-fail");
        let prepared = prepare_application_backends(&root, "notes-app").unwrap();
        // 旧 kv 数据（哨兵字节）必须原样保留。
        std::fs::write(&prepared.paths.kv, b"sentinel-kv").unwrap();
        // sql 被替换为 symlink：整体 not ready。
        std::fs::remove_file(&prepared.paths.sql).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", &prepared.paths.sql).unwrap();
        let failed = prepare_application_backends(&root, "notes-app").unwrap_err();
        assert_eq!(failed.code, WASM_HOST_SERVICE_PREPARATION_NOT_READY);
        // 失败不扰动旧状态：kv 哨兵原样，symlink 原样（绝不删除/截断/重写既有路径）。
        assert_eq!(std::fs::read(&prepared.paths.kv).unwrap(), b"sentinel-kv");
        assert!(prepared.paths.sql.is_symlink());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_fails_not_ready_on_wrong_permission_and_directory_occupation() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temp_root("prepare-mode");
        let prepared = prepare_application_backends(&root, "notes-app").unwrap();
        std::fs::set_permissions(&prepared.paths.kv, std::fs::Permissions::from_mode(0o644)).unwrap();
        let failed = prepare_application_backends(&root, "notes-app").unwrap_err();
        assert_eq!(failed.code, WASM_HOST_SERVICE_PREPARATION_NOT_READY);
        // 目录位置被普通文件占用 → not ready，且不产生任何文件。
        let root2 = temp_root("prepare-occupied");
        std::fs::create_dir_all(&root2).unwrap();
        std::fs::write(root2.join("other-app"), b"occupied").unwrap();
        let failed2 = prepare_application_backends(&root2, "other-app").unwrap_err();
        assert_eq!(failed2.code, WASM_HOST_SERVICE_PREPARATION_NOT_READY);
        assert!(root2.join("other-app").is_file());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&root2);
    }

    // ------------------------------------------------------------------
    // ledger：reserve / proof / marker gate / finalize / release / 单调 revision
    // ------------------------------------------------------------------

    #[test]
    fn reserve_enforces_aggregate_and_service_caps_atomically() {
        let usage = LedgerUsageV2::initial();
        // aggregate: 0 + 0 + 1001 > 1000 → 写前拒绝，且不改任何后端/快照。
        let denied = reserve_quota(
            &usage,
            &envelope(),
            &ReserveQuotaInput {
                application_id: "notes-app",
                backend: QuotaBackend::Kv,
                reservation_id: &uuidv7(1),
                operation_id: &uuidv7(2),
                reserved_delta_bytes: 1001,
                expires_at_ms: 10_000,
                now_ms: 1_000,
            },
        )
        .unwrap_err();
        assert_eq!(denied.code, WASM_HOST_SERVICE_QUOTA_EXCEEDED);
        // delta <= envelope 但 > 服务 cap。
        let service_denied = reserve_quota(
            &usage,
            &envelope(),
            &ReserveQuotaInput {
                application_id: "notes-app",
                backend: QuotaBackend::Sql,
                reservation_id: &uuidv7(3),
                operation_id: &uuidv7(4),
                reserved_delta_bytes: 700,
                expires_at_ms: 10_000,
                now_ms: 1_000,
            },
        )
        .unwrap_err();
        assert_eq!(service_denied.code, WASM_HOST_SERVICE_QUOTA_EXCEEDED);
        // 不可证明输入（delta 0）同样写前拒绝。
        let zero_delta = reserve_quota(
            &usage,
            &envelope(),
            &ReserveQuotaInput {
                application_id: "notes-app",
                backend: QuotaBackend::Kv,
                reservation_id: &uuidv7(5),
                operation_id: &uuidv7(6),
                reserved_delta_bytes: 0,
                expires_at_ms: 10_000,
                now_ms: 1_000,
            },
        );
        assert!(zero_delta.is_err());
        let expired = reserve_quota(
            &usage,
            &envelope(),
            &ReserveQuotaInput {
                application_id: "notes-app",
                backend: QuotaBackend::Kv,
                reservation_id: &uuidv7(7),
                operation_id: &uuidv7(8),
                reserved_delta_bytes: 10,
                expires_at_ms: 500,
                now_ms: 1_000,
            },
        )
        .unwrap_err();
        assert_eq!(expired.code, WASM_HOST_SERVICE_LEDGER_INVALID);
    }

    #[test]
    fn reservation_proof_binds_reserved_state_and_tampering_is_detected() {
        let (reservation, _) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 100, 1);
        assert!(verify_reservation_proof(&reservation).is_ok());
        // 任何字段篡改（delta）都会使 proof 复算失败。
        let mut tampered = reservation.clone();
        tampered.reserved_delta_bytes += 1;
        assert_eq!(verify_reservation_proof(&tampered).unwrap_err().code, WASM_HOST_SERVICE_RESERVATION_PROOF_MISMATCH);
        // committed/released 状态下 proof 仍按 reserved 形状复算（proof 是 durable 的）。
        let mut committed = reservation.clone();
        committed.state = ReservationState::Committed;
        assert!(verify_reservation_proof(&committed).is_ok());
    }

    #[test]
    fn backend_write_gate_requires_durable_matching_reservation_and_usage_revision() {
        let (reservation, usage) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Sql, 100, 2);
        let marker = marker_for(&reservation, 150, 150);
        assert!(verify_backend_write_authority(&marker, &reservation, "notes-app", usage.usage_revision).is_ok());
        // 跨应用。
        assert_eq!(
            verify_backend_write_authority(&marker, &reservation, "other-app", usage.usage_revision).unwrap_err().code,
            WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH
        );
        // stale usage revision（并发写后过期检查）。
        assert_eq!(
            verify_backend_write_authority(&marker, &reservation, "notes-app", usage.usage_revision + 1).unwrap_err().code,
            WASM_HOST_SERVICE_LEDGER_STALE
        );
        // released 行不得授权后端写。
        let (released, _) = release_reservation(&usage, &reservation).unwrap();
        assert_eq!(
            verify_backend_write_authority(&marker, &released, "notes-app", usage.usage_revision).unwrap_err().code,
            WASM_HOST_SERVICE_BACKEND_MARKER_MISMATCH
        );
        // 伪造 marker（他人 proof）。
        let mut forged = marker.clone();
        forged.reservation_proof_digest = "f".repeat(64);
        assert!(verify_backend_write_authority(&forged, &reservation, "notes-app", usage.usage_revision).is_err());
    }

    #[test]
    fn finalize_is_exactly_once_and_ledger_revision_is_strictly_monotonic() {
        let (reservation, after_reserve) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 100, 3);
        assert_eq!(after_reserve.ledger_revision, 1);
        let marker = marker_for(&reservation, 120, 120);
        verify_backend_write_authority(&marker, &reservation, "notes-app", after_reserve.usage_revision).unwrap();
        let (committed, after_finalize) = finalize_reservation(
            &after_reserve,
            &envelope(),
            &reservation,
            &FinalizeReservationInput { measured_committed_bytes: 120, measured_backend_committed_bytes: 120 },
        )
        .unwrap();
        assert_eq!(committed.state, ReservationState::Committed);
        assert_eq!(after_finalize.ledger_revision, 2);
        assert_eq!(after_finalize.usage_revision, 1);
        assert_eq!(after_finalize.committed_bytes, 120);
        assert_eq!(after_finalize.outstanding_reserved_bytes, 0);
        assert_eq!(after_finalize.kv_committed_bytes, 120);
        // 幂等重放：committed 行 finalize 返回原状，不再递增任何 revision。
        let (replayed, after_replay) = finalize_reservation(
            &after_finalize,
            &envelope(),
            &committed,
            &FinalizeReservationInput { measured_committed_bytes: 999, measured_backend_committed_bytes: 999 },
        )
        .unwrap();
        assert_eq!(replayed, committed);
        assert_eq!(after_replay, after_finalize);
        // 释放路径只减 outstanding，不动 committed/usage revision。
        let (reservation2, after_reserve2) = reserve(&after_finalize, QuotaBackend::Sql, 50, 4);
        let (released, after_release) = release_reservation(&after_reserve2, &reservation2).unwrap();
        assert_eq!(released.state, ReservationState::Released);
        assert_eq!(after_release.committed_bytes, after_finalize.committed_bytes);
        assert_eq!(after_release.usage_revision, after_finalize.usage_revision);
        assert_eq!(after_release.ledger_revision, 4);
        // 超过 envelope 的测量值 → recovery/quarantine 码（不是配额 no-op）。
        let (reservation3, after_reserve3) = reserve(&after_release, QuotaBackend::Kv, 10, 5);
        let over = finalize_reservation(
            &after_reserve3,
            &envelope(),
            &reservation3,
            &FinalizeReservationInput { measured_committed_bytes: 1001, measured_backend_committed_bytes: 1001 },
        )
        .unwrap_err();
        assert_eq!(over.code, WASM_HOST_SERVICE_RECOVERY_REQUIRED);
    }

    #[test]
    fn concurrent_kv_and_sql_cannot_both_pass_the_pre_write_check() {
        // envelope 1000；先到 kv reserve 600（=kv cap）。
        let (kv_reservation, after_kv) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 600, 6);
        // sql 只剩 400 可用：500 必须写前拒绝。
        let denied = reserve_quota(
            &after_kv,
            &envelope(),
            &ReserveQuotaInput {
                application_id: "notes-app",
                backend: QuotaBackend::Sql,
                reservation_id: &uuidv7(7),
                operation_id: &uuidv7(8),
                reserved_delta_bytes: 500,
                expires_at_ms: 10_000,
                now_ms: 1_000,
            },
        )
        .unwrap_err();
        assert_eq!(denied.code, WASM_HOST_SERVICE_QUOTA_EXCEEDED);
        // 400 恰好放行：串行化保证后提交 envelope 恰好装满。
        let (sql_reservation, after_sql) = reserve(&after_kv, QuotaBackend::Sql, 400, 9);
        assert_eq!(after_sql.outstanding_reserved_bytes, 1000);
        // 再 1 字节也被拒，且拒绝不改变任何 ledger 状态。
        let denied_more = reserve_quota(
            &after_sql,
            &envelope(),
            &ReserveQuotaInput {
                application_id: "notes-app",
                backend: QuotaBackend::Sql,
                reservation_id: &uuidv7(12),
                operation_id: &uuidv7(13),
                reserved_delta_bytes: 1,
                expires_at_ms: 10_000,
                now_ms: 1_000,
            },
        )
        .unwrap_err();
        assert_eq!(denied_more.code, WASM_HOST_SERVICE_QUOTA_EXCEEDED);
        assert_eq!(after_sql.outstanding_reserved_bytes, 1000);
        // 跨后端原子证明：marker 必须与同一 reservation 行配对；把 sql 的 marker 对上 kv 的行
        // 在 provider 写闸门处拒绝。
        let forged_marker = marker_for(&sql_reservation, 1000, 400);
        assert!(verify_backend_write_authority(&forged_marker, &kv_reservation, "notes-app", after_kv.usage_revision).is_err());
        // 无 ledger 行支撑的孤立 marker 进入恢复计划时必须被隔离。
        let plan = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &after_sql,
            envelope: &envelope(),
            reservations: std::slice::from_ref(&kv_reservation),
            markers: &[forged_marker],
        })
        .unwrap();
        assert_eq!(plan.status, LedgerRecoveryStatus::Quarantined);
    }

    // ------------------------------------------------------------------
    // 崩溃矩阵（design 恢复表逐行）
    // ------------------------------------------------------------------

    #[test]
    fn recovery_matrix_releases_reserved_without_marker() {
        let (reservation, usage) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 100, 1);
        let plan = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &usage,
            envelope: &envelope(),
            reservations: std::slice::from_ref(&reservation),
            markers: &[],
        })
        .unwrap();
        assert_eq!(plan.status, LedgerRecoveryStatus::Recovering);
        assert!(matches!(plan.actions[0], RecoveryActionV2::ReleaseReservation { .. }));
        assert_eq!(plan.resulting_usage.outstanding_reserved_bytes, 0);
        assert_eq!(plan.resulting_usage.committed_bytes, 0, "expired/uncommitted reservations are never charged");
    }

    #[test]
    fn recovery_matrix_finalizes_reserved_with_marker_exactly_once() {
        let (reservation, usage) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Sql, 100, 2);
        let marker = marker_for(&reservation, 90, 90);
        let plan = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &usage,
            envelope: &envelope(),
            reservations: &[reservation],
            markers: &[marker],
        })
        .unwrap();
        assert_eq!(plan.status, LedgerRecoveryStatus::Recovering);
        assert!(matches!(plan.actions[0], RecoveryActionV2::FinalizeFromMarker { .. }));
        assert_eq!(plan.resulting_usage.committed_bytes, 90);
        assert_eq!(plan.resulting_usage.sql_committed_bytes, 90);
        assert_eq!(plan.resulting_usage.outstanding_reserved_bytes, 0);
        assert_eq!(plan.resulting_usage.usage_revision, 1);
    }

    #[test]
    fn recovery_matrix_committed_with_marker_is_idempotent_replay() {
        let (reservation, after_reserve) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 100, 3);
        let (committed, usage) = finalize_reservation(
            &after_reserve,
            &envelope(),
            &reservation,
            &FinalizeReservationInput { measured_committed_bytes: 80, measured_backend_committed_bytes: 80 },
        )
        .unwrap();
        let marker = marker_for(&committed, 80, 80);
        let plan = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &usage,
            envelope: &envelope(),
            reservations: &[committed],
            markers: &[marker],
        })
        .unwrap();
        assert_eq!(plan.status, LedgerRecoveryStatus::Healthy);
        assert!(plan.actions.is_empty(), "committed + marker replays the stored result without another finalize");
        assert_eq!(plan.resulting_usage.committed_bytes, 80);
    }

    #[test]
    fn recovery_matrix_orphan_marker_quarantines_then_reconstructs() {
        let orphan = BackendOperationMarkerV2 {
            schema_version: 2,
            application_id: "notes-app".into(),
            backend: QuotaBackend::Sql,
            operation_id: uuidv7(4),
            reservation_id: uuidv7(5),
            reservation_proof_digest: "a".repeat(64),
            committed_bytes: 70,
            backend_committed_bytes: 70,
        };
        let usage = LedgerUsageV2::initial();
        let plan = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &usage,
            envelope: &envelope(),
            reservations: &[],
            markers: &[orphan],
        })
        .unwrap();
        assert_eq!(plan.status, LedgerRecoveryStatus::Quarantined);
        assert!(plan.actions.iter().any(|action| matches!(action, RecoveryActionV2::QuarantineBackend { .. })));
        assert!(plan.actions.iter().any(|action| matches!(action, RecoveryActionV2::FinalizeFromMarker { .. })));
    }

    #[test]
    fn recovery_matrix_released_with_committed_marker_requires_owner() {
        let (reservation, after_reserve) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 100, 6);
        let (released, usage) = release_reservation(&after_reserve, &reservation).unwrap();
        let marker = marker_for(&released, 80, 80);
        let plan = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &usage,
            envelope: &envelope(),
            reservations: &[released],
            markers: &[marker],
        })
        .unwrap();
        assert_eq!(plan.status, LedgerRecoveryStatus::OwnerRecoveryRequired);
        // 绝不扣减其它 operation 的用量。
        assert_eq!(plan.resulting_usage.committed_bytes, usage.committed_bytes);
    }

    #[test]
    fn recovery_matrix_rejects_impossible_revisions_and_cross_application_rows() {
        let (reservation, usage) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 100, 7);
        let duplicate = QuotaReservationV2 { ledger_revision: reservation.ledger_revision, ..reservation.clone() };
        let plan = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &usage,
            envelope: &envelope(),
            reservations: &[reservation.clone(), duplicate],
            markers: &[],
        })
        .unwrap();
        assert_eq!(plan.status, LedgerRecoveryStatus::OwnerRecoveryRequired);
        // committed 无 marker：不可证明。
        let (committed, usage2) = finalize_reservation(
            &usage,
            &envelope(),
            &reservation,
            &FinalizeReservationInput { measured_committed_bytes: 50, measured_backend_committed_bytes: 50 },
        )
        .unwrap();
        let plan2 = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &usage2,
            envelope: &envelope(),
            reservations: &[committed],
            markers: &[],
        })
        .unwrap();
        assert_eq!(plan2.status, LedgerRecoveryStatus::OwnerRecoveryRequired);
        // 跨应用行直接拒绝。
        let mut foreign = reservation;
        foreign.application_id = "other-app".into();
        let denied = plan_ledger_recovery(&LedgerRecoveryInput {
            application_id: "notes-app",
            usage: &LedgerUsageV2::initial(),
            envelope: &envelope(),
            reservations: &[foreign],
            markers: &[],
        });
        assert!(denied.is_err());
    }

    // ------------------------------------------------------------------
    // 数据面/控制面结构隔离
    // ------------------------------------------------------------------

    #[test]
    fn data_plane_records_never_carry_control_authority_fields() {
        let (reservation, usage) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 10, 8);
        let marker = marker_for(&reservation, 10, 10);
        let summary = ControlStateServicePolicySummaryV2 {
            schema_version: 2,
            policy_digest: "b".repeat(64),
            storage_bytes: 1000,
            data_directory_profile: "per-app-sqlite-v1".into(),
            durability_profile: "sqlite-full-fsync-v1".into(),
            host_services: HostServicesEnabledV2 {
                kv: Some("bounded-cas-list-v1".into()),
                sql: None,
                logging: Some("bounded-memory-ring-v1".into()),
            },
        };
        for record in [
            serde_json::to_vec(&reservation).unwrap(),
            serde_json::to_vec(&marker).unwrap(),
            serde_json::to_vec(&usage).unwrap(),
            serde_json::to_vec(&summary).unwrap(),
        ] {
            // jcs_bytes 兼作 canonical 化（键排序后逐键扫描）。
            let value: serde_json::Value = serde_json::from_slice(&record).unwrap();
            let canonical = jcs_bytes(&value).unwrap();
            assert!(record_is_control_authority_free(&canonical), "data-plane record must not carry control CAS fields");
        }
        // 反例：携带 controlRevision 的对象必须被识别。
        let tainted = br#"{"controlRevision":3}"#;
        assert!(!record_is_control_authority_free(tainted));
    }

    #[test]
    fn data_plane_files_and_control_state_are_independent_cas_domains() {
        let root = Path::new("/data/kernel/wasm-data");
        let paths = derive_application_data_paths(root, "notes-app").unwrap();
        let control_state = Path::new("/data/kernel/wasm/wasm-control-state-v2.json");
        assert_independent_cas_domains(&paths, control_state).unwrap();
        // 控制态落在数据目录内/数据文件即控制态：结构性拒绝。
        assert!(assert_independent_cas_domains(&paths, &paths.directory.join("wasm-control-state-v2.json")).is_err());
        assert!(assert_independent_cas_domains(&paths, &paths.quota).is_err());
    }

    // ------------------------------------------------------------------
    // 备份/恢复 quiesce 与身份校验
    // ------------------------------------------------------------------

    fn backup_descriptor(application_id: &str) -> BackupSetDescriptorV2 {
        BackupSetDescriptorV2 {
            schema_version: 2,
            application_id: application_id.into(),
            host_service_policy_digest: "c".repeat(64),
            ledger_revision: 3,
            usage_revision: 2,
            quiesced: true,
            files: vec![
                BackupFileEntryV2 { kind: BackupFileKind::Kv, byte_len: 4096, sha256: "1".repeat(64), mode: 0o600, symlink: false },
                BackupFileEntryV2 { kind: BackupFileKind::Sql, byte_len: 4096, sha256: "2".repeat(64), mode: 0o600, symlink: false },
                BackupFileEntryV2 { kind: BackupFileKind::Quota, byte_len: 8192, sha256: "3".repeat(64), mode: 0o600, symlink: false },
            ],
        }
    }

    #[test]
    fn backup_plan_requires_settled_healthy_frozen_ledger_in_fixed_order() {
        let ok = plan_backup_quiesce(&BackupQuiesceStateV2 {
            outstanding_reserved_bytes: 0,
            recovery_status: LedgerRecoveryStatus::Healthy,
            ledger_revision: 7,
            frozen_ledger_revision: Some(7),
        })
        .unwrap();
        assert_eq!(
            ok,
            vec![
                BackupStepV2::DrainHostCalls,
                BackupStepV2::SettleReservations,
                BackupStepV2::FreezeLedger,
                BackupStepV2::FsyncBackends,
                BackupStepV2::CaptureIdentityAndFiles,
            ]
        );
        let outstanding = plan_backup_quiesce(&BackupQuiesceStateV2 {
            outstanding_reserved_bytes: 10,
            recovery_status: LedgerRecoveryStatus::Healthy,
            ledger_revision: 7,
            frozen_ledger_revision: Some(7),
        })
        .unwrap_err();
        assert_eq!(outstanding.code, WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED);
        let recovering = plan_backup_quiesce(&BackupQuiesceStateV2 {
            outstanding_reserved_bytes: 0,
            recovery_status: LedgerRecoveryStatus::Recovering,
            ledger_revision: 7,
            frozen_ledger_revision: Some(7),
        })
        .unwrap_err();
        assert_eq!(recovering.code, WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED);
        let unfrozen = plan_backup_quiesce(&BackupQuiesceStateV2 {
            outstanding_reserved_bytes: 0,
            recovery_status: LedgerRecoveryStatus::Healthy,
            ledger_revision: 7,
            frozen_ledger_revision: Some(6),
        })
        .unwrap_err();
        assert_eq!(unfrozen.code, WASM_HOST_SERVICE_BACKUP_QUIESCE_REQUIRED);
    }

    #[test]
    fn backup_and_restore_refuse_incomplete_cross_application_or_symlinked_sets() {
        let descriptor = backup_descriptor("notes-app");
        assert!(validate_restore_set(&descriptor, "notes-app", &"c".repeat(64)).is_ok());
        // 跨应用身份拒绝。
        assert_eq!(
            validate_restore_set(&descriptor, "other-app", &"c".repeat(64)).unwrap_err().code,
            WASM_HOST_SERVICE_BACKUP_INVALID
        );
        // policy digest 不匹配拒绝。
        assert!(validate_restore_set(&descriptor, "notes-app", &"d".repeat(64)).is_err());
        // 成员缺失。
        let missing = BackupSetDescriptorV2 { files: descriptor.files[..2].to_vec(), ..descriptor.clone() };
        assert!(validate_restore_set(&missing, "notes-app", &"c".repeat(64)).is_err());
        // symlink 成员拒绝。
        let mut symlinked = descriptor.clone();
        symlinked.files[0].symlink = true;
        assert!(validate_restore_set(&symlinked, "notes-app", &"c".repeat(64)).is_err());
        // 权限漂移拒绝。
        let mut wrong_mode = descriptor.clone();
        wrong_mode.files[1].mode = 0o644;
        assert!(validate_restore_set(&wrong_mode, "notes-app", &"c".repeat(64)).is_err());
        // 未 quiesce / 零长度成员（restore 侧空镜像拒绝）拒绝。
        let mut unquiesced = descriptor.clone();
        unquiesced.quiesced = false;
        assert!(validate_restore_set(&unquiesced, "notes-app", &"c".repeat(64)).is_err());
        let mut empty = descriptor;
        empty.files[2].byte_len = 0;
        assert!(validate_restore_set(&empty, "notes-app", &"c".repeat(64)).is_err());
    }

    // ------------------------------------------------------------------
    // wire：deny_unknown_fields + 精确键集（serde 层面 fail-closed）
    // ------------------------------------------------------------------

    #[test]
    fn reservation_and_marker_wires_reject_unknown_fields_and_wrong_literals() {
        let (reservation, _) = reserve(&LedgerUsageV2::initial(), QuotaBackend::Kv, 10, 9);
        let good = serde_json::to_value(&reservation).unwrap();
        let mut extra = good.clone();
        extra["controlRevision"] = serde_json::json!(3);
        assert!(serde_json::from_value::<QuotaReservationV2>(extra).is_err());
        let mut bad_state = good.clone();
        bad_state["state"] = serde_json::json!("expired");
        assert!(serde_json::from_value::<QuotaReservationV2>(bad_state).is_err());
        let mut bad_backend = good;
        bad_backend["backend"] = serde_json::json!("logging");
        assert!(serde_json::from_value::<QuotaReservationV2>(bad_backend).is_err());

        let marker = marker_for(&reservation, 10, 10);
        let mut marker_extra = serde_json::to_value(&marker).unwrap();
        marker_extra["path"] = serde_json::json!("/etc/passwd");
        assert!(serde_json::from_value::<BackendOperationMarkerV2>(marker_extra).is_err());
    }
}
