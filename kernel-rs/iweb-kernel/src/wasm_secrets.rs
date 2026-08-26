//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 2.3）：secrets rotation 线性化——
//! app mutation fence → Kernel secret-store revision commit/outbox → supervisor
//! sandbox journal fence 的固定锁序；journal 只存 revision/opaque reference，
//! 绝不存 secret 值。覆盖每个 crash 点、ack 丢失和连续两次 rotation——最终只
//! 接受最大 revision 的 candidate，active snapshot 保留到下一次激活。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//! "Secrets rotate through one Kernel linearization point"（锁序/崩溃矩阵/双 rotation
//! 乱序/owner 突变 CAS 语义）。
//! 纯函数权威：packages/contracts/wasm-execution.ts（nextSecretRevision/
//! matchesSecretRevisionFence——u53、单调、激活 fence 相等）。
//!
//! 正交意图：
//! 1. secret-store revision 状态机（owner mutation fence、单调 revision、连续
//!    rotation 取最大、outbox 记录）——值只存在于 Kernel store 行内；
//! 2. rotation 线性化锁序纯函数（RotationLockStep/check_rotation_lock_order）；
//! 3. supervisor invalidation journal（只存 applicationId/revision/opaque
//!    reference/identity fence；reducer 只保留最大 revision）；
//! 4. 崩溃矩阵驱动（run_secret_rotation 的 crash 注入 + recover_rotation 收敛，
//!    每个 crash 点唯一恢复结果：rotation 前提交 / 提交后命令前 / 命令后
//!    journal 前 / journal 后 ack 丢失 / 停止后重备前；双 rotation 乱序由
//!    reducer 与单向 stop 覆盖；"candidate health 后、activation CAS 前"由
//!    matches_secret_revision_fence + wasm_activation 覆盖）；
//! 5. active snapshot 保留语义（rotation 不替换；下一次成功激活才替换）。
//!
//! 不可调和原因：1/2/4 共享同一锁序与崩溃矩阵，拆分会重引入线性化点语义矛盾；
//! 3 是 4 的 durable 对面，同文件保证 journal 字段集与"绝无值"约束不漂移。
//!
//! 建模注记（接线批次映射，非语义变更）：本模块是纯状态机，时间一律用
//! epoch 毫秒 u64 表示（wire 侧 RFC3339-UTC 由 wasm_admission 的
//! parse/format_rfc3339_utc_millis 转换）；command_id 由调用方提供，
//! journal_revision 由状态机 CAS 分配，本模块不做 I/O。

use crate::wasm_admission::WASM_U53_MAX;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误码（沿用 contracts 命名风格；不覆盖 spec 已命名码）
// ---------------------------------------------------------------------------

/// spec 已命名：owner 以过期 expectedSecretRevision 提交替换。
pub const SECRET_REVISION_CONFLICT: &str = "SECRET_REVISION_CONFLICT";
/// contracts 已命名（nextSecretRevision）：u53 上界耗尽。
pub const SECRET_REVISION_EXHAUSTED: &str = "SECRET_REVISION_EXHAUSTED";
/// contracts 已命名：当前 revision 不是合法 u53。
pub const WASM_SECRET_REVISION_INVALID: &str = "WASM_SECRET_REVISION_INVALID";

pub const WASM_SECRET_APPLICATION_INVALID: &str = "WASM_SECRET_APPLICATION_INVALID";
pub const WASM_SECRET_KEY_INVALID: &str = "WASM_SECRET_KEY_INVALID";
pub const WASM_SECRET_ALLOWLIST_INVALID: &str = "WASM_SECRET_ALLOWLIST_INVALID";
pub const WASM_SECRET_IDENTITY_FENCE_INVALID: &str = "WASM_SECRET_IDENTITY_FENCE_INVALID";
pub const WASM_SECRET_ROTATION_LOCK_ORDER_INVALID: &str = "WASM_SECRET_ROTATION_LOCK_ORDER_INVALID";
pub const WASM_SECRET_OUTBOX_INVALID: &str = "WASM_SECRET_OUTBOX_INVALID";
pub const WASM_SECRET_OUTBOX_BACKLOG: &str = "WASM_SECRET_OUTBOX_BACKLOG";
pub const WASM_SECRET_JOURNAL_INVALID: &str = "WASM_SECRET_JOURNAL_INVALID";
pub const WASM_SECRET_REPREPARE_STALE: &str = "WASM_SECRET_REPREPARE_STALE";
pub const WASM_SECRET_SNAPSHOT_REF_INVALID: &str = "WASM_SECRET_SNAPSHOT_REF_INVALID";
/// 崩溃矩阵驱动的模拟崩溃标记（仅驱动注入用；生产路径不产生）。
pub const WASM_SECRET_SIMULATED_CRASH: &str = "WASM_SECRET_SIMULATED_CRASH";

/// allowlist 键数上界（spec：keys.length 为 0..256，含端点）。
pub const WASM_SECRET_MAX_KEYS: usize = 256;
/// 单值字节上界（spec：UTF-8 字符串 0..65536 字节，含端点）。
pub const WASM_SECRET_MAX_VALUE_BYTES: usize = 65_536;

/// 结构化 rotation 错误：code 为稳定 owner 可见码，detail 不含任何秘密值。
#[derive(Debug, Clone, PartialEq)]
pub struct SecretRotationError {
    pub code: &'static str,
    pub detail: String,
}

impl SecretRotationError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for SecretRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SecretRotationError {}

fn err(code: &'static str, detail: impl Into<String>) -> SecretRotationError {
    SecretRotationError::new(code, detail)
}

fn simulated_crash(point: &str) -> SecretRotationError {
    err(WASM_SECRET_SIMULATED_CRASH, format!("simulated crash at {point}"))
}

// ---------------------------------------------------------------------------
// 名称文法（applicationId / secret key / 身份 fence / sha256-hex opaque ref）
// ---------------------------------------------------------------------------

struct SecretRegexes {
    application_id: regex::Regex,
    secret_key: regex::Regex,
    sandbox_id: regex::Regex,
    version_id: regex::Regex,
    sha256_hex: regex::Regex,
}

fn regexes() -> &'static SecretRegexes {
    static REGEXES: OnceLock<SecretRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| SecretRegexes {
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
        // spec：^[a-z][a-z0-9._-]{0,127}$——1..128 字节，禁斜杠/空白/冒号/NUL。
        secret_key: regex::Regex::new(r"^[a-z][a-z0-9._-]{0,127}$").expect("secret key regex"),
        sandbox_id: regex::Regex::new(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$").expect("sandbox id regex"),
        version_id: regex::Regex::new(r"^[a-f0-9]{64}-[1-9][0-9]{0,15}$").expect("version id regex"),
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
    })
}

pub fn validate_secret_application_id(value: &str) -> Result<(), SecretRotationError> {
    if regexes().application_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_SECRET_APPLICATION_INVALID, "applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"))
    }
}

pub fn validate_secret_key(key: &str) -> Result<(), SecretRotationError> {
    if regexes().secret_key.is_match(key) {
        Ok(())
    } else {
        Err(err(WASM_SECRET_KEY_INVALID, format!("key must match ^[a-z][a-z0-9._-]{{0,127}}$ and carry no slash, whitespace, colon, or NUL: {key:?}")))
    }
}

/// opaque snapshot reference：sha256-hex；supervisor 与日志永不解析其内容。
pub fn validate_secret_snapshot_ref(value: &str) -> Result<(), SecretRotationError> {
    if regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_SECRET_SNAPSHOT_REF_INVALID, "secretSnapshotRef must be 64 lower-case hex characters"))
    }
}

fn require_u53(value: u64, field: &str) -> Result<(), SecretRotationError> {
    if value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(WASM_SECRET_REVISION_INVALID, format!("{field} must be a u53 integer")))
    }
}

// ---------------------------------------------------------------------------
// revision 纯函数（对位 wasm-execution.ts nextSecretRevision / matchesSecretRevisionFence）
// ---------------------------------------------------------------------------

/// 下一个 revision：当前值必须是合法 u53；到 u53 上界即 SECRET_REVISION_EXHAUSTED
/// （不回绕、不复用、不归零）；否则严格 +1。revision 0 表示未分配。
pub fn next_secret_revision(current_secret_revision: u64) -> Result<u64, SecretRotationError> {
    require_u53(current_secret_revision, "secretRevision")?;
    if current_secret_revision == WASM_U53_MAX {
        return Err(err(SECRET_REVISION_EXHAUSTED, "secret revision space is exhausted; no strictly higher u53 revision exists"));
    }
    Ok(current_secret_revision + 1)
}

/// 激活/候选 fence：候选 revision 必须等于当前 secret-store revision（严格相等；
/// "最终只接受最大 revision 的 candidate"在激活侧的判据）。
pub fn matches_secret_revision_fence(current_revision: u64, candidate_revision: u64) -> bool {
    current_revision == candidate_revision
}

/// 重备 fence：崩溃恢复 preparation 只允许 snapshot 当前最大已提交 revision
/// （spec 崩溃矩阵行 4：recovery prepares only at current greatest revision）。
pub fn check_reprepare_revision_fence(greatest_committed_revision: u64, requested_revision: u64) -> Result<(), SecretRotationError> {
    require_u53(greatest_committed_revision, "greatestCommittedRevision")?;
    require_u53(requested_revision, "requestedRevision")?;
    if greatest_committed_revision == requested_revision {
        Ok(())
    } else {
        Err(err(WASM_SECRET_REPREPARE_STALE, format!("a recovery preparation must snapshot the current greatest committed revision {greatest_committed_revision}, not {requested_revision}")))
    }
}

// ---------------------------------------------------------------------------
// owner 突变请求（PUT secret-allowlist 的纯模型；值只进入 store，永不流出）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretAllowlistMutation {
    pub schema_version: u64,
    pub application_id: String,
    pub expected_secret_revision: u64,
    /// 排序、去重、0..=256 个合法 key。
    pub keys: Vec<String>,
    /// 值只存在于 Kernel secret store；键集合必须逐字节等于 keys。
    pub values: BTreeMap<String, String>,
}

impl SecretAllowlistMutation {
    pub fn validate(&self) -> Result<(), SecretRotationError> {
        if self.schema_version != 1 {
            return Err(err(WASM_SECRET_ALLOWLIST_INVALID, "schemaVersion must be exactly 1"));
        }
        validate_secret_application_id(&self.application_id)?;
        require_u53(self.expected_secret_revision, "expectedSecretRevision")?;
        if self.keys.len() > WASM_SECRET_MAX_KEYS {
            return Err(err(WASM_SECRET_ALLOWLIST_INVALID, format!("keys must carry at most {WASM_SECRET_MAX_KEYS} entries")));
        }
        for pair in self.keys.windows(2) {
            if pair[0].as_bytes() >= pair[1].as_bytes() {
                return Err(err(WASM_SECRET_ALLOWLIST_INVALID, "keys must be sorted bytewise ascending and duplicate-free"));
            }
        }
        for key in &self.keys {
            validate_secret_key(key)?;
        }
        // 值对象键集合必须逐字节等于 keys（缺失/多余/重复一律拒绝；
        // BTreeMap 已天然去重，长度+包含检查即得集合相等）。
        if self.values.len() != self.keys.len() || !self.keys.iter().all(|key| self.values.contains_key(key)) {
            return Err(err(WASM_SECRET_ALLOWLIST_INVALID, "the values key set must equal keys"));
        }
        for value in self.values.values() {
            if value.len() > WASM_SECRET_MAX_VALUE_BYTES {
                return Err(err(WASM_SECRET_ALLOWLIST_INVALID, format!("each value must be at most {WASM_SECRET_MAX_VALUE_BYTES} UTF-8 bytes")));
            }
        }
        Ok(())
    }
}

/// owner 响应投影：{schemaVersion, applicationId, secretRevision, keys}——绝无值。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretAllowlistResponse {
    pub schema_version: u64,
    pub application_id: String,
    pub secret_revision: u64,
    pub keys: Vec<String>,
}

impl SecretAllowlistResponse {
    pub fn from_store(store: &SecretStoreRow) -> Self {
        Self { schema_version: 1, application_id: store.application_id.clone(), secret_revision: store.secret_revision, keys: store.keys.clone() }
    }
}

// ---------------------------------------------------------------------------
// 固定锁序纯函数（spec "The fixed linearization and lock order" 六步）
// ---------------------------------------------------------------------------

/// 一次 rotation 的锁序阶段。durable 语义：SecretRowCasCommitted 起的
/// revision/outbox 变更跨崩溃存在；mutation fence 与 row lock 是进程内锁，
/// 崩溃即消失（恢复把阶段复位回 Idle，durable 字段保留）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RotationLockStep {
    /// 无锁持有（或一轮锁序完成后复位）。
    Idle,
    /// 1. 已取得该 application 的 mutation fence。
    AppFenceAcquired,
    /// 2+3. secret-store 行 CAS 已提交（revision + outbox 同一提交）——线性化点。
    SecretRowCasCommitted,
    /// 4a. 行锁已释放（尚未持久化 invalidation 命令，不得等待 supervisor）。
    SecretRowLockReleased,
    /// 4b. supervisor invalidation 命令已持久化。
    InvalidationCommandPersisted,
    /// 5. mutation fence 已释放（本轮锁序完成，随后复位 Idle）。
    Completed,
}

/// 锁序合法性纯函数：只接受 spec 六步的正向推进。关键拒绝面：
/// - 未持 fence 即提交（Idle→SecretRowCasCommitted 跳步）；
/// - 持行锁等待 supervisor（AppFenceAcquired→InvalidationCommandPersisted
///   跳过行锁释放，即 spec 明令禁止的等待）；
/// - 命令未持久化即释放 fence（SecretRowLockReleased→Completed）；
/// - 任何回退或重复。
pub fn check_rotation_lock_order(from: RotationLockStep, to: RotationLockStep) -> Result<(), SecretRotationError> {
    use RotationLockStep::*;
    let allowed = matches!(
        (from, to),
        (Idle, AppFenceAcquired)
            | (AppFenceAcquired, SecretRowCasCommitted)
            | (SecretRowCasCommitted, SecretRowLockReleased)
            | (SecretRowLockReleased, InvalidationCommandPersisted)
            | (InvalidationCommandPersisted, Completed)
    );
    if allowed {
        Ok(())
    } else {
        Err(err(
            WASM_SECRET_ROTATION_LOCK_ORDER_INVALID,
            format!("illegal rotation lock-order transition {from:?} -> {to:?}; the fixed order is app fence -> secret-row CAS commit -> row-lock release -> invalidation command persistence -> fence release"),
        ))
    }
}

fn advance_lock(from: RotationLockStep, to: RotationLockStep) -> Result<RotationLockStep, SecretRotationError> {
    check_rotation_lock_order(from, to)?;
    Ok(to)
}

// ---------------------------------------------------------------------------
// Kernel secret store 行（revision 状态机；值只在本行内）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretStoreRow {
    pub application_id: String,
    /// 单调 revision；0 表示未分配。首分配/每次轮换严格 +1。
    pub secret_revision: u64,
    /// 当前 allowlist（排序、去重）。
    pub keys: Vec<String>,
    /// 秘密值只存在于本字段：绝不进入 outbox、journal、命令、响应或日志。
    pub values: BTreeMap<String, String>,
}

impl SecretStoreRow {
    /// 初始行：revision 0（未分配），空 allowlist。revision 0 也有 canonical
    /// 空 snapshot（固定 opaque ref 由接线层提供）。
    pub fn new(application_id: &str) -> Result<Self, SecretRotationError> {
        validate_secret_application_id(application_id)?;
        Ok(Self { application_id: application_id.to_string(), secret_revision: 0, keys: Vec::new(), values: BTreeMap::new() })
    }

    pub fn validate(&self) -> Result<(), SecretRotationError> {
        let probe = SecretAllowlistMutation {
            schema_version: 1,
            application_id: self.application_id.clone(),
            expected_secret_revision: self.secret_revision,
            keys: self.keys.clone(),
            values: self.values.clone(),
        };
        probe.validate()
    }
}

// ---------------------------------------------------------------------------
// 身份 fence / supervisor invalidation 命令 / outbox
// ---------------------------------------------------------------------------

/// 身份 fence：journal 条目携带的 (sandboxId, versionId, P, E) 四元组。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretIdentityFence {
    pub sandbox_id: String,
    pub version_id: String,
    pub preparation_generation: u64,
    pub execution_generation: u64,
}

impl SecretIdentityFence {
    pub fn validate(&self) -> Result<(), SecretRotationError> {
        if !regexes().sandbox_id.is_match(&self.sandbox_id) {
            return Err(err(WASM_SECRET_IDENTITY_FENCE_INVALID, "sandboxId must start with a lower-case letter and be at most 63 ASCII bytes"));
        }
        if !regexes().version_id.is_match(&self.version_id) {
            return Err(err(WASM_SECRET_IDENTITY_FENCE_INVALID, "versionId must be <64 lower-case hex>-<positive sequence without leading zero>"));
        }
        require_u53(self.preparation_generation, "preparationGeneration")?;
        require_u53(self.execution_generation, "executionGeneration")?;
        Ok(())
    }
}

/// Kernel 持久化的 supervisor invalidation 命令（锁序第 4 步产物）。
/// 字段集刻意排除任何秘密值：只有 revision、opaque reference 与 fence 目标。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretInvalidationCommand {
    pub schema_version: u64,
    pub command_id: String,
    pub application_id: String,
    /// 本次已提交的新 revision；supervisor 以此为 fence 停掉更旧候选。
    pub secret_revision: u64,
    /// 新 revision 的 opaque Kernel 引用（sha256-hex；supervisor 不解析）。
    pub secret_snapshot_ref: String,
    /// 本命令 fence 的非 active 候选（revision 低于 secret_revision 者）。
    pub fence_targets: Vec<SecretIdentityFence>,
}

impl SecretInvalidationCommand {
    pub fn validate(&self) -> Result<(), SecretRotationError> {
        if self.schema_version != 1 {
            return Err(err(WASM_SECRET_OUTBOX_INVALID, "schemaVersion must be exactly 1"));
        }
        validate_secret_application_id(&self.application_id)?;
        require_u53(self.secret_revision, "secretRevision")?;
        validate_secret_snapshot_ref(&self.secret_snapshot_ref)?;
        if self.secret_revision == 0 {
            return Err(err(WASM_SECRET_OUTBOX_INVALID, "an invalidation command must fence a committed revision of at least 1"));
        }
        for target in &self.fence_targets {
            target.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretOutboxDeliveryState {
    /// 命令已提交到 outbox（与 revision 同一 CAS），尚未物化/送达。
    Pending,
    /// 已物化并送达 supervisor（advisory；可重放）。
    Sent,
    /// supervisor journal 的 completed 条目已被 Kernel 校验投影。
    Acknowledged,
    /// 永久 fence 错误（owner 可见；不自动重试）。
    Dead,
}

/// outbox 记录：与 revision 提交同一 CAS 追加。`pending_snapshot_ref` 与
/// revision 同一提交持久化，使崩溃矩阵行 2 的恢复能确定性地重建同一条命令；
/// `invalidation_command` 在锁序第 4 步物化。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretInvalidationOutboxRecord {
    pub schema_version: u64,
    pub command_id: String,
    pub application_id: String,
    pub secret_revision: u64,
    pub created_at_epoch_millis: u64,
    pub delivery_state: SecretOutboxDeliveryState,
    pub attempts: u64,
    /// None = 尚未持久化 supervisor 命令（行 2 恢复点）。
    pub invalidation_command: Option<SecretInvalidationCommand>,
    /// 新 revision 的 opaque ref（与 revision 同一提交；命令重建的确定性输入）。
    pub pending_snapshot_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// supervisor sandbox journal（只有 revision / opaque reference / identity fence）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorSecretEntryKind {
    Received,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SupervisorSecretJournalEntry {
    pub schema_version: u64,
    pub kind: SupervisorSecretEntryKind,
    pub command_id: String,
    /// supervisor journal 自身 CAS 计数（与 Kernel controlRevision 互不替代）。
    pub journal_revision: u64,
    pub application_id: String,
    /// 本条 invalidation 对应的 revision fence。
    pub secret_revision: u64,
    /// opaque Kernel 引用；supervisor 视为不透明字节。
    pub secret_snapshot_ref: String,
    /// 本条命令 fence 的候选身份（active 永不在此）。
    pub fenced_candidates: Vec<SecretIdentityFence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorCandidateState {
    Preparing,
    Ready,
    Stopped,
}

/// supervisor 侧候选：secret_revision 是其 preparation snapshot 的 revision。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SupervisorCandidate {
    pub identity_fence: SecretIdentityFence,
    pub secret_revision: u64,
    pub state: SupervisorCandidateState,
    /// active execution 保持其已采纳 snapshot，直到下一次成功激活；永不被
    /// invalidation 停止。
    pub is_active: bool,
}

/// supervisor journal 状态（含候选集合与 invalidation fence）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SupervisorSecretJournalState {
    pub schema_version: u64,
    pub journal_revision: u64,
    pub entries: Vec<SupervisorSecretJournalEntry>,
    pub candidates: Vec<SupervisorCandidate>,
    /// invalidation reducer：只保留出现过的最大 revision；乱序旧消息不可降低。
    pub invalidation_fence_revision: u64,
}

impl SupervisorSecretJournalState {
    pub fn new() -> Self {
        Self { schema_version: 1, journal_revision: 0, entries: Vec::new(), candidates: Vec::new(), invalidation_fence_revision: 0 }
    }

    fn append_entry(&mut self, kind: SupervisorSecretEntryKind, command: &SecretInvalidationCommand, fenced: Vec<SecretIdentityFence>) -> SupervisorSecretJournalEntry {
        self.journal_revision += 1;
        let entry = SupervisorSecretJournalEntry {
            schema_version: 1,
            kind,
            command_id: command.command_id.clone(),
            journal_revision: self.journal_revision,
            application_id: command.application_id.clone(),
            secret_revision: command.secret_revision,
            secret_snapshot_ref: command.secret_snapshot_ref.clone(),
            fenced_candidates: fenced,
        };
        self.entries.push(entry.clone());
        entry
    }

    /// journal 的 invalidation reducer：全部条目中的最大 revision。
    pub fn reduce_max_invalidation_revision(&self) -> u64 {
        self.entries.iter().map(|entry| entry.secret_revision).max().unwrap_or(0)
    }

    fn has_command(&self, command_id: &str) -> bool {
        self.entries.iter().any(|entry| entry.command_id == command_id)
    }

    /// 停掉 revision 低于 committed_revision 的非 active 候选（幂等且单向：
    /// 已 Stopped 的候选保持 Stopped——乱序旧消息不能复活候选）。
    /// 返回本次真正停掉的 fence。
    pub fn stop_stale_candidates(&mut self, committed_revision: u64) -> Vec<SecretIdentityFence> {
        let mut stopped = Vec::new();
        for candidate in &mut self.candidates {
            if !candidate.is_active && candidate.secret_revision < committed_revision && candidate.state != SupervisorCandidateState::Stopped {
                candidate.state = SupervisorCandidateState::Stopped;
                stopped.push(candidate.identity_fence.clone());
            }
        }
        stopped
    }
}

impl Default for SupervisorSecretJournalState {
    fn default() -> Self {
        Self::new()
    }
}

/// 纯 reducer（不依赖状态对象）：条目集合的最大 revision。
pub fn reduce_max_invalidation_revision(entries: &[SupervisorSecretJournalEntry]) -> u64 {
    entries.iter().map(|entry| entry.secret_revision).max().unwrap_or(0)
}

/// 应用一条 invalidation 命令到 supervisor journal：
/// - 同 command_id 幂等：直接返回既有 completed 条目，无第二份副作用；
/// - 乱序旧命令（revision < 当前 fence）：仍记录条目（消息可以任意顺序到达），
///   但 fence 只升不降、候选停止单向（不复活）；
/// - 正常路径：journal CAS 追加 received → 停候选 → 追加 completed，
///   fence = max(fence, revision)。
///
/// 返回 completed 条目的 journal revision。
pub fn apply_invalidation_to_journal(
    supervisor: &mut SupervisorSecretJournalState,
    command: &SecretInvalidationCommand,
    now_epoch_millis: u64,
) -> Result<u64, SecretRotationError> {
    let _ = now_epoch_millis; // 时间戳持久化留给接线层；本函数只做 CAS 与 fence。
    command.validate()?;
    if supervisor.has_command(&command.command_id) {
        let completed = supervisor
            .entries
            .iter()
            .rev()
            .find(|entry| entry.command_id == command.command_id && entry.kind == SupervisorSecretEntryKind::Completed)
            .expect("has_command implies a completed entry exists");
        return Ok(completed.journal_revision);
    }
    let fenced = supervisor.stop_stale_candidates(command.secret_revision);
    supervisor.append_entry(SupervisorSecretEntryKind::Received, command, fenced.clone());
    let completed = supervisor.append_entry(SupervisorSecretEntryKind::Completed, command, fenced);
    if command.secret_revision > supervisor.invalidation_fence_revision {
        supervisor.invalidation_fence_revision = command.secret_revision;
    }
    Ok(completed.journal_revision)
}

// ---------------------------------------------------------------------------
// Kernel 侧 rotation 状态（store + outbox + 进程内锁序阶段 + active snapshot）
// ---------------------------------------------------------------------------

/// active execution 采纳的 snapshot：保留到下一次成功激活才被替换。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActiveSecretSnapshot {
    pub secret_revision: u64,
    pub secret_snapshot_ref: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KernelSecretRotationState {
    pub store: SecretStoreRow,
    pub outbox: Vec<SecretInvalidationOutboxRecord>,
    /// 进程内锁序阶段；崩溃后由恢复复位到 Idle（fence 随进程消失）。
    pub lock_step: RotationLockStep,
    /// active execution 当前采纳的 snapshot（从未激活过则 None）。
    pub active_snapshot: Option<ActiveSecretSnapshot>,
}

impl KernelSecretRotationState {
    pub fn new(application_id: &str) -> Result<Self, SecretRotationError> {
        Ok(Self {
            store: SecretStoreRow::new(application_id)?,
            outbox: Vec::new(),
            lock_step: RotationLockStep::Idle,
            active_snapshot: None,
        })
    }

    /// 当前最大已提交 revision（= store revision；commit 即线性化点）。
    pub fn greatest_committed_revision(&self) -> u64 {
        self.store.secret_revision
    }

    /// 激活成功后采纳新 snapshot（唯一替换点；rotation 本身不替换）。
    pub fn adopt_active_snapshot(&mut self, secret_revision: u64, secret_snapshot_ref: &str) -> Result<(), SecretRotationError> {
        require_u53(secret_revision, "secretRevision")?;
        validate_secret_snapshot_ref(secret_snapshot_ref)?;
        if secret_revision > self.store.secret_revision {
            return Err(err(WASM_SECRET_REVISION_INVALID, "an adopted snapshot revision cannot exceed the committed secret-store revision"));
        }
        self.active_snapshot = Some(ActiveSecretSnapshot { secret_revision, secret_snapshot_ref: secret_snapshot_ref.to_string() });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 崩溃矩阵驱动
// ---------------------------------------------------------------------------

/// 崩溃点（spec 崩溃矩阵行 1..4；行 5"candidate health 后、activation CAS 前"
/// 由 matches_secret_revision_fence 与 wasm_activation 覆盖；行 6 双 rotation
/// 乱序由 apply_invalidation_to_journal 的 reducer 与单向 stop 覆盖）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationCrashPoint {
    /// 行 1：secret-store commit 前——无 rotation 发生。
    BeforeSecretStoreCommit,
    /// 行 2：commit 后、invalidation 命令持久化前。
    AfterCommitBeforeInvalidation,
    /// 行 3：命令已持久化、送达丢失——journal 未落任何条目。
    AfterCommandBeforeJournal,
    /// 行 3 后半：journal 已 received+completed、ack 丢失（Kernel 未投影）。
    AfterJournalAckLost,
    /// 行 4：停止与 ack 投影完成，尚无 fresh prepare。
    AfterStopBeforeFreshPrepare,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RotationOutcome {
    pub secret_revision: u64,
    pub command_id: String,
    pub journal_revision: Option<u64>,
    pub acknowledged: bool,
    pub stopped_candidates: Vec<SecretIdentityFence>,
}

/// 崩溃矩阵行 2 恢复：从已提交 revision 确定性重建同一条命令。
/// fence_targets = journal 候选集合中低于已提交 revision 的非 active 候选
/// （与提交时一致：supervisor 候选集合在 commit 与恢复之间只可能因 stop 单向
/// 变化，不改变目标集合语义）；snapshot ref 取与 revision 同一提交持久化的
/// pending ref——缺失即 fail-closed（无法确定性重建）。
fn rebuild_invalidation_command(supervisor: &SupervisorSecretJournalState, record: &SecretInvalidationOutboxRecord) -> Result<SecretInvalidationCommand, SecretRotationError> {
    let pending_ref = record.pending_snapshot_ref.as_deref().ok_or_else(|| {
        err(WASM_SECRET_OUTBOX_INVALID, "the outbox row must persist the new revision's opaque snapshot reference before the command can be rebuilt deterministically")
    })?;
    let command = SecretInvalidationCommand {
        schema_version: 1,
        command_id: record.command_id.clone(),
        application_id: record.application_id.clone(),
        secret_revision: record.secret_revision,
        secret_snapshot_ref: pending_ref.to_string(),
        fence_targets: supervisor
            .candidates
            .iter()
            .filter(|candidate| !candidate.is_active && candidate.secret_revision < record.secret_revision)
            .map(|candidate| candidate.identity_fence.clone())
            .collect(),
    };
    command.validate()?;
    Ok(command)
}

fn outbox_record<'a>(kernel: &'a KernelSecretRotationState, command_id: &str) -> Result<&'a SecretInvalidationOutboxRecord, SecretRotationError> {
    kernel.outbox.iter().rev().find(|record| record.command_id == command_id).ok_or_else(|| err(WASM_SECRET_OUTBOX_INVALID, format!("unknown outbox command {command_id:?}")))
}

fn outbox_record_mut<'a>(kernel: &'a mut KernelSecretRotationState, command_id: &str) -> Result<&'a mut SecretInvalidationOutboxRecord, SecretRotationError> {
    kernel.outbox.iter_mut().rev().find(|record| record.command_id == command_id).ok_or_else(|| err(WASM_SECRET_OUTBOX_INVALID, format!("unknown outbox command {command_id:?}")))
}

/// 投递 outbox 中该 command 的命令到 supervisor journal（幂等重放；
/// 崩溃矩阵行 3：activation CAS 已拒绝旧 revision，重放幂等停候选）。
fn deliver_invalidation(kernel: &mut KernelSecretRotationState, supervisor: &mut SupervisorSecretJournalState, command_id: &str) -> Result<(), SecretRotationError> {
    let command = outbox_record(kernel, command_id)?
        .invalidation_command
        .clone()
        .ok_or_else(|| err(WASM_SECRET_OUTBOX_BACKLOG, "the invalidation command has not been persisted yet"))?;
    apply_invalidation_to_journal(supervisor, &command, 0)?;
    let record = outbox_record_mut(kernel, command_id)?;
    record.delivery_state = SecretOutboxDeliveryState::Sent;
    record.attempts += 1;
    Ok(())
}

/// 从 supervisor journal 的 completed 条目投影 ack（revision/ref 必须一致）。
fn project_invalidation_acknowledgement(kernel: &mut KernelSecretRotationState, supervisor: &SupervisorSecretJournalState, command_id: &str) -> Result<(), SecretRotationError> {
    let completed = supervisor
        .entries
        .iter()
        .rev()
        .find(|entry| entry.command_id == command_id && entry.kind == SupervisorSecretEntryKind::Completed)
        .ok_or_else(|| err(WASM_SECRET_JOURNAL_INVALID, "no completed journal entry to project"))?;
    let record = outbox_record_mut(kernel, command_id)?;
    let command_ref = record
        .invalidation_command
        .as_ref()
        .map(|command| command.secret_snapshot_ref.as_str())
        .or(record.pending_snapshot_ref.as_deref())
        .unwrap_or("");
    if completed.secret_revision != record.secret_revision || completed.secret_snapshot_ref != command_ref {
        return Err(err(WASM_SECRET_JOURNAL_INVALID, "the journal entry does not match the outbox row"));
    }
    record.delivery_state = SecretOutboxDeliveryState::Acknowledged;
    Ok(())
}

/// 完整 rotation 流程驱动（锁序 1..5 + 投递 + ack 投影）。
/// crash = None 走完整路径；Some(point) 在该点模拟崩溃（返回
/// WASM_SECRET_SIMULATED_CRASH；durable 状态停在崩溃点，进程内锁复位 Idle）。
pub fn run_secret_rotation(
    kernel: &mut KernelSecretRotationState,
    supervisor: &mut SupervisorSecretJournalState,
    request: &SecretAllowlistMutation,
    command_id: &str,
    pending_snapshot_ref: &str,
    now_epoch_millis: u64,
    crash: Option<RotationCrashPoint>,
) -> Result<RotationOutcome, SecretRotationError> {
    request.validate()?;
    if kernel.store.application_id != request.application_id {
        return Err(err(WASM_SECRET_APPLICATION_INVALID, "the rotation request must target this store's application"));
    }
    validate_secret_snapshot_ref(pending_snapshot_ref)?;
    require_u53(now_epoch_millis, "nowEpochMillis")?;
    // 锁序前置：fence 空闲 + 前一轮 outbox 已持久化命令（"第二个 rotation
    // waits for the first's outbox persistence"）。
    if kernel.lock_step != RotationLockStep::Idle {
        return Err(err(WASM_SECRET_ROTATION_LOCK_ORDER_INVALID, "a rotation cannot start while the application mutation fence is held"));
    }
    if kernel.outbox.iter().any(|record| record.invalidation_command.is_none()) {
        return Err(err(WASM_SECRET_OUTBOX_BACKLOG, "a second rotation must wait for the previous outbox invalidation command to be persisted"));
    }
    // 1. 取得 mutation fence。
    kernel.lock_step = advance_lock(kernel.lock_step, RotationLockStep::AppFenceAcquired)?;
    if crash == Some(RotationCrashPoint::BeforeSecretStoreCommit) {
        kernel.lock_step = RotationLockStep::Idle;
        return Err(simulated_crash("before secret-store commit"));
    }
    // 2. expectedSecretRevision CAS（不等即拒绝：无值写入、无 invalidation 命令）。
    if request.expected_secret_revision != kernel.store.secret_revision {
        kernel.lock_step = RotationLockStep::Idle;
        return Err(err(
            SECRET_REVISION_CONFLICT,
            format!("expectedSecretRevision {} does not match the current revision {}", request.expected_secret_revision, kernel.store.secret_revision),
        ));
    }
    let next_revision = next_secret_revision(kernel.store.secret_revision)?;
    // 3. COMMIT = 线性化点：revision 与 outbox 行（含 pending ref）同一提交。
    kernel.store.secret_revision = next_revision;
    kernel.store.keys = request.keys.clone();
    kernel.store.values = request.values.clone();
    kernel.outbox.push(SecretInvalidationOutboxRecord {
        schema_version: 1,
        command_id: command_id.to_string(),
        application_id: request.application_id.clone(),
        secret_revision: next_revision,
        created_at_epoch_millis: now_epoch_millis,
        delivery_state: SecretOutboxDeliveryState::Pending,
        attempts: 0,
        invalidation_command: None,
        pending_snapshot_ref: Some(pending_snapshot_ref.to_string()),
    });
    kernel.lock_step = advance_lock(kernel.lock_step, RotationLockStep::SecretRowCasCommitted)?;
    // 4a. 释放行锁。
    kernel.lock_step = advance_lock(kernel.lock_step, RotationLockStep::SecretRowLockReleased)?;
    // 4b. 持久化 supervisor invalidation 命令（此刻不持行锁；fence 仍持有）。
    let command = SecretInvalidationCommand {
        schema_version: 1,
        command_id: command_id.to_string(),
        application_id: request.application_id.clone(),
        secret_revision: next_revision,
        secret_snapshot_ref: pending_snapshot_ref.to_string(),
        fence_targets: supervisor
            .candidates
            .iter()
            .filter(|candidate| !candidate.is_active && candidate.secret_revision < next_revision)
            .map(|candidate| candidate.identity_fence.clone())
            .collect(),
    };
    command.validate()?;
    if crash == Some(RotationCrashPoint::AfterCommitBeforeInvalidation) {
        // 命令尚未持久化：停在 outbox Pending + command None 的恢复点。
        kernel.lock_step = RotationLockStep::Idle;
        return Err(simulated_crash("after commit, before invalidation command persistence"));
    }
    outbox_record_mut(kernel, command_id)?.invalidation_command = Some(command);
    kernel.lock_step = advance_lock(kernel.lock_step, RotationLockStep::InvalidationCommandPersisted)?;
    // 5. 释放 mutation fence（此后才允许触碰 supervisor）。
    kernel.lock_step = advance_lock(kernel.lock_step, RotationLockStep::Completed)?;
    kernel.lock_step = RotationLockStep::Idle;
    if crash == Some(RotationCrashPoint::AfterCommandBeforeJournal) {
        return Err(simulated_crash("after command persistence, before supervisor journal"));
    }
    // 投递（无锁窗口；ack 丢失由恢复重放）。
    deliver_invalidation(kernel, supervisor, command_id)?;
    if crash == Some(RotationCrashPoint::AfterJournalAckLost) {
        return Err(simulated_crash("after supervisor journal completion, before acknowledgement projection"));
    }
    // ack 投影。
    project_invalidation_acknowledgement(kernel, supervisor, command_id)?;
    let stopped = outbox_record(kernel, command_id)?
        .invalidation_command
        .as_ref()
        .expect("the command was just persisted")
        .fence_targets
        .clone();
    if crash == Some(RotationCrashPoint::AfterStopBeforeFreshPrepare) {
        return Err(simulated_crash("after stop and acknowledgement, before fresh preparation"));
    }
    let journal_revision = supervisor.entries.iter().rev().find(|entry| entry.command_id == command_id).map(|entry| entry.journal_revision);
    Ok(RotationOutcome { secret_revision: next_revision, command_id: command_id.to_string(), journal_revision, acknowledged: true, stopped_candidates: stopped })
}

/// 恢复驱动：对任意崩溃残留状态收敛到唯一结果。
/// - 复位进程内锁（fence/row lock 随崩溃消失）；
/// - 行 2：outbox 有未物化命令的已提交行 → 从 pending ref + 候选集确定性重建；
/// - 行 3：未送达/未完成的命令 → 幂等重放投递（重复投递无第二份副作用）；
/// - 行 3/4：journal completed 而 outbox 未 Acknowledged → 投影 ack；
/// - 报告最大 revision、已停候选与重备 fence（fresh prepare 只允许最大 revision）；
/// - 恢复后 reducer 与 fence 必须一致（fail-closed）。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RotationRecoveryReport {
    pub rebuilt_commands: Vec<String>,
    pub delivered_commands: Vec<String>,
    pub acknowledged_commands: Vec<String>,
    pub stopped_candidates: Vec<SecretIdentityFence>,
    pub greatest_committed_revision: u64,
    /// 存在被停候选或 active snapshot 落后于最大 revision 时，恢复要求的重备
    /// revision（fresh prepare 只允许该值）。
    pub reprepare_revision: Option<u64>,
}

pub fn recover_rotation(kernel: &mut KernelSecretRotationState, supervisor: &mut SupervisorSecretJournalState) -> Result<RotationRecoveryReport, SecretRotationError> {
    let mut report = RotationRecoveryReport::default();
    // 进程内锁复位（durable 不动）。
    kernel.lock_step = RotationLockStep::Idle;
    // 行 2：重建未物化的命令（按提交顺序）。
    for index in 0..kernel.outbox.len() {
        if kernel.outbox[index].invalidation_command.is_some() {
            continue;
        }
        let command = rebuild_invalidation_command(supervisor, &kernel.outbox[index])?;
        kernel.outbox[index].invalidation_command = Some(command);
        report.rebuilt_commands.push(kernel.outbox[index].command_id.clone());
    }
    // 行 3：投递所有未 Acknowledged 的命令（幂等）。
    let pending_ids: Vec<String> = kernel
        .outbox
        .iter()
        .filter(|record| record.delivery_state != SecretOutboxDeliveryState::Acknowledged)
        .map(|record| record.command_id.clone())
        .collect();
    for command_id in pending_ids {
        deliver_invalidation(kernel, supervisor, &command_id)?;
        report.delivered_commands.push(command_id);
    }
    // 行 3/4：投影 ack。
    let sent_ids: Vec<String> = kernel
        .outbox
        .iter()
        .filter(|record| record.delivery_state == SecretOutboxDeliveryState::Sent)
        .map(|record| record.command_id.clone())
        .collect();
    for command_id in sent_ids {
        project_invalidation_acknowledgement(kernel, supervisor, &command_id)?;
        report.acknowledged_commands.push(command_id);
    }
    report.greatest_committed_revision = kernel.greatest_committed_revision();
    report.stopped_candidates = supervisor
        .candidates
        .iter()
        .filter(|candidate| candidate.state == SupervisorCandidateState::Stopped && !candidate.is_active)
        .map(|candidate| candidate.identity_fence.clone())
        .collect();
    let active_revision = kernel.active_snapshot.as_ref().map(|snapshot| snapshot.secret_revision).unwrap_or(0);
    if !report.stopped_candidates.is_empty() || active_revision < report.greatest_committed_revision {
        report.reprepare_revision = Some(report.greatest_committed_revision);
    }
    // 恢复后 reducer 与 fence 必须一致（fail-closed 校验）。
    if supervisor.invalidation_fence_revision != supervisor.reduce_max_invalidation_revision() {
        return Err(err(WASM_SECRET_JOURNAL_INVALID, "the journal fence revision disagrees with the entry reducer"));
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// tests：revision 纯函数、锁序、崩溃矩阵全行、双 rotation 乱序、active snapshot
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "shop";
    const VERSION: &str = "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1";
    const REF_PREFIX: &str = "11";

    fn snapshot_ref(suffix: u64) -> String {
        format!("{REF_PREFIX}{suffix:0>62}")
    }

    fn fence(sandbox: &str, generation: u64) -> SecretIdentityFence {
        SecretIdentityFence { sandbox_id: sandbox.into(), version_id: VERSION.into(), preparation_generation: generation, execution_generation: generation }
    }

    fn mutation(expected: u64, keys: &[&str], values: &[&str]) -> SecretAllowlistMutation {
        let values = keys.iter().zip(values.iter()).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        SecretAllowlistMutation { schema_version: 1, application_id: APP.into(), expected_secret_revision: expected, keys: keys.iter().map(|k| k.to_string()).collect(), values }
    }

    fn harness() -> (KernelSecretRotationState, SupervisorSecretJournalState) {
        let mut kernel = KernelSecretRotationState::new(APP).expect("kernel state");
        let mut supervisor = SupervisorSecretJournalState::new();
        // 一个 active 候选（revision 0 起）与一个备选候选。
        supervisor.candidates.push(SupervisorCandidate { identity_fence: fence("sbx-active", 1), secret_revision: 0, state: SupervisorCandidateState::Ready, is_active: true });
        supervisor.candidates.push(SupervisorCandidate { identity_fence: fence("sbx-spare", 1), secret_revision: 0, state: SupervisorCandidateState::Ready, is_active: false });
        kernel.active_snapshot = Some(ActiveSecretSnapshot { secret_revision: 0, secret_snapshot_ref: snapshot_ref(0) });
        (kernel, supervisor)
    }

    fn rotate_once(kernel: &mut KernelSecretRotationState, supervisor: &mut SupervisorSecretJournalState, expected: u64, next: u64, crash: Option<RotationCrashPoint>) -> Result<RotationOutcome, SecretRotationError> {
        run_secret_rotation(kernel, supervisor, &mutation(expected, &["api-token"], &[next.to_string().as_str()]), &format!("cmd-{next}"), &snapshot_ref(next), 1_000, crash)
    }

    #[test]
    fn next_secret_revision_is_monotonic_u53() {
        assert_eq!(next_secret_revision(0).unwrap(), 1);
        assert_eq!(next_secret_revision(7).unwrap(), 8);
        assert_eq!(next_secret_revision(WASM_U53_MAX).unwrap_err().code, SECRET_REVISION_EXHAUSTED);
        assert_eq!(next_secret_revision(WASM_U53_MAX + 1).unwrap_err().code, WASM_SECRET_REVISION_INVALID);
        assert!(matches_secret_revision_fence(8, 8));
        assert!(!matches_secret_revision_fence(8, 7));
        assert!(!matches_secret_revision_fence(7, 8));
    }

    #[test]
    fn reprepare_fence_requires_greatest_revision() {
        assert!(check_reprepare_revision_fence(9, 9).is_ok());
        assert_eq!(check_reprepare_revision_fence(9, 8).unwrap_err().code, WASM_SECRET_REPREPARE_STALE);
        assert_eq!(check_reprepare_revision_fence(8, 9).unwrap_err().code, WASM_SECRET_REPREPARE_STALE);
    }

    #[test]
    fn allowlist_validation_rejects_unsorted_duplicate_and_bad_keys() {
        assert!(mutation(0, &["a-key", "b-key"], &["v1", "v2"]).validate().is_ok());
        assert!(mutation(0, &[], &[]).validate().is_ok());
        assert_eq!(mutation(0, &["b-key", "a-key"], &["v1", "v2"]).validate().unwrap_err().code, WASM_SECRET_ALLOWLIST_INVALID);
        assert_eq!(mutation(0, &["a-key", "a-key"], &["v1", "v2"]).validate().unwrap_err().code, WASM_SECRET_ALLOWLIST_INVALID);
        assert_eq!(mutation(0, &["Bad"], &["v"]).validate().unwrap_err().code, WASM_SECRET_KEY_INVALID);
        assert_eq!(mutation(0, &["a/b"], &["v"]).validate().unwrap_err().code, WASM_SECRET_KEY_INVALID);
        // 值键集合必须逐字节等于 keys。
        let mut bad = mutation(0, &["a-key"], &["v"]);
        bad.values.insert("extra".into(), "v".into());
        assert_eq!(bad.validate().unwrap_err().code, WASM_SECRET_ALLOWLIST_INVALID);
        let mut big = mutation(0, &["a-key"], &["v"]);
        big.values.insert("a-key".into(), "x".repeat(65_537));
        assert_eq!(big.validate().unwrap_err().code, WASM_SECRET_ALLOWLIST_INVALID);
        let mut too_many_keys = mutation(0, &[], &[]);
        too_many_keys.keys = (0..=256).map(|i| format!("k{i:03}")).collect();
        assert_eq!(too_many_keys.validate().unwrap_err().code, WASM_SECRET_ALLOWLIST_INVALID);
    }

    #[test]
    fn lock_order_accepts_only_the_fixed_sequence() {
        use RotationLockStep::*;
        assert!(check_rotation_lock_order(Idle, AppFenceAcquired).is_ok());
        assert!(check_rotation_lock_order(AppFenceAcquired, SecretRowCasCommitted).is_ok());
        assert!(check_rotation_lock_order(SecretRowCasCommitted, SecretRowLockReleased).is_ok());
        assert!(check_rotation_lock_order(SecretRowLockReleased, InvalidationCommandPersisted).is_ok());
        assert!(check_rotation_lock_order(InvalidationCommandPersisted, Completed).is_ok());
        // 未持 fence 即提交。
        assert_eq!(check_rotation_lock_order(Idle, SecretRowCasCommitted).unwrap_err().code, WASM_SECRET_ROTATION_LOCK_ORDER_INVALID);
        // 持行锁等 supervisor（跳过行锁释放）——spec 明令禁止的等待。
        assert_eq!(check_rotation_lock_order(AppFenceAcquired, InvalidationCommandPersisted).unwrap_err().code, WASM_SECRET_ROTATION_LOCK_ORDER_INVALID);
        // 命令未持久化即释放 fence。
        assert_eq!(check_rotation_lock_order(SecretRowLockReleased, Completed).unwrap_err().code, WASM_SECRET_ROTATION_LOCK_ORDER_INVALID);
        // 回退与重复一律拒绝。
        assert!(check_rotation_lock_order(SecretRowLockReleased, SecretRowCasCommitted).is_err());
        assert!(check_rotation_lock_order(AppFenceAcquired, AppFenceAcquired).is_err());
        assert!(check_rotation_lock_order(Completed, AppFenceAcquired).is_err());
    }

    #[test]
    fn stale_expected_revision_conflicts_without_side_effects() {
        let (mut kernel, mut supervisor) = harness();
        // 先提交 revision 1。
        rotate_once(&mut kernel, &mut supervisor, 0, 1, None).expect("first rotation");
        let store_before = kernel.store.clone();
        let outbox_before = kernel.outbox.clone();
        let journal_before = supervisor.clone();
        // 以过期 expected=0 再提交：SECRET_REVISION_CONFLICT，无值写入、无命令。
        let failure = rotate_once(&mut kernel, &mut supervisor, 0, 2, None).unwrap_err();
        assert_eq!(failure.code, SECRET_REVISION_CONFLICT);
        assert_eq!(kernel.store, store_before);
        assert_eq!(kernel.outbox, outbox_before);
        assert_eq!(supervisor, journal_before);
        assert_eq!(kernel.lock_step, RotationLockStep::Idle);
    }

    #[test]
    fn happy_path_commits_delivers_and_stops_only_non_active() {
        let (mut kernel, mut supervisor) = harness();
        let outcome = rotate_once(&mut kernel, &mut supervisor, 0, 1, None).expect("rotation completes");
        assert_eq!(outcome.secret_revision, 1);
        assert!(outcome.acknowledged);
        assert_eq!(kernel.store.secret_revision, 1);
        assert_eq!(kernel.lock_step, RotationLockStep::Idle);
        assert_eq!(kernel.outbox.last().unwrap().delivery_state, SecretOutboxDeliveryState::Acknowledged);
        // 非 active 候选被停；active 候选保持 Ready（保留其 snapshot）。
        assert!(supervisor.candidates.iter().any(|c| c.identity_fence.sandbox_id == "sbx-spare" && c.state == SupervisorCandidateState::Stopped));
        assert!(supervisor.candidates.iter().any(|c| c.identity_fence.sandbox_id == "sbx-active" && c.state == SupervisorCandidateState::Ready && c.is_active));
        // active snapshot 未被 rotation 替换（保留到下一次激活）。
        assert_eq!(kernel.active_snapshot.as_ref().unwrap().secret_revision, 0);
        // journal/reducer 收敛。
        assert_eq!(supervisor.invalidation_fence_revision, 1);
        assert_eq!(supervisor.reduce_max_invalidation_revision(), 1);
    }

    #[test]
    fn crash_before_commit_changes_nothing() {
        let (mut kernel, mut supervisor) = harness();
        let store_before = kernel.store.clone();
        let failure = rotate_once(&mut kernel, &mut supervisor, 0, 1, Some(RotationCrashPoint::BeforeSecretStoreCommit)).unwrap_err();
        assert_eq!(failure.code, WASM_SECRET_SIMULATED_CRASH);
        assert_eq!(kernel.store, store_before);
        assert!(kernel.outbox.is_empty());
        // 行 1：无 rotation 发生；既有候选仍受正常 activation CAS 约束
        // （候选 revision == 当前 store revision → fence 通过）。
        let report = recover_rotation(&mut kernel, &mut supervisor).expect("recover");
        assert_eq!(report.greatest_committed_revision, 0);
        assert!(report.rebuilt_commands.is_empty());
        assert!(matches_secret_revision_fence(kernel.store.secret_revision, 0));
    }

    #[test]
    fn crash_after_commit_before_invalidation_recovers_same_fence() {
        let (mut kernel, mut supervisor) = harness();
        let failure = rotate_once(&mut kernel, &mut supervisor, 0, 1, Some(RotationCrashPoint::AfterCommitBeforeInvalidation)).unwrap_err();
        assert_eq!(failure.code, WASM_SECRET_SIMULATED_CRASH);
        // durable：revision 已提交、outbox 行存在但命令未物化。
        assert_eq!(kernel.store.secret_revision, 1);
        assert_eq!(kernel.outbox.last().unwrap().delivery_state, SecretOutboxDeliveryState::Pending);
        assert!(kernel.outbox.last().unwrap().invalidation_command.is_none());
        // 第二个 rotation 必须等待第一个的 outbox 持久化。
        assert_eq!(rotate_once(&mut kernel, &mut supervisor, 1, 2, None).unwrap_err().code, WASM_SECRET_OUTBOX_BACKLOG);
        // 行 2 恢复：扫描已提交 outbox，重建并追加同一 revision fence。
        let report = recover_rotation(&mut kernel, &mut supervisor).expect("recover");
        assert_eq!(report.rebuilt_commands, vec!["cmd-1".to_string()]);
        assert_eq!(report.greatest_committed_revision, 1);
        assert_eq!(kernel.outbox.last().unwrap().delivery_state, SecretOutboxDeliveryState::Acknowledged);
        assert_eq!(supervisor.invalidation_fence_revision, 1);
        // 恢复后第二个 rotation 可以继续（更大 revision）。
        rotate_once(&mut kernel, &mut supervisor, 1, 2, None).expect("second rotation after recovery");
        assert_eq!(kernel.store.secret_revision, 2);
    }

    #[test]
    fn crash_after_command_before_journal_replays_idempotently() {
        let (mut kernel, mut supervisor) = harness();
        let failure = rotate_once(&mut kernel, &mut supervisor, 0, 1, Some(RotationCrashPoint::AfterCommandBeforeJournal)).unwrap_err();
        assert_eq!(failure.code, WASM_SECRET_SIMULATED_CRASH);
        assert!(kernel.outbox.last().unwrap().invalidation_command.is_some());
        assert!(supervisor.entries.is_empty());
        // 行 3：activation CAS 已拒绝旧 revision（store=1 vs 候选=0）。
        assert!(!matches_secret_revision_fence(kernel.store.secret_revision, 0));
        let report = recover_rotation(&mut kernel, &mut supervisor).expect("recover");
        assert_eq!(report.delivered_commands, vec!["cmd-1".to_string()]);
        // 重复投递无第二份副作用（journal 只有一对 received/completed）。
        apply_invalidation_to_journal(&mut supervisor, kernel.outbox.last().unwrap().invalidation_command.as_ref().unwrap(), 2_000).expect("idempotent replay");
        assert_eq!(supervisor.entries.iter().filter(|e| e.command_id == "cmd-1").count(), 2);
        assert_eq!(supervisor.candidates.iter().filter(|c| c.state == SupervisorCandidateState::Stopped).count(), 1);
    }

    #[test]
    fn crash_after_journal_ack_lost_projects_from_journal() {
        let (mut kernel, mut supervisor) = harness();
        let failure = rotate_once(&mut kernel, &mut supervisor, 0, 1, Some(RotationCrashPoint::AfterJournalAckLost)).unwrap_err();
        assert_eq!(failure.code, WASM_SECRET_SIMULATED_CRASH);
        // journal 已 received+completed；Kernel outbox 仍 Sent（ack 丢失）。
        assert_eq!(kernel.outbox.last().unwrap().delivery_state, SecretOutboxDeliveryState::Sent);
        assert_eq!(supervisor.entries.iter().filter(|e| e.command_id == "cmd-1").count(), 2);
        let report = recover_rotation(&mut kernel, &mut supervisor).expect("recover");
        assert_eq!(report.acknowledged_commands, vec!["cmd-1".to_string()]);
        assert_eq!(kernel.outbox.last().unwrap().delivery_state, SecretOutboxDeliveryState::Acknowledged);
        // 恢复不追加新 journal 条目。
        assert_eq!(supervisor.entries.iter().filter(|e| e.command_id == "cmd-1").count(), 2);
    }

    #[test]
    fn crash_after_stop_before_fresh_prepare_gates_reprepare() {
        let (mut kernel, mut supervisor) = harness();
        let failure = rotate_once(&mut kernel, &mut supervisor, 0, 1, Some(RotationCrashPoint::AfterStopBeforeFreshPrepare)).unwrap_err();
        assert_eq!(failure.code, WASM_SECRET_SIMULATED_CRASH);
        assert_eq!(kernel.outbox.last().unwrap().delivery_state, SecretOutboxDeliveryState::Acknowledged);
        // 行 4：恢复只允许在当前最大 revision 重备。
        let report = recover_rotation(&mut kernel, &mut supervisor).expect("recover");
        assert_eq!(report.reprepare_revision, Some(1));
        assert!(check_reprepare_revision_fence(report.greatest_committed_revision, 1).is_ok());
        assert_eq!(check_reprepare_revision_fence(report.greatest_committed_revision, 0).unwrap_err().code, WASM_SECRET_REPREPARE_STALE);
    }

    #[test]
    fn rotation_races_ready_candidate_rejects_old_revision() {
        // spec 场景：候选 revision 7 ready，Kernel 在 activation CAS 前提交 8。
        let (mut kernel, mut supervisor) = harness();
        // 快进到 revision 7，并有一个 revision-7 ready 候选与 active snapshot 7。
        for revision in 1..=7u64 {
            rotate_once(&mut kernel, &mut supervisor, revision - 1, revision, None).expect("rotation");
        }
        supervisor.candidates.push(SupervisorCandidate { identity_fence: fence("sbx-candidate", 8), secret_revision: 7, state: SupervisorCandidateState::Ready, is_active: false });
        kernel.adopt_active_snapshot(7, &snapshot_ref(7)).expect("adopt");
        rotate_once(&mut kernel, &mut supervisor, 7, 8, None).expect("rotation to 8");
        // CAS 拒绝 revision-7 候选；journal 幂等停掉它；只有 snapshot revision-8
        // 的 preparation 才可能 active。
        assert!(!matches_secret_revision_fence(kernel.store.secret_revision, 7));
        assert!(matches_secret_revision_fence(kernel.store.secret_revision, 8));
        assert!(supervisor.candidates.iter().any(|c| c.identity_fence.sandbox_id == "sbx-candidate" && c.state == SupervisorCandidateState::Stopped));
        // active snapshot 在成功激活前保持 revision 7。
        assert_eq!(kernel.active_snapshot.as_ref().unwrap().secret_revision, 7);
        kernel.adopt_active_snapshot(8, &snapshot_ref(8)).expect("adopt after activation");
        assert_eq!(kernel.active_snapshot.as_ref().unwrap().secret_revision, 8);
    }

    #[test]
    fn two_rotations_out_of_order_retain_maximum() {
        // spec 场景：8 与 9 在 supervisor 重启期间提交，journal 消息任意顺序到达。
        let (mut kernel, mut supervisor) = harness();
        for revision in 1..=6u64 {
            rotate_once(&mut kernel, &mut supervisor, revision - 1, revision, None).expect("rotation");
        }
        // 直接提交 8 与 9（第二条消息先到）。
        let command_8 = SecretInvalidationCommand {
            schema_version: 1,
            command_id: "cmd-8".into(),
            application_id: APP.into(),
            secret_revision: 8,
            secret_snapshot_ref: snapshot_ref(8),
            fence_targets: vec![],
        };
        let command_9 = SecretInvalidationCommand {
            schema_version: 1,
            command_id: "cmd-9".into(),
            application_id: APP.into(),
            secret_revision: 9,
            secret_snapshot_ref: snapshot_ref(9),
            fence_targets: vec![],
        };
        apply_invalidation_to_journal(&mut supervisor, &command_9, 1_000).expect("9 arrives first");
        apply_invalidation_to_journal(&mut supervisor, &command_8, 2_000).expect("8 arrives late");
        // reducer 保留 9；旧 invalidation 不降低 fence。
        assert_eq!(supervisor.invalidation_fence_revision, 9);
        assert_eq!(supervisor.reduce_max_invalidation_revision(), 9);
        // 乱序旧消息不能复活候选：备选候选保持 Stopped。
        assert!(supervisor.candidates.iter().any(|c| c.identity_fence.sandbox_id == "sbx-spare" && c.state == SupervisorCandidateState::Stopped));
        // 恢复收敛到唯一候选集：只接受 revision 9。
        kernel.store.secret_revision = 9;
        let report = recover_rotation(&mut kernel, &mut supervisor).expect("recover");
        assert_eq!(report.greatest_committed_revision, 9);
        assert_eq!(report.reprepare_revision, Some(9));
    }

    #[test]
    fn consecutive_rotations_commit_larger_revisions_and_take_max() {
        let (mut kernel, mut supervisor) = harness();
        rotate_once(&mut kernel, &mut supervisor, 0, 1, None).expect("rotation 1");
        rotate_once(&mut kernel, &mut supervisor, 1, 2, None).expect("rotation 2");
        assert_eq!(kernel.store.secret_revision, 2);
        assert_eq!(kernel.outbox.len(), 2);
        assert!(kernel.outbox.iter().all(|record| record.delivery_state == SecretOutboxDeliveryState::Acknowledged));
        assert_eq!(supervisor.invalidation_fence_revision, 2);
        assert_eq!(supervisor.reduce_max_invalidation_revision(), 2);
        // journal revision 单调 +1（每命令恰一对条目）。
        assert_eq!(supervisor.journal_revision, 4);
    }

    #[test]
    fn journal_outbox_and_commands_never_contain_secret_values() {
        let (mut kernel, mut supervisor) = harness();
        let secret_marker = "do-not-emit-this-value";
        let request = SecretAllowlistMutation {
            schema_version: 1,
            application_id: APP.into(),
            expected_secret_revision: 0,
            keys: vec!["api-token".into()],
            values: BTreeMap::from([("api-token".into(), secret_marker.to_string())]),
        };
        run_secret_rotation(&mut kernel, &mut supervisor, &request, "cmd-1", &snapshot_ref(1), 1_000, None).expect("rotation");
        let serialized = serde_json::to_string(&supervisor).expect("journal json") + &serde_json::to_string(&kernel.outbox).expect("outbox json") + &serde_json::to_string(&SecretAllowlistResponse::from_store(&kernel.store)).expect("response json");
        assert!(!serialized.contains(secret_marker), "secret values must never appear in journal/outbox/response");
    }

    #[test]
    fn first_assignment_from_revision_zero_allows_empty_keys() {
        let (mut kernel, mut supervisor) = harness();
        let request = SecretAllowlistMutation { schema_version: 1, application_id: APP.into(), expected_secret_revision: 0, keys: vec![], values: BTreeMap::new() };
        let outcome = run_secret_rotation(&mut kernel, &mut supervisor, &request, "cmd-empty", &snapshot_ref(1), 1_000, None).expect("empty first assignment");
        assert_eq!(outcome.secret_revision, 1);
        assert!(kernel.store.keys.is_empty());
        // revision 0 也有 canonical 空 snapshot：active snapshot ref 始终非空。
        assert!(!kernel.active_snapshot.as_ref().unwrap().secret_snapshot_ref.is_empty());
    }
}
