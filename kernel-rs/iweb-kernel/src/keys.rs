//! Owner key 管理（owner-key-management change）：一个身份多把可吊销令牌。
//! 格式 iwb_<keyId>_<secret>（keyId 8hex，secret 32B base64url）；
//! 只存 SHA-256 hash；快照 keys.json + keys.pending 事务（崩溃对账二择一）；
//! 审计 append-only audit.log（4×1MiB 轮转）。bootstrap（IWEB_API_TOKEN）
//! 只在内存保存 digest、永远有效且不可吊销——api.<base> 恢复法律的凭据面。

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

const AUDIT_SEGMENT_LIMIT: u64 = 1024 * 1024;
const AUDIT_SEGMENTS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "secretHash")]
    pub secret_hash: String,
    pub label: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "bannedAt")]
    pub banned_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    version: u32,
    keys: Vec<KeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PendingOp {
    Create { key_id: String },
    Ban { key_id: String },
}

/// 事务意图（WAL）：txn 幂等 ID + before/after 快照 digest + 阶段。
/// phase 1 = 快照写入前；phase 2 = 快照已写、审计未提交。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingIntent {
    txn: String,
    phase: u8,
    before: String,
    after: String,
    op: PendingOp,
    event: AuditEvent,
}

/// 鉴权主体：bootstrap 或某把 delegated key。
#[derive(Debug, Clone, PartialEq)]
pub enum Actor {
    Bootstrap,
    Delegated(String),
}

impl Actor {
    pub fn audit_id(&self) -> &str {
        match self {
            Actor::Bootstrap => "bootstrap",
            Actor::Delegated(id) => id,
        }
    }
}

/// 审计事件（不含任何凭据材料：无 bearer、无 ticket、无 body）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub ts: String,
    #[serde(rename = "keyId")]
    pub key_id: Option<String>,
    pub action: String,
    pub method: String,
    /// 归一化路径（无 query；构造侧负责截断至 256 字符防日志膨胀）。
    pub path: String,
    pub status: u16,
    /// 事务幂等 ID（仅 mutation 事件携带；可选）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn: Option<String>,
}

struct Inner {
    keys: Mutex<Vec<KeyRecord>>,
    /// 单写者互斥：快照 + 审计的变更序列化（并发 create/ban 不丢更新）。
    writer: Mutex<()>,
    /// 损坏/不可用状态：delegated 全拒绝、create/ban 返回 503、绝不自动重写快照。
    damaged: std::sync::atomic::AtomicBool,
    /// ban/变更版本广播：monitor 长连接立即重验并关闭。
    revision: tokio::sync::watch::Sender<u64>,
}

/// 进程级 key 存储；Clone 共享同一底层状态。
#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<Inner>,
    path: PathBuf,
    bootstrap_digest: [u8; 32],
    audit_path: PathBuf,
    pending_path: PathBuf,
}

pub struct IssuedKey {
    pub token: String,
    pub record: KeyRecord,
}

#[derive(Debug)]
pub struct KeyError(pub String);

fn utc_now() -> String {
    crate::monitor::iso_now()
}

fn sha256_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// 审计事件读取校验（与 Admin 严格 schema 同口径）。
fn valid_audit_event(event: &AuditEvent) -> bool {
    valid_utc_stamp(&event.ts)
        && event.method.bytes().all(|b| b.is_ascii_uppercase())
        && !event.method.is_empty()
        && event.action.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && event.action.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
        && event.action.len() <= 64
        && event.path.len() <= 256
        && event.key_id.as_deref().is_none_or(|id| id == "bootstrap" || (id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())))
        && event.txn.as_deref().is_none_or(|txn| txn.len() == 16 && txn.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn bearer_digest_matches(bearer: &str, expected: &[u8; 32]) -> bool {
    sha256_bytes(bearer.as_bytes()).ct_eq(expected).into()
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_bytes(count: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buffer = vec![0u8; count];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .expect("/dev/urandom");
    buffer
}

/// 记录形状校验：keyId 8hex、secretHash 64hex、时间戳合法。
/// 日按月校验（含闰年二月）。
fn valid_day(bytes: &[u8]) -> bool {
    let month = (bytes[5] - b'0') * 10 + (bytes[6] - b'0');
    let day = (bytes[8] - b'0') * 10 + (bytes[9] - b'0');
    let year = (bytes[0] - b'0') as u32 * 1000 + (bytes[1] - b'0') as u32 * 100 + (bytes[2] - b'0') as u32 * 10 + (bytes[3] - b'0') as u32;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max).contains(&(day as u32))
}

fn digest_of(keys: &[KeyRecord]) -> String {
    let file = KeysFile { version: 1, keys: keys.to_vec() };
    sha256_hex(serde_json::to_string(&file).expect("snapshot serialize").as_bytes())
}

/// 快照整体校验：version、记录形状、keyId 唯一性。
fn valid_snapshot(file: &KeysFile) -> bool {
    file.version == 1
        && file.keys.iter().all(valid_record)
        && {
            let mut ids: Vec<&str> = file.keys.iter().map(|key| key.key_id.as_str()).collect();
            ids.sort();
            ids.dedup();
            ids.len() == file.keys.len()
        }
}

fn valid_record(record: &KeyRecord) -> bool {
    record.key_id.len() == 8
        && record.key_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && record.secret_hash.len() == 64
        && record.secret_hash.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && valid_label(&record.label)
        && valid_utc_stamp(&record.created_at)
        && record.expires_at.as_deref().is_none_or(valid_utc_stamp)
        && record.banned_at.as_deref().is_none_or(valid_utc_stamp)
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 128
        && !label.chars().any(|c| c.is_control())
}

/// RFC3339 UTC 校验（YYYY-MM-DDTHH:MM:SS(.sss)?Z，数字位逐个验证）。
fn valid_utc_stamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 && bytes.len() != 24 {
        return false;
    }
    let digits_at = |indices: &[usize]| indices.iter().all(|&i| bytes[i].is_ascii_digit());
    if !([0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15]).iter().all(|&i| bytes[i].is_ascii_digit()) {
        return false;
    }
    bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b'T' && bytes[13] == b':' && bytes[16] == b':' && bytes[bytes.len() - 1] == b'Z'
        && (bytes.len() == 20 || (bytes[19] == b'.' && digits_at(&[20, 21, 22])))
        // 取值范围：月 01-12、日 01-31、时 <24、分/秒 <60。
        && (bytes[5] == b'0' && (b'1'..=b'9').contains(&bytes[6]) || bytes[5] == b'1' && (b'0'..=b'2').contains(&bytes[6]))
        && valid_day(bytes)
        && (bytes[11] == b'0' && bytes[12].is_ascii_digit()
            || bytes[11] == b'1' && bytes[12].is_ascii_digit()
            || bytes[11] == b'2' && (b'0'..=b'3').contains(&bytes[12]))
        && (b'0'..=b'5').contains(&bytes[14])
        && bytes[15].is_ascii_digit()
        && (b'0'..=b'5').contains(&bytes[17])
        && bytes[18].is_ascii_digit()
}

impl KeyStore {
    /// 加载或初始化。keys.json 缺失/损坏时：delegated 全拒绝（fail-closed），
    /// 不自动重写文件；bootstrap 依然可用（恢复语义）。
    pub fn load(path: &Path, bootstrap_token: &str) -> Self {
        let audit_path = path.parent().unwrap_or_else(|| Path::new(".")).join("audit.log");
        let pending_path = path.with_extension("pending");
        let mut keys = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<KeysFile>(&text).ok())
            .map(|file| file.keys)
            .unwrap_or_default();
        // 区分首次初始化（不存在）与损坏：symlink、解析失败、未知版本/字段、
        // 记录形状非法、权限过宽都按损坏处理（fail-closed，绝不自动重写）。
        // 缺失快照：合法的首次初始化——delegated 从空开始（全部拒绝），
        // bootstrap（恢复权威）可在空存储上创建首把委托 key（spec 场景：
        // Bootstrap remains available when the delegated key store is damaged；
        // 产品法：api.<base> 恢复路径的凭据面）。创建动作进审计流归因 bootstrap。
        // 已存在但非法的快照 fail-closed（见下），绝不静默重建。
        let mut damaged = false;
        if pending_path.is_symlink() || audit_path.is_symlink() {
            eprintln!("iweb-kernel: keys transaction or audit file is a symlink; refusing delegated state");
            damaged = true;
        }
        if path.is_symlink() {
            eprintln!("iweb-kernel: keys snapshot is a symlink; refusing delegated state");
            damaged = true;
        } else if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(text) => match serde_json::from_str::<KeysFile>(&text) {
                    Ok(file) if valid_snapshot(&file) => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(meta) = std::fs::metadata(path) {
                                if meta.permissions().mode() & 0o077 != 0 {
                                    eprintln!("iweb-kernel: keys snapshot permissions are wider than 0600; refusing delegated state");
                                    damaged = true;
                                }
                            }
                        }
                    }
                    _ => {
                        eprintln!("iweb-kernel: keys snapshot failed integrity validation; delegated keys are disabled until manually restored");
                        damaged = true;
                    }
                },
                Err(_) => damaged = true,
            }
        }
        if damaged {
            keys = Vec::new();
        }
        let (revision, _) = tokio::sync::watch::channel(0u64);
        let store = Self {
            inner: Arc::new(Inner { keys: Mutex::new(keys), writer: Mutex::new(()), damaged: std::sync::atomic::AtomicBool::new(damaged), revision }),
            path: path.to_path_buf(),
            bootstrap_digest: sha256_bytes(bootstrap_token.as_bytes()),
            audit_path,
            pending_path,
        };
        if !damaged {
            store.reconcile_pending();
        }
        store
    }

    /// 启动对账：pending 意图要么已应用到快照（补写审计、清 pending），
    /// 要么未应用（放弃，清 pending）——二择一，绝不半授权。
    fn reconcile_pending(&self) {
        let pending = match std::fs::read_to_string(&self.pending_path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                // 不可读 pending（权限/IO）：无法判断 WAL 状态——fail-closed。
                eprintln!("iweb-kernel: keys.pending unreadable ({error}); delegated key mutations are disabled");
                self.mark_damaged();
                return;
            }
        };
        let parsed = serde_json::from_str::<PendingIntent>(&pending);
        let intent = match parsed {
            Ok(intent) if Self::valid_intent(&intent) => intent,
            _ => {
                // 损坏/形状非法 pending：不猜测、不清除——进入不可用态等待人工处置。
                eprintln!("iweb-kernel: keys.pending is corrupt; delegated key mutations are disabled");
                self.mark_damaged();
                return;
            }
        };
        let current = self.snapshot_digest();
        if current == intent.after {
            // 已应用：幂等补写审计（txn 已存在则跳过），然后清除。
            let already_committed = match self.audit_txn_lookup(&intent.txn) {
                Ok(found) => found,
                Err(_) => {
                    self.mark_damaged();
                    return;
                }
            };
            if !already_committed && self.append_audit_locked_with_txn(&intent.txn, &intent.event).is_err() {
                self.mark_damaged();
                return;
            }
        } else if current == intent.before {
            // 未应用：补写 aborted 修正事件——无论原事件是否已部分写入（原事件
            // 存在恰好是需要 aborted 修正的情形）；仅当 aborted 本身已存在才跳过。
            let aborted = AuditEvent {
                ts: utc_now(),
                key_id: intent.event.key_id.clone(),
                action: "key.txn.aborted".into(),
                method: intent.event.method.clone(),
                path: intent.event.path.clone(),
                status: 503,
                txn: None,
            };
            let aborted_committed = match self.audit_contains_action_txn("key.txn.aborted", &intent.txn) {
                Ok(found) => found,
                Err(_) => {
                    self.mark_damaged();
                    return;
                }
            };
            if !aborted_committed && self.append_audit_locked_with_txn(&intent.txn, &aborted).is_err() {
                self.mark_damaged();
                return;
            }
        } else {
            // 快照既非 before 也非 after：不猜测——人工处置。
            eprintln!("iweb-kernel: keys.pending does not match snapshot state; manual recovery required");
            self.mark_damaged();
            return;
        }
        if std::fs::remove_file(&self.pending_path).is_err() {
            self.mark_damaged();
        }
    }

    fn write_pending(&self, intent: &PendingIntent, phase: u8) -> Result<(), KeyError> {
        // 原子替换：同目录 temp（create_new 防 symlink）+ fsync + rename + 目录 fsync。
        // phase-2 覆盖 phase-1 时崩溃 → 旧 intent 仍在（rename 原子性），
        // 快照已是 after → reconcile 走 after 分支补审计——不产生无 intent 的半提交。
        let staged = PendingIntent { phase, ..intent.clone() };
        let temporary = self.pending_path.with_extension("pending.tmp");
        (|| {
            let _ = std::fs::remove_file(&temporary);
            let mut handle = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&temporary)?;
            handle.write_all(serde_json::to_string(&staged).expect("intent serialize").as_bytes())?;
            handle.sync_all()?;
            drop(handle);
            std::fs::rename(&temporary, &self.pending_path)?;
            let directory = std::fs::File::open(self.pending_path.parent().unwrap_or_else(|| std::path::Path::new(".")))?;
            directory.sync_all()
        })()
        .map_err(|e| KeyError(format!("pending write failed: {e}")))
    }

    fn snapshot_digest(&self) -> String {
        let keys = self.inner.keys.lock().expect("keys lock");
        let file = KeysFile { version: 1, keys: keys.clone() };
        sha256_hex(serde_json::to_string(&file).expect("snapshot serialize").as_bytes())
    }

    /// 结构化 action+txn 匹配（aborted 幂等判定专用）。
    /// 段存在但不可读 → Err（fail-closed，与 after 分支语义一致）。
    fn audit_contains_action_txn(&self, action: &str, txn: &str) -> Result<bool, KeyError> {
        if txn.is_empty() {
            return Ok(true);
        }
        for path in std::iter::once(self.audit_path.clone()).chain((1..AUDIT_SEGMENTS).map(|index| self.audit_path.with_file_name(format!("audit.log.{index}")))) {
            if !path.exists() {
                continue;
            }
            let text = std::fs::read_to_string(&path).map_err(|e| KeyError(format!("audit segment {} unreadable: {e}", path.display())))?;
            for line in text.lines() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                    let txn_match = value.get("txn").and_then(|field| field.as_str()) == Some(txn);
                    let action_match = value.get("action").and_then(|field| field.as_str()) == Some(action);
                    if txn_match && action_match {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// 结构化 txn 匹配：解析行 JSON 后比较 txn 字段（非全文 contains）。
    /// 段存在但不可读 → 无法证明幂等状态 → 返回 None（调用方进 damaged）。
    fn audit_txn_lookup(&self, txn: &str) -> Result<bool, KeyError> {
        if txn.is_empty() {
            return Ok(true);
        }
        for path in std::iter::once(self.audit_path.clone()).chain((1..AUDIT_SEGMENTS).map(|index| self.audit_path.with_file_name(format!("audit.log.{index}")))) {
            if !path.exists() {
                continue;
            }
            let text = std::fs::read_to_string(&path).map_err(|e| KeyError(format!("audit segment {} unreadable: {e}", path.display())))?;
            for line in text.lines() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                    if value.get("txn").and_then(|field| field.as_str()) == Some(txn) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// intent 形状校验：txn 16hex、phase ∈ {1,2}、digest 64hex、事件非空。
    fn valid_intent(intent: &PendingIntent) -> bool {
        intent.txn.len() == 16
            && intent.txn.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && (intent.phase == 1 || intent.phase == 2)
            && is_digest(&intent.before)
            && is_digest(&intent.after)
            && !intent.event.action.is_empty()
    }

    /// 鉴权：bootstrap（对 bearer 原文取 digest 后恒定时间比较）或
    /// iwb_<keyId>_<secret> 委托 key（未知/过期/被 ban 统一拒绝）。
    pub fn authenticate(&self, bearer: &str) -> Option<Actor> {
        // damaged（pending/快照异常）→ delegated 全拒（fail-closed），bootstrap 不受影响。
        if self.inner.damaged.load(std::sync::atomic::Ordering::SeqCst) {
            return bearer_digest_matches(bearer, &self.bootstrap_digest).then_some(Actor::Bootstrap);
        }
        let bearer_digest = sha256_bytes(bearer.as_bytes());
        if bearer_digest.ct_eq(&self.bootstrap_digest).into() {
            return Some(Actor::Bootstrap);
        }
        let rest = bearer.strip_prefix("iwb_")?;
        let (key_id, secret) = rest.split_once('_')?;
        if key_id.len() != 8 || !key_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        // secret 形状先验证（未编码到 32B 的值直接拒绝，避免畸形输入进入比较）。
        if secret.len() != 43 || !secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return None;
        }
        let secret_digest = sha256_hex(secret.as_bytes());
        let keys = self.inner.keys.lock().expect("keys lock");
        // 存在性时序：对全部记录做恒定时间比较后再选活跃匹配——不因 keyId
        // 是否存在提前返回（统一 401，响应时间不泄露 keyId 枚举信息）。
        let now = utc_now();
        let mut matched: Option<&KeyRecord> = None;
        for record in keys.iter() {
            let digest_match: bool = secret_digest.as_bytes().ct_eq(record.secret_hash.as_bytes()).into();
            let id_match: bool = key_id.as_bytes().ct_eq(record.key_id.as_bytes()).into();
            if digest_match && id_match {
                matched = Some(record);
            }
        }
        let record = matched?;
        if record.banned_at.is_some() || record.expires_at.as_deref().is_some_and(|expiry| expiry <= now.as_str()) {
            return None;
        }
        Some(Actor::Delegated(key_id.to_owned()))
    }

    fn write_snapshot(&self, keys: &[KeyRecord]) -> Result<(), KeyError> {
        let file = KeysFile { version: 1, keys: keys.to_vec() };
        let text = serde_json::to_string_pretty(&file).expect("keys serialize");
        let temporary = self.path.with_extension("tmp");
        (|| {
            // create_new 防同目录恶意 symlink 跟随；残留 tmp 先清除。
            let _ = std::fs::remove_file(&temporary);
            if std::path::Path::new(&temporary).exists() {
                return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "keys tmp path occupied"));
            }
            let mut handle = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&temporary)?;
            handle.write_all(text.as_bytes())?;
            handle.sync_all()?;
            drop(handle);
            std::fs::rename(&temporary, &self.path)?;
            // 目录 fsync：rename 持久化（崩溃后不出现孤儿 tmp 或丢失 rename）。
            let directory = std::fs::File::open(self.path.parent().unwrap_or_else(|| std::path::Path::new(".")))?;
            directory.sync_all()
        })()
        .map_err(|e| KeyError(format!("keys snapshot write failed: {e}")))
    }

    fn append_audit_locked(&self, event: &AuditEvent) -> Result<(), KeyError> {
        // 事件携带幂等 txn id（无则空），重启补写据此去重。
        let txn = event
            .path
            .rsplit('/')
            .next()
            .filter(|segment| segment.len() == 8 && segment.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|_| String::new())
            .unwrap_or_default();
        self.append_audit_locked_with_txn(&txn, event)
    }

    fn append_audit_locked_with_txn(&self, txn: &str, event: &AuditEvent) -> Result<(), KeyError> {
        let mut enriched = serde_json::to_value(event).expect("audit serialize");
        if let Some(object) = enriched.as_object_mut() {
            if txn.is_empty() {
                // 非事务事件完全省略 txn 字段（wire 契约：出现即必须 16hex）。
                object.remove("txn");
            } else {
                object.insert("txn".into(), serde_json::json!(txn));
            }
        }
        let line = format!("{enriched}\n");
        // 轮转：主段超限 → audit.log.2→.3、.1→.2、audit.log→.1（仅丢最老段）；
        // 段名保持 audit.log.N（with_extension 会吞掉 .log，故显式拼接）。
        if std::fs::metadata(&self.audit_path).map(|meta| meta.len()).unwrap_or(0) + line.len() as u64 > AUDIT_SEGMENT_LIMIT {
            for index in (1..AUDIT_SEGMENTS - 1).rev() {
                let from = format!("{}.{index}", self.audit_path.display());
                let to = format!("{}.{}", self.audit_path.display(), index + 1);
                // 历史段不存在是首次轮转的正常情况（ENOENT 跳过）。
                if !std::path::Path::new(&from).exists() {
                    continue;
                }
                std::fs::rename(&from, &to).map_err(|e| KeyError(format!("audit rotate failed: {e}")))?;
            }
            std::fs::rename(&self.audit_path, format!("{}.1", self.audit_path.display()))
                .map_err(|e| KeyError(format!("audit rotate failed: {e}")))?;
            std::fs::File::open(self.audit_path.parent().unwrap_or_else(|| std::path::Path::new(".")))
                .and_then(|handle| handle.sync_all())
                .map_err(|e| KeyError(format!("audit rotate fsync failed: {e}")))?;
        }
        // audit.log 追加：symlink 拒绝（换 503，不跟随）。
        if self.audit_path.is_symlink() {
            return Err(KeyError("audit log is a symlink".into()));
        }
        let mut handle = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&self.audit_path)
            .map_err(|e| KeyError(format!("audit append failed: {e}")))?;
        handle.write_all(line.as_bytes())
            .and_then(|()| handle.sync_all())
            .and_then(|()| {
                // 目录 fsync：首次创建 active 段/轮转后的 rename 持久化窗口。
                std::fs::File::open(self.audit_path.parent().unwrap_or_else(|| std::path::Path::new(".")))?
                    .sync_all()
            })
            .map_err(|e| KeyError(format!("audit append failed: {e}")))
    }

    /// WAL 四段提交：pending(phase1) → 快照(after) → pending(phase2) → 审计 → 清除。
    /// 崩溃后 reconcile 按 before/after digest 二择一收敛；txn id 保证审计幂等。
    fn commit(&self, op: PendingOp, event: AuditEvent, mutate: impl FnOnce(&mut Vec<KeyRecord>) -> Result<KeyRecord, KeyError>) -> Result<KeyRecord, KeyError> {
        let _guard = self.inner.writer.lock().expect("writer lock");

        let mut keys = self.inner.keys.lock().expect("keys lock").clone();
        let previous = keys.clone();
        let record = mutate(&mut keys)?;
        let before = digest_of(&previous);
        let after = digest_of(&keys);
        let txn: String = random_bytes(8).iter().map(|b| format!("{b:02x}")).collect();
        let intent = PendingIntent { txn: txn.clone(), phase: 1, before: before.clone(), after: after.clone(), op, event: event.clone() };
        // 所有 durable-stage（含 phase-1 自身——rename 成功但目录 fsync 失败的
        // 窗口在内）失败：磁盘可能已部分变更而内存仍是 before——统一 fail-closed
        // （delegated 拒绝 + WS 关闭 + mutation 503），绝不让后续 mutation 覆盖。
        if let Err(error) = self
            .write_pending(&intent, 1)
            .and_then(|()| self.write_snapshot(&keys))
            .and_then(|()| self.write_pending(&intent, 2))
        {
            self.mark_damaged();
            return Err(error);
        }

        if let Err(error) = self.append_audit_locked_with_txn(&txn, &event) {
            // 审计失败：回滚快照到 before；回滚成功则补写 aborted 修正事件
            // （txn 去重）再清除 pending——事件流宁可 create+aborted 重复，
            // 绝不静默丢失半提交痕迹。回滚失败 → damaged 交重启 reconcile。
            if self.write_snapshot(&previous).is_ok() {
                let aborted = AuditEvent {
                    ts: utc_now(),
                    key_id: event.key_id.clone(),
                    action: "key.txn.aborted".into(),
                    method: event.method.clone(),
                    path: event.path.clone(),
                    status: 503,
                    txn: None,
                };
                if self.append_audit_locked_with_txn(&txn, &aborted).is_err() {
                    self.mark_damaged();
                    return Err(error);
                }
                if std::fs::remove_file(&self.pending_path).is_err() {
                    self.mark_damaged();
                }
            } else {
                self.mark_damaged();
            }
            return Err(error);
        }
        if std::fs::remove_file(&self.pending_path).is_err() {
            // 成功提交但 pending 无法清除：重启对账幂等（txn 去重）——保守进入不可用态。
            self.mark_damaged();
        }

        *self.inner.keys.lock().expect("keys lock") = keys;
        let _ = self.inner.revision.send(self.revision_value() + 1);
        Ok(record)
    }

    /// 创建 key：返回一次性的完整 token（明文此后不再可见）。
    pub fn create(&self, label: &str, expires_at: Option<&str>, actor: &Actor) -> Result<IssuedKey, KeyError> {
        if self.inner.damaged.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(KeyError("key store is damaged; delegated state must be restored manually".into()));
        }
        if !valid_label(label) {
            return Err(KeyError("label must be 1-128 bytes without control characters".into()));
        }
        if let Some(expiry) = expires_at {
            if !valid_utc_stamp(expiry) || expiry <= utc_now().as_str() {
            return Err(KeyError("expiresAt must be a future RFC3339 UTC timestamp".into()));
            }
        }
        // 碰撞重试：writer 锁内重新检查（spec 场景）。
        loop {
            let id_bytes = random_bytes(4);
            let key_id = id_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let exists = self.inner.keys.lock().expect("keys lock").iter().any(|key| key.key_id == key_id);
            if exists {
                continue;
            }
            let secret_bytes = random_bytes(32);
            let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&secret_bytes);
            let token = format!("iwb_{key_id}_{secret}");
            let record = KeyRecord {
                key_id: key_id.clone(),
                secret_hash: sha256_hex(secret.as_bytes()),
                label: label.to_owned(),
                created_at: utc_now(),
                expires_at: expires_at.map(str::to_owned),
                banned_at: None,
            };
            let issued_record = record.clone();
            let event = AuditEvent {
                ts: utc_now(),
                key_id: Some(actor.audit_id().to_owned()),
                action: "key.create".into(),
                method: "POST".into(),
                path: format!("/v1/keys/{key_id}"),
                status: 201,
                txn: None,
            };
            let key_id_for_op = key_id.clone();
            let record_clone = record.clone();
            let (record, token) = (record, token);
            self.commit(
                PendingOp::Create { key_id: key_id_for_op },
                event,
                move |keys| {
                    if keys.iter().any(|key| key.key_id == key_id) {
                        return Err(KeyError("key identifier collision".into()));
                    }
                    keys.push(record);
                    Ok(record_clone)
                },
            )?;
            return Ok(IssuedKey { token, record: issued_record });
        }
    }

    /// 吊销 key（幂等；bootstrap 不可吊销）。
    pub fn ban(&self, key_id: &str, actor: &Actor) -> Result<(), KeyError> {
        if self.inner.damaged.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(KeyError("key store is damaged; delegated state must be restored manually".into()));
        }
        if key_id == "bootstrap" {
            return Err(KeyError("IMMUTABLE_BOOTSTRAP".into()));
        }
        let banned_at = utc_now();
        let event = AuditEvent {
            ts: utc_now(),
            key_id: Some(actor.audit_id().to_owned()),
            action: "key.ban".into(),
            method: "DELETE".into(),
            path: format!("/v1/keys/{key_id}"),
            status: 204,
            txn: None,
        };
        let target = key_id.to_owned();
        self.commit(
            PendingOp::Ban { key_id: key_id.to_owned() },
            event,
            move |keys| {
                let record = keys
                    .iter_mut()
                    .find(|key| key.key_id == target)
                    .ok_or_else(|| KeyError("UNKNOWN_KEY".into()))?;
                if record.banned_at.is_none() {
                    record.banned_at = Some(banned_at);
                }
                Ok(record.clone())
            },
        )?;
        // 幂等重复 ban：banned_at 已设置时上面的闭包不再改动——仍返回 Ok。
        Ok(())
    }

    /// 元数据投影（无 secret/hash）。
    pub fn metadata(&self) -> Vec<serde_json::Value> {
        let keys = self.inner.keys.lock().expect("keys lock");
        let now = utc_now();
        let mut entries = vec![serde_json::json!({
            "keyId": "bootstrap",
            "label": "recovery (IWEB_API_TOKEN)",
            "createdAt": null,
            "expiresAt": null,
            "bannedAt": null,
            "status": "active",
            "revocable": false,
        })];
        for key in keys.iter() {
            let status = if key.banned_at.is_some() {
                "banned"
            } else if key.expires_at.as_deref().is_some_and(|expiry| expiry <= now.as_str()) {
                "expired"
            } else {
                "active"
            };
            entries.push(serde_json::json!({
                "keyId": key.key_id,
                "label": key.label,
                "createdAt": key.created_at,
                "expiresAt": key.expires_at,
                "bannedAt": key.banned_at,
                "status": status,
                "revocable": true,
            }));
        }
        entries
    }

    /// 读取最近审计事件（newest-first，limit ≤ 200，可按 keyId 过滤）。
    /// 段 IO 错误（非不存在）传播为 Err；坏行跳过并计数（dropped 信号）。
    pub fn audit(&self, key_id: Option<&str>, limit: usize) -> Result<(Vec<AuditEvent>, usize), KeyError> {
        let limit = limit.clamp(1, 200);
        let mut lines: Vec<String> = Vec::new();
        for index in (1..AUDIT_SEGMENTS).rev() {
            let segment = format!("{}.{index}", self.audit_path.display());
            if !std::path::Path::new(&segment).exists() {
                continue;
            }
            match std::fs::read_to_string(&segment) {
                Ok(text) => lines.extend(text.lines().filter(|line| !line.is_empty()).map(str::to_owned)),
                Err(e) => return Err(KeyError(format!("audit segment {segment} unreadable: {e}"))),
            }
        }
        if self.audit_path.exists() {
            match std::fs::read_to_string(&self.audit_path) {
                Ok(text) => lines.extend(text.lines().filter(|line| !line.is_empty()).map(str::to_owned)),
                Err(e) => return Err(KeyError(format!("audit log unreadable: {e}"))),
            }
        }
        let mut events: Vec<AuditEvent> = Vec::new();
        let mut dropped = 0usize;
        for line in lines {
            match serde_json::from_str::<AuditEvent>(&line) {
                // 语义校验：与 Admin strict schema 同口径——坏行计入 dropped
                // 而非静默下发导致 Admin parse 失败。
                Ok(event) if valid_audit_event(&event) => events.push(event),
                _ => {
                    dropped += 1;
                    eprintln!("iweb-kernel: dropping corrupt audit line");
                }
            }
        }
        events.retain(|event| match key_id { None => true, Some(id) => event.key_id.as_deref() == Some(id) });
        events.reverse();
        events.truncate(limit);
        Ok((events, dropped))
    }

    /// 记录一次控制面请求（成功或 401 拒绝）；与轮转互斥（writer 锁）。
    pub fn record_request(&self, actor: Option<&Actor>, method: &str, path: &str, status: u16) {
        let bounded_path: String = path.chars().take(256).collect();
        let event = AuditEvent {
            ts: utc_now(),
            key_id: actor.map(|a| a.audit_id().to_owned()),
            action: "control.request".into(),
            method: method.to_owned(),
            path: bounded_path,
            status,
                txn: None,
        };
        let _guard = self.inner.writer.lock().expect("writer lock");
        if let Err(error) = self.append_audit_locked(&event) {
            eprintln!("iweb-kernel: audit append failed: {}", error.0);
        }
    }

    /// 指定 keyId 是否仍可鉴权（monitor 长连接重验用）。
    /// damaged 状态下 delegated 一律不活跃（WS 据此关闭）。
    pub fn is_active(&self, key_id: &str) -> bool {
        if self.inner.damaged.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        let keys = self.inner.keys.lock().expect("keys lock");
        keys.iter().any(|key| {
            key.key_id == key_id
                && key.banned_at.is_none()
                && key.expires_at.as_deref().is_none_or(|expiry| expiry > utc_now().as_str())
        })
    }

    /// damaged 置位 + 广播（所有 delegated WS 立即关闭）。
    fn mark_damaged(&self) {
        self.inner.damaged.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.inner.revision.send(self.revision_value() + 1);
    }

    /// 订阅 ban/变更广播（monitor 长连接据此立即重验并关闭）。
    pub fn subscribe_revision(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.revision.subscribe()
    }

    fn revision_value(&self) -> u64 {
        *self.inner.revision.subscribe().borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(tag: &str) -> (KeyStore, PathBuf) {
        let directory = std::env::temp_dir().join(format!("iweb-keys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("keys.json");
        (KeyStore::load(&path, "bootstrap-token"), directory)
    }

    #[test]
    fn bootstrap_and_delegated_authenticate_and_ban() {
        let (keys, _dir) = store("auth");
        assert_eq!(keys.authenticate("bootstrap-token"), Some(Actor::Bootstrap));
        assert_eq!(keys.authenticate("wrong"), None);

        let issued = keys.create("agent-a", None, &Actor::Bootstrap).expect("create");
        assert_eq!(keys.authenticate(&issued.token), Some(Actor::Delegated(issued.record.key_id.clone())));
        assert_eq!(keys.authenticate("iwb_00000000_wrongsecret"), None);

        keys.ban(&issued.record.key_id, &Actor::Bootstrap).expect("ban");
        assert_eq!(keys.authenticate(&issued.token), None);
        // 幂等重复 ban。
        keys.ban(&issued.record.key_id, &Actor::Bootstrap).expect("idempotent ban");
        // bootstrap 不可吊销。
        assert_eq!(keys.ban("bootstrap", &Actor::Bootstrap).unwrap_err().0, "IMMUTABLE_BOOTSTRAP");
    }

    #[test]
    fn expiry_and_validation_rules() {
        let (keys, _dir) = store("expiry");
        assert!(keys.create("", None, &Actor::Bootstrap).is_err());
        assert!(keys.create(&"x".repeat(129), None, &Actor::Bootstrap).is_err());
        assert!(keys.create("ok", Some("2020-01-01T00:00:00.000Z"), &Actor::Bootstrap).is_err());
        assert!(keys.create("ok", Some("not-a-stamp"), &Actor::Bootstrap).is_err());
        // 过期后拒绝。
        let past = "2099-01-01T00:00:00.000Z";
        let issued = keys.create("short-lived", Some(past), &Actor::Bootstrap).expect("create");
        assert!(keys.authenticate(&issued.token).is_some());
    }

    #[test]
    fn persistence_and_reload() {
        let (keys, directory) = store("persist");
        let issued = keys.create("persisted", None, &Actor::Bootstrap).expect("create");
        let reloaded = KeyStore::load(&directory.join("keys.json"), "bootstrap-token");
        assert_eq!(reloaded.authenticate(&issued.token), Some(Actor::Delegated(issued.record.key_id.clone())));
        // 损坏快照：fail-closed（delegated 拒绝、bootstrap 可用、文件不被重写）。
        std::fs::write(directory.join("keys.json"), "{corrupt").unwrap();
        let damaged = KeyStore::load(&directory.join("keys.json"), "bootstrap-token");
        assert_eq!(damaged.authenticate(&issued.token), None);
        assert_eq!(damaged.authenticate("bootstrap-token"), Some(Actor::Bootstrap));
    }

    #[test]
    fn uppercase_audit_keyid_is_dropped_not_served() {
        let (keys, directory) = store("upper");
        keys.record_request(Some(&Actor::Delegated("abcdef01".into())), "GET", "/v1/status", 200);
        // 注入大写 keyId 坏行（Kernel 校验应拒绝下发、计入 dropped）。
        let audit_path = directory.join("audit.log");
        let existing = std::fs::read_to_string(&audit_path).unwrap_or_default();
        let bad_line = concat!(
            r#"{"ts":"2099-01-01T00:00:00.000Z","#,
            r#""keyId":"ABCDEF01","#,
            r#""action":"control.request","#,
            r#""method":"GET","path":"/v1/status","status":200}"#,
            "\n"
        );
        let corrupt = format!("{existing}{bad_line}");
        std::fs::write(&audit_path, corrupt).unwrap();
        let (events, dropped) = keys.audit(None, 50).expect("audit");
        assert!(events.iter().all(|event| event.key_id.as_deref() != Some("ABCDEF01")));
        assert!(dropped >= 1);
    }

    #[test]
    fn phase1_failure_disables_all_mutations() {
        let (keys, directory) = store("phase1fail");
        use std::os::unix::fs::PermissionsExt;
        // 目录只读：phase-1 write_pending 即失败 → mark_damaged。
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555)).unwrap();
        let first = keys.create("first", None, &Actor::Bootstrap);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(first.is_err());
        // damaged 之后：即使目录恢复可写，mutation 仍被拒（503），delegated 全拒。
        assert!(keys.create("second", None, &Actor::Bootstrap).is_err());
        assert_eq!(keys.authenticate("anything"), None);
    }

    #[test]
    fn snapshot_write_failure_fails_closed() {
        let (keys, directory) = store("failclosed");
        // 目录只读 → 快照/审计/pending 均无法写 → create 必须 503 且内存不变。
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = keys.create("blocked", None, &Actor::Bootstrap);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err(), "create must fail when durable writes fail");
        // fail-closed：delegated 全拒（damaged），列表仍只有 bootstrap 合成条目。
        assert_eq!(keys.authenticate("anything"), None);
        assert_eq!(keys.metadata().len(), 1);
    }

    #[test]
    fn audit_rotation_and_query_bounds() {
        let (keys, _dir) = store("audit");
        keys.record_request(Some(&Actor::Bootstrap), "GET", "/v1/status", 200);
        keys.record_request(None, "POST", "/v1/keys", 401);
        let (all, _) = keys.audit(None, 50).expect("audit");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].status, 401, "newest-first");
        assert_eq!(all[1].status, 200);
        let (filtered, _) = keys.audit(Some("bootstrap"), 50).expect("audit");
        assert_eq!(filtered.len(), 1);
        assert!(keys.audit(None, 0).is_ok(), "limit clamped not rejected");
    }
}
