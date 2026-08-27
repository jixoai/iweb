//! 用户原始需求（2026-08-27，add-wasm-host-services 任务 4.3/5.6）：iweb:kv@1.0.0 的
//! 内嵌 SQLite 后端——单 key 线性化 CAS（K2）、delete tombstone 阻断 stale writer
//! 复活、K1 有界 list(prefix,cursor,limit)（宿主签发 opaque cursor，绑定
//! applicationId/policyDigest/prefix/snapshotToken/lastKey/expiry）、两阶段 quota 写前
//! 判定与 backend operation marker。规范权威：specs/wasm-host-kv/spec.md 与
//! packages/contracts/wasm-host-kv.ts（Rust 逐语义对齐：CAS 决策、limit 天花板
//! min(256, maxListItems)、首个候选 item 单独超 maxListBytes → limit-exceeded、
//! 跨 scope cursor 稳定映射 invalid-key、过期边界含等号）。
//!
//! 版本线：version 是严格递增 u64，上界 u53（契约 IWEB_KV_VERSION_MAX）；计数器
//! 耗尽/回绕 → unavailable，绝不提交回绕版本。tombstone 与值共享同一条 CAS 线。

use crate::host_services::quota::{QuotaError, QuotaLedger, ReservationRecordV2};
use crate::jcs::{validate_application_key, WireError, WASM_U53_MAX};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::time::Instant;

/// KV 后端稳定错误码前缀（owner 诊断面）。
pub const WASMD_KV_BACKEND_INVALID: &str = "WASMD_KV_BACKEND_INVALID";

/// key/value 界（contracts wasm-host-kv.ts 同值）。
pub const KV_KEY_MAX_BYTES: usize = 128;
pub const KV_VALUE_MAX_BYTES: usize = 65536;
pub const KV_LIST_LIMIT_MAX: u32 = 256;

/// KV 服务的调用侧错误（WIT variant ↔ host-call code 的映射面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvError {
    InvalidKey,
    NotFound,
    Conflict,
    QuotaExceeded,
    LimitExceeded,
    CursorExpired,
    Busy,
    Timeout,
    Unavailable,
    Internal,
}

impl KvError {
    /// host-call frame 的 detailCode（bounded opaque；不含 key/value）。
    pub fn detail_code(self) -> &'static str {
        match self {
            KvError::InvalidKey => "IWEB_KV_INVALID_KEY",
            KvError::NotFound => "IWEB_KV_NOT_FOUND",
            KvError::Conflict => "IWEB_KV_CONFLICT",
            KvError::QuotaExceeded => "IWEB_KV_QUOTA_EXCEEDED",
            KvError::LimitExceeded => "IWEB_KV_LIMIT_EXCEEDED",
            KvError::CursorExpired => "IWEB_KV_CURSOR_EXPIRED",
            KvError::Busy => "IWEB_KV_BUSY",
            KvError::Timeout => "IWEB_KV_TIMEOUT",
            KvError::Unavailable => "IWEB_KV_UNAVAILABLE",
            KvError::Internal => "IWEB_KV_INTERNAL",
        }
    }

    /// host-call frame 的 closed code。
    pub fn host_call_code(self) -> &'static str {
        match self {
            KvError::InvalidKey => "INVALID_ARGUMENT",
            KvError::NotFound => "NOT_FOUND",
            KvError::Conflict => "CONFLICT",
            KvError::QuotaExceeded => "QUOTA_EXCEEDED",
            KvError::LimitExceeded => "LIMIT_EXCEEDED",
            KvError::CursorExpired => "LIMIT_EXCEEDED",
            KvError::Busy => "BUSY",
            KvError::Timeout => "TIMEOUT",
            KvError::Unavailable => "UNAVAILABLE",
            KvError::Internal => "INTERNAL",
        }
    }
}

impl From<QuotaError> for KvError {
    fn from(error: QuotaError) -> Self {
        match error {
            QuotaError::Exceeded => KvError::QuotaExceeded,
            QuotaError::Busy => KvError::Busy,
            QuotaError::Unavailable(_) => KvError::Unavailable,
        }
    }
}

/// CAS 纯决策（contracts applyIwebKvCas 同式）：expected null = 无条件；expected ==
/// current 提交；其余 conflict（含 key 从未存在但携带 expected）；next 必须严格大于
/// current；耗尽 → unavailable。
pub fn apply_kv_cas(current_version: Option<u64>, expected: Option<u64>, next_version: u64) -> Result<u64, KvError> {
    if let Some(expected) = expected {
        if Some(expected) != current_version {
            return Err(KvError::Conflict);
        }
    }
    let current = current_version.unwrap_or(0);
    if current >= WASM_U53_MAX {
        return Err(KvError::Unavailable); // 计数器耗尽，绝不回绕。
    }
    if next_version <= current {
        return Err(KvError::Unavailable); // 必须严格更大（含回绕）。
    }
    Ok(next_version)
}

/// cursor 的宿主侧绑定（spec「authenticated payload」字段逐字；host-issued，不落
/// caller 手）。in-memory registry 使 token 不可伪造：未签发 token 一律 invalid-key。
#[derive(Debug, Clone, PartialEq)]
pub struct CursorBindingV1 {
    pub application_id: String,
    pub host_service_policy_digest: String,
    pub prefix: String,
    pub snapshot_token: String,
    pub last_key: String,
    pub expires_at_ms: u64,
}

/// kv.sqlite3 后端。
pub struct KvBackend {
    conn: Connection,
    application_id: String,
    host_service_policy_digest: String,
    cursors: HashMap<String, CursorBindingV1>,
    snapshots: HashMap<String, u64>,
    /// quarantine 原因（unavailable 域；owner recovery 前拒绝一切服务调用）。
    pub quarantined: Option<&'static str>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS kv_entries (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  version INTEGER NOT NULL,
  tombstone INTEGER NOT NULL DEFAULT 0,
  deleted_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS kv_operations (
  operation_id TEXT PRIMARY KEY,
  reservation_id TEXT NOT NULL,
  proof_digest TEXT NOT NULL,
  method TEXT NOT NULL,
  key TEXT NOT NULL,
  assigned_version INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);
";

/// list 页条目。
#[derive(Debug, Clone, PartialEq)]
pub struct KvListEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub version: u64,
}

/// Durable KV operation marker used by replay recovery.  The marker is
/// committed in the same SQLite transaction as the value/tombstone, so a
/// present marker proves that the backend mutation happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvOperationMarker {
    pub operation_id: String,
    pub reservation_id: String,
    pub proof_digest: String,
    pub method: String,
    pub key: String,
    pub assigned_version: u64,
}

impl KvBackend {
    pub fn new(
        conn: Connection,
        application_id: &str,
        host_service_policy_digest: &str,
    ) -> Result<Self, KvError> {
        conn.execute_batch(SCHEMA).map_err(|_| KvError::Unavailable)?;
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| KvError::Unavailable)?;
        Ok(Self {
            conn,
            application_id: application_id.to_string(),
            host_service_policy_digest: host_service_policy_digest.to_string(),
            cursors: HashMap::new(),
            snapshots: HashMap::new(),
            quarantined: None,
        })
    }

    fn ensure_available(&self) -> Result<(), KvError> {
        if self.quarantined.is_some() {
            return Err(KvError::Unavailable);
        }
        Ok(())
    }

    /// 恢复扫描用的宿主侧连接访问（绝不暴露给组件；无 path/handle 泄漏面）。
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    fn check_deadline(&self, deadline: Instant) -> Result<(), KvError> {
        if Instant::now() >= deadline {
            Err(KvError::Timeout)
        } else {
            Ok(())
        }
    }

    /// get：只读已提交的非 tombstone 条目。
    pub fn get(&mut self, key: &str, deadline: Instant) -> Result<(Vec<u8>, u64), KvError> {
        self.ensure_available()?;
        self.check_deadline(deadline)?;
        if validate_application_key(key).is_err() {
            return Err(KvError::InvalidKey);
        }
        let row = self
            .conn
            .query_row(
                "SELECT value, version FROM kv_entries WHERE key = ?1 AND tombstone = 0",
                params![key],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?.max(0) as u64)),
            )
            .optional()
            .map_err(|_| KvError::Internal)?;
        match row {
            None => Err(KvError::NotFound),
            Some((value, version)) => Ok((value, version)),
        }
    }

    /// set：quota reserve → 单事务（CAS + upsert + marker）→ finalize。
    /// 冲突在任何持久化之前回滚（envelope/SQL 数据不变）。
    #[allow(clippy::too_many_arguments)]
    pub fn set(
        &mut self,
        key: &str,
        value: &[u8],
        expected: Option<u64>,
        ledger: &mut QuotaLedger,
        envelope_bytes: u64,
        service_cap_bytes: u64,
        entry_overhead_bytes: u64,
        reservation_ttl_ms: u64,
        now_ms: u64,
        deadline: Instant,
    ) -> Result<u64, KvError> {
        let operation_id = uuid::Uuid::now_v7().hyphenated().to_string();
        self.set_with_operation_id(
            key,
            value,
            expected,
            ledger,
            envelope_bytes,
            service_cap_bytes,
            entry_overhead_bytes,
            reservation_ttl_ms,
            now_ms,
            deadline,
            &operation_id,
        )
    }

    /// 与 host-call replay claim 共用 operation marker 的写入入口。
    /// operationId 由 ledger claim 生成，后端不得自行替换，否则崩溃恢复无法把
    /// backend marker 关联回原始 requestId。
    #[allow(clippy::too_many_arguments)]
    pub fn set_with_operation_id(
        &mut self,
        key: &str,
        value: &[u8],
        expected: Option<u64>,
        ledger: &mut QuotaLedger,
        envelope_bytes: u64,
        service_cap_bytes: u64,
        entry_overhead_bytes: u64,
        reservation_ttl_ms: u64,
        now_ms: u64,
        deadline: Instant,
        operation_id: &str,
    ) -> Result<u64, KvError> {
        self.ensure_available()?;
        self.check_deadline(deadline)?;
        if validate_application_key(key).is_err() {
            return Err(KvError::InvalidKey);
        }
        if value.len() > KV_VALUE_MAX_BYTES {
            return Err(KvError::LimitExceeded);
        }
        // 保守预留上界：key + value + entry 记账上界（触碰后端之前计算）。
        let delta = (key.len() as u64) + (value.len() as u64) + entry_overhead_bytes;
        let reservation = ledger.reserve("kv", operation_id, delta, envelope_bytes, service_cap_bytes, now_ms, reservation_ttl_ms)?;
        match self.commit_cas("set", key, Some(value), expected, &reservation, operation_id, now_ms) {
            Ok(version) => {
                self.finalize_or_quarantine(ledger, &reservation);
                Ok(version)
            }
            Err(KvError::Conflict) => {
                ledger.release(&reservation.reservation_id).map_err(KvError::from)?;
                Err(KvError::Conflict)
            }
            Err(error) => {
                let _ = ledger.release(&reservation.reservation_id);
                Err(error)
            }
        }
    }

    /// delete：提交更高版本 tombstone；stale writer（expected < tombstone 版本）必
    /// conflict（「Delete prevents stale resurrection」）。
    #[allow(clippy::too_many_arguments)]
    pub fn delete(
        &mut self,
        key: &str,
        expected: Option<u64>,
        ledger: &mut QuotaLedger,
        envelope_bytes: u64,
        service_cap_bytes: u64,
        entry_overhead_bytes: u64,
        reservation_ttl_ms: u64,
        now_ms: u64,
        deadline: Instant,
    ) -> Result<u64, KvError> {
        let operation_id = uuid::Uuid::now_v7().hyphenated().to_string();
        self.delete_with_operation_id(
            key,
            expected,
            ledger,
            envelope_bytes,
            service_cap_bytes,
            entry_overhead_bytes,
            reservation_ttl_ms,
            now_ms,
            deadline,
            &operation_id,
        )
    }

    /// 与 host-call replay claim 共用 operation marker 的删除入口。
    #[allow(clippy::too_many_arguments)]
    pub fn delete_with_operation_id(
        &mut self,
        key: &str,
        expected: Option<u64>,
        ledger: &mut QuotaLedger,
        envelope_bytes: u64,
        service_cap_bytes: u64,
        entry_overhead_bytes: u64,
        reservation_ttl_ms: u64,
        now_ms: u64,
        deadline: Instant,
        operation_id: &str,
    ) -> Result<u64, KvError> {
        self.ensure_available()?;
        self.check_deadline(deadline)?;
        if validate_application_key(key).is_err() {
            return Err(KvError::InvalidKey);
        }
        let delta = (key.len() as u64) + entry_overhead_bytes;
        let reservation = ledger.reserve("kv", operation_id, delta, envelope_bytes, service_cap_bytes, now_ms, reservation_ttl_ms)?;
        match self.commit_cas("delete", key, None, expected, &reservation, operation_id, now_ms) {
            Ok(version) => {
                self.finalize_or_quarantine(ledger, &reservation);
                Ok(version)
            }
            Err(KvError::Conflict) => {
                ledger.release(&reservation.reservation_id).map_err(KvError::from)?;
                Err(KvError::Conflict)
            }
            Err(error) => {
                let _ = ledger.release(&reservation.reservation_id);
                Err(error)
            }
        }
    }

    /// 单事务 CAS 提交：mutation + operation marker 原子落盘（backend transaction
    /// with an idempotency marker containing the reservation, proof and operation IDs）。
    #[allow(clippy::too_many_arguments)]
    fn commit_cas(
        &mut self,
        method: &str,
        key: &str,
        value: Option<&[u8]>,
        expected: Option<u64>,
        reservation: &ReservationRecordV2,
        operation_id: &str,
        now_ms: u64,
    ) -> Result<u64, KvError> {
        let tx = self.conn.transaction().map_err(|_| KvError::Internal)?;
        let current: Option<(u64, bool)> = tx
            .query_row(
                "SELECT version, tombstone FROM kv_entries WHERE key = ?1",
                params![key],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as u64, row.get::<_, i64>(1)? != 0)),
            )
            .optional()
            .map_err(|_| KvError::Internal)?;
        // tombstone 也是 current（值缺席、版本在场）——CAS 线唯一。
        let current_version = current.map(|(version, _tombstone)| version);
        let next_version = current_version.unwrap_or(0) + 1;
        let assigned = apply_kv_cas(current_version, expected, next_version)?;
        if method == "set" {
            tx.execute(
                "INSERT INTO kv_entries (key, value, version, tombstone, deleted_at_ms) VALUES (?1, ?2, ?3, 0, NULL)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, version = excluded.version, tombstone = 0, deleted_at_ms = NULL",
                params![key, value.unwrap_or_default(), assigned as i64],
            )
            .map_err(|_| KvError::Internal)?;
        } else {
            tx.execute(
                "INSERT INTO kv_entries (key, value, version, tombstone, deleted_at_ms) VALUES (?1, X'', ?2, 1, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = X'', version = excluded.version, tombstone = 1, deleted_at_ms = excluded.deleted_at_ms",
                params![key, assigned as i64, now_ms as i64],
            )
            .map_err(|_| KvError::Internal)?;
        }
        tx.execute(
            "INSERT INTO kv_operations (operation_id, reservation_id, proof_digest, method, key, assigned_version, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                operation_id,
                reservation.reservation_id,
                reservation.reservation_proof_digest,
                method,
                key,
                assigned as i64,
                now_ms as i64
            ],
        )
        .map_err(|_| KvError::Internal)?;
        tx.commit().map_err(|_| KvError::Internal)?;
        Ok(assigned)
    }

    /// backend commit 成功后的 finalize；失败进入 quarantine（绝不伪装 quota no-op）。
    fn finalize_or_quarantine(&mut self, ledger: &mut QuotaLedger, reservation: &ReservationRecordV2) {
        let measured = crate::host_services::quota::QuotaLedger::measure_sqlite_file_bytes(&self.conn)
            .unwrap_or(u64::MAX);
        if measured != u64::MAX {
            if ledger.finalize(reservation, measured).is_err() {
                self.quarantined = Some(WASMD_KV_BACKEND_INVALID);
            }
        } else {
            self.quarantined = Some(WASMD_KV_BACKEND_INVALID);
        }
    }

    /// K1 有界 list。cursor 跨 scope → invalid-key（不泄露匹配 key/计数）；过期 →
    /// cursor-expired（绝不从开头重启）。
    #[allow(clippy::too_many_arguments)]
    pub fn list(
        &mut self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u32,
        max_list_items: u64,
        max_list_bytes: u64,
        cursor_ttl_ms: u64,
        now_ms: u64,
        deadline: Instant,
    ) -> Result<(Vec<KvListEntry>, Option<String>), KvError> {
        self.ensure_available()?;
        self.check_deadline(deadline)?;
        if validate_application_key(prefix).is_err() || prefix.is_empty() {
            return Err(KvError::InvalidKey);
        }
        let ceiling = max_list_items.min(KV_LIST_LIMIT_MAX as u64);
        if limit < 1 || limit as u64 > ceiling {
            return Err(KvError::LimitExceeded);
        }
        // 先捕获 cursor 绑定与 snapshot 存活态，再惰性 GC——同调用内到期的 cursor
        // 必须报告 cursor-expired（而非被 GC 抹成 invalid-key）；早于本调用被 GC 的
        // token 无法区分伪造，稳定 invalid-key（fail-closed，已上报）。
        let resolved_binding = match cursor {
            Some(token) => match self.cursors.get(token) {
                Some(binding) => {
                    let snapshot_alive = self.snapshots.contains_key(&binding.snapshot_token);
                    Some((binding.clone(), snapshot_alive))
                }
                None => None,
            },
            None => None,
        };
        self.gc_cursors(now_ms);
        let (snapshot_token, after_key) = match (cursor, resolved_binding) {
            (None, _) => {
                let token = uuid::Uuid::now_v7().hyphenated().to_string();
                self.snapshots.insert(token.clone(), now_ms + cursor_ttl_ms);
                (token, None)
            }
            (Some(_), None) => return Err(KvError::InvalidKey), // 未签发/伪造/已被回收：稳定 invalid-key。
            (Some(_), Some((binding, snapshot_alive))) => {
                // scope：app/policy/prefix 必须全等（先于任何扫描，不泄露匹配 key/计数）。
                // spec：快照被回收（reclaimed snapshot）与过期 token 同判 cursor-expired，
                // 绝不归入 scope 错误——golden 表 snapshot-recycled-while-cursor-live。
                if binding.application_id != self.application_id
                    || binding.host_service_policy_digest != self.host_service_policy_digest
                    || binding.prefix != prefix
                {
                    return Err(KvError::InvalidKey);
                }
                if !snapshot_alive || now_ms >= binding.expires_at_ms {
                    return Err(KvError::CursorExpired);
                }
                (binding.snapshot_token.clone(), Some(binding.last_key.clone()))
            }
        };
        // 键域上界：grammar 字符集 < '{'（'z'+1），prefix 前缀的所有键都落在半开区间内。
        let upper_bound = format!("{prefix}{{");
        let scan_limit = limit as i64 + 1; // 多取一条判定 has_more。
        let mut statement = self
            .conn
            .prepare(
                "SELECT key, value, version FROM kv_entries
                 WHERE tombstone = 0 AND key >= ?1 AND key < ?2 AND (?3 IS NULL OR key > ?3)
                 ORDER BY key ASC LIMIT ?4",
            )
            .map_err(|_| KvError::Internal)?;
        let rows = statement
            .query_map(params![prefix, upper_bound, after_key, scan_limit], |row| {
                Ok(KvListEntry {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    version: row.get::<_, i64>(2)?.max(0) as u64,
                })
            })
            .map_err(|_| KvError::Internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KvError::Internal)?;
        if rows.is_empty() {
            return Ok((Vec::new(), None));
        }
        let total_matches = rows.len();
        let candidates: Vec<KvListEntry> = rows.into_iter().take(limit as usize).collect();
        let mut items = Vec::new();
        let mut page_bytes: u64 = 0;
        let mut byte_break = false;
        for entry in candidates {
            let entry_bytes = (entry.key.len() + entry.value.len()) as u64;
            if page_bytes + entry_bytes > max_list_bytes {
                if items.is_empty() {
                    // 契约裁决 2：首个候选 item 单独超过 maxListBytes → limit-exceeded
                    //（杜绝「空页+游标」死循环）。
                    return Err(KvError::LimitExceeded);
                }
                byte_break = true; // 剩余候选存在但超页字节：返回先前有界页。
                break;
            }
            page_bytes += entry_bytes;
            items.push(entry);
        }
        if items.is_empty() {
            return Ok((Vec::new(), None));
        }
        // next-cursor 仅当还有可见匹配（查询截断或字节截断）。
        let has_more = total_matches > limit as usize || byte_break;
        let next_cursor = if has_more {
            // 未纳入 limit/bytes 的剩余可见匹配存在 → 续游标。
            let last_key = items.last().expect("non-empty").key.clone();
            let token = uuid::Uuid::now_v7().hyphenated().to_string();
            self.cursors.insert(
                token.clone(),
                CursorBindingV1 {
                    application_id: self.application_id.clone(),
                    host_service_policy_digest: self.host_service_policy_digest.clone(),
                    prefix: prefix.to_string(),
                    snapshot_token,
                    last_key,
                    expires_at_ms: now_ms + cursor_ttl_ms,
                },
            );
            Some(token)
        } else {
            None
        };
        Ok((items, next_cursor))
    }

    /// 过期 cursor/snapshot 惰性回收（expiry 边界含等号，fail-closed）。
    fn gc_cursors(&mut self, now_ms: u64) {
        self.cursors.retain(|_, binding| now_ms < binding.expires_at_ms);
        self.snapshots.retain(|_, expiry| now_ms < *expiry);
    }

    /// tombstone GC：仅当能证明没有活跃 cursor（registry 空）且已过保留下限
    /// （maxCursorTtl + hostCallReplayTtl；「if that proof is unavailable they remain
    /// retained and count toward quota」）。保守：证明不可得即保留。
    pub fn gc_tombstones(&mut self, max_cursor_ttl_ms: u64, host_call_replay_ttl_ms: u64, now_ms: u64) -> Result<usize, KvError> {
        if !self.cursors.is_empty() || !self.snapshots.is_empty() {
            return Ok(0); // 活跃 cursor 存在：保留下限内一律保留。
        }
        let floor = max_cursor_ttl_ms.saturating_add(host_call_replay_ttl_ms);
        let removed = self
            .conn
            .execute(
                "DELETE FROM kv_entries WHERE tombstone = 1 AND deleted_at_ms IS NOT NULL AND (?1 - deleted_at_ms) >= ?2",
                params![now_ms as i64, floor as i64],
            )
            .map_err(|_| KvError::Internal)?;
        Ok(removed)
    }

    // -----------------------------------------------------------------
    // 恢复扫描面（provider.recover 协调 ledger 与 backend marker）。
    // -----------------------------------------------------------------

    pub fn has_operation_marker(&self, operation_id: &str) -> Result<bool, KvError> {
        let found: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM kv_operations WHERE operation_id = ?1", params![operation_id], |row| row.get(0))
            .optional()
            .map_err(|_| KvError::Internal)?;
        Ok(found.is_some())
    }

    /// Return the complete marker for recovery.  A malformed marker is an
    /// unavailable backend, never a reason to execute the request again.
    pub fn operation_marker(&self, operation_id: &str) -> Result<Option<KvOperationMarker>, KvError> {
        self.conn
            .query_row(
                "SELECT operation_id, reservation_id, proof_digest, method, key, assigned_version
                 FROM kv_operations WHERE operation_id = ?1",
                params![operation_id],
                |row| {
                    Ok(KvOperationMarker {
                        operation_id: row.get(0)?,
                        reservation_id: row.get(1)?,
                        proof_digest: row.get(2)?,
                        method: row.get(3)?,
                        key: row.get(4)?,
                        assigned_version: row.get::<_, i64>(5)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .optional()
            .map_err(|_| KvError::Internal)
    }

    pub fn list_operation_ids(&self) -> Result<Vec<String>, KvError> {
        let mut statement = self
            .conn
            .prepare("SELECT operation_id FROM kv_operations")
            .map_err(|_| KvError::Internal)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| KvError::Internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KvError::Internal)?;
        Ok(rows)
    }

    /// 恢复：孤儿 marker（后端有、ledger 无 reservation）→ quarantine。
    pub fn quarantine_on_orphan_marker(&mut self, ledger_operation_ids: &[String]) {
        let known = self.list_operation_ids().unwrap_or_default();
        if known.iter().any(|id| !ledger_operation_ids.contains(id)) {
            self.quarantined = Some(WASMD_KV_BACKEND_INVALID);
        }
    }
}

/// 兼容 helper：WireError → KvError（文法层共享）。
impl From<WireError> for KvError {
    fn from(_: WireError) -> Self {
        KvError::InvalidKey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        backend: KvBackend,
        ledger: QuotaLedger,
    }

    /// 真文件 fixture（journal durability 与跨连接可见性按生产路径验证）。
    fn fixture() -> (Fixture, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = Connection::open(dir.path().join("kv.sqlite3")).expect("kv db");
        let backend = KvBackend::new(conn, "alpha", &"cd".repeat(32)).expect("backend");
        let ledger = QuotaLedger::new(
            Connection::open(dir.path().join("quota.sqlite3")).expect("quota db"),
            "alpha",
        )
        .expect("ledger");
        ((Fixture { backend, ledger }), dir)
    }

    const ENVELOPE: u64 = 1_048_576;
    const CAP: u64 = 1_048_576;
    const OVERHEAD: u64 = 64;
    const TTL: u64 = 60_000;
    const CURSOR_TTL: u64 = 60_000;

    fn now() -> Instant {
        Instant::now() + std::time::Duration::from_secs(60)
    }

    #[test]
    fn set_get_delete_round_trip_with_versions() {
        let (mut fixture, _dir) = fixture();
        let v1 = fixture.backend.set("a", b"value-one", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("set");
        assert_eq!(v1, 1);
        let (value, version) = fixture.backend.get("a", now()).expect("get");
        assert_eq!((value.as_slice(), version), (b"value-one".as_slice(), 1));
        let v2 = fixture.backend.set("a", b"value-two", Some(1), &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("cas set");
        assert_eq!(v2, 2);
        let deleted = fixture.backend.delete("a", Some(2), &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("delete");
        assert_eq!(deleted, 3);
        assert_eq!(fixture.backend.get("a", now()).expect_err("tombstoned"), KvError::NotFound);
    }

    #[test]
    fn cas_conflict_and_tombstone_prevent_stale_resurrection() {
        let (mut fixture, _dir) = fixture();
        fixture.backend.set("k", b"v1", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("set v1");
        // 两个携带同一 expected 的写：第二个必须 conflict。
        fixture.backend.set("k", b"first", Some(1), &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("first wins");
        assert_eq!(
            fixture.backend.set("k", b"second", Some(1), &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect_err("stale writer"),
            KvError::Conflict
        );
        // delete tombstone 后，携带旧 expected 的写复活被拒。
        fixture.backend.delete("k", Some(2), &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("delete");
        assert_eq!(
            fixture.backend.set("k", b"resurrect", Some(1), &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect_err("stale resurrection"),
            KvError::Conflict
        );
        assert_eq!(fixture.backend.get("k", now()).expect_err("still deleted"), KvError::NotFound);
        // expected:null 的无条件重建合法（tombstone 只阻断 stale writer）。
        fixture.backend.set("k", b"recreated", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("recreate");
    }

    #[test]
    fn key_and_value_bounds_are_enforced_before_allocation() {
        let (mut fixture, _dir) = fixture();
        assert_eq!(fixture.backend.get("UPPER", now()).expect_err("grammar"), KvError::InvalidKey);
        assert_eq!(fixture.backend.get("", now()).expect_err("empty"), KvError::InvalidKey);
        let big = vec![b'x'; KV_VALUE_MAX_BYTES + 1];
        assert_eq!(
            fixture.backend.set("a", &big, None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect_err("value bound"),
            KvError::LimitExceeded
        );
    }

    #[test]
    fn quota_exceeded_rejects_before_any_mutation() {
        let (mut fixture, _dir) = fixture();
        let small_cap = 4_096; // page 粒度之下仍先撞保守预留上界。
        fixture.backend.set("a", b"first", None, &mut fixture.ledger, ENVELOPE, small_cap, OVERHEAD, TTL, 0, now()).expect("first fits");
        // 第二次写：envelope 允许但 service cap 以实测 page 字节封口后即超。
        let second = fixture.backend.set("b", b"second", None, &mut fixture.ledger, ENVELOPE, small_cap, OVERHEAD, TTL, 0, now());
        let error = second.expect_err("service cap");
        assert!(matches!(error, KvError::QuotaExceeded | KvError::Unavailable), "cap enforcement: {error:?}");
        // 拒绝路径不产生 key/版本/marker。
        assert_eq!(fixture.backend.get("b", now()).expect_err("no mutation"), KvError::NotFound);
    }

    #[test]
    fn list_pages_by_prefix_with_cursors_and_tombstone_skip() {
        let (mut fixture, _dir) = fixture();
        for key in ["a.one", "a.two", "b.one"] {
            fixture.backend.set(key, b"v", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("seed");
        }
        fixture.backend.delete("a.two", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("tombstone");
        let (page, cursor) = fixture.backend.list("a.", None, 10, 256, 65_536, CURSOR_TTL, 0, now()).expect("list");
        assert_eq!(page.len(), 1, "tombstone skipped");
        assert_eq!(page[0].key, "a.one");
        assert!(cursor.is_none(), "no more matches");

        // 分页 + 续游标。
        for key in ["c.1", "c.2", "c.3"] {
            fixture.backend.set(key, b"v", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("seed");
        }
        let (page1, cursor1) = fixture.backend.list("c.", None, 1, 256, 65_536, CURSOR_TTL, 0, now()).expect("page1");
        assert_eq!(page1.len(), 1);
        let cursor1 = cursor1.expect("continuation");
        let (page2, cursor2) = fixture.backend.list("c.", Some(&cursor1), 1, 256, 65_536, CURSOR_TTL, 0, now()).expect("page2");
        assert_eq!(page2.len(), 1);
        assert_ne!(page1[0].key, page2[0].key);
        assert!(cursor2.is_some(), "third page remains");

        // 跨 prefix cursor → invalid-key（不泄露匹配 key/计数）。
        assert_eq!(
            fixture.backend.list("a.", Some(&cursor1), 1, 256, 65_536, CURSOR_TTL, 0, now()).expect_err("cross prefix"),
            KvError::InvalidKey
        );
        // 伪造/未签发 token → invalid-key。
        assert_eq!(
            fixture.backend.list("c.", Some("018f6b1e-5c0a-7740-afbc-57a9016f2085"), 1, 256, 65_536, CURSOR_TTL, 0, now()).expect_err("forged"),
            KvError::InvalidKey
        );
        // 过期 → cursor-expired（不从开头重启）。
        assert_eq!(
            fixture.backend.list("c.", Some(&cursor1), 1, 256, 65_536, CURSOR_TTL, CURSOR_TTL, now()).expect_err("expired"),
            KvError::CursorExpired
        );
    }

    #[test]
    fn page_byte_cap_returns_bounded_page_and_first_oversize_item_rejects() {
        let (mut fixture, _dir) = fixture();
        fixture.backend.set("a.big", &[b'x'; 200], None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("big");
        fixture.backend.set("a.small", b"s", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("small");
        // 首个候选（a.big）单独超过 maxListBytes → limit-exceeded（裁决 2）。
        assert_eq!(
            fixture.backend.list("a.", None, 10, 256, 100, CURSOR_TTL, 0, now()).expect_err("first oversize"),
            KvError::LimitExceeded
        );
        // 字节上限之上的下一条 → 返回先前有界页 + 续游标。
        let (page, cursor) = fixture.backend.list("a.", None, 10, 256, 205, CURSOR_TTL, 0, now()).expect("bounded page");
        assert_eq!(page.len(), 1, "big item (5+200 bytes) fits alone at cap 205; small item exceeds the cap");
        assert_eq!(page[0].key, "a.big");
        assert!(cursor.is_some(), "a.small remains as continuation");
    }

    #[test]
    fn limit_ceiling_is_min_of_256_and_profile() {
        let (mut fixture, _dir) = fixture();
        assert_eq!(fixture.backend.list("a.", None, 0, 256, 65_536, CURSOR_TTL, 0, now()).expect_err("zero limit"), KvError::LimitExceeded);
        assert_eq!(fixture.backend.list("a.", None, 257, 256, 65_536, CURSOR_TTL, 0, now()).expect_err("over 256"), KvError::LimitExceeded);
        assert_eq!(fixture.backend.list("a.", None, 9, 8, 65_536, CURSOR_TTL, 0, now()).expect_err("over profile"), KvError::LimitExceeded);
        fixture.backend.list("a.", None, 8, 8, 65_536, CURSOR_TTL, 0, now()).expect("at profile ceiling");
    }

    #[test]
    fn tombstone_gc_is_conservative_while_cursors_live() {
        let (mut fixture, _dir) = fixture();
        for key in ["a.1", "a.2", "a.3"] {
            fixture.backend.set(key, b"v", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("seed");
        }
        fixture.backend.delete("a.1", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("tombstone");
        // 分页留下活跃 cursor（limit 1，两条可见匹配 → 续游标）。
        let (_page, cursor) = fixture.backend.list("a.", None, 1, 256, 65_536, CURSOR_TTL, 0, now()).expect("list");
        assert!(cursor.is_some(), "cursor live with more visible matches");
        // 活跃 cursor 存在：即使过了保留下限也不 GC。
        assert_eq!(fixture.backend.gc_tombstones(CURSOR_TTL, TTL, 10_000_000).expect("gc"), 0);
        // registry 清空（快照回收/无活跃引用证明）且过保留下限 → GC 恰好该 tombstone。
        fixture.backend.cursors.clear();
        fixture.backend.snapshots.clear();
        let removed = fixture.backend.gc_tombstones(CURSOR_TTL, TTL, 10 * (CURSOR_TTL + TTL)).expect("gc");
        assert_eq!(removed, 1, "retention floor passed and no live cursor");
        // GC 后旧 expected:1 的写因 key 缺席而 conflict（不复活已 GC 的版本线）。
        assert_eq!(
            fixture.backend.set("a.1", b"again", Some(1), &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect_err("expected on absent"),
            KvError::Conflict
        );
    }

    #[test]
    fn quarantined_backend_refuses_service() {
        let (mut fixture, _dir) = fixture();
        fixture.backend.quarantined = Some(WASMD_KV_BACKEND_INVALID);
        assert_eq!(fixture.backend.get("a", now()).expect_err("quarantined"), KvError::Unavailable);
        assert_eq!(
            fixture.backend.set("a", b"v", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect_err("quarantined"),
            KvError::Unavailable
        );
    }

    #[test]
    fn deadline_breach_times_out_before_work() {
        let (mut fixture, _dir) = fixture();
        let past = Instant::now() - std::time::Duration::from_secs(1);
        assert_eq!(fixture.backend.get("a", past).expect_err("deadline"), KvError::Timeout);
    }

    #[test]
    fn orphan_backend_marker_quarantines() {
        let (mut fixture, _dir) = fixture();
        fixture.backend.set("a", b"v", None, &mut fixture.ledger, ENVELOPE, CAP, OVERHEAD, TTL, 0, now()).expect("set");
        // marker 存在且 ledger 认识该 operation → 不 quarantine。
        let ledger_ids = fixture.ledger.known_operation_ids().expect("ids");
        fixture.backend.quarantine_on_orphan_marker(&ledger_ids);
        assert!(fixture.backend.quarantined.is_none());
        // 伪造「ledger 一无所知」→ quarantine。
        fixture.backend.quarantine_on_orphan_marker(&[]);
        assert_eq!(fixture.backend.quarantined, Some(WASMD_KV_BACKEND_INVALID));
    }
}
