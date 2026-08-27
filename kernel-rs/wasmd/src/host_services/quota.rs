//! 用户原始需求（2026-08-27，add-wasm-host-services 任务 4.2/4.6）：单一 quota
//! ledger（quota.sqlite3）承载 KV+SQL 共享 resources.storageBytes envelope 的两阶段
//! 写前判定——serialized reserve（committed + outstandingReserved + delta <= envelope
//! 与 service cap）、durable reservationProofDigest、backend operation marker 协调的
//! finalize/release、崩溃恢复扫描与 impossible-state quarantine。规范权威：design.md
//! §4 与 specs/wasm-application-runtime/spec.md「Host-service data uses one data-plane
//! quota authority outside control CAS」。
//!
//! 数据面法则：ledger 是数据面状态，绝不写 control state/admission proof/route/
//! readiness/journal/audit；mutation 不推进 controlRevision。reservedDeltaBytes 是
//! 触碰任何后端之前算出的有限保守上界；不可证明即 quota-exceeded（design §4
//! 「an over-limit or unprovable reservation changes no key, tombstone, SQL data」）。

use crate::host_services::policy::QUOTA_RESERVATION_HASH_DOMAIN_V2;
use crate::jcs::{digest_v2, jcs_bytes, validate_uuid_v7, WireError};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// quota ledger 稳定错误码（owner 诊断面；不含 payload）。
pub const WASMD_QUOTA_LEDGER_INVALID: &str = "WASMD_QUOTA_LEDGER_INVALID";

/// reserve/finalize 的对外结果分类（provider 映射到 WIT/host-call 错误）。
#[derive(Debug, Clone, PartialEq)]
pub enum QuotaError {
    /// 写前不等式不成立（envelope 或 service cap）——一切后端不变。
    Exceeded,
    /// ledger 锁等待超界。
    Busy,
    /// 不可证明/不可恢复的 ledger 状态（quarantine 候选）。
    Unavailable(String),
}

impl From<rusqlite::Error> for QuotaError {
    fn from(error: rusqlite::Error) -> Self {
        if matches!(error, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::DatabaseBusy || f.code == rusqlite::ErrorCode::DatabaseLocked) {
            QuotaError::Busy
        } else {
            QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())
        }
    }
}

impl From<WireError> for QuotaError {
    fn from(_: WireError) -> Self {
        QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())
    }
}

/// QuotaReservationV2 的 proof 输入（design §4 精确键集；state 恒 "reserved"、proof
/// 省略——digest 公式钉死「JCS(reservation with state:"reserved" and the proof omitted)」）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuotaReservationProofPayloadV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "reservationId")]
    pub reservation_id: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub backend: String,
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
    pub state: String,
}

/// ledger 内的一条 reservation（含 proof）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReservationRecordV2 {
    #[serde(rename = "reservationId")]
    pub reservation_id: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub backend: String,
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
    pub state: String,
    #[serde(rename = "reservationProofDigest")]
    pub reservation_proof_digest: String,
}

/// 用量快照（monitor 投影面；无 payload）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsageSnapshot {
    pub usage_revision: u64,
    pub committed_bytes: u64,
    pub kv_committed_bytes: u64,
    pub sql_committed_bytes: u64,
}

/// Host-call replay 的完整幂等键。
///
/// `request_id` 不是唯一键：同一 UUID 在不同执行身份上必须不能互相
/// 覆盖。`canonical_body` 保留原始 JCS 字节，digest 只作为索引/快速比较；
/// 所有字段都在 claim 事务内再次比较，避免把哈希碰撞当成相同请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayKeyV2 {
    pub request_id: String,
    pub canonical_body: Vec<u8>,
    pub service: String,
    pub method: String,
    pub identity_digest: String,
    pub policy_digest: String,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    pub fence_nonce: String,
}

/// Durable replay row exposed to the provider recovery coordinator.  The
/// canonical request body is retained so a response can be rebuilt after a
/// process restart without accepting a second backend operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecordV2 {
    pub key: ReplayKeyV2,
    pub operation_id: String,
    pub response_payload: Option<Vec<u8>>,
    pub outcome: String,
    pub state: String,
    pub expires_at: u64,
}

impl ReplayKeyV2 {
    /// Stable key digest over the complete tuple (not over a hex digest alone).
    pub fn key_digest(&self) -> Result<String, QuotaError> {
        let body_digest = crate::jcs::sha256_hex(&self.canonical_body);
        let projection = ReplayKeyProjectionV2 {
            schema_version: 2,
            request_id: &self.request_id,
            canonical_body_digest: &body_digest,
            service: &self.service,
            method: &self.method,
            identity_digest: &self.identity_digest,
            policy_digest: &self.policy_digest,
            preparation_generation: self.preparation_generation,
            execution_generation: self.execution_generation,
            fence_nonce: &self.fence_nonce,
        };
        let bytes = jcs_bytes(&projection).map_err(QuotaError::from)?;
        Ok(digest_v2(HOST_CALL_REPLAY_HASH_DOMAIN_V2, &bytes))
    }
}

#[derive(Serialize)]
struct ReplayKeyProjectionV2<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "requestId")]
    request_id: &'a str,
    #[serde(rename = "canonicalBodyDigest")]
    canonical_body_digest: &'a str,
    service: &'a str,
    method: &'a str,
    #[serde(rename = "identityDigest")]
    identity_digest: &'a str,
    #[serde(rename = "policyDigest")]
    policy_digest: &'a str,
    #[serde(rename = "preparationGeneration")]
    preparation_generation: u64,
    #[serde(rename = "executionGeneration")]
    execution_generation: u64,
    #[serde(rename = "fenceNonce")]
    fence_nonce: &'a str,
}

/// 原子 claim 的结果。`InFlight` 永远不能继续执行后端 mutation。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayClaimV2 {
    Claimed { operation_id: String },
    Completed { response_payload: Vec<u8>, outcome: String },
    InFlight,
    Conflict,
    Expired,
}

/// replay key 的 V2 hash domain。与 frame/policy/quota reservation domain 分开，
/// 防止把一段 payload 的 digest 误当成幂等键。
pub const HOST_CALL_REPLAY_HASH_DOMAIN_V2: &str = "iweb-wasm-host-call-v2";

/// 单一 quota ledger（quota.sqlite3；每应用一份，provider 独占）。
pub struct QuotaLedger {
    conn: Connection,
    application_id: String,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ledger_usage (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  usage_revision INTEGER NOT NULL,
  committed_bytes INTEGER NOT NULL,
  kv_committed_bytes INTEGER NOT NULL,
  sql_committed_bytes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_reservations (
  reservation_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  application_id TEXT NOT NULL,
  backend TEXT NOT NULL CHECK (backend IN ('kv','sql')),
  ledger_revision INTEGER NOT NULL,
  expected_usage_revision INTEGER NOT NULL,
  base_committed_bytes INTEGER NOT NULL,
  reserved_delta_bytes INTEGER NOT NULL,
  projected_committed_bytes INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved','committed','released')),
  proof_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_call_replay (
  replay_key TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  canonical_body BLOB NOT NULL,
  canonical_body_digest TEXT NOT NULL,
  service TEXT NOT NULL,
  method TEXT NOT NULL,
  identity_digest TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  preparation_generation INTEGER NOT NULL,
  execution_generation INTEGER NOT NULL,
  fence_nonce TEXT NOT NULL,
  operation_id TEXT NOT NULL UNIQUE,
  response_payload BLOB,
  outcome TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('claimed','ok','error')),
  claimed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS host_call_replay_request_idx ON host_call_replay (request_id);
";

impl QuotaLedger {
    /// 打开（或初始化）本应用的 ledger。connection 由调用方先行打开并加固。
    pub fn new(conn: Connection, application_id: &str) -> Result<Self, QuotaError> {
        conn.busy_timeout(Duration::from_millis(250))?;
        conn.execute_batch(SCHEMA)?;
        // Existing installations may have been created by the first hardening
        // pass.  Missing result columns are added explicitly; old markers with
        // NULL results are treated as unrecoverable rather than guessed.
        let _ = conn.execute("ALTER TABLE host_call_replay ADD COLUMN recovery_revision INTEGER NOT NULL DEFAULT 1", []);
        conn.execute(
            "INSERT OR IGNORE INTO ledger_usage (id, usage_revision, committed_bytes, kv_committed_bytes, sql_committed_bytes) VALUES (1, 0, 0, 0, 0)",
            [],
        )?;
        Ok(Self { conn, application_id: application_id.to_string() })
    }

    /// 宿主侧文件用量测量（page_count * page_size；保守口径，自由页同样计费）。
    pub fn measure_sqlite_file_bytes(conn: &Connection) -> Result<u64, QuotaError> {
        let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        if page_count < 0 || page_size <= 0 {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        Ok((page_count as u64) * (page_size as u64))
    }

    fn load_usage(&self) -> Result<UsageSnapshot, QuotaError> {
        self.conn
            .query_row(
                "SELECT usage_revision, committed_bytes, kv_committed_bytes, sql_committed_bytes FROM ledger_usage WHERE id = 1",
                [],
                |row| {
                    Ok(UsageSnapshot {
                        usage_revision: row.get::<_, i64>(0)?.max(0) as u64,
                        committed_bytes: row.get::<_, i64>(1)?.max(0) as u64,
                        kv_committed_bytes: row.get::<_, i64>(2)?.max(0) as u64,
                        sql_committed_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                    })
                },
            )
            .map_err(QuotaError::from)
    }

    /// 序列化两阶段第一步：写前原子证明。
    /// 不等式：committed + outstandingReserved + delta <= envelope 且
    /// backendCommitted + backendOutstandingReserved + delta <= serviceCapBytes。
    /// 任何输入不可证明（含 reservation TTL 非法）→ Exceeded，不触任何后端。
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        backend: &str,
        operation_id: &str,
        reserved_delta_bytes: u64,
        envelope_bytes: u64,
        service_cap_bytes: u64,
        now_ms: u64,
        reservation_ttl_ms: u64,
    ) -> Result<ReservationRecordV2, QuotaError> {
        if !matches!(backend, "kv" | "sql") {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        if reserved_delta_bytes == 0 || reservation_ttl_ms == 0 {
            return Err(QuotaError::Exceeded);
        }
        validate_uuid_v7(operation_id).map_err(|_| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?;
        let application_id = self.application_id.clone();
        // Reservations are the single serialized quota authority.  An
        // immediate transaction takes the write lock before reading usage so
        // two callers cannot both pass the same envelope check.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(QuotaError::from)?;
        let usage = {
            let mut statement = tx.prepare(
                "SELECT usage_revision, committed_bytes, kv_committed_bytes, sql_committed_bytes FROM ledger_usage WHERE id = 1",
            )?;
            statement
                .query_row([], |row| {
                    Ok(UsageSnapshot {
                        usage_revision: row.get::<_, i64>(0)?.max(0) as u64,
                        committed_bytes: row.get::<_, i64>(1)?.max(0) as u64,
                        kv_committed_bytes: row.get::<_, i64>(2)?.max(0) as u64,
                        sql_committed_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                    })
                })
                .map_err(QuotaError::from)?
        };
        // outstanding 只计未过期 reserved（「expired reservations are never charged」）。
        let (outstanding_total, outstanding_backend) = {
            let mut statement = tx.prepare(
                "SELECT COALESCE(SUM(reserved_delta_bytes),0),
                        COALESCE(SUM(CASE WHEN backend = ?1 THEN reserved_delta_bytes ELSE 0 END),0)
                 FROM ledger_reservations
                 WHERE state = 'reserved' AND expires_at > ?2",
            )?;
            statement
                .query_row(params![backend, now_ms as i64], |row| {
                    Ok((row.get::<_, i64>(0)?.max(0) as u64, row.get::<_, i64>(1)?.max(0) as u64))
                })
                .map_err(QuotaError::from)?
        };
        let projected_total = usage
            .committed_bytes
            .checked_add(outstanding_total)
            .and_then(|value| value.checked_add(reserved_delta_bytes))
            .ok_or(QuotaError::Exceeded)?;
        if projected_total > envelope_bytes {
            return Err(QuotaError::Exceeded);
        }
        let backend_committed = if backend == "kv" { usage.kv_committed_bytes } else { usage.sql_committed_bytes };
        let projected_backend = backend_committed
            .checked_add(outstanding_backend)
            .and_then(|value| value.checked_add(reserved_delta_bytes))
            .ok_or(QuotaError::Exceeded)?;
        if projected_backend > service_cap_bytes {
            return Err(QuotaError::Exceeded);
        }
        let ledger_revision: u64 = tx
            .query_row("SELECT COALESCE(MAX(ledger_revision),0) + 1 FROM ledger_reservations", [], |row| {
                row.get::<_, i64>(0).map(|v| v.max(1) as u64)
            })
            .map_err(QuotaError::from)?;
        let reservation_id = uuid::Uuid::now_v7().hyphenated().to_string();
        let expires_at = now_ms.checked_add(reservation_ttl_ms).ok_or(QuotaError::Exceeded)?;
        let proof_payload = QuotaReservationProofPayloadV2 {
            schema_version: 2,
            reservation_id: reservation_id.clone(),
            operation_id: operation_id.to_string(),
            application_id: application_id.clone(),
            backend: backend.to_string(),
            ledger_revision,
            expected_usage_revision: usage.usage_revision,
            base_committed_bytes: usage.committed_bytes,
            reserved_delta_bytes,
            projected_committed_bytes: projected_total,
            expires_at,
            state: "reserved".into(),
        };
        let proof_digest = digest_v2(
            QUOTA_RESERVATION_HASH_DOMAIN_V2,
            &jcs_bytes(&proof_payload).map_err(|_| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?,
        );
        tx.execute(
            "INSERT INTO ledger_reservations
             (reservation_id, operation_id, application_id, backend, ledger_revision,
              expected_usage_revision, base_committed_bytes, reserved_delta_bytes,
              projected_committed_bytes, expires_at, state, proof_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'reserved', ?11)",
            params![
                reservation_id,
                operation_id,
                application_id,
                backend,
                ledger_revision as i64,
                usage.usage_revision as i64,
                usage.committed_bytes as i64,
                reserved_delta_bytes as i64,
                projected_total as i64,
                expires_at as i64,
                proof_digest
            ],
        )
        .map_err(QuotaError::from)?;
        tx.commit().map_err(QuotaError::from)?;
        Ok(ReservationRecordV2 {
            reservation_id,
            operation_id: operation_id.to_string(),
            application_id,
            backend: backend.to_string(),
            ledger_revision,
            expected_usage_revision: usage.usage_revision,
            base_committed_bytes: usage.committed_bytes,
            reserved_delta_bytes,
            projected_committed_bytes: projected_total,
            expires_at,
            state: "reserved".into(),
            reservation_proof_digest: proof_digest,
        })
    }

    /// SQL mutation 的「预留全部剩余额度」模式：SQL 行增量不可静态预知，profile 又
    /// 未冻结独立预留字段——保守上界 = envelope − committed − outstanding（有限、
    /// 覆盖任意单语句增长；副作用是并发 mutation 经 ledger 串行化，与 design §4
    /// 「serialize reservations per application」一致）。剩余为 0 → Exceeded。
    pub fn reserve_remaining(
        &mut self,
        backend: &str,
        operation_id: &str,
        envelope_bytes: u64,
        now_ms: u64,
        reservation_ttl_ms: u64,
    ) -> Result<ReservationRecordV2, QuotaError> {
        if !matches!(backend, "kv" | "sql") {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        validate_uuid_v7(operation_id).map_err(|_| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?;
        let usage = self.load_usage()?;
        let outstanding: u64 = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(reserved_delta_bytes),0) FROM ledger_reservations WHERE state = 'reserved' AND expires_at > ?1",
                [now_ms as i64],
                |row| row.get::<_, i64>(0).map(|value| value.max(0) as u64),
            )
            .map_err(QuotaError::from)?;
        let delta = envelope_bytes
            .checked_sub(usage.committed_bytes)
            .and_then(|value| value.checked_sub(outstanding))
            .unwrap_or(0);
        if delta == 0 {
            return Err(QuotaError::Exceeded);
        }
        self.reserve(backend, operation_id, delta, envelope_bytes, envelope_bytes, now_ms, reservation_ttl_ms)
    }

    /// 两阶段第三步：backend commit 与 durability 成功后，以实测字节封口。
    /// measured_backend_bytes 是该 backend 文件的实测用量；总量按两 backend 实测和重算。
    pub fn finalize(&mut self, reservation: &ReservationRecordV2, measured_backend_bytes: u64) -> Result<(), QuotaError> {
        self.validate_reservation_record(reservation)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(QuotaError::from)?;
        let state: String = tx
            .query_row("SELECT state FROM ledger_reservations WHERE reservation_id = ?1", params![reservation.reservation_id], |row| row.get(0))
            .optional()
            .map_err(QuotaError::from)?
            .ok_or_else(|| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?;
        if state == "committed" {
            return Ok(()); // 幂等 replay：只封口一次。
        }
        if state != "reserved" {
            // released 携带已提交 marker 或 revision 回退：impossible ledger state。
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        let usage = {
            tx.query_row(
                "SELECT usage_revision, committed_bytes, kv_committed_bytes, sql_committed_bytes FROM ledger_usage WHERE id = 1",
                [],
                |row| {
                    Ok(UsageSnapshot {
                        usage_revision: row.get::<_, i64>(0)?.max(0) as u64,
                        committed_bytes: row.get::<_, i64>(1)?.max(0) as u64,
                        kv_committed_bytes: row.get::<_, i64>(2)?.max(0) as u64,
                        sql_committed_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                    })
                },
            )
            .map_err(QuotaError::from)?
        };
        if usage.usage_revision < reservation.expected_usage_revision {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())); // revision 回退，quarantine。
        }
        let (kv_bytes, sql_bytes) = if reservation.backend == "kv" {
            (measured_backend_bytes, usage.sql_committed_bytes)
        } else {
            (usage.kv_committed_bytes, measured_backend_bytes)
        };
        let committed_bytes = kv_bytes.checked_add(sql_bytes).ok_or(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?;
        tx.execute(
            "UPDATE ledger_reservations SET state = 'committed' WHERE reservation_id = ?1",
            params![reservation.reservation_id],
        )
        .map_err(QuotaError::from)?;
        tx.execute(
            "UPDATE ledger_usage SET usage_revision = usage_revision + 1, committed_bytes = ?1, kv_committed_bytes = ?2, sql_committed_bytes = ?3 WHERE id = 1",
            params![committed_bytes as i64, kv_bytes as i64, sql_bytes as i64],
        )
        .map_err(QuotaError::from)?;
        tx.commit().map_err(QuotaError::from)?;
        Ok(())
    }

    /// 释放未触碰后端的 reservation（backend 失败/过期恢复路径）。
    pub fn release(&mut self, reservation_id: &str) -> Result<(), QuotaError> {
        self.conn
            .execute(
                "UPDATE ledger_reservations SET state = 'released' WHERE reservation_id = ?1 AND state = 'reserved'",
                params![reservation_id],
            )
            .map_err(QuotaError::from)?;
        Ok(())
    }

    pub fn usage(&self) -> Result<UsageSnapshot, QuotaError> {
        self.load_usage()
    }

    /// 恢复扫描面 1：全部 open（reserved）reservation（provider 据后端 marker 分派）。
    pub fn open_reservations(&self) -> Result<Vec<ReservationRecordV2>, QuotaError> {
        let mut statement = self
            .conn
            .prepare("SELECT reservation_id, operation_id, application_id, backend, ledger_revision, expected_usage_revision, base_committed_bytes, reserved_delta_bytes, projected_committed_bytes, expires_at, state, proof_digest FROM ledger_reservations WHERE state = 'reserved'")
            .map_err(QuotaError::from)?;
        let rows = statement
            .query_map([], row_to_reservation)
            .map_err(QuotaError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuotaError::from)?;
        Ok(rows)
    }

    /// Read all host-call claims, including in-flight rows.  Recovery uses the
    /// stored canonical body and operation id to join the request to a backend
    /// marker; no payload is exposed to monitor callers.
    pub fn replay_records(&self) -> Result<Vec<ReplayRecordV2>, QuotaError> {
        let mut statement = self.conn.prepare(
            "SELECT request_id, canonical_body, canonical_body_digest, service, method,
                    identity_digest, policy_digest, preparation_generation,
                    execution_generation, fence_nonce, operation_id, response_payload,
                    outcome, state, expires_at
             FROM host_call_replay ORDER BY claimed_at ASC",
        )?;
        let rows = statement
            .query_map([], |row| {
                let request_id: String = row.get(0)?;
                let canonical_body: Vec<u8> = row.get(1)?;
                let canonical_body_digest: String = row.get(2)?;
                let service: String = row.get(3)?;
                let method: String = row.get(4)?;
                let identity_digest: String = row.get(5)?;
                let policy_digest: String = row.get(6)?;
                let preparation_generation = row.get::<_, i64>(7)?.max(0) as u64;
                let execution_generation = row.get::<_, i64>(8)?.max(0) as u64;
                let fence_nonce: String = row.get(9)?;
                let operation_id: String = row.get(10)?;
                let response_payload: Option<Vec<u8>> = row.get(11)?;
                let outcome: String = row.get(12)?;
                let state: String = row.get(13)?;
                let expires_at = row.get::<_, i64>(14)?.max(0) as u64;
                let key = ReplayKeyV2 {
                    request_id,
                    canonical_body,
                    service,
                    method,
                    identity_digest,
                    policy_digest,
                    preparation_generation,
                    execution_generation,
                    fence_nonce,
                };
                // Keep the digest in the row as a consistency check.  A
                // corrupted row is not silently reconstructed from the body.
                if crate::jcs::sha256_hex(&key.canonical_body) != canonical_body_digest {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(ReplayRecordV2 { key, operation_id, response_payload, outcome, state, expires_at })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuotaError::from)?;
        Ok(rows)
    }

    /// Release one in-flight claim after recovery has proved that no backend
    /// marker exists.  Terminal rows are immutable and cannot be deleted.
    pub fn release_replay_claim_by_operation_id(&mut self, operation_id: &str) -> Result<bool, QuotaError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(QuotaError::from)?;
        let changed = tx
            .execute(
                "DELETE FROM host_call_replay WHERE operation_id = ?1 AND state = 'claimed'",
                params![operation_id],
            )
            .map_err(QuotaError::from)?;
        tx.commit().map_err(QuotaError::from)?;
        Ok(changed == 1)
    }

    /// 恢复扫描面 2：全部已 released 的 reservation（若后端存在同 operation 的已提交
    /// marker，即 design「released with a committed marker」的 impossible state）。
    pub fn released_operation_ids(&self) -> Result<Vec<String>, QuotaError> {
        let mut statement = self
            .conn
            .prepare("SELECT operation_id FROM ledger_reservations WHERE state = 'released'")
            .map_err(QuotaError::from)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(QuotaError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuotaError::from)?;
        Ok(rows)
    }

    /// 恢复扫描面 3：ledger 已知全部 operationId（识别后端孤儿 marker）。
    pub fn known_operation_ids(&self) -> Result<Vec<String>, QuotaError> {
        let mut statement = self
            .conn
            .prepare("SELECT operation_id FROM ledger_reservations")
            .map_err(QuotaError::from)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(QuotaError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuotaError::from)?;
        Ok(rows)
    }

    /// Look up the reservation joined to a backend operation marker.  Recovery
    /// uses this to verify both reservationId and reservationProofDigest before
    /// accepting a marker as evidence of a committed mutation.
    pub fn reservation_for_operation(&self, operation_id: &str) -> Result<Option<ReservationRecordV2>, QuotaError> {
        self.conn
            .query_row(
                "SELECT reservation_id, operation_id, application_id, backend, ledger_revision,
                        expected_usage_revision, base_committed_bytes, reserved_delta_bytes,
                        projected_committed_bytes, expires_at, state, proof_digest
                 FROM ledger_reservations WHERE operation_id = ?1 ORDER BY ledger_revision DESC LIMIT 1",
                params![operation_id],
                row_to_reservation,
            )
            .optional()
            .map_err(QuotaError::from)
    }

    /// Validate the durable reservation and its proof before a backend marker
    /// is accepted as evidence of a committed operation.  A caller-provided
    /// reservation is never trusted merely because its id exists: every
    /// immutable field and the digest-domain payload must match the ledger.
    pub fn validate_reservation_record(&self, reservation: &ReservationRecordV2) -> Result<(), QuotaError> {
        if reservation.application_id != self.application_id
            || !matches!(reservation.backend.as_str(), "kv" | "sql")
            || !matches!(reservation.state.as_str(), "reserved" | "committed" | "released")
            || reservation.reserved_delta_bytes == 0
            || reservation.expires_at == 0
        {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        validate_uuid_v7(&reservation.reservation_id).map_err(|_| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?;
        validate_uuid_v7(&reservation.operation_id).map_err(|_| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?;
        let proof_payload = QuotaReservationProofPayloadV2 {
            schema_version: 2,
            reservation_id: reservation.reservation_id.clone(),
            operation_id: reservation.operation_id.clone(),
            application_id: reservation.application_id.clone(),
            backend: reservation.backend.clone(),
            ledger_revision: reservation.ledger_revision,
            expected_usage_revision: reservation.expected_usage_revision,
            base_committed_bytes: reservation.base_committed_bytes,
            reserved_delta_bytes: reservation.reserved_delta_bytes,
            projected_committed_bytes: reservation.projected_committed_bytes,
            expires_at: reservation.expires_at,
            state: "reserved".into(),
        };
        let expected_proof = digest_v2(
            QUOTA_RESERVATION_HASH_DOMAIN_V2,
            &jcs_bytes(&proof_payload).map_err(|_| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?,
        );
        if reservation.reservation_proof_digest != expected_proof {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        // Operation ids are intended to be one-to-one with reservations.  A
        // duplicate row is an impossible ledger state, even if one row looks
        // otherwise valid.
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_reservations WHERE operation_id = ?1",
                params![reservation.operation_id],
                |row| row.get(0),
            )
            .map_err(QuotaError::from)?;
        if count != 1 {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        let stored = self
            .reservation_for_operation(&reservation.operation_id)?
            .ok_or_else(|| QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()))?;
        let immutable_fields_match = stored.reservation_id == reservation.reservation_id
            && stored.operation_id == reservation.operation_id
            && stored.application_id == reservation.application_id
            && stored.backend == reservation.backend
            && stored.ledger_revision == reservation.ledger_revision
            && stored.expected_usage_revision == reservation.expected_usage_revision
            && stored.base_committed_bytes == reservation.base_committed_bytes
            && stored.reserved_delta_bytes == reservation.reserved_delta_bytes
            && stored.projected_committed_bytes == reservation.projected_committed_bytes
            && stored.expires_at == reservation.expires_at
            && stored.reservation_proof_digest == reservation.reservation_proof_digest;
        let state_transition_allowed = stored.state == reservation.state
            || (reservation.state == "reserved" && stored.state == "committed");
        if !immutable_fields_match || !state_transition_allowed {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // host-call replay（design §5：mutating 请求对 (identity, requestId)
    // at-most-once，identical replay 返回存储响应，changed bytes → conflict）。
    // -----------------------------------------------------------------

    /// 在一个 `BEGIN IMMEDIATE` 事务中 claim 一个 host-call。
    ///
    /// 事务同时完成“按 requestId 找既有行”和“插入不可覆盖 operation marker”；
    /// 两个并发调用最多一个得到 `Claimed`。同 requestId 的任一字段变化都只得到
    /// `Conflict`，绝不会删除、替换或重置既有 marker。不同完整身份可以合法地
    /// 重用 requestId；它们永远不会读取或接管另一身份的行。
    pub fn claim_replay(&mut self, key: &ReplayKeyV2, now_ms: u64, expires_at: u64) -> Result<ReplayClaimV2, QuotaError> {
        if key.canonical_body.is_empty() || expires_at <= now_ms {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        let replay_key = key.key_digest()?;
        let canonical_body_digest = crate::jcs::sha256_hex(&key.canonical_body);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(QuotaError::from)?;
        // Exact replay key is authoritative.  The request-id lookup below is
        // only a same-identity conflict check; it must never select a row from
        // another application/version/fence.
        let exact = tx
            .query_row(
                "SELECT replay_key, canonical_body, canonical_body_digest, service, method,
                        identity_digest, policy_digest, preparation_generation,
                        execution_generation, fence_nonce, operation_id, response_payload,
                        outcome, state, expires_at
                 FROM host_call_replay WHERE replay_key = ?1",
                params![replay_key],
                replay_row_from_row,
            )
            .optional()
            .map_err(QuotaError::from)?;
        let existing = match exact {
            Some(row) => Some(row),
            None => tx
                .query_row(
                    "SELECT replay_key, canonical_body, canonical_body_digest, service, method,
                            identity_digest, policy_digest, preparation_generation,
                            execution_generation, fence_nonce, operation_id, response_payload,
                            outcome, state, expires_at
                     FROM host_call_replay
                     WHERE request_id = ?1 AND identity_digest = ?2 AND policy_digest = ?3
                       AND preparation_generation = ?4 AND execution_generation = ?5 AND fence_nonce = ?6
                     ORDER BY claimed_at ASC LIMIT 1",
                    params![
                        key.request_id,
                        key.identity_digest,
                        key.policy_digest,
                        key.preparation_generation as i64,
                        key.execution_generation as i64,
                        key.fence_nonce,
                    ],
                    replay_row_from_row,
                )
                .optional()
                .map_err(QuotaError::from)?,
        };

        if let Some(row) = existing {
            let same = row.replay_key == replay_key
                && row.canonical_body == key.canonical_body
                && row.canonical_body_digest == canonical_body_digest
                && row.service == key.service
                && row.method == key.method
                && row.identity_digest == key.identity_digest
                && row.policy_digest == key.policy_digest
                && row.preparation_generation == key.preparation_generation
                && row.execution_generation == key.execution_generation
                && row.fence_nonce == key.fence_nonce;
            if !same {
                tx.commit().map_err(QuotaError::from)?;
                return Ok(ReplayClaimV2::Conflict);
            }
            if now_ms >= row.expires_at {
                tx.commit().map_err(QuotaError::from)?;
                return Ok(ReplayClaimV2::Expired);
            }
            let result = match row.state.as_str() {
                "claimed" => ReplayClaimV2::InFlight,
                "ok" | "error" => match row.response_payload {
                    Some(response_payload) => ReplayClaimV2::Completed { response_payload, outcome: row.outcome },
                    None => return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())),
                },
                _ => return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())),
            };
            tx.commit().map_err(QuotaError::from)?;
            return Ok(result);
        }

        let operation_id = uuid::Uuid::now_v7().hyphenated().to_string();
        tx.execute(
            "INSERT INTO host_call_replay
             (replay_key, request_id, canonical_body, canonical_body_digest, service, method,
              identity_digest, policy_digest, preparation_generation, execution_generation,
              fence_nonce, operation_id, response_payload, outcome, state, claimed_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, 'in-flight', 'claimed', ?13, ?14)",
            params![
                replay_key,
                key.request_id,
                key.canonical_body,
                canonical_body_digest,
                key.service,
                key.method,
                key.identity_digest,
                key.policy_digest,
                key.preparation_generation as i64,
                key.execution_generation as i64,
                key.fence_nonce,
                operation_id,
                now_ms as i64,
                expires_at as i64,
            ],
        )
        .map_err(QuotaError::from)?;
        tx.commit().map_err(QuotaError::from)?;
        Ok(ReplayClaimV2::Claimed { operation_id })
    }

    /// 将 claim 原子转换为不可覆盖的终态响应。`response_payload` 是完整的
    /// response-frame JCS body，而非只存业务结果，保证重放字节完全一致。
    pub fn complete_replay(
        &mut self,
        key: &ReplayKeyV2,
        operation_id: &str,
        response_payload: &[u8],
        outcome: &str,
    ) -> Result<(), QuotaError> {
        if !matches!(outcome, "ok" | "error") || response_payload.is_empty() {
            return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into()));
        }
        let replay_key = key.key_digest()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(QuotaError::from)?;
        let state: Option<(String, Option<Vec<u8>>, String)> = tx
            .query_row(
                "SELECT state, response_payload, outcome FROM host_call_replay WHERE replay_key = ?1 AND operation_id = ?2",
                params![replay_key, operation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(QuotaError::from)?;
        match state {
            Some((state, _old_response, _old_outcome)) if state == "claimed" => {
                tx.execute(
                    "UPDATE host_call_replay SET response_payload = ?1, outcome = ?2, state = ?3
                     WHERE replay_key = ?4 AND operation_id = ?5 AND state = 'claimed'",
                    params![response_payload, outcome, outcome, replay_key, operation_id],
                )
                .map_err(QuotaError::from)?;
            }
            Some((state, Some(old_response), old_outcome))
                if (state == "ok" || state == "error") && old_response == response_payload && old_outcome == outcome => {}
            Some(_) => return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())),
            None => return Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())),
        }
        tx.commit().map_err(QuotaError::from)
    }

    /// 仅供恢复路径在确认没有 backend marker 后释放在途 claim；不会覆盖终态。
    pub fn release_replay_claim(&mut self, key: &ReplayKeyV2, operation_id: &str) -> Result<bool, QuotaError> {
        let replay_key = key.key_digest()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(QuotaError::from)?;
        let changed = tx
            .execute(
                "DELETE FROM host_call_replay WHERE replay_key = ?1 AND operation_id = ?2 AND state = 'claimed'",
                params![replay_key, operation_id],
            )
            .map_err(QuotaError::from)?;
        tx.commit().map_err(QuotaError::from)?;
        Ok(changed == 1)
    }

    /// 恢复/监控读取在途 claim（不返回请求 payload 之外的秘密；调用方只使用
    /// operationId 做 marker 关联）。
    pub fn in_flight_replay_operation_ids(&self) -> Result<Vec<String>, QuotaError> {
        let mut statement = self.conn.prepare("SELECT operation_id FROM host_call_replay WHERE state = 'claimed'")?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(QuotaError::from)?;
        Ok(rows)
    }

    /// 兼容旧的 ledger 单元测试/诊断调用：通过同一 claim+complete 原子路径写入，
    /// 绝不使用可覆盖 INSERT。生产 provider 使用 `claim_replay` 直接传完整 key。
    #[allow(clippy::too_many_arguments)]
    pub fn record_replay(
        &mut self,
        request_id: &str,
        identity_digest: &str,
        method: &str,
        payload_digest: &str,
        response_payload: &[u8],
        outcome: &str,
        expires_at: u64,
    ) -> Result<(), QuotaError> {
        let (service, method_name) = method.split_once(':').unwrap_or(("unknown", method));
        let key = ReplayKeyV2 {
            request_id: request_id.to_string(),
            canonical_body: payload_digest.as_bytes().to_vec(),
            service: service.to_string(),
            method: method_name.to_string(),
            identity_digest: identity_digest.to_string(),
            policy_digest: identity_digest.to_string(),
            preparation_generation: 1,
            execution_generation: 1,
            fence_nonce: "0".repeat(32),
        };
        match self.claim_replay(&key, expires_at.saturating_sub(1), expires_at)? {
            ReplayClaimV2::Claimed { operation_id } => self.complete_replay(&key, &operation_id, response_payload, outcome),
            ReplayClaimV2::Completed { response_payload: existing, outcome: existing_outcome }
                if existing == response_payload && existing_outcome == outcome => Ok(()),
            _ => Err(QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())),
        }
    }

    /// 旧查询投影；生产路径应使用 `claim_replay`，它不会暴露半完成 marker。
    #[allow(clippy::type_complexity)]
    pub fn lookup_replay(&self, request_id: &str, now_ms: u64) -> Result<Option<(String, Vec<u8>, bool)>, QuotaError> {
        let row = self.conn.query_row(
            "SELECT canonical_body_digest, response_payload, expires_at, state FROM host_call_replay WHERE request_id = ?1 ORDER BY claimed_at DESC LIMIT 1",
            params![request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?)),
        ).optional().map_err(QuotaError::from)?;
        match row {
            Some((digest, Some(response), expires_at, state)) if state == "ok" || state == "error" => Ok(Some((digest, response, expires_at.max(0) as u64 <= now_ms))),
            Some((_digest, None, expires_at, _)) => Ok(Some((String::new(), Vec::new(), expires_at.max(0) as u64 <= now_ms))),
            Some((digest, Some(response), expires_at, _)) => Ok(Some((digest, response, expires_at.max(0) as u64 <= now_ms))),
            None => Ok(None),
        }
    }
}

struct ReplayRow {
    replay_key: String,
    canonical_body: Vec<u8>,
    canonical_body_digest: String,
    service: String,
    method: String,
    identity_digest: String,
    policy_digest: String,
    preparation_generation: u64,
    execution_generation: u64,
    fence_nonce: String,
    _operation_id: String,
    response_payload: Option<Vec<u8>>,
    outcome: String,
    state: String,
    expires_at: u64,
}

fn replay_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReplayRow> {
    Ok(ReplayRow {
        replay_key: row.get(0)?,
        canonical_body: row.get(1)?,
        canonical_body_digest: row.get(2)?,
        service: row.get(3)?,
        method: row.get(4)?,
        identity_digest: row.get(5)?,
        policy_digest: row.get(6)?,
        preparation_generation: row.get::<_, i64>(7)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        execution_generation: row.get::<_, i64>(8)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        fence_nonce: row.get(9)?,
        _operation_id: row.get(10)?,
        response_payload: row.get(11)?,
        outcome: row.get(12)?,
        state: row.get(13)?,
        expires_at: row.get::<_, i64>(14)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn row_to_reservation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReservationRecordV2> {
    Ok(ReservationRecordV2 {
        reservation_id: row.get(0)?,
        operation_id: row.get(1)?,
        application_id: row.get(2)?,
        backend: row.get(3)?,
        ledger_revision: row.get::<_, i64>(4)?.max(0) as u64,
        expected_usage_revision: row.get::<_, i64>(5)?.max(0) as u64,
        base_committed_bytes: row.get::<_, i64>(6)?.max(0) as u64,
        reserved_delta_bytes: row.get::<_, i64>(7)?.max(0) as u64,
        projected_committed_bytes: row.get::<_, i64>(8)?.max(0) as u64,
        expires_at: row.get::<_, i64>(9)?.max(0) as u64,
        state: row.get(10)?,
        reservation_proof_digest: row.get(11)?,
    })
}

/// 纯函数：写前不等式（与 contracts checkIwebKvWriteQuota 同式；不可证明即拒绝）。
pub fn check_write_quota(
    committed_bytes: u64,
    outstanding_reserved_bytes: u64,
    reserved_delta_bytes: u64,
    aggregate_envelope_bytes: u64,
    backend_committed_bytes: u64,
    backend_service_cap_bytes: u64,
) -> Result<u64, QuotaError> {
    let projected = committed_bytes
        .checked_add(outstanding_reserved_bytes)
        .and_then(|value| value.checked_add(reserved_delta_bytes))
        .ok_or(QuotaError::Exceeded)?;
    if projected > aggregate_envelope_bytes {
        return Err(QuotaError::Exceeded);
    }
    let backend_projected = backend_committed_bytes
        .checked_add(outstanding_reserved_bytes)
        .and_then(|value| value.checked_add(reserved_delta_bytes))
        .ok_or(QuotaError::Exceeded)?;
    if backend_projected > backend_service_cap_bytes {
        return Err(QuotaError::Exceeded);
    }
    Ok(projected)
}



#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> QuotaLedger {
        QuotaLedger::new(Connection::open_in_memory().expect("memory db"), "alpha").expect("ledger")
    }

    #[test]
    fn reserve_respects_envelope_and_service_cap_atomically() {
        let mut ledger = ledger();
        let envelope = 10_000;
        let first = ledger.reserve("kv", &uuid::Uuid::now_v7().hyphenated().to_string(), 4_000, envelope, 10_000, 0, 60_000).expect("first reserve");
        assert_eq!(first.state, "reserved");
        assert_eq!(first.reserved_delta_bytes, 4_000);
        // envelope：outstanding 4k + delta 7k > 10k → 拒绝。
        let second = ledger.reserve("sql", &uuid::Uuid::now_v7().hyphenated().to_string(), 7_000, envelope, 10_000, 0, 60_000);
        assert_eq!(second.expect_err("envelope"), QuotaError::Exceeded);
        // service cap：kv cap 5k，outstanding 4k + delta 2k > 5k → 拒绝（envelope 允许）。
        let third = ledger.reserve("kv", &uuid::Uuid::now_v7().hyphenated().to_string(), 2_000, envelope, 5_000, 0, 60_000);
        assert_eq!(third.expect_err("service cap"), QuotaError::Exceeded);
        // finalize 封口后 outstanding 归零（kv 实测 4k，cap 5k → 仍可再预留 1k）。
        ledger.finalize(&first, 4_000).expect("finalize");
        assert_eq!(ledger.usage().expect("usage").committed_bytes, 4_000);
        let fourth = ledger.reserve("kv", &uuid::Uuid::now_v7().hyphenated().to_string(), 1_000, envelope, 5_000, 0, 60_000);
        fourth.expect("outstanding cleared after finalize");
    }

    #[test]
    fn expired_reservations_are_never_charged() {
        let mut ledger = ledger();
        let now = 1_000_000;
        let ttl = 60_000;
        let first = ledger.reserve("kv", &uuid::Uuid::now_v7().hyphenated().to_string(), 9_000, 10_000, 10_000, now, ttl).expect("reserve");
        // 时间前进到过期之后：outstanding 不再计费，可再预留。
        let second = ledger.reserve("sql", &uuid::Uuid::now_v7().hyphenated().to_string(), 9_000, 10_000, 10_000, now + ttl + 1, ttl);
        second.expect("expired reservation is not charged");
        // 过期预留随后可被释放（恢复路径）。
        ledger.release(&first.reservation_id).expect("release");
    }

    #[test]
    fn finalize_is_idempotent_and_rejects_impossible_state() {
        let mut ledger = ledger();
        let reservation = ledger.reserve("kv", &uuid::Uuid::now_v7().hyphenated().to_string(), 100, 10_000, 10_000, 0, 60_000).expect("reserve");
        ledger.finalize(&reservation, 512).expect("first finalize");
        ledger.finalize(&reservation, 512).expect("second finalize is idempotent");
        // released 之后 finalize → impossible state。
        let other = ledger.reserve("kv", &uuid::Uuid::now_v7().hyphenated().to_string(), 100, 10_000, 10_000, 0, 60_000).expect("reserve");
        ledger.release(&other.reservation_id).expect("release");
        assert_eq!(
            ledger.finalize(&other, 512).expect_err("released finalize"),
            QuotaError::Unavailable(WASMD_QUOTA_LEDGER_INVALID.into())
        );
    }

    #[test]
    fn reservation_proof_digest_recomputes() {
        let mut ledger = ledger();
        let reservation = ledger.reserve("kv", &uuid::Uuid::now_v7().hyphenated().to_string(), 1_000, 10_000, 10_000, 5_000, 60_000).expect("reserve");
        let payload = QuotaReservationProofPayloadV2 {
            schema_version: 2,
            reservation_id: reservation.reservation_id.clone(),
            operation_id: reservation.operation_id.clone(),
            application_id: reservation.application_id.clone(),
            backend: reservation.backend.clone(),
            ledger_revision: reservation.ledger_revision,
            expected_usage_revision: reservation.expected_usage_revision,
            base_committed_bytes: reservation.base_committed_bytes,
            reserved_delta_bytes: reservation.reserved_delta_bytes,
            projected_committed_bytes: reservation.projected_committed_bytes,
            expires_at: reservation.expires_at,
            state: "reserved".into(),
        };
        let expected = digest_v2(QUOTA_RESERVATION_HASH_DOMAIN_V2, &jcs_bytes(&payload).expect("jcs"));
        assert_eq!(reservation.reservation_proof_digest, expected);
    }

    #[test]
    fn replay_lookup_reports_expiry() {
        let mut ledger = ledger();
        let request_id = uuid::Uuid::now_v7().hyphenated().to_string();
        ledger.record_replay(&request_id, "identity", "kv:set", "digest", b"resp", "ok", 1_000).expect("record");
        let (_, _, expired) = ledger.lookup_replay(&request_id, 500).expect("lookup").expect("present");
        assert!(!expired);
        let (_, _, expired) = ledger.lookup_replay(&request_id, 1_000).expect("lookup").expect("present");
        assert!(expired, "boundary is inclusive (fail-closed)");
        assert!(ledger.lookup_replay(&uuid::Uuid::now_v7().hyphenated().to_string(), 0).expect("lookup").is_none());
    }

    fn replay_key(request_id: &str) -> ReplayKeyV2 {
        ReplayKeyV2 {
            request_id: request_id.into(),
            canonical_body: br#"{"requestId":"same","service":"kv","method":"set"}"#.to_vec(),
            service: "kv".into(),
            method: "set".into(),
            identity_digest: "aa".repeat(32),
            policy_digest: "bb".repeat(32),
            preparation_generation: 4,
            execution_generation: 9,
            fence_nonce: "cc".repeat(16),
        }
    }

    #[test]
    fn replay_claim_is_atomic_and_binds_every_identity_dimension() {
        let mut ledger = ledger();
        let request_id = uuid::Uuid::now_v7().hyphenated().to_string();
        let key = replay_key(&request_id);
        let first = ledger.claim_replay(&key, 100, 10_000).expect("first claim");
        let operation_id = match first {
            ReplayClaimV2::Claimed { operation_id } => operation_id,
            other => panic!("expected claim, got {other:?}"),
        };
        assert!(matches!(ledger.claim_replay(&key, 101, 10_001).expect("second claim"), ReplayClaimV2::InFlight));

        // 同 requestId 但 method/body/identity/P-E/fence 任一变化，都只能冲突，
        // 不能接管第一条 operation marker。
        for (index, changed) in [
            {
                let mut value = key.clone();
                value.method = "delete".into();
                value
            },
            {
                let mut value = key.clone();
                value.canonical_body = br#"{"requestId":"same","service":"kv","method":"set","changed":true}"#.to_vec();
                value
            },
            {
                let mut value = key.clone();
                value.identity_digest = "dd".repeat(32);
                value
            },
            {
                let mut value = key.clone();
                value.policy_digest = "ee".repeat(32);
                value
            },
            {
                let mut value = key.clone();
                value.execution_generation += 1;
                value
            },
            {
                let mut value = key.clone();
                value.fence_nonce = "ff".repeat(16);
                value
            },
        ]
        .into_iter()
        .enumerate()
        {
            let result = ledger.claim_replay(&changed, 102 + index as u64, 10_002 + index as u64).expect("claim");
            if index < 2 {
                assert!(matches!(result, ReplayClaimV2::Conflict));
            } else {
                // A distinct identity/fence is a distinct idempotency key;
                // it must not borrow the first operation's marker.
                assert!(matches!(result, ReplayClaimV2::Claimed { .. }));
            }
        }

        let response = br#"{"response":true}"#;
        ledger.complete_replay(&key, &operation_id, response, "ok").expect("complete");
        match ledger.claim_replay(&key, 103, 10_003).expect("terminal replay") {
            ReplayClaimV2::Completed { response_payload, outcome } => {
                assert_eq!(response_payload, response);
                assert_eq!(outcome, "ok");
            }
            other => panic!("expected terminal replay, got {other:?}"),
        }
        // operation marker 不可被第二次 complete 覆盖。
        assert!(ledger.complete_replay(&key, &operation_id, br#"{"other":true}"#, "ok").is_err());
    }

    #[test]
    fn expired_or_inflight_claims_never_execute_a_second_operation() {
        let mut ledger = ledger();
        let key = replay_key(&uuid::Uuid::now_v7().hyphenated().to_string());
        let first = ledger.claim_replay(&key, 1_000, 2_000).expect("claim");
        assert!(matches!(first, ReplayClaimV2::Claimed { .. }));
        assert!(matches!(ledger.claim_replay(&key, 2_000, 3_000).expect("expired"), ReplayClaimV2::Expired));
    }
}
