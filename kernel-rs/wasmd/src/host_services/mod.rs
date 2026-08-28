//! 用户原始需求（2026-08-27，add-wasm-host-services 任务 5.1/5.4/5.5/5.6）：
//! embedded-host-services-v2 provider——三个 host import（iweb:kv@1.0.0/store、
//! iweb:sql@1.0.0/store、iweb:logging@1.0.0/logger）的 bindgen 宿主实现、每次调用
//! 注入 execution identity（applicationId/versionId/P/E/fenceNonce，来自 argv；
//! 组件不可提供或替换）、跨身份/跨策略/过期代次拒绝、canonical host-call v2 frame
//! 入口（身份门 + requestId at-most-once replay + deadline）、per-app 数据目录与
//! 恢复扫描。规范权威：design.md §5/§7 与 specs/wasm-application-runtime/spec.md
//! 「Embedded host-call transport binds identity and has stable replay semantics」。
//!
//! WIT bindgen 锚点 world = iweb:host/host-service-imports（wit/host.wit）；包本体在
//! wit/deps（逐字节来自 packages/contracts/wit，除三处已注释的语法修正）。
//!
//! epoch 上界：WIT 路径的每次 host call 预算 = min(服务 profile 上限, 本请求 Store
//! epoch deadline 剩余)；SQL 在 SQLite progress checkpoint 上观测该 deadline，长语句
//! 可中断（spec「Cancellation is a host-owned token observed before allocation and at
//! SQLite progress checkpoints」）。
//!
//! 复审 P0-1/P0-2（2026-08-28）：
//! - P0-1：WIT bindgen Host impl（kv/sql/logging）全部经 dispatch_wit_frame——构造
//!   canonical HostCallFrameRequestV2 → dispatch_frame（原子 claim/replay/身份门 →
//!   后端）→ 反解响应帧。requestId 为宿主自动 UUIDv7：WIT 路径的 at-most-once 粒度
//!   是调用级而非 requestId 级（取舍详注 dispatch_wit_frame）。mutating 后端效果只在
//!   claim 内发生（claim-free 写入口已删除）；logging claim 的 operationId 以宿主注入
//!   字段盖进保留事件，恢复路径按 service 分派（logging 无 marker 构造性释放、
//!   kv/sql 无凭证不释放）。
//! - P0-2：HostCallExecutionIdentity 扩为完整身份类型（application/version、catalog
//!   与 capability pin、policyDigest、P/E/fence）；open 以 argv@2 的 WasmdIdentityV2
//!   （含 applicationId）与 context 做相等交叉校验，错绑 fail-closed。

pub mod frame;
pub mod kv;
pub mod logging;
pub mod policy;
pub mod quota;
pub mod sql;

use crate::jcs::{err, jcs_bytes, parse_canonical, sha256_hex, WireError};
use crate::wire::{WasmdIdentityV2, MATRIX_HOST_ABI_V2};
use frame::{
    decode_base64url, encode_base64url, FrameExecutionV2, HostCallErrorV2, HostCallFrameRequestV2,
    HostCallFrameResponseV2, HOST_CALL_DEADLINE_MAX_MS,
};
use policy::{HostServicePolicyV2, WasmdHostServicesContextV2};
use quota::{QuotaLedger, ReplayClaimV2, ReplayKeyV2};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wasmtime::component::bindgen;

bindgen!({
    path: "wit",
    world: "iweb:host/host-service-imports",
    // 宿主实现走可捕获错误路径（Host trait 返回 Result）。
    imports: { default: trappable },
});

/// provider 打开失败稳定码（目录/权限/后端初始化/恢复扫描失败；fail-closed）。
pub const WASMD_HOST_SERVICES_OPEN_FAILED: &str = "WASMD_HOST_SERVICES_OPEN_FAILED";

/// per-app 数据目录根（design §3 逐字：/data/kernel/wasm-data/<applicationId>/；
/// 无环境变量/路径参数可重定向——测试经 HostServicesProvider::open 的 root 参数注入）。
pub const HOST_SERVICES_DATA_ROOT: &str = "/data/kernel/wasm-data";

/// 注入的执行身份（design §5 execution 对象；supervisor 独占生成，组件不可伪造）。
/// 复审 P0-2（2026-08-28）：扩为完整身份类型——applicationId/versionId、catalog
/// revision+hash、capability revision+hash、policyDigest、P/E 双代次与 fenceNonce
/// 全部进身份；replay 身份摘要覆盖全部字段。第三轮复审（2026-08-28）：帧 wire
///（FrameExecutionV2）同步扩为完整身份面——帧绑全集，dispatch_frame 与注入身份
/// 逐字段相等校验（不再存在「帧绑子集、provider 绑全集」的半绑定形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCallExecutionIdentity {
    pub application_id: String,
    pub version_id: String,
    pub catalog_revision: u64,
    pub catalog_hash: String,
    pub capability_revision: u64,
    pub capability_hash: String,
    pub policy_digest: String,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    pub fence_nonce: String,
}

impl HostCallExecutionIdentity {
    pub fn to_frame(&self) -> FrameExecutionV2 {
        FrameExecutionV2 {
            application_id: self.application_id.clone(),
            version_id: self.version_id.clone(),
            catalog_revision: self.catalog_revision,
            catalog_hash: self.catalog_hash.clone(),
            capability_record_revision: self.capability_revision,
            capability_record_hash: self.capability_hash.clone(),
            host_service_policy_digest: self.policy_digest.clone(),
            preparation_generation: self.preparation_generation,
            execution_generation: self.execution_generation,
            fence_nonce: self.fence_nonce.clone(),
        }
    }

    /// 帧身份与注入身份的逐字段相等（完整身份面；任何字段偏差都是 IDENTITY_MISMATCH）。
    fn matches_frame(&self, frame: &FrameExecutionV2) -> bool {
        frame.application_id == self.application_id
            && frame.version_id == self.version_id
            && frame.catalog_revision == self.catalog_revision
            && frame.catalog_hash == self.catalog_hash
            && frame.capability_record_revision == self.capability_revision
            && frame.capability_record_hash == self.capability_hash
            && frame.host_service_policy_digest == self.policy_digest
            && frame.preparation_generation == self.preparation_generation
            && frame.execution_generation == self.execution_generation
            && frame.fence_nonce == self.fence_nonce
    }
}

/// unix 毫秒时钟（host 侧唯一时间源；cursor/marker/replay 计量共用）。
pub fn unix_now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0)
}

/// UTC ISO-8601 毫秒精度（Z 后缀；logging timestampUtc 的宿主注入形态）。
pub fn format_utc_timestamp(now: SystemTime) -> String {
    let millis = now.duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0);
    let seconds = millis / 1_000;
    let millisecond = millis % 1_000;
    let days = (seconds / 86_400) as i64;
    let secs_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millisecond:03}Z",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60
    )
}

/// Howard Hinnant civil_from_days（无 chrono 依赖的确定性日历）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

// ---------------------------------------------------------------------------
// embedded provider
// ---------------------------------------------------------------------------

/// embedded-host-services-v2 provider（每应用一份；宿主进程内独占后端连接）。
pub struct HostServicesProvider {
    identity: HostCallExecutionIdentity,
    policy: HostServicePolicyV2,
    policy_digest_hex: String,
    data_dir: PathBuf,
    quota: Mutex<QuotaLedger>,
    kv: Option<Mutex<kv::KvBackend>>,
    sql: Option<Mutex<sql::SqlBackend>>,
    ring: Mutex<logging::LoggingRing>,
    forwarding: logging::ForwardingConfig,
}

#[derive(Debug, Clone)]
enum BackendOperationMarker {
    Kv(kv::KvOperationMarker),
    Sql(sql::SqlOperationMarker),
}

impl BackendOperationMarker {
    fn operation_id(&self) -> &str {
        match self {
            Self::Kv(marker) => &marker.operation_id,
            Self::Sql(marker) => &marker.operation_id,
        }
    }

    fn reservation_id(&self) -> &str {
        match self {
            Self::Kv(marker) => &marker.reservation_id,
            Self::Sql(marker) => &marker.reservation_id,
        }
    }

    fn proof_digest(&self) -> &str {
        match self {
            Self::Kv(marker) => &marker.proof_digest,
            Self::Sql(marker) => &marker.proof_digest,
        }
    }

    fn backend(&self) -> &'static str {
        match self {
            Self::Kv(_) => "kv",
            Self::Sql(_) => "sql",
        }
    }
}

impl HostServicesProvider {
    /// 打开（或恢复）本应用的 host-service 数据面：
    /// root/<applicationId>/（0700、无 symlink）下的 kv/sql/quota sqlite3 文件
    /// （0600）。恢复扫描失败按 design §4 表分派（release/finalize/quarantine）。
    ///
    /// P0-2：identity 是 argv@2 的 WasmdIdentityV2（含 applicationId）——与 context
    /// 的 applicationId 做相等交叉校验；两 argv 元素错绑（分属不同应用）在打开即
    /// fail-closed，绝不以 context 或 identity 单侧派生数据目录。
    pub fn open(
        context: &WasmdHostServicesContextV2,
        identity: &WasmdIdentityV2,
        data_root: &Path,
        forwarding: logging::ForwardingConfig,
    ) -> Result<Self, WireError> {
        context.validate()?;
        if context.application_id != identity.application_id {
            return Err(err(
                WASMD_HOST_SERVICES_OPEN_FAILED,
                "host-services context applicationId must equal the identity tuple applicationId (argv cross-bind failed)",
            ));
        }
        identity.validate_with_host_abi(MATRIX_HOST_ABI_V2)
            .map_err(|error| err(WASMD_HOST_SERVICES_OPEN_FAILED, error.detail))?;
        forwarding.validate().map_err(|error| err(WASMD_HOST_SERVICES_OPEN_FAILED, error.detail))?;
        let policy = context.host_service_policy.clone();
        let policy_digest_hex = policy.policy_digest.clone();
        let application_id = context.application_id.clone();
        // 目录派生只来自 Kernel application identity（grammar 已验证；无 caller path）。
        let app_dir = data_root.join(&application_id);
        create_private_directory(&app_dir)?;

        let quota_path = app_dir.join("quota.sqlite3");
        let kv_path = app_dir.join("kv.sqlite3");
        let sql_path = app_dir.join("sql.sqlite3");
        let quota_conn = open_private_database(&quota_path)?;
        let ledger = QuotaLedger::new(quota_conn, &application_id)
            .map_err(|_| err(WASMD_HOST_SERVICES_OPEN_FAILED, "quota ledger initialization failed"))?;

        let kv_backend = match &policy.payload.host_services.kv {
            Some(member) => {
                let conn = open_private_database(&kv_path)?;
                let mut backend = kv::KvBackend::new(conn, &application_id, &policy_digest_hex)
                    .map_err(|_| err(WASMD_HOST_SERVICES_OPEN_FAILED, "kv backend initialization failed"))?;
                let _ = backend.gc_tombstones(member.limits.cursor_ttl_ms, policy::HOST_CALL_REPLAY_TTL_MS, unix_now_ms());
                Some(Mutex::new(backend))
            }
            None => None,
        };
        let sql_backend = match &policy.payload.host_services.sql {
            Some(_) => {
                let conn = open_private_database(&sql_path)?;
                let backend = sql::SqlBackend::new(conn)
                    .map_err(|_| err(WASMD_HOST_SERVICES_OPEN_FAILED, "sql backend initialization failed"))?;
                Some(Mutex::new(backend))
            }
            None => None,
        };
        let ring = match &policy.payload.host_services.logging {
            Some(member) => logging::LoggingRing::new(
                &application_id,
                logging::RingCapacity { max_events: member.limits.ring_max_events as usize, max_bytes: member.limits.ring_max_bytes },
            )
            .map_err(|_| err(WASMD_HOST_SERVICES_OPEN_FAILED, "logging ring initialization failed"))?,
            None => logging::LoggingRing::new(&application_id, logging::RingCapacity { max_events: 1, max_bytes: 1 })
                .map_err(|_| err(WASMD_HOST_SERVICES_OPEN_FAILED, "logging ring initialization failed"))?,
        };

        let identity_tuple = HostCallExecutionIdentity {
            application_id: application_id.clone(),
            version_id: identity.version_id.clone(),
            catalog_revision: identity.runtime_binding.catalog_revision,
            catalog_hash: identity.runtime_binding.catalog_hash.clone(),
            capability_revision: identity.capability_record_revision,
            capability_hash: identity.capability_record_hash.clone(),
            policy_digest: policy_digest_hex.clone(),
            preparation_generation: identity.preparation_generation,
            execution_generation: identity.execution_generation,
            fence_nonce: context.fence_nonce.clone(),
        };
        let mut provider = Self {
            identity: identity_tuple,
            policy,
            policy_digest_hex,
            data_dir: app_dir,
            quota: Mutex::new(ledger),
            kv: kv_backend,
            sql: sql_backend,
            ring: Mutex::new(ring),
            forwarding,
        };
        provider.recover(unix_now_ms())?;
        Ok(provider)
    }

    /// 崩溃恢复扫描（design §4 恢复表）：
    /// - reserved 无 marker：过期即 release（未过期视为在飞，保留）；
    /// - reserved 有 marker：重算用量并恰好 finalize 一次；
    /// - released 携带已提交 marker / 孤儿 marker（后端有 ledger 无）：quarantine。
    fn recover(&mut self, now_ms: u64) -> Result<(), WireError> {
        let open_fail = |detail: &str| err(WASMD_HOST_SERVICES_OPEN_FAILED, detail);

        // Never hold the quota lock while acquiring a backend lock.  Normal
        // writes use backend -> quota, so recovery first snapshots ledger rows,
        // then performs each backend read in a short independent scope.
        let open_reservations = {
            let ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
            ledger.open_reservations().map_err(|_| open_fail("recovery scan of open reservations failed"))?
        };

        for reservation in &open_reservations {
            let marker = self
                .backend_marker(&reservation.backend, &reservation.operation_id)
                .map_err(|_| open_fail("recovery marker scan failed"))?;
            match marker {
                Some(marker) if self.marker_matches_reservation(&marker, reservation) => {
                    let measured = self
                        .measure_backend(&reservation.backend)
                        .map_err(|_| open_fail("recovery measurement failed"))?;
                    let failed = {
                        let mut ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
                        ledger.validate_reservation_record(reservation).is_err() || ledger.finalize(reservation, measured).is_err()
                    };
                    if failed {
                        self.quarantine_backend(&reservation.backend);
                    }
                }
                Some(_) => self.quarantine_backend(&reservation.backend),
                None if now_ms >= reservation.expires_at => {
                    let failed = {
                        let mut ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
                        ledger.release(&reservation.reservation_id).is_err()
                    };
                    if failed {
                        self.quarantine_backend(&reservation.backend);
                    }
                }
                None => {}
            }
        }

        let (known, released, replay_records) = {
            let ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
            (
                ledger.known_operation_ids().map_err(|_| open_fail("ledger operation scan failed"))?,
                ledger.released_operation_ids().map_err(|_| open_fail("released reservation scan failed"))?,
                ledger.replay_records().map_err(|_| open_fail("replay ledger scan failed"))?,
            )
        };

        // Every durable backend marker must have exactly one matching ledger
        // reservation.  This catches orphan, released, cross-backend and
        // proof-mismatched markers before any request can be retried.
        // P0-1（2026-08-28）：只扫描 policy 启用的后端——禁用后端没有打开的连接，
        // 也就没有活 marker 面（logging-only/partial policy 不因缺席后端而砖死）；
        // claimed kv/sql 行的无凭证释放仍由 recover_claimed_replay fail-closed。
        let scanned_backends: Vec<&str> = ["kv", "sql"].into_iter().filter(|name| self.backend_enabled(name)).collect();
        for backend_name in scanned_backends {
            let marker_ids = self
                .backend_marker_ids(backend_name)
                .map_err(|_| open_fail("backend marker index scan failed"))?;
            for operation_id in marker_ids {
                let marker = self
                    .backend_marker(backend_name, &operation_id)
                    .map_err(|_| open_fail("backend marker read failed"))?;
                let reservation = {
                    let ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
                    ledger.reservation_for_operation(&operation_id).map_err(|_| open_fail("reservation join failed"))?
                };
                let valid = match (marker, reservation) {
                    (Some(marker), Some(reservation)) => {
                        !released.contains(&operation_id)
                            && self.marker_matches_reservation(&marker, &reservation)
                            && known.contains(&operation_id)
                    }
                    _ => false,
                };
                if !valid {
                    self.quarantine_backend(backend_name);
                }
            }
        }

        // Reconcile claimed host-call rows after backend/ledger recovery.  A
        // marker lets us rebuild the exact response; no marker permits claim
        // release only after both backend indexes have been checked.
        for record in replay_records {
            match record.state.as_str() {
                "claimed" => self.recover_claimed_replay(&record, now_ms),
                "ok" | "error" => self.validate_terminal_replay(&record),
                _ => {
                    self.quarantine_all_backends();
                    Err(open_fail("replay ledger contains an unknown state"))
                }
            }?;
        }
        Ok(())
    }

    fn backend_marker(&self, backend: &str, operation_id: &str) -> Result<Option<BackendOperationMarker>, ()> {
        match backend {
            "kv" => self
                .kv
                .as_ref()
                .ok_or(())?
                .lock()
                .map_err(|_| ())?
                .operation_marker(operation_id)
                .map_err(|_| ())
                .map(|marker| marker.map(BackendOperationMarker::Kv)),
            "sql" => self
                .sql
                .as_ref()
                .ok_or(())?
                .lock()
                .map_err(|_| ())?
                .operation_marker(operation_id)
                .map_err(|_| ())
                .map(|marker| marker.map(BackendOperationMarker::Sql)),
            _ => Err(()),
        }
    }

    fn backend_marker_ids(&self, backend: &str) -> Result<Vec<String>, ()> {
        match backend {
            "kv" => self.kv.as_ref().ok_or(())?.lock().map_err(|_| ())?.list_operation_ids().map_err(|_| ()),
            "sql" => self.sql.as_ref().ok_or(())?.lock().map_err(|_| ())?.list_operation_ids().map_err(|_| ()),
            _ => Err(()),
        }
    }

    /// policy 是否启用该后端（恢复扫描的 marker 面只覆盖启用后端）。
    fn backend_enabled(&self, backend: &str) -> bool {
        match backend {
            "kv" => self.kv.is_some(),
            "sql" => self.sql.is_some(),
            _ => false,
        }
    }

    fn measure_backend(&self, backend: &str) -> Result<u64, ()> {
        match backend {
            "kv" => {
                let guard = self.kv.as_ref().ok_or(())?.lock().map_err(|_| ())?;
                QuotaLedger::measure_sqlite_file_bytes(guard.connection()).map_err(|_| ())
            }
            "sql" => {
                let guard = self.sql.as_ref().ok_or(())?.lock().map_err(|_| ())?;
                QuotaLedger::measure_sqlite_file_bytes(guard.connection()).map_err(|_| ())
            }
            _ => Err(()),
        }
    }

    fn quarantine_backend(&mut self, backend: &str) {
        match backend {
            "kv" => {
                if let Some(backend) = &self.kv {
                    if let Ok(mut backend) = backend.lock() {
                        backend.quarantined = Some(kv::WASMD_KV_BACKEND_INVALID);
                    }
                }
            }
            "sql" => {
                if let Some(backend) = &self.sql {
                    if let Ok(mut backend) = backend.lock() {
                        backend.quarantined = Some(sql::WASMD_SQL_BACKEND_INVALID);
                    }
                }
            }
            _ => self.quarantine_all_backends(),
        }
    }

    fn quarantine_all_backends(&mut self) {
        self.quarantine_backend("kv");
        self.quarantine_backend("sql");
    }

    fn marker_matches_reservation(&self, marker: &BackendOperationMarker, reservation: &quota::ReservationRecordV2) -> bool {
        if marker.backend() != reservation.backend
            || marker.operation_id() != reservation.operation_id
            || marker.reservation_id() != reservation.reservation_id
            || marker.proof_digest() != reservation.reservation_proof_digest
            || reservation.state == "released"
        {
            return false;
        }
        match marker {
            BackendOperationMarker::Kv(marker) => {
                matches!(marker.method.as_str(), "set" | "delete")
                    && crate::jcs::validate_application_key(&marker.key).is_ok()
                    && marker.assigned_version > 0
            }
            BackendOperationMarker::Sql(marker) => marker.affected <= crate::jcs::WASM_U53_MAX,
        }
    }

    fn recover_claimed_replay(&mut self, record: &quota::ReplayRecordV2, _now_ms: u64) -> Result<(), WireError> {
        let open_fail = |detail: &str| err(WASMD_HOST_SERVICES_OPEN_FAILED, detail);
        // P0-1（2026-08-28）：claimed 行按 service 分派恢复语义。
        // - logging：profile no-durable-claim-v1——环是进程内存，kv/sql marker 在
        //   构造上不可能与 logging operationId 关联（后端 marker 索引扫描另行捕捉
        //   任何错挂 marker）。「无 marker」因此不需要（也不能，后端可能未启用）
        //   经 backend 读证明：唯一 impossible state 是 ledger 挂着同 operationId
        //   的 reservation（logging 从不 reserve）→ quarantine + open 失败；否则
        //   释放 claim——丢失响应发生在任何 durable 效果之前，可安全重试
        //   （design §5「a response lost before a backend commit is retried with
        //   the same idempotency key」）。
        // - kv/sql：维持两后端 marker join；marker 读失败（含后端未启用）→ open
        //   fail-closed——绝不在「无 marker」不可证明时释放 claim。
        // - 未知 service：impossible state → quarantine + open 失败。
        match record.key.service.as_str() {
            "logging" => {
                let reservation = {
                    let ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
                    ledger
                        .reservation_for_operation(&record.operation_id)
                        .map_err(|_| open_fail("replay reservation join failed"))?
                };
                if reservation.is_some() {
                    self.quarantine_all_backends();
                    return Err(open_fail("a logging replay claim must not carry a quota reservation"));
                }
                let mut ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
                ledger
                    .release_replay_claim_by_operation_id(&record.operation_id)
                    .map_err(|_| open_fail("replay claim release failed"))?;
                return Ok(());
            }
            "kv" | "sql" => {}
            _ => {
                self.quarantine_all_backends();
                return Err(open_fail("replay ledger carries an unknown service"));
            }
        }
        let kv_marker = self.backend_marker("kv", &record.operation_id).map_err(|_| open_fail("replay KV marker read failed"))?;
        let sql_marker = self.backend_marker("sql", &record.operation_id).map_err(|_| open_fail("replay SQL marker read failed"))?;
        if kv_marker.is_some() && sql_marker.is_some() {
            self.quarantine_all_backends();
            return Ok(());
        }
        let marker = kv_marker.or(sql_marker);
        let reservation = {
            let ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
            ledger.reservation_for_operation(&record.operation_id).map_err(|_| open_fail("replay reservation join failed"))?
        };
        let Some(marker) = marker else {
            let invalid_state = reservation.as_ref().is_some_and(|value| value.state != "reserved" && value.state != "released");
            if invalid_state {
                self.quarantine_backend(reservation.as_ref().map(|value| value.backend.as_str()).unwrap_or(""));
                return Ok(());
            }
            {
                let mut ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
                if let Some(reservation) = reservation {
                    if reservation.state == "reserved" {
                        ledger.release(&reservation.reservation_id).map_err(|_| open_fail("replay reservation release failed"))?;
                    }
                }
                ledger
                    .release_replay_claim_by_operation_id(&record.operation_id)
                    .map_err(|_| open_fail("replay claim release failed"))?;
            }
            return Ok(());
        };
        let Some(reservation) = reservation else {
            self.quarantine_backend(marker.backend());
            return Ok(());
        };
        if !self.marker_matches_reservation(&marker, &reservation) {
            self.quarantine_backend(marker.backend());
            return Ok(());
        }
        if reservation.state == "reserved" {
            let measured = self.measure_backend(marker.backend()).map_err(|_| open_fail("replay measurement failed"))?;
            let failed = {
                let mut ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
                ledger.finalize(&reservation, measured).is_err()
            };
            if failed {
                self.quarantine_backend(marker.backend());
                return Ok(());
            }
        }
        let response_body = match self.rebuild_replay_response(record, &marker) {
            Ok(body) => body,
            Err(_) => {
                self.quarantine_backend(marker.backend());
                return Ok(());
            }
        };
        let mut ledger = self.quota.lock().map_err(|_| open_fail("quota ledger lock poisoned"))?;
        ledger
            .complete_replay(&record.key, &record.operation_id, &response_body, "ok")
            .map_err(|_| open_fail("replay response completion failed"))
    }

    fn validate_terminal_replay(&mut self, record: &quota::ReplayRecordV2) -> Result<(), WireError> {
        let invalid = |detail: &str| err(WASMD_HOST_SERVICES_OPEN_FAILED, detail);
        let Some(body) = &record.response_payload else {
            self.quarantine_all_backends();
            return Err(invalid("terminal replay has no response body"));
        };
        let response: HostCallFrameResponseV2 = match parse_canonical(body, frame::HOST_FRAME_INVALID) {
            Ok(response) => response,
            Err(_) => {
                self.quarantine_all_backends();
                return Err(invalid("terminal replay response is not canonical"));
            }
        };
        if response.validate().is_err()
            || response.request_id != record.key.request_id
            || response.host_service_policy_digest != record.key.policy_digest
            || !self.identity.matches_frame(&response.execution)
            || response.outcome != record.outcome
        {
            self.quarantine_all_backends();
            return Err(invalid("terminal replay identity or outcome mismatch"));
        }
        Ok(())
    }

    fn rebuild_replay_response(&self, record: &quota::ReplayRecordV2, marker: &BackendOperationMarker) -> Result<Vec<u8>, ()> {
        let request: HostCallFrameRequestV2 = parse_canonical(&record.key.canonical_body, frame::HOST_FRAME_INVALID).map_err(|_| ())?;
        request.validate().map_err(|_| ())?;
        if request.request_id != record.key.request_id
            || request.service != record.key.service
            || request.method != record.key.method
            || request.host_service_policy_digest != self.policy_digest_hex
            || !self.identity.matches_frame(&request.execution)
            || record.key.identity_digest != self.identity_digest()
        {
            return Err(());
        }
        let payload = decode_base64url(&request.payload).map_err(|_| ())?;
        let result_payload = match marker {
            BackendOperationMarker::Kv(marker) => {
                if request.service != "kv" || marker.method != request.method {
                    return Err(());
                }
                let key = match request.method.as_str() {
                    "set" => serde_json::from_slice::<KvSetPayload>(&payload).map_err(|_| ())?.key,
                    "delete" => serde_json::from_slice::<KvDeletePayload>(&payload).map_err(|_| ())?.key,
                    _ => return Err(()),
                };
                if key != marker.key || !self.verify_kv_marker_data(marker)? {
                    return Err(());
                }
                encode_result(&KvVersionResult { version: marker.assigned_version }).map_err(|_| ())?
            }
            BackendOperationMarker::Sql(marker) => {
                if request.service != "sql" || request.method != "execute" {
                    return Err(());
                }
                let payload = serde_json::from_slice::<SqlExecutePayload>(&payload).map_err(|_| ())?;
                let member = self.policy.payload.host_services.sql.as_ref().ok_or(())?;
                let parameters = payload
                    .parameters
                    .iter()
                    .map(sql_value_from_payload)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ())?;
                let analysis = sql::validate_execute_request(&payload.statement, &parameters, &member.limits).map_err(|_| ())?;
                if !analysis.kind.is_mutation() || marker.affected > member.limits.max_affected_rows {
                    return Err(());
                }
                encode_result(&SqlExecuteResultPayload { rows: Vec::new(), affected: marker.affected, last_insert_id: marker.last_insert_id }).map_err(|_| ())?
            }
        };
        let response = HostCallFrameResponseV2::ok(&request, result_payload);
        response.validate().map_err(|_| ())?;
        jcs_bytes(&response).map_err(|_| ())
    }

    fn verify_kv_marker_data(&self, marker: &kv::KvOperationMarker) -> Result<bool, ()> {
        let backend = self.kv.as_ref().ok_or(())?.lock().map_err(|_| ())?;
        let row: Option<(i64, i64)> = backend
            .connection()
            .query_row(
                "SELECT version, tombstone FROM kv_entries WHERE key = ?1",
                rusqlite::params![marker.key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ())?;
        Ok(row.is_some_and(|(version, tombstone)| {
            version >= 0
                && version as u64 == marker.assigned_version
                && ((marker.method == "delete" && tombstone != 0) || (marker.method == "set" && tombstone == 0))
        }))
    }

    pub fn identity(&self) -> &HostCallExecutionIdentity {
        &self.identity
    }

    pub fn policy_digest_hex(&self) -> &str {
        &self.policy_digest_hex
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn forwarding_config(&self) -> &logging::ForwardingConfig {
        &self.forwarding
    }

    pub fn kv_enabled(&self) -> bool {
        self.kv.is_some()
    }

    pub fn sql_enabled(&self) -> bool {
        self.sql.is_some()
    }

    pub fn logging_enabled(&self) -> bool {
        self.policy.payload.host_services.logging.is_some()
    }

    fn kv_member(&self) -> Result<&policy::ServiceMemberV2<policy::KvLimitsV2>, HostCallErrorV2> {
        self.policy
            .payload
            .host_services
            .kv
            .as_ref()
            .ok_or_else(|| HostCallErrorV2::new("POLICY_MISMATCH", Some("IWEB_KV_POLICY_DISABLED")))
    }

    fn sql_member(&self) -> Result<&policy::ServiceMemberV2<policy::SqlLimitsV2>, HostCallErrorV2> {
        self.policy
            .payload
            .host_services
            .sql
            .as_ref()
            .ok_or_else(|| HostCallErrorV2::new("POLICY_MISMATCH", Some("IWEB_SQL_POLICY_DISABLED")))
    }

    fn logging_member(&self) -> Result<&policy::ServiceMemberV2<policy::LoggingLimitsV2>, HostCallErrorV2> {
        self.policy
            .payload
            .host_services
            .logging
            .as_ref()
            .ok_or_else(|| HostCallErrorV2::new("POLICY_MISMATCH", Some("IWEB_LOG_POLICY_DISABLED")))
    }

    // -----------------------------------------------------------------
    // typed core（WIT 路径与 frame 路径共用的唯一语义面；身份恒为注入身份）。
    // P0-1（2026-08-28）：mutating 后端效果只在 host-call claim 内发生——
    // kv set/delete 与 sql execute 一律携带 claim operationId（无 claim 的
    // claim-free 写入口已删除；读取方法不经 claim）。
    // -----------------------------------------------------------------

    pub fn kv_get(&self, key: &str, deadline: Instant) -> Result<(Vec<u8>, u64), kv::KvError> {
        self.kv_member().ok();
        let backend = self.kv.as_ref().expect("kv enabled");
        let mut backend = backend.lock().map_err(|_| kv::KvError::Internal)?;
        backend.get(key, deadline)
    }

    fn kv_set_claimed(
        &self,
        key: &str,
        value: &[u8],
        expected: Option<u64>,
        deadline: Instant,
        operation_id: &str,
    ) -> Result<u64, kv::KvError> {
        self.kv_member().ok();
        let member = self.policy.payload.host_services.kv.as_ref().expect("kv enabled");
        let backend = self.kv.as_ref().expect("kv enabled");
        let mut backend = backend.lock().map_err(|_| kv::KvError::Internal)?;
        let mut ledger = self.quota.lock().map_err(|_| kv::KvError::Internal)?;
        backend.set_with_operation_id(
            key,
            value,
            expected,
            &mut ledger,
            self.policy.payload.storage_bytes,
            self.policy.payload.storage_bytes, // 契约未冻结独立 service cap：仅共享 envelope（上报）。
            member.limits.entry_overhead_bytes,
            policy::HOST_CALL_REPLAY_TTL_MS,
            unix_now_ms(),
            deadline,
            operation_id,
        )
    }

    fn kv_delete_claimed(&self, key: &str, expected: Option<u64>, deadline: Instant, operation_id: &str) -> Result<u64, kv::KvError> {
        self.kv_member().ok();
        let member = self.policy.payload.host_services.kv.as_ref().expect("kv enabled");
        let backend = self.kv.as_ref().expect("kv enabled");
        let mut backend = backend.lock().map_err(|_| kv::KvError::Internal)?;
        let mut ledger = self.quota.lock().map_err(|_| kv::KvError::Internal)?;
        backend.delete_with_operation_id(
            key,
            expected,
            &mut ledger,
            self.policy.payload.storage_bytes,
            self.policy.payload.storage_bytes,
            member.limits.entry_overhead_bytes,
            policy::HOST_CALL_REPLAY_TTL_MS,
            unix_now_ms(),
            deadline,
            operation_id,
        )
    }

    pub fn kv_list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u32,
        deadline: Instant,
    ) -> Result<(Vec<kv::KvListEntry>, Option<String>), kv::KvError> {
        self.kv_member().ok();
        let member = self.policy.payload.host_services.kv.as_ref().expect("kv enabled");
        let backend = self.kv.as_ref().expect("kv enabled");
        let mut backend = backend.lock().map_err(|_| kv::KvError::Internal)?;
        backend.list(
            prefix,
            cursor,
            limit,
            member.limits.max_list_items,
            member.limits.max_list_bytes,
            member.limits.cursor_ttl_ms,
            unix_now_ms(),
            deadline,
        )
    }

    fn sql_execute_claimed(
        &self,
        statement: &str,
        parameters: &[sql::SqlValue],
        deadline: Instant,
        operation_id: &str,
    ) -> Result<sql::SqlExecuteResult, sql::SqlError> {
        self.sql_member().ok();
        let member = self.policy.payload.host_services.sql.as_ref().expect("sql enabled");
        let backend = self.sql.as_ref().expect("sql enabled");
        let mut backend = backend.lock().map_err(|_| sql::SqlError::Internal)?;
        let mut ledger = self.quota.lock().map_err(|_| sql::SqlError::Internal)?;
        backend.execute_with_operation_id(
            statement,
            parameters,
            &mut ledger,
            self.policy.payload.storage_bytes,
            &member.limits,
            unix_now_ms(),
            deadline,
            operation_id,
        )
    }

    /// logging write：宿主注入身份/时间戳/claim 关联；redaction 先于计量（ring 内部
    /// 强制）。`operation_id` 是本写所属 host-call claim（P0-1：claim 内的写才产生
    /// 事件；None 仅限宿主侧非 claim 诊断写）。
    pub fn logging_write(
        &self,
        level: logging::LogLevel,
        message: &str,
        fields: &[logging::LoggingField],
        operation_id: Option<&str>,
    ) -> Result<bool, logging::LoggingError> {
        self.logging_member().ok();
        let member = self.policy.payload.host_services.logging.as_ref().expect("logging enabled");
        let mut ring = self.ring.lock().map_err(|_| logging::LoggingError::Internal)?;
        let host = logging::LoggingHostContext {
            application_id: self.identity.application_id.clone(),
            version_id: self.identity.version_id.clone(),
            preparation_generation: self.identity.preparation_generation,
            execution_generation: self.identity.execution_generation,
            timestamp_utc: format_utc_timestamp(SystemTime::now()),
            operation_id: operation_id.map(str::to_string),
        };
        let event = logging::LoggingEvent { level, message: message.to_string(), fields: fields.to_vec() };
        ring.write(&host, &event, member.limits.max_event_bytes)
    }

    /// owner 授权 drain（只返回本应用 bounded 记录；跨应用 → 隔离违约）。
    pub fn logging_drain(&self, application_id: &str, after_event_id: u64, max_events: usize) -> Result<logging::DrainResponse, logging::LoggingError> {
        let ring = self.ring.lock().map_err(|_| logging::LoggingError::Internal)?;
        ring.drain(application_id, after_event_id, max_events)
    }

    pub fn logging_monitor_summary(&self) -> Result<logging::MonitorSummary, logging::LoggingError> {
        let ring = self.ring.lock().map_err(|_| logging::LoggingError::Internal)?;
        Ok(ring.monitor_summary())
    }

    /// quota 用量投影（monitor 面；无 payload）。
    pub fn quota_usage(&self) -> Result<quota::UsageSnapshot, quota::QuotaError> {
        self.quota.lock().expect("quota ledger lock").usage()
    }

    // -----------------------------------------------------------------
    // canonical host-call frame 入口（身份门 + replay + deadline + 服务分派）
    // -----------------------------------------------------------------

    /// 处理一个请求帧，返回响应帧字节（传输/身份/策略/重放错误也以响应帧承载）。
    pub fn dispatch(&self, frame_bytes: &[u8]) -> Vec<u8> {
        match self.dispatch_frame(frame_bytes) {
            Ok(response) => response.encode_frame().unwrap_or_default(),
            Err(response) => response.encode_frame().unwrap_or_default(),
        }
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_frame(&self, frame_bytes: &[u8]) -> Result<HostCallFrameResponseV2, HostCallFrameResponseV2> {
        let request = match HostCallFrameRequestV2::decode_frame(frame_bytes) {
            Ok(request) => request,
            Err(_) => {
                return Err(HostCallFrameResponseV2::error(
                    "",
                    self.identity.to_frame(),
                    &self.policy_digest_hex,
                    HostCallErrorV2::new("INVALID_FRAME", Some("IWEB_HOST_FRAME_INVALID")),
                ))
            }
        };
        // 身份门（顺序固定：先隔离/代次/身份全集，后策略 digest）。第三轮复审：
        // 帧身份与 provider 注入身份逐字段相等（完整 HostServiceIdentityV2 面——
        // catalog/capability revision+hash 也在比对集内；任一偏差 IDENTITY_MISMATCH）。
        let execution = &request.execution;
        if execution.application_id != self.identity.application_id {
            return Err(self.error_response(&request, "APP_ISOLATION", "IWEB_HOST_APP_ISOLATION"));
        }
        if execution.preparation_generation < self.identity.preparation_generation
            || (execution.preparation_generation == self.identity.preparation_generation
                && execution.execution_generation < self.identity.execution_generation)
        {
            return Err(self.error_response(&request, "STALE_EXECUTION", "IWEB_HOST_STALE_EXECUTION"));
        }
        if !self.identity.matches_frame(execution) {
            return Err(self.error_response(&request, "IDENTITY_MISMATCH", "IWEB_HOST_IDENTITY_MISMATCH"));
        }
        if request.host_service_policy_digest != self.policy_digest_hex {
            return Err(self.error_response(&request, "POLICY_MISMATCH", "IWEB_HOST_POLICY_MISMATCH"));
        }
        if execution.host_service_policy_digest != self.policy_digest_hex {
            return Err(self.error_response(&request, "POLICY_MISMATCH", "IWEB_HOST_POLICY_MISMATCH"));
        }
        let mutating = matches!(
            (request.service.as_str(), request.method.as_str()),
            ("kv", "set") | ("kv", "delete") | ("sql", "execute") | ("logging", "write")
        );
        // mutating 服务的 replay TTL：wasmd 内部派生常量（契约留白，上报）。
        let replay_ttl_ms = match request.service.as_str() {
            "kv" => match self.kv_member() {
                Ok(_) => Some(policy::HOST_CALL_REPLAY_TTL_MS),
                Err(error) => return Err(self.error_from(&request, error)),
            },
            "sql" => match self.sql_member() {
                Ok(_) => Some(policy::HOST_CALL_REPLAY_TTL_MS),
                Err(error) => return Err(self.error_from(&request, error)),
            },
            "logging" => match self.logging_member() {
                Ok(_) => Some(policy::HOST_CALL_REPLAY_TTL_MS),
                Err(error) => return Err(self.error_from(&request, error)),
            },
            _ => None,
        };
        let now_ms = unix_now_ms();
        let payload_bytes = match decode_base64url(&request.payload) {
            Ok(bytes) => bytes,
            Err(_) => return Err(self.error_response(&request, "INVALID_ARGUMENT", "IWEB_HOST_PAYLOAD_INVALID")),
        };
        // requestId at-most-once：claim 与既有行的比较/插入在同一个 SQLite
        // BEGIN IMMEDIATE 事务内完成。canonical body 是完整 request JCS，而不是
        // 仅 payload；因此 service/method、deadline、identity 或 P/E 任一变化都不能
        // 借用旧 marker。
        let mut replay_claim: Option<(ReplayKeyV2, String)> = None;
        if mutating {
            let canonical_body = jcs_bytes(&request).map_err(|_| self.error_response(&request, "INVALID_FRAME", "IWEB_HOST_FRAME_INVALID"))?;
            let key = ReplayKeyV2 {
                request_id: request.request_id.clone(),
                canonical_body,
                service: request.service.clone(),
                method: request.method.clone(),
                identity_digest: self.identity_digest(),
                policy_digest: self.policy_digest_hex.clone(),
                preparation_generation: request.execution.preparation_generation,
                execution_generation: request.execution.execution_generation,
                fence_nonce: request.execution.fence_nonce.clone(),
            };
            let expires_at = now_ms.saturating_add(replay_ttl_ms.unwrap_or(HOST_CALL_DEADLINE_MAX_MS));
            let claim_result = self
                .quota
                .lock()
                .map_err(|_| self.error_response(&request, "INTERNAL", "IWEB_HOST_QUOTA_LOCK"))?
                .claim_replay(&key, now_ms, expires_at)
                .map_err(|_| self.error_response(&request, "UNAVAILABLE", "IWEB_HOST_REPLAY_UNAVAILABLE"))?;
            match claim_result {
                ReplayClaimV2::Claimed { operation_id } => replay_claim = Some((key, operation_id)),
                ReplayClaimV2::Completed { response_payload, outcome } => {
                    let response: HostCallFrameResponseV2 = parse_canonical::<HostCallFrameResponseV2>(&response_payload, frame::HOST_FRAME_INVALID)
                        .map_err(|_| self.error_response(&request, "UNAVAILABLE", "IWEB_HOST_REPLAY_UNAVAILABLE"))?;
                    response
                        .validate()
                        .map_err(|_| self.error_response(&request, "UNAVAILABLE", "IWEB_HOST_REPLAY_UNAVAILABLE"))?;
                    if response.request_id != request.request_id || response.outcome != outcome {
                        return Err(self.error_response(&request, "UNAVAILABLE", "IWEB_HOST_REPLAY_UNAVAILABLE"));
                    }
                    return if response.outcome == "ok" { Ok(response) } else { Err(response) };
                }
                ReplayClaimV2::InFlight => {
                    return Err(self.error_response(&request, "BUSY", "IWEB_HOST_REPLAY_IN_FLIGHT"));
                }
                ReplayClaimV2::Conflict => {
                    return Err(self.error_response(&request, "REQUEST_ID_CONFLICT", "IWEB_HOST_REQUEST_ID_CONFLICT"));
                }
                ReplayClaimV2::Expired => {
                    return Err(self.error_response(&request, "REPLAY_UNAVAILABLE", "IWEB_HOST_REPLAY_EXPIRED"));
                }
            }
        }
        // deadline：相对 provider 入口，钉 profile 上界（sql 用 executionMaxMs）。
        let service_cap = match request.service.as_str() {
            "sql" => match self.sql_member() {
                Ok(member) => member.limits.execution_max_ms,
                Err(error) => return Err(self.error_from(&request, error)),
            },
            _ => HOST_CALL_DEADLINE_MAX_MS,
        };
        let budget = request.deadline_ms.min(service_cap);
        let deadline = Instant::now() + Duration::from_millis(budget.max(1));
        let response = match self.dispatch_payload(&request, &payload_bytes, deadline, replay_claim.as_ref().map(|(_, operation_id)| operation_id.as_str())) {
            Ok(result_payload) => HostCallFrameResponseV2::ok(&request, result_payload),
            Err(error) => self.error_from(&request, error),
        };
        if let Some((key, operation_id)) = replay_claim {
            let encoded = response
                .encode_frame()
                .map_err(|_| self.error_response(&request, "UNAVAILABLE", "IWEB_HOST_REPLAY_UNAVAILABLE"))?;
            let body = encoded
                .get(4..)
                .ok_or_else(|| self.error_response(&request, "UNAVAILABLE", "IWEB_HOST_REPLAY_UNAVAILABLE"))?;
            self.quota
                .lock()
                .map_err(|_| self.error_response(&request, "INTERNAL", "IWEB_HOST_QUOTA_LOCK"))?
                .complete_replay(&key, &operation_id, body, &response.outcome)
                .map_err(|_| self.error_response(&request, "UNAVAILABLE", "IWEB_HOST_REPLAY_UNAVAILABLE"))?;
        }
        if response.outcome == "ok" { Ok(response) } else { Err(response) }
    }

    fn dispatch_payload(
        &self,
        request: &HostCallFrameRequestV2,
        payload: &[u8],
        deadline: Instant,
        operation_id: Option<&str>,
    ) -> Result<Vec<u8>, HostCallErrorV2> {
        // P0-1：mutating 方法（kv:set|delete、sql:execute、logging:write）的后端
        // 效果只在 claim 内发生——operationId 缺席即内部不变式破坏，fail-closed
        // 拒绝且不触任何后端。读取方法（kv:get|list）不经 claim，operationId 恒 None。
        let require_claim = || {
            operation_id.ok_or_else(|| HostCallErrorV2::new("INTERNAL", Some("IWEB_HOST_CLAIM_REQUIRED")))
        };
        match (request.service.as_str(), request.method.as_str()) {
            ("kv", "get") => {
                let payload: KvGetPayload = parse_payload(payload)?;
                let (value, version) = self.kv_get(&payload.key, deadline).map_err(kv_error)?;
                encode_result(&KvGetResult { key: payload.key, value: encode_base64url(&value), version })
            }
            ("kv", "set") => {
                let payload: KvSetPayload = parse_payload(payload)?;
                let value = decode_base64url(&payload.value)
                    .map_err(|_| HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_KV_VALUE_WIRE_INVALID")))?;
                let version = self
                    .kv_set_claimed(&payload.key, &value, payload.expected, deadline, require_claim()?)
                    .map_err(kv_error)?;
                encode_result(&KvVersionResult { version })
            }
            ("kv", "delete") => {
                let payload: KvDeletePayload = parse_payload(payload)?;
                let version = self
                    .kv_delete_claimed(&payload.key, payload.expected, deadline, require_claim()?)
                    .map_err(kv_error)?;
                encode_result(&KvVersionResult { version })
            }
            ("kv", "list") => {
                let payload: KvListPayload = parse_payload(payload)?;
                let (items, next_cursor) = self
                    .kv_list(&payload.prefix, payload.cursor.as_deref(), payload.limit, deadline)
                    .map_err(kv_error)?;
                encode_result(&KvListResult {
                    items: items
                        .into_iter()
                        .map(|entry| KvListEntryPayload { key: entry.key, value: encode_base64url(&entry.value), version: entry.version })
                        .collect(),
                    // 帧路径 cursor 与请求侧/WIT 路径对称：一律原始 registry token，
                    // 不做 base64url 编码（spec：frame cursor strings are the raw tokens）。
                    next_cursor,
                })
            }
            ("sql", "execute") => {
                let payload: SqlExecutePayload = parse_payload(payload)?;
                let parameters: Vec<sql::SqlValue> = payload
                    .parameters
                    .iter()
                    .map(sql_value_from_payload)
                    .collect::<Result<_, _>>()?;
                let result = self
                    .sql_execute_claimed(&payload.statement, &parameters, deadline, require_claim()?)
                    .map_err(sql_error)?;
                encode_result(&SqlExecuteResultPayload {
                    rows: result
                        .rows
                        .into_iter()
                        .map(|row| SqlRowPayload {
                            columns: row
                                .columns
                                .into_iter()
                                .map(|column| SqlColumnPayload { name: column.name, value: sql_value_to_payload(&column.value) })
                                .collect(),
                        })
                        .collect(),
                    affected: result.affected,
                    last_insert_id: result.last_insert_id,
                })
            }
            ("logging", "write") => {
                self.logging_member()?;
                // P0-1：logging 无 durable backend marker（profile no-durable-claim-v1，
                // 环为进程内存）——claim operationId 的消费形态是把宿主注入的关联
                // operationId 盖进保留事件（与 timestampUtc/身份同一信任级，caller
                // 不可携带），并保持「写只在 claim 内发生」的统一不变式。
                let operation_id = require_claim()?;
                let payload: LoggingWritePayload = parse_payload(payload)?;
                let level = logging::LogLevel::parse(&payload.level)
                    .ok_or_else(|| HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_LOG_INVALID_EVENT")))?;
                let message = decode_base64url(&payload.message)
                    .map_err(|_| HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_LOG_MESSAGE_WIRE_INVALID")))?;
                let message = String::from_utf8(message)
                    .map_err(|_| HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_LOG_MESSAGE_UTF8_INVALID")))?;
                let mut fields = Vec::with_capacity(payload.fields.len());
                for field in &payload.fields {
                    let value = decode_base64url(&field.value)
                        .map_err(|_| HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_LOG_VALUE_WIRE_INVALID")))?;
                    fields.push(logging::LoggingField {
                        key: field.key.clone(),
                        value: String::from_utf8(value)
                            .map_err(|_| HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_LOG_VALUE_UTF8_INVALID")))?,
                    });
                }
                let accepted = self
                    .logging_write(level, &message, &fields, Some(operation_id))
                    .map_err(logging_error)?;
                encode_result(&LoggingWriteResult {
                    outcome: if accepted { "accepted" } else { "dropped" }.into(),
                })
            }
            _ => Err(HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_HOST_METHOD_INVALID"))),
        }
    }

    fn error_response(&self, request: &HostCallFrameRequestV2, code: &str, detail: &str) -> HostCallFrameResponseV2 {
        HostCallFrameResponseV2::error(
            &request.request_id,
            self.identity.to_frame(),
            &self.policy_digest_hex,
            HostCallErrorV2::new(code, Some(detail)),
        )
    }

    /// WIT 路径统一入口（复审 P0-1，2026-08-28）：构造完整 HostCallFrameRequestV2
    /// 并经 `dispatch_frame`——与传输帧路径共享同一原子 claim/replay、身份门、
    /// deadline 与后端分派语义；组件侧 import 不再有绕过帧的第二语义面。
    ///
    /// requestId 取舍（报告）：bindgen 参数面无 requestId——每次 WIT 调用由宿主
    /// 自动生成 UUIDv7。同一逻辑调用在两条路径的幂等语义一致（payload/身份/策略
    /// digest 的 canonical 体一致、mutating 后端效果恰一次），但 WIT 路径的
    /// at-most-once 粒度是「调用级」而非 requestId 级：进程内重试同一 WIT 调用得到
    /// 新 requestId/新 claim（各执行一次，绝无 InFlight 互阻）；requestId 级幂等
    /// （同 id 重放返回存储响应、变更体冲突）由显式携带 requestId 的帧路径提供。
    #[allow(clippy::result_large_err)]
    fn dispatch_wit_frame(
        &self,
        service: &str,
        method: &str,
        payload: &impl Serialize,
        deadline_ms: u64,
    ) -> Result<HostCallFrameResponseV2, HostCallFrameResponseV2> {
        let request_id = uuid::Uuid::now_v7().hyphenated().to_string();
        // caller 字符串进入 canonical 帧前域（ASCII-only JCS）失败 → INVALID_ARGUMENT
        // （WIT 路径唯一成因：caller 提交的非 ASCII key/statement/field-key；各服务
        // 反解映射到其 invalid-argument 变体）。
        let payload_bytes = match jcs_bytes(payload) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(HostCallFrameResponseV2::error(
                    &request_id,
                    self.identity.to_frame(),
                    &self.policy_digest_hex,
                    HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_WIT_PAYLOAD_NON_CANONICAL")),
                ))
            }
        };
        let request = HostCallFrameRequestV2 {
            schema_version: 2,
            protocol: frame::HOST_CALL_PROTOCOL.into(),
            kind: "request".into(),
            request_id,
            service: service.into(),
            method: method.into(),
            execution: self.identity.to_frame(),
            host_service_policy_digest: self.policy_digest_hex.clone(),
            deadline_ms: deadline_ms.clamp(1, HOST_CALL_DEADLINE_MAX_MS),
            payload: encode_base64url(&payload_bytes),
        };
        let frame_bytes = match request.encode_frame() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(HostCallFrameResponseV2::error(
                    &request.request_id,
                    self.identity.to_frame(),
                    &self.policy_digest_hex,
                    HostCallErrorV2::new("INVALID_FRAME", Some("IWEB_HOST_FRAME_INVALID")),
                ))
            }
        };
        self.dispatch_frame(&frame_bytes)
    }

    fn error_from(&self, request: &HostCallFrameRequestV2, error: HostCallErrorV2) -> HostCallFrameResponseV2 {
        HostCallFrameResponseV2::error(&request.request_id, self.identity.to_frame(), &self.policy_digest_hex, error)
    }

    /// replay 行的身份摘要（内部冲突探测用；不含 payload）。P0-2：覆盖完整身份
    /// 元组（application/version、catalog 与 capability pin、policyDigest、P/E/fence）。
    fn identity_digest(&self) -> String {
        sha256_hex(
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                self.identity.application_id,
                self.identity.version_id,
                self.identity.catalog_revision,
                self.identity.catalog_hash,
                self.identity.capability_revision,
                self.identity.capability_hash,
                self.identity.policy_digest,
                self.identity.preparation_generation,
                self.identity.execution_generation,
                self.identity.fence_nonce,
            )
            .as_bytes(),
        )
    }
}

fn kv_error(error: kv::KvError) -> HostCallErrorV2 {
    HostCallErrorV2::new(error.host_call_code(), Some(error.detail_code()))
}

fn sql_error(error: sql::SqlError) -> HostCallErrorV2 {
    HostCallErrorV2::new(error.host_call_code(), Some(error.detail_code()))
}

fn logging_error(error: logging::LoggingError) -> HostCallErrorV2 {
    HostCallErrorV2::new(error.host_call_code(), Some(error.detail_code()))
}

fn parse_payload<T>(payload: &[u8]) -> Result<T, HostCallErrorV2>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(payload).map_err(|_| HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_HOST_PAYLOAD_INVALID")))
}

fn encode_result<T: Serialize>(result: &T) -> Result<Vec<u8>, HostCallErrorV2> {
    serde_json::to_vec(result).map_err(|_| HostCallErrorV2::new("INTERNAL", Some("IWEB_HOST_RESULT_ENCODE_FAILED")))
}

// ---------------------------------------------------------------------------
// frame payload 投影（canonical JCS 值域：二进制/非 ASCII/超 u53 数值一律
// unpadded base64url 或十进制字符串；ASCII 文法字符串直接为 JSON string）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvGetPayload {
    key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvGetResult {
    key: String,
    value: String,
    version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvSetPayload {
    key: String,
    value: String,
    expected: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvDeletePayload {
    key: String,
    expected: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvVersionResult {
    version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvListPayload {
    prefix: String,
    cursor: Option<String>,
    limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvListEntryPayload {
    key: String,
    value: String,
    version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KvListResult {
    items: Vec<KvListEntryPayload>,
    #[serde(rename = "nextCursor")]
    next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlExecutePayload {
    statement: String,
    parameters: Vec<SqlValuePayload>,
}

/// SQL 值的 payload 投影：integer=十进制字符串（保全 s64），real=8 字节 IEEE-754 BE，
/// text/blob=UTF-8 字节（canonical JCS 值域内不可载浮点/非 ASCII）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind")]
enum SqlValuePayload {
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "integer")]
    Integer { value: String },
    #[serde(rename = "real")]
    Real { bytes: String },
    #[serde(rename = "text")]
    Text { bytes: String },
    #[serde(rename = "blob")]
    Blob { bytes: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlColumnPayload {
    name: String,
    value: SqlValuePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlRowPayload {
    columns: Vec<SqlColumnPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlExecuteResultPayload {
    rows: Vec<SqlRowPayload>,
    affected: u64,
    #[serde(rename = "lastInsertId")]
    last_insert_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoggingFieldPayload {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoggingWritePayload {
    level: String,
    message: String,
    fields: Vec<LoggingFieldPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoggingWriteResult {
    outcome: String,
}

fn sql_value_to_payload(value: &sql::SqlValue) -> SqlValuePayload {
    match value {
        sql::SqlValue::Null => SqlValuePayload::Null,
        sql::SqlValue::Integer(int) => SqlValuePayload::Integer { value: int.to_string() },
        sql::SqlValue::Real(real) => SqlValuePayload::Real { bytes: encode_base64url(&real.to_bits().to_be_bytes()) },
        sql::SqlValue::Text(text) => SqlValuePayload::Text { bytes: encode_base64url(text.as_bytes()) },
        sql::SqlValue::Blob(bytes) => SqlValuePayload::Blob { bytes: encode_base64url(bytes) },
    }
}

fn sql_value_from_payload(value: &SqlValuePayload) -> Result<sql::SqlValue, HostCallErrorV2> {
    let invalid = || HostCallErrorV2::new("INVALID_ARGUMENT", Some("IWEB_SQL_PARAMETER_VALUE_INVALID"));
    match value {
        SqlValuePayload::Null => Ok(sql::SqlValue::Null),
        SqlValuePayload::Integer { value } => value.parse::<i64>().map(sql::SqlValue::Integer).map_err(|_| invalid()),
        SqlValuePayload::Real { bytes } => {
            let raw = decode_base64url(bytes).map_err(|_| invalid())?;
            let raw: [u8; 8] = raw.as_slice().try_into().map_err(|_| invalid())?;
            Ok(sql::SqlValue::Real(f64::from_bits(u64::from_be_bytes(raw))))
        }
        SqlValuePayload::Text { bytes } => {
            let raw = decode_base64url(bytes).map_err(|_| invalid())?;
            String::from_utf8(raw).map(sql::SqlValue::Text).map_err(|_| invalid())
        }
        SqlValuePayload::Blob { bytes } => decode_base64url(bytes).map(sql::SqlValue::Blob).map_err(|_| invalid()),
    }
}

// ---------------------------------------------------------------------------
// 数据目录/文件加固（host-owned 0700/0600；无 symlink）
// ---------------------------------------------------------------------------

fn create_private_directory(path: &Path) -> Result<(), WireError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .or_else(|error| {
            // 已存在时校验目录性与非 symlink，绝不重建空替换。
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|error| err(WASMD_HOST_SERVICES_OPEN_FAILED, format!("data directory creation failed: {error}")))?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| err(WASMD_HOST_SERVICES_OPEN_FAILED, format!("data directory stat failed: {error}")))?;
    if !metadata.is_dir() {
        return Err(err(WASMD_HOST_SERVICES_OPEN_FAILED, "data directory path is not a directory (symlink refused)"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| err(WASMD_HOST_SERVICES_OPEN_FAILED, format!("data directory permission hardening failed: {error}")))?;
    }
    Ok(())
}

fn open_private_database(path: &Path) -> Result<rusqlite::Connection, WireError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.is_file() {
            return Err(err(WASMD_HOST_SERVICES_OPEN_FAILED, "database path is not a regular file (symlink refused)"));
        }
    }
    let connection = rusqlite::Connection::open(path)
        .map_err(|error| err(WASMD_HOST_SERVICES_OPEN_FAILED, format!("database open failed: {error}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| err(WASMD_HOST_SERVICES_OPEN_FAILED, format!("database permission hardening failed: {error}")))?;
    }
    Ok(connection)
}

// ---------------------------------------------------------------------------
// WIT host 实现层（bindgen Host trait；身份注入 + epoch 预算）
// ---------------------------------------------------------------------------

/// 每请求 Store 的进入时刻与 epoch 上界（host call 预算 = min(profile, 剩余 epoch)）。
#[derive(Debug, Clone)]
pub struct HostCallBudget {
    entered_at: Instant,
    epoch_deadline_ms: u64,
}

impl HostCallBudget {
    pub fn new(epoch_deadline_ms: u64) -> Self {
        Self { entered_at: Instant::now(), epoch_deadline_ms }
    }

    /// WIT 帧的 deadlineMs（P0-1）：本请求 Store 的剩余 epoch 预算（1..=300_000；
    /// service profile 上界由 dispatch_frame 的 min 钉口——sql 用 executionMaxMs）。
    fn frame_deadline_ms(&self) -> u64 {
        let elapsed = self.entered_at.elapsed().as_millis() as u64;
        self.epoch_deadline_ms.saturating_sub(elapsed).clamp(1, HOST_CALL_DEADLINE_MAX_MS)
    }
}

// ---------------------------------------------------------------------------
// WIT host 实现层（bindgen Host trait；P0-1：全部经 dispatch_wit_frame——
// 构造 canonical 帧 → 原子 claim/replay/身份门 → 后端，再反解响应帧。身份与
// policyDigest 恒取注入值；requestId 为宿主自动 UUIDv7（取舍见 dispatch_wit_frame）。
// ---------------------------------------------------------------------------

/// iweb:kv/store 宿主实现（WIT 路径；身份恒为注入身份，组件不可携带身份字段）。
pub struct KvHostService {
    provider: Arc<HostServicesProvider>,
    budget: HostCallBudget,
}

impl KvHostService {
    pub fn new(provider: Arc<HostServicesProvider>, budget: HostCallBudget) -> Self {
        Self { provider, budget }
    }
}

/// 帧响应 error → iweb:kv/store Error（detailCode 优先；code 兜底；未知 → Internal）。
fn kv_wit_error_from_frame(error: &HostCallErrorV2) -> iweb::kv::store::Error {
    match error.detail_code.as_deref() {
        Some("IWEB_KV_INVALID_KEY") => iweb::kv::store::Error::InvalidKey,
        Some("IWEB_KV_NOT_FOUND") => iweb::kv::store::Error::NotFound,
        Some("IWEB_KV_CONFLICT") => iweb::kv::store::Error::Conflict,
        Some("IWEB_KV_QUOTA_EXCEEDED") => iweb::kv::store::Error::QuotaExceeded,
        Some("IWEB_KV_LIMIT_EXCEEDED") => iweb::kv::store::Error::LimitExceeded,
        Some("IWEB_KV_CURSOR_EXPIRED") => iweb::kv::store::Error::CursorExpired,
        Some("IWEB_KV_BUSY") | Some("IWEB_KV_TIMEOUT") | Some("IWEB_KV_UNAVAILABLE") => iweb::kv::store::Error::Unavailable,
        // WIT 路径的 INVALID_ARGUMENT 只能来自非 canonical caller key/value。
        Some("IWEB_KV_INTERNAL") | Some("IWEB_WIT_PAYLOAD_NON_CANONICAL") | None if error.code == "INVALID_ARGUMENT" => {
            iweb::kv::store::Error::InvalidKey
        }
        Some(_) if error.code == "NOT_FOUND" => iweb::kv::store::Error::NotFound,
        Some(_) if error.code == "CONFLICT" => iweb::kv::store::Error::Conflict,
        Some(_) if error.code == "QUOTA_EXCEEDED" => iweb::kv::store::Error::QuotaExceeded,
        Some(_) if error.code == "LIMIT_EXCEEDED" => iweb::kv::store::Error::LimitExceeded,
        Some(_) if error.code == "UNAVAILABLE" => iweb::kv::store::Error::Unavailable,
        _ => iweb::kv::store::Error::Internal,
    }
}

/// ok 响应 result（b64url JSON）反解（宿主自编码；失败即内部不变式破坏 → INTERNAL）。
fn wit_ok_result<T: for<'de> Deserialize<'de>>(response: &HostCallFrameResponseV2) -> Result<T, HostCallErrorV2> {
    let encoded = response
        .result
        .as_deref()
        .ok_or_else(|| HostCallErrorV2::new("INTERNAL", Some("IWEB_WIT_RESULT_MISSING")))?;
    let bytes = decode_base64url(encoded)
        .map_err(|_| HostCallErrorV2::new("INTERNAL", Some("IWEB_WIT_RESULT_WIRE_INVALID")))?;
    serde_json::from_slice(&bytes).map_err(|_| HostCallErrorV2::new("INTERNAL", Some("IWEB_WIT_RESULT_DECODE_FAILED")))
}

fn wit_b64url_bytes(value: &str) -> Result<Vec<u8>, HostCallErrorV2> {
    decode_base64url(value).map_err(|_| HostCallErrorV2::new("INTERNAL", Some("IWEB_WIT_RESULT_WIRE_INVALID")))
}

impl iweb::kv::store::Host for KvHostService {
    fn get(&mut self, key: String) -> Result<Result<iweb::kv::store::Item, iweb::kv::store::Error>, wasmtime::Error> {
        let response = self
            .provider
            .dispatch_wit_frame("kv", "get", &KvGetPayload { key }, self.budget.frame_deadline_ms());
        Ok(match response {
            Ok(response) => match wit_ok_result::<KvGetResult>(&response) {
                Ok(result) => match wit_b64url_bytes(&result.value) {
                    Ok(value) => Ok(iweb::kv::store::Item { key: result.key, value, version: result.version }),
                    Err(error) => Err(kv_wit_error_from_frame(&error)),
                },
                Err(error) => Err(kv_wit_error_from_frame(&error)),
            },
            Err(response) => {
                let error = response.error.clone().unwrap_or_else(|| HostCallErrorV2::new("INTERNAL", None));
                Err(kv_wit_error_from_frame(&error))
            }
        })
    }

    fn set(&mut self, key: String, value: Vec<u8>, expected: Option<u64>) -> Result<Result<u64, iweb::kv::store::Error>, wasmtime::Error> {
        let response = self.provider.dispatch_wit_frame(
            "kv",
            "set",
            &KvSetPayload { key, value: encode_base64url(&value), expected },
            self.budget.frame_deadline_ms(),
        );
        Ok(match response {
            Ok(response) => match wit_ok_result::<KvVersionResult>(&response) {
                Ok(result) => Ok(result.version),
                Err(error) => Err(kv_wit_error_from_frame(&error)),
            },
            Err(response) => {
                let error = response.error.clone().unwrap_or_else(|| HostCallErrorV2::new("INTERNAL", None));
                Err(kv_wit_error_from_frame(&error))
            }
        })
    }

    fn delete(&mut self, key: String, expected: Option<u64>) -> Result<Result<u64, iweb::kv::store::Error>, wasmtime::Error> {
        let response = self.provider.dispatch_wit_frame(
            "kv",
            "delete",
            &KvDeletePayload { key, expected },
            self.budget.frame_deadline_ms(),
        );
        Ok(match response {
            Ok(response) => match wit_ok_result::<KvVersionResult>(&response) {
                Ok(result) => Ok(result.version),
                Err(error) => Err(kv_wit_error_from_frame(&error)),
            },
            Err(response) => {
                let error = response.error.clone().unwrap_or_else(|| HostCallErrorV2::new("INTERNAL", None));
                Err(kv_wit_error_from_frame(&error))
            }
        })
    }

    fn list(
        &mut self,
        prefix: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<Result<iweb::kv::store::Page, iweb::kv::store::Error>, wasmtime::Error> {
        let response = self.provider.dispatch_wit_frame(
            "kv",
            "list",
            &KvListPayload { prefix, cursor, limit },
            self.budget.frame_deadline_ms(),
        );
        Ok(match response {
            Ok(response) => match wit_ok_result::<KvListResult>(&response) {
                Ok(result) => {
                    let mut items = Vec::with_capacity(result.items.len());
                    let mut failed = None;
                    for entry in result.items {
                        match wit_b64url_bytes(&entry.value) {
                            Ok(value) => items.push(iweb::kv::store::Item { key: entry.key, value, version: entry.version }),
                            Err(error) => {
                                failed = Some(kv_wit_error_from_frame(&error));
                                break;
                            }
                        }
                    }
                    match failed {
                        Some(error) => Err(error),
                        None => Ok(iweb::kv::store::Page { items, next_cursor: result.next_cursor }),
                    }
                }
                Err(error) => Err(kv_wit_error_from_frame(&error)),
            },
            Err(response) => {
                let error = response.error.clone().unwrap_or_else(|| HostCallErrorV2::new("INTERNAL", None));
                Err(kv_wit_error_from_frame(&error))
            }
        })
    }
}

/// iweb:sql/store 宿主实现。
pub struct SqlHostService {
    provider: Arc<HostServicesProvider>,
    budget: HostCallBudget,
}

impl SqlHostService {
    pub fn new(provider: Arc<HostServicesProvider>, budget: HostCallBudget) -> Self {
        Self { provider, budget }
    }
}

/// 帧响应 error → iweb:sql/store Error（detailCode 优先；code 兜底；未知 → Internal）。
fn sql_wit_error_from_frame(error: &HostCallErrorV2) -> iweb::sql::store::Error {
    match error.detail_code.as_deref() {
        Some("IWEB_SQL_INVALID_SQL") => iweb::sql::store::Error::InvalidSql,
        Some("IWEB_SQL_INVALID_PARAMETER") => iweb::sql::store::Error::InvalidParameter,
        Some("IWEB_SQL_CONSTRAINT") => iweb::sql::store::Error::Constraint,
        Some("IWEB_SQL_BUSY") => iweb::sql::store::Error::Busy,
        Some("IWEB_SQL_QUOTA_EXCEEDED") => iweb::sql::store::Error::QuotaExceeded,
        Some("IWEB_SQL_LIMIT_EXCEEDED") | Some("IWEB_SQL_TIMEOUT") => iweb::sql::store::Error::LimitExceeded,
        Some("IWEB_SQL_UNAVAILABLE") => iweb::sql::store::Error::Unavailable,
        // WIT 路径的 INVALID_ARGUMENT 只能来自非 canonical caller statement。
        Some("IWEB_SQL_INTERNAL") | Some("IWEB_WIT_PAYLOAD_NON_CANONICAL") | None if error.code == "INVALID_ARGUMENT" => {
            iweb::sql::store::Error::InvalidSql
        }
        Some(_) if error.code == "CONFLICT" => iweb::sql::store::Error::Constraint,
        Some(_) if error.code == "QUOTA_EXCEEDED" => iweb::sql::store::Error::QuotaExceeded,
        Some(_) if error.code == "LIMIT_EXCEEDED" => iweb::sql::store::Error::LimitExceeded,
        Some(_) if error.code == "BUSY" => iweb::sql::store::Error::Busy,
        Some(_) if error.code == "UNAVAILABLE" => iweb::sql::store::Error::Unavailable,
        _ => iweb::sql::store::Error::Internal,
    }
}

impl iweb::sql::store::Host for SqlHostService {
    fn execute(
        &mut self,
        statement: String,
        parameters: Vec<iweb::sql::store::Parameter>,
    ) -> Result<Result<iweb::sql::store::QueryResult, iweb::sql::store::Error>, wasmtime::Error> {
        let values: Vec<sql::SqlValue> = parameters.into_iter().map(|parameter| sql_value_from_wit(parameter.value)).collect();
        let payload = SqlExecutePayload {
            statement,
            parameters: values.iter().map(sql_value_to_payload).collect(),
        };
        let response = self
            .provider
            .dispatch_wit_frame("sql", "execute", &payload, self.budget.frame_deadline_ms());
        Ok(match response {
            Ok(response) => match wit_ok_result::<SqlExecuteResultPayload>(&response) {
                Ok(result) => {
                    let mut rows = Vec::with_capacity(result.rows.len());
                    let mut failed = None;
                    'outer: for row in result.rows {
                        let mut columns = Vec::with_capacity(row.columns.len());
                        for column in row.columns {
                            match sql_value_from_payload(&column.value) {
                                Ok(value) => columns.push(iweb::sql::store::Column { name: column.name, value: sql_value_to_wit(value) }),
                                Err(error) => {
                                    failed = Some(sql_wit_error_from_frame(&error));
                                    break 'outer;
                                }
                            }
                        }
                        rows.push(iweb::sql::store::Row { columns });
                    }
                    match failed {
                        Some(error) => Err(error),
                        None => Ok(iweb::sql::store::QueryResult {
                            rows,
                            affected: result.affected,
                            last_insert_id: result.last_insert_id,
                        }),
                    }
                }
                Err(error) => Err(sql_wit_error_from_frame(&error)),
            },
            Err(response) => {
                let error = response.error.clone().unwrap_or_else(|| HostCallErrorV2::new("INTERNAL", None));
                Err(sql_wit_error_from_frame(&error))
            }
        })
    }
}

fn sql_value_from_wit(value: iweb::sql::store::Value) -> sql::SqlValue {
    match value {
        iweb::sql::store::Value::Null => sql::SqlValue::Null,
        iweb::sql::store::Value::Integer(int) => sql::SqlValue::Integer(int),
        iweb::sql::store::Value::Real(real) => sql::SqlValue::Real(real),
        iweb::sql::store::Value::Text(text) => sql::SqlValue::Text(text),
        iweb::sql::store::Value::Blob(bytes) => sql::SqlValue::Blob(bytes),
    }
}

fn sql_value_to_wit(value: sql::SqlValue) -> iweb::sql::store::Value {
    match value {
        sql::SqlValue::Null => iweb::sql::store::Value::Null,
        sql::SqlValue::Integer(int) => iweb::sql::store::Value::Integer(int),
        sql::SqlValue::Real(real) => iweb::sql::store::Value::Real(real),
        sql::SqlValue::Text(text) => iweb::sql::store::Value::Text(text),
        sql::SqlValue::Blob(bytes) => iweb::sql::store::Value::Blob(bytes),
    }
}

/// iweb:logging/logger 宿主实现。
pub struct LoggingHostService {
    provider: Arc<HostServicesProvider>,
    budget: HostCallBudget,
}

impl LoggingHostService {
    pub fn new(provider: Arc<HostServicesProvider>, budget: HostCallBudget) -> Self {
        Self { provider, budget }
    }
}

/// 帧响应 error → iweb:logging/logger Error（detailCode 优先；code 兜底；未知 → Internal）。
fn logging_wit_error_from_frame(error: &HostCallErrorV2) -> iweb::logging::logger::Error {
    match error.detail_code.as_deref() {
        Some("IWEB_LOG_INVALID_EVENT") => iweb::logging::logger::Error::InvalidEvent,
        Some("IWEB_LOG_LIMIT_EXCEEDED") => iweb::logging::logger::Error::LimitExceeded,
        Some("IWEB_LOG_UNAVAILABLE") => iweb::logging::logger::Error::Unavailable,
        // WIT 路径的 INVALID_ARGUMENT 只能来自非 canonical caller field key/level 投影。
        Some("IWEB_LOG_APP_ISOLATION") | Some("IWEB_LOG_INTERNAL") | Some("IWEB_WIT_PAYLOAD_NON_CANONICAL") | None
            if error.code == "INVALID_ARGUMENT" =>
        {
            iweb::logging::logger::Error::InvalidEvent
        }
        Some(_) if error.code == "LIMIT_EXCEEDED" => iweb::logging::logger::Error::LimitExceeded,
        Some(_) if error.code == "UNAVAILABLE" => iweb::logging::logger::Error::Unavailable,
        _ => iweb::logging::logger::Error::Internal,
    }
}

impl iweb::logging::logger::Host for LoggingHostService {
    fn write(
        &mut self,
        event: iweb::logging::logger::Event,
    ) -> Result<Result<iweb::logging::logger::Outcome, iweb::logging::logger::Error>, wasmtime::Error> {
        let level = match event.level {
            iweb::logging::logger::Level::Trace => logging::LogLevel::Trace,
            iweb::logging::logger::Level::Debug => logging::LogLevel::Debug,
            iweb::logging::logger::Level::Info => logging::LogLevel::Info,
            iweb::logging::logger::Level::Warn => logging::LogLevel::Warn,
            iweb::logging::logger::Level::Error => logging::LogLevel::Error,
        };
        let payload = LoggingWritePayload {
            level: level.as_str().to_string(),
            message: encode_base64url(event.message.as_bytes()),
            fields: event
                .fields
                .into_iter()
                .map(|field| LoggingFieldPayload { key: field.key, value: encode_base64url(field.value.as_bytes()) })
                .collect(),
        };
        let response = self
            .provider
            .dispatch_wit_frame("logging", "write", &payload, self.budget.frame_deadline_ms());
        Ok(match response {
            Ok(response) => match wit_ok_result::<LoggingWriteResult>(&response) {
                Ok(result) => match result.outcome.as_str() {
                    "accepted" => Ok(iweb::logging::logger::Outcome::Accepted),
                    "dropped" => Ok(iweb::logging::logger::Outcome::Dropped),
                    _ => Err(iweb::logging::logger::Error::Internal),
                },
                Err(error) => Err(logging_wit_error_from_frame(&error)),
            },
            Err(response) => {
                let error = response.error.clone().unwrap_or_else(|| HostCallErrorV2::new("INTERNAL", None));
                Err(logging_wit_error_from_frame(&error))
            }
        })
    }
}

/// 把三个 host-service import 注册进 linker（仅 policy 启用的成员；未启用成员
/// 不注册——组件 import 即实例化失败，admission fail-closed 的运行侧对面）。
pub fn add_host_service_imports_to_linker<S>(
    linker: &mut wasmtime::component::Linker<S>,
    provider: &Arc<HostServicesProvider>,
    kv_state: fn(&mut S) -> &mut KvHostService,
    sql_state: fn(&mut S) -> &mut SqlHostService,
    logging_state: fn(&mut S) -> &mut LoggingHostService,
) -> wasmtime::Result<()> {
    if provider.kv_enabled() {
        iweb::kv::store::add_to_linker::<_, wasmtime::component::HasSelf<KvHostService>>(linker, kv_state)?;
    }
    if provider.sql_enabled() {
        iweb::sql::store::add_to_linker::<_, wasmtime::component::HasSelf<SqlHostService>>(linker, sql_state)?;
    }
    if provider.logging_enabled() {
        iweb::logging::logger::add_to_linker::<_, wasmtime::component::HasSelf<LoggingHostService>>(linker, logging_state)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
