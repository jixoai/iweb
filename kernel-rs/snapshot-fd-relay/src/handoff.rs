//! 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 3）：relay 代持台账——把经
//! SCM_RIGHTS 收到的（handoff payload, descriptor, fd 字节）按 commandId 持有，供 Node
//! supervisor 查询复核与 FD 注入 spawn；重复投递幂等、身份分歧冲突、过期/摘要链失败一律
//! fail-closed。
//!
//! 规范权威：spec "Snapshot descriptors use an independent framed raw socket"（重复
//! commandId 同 handoffDigest → 存档 ack；不同 → SNAPSHOT_HANDOFF_ID_CONFLICT）与
//! "Snapshot FD content is bound across Kernel, supervisor, Podman, and wasmd"（摘要链
//! 等式、fstat regular + F_GETFL read-only、expiresAt 窗口）。摘要与 payload 判定复用
//! iweb-kernel::wasm_snapshot_fd 纯函数，不造第二套。

use iweb_kernel::wasm_snapshot_fd::{
    compute_snapshot_fd_digest,
    compute_snapshot_handoff_digest,
    SnapshotFdAckV1,
    SnapshotFdError,
    SnapshotAckStatus,
    SnapshotHandoffPayload,
    SNAPSHOT_FD_POLICY_REJECTED,
    SNAPSHOT_HANDOFF_ID_CONFLICT,
    SNAPSHOT_VALUES_DIGEST_MISMATCH,
    SNAPSHOT_WIRE_INVALID,
};
use iweb_kernel::wasm_admission::parse_rfc3339_utc_millis;
use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::Mutex;

/// secret handoff 过期拒绝码（spec 已命名；kernel 侧常量集未导出，relay 以同名对位）。
pub const IWEB_SECRET_SNAPSHOT_EXPIRED: &str = "IWEB_SECRET_SNAPSHOT_EXPIRED";
/// config handoff 过期拒绝码（spec 已命名）。
pub const IWEB_CONFIG_SNAPSHOT_EXPIRED: &str = "IWEB_CONFIG_SNAPSHOT_EXPIRED";
/// spawn 时找不到代持 handoff 的内部码（非 spec wire 稳定码）。
pub const SNAPSHOT_HANDOFF_MISSING: &str = "SNAPSHOT_HANDOFF_MISSING";

/// 一条已接受的 handoff：payload + 代持描述符 + 已读字节 + 描述符事实 + 存档 ack。
pub struct HeldHandoff {
    pub payload: SnapshotHandoffPayload,
    pub fd: OwnedFd,
    pub fd_bytes: Vec<u8>,
    pub descriptor_regular_file: bool,
    pub descriptor_read_only: bool,
    /// 接受时产出的 accepted ack（重复同 digest 投递原样重发，幂等）。
    pub stored_ack: SnapshotFdAckV1,
}

/// 每 commandId 的代持组：恰好一条 secret（spec：每个 prepare/start 恰一 secret 帧）+
/// 至多一条 config（仅当 configRevision > 0）。
#[derive(Default)]
pub struct HeldCommand {
    pub secret: Option<HeldHandoff>,
    pub config: Option<HeldHandoff>,
}

/// 代持台账：commandId → HeldCommand；`next_journal_revision` 是 relay 本地 handoff 序号
/// （ack payload 的 journalRevision 字段来源；supervisor 真正的执行 journal 由 Node 侧
/// wasm-control.ts 持有，该字段在 7.3 全链路接线时对齐——relay 只保证单调递增可对账）。
pub struct HandoffTable {
    inner: Mutex<HashMap<String, HeldCommand>>,
    next_journal_revision: Mutex<u64>,
}

impl HandoffTable {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            next_journal_revision: Mutex::new(0),
        }
    }

    fn allocate_journal_revision(&self) -> u64 {
        let mut revision = self.next_journal_revision.lock().expect("handoff journal revision lock");
        *revision += 1;
        *revision
    }

    /// 幂等查询（不消费）：FD 留在台账内，视图携带 fd 字节与描述符事实供 Node 复核。
    pub fn lookup(&self, command_id: &str) -> (Option<HeldHandoffSummary>, Option<HeldHandoffSummary>) {
        let guard = self.inner.lock().expect("handoff table lock");
        let Some(command) = guard.get(command_id) else {
            return (None, None);
        };
        let secret = command.secret.as_ref().map(HeldHandoffSummary::from);
        let config = command.config.as_ref().map(HeldHandoffSummary::from);
        (secret, config)
    }

    /// spawn 前置：判定代持齐备并暴露原始 fd 编号（dup2 发生在 fork 出的子进程内，
    /// 见 spawn.rs；台账锁在 spawn 全程持有，避免并发消费）。
    pub fn with_spawn_inputs<T>(&self, command_id: &str, run: impl FnOnce(SpawnInputs) -> T) -> Result<T, &'static str> {
        let guard = self.inner.lock().expect("handoff table lock");
        let Some(command) = guard.get(command_id) else {
            return Err(SNAPSHOT_HANDOFF_MISSING);
        };
        let Some(secret) = command.secret.as_ref() else {
            return Err(SNAPSHOT_HANDOFF_MISSING);
        };
        let config = command.config.as_ref().map(|held| held.fd.as_fd().as_raw_fd());
        Ok(run(SpawnInputs { secret_fd: secret.fd.as_fd().as_raw_fd(), config_fd: config }))
    }

    /// spawn 成功后消费：关闭代持描述符并移除台账（容器侧经 conmon 持有注入后的 FD）。
    /// 失败路径不消费（同命令字节重放可再试；Kernel 亦可经 query/replay 重发帧）。
    pub fn consume(&self, command_id: &str) -> u32 {
        let mut guard = self.inner.lock().expect("handoff table lock");
        guard
            .remove(command_id)
            .map(|command| u32::from(command.secret.is_some()) + u32::from(command.config.is_some()))
            .unwrap_or(0)
    }

    /// 接受一条 handoff：过期 → 摘要链 → 描述符策略 → 台账幂等/冲突。返回应回发的 ack。
    pub fn accept(
        &self,
        payload: SnapshotHandoffPayload,
        fd: OwnedFd,
        fd_bytes: Vec<u8>,
        descriptor_regular_file: bool,
        descriptor_read_only: bool,
        now_epoch_millis: i64,
    ) -> Result<SnapshotFdAckV1, SnapshotFdError> {
        let expired_code = match &payload {
            SnapshotHandoffPayload::Secret(_) => IWEB_SECRET_SNAPSHOT_EXPIRED,
            SnapshotHandoffPayload::Config(_) => IWEB_CONFIG_SNAPSHOT_EXPIRED,
        };
        // 过期窗口（spec：expiresAt bounds the handoff window；接受前逐字校验）。
        let expires_millis = handoff_expires_epoch_millis(&payload)?;
        if now_epoch_millis >= expires_millis {
            return Err(SnapshotFdError::new(expired_code, "the snapshot handoff window has expired; no descriptor is retained"));
        }
        // 摘要链：fdDigest == valuesDigest == 域前缀单次 SHA-256(fdBytes)。
        let recomputed = compute_snapshot_fd_digest(payload.frame_kind(), &fd_bytes)?;
        let (payload_fd_digest, payload_values_digest) = match &payload {
            SnapshotHandoffPayload::Secret(p) => (p.fd_digest.clone(), p.values_digest.clone()),
            SnapshotHandoffPayload::Config(p) => (p.fd_digest.clone(), p.values_digest.clone()),
        };
        if recomputed != payload_fd_digest || recomputed != payload_values_digest {
            return Err(SnapshotFdError::new(
                SNAPSHOT_VALUES_DIGEST_MISMATCH,
                "the descriptor bytes digest does not equal the handoff fdDigest and valuesDigest",
            ));
        }
        // 描述符策略事实由调用方（recv 路径 fstat/F_GETFL）给出；未证明即拒绝。
        if !descriptor_regular_file || !descriptor_read_only {
            return Err(SnapshotFdError::new(
                SNAPSHOT_FD_POLICY_REJECTED,
                "the received descriptor must reference a regular read-only file",
            ));
        }
        let handoff_digest = compute_snapshot_handoff_digest(&payload)?;
        let command_id = payload.command_id().to_string();
        let mut guard = self.inner.lock().expect("handoff table lock");
        let command = guard.entry(command_id.clone()).or_default();
        let slot = match &payload {
            SnapshotHandoffPayload::Secret(_) => &mut command.secret,
            SnapshotHandoffPayload::Config(_) => &mut command.config,
        };
        if let Some(existing) = slot {
            // 幂等：同 commandId 同 handoff 字节 → 存档 ack；分歧 → ID_CONFLICT。
            let existing_digest = compute_snapshot_handoff_digest(&existing.payload)?;
            if existing_digest == handoff_digest {
                return Ok(existing.stored_ack.clone());
            }
            return Err(SnapshotFdError::new(
                SNAPSHOT_HANDOFF_ID_CONFLICT,
                "a known commandId was re-sent with a differing handoff body; no descriptor is replaced",
            ));
        }
        let revision = self.allocate_journal_revision();
        let ack = SnapshotFdAckV1 {
            schema_version: 1,
            kind: "ack".to_string(),
            command_id,
            handoff_digest,
            status: SnapshotAckStatus::Accepted,
            failure_code: None,
            journal_revision: revision,
        };
        *slot = Some(HeldHandoff {
            payload,
            fd,
            fd_bytes,
            descriptor_regular_file,
            descriptor_read_only,
            stored_ack: ack.clone(),
        });
        Ok(ack)
    }
}

/// spawn 子进程需要的 FD 编号（在台账锁内取得，避免取出后并发消费）。
pub struct SpawnInputs {
    pub secret_fd: i32,
    pub config_fd: Option<i32>,
}

fn handoff_expires_epoch_millis(payload: &SnapshotHandoffPayload) -> Result<i64, SnapshotFdError> {
    let expires_at = match payload {
        SnapshotHandoffPayload::Secret(p) => p.expires_at.clone(),
        SnapshotHandoffPayload::Config(p) => p.expires_at.clone(),
    };
    let millis = parse_rfc3339_utc_millis(&expires_at)
        .map_err(|error| SnapshotFdError::new(SNAPSHOT_WIRE_INVALID, format!("expiresAt is not RFC3339 UTC: {}", error.detail)))?;
    i64::try_from(millis).map_err(|_| SnapshotFdError::new(SNAPSHOT_WIRE_INVALID, "expiresAt exceeds the epoch-millisecond domain"))
}

/// 查询视图的纯数据部分（control.rs 的 HandoffView 由 main.rs 组装 base64）。
pub struct HeldHandoffSummary {
    pub payload: SnapshotHandoffPayload,
    pub fd_bytes: Vec<u8>,
    pub descriptor_regular_file: bool,
    pub descriptor_read_only: bool,
}

impl From<&HeldHandoff> for HeldHandoffSummary {
    fn from(held: &HeldHandoff) -> Self {
        Self {
            payload: held.payload.clone(),
            fd_bytes: held.fd_bytes.clone(),
            descriptor_regular_file: held.descriptor_regular_file,
            descriptor_read_only: held.descriptor_read_only,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iweb_kernel::wasm_snapshot_fd::{SecretSnapshotFdHandoffV1, SnapshotFrameKind};

    fn secret_handoff(values_digest: &str, fd_digest: &str, expires_at: &str) -> SecretSnapshotFdHandoffV1 {
        SecretSnapshotFdHandoffV1 {
            schema_version: 1,
            kind: "secret".to_string(),
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".to_string(),
            command_digest: "1".repeat(64),
            reference: "5".repeat(64),
            application_id: "vector".to_string(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            secret_revision: 3,
            values_digest: values_digest.to_string(),
            fd_digest: fd_digest.to_string(),
            expires_at: expires_at.to_string(),
        }
    }

    /// 以只读 regular 临时文件充当收到的描述符（策略事实显式给出，测试不依赖 F_GETFL）。
    fn temp_descriptor(bytes: &[u8]) -> OwnedFd {
        use std::os::fd::{FromRawFd, IntoRawFd};
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let unique = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("iweb-relay-handoff-{}-{unique}-{}", std::process::id(), bytes.len()));
        std::fs::write(&path, bytes).expect("write temp descriptor bytes");
        let raw = std::fs::File::open(&path).expect("reopen temp descriptor read-only").into_raw_fd();
        let _ = std::fs::remove_file(&path);
        unsafe { OwnedFd::from_raw_fd(raw) }
    }

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn accepts_a_digest_consistent_handoff_and_replays_idempotently() {
        let table = HandoffTable::new();
        let bytes = b"{\"k\":\"v\"}".to_vec();
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &bytes).unwrap();
        let payload = SnapshotHandoffPayload::Secret(secret_handoff(&digest, &digest, "2100-01-01T00:00:00Z"));
        let first = table.accept(payload.clone(), temp_descriptor(&bytes), bytes.clone(), true, true, NOW).unwrap();
        assert_eq!(first.journal_revision, 1);
        // 同 commandId 同 digest 重复投递 → 存档 ack（同一 journalRevision）。
        let second = table.accept(payload, temp_descriptor(&bytes), bytes, true, true, NOW).unwrap();
        assert_eq!(second, first);
    }

    #[test]
    fn mismatched_digest_chain_is_rejected() {
        let table = HandoffTable::new();
        let bytes = b"{\"k\":\"v\"}".to_vec();
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &bytes).unwrap();
        let payload = SnapshotHandoffPayload::Secret(secret_handoff(&digest, &"0".repeat(64), "2100-01-01T00:00:00Z"));
        let rejected = table.accept(payload, temp_descriptor(&bytes), bytes, true, true, NOW).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_VALUES_DIGEST_MISMATCH);
    }

    #[test]
    fn expired_window_is_rejected_with_the_kind_code() {
        let table = HandoffTable::new();
        let bytes = b"{}".to_vec();
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &bytes).unwrap();
        let payload = SnapshotHandoffPayload::Secret(secret_handoff(&digest, &digest, "2020-01-01T00:00:00Z"));
        let rejected = table.accept(payload, temp_descriptor(&bytes), bytes, true, true, NOW).unwrap_err();
        assert_eq!(rejected.code, IWEB_SECRET_SNAPSHOT_EXPIRED);
    }

    #[test]
    fn unproven_descriptor_policy_fails_closed() {
        let table = HandoffTable::new();
        let bytes = b"{}".to_vec();
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &bytes).unwrap();
        let payload = SnapshotHandoffPayload::Secret(secret_handoff(&digest, &digest, "2100-01-01T00:00:00Z"));
        let rejected = table.accept(payload, temp_descriptor(&bytes), bytes, true, false, NOW).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_FD_POLICY_REJECTED);
    }

    #[test]
    fn conflicting_duplicate_command_id_is_rejected() {
        let table = HandoffTable::new();
        let bytes = b"{}".to_vec();
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &bytes).unwrap();
        let first = SnapshotHandoffPayload::Secret(secret_handoff(&digest, &digest, "2100-01-01T00:00:00Z"));
        table.accept(first, temp_descriptor(&bytes), bytes, true, true, NOW).unwrap();
        // 同 commandId 但 valuesDigest 分歧（digest 链对新字节成立）→ ID_CONFLICT。
        let other_bytes = b"{\"other\":true}".to_vec();
        let other_digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &other_bytes).unwrap();
        let conflicting = SnapshotHandoffPayload::Secret(secret_handoff(&other_digest, &other_digest, "2100-01-01T00:00:00Z"));
        let rejected = table.accept(conflicting, temp_descriptor(&other_bytes), other_bytes, true, true, NOW).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_HANDOFF_ID_CONFLICT);
    }

    #[test]
    fn lookup_spawn_inputs_and_consume_track_held_kinds() {
        let table = HandoffTable::new();
        let bytes = b"secret".to_vec();
        let digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &bytes).unwrap();
        let payload = SnapshotHandoffPayload::Secret(secret_handoff(&digest, &digest, "2100-01-01T00:00:00Z"));
        table.accept(payload, temp_descriptor(&bytes), bytes, true, true, NOW).unwrap();
        let (secret_view, config_view) = table.lookup("018f1e2c-3d4b-7a5e-9f01-23456789abcd");
        assert!(secret_view.is_some(), "the accepted secret handoff must be visible to lookup");
        assert!(config_view.is_none(), "no config frame was handed off");
        let seen = table
            .with_spawn_inputs("018f1e2c-3d4b-7a5e-9f01-23456789abcd", |inputs| (inputs.secret_fd >= 0, inputs.config_fd.is_none()))
            .unwrap();
        assert_eq!(seen, (true, true));
        assert_eq!(table.consume("018f1e2c-3d4b-7a5e-9f01-23456789abcd"), 1);
        // 消费后：查无、spawn 无输入、再消费幂等为 0。
        assert!(table.lookup("018f1e2c-3d4b-7a5e-9f01-23456789abcd").0.is_none());
        assert!(table.with_spawn_inputs("018f1e2c-3d4b-7a5e-9f01-23456789abcd", |_| ()).is_err());
        assert_eq!(table.consume("018f1e2c-3d4b-7a5e-9f01-23456789abcd"), 0);
    }
}
