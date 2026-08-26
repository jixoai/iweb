//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1/8.1 语义子集）：snapshot FD
//! 三方契约的 wasmd 侧——验证槽位号（secret=3、config=4）、O_RDONLY、regular file、
//! 并按同一域前缀单次 SHA-256 复算 digest（wasmd.readDigest 与 fdDigest 同式）。
//! configRevision:0 时 FD 4 必须不存在；两个 FD 都绝不传给网关或非 wasmd 子进程。
//! 规范权威：spec "Snapshot FD content is bound across Kernel, supervisor, Podman,
//! and wasmd" 与 "Secret snapshot references have one Kernel-resolved, read-only FD"。
//!
//! TODO(5.x Linux 实测)：Podman `--preserve-fds=2`、FD_CLOEXEC 清除范围与容器入口
//! 描述符清理属任务 5.1/8.1 的真实双容器验收；本模块只承载 wasmd 进程内可证明的部分
//! （macOS/Linux 均可运行的 fcntl/fstat/read 语义）。

use crate::jcs::{domain_digest, err, WireError};
use crate::wire::{SnapshotValuesPayloadV1, WasmdIdentityV1};
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;


/// wasmd 补充稳定码：FD 槽位/只读/regular/身份/digest 任一不满足。
pub const WASMD_SNAPSHOT_FD_INVALID: &str = "WASMD_SNAPSHOT_FD_INVALID";
/// 规范域前缀（secret 与 config 各一；wasmd.readDigest 与 fdDigest 同式）。
pub const SECRET_SNAPSHOT_DIGEST_DOMAIN: &str = "iweb-secret-snapshot-v1";
pub const CONFIG_SNAPSHOT_DIGEST_DOMAIN: &str = "iweb-config-snapshot-v1";

/// 固定槽位。
pub const SECRET_FD: i32 = 3;
pub const CONFIG_FD: i32 = 4;

/// 读单个 FD 的完整内容（pread 语义：从 offset 0 读到 EOF，不重序列化）。
fn read_fd(fd: i32, noun: &str) -> Result<Vec<u8>, WireError> {
    let mut file = ManuallyCheckedFd::wrap(fd, noun)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| err(WASMD_SNAPSHOT_FD_INVALID, format!("{noun}: reading the descriptor failed: {e}")))?;
    Ok(bytes)
}

/// 验证 FD 状态：已打开（F_GETFD 不返回 EBADF）、O_RDONLY（无写位）、regular file。
fn check_fd_state(fd: i32, noun: &str) -> Result<(), WireError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(err(WASMD_SNAPSHOT_FD_INVALID, format!("{noun}: descriptor is not open (fcntl F_GETFL failed)")));
    }
    let access = flags & libc::O_ACCMODE;
    if access != libc::O_RDONLY {
        return Err(err(WASMD_SNAPSHOT_FD_INVALID, format!("{noun}: descriptor must be read-only (O_RDONLY)")));
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut stat) };
    if rc != 0 {
        return Err(err(WASMD_SNAPSHOT_FD_INVALID, format!("{noun}: fstat failed")));
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(err(WASMD_SNAPSHOT_FD_INVALID, format!("{noun}: descriptor must reference a regular file")));
    }
    Ok(())
}

/// 包装原始 FD：仅做状态检查与读取；所有权仍属进程启动继承（drop 不关闭，避免
/// 误伤 supervisor 契约之外的描述符生命周期语义；读取完成后由 Drop 统一处理见
/// SnapshotSlots）。
struct ManuallyCheckedFd {
    file: Option<File>,
}

impl ManuallyCheckedFd {
    fn wrap(fd: i32, noun: &str) -> Result<Self, WireError> {
        check_fd_state(fd, noun)?;
        // SAFETY：FD 已验证处于打开状态；File 仅用于读取，drop 时关闭描述符
        // （本进程不再需要；spec 要求 wasmd 不把它传给任何子进程——本进程无子进程）。
        Ok(Self { file: Some(unsafe { File::from_raw_fd(fd) }) })
    }
}

impl std::io::Read for ManuallyCheckedFd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.as_mut().expect("file present").read(buf)
    }
}

/// 验证后的快照槽位（值载荷已解析并绑定到身份 tuple）。
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotSlots {
    pub secret: SnapshotValuesPayloadV1,
    /// configRevision:0 时为 None（FD 4 必须缺席）。
    pub config: Option<SnapshotValuesPayloadV1>,
}

/// 消费固定槽位 3/4：验证、按域前缀复算 digest、与身份 tuple 绑定。
/// - FD 3 必须存在；fdDigest == identity.secretValuesDigest；
/// - payload 的 versionId/preparationGeneration/revision 必须与身份 tuple 相等
///   （applicationId 不在 argv 身份里，由 digest 绑定唯一锚定——见报告歧义）；
/// - configRevision == 0 时 FD 4 必须不存在（EBADF）；否则镜像检查。
pub fn consume_snapshot_slots(identity: &WasmdIdentityV1) -> Result<SnapshotSlots, WireError> {
    consume_snapshot_slots_at(SECRET_FD, CONFIG_FD, identity)
}

/// 参数化槽位消费（生产固定 3/4；测试用高位槽位避免与并发测试的 fd 分配竞争）。
fn consume_snapshot_slots_at(
    secret_fd: i32,
    config_fd: i32,
    identity: &WasmdIdentityV1,
) -> Result<SnapshotSlots, WireError> {
    // FD 3：secret 快照（每个 prepare/start 命令都有，包括 revision 0 的空快照）。
    let secret_bytes = read_fd(secret_fd, "secret fd 3")?;
    let secret_digest = domain_digest(SECRET_SNAPSHOT_DIGEST_DOMAIN, &secret_bytes);
    if secret_digest != identity.secret_values_digest {
        return Err(err(WASMD_SNAPSHOT_FD_INVALID, "secret fd digest does not equal the identity-pinned secretValuesDigest"));
    }
    let secret = SnapshotValuesPayloadV1::parse(&secret_bytes, "secret snapshot")?;
    bind_payload_to_identity(&secret, identity, identity.secret_revision, "secret")?;

    let config = if identity.config_revision == 0 {
        // FD 4 必须缺席：fcntl(F_GETFD) 必须返回 EBADF。
        let flags = unsafe { libc::fcntl(config_fd, libc::F_GETFD) };
        if flags >= 0 {
            return Err(err(WASMD_SNAPSHOT_FD_INVALID, "config fd 4 must be absent when configRevision is 0"));
        }
        None
    } else {
        let config_bytes = read_fd(config_fd, "config fd 4")?;
        let config_digest = domain_digest(CONFIG_SNAPSHOT_DIGEST_DOMAIN, &config_bytes);
        let expected = required_digest(identity.config_values_digest.as_deref(), "non-zero revision carries digest")?;
        if config_digest != expected {
            return Err(err(WASMD_SNAPSHOT_FD_INVALID, "config fd digest does not equal the identity-pinned configValuesDigest"));
        }
        let config = SnapshotValuesPayloadV1::parse(&config_bytes, "config snapshot")?;
        bind_payload_to_identity(&config, identity, identity.config_revision, "config")?;
        Some(config)
    };
    Ok(SnapshotSlots { secret, config })
}

/// payload 与身份 tuple 的三字段绑定（versionId/preparationGeneration/revision）。
/// applicationId 不在 argv 身份 tuple 里：由域前缀 digest（与 Kernel 命令 digest 同源）
/// 唯一锚定——见模块报告歧义备注。
fn bind_payload_to_identity(
    payload: &SnapshotValuesPayloadV1,
    identity: &WasmdIdentityV1,
    revision: u64,
    noun: &str,
) -> Result<(), WireError> {
    if payload.version_id != identity.version_id
        || payload.preparation_generation != identity.preparation_generation
        || payload.revision != revision
    {
        return Err(err(WASMD_SNAPSHOT_FD_INVALID, format!("{noun} snapshot payload does not match the identity tuple (versionId/preparationGeneration/revision)")));
    }
    Ok(())
}

/// 内部不变式的窄化 Option 错误（非外部输入路径；保持无 unwrap 纪律）。
fn required_digest<'a>(value: Option<&'a str>, message: &str) -> Result<&'a str, WireError> {
    value.ok_or_else(|| err(WASMD_SNAPSHOT_FD_INVALID, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::RuntimeBindingIdentityV1;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    fn identity_for(secret_digest: &str, config: Option<&str>) -> WasmdIdentityV1 {
        WasmdIdentityV1 {
            sandbox_id: "sbx-vector".into(),
            version_id: format!("{}-1", "a".repeat(64)),
            package_digest: "0".repeat(64),
            runtime_binding: RuntimeBindingIdentityV1 {
                kind: "wasm".into(),
                catalog_revision: 9,
                catalog_hash: "ab".repeat(32),
                entry_key: "iweb-wasmd".into(),
                image_digest: format!("sha256:{}", "cd".repeat(32)),
                host_abi: "iweb-wasmd-abi@1.0.0".into(),
                world: "wasi:http/proxy@0.2.8".into(),
            },
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            secret_revision: 3,
            secret_values_digest: secret_digest.to_string(),
            config_revision: if config.is_some() { 2 } else { 0 },
            config_snapshot_ref: config.map(|_| "7".repeat(64)),
            config_values_digest: config.map(|digest| digest.to_string()),
            preparation_generation: 1,
            execution_generation: 1,
        }
    }

    fn payload_bytes(revision: u64, keys: &[(&str, &str)]) -> Vec<u8> {
        let mut values = std::collections::BTreeMap::new();
        for (key, value) in keys {
            values.insert(key.to_string(), value.to_string());
        }
        let payload = SnapshotValuesPayloadV1 {
            application_id: "alpha".into(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            revision,
            keys: keys.iter().map(|(key, _)| key.to_string()).collect(),
            values,
        };
        crate::jcs::jcs_bytes(&payload).expect("payload jcs")
    }

    /// 测试使用高位槽位（100/101），避免与并发测试的 fd 分配竞争；生产路径固定 3/4。
    const TEST_SECRET_FD: i32 = 100;
    const TEST_CONFIG_FD: i32 = 101;

    /// 槽位测试之间串行（100/101 是同一对全局资源）。
    static SLOT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 把 JCS 载荷写进临时文件并临时占用指定槽位（dup2）。
    #[allow(clippy::type_complexity)]
    fn occupy_slot(fd: i32, bytes: &[u8]) -> Box<dyn FnOnce() + '_> {
        let mut named = tempfile::NamedTempFile::new().expect("temp file");
        named.write_all(bytes).expect("write payload");
        named.flush().expect("flush");
        // 以 O_RDONLY 打开真实路径（生产契约：只读 regular file；/dev/fd 在 BSD 系
        // 会复制原访问模式，不能用）。
        let file = std::fs::File::open(named.path()).expect("reopen read-only");
        drop(named);
        // 测试槽位在测试进程内通常关闭；dup 失败时无保存项，恢复即关闭。
        let saved = unsafe { libc::dup(fd) };
        let rc = unsafe { libc::dup2(file.as_raw_fd(), fd) };
        assert!(rc >= 0, "dup2 onto slot");
        Box::new(move || {
            if saved >= 0 {
                unsafe { libc::dup2(saved, fd) };
                unsafe { libc::close(saved) };
            } else {
                unsafe { libc::close(fd) };
            }
        })
    }

    #[test]
    fn secret_fd_digest_and_tuple_binding() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let bytes = payload_bytes(3, &[("token", "v")]);
        let digest = domain_digest(SECRET_SNAPSHOT_DIGEST_DOMAIN, &bytes);
        let identity = identity_for(&digest, None);
        let restore = occupy_slot(TEST_SECRET_FD, &bytes);
        // FD 4 等价槽位缺席（fcntl(F_GETFD) 返回 EBADF）。
        let saved4 = unsafe { libc::fcntl(TEST_CONFIG_FD, libc::F_GETFD) };
        let had4 = saved4 >= 0;
        let backup4 = if had4 { Some(unsafe { libc::dup(TEST_CONFIG_FD) }) } else { None };
        if had4 {
            unsafe { libc::close(TEST_CONFIG_FD) };
        }
        let slots = consume_snapshot_slots_at(TEST_SECRET_FD, TEST_CONFIG_FD, &identity).expect("slots consumed");
        restore();
        assert_eq!(slots.secret.revision, 3);
        assert!(slots.config.is_none());
        if let Some(backup) = backup4 {
            assert!(unsafe { libc::dup2(backup, TEST_CONFIG_FD) } >= 0);
            unsafe { libc::close(backup) };
        }
    }

    #[test]
    fn wrong_digest_fails_closed() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let bytes = payload_bytes(3, &[("token", "v")]);
        let identity = identity_for(&crate::jcs::sha256_hex(b"other"), None);
        let restore = occupy_slot(TEST_SECRET_FD, &bytes);
        let saved4 = unsafe { libc::fcntl(TEST_CONFIG_FD, libc::F_GETFD) };
        let had4 = saved4 >= 0;
        let backup4 = if had4 { Some(unsafe { libc::dup(TEST_CONFIG_FD) }) } else { None };
        if had4 {
            unsafe { libc::close(TEST_CONFIG_FD) };
        }
        let error = consume_snapshot_slots_at(TEST_SECRET_FD, TEST_CONFIG_FD, &identity).expect_err("digest mismatch");
        restore();
        if let Some(backup) = backup4 {
            assert!(unsafe { libc::dup2(backup, TEST_CONFIG_FD) } >= 0);
            unsafe { libc::close(backup) };
        }
        assert_eq!(error.code, WASMD_SNAPSHOT_FD_INVALID);
    }

    #[test]
    fn config_fd_present_with_revision_zero_fails_closed() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let bytes = payload_bytes(3, &[("token", "v")]);
        let digest = domain_digest(SECRET_SNAPSHOT_DIGEST_DOMAIN, &bytes);
        let identity = identity_for(&digest, None);
        let restore_secret = occupy_slot(TEST_SECRET_FD, &bytes);
        let config_bytes = payload_bytes(2, &[("mode", "x")]);
        let restore_config = occupy_slot(TEST_CONFIG_FD, &config_bytes);
        let error = consume_snapshot_slots_at(TEST_SECRET_FD, TEST_CONFIG_FD, &identity).expect_err("fd 4 present");
        restore_secret();
        restore_config();
        assert_eq!(error.code, WASMD_SNAPSHOT_FD_INVALID);
    }

    #[test]
    fn config_fd_digest_mismatch_fails_closed() {
        let _guard = SLOT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let secret_bytes = payload_bytes(3, &[("token", "v")]);
        let secret_digest = domain_digest(SECRET_SNAPSHOT_DIGEST_DOMAIN, &secret_bytes);
        let config_bytes = payload_bytes(2, &[("mode", "x")]);
        let wrong_config_digest = domain_digest(CONFIG_SNAPSHOT_DIGEST_DOMAIN, b"other");
        let identity = identity_for(&secret_digest, Some(&wrong_config_digest));
        let restore_secret = occupy_slot(TEST_SECRET_FD, &secret_bytes);
        let restore_config = occupy_slot(TEST_CONFIG_FD, &config_bytes);
        let error = consume_snapshot_slots_at(TEST_SECRET_FD, TEST_CONFIG_FD, &identity).expect_err("config digest mismatch");
        restore_secret();
        restore_config();
        assert_eq!(error.code, WASMD_SNAPSHOT_FD_INVALID);
    }
}
