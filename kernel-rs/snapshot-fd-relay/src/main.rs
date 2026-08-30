//! 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2+3；R2 修复轮 2026-08-30
//! tasks 9.2 直执行）：snapshot FD 原生 relay 二进制——supervisor（Node）的子进程，
//! 持有 `/run/iweb-sandbox/snapshot-fd.sock` 的 SOCK_SEQPACKET 循环
//! （recvmsg/SCM_RIGHTS/对端凭据/帧校验全按 iweb-kernel wasm_snapshot.rs 既有纯函数
//! 复用），并经 SOCK_STREAM 控制 socket 接受 supervisor 指令：查询 handoff、以代持
//! FD 直 execv 固定的 wasmd 二进制（`--exec`；无 shell、无 launcher、无参数拼接）、
//! 等待子进程退出（wait/reap 关系）、释放。子进程退出由专用 reaper 线程回收并按
//! commandId 记录，经 wait 指令上报控制 socket。
//!
//! 形态取舍（见子代理报告）：Node/Bun 无 SCM_RIGHTS 接收能力，FD 无法经 pipe/UDS 传回
//! Node，故 relay 代持描述符并按 supervisor 指令执行 FD 承载的 spawn——这是 spec 三方
//! 契约（Kernel → SCM_RIGHTS → supervisor → relay 直 execv → wasmd fd 3/4）下唯一
//! 不造第二套传递语义的形态。
//!
//! 能力边界（诚实声明）：AF_UNIX SOCK_SEQPACKET 在 macOS 不可用（EPROTONOSUPPORT）——
//! 非 Linux 宿主上 fd socket 绑定失败即以 SNAPSHOT_TRANSPORT_UNAVAILABLE 退出（fail-
//! closed，绝不降级 SOCK_DGRAM/STREAM）。Linux 实机对拍（Kernel 端 connect/sendmsg 与
//! relay 端 recvmsg 全链路）由 `tests/relay_integration.rs` 的 linux-gated 用例覆盖。

mod control;
mod execution_proxy;
mod handoff;
mod spawn;

use execution_proxy::{bind_execution_listener, run_execution_proxy, ExecutionProxyConfig};
use handoff::{HandoffTable, HeldHandoffSummary};
use iweb_kernel::wasm_snapshot_fd::{
    receive_snapshot_request,
    send_snapshot_frame_without_ancillary,
    require_peer_credentials,
    require_seqpacket_socket,
    SnapshotFdAckV1,
    SnapshotAckStatus,
    SnapshotHandoffPayload,
    SnapshotSocketPeer,
    SNAPSHOT_TRANSPORT_UNAVAILABLE,
};
use spawn::{ChildTable, SpawnChild};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_FD_SOCKET_PATH: &str = "/run/iweb-sandbox/snapshot-fd.sock";
const DEFAULT_CONTROL_SOCKET_PATH: &str = "/run/iweb-sandbox/snapshot-fd-relay.sock";
/// 直执行目标缺省值：digest-pinned wasmd 二进制的容器内路径（与 supervisor
/// DEFAULT_WASMD_BINARY_PATH 对齐；supervisor 以 `--exec` 显式传入）。
const DEFAULT_EXEC_PATH: &str = "/opt/iweb/wasmd/iweb-wasmd";
/// wait 指令的时限上限（防无界占用控制连接；supervisor 可用更短值轮询）。
const WAIT_TIMEOUT_MAX_MS: u64 = 60_000;

struct RelayConfig {
    fd_socket: PathBuf,
    control_socket: PathBuf,
    kernel_peer: SnapshotSocketPeer,
    exec_path: String,
    execution: Option<ExecutionProxyConfig>,
}

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!(
        "usage: snapshot-fd-relay [--fd-socket PATH] [--control-socket PATH] \
         [--kernel-peer-uid UID] [--kernel-peer-gid GID] [--exec PATH] \
         [--execution-socket PATH --execution-upstream PATH --execution-upstream-token HEX]"
    );
    std::process::exit(code)
}

fn parse_config(args: &[String]) -> RelayConfig {
    let mut config = RelayConfig {
        fd_socket: PathBuf::from(DEFAULT_FD_SOCKET_PATH),
        control_socket: PathBuf::from(DEFAULT_CONTROL_SOCKET_PATH),
        kernel_peer: SnapshotSocketPeer { uid: 0, gid: 0 },
        exec_path: DEFAULT_EXEC_PATH.to_string(),
        execution: None,
    };
    let mut execution_socket: Option<PathBuf> = None;
    let mut execution_upstream: Option<PathBuf> = None;
    let mut execution_upstream_token: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        let value = |index: &mut usize| -> String {
            *index += 1;
            args.get(*index).cloned().unwrap_or_else(|| print_usage_and_exit(2))
        };
        match argument {
            "--fd-socket" => config.fd_socket = PathBuf::from(value(&mut index)),
            "--control-socket" => config.control_socket = PathBuf::from(value(&mut index)),
            "--kernel-peer-uid" => {
                let raw = value(&mut index);
                config.kernel_peer.uid = raw.parse().unwrap_or_else(|_| print_usage_and_exit(2));
            }
            "--kernel-peer-gid" => {
                let raw = value(&mut index);
                config.kernel_peer.gid = raw.parse().unwrap_or_else(|_| print_usage_and_exit(2));
            }
            // R2 修复轮 9.2：--podman 语义废除——--exec 是唯一注入型 exec 目标
            //（relay 直 execv 该二进制；argv[0] 必须等于本路径）。
            "--exec" => config.exec_path = value(&mut index),
            "--execution-socket" => execution_socket = Some(PathBuf::from(value(&mut index))),
            "--execution-upstream" => execution_upstream = Some(PathBuf::from(value(&mut index))),
            "--execution-upstream-token" => execution_upstream_token = Some(value(&mut index)),
            "--help" | "-h" => print_usage_and_exit(0),
            _ => print_usage_and_exit(2),
        }
        index += 1;
    }
    match (execution_socket, execution_upstream, execution_upstream_token) {
        (None, None, None) => {}
        (Some(public_socket), Some(upstream_socket), Some(upstream_authorization)) => {
            config.execution = Some(ExecutionProxyConfig {
                public_socket,
                upstream_socket,
                upstream_authorization,
                kernel_peer: config.kernel_peer,
                supervisor_peer: SnapshotSocketPeer {
                    uid: unsafe { libc::getuid() },
                    gid: unsafe { libc::getgid() },
                },
            });
        }
        _ => print_usage_and_exit(2),
    }
    config
}

fn fail_closed(code: &str, detail: &str) -> ! {
    eprintln!("snapshot-fd-relay: {code}: {detail}");
    std::process::exit(1);
}

fn now_epoch_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// 回收崩溃残留的 socket 文件（supervisor 约定对位：server.ts 绑定前 rmSync(force)）。
/// 生命周期所有权：relay 是 supervisor 的独占子进程（supervisor.sock 互斥保证同一
/// runtime 目录至多一个 supervisor，stop 路径 SIGTERM 其 relay 子进程）；残留文件只可能
/// 来自崩溃路径，不清除会让重启永久 EADDRINUSE——恢复语义（journal replay）要求
/// restart 可达，故按仓库既有约定盲 unlink（ENOENT 无害）。
fn reclaim_stale_socket_path(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// 绑定 SOCK_SEQPACKET fd socket：socket → bind → listen → chmod 0600。
/// socket(2) 层即拒绝非 seqpacket 宿主（macOS → SNAPSHOT_TRANSPORT_UNAVAILABLE）。
fn bind_fd_socket(path: &Path) -> std::os::unix::net::UnixListener {
    // SOCK_SEQPACKET 专有绑定：UnixListener 仅提供 SOCK_STREAM；以 libc 建链后转交。
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .unwrap_or_else(|_| fail_closed("SNAPSHOT_SOCKET_PATH_REJECTED", "socket path contains a NUL byte"));
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0) };
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EPROTONOSUPPORT || errno == libc::EPROTOTYPE || errno == libc::EAFNOSUPPORT || errno == libc::ENOSYS {
            fail_closed(
                SNAPSHOT_TRANSPORT_UNAVAILABLE,
                "AF_UNIX SOCK_SEQPACKET is unavailable on this host; the relay fails closed instead of degrading to another socket type",
            );
        }
        fail_closed("SNAPSHOT_TRANSPORT_IO", &format!("socket(AF_UNIX, SOCK_SEQPACKET) failed with errno {errno}"));
    }
    // 传输能力已证明后才回收残留文件（不支持 seqpacket 的宿主不触碰文件系统）。
    reclaim_stale_socket_path(path);
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if c_path.as_bytes_with_nul().len() > address.sun_path.len() {
        fail_closed("SNAPSHOT_SOCKET_PATH_REJECTED", "socket path exceeds the sockaddr_un sun_path capacity");
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            c_path.as_ptr() as *const u8,
            address.sun_path.as_mut_ptr() as *mut u8,
            c_path.as_bytes_with_nul().len(),
        );
    }
    let bind_result = unsafe {
        libc::bind(
            fd,
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if bind_result != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        fail_closed("SNAPSHOT_TRANSPORT_IO", &format!("bind on the fd socket failed with errno {errno}"));
    }
    if unsafe { libc::listen(fd, 4) } != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        fail_closed("SNAPSHOT_TRANSPORT_IO", &format!("listen on the fd socket failed with errno {errno}"));
    }
    let mode_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path is NUL-free");
    unsafe {
        libc::chmod(mode_path.as_ptr(), 0o600);
    }
    // 以已连接语义接管监听 fd：UnixListener::from_raw_fd。
    use std::os::fd::FromRawFd;
    unsafe { UnixListener::from_raw_fd(fd) }
}

/// fstat regular + fcntl(F_GETFL) O_RDONLY：supervisor 侧描述符策略事实（spec 逐字）。
fn descriptor_policy_facts(fd: &OwnedFd) -> (bool, bool) {
    let raw = fd.as_fd().as_raw_fd();
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(raw, &mut stat) } != 0 {
        return (false, false);
    }
    let regular = stat.st_mode & libc::S_IFMT == libc::S_IFREG;
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    let read_only = flags >= 0 && (flags & libc::O_ACCMODE) == libc::O_RDONLY;
    (regular, read_only)
}

use std::os::fd::AsRawFd;

fn rejected_ack(payload: &SnapshotHandoffPayload, journal_revision: u64, code: &str) -> Option<SnapshotFdAckV1> {
    let handoff_digest = iweb_kernel::wasm_snapshot_fd::compute_snapshot_handoff_digest(payload).ok()?;
    Some(SnapshotFdAckV1 {
        schema_version: 1,
        kind: "ack".to_string(),
        command_id: payload.command_id().to_string(),
        handoff_digest,
        status: SnapshotAckStatus::Rejected,
        failure_code: Some(code.to_string()),
        journal_revision,
    })
}

/// fd socket 主循环：每连接做凭据 → socket type → 单 recvmsg 帧判定 → 台账接受 → ack。
fn fd_accept_loop(listener: UnixListener, table: Arc<HandoffTable>, kernel_peer: SnapshotSocketPeer) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        if let Err(error) = require_peer_credentials(&stream, &kernel_peer) {
            eprintln!("snapshot-fd-relay: fd socket peer rejected: {}", error);
            continue;
        }
        if let Err(error) = require_seqpacket_socket(&stream) {
            eprintln!("snapshot-fd-relay: fd socket type rejected: {}", error);
            continue;
        }
        handle_fd_connection(&stream, &table);
    }
}

fn handle_fd_connection(stream: &std::os::unix::net::UnixStream, table: &HandoffTable) {
    let received = receive_snapshot_request(stream);
    let (payload, fd) = match received {
        Ok(value) => value,
        Err(error) => {
            // 帧级失败：无可回 ack 的 commandId，按 spec「reject before payload handling」
            // 关闭连接（SCM_RIGHTS 收到的描述符已由 OwnedFd drop 关闭）。
            eprintln!("snapshot-fd-relay: fd frame rejected: {}", error);
            return;
        }
    };
    let fd_bytes = match iweb_kernel::wasm_snapshot_fd::read_snapshot_fd_bytes(&fd) {
        Ok(bytes) => bytes,
        Err(error) => {
            let ack = rejected_ack(&payload, 0, error.code).unwrap_or_else(|| fallback_rejected_ack(&payload));
            send_ack(stream, &ack);
            return;
        }
    };
    let (regular, read_only) = descriptor_policy_facts(&fd);
    let ack = match table.accept(payload.clone(), fd, fd_bytes, regular, read_only, now_epoch_millis()) {
        Ok(ack) => ack,
        Err(error) => rejected_ack(&payload, next_journal_revision_for_reject(table), error.code).unwrap_or_else(|| fallback_rejected_ack(&payload)),
    };
    send_ack(stream, &ack);
}

fn next_journal_revision_for_reject(_table: &HandoffTable) -> u64 {
    // 拒绝 ack 的 journalRevision：以 0 表达「无台账条目」（该命令未被接受）。
    0
}

fn fallback_rejected_ack(payload: &SnapshotHandoffPayload) -> SnapshotFdAckV1 {
    SnapshotFdAckV1 {
        schema_version: 1,
        kind: "ack".to_string(),
        command_id: payload.command_id().to_string(),
        handoff_digest: "0".repeat(64),
        status: SnapshotAckStatus::Rejected,
        failure_code: Some("SNAPSHOT_WIRE_INVALID".to_string()),
        journal_revision: 0,
    }
}

fn send_ack(stream: &std::os::unix::net::UnixStream, ack: &SnapshotFdAckV1) {
    if let Ok(frame) = ack.encode_frame() {
        if let Err(error) = send_snapshot_frame_without_ancillary(stream, &frame) {
            eprintln!("snapshot-fd-relay: failed to send the snapshot ack: {}", error);
        }
    }
}

fn handoff_view_of(summary: &HeldHandoffSummary) -> control::HandoffView {
    let (reference, command_digest, application_id, version_id, preparation_generation, revision, values_digest, fd_digest, expires_at, kind) =
        match &summary.payload {
            SnapshotHandoffPayload::Secret(p) => (
                p.reference.clone(),
                p.command_digest.clone(),
                p.application_id.clone(),
                p.version_id.clone(),
                p.preparation_generation,
                p.secret_revision,
                p.values_digest.clone(),
                p.fd_digest.clone(),
                p.expires_at.clone(),
                "secret",
            ),
            SnapshotHandoffPayload::Config(p) => (
                p.reference.clone(),
                p.command_digest.clone(),
                p.application_id.clone(),
                p.version_id.clone(),
                p.preparation_generation,
                p.config_revision,
                p.values_digest.clone(),
                p.fd_digest.clone(),
                p.expires_at.clone(),
                "config",
            ),
        };
    control::HandoffView {
        command_id: summary.payload.command_id().to_string(),
        kind: kind.to_string(),
        command_digest,
        reference,
        application_id,
        version_id,
        preparation_generation,
        revision,
        values_digest,
        fd_digest,
        expires_at,
        fd_bytes_base64: {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(summary.fd_bytes.as_slice())
        },
        descriptor_regular_file: summary.descriptor_regular_file,
        descriptor_read_only: summary.descriptor_read_only,
    }
}

fn dispatch_control_request(
    request: control::ControlRequest,
    table: &HandoffTable,
    children: &Arc<ChildTable>,
    exec_path: &str,
) -> control::ControlResponse {
    match request {
        control::ControlRequest::Lookup { command_id } => {
            let (secret, config) = table.lookup(&command_id);
            control::ControlResponse::Lookup {
                ok: true,
                secret: secret.as_ref().map(|summary| Box::new(handoff_view_of(summary))),
                config: config.as_ref().map(|summary| Box::new(handoff_view_of(summary))),
            }
        }
        control::ControlRequest::Spawn { command_id, exec_argv } => {
            let spawn_result = table.with_spawn_inputs(&command_id, |inputs| {
                let request = spawn::FdSpawnRequest {
                    program: exec_path,
                    argv: &exec_argv,
                    secret_fd: inputs.secret_fd,
                    config_fd: inputs.config_fd,
                };
                spawn::spawn_exec_with_snapshot_fds(&request)
            });
            match spawn_result {
                Ok(Ok(SpawnChild { pid })) => {
                    // exec 已派发：子进程持有注入的 FD（fork 复制了描述符表，父进程
                    // 关闭自己的副本不影响子进程）；relay 立即关闭代持副本并登记
                    // wait/reap 观测。退出码经 wait 指令上报。
                    table.consume(&command_id);
                    children.register(&command_id, pid);
                    control::ControlResponse::Spawn { ok: true, pid: Some(pid) }
                }
                Ok(Err(detail)) => control::ControlResponse::Error {
                    ok: false,
                    code: control::RELAY_SPAWN_FAILED.to_string(),
                    message: detail,
                },
                Err(code) => control::ControlResponse::Error {
                    ok: false,
                    code: code.to_string(),
                    message: "no held snapshot descriptor matches the command".to_string(),
                },
            }
        }
        control::ControlRequest::Wait { command_id, timeout_ms } => {
            let timeout = Duration::from_millis(timeout_ms.min(WAIT_TIMEOUT_MAX_MS));
            match children.wait_for_exit(&command_id, timeout) {
                Some(status) => control::ControlResponse::Wait {
                    ok: true,
                    pid: status.pid,
                    running: status.exit_code.is_none(),
                    exit_code: status.exit_code,
                },
                None => control::ControlResponse::Error {
                    ok: false,
                    code: control::SNAPSHOT_CHILD_UNKNOWN.to_string(),
                    message: "no spawned child is known for this command".to_string(),
                },
            }
        }
        control::ControlRequest::Discard { command_id } => {
            let dropped = table.consume(&command_id);
            children.forget(&command_id);
            control::ControlResponse::Discard { ok: true, dropped }
        }
    }
}

/// 控制 socket 主循环：每连接一个线程（wait 可长阻塞，不占死其它连接）、
/// 连接内逐行请求/响应（同 UID、0600 的 supervisor 私有 wire）。
fn control_accept_loop(listener: UnixListener, table: Arc<HandoffTable>, children: Arc<ChildTable>, exec_path: String) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let table = Arc::clone(&table);
        let children = Arc::clone(&children);
        let exec_path = exec_path.clone();
        std::thread::spawn(move || {
            let writer = match stream.try_clone() {
                Ok(writer) => writer,
                Err(_) => return,
            };
            let mut writer = writer;
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                if line.len() > control::CONTROL_MAX_LINE_BYTES {
                    let response = control::ControlResponse::Error {
                        ok: false,
                        code: control::RELAY_REQUEST_INVALID.to_string(),
                        message: "control request line exceeds the fixed bound".to_string(),
                    };
                    let _ = writeln!(writer, "{}", control::encode_response_line(&response).trim_end());
                    break;
                }
                let response = match control::parse_request_line(line.as_str()) {
                    Ok(request) => dispatch_control_request(request, &table, &children, &exec_path),
                    Err(detail) => control::ControlResponse::Error {
                        ok: false,
                        code: control::RELAY_REQUEST_INVALID.to_string(),
                        message: detail,
                    },
                };
                if writeln!(writer, "{}", control::encode_response_line(&response).trim_end()).is_err() {
                    break;
                }
            }
        });
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = parse_config(&args);
    // 控制连接半关闭不应终止 relay（SIGPIPE 忽略；写失败按行处理）。
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let fd_listener = bind_fd_socket(&config.fd_socket);
    // The public HTTP socket is optional only for the relay's isolated FD tests.
    // Production supervisor startup always supplies all three execution options.
    let execution_listener = config.execution.as_ref().map(bind_execution_listener).transpose().unwrap_or_else(|error| {
        fail_closed(error.code, &error.to_string())
    });
    // 控制 socket：父目录先于 bind 就绪（--control-socket 可与 fd socket 不同目录）。
    if let Some(parent) = config.control_socket.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    reclaim_stale_socket_path(&config.control_socket);
    let control_listener = UnixListener::bind(&config.control_socket).unwrap_or_else(|error| {
        fail_closed(
            "SNAPSHOT_TRANSPORT_IO",
            &format!("bind on the control socket {} failed: {error}", config.control_socket.display()),
        )
    });
    let control_mode = std::ffi::CString::new(config.control_socket.as_os_str().as_encoded_bytes()).expect("control path is NUL-free");
    unsafe {
        libc::chmod(control_mode.as_ptr(), 0o600);
    }
    let table = Arc::new(HandoffTable::new());
    // 子进程台账 + reaper：父进程（relay）对直执行子进程保持 wait/reap 关系
    //（tasks 9.2：SIGCHLD 语义等价的显式回收；退出码经控制 socket 的 wait 上报）。
    let children = Arc::new(ChildTable::new());
    spawn::spawn_child_reaper(Arc::clone(&children));
    eprintln!(
        "snapshot-fd-relay: ready fd-socket={} control-socket={} execution-socket={} execution-upstream={} exec={}",
        config.fd_socket.display(),
        config.control_socket.display(),
        config
            .execution
            .as_ref()
            .map(|execution| execution.public_socket.display().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        config
            .execution
            .as_ref()
            .map(|execution| execution.upstream_socket.display().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        config.exec_path
    );
    let fd_table = Arc::clone(&table);
    let fd_peer = config.kernel_peer;
    let fd_thread = std::thread::spawn(move || fd_accept_loop(fd_listener, fd_table, fd_peer));
    let control_table = Arc::clone(&table);
    let control_thread = std::thread::spawn(move || {
        control_accept_loop(control_listener, control_table, children, config.exec_path)
    });
    let execution_thread = match (execution_listener, config.execution) {
        (Some((listener, bound)), Some(execution)) => {
            let execution = Arc::new(execution);
            Some(std::thread::spawn(move || run_execution_proxy(listener, execution, bound)))
        }
        (None, None) => None,
        _ => unreachable!("execution listener and configuration are created together"),
    };
    let _ = fd_thread.join();
    let _ = control_thread.join();
    if let Some(thread) = execution_thread {
        let _ = thread.join();
    }
}
