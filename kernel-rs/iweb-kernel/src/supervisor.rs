//! Supervisor 客户端（对位 kernel/supervisor-client.js）。
//! 私有 Unix socket；固定 /v1/health；响应 ≤16KiB；等待 ≤500ms；
//! 失败 → unavailable（不泄露宿主细节）。手写最小 HTTP/1.1，零新依赖。
//! wasm engine metrics v1（add-wasm-runtime 4.1）：同 socket 的
//! GET /v1/execution-metrics/<sandboxId> 拉取——只接受通过 wire 校验的 200 载荷；
//! 404/503/超时/畸形一律 None（fail-closed，绝不部分采纳）。

use serde::Deserialize;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::UnixStream;

use crate::metrics::{validate_wasm_engine_metrics_v1, WasmEngineMetricsV1};

const MAXIMUM_RESPONSE_BYTES: usize = 16 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 500;

/// supervisor 私有 socket 的环境变量名（健康探测与 wasm 执行通道共用同一端点）。
pub const SUPERVISOR_SOCKET_ENV: &str = "IWEB_SANDBOX_SOCKET";
/// iweb-execution-rpc-v1 唯一合法 Unix socket。环境变量只可重复声明这个字面量，
/// 不得把 Kernel 连接重定向到任意路径或 TCP bridge。
pub const SUPERVISOR_SOCKET_PATH: &str = "/run/iweb-sandbox/supervisor.sock";
pub const SUPERVISOR_SOCKET_PATH_REJECTED: &str = "SUPERVISOR_SOCKET_PATH_REJECTED";
pub const SUPERVISOR_PEER_CREDENTIALS_REJECTED: &str = "SUPERVISOR_PEER_CREDENTIALS_REJECTED";
const SUPERVISOR_SOCKET_OWNER_NAME: &str = "iweb-sandbox";

/// 已解析的 `iweb-sandbox` socket 创建者。这个数值对同时约束 socket inode
/// 和 Kernel 连接后看到的 SO_PEERCRED 对端；环境变量不能改写它。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorSocketPeer {
    pub uid: u32,
    pub gid: u32,
}

/// lstat 的最小、可比较观测。`device + inode` 是路径替换探测的身份，不只看
/// mode/owner，以免一次合法重绑在 connect 期间被误采纳。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketPathObservation {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SupervisorSocketPathIdentity {
    socket: SocketPathObservation,
    parent: SocketPathObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorSocketError {
    pub code: &'static str,
    detail: String,
}

impl SupervisorSocketError {
    fn path(detail: impl Into<String>) -> Self {
        Self { code: SUPERVISOR_SOCKET_PATH_REJECTED, detail: detail.into() }
    }

    fn peer(detail: impl Into<String>) -> Self {
        Self { code: SUPERVISOR_PEER_CREDENTIALS_REJECTED, detail: detail.into() }
    }
}

impl std::fmt::Display for SupervisorSocketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SupervisorSocketError {}

/// Resolve the fixed supervisor endpoint. Only an absent environment variable
/// selects the canonical deployment default; a supplied value must match the
/// literal byte-for-byte.
pub fn fixed_supervisor_socket_path(value: Option<&str>) -> Result<&'static str, String> {
    match value {
        None | Some(SUPERVISOR_SOCKET_PATH) => Ok(SUPERVISOR_SOCKET_PATH),
        Some(other) => Err(format!(
            "{SUPERVISOR_SOCKET_PATH_REJECTED}: IWEB_SANDBOX_SOCKET must equal {SUPERVISOR_SOCKET_PATH}, got a non-canonical path ({})",
            other.len()
        )),
    }
}

/// Resolve the fixed service account installed by packaging. The socket's group
/// is resolved by its declared group name rather than accepting an inherited
/// primary group or an environment override.
pub fn resolve_supervisor_socket_peer() -> Result<SupervisorSocketPeer, SupervisorSocketError> {
    let account = std::ffi::CString::new(SUPERVISOR_SOCKET_OWNER_NAME)
        .expect("the fixed supervisor account name contains no NUL byte");
    let password = unsafe { libc::getpwnam(account.as_ptr()) };
    if password.is_null() {
        return Err(SupervisorSocketError::peer(
            "the fixed iweb-sandbox supervisor account cannot be resolved",
        ));
    }
    let group = unsafe { libc::getgrnam(account.as_ptr()) };
    if group.is_null() {
        return Err(SupervisorSocketError::peer(
            "the fixed iweb-sandbox supervisor group cannot be resolved",
        ));
    }
    let uid = unsafe { (*password).pw_uid };
    let gid = unsafe { (*group).gr_gid };
    Ok(SupervisorSocketPeer { uid, gid })
}

fn lstat_observation(path: &Path) -> Result<SocketPathObservation, SupervisorSocketError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| SupervisorSocketError::path("the configured socket path contains a NUL byte"))?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(SupervisorSocketError::path(format!(
            "lstat on the fixed supervisor socket path failed (errno {})",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        )));
    }
    Ok(SocketPathObservation {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
    })
}

fn validate_socket_observation(
    observed: SocketPathObservation,
    expected: SupervisorSocketPeer,
) -> Result<(), SupervisorSocketError> {
    if observed.mode & libc::S_IFMT as u32 != libc::S_IFSOCK as u32 {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor socket path is not a socket inode",
        ));
    }
    if observed.uid != expected.uid || observed.gid != expected.gid {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor socket owner does not equal the resolved iweb-sandbox uid/gid pair",
        ));
    }
    if observed.mode & 0o7777 != 0o600 {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor socket mode must be exactly 0600",
        ));
    }
    Ok(())
}

fn validate_parent_observation(
    observed: SocketPathObservation,
    expected: SupervisorSocketPeer,
) -> Result<(), SupervisorSocketError> {
    if observed.mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32 {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor socket parent is not a directory inode",
        ));
    }
    if observed.uid != expected.uid || observed.gid != expected.gid {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor socket parent owner does not equal the resolved iweb-sandbox uid/gid pair",
        ));
    }
    if observed.mode & 0o7777 != 0o700 {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor socket parent mode must be exactly 0700",
        ));
    }
    Ok(())
}

fn inspect_supervisor_socket_path(
    path: &Path,
    expected: SupervisorSocketPeer,
) -> Result<SupervisorSocketPathIdentity, SupervisorSocketError> {
    let socket = lstat_observation(path)?;
    validate_socket_observation(socket, expected)?;
    let parent = lstat_observation(path.parent().unwrap_or_else(|| Path::new("/")))?;
    validate_parent_observation(parent, expected)?;
    Ok(SupervisorSocketPathIdentity { socket, parent })
}

fn require_unchanged_socket_identity(
    before: SupervisorSocketPathIdentity,
    after: SupervisorSocketPathIdentity,
) -> Result<(), SupervisorSocketError> {
    if before.socket.device != after.socket.device
        || before.socket.inode != after.socket.inode
        || before.parent.device != after.parent.device
        || before.parent.inode != after.parent.inode
    {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor socket or its parent inode changed while connecting",
        ));
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn validate_peer_credentials(
    actual: SupervisorSocketPeer,
    expected: SupervisorSocketPeer,
) -> Result<(), SupervisorSocketError> {
    if actual != expected {
        return Err(SupervisorSocketError::peer(
            "the connected supervisor peer uid/gid does not equal the resolved iweb-sandbox pair",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_supervisor_peer_credentials(
    stream: &std::os::unix::net::UnixStream,
    expected: SupervisorSocketPeer,
) -> Result<(), SupervisorSocketError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if result != 0 || length != std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        return Err(SupervisorSocketError::peer(format!(
            "SO_PEERCRED is unavailable on the connected supervisor socket (errno {})",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        )));
    }
    validate_peer_credentials(
        SupervisorSocketPeer { uid: credentials.uid, gid: credentials.gid },
        expected,
    )
}

#[cfg(not(target_os = "linux"))]
fn require_supervisor_peer_credentials(
    _stream: &std::os::unix::net::UnixStream,
    _expected: SupervisorSocketPeer,
) -> Result<(), SupervisorSocketError> {
    Err(SupervisorSocketError::peer(
        "SO_PEERCRED requires Linux; unverified execution peers are rejected",
    ))
}

fn require_stream_socket(stream: &std::os::unix::net::UnixStream) -> Result<(), SupervisorSocketError> {
    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut socket_type as *mut libc::c_int as *mut libc::c_void,
            &mut length,
        )
    };
    if result != 0 || socket_type != libc::SOCK_STREAM {
        return Err(SupervisorSocketError::path(
            "the fixed supervisor execution socket is not SOCK_STREAM",
        ));
    }
    Ok(())
}

fn connect_execution_rpc_socket_at_path_with_after_connect<F>(
    path: &Path,
    expected: SupervisorSocketPeer,
    after_connect: F,
) -> Result<std::os::unix::net::UnixStream, SupervisorSocketError>
where
    F: FnOnce(),
{
    let before = inspect_supervisor_socket_path(path, expected)?;
    let stream = std::os::unix::net::UnixStream::connect(path).map_err(|error| {
        SupervisorSocketError::path(format!("connect to the fixed supervisor socket failed: {error}"))
    })?;
    require_stream_socket(&stream)?;
    require_supervisor_peer_credentials(&stream, expected)?;
    after_connect();
    let after = inspect_supervisor_socket_path(path, expected)?;
    require_unchanged_socket_identity(before, after)?;
    Ok(stream)
}

fn connect_execution_rpc_socket_at_path(
    path: &Path,
    expected: SupervisorSocketPeer,
) -> Result<std::os::unix::net::UnixStream, SupervisorSocketError> {
    connect_execution_rpc_socket_at_path_with_after_connect(path, expected, || {})
}

/// Fixed execution RPC connector: lstat socket and parent, connect, require
/// Linux SO_PEERCRED, then re-lstat both inodes before any HTTP byte is sent.
/// The production API intentionally has no path parameter; alternate-path
/// connectors exist only as private test transport seams.
pub fn connect_execution_rpc_socket(
    expected: SupervisorSocketPeer,
) -> Result<std::os::unix::net::UnixStream, SupervisorSocketError> {
    connect_execution_rpc_socket_at_path(Path::new(SUPERVISOR_SOCKET_PATH), expected)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SupervisorHealth {
    pub configured: bool,
    pub available: bool,
    pub version: Option<u8>,
}

#[derive(Deserialize)]
struct HealthBody {
    service: String,
    version: serde_json::Number,
    ready: bool,
}

/// 对位 supervisorHealth：空路径 = 未配置；任何失败 = configured+unavailable。
pub async fn supervisor_health(socket_path: Option<&str>, timeout_ms: Option<u64>) -> SupervisorHealth {
    let Some(path) = socket_path.filter(|p| !p.is_empty()) else {
        return SupervisorHealth::default();
    };
    if path != SUPERVISOR_SOCKET_PATH {
        return SupervisorHealth { configured: true, available: false, version: None };
    }
    let timeout_ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let request = b"GET /v1/health HTTP/1.1\r\nHost: iweb-supervisor\r\nConnection: close\r\n\r\n".to_vec();
    let response = tokio::task::spawn_blocking(move || {
        authenticated_supervisor_http_request(&request, timeout_ms, MAXIMUM_RESPONSE_BYTES)
    })
    .await
    .ok()
    .flatten();
    match response.and_then(|(status, body)| parse_health_response(status, &body)) {
        Some(version) => SupervisorHealth { configured: true, available: true, version: Some(version) },
        None => SupervisorHealth { configured: true, available: false, version: None },
    }
}

fn parse_health_response(status: u16, body: &[u8]) -> Option<u8> {
    if status != 200 {
        return None;
    }
    let parsed: HealthBody = serde_json::from_slice(body).ok()?;
    // 对位严格形状：service/version/ready 三重校验，宽一毫都不行。
    if parsed.service != "iweb-sandbox-supervisor" || parsed.version.as_u64() != Some(1) || !parsed.ready {
        return None;
    }
    Some(1)
}

/// Tests intentionally use a temporary listener, so this is the only direct
/// transport seam. Production callers use the fixed authenticated connector.
#[cfg(test)]
async fn health_once_for_test(path: &str, timeout_ms: u64) -> Option<u8> {
    let future = async {
        let mut stream = UnixStream::connect(path).await.ok()?;
        let request = "GET /v1/health HTTP/1.1\r\nHost: iweb-supervisor\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > MAXIMUM_RESPONSE_BYTES {
                return None; // 对位：超限即毁连接
            }
            if let Some(header_end) = find_header_end(&buffer) {
                if buffer.len() >= header_end + content_length(&buffer[..header_end]) {
                    break;
                }
            }
        }
        let header_end = find_header_end(&buffer)?;
        let header_text = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let status_line = header_text.lines().next()?;
        let status = status_line.split_whitespace().nth(1)?.parse().ok()?;
        let body = &buffer[header_end..];
        parse_health_response(status, body)
    };
    tokio::time::timeout(Duration::from_millis(timeout_ms), future).await.ok().flatten()
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Kernel 侧拉取 supervisor 的 wasm engine metrics v1（4.1）。
/// - sandboxId 文法先于请求判定（非法即 None，绝不向 socket 发任意路径）。
/// - 仅 200 + 可解析 + 过 validate_wasm_engine_metrics_v1 的载荷返回 Some；
///   404（未知 sandbox）/503（未配置采样通道）/超时/超限/畸形一律 None。
/// - 身份 correlate 与窗口单调判定不在本层：调用方以 Kernel 权威 fence 调
///   WasmEngineMetricsRegistry::accept_validated（supervisor journal 绝不是 route
///   authority；本客户端只搬运可验证字节）。
pub async fn wasm_engine_metrics(socket_path: &str, sandbox_id: &str, timeout_ms: Option<u64>) -> Option<WasmEngineMetricsV1> {
    if socket_path != SUPERVISOR_SOCKET_PATH || !valid_metrics_sandbox_id(sandbox_id) {
        return None;
    }
    let timeout_ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let request = format!(
        "GET /v1/execution-metrics/{sandbox_id} HTTP/1.1\r\nHost: iweb-supervisor\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let response = tokio::task::spawn_blocking(move || {
        authenticated_supervisor_http_request(&request, timeout_ms, MAXIMUM_RESPONSE_BYTES)
    })
    .await
    .ok()
    .flatten()?;
    if response.0 != 200 {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_slice(&response.1).ok()?;
    validate_wasm_engine_metrics_v1(&parsed).ok()
}

/// Tests intentionally provide a temporary UDS responder. It is cfg-gated so
/// no production caller can bypass the fixed peer-authenticated transport.
#[cfg(test)]
async fn wasm_engine_metrics_at_path_for_test(
    socket_path: &str,
    sandbox_id: &str,
    timeout_ms: Option<u64>,
) -> Option<WasmEngineMetricsV1> {
    if !valid_metrics_sandbox_id(sandbox_id) {
        return None;
    }
    let future = async {
        let mut stream = UnixStream::connect(socket_path).await.ok()?;
        let request = format!(
            "GET /v1/execution-metrics/{sandbox_id} HTTP/1.1\r\nHost: iweb-supervisor\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > MAXIMUM_RESPONSE_BYTES {
                return None;
            }
            if let Some(header_end) = find_header_end(&buffer) {
                if buffer.len() >= header_end + content_length(&buffer[..header_end]) {
                    break;
                }
            }
        }
        let header_end = find_header_end(&buffer)?;
        let header_text = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let status_line = header_text.lines().next()?;
        if !status_line.contains("200") {
            return None;
        }
        let body = &buffer[header_end..];
        let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
        validate_wasm_engine_metrics_v1(&parsed).ok()
    };
    tokio::time::timeout(Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)), future).await.ok().flatten()
}

fn valid_metrics_sandbox_id(sandbox_id: &str) -> bool {
    static SANDBOX_ID: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SANDBOX_ID
        .get_or_init(|| regex::Regex::new(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$").expect("sandbox id regex"))
        .is_match(sandbox_id)
}

/// 阻塞版 /v1/execution-rpc 调用（wasm 投递闭环；std UDS + 手写最小 HTTP/1.1，
/// 与上方 async 客户端同一 socket 约定：单请求单连接、Connection: close）。
/// 成功返回 (HTTP status, body 字节)；传输失败/超时/超限返回 None（调用方按
/// 「不确定结果」处理——只能 query/replay，绝不重发 command 语义之外的旁路）。
pub fn execution_rpc_blocking(socket_path: &str, request_body: &[u8], timeout_ms: u64) -> Option<(u16, Vec<u8>)> {
    if socket_path != SUPERVISOR_SOCKET_PATH {
        return None;
    }
    let mut request = format!(
        "POST /v1/execution-rpc HTTP/1.1\r\nHost: iweb-supervisor\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request_body.len()
    )
    .into_bytes();
    request.extend_from_slice(request_body);
    authenticated_supervisor_http_request(&request, timeout_ms, EXECUTION_RPC_MAX_RESPONSE_BYTES)
}

/// Every production HTTP request shares this one fixed, peer-authenticated
/// connection sequence. No caller supplies a transport path.
fn authenticated_supervisor_http_request(
    request: &[u8],
    timeout_ms: u64,
    maximum_response_bytes: usize,
) -> Option<(u16, Vec<u8>)> {
    use std::io::{Read, Write};
    let expected = resolve_supervisor_socket_peer().ok()?;
    let mut stream = connect_execution_rpc_socket(expected).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    stream.write_all(request).ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > maximum_response_bytes {
                    return None;
                }
                if let Some(header_end) = find_header_end(&buffer) {
                    if buffer.len() >= header_end + content_length(&buffer[..header_end]) {
                        break;
                    }
                }
            }
            Err(_) => return None,
        }
    }
    let header_end = find_header_end(&buffer)?;
    let header_text = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let status_line = header_text.lines().next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    let length = content_length(&buffer[..header_end]);
    let body_end = header_end.checked_add(length)?;
    if buffer.len() < body_end {
        return None;
    }
    Some((status, buffer[header_end..body_end].to_vec()))
}

/// envelope/ack 尺寸上界（16 KiB 的 4 倍：query-result 含完整命令 + ack 双记录）。
pub const EXECUTION_RPC_MAX_RESPONSE_BYTES: usize = 64 * 1024;


fn content_length(header: &[u8]) -> usize {
    let text = String::from_utf8_lossy(header);
    for line in text.lines() {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return value.trim().parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_socket_is_not_configured() {
        let health = supervisor_health(None, None).await;
        assert_eq!(health, SupervisorHealth { configured: false, available: false, version: None });
    }

    #[tokio::test]
    async fn missing_socket_is_unavailable() {
        let health = supervisor_health(Some("/nonexistent/supervisor.sock"), None).await;
        assert!(health.configured && !health.available);
    }

    #[test]
    fn fixed_execution_socket_rejects_environment_redirection() {
        assert_eq!(fixed_supervisor_socket_path(None).unwrap(), SUPERVISOR_SOCKET_PATH);
        assert_eq!(fixed_supervisor_socket_path(Some(SUPERVISOR_SOCKET_PATH)).unwrap(), SUPERVISOR_SOCKET_PATH);
        let failure = fixed_supervisor_socket_path(Some("/tmp/attacker.sock")).expect_err("alternate socket must be rejected");
        assert!(failure.starts_with(SUPERVISOR_SOCKET_PATH_REJECTED));
        assert!(fixed_supervisor_socket_path(Some("")).is_err());
        assert!(fixed_supervisor_socket_path(Some(" ")).is_err());
    }

    fn socket_observation(inode: u64, uid: u32, gid: u32, mode: u32) -> SocketPathObservation {
        SocketPathObservation { device: 9, inode, uid, gid, mode }
    }

    fn socket_identity(peer: SupervisorSocketPeer) -> SupervisorSocketPathIdentity {
        SupervisorSocketPathIdentity {
            socket: socket_observation(10, peer.uid, peer.gid, (libc::S_IFSOCK | 0o600) as u32),
            parent: socket_observation(11, peer.uid, peer.gid, (libc::S_IFDIR | 0o700) as u32),
        }
    }

    #[test]
    fn execution_socket_path_rejects_wrong_owner_mode_and_inode_replacement() {
        let peer = SupervisorSocketPeer { uid: 1001, gid: 1002 };
        let valid = socket_identity(peer);
        assert!(validate_socket_observation(valid.socket, peer).is_ok());
        assert!(validate_parent_observation(valid.parent, peer).is_ok());

        let wrong_owner = socket_observation(10, peer.uid + 1, peer.gid, (libc::S_IFSOCK | 0o600) as u32);
        assert_eq!(validate_socket_observation(wrong_owner, peer).unwrap_err().code, SUPERVISOR_SOCKET_PATH_REJECTED);
        let wrong_mode = socket_observation(10, peer.uid, peer.gid, (libc::S_IFSOCK | 0o660) as u32);
        assert_eq!(validate_socket_observation(wrong_mode, peer).unwrap_err().code, SUPERVISOR_SOCKET_PATH_REJECTED);
        let wrong_parent_mode = socket_observation(11, peer.uid, peer.gid, (libc::S_IFDIR | 0o755) as u32);
        assert_eq!(validate_parent_observation(wrong_parent_mode, peer).unwrap_err().code, SUPERVISOR_SOCKET_PATH_REJECTED);

        let replaced = SupervisorSocketPathIdentity {
            socket: socket_observation(12, peer.uid, peer.gid, (libc::S_IFSOCK | 0o600) as u32),
            parent: valid.parent,
        };
        assert_eq!(require_unchanged_socket_identity(valid, replaced).unwrap_err().code, SUPERVISOR_SOCKET_PATH_REJECTED);
    }

    #[test]
    fn execution_socket_rejects_wrong_peer_credentials_before_http() {
        let expected = SupervisorSocketPeer { uid: 0, gid: 0 };
        let wrong = SupervisorSocketPeer { uid: 1000, gid: 0 };
        assert_eq!(validate_peer_credentials(wrong, expected).unwrap_err().code, SUPERVISOR_PEER_CREDENTIALS_REJECTED);
    }

    #[cfg(target_os = "linux")]
    fn chmod(path: &Path, mode: libc::mode_t) {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("temporary path is NUL-free");
        assert_eq!(unsafe { libc::chmod(path.as_ptr(), mode) }, 0, "chmod must succeed");
    }

    #[cfg(target_os = "linux")]
    fn current_peer() -> SupervisorSocketPeer {
        SupervisorSocketPeer { uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() } }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_connector_accepts_the_current_peer_and_detects_post_connect_replacement() {
        use std::os::unix::net::UnixListener;

        let directory = std::env::temp_dir().join(format!("iweb-supervisor-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create temporary socket directory");
        chmod(&directory, 0o700);
        let socket = directory.join("supervisor.sock");
        let listener = UnixListener::bind(&socket).expect("bind initial socket");
        chmod(&socket, 0o600);
        let peer = current_peer();

        let accepted = connect_execution_rpc_socket_at_path(&socket, peer);
        assert!(accepted.is_ok(), "the current Linux listener must satisfy SO_PEERCRED");
        drop(accepted);
        drop(listener);
        let _ = std::fs::remove_file(&socket);

        let listener = UnixListener::bind(&socket).expect("rebind initial socket");
        chmod(&socket, 0o600);
        let replaced = connect_execution_rpc_socket_at_path_with_after_connect(&socket, peer, || {
            std::fs::remove_file(&socket).expect("unlink the old socket after connect");
            let replacement = UnixListener::bind(&socket).expect("bind replacement socket");
            chmod(&socket, 0o600);
            drop(replacement);
        });
        assert_eq!(replaced.unwrap_err().code, SUPERVISOR_SOCKET_PATH_REJECTED);
        drop(listener);
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_dir_all(&directory);
    }

    // --- wasm engine metrics v1 拉取（4.1）：真实 UDS 应答者的正/负向量 ---
    fn example_engine_metrics_body() -> String {
        // 与 packages/contracts/wasm-health.ts exampleWasmEngineMetricsV1() 同一对象
        //（跨实现 wire 向量；TS 侧 golden 锁定其形状语义）。
        serde_json::json!({
            "schemaVersion": 1,
            "sandboxId": "sbx-vector",
            "versionId": format!("{}-1", "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532"),
            "packageDigest": "0".repeat(64),
            "runtimeBinding": {
                "kind": "wasm",
                "catalogRevision": 9,
                "catalogHash": "ab".repeat(32),
                "entryKey": "iweb-wasmd",
                "imageDigest": format!("sha256:{}", "cd".repeat(32)),
                "hostABI": "iweb-wasmd-abi@1.0.0",
                "world": "wasi:http/proxy@0.2.8"
            },
            "capabilityRecordRevision": 5,
            "capabilityRecordHash": "2".repeat(64),
            "secretRevision": 3,
            "configRevision": 2,
            "configSnapshotRef": "7".repeat(64),
            "preparationGeneration": 1,
            "executionGeneration": 1,
            "sampledAt": "2026-08-26T00:00:00Z",
            "availability": "available",
            "engine": {
                "fuelConsumedCumulative": 1000,
                "epochTimeoutsCumulative": 0,
                "instancesLiveInstant": 1,
                "instancesHighWaterCumulative": 1,
                "guestMemoryBytesInstant": 2097152
            }
        }).to_string()
    }

    #[tokio::test]
    async fn engine_metrics_fetch_over_real_socket() {
        let dir = std::env::temp_dir().join(format!("iweb-super-metrics-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("metrics.sock");
        let body = example_engine_metrics_body();
        // 正例：200 + 合法 wire → Some（身份字段可达 registry accept）。
        {
            let _ = std::fs::remove_file(&socket_path);
            let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
            let path_for_server = socket_path.clone();
            let body_for_server = body.clone();
            let server = tokio::spawn(async move {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buffer = [0u8; 512];
                    let _ = socket.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_for_server.len(),
                        body_for_server
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
                let _ = std::fs::remove_file(&path_for_server);
            });
            let fetched = wasm_engine_metrics_at_path_for_test(socket_path.to_str().unwrap(), "sbx-vector", None).await;
            let payload = fetched.expect("valid wire payload fetched");
            assert_eq!(payload.sandbox_id, "sbx-vector");
            assert_eq!(payload.execution_generation, 1);
            assert_eq!(payload.engine.expect("counters").guest_memory_bytes_instant, 2097152);
            server.await.unwrap();
        }
        // 负例：404（未知 sandbox）与畸形 200 均为 None（fail-closed）。
        for (status, body_text) in [
            ("404 Not Found", r#"{"ok":false,"code":"EXECUTION_SANDBOX_UNKNOWN"}"#),
            ("200 OK", r#"{"schemaVersion":1,"surplus":true}"#),
        ] {
            let _ = std::fs::remove_file(&socket_path);
            let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
            let path_for_server = socket_path.clone();
            let status_for_server = status.to_string();
            let body_for_server = body_text.to_string();
            let server = tokio::spawn(async move {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buffer = [0u8; 512];
                    let _ = socket.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 {status_for_server}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_for_server.len(),
                        body_for_server
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
                let _ = std::fs::remove_file(&path_for_server);
            });
            assert!(wasm_engine_metrics_at_path_for_test(socket_path.to_str().unwrap(), "sbx-vector", None).await.is_none(), "status {status}");
            server.await.unwrap();
        }
        // 非法 sandboxId：不发请求即 None。
        assert!(wasm_engine_metrics_at_path_for_test(socket_path.to_str().unwrap(), "../etc", None).await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn strict_shape_validation_over_real_socket() {
        // 真实 UDS 握手：起一个最小应答者，验证三重形状校验（正例 + 各负例）。
        let dir = std::env::temp_dir().join(format!("iweb-super-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("s.sock");
        for (body, expect_available) in [
            (r#"{"service":"iweb-sandbox-supervisor","version":1,"ready":true}"#, true),
            (r#"{"service":"wrong","version":1,"ready":true}"#, false),
            (r#"{"service":"iweb-sandbox-supervisor","version":2,"ready":true}"#, false),
            (r#"{"service":"iweb-sandbox-supervisor","version":1,"ready":false}"#, false),
        ] {
            let _ = std::fs::remove_file(&socket_path);
            let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
            let path_for_server = socket_path.clone();
            let server = tokio::spawn(async move {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buffer = [0u8; 256];
                    let _ = socket.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
                let _ = std::fs::remove_file(&path_for_server);
            });
            let available = health_once_for_test(socket_path.to_str().unwrap(), DEFAULT_TIMEOUT_MS).await.is_some();
            assert_eq!(available, expect_available, "body {body}");
            server.await.unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
