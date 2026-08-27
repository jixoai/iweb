//! Supervisor 客户端（对位 kernel/supervisor-client.js）。
//! 私有 Unix socket；固定 /v1/health；响应 ≤16KiB；等待 ≤500ms；
//! 失败 → unavailable（不泄露宿主细节）。手写最小 HTTP/1.1，零新依赖。
//! wasm engine metrics v1（add-wasm-runtime 4.1）：同 socket 的
//! GET /v1/execution-metrics/<sandboxId> 拉取——只接受通过 wire 校验的 200 载荷；
//! 404/503/超时/畸形一律 None（fail-closed，绝不部分采纳）。

use serde::Deserialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// Resolve the fixed supervisor endpoint. Missing/empty remains the canonical
/// deployment default; every other environment value is a configuration error.
pub fn fixed_supervisor_socket_path(value: Option<&str>) -> Result<&'static str, String> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some(SUPERVISOR_SOCKET_PATH) => Ok(SUPERVISOR_SOCKET_PATH),
        Some(other) => Err(format!(
            "{SUPERVISOR_SOCKET_PATH_REJECTED}: IWEB_SANDBOX_SOCKET must equal {SUPERVISOR_SOCKET_PATH}, got a non-canonical path ({})",
            other.len()
        )),
    }
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
    match health_once(path, timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)).await {
        Some(version) => SupervisorHealth { configured: true, available: true, version: Some(version) },
        None => SupervisorHealth { configured: true, available: false, version: None },
    }
}

async fn health_once(path: &str, timeout_ms: u64) -> Option<u8> {
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
        if !status_line.contains("200") {
            return None;
        }
        let body = &buffer[header_end..];
        let parsed: HealthBody = serde_json::from_slice(body).ok()?;
        // 对位严格形状：service/version/ready 三重校验，宽一毫都不行。
        if parsed.service != "iweb-sandbox-supervisor" || parsed.version.as_u64() != Some(1) || !parsed.ready {
            return None;
        }
        Some(1u8)
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
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket_path).ok()?;
    let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let request = format!(
        "POST /v1/execution-rpc HTTP/1.1\r\nHost: iweb-supervisor\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request_body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    stream.write_all(request_body).ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > EXECUTION_RPC_MAX_RESPONSE_BYTES {
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
            let fetched = wasm_engine_metrics(socket_path.to_str().unwrap(), "sbx-vector", None).await;
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
            assert!(wasm_engine_metrics(socket_path.to_str().unwrap(), "sbx-vector", None).await.is_none(), "status {status}");
            server.await.unwrap();
        }
        // 非法 sandboxId：不发请求即 None。
        assert!(wasm_engine_metrics(socket_path.to_str().unwrap(), "../etc", None).await.is_none());
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
            let health = supervisor_health(socket_path.to_str(), None).await;
            assert_eq!(health.available, expect_available, "body {body}");
            server.await.unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
