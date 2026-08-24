//! Supervisor 客户端（对位 kernel/supervisor-client.js）。
//! 私有 Unix socket；固定 /v1/health；响应 ≤16KiB；等待 ≤500ms；
//! 失败 → unavailable（不泄露宿主细节）。手写最小 HTTP/1.1，零新依赖。

use serde::Deserialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAXIMUM_RESPONSE_BYTES: usize = 16 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 500;

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
