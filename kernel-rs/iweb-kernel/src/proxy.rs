//! celld 反向代理（对位 kernel/index.js proxyToCelld）。
//! 头部契约逐项平价：host 重写为 <app>.app.<base>、x-iweb-original-host、
//! x-iweb-external-host(:port)、x-iweb-app-base（路径别名时）；connection 剥离。
//! 指标（inFlight/requests/errors/latency）随 §4.2 monitor 帧接入。
//! WebSocket/升级请求走 upgrade 隧道（reqwest 不支持协议升级透传）。

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
pub struct CelldTarget {
    pub port: u16,
    pub app_name: String,
    pub app_base_path: Option<String>,
    /// §4.2：随转发记录每应用指标（inFlight/requests/errors/latency）。
    pub metrics: crate::metrics::AppMetrics,
}

/// 转发请求到 127.0.0.1:<port>。连接失败 → 502 {error: "application unavailable"}；
/// 底层诊断只进容器日志（owner 面），绝不进公开响应（AGENTS.md 泛化错误法律）。
pub async fn forward(
    client: &reqwest::Client,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
    target: &CelldTarget,
    base_host: &str,
) -> Response<Body> {
    let upstream_base = format!("http://127.0.0.1:{}", target.port);
    let url = format!("{upstream_base}{path_and_query}");

    let mut request = client.request(method, &url);
    for (name, value) in headers.iter() {
        if name.as_str() == "connection" || name.as_str() == "host" {
            continue;
        }
        if let Ok(header_value) = value.to_str() {
            request = request.header(name.as_str(), header_value);
        }
    }
    request = request
        .header("host", format!("{}.app.{}", target.app_name, base_host))
        .header("x-iweb-original-host", original_host(headers));
    let external = external_host_header(headers);
    if let Some(external) = external {
        request = request.header("x-iweb-external-host", external);
    }
    if let Some(base) = &target.app_base_path {
        request = request.header("x-iweb-app-base", base);
    }
    // 标记出口请求：外部 host 回打入口时可被识别为环。
    request = request.header("x-iweb-via", "kernel");

    target.metrics.in_flight_enter(&target.app_name);
    let started = std::time::Instant::now();
    let outcome = match request.body(reqwest::Body::from(body)).send().await {
        Ok(upstream) => match axum_response(upstream).await {
            Ok(response) => Ok(response),
            Err(message) => Err(message),
        },
        Err(error) => Err(error.to_string()),
    };
    // error 语义对位 JS：上游 ≥500 或传输/转换失败都计入 errors。
    let error = match &outcome {
        Err(_) => true,
        Ok(response) => response.status().as_u16() >= 500,
    };
    target.metrics.observe(&target.app_name, started, error);
    match outcome {
        Ok(response) => response,
        Err(detail) => celld_unavailable(detail),
    }
}

fn celld_unavailable(detail: String) -> Response<Body> {
    // 诊断细节（对端地址/连接错误）仅进 owner 日志；公开响应是固定泛化文案。
    eprintln!("iweb-kernel: application upstream unavailable: {detail}");
    let body = serde_json::json!({ "error": "application unavailable" });
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static response")
}

async fn axum_response(upstream: reqwest::Response) -> Result<Response<Body>, String> {
    let status = upstream.status();
    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).map_err(|e| e.to_string())?);
    for (name, value) in upstream.headers().iter() {
        // 帧头（content-length/transfer-encoding/connection）由本地 Body 重算；
        // 复制会造成重复头，hyper 直接断连（lima 实测 admin \"/\" 200→空回复的根因）。
        if matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection") {
            continue;
        }
        let header_name = HeaderName::from_bytes(name.as_str().as_bytes()).map_err(|e| e.to_string())?;
        let header_value = HeaderValue::from_bytes(value.as_bytes()).map_err(|e| e.to_string())?;
        builder = builder.header(header_name, header_value);
    }
    let bytes = upstream.bytes().await.map_err(|e| e.to_string())?;
    builder.body(Body::from(bytes)).map_err(|e| e.to_string())
}

fn original_host(headers: &HeaderMap) -> &str {
    headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h))
        .unwrap_or("")
}

/// 对位 x-external-host(:port) 合成；无 host 头时空串省略。
fn external_host_header(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())?;
    let external_host = headers
        .get("x-iweb-external-host")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(|v| v.split(':').next().unwrap_or(v).to_string())
        .unwrap_or(host);
    let port = headers
        .get("x-iweb-external-port")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty());
    Some(match port {
        Some(port) => format!("{external_host}:{port}"),
        None => external_host,
    })
}

/// 升级请求判定：Connection 含 upgrade（大小写不敏感）且存在 Upgrade 头。
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let wants_upgrade = headers
        .get("connection")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    wants_upgrade && headers.contains_key("upgrade")
}

/// WebSocket/协议升级隧道：绕过 reqwest（其 body 模型不支持升级透传），
/// 直接 TCP 连 celld：转发原始请求 → 读上游响应头 → 101 原样回给客户端 →
/// hyper upgrade 接管下游连接后与上游双向桥接。上游首帧可能在响应头同包到达，
/// 残余字节必须先行写入下游，否则首帧丢失（实测教训）。
pub async fn upgrade_tunnel(
    mut request: axum::extract::Request,
    port: u16,
    app_name: &str,
    base_host: &str,
    metrics: crate::metrics::AppMetrics,
    request_started: std::time::Instant,
) -> Response<Body> {
    metrics.in_flight_enter(app_name);
    eprintln!("iweb-kernel: upgrade tunnel engaged for {app_name}");
    let body = match axum::body::to_bytes(std::mem::take(request.body_mut()), 64 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            metrics.observe(app_name, request_started, true);
            return celld_unavailable("upgrade request body read failed".into());
        }
    };
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let upstream = match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("iweb-kernel: upgrade upstream unavailable: {error}");
            metrics.observe(app_name, request_started, true);
            return celld_unavailable(error.to_string());
        }
    };
    let mut upstream = upstream;

    // 头部契约与 forward() 一致：host 重写、connection/host 剥离、环标记。
    let mut head = format!("{} {} HTTP/1.1\r\n", method, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
    for (name, value) in headers.iter() {
        let name = name.as_str();
        // Connection/Upgrade 是升级请求的功能头，必须原样转发（诊断实证：
        // 剥掉 Connection 后 celld 不再按升级处理，响应退化为无握手头的 101）。
        if matches!(name, "host" | "content-length" | "transfer-encoding") {
            continue;
        }
        if let Ok(value) = value.to_str() {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str(&format!("host: {app_name}.app.{base_host}\r\n"));
    head.push_str(&format!("content-length: {}\r\n", body.len()));
    head.push_str("\r\n");

    let mut request_bytes = head.into_bytes();
    request_bytes.extend_from_slice(&body);
    use tokio::io::AsyncWriteExt;
    if let Err(error) = upstream.write_all(&request_bytes).await {
        metrics.observe(app_name, request_started, true);
        return celld_unavailable(error.to_string());
    }

    // 读上游响应头（到 \r\n\r\n），保留残余字节（可能是 WS 首帧）。
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let Ok(n) = upstream.read(&mut chunk).await else {
            metrics.observe(app_name, request_started, true);
            return celld_unavailable("upgrade upstream closed before response head".into());
        };
        if n == 0 {
            metrics.observe(app_name, request_started, true);
            return celld_unavailable("upgrade upstream closed before response head".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Ok(pos) = find_header_end(&buffer) {
            let head_bytes = buffer[..pos].to_vec();
            let leftover = buffer[pos + 4..].to_vec();
            let mut builder = Response::builder();
            let mut upgrade_ok = false;
            for line in String::from_utf8_lossy(&head_bytes).lines() {
                if line.is_empty() {
                    continue;
                }
                if line.starts_with("HTTP/") {
                    if let Some(code) = line.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok()) {
                        builder = builder.status(code);
                        upgrade_ok = code == 101;
                    }
                    continue;
                }
                if let Some((name, value)) = line.split_once(':') {
                    // 帧头由本地连接重算，禁止透传；connection: upgrade 例外——
                    // 中间代理（实测 Portless）依赖它识别升级并转入隧道模式。
                    if name.trim().eq_ignore_ascii_case("content-length")
                        || name.trim().eq_ignore_ascii_case("transfer-encoding")
                    {
                        continue;
                    }
                    builder = builder.header(name.trim(), value.trim());
                }
            }
            if !upgrade_ok {
                // 非升级响应（如拒绝）：无隧道，直接回传（含残余 body）。
                metrics.observe(app_name, request_started, false);
                return builder
                    .body(Body::from(leftover))
                    .unwrap_or_else(|_| celld_unavailable("bad upstream response".into()));
            }
            let on_upgrade = hyper::upgrade::on(&mut request);
            let app_name = app_name.to_owned();
            tokio::spawn(async move {
                let Ok(upgraded) = on_upgrade.await else { return };
                let mut downstream = hyper_util::rt::TokioIo::new(upgraded);
                // 先冲残余字节（首帧竞态），再双向桥接。
                use tokio::io::AsyncWriteExt;
                let _ = downstream.write_all(&leftover).await;
                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
            });
            metrics.observe(&app_name, request_started, false);
            return builder.body(Body::empty()).expect("static upgrade response");
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Result<usize, ()> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n").ok_or(())
}

use tokio::io::AsyncReadExt;

// ---------------------------------------------------------------------------
// 沙箱网关 ingress 代理（P0-1：公开入口的 wasm 路由；对位 celld 的代理方式）
// ---------------------------------------------------------------------------

/// 沙箱网关 unix socket 目录（对位 JS kernel 的 GATEWAY_DIRECTORY）。
pub const SANDBOX_GATEWAY_DIRECTORY_ENV: &str = "IWEB_SANDBOX_GATEWAY_DIR";
pub const SANDBOX_GATEWAY_DIRECTORY_DEFAULT: &str = "/run/iweb-sandbox/gw";
const SANDBOX_INGRESS_SOCKET: &str = "ingress.sock";
/// 沙箱请求体上界（与 celld 转发的缓冲上限一致）。
const SANDBOX_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// 沙箱转发目标：sandboxId 寻址网关 socket；app 名用于 host 重写与指标归因。
pub struct SandboxTarget {
    pub sandbox_id: String,
    pub app_name: String,
    pub app_base_path: Option<String>,
    /// §4.2：随转发记录每应用指标（与 celld 转发同一归因面）。
    pub metrics: crate::metrics::AppMetrics,
}

/// sandboxId 文法（spec SandboxId；顺带排除路径分隔/遍历字符，socket 路径拼接安全）。
fn valid_sandbox_route_id(value: &str) -> bool {
    static SANDBOX_ID: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SANDBOX_ID
        .get_or_init(|| regex::Regex::new(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$").expect("sandbox id regex"))
        .is_match(value)
}

/// 解析沙箱 ingress socket 路径（非法 sandboxId → None；绝不拼接出目录外路径）。
pub fn sandbox_ingress_socket(sandbox_id: &str) -> Option<std::path::PathBuf> {
    if !valid_sandbox_route_id(sandbox_id) {
        return None;
    }
    let directory = std::env::var(SANDBOX_GATEWAY_DIRECTORY_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| SANDBOX_GATEWAY_DIRECTORY_DEFAULT.to_string());
    Some(std::path::PathBuf::from(directory).join(sandbox_id).join(SANDBOX_INGRESS_SOCKET))
}

/// 公开入口 → 沙箱网关私有 ingress（0600 unix socket；单请求单连接）。
/// 头部契约对位 celld 转发与 JS proxyToSandbox：host 重写 `<app>.app.<base>`、
/// x-iweb-original-host、x-iweb-external-host(:port)、x-iweb-app-base（别名时）、
/// connection 剥离。任何失败（socket 缺失/超时/畸形响应/升级请求）→ 泛化
/// `502 application unavailable`（AGENTS.md：绝不泄露沙箱/supervisor 诊断）。
pub async fn sandbox_forward(
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
    target: &SandboxTarget,
    base_host: &str,
) -> Response<Body> {
    let socket_path = match sandbox_ingress_socket(&target.sandbox_id) {
        Some(path) => path,
        None => {
            target.metrics.observe(&target.app_name, std::time::Instant::now(), true);
            return sandbox_unavailable("sandbox id is not routable".into());
        }
    };
    sandbox_forward_to(&socket_path, method, path_and_query, headers, body, target, base_host).await
}

/// 显式 socket 路径版（生产入口由 sandbox_forward 经 env 解析；测试/接线直连）。
pub async fn sandbox_forward_to(
    socket_path: &std::path::Path,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
    target: &SandboxTarget,
    base_host: &str,
) -> Response<Body> {
    // ingress 是 HTTP-only 单请求通道（spec SnapshotFdTransport/execution socket 分离）；
    // 升级请求无透传语义——按不可用 fail-closed，绝不伪装配隧道。
    if is_upgrade_request(headers) {
        target.metrics.observe(&target.app_name, std::time::Instant::now(), true);
        return sandbox_unavailable("the sandbox ingress does not carry upgrade requests".into());
    }
    target.metrics.in_flight_enter(&target.app_name);
    let started = std::time::Instant::now();
    let outcome = sandbox_exchange(socket_path, method, path_and_query, headers, body, target, base_host).await;
    let error = match &outcome {
        Err(_) => true,
        Ok(response) => response.status().as_u16() >= 500,
    };
    target.metrics.observe(&target.app_name, started, error);
    match outcome {
        Ok(response) => response,
        Err(detail) => sandbox_unavailable(detail),
    }
}

fn sandbox_unavailable(detail: String) -> Response<Body> {
    // 诊断只进容器日志；公开响应是固定泛化文案（对位 celld_unavailable）。
    eprintln!("iweb-kernel: sandbox upstream unavailable: {detail}");
    let body = serde_json::json!({ "error": "application unavailable" });
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static response")
}

async fn sandbox_exchange(
    socket_path: &std::path::Path,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
    target: &SandboxTarget,
    base_host: &str,
) -> Result<Response<Body>, String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut upstream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("cannot connect {}: {e}", socket_path.display()))?;
    // 手写最小 HTTP/1.1（reqwest 无 UDS 直连；网关按单请求单连接 + Connection: close）。
    let mut head = format!("{} {} HTTP/1.1\r\n", method, path_and_query);
    for (name, value) in headers.iter() {
        let name = name.as_str();
        if matches!(name, "host" | "connection" | "content-length" | "transfer-encoding") {
            continue;
        }
        if let Ok(value) = value.to_str() {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str(&format!("host: {}.app.{}\r\n", target.app_name, base_host));
    head.push_str(&format!("x-iweb-original-host: {}\r\n", original_host(headers)));
    if let Some(external) = external_host_header(headers) {
        head.push_str(&format!("x-iweb-external-host: {external}\r\n"));
    }
    if let Some(base) = &target.app_base_path {
        head.push_str(&format!("x-iweb-app-base: {base}\r\n"));
    }
    head.push_str(&format!("content-length: {}\r\n", body.len()));
    head.push_str("connection: close\r\n\r\n");
    let mut request_bytes = head.into_bytes();
    request_bytes.extend_from_slice(&body);
    upstream.write_all(&request_bytes).await.map_err(|e| e.to_string())?;

    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0u8; 8192];
    loop {
        let read = upstream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > SANDBOX_MAX_BODY_BYTES {
            return Err("sandbox response exceeds the body budget".into());
        }
        if let Ok(position) = find_header_end(&buffer) {
            let header_text = String::from_utf8_lossy(&buffer[..position]).to_string();
            if let Some(length) = header_content_length(&header_text) {
                if buffer.len() >= position + length {
                    break;
                }
            }
        }
    }
    let position = find_header_end(&buffer).map_err(|_| "sandbox response has no header terminator".to_string())?;
    let header_text = String::from_utf8_lossy(&buffer[..position]).to_string();
    let mut lines = header_text.lines();
    let status_line = lines.next().ok_or_else(|| "empty sandbox response".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "sandbox response carries no status".to_string())?;
    let mut builder = Response::builder().status(StatusCode::from_u16(status).map_err(|e| e.to_string())?);
    let mut declared_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            // 帧头（content-length/transfer-encoding/connection）由本地 Body 重算。
            if name.trim().eq_ignore_ascii_case("content-length") {
                declared_length = value.trim().parse().ok();
                continue;
            }
            if name.trim().eq_ignore_ascii_case("transfer-encoding") || name.trim().eq_ignore_ascii_case("connection") {
                continue;
            }
            builder = builder.header(name.trim(), value.trim());
        }
    }
    // body 起点越过 \r\n\r\n（4 字节）；按声明的 content-length 精确切分（无声明时
    // 取到连接关闭为止的全部残余）。
    let body_start = position + 4;
    let body_end = match declared_length {
        Some(length) => body_start.checked_add(length).filter(|end| *end <= buffer.len()).ok_or_else(|| "sandbox response body is shorter than its content-length".to_string())?,
        None => buffer.len(),
    };
    let body_bytes = buffer[body_start..body_end].to_vec();
    builder.body(Body::from(body_bytes)).map_err(|e| e.to_string())
}

fn header_content_length(header_text: &str) -> Option<usize> {
    for line in header_text.lines() {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return value.trim().parse().ok();
        }
    }
    None
}

