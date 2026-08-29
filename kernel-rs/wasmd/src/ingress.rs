//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1/3.3/3.4）：监听契约与生命周期
//! ——只在 supervisor 给定的唯一地址上监听（配对 gateway ingress 拨打的沙箱内地址）；
//! readiness health v2 从该 listener 的固定内部端点 GET /healthz 以 JCS 返回完整身份
//! payload（gateway 原样比对，绝不由配置合成）；SIGTERM 优雅 drain（停止接新连接/
//! 新请求、在飞请求等到 capability record 的 drainDeadlineMs，超时后退出——epoch 引擎
//! 侧按执行强杀不崩进程的机制见 host.rs）。
//! 规范权威：spec "Wasmd has a fixed command and host-mediated network contract" /
//! "Wasm readiness is a full identity attestation" / "Lifecycle keeps one routed
//! execution while allowing bounded drain"。
//!
//! 预留路径歧义（fail-closed 取舍）：health 端点固定为单 listener 上的 `GET /healthz`
//! ——spec 只规定“固定 sandbox-local ingress 目标”未点名路径；本实现把该路径保留为
//! 宿主保留路径，应用流量不会在该路径收到应用响应。drain 中新请求一律 503。

use crate::host::WasmdEngine;
use crate::jcs::{err, WireError};
use crate::limits::{check_header_limits, LimitedBody};
use crate::wire::WasmReadinessHealthV2;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::WasiBody;

/// 固定内部健康端点（保留路径；见模块注释的歧义取舍）。
pub const HEALTH_PATH: &str = "/healthz";

/// owner 诊断保留路径（第三轮复审 2026-08-28，logging 权威接通）：wasmd 进程内
/// per-app ring 的唯一读取面——supervisor 经沙箱网络拉取（/v1/host-logging/drain/
/// <applicationId> 与 /v1/host-logging/summary/<applicationId>）。与 /healthz 同为
/// 宿主保留路径：应用流量不会在这些路径收到应用响应；回答不依赖 graceful-drain
/// 状态（drain 窗口内 owner 仍可拉取最后的事件）。
pub const HOST_LOGGING_DRAIN_PATH: &str = "/v1/host-logging/drain";
pub const HOST_LOGGING_SUMMARY_PATH: &str = "/v1/host-logging/summary";

/// wasmd 补充稳定码。
pub const INGRESS_BIND_FAILED: &str = "WASMD_INGRESS_BIND_FAILED";
pub const INGRESS_SIGNAL_FAILED: &str = "WASMD_INGRESS_SIGNAL_FAILED";

/// drain 状态（SIGTERM 后：不接新连接/新请求；在飞等到 deadline）。
#[derive(Debug, Default)]
pub struct DrainState {
    draining: AtomicBool,
    in_flight: std::sync::atomic::AtomicU64,
}

impl DrainState {
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    fn enter(&self) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
    }

    fn leave(&self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }
}

/// ingress 服务句柄：accept 循环任务 + drain 状态。
pub struct IngressHandle {
    drain: Arc<DrainState>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl IngressHandle {
    /// 优雅 drain：标记 draining、停接新连接/新请求、在飞清零或 deadline 超时。
    /// 返回 true = 在飞全部完成；false = deadline 到达仍有在飞（强制退出由调用方
    /// 决定，退出码语义见 main.rs）。
    pub async fn graceful_drain(&self, drain_deadline_ms: u64) -> bool {
        self.drain.draining.store(true, Ordering::SeqCst);
        self.accept_task.abort();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(drain_deadline_ms);
        while self.drain.in_flight() > 0 {
            if tokio::time::Instant::now() >= deadline {
                eprintln!(
                    "wasmd: drain deadline reached with {} in-flight request(s); forcing exit",
                    self.drain.in_flight()
                );
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }
}

/// 在唯一 listener 上启动服务：health 端点 + 应用请求（入站上限强制 + 引擎执行）。
/// listener 绑定失败即启动 fail-closed（调用方 exit 70）。
pub async fn serve(
    engine: Arc<WasmdEngine>,
    health: WasmReadinessHealthV2,
    listen: std::net::SocketAddr,
    http_limits: crate::capability::NodeHttpLimitsV1,
) -> Result<IngressHandle, WireError> {
    let health_bytes = health.jcs()?;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| err(INGRESS_BIND_FAILED, format!("listen {listen} failed: {error}")))?;
    let drain = Arc::new(DrainState::default());

    let accept_drain = Arc::clone(&drain);
    let accept_task = tokio::spawn(async move {
        loop {
            if accept_drain.is_draining() {
                break;
            }
            let Ok((socket, _peer)) = listener.accept().await else {
                continue;
            };
            let engine = Arc::clone(&engine);
            let drain = Arc::clone(&accept_drain);
            let health_bytes = health_bytes.clone();
            let http_limits = http_limits.clone();
            tokio::spawn(async move {
                let builder_limits = http_limits.clone();
                let service = service_fn(move |request: Request<Incoming>| {
                    let engine = Arc::clone(&engine);
                    let drain = Arc::clone(&drain);
                    let health_bytes = health_bytes.clone();
                    let http_limits = http_limits.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            handle(engine, drain, http_limits, health_bytes, request).await,
                        )
                    }
                });
                // http1 单连接多请求（keep-alive）；头部计数上限交给 hyper max_headers，
                // 头部字节上限约束解析缓冲并在解析后复检。
                let _ = hyper::server::conn::http1::Builder::new()
                    .max_headers(builder_limits.max_request_header_count as usize)
                    .max_buf_size((builder_limits.max_request_header_bytes as usize).saturating_mul(2))
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });

    Ok(IngressHandle { drain, accept_task })
}

/// 空体固定响应（错误路径；文案固定，不外泄 guest/引擎细节）。
fn respond_empty(status: StatusCode) -> Response<WasiBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()).map_err(|error| match error {}).boxed_unsync())
        .expect("static empty response")
}

/// 单请求处理：health 保留路径 → drain 503 → 入站上限 → 引擎执行。
async fn handle(
    engine: Arc<WasmdEngine>,
    drain: Arc<DrainState>,
    http_limits: crate::capability::NodeHttpLimitsV1,
    health_bytes: Vec<u8>,
    request: Request<Incoming>,
) -> Response<WasiBody> {
    drain.enter();
    let _guard = InFlightGuard { drain: Arc::clone(&drain) };

    // 保留路径：health v2 原样返回（gateway 比对全字段；绝不由配置合成）。
    if request.uri().path() == HEALTH_PATH {
        return match *request.method() {
            hyper::Method::GET | hyper::Method::HEAD => Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(health_bytes)).map_err(|error| match error {}).boxed_unsync())
                .expect("static health response"),
            _ => respond_empty(StatusCode::METHOD_NOT_ALLOWED),
        };
    }

    // 保留路径：owner 诊断（logging ring 投影）。无 provider（argv@1 / 服务未启用）
    // = 该应用无环 → 404；wire/隔离偏差 fail-closed；跨应用请求 → 403。
    if request.uri().path().starts_with(HOST_LOGGING_DRAIN_PATH) || request.uri().path().starts_with(HOST_LOGGING_SUMMARY_PATH) {
        return handle_host_logging(&engine, request)
            .await
            .unwrap_or_else(|| respond_empty(StatusCode::NOT_FOUND));
    }


    if drain.is_draining() {
        return respond_empty(StatusCode::SERVICE_UNAVAILABLE);
    }

    // 入站头部上限（计数已由 hyper max_headers 强制；此处复检字节数）。
    if check_header_limits(request.headers(), u64::MAX, http_limits.max_request_header_bytes).is_err() {
        return respond_empty(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }

    // 入站请求体上限：Content-Length 预检 + 流式截断。
    if let Some(length) = request
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        if length > http_limits.max_request_bytes {
            return respond_empty(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    let capped = request.map(|body| LimitedBody::new(body, http_limits.max_request_bytes).boxed_unsync());

    match engine.handle_request(capped).await {
        Ok(response) => response,
        Err(_error) => {
            // guest trap / epoch 超时 / guest 未设置响应：generic 502（应用侧归因；
            // 细节不外泄；epoch 计数已在 host 层累计）。
            respond_empty(StatusCode::BAD_GATEWAY)
        }
    }
}

struct InFlightGuard {
    drain: Arc<DrainState>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.drain.leave();
    }
}

// ---------------------------------------------------------------------------
// owner 诊断保留路径（logging ring 投影；宿主保留路径与 /healthz 同级）
// ---------------------------------------------------------------------------

/// drain 请求体上限（{schemaVersion, applicationId, afterEventId, maxEvents} 的
/// 有界 JSON；诊断面不接受大 body）。
const HOST_LOGGING_DRAIN_MAX_BODY_BYTES: usize = 4_096;

fn json_response(status: StatusCode, payload: Vec<u8>) -> Response<WasiBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(payload)).map_err(|error| match error {}).boxed_unsync())
        .expect("static json response")
}

fn logging_error_response(status: StatusCode, code: &str, detail: &str) -> Response<WasiBody> {
    let payload = format!("{{\"code\":\"{code}\",\"detail\":\"{detail}\"}}");
    json_response(status, payload.into_bytes())
}

/// 路径 → (prefix 命中, applicationId)。applicationId 文法先于 provider 判定。
fn split_host_logging_path(path: &str, prefix: &str) -> Option<String> {
    let suffix = path.strip_prefix(prefix)?.strip_prefix('/')?;
    if suffix.is_empty() || suffix.contains('/') {
        return None;
    }
    Some(suffix.to_string())
}

/// 保留路径处理：None = 非 host-logging 路径（回到常规请求面）。provider 缺席
///（argv@1 / 服务未启用）= 该应用无环 → 404；隔离违约 403；wire 偏差 400。
/// 安全法：这些路径在公共 listener 上——必须携带与 execution identity 绑定的
/// X-Iweb-Host-Logging-Token 头（supervisor 从 argv context 派生注入）才放行；
/// 无 token / 错 token 一律 403，防止公共流量经 gateway 读取日志正文。
async fn handle_host_logging(engine: &Arc<WasmdEngine>, request: Request<Incoming>) -> Option<Response<WasiBody>> {
    let path = request.uri().path();
    let method = request.method().clone();
    let provider = engine.host_services();

    // 鉴权先行：无 token / 错 token → 403，不暴露任何路径语义。
    let expected_token = engine.host_logging_access_token();
    let presented = request.headers().get("x-iweb-host-logging-token").and_then(|v| v.to_str().ok());
    match (expected_token.as_deref(), presented) {
        (Some(expected), Some(given)) if crate::jcs::constant_time_eq(expected.as_bytes(), given.as_bytes()) => {},
        _ => return Some(logging_error_response(StatusCode::FORBIDDEN, "IWEB_LOG_AUTH_REQUIRED", "host-logging endpoints require the execution-bound access token")),
    }

    if let Some(application_id) = split_host_logging_path(path, HOST_LOGGING_SUMMARY_PATH) {
        if method != hyper::Method::GET {
            return Some(respond_empty(StatusCode::METHOD_NOT_ALLOWED));
        }
        if crate::jcs::validate_application_id(&application_id).is_err() {
            return Some(respond_empty(StatusCode::NOT_FOUND));
        }
        let Some(provider) = provider else {
            return Some(logging_error_response(StatusCode::NOT_FOUND, "IWEB_LOG_APPLICATION_UNKNOWN", "no logging ring exists for this application"));
        };
        let summary = match provider.logging_monitor_summary() {
            Ok(summary) => summary,
            Err(_) => return Some(logging_error_response(StatusCode::INTERNAL_SERVER_ERROR, "IWEB_LOG_INTERNAL", "the logging ring is unavailable")),
        };
        if summary.application_id != application_id {
            return Some(logging_error_response(StatusCode::FORBIDDEN, "IWEB_LOG_APP_ISOLATION", "the monitor summary belongs to another application"));
        }
        let payload = crate::jcs::jcs_bytes(&summary.to_wire()).ok()?;
        return Some(json_response(StatusCode::OK, payload));
    }

    if let Some(application_id) = split_host_logging_path(path, HOST_LOGGING_DRAIN_PATH) {
        if method != hyper::Method::POST {
            return Some(respond_empty(StatusCode::METHOD_NOT_ALLOWED));
        }
        if crate::jcs::validate_application_id(&application_id).is_err() {
            return Some(respond_empty(StatusCode::NOT_FOUND));
        }
        let Some(provider) = provider else {
            return Some(logging_error_response(StatusCode::NOT_FOUND, "IWEB_LOG_APPLICATION_UNKNOWN", "no logging ring exists for this application"));
        };
        // 有界读（诊断面固定上限；应用流量的大 body 上限属常规请求面）。
        let bounded = request.into_body().collect().await.ok()?.to_bytes();
        if bounded.len() > HOST_LOGGING_DRAIN_MAX_BODY_BYTES {
            return Some(respond_empty(StatusCode::PAYLOAD_TOO_LARGE));
        }
        let wire_request: crate::host_services::logging::LoggingDrainRequestWireV1 = match serde_json::from_slice(&bounded) {
            Ok(value) => value,
            Err(_) => return Some(logging_error_response(StatusCode::BAD_REQUEST, "IWEB_LOG_DRAIN_REQUEST_INVALID", "the drain request body does not parse as the typed record")),
        };
        if let Err(error) = wire_request.validate() {
            return Some(logging_error_response(StatusCode::BAD_REQUEST, "IWEB_LOG_DRAIN_REQUEST_INVALID", &error.detail));
        }
        if wire_request.application_id != application_id {
            return Some(logging_error_response(StatusCode::FORBIDDEN, "IWEB_LOG_APP_ISOLATION", "the drain request names a different application than the drain target"));
        }
        let drained = match provider.logging_drain(&application_id, wire_request.after_event_id, wire_request.max_events as usize) {
            Ok(response) => response,
            Err(crate::host_services::logging::LoggingError::AppIsolation) => {
                return Some(logging_error_response(StatusCode::FORBIDDEN, "IWEB_LOG_APP_ISOLATION", "the drain target does not own this logging ring"))
            }
            Err(crate::host_services::logging::LoggingError::LimitExceeded) => {
                return Some(logging_error_response(StatusCode::BAD_REQUEST, "IWEB_LOG_LIMIT_EXCEEDED", "the drain request exceeds the bounded drain window"))
            }
            Err(_) => return Some(logging_error_response(StatusCode::INTERNAL_SERVER_ERROR, "IWEB_LOG_INTERNAL", "the logging ring is unavailable")),
        };
        let payload = crate::jcs::jcs_bytes(&drained.to_wire()).ok()?;
        return Some(json_response(StatusCode::OK, payload));
    }

    None
}
