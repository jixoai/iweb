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
