//! Kernel HTTP 面最小服务集（§4.1 开篇）：
//! /health（免鉴权探针）、401 鉴权墙、/v1/status、/v1/applications 发布闸门 503。
//! 其余端点按 tasks §4 逐个移植；未实现端点统一 501（与 JS 行为对位前不冒充成功）。


use iweb_kernel::config::Config;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use axum::http::{Response, StatusCode};
use axum::middleware::Next;
use std::net::SocketAddr;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    control_db_path: String,
    routes_path: Option<String>,
    http_client: Arc<reqwest::Client>,
    monitor_tickets: Arc<iweb_kernel::monitor::Tickets>,
    /// monitor 票据 → 鉴权主体（ban 后票据立即失效）。
    ticket_actors: Arc<std::sync::Mutex<std::collections::HashMap<String, iweb_kernel::keys::Actor>>>,
    keys: Arc<iweb_kernel::keys::KeyStore>,
    celld_samples: Arc<iweb_kernel::sampling::CelldSamples>,
    metrics: Arc<iweb_kernel::metrics::AppMetrics>,
    /// 进程启动时刻（uptime 从这里起算，而非首个 monitor 连接）。
    started_at: std::time::Instant,
}

impl AppState {
    /// 统一鉴权：bootstrap（IWEB_API_TOKEN）或委托 key（owner-key-management）。
    fn authorize(&self, headers: &HeaderMap) -> Option<iweb_kernel::keys::Actor> {
        let bearer = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))?;
        self.keys.authenticate(bearer)
    }
}

/// 对位 kernel/index.js normalizeHost：lowercase、剥尾部 :port、剥尾部点。
fn normalize_host(value: &str) -> String {
    let mut host = value.trim().to_lowercase();
    if let Some((head, tail)) = host.rsplit_once(':') {
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            host = head.to_owned();
        }
    }
    if host.ends_with('.') {
        host.pop();
    }
    host
}

/// CORS（对位 kernel/index.js jsonHandlers 的 admin-origin 回显）：Admin 从
/// admin.<base> / <base> / admin.app.<base> 三源跨域调 api.<base>；仅这些来源被回显，
/// 其余来源不发任何 CORS 头。Rust 端曾漏移植本契约，2026-08-21 真浏览器登录暴露。
fn cors_origin_headers(origin: &str, base_host: &str) -> Option<Vec<(&'static str, String)>> {
    let after_scheme = origin.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = normalize_host(authority);
    let matches = host == base_host
        || host == format!("admin.{base_host}")
        || host == format!("admin.app.{base_host}");
    matches.then(|| {
        vec![
            ("access-control-allow-origin", origin.to_owned()),
            ("access-control-allow-headers", "authorization, content-type".into()),
            ("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS".into()),
            ("vary", "Origin".into()),
        ]
    })
}

/// 控制 Router 的 CORS 中间件：preflight（带 access-control-request-method 的 OPTIONS）
/// 免鉴权 204（对位 JS handleApi 首分支）；其余响应追加 CORS 头。
async fn cors_middleware(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response<Body> {
    let cors = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .and_then(|origin| cors_origin_headers(origin, &state.config.base_host));
    let Some(cors) = cors else {
        return next.run(request).await;
    };
    if request.method() == axum::http::Method::OPTIONS
        && request.headers().contains_key("access-control-request-method")
    {
        let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
        for (name, value) in &cors {
            builder = builder.header(*name, value.clone());
        }
        return builder.body(Body::empty()).expect("static response");
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in cors {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    }
    response
}

/// 审计中间件（owner-key-management）：/v1/* 控制面请求按实际鉴权主体归因，
/// 401 拒绝记录为未归属事件；路径归一化去 query；绝不记录 bearer/票据/body。
async fn audit_middleware(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response<Body> {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let is_control = path.starts_with("/v1/");
    let actor = if is_control {
        state.authorize(request.headers())
    } else {
        None
    };
    let response = next.run(request).await;
    if is_control {
        state.keys.record_request(actor.as_ref(), &method, &path, response.status().as_u16());
    }
    response
}

/// 启动服务（阻塞至进程退出；SIGTERM 优雅退出）。
/// 两个监听器（§5.1）：回环控制 API（config.api_addr）+ 发布入口（IWEB_HTTP_PORT，默认 8080）。
/// 入口做 host 路由：api.<base> → 控制 API；已知应用 host/路径别名 → 502（celld 代理下一任务接入，
/// notes 502 语义今日即平价）；/_iweb/health → 200；未知 → 404。X-Iweb-Internal-Control 废除。
pub fn serve(config: Config) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let addr = config.api_addr;
    let ingress_port: u16 = std::env::var("IWEB_HTTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let control_db_path = std::env::var("IWEB_CONTROL_DB_FILE").unwrap_or_default();
    let routes_path = std::env::var("IWEB_ROUTES_FILE").ok();
    let celld_samples = Arc::new(iweb_kernel::sampling::CelldSamples::default());
    iweb_kernel::sampling::spawn_refresh_loop(celld_samples.clone());
    let api_token = config.api_token.clone();
    let base_host_for_keys = config.base_host.clone();
    let _ = base_host_for_keys;
let keys_path: std::path::PathBuf = std::env::var("IWEB_KEYS_FILE")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| routes_path.as_ref().map(|p| std::path::Path::new(p).parent().unwrap_or(std::path::Path::new(".")).join("keys.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("/data/kernel/keys.json"));
    let keys = Arc::new(iweb_kernel::keys::KeyStore::load(&keys_path, &api_token));
    let state = AppState { config: Arc::new(config), control_db_path, routes_path, http_client: Arc::new(reqwest::Client::new()), monitor_tickets: Arc::new(iweb_kernel::monitor::Tickets::default()), ticket_actors: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())), keys, celld_samples, metrics: Arc::new(iweb_kernel::metrics::AppMetrics::default()), started_at: std::time::Instant::now() };
    runtime.block_on(async move {
        // reqwest Client 必须在将要使用它的 runtime 内构造：跨 runtime 的连接池会死锁
        //（Client 在无 runtime 环境下惰性初始化，首次使用绑定错误 runtime）。
        let http_client = Arc::new(
            reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("http client"),
        );
        let state = AppState { config: state.config.clone(), control_db_path: state.control_db_path.clone(), routes_path: state.routes_path.clone(), http_client, monitor_tickets: Arc::new(iweb_kernel::monitor::Tickets::default()), ticket_actors: state.ticket_actors.clone(), keys: state.keys.clone(), celld_samples: state.celld_samples.clone(), metrics: state.metrics.clone(), started_at: state.started_at };
        let api = control_router(state.clone());
        let api_listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));
        println!("iweb-kernel control listening on {addr}");

        let ingress = Router::new()
            .route("/_iweb/health", get(ingress_health))
            .fallback(ingress_router)
            .with_state(state);
        let ingress_addr = SocketAddr::from(([0, 0, 0, 0], ingress_port));
        let ingress_listener = tokio::net::TcpListener::bind(ingress_addr)
            .await
            .unwrap_or_else(|e| panic!("cannot bind {ingress_addr}: {e}"));
        println!("iweb-kernel ingress listening on {ingress_addr}");

        let api_task = tokio::spawn(async move {
            axum::serve(api_listener, api)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .expect("api server error");
        });
        let ingress_task = tokio::spawn(async move {
            axum::serve(ingress_listener, ingress)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .expect("ingress server error");
        });
        let _ = tokio::join!(api_task, ingress_task);
    });
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

fn unauthorized() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "missing or invalid API token" })))
}

/// owner key 能力描述（对位 JS /v1/key 静态载荷；ownerKeySchema）。
async fn owner_key(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    Ok(Json(json!({
        "kind": "owner",
        "capabilities": {
            "read": ["/**"],
            "write": ["/**"],
            "deploy": ["*"],
            "domains": ["*"],
            "environment": ["*"]
        }
    })))
}

/// owner-key-management：列表（元数据，含不可吊销的 bootstrap 合成条目）。
async fn keys_list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    Ok(Json(json!({ "keys": state.keys.metadata() })))
}

/// 创建：明文 token 只在本响应出现一次；快照/审计提交失败 → 503。
async fn keys_create(State(state): State<AppState>, headers: HeaderMap, body: axum::body::Bytes) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let Some(actor) = state.authorize(&headers) else {
        return Err(unauthorized());
    };
    let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&body);
    let Ok(input) = parsed else {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid JSON body" }))));
    };
    // 输入严格校验：只接受 {label, expiresAt} 两键（多余字段拒绝）。
    let known = ["label", "expiresAt"];
    if input.as_object().map(|object| object.keys().any(|key| !known.contains(&key.as_str()))).unwrap_or(true) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": "only label and expiresAt are accepted" }))));
    }
    let expires_at = match input.get("expiresAt") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.as_str()),
        Some(_) => return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": "expiresAt must be a string or null" })))),
    };
    let label = input.get("label").and_then(|v| v.as_str()).unwrap_or_default();
    match state.keys.create(label, expires_at, &actor) {
        Ok(issued) => Ok((
            StatusCode::CREATED,
            Json(json!({ "token": issued.token, "key": metadata_json(&issued.record) })),
        )),
        Err(error) if error.0.contains("snapshot") || error.0.contains("pending") || error.0.contains("audit") || error.0.contains("damaged") => {
            Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "key store is temporarily unavailable" }))))
        }
        Err(error) => Err((StatusCode::BAD_REQUEST, Json(json!({ "error": error.0 })))),
    }
}

/// 吊销（幂等；bootstrap → 409 IMMUTABLE_BOOTSTRAP）。
async fn keys_ban(State(state): State<AppState>, headers: HeaderMap, axum::extract::Path(key_id): axum::extract::Path<String>) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let Some(actor) = state.authorize(&headers) else {
        return Err(unauthorized());
    };
    match state.keys.ban(&key_id, &actor) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(error) if error.0 == "IMMUTABLE_BOOTSTRAP" => {
            Err((StatusCode::CONFLICT, Json(json!({ "error": "IMMUTABLE_BOOTSTRAP" }))))
        }
        Err(error) if error.0 == "UNKNOWN_KEY" => {
            Err((StatusCode::NOT_FOUND, Json(json!({ "error": "UNKNOWN_KEY" }))))
        }
        Err(_) => Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "key store is temporarily unavailable" })))),
    }
}

/// 审计读取（newest-first，limit 1..=200，keyId 可选过滤；无任何凭据材料）。
async fn audit_list(State(state): State<AppState>, headers: HeaderMap, axum::extract::RawQuery(query): axum::extract::RawQuery) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let key_id = query
        .as_deref()
        .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("keyId=")))
        .map(str::to_owned);
    let limit = query
        .as_deref()
        .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("limit=")))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50);
    match state.keys.audit(key_id.as_deref(), limit) {
        Ok((events, dropped)) => Ok(Json(json!({ "events": events, "dropped": dropped }))),
        Err(_) => Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "audit log is unavailable" })))),
    }
}

fn metadata_json(record: &iweb_kernel::keys::KeyRecord) -> serde_json::Value {
    let now = iweb_kernel::monitor::iso_now();
    let status = if record.banned_at.is_some() {
        "banned"
    } else if record.expires_at.as_deref().is_some_and(|expiry| expiry <= now.as_str()) {
        "expired"
    } else {
        "active"
    };
    json!({
        "keyId": record.key_id,
        "label": record.label,
        "createdAt": record.created_at,
        "expiresAt": record.expires_at,
        "bannedAt": record.banned_at,
        "status": status,
        "revocable": true,
    })
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let applications = iweb_kernel::control::read_state(std::path::Path::new(&state.control_db_path))
        .map(|file| {
            file.applications
                .values()
                .map(|app| {
                    let mut projection = iweb_kernel::control::project_application(app);
                    // 控制面应用：真实进程 RSS 采样（无采样 → null，绝不补 0）。
                    if let Some(id) = projection.get("id").and_then(|v| v.as_str()) {
                        if let Some(sample) = state.celld_samples.current(id) {
                            projection["resources"] = json!({
                                "versionId": "celld-process",
                                "sampledAt": sample.sampled_at,
                                "cpuMillis": { "available": false },
                                "memoryBytes": { "available": true, "value": sample.bytes },
                                "pidCount": { "available": false },
                                "terminated": { "available": false },
                                "limits": null,
                            });
                        }
                    }
                    projection
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let routes_count = state
        .routes_path
        .as_deref()
        .and_then(|p| {
            std::panic::catch_unwind(|| iweb_kernel::routes::RouteStore::load(std::path::Path::new(p)))
                .ok()
                .map(|store| store.snapshot().len())
        })
        .unwrap_or(0);
    let memory = memory_flat();
    // §4.5：supervisor 探测经私有 UDS（未配置 → configured:false，语义对位 JS）。
    let socket = std::env::var("IWEB_SANDBOX_SOCKET").ok();
    let health = iweb_kernel::supervisor::supervisor_health(socket.as_deref(), None).await;
    Ok(Json(json!({
        "baseHost": state.config.base_host,
        "runtime": "celld",
        "routes": routes_count,
        "memory": memory,
        "applicationPublication": { "enabled": false, "reasons": ["publication-not-requested", "sandbox-acceptance-missing"] },
        "sandboxSupervisor": { "configured": health.configured, "available": health.available, "version": health.version },
        "applications": applications,
    })))
}

async fn applications_gate(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "application publication is disabled until sandbox acceptance passes",
            "code": "APPLICATION_PUBLICATION_DISABLED"
        })),
    ))
}

async fn recover_bounded(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    // 有界失败而非伪装成功（对位 JS 的 secret 缺失分支）；§4.3 控制日志移植后接真实 reconciliation。
    let secrets_missing = std::env::var("IWEB_CONTROL_SECRETS_FILE")
        .ok()
        .filter(|p| !p.is_empty() && !std::path::Path::new(p).exists())
        .is_some();
    let message = if secrets_missing {
        "control secrets unavailable: rust kernel port in progress"
    } else {
        "recovery bounded: rust kernel port in progress"
    };
    Err((StatusCode::BAD_REQUEST, Json(json!({ "error": message }))))
}

async fn ingress_health() -> &'static str {
    "ok"
}

/// 入口 host 路由（对位 Caddyfile 的每一条 handle）：api.<base> → 控制 API 直达；
/// 应用 host / base 路径别名 → 502（celld 代理在 §4.6 接线；notes 等无 handler 应用按设计 502）；
/// 未知 host/路径 → 404。头部路由戏法（X-Iweb-Internal-Control）不复存在。
async fn ingress_router(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response<Body> {
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
        .unwrap_or_default();
    let base = state.config.base_host.clone();
    let path = request.uri().path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_else(|| "/".into());

    if host == format!("api.{base}") {
        // 控制 API 通过入口直达：恢复权威不依赖任何其它进程（kernel-control-plane 规范）。
        return control_via_ingress(State(state), request).await;
    }

    let Some(routes_path) = state.routes_path.clone() else {
        return not_found();
    };
    let store = match std::panic::catch_unwind(|| iweb_kernel::routes::RouteStore::load(std::path::Path::new(&routes_path))) {
        Ok(store) => store,
        Err(_) => return unavailable(),
    };
    // 回环防护：celld Worker 可能用外部 host 回打入口，形成 admin→kernel→celld 死环
    //（lima 实测 "read header from client timeout"）。带标记的请求直接有界失败。
    if request.headers().get("x-iweb-via").map(|v| v.as_bytes()) == Some(b"kernel") {
        return response_json(StatusCode::BAD_GATEWAY, json!({ "error": "application unavailable" }));
    }
    match iweb_kernel::routes::resolve(&store, &base, &host, &path) {
        Some(resolved) => {
            // §4.6：system 目标代理到 per-app celld；sandbox 目标（无运行时接线）按设计 502。
            match store.action_for(&resolved.route) {
                Some(iweb_kernel::routes::RouteAction::System { app_name }) => {
                    let ports = iweb_kernel::routes::celld_ports();
                    // 未知应用无 celld 端口映射：fail-closed 502，绝不回退 admin 端口。
                    let Some(port) = ports.get(&app_name).copied() else {
                        return unavailable();
                    };
                    // WebSocket/协议升级走专用隧道（reqwest 不支持升级透传）。
                    if iweb_kernel::proxy::is_upgrade_request(request.headers()) {
                        let started = std::time::Instant::now();
                        return iweb_kernel::proxy::upgrade_tunnel(
                            request,
                            port,
                            &app_name,
                            &base,
                            (*state.metrics).clone(),
                            started,
                        )
                        .await;
                    }
                    let (parts, body) = request.into_parts();
                    let bytes = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
                        Ok(bytes) => bytes,
                        Err(_) => return unavailable(),
                    };
                    let target = iweb_kernel::proxy::CelldTarget {
                        port,
                        app_name,
                        app_base_path: resolved.app_base_path.clone(),
                        metrics: (*state.metrics).clone(),
                    };
                    iweb_kernel::proxy::forward(
                        &state.http_client,
                        parts.method,
                        &resolved.upstream_path,
                        &parts.headers,
                        bytes,
                        &target,
                        &base,
                    )
                    .await
                }
                _ => unavailable(),
            }
        }
        None => not_found(),
    }
}

fn not_found() -> Response<Body> {
    response_json(StatusCode::NOT_FOUND, json!({ "error": "unknown iweb route" }))
}

fn unavailable() -> Response<Body> {
    response_json(StatusCode::BAD_GATEWAY, json!({ "error": "application unavailable" }))
}

fn response_json(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static response")
}

/// 浏览器契约（admin nodeStatusSchema/monitorSnapshotSchema，对位 JS memorySnapshot）：
/// memory 是扁平四字段——usage/limit/percent 缺测为 null，绝不以 0 冒充。
fn memory_flat() -> serde_json::Value {
    let (current, max) = iweb_kernel::sampling::container_memory();
    let usage = match current {
        iweb_kernel::sampling::MemoryValue::Bytes(v) => Some(v),
        iweb_kernel::sampling::MemoryValue::Unavailable => None,
    };
    let limit = match max {
        iweb_kernel::sampling::MemoryValue::Bytes(v) if v > 0 => Some(v),
        _ => None,
    };
    let percent = match (usage, limit) {
        (Some(u), Some(l)) => Some(((u as f64 / l as f64) * 10_000.0).round() / 100.0),
        _ => None,
    };
    json!({
        "usageBytes": usage,
        "limitBytes": limit,
        "usagePercent": percent,
        "kernelHeapUsedBytes": kernel_self_rss_anon(),
    })
}

/// JS 用 V8 heapUsed；Rust 内核的对应真实测量是自身进程 RssAnon（/proc/self/status，
/// 原始单位 KiB，×1024 转字节）。无 /proc 的开发宿主返回 None——缺测绝不以 0 冒充
/// （zero-law；浏览器契约字段为 nullable）。
fn kernel_self_rss_anon() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("RssAnon:"))
                .and_then(|line| line.split_whitespace().nth(1).and_then(|kib| kib.parse::<u64>().ok()))
        })
        .map(|kib| kib * 1024)
}

/// 控制 API Router：回环监听器与 api.<base> 入口直达共用（同一鉴权、同一行为）。
fn control_router(state: AppState) -> Router {
    let audit_state = state.clone();
    Router::new()
        .route("/health", get(health))
        .route("/v1/status", get(status))
        .route("/v1/key", get(owner_key))
        .route("/v1/routes", get(routes_list).post(routes_create))
        .route("/v1/routes/{hostId}", axum::routing::delete(routes_delete))
        .route("/v1/workspace", get(workspace_list))
        .route("/v1/workspace/file", get(workspace_read).put(workspace_write).delete(workspace_delete))
        .route("/v1/monitor/session", post(monitor_session))
        .route("/v1/keys", get(keys_list).post(keys_create))
        .route("/v1/keys/{keyId}", axum::routing::delete(keys_ban))
        .route("/v1/audit", get(audit_list))
        .route("/v1/monitor", get(monitor_socket))
        // 对位 JS：publication 关闭期间，/v1/applications 下任意方法/子路径一律 503 gate。
        .route("/v1/applications", axum::routing::any(applications_gate))
        .route("/v1/applications/{*rest}", axum::routing::any(applications_gate))
        .route("/v1/recover/sandboxes", post(recover_bounded))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(state, cors_middleware))
        .layer(axum::middleware::from_fn_with_state(audit_state, audit_middleware))
}

async fn control_via_ingress(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response<Body> {
    // §4.1 完整接线：api.<base> 的控制调用与回环控制面同一 Router 同一鉴权。
    use tower::ServiceExt;
    let router = control_router(state);
    match router.oneshot(request).await {
        Ok(response) => response,
        Err(_) => response_json(StatusCode::BAD_REQUEST, json!({ "error": "control request rejected" })),
    }
}

// ---- /v1/routes CRUD（对位 kernel/index.js validateRoute + POST/DELETE 语义）----

const RESERVED_HOST_PREFIXES: [&str; 4] = ["api", "admin", "mcp", "notes"];

fn validate_user_route(input: &serde_json::Value) -> Result<iweb_kernel::routes::RouteRecord, String> {
    let Some(object) = input.as_object() else {
        return Err("route body must be an object".into());
    };
    let host_id = object.get("hostId").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
    let app_name = object.get("appName").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
    if !valid_host_id(&host_id) {
        return Err("hostId is not a valid relative hostname".into());
    }
    if !valid_host_id(&app_name) || app_name.contains('.') {
        return Err("appName is not a valid app identifier".into());
    }
    let first_label = host_id.split('.').next().unwrap_or_default();
    if RESERVED_HOST_PREFIXES.contains(&first_label) {
        return Err(format!("hostId prefix {first_label} is reserved"));
    }
    if !host_id.ends_with(".app") {
        return Err("v1 user routes must use the .app namespace".into());
    }
    let enabled = object.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    Ok(iweb_kernel::routes::RouteRecord {
        host_id,
        target: iweb_kernel::routes::RouteTarget { kind: "celld-app".into(), app_name: Some(app_name), sandbox_id: None },
        system: false,
        enabled,
    })
}

fn valid_host_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        let b = label.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && (b[b.len() - 1].is_ascii_lowercase() || b[b.len() - 1].is_ascii_digit())
            && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    })
}

fn load_routes_store(state: &AppState) -> Option<iweb_kernel::routes::RouteStore> {
    let path = state.routes_path.clone()?;
    std::panic::catch_unwind(|| iweb_kernel::routes::RouteStore::load(std::path::Path::new(&path))).ok()
}

async fn routes_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    match load_routes_store(&state) {
        Some(store) => {
            let file = iweb_kernel::routes::RouteStoreFile { version: 1, routes: store.snapshot() };
            Ok(Json(serde_json::to_value(file).expect("routes serialize")))
        }
        None => Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "route registry unavailable" })))),
    }
}

async fn routes_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({ "error": "request body must be JSON" }))))?;
    let route = validate_user_route(&parsed).map_err(|message| (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))))?;
    let store = load_routes_store(&state).ok_or((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "route registry unavailable" }))))?;
    if store.snapshot().iter().any(|candidate| candidate.host_id == route.host_id && candidate.system) {
        return Err((StatusCode::CONFLICT, Json(json!({ "error": "system route cannot be overwritten" }))));
    }
    store.record(route.clone());
    store.persist();
    Ok((StatusCode::CREATED, Json(serde_json::to_value(route).expect("route serialize"))))
}

async fn routes_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(host_id): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let host_id = urldecode(&host_id);
    let store = load_routes_store(&state).ok_or((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "route registry unavailable" }))))?;
    let existing = store.snapshot().into_iter().find(|candidate| candidate.host_id == host_id);
    match existing {
        None => Err((StatusCode::NOT_FOUND, Json(json!({ "error": "route not found" })))),
        Some(route) if route.system => Err((StatusCode::CONFLICT, Json(json!({ "error": "system route cannot be deleted" })))),
        Some(_) => {
            store.delete(&host_id);
            store.persist();
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

fn urldecode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                output.push(byte as char);
                continue;
            }
        }
        output.push(c);
    }
    output
}

// ---- /v1/workspace（对位 JS workspaceSnapshot / readWorkspaceFile）----

fn workspace(_state: &AppState) -> Option<iweb_kernel::workspace::Workspace> {
    let object = std::env::var("IWEB_WORKSPACE_OBJECT").ok()?;
    Some(iweb_kernel::workspace::Workspace { object })
}

async fn workspace_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let Some(ws) = workspace(&state) else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "workspace is unavailable" }))));
    };
    let prefix = query
        .as_deref()
        .and_then(|q| q.split('&').find(|p| p.starts_with("prefix=")))
        .and_then(|p| p.strip_prefix("prefix="))
        .map(urldecode)
        .unwrap_or_default();
    let prefix_for_listing = prefix.clone();
    let files = tokio::task::spawn_blocking(move || ws.list(&prefix_for_listing)).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("workspace listing join failed: {e}") })))
    })?.map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": e.0 })))
    })?;
    let listing: Vec<serde_json::Value> = files
        .iter()
        .map(|(path, size, last_modified)| json!({ "path": path, "size": size, "lastModified": last_modified }))
        .collect();
    // typescript-monorepo：apps 投影纯路由派生（唯一权威）；普通文件列表保留。
    let routes = load_routes_store(&state)
        .map(|store| store.snapshot())
        .unwrap_or_default();
    let apps: Vec<serde_json::Value> = route_app_ids(&routes)
        .iter()
        .map(|app| workspace_app_projection(app, &routes))
        .collect();
    Ok(Json(json!({ "root": "/", "files": listing, "apps": apps })))
}

async fn workspace_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let raw = query
        .as_deref()
        .and_then(|q| q.split('&').find(|p| p.starts_with("path=")))
        .and_then(|p| p.strip_prefix("path="))
        .map(urldecode)
        .ok_or((StatusCode::BAD_REQUEST, Json(json!({ "error": "path is required" }))))?;
    let path = iweb_kernel::workspace::normalize_workspace_path(&raw)
        .map_err(|message| (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))))?;
    let Some(ws) = workspace(&state) else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "workspace is unavailable" }))));
    };
    let content = { let path = path.clone(); tokio::task::spawn_blocking(move || ws.read(&path)).await }
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("workspace read join failed: {e}") }))))?
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.0 }))))?;
    Ok(Json(json!({ "path": path, "content": content })))
}

// ---- /v1/monitor（§4.2：票据 + WS 快照推送，对位 JS upgrade 手写握手语义）----

async fn monitor_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let Some(actor) = state.authorize(&headers) else {
        return Err(unauthorized());
    };
    let (ticket, expires_at) = state.monitor_tickets.create();
    state.ticket_actors.lock().expect("ticket actors lock").insert(ticket.clone(), actor.clone());
    // monitor 生命周期审计（spec）：票据签发按主体归因（不记票据值）。
    state.keys.record_request(Some(&actor), "POST", "/v1/monitor/ticket", 201);
    Ok((StatusCode::CREATED, Json(json!({ "ticket": ticket, "expiresAt": expires_at }))))
}

async fn monitor_socket(
    State(state): State<AppState>,
    upgrade: axum::extract::ws::WebSocketUpgrade,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response<Body> {
    // 对位：票据一次性消费失败即拒绝（不回 401，直接断——浏览器 WS 无法读状态码）。
    let ticket = query
        .as_deref()
        .and_then(|q| q.split('&').find(|p| p.starts_with("ticket=")))
        .and_then(|p| p.strip_prefix("ticket="))
        .map(urldecode)
        .unwrap_or_default();
    let actor = state.ticket_actors.lock().expect("ticket actors lock").remove(&ticket);
    if !state.monitor_tickets.consume(&ticket) {
        return response_json(StatusCode::UNAUTHORIZED, json!({ "error": "monitor ticket is invalid or expired" }));
    }
    // 归属校验：ban 后票据立即失效（spec：revocation applies to unconsumed tickets）。
    let monitor_actor_valid = match &actor {
        Some(iweb_kernel::keys::Actor::Bootstrap) => true,
        Some(iweb_kernel::keys::Actor::Delegated(id)) => state.keys.is_active(id),
        None => false,
    };
    if !monitor_actor_valid {
        return response_json(StatusCode::UNAUTHORIZED, json!({ "error": "monitor ticket is invalid or expired" }));
    }
    let _monitor_actor = actor;
    let _monitor_ws_actor = _monitor_actor.clone();
    upgrade.on_upgrade(move |socket| async move {
        use axum::extract::ws::Message;
        use futures_util::{SinkExt, StreamExt};
        let state = state.clone();
        let (mut sender, mut receiver) = socket.split();
        let monitor_key = match &_monitor_actor {
            Some(iweb_kernel::keys::Actor::Delegated(id)) => Some(id.clone()),
            _ => None,
        };
        // 先订阅变更再发首帧：订阅窗口内的 ban 不会漏（P1 竞态修复）。
        let mut metrics_changed = state.metrics.subscribe();
        let mut revision_changed = state.keys.subscribe_revision();
        // 首帧前双保险：is_active 即时检查 + biased select 探测已发生的 revision
        // 变更（订阅与首帧发送之间的 ban 窗口）。
        if let Some(id) = &monitor_key {
            if !state.keys.is_active(id) {
                let _ = sender.send(Message::Close(Some(axum::extract::ws::CloseFrame { code: 1008, reason: "owner key revoked".into() }))).await;
                state.keys.record_request(_monitor_ws_actor.as_ref(), "GET", "/v1/monitor", 1008);
                return;
            }
        }
        // 首帧前的最后窗口：biased select 优先处理已发生的 revision 变更
        // （check 与 send 之间仍非原子——这是记录在案的微窗口，revision 订阅
        // 在 select 中就绪即关闭，剩余亚毫秒窗口由 5s 重验兜底关闭）。
        tokio::select! {
            biased;
            _ = revision_changed.changed() => {
                if let Some(id) = &monitor_key {
                    if !state.keys.is_active(id) {
                        let _ = sender.send(Message::Close(Some(axum::extract::ws::CloseFrame { code: 1008, reason: "owner key revoked".into() }))).await;
                        state.keys.record_request(_monitor_ws_actor.as_ref(), "GET", "/v1/monitor", 1008);
                        return;
                    }
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(0)) => {}
        }
        // 首帧 = 完整 monitor snapshot；此后每次指标落账广播新帧（对位 JS
        // broadcastMonitorSnapshot；admin 用 monitorSnapshotSchema 逐字段解析）。
        let _ = sender.send(Message::Text(monitor_snapshot(&state).to_string().into())).await;
        // ban 主动关闭：key 失效（ban/过期）后按策略关闭帧断开（spec：revocation
        // closes delegated monitor streams）。5s 兜底重验覆盖非 metrics 驱动的过期。
        let mut revalidate = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                changed = metrics_changed.changed() => {
                    if changed.is_ok() {
                        // 广播发送前重验：ban 后不再发送任何帧。
                        if let Some(id) = &monitor_key {
                            if !state.keys.is_active(id) {
                                let _ = sender.send(Message::Close(Some(axum::extract::ws::CloseFrame { code: 1008, reason: "owner key revoked".into() }))).await;
                                break;
                            }
                        }
                        let _ = sender.send(Message::Text(monitor_snapshot(&state).to_string().into())).await;
                    } else {
                        break;
                    }
                }
                message = receiver.next() => {
                    match message {
                        Some(Ok(Message::Ping(_))) => { let _ = sender.send(Message::Pong(vec![].into())).await; }
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => {}
                    }
                }
                _ = revision_changed.changed() => {
                    if let Some(id) = &monitor_key {
                        if !state.keys.is_active(id) {
                            let _ = sender.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: 1008,
                                reason: "owner key revoked".into(),
                            }))).await;
                            break;
                        }
                    }
                }
                _ = revalidate.tick() => {
                    if let Some(id) = &monitor_key {
                        if !state.keys.is_active(id) {
                            let _ = sender.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: 1008,
                                reason: "owner key revoked".into(),
                            }))).await;
                            break;
                        }
                    }
                }
            }
        }
        let _ = sender.close().await;
        // 连接关闭审计（统一语义：建立由 middleware 记 GET /v1/monitor 101，
        // 关闭在此记 action=monitor.close，主体归因连接的 keyId）。
        if let Some(actor_ref) = _monitor_ws_actor.as_ref() {
            state.keys.record_request(Some(actor_ref), "GET", "/v1/monitor", 1005);
        }
    })
}

/// app 集合纯路由派生（typescript-monorepo spec：路由注册表是应用身份唯一权威）。
fn route_app_ids(routes: &[iweb_kernel::routes::RouteRecord]) -> Vec<String> {
    // 对位 JS：只接受 kind=celld-app 且 app_name 符合 ID 格式（负向路由不产生投影）。
    let mut ids: Vec<String> = routes
        .iter()
        .filter(|route| route.target.kind == "celld-app")
        .filter_map(|route| route.target.app_name.clone())
        .filter(|name| iweb_kernel::routes::valid_app_id(name))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// workspace 视图的 app 投影（workspaceAppSchema 六字段）。
fn workspace_app_projection(app: &str, routes: &[iweb_kernel::routes::RouteRecord]) -> serde_json::Value {
    let app_routes: Vec<_> = routes
        .iter()
        .filter(|route| route.target.kind == "celld-app" && route.target.app_name.as_deref() == Some(app))
        .collect();
    let mut domains: Vec<&str> = app_routes.iter().map(|route| route.host_id.as_str()).collect();
    domains.sort();
    json!({
        "id": app,
        "deployed": app_routes.iter().any(|route| route.enabled),
        "system": app_routes.iter().any(|route| route.system),
        "domains": domains,
    })
}

/// 完整 monitor 快照：首帧与广播帧共用同一构造器，保证同形（对位 JS monitorSnapshot）。
fn monitor_snapshot(state: &AppState) -> serde_json::Value {
    let routes = load_routes_store(state)
        .map(|store| store.snapshot())
        .unwrap_or_default();
    // workspace 用量为 advisory（对位 JS：mc 失败 → 0/0，不阻断帧）。
    let workspace_files = workspace(state)
        .and_then(|ws| ws.list("").ok())
        .unwrap_or_default();
    let (workspace_file_count, workspace_bytes) = workspace_files
        .iter()
        .fold((0usize, 0u64), |(count, total), (_, size, _)| (count + 1, total + size));
    let apps: Vec<serde_json::Value> = route_app_ids(&routes)
        .iter()
        .map(|app| {
            let app_routes: Vec<_> = routes
                .iter()
                .filter(|route| route.target.kind == "celld-app" && route.target.app_name.as_deref() == Some(app.as_str()))
                .collect();
            let mut domains: Vec<&str> = app_routes.iter().map(|route| route.host_id.as_str()).collect();
            domains.sort();
            let metric = state.metrics.snapshot(app);
            let resources = state
                .celld_samples
                .current(app)
                .map(|sample| {
                    json!({
                        "versionId": "celld-process",
                        "sampledAt": sample.sampled_at,
                        "cpuMillis": { "available": false },
                        "memoryBytes": { "available": true, "value": sample.bytes },
                        "pidCount": { "available": false },
                        "terminated": { "available": false },
                        "limits": null,
                    })
                })
                .unwrap_or(serde_json::Value::Null);
            // monitorAppSchema 字段集（typescript-monorepo：无 sourcePath/manifestPath）。
            json!({
                "id": app,
                "domains": domains,
                "deployed": app_routes.iter().any(|route| route.enabled),
                "system": app_routes.iter().any(|route| route.system),
                "requests": metric.requests,
                "errors": metric.errors,
                "inFlight": metric.in_flight,
                "averageLatencyMs": metric.average_latency_ms,
                "lastRequestAt": metric.last_request_at,
                "resources": resources,
            })
        })
        .collect();
    let sandboxes: Vec<serde_json::Value> =
        iweb_kernel::control::read_state(std::path::Path::new(&state.control_db_path))
            .map(|file| file.applications.values().map(iweb_kernel::control::project_application).collect())
            .unwrap_or_default();
    json!({
        "type": "snapshot",
        "emittedAt": iweb_kernel::monitor::iso_now(),
        "node": {
            "uptimeSeconds": state.started_at.elapsed().as_secs(),
            "routeCount": routes.len(),
            "workspaceFileCount": workspace_file_count,
            "workspaceBytes": workspace_bytes,
            "memory": memory_flat(),
        },
        "apps": apps,
        "sandboxes": sandboxes,
    })
}


async fn workspace_write(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({ "error": "request body must be JSON" }))))?;
    let Some(object) = parsed.as_object() else {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": "workspace file body must be an object" }))));
    };
    let raw = object.get("path").and_then(|v| v.as_str()).unwrap_or_default();
    let path = iweb_kernel::workspace::normalize_workspace_path(raw)
        .map_err(|message| (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))))?;
    let content = object.get("content").and_then(|v| v.as_str()).ok_or((
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "workspace file content must be text" })),
    ))?.to_string();
    let Some(ws) = workspace(&state) else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "workspace is unavailable" }))));
    };
    let response_path = path.clone();
    let bytes = tokio::task::spawn_blocking(move || ws.write(&response_path, content.as_str())).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("workspace write join failed: {e}") }))))?.map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.0 }))))?;
    Ok((StatusCode::CREATED, Json(json!({ "path": path, "bytes": bytes }))))
}

async fn workspace_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    if state.authorize(&headers).is_none() {
        return Err(unauthorized());
    }
    let raw = query
        .as_deref()
        .and_then(|q| q.split('&').find(|p| p.starts_with("path=")))
        .and_then(|p| p.strip_prefix("path="))
        .map(urldecode)
        .ok_or((StatusCode::BAD_REQUEST, Json(json!({ "error": "path is required" }))))?;
    let path = iweb_kernel::workspace::normalize_workspace_path(&raw)
        .map_err(|message| (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))))?;
    let Some(ws) = workspace(&state) else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "workspace is unavailable" }))));
    };
    tokio::task::spawn_blocking(move || ws.delete(&path)).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("workspace delete join failed: {e}") }))))?.map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e.0 }))))?;
    Ok(StatusCode::NO_CONTENT)
}
