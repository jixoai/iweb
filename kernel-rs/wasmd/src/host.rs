//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.2/3.4）：Wasmtime 嵌入与每请求
//! 执行——加载 0.2 proxy world 组件、实例执行 incoming-handler；资源强制（store limits：
//! guest 线性内存上限 = memoryBytes − reserve(arch)、实例上限；epoch 墙钟每请求
//! deadline、超时终止“该执行”而不崩进程；fuel 可选默认关）。矩阵中未列接口（sockets/
//! tls/filesystem 等）不进 linker，组件 import 即实例化失败（fail-closed）。
//! 规范权威：spec "Wasmd has a fixed command and host-mediated network contract"；
//! 引擎用法背景 docs/research/wasm-runtime-selection.md §5（epoch 比 fuel 更适合不可信
//! guest；ResourceLimiter/内存/实例数是 cgroup 之下的第二层强制）。
//!
//! 实例模型（对位 wasmtime serve 的 p2 语义）：每请求新 Store + 新实例——epoch/fuel
//! deadline 因此天然按请求隔离；maxConcurrentRequests 由并发信号量强制，
//! maxLiveInstances 由实例存活计数观测（高水位单调，供 metrics v1 单调窗口使用）。

use crate::capability::NodeCapabilityRecordV1;
use crate::fd::SnapshotSlots;
use crate::gateway::{GatewayEgress, GatewayHooks};
use crate::snapshot_store::{ConfigHost, SecretsHost};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, Semaphore};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config as EngineConfig, Engine, Result as WasmtimeResult, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use http_body_util::BodyExt;
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpCtxView, WasiHttpView};

/// 每 Store 的实例数上限（嵌套组件内部闭包的余量；跨请求并发由信号量强制）。
const PER_STORE_INSTANCE_LIMIT: usize = 64;
/// stdout/stderr 丢弃槽的累计字节上界（spec：bounded discard sinks；绝不成为应用日志）。
const DISCARD_SINK_CAP_BYTES: u64 = 1 << 20;

/// 引擎侧计数（metrics v1 的任务 4.1 接线预留；本任务只做内部递增与测试断言）。
#[derive(Debug, Default)]
pub struct EngineCounters {
    pub epoch_timeouts_cumulative: AtomicU64,
    pub instances_live_instant: AtomicU64,
    pub instances_high_water_cumulative: AtomicU64,
    pub fuel_consumed_cumulative: AtomicU64,
}

/// 引擎运行配置（record 数值 + 启动期推导；epoch ticker 1 tick = 1 ms）。
#[derive(Debug, Clone)]
pub struct EngineLimitsConfig {
    pub epoch_deadline_ticks: u64,
    pub fuel_per_request: Option<u64>,
    pub memory_size: usize,
    pub max_response_bytes: u64,
}

/// 请求级错误（对访客只映射 generic 状态；细节不外泄、不落请求体/凭证/秘密）。
#[derive(Debug)]
pub enum RequestError {
    /// guest 陷阱/epoch 超时/资源超限——该请求失败；进程与邻居沙箱不受影响。
    GuestTrap { epoch_timeout: bool },
    GuestNoResponse,
    GuestProtocol(String),
    Internal(String),
}

/// 每 Store 的宿主状态（WasiHttpView/WasiView + iweb store 宿主 + store limits）。
pub struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    http_ctx: WasiHttpCtx,
    limits: StoreLimits,
    hooks: GatewayHooks,
    secrets: SecretsHost,
    config: ConfigHost,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

impl WasiHttpView for HostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView { ctx: &mut self.http_ctx, table: &mut self.table, hooks: &mut self.hooks }
    }
}

/// 有界丢弃槽（stdout/stderr；超界向 guest 报写错误，内容绝不落日志/落盘）。
struct BoundedDiscard {
    written: Arc<AtomicU64>,
}

impl IsTerminal for BoundedDiscard {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for BoundedDiscard {
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        struct BoundedWriter {
            written: Arc<AtomicU64>,
        }
        impl tokio::io::AsyncWrite for BoundedWriter {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                let total = self.written.fetch_add(buf.len() as u64, Ordering::Relaxed) + buf.len() as u64;
                if total > DISCARD_SINK_CAP_BYTES {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::FileTooLarge,
                        "stdout/stderr discard sink cap exceeded",
                    )));
                }
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        Box::new(BoundedWriter { written: Arc::clone(&self.written) })
    }
}

/// 已就绪的 wasmd 执行引擎（启动校验全部通过后构造；listener 之后才绑定）。
pub struct WasmdEngine {
    engine: Engine,
    pre: ProxyPre<HostState>,
    limits: EngineLimitsConfig,
    counters: Arc<EngineCounters>,
    concurrency: Arc<Semaphore>,
    snapshots: SnapshotSlots,
    egress: Arc<GatewayEgress>,
}

impl WasmdEngine {
    /// 启动期构造：引擎/组件/linker/pre-instantiation 全部在此完成；任何失败都是
    /// 启动 fail-closed（调用方 exit 70），listener 不会绑定。
    /// 未列矩阵的 import（sockets/tls/filesystem…）在 instantiate_pre 即被拒。
    pub fn new(
        component_bytes: &[u8],
        record: &NodeCapabilityRecordV1,
        binding: &crate::wire::RuntimeBindingIdentityV1,
        architecture: &str,
        memory_bytes: u64,
        snapshots: SnapshotSlots,
        egress: Arc<GatewayEgress>,
    ) -> WasmtimeResult<Self> {
        let guest_limit = record
            .guest_memory_limit_bytes(binding, architecture, memory_bytes)
            .map_err(|error| wasmtime::Error::msg(format!("capability record rejected: {}", error)))?;
        if guest_limit > usize::MAX as u64 {
            return Err(wasmtime::Error::msg("guest memory limit exceeds host pointer width"));
        }
        let mut config = EngineConfig::default();
        // async_support 在 wasmtime 48 已无效果（默认异步模型）；保留 epoch/fuel 配置。
        config.epoch_interruption(true);
        if record.engine.fuel_per_request.is_some() {
            config.consume_fuel(true);
        }
        let engine = Engine::new(&config)?;
        let component = Component::from_binary(&engine, component_bytes)?;

        let mut linker: Linker<HostState> = Linker::new(&engine);
        // proxy interfaces（clocks/random/io/cli + http）——刻意不含 sockets/filesystem/
        // wasi:tls；未列 import 的组件在 instantiate_pre 即失败（fail-closed）。
        wasmtime_wasi_http::p2::add_to_linker_async(&mut linker)?;
        // iweb 宿主接口（secrets/config store；FD 3/4 快照支撑，仅 host get）。
        crate::snapshot_store::iweb::secrets::store::add_to_linker::<_, wasmtime::component::HasSelf<crate::snapshot_store::SecretsHost>>(
            &mut linker,
            |state: &mut HostState| &mut state.secrets,
        )?;
        crate::snapshot_store::iweb::config::store::add_to_linker::<_, wasmtime::component::HasSelf<crate::snapshot_store::ConfigHost>>(
            &mut linker,
            |state: &mut HostState| &mut state.config,
        )?;
        let pre = ProxyPre::new(linker.instantiate_pre(&component)?)?;

        let counters = Arc::new(EngineCounters::default());
        let concurrency = Arc::new(Semaphore::new(record.http.max_concurrent_requests as usize));
        Ok(Self {
            engine,
            pre,
            limits: EngineLimitsConfig {
                // epoch ticker 1 tick = 1 ms（见 spawn_epoch_ticker）。
                epoch_deadline_ticks: record.engine.max_epoch_deadline_ms.max(1),
                fuel_per_request: record.engine.fuel_per_request,
                memory_size: guest_limit as usize,
                max_response_bytes: record.http.max_response_bytes,
            },
            counters,
            concurrency,
            snapshots,
            egress,
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn counters(&self) -> &Arc<EngineCounters> {
        &self.counters
    }

    fn new_store(&self) -> Store<HostState> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.memory_size)
            .instances(PER_STORE_INSTANCE_LIMIT)
            .build();
        let wasi = WasiCtxBuilder::new()
            .stdin(tokio::io::empty())
            .stdout(BoundedDiscard { written: Arc::new(AtomicU64::new(0)) })
            .stderr(BoundedDiscard { written: Arc::new(AtomicU64::new(0)) })
            .build();
        let secrets = SecretsHost(crate::snapshot_store::HostStore::new(Some(self.snapshots.secret.clone())));
        let config = ConfigHost(crate::snapshot_store::HostStore::new(self.snapshots.config.clone()));
        let mut store = Store::new(
            &self.engine,
            HostState {
                table: ResourceTable::new(),
                wasi,
                http_ctx: WasiHttpCtx::new(),
                limits,
                hooks: GatewayHooks { egress: Arc::clone(&self.egress) },
                secrets,
                config,
            },
        );
        store.limiter(|state| &mut state.limits);
        // 每请求 deadline：当前 epoch 起 epoch_deadline_ticks 内有效（1 tick = 1 ms）。
        store.set_epoch_deadline(self.limits.epoch_deadline_ticks);
        if let Some(fuel) = self.limits.fuel_per_request {
            // set_fuel 失败只能是引擎未启用 fuel 的配置错误（启动期已对齐），此处
            // 忽略 Result 会掩盖配置漂移——改为记录性检查。
            if let Err(error) = store.set_fuel(fuel) {
                // 配置漂移属宿主内部不变式破坏：log 到 stderr（无请求内容）。
                eprintln!("wasmd: fuel configuration mismatch: {error}");
            }
        }
        store
    }

    /// 处理一个访客请求：建 Store/实例 → 调 incoming-handler → 等 guest 设置响应。
    /// 入站上限（头部计数/字节、请求体）在 ingress 层强制；本方法负责引擎侧与
    /// 响应体上限（guest 侧无界响应在此截断，只失败本请求）。
    pub async fn handle_request<B>(
        self: &Arc<Self>,
        request: http::Request<B>,
    ) -> Result<http::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody>, RequestError>
    where
        B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::Error> + Send + Sync + 'static,
    {
        let _permit = Arc::clone(&self.concurrency)
            .acquire_owned()
            .await
            .map_err(|error| RequestError::Internal(format!("concurrency semaphore closed: {error}")))?;
        let _live_guard = InstanceLiveGuard::new(Arc::clone(&self.counters));
        let mut store = self.new_store();
        let (sender, receiver) = oneshot::channel();
        // 沙箱内 ingress 一律明文 HTTP（visitor TLS 在 front proxy 终结）。
        let incoming = store
            .data_mut()
            .http()
            .new_incoming_request(Scheme::Http, request)
            .map_err(|error| RequestError::Internal(format!("incoming request resource: {error}")))?;
        let outparam = store
            .data_mut()
            .http()
            .new_response_outparam(sender)
            .map_err(|error| RequestError::Internal(format!("response outparam resource: {error}")))?;
        let pre = self.pre.clone();
        let counters = Arc::clone(&self.counters);
        let task_counters = Arc::clone(&self.counters);
        let initial_fuel = self.limits.fuel_per_request;
        let task = tokio::task::spawn(async move {
            let proxy = pre.instantiate_async(&mut store).await?;
            let result = proxy.wasi_http_incoming_handler().call_handle(&mut store, incoming, outparam).await;
            // fuel 计量（metrics 预备）：consumed = initial − remaining；禁用时跳过。
            if let (Some(initial), Ok(remaining)) = (initial_fuel, store.get_fuel()) {
                if remaining <= initial {
                    task_counters.fuel_consumed_cumulative.fetch_add(initial - remaining, Ordering::Relaxed);
                }
            }
            result
        });
        match receiver.await {
            Ok(Ok(response)) => {
                // guest 生成的响应体与上游响应共用 maxResponseBytes 口径：流式截断，
                // 超限只失败本请求（CVE-2026-27887）。
                Ok(response.map(|body| crate::limits::LimitedBody::new(body, self.limits.max_response_bytes).boxed_unsync()))
            }
            Ok(Err(error_code)) => Err(RequestError::GuestProtocol(format!("{error_code:?}"))),
            Err(_) => {
                // guest 未调用 response-outparam::set（或 trap）：从任务侧取真实错误。
                match task.await {
                    Ok(Ok(())) => Err(RequestError::GuestNoResponse),
                    Ok(Err(error)) => Err(classify_request_error(&error, &counters)),
                    Err(join_error) => Err(RequestError::Internal(format!("guest task failed: {join_error}"))),
                }
            }
        }
    }
}

fn classify_request_error(error: &wasmtime::Error, counters: &EngineCounters) -> RequestError {
    // epoch 墙钟到期 → trap（Interrupt 语义）；文本兜底覆盖 fuel 耗尽等场景。
    let text = format!("{error}");
    let epoch_timeout = matches!(error.downcast_ref::<wasmtime::Trap>(), Some(wasmtime::Trap::Interrupt))
        || text.contains("epoch deadline")
        || text.contains("all fuel consumed");
    if epoch_timeout {
        counters.epoch_timeouts_cumulative.fetch_add(1, Ordering::Relaxed);
    }
    RequestError::GuestTrap { epoch_timeout }
}

/// 实例存活计数 guard（live ±1；high water 单调不减）。
struct InstanceLiveGuard {
    counters: Arc<EngineCounters>,
}

impl InstanceLiveGuard {
    fn new(counters: Arc<EngineCounters>) -> Self {
        let live = counters.instances_live_instant.fetch_add(1, Ordering::Relaxed) + 1;
        let mut previous = counters.instances_high_water_cumulative.load(Ordering::Relaxed);
        while live > previous {
            match counters.instances_high_water_cumulative.compare_exchange(
                previous,
                live,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => previous = actual,
            }
        }
        Self { counters }
    }
}

impl Drop for InstanceLiveGuard {
    fn drop(&mut self) {
        self.counters.instances_live_instant.fetch_sub(1, Ordering::Relaxed);
    }
}

/// epoch ticker：1 tick = 1 ms（独立线程，进程生命周期常驻；epoch 只增，各 Store 相对
/// deadline 自行判定——超时终止单个执行，绝不拖垮进程；这也是 drain 强杀的引擎侧机制）。
pub fn spawn_epoch_ticker(engine: &Engine) -> std::thread::JoinHandle<()> {
    let engine = engine.clone();
    std::thread::Builder::new()
        .name("wasmd-epoch".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
            engine.increment_epoch();
        })
        .expect("epoch ticker thread")
}
