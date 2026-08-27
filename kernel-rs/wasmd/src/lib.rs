//! iweb-wasmd：内嵌 Wasmtime 的 wasm 应用执行进程（add-wasm-runtime 任务 3.1-3.4
//! 的 wasmd 本体库）。bin 入口见 main.rs；库形态供集成测试复用同一执行路径。
//!
//! 模块图：
//! - jcs：canonical JSON + digest + 文法（对齐 contracts/kernel 编码语义）；
//! - wire：身份/绑定/health v2/快照载荷（Rust 手写同形状 JSON）；
//! - capability：NodeCapabilityRecordV1 只读验证 + recordHash + reserve 推导；
//! - argv：固定启动契约（supervisor 独占生成；未知参数 fail-closed）；
//! - fd：snapshot FD 3/4 三方契约的 wasmd 侧验证；
//! - snapshot_store：iweb:config/secrets 宿主 store（FD 快照支撑的 host get）；
//! - limits：宿主 HTTP 上限（流式字节/头部计数；CVE-2026-27887 回归机制）；
//! - gateway：宿主中介出网（唯一拨号目的地 = 固定网关；TLS 在网关隧道上终结）；
//! - host：Wasmtime 嵌入（store limits/epoch/fuel/每请求实例与并发）；
//! - ingress：唯一 listener + health v2 端点 + SIGTERM drain。

pub mod argv;
pub mod capability;
pub mod fd;
pub mod gateway;
pub mod host;
pub mod host_services;
pub mod ingress;
pub mod jcs;
pub mod limits;
pub mod snapshot_store;
pub mod wire;
