//! iweb-kernel 库面：集成测试与后续模块从这里访问。
//! 二进制入口在 src/main.rs（--version 契约）。
//!
//! two-tier-runtime-trust（2026-08-30）：celld 控制状态模块（control/control_journal）
//! 已删除——celld 应用清单的唯一权威是路由注册表（镜像种子），运行时准入仅 wasm。

pub mod auth;
pub mod config;
pub mod credential_scan;
pub mod digest;
pub mod keys;
pub mod metrics;
pub mod monitor;
pub mod notes_migration;
pub mod package_store;
pub mod proxy;
pub mod routes;
pub mod sampling;
pub mod supervisor;
pub mod wasm_activation;
pub mod wasm_admission;
pub mod wasm_commands;
pub mod wasm_host_services;
pub mod wasm_kind_registry;
pub mod wasm_publication;
pub mod wasm_runtime;
pub mod wasm_secrets;
pub mod wasm_snapshot_fd;
pub mod workspace;
