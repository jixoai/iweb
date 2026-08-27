//! add-wasm-runtime 7.3/7.4：让未接线（lib.rs 由编排者统一注册）的
//! `src/wasm_snapshot_fd.rs` 在 `cargo test` 立即可跑。`#[path]` 引入把该模块
//! 编译进本测试 crate（`crate::wasm_admission` 引用同样可解析），模块内
//! `#[cfg(test)]` 测试随之执行；lib.rs 接线（`pub mod wasm_snapshot_fd;`）后
//! 本文件保持有效（模块被编译两次，仅测试期成本，无生产影响），编排者可按需
//! 改为 `use iweb_kernel::wasm_snapshot_fd;`。
//!
//! 能力边界见模块头注：AF_UNIX SOCK_SEQPACKET 在 macOS 不可用，完整对拍测试
//! 为 `#[cfg(target_os = "linux")]` 专有；macOS 跑帧/拒绝/摘要/路径/ancillary 往返。

#[path = "../src/wasm_host_services.rs"]
pub mod wasm_host_services;
#[path = "../src/wasm_admission.rs"]
pub mod wasm_admission;
// dead_code allow：模块内 Linux-only 测试与 Kernel 接线点在 macOS 编译时暂无调用方，
// lib.rs 接线（pub mod）后 pub 可见性自然消除告警；测试 crate 需要显式放行。
#[path = "../src/wasm_snapshot_fd.rs"]
#[allow(dead_code)]
mod wasm_snapshot_fd;

#[test]
fn snapshot_fd_module_compiles_standalone_before_lib_wiring() {
    // 接线哨兵：模块常量与本测试 crate 的引入路径一致，防止静默漂移。
    assert_eq!(wasm_snapshot_fd::SNAPSHOT_FD_SOCKET_PATH, "/run/iweb-sandbox/snapshot-fd.sock");
    assert_eq!(hex_of(&wasm_snapshot_fd::SNAPSHOT_FRAME_MAGIC), "4957454246443100");
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
