//! iweb-kernel：rust-kernel-rustfs-storage 的控制面二进制入口。
//! 规范契约（kernel-control-plane delta）：自包含静态二进制；--version 报告身份；
//! api.<base> 恢复权威独立于 celld。

mod http;

use iweb_kernel::config;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version") => {
            println!("iweb-kernel {VERSION}");
            ExitCode::SUCCESS
        }
        _ => match config::Config::from_env() {
            Ok(config) => {
                http::serve(config);
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("iweb-kernel: {message}");
                ExitCode::from(78)
            }
        },
    }
}
