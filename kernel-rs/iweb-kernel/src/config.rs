//! Kernel 进程配置（对位 kernel/index.js 的 env 契约）。
//! fail-closed：缺必需变量直接退出（与 JS requiredString/requiredHost 语义一致）。

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub base_host: String,
    pub api_token: String,
    pub api_addr: SocketAddr,
}

impl Config {
    /// 从环境构造；缺失必需变量时返回 Err（进程拒绝启动）。
    pub fn from_env() -> Result<Self, String> {
        let base_host = required("IWEB_BASE_HOST")?;
        host_shape(&base_host)?;
        let api_token = required("IWEB_API_TOKEN")?;
        if api_token.is_empty() {
            return Err("IWEB_API_TOKEN must not be empty".into());
        }
        let port: u16 = std::env::var("IWEB_API_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7070);
        Ok(Config {
            base_host,
            api_token,
            api_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        })
    }
}

fn required(name: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("{name} must be set")),
    }
}

/// IWEB_BASE_HOST 只允许 host 形态（无 scheme/port/path，对位 requiredHost）。
fn host_shape(value: &str) -> Result<(), String> {
    let bad = value.is_empty()
        || value.contains("://")
        || value.contains('/')
        || value.contains(':')
        || value.contains('@');
    if bad {
        return Err("IWEB_BASE_HOST must be a bare host (no scheme, port, path, or userinfo)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_passes_shape() {
        assert!(host_shape("iweb.localhost").is_ok());
        assert!(host_shape("https://x.example").is_err());
        assert!(host_shape("a.example:8080").is_err());
        assert!(host_shape("a/b").is_err());
    }
}
