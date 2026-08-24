//! Bearer owner-key 鉴权（对位 safeTokenEquals/isAuthorized）。
//! timing-safe：长度不等时也走恒定时间比较（JS 实现的 length 短路泄漏长度信息，
//! 这里顺手收紧：恒定时间比较 + 长度隐藏在比较内部处理）。

use crate::config::Config;
use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

/// 校验请求是否携带正确 owner bearer。
pub fn is_authorized(headers: &HeaderMap, config: &Config) -> bool {
    let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(config.api_token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn config() -> Config {
        Config { base_host: "x.test".into(), api_token: "secret-token".into(), api_addr: "127.0.0.1:7070".parse().unwrap() }
    }

    #[test]
    fn correct_token_authorizes() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer secret-token"));
        assert!(is_authorized(&headers, &config()));
    }

    #[test]
    fn wrong_token_and_shapes_rejected() {
        let c = config();
        for value in ["Bearer wrong", "bearer secret-token", "secret-token", "Bearer  "] {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", HeaderValue::from_static(value));
            assert!(!is_authorized(&headers, &c), "must reject {value:?}");
        }
        assert!(!is_authorized(&HeaderMap::new(), &c));
    }
}
