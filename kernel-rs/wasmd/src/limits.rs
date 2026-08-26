//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.2）：宿主 HTTP 上限——入站请求
//! 字节/头部、出站（上游）响应字节/头部在流式转发时强制；超限只失败该请求
//! （CVE-2026-27887 回归：无界响应绝不整缓冲进宿主内存，也不拖垮进程/邻居沙箱）。
//! 上限数值唯一来自 pinned capability record（见 capability.rs）；本模块只做机制。
//!
//! 口径备注（spec 表格对位）：
//! - maxRequestBytes / maxRequestHeader*：访客 → 应用的入站请求；
//! - maxResponseBytes / maxResponseHeader*：应用出站请求的上游响应（含应用直接
//!   生成给访客的响应体——两者共用同一上限值，均按“该请求失败”处理）。

use bytes::Bytes;
use http_body::Body;
use std::task::{Context, Poll};
use wasmtime_wasi_http::Error;

/// 带累计字节上限的 body 包装：超限时 poll_body 返回错误（下游只看到该请求失败），
/// 绝不缓冲超限数据。
#[derive(Debug)]
pub struct LimitedBody<B> {
    inner: B,
    remaining: u64,
}

impl<B> LimitedBody<B> {
    pub fn new(inner: B, limit: u64) -> Self {
        Self { inner, remaining: limit }
    }
}

impl<B> Body for LimitedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(map_body_error(error)))),
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let size = data.len() as u64;
                    if size > this.remaining {
                        // CVE-2026-27887：无界流在超限瞬间终止，仅本请求失败。
                        return Poll::Ready(Some(Err(Error::HttpResponseBodySize(None))));
                    }
                    this.remaining -= size;
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }
}

fn map_body_error<E: std::fmt::Debug + Send + Sync + 'static>(error: E) -> Error {
    Error::InternalError(Some(format!("body stream failed: {error:?}")))
}

/// 头部计数/字节上限检查（name + value 字节和；超限返回错误码，不回显值内容）。
pub fn check_header_limits(headers: &http::HeaderMap, max_count: u64, max_bytes: u64) -> Result<(), Error> {
    let count = headers.keys_len() as u64;
    if count > max_count {
        return Err(Error::HttpResponseHeaderSectionSize(None));
    }
    let mut total = 0u64;
    for (name, value) in headers.iter() {
        total += (name.as_str().len() + value.len()) as u64;
        if total > max_bytes {
            return Err(Error::HttpResponseHeaderSectionSize(None));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use http_body_util::Full;

    #[tokio::test]
    async fn oversized_body_fails_only_that_request() {
        // 两个请求复用同一上限：第一个超限失败，第二个照常读完。
        let first = LimitedBody::new(Full::new(Bytes::from(vec![b'x'; 64])), 32);
        let result = first.collect().await;
        assert!(result.is_err(), "over-limit body must fail");

        let second = LimitedBody::new(Full::new(Bytes::from(vec![b'y'; 32])), 32);
        let collected = second.collect().await.expect("within limit");
        assert_eq!(collected.to_bytes().len(), 32);
    }

    #[test]
    fn header_limits_enforce_count_and_bytes() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-a", http::HeaderValue::from_static("v"));
        assert!(check_header_limits(&headers, 1, 8).is_ok());
        assert!(check_header_limits(&headers, 0, 8).is_err(), "count");
        assert!(check_header_limits(&headers, 1, 2).is_err(), "bytes");
    }
}
