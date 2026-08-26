//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.2）：宿主中介出网——
//! wasi:http/outgoing-handler 是组件唯一出网接口；宿主实现只拨固定网关地址，
//! 不解析应用目的地 DNS、不直连任何目的地；HTTP 以绝对形式经网关转发，HTTPS 经
//! 网关 CONNECT 隧道后在宿主终结 TLS（rustls，证书校验不放宽，SNI = 目的地 host）。
//! 组件拿不到 wasi:sockets/wasi:tls（linker 不注册，实例化即 fail-closed）。
//! 规范权威：spec "Wasmd has a fixed command and host-mediated network contract"；
//! 调研背景 docs/research/wasm-runtime-selection.md §5（出网三层：能力缺失 +
//! 宿主必经 + 拓扑兜底；本模块是“宿主必经”层）。
//!
//! 纪律：本进程唯一的 TcpStream::connect 目的地是 argv 网关地址；日志不落请求体、
//! 凭证、配置或秘密值。

use crate::capability::NodeHttpLimitsV1;
use crate::limits::{check_header_limits, LimitedBody};
use http_body_util::BodyExt;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::{Error, RequestOptions, WasiBody, WasiHttpHooks};

/// 通往网关的传输流：明文 TCP 或网关 CONNECT 隧道上的 TLS。
enum GatewayStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for GatewayStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            GatewayStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            GatewayStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for GatewayStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        match self.get_mut() {
            GatewayStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            GatewayStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            GatewayStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            GatewayStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            GatewayStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            GatewayStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// 出网钩子的共享配置（地址/上限/TLS 根集合）。
pub struct GatewayEgress {
    /// 唯一允许拨出的固定网关地址。
    pub gateway: std::net::SocketAddr,
    /// 上游响应头部/字节上限（capability record）。
    pub http_limits: NodeHttpLimitsV1,
    /// TLS 客户端配置（生产根集合 = webpki-roots；测试可注入自建 CA）。
    pub tls: Arc<tokio_rustls::TlsConnector>,
}

impl GatewayEgress {
    /// 生产 TLS 配置：webpki-roots 唯一根集合；不放宽校验、不降低协议版本下限。
    pub fn production_tls() -> Arc<tokio_rustls::TlsConnector> {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(tokio_rustls::TlsConnector::from(Arc::new(config)))
    }

    /// 出网请求（send_request 钩子核心）：只拨网关，按 scheme 走明文代理或 CONNECT+TLS。
    pub async fn send(
        &self,
        request: http::Request<WasiBody>,
    ) -> Result<(http::Response<WasiBody>, Box<dyn std::future::Future<Output = Result<(), Error>> + Send>), Error> {
        let (parts, body) = request.into_parts();
        let uri = parts.uri.clone();
        let scheme = uri.scheme_str().ok_or_else(|| Error::HttpRequestUriInvalid)?.to_string();
        let authority = uri.authority().ok_or_else(|| Error::HttpRequestUriInvalid)?.as_str().to_string();
        if authority.is_empty() {
            return Err(Error::HttpRequestUriInvalid);
        }
        // SNI host（不做任何 DNS——本进程唯一的拨号目的地是网关地址）。
        let host = authority
            .rsplit_once(':')
            .map(|(host, _)| host.to_string())
            .unwrap_or_else(|| authority.clone());

        // 唯一 connect：固定网关地址。
        let tcp = TcpStream::connect(self.gateway)
            .await
            .map_err(Error::Connect)?;

        let stream = match scheme.as_str() {
            "https" => {
                let tunnel = self.connect_tunnel(tcp, &authority).await?;
                let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|_| Error::HttpRequestUriInvalid)?;
                let tls = self.tls.connect(server_name, tunnel).await.map_err(Error::Tls)?;
                GatewayStream::Tls(Box::new(tls))
            }
            "http" => GatewayStream::Plain(tcp),
            _ => return Err(Error::HttpRequestUriInvalid),
        };

        // 明文 HTTP 经正向代理必须用绝对形式 URI；TLS 隧道内用 origin 形式 + Host 头。
        let path_and_query = uri.path_and_query().map(|value| value.as_str().to_string()).unwrap_or_else(|| "/".to_string());
        let request_target = if scheme == "https" {
            http::Uri::builder()
                .path_and_query(path_and_query)
                .build()
                .map_err(|_| Error::HttpRequestUriInvalid)?
        } else {
            http::Uri::builder()
                .scheme("http")
                .authority(authority.clone())
                .path_and_query(path_and_query)
                .build()
                .map_err(|_| Error::HttpRequestUriInvalid)?
        };
        let mut request = http::Request::from_parts(parts, body);
        if scheme == "https" && !request.headers().contains_key(http::header::HOST) {
            // HeaderMap 直插 Host（origin-form 下 hyper 不再从 URI 推导）。
            request.headers_mut().insert(
                http::header::HOST,
                http::HeaderValue::from_str(&host).map_err(|_| Error::HttpRequestUriInvalid)?,
            );
        }
        *request.uri_mut() = request_target;

        let (mut response_sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(Error::Hyper)?;
        let connection: tokio::task::JoinHandle<Result<(), Error>> = tokio::spawn(async move {
            connection.await.map_err(Error::Hyper)?;
            Ok(())
        });

        let response = response_sender.send_request(request).await.map_err(Error::Hyper)?;
        // 出站（上游）响应头部上限（计数与字节；来自 capability record）。
        check_header_limits(response.headers(), self.http_limits.max_response_header_count, self.http_limits.max_response_header_bytes)?;
        // 无界响应在流式包装上截断：超限只失败本请求（CVE-2026-27887）。
        let limited = response.map(|body| LimitedBody::new(body, self.http_limits.max_response_bytes).boxed_unsync());
        let io: Box<dyn std::future::Future<Output = Result<(), Error>> + Send> = Box::new(async move {
            match connection.await {
                Ok(result) => result,
                Err(error) => Err(Error::InternalError(Some(format!("connection task failed: {error}")))),
            }
        });
        Ok((limited, io))
    }

    /// CONNECT 隧道握手：手写最小 CONNECT（单一请求/响应；2xx 即隧道建立）。
    async fn connect_tunnel(&self, mut tcp: TcpStream, authority: &str) -> Result<TcpStream, Error> {
        tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
            .await
            .map_err(Error::Connect)?;
        // 逐块读到头部终结符；只解析状态行，响应体不被代理发送。
        let mut buffer = Vec::with_capacity(512);
        let mut chunk = [0u8; 256];
        loop {
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            let read = tcp.read(&mut chunk).await.map_err(Error::Connect)?;
            if read == 0 {
                return Err(Error::Connect(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "gateway closed during CONNECT")));
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > 8_192 {
                return Err(Error::Connect(std::io::Error::new(std::io::ErrorKind::InvalidData, "gateway CONNECT response header too large")));
            }
        }
        let header = String::from_utf8_lossy(&buffer);
        let status_line = header.lines().next().unwrap_or_default();
        // 形如 "HTTP/1.1 200 Connection established"；仅取状态码。
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| Error::Connect(std::io::Error::new(std::io::ErrorKind::InvalidData, "gateway CONNECT returned a malformed status line")))?;
        if !(200..300).contains(&code) {
            return Err(Error::HttpRequestDenied);
        }
        Ok(tcp)
    }
}

/// WasiHttpHooks 实现：send_request 全量经网关（wasmtime-wasi-http 关闭
/// default-send-request 特性后，本实现缺失即编译错误——结构性 fail-closed）。
pub struct GatewayHooks {
    pub egress: Arc<GatewayEgress>,
}

impl WasiHttpHooks for GatewayHooks {
    fn send_request(
        &mut self,
        request: http::Request<WasiBody>,
        _options: Option<RequestOptions>,
        _fut: Box<dyn std::future::Future<Output = Result<(), Error>> + Send>,
    ) -> Box<dyn std::future::Future<Output = Result<(http::Response<WasiBody>, Box<dyn std::future::Future<Output = Result<(), Error>> + Send>), Error>> + Send> {
        let egress = Arc::clone(&self.egress);
        Box::new(async move { egress.send(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use http_body_util::Full;

    /// 读取一整段 HTTP/1.1 请求文本（到空行为止；返回头部长度便于测试断言）。
    async fn read_request_head<S: tokio::io::AsyncRead + Unpin>(socket: &mut S) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            let read = socket.read(&mut chunk).await.expect("read");
            assert!(read > 0, "peer closed");
            buffer.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }

    async fn write_response(socket: &mut TcpStream, head: &str, body: &[u8]) {
        socket
            .write_all(format!("{head}Content-Length: {}\r\n\r\n", body.len()).as_bytes())
            .await
            .expect("write head");
        socket.write_all(body).await.expect("write body");
    }

    fn egress_for(gateway: std::net::SocketAddr, max_response_bytes: u64) -> Arc<GatewayEgress> {
        Arc::new(GatewayEgress {
            gateway,
            http_limits: NodeHttpLimitsV1 {
                max_request_bytes: 1_048_576,
                max_response_bytes,
                max_request_header_bytes: 8_192,
                max_response_header_bytes: 8_192,
                max_request_header_count: 64,
                max_response_header_count: 64,
                max_concurrent_requests: 16,
            },
            tls: GatewayEgress::production_tls(),
        })
    }

    fn request_to(uri: &str) -> http::Request<WasiBody> {
        http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()).map_err(|error| match error {}).boxed_unsync())
            .expect("request")
    }

    #[tokio::test]
    async fn plain_http_goes_through_gateway_in_absolute_form() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway = listener.local_addr().expect("addr");
        let egress = egress_for(gateway, 1 << 20);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let head = read_request_head(&mut socket).await;
            // 绝对形式：正向代理语义。
            assert!(head.starts_with("GET http://origin.example:8080/path?q=1 HTTP/1.1"), "head: {head}");
            write_response(&mut socket, "HTTP/1.1 200 OK\r\n", b"hello").await;
        });
        let (response, io) = egress.send(request_to("http://origin.example:8080/path?q=1")).await.expect("send");
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&body[..], b"hello");
        Box::into_pin(io).await.expect("io");
        task.await.expect("task");
    }

    #[tokio::test]
    async fn unbounded_response_fails_only_that_request() {
        // CVE-2026-27887 回归：上限 8 字节；第一个响应 16 字节失败，第二个 4 字节成功。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway = listener.local_addr().expect("addr");
        let egress = egress_for(gateway, 8);
        let server = tokio::spawn(async move {
            for size in [16u8, 4u8] {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let _head = read_request_head(&mut socket).await;
                write_response(&mut socket, "HTTP/1.1 200 OK\r\n", &vec![b'x'; size as usize]).await;
            }
        });
        let (first, io_first) = egress.send(request_to("http://a.example/")).await.expect("send 1");
        let result = first.into_body().collect().await;
        assert!(result.is_err(), "over-cap response must fail");
        let _ = Box::into_pin(io_first).await;
        let (second, io_second) = egress.send(request_to("http://a.example/")).await.expect("send 2");
        let body = second.into_body().collect().await.expect("within cap").to_bytes();
        assert_eq!(body.len(), 4);
        let _ = Box::into_pin(io_second).await;
        server.await.expect("server");
    }

    #[tokio::test]
    async fn https_connect_tunnel_terminates_tls_in_wasmd() {
        // 自签 CA + 服务器证书（仅注入测试根集合；生产根仍为 webpki-roots，不放宽校验）。
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params = rcgen::CertificateParams::new(vec!["ca.iweb.test".to_string()]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca issuer");
        let server_key = rcgen::KeyPair::generate().expect("server key");
        let server_params = rcgen::CertificateParams::new(vec!["origin.example".to_string()]).expect("server params");
        let server_cert = server_params.signed_by(&server_key, &ca).expect("server cert");

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).expect("test root");
        let mut test_tls = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // ALPN 只留 http/1.1（隧道内明文 HTTP）。
        test_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = Arc::new(tokio_rustls::TlsConnector::from(Arc::new(test_tls)));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway = listener.local_addr().expect("addr");
        let mut limits = egress_for(gateway, 1 << 20).http_limits.clone();
        limits.max_concurrent_requests = 16;
        let egress = Arc::new(GatewayEgress { gateway, http_limits: limits, tls });

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut socket = socket;
            let head = read_request_head(&mut socket).await;
            assert!(head.starts_with("CONNECT origin.example:443 HTTP/1.1"), "head: {head}");
            socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.expect("connect ok");
            // 隧道上终结 TLS（服务端），再收明文 HTTP。
            let server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(server_cert.der().to_vec())],
                    tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
                )
                .expect("server tls");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            let mut tls_stream = acceptor.accept(socket).await.expect("tls accept");
            let plain = read_request_head(&mut tls_stream).await;
            assert!(plain.starts_with("GET /path HTTP/1.1"), "plain: {plain}");
            assert!(plain.to_lowercase().contains("host: origin.example"));
            tls_stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .expect("write");
        });

        let (response, io) = egress.send(request_to("https://origin.example:443/path")).await.expect("send");
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&body[..], b"hello");
        // io 完成通道在服务端未发 close_notify 时会报 TLS EOF——与本测试断言无关。
        let _ = Box::into_pin(io).await;
        server.await.expect("server");
    }

    #[tokio::test]
    async fn bad_certificate_fails_closed_in_tunnel() {
        // 无测试根注入（生产 webpki-roots）：自签证书必须校验失败。
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        let server_key = rcgen::KeyPair::generate().expect("key");
        let server_params = rcgen::CertificateParams::new(vec!["origin.example".to_string()]).expect("params");
        let server_cert = server_params.self_signed(&server_key).expect("cert");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway = listener.local_addr().expect("addr");
        let egress = egress_for(gateway, 1 << 20);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut socket = socket;
            let _head = read_request_head(&mut socket).await;
            socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.expect("connect ok");
            let server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(server_cert.der().to_vec())],
                    tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
                )
                .expect("server tls");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            let mut tls_stream = match acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(_) => return,
            };
            // 客户端校验失败会断开；这里只是尽量读，忽略结果。
            let mut chunk = [0u8; 64];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tls_stream.read(&mut chunk)).await;
        });
        let result = egress.send(request_to("https://origin.example:443/")).await;
        assert!(result.is_err(), "untrusted certificate must fail closed");
        server.await.expect("server");
    }
}
