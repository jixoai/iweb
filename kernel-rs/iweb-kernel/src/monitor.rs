//! Monitor WebSocket（对位 kernel/index.js：票据签发/一次性消费 + 手工握手 + 帧推送）。
//! 票据：24 随机字节 base64url，30s 过期，单次消费。
//! 帧：服务端不掩码，JSON 快照；客户端 ping（0x9）回 pong（0x8A）。

use sha1_smol::Sha1;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct Tickets {
    inner: Mutex<HashMap<String, u128>>,
}

impl Tickets {
    pub fn create(&self) -> (String, String) {
        let ticket = base64url_random(24);
        let expires_at = now_millis() + 30_000;
        self.inner.lock().expect("ticket lock").insert(ticket.clone(), expires_at);
        (ticket, iso_from_millis(expires_at))
    }

    /// 一次性消费：不存在/过期均 false（对位 consumeMonitorTicket）。
    pub fn consume(&self, ticket: &str) -> bool {
        let mut guard = self.inner.lock().expect("ticket lock");
        match guard.remove(ticket) {
            Some(expires_at) => expires_at >= now_millis(),
            None => false,
        }
    }
}

/// 当前 UTC ISO 毫秒戳（供采样模块共用）。
pub fn iso_now() -> String {
    iso_from_millis(now_millis())
}

pub fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

fn iso_from_millis(millis: u128) -> String {
    // RFC3339（毫秒）：单节点本地时区无关，UTC 固定格式即可满足 Admin 解析。
    let secs = (millis / 1000) as i64;
    let ms = (millis % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn base64url_random(bytes: usize) -> String {
    use base64::Engine as _;
    let mut raw = vec![0u8; bytes];
    getrandom_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn getrandom_bytes(buffer: &mut [u8]) {
    // 读 /dev/urandom：无额外依赖，容器/宿主均可用。
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buffer))
        .expect("/dev/urandom");
}

/// Sec-WebSocket-Accept（RFC6455：SHA1(key + magic) base64 标准字母表）。
pub fn websocket_accept(key: &str) -> String {
    use base64::Engine as _;
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(hasher.digest().bytes())
}

/// 服务端帧编码（<126 短长度；126..=65535 扩展长度；对位 encodeWebSocketFrame）。
pub fn encode_frame(payload: &str) -> Result<Vec<u8>, String> {
    let body = payload.as_bytes();
    if body.len() >= 65_536 {
        return Err("monitor frame is too large".into());
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.push(0x81);
    if body.len() < 126 {
        frame.push(body.len() as u8);
    } else {
        frame.push(126);
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(body);
    Ok(frame)
}

/// 解析客户端首字节：返回 true 当为 ping（opcode 0x9）——对位“不解析应用数据”的保守应答。
pub fn is_ping(first_byte: u8) -> bool {
    first_byte & 0x0f == 0x9
}

pub const PONG: [u8; 2] = [0x8a, 0x00];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_single_use_and_expiry() {
        let tickets = Tickets::default();
        let (ticket, expires) = tickets.create();
        assert!(tickets.consume(&ticket));
        assert!(!tickets.consume(&ticket), "ticket must be single-use");
        assert!(expires.ends_with('Z'));
    }

    #[test]
    fn expired_ticket_rejected() {
        let tickets = Tickets::default();
        let (ticket, _) = tickets.create();
        tickets.inner.lock().unwrap().insert(ticket.clone(), now_millis() - 1);
        assert!(!tickets.consume(&ticket));
    }

    #[test]
    fn rfc6455_accept_known_vector() {
        // RFC 6455 §1.3 示例向量
        // RFC 6455 §1.3 官方向量：client key → s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        assert_eq!(websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn frame_encoding_short_and_extended() {
        let short = encode_frame("hi").unwrap();
        assert_eq!(&short[..2], &[0x81, 2]);
        let long = "x".repeat(300);
        let extended = encode_frame(&long).unwrap();
        assert_eq!(&extended[..4], &[0x81, 126, 0x01, 44]); // 300 = 0x012C
        assert!(encode_frame(&"y".repeat(70_000)).is_err());
    }

    #[test]
    fn ping_detection() {
        assert!(is_ping(0x89));
        assert!(!is_ping(0x81));
        assert!(!is_ping(0x88));
    }

    #[test]
    fn iso_format_shape() {
        let stamp = iso_from_millis(1_786_807_054_123);
        assert!(stamp.starts_with("20") && stamp.len() == 24 && stamp.ends_with('Z'));
    }
}
