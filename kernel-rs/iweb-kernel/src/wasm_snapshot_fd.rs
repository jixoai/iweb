//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 7.3 + 7.4 的传输实现）：秘密/配置
//!   快照 FD 经独立 raw-UDS SOCK_SEQPACKET 通道 `/run/iweb-sandbox/snapshot-fd.sock`
//!   以单一 `SCM_RIGHTS` 描述符 handoff；帧/ancillary/拒绝规则逐字对齐 spec。
//! 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//! "Snapshot descriptors use an independent framed raw socket"（SnapshotFdTransportV1 全部
//! 条款：16 字节头、magic 4957454246443100、u32-BE 长度 1..65536、frameType 1/2/0x81、
//! 单 sendmsg 单 iovec 单 SCM_RIGHTS 单 FD、MSG_EOR 必须、MSG_TRUNC/MSG_CTRUNC/多余
//! 控制消息/缺失或多于一个描述符一律拒绝并关闭收到的 FD、SNAPSHOT_FRAME_INVALID
//! 预解析拒绝、SNAPSHOT_WIRE_INVALID JCS 形状拒绝、HTTP 与 raw 双向互拒）。
//! 纯函数对位：packages/contracts/wasm-execution.ts（WASM_SNAPSHOT_FRAME_MAGIC_HEX）与
//! supervisor/snapshot-fd.ts（TS 侧判定层；socket 原生能力边界见该文件头注）。
//!
//! 正交意图：
//! 1. 帧编解码纯函数（magic/version/flags/length/边界/frameType 预解析拒绝 +
//!    `POST `/`GET `/HTTP 头前缀 SNAPSHOT_HTTP_ON_RAW_SOCKET 先于一切解析）；
//! 2. handoff/ack payload 的 typed JCS 契约（deny_unknown_fields + 字节必须等于
//!    JCS(parse(bytes)) + kind 与 frameType 一致 + 全部身份/文法/耦合校验）；
//! 3. 域前缀单次 SHA-256 digest 公式（fdDigest 与 handoffDigest，绝不二次 hash）；
//! 4. 真 `sendmsg`/`recvmsg` + SCM_RIGHTS ancillary 收发（libc，版本钉死 =0.2.189）；
//! 5. Kernel 侧固定路径/inode/owner/mode/连接后复查 + SO_TYPE==SOCK_SEQPACKET +
//!    SO_PEERCRED 对端凭据调用点（Linux 实测；非 Linux 一律失败关闭）。
//!
//! 接线备注（本文件不改 lib.rs，由编排者注册）：在 lib.rs 的 `pub mod wasm_secrets;`
//! 之后追加一行 `pub mod wasm_snapshot_fd;`。Kernel 发送点（spec "For prepare and
//! start, Kernel sends exactly one secret frame first, then exactly one config frame
//! iff configRevision > 0"）在命令投递层（wasm_commands.rs 的 outbox 投递处）组合
//! `deliver_snapshot_handoff`（secret 先、config 仅当 configRevision>0）；HTTP envelope
//! 只在 raw 双 ack accepted 之后由新开连接发送（本模块不触碰 HTTP）。
//!
//! 能力边界（诚实声明）：AF_UNIX SOCK_SEQPACKET 在 macOS 不可用（socket(2) 返回
//! EPROTONOSUPPORT，已实证）。因此：
//! - 完整 seqpacket 对拍测试（线程作 supervisor 端 recvmsg 断言字节与 FD）为
//!   `#[cfg(target_os = "linux")]` 专有，在 Linux 节点执行；
//! - macOS 开发机运行帧/拒绝/摘要纯函数测试 + SOCK_DGRAM ancillary 往返
//!   （复用同一 sendmsg/recvmsg 核心，证明 cmsg 构造/解析与 FD 传递），并覆盖
//!   SO_TYPE 拒绝、路径/inode/mode 拒绝与 SO_PEERCRED 失败关闭；
//! - TS（Node/Bun）无 SOCK_SEQPACKET 与 SCM_RIGHTS 原生能力，TS 侧只承载判定层
//!   （见 supervisor/snapshot-fd.ts 头注）。
//!
//! 歧义备注（保守 fail-closed 取舍，供 review 对照）：
//! 1. HTTP-on-raw 检测置于 magic 检查之前：`POST `/`GET ` 前缀或首行形如
//!    `METHOD SP target SP HTTP/x` 的包不可能同时携带合法 magic，先分类为
//!    SNAPSHOT_HTTP_ON_RAW_SOCKET 与 spec 场景语义一致且信息更准。
//! 2. `sendmsg` 的 EINTR 重试不计为"第二次发送"（内核未移送任何字节）；除此之外
//!    严格单次调用，返回值必须等于整帧长度。
//! 3. recv 侧控制缓冲固定 256 字节（可容纳最多 ~56 个 FD 的单一 cmsg）：超出即
//!    MSG_CTRUNC 拒绝，符合"多余描述符拒绝"且更早失败。
//! 4. 非 Linux 的 SO_PEERCRED 与不可用 seqpacket 属"凭据缺失/不可用"，按 spec
//!    "A missing, unavailable, or mismatched credential is
//!    SUPERVISOR_PEER_CREDENTIALS_REJECTED" 失败关闭；seqpacket 不可用另以内部码
//!    SNAPSHOT_TRANSPORT_UNAVAILABLE 表达（支持拓扑的 Linux 上不可达，非 wire 稳定码）。
//! 5. recvmsg 返回 0 视为对端关闭（seqpacket 上与零长度包不可区分；两者都失败，
//!    Kernel 走 query/replay 重发路径），以内部码 SNAPSHOT_TRANSPORT_CLOSED 表达。
//! 6. fdBytes 复读复核（fdDigest == valuesDigest == command digest）是 supervisor 侧
//!    职责；Kernel 侧构建 handoff 时以同一公式写 fd_digest（公式单一来源在本文件）。

use crate::wasm_admission::{jcs_bytes, parse_rfc3339_utc_millis, AdmissionError, WASM_U53_MAX};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误码（spec "The raw transport's stable failure codes"）
// ---------------------------------------------------------------------------

/// SnapshotFdTransportV1 固定 socket 字面量（环境不可重定向）。
pub const SNAPSHOT_FD_SOCKET_PATH: &str = "/run/iweb-sandbox/snapshot-fd.sock";
/// ASCII `IWEBFD1\0`，hex `4957454246443100`（与 contracts WASM_SNAPSHOT_FRAME_MAGIC_HEX 同源）。
pub const SNAPSHOT_FRAME_MAGIC: [u8; 8] = *b"IWEBFD1\0";
/// 固定 16 字节头（magic 8 + version 2 + frameType 1 + flags 1 + payloadLength 4）。
pub const SNAPSHOT_FRAME_HEADER_BYTES: usize = 16;
pub const SNAPSHOT_FRAME_VERSION: u16 = 1;
/// payloadLength 1..=65536（含端点，u32 大端）。
pub const SNAPSHOT_MAX_PAYLOAD_BYTES: usize = 65_536;
/// frameType: 1 secret-request / 2 config-request / 0x81 acknowledgement。
pub const SNAPSHOT_FRAME_TYPE_SECRET_REQUEST: u8 = 1;
pub const SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST: u8 = 2;
pub const SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT: u8 = 0x81;

/// spec 已命名：固定路径被替换/环境重定向（空、相对、备选、symlink、TCP）。
pub const SNAPSHOT_SOCKET_PATH_REJECTED: &str = "SNAPSHOT_SOCKET_PATH_REJECTED";
/// spec 已命名：header、边界、ancillary 数量或 socket type 的预解析拒绝。
pub const SNAPSHOT_FRAME_INVALID: &str = "SNAPSHOT_FRAME_INVALID";
/// spec 已命名：JCS payload 形状拒绝（边界已被接受）。
pub const SNAPSHOT_WIRE_INVALID: &str = "SNAPSHOT_WIRE_INVALID";
/// spec 已命名：raw socket 收到 HTTP。
pub const SNAPSHOT_HTTP_ON_RAW_SOCKET: &str = "SNAPSHOT_HTTP_ON_RAW_SOCKET";
/// spec 已命名：handoff 身份冲突（commandDigest/tuple/ref/valuesDigest 分歧）。
pub const SNAPSHOT_HANDOFF_ID_CONFLICT: &str = "SNAPSHOT_HANDOFF_ID_CONFLICT";
/// spec 已命名：fd 字节摘要与 valuesDigest 分歧。
pub const SNAPSHOT_VALUES_DIGEST_MISMATCH: &str = "SNAPSHOT_VALUES_DIGEST_MISMATCH";
/// spec 已命名：fstat 非 regular / F_GETFL 非只读等 FD 策略拒绝。
pub const SNAPSHOT_FD_POLICY_REJECTED: &str = "SNAPSHOT_FD_POLICY_REJECTED";
/// SupervisorSocketAuthV1 共享：凭据缺失/不可用/不匹配。
pub const SUPERVISOR_PEER_CREDENTIALS_REJECTED: &str = "SUPERVISOR_PEER_CREDENTIALS_REJECTED";
/// 内部 fail-closed 码（非 wire 稳定）：本机无 AF_UNIX SOCK_SEQPACKET（macOS 开发机）。
pub const SNAPSHOT_TRANSPORT_UNAVAILABLE: &str = "SNAPSHOT_TRANSPORT_UNAVAILABLE";
/// 内部 fail-closed 码（非 wire 稳定）：对端在 ack 前关闭（驱动 query/replay 重发）。
pub const SNAPSHOT_TRANSPORT_CLOSED: &str = "SNAPSHOT_TRANSPORT_CLOSED";
/// 内部 fail-closed 码（非 wire 稳定）：系统调用层面的传输错误。
pub const SNAPSHOT_TRANSPORT_IO: &str = "SNAPSHOT_TRANSPORT_IO";

/// fdDigest / valuesDigest 的域前缀（spec 逐字；单次 SHA-256，绝不对 hex 串二次 hash）。
pub const SECRET_SNAPSHOT_DIGEST_DOMAIN: &str = "iweb-secret-snapshot-v1";
pub const CONFIG_SNAPSHOT_DIGEST_DOMAIN: &str = "iweb-config-snapshot-v1";
/// handoffDigest 域前缀。
pub const SNAPSHOT_HANDOFF_DIGEST_DOMAIN: &str = "iweb-snapshot-handoff-v1";

/// 结构化错误：code 为稳定 owner 可见码，detail 不含任何秘密值或路径内容。
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotFdError {
    pub code: &'static str,
    pub detail: String,
}

impl SnapshotFdError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for SnapshotFdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SnapshotFdError {}

fn err(code: &'static str, detail: impl Into<String>) -> SnapshotFdError {
    SnapshotFdError::new(code, detail.into())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// libc::CMSG_LEN 的平台签名：libc 0.2.189 在 Linux 与 apple 上均为 c_uint 入/出参
/// （远程 Linux 构建实证；原 cfg 分支方向写反导致 Linux 编译 E0308）。统一带 cast。
fn cmsg_len(data_len: usize) -> usize {
    unsafe { libc::CMSG_LEN(data_len as libc::c_uint) as usize }
}

/// libc::CMSG_SPACE 同款归一（BSD/macOS 的 sendmsg 要求 controllen 恰好覆盖 cmsg 链）。
fn cmsg_space(data_len: usize) -> usize {
    unsafe { libc::CMSG_SPACE(data_len as libc::c_uint) as usize }
}

// ---------------------------------------------------------------------------
// 文法（与 wasm_secrets/wasm_admission 同款；本模块自带避免跨模块私有依赖）
// ---------------------------------------------------------------------------

struct SnapshotRegexes {
    uuid_v7: regex::Regex,
    sha256_hex: regex::Regex,
    application_id: regex::Regex,
    version_id: regex::Regex,
    failure_code: regex::Regex,
}

fn regexes() -> &'static SnapshotRegexes {
    static REGEXES: OnceLock<SnapshotRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| SnapshotRegexes {
        // lower-case UUIDv7：version nibble 7，variant 位 [89ab]（RFC 9562）。
        uuid_v7: regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").expect("uuid v7 regex"),
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
        version_id: regex::Regex::new(r"^[a-f0-9]{64}-[1-9][0-9]{0,15}$").expect("version id regex"),
        failure_code: regex::Regex::new(r"^[A-Z][A-Z0-9_]{0,63}$").expect("failure code regex"),
    })
}

// ---------------------------------------------------------------------------
// 帧编解码（纯函数；Kernel 发送端与 supervisor/对拍接收端共享）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotFrameKind {
    SecretRequest,
    ConfigRequest,
    Acknowledgement,
}

impl SnapshotFrameKind {
    pub fn frame_type(self) -> u8 {
        match self {
            SnapshotFrameKind::SecretRequest => SNAPSHOT_FRAME_TYPE_SECRET_REQUEST,
            SnapshotFrameKind::ConfigRequest => SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST,
            SnapshotFrameKind::Acknowledgement => SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotFrameHeader {
    pub kind: SnapshotFrameKind,
    pub payload_length: usize,
}

/// spec：raw socket 拒绝 `POST `、`GET ` 或 HTTP 头（SNAPSHOT_HTTP_ON_RAW_SOCKET）。
/// 先于 magic 检查执行——HTTP 前缀与合法 magic 互斥，先分类信息更准（歧义备注 #1）。
pub fn reject_http_on_raw_socket(packet: &[u8]) -> Result<(), SnapshotFdError> {
    let text = match std::str::from_utf8(packet) {
        Ok(text) => text,
        Err(_) => return Ok(()), // 非 UTF-8 交给 magic/header 拒绝路径。
    };
    if text.starts_with("POST ") || text.starts_with("GET ") {
        return Err(err(SNAPSHOT_HTTP_ON_RAW_SOCKET, "the raw snapshot socket carries framed snapshot bytes only; an HTTP request preamble is rejected before any parsing"));
    }
    // 首行形如 `METHOD SP request-target SP HTTP/x`（请求行）或以 `HTTP/` 开头（状态行）。
    let first_line = text.split("\r\n").next().unwrap_or("");
    let mut parts = first_line.split(' ');
    let looks_like_request_line = matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(method), Some(_), Some(version)) if !method.is_empty()
            && method.len() <= 16
            && method.bytes().all(|b| b.is_ascii_uppercase())
            && version.starts_with("HTTP/")
    );
    if looks_like_request_line || first_line.starts_with("HTTP/") {
        return Err(err(SNAPSHOT_HTTP_ON_RAW_SOCKET, "the raw snapshot socket carries framed snapshot bytes only; an HTTP header line is rejected before any parsing"));
    }
    Ok(())
}

/// 预解析帧头：magic/version/flags/length/包边界/frameType 逐一拒绝
/// （全部 SNAPSHOT_FRAME_INVALID；spec "Any packet with a wrong magic, version, flags,
/// length, packet boundary, or unexpected frame type is rejected before payload parsing"）。
pub fn parse_snapshot_frame_header(packet: &[u8]) -> Result<SnapshotFrameHeader, SnapshotFdError> {
    reject_http_on_raw_socket(packet)?;
    if packet.len() < SNAPSHOT_FRAME_HEADER_BYTES {
        return Err(err(SNAPSHOT_FRAME_INVALID, "frame shorter than the fixed 16-byte header"));
    }
    if packet[0..8] != SNAPSHOT_FRAME_MAGIC {
        return Err(err(SNAPSHOT_FRAME_INVALID, "frame magic must be the ASCII bytes IWEBFD1 NUL"));
    }
    let version = u16::from_be_bytes([packet[8], packet[9]]);
    if version != SNAPSHOT_FRAME_VERSION {
        return Err(err(SNAPSHOT_FRAME_INVALID, format!("frame version must be exactly {SNAPSHOT_FRAME_VERSION}")));
    }
    let kind = match packet[10] {
        SNAPSHOT_FRAME_TYPE_SECRET_REQUEST => SnapshotFrameKind::SecretRequest,
        SNAPSHOT_FRAME_TYPE_CONFIG_REQUEST => SnapshotFrameKind::ConfigRequest,
        SNAPSHOT_FRAME_TYPE_ACKNOWLEDGEMENT => SnapshotFrameKind::Acknowledgement,
        _ => {
            return Err(err(
                SNAPSHOT_FRAME_INVALID,
                "frame type must be 1 (secret-request), 2 (config-request), or 0x81 (acknowledgement)",
            ))
        }
    };
    if packet[11] != 0 {
        return Err(err(SNAPSHOT_FRAME_INVALID, "frame flags must be exactly 0"));
    }
    let payload_length = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]) as usize;
    if payload_length == 0 || payload_length > SNAPSHOT_MAX_PAYLOAD_BYTES {
        return Err(err(SNAPSHOT_FRAME_INVALID, "frame payloadLength must be between 1 and 65536 bytes"));
    }
    // 包边界：SOCK_SEQPACKET 单包无流重组，包长必须恰等于 16 + payloadLength。
    if packet.len() != SNAPSHOT_FRAME_HEADER_BYTES + payload_length {
        return Err(err(SNAPSHOT_FRAME_INVALID, "packet boundary must equal the fixed header plus payloadLength with no stream reassembly"));
    }
    Ok(SnapshotFrameHeader { kind, payload_length })
}

/// 编码完整帧（单一缓冲区；发送侧单 iovec 的物化基础）。
pub fn encode_snapshot_frame(kind: SnapshotFrameKind, payload: &[u8]) -> Result<Vec<u8>, SnapshotFdError> {
    if payload.is_empty() || payload.len() > SNAPSHOT_MAX_PAYLOAD_BYTES {
        return Err(err(SNAPSHOT_FRAME_INVALID, "frame payloadLength must be between 1 and 65536 bytes"));
    }
    let mut frame = Vec::with_capacity(SNAPSHOT_FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&SNAPSHOT_FRAME_MAGIC);
    frame.extend_from_slice(&SNAPSHOT_FRAME_VERSION.to_be_bytes());
    frame.push(kind.frame_type());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

// ---------------------------------------------------------------------------
// digest 公式（域前缀单次 SHA-256）
// ---------------------------------------------------------------------------

fn domain_digest(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// fdDigest = hex(SHA-256(UTF8("iweb-secret-snapshot-v1\n" || fdBytes)))（kind 对应域）。
pub fn compute_snapshot_fd_digest(kind: SnapshotFrameKind, fd_bytes: &[u8]) -> Result<String, SnapshotFdError> {
    let domain = match kind {
        SnapshotFrameKind::SecretRequest => SECRET_SNAPSHOT_DIGEST_DOMAIN,
        SnapshotFrameKind::ConfigRequest => CONFIG_SNAPSHOT_DIGEST_DOMAIN,
        SnapshotFrameKind::Acknowledgement => {
            return Err(err(SNAPSHOT_WIRE_INVALID, "an acknowledgement frame carries no snapshot descriptor digest"))
        }
    };
    Ok(domain_digest(domain, fd_bytes))
}

/// handoffDigest = hex(SHA-256(UTF8("iweb-snapshot-handoff-v1\n" || JCS(request payload))))。
pub fn compute_snapshot_handoff_digest(request_payload: &SnapshotHandoffPayload) -> Result<String, SnapshotFdError> {
    Ok(domain_digest(SNAPSHOT_HANDOFF_DIGEST_DOMAIN, &handoff_jcs_bytes(request_payload)?))
}

// ---------------------------------------------------------------------------
// handoff / ack payload 契约（typed JCS；字节必须等于 JCS(parse(bytes))）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSnapshotFdHandoffV1 {
    pub schema_version: u32,
    pub kind: String,
    pub command_id: String,
    pub command_digest: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub application_id: String,
    pub version_id: String,
    pub preparation_generation: u64,
    pub secret_revision: u64,
    pub values_digest: String,
    pub fd_digest: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSnapshotFdHandoffV1 {
    pub schema_version: u32,
    pub kind: String,
    pub command_id: String,
    pub command_digest: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub application_id: String,
    pub version_id: String,
    pub preparation_generation: u64,
    pub config_revision: u64,
    pub values_digest: String,
    pub fd_digest: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotAckStatus {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFdAckV1 {
    pub schema_version: u32,
    pub kind: String,
    pub command_id: String,
    pub handoff_digest: String,
    pub status: SnapshotAckStatus,
    pub failure_code: Option<String>,
    pub journal_revision: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SnapshotHandoffPayload {
    Secret(SecretSnapshotFdHandoffV1),
    Config(ConfigSnapshotFdHandoffV1),
}

impl SnapshotHandoffPayload {
    pub fn frame_kind(&self) -> SnapshotFrameKind {
        match self {
            SnapshotHandoffPayload::Secret(_) => SnapshotFrameKind::SecretRequest,
            SnapshotHandoffPayload::Config(_) => SnapshotFrameKind::ConfigRequest,
        }
    }

    pub fn command_id(&self) -> &str {
        match self {
            SnapshotHandoffPayload::Secret(p) => &p.command_id,
            SnapshotHandoffPayload::Config(p) => &p.command_id,
        }
    }

    /// JCS 权威：payload 字节必须逐字节等于 JCS(parse(bytes))。
    fn require_canonical_jcs<T: for<'de> Deserialize<'de> + Serialize>(payload: &[u8]) -> Result<T, SnapshotFdError> {
        let parsed: T = serde_json::from_slice(payload)
            .map_err(|e| err(SNAPSHOT_WIRE_INVALID, format!("payload bytes do not parse as the typed handoff record: {e}")))?;
        let canonical = jcs_bytes(&parsed).map_err(|e| err(SNAPSHOT_WIRE_INVALID, format!("payload does not serialize to canonical JCS: {}", e.detail)))?;
        if canonical != payload {
            return Err(err(SNAPSHOT_WIRE_INVALID, "payload bytes must equal JCS(parse(bytes)); reordered or non-canonical bytes are rejected"));
        }
        Ok(parsed)
    }

    /// frameType 与 JCS kind 必须一致（frameType:1↔secret，frameType:2↔config）。
    pub fn parse(frame_kind: SnapshotFrameKind, payload: &[u8]) -> Result<SnapshotHandoffPayload, SnapshotFdError> {
        match frame_kind {
            SnapshotFrameKind::SecretRequest => {
                let parsed: SecretSnapshotFdHandoffV1 = Self::require_canonical_jcs(payload)?;
                parsed.validate()?;
                Ok(SnapshotHandoffPayload::Secret(parsed))
            }
            SnapshotFrameKind::ConfigRequest => {
                let parsed: ConfigSnapshotFdHandoffV1 = Self::require_canonical_jcs(payload)?;
                parsed.validate()?;
                Ok(SnapshotHandoffPayload::Config(parsed))
            }
            SnapshotFrameKind::Acknowledgement => Err(err(SNAPSHOT_WIRE_INVALID, "an acknowledgement payload is not a snapshot handoff")),
        }
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, SnapshotFdError> {
        encode_snapshot_frame(self.frame_kind(), &handoff_jcs_bytes(self)?)
    }
}

fn handoff_jcs_bytes(payload: &SnapshotHandoffPayload) -> Result<Vec<u8>, SnapshotFdError> {
    match payload {
        SnapshotHandoffPayload::Secret(p) => jcs_bytes(p).map_err(snapshot_wire_from_admission),
        SnapshotHandoffPayload::Config(p) => jcs_bytes(p).map_err(snapshot_wire_from_admission),
    }
}

fn snapshot_wire_from_admission(error: AdmissionError) -> SnapshotFdError {
    err(SNAPSHOT_WIRE_INVALID, format!("handoff payload is outside the canonical JCS domain: {}", error.detail))
}

#[allow(clippy::too_many_arguments)]
fn require_common_handoff_fields(
    schema_version: u32,
    kind_literal: &str,
    kind: &str,
    command_id: &str,
    command_digest: &str,
    reference: &str,
    application_id: &str,
    version_id: &str,
    preparation_generation: u64,
    values_digest: &str,
    fd_digest: &str,
    expires_at: &str,
) -> Result<(), SnapshotFdError> {
    if schema_version != 1 {
        return Err(err(SNAPSHOT_WIRE_INVALID, "schemaVersion must be exactly 1"));
    }
    if kind != kind_literal {
        return Err(err(SNAPSHOT_WIRE_INVALID, format!("payload kind must be exactly \"{kind_literal}\"")));
    }
    if !regexes().uuid_v7.is_match(command_id) {
        return Err(err(SNAPSHOT_WIRE_INVALID, "commandId must be a lower-case UUIDv7"));
    }
    for (field, value) in [("commandDigest", command_digest), ("ref", reference), ("valuesDigest", values_digest), ("fdDigest", fd_digest)] {
        if !regexes().sha256_hex.is_match(value) {
            return Err(err(SNAPSHOT_WIRE_INVALID, format!("{field} must be 64 lower-case hex characters")));
        }
    }
    if !regexes().application_id.is_match(application_id) {
        return Err(err(SNAPSHOT_WIRE_INVALID, "applicationId must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"));
    }
    if !regexes().version_id.is_match(version_id) {
        return Err(err(SNAPSHOT_WIRE_INVALID, "versionId must be <64 lower-case hex>-<positive sequence>"));
    }
    if preparation_generation == 0 || preparation_generation > WASM_U53_MAX {
        return Err(err(SNAPSHOT_WIRE_INVALID, "preparationGeneration must be a u53 integer >= 1"));
    }
    parse_rfc3339_utc_millis(expires_at)
        .map_err(|e| err(SNAPSHOT_WIRE_INVALID, format!("expiresAt must be RFC3339 UTC ending in Z: {}", e.detail)))?;
    Ok(())
}

impl SecretSnapshotFdHandoffV1 {
    pub fn validate(&self) -> Result<(), SnapshotFdError> {
        require_common_handoff_fields(
            self.schema_version,
            "secret",
            &self.kind,
            &self.command_id,
            &self.command_digest,
            &self.reference,
            &self.application_id,
            &self.version_id,
            self.preparation_generation,
            &self.values_digest,
            &self.fd_digest,
            &self.expires_at,
        )?;
        if self.secret_revision > WASM_U53_MAX {
            return Err(err(SNAPSHOT_WIRE_INVALID, "secretRevision must be a u53 integer"));
        }
        Ok(())
    }
}

impl ConfigSnapshotFdHandoffV1 {
    pub fn validate(&self) -> Result<(), SnapshotFdError> {
        require_common_handoff_fields(
            self.schema_version,
            "config",
            &self.kind,
            &self.command_id,
            &self.command_digest,
            &self.reference,
            &self.application_id,
            &self.version_id,
            self.preparation_generation,
            &self.values_digest,
            &self.fd_digest,
            &self.expires_at,
        )?;
        if self.config_revision > WASM_U53_MAX {
            return Err(err(SNAPSHOT_WIRE_INVALID, "configRevision must be a u53 integer"));
        }
        Ok(())
    }
}

impl SnapshotFdAckV1 {
    pub fn validate(&self) -> Result<(), SnapshotFdError> {
        if self.schema_version != 1 {
            return Err(err(SNAPSHOT_WIRE_INVALID, "schemaVersion must be exactly 1"));
        }
        if self.kind != "ack" {
            return Err(err(SNAPSHOT_WIRE_INVALID, "payload kind must be exactly \"ack\""));
        }
        if !regexes().uuid_v7.is_match(&self.command_id) {
            return Err(err(SNAPSHOT_WIRE_INVALID, "commandId must be a lower-case UUIDv7"));
        }
        if !regexes().sha256_hex.is_match(&self.handoff_digest) {
            return Err(err(SNAPSHOT_WIRE_INVALID, "handoffDigest must be 64 lower-case hex characters"));
        }
        if self.journal_revision > WASM_U53_MAX {
            return Err(err(SNAPSHOT_WIRE_INVALID, "journalRevision must be a u53 integer"));
        }
        // failureCode 为 null 当且仅当 status 为 accepted；非空时匹配稳定码文法。
        match (&self.status, &self.failure_code) {
            (SnapshotAckStatus::Accepted, Some(_)) => Err(err(SNAPSHOT_WIRE_INVALID, "an accepted acknowledgement must carry failureCode null")),
            (SnapshotAckStatus::Rejected, None) => Err(err(SNAPSHOT_WIRE_INVALID, "a rejected acknowledgement must carry a bounded failureCode")),
            (SnapshotAckStatus::Rejected, Some(code)) => {
                if regexes().failure_code.is_match(code) {
                    Ok(())
                } else {
                    Err(err(SNAPSHOT_WIRE_INVALID, "failureCode must match ^[A-Z][A-Z0-9_]{0,63}$"))
                }
            }
            (SnapshotAckStatus::Accepted, None) => Ok(()),
        }
    }

    pub fn parse(frame_kind: SnapshotFrameKind, payload: &[u8]) -> Result<SnapshotFdAckV1, SnapshotFdError> {
        if frame_kind != SnapshotFrameKind::Acknowledgement {
            return Err(err(SNAPSHOT_WIRE_INVALID, "an acknowledgement payload requires frameType 0x81"));
        }
        let parsed: SnapshotFdAckV1 = SnapshotHandoffPayload::require_canonical_jcs(payload)?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, SnapshotFdError> {
        self.validate()?;
        encode_snapshot_frame(SnapshotFrameKind::Acknowledgement, &jcs_bytes(self).map_err(snapshot_wire_from_admission)?)
    }
}

// ---------------------------------------------------------------------------
// recvmsg ancillary 判定（纯函数；原生 recv 层供给事实，本层拥有全部拒绝规则）
// ---------------------------------------------------------------------------

/// 一次 recvmsg 的可判定事实（由原生层供给；TS 判定层使用同构形状）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnapshotRecvAncillaryFacts {
    /// 收到完整记录（SOCK_SEQPACKET 每个包必须置位）。
    pub eor: bool,
    /// MSG_TRUNC：数据被截断。
    pub truncated: bool,
    /// MSG_CTRUNC：控制消息被截断。
    pub control_truncated: bool,
    /// 控制消息条数（多于一条即"extra control messages"）。
    pub control_message_count: usize,
    /// SCM_RIGHTS 送达的描述符总数。
    pub descriptor_count: usize,
}

/// 请求帧（frameType 1/2）：恰好一条 SCM_RIGHTS 控制消息、恰好一个描述符。
pub fn validate_request_ancillary(facts: &SnapshotRecvAncillaryFacts) -> Result<(), SnapshotFdError> {
    validate_common_ancillary(facts)?;
    if facts.control_message_count != 1 || facts.descriptor_count != 1 {
        return Err(err(SNAPSHOT_FRAME_INVALID, "a request frame requires exactly one SCM_RIGHTS control message carrying exactly one descriptor"));
    }
    Ok(())
}

/// ack 帧（frameType 0x81）：无任何 ancillary 描述符。
pub fn validate_ack_ancillary(facts: &SnapshotRecvAncillaryFacts) -> Result<(), SnapshotFdError> {
    validate_common_ancillary(facts)?;
    if facts.control_message_count != 0 || facts.descriptor_count != 0 {
        return Err(err(SNAPSHOT_FRAME_INVALID, "an acknowledgement frame must carry no ancillary descriptor"));
    }
    Ok(())
}

fn validate_common_ancillary(facts: &SnapshotRecvAncillaryFacts) -> Result<(), SnapshotFdError> {
    if !facts.eor {
        return Err(err(SNAPSHOT_FRAME_INVALID, "recvmsg must report MSG_EOR for a complete frame"));
    }
    if facts.truncated {
        return Err(err(SNAPSHOT_FRAME_INVALID, "recvmsg reported MSG_TRUNC; truncated frames are rejected"));
    }
    if facts.control_truncated {
        return Err(err(SNAPSHOT_FRAME_INVALID, "recvmsg reported MSG_CTRUNC; truncated control data is rejected"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 真 sendmsg / recvmsg（libc；版本钉死 =0.2.189）
// ---------------------------------------------------------------------------

/// 单 sendmsg + 单 iovec（完整帧）+ 单 SCM_RIGHTS 控制消息（单 FD）。
/// `flags` 由调用层固定为 MSG_EOR（Kernel 规范入口）；EINTR 重试不产生第二次传输
/// （歧义备注 #2）；返回值必须等于整帧长度。
pub fn sendmsg_frame_with_single_descriptor(sock: impl AsFd, frame: &[u8], descriptor: impl AsFd, flags: i32) -> Result<(), SnapshotFdError> {
    if frame.len() < SNAPSHOT_FRAME_HEADER_BYTES + 1 {
        return Err(err(SNAPSHOT_FRAME_INVALID, "a request frame is at least the fixed header plus one payload byte"));
    }
    let descriptor_raw: libc::c_int = descriptor.as_fd().as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr() as *mut libc::c_void,
        iov_len: frame.len(),
    };
    // 128 字节控制缓冲：单 FD 只需 CMSG_SPACE(sizeof(int))；controllen 恰好覆盖
    // 单条 cmsg（BSD/macOS 的 sendmsg 要求链长精确，不接受尾部零填充）。
    let mut control = [0u8; 128];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = cmsg_space(std::mem::size_of::<libc::c_int>()) as _;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(err(SNAPSHOT_TRANSPORT_IO, "CMSG_FIRSTHDR returned null while building the SCM_RIGHTS control message"));
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = cmsg_len(std::mem::size_of::<libc::c_int>()) as _;
        std::ptr::copy_nonoverlapping(
            &descriptor_raw as *const libc::c_int as *const u8,
            libc::CMSG_DATA(header),
            std::mem::size_of::<libc::c_int>(),
        );
    }
    let sock_raw = sock.as_fd().as_raw_fd();
    loop {
        let sent = unsafe { libc::sendmsg(sock_raw, &message, flags) };
        if sent >= 0 {
            if sent as usize == frame.len() {
                return Ok(());
            }
            return Err(err(SNAPSHOT_TRANSPORT_IO, "sendmsg transferred fewer bytes than the single complete frame"));
        }
        match errno() {
            libc::EINTR => continue,
            code => return Err(err(SNAPSHOT_TRANSPORT_IO, format!("sendmsg failed with errno {code}"))),
        }
    }
}

/// Kernel 发送请求帧的规范入口：强制 MSG_EOR。
pub fn send_snapshot_frame_with_descriptor(sock: impl AsFd, frame: &[u8], descriptor: impl AsFd) -> Result<(), SnapshotFdError> {
    sendmsg_frame_with_single_descriptor(sock, frame, descriptor, libc::MSG_EOR)
}

/// 无 ancillary 的单帧发送（supervisor→Kernel 的 ack；对拍测试复用）。
pub fn send_snapshot_frame_without_ancillary(sock: impl AsFd, frame: &[u8]) -> Result<(), SnapshotFdError> {
    if frame.len() < SNAPSHOT_FRAME_HEADER_BYTES + 1 {
        return Err(err(SNAPSHOT_FRAME_INVALID, "a frame is at least the fixed header plus one payload byte"));
    }
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr() as *mut libc::c_void,
        iov_len: frame.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    let sock_raw = sock.as_fd().as_raw_fd();
    loop {
        let sent = unsafe { libc::sendmsg(sock_raw, &message, libc::MSG_EOR) };
        if sent >= 0 {
            if sent as usize == frame.len() {
                return Ok(());
            }
            return Err(err(SNAPSHOT_TRANSPORT_IO, "sendmsg transferred fewer bytes than the single complete frame"));
        }
        match errno() {
            libc::EINTR => continue,
            code => return Err(err(SNAPSHOT_TRANSPORT_IO, format!("sendmsg failed with errno {code}"))),
        }
    }
}

/// 一次 recvmsg 的结果：帧字节、收到的描述符（拒绝路径由 drop 关闭）与判定事实。
#[derive(Debug)]
pub struct ReceivedSnapshotPacket {
    pub bytes: Vec<u8>,
    pub descriptors: Vec<OwnedFd>,
    pub facts: SnapshotRecvAncillaryFacts,
}

/// 单次 recvmsg：缓冲 16+65536（超出即 MSG_TRUNC 拒绝）；控制缓冲 256 字节
/// （超出即 MSG_CTRUNC 拒绝）。任何多余的 cmsg 计入事实并拒绝。
pub fn recvmsg_snapshot_packet(sock: impl AsFd) -> Result<ReceivedSnapshotPacket, SnapshotFdError> {
    let mut buffer = vec![0u8; SNAPSHOT_FRAME_HEADER_BYTES + SNAPSHOT_MAX_PAYLOAD_BYTES];
    let mut control = [0u8; 256];
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control.len() as _;
    let sock_raw = sock.as_fd().as_raw_fd();
    let received = loop {
        let n = unsafe { libc::recvmsg(sock_raw, &mut message, 0) };
        if n >= 0 {
            break n as usize;
        }
        match errno() {
            libc::EINTR => continue,
            code => return Err(err(SNAPSHOT_TRANSPORT_IO, format!("recvmsg failed with errno {code}"))),
        }
    };
    if received == 0 {
        // seqpacket 上对端关闭与零长度包不可区分：两者都失败（歧义备注 #5）。
        return Err(err(SNAPSHOT_TRANSPORT_CLOSED, "the peer closed the connection or sent an empty packet before a complete frame"));
    }
    let flags = message.msg_flags;
    let mut descriptors: Vec<OwnedFd> = Vec::new();
    let mut control_message_count = 0usize;
    let mut cursor = message.msg_control as *mut libc::cmsghdr;
    while !cursor.is_null() {
        let header = unsafe { &*cursor };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let data_len = (header.cmsg_len as usize).saturating_sub(cmsg_len(0));
            let fd_count = data_len / std::mem::size_of::<libc::c_int>();
            let data = unsafe { libc::CMSG_DATA(cursor) };
            for index in 0..fd_count {
                let mut raw: libc::c_int = -1;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        data.add(index * std::mem::size_of::<libc::c_int>()),
                        &mut raw as *mut libc::c_int as *mut u8,
                        std::mem::size_of::<libc::c_int>(),
                    );
                }
                if raw >= 0 {
                    descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        }
        control_message_count += 1;
        cursor = unsafe { libc::CMSG_NXTHDR(&message, cursor) };
    }
    let facts = SnapshotRecvAncillaryFacts {
        eor: flags & libc::MSG_EOR != 0,
        truncated: flags & libc::MSG_TRUNC != 0,
        control_truncated: flags & libc::MSG_CTRUNC != 0,
        control_message_count,
        descriptor_count: descriptors.len(),
    };
    buffer.truncate(received);
    Ok(ReceivedSnapshotPacket { bytes: buffer, descriptors, facts })
}

/// supervisor/对拍端接收请求帧：ancillary 判定 + 帧头 + payload 契约一站式。
/// 任何拒绝路径上已收到的描述符都被关闭（OwnedFd drop）。
pub fn receive_snapshot_request(sock: impl AsFd) -> Result<(SnapshotHandoffPayload, OwnedFd), SnapshotFdError> {
    let packet = recvmsg_snapshot_packet(sock)?;
    validate_request_ancillary(&packet.facts)?;
    let header = parse_snapshot_frame_header(&packet.bytes)?;
    if header.kind == SnapshotFrameKind::Acknowledgement {
        return Err(err(SNAPSHOT_FRAME_INVALID, "a request socket received an acknowledgement frame type"));
    }
    let descriptor = packet
        .descriptors
        .into_iter()
        .next()
        .ok_or_else(|| err(SNAPSHOT_FRAME_INVALID, "ancillary validation must deliver exactly one descriptor"))?;
    let payload = SnapshotHandoffPayload::parse(header.kind, &packet.bytes[SNAPSHOT_FRAME_HEADER_BYTES..])?;
    Ok((payload, descriptor))
}

/// Kernel 端接收 ack：无 ancillary + frameType 0x81 + payload 契约 + handoffDigest 回核。
pub fn receive_snapshot_ack(sock: impl AsFd, sent_handoff: &SnapshotHandoffPayload) -> Result<SnapshotFdAckV1, SnapshotFdError> {
    let packet = recvmsg_snapshot_packet(sock)?;
    validate_ack_ancillary(&packet.facts)?;
    let header = parse_snapshot_frame_header(&packet.bytes)?;
    if header.kind != SnapshotFrameKind::Acknowledgement {
        return Err(err(SNAPSHOT_FRAME_INVALID, "the acknowledgement socket received a request frame type"));
    }
    let ack = SnapshotFdAckV1::parse(header.kind, &packet.bytes[SNAPSHOT_FRAME_HEADER_BYTES..])?;
    if ack.command_id != sent_handoff.command_id() {
        return Err(err(SNAPSHOT_HANDOFF_ID_CONFLICT, "acknowledgement commandId does not match the handed-off command"));
    }
    if ack.handoff_digest != compute_snapshot_handoff_digest(sent_handoff)? {
        return Err(err(SNAPSHOT_HANDOFF_ID_CONFLICT, "acknowledgement handoffDigest does not equal the sent request payload digest"));
    }
    Ok(ack)
}

// ---------------------------------------------------------------------------
// FD 策略（O_RDONLY|O_CLOEXEC、regular file、pread 到 EOF）
// ---------------------------------------------------------------------------

/// Kernel 打开 canonical snapshot 文件：O_RDONLY|O_CLOEXEC；非 regular 即策略拒绝。
pub fn open_snapshot_readonly(path: &Path) -> Result<OwnedFd, SnapshotFdError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| err(SNAPSHOT_FD_POLICY_REJECTED, "snapshot path contains a NUL byte"))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(err(SNAPSHOT_FD_POLICY_REJECTED, format!("cannot open the snapshot source read-only with O_CLOEXEC (errno {})", errno())));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(err(SNAPSHOT_FD_POLICY_REJECTED, format!("fstat on the snapshot descriptor failed (errno {})", errno())));
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(err(SNAPSHOT_FD_POLICY_REJECTED, "the snapshot descriptor must reference a regular file"));
    }
    Ok(owned)
}

/// pread(fd, offset=0) 直到 fstat 长度耗尽并在 EOF 做最终读取；不重序列化。
pub fn read_snapshot_fd_bytes(fd: impl AsFd) -> Result<Vec<u8>, SnapshotFdError> {
    let raw = fd.as_fd().as_raw_fd();
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(raw, &mut stat) } != 0 {
        return Err(err(SNAPSHOT_FD_POLICY_REJECTED, format!("fstat on the snapshot descriptor failed (errno {})", errno())));
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(err(SNAPSHOT_FD_POLICY_REJECTED, "the snapshot descriptor must reference a regular file"));
    }
    let expected = stat.st_size.max(0) as usize;
    let mut out = Vec::with_capacity(expected);
    let mut offset = 0usize;
    loop {
        let mut chunk = [0u8; 8192];
        let n = unsafe { libc::pread(raw, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len(), offset as libc::off_t) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(err(SNAPSHOT_TRANSPORT_IO, format!("pread on the snapshot descriptor failed (errno {})", errno())));
        }
        let n = n as usize;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        offset += n;
    }
    if out.len() != expected {
        return Err(err(SNAPSHOT_FD_POLICY_REJECTED, "snapshot bytes changed length while reading; the descriptor must be immutable"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Kernel 侧固定路径 / inode / 对端凭据（SupervisorSocketAuthV1 复查规则的 raw 复用）
// ---------------------------------------------------------------------------

/// 期望的 socket 属主（resolved `iweb-sandbox` 数值对；由部署解析，Kernel 不猜测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotSocketPeer {
    pub uid: u32,
    pub gid: u32,
}

/// 配置路径必须逐字节等于固定字面量（空/相对/备选一律 SNAPSHOT_SOCKET_PATH_REJECTED，
/// 绝不回退固定路径、绝不尝试 TCP）。
pub fn validate_configured_snapshot_socket_path(configured: &str) -> Result<(), SnapshotFdError> {
    if configured != SNAPSHOT_FD_SOCKET_PATH {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the snapshot fd socket path must equal the fixed literal /run/iweb-sandbox/snapshot-fd.sock; empty, relative, alternate, symlinked, or TCP paths are rejected with no fallback"));
    }
    Ok(())
}

fn lstat_path(path: &Path) -> Result<libc::stat, SnapshotFdError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| err(SNAPSHOT_SOCKET_PATH_REJECTED, "socket path contains a NUL byte"))?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, format!("lstat on the configured socket path failed (errno {})", errno())));
    }
    Ok(stat)
}

/// 连接前/连接后的同套复查：socket inode、属主等于期望对、mode 0600、父目录非
/// symlink、mode 0700、同属主（spec：两 socket 共享 SupervisorSocketAuthV1 复查）。
pub fn inspect_snapshot_socket_path(path: &Path, expected_owner: &SnapshotSocketPeer) -> Result<(), SnapshotFdError> {
    let stat = lstat_path(path)?;
    if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the configured socket path is a symlink"));
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the configured socket path is not a socket inode"));
    }
    if stat.st_uid != expected_owner.uid || stat.st_gid != expected_owner.gid {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the socket inode owner does not equal the resolved supervisor uid/gid pair"));
    }
    if stat.st_mode & 0o7777 != 0o600 {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the socket inode mode must be exactly 0600"));
    }
    let parent = path.parent().unwrap_or(Path::new("/"));
    let parent_stat = lstat_path(parent)?;
    if parent_stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the socket parent directory is a symlink"));
    }
    if parent_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the socket parent is not a directory"));
    }
    if parent_stat.st_mode & 0o7777 != 0o700 {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the socket parent directory mode must be exactly 0700"));
    }
    if parent_stat.st_uid != expected_owner.uid || parent_stat.st_gid != expected_owner.gid {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "the socket parent directory owner does not equal the resolved supervisor uid/gid pair"));
    }
    Ok(())
}

/// SOCK_CLOEXEC：Linux 有原子 flag；BSD/macOS 以 fcntl(F_SETFD, FD_CLOEXEC) 等价补齐。
#[cfg(target_os = "linux")]
const SOCK_CLOEXEC_FLAG: libc::c_int = libc::SOCK_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const SOCK_CLOEXEC_FLAG: libc::c_int = 0;

fn set_cloexec(fd: libc::c_int) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags >= 0 {
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

fn seqpacket_socket() -> Result<OwnedFd, SnapshotFdError> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | SOCK_CLOEXEC_FLAG, 0) };
    if fd >= 0 {
        set_cloexec(fd);
        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let code = errno();
    if code == libc::EPROTONOSUPPORT || code == libc::EPROTOTYPE || code == libc::EAFNOSUPPORT || code == libc::ENOSYS {
        return Err(err(SNAPSHOT_TRANSPORT_UNAVAILABLE, "AF_UNIX SOCK_SEQPACKET is unavailable on this host; the snapshot fd transport fails closed instead of degrading to another socket type"));
    }
    Err(err(SNAPSHOT_TRANSPORT_IO, format!("socket(AF_UNIX, SOCK_SEQPACKET) failed with errno {code}")))
}

/// getsockopt(SO_TYPE) 必须仍是 SOCK_SEQPACKET（socket type 拒绝归属 SNAPSHOT_FRAME_INVALID）。
pub fn require_seqpacket_socket(sock: impl AsFd) -> Result<(), SnapshotFdError> {
    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut socket_type as *mut libc::c_int as *mut libc::c_void,
            &mut length,
        )
    };
    if rc != 0 {
        return Err(err(SNAPSHOT_FRAME_INVALID, format!("getsockopt(SO_TYPE) failed with errno {}", errno())));
    }
    if socket_type != libc::SOCK_SEQPACKET as libc::c_int {
        return Err(err(SNAPSHOT_FRAME_INVALID, "the snapshot fd transport requires a SOCK_SEQPACKET socket; any other socket type is rejected"));
    }
    Ok(())
}

/// SO_PEERCRED 对端凭据调用点：Kernel 要求对端是 resolved `iweb-sandbox` 数值对。
/// Linux 专用；其他平台按 spec「missing/unavailable credential」失败关闭。
#[cfg(target_os = "linux")]
pub fn require_peer_credentials(sock: impl AsFd, expected: &SnapshotSocketPeer) -> Result<(), SnapshotFdError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if rc != 0 {
        return Err(err(SUPERVISOR_PEER_CREDENTIALS_REJECTED, format!("SO_PEERCRED is unavailable on the accepted socket (errno {})", errno())));
    }
    if credentials.uid != expected.uid || credentials.gid != expected.gid {
        return Err(err(SUPERVISOR_PEER_CREDENTIALS_REJECTED, "peer credentials do not equal the resolved supervisor uid/gid pair"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn require_peer_credentials(_sock: impl AsFd, _expected: &SnapshotSocketPeer) -> Result<(), SnapshotFdError> {
    Err(err(SUPERVISOR_PEER_CREDENTIALS_REJECTED, "SO_PEERCRED requires Linux; a non-Linux host fails closed instead of accepting unverified peers"))
}

/// 连接（lstat 复查 → SOCK_SEQPACKET socket → connect → 复查 → SO_TYPE → SO_PEERCRED）。
/// 调用方先以 validate_configured_snapshot_socket_path 证明固定字面量。
pub fn connect_snapshot_socket(path: &Path, expected_owner: &SnapshotSocketPeer) -> Result<OwnedFd, SnapshotFdError> {
    inspect_snapshot_socket_path(path, expected_owner)?;
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| err(SNAPSHOT_SOCKET_PATH_REJECTED, "socket path contains a NUL byte"))?;
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if c_path.as_bytes_with_nul().len() > address.sun_path.len() {
        return Err(err(SNAPSHOT_SOCKET_PATH_REJECTED, "socket path exceeds the sockaddr_un sun_path capacity"));
    }
    let sock = seqpacket_socket()?;
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            c_path.as_ptr() as *const u8,
            address.sun_path.as_mut_ptr() as *mut u8,
            c_path.as_bytes_with_nul().len(),
        );
    }
    let raw = sock.as_fd().as_raw_fd();
    loop {
        let rc = unsafe {
            libc::connect(
                raw,
                &address as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            break;
        }
        match errno() {
            libc::EINTR => continue,
            code => return Err(err(SNAPSHOT_TRANSPORT_IO, format!("connect to the snapshot fd socket failed with errno {code}"))),
        }
    }
    // 连接后复查（击败路径替换）+ socket type + 对端凭据。
    inspect_snapshot_socket_path(path, expected_owner)?;
    require_seqpacket_socket(&sock)?;
    require_peer_credentials(&sock, expected_owner)?;
    Ok(sock)
}

// ---------------------------------------------------------------------------
// Kernel 端单帧投递流：open(O_RDONLY) → connect → 单 sendmsg(单 FD, MSG_EOR) → recv ack
// ---------------------------------------------------------------------------

pub struct SnapshotHandoffDelivery<'a> {
    /// 已通过 validate_configured_snapshot_socket_path 的固定字面量路径。
    pub socket_path: &'a Path,
    /// resolved `iweb-sandbox` 数值对（socket 属主 = 对端凭据期望）。
    pub expected_owner: SnapshotSocketPeer,
    /// 完整 handoff payload（secret 或 config；fdDigest 由调用方以本模块公式计算）。
    pub handoff: SnapshotHandoffPayload,
    /// canonical snapshot 文件（/data/kernel/{secrets,config}/snapshots/<ref>.json）。
    pub snapshot_path: &'a Path,
}

/// 单帧投递 + ack 回核。连接在 accepted ack 后由 OwnedFd drop 关闭
/// （spec：Kernel closes the raw connection after the accepted acknowledgements）。
/// supervisor 的 rejected ack 以 `RejectedBySupervisor` 交付（failureCode 是 supervisor
/// 的 wire 稳定码，属运行期字符串，不能塞进 SnapshotFdError 的 'static code）。
pub fn deliver_snapshot_handoff(delivery: &SnapshotHandoffDelivery<'_>) -> Result<SnapshotDeliveryOutcome, SnapshotFdError> {
    let descriptor = open_snapshot_readonly(delivery.snapshot_path)?;
    let sock = connect_snapshot_socket(delivery.socket_path, &delivery.expected_owner)?;
    let frame = delivery.handoff.encode_frame()?;
    send_snapshot_frame_with_descriptor(&sock, &frame, &descriptor)?;
    let ack = receive_snapshot_ack(&sock, &delivery.handoff)?;
    match ack.status {
        SnapshotAckStatus::Accepted => Ok(SnapshotDeliveryOutcome::Accepted(ack)),
        SnapshotAckStatus::Rejected => Ok(SnapshotDeliveryOutcome::RejectedBySupervisor(ack)),
    }
}

/// 单帧投递结果：supervisor 的拒绝是带 failureCode 的正常 wire 结果，不是传输错误。
#[derive(Debug, Clone, PartialEq)]
pub enum SnapshotDeliveryOutcome {
    Accepted(SnapshotFdAckV1),
    RejectedBySupervisor(SnapshotFdAckV1),
}

// ---------------------------------------------------------------------------
// 测试辅助：临时目录 + 属主（本机 uid/gid）与 0700/0600 布置
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_support {
    use super::*;
    use std::os::fd::RawFd;

    pub fn current_peer() -> SnapshotSocketPeer {
        SnapshotSocketPeer { uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() } }
    }

    pub struct TempSocketDir {
        pub dir: std::path::PathBuf,
    }

    impl TempSocketDir {
        pub fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("iweb-snapshot-fd-{label}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            set_mode(&dir, 0o700);
            Self { dir }
        }

        pub fn socket_path(&self) -> std::path::PathBuf {
            self.dir.join("snapshot-fd.sock")
        }
    }

    impl Drop for TempSocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.socket_path());
            let _ = std::fs::remove_dir(&self.dir);
        }
    }

    pub fn set_mode(path: &Path, mode: libc::mode_t) {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("temp path is NUL-free");
        let rc = unsafe { libc::chmod(c_path.as_ptr(), mode) };
        assert_eq!(rc, 0, "chmod must succeed on the temp fixture");
    }

    /// 绑定一个指定类型的 AF_UNIX listening socket（对拍 supervisor 端用；macOS 用
    /// SOCK_DGRAM 作为 ancillary 往返载体，Linux 用 SOCK_SEQPACKET 走完整语义）。
    pub fn bind_unix_listener(path: &Path, socket_kind: i32) -> RawFd {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("temp path is NUL-free");
        let fd = unsafe { libc::socket(libc::AF_UNIX, socket_kind | SOCK_CLOEXEC_FLAG, 0) };
        assert!(fd >= 0, "socket() for the test listener must succeed");
        set_cloexec(fd);
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        unsafe {
            std::ptr::copy_nonoverlapping(
                c_path.as_ptr() as *const u8,
                address.sun_path.as_mut_ptr() as *mut u8,
                c_path.as_bytes_with_nul().len(),
            );
        }
        let rc = unsafe {
            libc::bind(
                fd,
                &address as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "bind must succeed on the test listener");
        if socket_kind == libc::SOCK_SEQPACKET {
            assert_eq!(unsafe { libc::listen(fd, 1) }, 0, "listen must succeed on the seqpacket test listener");
        }
        set_mode(path, 0o600);
        fd
    }

    pub fn connect_unix(path: &Path, socket_kind: i32) -> RawFd {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("temp path is NUL-free");
        let fd = unsafe { libc::socket(libc::AF_UNIX, socket_kind | SOCK_CLOEXEC_FLAG, 0) };
        assert!(fd >= 0, "client socket must be created");
        set_cloexec(fd);
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        unsafe {
            std::ptr::copy_nonoverlapping(
                c_path.as_ptr() as *const u8,
                address.sun_path.as_mut_ptr() as *mut u8,
                c_path.as_bytes_with_nul().len(),
            );
        }
        let rc = unsafe {
            libc::connect(
                fd,
                &address as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "client connect must succeed");
        fd
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::os::fd::{AsRawFd, BorrowedFd};

    const VECTOR_PAYLOAD_HEX: &str = "7b22736368656d6156657273696f6e223a317d";
    // spec 打印的 header 字面量 `495745424644310000010100000013`（30 个 hex 字符）与
    // 其自身规范性约束自相矛盾：offset 表固定 headerBytes:16、payloadLength 为
    // offset 12..15 的 u32-BE，且 spec 同句声明 total frame length 35 = 16+19。
    // 按规范性 offset 表复算的唯一 header 是下面的 32 字符值（u32-BE 19 = 00000013，
    // 打印字面量恰好少了长度域的一对 "00"）。实现以 offset 表 + total 35 为准；
    // 该 spec 字面量笔误需编排者在 openspec 侧勘误。
    const VECTOR_HEADER_HEX: &str = "49574542464431000001010000000013";

    fn example_secret_handoff() -> SecretSnapshotFdHandoffV1 {
        SecretSnapshotFdHandoffV1 {
            schema_version: 1,
            kind: "secret".to_string(),
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".to_string(),
            command_digest: "1".repeat(64),
            reference: "5".repeat(64),
            application_id: "vector".to_string(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            secret_revision: 3,
            values_digest: "6".repeat(64),
            fd_digest: "9".repeat(64),
            expires_at: "2026-09-01T00:00:00Z".to_string(),
        }
    }

    fn example_config_handoff() -> ConfigSnapshotFdHandoffV1 {
        ConfigSnapshotFdHandoffV1 {
            schema_version: 1,
            kind: "config".to_string(),
            command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".to_string(),
            command_digest: "1".repeat(64),
            reference: "7".repeat(64),
            application_id: "vector".to_string(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            config_revision: 2,
            values_digest: "8".repeat(64),
            fd_digest: "a".repeat(64),
            expires_at: "2026-09-01T00:00:00Z".to_string(),
        }
    }

    fn facts_request_ok() -> SnapshotRecvAncillaryFacts {
        SnapshotRecvAncillaryFacts { eor: true, truncated: false, control_truncated: false, control_message_count: 1, descriptor_count: 1 }
    }

    // --- 固定向量 -----------------------------------------------------------

    #[test]
    fn framing_vector_is_byte_exact() {
        let payload = hex::decode(VECTOR_PAYLOAD_HEX).unwrap();
        assert_eq!(payload, b"{\"schemaVersion\":1}");
        let frame = encode_snapshot_frame(SnapshotFrameKind::SecretRequest, &payload).unwrap();
        assert_eq!(frame.len(), 35, "total frame length must be 35 bytes");
        assert_eq!(hex::encode(&frame[..SNAPSHOT_FRAME_HEADER_BYTES]), VECTOR_HEADER_HEX);
        assert_eq!(hex::encode(&frame), format!("{VECTOR_HEADER_HEX}{VECTOR_PAYLOAD_HEX}"));
        let header = parse_snapshot_frame_header(&frame).unwrap();
        assert_eq!(header.kind, SnapshotFrameKind::SecretRequest);
        assert_eq!(header.payload_length, 19);
    }

    #[test]
    fn vector_boundary_is_accepted_then_payload_rejected_as_wire_invalid() {
        let frame = encode_snapshot_frame(SnapshotFrameKind::SecretRequest, &hex::decode(VECTOR_PAYLOAD_HEX).unwrap()).unwrap();
        // 边界必须被接受（预解析不报长度/magic 错误）。
        let header = parse_snapshot_frame_header(&frame).unwrap();
        // ancillary 判定独立通过。
        validate_request_ancillary(&facts_request_ok()).unwrap();
        // payload 因缺失 handoff 字段拒绝为 SNAPSHOT_WIRE_INVALID（绝不是 FRAME）。
        let rejected = SnapshotHandoffPayload::parse(header.kind, &frame[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_WIRE_INVALID, "the fixed vector must be rejected for its missing handoff fields, never as a length or magic error");
    }

    #[test]
    fn vector_with_appended_byte_is_frame_invalid() {
        let mut frame = encode_snapshot_frame(SnapshotFrameKind::SecretRequest, &hex::decode(VECTOR_PAYLOAD_HEX).unwrap()).unwrap();
        frame.push(0x00);
        let rejected = parse_snapshot_frame_header(&frame).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_FRAME_INVALID);
    }

    // --- 预解析拒绝 ---------------------------------------------------------

    #[test]
    fn header_rejections_are_frame_invalid() {
        let payload = b"{\"schemaVersion\":1}".to_vec();
        let base = encode_snapshot_frame(SnapshotFrameKind::SecretRequest, &payload).unwrap();

        let mut wrong_magic = base.clone();
        wrong_magic[0] = b'X';
        assert_eq!(parse_snapshot_frame_header(&wrong_magic).unwrap_err().code, SNAPSHOT_FRAME_INVALID);

        let mut wrong_version = base.clone();
        wrong_version[8] = 0x00;
        wrong_version[9] = 0x02;
        assert_eq!(parse_snapshot_frame_header(&wrong_version).unwrap_err().code, SNAPSHOT_FRAME_INVALID);

        let mut wrong_flags = base.clone();
        wrong_flags[11] = 0x01;
        assert_eq!(parse_snapshot_frame_header(&wrong_flags).unwrap_err().code, SNAPSHOT_FRAME_INVALID);

        let mut zero_length = base.clone();
        zero_length[12..16].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(parse_snapshot_frame_header(&zero_length).unwrap_err().code, SNAPSHOT_FRAME_INVALID);

        let mut oversize_length = base.clone();
        oversize_length[12..16].copy_from_slice(&65_537u32.to_be_bytes());
        assert_eq!(parse_snapshot_frame_header(&oversize_length).unwrap_err().code, SNAPSHOT_FRAME_INVALID);

        let mut unknown_type = base.clone();
        unknown_type[10] = 0x03;
        assert_eq!(parse_snapshot_frame_header(&unknown_type).unwrap_err().code, SNAPSHOT_FRAME_INVALID);

        let mut truncated = base.clone();
        truncated.truncate(10);
        assert_eq!(parse_snapshot_frame_header(&truncated).unwrap_err().code, SNAPSHOT_FRAME_INVALID);

        // 头声明长度与包长不一致。
        let mut short_packet = base.clone();
        short_packet.pop();
        assert_eq!(parse_snapshot_frame_header(&short_packet).unwrap_err().code, SNAPSHOT_FRAME_INVALID);
    }

    #[test]
    fn http_on_raw_socket_is_rejected_before_parsing() {
        let post = b"POST /v1/execution-rpc HTTP/1.1\r\nHost: supervisor\r\n\r\n";
        let get = b"GET /v1/rpc HTTP/1.1\r\nHost: supervisor\r\n\r\n";
        let status_line = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        for packet in [post.as_slice(), get.as_slice(), status_line.as_slice()] {
            let rejected = parse_snapshot_frame_header(packet).unwrap_err();
            assert_eq!(rejected.code, SNAPSHOT_HTTP_ON_RAW_SOCKET, "HTTP bytes on the raw socket must be classified SNAPSHOT_HTTP_ON_RAW_SOCKET");
        }
    }

    #[test]
    fn ancillary_rejections_are_frame_invalid() {
        let mut facts = facts_request_ok();
        facts.eor = false;
        assert_eq!(validate_request_ancillary(&facts).unwrap_err().code, SNAPSHOT_FRAME_INVALID);
        facts = facts_request_ok();
        facts.truncated = true;
        assert_eq!(validate_request_ancillary(&facts).unwrap_err().code, SNAPSHOT_FRAME_INVALID);
        facts = facts_request_ok();
        facts.control_truncated = true;
        assert_eq!(validate_request_ancillary(&facts).unwrap_err().code, SNAPSHOT_FRAME_INVALID);
        facts = facts_request_ok();
        facts.descriptor_count = 0;
        assert_eq!(validate_request_ancillary(&facts).unwrap_err().code, SNAPSHOT_FRAME_INVALID, "a missing descriptor is rejected");
        facts.descriptor_count = 2;
        assert_eq!(validate_request_ancillary(&facts).unwrap_err().code, SNAPSHOT_FRAME_INVALID, "two descriptors in one request are rejected");
        facts = facts_request_ok();
        facts.control_message_count = 2;
        assert_eq!(validate_request_ancillary(&facts).unwrap_err().code, SNAPSHOT_FRAME_INVALID, "extra control messages are rejected");
        // ack：任何描述符/控制消息都拒绝。
        let mut ack_facts = SnapshotRecvAncillaryFacts { eor: true, truncated: false, control_truncated: false, control_message_count: 0, descriptor_count: 0 };
        validate_ack_ancillary(&ack_facts).unwrap();
        ack_facts.descriptor_count = 1;
        assert_eq!(validate_ack_ancillary(&ack_facts).unwrap_err().code, SNAPSHOT_FRAME_INVALID);
    }

    // --- payload 契约 -------------------------------------------------------

    #[test]
    fn handoff_payload_round_trip_and_kind_agreement() {
        let secret = SnapshotHandoffPayload::Secret(example_secret_handoff());
        let frame = secret.encode_frame().unwrap();
        let header = parse_snapshot_frame_header(&frame).unwrap();
        assert_eq!(header.kind, SnapshotFrameKind::SecretRequest);
        let parsed = SnapshotHandoffPayload::parse(header.kind, &frame[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap();
        assert_eq!(parsed, secret);

        let config = SnapshotHandoffPayload::Config(example_config_handoff());
        let frame = config.encode_frame().unwrap();
        let header = parse_snapshot_frame_header(&frame).unwrap();
        assert_eq!(header.kind, SnapshotFrameKind::ConfigRequest);
        assert_eq!(SnapshotHandoffPayload::parse(header.kind, &frame[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap(), config);

        // kind 与 frameType 交叉：secret payload 放进 config 帧被 WIRE 拒绝。
        let secret_bytes = handoff_jcs_bytes(&secret).unwrap();
        let crossed = encode_snapshot_frame(SnapshotFrameKind::ConfigRequest, &secret_bytes).unwrap();
        let header = parse_snapshot_frame_header(&crossed).unwrap();
        let rejected = SnapshotHandoffPayload::parse(header.kind, &crossed[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_WIRE_INVALID);
    }

    #[test]
    fn handoff_payload_rejects_unknown_fields_and_non_canonical_bytes() {
        // 未知字段（JCS 键序下插入 extra）。
        let extended = format!(
            "{{\"applicationId\":\"vector\",\"commandDigest\":\"{}\",\"commandId\":\"018f1e2c-3d4b-7a5e-9f01-23456789abcd\",\"expiresAt\":\"2026-09-01T00:00:00Z\",\"extra\":1,\"fdDigest\":\"{}\",\"kind\":\"secret\",\"preparationGeneration\":1,\"ref\":\"{}\",\"schemaVersion\":1,\"secretRevision\":3,\"valuesDigest\":\"{}\",\"versionId\":\"{}-1\"}}",
            "1".repeat(64),
            "9".repeat(64),
            "5".repeat(64),
            "6".repeat(64),
            "a".repeat(64),
        );
        let frame = encode_snapshot_frame(SnapshotFrameKind::SecretRequest, extended.as_bytes()).unwrap();
        let header = parse_snapshot_frame_header(&frame).unwrap();
        let rejected = SnapshotHandoffPayload::parse(header.kind, &frame[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_WIRE_INVALID);

        // 非 JCS 字节（键序偏差）：parse 后重序列化不等于原始字节。
        let reordered = format!(
            "{{\"kind\":\"secret\",\"schemaVersion\":1,\"commandId\":\"018f1e2c-3d4b-7a5e-9f01-23456789abcd\",\"commandDigest\":\"{}\",\"ref\":\"{}\",\"applicationId\":\"vector\",\"versionId\":\"{}-1\",\"preparationGeneration\":1,\"secretRevision\":3,\"valuesDigest\":\"{}\",\"fdDigest\":\"{}\",\"expiresAt\":\"2026-09-01T00:00:00Z\"}}",
            "1".repeat(64),
            "5".repeat(64),
            "a".repeat(64),
            "6".repeat(64),
            "9".repeat(64),
        );
        let frame = encode_snapshot_frame(SnapshotFrameKind::SecretRequest, reordered.as_bytes()).unwrap();
        let header = parse_snapshot_frame_header(&frame).unwrap();
        let rejected = SnapshotHandoffPayload::parse(header.kind, &frame[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_WIRE_INVALID, "payload bytes must equal JCS(parse(bytes))");

        // 非法文法（versionId 形状）。
        let mut invalid = example_secret_handoff();
        invalid.version_id = "not-a-version".to_string();
        let frame = SnapshotHandoffPayload::Secret(invalid).encode_frame().unwrap();
        let header = parse_snapshot_frame_header(&frame).unwrap();
        let rejected = SnapshotHandoffPayload::parse(header.kind, &frame[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_WIRE_INVALID);
    }

    #[test]
    fn digest_formulas_are_domain_separated_single_sha256() {
        let fd_bytes = b"{\"applicationId\":\"vector\"}";
        let secret_digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, fd_bytes).unwrap();
        let config_digest = compute_snapshot_fd_digest(SnapshotFrameKind::ConfigRequest, fd_bytes).unwrap();
        // 手工复算：单次 SHA-256(domain "\n" bytes)。
        let mut expected = Sha256::new();
        expected.update(b"iweb-secret-snapshot-v1\n");
        expected.update(fd_bytes);
        assert_eq!(secret_digest, hex::encode(expected.finalize()));
        assert_ne!(secret_digest, config_digest, "secret/config domains must produce distinct digests");

        let handoff = SnapshotHandoffPayload::Secret(example_secret_handoff());
        let digest = compute_snapshot_handoff_digest(&handoff).unwrap();
        let mut expected = Sha256::new();
        expected.update(b"iweb-snapshot-handoff-v1\n");
        expected.update(handoff_jcs_bytes(&handoff).unwrap());
        assert_eq!(digest, hex::encode(expected.finalize()));
    }

    #[test]
    fn ack_payload_contract() {
        let handoff = SnapshotHandoffPayload::Secret(example_secret_handoff());
        let ack = SnapshotFdAckV1 {
            schema_version: 1,
            kind: "ack".to_string(),
            command_id: handoff.command_id().to_string(),
            handoff_digest: compute_snapshot_handoff_digest(&handoff).unwrap(),
            status: SnapshotAckStatus::Accepted,
            failure_code: None,
            journal_revision: 5,
        };
        let frame = ack.encode_frame().unwrap();
        let header = parse_snapshot_frame_header(&frame).unwrap();
        assert_eq!(header.kind, SnapshotFrameKind::Acknowledgement);
        assert_eq!(header.kind.frame_type(), 0x81);
        let parsed = SnapshotFdAckV1::parse(header.kind, &frame[SNAPSHOT_FRAME_HEADER_BYTES..]).unwrap();
        assert_eq!(parsed, ack);
        assert_eq!(parsed.handoff_digest, compute_snapshot_handoff_digest(&handoff).unwrap());
        assert_eq!(parsed.command_id, handoff.command_id());

        // rejected ack：failureCode 必须非空且匹配稳定码文法。
        let rejected_ack = SnapshotFdAckV1 {
            status: SnapshotAckStatus::Rejected,
            failure_code: Some("SNAPSHOT_VALUES_DIGEST_MISMATCH".to_string()),
            ..ack.clone()
        };
        assert!(rejected_ack.validate().is_ok());
        let bad_code = SnapshotFdAckV1 {
            failure_code: Some("lower-case".to_string()),
            ..rejected_ack.clone()
        };
        assert_eq!(bad_code.validate().unwrap_err().code, SNAPSHOT_WIRE_INVALID);
        let accepted_with_code = SnapshotFdAckV1 { failure_code: Some("SNAPSHOT_FRAME_INVALID".to_string()), ..ack.clone() };
        assert_eq!(accepted_with_code.validate().unwrap_err().code, SNAPSHOT_WIRE_INVALID);
        let rejected_without_code = SnapshotFdAckV1 { status: SnapshotAckStatus::Rejected, failure_code: None, ..ack };
        assert_eq!(rejected_without_code.validate().unwrap_err().code, SNAPSHOT_WIRE_INVALID);
    }

    // --- 固定路径 / inode / 属主 / mode ------------------------------------

    #[test]
    fn configured_path_must_be_the_fixed_literal() {
        assert!(validate_configured_snapshot_socket_path(SNAPSHOT_FD_SOCKET_PATH).is_ok());
        for bad in [
            "",
            "/tmp/supervisor.sock",
            "run/iweb-sandbox/snapshot-fd.sock",
            "/run/iweb-sandbox/snapshot-fd.sock/",
            "/run/iweb-sandbox/snapshot-fd.sock.extra",
        ] {
            assert_eq!(
                validate_configured_snapshot_socket_path(bad).unwrap_err().code,
                SNAPSHOT_SOCKET_PATH_REJECTED,
                "alternate path {bad:?} must be rejected with no fallback"
            );
        }
    }

    #[test]
    fn socket_inode_checks_reject_wrong_shape_owner_and_mode() {
        let tmp = TempSocketDir::new("inode");
        let peer = current_peer();

        // 非 socket 文件。
        let regular = tmp.dir.join("regular.sock");
        std::fs::write(&regular, b"not a socket").unwrap();
        assert_eq!(inspect_snapshot_socket_path(&regular, &peer).unwrap_err().code, SNAPSHOT_SOCKET_PATH_REJECTED);

        // symlink 指向合法 socket 也拒绝（lstat 抓 S_IFLNK）。
        let real = tmp.socket_path();
        let listener = bind_unix_listener(&real, libc::SOCK_DGRAM);
        let link = tmp.dir.join("link.sock");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(inspect_snapshot_socket_path(&link, &peer).unwrap_err().code, SNAPSHOT_SOCKET_PATH_REJECTED);

        // mode 偏差。
        set_mode(&real, 0o644);
        assert_eq!(inspect_snapshot_socket_path(&real, &peer).unwrap_err().code, SNAPSHOT_SOCKET_PATH_REJECTED);
        set_mode(&real, 0o600);
        assert!(inspect_snapshot_socket_path(&real, &peer).is_ok());

        // 属主偏差（与 peer uid 必不相同：0x5a5a 非零）。
        let wrong = SnapshotSocketPeer { uid: peer.uid ^ 0x5a5a, gid: peer.gid };
        assert_eq!(inspect_snapshot_socket_path(&real, &wrong).unwrap_err().code, SNAPSHOT_SOCKET_PATH_REJECTED);

        // 父目录 mode 偏差。
        set_mode(&tmp.dir, 0o755);
        assert_eq!(inspect_snapshot_socket_path(&real, &peer).unwrap_err().code, SNAPSHOT_SOCKET_PATH_REJECTED);
        set_mode(&tmp.dir, 0o700);

        unsafe { libc::close(listener) };
    }

    #[test]
    fn socket_type_check_rejects_non_seqpacket() {
        let tmp = TempSocketDir::new("sotype");
        let path = tmp.socket_path();
        let listener = bind_unix_listener(&path, libc::SOCK_DGRAM);
        let client = connect_unix(&path, libc::SOCK_DGRAM);
        assert_eq!(
            require_seqpacket_socket(unsafe { BorrowedFd::borrow_raw(client) }).unwrap_err().code,
            SNAPSHOT_FRAME_INVALID
        );
        unsafe {
            libc::close(client);
            libc::close(listener);
        }
    }

    #[test]
    fn peer_credentials_fail_closed_off_linux() {
        let tmp = TempSocketDir::new("peercred");
        let path = tmp.socket_path();
        let listener = bind_unix_listener(&path, libc::SOCK_DGRAM);
        let client = connect_unix(&path, libc::SOCK_DGRAM);
        let rejected = require_peer_credentials(unsafe { BorrowedFd::borrow_raw(client) }, &current_peer()).unwrap_err();
        assert_eq!(rejected.code, SUPERVISOR_PEER_CREDENTIALS_REJECTED);
        unsafe {
            libc::close(client);
            libc::close(listener);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_credentials_accept_current_principal_on_linux() {
        let tmp = TempSocketDir::new("peercred-linux");
        let path = tmp.socket_path();
        let listener = bind_unix_listener(&path, libc::SOCK_SEQPACKET);
        let client = connect_unix(&path, libc::SOCK_SEQPACKET);
        assert!(require_peer_credentials(unsafe { BorrowedFd::borrow_raw(client) }, &current_peer()).is_ok());
        let wrong = SnapshotSocketPeer { uid: current_peer().uid + 1, gid: current_peer().gid };
        assert_eq!(
            require_peer_credentials(unsafe { BorrowedFd::borrow_raw(client) }, &wrong).unwrap_err().code,
            SUPERVISOR_PEER_CREDENTIALS_REJECTED
        );
        unsafe {
            libc::close(client);
            libc::close(listener);
        }
    }

    // --- FD 策略 -----------------------------------------------------------

    #[test]
    fn snapshot_fd_policy_requires_regular_readonly_file() {
        let tmp = TempSocketDir::new("fdpolicy");
        let file_path = tmp.dir.join("snapshot.json");
        let body = b"{\"schemaVersion\":1}".to_vec();
        std::fs::write(&file_path, &body).unwrap();
        let fd = open_snapshot_readonly(&file_path).unwrap();
        // 打开 flags 必须是 O_RDONLY（F_GETFL 的 access mode 位）。
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
        assert_eq!(read_snapshot_fd_bytes(&fd).unwrap(), body);

        // 目录不是 regular file。
        let rejected = open_snapshot_readonly(&tmp.dir).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_FD_POLICY_REJECTED);

        // F_GETFL 只读断言（supervisor 端对收到描述符的同款检查公式）。
        fn assert_readonly(fd: &OwnedFd) -> Result<(), SnapshotFdError> {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(err(SNAPSHOT_FD_POLICY_REJECTED, "fcntl(F_GETFL) failed on the received descriptor"));
            }
            if flags & libc::O_ACCMODE != libc::O_RDONLY {
                return Err(err(SNAPSHOT_FD_POLICY_REJECTED, "the received descriptor must be read-only"));
            }
            Ok(())
        }
        assert!(assert_readonly(&fd).is_ok());
    }

    // --- ancillary 往返（macOS 以 SOCK_DGRAM 复用同一 sendmsg/recvmsg 核心） ---

    #[test]
    fn scm_rights_roundtrip_carries_frame_bytes_and_single_fd() {
        let tmp = TempSocketDir::new("dgram-roundtrip");
        let path = tmp.socket_path();
        let listener = bind_unix_listener(&path, libc::SOCK_DGRAM);
        let client = connect_unix(&path, libc::SOCK_DGRAM);

        let snapshot_path = tmp.dir.join("snapshot.json");
        let fd_bytes = b"{\"applicationId\":\"vector\"}".to_vec();
        std::fs::write(&snapshot_path, &fd_bytes).unwrap();
        let descriptor = open_snapshot_readonly(&snapshot_path).unwrap();

        let handoff = SnapshotHandoffPayload::Secret(example_secret_handoff());
        let frame = handoff.encode_frame().unwrap();
        // DGRAM 上不传 MSG_EOR（macOS 会 EINVAL）；ancillary 构造/解析与 seqpacket 完全共享。
        sendmsg_frame_with_single_descriptor(unsafe { BorrowedFd::borrow_raw(client) }, &frame, &descriptor, 0).unwrap();

        let packet = recvmsg_snapshot_packet(unsafe { BorrowedFd::borrow_raw(listener) }).unwrap();
        assert_eq!(packet.bytes, frame, "received bytes must equal the single complete frame");
        assert_eq!(packet.descriptors.len(), 1, "exactly one descriptor must arrive");
        assert_eq!(packet.facts.control_message_count, 1);
        assert_eq!(read_snapshot_fd_bytes(&packet.descriptors[0]).unwrap(), fd_bytes, "the received descriptor must read the exact snapshot bytes");

        unsafe {
            libc::close(client);
            libc::close(listener);
        }
    }

    #[test]
    fn two_descriptors_in_one_packet_are_detected() {
        let tmp = TempSocketDir::new("two-fds");
        let path = tmp.socket_path();
        let listener = bind_unix_listener(&path, libc::SOCK_DGRAM);
        let client = connect_unix(&path, libc::SOCK_DGRAM);

        let snapshot_path = tmp.dir.join("snapshot.json");
        std::fs::write(&snapshot_path, b"{}").unwrap();
        let first = open_snapshot_readonly(&snapshot_path).unwrap();
        let second = open_snapshot_readonly(&snapshot_path).unwrap();

        let frame = SnapshotHandoffPayload::Secret(example_secret_handoff()).encode_frame().unwrap();
        let mut iov = libc::iovec { iov_base: frame.as_ptr() as *mut libc::c_void, iov_len: frame.len() };
        let mut control = [0u8; 128];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = cmsg_space(2 * std::mem::size_of::<libc::c_int>()) as _;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = cmsg_len(2 * std::mem::size_of::<libc::c_int>()) as _;
            let fds = [first.as_raw_fd(), second.as_raw_fd()];
            std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(header), std::mem::size_of_val(&fds));
        }
        assert!(unsafe { libc::sendmsg(client, &message, 0) } >= 0);

        let packet = recvmsg_snapshot_packet(unsafe { BorrowedFd::borrow_raw(listener) }).unwrap();
        assert_eq!(packet.facts.descriptor_count, 2, "both descriptors must be counted before rejection");
        let rejected = validate_request_ancillary(&packet.facts).unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_FRAME_INVALID);
        // drop(packet) 关闭全部已收到描述符（OwnedFd 语义）。

        unsafe {
            libc::close(client);
            libc::close(listener);
        }
    }

    // --- Linux 完整 seqpacket 对拍（支持拓扑的真语义） -----------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_seqpacket_full_handoff_exchange_with_supervisor_thread() {
        let tmp = TempSocketDir::new("seqpacket-linux");
        let path = tmp.socket_path();
        let listener = bind_unix_listener(&path, libc::SOCK_SEQPACKET);

        let snapshot_path = tmp.dir.join("snapshot.json");
        let fd_bytes = b"{\"applicationId\":\"vector\",\"preparationGeneration\":1,\"secretRevision\":3,\"keys\":[],\"values\":{}}".to_vec();
        std::fs::write(&snapshot_path, &fd_bytes).unwrap();

        let supervisor = std::thread::spawn(move || {
            let accepted = unsafe { libc::accept4(listener, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
            assert!(accepted >= 0, "supervisor accept must succeed");
            let accepted_fd = unsafe { BorrowedFd::borrow_raw(accepted) };
            assert!(require_peer_credentials(accepted_fd, &current_peer()).is_ok(), "kernel peer must be the current principal in the test topology");
            let (payload, descriptor) = receive_snapshot_request(accepted_fd).expect("supervisor recvmsg must accept the frame");
            let secret = match &payload {
                SnapshotHandoffPayload::Secret(secret) => secret.clone(),
                other => panic!("expected a secret handoff, got {other:?}"),
            };
            let bytes = read_snapshot_fd_bytes(&descriptor).expect("fd bytes must read");
            assert_eq!(bytes, fd_bytes, "received descriptor must carry the exact snapshot bytes");
            let fd_digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &bytes).unwrap();
            assert_eq!(fd_digest, secret.fd_digest, "fdDigest must recompute from the received bytes");
            let ack = SnapshotFdAckV1 {
                schema_version: 1,
                kind: "ack".to_string(),
                command_id: secret.command_id.clone(),
                handoff_digest: compute_snapshot_handoff_digest(&payload).unwrap(),
                status: SnapshotAckStatus::Accepted,
                failure_code: None,
                journal_revision: 7,
            };
            send_snapshot_frame_without_ancillary(accepted_fd, &ack.encode_frame().unwrap()).expect("supervisor ack send must succeed");
            unsafe { libc::close(accepted) };
            unsafe { libc::close(listener) };
        });

        let descriptor = open_snapshot_readonly(&snapshot_path).unwrap();
        let mut handoff = example_secret_handoff();
        handoff.fd_digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &fd_bytes).unwrap();
        let payload = SnapshotHandoffPayload::Secret(handoff);
        let frame = payload.encode_frame().unwrap();
        let sock = connect_snapshot_socket(&path, &current_peer()).expect("kernel connect path (fixed checks + SO_TYPE + peer creds) must pass");
        send_snapshot_frame_with_descriptor(&sock, &frame, &descriptor).expect("kernel single sendmsg must deliver the frame");
        let ack = receive_snapshot_ack(&sock, &payload).expect("kernel must receive and correlate the ack");
        assert_eq!(ack.status, SnapshotAckStatus::Accepted);
        assert_eq!(ack.journal_revision, 7);
        supervisor.join().expect("supervisor thread must complete");
    }

    // --- 非 Linux 的 seqpacket 失败关闭 -------------------------------------

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seqpacket_socket_fails_closed_where_unavailable() {
        // macOS 实证 AF_UNIX SOCK_SEQPACKET 不可用：失败关闭而非降级。
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | SOCK_CLOEXEC_FLAG, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            // 若未来平台提供 seqpacket，本断言提醒更新对拍测试的 cfg 门。
            panic!("AF_UNIX SOCK_SEQPACKET became available on this host; move the full exchange test out of the linux-only cfg gate");
        }
        let rejected = seqpacket_socket().unwrap_err();
        assert_eq!(rejected.code, SNAPSHOT_TRANSPORT_UNAVAILABLE);
    }
}
