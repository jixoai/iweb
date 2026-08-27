//! 用户原始需求（2026-08-27，add-wasm-host-services 任务 5.2）：embedded-host-
//! services-v2 provider 的 canonical host-call frame——u32 big-endian 长度前缀 +
//! 单个 UTF-8 JCS 对象，长度 1..=1048576、无尾随字节；closed HostCallErrorV2 wire；
//! base64url（unpadded）payload 投影。规范权威：design.md §5 与
//! specs/wasm-application-runtime/spec.md「Embedded host-call transport binds identity
//! and has stable replay semantics」。
//!
//! 有效方法对恰为 kv:get|set|delete|list、sql:execute、logging:write；service/method
//! 不匹配 → INVALID_ARGUMENT。outcome:"ok" 要求 result 非 null 且 error null，
//! outcome:"error" 反之（无第三形态）。
//!
//! 帧内二进制值投影（fail-closed 裁决，报告）：payload 是 base64url 字节串（design
//! 原文），其内部编码由 embedded provider 定义为 canonical JCS 投影——潜在非 ASCII
//! 的文本与数值二进制（text/blob 列值、integer 超出 u53、real 的 IEEE-758 位型）一律
//! 以 unpadded base64url 携带，绝不把浮点/非 ASCII 引入 canonical JSON 值域。

use crate::jcs::{err, jcs_bytes, parse_canonical, validate_application_id, validate_fence_nonce, validate_sha256_hex, validate_uuid_v7, validate_version_id, WireError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// 帧长度域上界（design §5：length 1..1048576）。
pub const FRAME_MAX_BYTES: usize = 1_048_576;
/// 协议字面量。
pub const HOST_CALL_PROTOCOL: &str = "iweb-wasmd-host-call-v2";

/// kv/logging 帧的 deadlineMs 上界（sql 用 profile executionMaxMs 钉界；spec 只要求
/// 「bounded by the pinned profile」——kv/logging profile 未定义执行时限字段，取引擎
/// epoch 上界的同一量级 300_000ms 常量并报告）。
pub const HOST_CALL_DEADLINE_MAX_MS: u64 = 300_000;

/// HostCallErrorV2 code 闭集（design §5 逐字；17 个，无新增面）。
pub const HOST_CALL_ERROR_CODES: &[&str] = &[
    "INVALID_FRAME",
    "IDENTITY_MISMATCH",
    "POLICY_MISMATCH",
    "STALE_EXECUTION",
    "APP_ISOLATION",
    "INVALID_ARGUMENT",
    "NOT_FOUND",
    "CONFLICT",
    "QUOTA_EXCEEDED",
    "LIMIT_EXCEEDED",
    "BUSY",
    "TIMEOUT",
    "CANCELLED",
    "UNAVAILABLE",
    "INTERNAL",
    "REQUEST_ID_CONFLICT",
    "REPLAY_UNAVAILABLE",
];

/// detailCode 的有界长度（bounded opaque code；绝不含 SQL/KV/日志正文或路径）。
pub const HOST_CALL_DETAIL_MAX_BYTES: usize = 128;

/// 合法 (service, method) 对（design §5「The only method pairs are ...」）。
pub const HOST_CALL_METHODS: &[(&str, &str)] = &[
    ("kv", "get"),
    ("kv", "set"),
    ("kv", "delete"),
    ("kv", "list"),
    ("sql", "execute"),
    ("logging", "write"),
];

/// 帧内执行身份（design §5 execution 对象；字段恰好五个）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FrameExecutionV2 {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    #[serde(rename = "executionGeneration")]
    pub execution_generation: u64,
    #[serde(rename = "fenceNonce")]
    pub fence_nonce: String,
}

/// 请求帧对象（design §5 精确键集）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostCallFrameRequestV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub protocol: String,
    pub kind: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub service: String,
    pub method: String,
    pub execution: FrameExecutionV2,
    #[serde(rename = "hostServicePolicyDigest")]
    pub host_service_policy_digest: String,
    #[serde(rename = "deadlineMs")]
    pub deadline_ms: u64,
    /// unpadded base64url（payload 字节串的 JSON 投影）。
    pub payload: String,
}

/// HostCallErrorV2（{code, detailCode}；code ∈ HOST_CALL_ERROR_CODES）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostCallErrorV2 {
    pub code: String,
    #[serde(rename = "detailCode")]
    pub detail_code: Option<String>,
}

impl HostCallErrorV2 {
    pub fn new(code: &str, detail: Option<&str>) -> Self {
        debug_assert!(HOST_CALL_ERROR_CODES.contains(&code), "closed error code set");
        Self {
            code: code.to_string(),
            detail_code: detail.map(str::to_string),
        }
    }
}

/// 响应帧对象（design §5 精确键集；outcome 二值互斥）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostCallFrameResponseV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub protocol: String,
    pub kind: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub execution: FrameExecutionV2,
    #[serde(rename = "hostServicePolicyDigest")]
    pub host_service_policy_digest: String,
    pub outcome: String,
    pub result: Option<String>,
    pub error: Option<HostCallErrorV2>,
}

/// 帧级稳定错误码（传输层；不进 HostCallErrorV2 闭集的内部通道错误）。
pub const HOST_FRAME_INVALID: &str = "WASMD_HOST_FRAME_INVALID";

impl HostCallFrameRequestV2 {
    /// 结构 + 文法 + 方法对校验（不触后端；任何偏差在 INVALID_ARGUMENT/INVALID_FRAME 层拒绝）。
    pub fn validate(&self) -> Result<(), WireError> {
        if self.schema_version != 2 {
            return Err(err(HOST_FRAME_INVALID, "frame schemaVersion must be the literal 2"));
        }
        if self.protocol != HOST_CALL_PROTOCOL {
            return Err(err(HOST_FRAME_INVALID, "frame protocol must be iweb-wasmd-host-call-v2"));
        }
        if self.kind != "request" {
            return Err(err(HOST_FRAME_INVALID, "frame kind must be request"));
        }
        validate_uuid_v7(&self.request_id)?;
        validate_application_id(&self.execution.application_id)?;
        validate_version_id(&self.execution.version_id)?;
        crate::jcs::require_u53(self.execution.preparation_generation, 1, crate::jcs::WASM_U53_MAX, "execution.preparationGeneration")?;
        crate::jcs::require_u53(self.execution.execution_generation, 1, crate::jcs::WASM_U53_MAX, "execution.executionGeneration")?;
        validate_fence_nonce(&self.execution.fence_nonce)?;
        validate_sha256_hex(&self.host_service_policy_digest, "hostServicePolicyDigest")?;
        if self.deadline_ms == 0 || self.deadline_ms > HOST_CALL_DEADLINE_MAX_MS {
            return Err(err(HOST_FRAME_INVALID, "deadlineMs must be a positive bounded value"));
        }
        // 方法对白名单不在帧结构层拒绝：design §5「a service/method mismatch is
        // INVALID_ARGUMENT」——由 provider 分派层返回（帧结构合法即可解码）。
        decode_base64url(&self.payload)?;
        Ok(())
    }

    /// 编码为传输帧：u32 BE 长度前缀 + JCS（无尾随字节）。
    pub fn encode_frame(&self) -> Result<Vec<u8>, WireError> {
        let body = jcs_bytes(self)?;
        if body.is_empty() || body.len() > FRAME_MAX_BYTES {
            return Err(err(HOST_FRAME_INVALID, format!("frame body must be 1..={FRAME_MAX_BYTES} bytes")));
        }
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// 从传输帧解码（长度域校验 + 规范 JCS + 结构校验；尾随字节拒绝）。
    pub fn decode_frame(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 5 {
            return Err(err(HOST_FRAME_INVALID, "frame must carry a 4-byte length prefix and a body"));
        }
        let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if length == 0 || length > FRAME_MAX_BYTES {
            return Err(err(HOST_FRAME_INVALID, format!("frame length must be 1..={FRAME_MAX_BYTES}")));
        }
        if bytes.len() != 4 + length {
            return Err(err(HOST_FRAME_INVALID, "frame must not carry trailing bytes"));
        }
        let parsed: Self = parse_canonical(&bytes[4..], HOST_FRAME_INVALID)?;
        parsed.validate()?;
        Ok(parsed)
    }
}

impl HostCallFrameResponseV2 {
    /// ok 响应（result 非 null、error null）。
    pub fn ok(request: &HostCallFrameRequestV2, result_payload: Vec<u8>) -> Self {
        Self {
            schema_version: 2,
            protocol: HOST_CALL_PROTOCOL.into(),
            kind: "response".into(),
            request_id: request.request_id.clone(),
            execution: request.execution.clone(),
            host_service_policy_digest: request.host_service_policy_digest.clone(),
            outcome: "ok".into(),
            result: Some(encode_base64url(&result_payload)),
            error: None,
        }
    }

    /// error 响应（result null、error 非 null；detailCode 有界 opaque）。
    pub fn error(request_request_id: &str, execution: FrameExecutionV2, policy_digest: &str, error: HostCallErrorV2) -> Self {
        let mut error = error;
        if let Some(detail) = &error.detail_code {
            if detail.len() > HOST_CALL_DETAIL_MAX_BYTES {
                error.detail_code = None;
            }
        }
        Self {
            schema_version: 2,
            protocol: HOST_CALL_PROTOCOL.into(),
            kind: "response".into(),
            request_id: request_request_id.to_string(),
            execution,
            host_service_policy_digest: policy_digest.to_string(),
            outcome: "error".into(),
            result: None,
            error: Some(error),
        }
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, WireError> {
        let body = jcs_bytes(self)?;
        if body.is_empty() || body.len() > FRAME_MAX_BYTES {
            return Err(err(HOST_FRAME_INVALID, "response frame exceeds the transport bound"));
        }
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }
}

/// unpadded base64url 编码（canonical；解码端拒绝 padding/替代编码）。
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// unpadded base64url 解码：拒绝非法字母表、padding、mod 4 == 1 与非 canonical
/// round-trip（同一字节串只有一种合法编码；contracts decodeIwebKvValueWire 同式）。
pub fn decode_base64url(value: &str) -> Result<Vec<u8>, WireError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() % 4 == 1 {
        return Err(err(HOST_FRAME_INVALID, "base64url payload length mod 4 must not be 1"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| err(HOST_FRAME_INVALID, "payload must be unpadded base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(err(HOST_FRAME_INVALID, "payload must be the canonical unpadded base64url encoding"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_execution() -> FrameExecutionV2 {
        FrameExecutionV2 {
            application_id: "alpha".into(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            execution_generation: 1,
            fence_nonce: "ab".repeat(16),
        }
    }

    pub(crate) fn vector_request(service: &str, method: &str) -> HostCallFrameRequestV2 {
        HostCallFrameRequestV2 {
            schema_version: 2,
            protocol: HOST_CALL_PROTOCOL.into(),
            kind: "request".into(),
            request_id: "018f6b1e-5c0a-7740-afbc-57a9016f2085".into(),
            service: service.into(),
            method: method.into(),
            execution: vector_execution(),
            host_service_policy_digest: "cd".repeat(32),
            deadline_ms: 1_000,
            payload: encode_base64url(br#"{"key":"a"}"#),
        }
    }

    #[test]
    fn frame_round_trips_with_length_prefix() {
        let request = vector_request("kv", "get");
        let frame = request.encode_frame().expect("frame");
        // 长度前缀恰为 body 字节数（u32 BE）。
        assert_eq!(u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize, frame.len() - 4);
        let decoded = HostCallFrameRequestV2::decode_frame(&frame).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn frame_rejects_oversize_trailing_and_wrong_protocol() {
        let request = vector_request("kv", "get");
        let mut frame = request.encode_frame().expect("frame");
        frame.push(b' ');
        assert!(HostCallFrameRequestV2::decode_frame(&frame).is_err(), "trailing bytes");

        let mut wrong = vector_request("kv", "get");
        wrong.protocol = "iweb-wasmd-host-call-v1".into();
        let bytes = jcs_bytes(&wrong).unwrap();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&bytes);
        assert!(HostCallFrameRequestV2::decode_frame(&frame).is_err(), "protocol literal");

        // 未知方法对在帧结构层可解码（INVALID_ARGUMENT 由 provider 分派层返回）。
        let wrong = vector_request("kv", "query");
        let bytes = jcs_bytes(&wrong).unwrap();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&bytes);
        assert!(HostCallFrameRequestV2::decode_frame(&frame).is_ok(), "method pair is dispatch-level, not frame-level");

        let mut wrong = vector_request("kv", "get");
        wrong.request_id = "not-a-uuid".into();
        let bytes = jcs_bytes(&wrong).unwrap();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&bytes);
        assert!(HostCallFrameRequestV2::decode_frame(&frame).is_err(), "requestId grammar");

        let mut wrong = vector_request("kv", "get");
        wrong.deadline_ms = HOST_CALL_DEADLINE_MAX_MS + 1;
        let bytes = jcs_bytes(&wrong).unwrap();
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&bytes);
        assert!(HostCallFrameRequestV2::decode_frame(&frame).is_err(), "deadline bound");
    }

    #[test]
    fn base64url_is_canonical_only() {
        assert_eq!(decode_base64url("").expect("empty"), Vec::<u8>::new());
        let encoded = encode_base64url(b"payload bytes");
        assert_eq!(decode_base64url(&encoded).expect("canonical"), b"payload bytes".to_vec());
        assert!(decode_base64url(&format!("{encoded}=")).is_err(), "padding rejected");
        assert!(decode_base64url("a").is_err(), "mod 4 == 1 rejected");
        assert!(decode_base64url("ab-dc").is_err() || decode_base64url("ab-c").is_err(), "invalid alphabet rejected");
    }

    #[test]
    fn response_outcome_pairing_is_exact() {
        let request = vector_request("kv", "get");
        let ok = HostCallFrameResponseV2::ok(&request, b"{}".to_vec());
        assert_eq!(ok.outcome, "ok");
        assert!(ok.result.is_some() && ok.error.is_none());
        let error = HostCallFrameResponseV2::error(
            &request.request_id,
            request.execution.clone(),
            &request.host_service_policy_digest,
            HostCallErrorV2::new("QUOTA_EXCEEDED", Some("IWEB_KV_QUOTA_EXCEEDED")),
        );
        assert_eq!(error.outcome, "error");
        assert!(error.result.is_none() && error.error.is_some());
        // detailCode 有界：超长 opaque detail 被丢弃而不是截断成误导码。
        let bounded = HostCallFrameResponseV2::error(
            &request.request_id,
            request.execution,
            &request.host_service_policy_digest,
            HostCallErrorV2::new("INTERNAL", Some(&"x".repeat(200))),
        );
        assert!(bounded.error.expect("error").detail_code.is_none());
    }
}
