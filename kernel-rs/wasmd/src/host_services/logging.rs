//! 用户原始需求（2026-08-27，add-wasm-host-services 任务 6.1/6.2/6.5）：iweb:
//! logging@1.0.0 的有界内存环——结构化事件校验（level/message/fields grammar 与
//! 界）、reserved 敏感字段 redaction（先于大小计量/保留/投影，原值绝不保留）、
//! drop-on-full（显式 dropped + 计数，不驱逐、不阻塞）、宿主注入身份/时间戳、
//! owner 授权 drain 与 monitor 投影、外部转发配置 wire（默认关 fail-closed）。
//! 规范权威：specs/wasm-host-logging/spec.md 与 packages/contracts/
//! wasm-host-logging.ts（Rust 逐语义对齐：容量判定、eventId 单调、过期边界、
//! sink 法 kernel-audit/stdout/stderr 禁止）。

use crate::jcs::{validate_application_id, WireError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// logging 稳定错误码（WIT variant 之外的传输层码；owner 诊断面）。
pub const WASMD_LOG_RING_INVALID: &str = "WASMD_LOG_RING_INVALID";

/// 事件 grammar 界（contracts wasm-host-logging.ts 同值）。
pub const LOG_MESSAGE_MAX_BYTES: usize = 4_096;
pub const LOG_FIELDS_MAX: usize = 32;
pub const LOG_FIELD_VALUE_MAX_BYTES: usize = 1_024;

/// WIT level（trace|debug|info|warn|error）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }
}

/// logging 服务的调用侧错误（WIT variant ↔ host-call code 的映射面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggingError {
    /// 结构/grammar/level/disabled-level → invalid-event。
    InvalidEvent,
    /// 长度/数量/事件总字节越界 → limit-exceeded。
    LimitExceeded,
    /// 宿主上下文与环属主不一致（隔离违约）→ internal 域故障。
    AppIsolation,
    Unavailable,
    Internal,
}

impl LoggingError {
    /// host-call frame 的 detailCode（bounded opaque；不含日志正文）。
    pub fn detail_code(self) -> &'static str {
        match self {
            LoggingError::InvalidEvent => "IWEB_LOG_INVALID_EVENT",
            LoggingError::LimitExceeded => "IWEB_LOG_LIMIT_EXCEEDED",
            LoggingError::AppIsolation => "IWEB_LOG_APP_ISOLATION",
            LoggingError::Unavailable => "IWEB_LOG_UNAVAILABLE",
            LoggingError::Internal => "IWEB_LOG_INTERNAL",
        }
    }

    /// host-call frame 的 closed code。
    pub fn host_call_code(self) -> &'static str {
        match self {
            LoggingError::InvalidEvent => "INVALID_ARGUMENT",
            LoggingError::LimitExceeded => "LIMIT_EXCEEDED",
            LoggingError::AppIsolation | LoggingError::Internal => "INTERNAL",
            LoggingError::Unavailable => "UNAVAILABLE",
        }
    }
}

/// caller 事件（level/message/fields 三个 caller 字段；timestamp/identity 由宿主注入）。
#[derive(Debug, Clone, PartialEq)]
pub struct LoggingEvent {
    pub level: LogLevel,
    pub message: String,
    pub fields: Vec<LoggingField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingField {
    pub key: String,
    pub value: String,
}

/// 宿主注入身份（timestampUtc/身份/代次全部宿主侧，绝不来自 caller）。
/// `operation_id`（P0-1，2026-08-28）：本事件关联的 host-call claim operationId
/// （宿主自动 UUIDv7 注入；caller 不可携带）。claim 内的写才产生事件——非 claim
/// 的宿主诊断写为 None。
#[derive(Debug, Clone, PartialEq)]
pub struct LoggingHostContext {
    pub application_id: String,
    pub version_id: String,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    pub timestamp_utc: String,
    pub operation_id: Option<String>,
}

/// design §6 固定的 reserved 敏感字段 key 闭集（替换值；key 保留进诊断）。
pub const LOG_RESERVED_FIELD_KEYS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "token",
    "secret",
    "password",
    "credential",
    "request-body",
    "sql",
    "kv",
    "config",
    "owner-key",
];

pub const LOG_REDACTED_VALUE: &str = "[REDACTED]";

/// redaction 边界（先于大小计算/保留/投影；返回数组不引用被替换原值）。
pub fn redact_logging_fields(fields: &[LoggingField]) -> Vec<LoggingField> {
    fields
        .iter()
        .map(|field| {
            if LOG_RESERVED_FIELD_KEYS.contains(&field.key.as_str()) {
                LoggingField { key: field.key.clone(), value: LOG_REDACTED_VALUE.into() }
            } else {
                field.clone()
            }
        })
        .collect()
}

/// 字段 key 文法 ^[a-z][a-z0-9._-]{0,63}$（ASCII，字符数即字节数）。
fn is_valid_field_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..].iter().all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'_' || byte == b'-')
}

/// 被保留的诊断记录（字段闭集：宿主身份/时间戳/claim 关联 + caller level/message/
/// 已 redact fields + 单调 eventId；无 Kernel audit 别名字段）。
#[derive(Debug, Clone, PartialEq)]
pub struct RetainedLogRecord {
    pub event_id: u64,
    pub timestamp_utc: String,
    pub application_id: String,
    pub version_id: String,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    pub level: LogLevel,
    pub message: String,
    pub fields: Vec<LoggingField>,
    /// 产生本事件的 host-call claim operationId（claim 内写的关联证据；诊断写为 None）。
    pub operation_id: Option<String>,
}

/// 环容量（V2 policy limits 来源）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingCapacity {
    pub max_events: usize,
    pub max_bytes: u64,
}

/// per-app 有界环（drop-on-full；dropped 计数；eventId 生命周期内单调）。
pub struct LoggingRing {
    application_id: String,
    capacity: RingCapacity,
    events: std::collections::VecDeque<RetainedLogRecord>,
    retained_bytes: u64,
    dropped_count: u64,
    next_event_id: u64,
}

fn digit_count(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// canonical 字节计量（确定性口径；redaction 先于计算——入参先 redact）。
pub fn measure_logging_event_bytes(event: &LoggingEvent, host: &LoggingHostContext, event_id: u64) -> u64 {
    let redacted = redact_logging_fields(&event.fields);
    let mut total = (host.timestamp_utc.len()
        + host.application_id.len()
        + host.version_id.len()
        + host.operation_id.as_deref().map_or(0, str::len)
        + digit_count(host.preparation_generation)
        + digit_count(host.execution_generation)
        + digit_count(event_id)
        + event.level.as_str().len()
        + event.message.len()) as u64;
    for field in &redacted {
        total += (field.key.len() + field.value.len()) as u64;
    }
    total
}

/// 事件校验（grammar/界/唯一 key；caller timestamp/identity/owner credential/
/// request body/host handle 等未知字段在类型层不存在——WIT record 形状即闭集）。
pub fn validate_logging_event(event: &LoggingEvent, max_message_bytes: usize) -> Result<(), LoggingError> {
    if event.message.len() > max_message_bytes || event.message.len() > LOG_MESSAGE_MAX_BYTES {
        return Err(LoggingError::LimitExceeded);
    }
    if event.fields.len() > LOG_FIELDS_MAX {
        return Err(LoggingError::LimitExceeded);
    }
    let mut seen = HashSet::with_capacity(event.fields.len());
    for field in &event.fields {
        if !is_valid_field_key(&field.key) {
            return Err(LoggingError::InvalidEvent);
        }
        if !seen.insert(field.key.as_str()) {
            return Err(LoggingError::InvalidEvent); // 重复 key。
        }
        if field.value.len() > LOG_FIELD_VALUE_MAX_BYTES {
            return Err(LoggingError::LimitExceeded);
        }
    }
    Ok(())
}

impl LoggingRing {
    pub fn new(application_id: &str, capacity: RingCapacity) -> Result<Self, LoggingError> {
        validate_application_id(application_id).map_err(|_| LoggingError::Internal)?;
        if capacity.max_events == 0 || capacity.max_bytes == 0 {
            return Err(LoggingError::Internal);
        }
        Ok(Self {
            application_id: application_id.to_string(),
            capacity,
            events: std::collections::VecDeque::new(),
            retained_bytes: 0,
            dropped_count: 0,
            next_event_id: 1,
        })
    }

    /// WIT write 的环投影：校验 → redact → 计量 → per-event 上限 → 环准入。
    /// dropped：事件未被保留，不是 audit 确认；不驱逐既有事件（本应用或其他应用）。
    pub fn write(
        &mut self,
        host: &LoggingHostContext,
        event: &LoggingEvent,
        max_event_bytes: u64,
    ) -> Result<bool, LoggingError> {
        if host.application_id != self.application_id {
            return Err(LoggingError::AppIsolation);
        }
        validate_logging_event(event, LOG_MESSAGE_MAX_BYTES)?;
        let event_id = self.next_event_id;
        let event_bytes = measure_logging_event_bytes(event, host, event_id);
        if event_bytes > max_event_bytes {
            return Err(LoggingError::LimitExceeded);
        }
        if self.events.len() >= self.capacity.max_events || self.retained_bytes + event_bytes > self.capacity.max_bytes {
            self.dropped_count += 1;
            return Ok(false); // dropped：立即返回，不阻塞/不重试/不驱逐。
        }
        let record = RetainedLogRecord {
            event_id,
            timestamp_utc: host.timestamp_utc.clone(),
            application_id: host.application_id.clone(),
            version_id: host.version_id.clone(),
            preparation_generation: host.preparation_generation,
            execution_generation: host.execution_generation,
            level: event.level,
            message: event.message.clone(),
            fields: redact_logging_fields(&event.fields),
            operation_id: host.operation_id.clone(),
        };
        self.events.push_back(record);
        self.retained_bytes += event_bytes;
        self.next_event_id += 1;
        Ok(true)
    }

    /// owner 授权 drain：只返回请求应用自己的 bounded 保留记录。
    pub fn drain(&self, application_id: &str, after_event_id: u64, max_events: usize) -> Result<DrainResponse, LoggingError> {
        if application_id != self.application_id {
            return Err(LoggingError::AppIsolation);
        }
        if !(1..=DRAIN_MAX_EVENTS).contains(&max_events) {
            return Err(LoggingError::LimitExceeded);
        }
        let eligible: Vec<&RetainedLogRecord> = self.events.iter().filter(|record| record.event_id > after_event_id).collect();
        let selected = eligible.len().min(max_events);
        Ok(DrainResponse {
            application_id: self.application_id.clone(),
            events: eligible[..selected].iter().map(|record| (*record).clone()).collect(),
            dropped_count: self.dropped_count,
            has_more: selected < eligible.len(),
            last_event_id: self.next_event_id.saturating_sub(1),
        })
    }

    /// monitor 投影（用量面：只有计数与水位，无日志正文）。
    pub fn monitor_summary(&self) -> MonitorSummary {
        MonitorSummary {
            application_id: self.application_id.clone(),
            retained_events: self.events.len(),
            retained_bytes: self.retained_bytes,
            dropped_count: self.dropped_count,
            last_event_id: self.next_event_id.saturating_sub(1),
            capacity: self.capacity,
        }
    }

    /// 重置语义：supervisor/wasmd 重启/代次替换开启新生命周期（默认 profile 不做
    /// 跨重启持久化声明）。
    pub fn reset(&mut self) {
        self.events.clear();
        self.retained_bytes = 0;
        self.dropped_count = 0;
        self.next_event_id = 1;
    }

    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }
}

/// drain 上限（contracts IWEB_LOG_DRAIN_MAX_EVENTS_LIMIT）。
pub const DRAIN_MAX_EVENTS: usize = 1_000;
// ---------------------------------------------------------------------------
// owner 诊断面 wire（第三轮复审 2026-08-28，logging 权威接通）：wasmd 进程内 ring 的
// HTTP 投影——形状逐字对位 packages/contracts/wasm-host-logging.ts 的
// IwebLoggingDrainRequestV1 / IwebLoggingDrainResponseV1 / IwebLoggingMonitorSummaryV1
//（supervisor wasm-host-logging.ts 的消费面复验是第二道闸，本 wire 只做权威投影）。
// RetainedLogRecord.operation_id 是宿主侧 claim 关联证据，不属于 owner wire——绝不
// 序列化（消费面按未知字段 fail-closed）。
// ---------------------------------------------------------------------------

/// drain 请求 wire（POST /v1/host-logging/drain/<applicationId> body）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoggingDrainRequestWireV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "afterEventId")]
    pub after_event_id: u64,
    #[serde(rename = "maxEvents")]
    pub max_events: u64,
}

impl LoggingDrainRequestWireV1 {
    /// 结构校验（schemaVersion 恒 1；applicationId 归属由 ring 的 drain 判定）。
    pub fn validate(&self) -> Result<(), WireError> {
        if self.schema_version != 1 {
            return Err(crate::jcs::err(WASMD_LOG_RING_INVALID, "drain request schemaVersion must be the literal 1"));
        }
        validate_application_id(&self.application_id)?;
        crate::jcs::require_u53(self.after_event_id, 0, crate::jcs::WASM_U53_MAX, "afterEventId")?;
        if !(1..=DRAIN_MAX_EVENTS_U53).contains(&self.max_events) {
            return Err(crate::jcs::err(WASMD_LOG_RING_INVALID, "maxEvents must be a positive bounded value"));
        }
        Ok(())
    }
}

/// drain 上限的 wire 域（usize 上限换 u53 表达；contracts 同值）。
pub const DRAIN_MAX_EVENTS_U53: u64 = 1_000;

/// 保留记录的 owner 投影（operation_id 不出场）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RetainedLogRecordWireV1 {
    #[serde(rename = "eventId")]
    pub event_id: u64,
    #[serde(rename = "timestampUtc")]
    pub timestamp_utc: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    #[serde(rename = "executionGeneration")]
    pub execution_generation: u64,
    pub level: String,
    pub message: String,
    pub fields: Vec<LoggingField>,
}

/// drain 响应 wire（supervisor 消费面按精确键集复验）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoggingDrainResponseWireV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub events: Vec<RetainedLogRecordWireV1>,
    #[serde(rename = "droppedCount")]
    pub dropped_count: u64,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
    #[serde(rename = "lastEventId")]
    pub last_event_id: u64,
}

impl DrainResponse {
    /// 权威投影 → owner wire（operation_id 剥离；level 以闭集字符串出场）。
    pub fn to_wire(&self) -> LoggingDrainResponseWireV1 {
        LoggingDrainResponseWireV1 {
            schema_version: 1,
            application_id: self.application_id.clone(),
            events: self
                .events
                .iter()
                .map(|record| RetainedLogRecordWireV1 {
                    event_id: record.event_id,
                    timestamp_utc: record.timestamp_utc.clone(),
                    application_id: record.application_id.clone(),
                    version_id: record.version_id.clone(),
                    preparation_generation: record.preparation_generation,
                    execution_generation: record.execution_generation,
                    level: record.level.as_str().to_string(),
                    message: record.message.clone(),
                    fields: record.fields.clone(),
                })
                .collect(),
            dropped_count: self.dropped_count,
            has_more: self.has_more,
            last_event_id: self.last_event_id,
        }
    }
}

/// monitor summary wire（GET /v1/host-logging/summary/<applicationId>）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoggingMonitorSummaryWireV1 {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "retainedEvents")]
    pub retained_events: u64,
    #[serde(rename = "retainedBytes")]
    pub retained_bytes: u64,
    #[serde(rename = "droppedCount")]
    pub dropped_count: u64,
    #[serde(rename = "lastEventId")]
    pub last_event_id: u64,
    pub capacity: RingCapacityWireV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RingCapacityWireV1 {
    #[serde(rename = "maxEvents")]
    pub max_events: u64,
    #[serde(rename = "maxBytes")]
    pub max_bytes: u64,
}

impl MonitorSummary {
    pub fn to_wire(&self) -> LoggingMonitorSummaryWireV1 {
        LoggingMonitorSummaryWireV1 {
            application_id: self.application_id.clone(),
            retained_events: self.retained_events as u64,
            retained_bytes: self.retained_bytes,
            dropped_count: self.dropped_count,
            last_event_id: self.last_event_id,
            capacity: RingCapacityWireV1 {
                max_events: self.capacity.max_events as u64,
                max_bytes: self.capacity.max_bytes,
            },
        }
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct DrainResponse {
    pub application_id: String,
    pub events: Vec<RetainedLogRecord>,
    pub dropped_count: u64,
    pub has_more: bool,
    pub last_event_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorSummary {
    pub application_id: String,
    pub retained_events: usize,
    pub retained_bytes: u64,
    pub dropped_count: u64,
    pub last_event_id: u64,
    pub capacity: RingCapacity,
}

// ---------------------------------------------------------------------------
// owner 授权外部转发配置 wire（默认关、fail-closed；L1 终裁）
// ---------------------------------------------------------------------------

/// 转发格式闭集。
pub const LOG_FORWARDING_FORMATS: &[&str] = &["json-lines", "syslog"];

/// 端点 grammar：host:port（DNS 或 IPv4 literal；无 scheme/userinfo/path/IPv6 括号）。
pub fn is_valid_forwarding_endpoint(endpoint: &str) -> bool {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    let Ok(port_number) = port.parse::<u16>() else {
        return false;
    };
    if port_number == 0 {
        return false;
    }
    if host.is_empty() || host.len() > 253 || host == "localhost" {
        return false;
    }
    let is_ipv4 = host.split('.').count() == 4
        && host.split('.').all(|octet| !octet.is_empty() && octet.len() <= 3 && octet.bytes().all(|b| b.is_ascii_digit()))
        && host.split('.').all(|octet| octet.parse::<u8>().is_ok());
    if is_ipv4 {
        return true;
    }
    // DNS 名称：[a-z0-9] 段以点分隔；单段 1..63；禁大写与连字符端接。
    let lower = host.to_ascii_lowercase();
    if lower != host {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && label.bytes().last().is_some_and(|b| b.is_ascii_alphanumeric())
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// 转发配置（默认关）。wasmd 侧只承载与校验配置面；实际外部转发传输属
/// owner-authorized 消费者（wasmd 出网唯一目的地是网关，绝不隐式拨号——sink 法）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForwardingConfig {
    pub enabled: bool,
    pub format: Option<String>,
    pub endpoint: Option<String>,
}

pub const FORWARDING_DEFAULT: ForwardingConfig = ForwardingConfig { enabled: false, format: None, endpoint: None };

impl ForwardingConfig {
    /// 校验：enabled:false 时不得携带 format/endpoint；enabled:true 时必须合法。
    pub fn validate(&self) -> Result<(), WireError> {
        if !self.enabled {
            if self.format.is_some() || self.endpoint.is_some() {
                return Err(crate::jcs::err(WASMD_LOG_RING_INVALID, "format/endpoint must be null while forwarding is disabled"));
            }
            return Ok(());
        }
        let format = self.format.as_deref().unwrap_or_default();
        if !LOG_FORWARDING_FORMATS.contains(&format) {
            return Err(crate::jcs::err(WASMD_LOG_RING_INVALID, "forwarding format must be json-lines or syslog"));
        }
        if !self.endpoint.as_deref().is_some_and(is_valid_forwarding_endpoint) {
            return Err(crate::jcs::err(WASMD_LOG_RING_INVALID, "forwarding endpoint must be host:port with a DNS or IPv4 host"));
        }
        Ok(())
    }
}

/// sink 法（closed set）：kernel-audit/stdout/stderr/unbounded-file/implicit-rustfs
/// 永远不是 iweb:logging 的别名、回退或合并目标。
pub const LOG_ALLOWED_SINKS: &[&str] = &["memory-ring", "monitor-projection", "owner-forwarding"];
pub const LOG_FORBIDDEN_SINKS: &[&str] = &["kernel-audit", "stdout", "stderr", "unbounded-file", "implicit-rustfs"];

pub fn logging_sink_error_code(sink: &str) -> Option<&'static str> {
    if LOG_FORBIDDEN_SINKS.contains(&sink) {
        Some("IWEB_LOG_SINK_FORBIDDEN")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> LoggingHostContext {
        LoggingHostContext {
            application_id: "alpha".into(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            execution_generation: 1,
            timestamp_utc: "2026-08-27T00:00:00.000Z".into(),
            operation_id: Some("018f6b1e-5c0a-7740-afbc-57a9016f2085".into()),
        }
    }

    fn event(level: LogLevel, message: &str, fields: Vec<(&str, &str)>) -> LoggingEvent {
        LoggingEvent {
            level,
            message: message.into(),
            fields: fields.into_iter().map(|(key, value)| LoggingField { key: key.into(), value: value.into() }).collect(),
        }
    }

    #[test]
    fn accepted_events_carry_host_identity_and_monotonic_ids() {
        let mut ring = LoggingRing::new("alpha", RingCapacity { max_events: 4, max_bytes: 1_024 }).expect("ring");
        let first = ring.write(&host(), &event(LogLevel::Error, "boom", vec![("code", "500")]), 8_192).expect("write");
        assert!(first, "accepted");
        let second = ring.write(&host(), &event(LogLevel::Info, "ok", vec![]), 8_192).expect("write");
        assert!(second);
        let summary = ring.monitor_summary();
        assert_eq!(summary.retained_events, 2);
        assert_eq!(summary.last_event_id, 2);
        let drain = ring.drain("alpha", 0, 1_000).expect("drain");
        assert_eq!(drain.events.len(), 2);
        assert_eq!(drain.events[0].event_id, 1);
        assert_eq!(drain.events[0].application_id, "alpha");
        assert_eq!(drain.events[0].level, LogLevel::Error);
        assert_eq!(drain.events[0].fields[0].value, "500");
    }

    #[test]
    fn reserved_field_values_are_redacted_before_metering_and_retention() {
        let mut ring = LoggingRing::new("alpha", RingCapacity { max_events: 4, max_bytes: 1_024 }).expect("ring");
        let secret_event = event(
            LogLevel::Warn,
            "auth failed",
            vec![("authorization", "Bearer owner-secret-token"), ("code", "401")],
        );
        // 原值长度计入与否不影响结论：先 redact 再计量。
        let redacted_bytes = {
            let redacted = redact_logging_fields(&secret_event.fields);
            let mut probe = secret_event.clone();
            probe.fields = redacted;
            measure_logging_event_bytes(&probe, &host(), 1)
        };
        assert!(ring.write(&host(), &secret_event, redacted_bytes).expect("write"), "event fits after redaction");
        let drain = ring.drain("alpha", 0, 1_000).expect("drain");
        assert_eq!(drain.events[0].fields[0].value, "[REDACTED]", "original value never retained");
        assert_eq!(drain.events[0].fields[0].key, "authorization");
        assert_eq!(drain.events[0].fields[1].value, "401");
    }

    #[test]
    fn full_ring_drops_explicitly_without_eviction_or_blocking() {
        let mut ring = LoggingRing::new("alpha", RingCapacity { max_events: 2, max_bytes: 1_024 }).expect("ring");
        assert!(ring.write(&host(), &event(LogLevel::Info, "one", vec![]), 8_192).expect("w"));
        assert!(ring.write(&host(), &event(LogLevel::Info, "two", vec![]), 8_192).expect("w"));
        let dropped = ring.write(&host(), &event(LogLevel::Info, "three", vec![]), 8_192).expect("w");
        assert!(!dropped, "dropped outcome, not an error");
        assert_eq!(ring.dropped_count(), 1);
        assert_eq!(ring.monitor_summary().retained_events, 2, "no eviction");
        let drain = ring.drain("alpha", 0, 1_000).expect("drain");
        assert_eq!(drain.events.len(), 2);
        assert_eq!(drain.events[0].message, "one", "earliest event retained");

        // 字节容量同样触发 drop-on-full。
        let mut ring = LoggingRing::new("alpha", RingCapacity { max_events: 10, max_bytes: 1 }).expect("ring");
        let dropped = ring.write(&host(), &event(LogLevel::Info, "big message", vec![]), 8_192).expect("w");
        assert!(!dropped, "byte capacity reached");
        assert_eq!(ring.dropped_count(), 1);
    }

    #[test]
    fn invalid_events_are_rejected_with_stable_errors() {
        let mut ring = LoggingRing::new("alpha", RingCapacity { max_events: 4, max_bytes: 1_024 }).expect("ring");
        // 未知 level 在类型层不存在（enum）；非法字段 key → invalid-event。
        assert_eq!(ring.write(&host(), &event(LogLevel::Info, "m", vec![("Bad-Key", "v")]), 8_192).expect_err("grammar"), LoggingError::InvalidEvent);
        // 重复 key → invalid-event。
        assert_eq!(
            ring.write(&host(), &event(LogLevel::Info, "m", vec![("a", "1"), ("a", "2")]), 8_192).expect_err("duplicate"),
            LoggingError::InvalidEvent
        );
        // message 超界 → limit-exceeded。
        assert_eq!(
            ring.write(&host(), &event(LogLevel::Info, &"x".repeat(4_097), vec![]), 8_192).expect_err("message bound"),
            LoggingError::LimitExceeded
        );
        // 字段值超界 → limit-exceeded。
        assert_eq!(
            ring.write(&host(), &event(LogLevel::Info, "m", vec![("a", &"v".repeat(1_025))]), 8_192).expect_err("value bound"),
            LoggingError::LimitExceeded
        );
        // 事件总字节（含宿主元数据）超 maxEventBytes → limit-exceeded。
        assert_eq!(
            ring.write(&host(), &event(LogLevel::Info, "m", vec![]), 1).expect_err("event bytes"),
            LoggingError::LimitExceeded
        );
        // 跨应用宿主上下文 → 隔离违约。
        let mut other = host();
        other.application_id = "beta".into();
        assert_eq!(ring.write(&other, &event(LogLevel::Info, "m", vec![]), 8_192).expect_err("cross app"), LoggingError::AppIsolation);
        // 跨应用 drain → 隔离违约（不暴露既有事件）。
        assert_eq!(ring.drain("beta", 0, 10).expect_err("cross drain"), LoggingError::AppIsolation);
    }

    #[test]
    fn version_id_and_drain_bounds() {
        let ring = LoggingRing::new("alpha", RingCapacity { max_events: 4, max_bytes: 1_024 }).expect("ring");
        assert_eq!(ring.drain("alpha", 0, 0).expect_err("zero"), LoggingError::LimitExceeded);
        assert_eq!(ring.drain("alpha", 0, DRAIN_MAX_EVENTS + 1).expect_err("over"), LoggingError::LimitExceeded);
        ring.drain("alpha", 0, DRAIN_MAX_EVENTS).expect("at bound");
    }

    #[test]
    fn forwarding_config_is_default_off_and_strict() {
        assert_eq!(ForwardingConfig::default().validate(), Ok(()));
        const _: () = assert!(!FORWARDING_DEFAULT.enabled, "fail-closed default");
        let enabled = ForwardingConfig {
            enabled: true,
            format: Some("json-lines".into()),
            endpoint: Some("logs.example.com:514".into()),
        };
        assert_eq!(enabled.validate(), Ok(()));
        let syslog = ForwardingConfig { enabled: true, format: Some("syslog".into()), endpoint: Some("10.0.0.5:601".into()) };
        assert_eq!(syslog.validate(), Ok(()));
        // disabled 携带残留 → 拒绝。
        let leak = ForwardingConfig { enabled: false, format: Some("syslog".into()), endpoint: None };
        assert!(leak.validate().is_err());
        // 未知格式 / 畸形端点 → 拒绝。
        let bad_format = ForwardingConfig { enabled: true, format: Some("cef".into()), endpoint: Some("logs:514".into()) };
        assert!(bad_format.validate().is_err());
        for endpoint in ["http://x:1", "host:0", "host:65536", "localhost:514", "host name:1", "[::1]:514", "host"] {
            let bad = ForwardingConfig { enabled: true, format: Some("json-lines".into()), endpoint: Some(endpoint.into()) };
            assert!(bad.validate().is_err(), "endpoint {endpoint:?} must be rejected");
        }
    }

    #[test]
    fn sink_law_rejects_audit_and_stdio_targets() {
        for sink in LOG_FORBIDDEN_SINKS {
            assert_eq!(logging_sink_error_code(sink), Some("IWEB_LOG_SINK_FORBIDDEN"));
        }
        for sink in LOG_ALLOWED_SINKS {
            assert_eq!(logging_sink_error_code(sink), None);
        }
    }
}
