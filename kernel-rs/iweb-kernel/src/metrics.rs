//! 每应用请求指标（对位 kernel/index.js appMetrics）：§4.2 monitor 帧接入。
//! 只做真实计数——无流量时 requests=0 是可证明的零；绝不用估计值填充。
//! 每次指标落账后广播通知，monitor 连接据此推送新快照（对位 JS broadcastMonitorSnapshot）。
//!
//! wasm engine metrics v1（add-wasm-runtime 4.1）：supervisor → Kernel 的完整可用性
//! wire 在本模块落 Kernel 侧接受链——精确键集校验、与当前 execution 记录的全字段
//! correlate、同 E 非负单调窗口与 owner monitor 投影。wire 权威是
//! packages/contracts/wasm-health.ts（validateWasmEngineMetricsV1 /
//! correlateWasmEngineMetricsV1 / acceptWasmEngineMetricsSample）；本节 Rust 实现与
//! 其语义逐条对位，错误码沿用 contracts 已命名码，绝不引入第二套判定。
//! 投影法则：engine（wasmtime 引擎计数）与 resources（cgroup/进程口径）分开标注，
//! 互不换算、互不替代；无首样本/无法证明的唯一投影是 availability:"unavailable"
//! + engine:null，绝不补零。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::wasm_admission::{
    compose_wasm_version_id, parse_rfc3339_utc_millis, parse_wasm_version_id,
    validate_runtime_binding, AdmissionError, RuntimeBindingIdentityV1, WASM_U53_MAX,
};
use crate::wasm_commands::ExecutionCommandV1;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Default)]
struct Entry {
    requests: u64,
    errors: u64,
    in_flight: i64,
    total_latency_millis: f64,
    last_request_at: Option<String>,
}

struct Inner {
    entries: Mutex<HashMap<String, Entry>>,
    /// 指标落账通知；monitor 连接经 watch::Receiver 收到变更后重发快照。
    /// watch（而非 Notify）：带值语义，select 重挂窗口内的事件不会丢失。
    version: tokio::sync::watch::Sender<()>,
}

/// 进程级共享指标表；Clone 共享同一底层存储。
#[derive(Clone)]
pub struct AppMetrics(Arc<Inner>);

impl Default for AppMetrics {
    fn default() -> Self {
        let (version, _) = tokio::sync::watch::channel(());
        Self(Arc::new(Inner { entries: Mutex::new(HashMap::new()), version }))
    }
}

/// 单应用指标快照（帧字段逐一平价 JS monitorSnapshot 的 apps[]）。
pub struct Snapshot {
    pub requests: u64,
    pub errors: u64,
    pub in_flight: i64,
    /// JS 对位：requests=0 时为 0，否则四舍五入到 0.1ms。
    pub average_latency_ms: f64,
    pub last_request_at: Option<String>,
}

impl AppMetrics {
    fn with<R>(&self, app: &str, update: impl FnOnce(&mut Entry) -> R) -> R {
        let mut entries = self.0.entries.lock().expect("metrics lock");
        let entry = entries.entry(app.to_owned()).or_default();
        update(entry)
    }

    /// 请求进入代理时调用；必须与 observe 配对（observe 内饱和递减 in_flight）。
    pub fn in_flight_enter(&self, app: &str) {
        self.with(app, |entry| entry.in_flight += 1);
    }

    /// 请求离开代理时调用：计数、累计时延、记录完成时刻并广播。
    /// error 语义对位 JS：上游状态 ≥500 或传输/转换失败。
    pub fn observe(&self, app: &str, started: std::time::Instant, error: bool) {
        self.with(app, |entry| {
            entry.requests += 1;
            if error {
                entry.errors += 1;
            }
            entry.total_latency_millis += started.elapsed().as_secs_f64() * 1000.0;
            entry.last_request_at = Some(crate::monitor::iso_now());
            entry.in_flight = (entry.in_flight - 1).max(0);
        });
        let _ = self.0.version.send(());
    }

    /// monitor 连接的变更订阅句柄（watch：错过的变更在 changed() 里仍可见）。
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.0.version.subscribe()
    }

    pub fn snapshot(&self, app: &str) -> Snapshot {
        let entries = self.0.entries.lock().expect("metrics lock");
        let entry = entries.get(app);
        Snapshot {
            requests: entry.map(|e| e.requests).unwrap_or(0),
            errors: entry.map(|e| e.errors).unwrap_or(0),
            in_flight: entry.map(|e| e.in_flight).unwrap_or(0),
            average_latency_ms: entry
                .filter(|e| e.requests > 0)
                .map(|e| (e.total_latency_millis / e.requests as f64 * 10.0).round() / 10.0)
                .unwrap_or(0.0),
            last_request_at: entry.and_then(|e| e.last_request_at.clone()),
        }
    }
}

// ===========================================================================
// wasm engine metrics v1（Kernel 侧接受链；add-wasm-runtime 4.1）
// ===========================================================================

// 稳定错误码：与 packages/contracts/wasm-health.ts 逐名对齐（spec 已命名
// WASM_IDENTITY_INCOMPLETE 之外的 wire/窗口码）；补充码沿用同款命名风格。
pub const WASM_ENGINE_METRICS_INVALID: &str = "WASM_ENGINE_METRICS_INVALID";
pub const WASM_ENGINE_METRICS_STALE: &str = "WASM_ENGINE_METRICS_STALE";
pub const WASM_ENGINE_METRICS_TIME_REGRESSION: &str = "WASM_ENGINE_METRICS_TIME_REGRESSION";
pub const WASM_ENGINE_METRICS_COUNTER_REGRESSION: &str = "WASM_ENGINE_METRICS_COUNTER_REGRESSION";
pub const WASM_ENGINE_METRICS_FUEL_REPRESENTATION: &str = "WASM_ENGINE_METRICS_FUEL_REPRESENTATION";
pub const WASM_ENGINE_METRICS_MISMATCH: &str = "WASM_ENGINE_METRICS_MISMATCH";

const METRICS_TOP_LEVEL_KEYS: [&str; 15] = [
    "schemaVersion",
    "sandboxId",
    "versionId",
    "packageDigest",
    "runtimeBinding",
    "capabilityRecordRevision",
    "capabilityRecordHash",
    "secretRevision",
    "configRevision",
    "configSnapshotRef",
    "preparationGeneration",
    "executionGeneration",
    "sampledAt",
    "availability",
    "engine",
];
const ENGINE_COUNTER_KEYS: [&str; 5] = [
    "fuelConsumedCumulative",
    "epochTimeoutsCumulative",
    "instancesLiveInstant",
    "instancesHighWaterCumulative",
    "guestMemoryBytesInstant",
];

fn metrics_err(code: &'static str, detail: impl Into<String>) -> AdmissionError {
    AdmissionError::new(code, detail)
}

struct WasmMetricsRegexes {
    sandbox_id: regex::Regex,
    sha256_hex: regex::Regex,
    rfc3339_utc: regex::Regex,
}

fn wasm_metrics_regexes() -> &'static WasmMetricsRegexes {
    static REGEXES: OnceLock<WasmMetricsRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| WasmMetricsRegexes {
        sandbox_id: regex::Regex::new(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$").expect("sandbox id regex"),
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        // 与 contracts WASM_RFC3339_UTC_PATTERN 同口径：Z 结尾、可选任意位小数。
        rfc3339_utc: regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$").expect("rfc3339 utc regex"),
    })
}

/// engine counters（available 样本的精确五字段；fuel null = 禁用唯一表示）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WasmEngineCountersV1 {
    pub fuel_consumed_cumulative: Option<u64>,
    pub epoch_timeouts_cumulative: u64,
    pub instances_live_instant: u64,
    pub instances_high_water_cumulative: u64,
    pub guest_memory_bytes_instant: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WasmEngineAvailability {
    Available,
    Unavailable,
}

/// supervisor → Kernel 的 metrics v1 wire（spec "Wasm engine metrics use a complete
/// availability wire contract"；字段集/耦合律与 contracts 逐字段一致）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WasmEngineMetricsV1 {
    pub schema_version: u64,
    pub sandbox_id: String,
    pub version_id: String,
    pub package_digest: String,
    pub runtime_binding: RuntimeBindingIdentityV1,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    pub secret_revision: u64,
    pub config_revision: u64,
    pub config_snapshot_ref: Option<String>,
    pub preparation_generation: u64,
    pub execution_generation: u64,
    pub sampled_at: String,
    pub availability: WasmEngineAvailability,
    pub engine: Option<WasmEngineCountersV1>,
}

/// Kernel 当前执行记录的比对 fence（metrics wire 不携带 values digest 与 secret ref；
/// 从最后接受的 execution command / 业务记录推导）。
#[derive(Debug, Clone, PartialEq)]
pub struct WasmEngineMetricsFence {
    pub sandbox_id: String,
    pub version_id: String,
    pub package_digest: String,
    pub runtime_binding: RuntimeBindingIdentityV1,
    pub capability_record_revision: u64,
    pub capability_record_hash: String,
    pub secret_revision: u64,
    pub config_revision: u64,
    pub config_snapshot_ref: Option<String>,
    pub preparation_generation: u64,
    pub execution_generation: u64,
}

impl WasmEngineMetricsFence {
    /// 从 Kernel 授权的最后一条 execution command 推导 fence（同 tuple 的全字段即
    /// 当前执行记录；不引入第二套权威）。
    pub fn from_command(command: &ExecutionCommandV1) -> Self {
        Self {
            sandbox_id: command.identity.sandbox_id.clone(),
            version_id: command.identity.version_id.clone(),
            package_digest: command.package_digest.clone(),
            runtime_binding: command.runtime_binding.clone(),
            capability_record_revision: command.capability_record_revision,
            capability_record_hash: command.capability_record_hash.clone(),
            secret_revision: command.secret_revision,
            config_revision: command.config_revision,
            config_snapshot_ref: command.config_snapshot_ref.clone(),
            preparation_generation: command.identity.preparation_generation,
            execution_generation: command.identity.execution_generation,
        }
    }
}

// 精确键集：先于结构体解析在 Value 上执行（serde 对 Option 字段缺键默认 None，
// 无法单独强制「字段必须出现」；此处与 TS requireExactKeys 同判：未知键拒绝、
// 必备键缺失拒绝。serde_json::Value 与 JS JSON.parse 同样折叠重复键）。
fn require_exact_keys(value: &serde_json::Value, path: &str, keys: &[&str]) -> Result<(), AdmissionError> {
    let Some(object) = value.as_object() else {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, format!("{path} must be an object")));
    };
    for key in object.keys() {
        if !keys.contains(&key.as_str()) {
            return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, format!("{path}/{key}: unknown field is not allowed")));
        }
    }
    for key in keys {
        if !object.contains_key(*key) {
            return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, format!("{path}/{key}: required field is missing")));
        }
    }
    Ok(())
}

fn require_metrics_u53(value: &serde_json::Value, path: &str, minimum: u64) -> Result<u64, AdmissionError> {
    let Some(number) = value.as_u64() else {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, format!("{path} must be a non-negative integer (u53 range)")));
    };
    if number < minimum || number > WASM_U53_MAX {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, format!("{path} must be an integer between {minimum} and the u53 maximum")));
    }
    Ok(number)
}

fn require_metrics_sha256_hex(value: &serde_json::Value, path: &str) -> Result<String, AdmissionError> {
    let Some(text) = value.as_str() else {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, format!("{path} must be a string")));
    };
    if !wasm_metrics_regexes().sha256_hex.is_match(text) {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, format!("{path} must be 64 lower-case hex characters")));
    }
    Ok(text.to_string())
}

/// wire 校验（对位 validateWasmEngineMetricsV1）：精确键集、身份文法、
/// configRevision:0 ⇔ configSnapshotRef:null、存活双代次 >= 1、unavailable ⇔ engine:null。
pub fn validate_wasm_engine_metrics_v1(value: &serde_json::Value) -> Result<WasmEngineMetricsV1, AdmissionError> {
    require_exact_keys(value, "", &METRICS_TOP_LEVEL_KEYS)?;
    let object = value.as_object().expect("exact-key check passed");
    let field = |name: &str| object.get(name).expect("exact-key check passed");
    if field("schemaVersion").as_u64() != Some(1) {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "schemaVersion must be exactly 1"));
    }
    let Some(sandbox_id) = field("sandboxId").as_str() else {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "sandboxId must be a string"));
    };
    if !wasm_metrics_regexes().sandbox_id.is_match(sandbox_id) {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "sandboxId must start with a lower-case letter and span at most 63 ASCII bytes"));
    }
    let Some(version_id) = field("versionId").as_str() else {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "versionId must be a string"));
    };
    let (digest, sequence) = parse_wasm_version_id(version_id).map_err(|e| metrics_err(WASM_ENGINE_METRICS_INVALID, e.detail))?;
    if compose_wasm_version_id(&digest, sequence) != version_id {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "versionId must round-trip its digest-sequence label"));
    }
    let package_digest = require_metrics_sha256_hex(field("packageDigest"), "/packageDigest")?;
    let runtime_binding_value = field("runtimeBinding");
    require_exact_keys(runtime_binding_value, "/runtimeBinding", &[
        "kind", "catalogRevision", "catalogHash", "entryKey", "imageDigest", "hostABI", "world",
    ])?;
    let runtime_binding: RuntimeBindingIdentityV1 = serde_json::from_value(runtime_binding_value.clone())
        .map_err(|e| metrics_err(WASM_ENGINE_METRICS_INVALID, format!("/runtimeBinding: {e}")))?;
    validate_runtime_binding(&runtime_binding).map_err(|e| metrics_err(WASM_ENGINE_METRICS_INVALID, e.detail))?;
    let capability_record_revision = require_metrics_u53(field("capabilityRecordRevision"), "/capabilityRecordRevision", 1)?;
    let capability_record_hash = require_metrics_sha256_hex(field("capabilityRecordHash"), "/capabilityRecordHash")?;
    let secret_revision = require_metrics_u53(field("secretRevision"), "/secretRevision", 0)?;
    let config_revision = require_metrics_u53(field("configRevision"), "/configRevision", 0)?;
    let config_snapshot_ref = match field("configSnapshotRef") {
        serde_json::Value::Null => None,
        serde_json::Value::String(_) => Some(require_metrics_sha256_hex(field("configSnapshotRef"), "/configSnapshotRef")?),
        _ => return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "/configSnapshotRef must be null or a 64-character lower-case hex digest")),
    };
    // metrics wire 无 configValuesDigest 字段：revision 0 ⇔ ref null。
    if (config_revision == 0 && config_snapshot_ref.is_some()) || (config_revision > 0 && config_snapshot_ref.is_none()) {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "configRevision 0 requires configSnapshotRef null; a non-zero configRevision requires a configSnapshotRef"));
    }
    // 存活/报告 metrics 的 execution 双代次必须 >= 1（E:0 只允许出现在首次分配前）。
    let preparation_generation = require_metrics_u53(field("preparationGeneration"), "/preparationGeneration", 1)?;
    let execution_generation = require_metrics_u53(field("executionGeneration"), "/executionGeneration", 1)?;
    let Some(sampled_at) = field("sampledAt").as_str() else {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "sampledAt must be an RFC3339 UTC timestamp ending in Z"));
    };
    if !wasm_metrics_regexes().rfc3339_utc.is_match(sampled_at) {
        return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "sampledAt must be an RFC3339 UTC timestamp ending in Z"));
    }
    parse_rfc3339_utc_millis(sampled_at).map_err(|e| metrics_err(WASM_ENGINE_METRICS_INVALID, e.detail))?;
    let availability = match field("availability").as_str() {
        Some("available") => WasmEngineAvailability::Available,
        Some("unavailable") => WasmEngineAvailability::Unavailable,
        _ => return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, r#"availability must be exactly "available" or "unavailable""#)),
    };
    let engine_field = field("engine");
    let engine = match (availability, engine_field) {
        (WasmEngineAvailability::Unavailable, serde_json::Value::Null) => None,
        (WasmEngineAvailability::Unavailable, _) => {
            return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "engine must be null exactly when availability is unavailable"));
        }
        (WasmEngineAvailability::Available, serde_json::Value::Null) => {
            return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "an available sample must carry the exact engine counters object"));
        }
        (WasmEngineAvailability::Available, value) => {
            require_exact_keys(value, "/engine", &ENGINE_COUNTER_KEYS)?;
            let engine_object = value.as_object().expect("exact-key check passed");
            let counter = |name: &str| engine_object.get(name).expect("exact-key check passed");
            let fuel_consumed_cumulative = match counter("fuelConsumedCumulative") {
                serde_json::Value::Null => None,
                other => Some(require_metrics_u53(other, "/engine/fuelConsumedCumulative", 0)?),
            };
            let epoch_timeouts_cumulative = require_metrics_u53(counter("epochTimeoutsCumulative"), "/engine/epochTimeoutsCumulative", 0)?;
            let instances_live_instant = require_metrics_u53(counter("instancesLiveInstant"), "/engine/instancesLiveInstant", 0)?;
            let instances_high_water_cumulative = require_metrics_u53(counter("instancesHighWaterCumulative"), "/engine/instancesHighWaterCumulative", 0)?;
            let guest_memory_bytes_instant = require_metrics_u53(counter("guestMemoryBytesInstant"), "/engine/guestMemoryBytesInstant", 0)?;
            Some(WasmEngineCountersV1 {
                fuel_consumed_cumulative,
                epoch_timeouts_cumulative,
                instances_live_instant,
                instances_high_water_cumulative,
                guest_memory_bytes_instant,
            })
        }
    };
    Ok(WasmEngineMetricsV1 {
        schema_version: 1,
        sandbox_id: sandbox_id.to_string(),
        version_id: version_id.to_string(),
        package_digest,
        runtime_binding,
        capability_record_revision,
        capability_record_hash,
        secret_revision,
        config_revision,
        config_snapshot_ref,
        preparation_generation,
        execution_generation,
        sampled_at: sampled_at.to_string(),
        availability,
        engine,
    })
}

/// correlate（对位 correlateWasmEngineMetricsV1）：任一身份/binding/capability/
/// secret/config/P-E 字段与当前执行记录不一致即拒绝。已验证值域上的结构相等以
/// 字段相等为准（RuntimeBindingIdentityV1 为纯原始字段结构，PartialEq 即 JCS 相等）。
pub fn correlate_wasm_engine_metrics(expected: &WasmEngineMetricsFence, reported: &WasmEngineMetricsV1) -> Result<(), AdmissionError> {
    let mismatch = |field: &str, detail: &str| metrics_err(WASM_ENGINE_METRICS_MISMATCH, format!("/{field}: metrics {field} does not match the current execution record ({detail})"));
    if expected.sandbox_id != reported.sandbox_id {
        return Err(mismatch("sandboxId", "sandbox differs"));
    }
    if expected.version_id != reported.version_id {
        return Err(mismatch("versionId", "version differs"));
    }
    if expected.preparation_generation != reported.preparation_generation || expected.execution_generation != reported.execution_generation {
        return Err(metrics_err(
            WASM_ENGINE_METRICS_STALE,
            "/executionGeneration: metrics preparation/execution generations do not match the current execution record",
        ));
    }
    if expected.package_digest != reported.package_digest {
        return Err(mismatch("packageDigest", "package digest differs"));
    }
    if expected.runtime_binding != reported.runtime_binding {
        return Err(mismatch("runtimeBinding", "binding (including catalog revision/hash) differs"));
    }
    if expected.capability_record_revision != reported.capability_record_revision || expected.capability_record_hash != reported.capability_record_hash {
        return Err(mismatch("capabilityRecordRevision", "capability record pin differs"));
    }
    if expected.secret_revision != reported.secret_revision {
        return Err(mismatch("secretRevision", "secret revision differs"));
    }
    if expected.config_revision != reported.config_revision || expected.config_snapshot_ref != reported.config_snapshot_ref {
        return Err(mismatch("configRevision", "config revision/reference differs"));
    }
    Ok(())
}

/// 同 E 非负单调窗口（对位 acceptWasmEngineMetricsSample 的纯函数语义）。
/// 首条 available 样本建 baseline；此后 sampledAt 必须严格更晚；fuel（启用时）、
/// epochTimeouts、highWater 同 E 只增不减；瞬时值双向；旧 generation 延迟样本是
/// stale 不是 reset——重置只能经 Kernel 接受新 generation fence 后的 open_window。
#[derive(Debug, Clone, PartialEq)]
pub enum WasmEngineMetricsWindow {
    AwaitingFirstSample { execution_generation: u64 },
    Tracking {
        execution_generation: u64,
        last_accepted_sampled_at: String,
        fuel_consumed_cumulative: Option<u64>,
        epoch_timeouts_cumulative: u64,
        instances_high_water_cumulative: u64,
    },
}

impl WasmEngineMetricsWindow {
    pub fn execution_generation(&self) -> u64 {
        match self {
            WasmEngineMetricsWindow::AwaitingFirstSample { execution_generation } => *execution_generation,
            WasmEngineMetricsWindow::Tracking { execution_generation, .. } => *execution_generation,
        }
    }
}

/// fuel_enabled 来自 pinned NodeCapabilityRecordV1.engine.fuelPerRequest：
/// Some(true) 样本 fuel 必须非 null；Some(false) 必须为 null；None 只强制同 E 窗口内
/// 表示一致（fail-closed：Kernel 未持有 pinned record 时不得放宽为任意表示）。
pub fn accept_wasm_engine_metrics_sample(
    window: &WasmEngineMetricsWindow,
    payload: &WasmEngineMetricsV1,
    fuel_enabled: Option<bool>,
) -> Result<WasmEngineMetricsWindow, AdmissionError> {
    if payload.execution_generation != window.execution_generation() {
        return Err(metrics_err(
            WASM_ENGINE_METRICS_STALE,
            "a delayed prior-generation metrics payload is stale, not a reset; a fresh baseline requires the Kernel-accepted new generation fence",
        ));
    }
    let payload_sampled_ms = parse_rfc3339_utc_millis(&payload.sampled_at)
        .map_err(|e| metrics_err(WASM_ENGINE_METRICS_INVALID, e.detail))?;
    if let WasmEngineMetricsWindow::Tracking { last_accepted_sampled_at, .. } = window {
        let last_ms = parse_rfc3339_utc_millis(last_accepted_sampled_at)
            .map_err(|e| metrics_err(WASM_ENGINE_METRICS_INVALID, e.detail))?;
        if payload_sampled_ms <= last_ms {
            return Err(metrics_err(
                WASM_ENGINE_METRICS_TIME_REGRESSION,
                "later accepted samples need strictly later sampledAt",
            ));
        }
    }
    let Some(engine) = &payload.engine else {
        // unavailable 样本不带 counters：baseline（若有）保持不变，仅推进接受时刻。
        return Ok(match window {
            WasmEngineMetricsWindow::AwaitingFirstSample { execution_generation } => {
                WasmEngineMetricsWindow::AwaitingFirstSample { execution_generation: *execution_generation }
            }
            WasmEngineMetricsWindow::Tracking { execution_generation, fuel_consumed_cumulative, epoch_timeouts_cumulative, instances_high_water_cumulative, .. } => {
                WasmEngineMetricsWindow::Tracking {
                    execution_generation: *execution_generation,
                    last_accepted_sampled_at: payload.sampled_at.clone(),
                    fuel_consumed_cumulative: *fuel_consumed_cumulative,
                    epoch_timeouts_cumulative: *epoch_timeouts_cumulative,
                    instances_high_water_cumulative: *instances_high_water_cumulative,
                }
            }
        });
    };
    if fuel_enabled == Some(true) && engine.fuel_consumed_cumulative.is_none() {
        return Err(metrics_err(
            WASM_ENGINE_METRICS_FUEL_REPRESENTATION,
            "fuel is enabled by the pinned node record; null is the disabled-only representation",
        ));
    }
    if fuel_enabled == Some(false) && engine.fuel_consumed_cumulative.is_some() {
        return Err(metrics_err(
            WASM_ENGINE_METRICS_FUEL_REPRESENTATION,
            "fuel is disabled by the pinned node record; fuelConsumedCumulative must remain null for that execution generation",
        ));
    }
    if let WasmEngineMetricsWindow::Tracking {
        fuel_consumed_cumulative,
        epoch_timeouts_cumulative,
        instances_high_water_cumulative,
        ..
    } = window
    {
        if fuel_consumed_cumulative.is_some() != engine.fuel_consumed_cumulative.is_some() {
            return Err(metrics_err(
                WASM_ENGINE_METRICS_FUEL_REPRESENTATION,
                "the fuel disabled/enabled representation must remain constant within one execution generation",
            ));
        }
        if let (Some(prior), Some(current)) = (fuel_consumed_cumulative, engine.fuel_consumed_cumulative) {
            if current < *prior {
                return Err(metrics_err(
                    WASM_ENGINE_METRICS_COUNTER_REGRESSION,
                    "fuelConsumedCumulative must be greater than or equal to its prior accepted value within the same execution generation",
                ));
            }
        }
        if engine.epoch_timeouts_cumulative < *epoch_timeouts_cumulative {
            return Err(metrics_err(
                WASM_ENGINE_METRICS_COUNTER_REGRESSION,
                "epochTimeoutsCumulative must be greater than or equal to its prior accepted value within the same execution generation",
            ));
        }
        if engine.instances_high_water_cumulative < *instances_high_water_cumulative {
            return Err(metrics_err(
                WASM_ENGINE_METRICS_COUNTER_REGRESSION,
                "instancesHighWaterCumulative must be greater than or equal to its prior accepted value within the same execution generation",
            ));
        }
    }
    Ok(WasmEngineMetricsWindow::Tracking {
        execution_generation: window.execution_generation(),
        last_accepted_sampled_at: payload.sampled_at.clone(),
        fuel_consumed_cumulative: engine.fuel_consumed_cumulative,
        epoch_timeouts_cumulative: engine.epoch_timeouts_cumulative,
        instances_high_water_cumulative: engine.instances_high_water_cumulative,
    })
}

/// 每个 sandbox 的接受状态（窗口 + 打开窗口时的 fence 与 application 关联；
/// last_accepted 供 monitor 投影当前口径）。
struct WasmEngineMetricsEntry {
    application_id: Option<String>,
    fence: WasmEngineMetricsFence,
    window: WasmEngineMetricsWindow,
    last_accepted: Option<WasmEngineMetricsV1>,
}

/// Kernel 侧 engine metrics 接受/投影注册表（进程内共享；Clone 共享同一底层存储）。
/// 重置唯一入口是 open_window（Kernel 接受新 generation fence 时调用）。
#[derive(Clone)]
pub struct WasmEngineMetricsRegistry {
    inner: Arc<Mutex<HashMap<String, WasmEngineMetricsEntry>>>,
    version: Arc<tokio::sync::watch::Sender<()>>,
}

impl Default for WasmEngineMetricsRegistry {
    fn default() -> Self {
        let (version, _) = tokio::sync::watch::channel(());
        Self { inner: Arc::new(Mutex::new(HashMap::new())), version: Arc::new(version) }
    }
}

impl WasmEngineMetricsRegistry {
    /// Kernel 接受新 generation fence 时打开（或幂等确认）该 sandbox 的窗口。
    /// 同 E 幂等（仅刷新 fence/application 关联记录）；更高 E 重置为 awaiting-first-
    /// sample（唯一重置点）；更低 E 是 stale（不回拨）。
    pub fn open_window(&self, fence: &WasmEngineMetricsFence, application_id: Option<&str>) -> Result<(), AdmissionError> {
        let mut entries = self.inner.lock().expect("wasm engine metrics lock");
        if let Some(existing) = entries.get(&fence.sandbox_id) {
            let existing_generation = existing.window.execution_generation();
            if fence.execution_generation < existing_generation {
                return Err(metrics_err(
                    WASM_ENGINE_METRICS_STALE,
                    "an engine metrics window may only move forward: the new fence carries a lower execution generation",
                ));
            }
            if fence.execution_generation == existing_generation {
                if &existing.fence != fence {
                    return Err(metrics_err(
                        WASM_ENGINE_METRICS_MISMATCH,
                        "re-fencing the same execution generation must carry the identical execution record",
                    ));
                }
                return Ok(());
            }
        }
        if fence.preparation_generation < 1 || fence.execution_generation < 1 {
            return Err(metrics_err(WASM_ENGINE_METRICS_INVALID, "a metrics window requires an alive execution generation (>= 1)"));
        }
        entries.insert(
            fence.sandbox_id.clone(),
            WasmEngineMetricsEntry {
                application_id: application_id.map(str::to_string),
                fence: fence.clone(),
                window: WasmEngineMetricsWindow::AwaitingFirstSample { execution_generation: fence.execution_generation },
                last_accepted: None,
            },
        );
        let _ = self.version.send(());
        Ok(())
    }

    /// 接受一条 supervisor 样本：wire 校验 → fence correlate → 窗口单调推进。
    /// 无窗口（该 E 从未被 fence 接受）或 E 落后均 stale；接受的样本更新投影并在
    /// 成功推进时广播 monitor 变更。fuel_enabled 来自 pinned capability record。
    pub fn accept(&self, fence: &WasmEngineMetricsFence, payload: &serde_json::Value, fuel_enabled: Option<bool>) -> Result<(), AdmissionError> {
        let validated = validate_wasm_engine_metrics_v1(payload)?;
        self.accept_validated(fence, &validated, fuel_enabled)
    }

    /// 同 accept，但输入已通过 validate_wasm_engine_metrics_v1（supervisor 拉取客户端
    /// 在传输边界校验后的复用入口；不跳过 correlate 与窗口判定）。
    pub fn accept_validated(&self, fence: &WasmEngineMetricsFence, validated: &WasmEngineMetricsV1, fuel_enabled: Option<bool>) -> Result<(), AdmissionError> {
        correlate_wasm_engine_metrics(fence, validated)?;
        let mut entries = self.inner.lock().expect("wasm engine metrics lock");
        let existing = entries.get(&fence.sandbox_id).ok_or_else(|| {
            metrics_err(WASM_ENGINE_METRICS_STALE, "no Kernel-accepted generation fence exists for this execution; open the window before accepting samples")
        })?;
        // 先判代次再判记录：旧 generation fence/样本一律 stale（不是 mismatch）；
        // 同 E 而记录漂移才是 Kernel 侧矛盾（mismatch）。
        if fence.execution_generation != existing.window.execution_generation() {
            return Err(metrics_err(
                WASM_ENGINE_METRICS_STALE,
                "the fence names an execution generation other than the Kernel-accepted current one",
            ));
        }
        if &existing.fence != fence {
            return Err(metrics_err(WASM_ENGINE_METRICS_MISMATCH, "the fence differs from the Kernel-accepted execution record for this execution generation"));
        }
        let next_window = accept_wasm_engine_metrics_sample(&existing.window, validated, fuel_enabled)?;
        let updated = WasmEngineMetricsEntry {
            application_id: existing.application_id.clone(),
            fence: existing.fence.clone(),
            window: next_window,
            last_accepted: Some(validated.clone()),
        };
        entries.insert(fence.sandbox_id.clone(), updated);
        let _ = self.version.send(());
        Ok(())
    }

    /// owner monitor 投影（engine 口径；与 resources 的 cgroup/进程口径分开标注）。
    /// 无窗口/无关联 → Null；awaiting-first-sample 或最后接受样本为 unavailable →
    /// availability:"unavailable" + engine:null（唯一表示，绝不补零）。
    pub fn project_by_sandbox(&self, sandbox_id: &str) -> serde_json::Value {
        let entries = self.inner.lock().expect("wasm engine metrics lock");
        match entries.get(sandbox_id) {
            Some(entry) => project_wasm_engine_entry(entry),
            None => serde_json::Value::Null,
        }
    }

    /// 按 applicationId 投影（monitor app 行入口；关联在 open_window 时登记）。
    pub fn project_by_application(&self, application_id: &str) -> serde_json::Value {
        let entries = self.inner.lock().expect("wasm engine metrics lock");
        match entries.values().find(|entry| entry.application_id.as_deref() == Some(application_id)) {
            Some(entry) => project_wasm_engine_entry(entry),
            None => serde_json::Value::Null,
        }
    }

    /// monitor 连接的变更订阅句柄（与 AppMetrics::subscribe 同语义）。
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.version.subscribe()
    }
}

fn project_wasm_engine_entry(entry: &WasmEngineMetricsEntry) -> serde_json::Value {
    let (availability, engine, sampled_at) = match &entry.last_accepted {
        None => (WasmEngineAvailability::Unavailable, None, None),
        Some(payload) => (payload.availability, payload.engine.clone(), Some(payload.sampled_at.clone())),
    };
    serde_json::json!({
        "scope": "wasm-engine",
        "sandboxId": entry.fence.sandbox_id,
        "versionId": entry.fence.version_id,
        "preparationGeneration": entry.fence.preparation_generation,
        "executionGeneration": entry.fence.execution_generation,
        "sampledAt": sampled_at,
        "availability": match availability {
            WasmEngineAvailability::Available => "available",
            WasmEngineAvailability::Unavailable => "unavailable",
        },
        "engine": engine,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_average_round_to_tenth() {
        let metrics = AppMetrics::default();
        metrics.in_flight_enter("admin");
        let started = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        metrics.observe("admin", started, false);
        let snapshot = metrics.snapshot("admin");
        assert_eq!(snapshot.requests, 1);
        assert_eq!(snapshot.errors, 0);
        assert_eq!(snapshot.in_flight, 0);
        assert!(snapshot.average_latency_ms >= 1.9);
        assert!(snapshot.last_request_at.is_some());
        // 未记录过的应用：可证明的零，无捏造值。
        let unknown = metrics.snapshot("mcp");
        assert_eq!((unknown.requests, unknown.errors, unknown.in_flight), (0, 0, 0));
        assert_eq!(unknown.average_latency_ms, 0.0);
        assert!(unknown.last_request_at.is_none());
    }

    #[test]
    fn in_flight_never_goes_negative() {
        let metrics = AppMetrics::default();
        let started = std::time::Instant::now();
        // 无配对 enter 的 observe：饱和递减到 0，绝不出现负并发（对位 JS Math.max(0, x-1)）。
        metrics.observe("admin", started, false);
        assert_eq!(metrics.snapshot("admin").in_flight, 0);
    }

    // --- wasm engine metrics v1（4.1）---
    // 契约对位 fixture：与 packages/contracts/wasm-health.ts exampleWasmEngineMetricsV1()
    // 同一对象（JCS 字节由 TS 侧 golden 锁定；此处作为跨实现 wire 向量）。
    fn example_metrics_json(sampled_at: &str, execution_generation: u64) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 1,
            "sandboxId": "sbx-vector",
            "versionId": format!("{}-1", "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532"),
            "packageDigest": "0".repeat(64),
            "runtimeBinding": {
                "kind": "wasm",
                "catalogRevision": 9,
                "catalogHash": "ab".repeat(32),
                "entryKey": "iweb-wasmd",
                "imageDigest": format!("sha256:{}", "cd".repeat(32)),
                "hostABI": "iweb-wasmd-abi@1.0.0",
                "world": "wasi:http/proxy@0.2.8"
            },
            "capabilityRecordRevision": 5,
            "capabilityRecordHash": "2".repeat(64),
            "secretRevision": 3,
            "configRevision": 2,
            "configSnapshotRef": "7".repeat(64),
            "preparationGeneration": 1,
            "executionGeneration": execution_generation,
            "sampledAt": sampled_at,
            "availability": "available",
            "engine": {
                "fuelConsumedCumulative": 1000,
                "epochTimeoutsCumulative": 0,
                "instancesLiveInstant": 1,
                "instancesHighWaterCumulative": 1,
                "guestMemoryBytesInstant": 2097152
            }
        })
    }

    fn example_fence(execution_generation: u64) -> WasmEngineMetricsFence {
        let payload = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:00Z", execution_generation)).expect("example validates");
        WasmEngineMetricsFence {
            sandbox_id: payload.sandbox_id,
            version_id: payload.version_id,
            package_digest: payload.package_digest,
            runtime_binding: payload.runtime_binding,
            capability_record_revision: payload.capability_record_revision,
            capability_record_hash: payload.capability_record_hash,
            secret_revision: payload.secret_revision,
            config_revision: payload.config_revision,
            config_snapshot_ref: payload.config_snapshot_ref,
            preparation_generation: payload.preparation_generation,
            execution_generation: payload.execution_generation,
        }
    }

    #[test]
    fn example_wire_validates_and_rejects_shape_drift() {
        let payload = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:00Z", 1)).expect("example validates");
        assert_eq!(payload.availability, WasmEngineAvailability::Available);
        assert_eq!(payload.engine.as_ref().expect("counters").fuel_consumed_cumulative, Some(1000));
        // 未知字段拒绝（对位 TS requireExactKeys 的 unknown-field 判负）。
        let mut unknown = example_metrics_json("2026-08-26T00:00:00Z", 1);
        unknown["surplus"] = serde_json::json!(1);
        let rejected = validate_wasm_engine_metrics_v1(&unknown).expect_err("unknown field");
        assert_eq!(rejected.code, WASM_ENGINE_METRICS_INVALID);
        // 必备字段缺失拒绝（serde Option 缺省 None 不能替代「字段必须出现」）。
        let mut missing = example_metrics_json("2026-08-26T00:00:00Z", 1);
        missing.as_object_mut().expect("object").remove("configSnapshotRef");
        assert!(validate_wasm_engine_metrics_v1(&missing).is_err());
        // schemaVersion 字面量。
        let mut wrong_schema = example_metrics_json("2026-08-26T00:00:00Z", 1);
        wrong_schema["schemaVersion"] = serde_json::json!(2);
        assert!(validate_wasm_engine_metrics_v1(&wrong_schema).is_err());
        // celld 单字段信号（generation/sequence）不可作为 wasm 代次（身份不完整路径）。
        let mut celld_signal = example_metrics_json("2026-08-26T00:00:00Z", 1);
        celld_signal["generation"] = serde_json::json!(4);
        assert!(validate_wasm_engine_metrics_v1(&celld_signal).is_err());
    }

    #[test]
    fn unavailable_engine_coupling_and_fuel_null_semantics() {
        let mut unavailable = example_metrics_json("2026-08-26T00:00:00Z", 1);
        unavailable["availability"] = serde_json::json!("unavailable");
        // unavailable 唯一表示：engine 必须为 null。
        let still_available_counters = validate_wasm_engine_metrics_v1(&unavailable).expect_err("engine must be null");
        assert_eq!(still_available_counters.code, WASM_ENGINE_METRICS_INVALID);
        unavailable["engine"] = serde_json::Value::Null;
        validate_wasm_engine_metrics_v1(&unavailable).expect("unavailable + null engine validates");
        // available 样本：fuel null（禁用唯一表示）合法。
        let mut fuel_disabled = example_metrics_json("2026-08-26T00:00:00Z", 1);
        fuel_disabled["engine"]["fuelConsumedCumulative"] = serde_json::Value::Null;
        validate_wasm_engine_metrics_v1(&fuel_disabled).expect("fuel disabled representation");
        // configRevision:0 必须配 configSnapshotRef:null。
        let mut config_zero = fuel_disabled;
        config_zero["configRevision"] = serde_json::json!(0);
        assert!(validate_wasm_engine_metrics_v1(&config_zero).is_err());
        config_zero["configSnapshotRef"] = serde_json::Value::Null;
        validate_wasm_engine_metrics_v1(&config_zero).expect("config zero coupling");
    }

    #[test]
    fn correlate_rejects_every_identity_drift_as_stale_or_mismatch() {
        let fence = example_fence(2);
        let base = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:00Z", 2)).expect("valid");
        correlate_wasm_engine_metrics(&fence, &base).expect("exact record correlates");
        // 旧 generation 的延迟样本：stale（不是 reset）。
        let old = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:00Z", 1)).expect("valid");
        let stale = correlate_wasm_engine_metrics(&fence, &old).expect_err("stale generation");
        assert_eq!(stale.code, WASM_ENGINE_METRICS_STALE);
        // 其它字段漂移：mismatch。
        let mut drift = example_metrics_json("2026-08-26T00:00:00Z", 2);
        drift["secretRevision"] = serde_json::json!(4);
        let mismatch = correlate_wasm_engine_metrics(&fence, &validate_wasm_engine_metrics_v1(&drift).expect("valid")).expect_err("secret drift");
        assert_eq!(mismatch.code, WASM_ENGINE_METRICS_MISMATCH);
        let mut binding_drift = example_metrics_json("2026-08-26T00:00:00Z", 2);
        binding_drift["runtimeBinding"]["catalogRevision"] = serde_json::json!(10);
        let binding = correlate_wasm_engine_metrics(&fence, &validate_wasm_engine_metrics_v1(&binding_drift).expect("valid")).expect_err("binding drift");
        assert_eq!(binding.code, WASM_ENGINE_METRICS_MISMATCH);
    }

    #[test]
    fn window_is_monotonic_within_e_and_resets_only_via_new_fence() {
        let first = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:01Z", 4)).expect("valid");
        let window = accept_wasm_engine_metrics_sample(
            &WasmEngineMetricsWindow::AwaitingFirstSample { execution_generation: 4 },
            &first,
            Some(true),
        ).expect("first sample establishes the baseline");
        assert!(matches!(window, WasmEngineMetricsWindow::Tracking { .. }));
        // 同一时刻（相等即拒绝：strictly later）。
        let same_time = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:01Z", 4)).expect("valid");
        let regression = accept_wasm_engine_metrics_sample(&window, &same_time, Some(true)).expect_err("equal instant");
        assert_eq!(regression.code, WASM_ENGINE_METRICS_TIME_REGRESSION);
        // counter 回退拒绝。
        let mut counter_drop = example_metrics_json("2026-08-26T00:00:02Z", 4);
        counter_drop["engine"]["epochTimeoutsCumulative"] = serde_json::json!(0);
        counter_drop["engine"]["instancesHighWaterCumulative"] = serde_json::json!(0);
        let dropped = accept_wasm_engine_metrics_sample(&window, &validate_wasm_engine_metrics_v1(&counter_drop).expect("valid"), Some(true)).expect_err("counter regression");
        assert_eq!(dropped.code, WASM_ENGINE_METRICS_COUNTER_REGRESSION);
        // 旧 generation 延迟样本：stale，不是 reset。
        let delayed = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:09Z", 3)).expect("valid");
        let stale = accept_wasm_engine_metrics_sample(&window, &delayed, Some(true)).expect_err("delayed prior generation");
        assert_eq!(stale.code, WASM_ENGINE_METRICS_STALE);
        // fuel 表示：启用时 null 拒绝。
        let mut fuel_null = example_metrics_json("2026-08-26T00:00:02Z", 4);
        fuel_null["engine"]["fuelConsumedCumulative"] = serde_json::Value::Null;
        let fuel = accept_wasm_engine_metrics_sample(&window, &validate_wasm_engine_metrics_v1(&fuel_null).expect("valid"), Some(true)).expect_err("null fuel while enabled");
        assert_eq!(fuel.code, WASM_ENGINE_METRICS_FUEL_REPRESENTATION);
        // 禁用时数值拒绝（首样本窗口直接判表示）。
        let enabled_sample = validate_wasm_engine_metrics_v1(&example_metrics_json("2026-08-26T00:00:01Z", 5)).expect("valid");
        let disabled = accept_wasm_engine_metrics_sample(
            &WasmEngineMetricsWindow::AwaitingFirstSample { execution_generation: 5 },
            &enabled_sample,
            Some(false),
        ).expect_err("numeric fuel while disabled");
        assert_eq!(disabled.code, WASM_ENGINE_METRICS_FUEL_REPRESENTATION);
        // unavailable 样本推进接受时刻、保持 baseline。
        let mut unavailable = example_metrics_json("2026-08-26T00:00:03Z", 4);
        unavailable["availability"] = serde_json::json!("unavailable");
        unavailable["engine"] = serde_json::Value::Null;
        let after = accept_wasm_engine_metrics_sample(&window, &validate_wasm_engine_metrics_v1(&unavailable).expect("valid"), Some(true)).expect("unavailable advances time");
        match after {
            WasmEngineMetricsWindow::Tracking { last_accepted_sampled_at, epoch_timeouts_cumulative, .. } => {
                assert_eq!(last_accepted_sampled_at, "2026-08-26T00:00:03Z");
                assert_eq!(epoch_timeouts_cumulative, 0);
            }
            other => panic!("expected tracking window, got {other:?}"),
        }
    }

    #[test]
    fn registry_accepts_and_projects_labeled_engine_scope() {
        let registry = WasmEngineMetricsRegistry::default();
        let fence = example_fence(1);
        // 无窗口时直接 accept：stale（该 E 从未被 Kernel fence 接受）。
        let first_payload = example_metrics_json("2026-08-26T00:00:00Z", 1);
        let no_window = registry.accept(&fence, &first_payload, Some(true)).expect_err("window must open first");
        assert_eq!(no_window.code, WASM_ENGINE_METRICS_STALE);
        // open 后、首样本前：唯一投影 unavailable + engine:null（不补零）。
        registry.open_window(&fence, Some("notes")).expect("open window");
        let awaiting = registry.project_by_application("notes");
        assert_eq!(awaiting["scope"], "wasm-engine");
        assert_eq!(awaiting["availability"], "unavailable");
        assert!(awaiting["engine"].is_null());
        assert!(awaiting["sampledAt"].is_null());
        assert_eq!(awaiting["executionGeneration"], 1);
        // 接受 available 样本：投影携带 counters，且与 cgroup/resources 口径分开标注。
        registry.accept(&fence, &first_payload, Some(true)).expect("accept first sample");
        let projected = registry.project_by_sandbox("sbx-vector");
        assert_eq!(projected["scope"], "wasm-engine");
        assert_eq!(projected["availability"], "available");
        assert_eq!(projected["engine"]["guestMemoryBytesInstant"], 2097152);
        assert_eq!(projected["engine"]["fuelConsumedCumulative"], 1000);
        assert_eq!(projected["sampledAt"], "2026-08-26T00:00:00Z");
        // 更高 E 的新 fence：唯一重置入口，之后旧 E 样本 stale、投影回到无首样本。
        let mut higher_fence = example_fence(2);
        higher_fence.execution_generation = 2;
        registry.open_window(&higher_fence, Some("notes")).expect("open higher generation");
        let reset = registry.project_by_application("notes");
        assert_eq!(reset["availability"], "unavailable");
        assert!(reset["engine"].is_null());
        let old_payload = example_metrics_json("2026-08-26T00:00:05Z", 1);
        let stale = registry.accept(&fence, &old_payload, Some(true)).expect_err("old generation after reset");
        assert_eq!(stale.code, WASM_ENGINE_METRICS_STALE);
        // 更低 E 的 open：不回拨。
        let mut lower_fence = example_fence(1);
        lower_fence.execution_generation = 1;
        let back = registry.open_window(&lower_fence, Some("notes")).expect_err("lower generation rejected");
        assert_eq!(back.code, WASM_ENGINE_METRICS_STALE);
        // 未关联应用：Null（非 wasm/无窗口），不是 unavailable。
        assert!(registry.project_by_application("admin").is_null());
        assert!(registry.project_by_sandbox("sbx-none").is_null());
    }
}
