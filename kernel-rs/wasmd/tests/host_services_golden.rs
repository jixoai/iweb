//! add-wasm-host-services 任务 7.5（跨实现 golden + 端到端链路）：wasmd 侧消费者，
//! 吃与 bun 侧 tests/wasm-host-services-golden.test.ts、Kernel 侧
//! kernel-rs/iweb-kernel/tests/wasm_host_services_golden.rs 同一份 fixture：
//! tests/fixtures/wasm/host-services-golden-vectors.json。
//!
//! 覆盖 wasmd 拥有的共享语义：
//! - policyDigest = digestV2("iweb-wasm-host-policy-v2", JCS(payload))（正/负）；
//! - kv cursor 决策表（经真 SQLite 文件的 KvBackend 行为驱动，非纯函数复刻）；
//! - sql/kv/logging 错误 case ↔ detailCode/host-call code 映射闭集；
//! - logging 环计量与 sql 值 wire 字节数；
//! - host-call frame dispatch 全链（frame → 身份门 → 后端 → 响应）序列化场景：
//!   kv set→list→cursor 续、sql create 拒绝/insert/select、logging write→drain，
//!   并断言「数据面 mutation 不改 ledger 外任何状态」（被拒调用零字节写入、
//!   成功调用后 identity/policy 不变、数据目录文件集恒为三件套）。
//!
//! 已知分歧（上报 owner，fixture 双侧钉死）：TS 契约（wasm-host-kv.ts）把
//! 「快照被回收」映射为 cursor-expired；kv.rs 当前把 dead snapshot 归入 scope
//! 拒绝（invalid-key）。fixture 的 rustKnownDivergence 字段钉住 Rust 现值。

use iweb_wasmd::host_services::frame::{
    encode_base64url, HostCallFrameRequestV2, HostCallFrameResponseV2, FRAME_MAX_BYTES,
    HOST_CALL_DEADLINE_MAX_MS, HOST_CALL_ERROR_CODES, HOST_CALL_METHODS, HOST_CALL_PROTOCOL,
};
use iweb_wasmd::host_services::kv::{KvBackend, KvError};
use iweb_wasmd::host_services::logging::{
    LoggingError, LoggingEvent, LoggingField, LoggingHostContext, LogLevel, measure_logging_event_bytes,
};
use iweb_wasmd::host_services::policy::{
    HostServicePolicyPayloadV2, HostServicePolicyV2, WasmdHostServicesContextV2, WASMD_HOST_POLICY_INVALID,
};
use iweb_wasmd::host_services::quota::QuotaLedger;
use iweb_wasmd::host_services::sql::{
    open_sql_connection, sql_value_wire_bytes, SqlBackend, SqlError, SqlValue,
};
use iweb_wasmd::host_services::{
    add_host_service_imports_to_linker, HostCallBudget, HostServicesProvider, KvHostService,
    LoggingHostService, SqlHostService,
};
use iweb_wasmd::jcs::{jcs_bytes, parse_canonical};
use iweb_wasmd::wire::{RuntimeBindingIdentityV1, WasmdIdentityV2, MATRIX_HOST_ABI_V2, MATRIX_WORLD};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// fixture 装载（camelCase 结构镜像 bun/Kernel 两侧）
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenDoc {
    version: u32,
    policy_digest: Vec<PolicyVector>,
    policy_negative: Vec<PolicyNegativeVector>,
    sql_value_wire_bytes: Vec<SqlValueVector>,
    sql_error_map: Vec<ErrorMapEntry>,
    kv_error_map: Vec<ErrorMapEntry>,
    logging_error_map: Vec<ErrorMapEntry>,
    logging_metering: Vec<LoggingMeteringVector>,
    kv_cursor_decisions: Vec<CursorDecisionVector>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyVector {
    name: String,
    payload: Value,
    expected_policy_digest: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyNegativeVector {
    #[allow(dead_code)]
    name: String,
    payload: Value,
    policy_digest: String,
    ts_error_code: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SqlValueVector {
    #[allow(dead_code)]
    name: String,
    value: SqlValueFixture,
    expected_bytes: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SqlValueFixture {
    kind: String,
    value: Option<Value>,
    base64: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorMapEntry {
    case: String,
    wire_code: String,
    host_call_code: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoggingMeteringVector {
    #[allow(dead_code)]
    name: String,
    host_context: LoggingHostFixture,
    event: LoggingEventFixture,
    event_id: u64,
    expected_bytes: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoggingHostFixture {
    application_id: String,
    version_id: String,
    preparation_generation: u64,
    execution_generation: u64,
    timestamp_utc: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoggingEventFixture {
    level: String,
    message: String,
    fields: Vec<LoggingFieldFixture>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoggingFieldFixture {
    key: String,
    value: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorDecisionVector {
    name: String,
    #[allow(dead_code)]
    binding: Value,
    #[allow(dead_code)]
    request: Value,
    expected: String,
    rust_known_divergence: Option<String>,
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/wasm/host-services-golden-vectors.json")
}

fn load_doc() -> GoldenDoc {
    let text = std::fs::read_to_string(fixture_path())
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", fixture_path().display()));
    serde_json::from_str(&text).expect("golden fixture JSON must parse")
}

fn cursor_case<'a>(doc: &'a GoldenDoc, name: &str) -> &'a CursorDecisionVector {
    doc.kv_cursor_decisions.iter().find(|entry| entry.name == name).unwrap_or_else(|| panic!("cursor case {name} missing"))
}

// ---------------------------------------------------------------------------
// 身份/策略/后端 fixture（真 SQLite 文件；与单元测试同式但走集成面）
// ---------------------------------------------------------------------------

fn vector_identity() -> WasmdIdentityV2 {
    WasmdIdentityV2 {
        application_id: "alpha".into(),
        sandbox_id: "sbx-vector".into(),
        version_id: format!("{}-1", "a".repeat(64)),
        package_digest: "0".repeat(64),
        runtime_binding: RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: MATRIX_HOST_ABI_V2.into(),
            world: MATRIX_WORLD.into(),
        },
        capability_record_revision: 5,
        capability_record_hash: "2".repeat(64),
        secret_revision: 0,
        secret_values_digest: "6".repeat(64),
        config_revision: 0,
        config_snapshot_ref: None,
        config_values_digest: None,
        preparation_generation: 2,
        execution_generation: 2,
    }
}

fn vector_context(policy: HostServicePolicyV2) -> WasmdHostServicesContextV2 {
    WasmdHostServicesContextV2 { schema_version: 2, application_id: "alpha".into(), fence_nonce: "ab".repeat(16), host_service_policy: policy }
}

/// fixture 的 all-three-services payload（含期望 digest）解析为完整策略（复算封口）。
fn fixture_policy(doc: &GoldenDoc, vector_name: &str) -> HostServicePolicyV2 {
    let vector = doc.policy_digest.iter().find(|entry| entry.name == vector_name).expect("policy vector");
    let mut full = vector.payload.clone();
    full.as_object_mut().expect("payload object").insert("policyDigest".into(), Value::String(vector.expected_policy_digest.clone()));
    let policy: HostServicePolicyV2 = serde_json::from_value(full).expect("fixture policy must deserialize");
    policy.validate().expect("fixture policy must validate");
    policy
}

// ---------------------------------------------------------------------------
// golden：policy digestV2（正/负）
// ---------------------------------------------------------------------------

#[test]
fn golden_policy_digest_vectors_match_and_negative_fails_closed() {
    let doc = load_doc();
    assert_eq!(doc.version, 1);
    for vector in &doc.policy_digest {
        let policy = fixture_policy(&doc, &vector.name);
        assert_eq!(policy.policy_digest, vector.expected_policy_digest, "vector {}", vector.name);
        // 复算（不信任 fixture 的 digest 字段本身）。
        let recomputed = HostServicePolicyV2::compute_policy_digest(&policy.payload).expect("recompute");
        assert_eq!(recomputed, vector.expected_policy_digest, "vector {} recompute", vector.name);
    }
    for negative in &doc.policy_negative {
        let mut full = negative.payload.clone();
        full.as_object_mut().expect("payload object").insert("policyDigest".into(), Value::String(negative.policy_digest.clone()));
        let policy: HostServicePolicyV2 = serde_json::from_value(full).expect("deserialize");
        let rejected = policy.validate().expect_err("tampered digest must fail closed");
        assert_eq!(rejected.code, WASMD_HOST_POLICY_INVALID);
        assert_eq!(negative.ts_error_code, "WASM_HOST_POLICY_DIGEST_MISMATCH");
    }
}

// ---------------------------------------------------------------------------
// golden：错误码映射闭集（sql 含 host-call 投影；kv/logging detail 码）
// ---------------------------------------------------------------------------

#[test]
fn golden_sql_error_map_matches_contracts() {
    let doc = load_doc();
    assert_eq!(doc.sql_error_map.len(), 8);
    for entry in &doc.sql_error_map {
        let error = match entry.case.as_str() {
            "invalid-sql" => SqlError::InvalidSql,
            "invalid-parameter" => SqlError::InvalidParameter,
            "constraint" => SqlError::Constraint,
            "busy" => SqlError::Busy,
            "quota-exceeded" => SqlError::QuotaExceeded,
            "limit-exceeded" => SqlError::LimitExceeded,
            "unavailable" => SqlError::Unavailable,
            "internal" => SqlError::Internal,
            other => panic!("unknown sql error case {other}"),
        };
        assert_eq!(error.detail_code(), entry.wire_code, "sql case {}", entry.case);
        assert_eq!(error.host_call_code(), entry.host_call_code.as_deref().expect("host call code"), "sql case {}", entry.case);
    }
}

#[test]
fn golden_kv_error_map_matches_contracts() {
    let doc = load_doc();
    assert_eq!(doc.kv_error_map.len(), 8);
    for entry in &doc.kv_error_map {
        let error = match entry.case.as_str() {
            "invalid-key" => KvError::InvalidKey,
            "not-found" => KvError::NotFound,
            "conflict" => KvError::Conflict,
            "quota-exceeded" => KvError::QuotaExceeded,
            "limit-exceeded" => KvError::LimitExceeded,
            "cursor-expired" => KvError::CursorExpired,
            "unavailable" => KvError::Unavailable,
            "internal" => KvError::Internal,
            other => panic!("unknown kv error case {other}"),
        };
        assert_eq!(error.detail_code(), entry.wire_code, "kv case {}", entry.case);
    }
}

#[test]
fn golden_logging_error_map_matches_contracts() {
    let doc = load_doc();
    assert_eq!(doc.logging_error_map.len(), 4);
    for entry in &doc.logging_error_map {
        let error = match entry.case.as_str() {
            "invalid-event" => LoggingError::InvalidEvent,
            "limit-exceeded" => LoggingError::LimitExceeded,
            "unavailable" => LoggingError::Unavailable,
            "internal" => LoggingError::Internal,
            other => panic!("unknown logging error case {other}"),
        };
        assert_eq!(error.detail_code(), entry.wire_code, "logging case {}", entry.case);
    }
}

// ---------------------------------------------------------------------------
// golden：sql 值 wire 字节数与 logging 环计量（redaction 先于计算）
// ---------------------------------------------------------------------------

fn sql_value_of(fixture: &SqlValueFixture) -> SqlValue {
    match fixture.kind.as_str() {
        "null" => SqlValue::Null,
        "integer" => SqlValue::Integer(fixture.value.as_ref().and_then(Value::as_i64).expect("integer value")),
        "real" => SqlValue::Real(fixture.value.as_ref().and_then(Value::as_f64).expect("real value")),
        "text" => SqlValue::Text(fixture.value.as_ref().and_then(Value::as_str).expect("text value").to_string()),
        "blob" => {
            let raw = base64_decode(fixture.base64.as_deref().expect("blob base64"));
            SqlValue::Blob(raw)
        }
        other => panic!("unknown sql value kind {other}"),
    }
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).expect("fixture base64")
}

#[test]
fn golden_sql_value_wire_bytes_match() {
    let doc = load_doc();
    for vector in &doc.sql_value_wire_bytes {
        assert_eq!(sql_value_wire_bytes(&sql_value_of(&vector.value)) as u64, vector.expected_bytes, "vector {}", vector.name);
    }
}

#[test]
fn golden_logging_metering_matches() {
    let doc = load_doc();
    for vector in &doc.logging_metering {
        let host = LoggingHostContext {
            application_id: vector.host_context.application_id.clone(),
            version_id: vector.host_context.version_id.clone(),
            preparation_generation: vector.host_context.preparation_generation,
            execution_generation: vector.host_context.execution_generation,
            timestamp_utc: vector.host_context.timestamp_utc.clone(),
            operation_id: None,
        };
        let event = LoggingEvent {
            level: LogLevel::parse(&vector.event.level).expect("level"),
            message: vector.event.message.clone(),
            fields: vector.event.fields.iter().map(|field| LoggingField { key: field.key.clone(), value: field.value.clone() }).collect(),
        };
        assert_eq!(measure_logging_event_bytes(&event, &host, vector.event_id), vector.expected_bytes, "vector {}", vector.name);
    }
}

// ---------------------------------------------------------------------------
// golden：kv cursor 决策表（真 SQLite KvBackend 行为驱动）
// ---------------------------------------------------------------------------

const CURSOR_TTL: u64 = 60_000;
const ENVELOPE: u64 = 1_048_576;
const OVERHEAD: u64 = 64;
const RESERVATION_TTL: u64 = 60_000;

struct KvFixture {
    backend: KvBackend,
    ledger: QuotaLedger,
    _dir: tempfile::TempDir,
}

fn kv_fixture(application_id: &str, policy_digest: &str) -> KvFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = open_sql_connection(&dir.path().join("kv.sqlite3")).expect("kv db");
    let backend = KvBackend::new(conn, application_id, policy_digest).expect("kv backend");
    let ledger_conn = open_sql_connection(&dir.path().join("quota.sqlite3")).expect("quota db");
    let ledger = QuotaLedger::new(ledger_conn, application_id).expect("quota ledger");
    KvFixture { backend, ledger, _dir: dir }
}

fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

/// 与 fixture 绑定同构的续游标：3 个可见 key、limit 1、prefix "n."、创建于 t=0
/// （expiry = 0 + cursorTtl 60000，与 fixture 的 expiresAtMs 完全一致）。
fn fresh_cursor(fixture: &mut KvFixture) -> String {
    for key in ["n.1", "n.2", "n.3"] {
        fixture
            .backend
            .set(key, b"v", None, &mut fixture.ledger, ENVELOPE, ENVELOPE, OVERHEAD, RESERVATION_TTL, 0, far_deadline())
            .expect("seed");
    }
    let (_page, cursor) = fixture
        .backend
        .list("n.", None, 1, 256, 65_536, CURSOR_TTL, 0, far_deadline())
        .expect("first page must produce a continuation cursor");
    cursor.expect("continuation cursor")
}

fn cursor_error_of(result: Result<(Vec<iweb_wasmd::host_services::kv::KvListEntry>, Option<String>), KvError>) -> Option<&'static str> {
    match result {
        Ok(_) => None,
        Err(KvError::InvalidKey) => Some("invalid-scope"),
        Err(KvError::CursorExpired) => Some("expired"),
        Err(other) => panic!("cursor decision produced an out-of-table error: {other:?}"),
    }
}

#[test]
fn golden_kv_cursor_decisions_hold_on_the_real_backend() {
    let doc = load_doc();
    assert_eq!(doc.kv_cursor_decisions.len(), 7, "fixture carries the full decision table");

    // valid-continuation（fixture nowMs=30000 < expiresAtMs=60000）。
    let mut fixture = kv_fixture("alpha", &"cd".repeat(32));
    let cursor = fresh_cursor(&mut fixture);
    let ok = fixture.backend.list("n.", Some(&cursor), 1, 256, 65_536, CURSOR_TTL, 30_000, far_deadline());
    assert_eq!(cursor_error_of(ok), None, "case {}", cursor_case(&doc, "valid-continuation").name);

    // cross-prefix：同 token 换 prefix → invalid-scope（先于任何扫描）。
    let cross = fixture.backend.list("x.", Some(&cursor), 1, 256, 65_536, CURSOR_TTL, 30_000, far_deadline());
    assert_eq!(cursor_error_of(cross).unwrap(), cursor_case(&doc, "cross-prefix").expected);

    // cross-snapshot-token：未签发/伪造 token → invalid-scope。
    let forged = fixture.backend.list("n.", Some("01890f2e-4a1e-7856-8f0c-6c2f11a7b906"), 1, 256, 65_536, CURSOR_TTL, 30_000, far_deadline());
    assert_eq!(cursor_error_of(forged).unwrap(), cursor_case(&doc, "cross-snapshot-token").expected);

    // expired-at-boundary：now == expiresAt（边界含等号）→ expired（GC 先解析绑定后执行，
    // 同调用内到期不会被抹成 invalid-key）。
    let expired = fixture.backend.list("n.", Some(&cursor), 1, 256, 65_536, CURSOR_TTL, 60_000, far_deadline());
    assert_eq!(cursor_error_of(expired).unwrap(), cursor_case(&doc, "expired-at-boundary").expected);

    // cross-application / cross-policy-digest：同一 token 进不了另一个 (app, policy) 域。
    let mut beta = kv_fixture("beta", &"cd".repeat(32));
    let beta_error = beta.backend.list("n.", Some(&cursor), 1, 256, 65_536, CURSOR_TTL, 30_000, far_deadline());
    assert_eq!(cursor_error_of(beta_error).unwrap(), cursor_case(&doc, "cross-application").expected);
    let mut other_policy = kv_fixture("alpha", &"ef".repeat(32));
    let policy_error = other_policy.backend.list("n.", Some(&cursor), 1, 256, 65_536, CURSOR_TTL, 30_000, far_deadline());
    assert_eq!(cursor_error_of(policy_error).unwrap(), cursor_case(&doc, "cross-policy-digest").expected);

    // snapshot-recycled-while-cursor-live：spec「过期 token 或快照被回收 → cursor-expired」。
    // kv.rs 已按 golden 表对齐（reclaimed snapshot 不再归入 scope 错误）；本断言锁死对齐值。
    // 场景：4 个可见 key 串出「snapshot 过期但续游标仍活」的时刻。
    let mut recycled = kv_fixture("alpha", &"cd".repeat(32));
    for key in ["n.1", "n.2", "n.3", "n.4"] {
        recycled
            .backend
            .set(key, b"v", None, &mut recycled.ledger, ENVELOPE, ENVELOPE, OVERHEAD, RESERVATION_TTL, 0, far_deadline())
            .expect("seed");
    }
    let (_p1, c1) = recycled.backend.list("n.", None, 1, 256, 65_536, CURSOR_TTL, 0, far_deadline()).expect("page1");
    let c1 = c1.expect("cursor1");
    let (_p2, c2) = recycled.backend.list("n.", Some(&c1), 1, 256, 65_536, CURSOR_TTL, 30_000, far_deadline()).expect("page2");
    let c2 = c2.expect("cursor2 (expiry 90000 > snapshot expiry 60000)");
    // page3 于 t=60000：本次调用 GC 先回收 snapshot（60000 !< 60000），页内仍产出 cursor3。
    let (_p3, c3) = recycled.backend.list("n.", Some(&c2), 1, 256, 65_536, CURSOR_TTL, 60_000, far_deadline()).expect("page3");
    let c3 = c3.expect("cursor3 bound to the recycled snapshot");
    let recycled_error = recycled.backend.list("n.", Some(&c3), 1, 256, 65_536, CURSOR_TTL, 60_001, far_deadline());
    let recycled_case = cursor_case(&doc, "snapshot-recycled-while-cursor-live");
    let observed = cursor_error_of(recycled_error).expect("must land in the closed error set");
    assert_eq!(observed, recycled_case.expected, "reclaimed snapshot must report cursor-expired per spec");
}

// ---------------------------------------------------------------------------
// 端到端链路（任务 7.5 第二项）：frame → 身份门 → 后端 → 响应 的序列化场景
// ---------------------------------------------------------------------------
fn request_frame(provider: &HostServicesProvider, service: &str, method: &str, payload: Value, request_id: &str) -> Vec<u8> {
    let identity = provider.identity();
    let request = HostCallFrameRequestV2 {
        schema_version: 2,
        protocol: HOST_CALL_PROTOCOL.into(),
        kind: "request".into(),
        request_id: request_id.into(),
        service: service.into(),
        method: method.into(),
        execution: identity.to_frame(),
        host_service_policy_digest: provider.policy_digest_hex().into(),
        deadline_ms: 5_000,
        payload: encode_base64url(&jcs_bytes(&payload).expect("payload jcs")),
    };
    request.encode_frame().expect("request frame")
}

fn response_of(frame_bytes: &[u8]) -> HostCallFrameResponseV2 {
    assert!(frame_bytes.len() >= 5, "response frame carries the length prefix");
    let length = u32::from_be_bytes([frame_bytes[0], frame_bytes[1], frame_bytes[2], frame_bytes[3]]) as usize;
    assert_eq!(frame_bytes.len(), 4 + length, "no trailing bytes");
    parse_canonical(&frame_bytes[4..], "INVALID").expect("response frame decodes")
}

fn outcome_code(response: &HostCallFrameResponseV2) -> Option<&str> {
    response.error.as_ref().map(|error| error.code.as_str())
}

fn result_json(response: &HostCallFrameResponseV2) -> Value {
    let result = response.result.as_deref().unwrap_or_else(|| panic!("expected ok result, got {response:?}"));
    let bytes = iweb_wasmd::host_services::frame::decode_base64url(result).expect("result b64url");
    serde_json::from_slice(&bytes).expect("result json")
}

fn fresh_request_id() -> String {
    // wasmd 依赖面的 uuid v7（grammar 与生产 requestId 一致；集成测试可直接复用）。
    uuid::Uuid::now_v7().hyphenated().to_string()
}

fn file_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn data_dir_file_set(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir).expect("read data dir").map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned()).collect()
}

#[test]
fn host_call_dispatch_full_chain_with_real_sqlite_backends() {
    let doc = load_doc();
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = HostServicesProvider::open(&vector_context(fixture_policy(&doc, "all-three-services")), &vector_identity(), dir.path(), iweb_wasmd::host_services::logging::ForwardingConfig::default())
        .expect("provider open");
    let app_dir = provider.data_dir().to_path_buf();
    let identity_before = provider.identity().clone();
    let policy_digest_before = provider.policy_digest_hex().to_string();

    // SQL schema 由宿主侧预置（DDL 未冻结：应用不能 CREATE；第二个宿主连接执行）。
    {
        let seed_conn = open_sql_connection(&app_dir.join("sql.sqlite3")).expect("seed connection");
        let seed_backend = SqlBackend::new(seed_conn).expect("seed backend");
        seed_backend.connection().execute_batch("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);").expect("seed schema");
    }

    // -- 基线快照：被拒调用必须零字节写入（数据面 mutation 不改 ledger 外任何状态）--
    let usage_before = provider.quota_usage().expect("usage");
    let kv_bytes_before = file_bytes(&app_dir.join("kv.sqlite3"));
    let sql_bytes_before = file_bytes(&app_dir.join("sql.sqlite3"));
    let files_before = data_dir_file_set(&app_dir);

    // sql create（DDL）经链路拒绝：INVALID_ARGUMENT。
    let denied = response_of(&provider.dispatch(&request_frame(&provider, "sql", "execute", serde_json::json!({"statement": "CREATE TABLE evil (id INTEGER)", "parameters": []}), &fresh_request_id())));
    assert_eq!(outcome_code(&denied), Some("INVALID_ARGUMENT"), "DDL is outside minimal-sqlite-v1");
    // kv 畸形 base64url 拒绝。
    let bad_wire = response_of(&provider.dispatch(&request_frame(&provider, "kv", "set", serde_json::json!({"key": "a", "value": "not+base64/url!", "expected": null}), &fresh_request_id())));
    assert_eq!(outcome_code(&bad_wire), Some("INVALID_ARGUMENT"));
    // 未知方法对拒绝（帧结构合法、分派层拒绝）。
    let unknown = response_of(&provider.dispatch(&request_frame(&provider, "kv", "query", serde_json::json!({}), &fresh_request_id())));
    assert_eq!(outcome_code(&unknown), Some("INVALID_ARGUMENT"));

    assert_eq!(file_bytes(&app_dir.join("kv.sqlite3")), kv_bytes_before, "rejected calls write no kv bytes");
    assert_eq!(file_bytes(&app_dir.join("sql.sqlite3")), sql_bytes_before, "rejected calls write no sql bytes");
    assert_eq!(data_dir_file_set(&app_dir), files_before, "rejected calls create no files");
    assert_eq!(provider.quota_usage().expect("usage after rejects"), usage_before, "rejected calls change no committed/outstanding accounting");

    // -- kv set → list → cursor 续 --
    for (key, value) in [("n.1", b"v1".as_ref()), ("n.2", b"v2".as_ref()), ("n.3", b"v3".as_ref())] {
        let set = response_of(&provider.dispatch(&request_frame(&provider, "kv", "set", serde_json::json!({"key": key, "value": encode_base64url(value), "expected": null}), &fresh_request_id())));
        assert_eq!(set.outcome, "ok", "{:?}", set.error);
        assert_eq!(result_json(&set)["version"], 1);
    }
    let page1 = response_of(&provider.dispatch(&request_frame(&provider, "kv", "list", serde_json::json!({"prefix": "n.", "cursor": null, "limit": 1}), &fresh_request_id())));
    assert_eq!(page1.outcome, "ok", "{:?}", page1.error);
    let page1_result = result_json(&page1);
    assert_eq!(page1_result["items"].as_array().expect("items").len(), 1);
    assert_eq!(page1_result["items"][0]["key"], "n.1");
    // spec：帧路径 cursor 与请求侧/WIT 路径对称——nextCursor 即原始 registry token，
    // 续页直接透传，无编码层。
    let cursor_raw = page1_result["nextCursor"].as_str().expect("continuation cursor").to_string();
    let page2 = response_of(&provider.dispatch(&request_frame(&provider, "kv", "list", serde_json::json!({"prefix": "n.", "cursor": cursor_raw, "limit": 1}), &fresh_request_id())));
    let page2_result = result_json(&page2);
    assert_eq!(page2_result["items"][0]["key"], "n.2", "cursor continues after the last served key");
    // 跨 prefix 续游标经链路 → INVALID_ARGUMENT（detail IWEB_KV_INVALID_KEY；不泄露匹配计数）。
    let cross = response_of(&provider.dispatch(&request_frame(&provider, "kv", "list", serde_json::json!({"prefix": "x.", "cursor": cursor_raw, "limit": 1}), &fresh_request_id())));
    assert_eq!(outcome_code(&cross), Some("INVALID_ARGUMENT"));
    assert_eq!(cross.error.expect("error").detail_code.as_deref(), Some("IWEB_KV_INVALID_KEY"));

    // -- sql insert / select（真 SQLite 文件；text 经 unpadded base64url 投影）--
    let insert = response_of(&provider.dispatch(&request_frame(&provider, "sql", "execute", serde_json::json!({"statement": "INSERT INTO notes (body) VALUES (?1)", "parameters": [{"kind": "text", "bytes": encode_base64url("chain".as_bytes())}]}), &fresh_request_id())));
    assert_eq!(insert.outcome, "ok", "{:?}", insert.error);
    let insert_result = result_json(&insert);
    assert_eq!(insert_result["affected"], 1);
    assert!(insert_result["lastInsertId"].is_number());
    let select = response_of(&provider.dispatch(&request_frame(&provider, "sql", "execute", serde_json::json!({"statement": "SELECT id, body FROM notes WHERE body = ?1", "parameters": [{"kind": "text", "bytes": encode_base64url("chain".as_bytes())}]}), &fresh_request_id())));
    assert_eq!(select.outcome, "ok", "{:?}", select.error);
    let rows = result_json(&select)["rows"].as_array().expect("rows").clone();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["columns"][1]["name"], "body");
    let body = iweb_wasmd::host_services::frame::decode_base64url(rows[0]["columns"][1]["value"]["bytes"].as_str().expect("text bytes")).expect("b64");
    assert_eq!(String::from_utf8(body).expect("utf8"), "chain");

    // -- logging write → drain（redaction 先于保留）--
    let write = response_of(&provider.dispatch(&request_frame(&provider, "logging", "write", serde_json::json!({"level": "warn", "message": encode_base64url("chain log".as_bytes()), "fields": [{"key": "authorization", "value": encode_base64url("Bearer owner-secret".as_bytes())}, {"key": "code", "value": encode_base64url("500".as_bytes())}]}), &fresh_request_id())));
    assert_eq!(write.outcome, "ok", "{:?}", write.error);
    assert_eq!(result_json(&write)["outcome"], "accepted");
    let drain = provider.logging_drain("alpha", 0, 100).expect("drain");
    assert_eq!(drain.events.len(), 1);
    assert_eq!(drain.events[0].fields[0].key, "authorization");
    assert_eq!(drain.events[0].fields[0].value, "[REDACTED]", "original secret never retained");
    assert_eq!(drain.events[0].fields[1].value, "500");
    let summary = provider.logging_monitor_summary().expect("summary");
    assert_eq!(summary.retained_events, 1);
    assert_eq!(summary.last_event_id, 1);

    // -- 收尾不变量：identity/policy 不变、文件集恒为三件套、用量记账自洽 --
    assert_eq!(provider.identity(), &identity_before, "data-plane mutations never touch the injected identity");
    assert_eq!(provider.policy_digest_hex(), policy_digest_before);
    assert_eq!(data_dir_file_set(&app_dir), BTreeSet::from(["kv.sqlite3".to_string(), "sql.sqlite3".to_string(), "quota.sqlite3".to_string()]), "the data directory holds exactly the three host-owned backends");
    let usage_after = provider.quota_usage().expect("usage after");
    assert!(usage_after.kv_committed_bytes > 0, "kv mutations are ledger-accounted");
    assert!(usage_after.sql_committed_bytes > 0, "sql mutations are ledger-accounted");
    assert_eq!(usage_after.committed_bytes, usage_after.kv_committed_bytes + usage_after.sql_committed_bytes, "one aggregate envelope authority");
    assert!(usage_after.usage_revision >= usage_before.usage_revision);

    // 跨身份帧在全链上仍被身份门拦截（任何后端访问之前）。
    let mut forged = HostCallFrameRequestV2::decode_frame(&request_frame(&provider, "kv", "get", serde_json::json!({"key": "n.1"}), &fresh_request_id())).expect("decode");
    forged.execution.application_id = "beta".into();
    let isolated = response_of(&provider.dispatch(&forged.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&isolated), Some("APP_ISOLATION"));
}

// ---------------------------------------------------------------------------
// 帧传输界的闭集哨兵（与 contracts 的 frame 语义对齐；防 fixture/实现漂移）
// ---------------------------------------------------------------------------

#[test]
fn frame_transport_constants_stay_pinned() {
    assert_eq!(FRAME_MAX_BYTES, 1_048_576);
    assert_eq!(HOST_CALL_PROTOCOL, "iweb-wasmd-host-call-v2");
    assert_eq!(HOST_CALL_DEADLINE_MAX_MS, 300_000);
    assert_eq!(HOST_CALL_ERROR_CODES.len(), 17, "closed HostCallErrorV2 code set");
    let methods: BTreeSet<(String, String)> = HOST_CALL_METHODS.iter().map(|(service, method)| ((*service).to_string(), (*method).to_string())).collect();
    assert_eq!(
        methods,
        BTreeSet::from([
            ("kv".to_string(), "get".to_string()),
            ("kv".to_string(), "set".to_string()),
            ("kv".to_string(), "delete".to_string()),
            ("kv".to_string(), "list".to_string()),
            ("sql".to_string(), "execute".to_string()),
            ("logging".to_string(), "write".to_string()),
        ])
    );
}

// ---------------------------------------------------------------------------
// 任务 7.5 第三项：import 三服务的最小组件（wasm-tools 1.258.0 直构，fixture 由
// tests/fixtures/wasm/generate-host-services-fixtures.sh.ts 生成）——linker 注册面
// 与「策略禁用即不注册、组件 import 即实例化失败」的运行侧 fail-closed。
// ---------------------------------------------------------------------------

#[test]
fn host_service_imports_register_into_linker_and_policy_disabled_rejects_instantiation() {
    let doc = load_doc();
    let component_path = fixture_path().parent().expect("fixtures dir").join("host-services-imports.wasm");
    let engine = wasmtime::Engine::default();
    let component =
        wasmtime::component::Component::from_file(&engine, &component_path).expect("fixture component compiles under wasmtime 48");

    struct Hosts {
        kv: KvHostService,
        sql: SqlHostService,
        logging: LoggingHostService,
    }

    // 全启用：三个 host import 全部注册 → 组件实例化成功。
    let dir_all = tempfile::tempdir().expect("tempdir");
    let provider_all = Arc::new(
        HostServicesProvider::open(
            &vector_context(fixture_policy(&doc, "all-three-services")),
            &vector_identity(),
            dir_all.path(),
            iweb_wasmd::host_services::logging::ForwardingConfig::default(),
        )
        .expect("provider open"),
    );
    {
        let mut linker = wasmtime::component::Linker::new(&engine);
        add_host_service_imports_to_linker(&mut linker, &provider_all, |s: &mut Hosts| &mut s.kv, |s: &mut Hosts| &mut s.sql, |s: &mut Hosts| &mut s.logging)
            .expect("linker registers every enabled host-service import");
        let mut store = wasmtime::Store::new(
            &engine,
            Hosts {
                kv: KvHostService::new(provider_all.clone(), HostCallBudget::new(1_000)),
                sql: SqlHostService::new(provider_all.clone(), HostCallBudget::new(1_000)),
                logging: LoggingHostService::new(provider_all.clone(), HostCallBudget::new(1_000)),
            },
        );
        linker.instantiate(&mut store, &component).expect("component importing kv/sql/logging instantiates against the full policy");
    }

    // logging 禁用（kv/sql 保留）：linker 不注册 logging import → 实例化 fail-closed。
    let mut payload = doc
        .policy_digest
        .iter()
        .find(|entry| entry.name == "all-three-services")
        .expect("all-three vector")
        .payload
        .clone();
    payload["hostServices"]["logging"] = Value::Null;
    let policy_payload: HostServicePolicyPayloadV2 = serde_json::from_value(payload).expect("payload");
    let policy = HostServicePolicyV2 {
        policy_digest: HostServicePolicyV2::compute_policy_digest(&policy_payload).expect("digest"),
        payload: policy_payload,
    };
    let dir_partial = tempfile::tempdir().expect("tempdir");
    let provider_partial = Arc::new(
        HostServicesProvider::open(&vector_context(policy), &vector_identity(), dir_partial.path(), iweb_wasmd::host_services::logging::ForwardingConfig::default())
            .expect("provider open"),
    );
    assert!(provider_partial.kv_enabled() && provider_partial.sql_enabled(), "kv/sql stay enabled");
    assert!(!provider_partial.logging_enabled(), "logging is policy-disabled");
    let mut linker = wasmtime::component::Linker::new(&engine);
    add_host_service_imports_to_linker(&mut linker, &provider_partial, |s: &mut Hosts| &mut s.kv, |s: &mut Hosts| &mut s.sql, |s: &mut Hosts| &mut s.logging)
        .expect("linker registers only the enabled subset");
    let mut store = wasmtime::Store::new(
        &engine,
        Hosts {
            kv: KvHostService::new(provider_partial.clone(), HostCallBudget::new(1_000)),
            sql: SqlHostService::new(provider_partial.clone(), HostCallBudget::new(1_000)),
            logging: LoggingHostService::new(provider_partial.clone(), HostCallBudget::new(1_000)),
        },
    );
    let rejected = linker
        .instantiate(&mut store, &component)
        .expect_err("a component importing the disabled service must fail instantiation");
    let message = format!("{rejected}").to_lowercase();
    assert!(message.contains("logging"), "the rejection must name the unregistered iweb:logging import: {rejected}");
}
