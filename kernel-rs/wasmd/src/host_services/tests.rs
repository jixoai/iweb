//! host_services provider 级测试（add-wasm-host-services 任务 8.x 子集）：
//! 身份绑定拒绝（APP_ISOLATION/IDENTITY_MISMATCH/STALE_EXECUTION/POLICY_MISMATCH）、
//! 帧路径三服务正/负例、配额写前拒绝、requestId at-most-once replay、环溢出 dropped、
//! SQL 方言拒绝经帧路径、epoch/deadline 中断、重启持久性。
//! 复审 P0-1/P0-2（2026-08-28）：WIT Host impl 经 frame 的证据测试（replay 表条目、
//! 并发原子 claim、logging claim 关联/恢复）、argv 身份错绑 open 拒绝。

use super::*;
use crate::jcs::jcs_bytes;
use crate::wire::WasmdIdentityV2;
use std::time::Duration;

fn vector_identity_v2() -> WasmdIdentityV2 {
    WasmdIdentityV2 {
        application_id: "alpha".into(),
        sandbox_id: "sbx-vector".into(),
        version_id: format!("{}-1", "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532"),
        package_digest: "0".repeat(64),
        runtime_binding: crate::wire::RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: crate::wire::MATRIX_HOST_ABI_V2.into(),
            world: crate::wire::MATRIX_WORLD.into(),
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

fn vector_context() -> policy::WasmdHostServicesContextV2 {
    policy::WasmdHostServicesContextV2 {
        schema_version: 2,
        application_id: "alpha".into(),
        fence_nonce: "ab".repeat(16),
        host_service_policy: policy::vector_policy(),
    }
}

struct Fixture {
    provider: Arc<HostServicesProvider>,
    _dir: tempfile::TempDir,
}

fn provider_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider =
        HostServicesProvider::open(&vector_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default())
            .expect("provider open");
    Fixture { provider: Arc::new(provider), _dir: dir }
}

fn seed_schema(provider: &HostServicesProvider) {
    let backend = provider.sql.as_ref().expect("sql enabled").lock().expect("sql lock");
    backend
        .connection()
        .execute_batch("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);")
        .expect("seed schema");
}

fn request_frame(provider: &HostServicesProvider, service: &str, method: &str, payload: serde_json::Value, request_id: &str) -> Vec<u8> {
    let identity = provider.identity();
    let request = HostCallFrameRequestV2 {
        schema_version: 2,
        protocol: frame::HOST_CALL_PROTOCOL.into(),
        kind: "request".into(),
        request_id: request_id.into(),
        service: service.into(),
        method: method.into(),
        execution: identity.to_frame(),
        host_service_policy_digest: provider.policy_digest_hex().into(),
        deadline_ms: 5_000,
        payload: encode_base64url(&jcs_bytes(&payload).expect("payload jcs")),
    };
    request.encode_frame().expect("frame")
}

fn response_of(frame_bytes: &[u8]) -> HostCallFrameResponseV2 {
    decode_response_frame(frame_bytes).expect("response frame decodes")
}

fn decode_response_frame(frame_bytes: &[u8]) -> Result<HostCallFrameResponseV2, crate::jcs::WireError> {
    if frame_bytes.len() < 5 {
        return Err(crate::jcs::err("INVALID", "short frame"));
    }
    let length = u32::from_be_bytes([frame_bytes[0], frame_bytes[1], frame_bytes[2], frame_bytes[3]]) as usize;
    if frame_bytes.len() != 4 + length {
        return Err(crate::jcs::err("INVALID", "length mismatch"));
    }
    crate::jcs::parse_canonical(&frame_bytes[4..], "INVALID")
}

fn outcome_code(response: &HostCallFrameResponseV2) -> Option<String> {
    response.error.as_ref().map(|error| error.code.clone())
}

fn result_json(response: &HostCallFrameResponseV2) -> serde_json::Value {
    let result = response.result.as_deref().expect("ok result");
    let bytes = decode_base64url(result).expect("result b64url");
    serde_json::from_slice(&bytes).expect("result json")
}

fn fresh_request_id() -> String {
    uuid::Uuid::now_v7().hyphenated().to_string()
}

#[test]
fn kv_get_set_delete_round_trip_over_frame_path() {
    let fixture = provider_fixture();
    let set = fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "set",
        serde_json::json!({"key": "a", "value": encode_base64url(b"v1"), "expected": null}),
        &fresh_request_id(),
    ));
    let response = response_of(&set);
    assert_eq!(response.outcome, "ok", "set succeeds: {:?}", response.error);
    assert_eq!(result_json(&response)["version"], 1);

    let get = fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "get",
        serde_json::json!({"key": "a"}),
        &fresh_request_id(),
    ));
    let response = response_of(&get);
    assert_eq!(response.outcome, "ok");
    let result = result_json(&response);
    assert_eq!(result["key"], "a");
    assert_eq!(decode_base64url(result["value"].as_str().expect("b64")).expect("v"), b"v1".to_vec());

    let delete = fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "delete",
        serde_json::json!({"key": "a", "expected": 1}),
        &fresh_request_id(),
    ));
    let response = response_of(&delete);
    assert_eq!(response.outcome, "ok");
    assert_eq!(result_json(&response)["version"], 2);

    // tombstone 后 get → NOT_FOUND；stale resurrection → CONFLICT。
    let get = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "get",
        serde_json::json!({"key": "a"}),
        &fresh_request_id(),
    )));
    assert_eq!(outcome_code(&get).as_deref(), Some("NOT_FOUND"));
    let stale = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "set",
        serde_json::json!({"key": "a", "value": encode_base64url(b"resurrect"), "expected": 1}),
        &fresh_request_id(),
    )));
    assert_eq!(outcome_code(&stale).as_deref(), Some("CONFLICT"));

    // 非 canonical base64url / 畸形 payload → INVALID_ARGUMENT。
    let bad = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "set",
        serde_json::json!({"key": "a", "value": "not+base64/url!", "expected": null}),
        &fresh_request_id(),
    )));
    assert_eq!(outcome_code(&bad).as_deref(), Some("INVALID_ARGUMENT"));
}

#[test]
fn identity_binding_rejects_cross_identity_and_stale_frames() {
    let fixture = provider_fixture();
    let identity = fixture.provider.identity().clone();
    let digest = fixture.provider.policy_digest_hex().to_string();

    let request = HostCallFrameRequestV2 {
        schema_version: 2,
        protocol: frame::HOST_CALL_PROTOCOL.into(),
        kind: "request".into(),
        request_id: fresh_request_id(),
        service: "kv".into(),
        method: "get".into(),
        execution: identity.to_frame(),
        host_service_policy_digest: digest,
        deadline_ms: 1_000,
        payload: encode_base64url(br#"{"key":"a"}"#),
    };

    // 伪造他应用身份 → APP_ISOLATION（任何后端访问之前）。
    let mut forged = request.clone();
    forged.execution.application_id = "beta".into();
    let response = response_of(&fixture.provider.dispatch(&forged.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("APP_ISOLATION"));

    // 过期代次（P/E 更低）→ STALE_EXECUTION。
    let mut stale = request.clone();
    stale.execution.execution_generation = identity.execution_generation - 1;
    let response = response_of(&fixture.provider.dispatch(&stale.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("STALE_EXECUTION"));

    // 同应用但 versionId/fenceNonce 不一致 → IDENTITY_MISMATCH。
    let mut wrong_version = request.clone();
    wrong_version.execution.version_id = format!("{}-2", "b".repeat(64));
    let response = response_of(&fixture.provider.dispatch(&wrong_version.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("IDENTITY_MISMATCH"));
    let mut wrong_nonce = request.clone();
    wrong_nonce.execution.fence_nonce = "cd".repeat(16);
    let response = response_of(&fixture.provider.dispatch(&wrong_nonce.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("IDENTITY_MISMATCH"));

    // 第三轮复审（完整身份面）：catalog/capability pin 与帧内 policyDigest 的任一
    // 偏差同样被身份门拒绝——帧绑全集，逐字段相等。
    let mut wrong_catalog = request.clone();
    wrong_catalog.execution.catalog_revision += 1;
    let response = response_of(&fixture.provider.dispatch(&wrong_catalog.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("IDENTITY_MISMATCH"));
    let mut wrong_catalog_hash = request.clone();
    wrong_catalog_hash.execution.catalog_hash = "ef".repeat(32);
    let response = response_of(&fixture.provider.dispatch(&wrong_catalog_hash.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("IDENTITY_MISMATCH"));
    let mut wrong_capability = request.clone();
    wrong_capability.execution.capability_record_hash = "ef".repeat(32);
    let response = response_of(&fixture.provider.dispatch(&wrong_capability.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("IDENTITY_MISMATCH"));
    let mut wrong_execution_policy = request.clone();
    wrong_execution_policy.execution.host_service_policy_digest = "ef".repeat(32);
    // 帧内 policyDigest 属于身份元组（完整身份面）：身份门先于顶层策略门拒绝。
    let response = response_of(&fixture.provider.dispatch(&wrong_execution_policy.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("IDENTITY_MISMATCH"));

    // 策略 digest 不一致 → POLICY_MISMATCH。
    let mut wrong_policy = request.clone();
    wrong_policy.host_service_policy_digest = "ef".repeat(32);
    let response = response_of(&fixture.provider.dispatch(&wrong_policy.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("POLICY_MISMATCH"));

    // 合法身份仍可达后端（负例不破坏后续可用性；key 不存在 → NOT_FOUND 业务错误）。
    let response = response_of(&fixture.provider.dispatch(&request.encode_frame().expect("frame")));
    assert_eq!(outcome_code(&response).as_deref(), Some("NOT_FOUND"));
}

#[test]
fn quota_exceeded_over_frame_rejects_before_mutation() {
    let fixture = provider_fixture();
    // envelope = storageBytes（vector policy 1 MiB）：64 KiB 值连续写入，实测 page
    // 计量封口后 envelope 关闭 → QUOTA_EXCEEDED（写前拒绝，无 mutation）。
    let mut committed = 0;
    for index in 0..24 {
        let response = response_of(&fixture.provider.dispatch(&request_frame(
            &fixture.provider,
            "kv",
            "set",
            serde_json::json!({"key": format!("k{index}"), "value": encode_base64url(&vec![b'x'; 65_536]), "expected": null}),
            &fresh_request_id(),
        )));
        match outcome_code(&response) {
            None => committed += 1,
            Some(code) => {
                assert_eq!(code, "QUOTA_EXCEEDED", "must be quota-exceeded, got {code:?}");
                // 拒绝路径不产生 mutation：被拒的下一个 key 不可见。
                let probe = response_of(&fixture.provider.dispatch(&request_frame(
                    &fixture.provider,
                    "kv",
                    "get",
                    serde_json::json!({"key": format!("k{}", index + 1)}),
                    &fresh_request_id(),
                )));
                assert_eq!(outcome_code(&probe).as_deref(), Some("NOT_FOUND"), "rejected write leaves no key");
                assert!(committed >= 1, "at least one write committed before the envelope closed");
                return;
            }
        }
    }
    panic!("1 MiB envelope must eventually reject 64 KiB writes (committed {committed})");
}

#[test]
fn mutating_request_is_at_most_once_with_replay_semantics() {
    let fixture = provider_fixture();
    let request_id = fresh_request_id();
    let payload = serde_json::json!({"key": "r", "value": encode_base64url(b"once"), "expected": null});
    let first = response_of(&fixture.provider.dispatch(&request_frame(&fixture.provider, "kv", "set", payload.clone(), &request_id)));
    assert_eq!(first.outcome, "ok");
    assert_eq!(result_json(&first)["version"], 1);

    // identical replay → 存储响应（同一 version，不重复写）。
    let replay = response_of(&fixture.provider.dispatch(&request_frame(&fixture.provider, "kv", "set", payload.clone(), &request_id)));
    assert_eq!(replay.outcome, "ok");
    assert_eq!(result_json(&replay)["version"], 1, "replay returns the stored response exactly once");

    // changed payload 同 requestId → REQUEST_ID_CONFLICT。
    let changed = serde_json::json!({"key": "r", "value": encode_base64url(b"twice"), "expected": null});
    let conflict = response_of(&fixture.provider.dispatch(&request_frame(&fixture.provider, "kv", "set", changed, &request_id)));
    assert_eq!(outcome_code(&conflict).as_deref(), Some("REQUEST_ID_CONFLICT"));

    // 新 requestId 的 CAS 写携带 expected:1 恒成功（版本线未因 replay 走两步）。
    let next = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "set",
        serde_json::json!({"key": "r", "value": encode_base64url(b"third"), "expected": 1}),
        &fresh_request_id(),
    )));
    assert_eq!(result_json(&next)["version"], 2);
}

#[test]
fn sql_execute_over_frame_path_with_dialect_and_epoch() {
    let fixture = provider_fixture();
    seed_schema(&fixture.provider);

    // 正例：参数化 mutation 提交并返回 affected/lastInsertId（text 经 b64url 投影）。
    let insert = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "sql",
        "execute",
        serde_json::json!({"statement": "INSERT INTO notes (body) VALUES (?1)", "parameters": [
            {"kind": "text", "bytes": encode_base64url("hello".as_bytes())}
        ]}),
        &fresh_request_id(),
    )));
    assert_eq!(insert.outcome, "ok", "{:?}", insert.error);
    let result = result_json(&insert);
    assert_eq!(result["affected"], 1);
    assert!(result["lastInsertId"].is_number());

    // 方言 denylist（真 SQLite 上行为对齐：脚本/ATTACH/PRAGMA/DDL/扩展函数 → INVALID_ARGUMENT）。
    for statement in [
        "INSERT INTO notes (body) VALUES ('a'); INSERT INTO notes (body) VALUES ('b')",
        "ATTACH DATABASE '/tmp/x' AS x",
        "PRAGMA journal_mode = WAL",
        "CREATE TABLE evil (id INTEGER)",
        "SELECT load_extension('/tmp/evil.so')",
    ] {
        let response = response_of(&fixture.provider.dispatch(&request_frame(
            &fixture.provider,
            "sql",
            "execute",
            serde_json::json!({"statement": statement, "parameters": []}),
            &fresh_request_id(),
        )));
        assert_eq!(outcome_code(&response).as_deref(), Some("INVALID_ARGUMENT"), "deny {statement:?}");
    }

    // deadline 中断：宿主侧预置大表 + 6 表自连接（≈6.9e10 组合），deadlineMs=50。
    {
        let backend = fixture.provider.sql.as_ref().expect("sql enabled").lock().expect("sql lock");
        backend
            .connection()
            .execute_batch(
                "CREATE TABLE big (id INTEGER PRIMARY KEY, pad TEXT);\n\
                 INSERT INTO big (pad) WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 64) SELECT 'x' FROM c;",
            )
            .expect("seed big");
    }
    let interrupt_request = request_frame(
        &fixture.provider,
        "sql",
        "execute",
        serde_json::json!({
            "statement": "SELECT COUNT(b1.id) FROM big b1, big b2, big b3, big b4, big b5, big b6 WHERE b1.pad = b2.pad AND b2.pad = b3.pad AND b3.pad = b4.pad AND b4.pad = b5.pad AND b5.pad = b6.pad",
            "parameters": []
        }),
        &fresh_request_id(),
    );
    let started = Instant::now();
    // deadlineMs 覆写为 50（builder 已按 5000 生成；重建一帧）。
    let mut raw: HostCallFrameRequestV2 = HostCallFrameRequestV2::decode_frame(&interrupt_request).expect("decode");
    raw.deadline_ms = 50;
    let response = response_of(&fixture.provider.dispatch(&raw.encode_frame().expect("frame")));
    assert!(started.elapsed() < Duration::from_secs(3), "long statement interrupted at deadline");
    assert_eq!(
        outcome_code(&response).as_deref(),
        Some("LIMIT_EXCEEDED"),
        "deadline maps to the closed timeout/limit set: {:?}",
        response.error
    );
}

#[test]
fn logging_write_accepts_drops_and_redacts_over_frame_path() {
    let fixture = provider_fixture();
    // accepted（含非 ASCII message 经 b64url 投影）。
    let accepted = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "logging",
        "write",
        serde_json::json!({
            "level": "warn",
            "message": encode_base64url("héllo 日志".as_bytes()),
            "fields": [
                {"key": "authorization", "value": encode_base64url("Bearer owner-secret".as_bytes())},
                {"key": "code", "value": encode_base64url("401".as_bytes())}
            ]
        }),
        &fresh_request_id(),
    )));
    assert_eq!(accepted.outcome, "ok");
    assert_eq!(result_json(&accepted)["outcome"], "accepted");

    // drain（owner 面）：reserved 值已 redacted，原值绝不保留。
    let drain = fixture.provider.logging_drain("alpha", 0, 100).expect("drain");
    assert_eq!(drain.events.len(), 1);
    assert_eq!(drain.events[0].fields[0].value, "[REDACTED]");
    assert_eq!(drain.events[0].fields[1].value, "401");
    assert_eq!(drain.events[0].level, logging::LogLevel::Warn);
    assert!(drain.events[0].message.contains("héllo"));

    // 环溢出：33+ 个 ~8KB 事件必超 ring_max_bytes（262144）→ 显式 dropped 计数。
    for index in 0..64 {
        let response = response_of(&fixture.provider.dispatch(&request_frame(
            &fixture.provider,
            "logging",
            "write",
            serde_json::json!({
                "level": "info",
                "message": encode_base64url(&vec![b'x'; 4_096]),
                "fields": []
            }),
            &fresh_request_id(),
        )));
        if index == 0 {
            assert_eq!(response.outcome, "ok", "first bulk event accepted: {:?}", response.error);
        }
    }
    let summary = fixture.provider.logging_monitor_summary().expect("summary");
    assert!(summary.dropped_count > 0, "ring overflow must drop explicitly");
    assert!(summary.retained_events <= 256);

    // 非法事件（重复 key / 未知 level）→ INVALID_ARGUMENT。
    let invalid = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "logging",
        "write",
        serde_json::json!({
            "level": "info",
            "message": encode_base64url(b"m"),
            "fields": [
                {"key": "a", "value": encode_base64url(b"1")},
                {"key": "a", "value": encode_base64url(b"2")}
            ]
        }),
        &fresh_request_id(),
    )));
    assert_eq!(outcome_code(&invalid).as_deref(), Some("INVALID_ARGUMENT"));
    let unknown_level = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "logging",
        "write",
        serde_json::json!({"level": "fatal", "message": encode_base64url(b"m"), "fields": []}),
        &fresh_request_id(),
    )));
    assert_eq!(outcome_code(&unknown_level).as_deref(), Some("INVALID_ARGUMENT"));
}

#[test]
fn committed_data_survives_provider_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider =
        HostServicesProvider::open(&vector_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default()).expect("open");
    let set = response_of(&provider.dispatch(&request_frame(
        &provider,
        "kv",
        "set",
        serde_json::json!({"key": "persist", "value": encode_base64url(b"durable"), "expected": null}),
        &fresh_request_id(),
    )));
    assert_eq!(set.outcome, "ok");
    drop(provider);

    // 重启（新 provider 实例，同一数据目录与身份）：committed 数据可见。
    let reopened =
        HostServicesProvider::open(&vector_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default()).expect("reopen");
    let get = response_of(&reopened.dispatch(&request_frame(
        &reopened,
        "kv",
        "get",
        serde_json::json!({"key": "persist"}),
        &fresh_request_id(),
    )));
    assert_eq!(get.outcome, "ok");
    let result = result_json(&get);
    assert_eq!(decode_base64url(result["value"].as_str().expect("b64")).expect("v"), b"durable".to_vec());
    assert_eq!(result["version"], 1);
}

#[test]
fn response_loss_after_backend_commit_is_recovered_without_reexecution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let request_id = fresh_request_id();
    let frame = {
        let provider = HostServicesProvider::open(
            &vector_context(),
            &vector_identity_v2(),
            dir.path(),
            logging::ForwardingConfig::default(),
        )
        .expect("open");
        let frame = request_frame(
            &provider,
            "kv",
            "set",
            serde_json::json!({"key": "lost", "value": encode_base64url(b"once"), "expected": null}),
            &request_id,
        );
        let request = HostCallFrameRequestV2::decode_frame(&frame).expect("request");
        let canonical_body = jcs_bytes(&request).expect("canonical request");
        let key = ReplayKeyV2 {
            request_id: request.request_id.clone(),
            canonical_body,
            service: request.service.clone(),
            method: request.method.clone(),
            identity_digest: provider.identity_digest(),
            policy_digest: provider.policy_digest_hex().to_string(),
            preparation_generation: request.execution.preparation_generation,
            execution_generation: request.execution.execution_generation,
            fence_nonce: request.execution.fence_nonce.clone(),
        };
        let reservation = {
            let mut ledger = provider.quota.lock().expect("quota");
            let operation_id = match ledger
                .claim_replay(&key, unix_now_ms(), unix_now_ms() + policy::HOST_CALL_REPLAY_TTL_MS)
                .expect("claim")
            {
                ReplayClaimV2::Claimed { operation_id } => operation_id,
                other => panic!("expected claim, got {other:?}"),
            };
            ledger
                .reserve(
                    "kv",
                    &operation_id,
                    128,
                    provider.policy.payload.storage_bytes,
                    provider.policy.payload.storage_bytes,
                    unix_now_ms(),
                    policy::HOST_CALL_REPLAY_TTL_MS,
                )
                .expect("reserve")
        };
        // Simulate the crash window: persist the value and marker, but do not
        // finalize the ledger or complete the replay response.
        {
            let backend = provider.kv.as_ref().expect("kv").lock().expect("kv lock");
            backend
                .connection()
                .execute(
                    "INSERT INTO kv_entries (key, value, version, tombstone, deleted_at_ms) VALUES (?1, ?2, 1, 0, NULL)",
                    rusqlite::params!["lost", b"once".as_slice()],
                )
                .expect("value");
            backend
                .connection()
                .execute(
                    "INSERT INTO kv_operations (operation_id, reservation_id, proof_digest, method, key, assigned_version, created_at_ms) VALUES (?1, ?2, ?3, 'set', 'lost', 1, ?4)",
                    rusqlite::params![reservation.operation_id, reservation.reservation_id, reservation.reservation_proof_digest, unix_now_ms() as i64],
                )
                .expect("marker");
        }
        frame
    };

    let reopened = HostServicesProvider::open(
        &vector_context(),
        &vector_identity_v2(),
        dir.path(),
        logging::ForwardingConfig::default(),
    )
    .expect("recovery open");
    let replay = reopened.dispatch(&frame);
    let expected = {
        let request = HostCallFrameRequestV2::decode_frame(&frame).expect("request");
        let result = serde_json::to_vec(&serde_json::json!({"version": 1})).expect("result");
        HostCallFrameResponseV2::ok(&request, result).encode_frame().expect("expected frame")
    };
    assert_eq!(replay, expected, "recovery must reproduce the original response bytes");
    assert_eq!(result_json(&response_of(&replay))["version"], 1);
    let usage = reopened.quota_usage().expect("usage");
    assert!(usage.committed_bytes > 0, "recovery finalized the reservation exactly once");
}

#[test]
fn invalid_frames_return_invalid_frame_error_response() {
    let fixture = provider_fixture();
    // 尾随字节 / 过短帧 → INVALID_FRAME（requestId 空）。
    let mut frame = request_frame(&fixture.provider, "kv", "get", serde_json::json!({"key": "a"}), &fresh_request_id());
    frame.push(b' ');
    let response = response_of(&fixture.provider.dispatch(&frame));
    assert_eq!(outcome_code(&response).as_deref(), Some("INVALID_FRAME"));
    let response = response_of(&fixture.provider.dispatch(&[0, 0, 0, 1, b'{']));
    assert_eq!(outcome_code(&response).as_deref(), Some("INVALID_FRAME"));

    // 未知方法对 → INVALID_ARGUMENT（帧结构合法）。
    let response = response_of(&fixture.provider.dispatch(&request_frame(
        &fixture.provider,
        "kv",
        "query",
        serde_json::json!({}),
        &fresh_request_id(),
    )));
    assert_eq!(outcome_code(&response).as_deref(), Some("INVALID_ARGUMENT"));
}

#[test]
fn data_directory_is_private_and_identity_fenced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider =
        HostServicesProvider::open(&vector_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default()).expect("open");
    let app_dir = provider.data_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(app_dir).expect("dir metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "directory mode 0700");
        let kv_mode = std::fs::metadata(app_dir.join("kv.sqlite3")).expect("kv metadata").permissions().mode();
        assert_eq!(kv_mode & 0o777, 0o600, "backend file mode 0600");
    }
    // 目录名只来自 applicationId（grammar 校验拒绝路径分隔符——provider open 已验）。
    assert!(app_dir.ends_with("alpha"), "derived only from the kernel application identity");

    // 跨应用/路径逃逸 applicationId → open 自身 fail-closed。
    let mut context = vector_context();
    context.application_id = "../escape".into();
    assert!(HostServicesProvider::open(&context, &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default()).is_err());
}

// ---------------------------------------------------------------------------
// 复审 P0-1/P0-2 证据测试（2026-08-28）
// ---------------------------------------------------------------------------

fn wit_budget() -> HostCallBudget {
    HostCallBudget::new(300_000)
}

fn replay_rows(provider: &HostServicesProvider) -> Vec<quota::ReplayRecordV2> {
    provider.quota.lock().expect("quota lock").replay_records().expect("replay records")
}

/// P0-1 证据：WIT Host impl 的每次调用都经 dispatch_frame——mutating 调用在
/// host_call_replay 表留下终态行、kv 后端留下与 claim operationId 对齐的 marker、
/// logging 保留事件携带 claim 关联 operationId；读取调用不留 claim。
#[test]
fn wit_host_impls_dispatch_through_frame_and_leave_replay_evidence() {
    use iweb::kv::store::Host as _;
    use iweb::logging::logger::Host as _;
    use iweb::sql::store::Host as _;

    let fixture = provider_fixture();
    seed_schema(&fixture.provider);
    let mut kv = KvHostService::new(Arc::clone(&fixture.provider), wit_budget());
    let mut sql = SqlHostService::new(Arc::clone(&fixture.provider), wit_budget());
    let mut logging_service = LoggingHostService::new(Arc::clone(&fixture.provider), wit_budget());

    // kv set → version 1；get → 原值；list → 有界页；delete → 版本推进。
    let version = kv.set("wit-key".into(), b"wit-value".to_vec(), None).expect("set trap").expect("set ok");
    assert_eq!(version, 1);
    let item = kv.get("wit-key".into()).expect("get trap").expect("get ok");
    assert_eq!(item.value, b"wit-value".to_vec());
    assert_eq!(item.version, 1);
    let page = kv.list("wit-".into(), None, 10).expect("list trap").expect("list ok");
    assert_eq!(page.items.len(), 1);
    let deleted = kv.delete("wit-key".into(), Some(1)).expect("delete trap").expect("delete ok");
    assert_eq!(deleted, 2);

    // sql execute（mutation）→ affected 1。
    let result = sql
        .execute(
            "INSERT INTO notes (body) VALUES (?1)".into(),
            vec![iweb::sql::store::Parameter { value: iweb::sql::store::Value::Text("wit-row".into()) }],
        )
        .expect("sql trap")
        .expect("sql ok");
    assert_eq!(result.affected, 1);

    // logging write → accepted（保留事件携带 claim operationId）。
    let outcome = logging_service
        .write(iweb::logging::logger::Event {
            level: iweb::logging::logger::Level::Info,
            message: "wit event".into(),
            fields: vec![iweb::logging::logger::Field { key: "code".into(), value: "200".into() }],
        })
        .expect("log trap");
    assert!(matches!(outcome, Ok(iweb::logging::logger::Outcome::Accepted)));

    // 证据 1：replay 表有全部 mutating 调用的终态行（kv:set/delete、sql:execute、
    // logging:write——WIT 路径与帧路径共用同一 claim/replay 通道）。
    let rows = replay_rows(&fixture.provider);
    let row_for = |service: &str, method: &str| {
        rows.iter()
            .find(|row| row.key.service == service && row.key.method == method && row.state != "claimed")
            .unwrap_or_else(|| panic!("terminal replay row for {service}:{method}"))
    };
    let kv_set_row = row_for("kv", "set");
    let sql_row = row_for("sql", "execute");
    let logging_row = row_for("logging", "write");
    assert_eq!(kv_set_row.state, "ok");
    assert_eq!(sql_row.state, "ok");
    assert_eq!(logging_row.state, "ok");
    // requestId 为宿主自动 UUIDv7（帧文法已过 decode/validate）。
    for row in [&kv_set_row, &sql_row, &logging_row] {
        assert!(crate::jcs::validate_uuid_v7(&row.key.request_id).is_ok(), "auto requestId is a UUIDv7");
    }
    // 身份绑定：replay 行的身份摘要与 provider 完整身份一致。
    assert_eq!(kv_set_row.key.identity_digest, fixture.provider.identity_digest());

    // 证据 2：kv 后端 marker 与 claim operationId 一一对齐（claim 内的后端效果）。
    let marker_ids = fixture
        .provider
        .kv
        .as_ref()
        .expect("kv enabled")
        .lock()
        .expect("kv lock")
        .list_operation_ids()
        .expect("markers");
    assert!(marker_ids.contains(&kv_set_row.operation_id), "kv set marker joins the claim operation id");
    assert!(!marker_ids.contains(&sql_row.operation_id), "sql claim never lands a kv marker");

    // 证据 3：logging 保留事件携带 claim 关联 operationId（claim 消费形态）。
    let drain = fixture.provider.logging_drain("alpha", 0, 100).expect("drain");
    let logging_event = drain
        .events
        .iter()
        .find(|event| event.message == "wit event")
        .expect("retained logging event");
    assert_eq!(logging_event.operation_id.as_deref(), Some(logging_row.operation_id.as_str()));
}

/// P0-1 证据：WIT 错误经帧反解映射回服务错误变体（缺 key → NotFound；非 canonical
/// caller key → InvalidKey；重复 logging field key → InvalidEvent）。
#[test]
fn wit_host_impls_map_frame_errors_to_service_variants() {
    use iweb::kv::store::Host as _;
    use iweb::logging::logger::Host as _;

    let fixture = provider_fixture();
    let mut kv = KvHostService::new(Arc::clone(&fixture.provider), wit_budget());
    let missing = kv.get("absent".into()).expect("get trap");
    assert!(matches!(missing, Err(iweb::kv::store::Error::NotFound)));
    // 非 ASCII key 无法进入 canonical 帧 → INVALID_ARGUMENT → InvalidKey。
    let non_canonical = kv.get("клю\u{7f}".into()).expect("get trap");
    assert!(matches!(non_canonical, Err(iweb::kv::store::Error::InvalidKey)));

    let mut logging_service = LoggingHostService::new(Arc::clone(&fixture.provider), wit_budget());
    let invalid = logging_service
        .write(iweb::logging::logger::Event {
            level: iweb::logging::logger::Level::Info,
            message: "m".into(),
            fields: vec![
                iweb::logging::logger::Field { key: "a".into(), value: "1".into() },
                iweb::logging::logger::Field { key: "a".into(), value: "2".into() },
            ],
        })
        .expect("log trap");
    assert!(matches!(invalid, Err(iweb::logging::logger::Error::InvalidEvent)));
}

/// P0-1 证据：并发 WIT 调用各自走原子 claim——全部成功、全部终态、无 InFlight
/// 残留（同 requestId 竞争的 BUSY 语义由帧路径的 requestId 级测试覆盖）。
#[test]
fn concurrent_wit_calls_each_claim_atomically() {
    use iweb::kv::store::Host as _;

    let fixture = provider_fixture();
    let provider = Arc::clone(&fixture.provider);
    let threads = 8;
    std::thread::scope(|scope| {
        for index in 0..threads {
            let provider = Arc::clone(&provider);
            scope.spawn(move || {
                let mut kv = KvHostService::new(provider, wit_budget());
                let version = kv
                    .set(format!("wit-concurrent-{index}"), vec![b'v'; 64], None)
                    .expect("set trap")
                    .expect("set ok");
                assert_eq!(version, 1);
            });
        }
    });
    let rows = replay_rows(&fixture.provider);
    let concurrent: Vec<&quota::ReplayRecordV2> = rows
        .iter()
        .filter(|row| row.key.service == "kv" && row.key.method == "set")
        .collect();
    assert_eq!(concurrent.len(), threads, "one terminal claim per concurrent call");
    assert!(concurrent.iter().all(|row| row.state == "ok"), "no in-flight leftovers: {:?}", concurrent.iter().map(|row| row.state.clone()).collect::<Vec<_>>());
    let mut operation_ids: Vec<&str> = concurrent.iter().map(|row| row.operation_id.as_str()).collect();
    operation_ids.sort_unstable();
    operation_ids.dedup();
    assert_eq!(operation_ids.len(), threads, "each call claims a distinct operation");
}

/// P0-2 证据：context.applicationId 与 identity.applicationId 错绑（argv 两元素分属
/// 不同应用）→ provider open fail-closed，绝不以单侧派生数据目录。
#[test]
fn open_rejects_context_identity_application_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut identity = vector_identity_v2();
    identity.application_id = "beta".into();
    let error = match HostServicesProvider::open(&vector_context(), &identity, dir.path(), logging::ForwardingConfig::default()) {
        Err(error) => error,
        Ok(_) => panic!("cross-bound identity must fail closed"),
    };
    assert_eq!(error.code, WASMD_HOST_SERVICES_OPEN_FAILED);
    // 错绑绝不落目录：beta/ 不被创建。
    assert!(!dir.path().join("beta").exists(), "no data directory is derived from a mismatched identity");
}

/// P0-1 恢复裁决证据：logging-only policy（kv/sql 均未启用）下，崩溃遗留的 claimed
/// logging 行在恢复时直接释放（无 durable marker 可证、也不需要后端读证明）——
/// open 不再因 backend 缺席而 fail-closed 砖死。
#[test]
fn logging_only_policy_recovers_claimed_row_without_backends() {
    fn logging_only_context() -> policy::WasmdHostServicesContextV2 {
        let mut context = vector_context();
        let mut payload = context.host_service_policy.payload.clone();
        payload.host_services.kv = None;
        payload.host_services.sql = None;
        let digest = policy::HostServicePolicyV2::compute_policy_digest(&payload).expect("digest");
        context.host_service_policy = policy::HostServicePolicyV2 { payload, policy_digest: digest };
        context
    }

    let dir = tempfile::tempdir().expect("tempdir");
    {
        let provider =
            HostServicesProvider::open(&logging_only_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default())
                .expect("logging-only open");
        assert!(!provider.kv_enabled() && !provider.sql_enabled());
        let key = ReplayKeyV2 {
            request_id: fresh_request_id(),
            canonical_body: br#"{"schemaVersion":2,"service":"logging","method":"write"}"#.to_vec(),
            service: "logging".into(),
            method: "write".into(),
            identity_digest: provider.identity_digest(),
            policy_digest: provider.policy_digest_hex().to_string(),
            preparation_generation: 2,
            execution_generation: 2,
            fence_nonce: "ab".repeat(16),
        };
        let claimed = provider
            .quota
            .lock()
            .expect("quota")
            .claim_replay(&key, unix_now_ms(), unix_now_ms() + policy::HOST_CALL_REPLAY_TTL_MS)
            .expect("claim");
        assert!(matches!(claimed, ReplayClaimV2::Claimed { .. }));
    }
    let reopened =
        HostServicesProvider::open(&logging_only_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default())
            .expect("recovery must release the claimed logging row without backend reads");
    assert!(
        replay_rows(&reopened).iter().all(|row| row.state != "claimed"),
        "the claimed logging row is released at recovery"
    );
}

/// P0-1 恢复裁决证据（fail-closed 对面）：claimed logging 行若挂着 quota reservation
/// （logging 从不 reserve——impossible state），恢复必须 quarantine 并让 open 失败，
/// 而不是无声释放。
#[test]
fn logging_claim_with_reservation_is_an_impossible_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let provider =
            HostServicesProvider::open(&vector_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default()).expect("open");
        let key = ReplayKeyV2 {
            request_id: fresh_request_id(),
            canonical_body: br#"{"schemaVersion":2,"service":"logging","method":"write"}"#.to_vec(),
            service: "logging".into(),
            method: "write".into(),
            identity_digest: provider.identity_digest(),
            policy_digest: provider.policy_digest_hex().to_string(),
            preparation_generation: 2,
            execution_generation: 2,
            fence_nonce: "ab".repeat(16),
        };
        let mut ledger = provider.quota.lock().expect("quota");
        let operation_id = match ledger
            .claim_replay(&key, unix_now_ms(), unix_now_ms() + policy::HOST_CALL_REPLAY_TTL_MS)
            .expect("claim")
        {
            ReplayClaimV2::Claimed { operation_id } => operation_id,
            other => panic!("expected claim, got {other:?}"),
        };
        ledger
            .reserve(
                "kv",
                &operation_id,
                128,
                provider.policy.payload.storage_bytes,
                provider.policy.payload.storage_bytes,
                unix_now_ms(),
                policy::HOST_CALL_REPLAY_TTL_MS,
            )
            .expect("reserved alongside a logging claim (impossible state seed)");
    }
    let error = match HostServicesProvider::open(&vector_context(), &vector_identity_v2(), dir.path(), logging::ForwardingConfig::default()) {
        Err(error) => error,
        Ok(_) => panic!("a logging claim with a reservation must fail recovery"),
    };
    assert_eq!(error.code, WASMD_HOST_SERVICES_OPEN_FAILED);
}
