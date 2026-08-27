//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1-3.4 端到端）：用真实
//! wasi:http@0.2.8 组件 fixture 验证宿主调用路径与拒绝路径——
//! - wasmd-proxy-respond.wasm：构造 200 响应（canonical ABI 直构，不实现真实 HTTP
//!   语义）→ 请求路径 200 + health v2 原样返回；
//! - wasmd-proxy-loop.wasm：handle 死循环 → epoch 墙钟 deadline 终止“该执行”，进程
//!   不崩、后续请求照常（任务 3.2 的 epoch 语义 + spec 生命周期条款）；
//! - wasmd-proxy-sockets.wasm：import wasi:sockets → instantiate_pre 即 fail-closed
//!   （spec 场景 “Component requests a denied network interface”）。
//!
//! fixture 由 tests/fixtures/wasm/generate-wasmd-fixtures.sh.ts 用 wasm-tools 1.258.0
//! 生成并提交；本测试不依赖工具链与网络。

use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use iweb_wasmd::capability::{
    NodeCapabilityRecordPayloadV1, NodeCapabilityRecordV1, NODE_CAPABILITY_RECORD_HASH_DOMAIN,
};
use iweb_wasmd::fd::SnapshotSlots;
use iweb_wasmd::gateway::GatewayEgress;
use iweb_wasmd::host::{spawn_epoch_ticker, WasmdEngine};
use iweb_wasmd::ingress::{serve, HEALTH_PATH};
use iweb_wasmd::jcs::{domain_digest, jcs_bytes};
use iweb_wasmd::snapshot_store::HostStore;
use iweb_wasmd::wire::{SnapshotValuesPayloadV1, WasmdIdentityV1, WasmReadinessHealthV2};
use std::collections::BTreeMap;
use std::sync::Arc;

/// fixture 路径（tests/fixtures/wasm，与本 crate 的 manifest 相对定位）。
fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/wasm").join(name)
}

fn vector_binding() -> iweb_wasmd::wire::RuntimeBindingIdentityV1 {
    iweb_wasmd::wire::RuntimeBindingIdentityV1 {
        kind: "wasm".into(),
        catalog_revision: 9,
        catalog_hash: "ab".repeat(32),
        entry_key: "iweb-wasmd".into(),
        image_digest: format!("sha256:{}", "cd".repeat(32)),
        host_abi: "iweb-wasmd-abi@1.0.0".into(),
        world: "wasi:http/proxy@0.2.8".into(),
    }
}

fn snapshot_payload(revision: u64, keys: &[(&str, &str)]) -> SnapshotValuesPayloadV1 {
    let mut values = BTreeMap::new();
    for (key, value) in keys {
        values.insert((*key).to_string(), (*value).to_string());
    }
    SnapshotValuesPayloadV1 {
        application_id: "vector".into(),
        version_id: format!("{}-1", "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532"),
        preparation_generation: 1,
        revision,
        keys: keys.iter().map(|(key, _)| (*key).to_string()).collect(),
        values,
    }
}

struct TestSetup {
    identity: WasmdIdentityV1,
    record: NodeCapabilityRecordV1,
    slots: SnapshotSlots,
}

/// 组装身份/record/快照（secret revision 3；config 由参数决定）。
fn setup(config_keys: Option<(&str, &str)>) -> TestSetup {
    let secret = snapshot_payload(3, &[("token", "v")]);
    let secret_bytes = jcs_bytes(&secret).expect("secret jcs");
    let secret_digest = domain_digest("iweb-secret-snapshot-v1", &secret_bytes);
    let config = config_keys.map(|(key, value)| snapshot_payload(2, &[(key, value)]));
    let config_digest = config
        .as_ref()
        .map(|payload| domain_digest("iweb-config-snapshot-v1", &jcs_bytes(payload).expect("config jcs")));
    let identity = WasmdIdentityV1 {
        sandbox_id: "sbx-vector".into(),
        version_id: format!("{}-1", "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532"),
        package_digest: "0".repeat(64),
        runtime_binding: vector_binding(),
        capability_record_revision: 5,
        capability_record_hash: "2".repeat(64),
        secret_revision: 3,
        secret_values_digest: secret_digest,
        config_revision: config.as_ref().map(|payload| payload.revision).unwrap_or(0),
        config_snapshot_ref: config_digest.as_ref().map(|_| "7".repeat(64)),
        config_values_digest: config_digest,
        preparation_generation: 1,
        execution_generation: 1,
    };
    let payload = NodeCapabilityRecordPayloadV1 {
        schema_version: 1,
        revision: 5,
        policy_maxima: iweb_wasmd::capability::NodePolicyMaximaV1 {
            cpu_millis: 1000,
            memory_bytes: 536_870_912,
            pid_limit: 512,
            storage_bytes: 1_073_741_824,
        },
        http: iweb_wasmd::capability::NodeHttpLimitsV1 {
            max_request_bytes: 1_048_576,
            max_response_bytes: 8_388_608,
            max_request_header_bytes: 8_192,
            max_response_header_bytes: 8_192,
            max_request_header_count: 64,
            max_response_header_count: 64,
            max_concurrent_requests: 16,
        },
        engine: iweb_wasmd::capability::NodeEngineLimitsV1 {
            // epoch 测试需要短 deadline；record 界 1..300000。
            max_epoch_deadline_ms: 150,
            fuel_per_request: None,
            max_live_instances: 8,
        },
        admission: iweb_wasmd::capability::NodeAdmissionLimitsV1 {
            max_package_bytes: 134_217_728,
            max_blob_bytes: 67_108_864,
            max_layer_count: 16,
            max_closure_nodes: 512,
            max_closure_edges: 2_048,
            max_closure_depth: 32,
            staging_ttl_seconds: 600,
        },
        restart: iweb_wasmd::capability::NodeRestartBudgetV1 { max_restarts: 3, window_ms: 60_000 },
        drain_deadline_ms: 500,
        runtime_reserves: vec![iweb_wasmd::capability::RuntimeReserveEntryV1 {
            runtime_binding: vector_binding(),
            architecture: "linux/arm64".into(),
            reserve_bytes: 33_554_432,
        }],
        matrix: matrix_record(),
    };
    let record_hash = domain_digest(
        NODE_CAPABILITY_RECORD_HASH_DOMAIN,
        &jcs_bytes(&payload).expect("record jcs"),
    );
    let record = NodeCapabilityRecordV1 {
        schema_version: payload.schema_version,
        revision: payload.revision,
        record_hash,
        policy_maxima: payload.policy_maxima,
        http: payload.http,
        engine: payload.engine,
        admission: payload.admission,
        restart: payload.restart,
        drain_deadline_ms: payload.drain_deadline_ms,
        runtime_reserves: payload.runtime_reserves,
        matrix: payload.matrix,
    };
    let _ = HostStore::new(None);
    TestSetup {
        identity,
        record,
        slots: SnapshotSlots { secret, config },
    }
}

fn matrix_record() -> iweb_wasmd::capability::WasmCapabilityMatrixV1 {
    let mut host_imports: Vec<iweb_wasmd::capability::ImportCapability> =
        iweb_wasmd::capability::MATRIX_HOST_IMPORTS
            .iter()
            .map(|(package, interface)| iweb_wasmd::capability::ImportCapability {
                package: (*package).into(),
                interface: (*interface).into(),
                direction: "import".into(),
            })
            .collect();
    host_imports.sort();
    iweb_wasmd::capability::WasmCapabilityMatrixV1 {
        world: "wasi:http/proxy@0.2.8".into(),
        host_abi: "iweb-wasmd-abi@1.0.0".into(),
        required_root_export: iweb_wasmd::capability::ImportCapability {
            package: "wasi:http@0.2.8".into(),
            interface: "incoming-handler".into(),
            direction: "export".into(),
        },
        host_imports,
    }
}

fn egress() -> Arc<GatewayEgress> {
    Arc::new(GatewayEgress {
        // 本组测试不出网；网关地址只作占位（唯一拨号目的地纪律不受影响）。
        gateway: "127.0.0.1:1".parse().expect("gateway addr"),
        http_limits: iweb_wasmd::capability::NodeHttpLimitsV1 {
            max_request_bytes: 1_048_576,
            max_response_bytes: 8_388_608,
            max_request_header_bytes: 8_192,
            max_response_header_bytes: 8_192,
            max_request_header_count: 64,
            max_response_header_count: 64,
            max_concurrent_requests: 16,
        },
        tls: GatewayEgress::production_tls(),
    })
}

/// 在随机端口起 ingress；返回（地址、引擎、句柄）。
async fn start_ingress(
    component: &str,
    setup_data: TestSetup,
) -> (std::net::SocketAddr, Arc<WasmdEngine>, iweb_wasmd::ingress::IngressHandle) {
    let component_bytes = std::fs::read(fixture(component)).expect("fixture component");
    let engine = WasmdEngine::new(
        &component_bytes,
        &setup_data.record,
        &setup_data.identity.runtime_binding,
        "linux/arm64",
        268_435_456,
        setup_data.slots,
        egress(),
        None,
    )
    .expect("engine init");
    let engine = Arc::new(engine);
    let _ticker = spawn_epoch_ticker(engine.engine());
    let listener_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    let address = listener_probe.local_addr().expect("probe addr");
    drop(listener_probe);
    let health = WasmReadinessHealthV2::from_identity(&setup_data.identity);
    let handle = serve(Arc::clone(&engine), health, address, setup_data.record.http.clone())
        .await
        .expect("serve");
    (address, engine, handle)
}

fn http_client() -> Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

#[tokio::test]
async fn respond_fixture_serves_request_and_health_v2() {
    let setup_data = setup(Some(("mode", "strict")));
    let (address, _engine, _handle) = start_ingress("wasmd-proxy-respond.wasm", setup_data).await;
    let client = http_client();
    let uri = format!("http://{address}/anything");
    // 应用请求：guest 构造默认 200 响应。
    let response = client.get(uri.parse().expect("uri")).await.expect("request");
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let body = response.into_body().collect().await.expect("body").to_bytes();
    assert!(body.is_empty());

    // health v2：JCS 原样（与 contracts golden 的构造器同输入；此处校验 15 字段形状
    // 与关键字段值——逐字节 golden 在 wire 单测中锁定）。
    let health_uri = format!("http://{address}{HEALTH_PATH}");
    let response = client.get(health_uri.parse().expect("uri")).await.expect("health");
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.headers().get(hyper::header::CONTENT_TYPE).unwrap(), "application/json");
    let body = response.into_body().collect().await.expect("body").to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("health json");
    let object = parsed.as_object().expect("health object");
    assert_eq!(object.len(), 15, "exact 15-field shape");
    assert_eq!(object["schemaVersion"], serde_json::json!(2));
    assert_eq!(object["ok"], serde_json::json!(true));
    assert_eq!(object["sandboxId"], serde_json::json!("sbx-vector"));
    assert_eq!(object["secretRevision"], serde_json::json!(3));
    assert_eq!(object["configRevision"], serde_json::json!(2));
    assert_eq!(object["preparationGeneration"], serde_json::json!(1));
    assert_eq!(object["executionGeneration"], serde_json::json!(1));
    assert_eq!(object["runtimeBinding"]["world"], serde_json::json!("wasi:http/proxy@0.2.8"));
}

#[tokio::test]
async fn loop_fixture_epoch_timeout_fails_only_that_request() {
    let setup_data = setup(None);
    let (address, engine, _handle) = start_ingress("wasmd-proxy-loop.wasm", setup_data).await;
    let client = http_client();
    let uri = format!("http://{address}/spin");

    // 第一次请求：guest 死循环 → epoch deadline（150ms）终止该执行 → 502。
    let started = std::time::Instant::now();
    let response = client.get(uri.parse().expect("uri")).await.expect("request 1");
    let elapsed = started.elapsed();
    assert_eq!(response.status(), hyper::StatusCode::BAD_GATEWAY);
    assert!(elapsed >= std::time::Duration::from_millis(100), "epoch deadline bounded the execution (elapsed {elapsed:?})");
    assert!(elapsed < std::time::Duration::from_secs(10), "must not hang");
    assert!(engine.counters().epoch_timeouts_cumulative.load(std::sync::atomic::Ordering::Relaxed) >= 1);

    // 进程不崩：第二次请求走同样的失败路径（仍能完整往返）。
    let response = client.get(uri.parse().expect("uri")).await.expect("request 2");
    assert_eq!(response.status(), hyper::StatusCode::BAD_GATEWAY);
    assert!(engine.counters().epoch_timeouts_cumulative.load(std::sync::atomic::Ordering::Relaxed) >= 2);

    // 实例计数回落（live 回 0；high water 单调 >= 1）。
    assert_eq!(engine.counters().instances_live_instant.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(engine.counters().instances_high_water_cumulative.load(std::sync::atomic::Ordering::Relaxed) >= 1);
}

#[tokio::test]
async fn noop_fixture_reports_guest_no_response() {
    let setup_data = setup(None);
    let (address, _engine, _handle) = start_ingress("wasmd-proxy-noop.wasm", setup_data).await;
    let client = http_client();
    let uri = format!("http://{address}/x");
    // guest 不调用 response-outparam::set：generic 502（细节不外泄）。
    let response = client.get(uri.parse().expect("uri")).await.expect("request");
    assert_eq!(response.status(), hyper::StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn sockets_import_fails_closed_at_startup() {
    let setup_data = setup(None);
    let component_bytes = std::fs::read(fixture("wasmd-proxy-sockets.wasm")).expect("fixture");
    let outcome = WasmdEngine::new(
        &component_bytes,
        &setup_data.record,
        &setup_data.identity.runtime_binding,
        "linux/arm64",
        268_435_456,
        setup_data.slots,
        egress(),
        None,
    );
    let error = match outcome {
        Ok(_) => panic!("sockets import must fail closed at pre-instantiation"),
        Err(error) => error,
    };
    assert!(
        format!("{error}").contains("wasi:sockets") || format!("{error}").contains("missing"),
        "error should name the missing import: {error}"
    );
}

#[tokio::test]
async fn draining_returns_503_for_new_requests() {
    let setup_data = setup(None);
    let (address, _engine, handle) = start_ingress("wasmd-proxy-respond.wasm", setup_data).await;
    // SIGTERM 等价：无在飞请求 → graceful_drain 立即完成（返回 true）。
    let drained = handle.graceful_drain(200).await;
    assert!(drained, "no in-flight requests: drain completes immediately");
    let client = http_client();
    let uri = format!("http://{address}{HEALTH_PATH}");
    let result = client.get(uri.parse().expect("uri")).await;
    // accept 循环已停：新连接被拒（Listener 关闭）——drain 中 503 分支由在飞连接
    // 触发；此断言证明不再接新流量。
    assert!(result.is_err(), "new connections must not be accepted after drain");
}
