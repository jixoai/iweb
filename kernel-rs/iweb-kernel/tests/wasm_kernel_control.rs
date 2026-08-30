//! two-tier-runtime-trust（Kernel 启动/HTTP 接线）集成测试：把 wasm_admission /
//! wasm_kind_registry / wasm_activation / wasm_publication / wasm_commands 状态机经
//! `iweb_kernel::wasm_runtime` 接进生产调用路径后的正/负行为：
//! - kind claims 从路由注册表派生（celld-app 路由 → 终身 celld claim → admission
//!   409 冲突；路由文件不可解析 → 节点启动失败，无 pending 模式）；
//! - admission 提交（发布门 → 事务 → kind registry 注册；join 幂等 / celld 冲突）；
//! - activation-rpc（lease/fence 判据、route CAS、replay、拒绝码）；
//! - admission → activation → retired 全链（含 drain receipt 投影）；
//! - wasm 单 gate 语义（无 celld gate、无 application switch）。

use iweb_kernel::wasm_activation::{
    compute_activation_command_digest, compute_service_readiness_lease_digest, generate_uuid_v7,
    ActivationCandidate, ActivationCommand, ActivationOperation, ServiceReadinessLeaseV2,
    ACTIVATION_RPC_PROTOCOL_LITERAL,
};
use iweb_kernel::wasm_admission::{
    jcs_bytes, RuntimeBindingIdentityV1, WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL,
};
use iweb_kernel::wasm_commands::{
    DrainReceiptV1, DrainRetirementProjection, WasmDrainResult, WasmExecutionIdentityV1,
};
use iweb_kernel::wasm_publication::{ENV_WASM_PUBLICATION_ENABLED, WASM_ACCEPTANCE_FILE};
use iweb_kernel::wasm_runtime::{WasmRuntime, WasmRuntimePaths};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

// -- spec 向量（与 wasm_admission/wasm_publication 的 golden 同源）--

const SPEC_VECTOR_MANIFEST: &str = r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#;
const SPEC_VECTOR_PACKAGE_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const SPEC_VECTOR_VERSION_DIGEST: &str =
    "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";

/// wasm_publication golden 验收记录（bun oracle 产出；node pins 与之逐字段相等）。
const GOLDEN_WASM_ACCEPTANCE_JCS: &str = r#"{"arch":"linux/amd64","capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"catalogEntryKey":"iweb-wasmd","catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"evidenceDigest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","gate":"application-sandbox","hostABI":"iweb-wasmd-abi@1.0.0","recordDigest":"69f0125fdd737b9b6f662fabd2c3cd52a3d0d93b82835ee9c10f19de7c2eea1f","result":"passed","runtimeImageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","runtimeKind":"wasm","version":2,"world":"wasi:http/proxy@0.2.8"}"#;


static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-kernel-ctl-{}-{}-{label}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("fixture root");
        Self { root }
    }

    fn paths(&self) -> WasmRuntimePaths {
        WasmRuntimePaths {
            root: self.root.join("wasm"),
            routes_registry: Some(self.root.join("routes.json")),
        }
    }

    /// 写路由注册表（kind-claim 派生源；空数组 = 无 celld claim）。
    fn write_routes(&self, celld_apps: &[&str]) {
        let routes: Vec<Value> = celld_apps
            .iter()
            .map(|app| {
                json!({
                    "hostId": app,
                    "target": { "kind": "celld-app", "appName": app },
                    "system": true,
                    "enabled": true,
                })
            })
            .collect();
        let file = json!({ "version": 1, "routes": routes });
        std::fs::write(
            self.root.join("routes.json"),
            serde_json::to_string(&file).expect("routes json"),
        )
        .expect("write routes");
    }

    /// 写 gate 节点 pin（与 golden 验收记录逐字段相等）。
    fn write_gate_pin(&self) {
        let pin = json!({
            "schemaVersion": 1,
            "runtimeKind": "wasm",
            "architecture": "linux/amd64",
            "capabilityRecordRevision": 5,
            "capabilityRecordHash": "2".repeat(64),
            "catalogRevision": 9,
            "catalogHash": "ab".repeat(32),
            "catalogEntry": {
                "entryKey": "iweb-wasmd",
                "imageDigest": format!("sha256:{}", "cd".repeat(32)),
                "hostABI": WASM_HOST_ABI_LITERAL,
                "world": WASM_WORLD_LITERAL,
            },
        });
        let bytes = jcs_bytes(&pin).expect("pin jcs");
        let wasm_root = self.root.join("wasm");
        std::fs::create_dir_all(&wasm_root).expect("wasm root");
        std::fs::write(wasm_root.join("gate-node-identity.json"), bytes).expect("write pin");
    }

    /// 启动运行时：验收记录 fixture + 开关（wasm-only 单开关；无 celld gate）。
    /// 默认写空路由注册表（无 celld claim）；需要 celld claim 的用例先 write_routes。
    fn start(&self, wasm_record: Option<&str>, switches: &[&str]) -> WasmRuntime {
        if !self.root.join("routes.json").is_file() {
            self.write_routes(&[]);
        }
        let wasm_record = wasm_record.map(str::as_bytes).map(Vec::from);
        WasmRuntime::startup(
            self.paths(),
            &|path: &str| {
                if path == WASM_ACCEPTANCE_FILE {
                    wasm_record
                        .clone()
                        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "unexpected path",
                    ))
                }
            },
            &|name: &str| switches.contains(&name).then(|| "1".to_string()),
        )
    }

    /// 全开环境（wasm 记录 + wasm 开关 + pin + 空路由）。
    fn start_enabled(&self) -> WasmRuntime {
        self.write_gate_pin();
        self.start(Some(GOLDEN_WASM_ACCEPTANCE_JCS), &[ENV_WASM_PUBLICATION_ENABLED])
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn vector_binding_value() -> Value {
    json!({
        "kind": "wasm",
        "catalogRevision": 9,
        "catalogHash": "ab".repeat(32),
        "entryKey": "iweb-wasmd",
        "imageDigest": format!("sha256:{}", "cd".repeat(32)),
        "hostABI": WASM_HOST_ABI_LITERAL,
        "world": WASM_WORLD_LITERAL,
    })
}

fn blob_entry(bytes: &[u8]) -> Value {
    let digest = sha256_hex(bytes);
    json!({ "digestHex": digest, "base64": b64(bytes) })
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// admission 提交 body（spec 向量 manifest；sequence 控制由 allow_resequence 表达）。
fn admission_body(application: &str, allow_resequence: bool) -> Vec<u8> {
    json!({
        "schemaVersion": 1,
        "applicationId": application,
        "packageDigest": SPEC_VECTOR_PACKAGE_DIGEST,
        "normalizedPolicy": serde_json::from_str::<Value>(SPEC_VECTOR_MANIFEST).expect("manifest"),
        "runtimeBinding": vector_binding_value(),
        "capabilityRecordRevision": 5,
        "capabilityRecordHash": "2".repeat(64),
        "stagingTtlSeconds": 600,
        "blobs": [blob_entry(b"wasm-component-bytes")],
        "allowResequence": allow_resequence,
    })
    .to_string()
    .into_bytes()
}

fn parse_body(body: &str) -> Value {
    serde_json::from_str(body.trim()).expect("response body is JSON")
}

fn submit_admission(
    runtime: &mut WasmRuntime,
    application: &str,
    allow_resequence: bool,
) -> (u16, Value) {
    let response = runtime.handle_admission_submit(
        true,
        Some("application/json"),
        &admission_body(application, allow_resequence),
        1_800_000_000_000,
    );
    let parsed = parse_body(&response.body);
    (response.status, parsed)
}

// -- fence / lease 播种（执行流集成面的固定文件契约）--

fn seed_fence(fixture: &Fixture, application: &str, current_version_id: &str, records: Value) {
    let file = json!({
        "schemaVersion": 1,
        "runtimeKind": "wasm",
        "applications": { application: { "currentVersionId": current_version_id, "records": records } },
    });
    let bytes = jcs_bytes(&file).expect("fence jcs");
    std::fs::write(fixture.paths().root.join("wasm-fences.json"), bytes).expect("write fences");
}

fn fence_record(
    version_id: &str,
    sandbox_id: &str,
    generation: u64,
    lifecycle: &str,
    drain_deadline: Option<u64>,
) -> (String, Value) {
    let record = json!({
        "versionId": version_id,
        "sandboxId": sandbox_id,
        "preparationGeneration": generation,
        "executionGeneration": generation,
        "secretRevision": 0,
        "secretSnapshotRef": "0".repeat(64),
        "secretValuesDigest": "6".repeat(64),
        "configRevision": 0,
        "configSnapshotRef": null,
        "configValuesDigest": null,
        "alive": true,
        "lifecycle": lifecycle,
        "bindingRevoked": false,
        "drainDeadlineEpochMillis": drain_deadline,
    });
    (version_id.to_string(), record)
}

fn build_lease(candidate: &ActivationCandidate, nonce: &str) -> ServiceReadinessLeaseV2 {
    let now = iweb_kernel::monitor::now_millis() as u64;
    let base = ServiceReadinessLeaseV2 {
        schema_version: 2,
        lease_nonce: nonce.to_string(),
        sandbox_id: candidate.sandbox_id.clone(),
        version_id: candidate.version_id.clone(),
        package_digest: candidate.package_digest.clone(),
        runtime_binding: candidate.runtime_binding.clone(),
        host_service_policy_digest: String::new(),
        capability_record_revision: 5,
        capability_record_hash: "2".repeat(64),
        secret_revision: candidate.secret_revision,
        secret_values_digest: candidate.secret_values_digest.clone(),
        config_revision: candidate.config_revision,
        config_snapshot_ref: candidate.config_snapshot_ref.clone(),
        config_values_digest: candidate.config_values_digest.clone(),
        preparation_generation: candidate.preparation_generation,
        execution_generation: candidate.execution_generation,
        issued_at: iweb_kernel::wasm_admission::format_rfc3339_utc_millis(now),
        expires_at: iweb_kernel::wasm_admission::format_rfc3339_utc_millis(now + 600_000),
        lease_digest: String::new(),
    };
    let digest = compute_service_readiness_lease_digest(&base).expect("lease digest");
    ServiceReadinessLeaseV2 {
        lease_digest: digest,
        ..base
    }
}

fn seed_lease(fixture: &Fixture, lease: &ServiceReadinessLeaseV2) {
    let value = serde_json::to_value(lease).expect("lease value");
    let file = json!({
        "schemaVersion": 1,
        "runtimeKind": "wasm",
        "leases": { lease.lease_nonce.clone(): value },
    });
    let bytes = jcs_bytes(&file).expect("lease jcs");
    std::fs::write(fixture.paths().root.join("readiness-leases.json"), bytes)
        .expect("write leases");
}

fn build_candidate(
    version_id: &str,
    admission_proof_digest: &str,
    sandbox_id: &str,
    generation: u64,
    nonce: &str,
    lease_digest: &str,
) -> ActivationCandidate {
    ActivationCandidate {
        runtime_kind: "wasm".into(),
        sandbox_id: sandbox_id.into(),
        version_id: version_id.into(),
        package_digest: SPEC_VECTOR_PACKAGE_DIGEST.into(),
        runtime_binding: iweb_kernel::wasm_commands::runtime_binding_v2_from_v1(
            &RuntimeBindingIdentityV1 {
                kind: "wasm".into(),
                catalog_revision: 9,
                catalog_hash: "ab".repeat(32),
                entry_key: "iweb-wasmd".into(),
                image_digest: format!("sha256:{}", "cd".repeat(32)),
                host_abi: WASM_HOST_ABI_LITERAL.into(),
                world: WASM_WORLD_LITERAL.into(),
            },
        )
        .expect("binding derives"),
        admission_proof_ref: format!("admission-proof/vector/{version_id}"),
        admission_proof_digest: admission_proof_digest.into(),
        preparation_generation: generation,
        execution_generation: generation,
        secret_revision: 0,
        secret_values_digest: "6".repeat(64),
        config_revision: 0,
        config_snapshot_ref: None,
        config_values_digest: None,
        lease_nonce: nonce.into(),
        lease_digest: lease_digest.into(),
    }
}

/// activation-rpc envelope（canonical JCS 字节）。
fn activation_envelope(command: &ActivationCommand) -> Vec<u8> {
    let body = serde_json::to_value(command).expect("command value");
    let envelope = json!({
        "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
        "requestId": generate_uuid_v7(iweb_kernel::monitor::now_millis() as u64),
        "body": body,
    });
    jcs_bytes(&envelope).expect("envelope jcs")
}

fn call_activation(runtime: &mut WasmRuntime, envelope: &[u8]) -> (u16, Value) {
    let response = runtime.handle_activation_rpc(
        Some("Bearer owner"),
        Some("application/json"),
        envelope,
        &|bearer| bearer == Some("Bearer owner"),
    );
    let parsed = parse_body(&response.body);
    (response.status, parsed)
}

fn wire_command(
    activation_id: &str,
    expected_route_generation: u64,
    candidate: ActivationCandidate,
) -> ActivationCommand {
    let command = ActivationCommand {
        schema_version: 2,
        activation_id: activation_id.into(),
        application_id: "vector".into(),
        operation: ActivationOperation::Activate,
        expected_route_generation,
        expected_control_revision: 0,
        candidate,
        host_service_policy_digest: String::new(),
        capability_record_revision: 5,
        capability_record_hash: "2".repeat(64),
        requested_at: iweb_kernel::wasm_admission::format_rfc3339_utc_millis(
            iweb_kernel::monitor::now_millis() as u64,
        ),
        command_digest: String::new(),
    };
    let command_digest = compute_activation_command_digest(&command).expect("command digest");
    ActivationCommand { command_digest, ..command }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[test]
fn celld_route_claim_conflicts_with_wasm_admission() {
    // celld-app 路由目标 → 终身 celld claim：同名 wasm 准入 409（零写入）。
    let fixture = Fixture::new("route-claim-conflict");
    fixture.write_gate_pin();
    fixture.write_routes(&["notes"]);
    let mut runtime = fixture.start(
        Some(GOLDEN_WASM_ACCEPTANCE_JCS),
        &[ENV_WASM_PUBLICATION_ENABLED],
    );
    let (status, body) = submit_admission(&mut runtime, "notes", false);
    assert_eq!(status, 409);
    assert_eq!(
        body["code"],
        json!(iweb_kernel::wasm_kind_registry::APPLICATION_RUNTIME_KIND_CONFLICT)
    );
    assert!(runtime.project_registry_rows().is_empty());
    // 派生状态投影：{state:"verified", claims:N, source:"route-registry"}。
    let projection = runtime.status_projection();
    assert_eq!(projection["bootstrap"]["state"], json!("verified"));
    assert_eq!(projection["bootstrap"]["claims"], json!(1));
    assert_eq!(projection["bootstrap"]["source"], json!("route-registry"));
    // 未冲突的名字照常准入（路由派生不阻塞 wasm）。
    let (status, _) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 201);
}

#[test]
fn unparseable_route_registry_fails_kernel_startup() {
    // 路由文件不可解析 → RouteStore panic → 节点启动失败（无 pending/partial 模式）。
    let fixture = Fixture::new("routes-corrupt");
    fixture.write_gate_pin();
    std::fs::write(fixture.root.join("routes.json"), b"{ not-a-route-registry").expect("write corrupt routes");
    let result = std::panic::catch_unwind(|| {
        fixture.start(
            Some(GOLDEN_WASM_ACCEPTANCE_JCS),
            &[ENV_WASM_PUBLICATION_ENABLED],
        )
    });
    assert!(result.is_err(), "corrupt route registry must abort startup");
}

#[test]
fn wasm_gate_is_single_switch_and_fail_closed() {
    let fixture = Fixture::new("gate-single");
    fixture.write_gate_pin();
    // (a) wasm 固定路径缺失 + 开关开：sandbox-acceptance-missing。
    let mut runtime = fixture.start(None, &[ENV_WASM_PUBLICATION_ENABLED]);
    assert!(!runtime.wasm_gate().enabled);
    assert_eq!(runtime.wasm_gate().reasons, vec!["sandbox-acceptance-missing"]);
    let (status, body) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 503);
    assert_eq!(body["code"], json!("WASM_PUBLICATION_DISABLED"));

    // (b) 无 wasm 开关（唯一开关；application switch 已随 celld 准入删除）→
    // publication-not-requested。
    let runtime = fixture.start(Some(GOLDEN_WASM_ACCEPTANCE_JCS), &[]);
    assert!(!runtime.wasm_gate().enabled);
    assert_eq!(runtime.wasm_gate().reasons, vec!["publication-not-requested"]);
    let mut runtime = runtime;
    let (status, _) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 503);

    // (c) wasm 路径放旧 v1 形状记录 → wasm-acceptance-invalid（无第二个 parser）。
    let v1_shape = r#"{"version":1,"gate":"application-sandbox","result":"passed","evidenceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let runtime = fixture.start(Some(v1_shape), &[ENV_WASM_PUBLICATION_ENABLED]);
    assert!(!runtime.wasm_gate().enabled);
    assert_eq!(runtime.wasm_gate().reasons, vec!["wasm-acceptance-invalid"]);

    // (d) 无节点 pin（pin 文件缺失）→ 三项 pin 失配关闭（绝不推断默认 pin）。
    let other = Fixture::new("gate-no-pin");
    let runtime = other.start(Some(GOLDEN_WASM_ACCEPTANCE_JCS), &[ENV_WASM_PUBLICATION_ENABLED]);
    assert!(!runtime.wasm_gate().enabled);
    assert!(
        runtime.wasm_gate().accepted,
        "the record itself is valid; only the pins are missing"
    );
    assert_eq!(
        runtime.wasm_gate().reasons,
        vec![
            "wasm-identity-mismatch",
            "capability-record-mismatch",
            "catalog-mismatch"
        ]
    );

    // (e) 全开：wasm gate 的选择响应为精确四键。
    let runtime = fixture.start_enabled();
    let selection = runtime.wasm_gate_selection();
    assert!(selection.enabled);
    assert_eq!(selection.reasons, Vec::<&str>::new());
    assert_eq!(selection.runtime_kind, "wasm");
}

#[test]
fn admission_happy_path_registers_kind_claim_and_joins_retries() {
    let fixture = Fixture::new("admission-happy");
    let mut runtime = fixture.start_enabled();
    let (status, body) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 201, "body: {body}");
    assert_eq!(body["state"], json!("visible"));
    assert_eq!(body["created"], json!(true));
    assert_eq!(
        body["versionId"],
        json!(format!("{SPEC_VECTOR_VERSION_DIGEST}-1"))
    );
    // AdmittedVisible 单点谓词：三段 witness 一致。
    let proof = runtime
        .admitted_visible("vector", &format!("{SPEC_VECTOR_VERSION_DIGEST}-1"))
        .expect("witness check runs")
        .expect("the version is visible");
    assert_eq!(proof.sequence, 1);
    // kind claim + v2 物化：visible admission 后立即生成并持久化
    // Prepare -> Start，业务行因此已进入 preparing，而不是停留在 admitted。
    let rows = runtime.project_registry_rows();
    assert_eq!(rows["vector"][0].lifecycle, "preparing");
    let control = runtime
        .control_state_projection()
        .expect("canonical v2 control state");
    assert_eq!(
        control.control_revision,
        5,
        "visible admission, Prepare append, Start append, and the two unavailable-relay delivery attempts each consume one persisted v2 CAS revision"
    );
    assert_eq!(control.command_outbox.len(), 2);
    assert_eq!(
        control.command_outbox[0].command.operation,
        iweb_kernel::wasm_commands::WasmExecutionOperation::Prepare
    );
    assert_eq!(control.command_outbox[0].command.expected_control_revision, 1);
    assert_eq!(control.command_outbox[0].attempts, 1);
    assert_eq!(
        control.command_outbox[0].delivery_state,
        iweb_kernel::wasm_commands::OutboxDeliveryState::Sent
    );
    assert_eq!(
        control.command_outbox[1].command.operation,
        iweb_kernel::wasm_commands::WasmExecutionOperation::Start
    );
    assert_eq!(control.command_outbox[1].command.expected_control_revision, 2);
    assert_eq!(control.command_outbox[1].attempts, 1);
    assert_eq!(
        control.command_outbox[1].delivery_state,
        iweb_kernel::wasm_commands::OutboxDeliveryState::Sent
    );
    let index =
        std::fs::read(fixture.root.join("wasm/kind-registry/index.json")).expect("kind index");
    assert!(
        String::from_utf8_lossy(&index).contains("\"vector\""),
        "the wasm kind claim is durably recorded"
    );
    // 重试 join：同事务幂等（created=false、同 versionId）。
    let (status, body) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 201);
    assert_eq!(body["created"], json!(false));
    assert_eq!(
        body["versionId"],
        json!(format!("{SPEC_VECTOR_VERSION_DIGEST}-1"))
    );
    // 显式 resequence：同 digest 分配更高 sequence。
    let (_, body) = submit_admission(&mut runtime, "vector", true);
    assert_eq!(
        body["versionId"],
        json!(format!("{SPEC_VECTOR_VERSION_DIGEST}-2"))
    );

    // celld-bound applicationId（路由派生 claim）→ 冲突（零写入）。
    let celld_fixture = Fixture::new("admission-celld-conflict");
    celld_fixture.write_gate_pin();
    celld_fixture.write_routes(&["notes"]);
    let mut runtime = celld_fixture.start_enabled();
    let (status, body) = submit_admission(&mut runtime, "notes", false);
    assert_eq!(status, 409);
    assert_eq!(
        body["code"],
        json!(iweb_kernel::wasm_kind_registry::APPLICATION_RUNTIME_KIND_CONFLICT)
    );
    assert!(runtime.project_registry_rows().is_empty());

    // 路由派生是无 digest 重验证链的确定性步骤：新 celld 路由只影响新 claim，
    // 已准入的 wasm 应用不受任何影响。
    let change_fixture = Fixture::new("admission-route-claims");
    change_fixture.write_gate_pin();
    change_fixture.write_routes(&["admin"]);
    let mut runtime = change_fixture.start_enabled();
    let (status, _) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 201);
    let (status, _) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 201, "join retry stays open beside celld route claims");
    let projection = runtime.status_projection();
    assert_eq!(projection["bootstrap"]["state"], json!("verified"));
    assert_eq!(projection["bootstrap"]["claims"], json!(1));
    assert_eq!(projection["bootstrap"]["source"], json!("route-registry"));
}

#[test]
fn activation_rpc_full_chain_from_admission_to_retired() {
    let fixture = Fixture::new("activation-chain");
    let mut runtime = fixture.start_enabled();

    // v1 准入（spec 向量 digest → versionId -1）。
    let (_, body) = submit_admission(&mut runtime, "vector", false);
    let v1: String = body["versionId"].as_str().expect("versionId").to_string();
    let rows = runtime.project_registry_rows();
    let proof_digest_v1: String = rows["vector"][0]
        .admission_proof_digest
        .as_str()
        .to_string();
    assert_eq!(
        rows["vector"][0].admission_proof_ref,
        format!("admission-proof/vector/{v1}")
    );

    // 无 fence/无 lease：激活被拒（lease 台账查无记录 → READINESS_LEASE_MISMATCH）。
    let nonce_v1 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    let candidate_v1 = build_candidate(
        &v1,
        &proof_digest_v1,
        "sbx-vector",
        1,
        nonce_v1,
        &"0".repeat(64),
    );
    let command = wire_command(
        &generate_uuid_v7(1_800_000_000_000),
        0,
        candidate_v1.clone(),
    );
    let (status, body) = call_activation(&mut runtime, &activation_envelope(&command));
    assert_eq!(status, 200);
    assert_eq!(body["body"]["status"], json!("rejected"));
    assert_eq!(
        body["body"]["event"]["reasonCode"],
        json!("READINESS_LEASE_MISMATCH")
    );

    // 播种 fence + lease（执行流集成面契约文件）。
    seed_fence(
        &fixture,
        "vector",
        &v1,
        json!({ v1.clone(): fence_record(&v1, "sbx-vector", 1, "ready", None).1 }),
    );
    let lease_v1 = build_lease(&candidate_v1, nonce_v1);
    assert!(lease_v1.validate().is_ok());
    seed_lease(&fixture, &lease_v1);
    let candidate_v1 = ActivationCandidate {
        lease_digest: lease_v1.lease_digest.clone(),
        ..candidate_v1.clone()
    };
    let command = wire_command(
        &generate_uuid_v7(1_800_000_001_000),
        0,
        candidate_v1.clone(),
    );

    // 错误 expectedRouteGeneration → ACTIVATION_ROUTE_CONFLICT（路由不动）。
    let wrong = wire_command(
        &generate_uuid_v7(1_800_000_002_000),
        7,
        candidate_v1.clone(),
    );
    let (status, body) = call_activation(&mut runtime, &activation_envelope(&wrong));
    assert_eq!(status, 200);
    assert_eq!(body["body"]["status"], json!("rejected"));
    assert_eq!(
        body["body"]["event"]["reasonCode"],
        json!("ACTIVATION_ROUTE_CONFLICT")
    );

    // 正确命令 → activated（route generation 0 → 1）。
    let (status, body) = call_activation(&mut runtime, &activation_envelope(&command));
    if body["body"]["status"] != json!("activated") {
        panic!("activation rejected: {body}");
    }
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["body"]["status"], json!("activated"));
    assert_eq!(body["body"]["event"]["routeGeneration"], json!(1));
    assert_eq!(body["body"]["event"]["next"]["versionId"], json!(v1));
    // lifecycle 同步：v1 → active。
    assert_eq!(
        runtime.project_registry_rows()["vector"][0].lifecycle,
        "active"
    );
    let control = runtime
        .control_state_projection()
        .expect("activation projects into canonical v2 control state");
    let active = control.applications["vector"]
        .versions
        .iter()
        .find(|version| version.version_id == v1)
        .expect("active v1 row");
    assert_eq!(
        active.readiness_lease_digest.as_deref(),
        Some(lease_v1.lease_digest.as_str())
    );

    // query：返回原始 activated 事件（无二次消费）。
    let query = json!({
        "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
        "requestId": generate_uuid_v7(1_800_000_003_000),
        "body": { "kind": "query", "activationId": command.activation_id },
    });
    let (status, body) = call_activation(&mut runtime, &jcs_bytes(&query).expect("query jcs"));
    assert_eq!(status, 200);
    assert_eq!(body["body"]["status"], json!("activated"));
    assert_eq!(body["body"]["event"]["routeGeneration"], json!(1));

    // byte-identical replay：同 activationId + 相同命令 → 原始事件，无二次递增。
    let (status, body) = call_activation(&mut runtime, &activation_envelope(&command));
    assert_eq!(status, 200);
    assert_eq!(body["body"]["status"], json!("activated"));
    assert_eq!(body["body"]["event"]["routeGeneration"], json!(1));

    // v2 准入（resequence）+ fence（含精确 drain deadline）+ lease → 激活替换。
    let (_, body) = submit_admission(&mut runtime, "vector", true);
    let v2: String = body["versionId"].as_str().expect("versionId").to_string();
    assert_eq!(v2, format!("{SPEC_VECTOR_VERSION_DIGEST}-2"));
    let proof_digest_v2: String = runtime.project_registry_rows()["vector"][1]
        .admission_proof_digest
        .clone();
    let drain_deadline = iweb_kernel::monitor::now_millis() as u64 + 300_000;
    let (fence_v1_key, fence_v1_value) =
        fence_record(&v1, "sbx-vector", 1, "ready", Some(drain_deadline));
    let (_, fence_v2_value) = fence_record(&v2, "sbx-vector2", 2, "ready", Some(drain_deadline));
    seed_fence(
        &fixture,
        "vector",
        &v2,
        json!({ fence_v1_key: fence_v1_value, v2.clone(): fence_v2_value }),
    );
    let nonce_v2 = "11223344556677889900aabbccddeeff";
    let candidate_v2 = build_candidate(
        &v2,
        &proof_digest_v2,
        "sbx-vector2",
        2,
        nonce_v2,
        &"0".repeat(64),
    );
    let lease_v2 = build_lease(&candidate_v2, nonce_v2);
    seed_lease(&fixture, &lease_v2);
    let candidate_v2 = ActivationCandidate {
        lease_digest: lease_v2.lease_digest.clone(),
        ..candidate_v2
    };
    let command_v2 = wire_command(&generate_uuid_v7(1_800_000_004_000), 1, candidate_v2);
    let (status, body) = call_activation(&mut runtime, &activation_envelope(&command_v2));
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["body"]["status"], json!("activated"));
    assert_eq!(body["body"]["event"]["routeGeneration"], json!(2));
    assert_eq!(body["body"]["event"]["previous"]["versionId"], json!(v1));

    // retiring 建档：v1 的 drain 命令 + 判据已持久化；v1 lifecycle 仍非 retired。
    let retirements = runtime.retiring_records();
    assert_eq!(retirements.len(), 1);
    let retiring = &retirements[0];
    assert_eq!(retiring.execution.version_id, v1);
    assert_eq!(retiring.route_generation, 1);
    assert!(!retiring.retired);
    assert_eq!(
        runtime.project_registry_rows()["vector"][0].lifecycle,
        "active",
        "retired is written only after the drain receipt projection"
    );

    // drain receipt 投影（supervisor 通道语义；此处经模块入口驱动）→ v1 retired。
    let receipt = DrainReceiptV1 {
        schema_version: 1,
        command_id: retiring.drain_command_id.clone(),
        application_id: "vector".into(),
        execution: WasmExecutionIdentityV1 {
            sandbox_id: "sbx-vector".into(),
            version_id: v1.clone(),
            preparation_generation: 1,
            execution_generation: 1,
        },
        package_digest: SPEC_VECTOR_PACKAGE_DIGEST.into(),
        runtime_binding: RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: WASM_HOST_ABI_LITERAL.into(),
            world: WASM_WORLD_LITERAL.into(),
        },
        route_generation: 1,
        drained_request_count: 0,
        deadline_at: iweb_kernel::wasm_admission::format_rfc3339_utc_millis(drain_deadline),
        forced_kill_at: None,
        result: WasmDrainResult::Drained,
        completed_at: iweb_kernel::wasm_admission::format_rfc3339_utc_millis(
            iweb_kernel::monitor::now_millis() as u64,
        ),
        journal_revision: 2,
        receipt_digest: String::new(),
    };
    let receipt = DrainReceiptV1 {
        receipt_digest: iweb_kernel::wasm_commands::drain_receipt_digest_v1(&receipt)
            .expect("receipt digest"),
        ..receipt
    };
    let projection = runtime
        .project_drain_receipt(&receipt)
        .expect("receipt projects");
    assert!(matches!(
        projection,
        DrainRetirementProjection::Retired { .. }
    ));
    let rows = runtime.project_registry_rows();
    assert_eq!(rows["vector"][0].lifecycle, "retired");
    assert_eq!(
        rows["vector"][1].lifecycle, "active",
        "the replacement keeps serving"
    );
    // 幂等重投影。
    let projection = runtime
        .project_drain_receipt(&receipt)
        .expect("replay projects");
    assert!(matches!(
        projection,
        DrainRetirementProjection::AlreadyRetired
    ));
    // status 投影收口：active 指针 = v2（routeGeneration 2），bootstrap verified。
    let status = runtime.status_projection();
    assert_eq!(status["applications"][0]["active"]["versionId"], json!(v2));
    assert_eq!(status["applications"][0]["routeGeneration"], json!(2));
    assert_eq!(status["bootstrap"]["state"], json!("verified"));
}

#[test]
fn unauthorized_and_framing_failures_do_not_mutate_state() {
    let fixture = Fixture::new("activation-negative");
    let mut runtime = fixture.start_enabled();
    // 未授权：401（无状态写入）。
    let response = runtime.handle_admission_submit(
        false,
        Some("application/json"),
        &admission_body("vector", false),
        1_800_000_000_000,
    );
    assert_eq!(response.status, 401);
    // content type 缺失：415。
    let response = runtime.handle_admission_submit(
        true,
        None,
        &admission_body("vector", false),
        1_800_000_000_000,
    );
    assert_eq!(response.status, 415);
    // wire 拒绝：schemaVersion=2 → 400。
    let response = runtime.handle_admission_submit(
        true,
        Some("application/json"),
        b"{\"schemaVersion\":2}",
        1_800_000_000_000,
    );
    assert_eq!(response.status, 400);
    assert!(runtime.project_registry_rows().is_empty());
    // activation bearer 失败：401（模块六步 framing 的第 4 步）。
    let envelope = activation_envelope(&wire_command(
        &generate_uuid_v7(1_800_000_005_000),
        0,
        build_candidate(
            &format!("{SPEC_VECTOR_VERSION_DIGEST}-1"),
            &"0".repeat(64),
            "sbx-vector",
            1,
            "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            &"0".repeat(64),
        ),
    ));
    let response = runtime.handle_activation_rpc(
        Some("Bearer wrong"),
        Some("application/json"),
        &envelope,
        &|bearer| bearer == Some("Bearer owner"),
    );
    assert_eq!(response.status, 401);
    // 非 JCS envelope → 400 ACTIVATION_RPC_ENVELOPE_INVALID。
    let response = runtime.handle_activation_rpc(
        Some("Bearer owner"),
        Some("application/json"),
        b"{ \"protocol\": \"iweb-wasm-activation-v1\" }",
        &|bearer| bearer == Some("Bearer owner"),
    );
    assert_eq!(response.status, 400);
    let body = parse_body(&response.body);
    assert_eq!(body["code"], json!("ACTIVATION_RPC_ENVELOPE_INVALID"));
}

#[test]
fn startup_recovery_replays_persisted_state_across_restart() {
    let fixture = Fixture::new("restart-recovery");
    {
        let mut runtime = fixture.start_enabled();
        let (status, _) = submit_admission(&mut runtime, "vector", false);
        assert_eq!(status, 201);
        let rows = runtime.project_registry_rows();
        assert_eq!(rows["vector"].len(), 1);
    }
    // 重启：持久化 proof 幂等重放（kind claim/业务行/激活态不漂移）。
    let runtime = fixture.start_enabled();
    let rows = runtime.project_registry_rows();
    assert_eq!(
        rows["vector"].len(),
        1,
        "the persisted proof replays exactly once"
    );
    assert_eq!(
        rows["vector"][0].version_id,
        format!("{SPEC_VECTOR_VERSION_DIGEST}-1")
    );
    assert_eq!(rows["vector"][0].lifecycle, "preparing");
    let control = runtime
        .control_state_projection()
        .expect("single startup round converges visible admission into v2 execution work");
    assert_eq!(
        control.command_outbox.len(),
        2,
        "recovery observes the already planned Prepare/Start pair without a second restart"
    );
    let projection = runtime.status_projection();
    assert_eq!(projection["bootstrap"]["state"], json!("verified"));
    // 重启后重试同请求 → join（created=false）。
    let mut runtime = runtime;
    let (status, body) = submit_admission(&mut runtime, "vector", false);
    assert_eq!(status, 201);
    assert_eq!(body["created"], json!(false));
}

#[test]
fn gate_wire_shape_is_the_wasm_only_projection() {
    let fixture = Fixture::new("gate-wire");
    let runtime = fixture.start_enabled();
    assert_eq!(runtime.wasm_gate().runtime_kind, "wasm");
    assert!(runtime.wasm_gate().enabled);
    let projection = runtime.status_projection();
    assert_eq!(
        projection["publicationGate"],
        json!({ "schemaVersion": 1, "runtimeKind": "wasm", "enabled": true, "reasons": [] })
    );
    // celldPublicationGate 已删除：键必须缺席（无 celld gate 投影）。
    assert!(projection.get("celldPublicationGate").is_none());
}
