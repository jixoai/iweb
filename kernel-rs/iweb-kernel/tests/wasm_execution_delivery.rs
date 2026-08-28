//! add-wasm-runtime P0 批次（codex-final 复审 4.6/10 的 Kernel 侧闭合）集成测试：
//! - P0-1 投递闭环：plan_execution_command 生成的 outbox 命令经 /v1/execution-rpc
//!   投递（真实 UDS 上的最小 supervisor 应答者），query/replay 和解与 ack 投影
//!   覆盖 response-lost / echo 拒绝 / journal 冲突留待重试；
//! - P0-1 ingress：Sandbox 路由代理到沙箱网关 ingress socket（头部契约 + 泛化 502）；
//! - P0-4 准入身份绑定：binding/capability/catalog pin 逐字段负例；
//! - P0-5 跨存储恢复窗口：witness→kind registry→route registry 三段写入崩溃矩阵
//!   （created=false 补写 + 启动从任一中间态收敛）；
//! - P0-6 控制态对齐：schema-1 → wasm-control-state-v2.json 一次性迁移。

use iweb_kernel::wasm_activation::{
    compute_readiness_lease_digest, generate_uuid_v7, ActivationCandidateV1, ActivationOperation,
    ReadinessLeaseV2, WireActivationCommandV1, ACTIVATION_RPC_PROTOCOL_LITERAL,
};
use iweb_kernel::wasm_admission::{
    jcs_bytes, RuntimeBindingIdentityV1, WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL,
};
use iweb_kernel::wasm_commands::OutboxDeliveryState;
use iweb_kernel::wasm_publication::{
    CELLD_ACCEPTANCE_FILE, ENV_APPLICATION_PUBLICATION_ENABLED, ENV_WASM_PUBLICATION_ENABLED,
    WASM_ACCEPTANCE_FILE,
};
use iweb_kernel::wasm_runtime::{WasmControlFailure, WasmRuntime, WasmRuntimePaths};
use iweb_kernel::wasm_snapshot_fd::{
    compute_snapshot_fd_digest, compute_snapshot_handoff_digest, SnapshotAckStatus,
    SnapshotDeliveryOutcome, SnapshotFdAckV1, SnapshotFdError, SnapshotFrameKind,
    SnapshotHandoffDelivery, SnapshotHandoffPayload, SnapshotSocketPeer,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const SPEC_VECTOR_MANIFEST: &str = r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#;
const SPEC_VECTOR_PACKAGE_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const SPEC_VECTOR_VERSION_DIGEST: &str =
    "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532";
const GOLDEN_WASM_ACCEPTANCE_JCS: &str = r#"{"arch":"linux/amd64","capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"catalogEntryKey":"iweb-wasmd","catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"evidenceDigest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","gate":"application-sandbox","hostABI":"iweb-wasmd-abi@1.0.0","recordDigest":"69f0125fdd737b9b6f662fabd2c3cd52a3d0d93b82835ee9c10f19de7c2eea1f","result":"passed","runtimeImageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","runtimeKind":"wasm","version":2,"world":"wasi:http/proxy@0.2.8"}"#;
const CELLD_V1_ACCEPTANCE: &str = r#"{"version":1,"gate":"application-sandbox","result":"passed","evidenceDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Fixture（对位 wasm_kernel_control.rs 的启动环境；本文件聚焦投递/绑定/恢复窗口）
// ---------------------------------------------------------------------------

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iweb-wasm-exec-delivery-{}-{}-{label}",
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
            celld_control_db: self.root.join("control-db.json"),
        }
    }

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

    fn start_enabled(&self) -> WasmRuntime {
        self.write_gate_pin();
        self.start(
            Some(GOLDEN_WASM_ACCEPTANCE_JCS),
            Some(CELLD_V1_ACCEPTANCE),
            &[
                ENV_APPLICATION_PUBLICATION_ENABLED,
                ENV_WASM_PUBLICATION_ENABLED,
            ],
        )
    }

    fn start(
        &self,
        wasm_record: Option<&str>,
        celld_record: Option<&str>,
        switches: &[&str],
    ) -> WasmRuntime {
        let wasm_record = wasm_record.map(str::as_bytes).map(Vec::from);
        let celld_record = celld_record.map(str::as_bytes).map(Vec::from);
        WasmRuntime::startup(
            self.paths(),
            &|path: &str| {
                if path == WASM_ACCEPTANCE_FILE {
                    wasm_record
                        .clone()
                        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
                } else if path == CELLD_ACCEPTANCE_FILE {
                    celld_record
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn vector_binding() -> RuntimeBindingIdentityV1 {
    RuntimeBindingIdentityV1 {
        kind: "wasm".into(),
        catalog_revision: 9,
        catalog_hash: "ab".repeat(32),
        entry_key: "iweb-wasmd".into(),
        image_digest: format!("sha256:{}", "cd".repeat(32)),
        host_abi: WASM_HOST_ABI_LITERAL.into(),
        world: WASM_WORLD_LITERAL.into(),
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// admission 提交 body（binding/capability pin 可覆写——身份绑定负例的注入点）。
fn admission_body_with_binding(
    application: &str,
    binding: Value,
    capability_revision: u64,
    capability_hash: &str,
) -> Vec<u8> {
    json!({
        "schemaVersion": 1,
        "applicationId": application,
        "packageDigest": SPEC_VECTOR_PACKAGE_DIGEST,
        "normalizedPolicy": serde_json::from_str::<Value>(SPEC_VECTOR_MANIFEST).expect("manifest"),
        "runtimeBinding": binding,
        "capabilityRecordRevision": capability_revision,
        "capabilityRecordHash": capability_hash,
        "stagingTtlSeconds": 600,
        "blobs": [{ "digestHex": sha256_hex(b"wasm-component-bytes"), "base64": b64(b"wasm-component-bytes") }],
        "allowResequence": false,
    })
    .to_string()
    .into_bytes()
}

fn admission_body(application: &str) -> Vec<u8> {
    admission_body_with_binding(
        application,
        serde_json::to_value(vector_binding()).expect("binding"),
        5,
        &"2".repeat(64),
    )
}

fn parse_body(body: &str) -> Value {
    serde_json::from_str(body.trim()).expect("response body is JSON")
}

fn submit_admission_body(runtime: &mut WasmRuntime, body: &[u8]) -> (u16, Value) {
    let response =
        runtime.handle_admission_submit(true, Some("application/json"), body, 1_800_000_000_000);
    let parsed = parse_body(&response.body);
    (response.status, parsed)
}

fn submit_admission(runtime: &mut WasmRuntime, application: &str) -> (u16, Value) {
    submit_admission_body(runtime, &admission_body(application))
}

// ---------------------------------------------------------------------------
// 激活链辅助（drain 命令是本批次投递闭环的生产触发点）
// ---------------------------------------------------------------------------

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

fn seed_fence(fixture: &Fixture, application: &str, current_version_id: &str, records: Value) {
    let file = json!({
        "schemaVersion": 1,
        "runtimeKind": "wasm",
        "applications": { application: { "currentVersionId": current_version_id, "records": records } },
    });
    let bytes = jcs_bytes(&file).expect("fence jcs");
    std::fs::write(fixture.paths().root.join("wasm-fences.json"), bytes).expect("write fences");
}

fn build_lease(candidate: &ActivationCandidateV1, nonce: &str) -> ReadinessLeaseV2 {
    let now = iweb_kernel::monitor::now_millis() as u64;
    let base = ReadinessLeaseV2 {
        schema_version: 2,
        lease_nonce: nonce.to_string(),
        sandbox_id: candidate.sandbox_id.clone(),
        version_id: candidate.version_id.clone(),
        package_digest: candidate.package_digest.clone(),
        runtime_binding: candidate.runtime_binding.clone(),
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
    let digest = compute_readiness_lease_digest(&base).expect("lease digest");
    ReadinessLeaseV2 {
        lease_digest: digest,
        ..base
    }
}

fn seed_lease(fixture: &Fixture, lease: &ReadinessLeaseV2) {
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
) -> ActivationCandidateV1 {
    ActivationCandidateV1 {
        runtime_kind: "wasm".into(),
        sandbox_id: sandbox_id.into(),
        version_id: version_id.into(),
        package_digest: SPEC_VECTOR_PACKAGE_DIGEST.into(),
        runtime_binding: vector_binding(),
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
        lease_digest: String::new(),
    }
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

fn activation_envelope(
    activation_id: &str,
    expected_route_generation: u64,
    candidate: ActivationCandidateV1,
) -> Vec<u8> {
    let command = WireActivationCommandV1 {
        schema_version: 1,
        activation_id: activation_id.into(),
        application_id: "vector".into(),
        operation: ActivationOperation::Activate,
        expected_route_generation,
        candidate,
        requested_at: iweb_kernel::wasm_admission::format_rfc3339_utc_millis(
            iweb_kernel::monitor::now_millis() as u64,
        ),
    };
    let envelope = json!({
        "protocol": ACTIVATION_RPC_PROTOCOL_LITERAL,
        "requestId": generate_uuid_v7(iweb_kernel::monitor::now_millis() as u64),
        "body": serde_json::to_value(&command).expect("command value"),
    });
    jcs_bytes(&envelope).expect("envelope jcs")
}

/// 走完 准入→激活替换，制造一条 pending 的 drain 命令（生产投递触发点）。
/// 返回 (v1, v2, drain_command_id)。
fn drive_to_replacement(fixture: &Fixture, runtime: &mut WasmRuntime) -> (String, String, String) {
    let (_, body) = submit_admission(runtime, "vector");
    let v1: String = body["versionId"].as_str().expect("versionId").to_string();
    let rows = runtime.project_registry_rows();
    let proof_digest_v1: String = rows["vector"][0]
        .admission_proof_digest
        .as_str()
        .to_string();
    let nonce_v1 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    let candidate_v1 = build_candidate(&v1, &proof_digest_v1, "sbx-vector", 1, nonce_v1);
    let drain_deadline = iweb_kernel::monitor::now_millis() as u64 + 300_000;
    seed_fence(
        fixture,
        "vector",
        &v1,
        json!({ v1.clone(): fence_record(&v1, "sbx-vector", 1, "ready", Some(drain_deadline)).1 }),
    );
    let lease_v1 = build_lease(&candidate_v1, nonce_v1);
    seed_lease(fixture, &lease_v1);
    let candidate_v1 = ActivationCandidateV1 {
        lease_digest: lease_v1.lease_digest.clone(),
        ..candidate_v1
    };
    let (status, body) = call_activation(
        runtime,
        &activation_envelope(&generate_uuid_v7(1_800_000_001_000), 0, candidate_v1),
    );
    assert_eq!(status, 200, "first activation: {body}");
    assert_eq!(body["body"]["status"], json!("activated"));

    let (_, body) = submit_admission_body(runtime, &{ json_admission_body_respec() });
    let v2: String = body["versionId"].as_str().expect("versionId").to_string();
    assert_eq!(v2, format!("{SPEC_VECTOR_VERSION_DIGEST}-2"));
    let rows = runtime.project_registry_rows();
    let proof_digest_v2: String = rows["vector"][1]
        .admission_proof_digest
        .as_str()
        .to_string();
    let nonce_v2 = "11223344556677889900aabbccddeeff";
    let candidate_v2 = build_candidate(&v2, &proof_digest_v2, "sbx-vector2", 2, nonce_v2);
    let mut records = serde_json::Map::new();
    records.insert(
        v1.clone(),
        fence_record(&v1, "sbx-vector", 1, "ready", Some(drain_deadline)).1,
    );
    records.insert(
        v2.clone(),
        fence_record(&v2, "sbx-vector2", 2, "ready", Some(drain_deadline)).1,
    );
    seed_fence(fixture, "vector", &v2, Value::Object(records));
    let lease_v2 = build_lease(&candidate_v2, nonce_v2);
    seed_lease(fixture, &lease_v2);
    let candidate_v2 = ActivationCandidateV1 {
        lease_digest: lease_v2.lease_digest.clone(),
        ..candidate_v2
    };
    let (status, body) = call_activation(
        runtime,
        &activation_envelope(&generate_uuid_v7(1_800_000_004_000), 1, candidate_v2),
    );
    assert_eq!(status, 200, "replacement activation: {body}");
    assert_eq!(body["body"]["status"], json!("activated"));
    let retirements = runtime.retiring_records();
    assert_eq!(
        retirements.len(),
        1,
        "one drain command is pending delivery"
    );
    (v1, v2, retirements[0].drain_command_id.clone())
}

fn json_admission_body_respec() -> Vec<u8> {
    json!({
        "schemaVersion": 1,
        "applicationId": "vector",
        "packageDigest": SPEC_VECTOR_PACKAGE_DIGEST,
        "normalizedPolicy": serde_json::from_str::<Value>(SPEC_VECTOR_MANIFEST).expect("manifest"),
        "runtimeBinding": serde_json::to_value(vector_binding()).expect("binding"),
        "capabilityRecordRevision": 5,
        "capabilityRecordHash": "2".repeat(64),
        "stagingTtlSeconds": 600,
        "blobs": [{ "digestHex": sha256_hex(b"wasm-component-bytes"), "base64": b64(b"wasm-component-bytes") }],
        "allowResequence": true,
    })
    .to_string()
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Fake supervisor：真实 UDS 上的 /v1/execution-rpc 最小应答者
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum FakeMode {
    Normal,
    /// journal 落盘 completion 后丢弃连接（response lost；命令已执行）。
    DropAfterCommit,
    /// 新命令一律 JOURNAL_REVISION_CONFLICT（Kernel 提示过期 → 留待重试）。
    AlwaysJournalConflict,
    /// ack 回显错误的 packageDigest（Kernel echo 校验必须拒绝投影）。
    TamperAckPackage,
}

struct FakeJournal {
    head: u64,
    /// commandId -> (commandDigest, journalRevision, command)。
    received: std::collections::HashMap<String, (String, u64, Value)>,
    completed: std::collections::HashMap<String, Value>,
}

struct FakeSupervisor {
    socket_path: PathBuf,
    journal: Arc<Mutex<FakeJournal>>,
    mode: Arc<Mutex<FakeMode>>,
    executions: Arc<AtomicUsize>,
}

impl FakeSupervisor {
    fn start(label: &str) -> Self {
        // macOS sun_path 上限 104 字节：socket 用 temp_dir 下的扁平短名
        //（label 只进 panic 诊断，不进路径）。
        let _ = label;
        let socket_path = std::env::temp_dir().join(format!(
            "iweb-fs-{}-{}.sock",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&socket_path);
        let supervisor = Self {
            socket_path: socket_path.clone(),
            journal: Arc::new(Mutex::new(FakeJournal {
                head: 0,
                received: std::collections::HashMap::new(),
                completed: std::collections::HashMap::new(),
            })),
            mode: Arc::new(Mutex::new(FakeMode::Normal)),
            executions: Arc::new(AtomicUsize::new(0)),
        };
        let journal = supervisor.journal.clone();
        let mode = supervisor.mode.clone();
        let executions = supervisor.executions.clone();
        let bind_path = socket_path.clone();
        std::thread::spawn(move || {
            let listener = match std::os::unix::net::UnixListener::bind(&bind_path) {
                Ok(listener) => listener,
                Err(_) => return,
            };
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let journal = journal.clone();
                let mode = mode.clone();
                let executions = executions.clone();
                std::thread::spawn(move || {
                    serve_execution_rpc(&mut stream, &journal, &mode, &executions);
                });
            }
        });
        // bind 完成哨兵：socket inode 出现后才允许客户端连接（避免启动竞态）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !socket_path.exists() {
            if std::time::Instant::now() > deadline {
                panic!("fake supervisor socket never appeared");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        supervisor
    }

    fn set_mode(&self, mode: FakeMode) {
        *self.mode.lock().expect("mode lock") = mode;
    }

    fn execution_count(&self) -> usize {
        self.executions.load(Ordering::SeqCst)
    }

    fn delivered_command(&self, command_id: &str) -> Value {
        self.journal
            .lock()
            .expect("journal lock")
            .received
            .get(command_id)
            .unwrap_or_else(|| panic!("missing delivered command {command_id}"))
            .2
            .clone()
    }

    fn socket(&self) -> &str {
        self.socket_path.to_str().expect("socket path")
    }
}

impl Drop for FakeSupervisor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn serve_execution_rpc(
    stream: &mut std::os::unix::net::UnixStream,
    journal: &Arc<Mutex<FakeJournal>>,
    mode: &Arc<Mutex<FakeMode>>,
    executions: &Arc<AtomicUsize>,
) {
    use std::io::Read as _;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    // 读到 header 结束 + content-length body。
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&buffer[..position]).to_ascii_lowercase();
            let length = header
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= position + 4 + length {
                break position + 4;
            }
        }
    };
    let request: Value = match serde_json::from_slice(&buffer[header_end..]) {
        Ok(value) => value,
        Err(_) => {
            let _ = write_response(
                stream,
                400,
                r#"{"ok":false,"code":"INVALID_JSON","message":"bad body"}"#,
            );
            return;
        }
    };
    let request_id = request["requestId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let body = &request["body"];
    let mode_now = *mode.lock().expect("mode lock");
    match body["kind"].as_str() {
        Some("query") => {
            let command_id = body["commandId"].as_str().unwrap_or_default().to_string();
            let journal = journal.lock().expect("journal lock");
            let payload = if !journal.completed.contains_key(&command_id)
                && !journal.received.contains_key(&command_id)
            {
                json!({ "kind": "query-result", "commandId": command_id, "status": "missing", "received": null, "acknowledgement": null })
            } else if let Some(ack) = journal.completed.get(&command_id) {
                json!({ "kind": "query-result", "commandId": command_id, "status": "completed", "received": received_view(&journal, &command_id), "acknowledgement": ack })
            } else {
                json!({ "kind": "query-result", "commandId": command_id, "status": "received", "received": received_view(&journal, &command_id), "acknowledgement": null })
            };
            let response = json!({ "protocol": "iweb-execution-rpc-v1", "requestId": request_id, "body": payload });
            let _ = write_ok(stream, &response.to_string());
        }
        Some("command") | Some("replay") => {
            let command = body["command"].clone();
            let command_id = command["commandId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let digest = iweb_kernel::wasm_commands::execution_command_digest_v1(
                &serde_json::from_value(command.clone()).expect("command parses"),
            )
            .expect("digest");
            let mut journal = journal.lock().expect("journal lock");
            if let Some(ack) = journal.completed.get(&command_id).cloned() {
                let stored_digest = journal
                    .received
                    .get(&command_id)
                    .map(|(digest, _, _)| digest.clone())
                    .unwrap_or_default();
                if stored_digest != digest {
                    let _ = write_response(
                        stream,
                        409,
                        r#"{"ok":false,"code":"EXECUTION_COMMAND_ID_CONFLICT","message":"differing body"}"#,
                    );
                    return;
                }
                let response = json!({ "protocol": "iweb-execution-rpc-v1", "requestId": request_id, "body": { "kind": "acknowledgement", "acknowledgement": ack } });
                let _ = write_ok(stream, &response.to_string());
                return;
            }
            if let Some((stored_digest, _, _)) = journal.received.get(&command_id).cloned() {
                if stored_digest != digest {
                    let _ = write_response(
                        stream,
                        409,
                        r#"{"ok":false,"code":"EXECUTION_COMMAND_ID_CONFLICT","message":"differing body"}"#,
                    );
                    return;
                }
                // received-incomplete → resume（执行副作用恰好一次）。
                if complete_command(
                    &mut journal,
                    &command,
                    &command_id,
                    &digest,
                    mode_now,
                    executions,
                ) {
                    let ack = journal
                        .completed
                        .get(&command_id)
                        .cloned()
                        .expect("just completed");
                    if mode_now == FakeMode::DropAfterCommit {
                        return; // response lost：completion 已落盘，连接直接丢弃。
                    }
                    let response = json!({ "protocol": "iweb-execution-rpc-v1", "requestId": request_id, "body": { "kind": "acknowledgement", "acknowledgement": ack } });
                    let _ = write_ok(stream, &response.to_string());
                }
                return;
            }
            if body["kind"] == "replay" {
                let _ = write_response(
                    stream,
                    404,
                    r#"{"ok":false,"code":"EXECUTION_COMMAND_UNKNOWN","message":"replay requires a received command"}"#,
                );
                return;
            }
            if mode_now == FakeMode::AlwaysJournalConflict
                || command["expectedJournalRevision"].as_u64() != Some(journal.head)
            {
                let _ = write_response(
                    stream,
                    409,
                    r#"{"ok":false,"code":"JOURNAL_REVISION_CONFLICT","message":"head mismatch"}"#,
                );
                return;
            }
            journal.head += 1;
            let received_revision = journal.head;
            journal.received.insert(
                command_id.clone(),
                (digest.clone(), received_revision, command.clone()),
            );
            if complete_command(
                &mut journal,
                &command,
                &command_id,
                &digest,
                mode_now,
                executions,
            ) {
                let ack = journal
                    .completed
                    .get(&command_id)
                    .cloned()
                    .expect("just completed");
                if mode_now == FakeMode::DropAfterCommit {
                    return;
                }
                let response = json!({ "protocol": "iweb-execution-rpc-v1", "requestId": request_id, "body": { "kind": "acknowledgement", "acknowledgement": ack } });
                let _ = write_ok(stream, &response.to_string());
            }
        }
        _ => {
            let _ = write_response(
                stream,
                400,
                r#"{"ok":false,"code":"EXECUTION_RPC_ENVELOPE_INVALID","message":"bad kind"}"#,
            );
        }
    }
}

fn received_view(journal: &FakeJournal, command_id: &str) -> Value {
    // CommandReceivedV1 精确键集（Kernel 侧 parse_command_query_result +
    // journal_observation_from_query 复算 digest 并比对命令字节）。
    let Some((digest, revision, command)) = journal.received.get(command_id) else {
        return Value::Null;
    };
    json!({
        "kind": "command-received",
        "commandId": command_id,
        "commandDigest": digest,
        "command": command,
        "snapshotHandoffDigest": Value::Null,
        "receivedAt": "2026-08-27T00:00:00.000Z",
        "journalRevision": revision,
    })
}

/// 模拟执行副作用 + completion CAS；返回是否落盘成功。
fn complete_command(
    journal: &mut FakeJournal,
    command: &Value,
    command_id: &str,
    digest: &str,
    mode: FakeMode,
    executions: &Arc<AtomicUsize>,
) -> bool {
    executions.fetch_add(1, Ordering::SeqCst);
    journal.head += 1;
    let mut ack = json!({
        "schemaVersion": 1,
        "commandId": command_id,
        "operation": command["operation"],
        "identity": command["identity"],
        "packageDigest": command["packageDigest"],
        "runtimeBinding": command["runtimeBinding"],
        "capabilityRecordRevision": command["capabilityRecordRevision"],
        "capabilityRecordHash": command["capabilityRecordHash"],
        "secretRevision": command["secretRevision"],
        "secretSnapshotRef": command["secretSnapshotRef"],
        "secretValuesDigest": command["secretValuesDigest"],
        "configRevision": command["configRevision"],
        "configSnapshotRef": command["configSnapshotRef"],
        "configValuesDigest": command["configValuesDigest"],
        "drainReceiptDigest": if command["operation"] == "drain" { json!("9".repeat(64)) } else { Value::Null },
        "result": "applied",
        "failureCode": Value::Null,
        "journalRevision": journal.head,
    });
    if mode == FakeMode::TamperAckPackage {
        ack["packageDigest"] = json!("1".repeat(64));
    }
    let _ = digest;
    journal.completed.insert(command_id.to_string(), ack);
    true
}

fn write_ok(stream: &mut std::os::unix::net::UnixStream, body: &str) -> std::io::Result<()> {
    write_response(stream, 200, body)
}

fn write_response(
    stream: &mut std::os::unix::net::UnixStream,
    status: u16,
    body: &str,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let head = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// P0-1 投递闭环
// ---------------------------------------------------------------------------

fn outbox_state(runtime: &WasmRuntime, command_id: &str) -> OutboxDeliveryState {
    let projection = runtime
        .control_state_projection()
        .expect("control state projects");
    let entry = projection
        .command_outbox
        .iter()
        .find(|entry| entry.command_id == command_id)
        .unwrap_or_else(|| panic!("outbox entry {command_id}"));
    entry.delivery_state
}

/// The production transport rejects every non-canonical socket path. This
/// integration-only client is passed through the explicit runtime test seam so
/// the fake supervisor can live under a short temporary UDS path on macOS.
fn test_execution_rpc_transport(
    socket_path: &str,
    request_body: &[u8],
    timeout_ms: u64,
) -> Option<(u16, Vec<u8>)> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut stream = UnixStream::connect(socket_path).ok()?;
    let timeout = Duration::from_millis(timeout_ms);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let request = format!(
        "POST /v1/execution-rpc HTTP/1.1\r\nHost: test-supervisor\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request_body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    stream.write_all(request_body).ok()?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&chunk[..read]);
                if response.len() > 64 * 1024 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        + 4;
    let status = std::str::from_utf8(&response[..header_end])
        .ok()?
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, response[header_end..].to_vec()))
}

fn deliver_to_fake(
    runtime: &mut WasmRuntime,
    supervisor: &FakeSupervisor,
) -> iweb_kernel::wasm_runtime::WasmDeliveryReport {
    runtime.deliver_pending_execution_commands_with_transport(
        Some(supervisor.socket()),
        iweb_kernel::monitor::now_millis() as u64,
        test_execution_rpc_transport,
    )
}

#[derive(Debug, Clone, PartialEq)]
struct ObservedSnapshotHandoff {
    kind: SnapshotFrameKind,
    command_id: String,
    command_digest: String,
    reference: String,
    version_id: String,
    preparation_generation: u64,
    secret_revision: Option<u64>,
    config_revision: Option<u64>,
    values_digest: String,
    source_digest: String,
}

fn snapshot_handoff_log() -> &'static Mutex<Vec<ObservedSnapshotHandoff>> {
    static LOG: OnceLock<Mutex<Vec<ObservedSnapshotHandoff>>> = OnceLock::new();
    LOG.get_or_init(|| Mutex::new(Vec::new()))
}

fn clear_snapshot_handoff_log() {
    snapshot_handoff_log()
        .lock()
        .expect("snapshot handoff log")
        .clear();
}

fn test_snapshot_peer() -> Result<SnapshotSocketPeer, WasmControlFailure> {
    Ok(SnapshotSocketPeer {
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    })
}

/// Test-only relay stub: it observes the descriptor bytes without exposing
/// them, proves their digest binding, and emits the same accepted wire result
/// a real supervisor relay must return before execution RPC may proceed.
fn accept_snapshot_handoff(
    delivery: &SnapshotHandoffDelivery<'_>,
) -> Result<SnapshotDeliveryOutcome, SnapshotFdError> {
    let source = std::fs::read(delivery.snapshot_path).map_err(|error| {
        SnapshotFdError::new(
            "SNAPSHOT_TRANSPORT_IO",
            format!("the integration relay cannot read its fixture descriptor: {error}"),
        )
    })?;
    let (
        kind,
        command_id,
        command_digest,
        reference,
        version_id,
        preparation_generation,
        secret_revision,
        config_revision,
        values_digest,
    ) = match &delivery.handoff {
        SnapshotHandoffPayload::Secret(handoff) => (
            SnapshotFrameKind::SecretRequest,
            handoff.command_id.clone(),
            handoff.command_digest.clone(),
            handoff.reference.clone(),
            handoff.version_id.clone(),
            handoff.preparation_generation,
            Some(handoff.secret_revision),
            None,
            handoff.values_digest.clone(),
        ),
        SnapshotHandoffPayload::Config(handoff) => (
            SnapshotFrameKind::ConfigRequest,
            handoff.command_id.clone(),
            handoff.command_digest.clone(),
            handoff.reference.clone(),
            handoff.version_id.clone(),
            handoff.preparation_generation,
            None,
            Some(handoff.config_revision),
            handoff.values_digest.clone(),
        ),
    };
    let source_digest = compute_snapshot_fd_digest(kind, &source)?;
    if source_digest != values_digest {
        return Err(SnapshotFdError::new(
            "SNAPSHOT_VALUES_DIGEST_MISMATCH",
            "the integration relay observed descriptor bytes outside the command-bound values digest",
        ));
    }
    snapshot_handoff_log()
        .lock()
        .expect("snapshot handoff log")
        .push(ObservedSnapshotHandoff {
            kind,
            command_id: command_id.clone(),
            command_digest,
            reference,
            version_id,
            preparation_generation,
            secret_revision,
            config_revision,
            values_digest,
            source_digest,
        });
    Ok(SnapshotDeliveryOutcome::Accepted(SnapshotFdAckV1 {
        schema_version: 1,
        kind: "ack".into(),
        command_id,
        handoff_digest: compute_snapshot_handoff_digest(&delivery.handoff)?,
        status: SnapshotAckStatus::Accepted,
        failure_code: None,
        journal_revision: 0,
    }))
}

#[test]
fn admission_prepare_start_handoffs_bind_before_executor_delivery() {
    let fixture = Fixture::new("admission-prepare-start-handoff");
    let mut runtime = fixture.start_enabled();
    let supervisor = FakeSupervisor::start("admission-prepare-start-handoff");
    let (status, body) = submit_admission(&mut runtime, "vector");
    assert_eq!(status, 201, "admission: {body}");

    let control = runtime
        .control_state_projection()
        .expect("canonical control state after admission");
    let planned: Vec<_> = control
        .command_outbox
        .iter()
        .filter(|entry| {
            matches!(
                entry.command.operation(),
                iweb_kernel::wasm_commands::WasmExecutionOperation::Prepare
                    | iweb_kernel::wasm_commands::WasmExecutionOperation::Start
            )
        })
        .map(|entry| entry.command.clone())
        .collect();
    assert_eq!(planned.len(), 2, "admission plans Prepare then Start");
    assert_eq!(
        planned[0].operation(),
        iweb_kernel::wasm_commands::WasmExecutionOperation::Prepare
    );
    assert_eq!(
        planned[1].operation(),
        iweb_kernel::wasm_commands::WasmExecutionOperation::Start
    );

    clear_snapshot_handoff_log();
    let report = runtime.deliver_pending_execution_commands_with_transports(
        Some(supervisor.socket()),
        iweb_kernel::monitor::now_millis() as u64,
        test_execution_rpc_transport,
        test_snapshot_peer,
        accept_snapshot_handoff,
    );
    assert_eq!(report.delivered, 2, "failures: {:?}", report.failures);
    assert_eq!(report.projected, 2);
    assert_eq!(supervisor.execution_count(), 2);

    let handoffs = snapshot_handoff_log()
        .lock()
        .expect("snapshot handoff log")
        .clone();
    assert_eq!(handoffs.len(), 2, "one secret handoff per command");
    for (handoff, command) in handoffs.iter().zip(&planned) {
        assert_eq!(handoff.kind, SnapshotFrameKind::SecretRequest);
        assert_eq!(handoff.command_id, command.command_id());
        assert_eq!(
            handoff.command_digest,
            iweb_kernel::wasm_commands::execution_command_digest_versioned(command)
                .expect("command digest")
        );
        assert_eq!(handoff.reference, command.secret_snapshot_ref());
        assert_eq!(handoff.version_id, command.identity().version_id);
        assert_eq!(
            handoff.preparation_generation,
            command.identity().preparation_generation
        );
        assert_eq!(handoff.secret_revision, Some(command.secret_revision()));
        assert_eq!(handoff.config_revision, None);
        assert_eq!(handoff.values_digest, command.secret_values_digest());
        assert_eq!(handoff.source_digest, command.secret_values_digest());
        assert_eq!(
            supervisor.delivered_command(command.command_id()),
            serde_json::to_value(command).expect("command value"),
            "the executor receives the exact command whose descriptor relay was accepted"
        );
        assert_eq!(
            outbox_state(&runtime, command.command_id()),
            OutboxDeliveryState::Acknowledged
        );
    }
}

#[test]
fn delivery_loop_projects_ack_through_the_canonical_control_state() {
    let fixture = Fixture::new("delivery-happy");
    let mut runtime = fixture.start_enabled();
    let supervisor = FakeSupervisor::start("delivery-happy");
    let (_, _, drain_command_id) = drive_to_replacement(&fixture, &mut runtime);

    // 启动期的不可达生产 relay 已留下 advisory sent 尝试；规范控制态仍是 V2。
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Sent
    );
    let before_delivery = runtime
        .control_state_projection()
        .expect("control state before delivery")
        .control_revision;
    let raw = std::fs::read(fixture.paths().root.join("wasm-control-state-v2.json"))
        .expect("control state file");
    assert!(
        String::from_utf8_lossy(&raw).contains(r#""schemaVersion":2"#),
        "the canonical control state file exists in v2 shape"
    );
    assert!(String::from_utf8_lossy(&raw).contains(r#""status":"not-started""#));

    let report = deliver_to_fake(&mut runtime, &supervisor);
    assert_eq!(report.delivered, 1, "failures: {:?}", report.failures);
    assert_eq!(report.projected, 1);
    assert_eq!(
        supervisor.execution_count(),
        1,
        "exactly one execution side effect"
    );
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Acknowledged
    );
    let after_delivery = runtime
        .control_state_projection()
        .expect("control state after delivery")
        .control_revision;
    assert!(
        after_delivery > before_delivery,
        "delivery attempt and acknowledgement projection each persist a v2 CAS mutation"
    );

    // 再跑一轮：已确认的 drain 不会再执行。其它 sent outbox 仍可在本轮
    // retry，因此不把整个 outbox 的 attempt 数当作此命令的幂等性证据。
    let executions_after_delivery = supervisor.execution_count();
    let _report = deliver_to_fake(&mut runtime, &supervisor);
    assert_eq!(supervisor.execution_count(), executions_after_delivery);
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Acknowledged
    );
    assert!(
        runtime
            .control_state_projection()
            .expect("control state after idempotent retry")
            .control_revision
            >= after_delivery,
        "other retryable outbox entries may advance v2, but the acknowledged drain cannot regress it"
    );
}

#[test]
fn response_lost_delivery_converges_by_query_without_a_second_side_effect() {
    let fixture = Fixture::new("delivery-response-lost");
    let mut runtime = fixture.start_enabled();
    let supervisor = FakeSupervisor::start("delivery-response-lost");
    let (_, _, drain_command_id) = drive_to_replacement(&fixture, &mut runtime);

    // 第一轮：supervisor 完成命令但丢弃响应（response lost）。
    supervisor.set_mode(FakeMode::DropAfterCommit);
    let report = deliver_to_fake(&mut runtime, &supervisor);
    assert_eq!(
        report.projected, 0,
        "no ack may project from an uncertain response"
    );
    assert_eq!(
        supervisor.execution_count(),
        1,
        "the command executed exactly once"
    );
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Sent,
        "the entry stays advisory-sent"
    );

    // 第二轮（Normal）：query 发现 completed → 投影 CAS；无第二次执行。
    supervisor.set_mode(FakeMode::Normal);
    let report = deliver_to_fake(&mut runtime, &supervisor);
    assert_eq!(report.projected, 1, "failures: {:?}", report.failures);
    assert_eq!(
        report.delivered, 0,
        "no new delivery happens for a completed journal entry"
    );
    assert_eq!(supervisor.execution_count(), 1);
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Acknowledged
    );
}

#[test]
fn tampered_ack_echo_is_rejected_without_projection() {
    let fixture = Fixture::new("delivery-tampered-ack");
    let mut runtime = fixture.start_enabled();
    let supervisor = FakeSupervisor::start("delivery-tampered-ack");
    let (_, _, drain_command_id) = drive_to_replacement(&fixture, &mut runtime);

    supervisor.set_mode(FakeMode::TamperAckPackage);
    let report = deliver_to_fake(&mut runtime, &supervisor);
    assert_eq!(
        report.projected, 0,
        "an ack that fails the echo check never projects"
    );
    assert!(
        report
            .failures
            .iter()
            .any(|note| note.contains("PACKAGE_DIGEST_MISMATCH")),
        "failures: {:?}",
        report.failures
    );
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Sent
    );
    // 修复后重试：query 命中已存 completion（伪造 ack 已持久在 fake journal——换回
    // Normal 后 completion 里的 ack 仍是坏的；本例断言 Kernel 持续拒绝而非路由）。
    supervisor.set_mode(FakeMode::Normal);
    let report = deliver_to_fake(&mut runtime, &supervisor);
    assert_eq!(report.projected, 0);
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Sent
    );
}

#[test]
fn journal_revision_conflict_leaves_the_command_pending_for_retry() {
    let fixture = Fixture::new("delivery-journal-conflict");
    let mut runtime = fixture.start_enabled();
    let supervisor = FakeSupervisor::start("delivery-journal-conflict");
    let (_, _, drain_command_id) = drive_to_replacement(&fixture, &mut runtime);

    // Kernel 提示（0）与 supervisor head 不一致 → 409，命令留待重试（绝不 dead）。
    supervisor.set_mode(FakeMode::AlwaysJournalConflict);
    let report = deliver_to_fake(&mut runtime, &supervisor);
    assert_eq!(report.projected, 0);
    assert!(
        report
            .failures
            .iter()
            .any(|note| note.contains("JOURNAL_REVISION_CONFLICT")),
        "failures: {:?}",
        report.failures
    );
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Sent
    );
    // attempts 簿记已落盘（一次已提交 mutation）。
    let projection = runtime.control_state_projection().expect("projection");
    let entry = projection
        .command_outbox
        .iter()
        .find(|entry| entry.command_id == drain_command_id)
        .expect("entry");
    assert!(entry.attempts >= 1);
    assert!(entry.last_attempt_at.is_some());
}

#[test]
fn unreachable_supervisor_keeps_commands_pending_without_fencing_the_control_plane() {
    let fixture = Fixture::new("delivery-unreachable");
    let mut runtime = fixture.start_enabled();
    let (_, _, drain_command_id) = drive_to_replacement(&fixture, &mut runtime);
    // 无 socket（None）与不可达路径都不得影响 wasm 控制面可用性。
    let report =
        runtime.deliver_pending_execution_commands(None, iweb_kernel::monitor::now_millis() as u64);
    assert_eq!(report.attempted, 0);
    let report = runtime.deliver_pending_execution_commands(
        Some("/nonexistent/supervisor.sock"),
        iweb_kernel::monitor::now_millis() as u64,
    );
    assert_eq!(report.projected, 0);
    assert_eq!(
        outbox_state(&runtime, &drain_command_id),
        OutboxDeliveryState::Sent
    );
    // 提交/激活面仍然开放（wasm 控制态未被投递失败围栏）。
    let (status, _) = submit_admission_body(&mut runtime, &admission_body("vector"));
    assert_eq!(status, 201);
}

// ---------------------------------------------------------------------------
// P0-6 控制态迁移：schema-1 文件 → wasm-control-state-v2.json
// ---------------------------------------------------------------------------

#[test]
fn legacy_command_control_migrates_once_into_the_canonical_v2_shape() {
    let fixture = Fixture::new("control-migration");
    fixture.write_gate_pin();
    let legacy_outbox_count;
    // 预置 J 批次 schema-1 文件（controlRevision 7 + 全部现有 outbox + 一条 retiring）。
    {
        let mut runtime = fixture.start_enabled();
        let (_, _, _) = drive_to_replacement(&fixture, &mut runtime);
        let old = std::fs::read(fixture.paths().root.join("wasm-control-state-v2.json"))
            .expect("v2 written by wiring");
        // 人为改写回 schema-1 布局（模拟旧节点）：v2 文件移除，legacy 文件以 schema 1 落盘。
        let projection: Value = serde_json::from_slice(&old).expect("v2 json");
        legacy_outbox_count = projection["commandOutbox"]
            .as_array()
            .expect("fixture outbox")
            .len();
        let mut legacy = json!({
            "schemaVersion": 1,
            "runtimeKind": "wasm",
            "controlRevision": 7,
            "command_outbox": projection["commandOutbox"],
            "retirements": Value::Array(Vec::new()),
        });
        // 借用 wiring 的 retiring 记录（从业务文件取）。
        let retirements = runtime.retiring_records();
        let retirements_value: Vec<Value> = retirements
            .iter()
            .map(|record| serde_json::to_value(record).expect("retiring value"))
            .collect();
        legacy["retirements"] = Value::Array(retirements_value);
        std::fs::remove_file(fixture.paths().root.join("wasm-control-state-v2.json"))
            .expect("remove v2");
        let legacy_bytes = jcs_bytes(&legacy).expect("legacy jcs");
        std::fs::write(
            fixture.paths().root.join("wasm-command-control.json"),
            legacy_bytes,
        )
        .expect("write legacy");
    }
    // 重启：一次性迁移物化 V2（carry controlRevision/outbox/retirements；not-started）。
    let runtime = fixture.start_enabled();
    let raw = std::fs::read(fixture.paths().root.join("wasm-control-state-v2.json"))
        .expect("v2 materialized");
    let parsed: Value = serde_json::from_slice(&raw).expect("v2 json");
    assert_eq!(parsed["schemaVersion"], json!(2));
    let first_revision = parsed["controlRevision"]
        .as_u64()
        .expect("v2 control revision");
    assert!(first_revision >= 7, "the legacy revision is retained and startup delivery attempts advance it through the same v2 CAS");
    assert_eq!(parsed["migration"]["status"], json!("not-started"));
    assert_eq!(
        parsed["commandOutbox"].as_array().expect("outbox").len(),
        legacy_outbox_count,
        "migration retains every pre-existing command rather than deriving an outbox from a registry projection"
    );
    assert_eq!(
        runtime.retiring_records().len(),
        1,
        "retirements carried into the business file"
    );
    // 旧文件保留（审计；不再读出）。
    assert!(fixture
        .paths()
        .root
        .join("wasm-command-control.json")
        .is_file());
    // 再重启：V2 已存在，legacy 不再被读；unreachable outbox retries may
    // advance the canonical revision, but it may never regress or re-migrate.
    let runtime = fixture.start_enabled();
    let parsed: Value = serde_json::from_slice(
        &std::fs::read(fixture.paths().root.join("wasm-control-state-v2.json"))
            .expect("v2 persists"),
    )
    .expect("v2 json");
    assert!(
        parsed["controlRevision"]
            .as_u64()
            .expect("second v2 revision")
            >= first_revision,
        "restarts preserve monotonic v2 controlRevision"
    );
    assert_eq!(runtime.retiring_records().len(), 1);
}

// ---------------------------------------------------------------------------
// P0-4 准入身份绑定负例
// ---------------------------------------------------------------------------

#[test]
fn admission_identity_binding_mismatches_fail_closed_field_by_field() {
    let fixture = Fixture::new("identity-binding");
    let mut runtime = fixture.start_enabled();

    let cases: [(&str, Value, u64, String); 4] = [
        (
            "catalogRevision",
            {
                let mut binding = serde_json::to_value(vector_binding()).expect("binding");
                binding["catalogRevision"] = json!(10);
                binding
            },
            5,
            "2".repeat(64),
        ),
        (
            "catalogHash",
            {
                let mut binding = serde_json::to_value(vector_binding()).expect("binding");
                binding["catalogHash"] = json!("ba".repeat(32));
                binding
            },
            5,
            "2".repeat(64),
        ),
        (
            "entryKey",
            {
                let mut binding = serde_json::to_value(vector_binding()).expect("binding");
                binding["entryKey"] = json!("other-wasmd");
                binding
            },
            5,
            "2".repeat(64),
        ),
        (
            "capabilityRecordHash",
            serde_json::to_value(vector_binding()).expect("binding"),
            6,
            "3".repeat(64),
        ),
    ];
    for (label, binding, capability_revision, capability_hash) in cases {
        let (status, body) = submit_admission_body(
            &mut runtime,
            &admission_body_with_binding("vector", binding, capability_revision, &capability_hash),
        );
        assert_eq!(status, 400, "[{label}] body: {body}");
        assert_eq!(
            body["code"],
            json!(iweb_kernel::wasm_runtime::WASM_ADMISSION_NODE_PIN_MISMATCH),
            "[{label}] code"
        );
        assert!(
            body["message"].as_str().expect("message").contains(label),
            "[{label}] the mismatching field is named: {body}"
        );
    }
    // 全部拒绝后零注册（无 proof/kind claim/sequence 泄漏）。
    assert!(runtime.project_registry_rows().is_empty());
    // 无 pin 文件的节点：fail-closed（结构化拒绝，绝不推断默认 pin）。
    let no_pin = Fixture::new("identity-no-pin");
    let mut runtime = no_pin.start(
        Some(GOLDEN_WASM_ACCEPTANCE_JCS),
        Some(CELLD_V1_ACCEPTANCE),
        &[
            ENV_APPLICATION_PUBLICATION_ENABLED,
            ENV_WASM_PUBLICATION_ENABLED,
        ],
    );
    let (status, body) = submit_admission(&mut runtime, "vector");
    assert_eq!(
        status, 503,
        "the gate itself closes first when the pin is missing: {body}"
    );
}

// ---------------------------------------------------------------------------
// P0-5 跨存储恢复窗口：三段写入崩溃矩阵
// ---------------------------------------------------------------------------

/// 复制 witness 四件套（journal/objects/db/receipts）到目标 fixture。
fn copy_witness_stages(from: &Fixture, to: &Fixture, stages: &[&str]) {
    for stage in stages {
        let source = from.paths().root.join(stage);
        let target = to.paths().root.join(stage);
        if source.is_dir() {
            copy_dir(&source, &target);
        } else if source.is_file() {
            std::fs::create_dir_all(target.parent().expect("parent")).expect("parent dir");
            std::fs::copy(&source, &target).expect("copy stage");
        }
    }
}

fn copy_dir(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).expect("target dir");
    for entry in std::fs::read_dir(source).expect("read dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy_dir(&path, &target.join(entry.file_name()));
        } else {
            std::fs::copy(&path, target.join(entry.file_name())).expect("copy file");
        }
    }
}

#[test]
fn three_stage_write_crash_matrix_converges_from_every_intermediate_state() {
    let source = Fixture::new("crash-source");
    {
        let mut runtime = source.start_enabled();
        let (status, _) = submit_admission(&mut runtime, "vector");
        assert_eq!(status, 201);
    }
    let version_id = format!("{SPEC_VECTOR_VERSION_DIGEST}-1");

    // (a) 崩溃在 witness 之后、kind registry 之前：只有 admission 四件套。
    let stage_a = Fixture::new("crash-stage-a");
    stage_a.write_gate_pin();
    copy_witness_stages(
        &source,
        &stage_a,
        &[
            "admission-journal.jsonl",
            "admission-objects",
            "admission-db.json",
            "admission-receipts.json",
        ],
    );
    let runtime = stage_a.start_enabled();
    let rows = runtime.project_registry_rows();
    assert_eq!(
        rows["vector"].len(),
        1,
        "startup back-fills the route registry from the admission db"
    );
    assert_eq!(rows["vector"][0].version_id, version_id);
    assert!(
        stage_a
            .paths()
            .root
            .join("kind-registry/index.json")
            .is_file(),
        "the kind claim is registered"
    );
    assert!(runtime
        .admitted_visible("vector", &version_id)
        .expect("witness check")
        .is_some());

    // (b) 崩溃在 kind registry 之后、route registry 之前：witness + kind-registry。
    let stage_b = Fixture::new("crash-stage-b");
    stage_b.write_gate_pin();
    copy_witness_stages(
        &source,
        &stage_b,
        &[
            "admission-journal.jsonl",
            "admission-objects",
            "admission-db.json",
            "admission-receipts.json",
            "kind-registry",
        ],
    );
    let runtime = stage_b.start_enabled();
    let rows = runtime.project_registry_rows();
    assert_eq!(
        rows["vector"].len(),
        1,
        "converges without duplicating the kind claim"
    );

    // (c) 完整状态重启：幂等（不产生第二行/claim）。
    let runtime = stage_b.start_enabled();
    assert_eq!(runtime.project_registry_rows()["vector"].len(), 1);

    // (d) join 重试补写：route registry 写入失败后，created=false 的重试仍完成业务记录。
    let stage_d = Fixture::new("crash-stage-d");
    let mut runtime = stage_d.start_enabled();
    let (status, _) = submit_admission(&mut runtime, "vector");
    assert_eq!(status, 201);
    // 模拟「commit 成功、route registry 保存失败」：删除业务文件后重试同一请求。
    std::fs::remove_file(stage_d.paths().root.join("wasm-route-registry.json"))
        .expect("drop the business record");
    let (status, body) = submit_admission(&mut runtime, "vector");
    assert_eq!(status, 201, "retry joins the committed witness: {body}");
    assert_eq!(body["created"], json!(false));
    let rows = runtime.project_registry_rows();
    assert_eq!(
        rows["vector"].len(),
        1,
        "created=false does not skip the back-fill"
    );
    // 重启后同样收敛（journal visible + registry 行一致）。
    let runtime = stage_d.start_enabled();
    assert_eq!(runtime.project_registry_rows()["vector"].len(), 1);
}

// ---------------------------------------------------------------------------
// P0-1 ingress：Sandbox 路由代理（真实 UDS 网关应答者）
// ---------------------------------------------------------------------------

fn metrics() -> iweb_kernel::metrics::AppMetrics {
    iweb_kernel::metrics::AppMetrics::default()
}

fn sandbox_target(
    app_name: &str,
    sandbox_id: &str,
    app_base_path: Option<String>,
) -> iweb_kernel::proxy::SandboxTarget {
    iweb_kernel::proxy::SandboxTarget {
        sandbox_id: sandbox_id.into(),
        app_name: app_name.into(),
        app_base_path,
        metrics: metrics(),
    }
}

fn request_headers(host: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "host",
        axum::http::HeaderValue::from_str(host).expect("host"),
    );
    headers.insert(
        "content-type",
        axum::http::HeaderValue::from_static("text/plain"),
    );
    headers
}

#[tokio::test]
async fn sandbox_ingress_proxy_relays_requests_and_rewrites_the_header_contract() {
    let dir = std::env::temp_dir().join(format!(
        "iweb-sbx-proxy-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sbx-one")).expect("sandbox dir");
    let socket_path = dir.join("sbx-one").join("ingress.sock");
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    {
        let captured = captured.clone();
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind gateway");
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 2048];
            loop {
                let n = socket.read(&mut chunk).await.expect("read");
                if n == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    let length = String::from_utf8_lossy(&buffer[..position])
                        .lines()
                        .find_map(|line| {
                            let lower = line.to_ascii_lowercase();
                            lower.strip_prefix("content-length:").map(str::to_string)
                        })
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buffer.len() >= position + 4 + length {
                        break;
                    }
                }
            }
            *captured.lock().expect("capture") = buffer.clone();
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}".to_string();
            socket.write_all(response.as_bytes()).await.expect("write");
        });
    }
    let response = iweb_kernel::proxy::sandbox_forward_to(
        &socket_path,
        axum::http::Method::POST,
        "/handle?x=1",
        &request_headers("vector.app.iweb.test"),
        axum::body::Bytes::from_static(b"payload"),
        &sandbox_target("vector", "sbx-one", Some("/vector/app/".into())),
        "iweb.test",
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body");
    assert_eq!(&body[..], b"{\"ok\":true}");
    // 头部契约：host 重写 + original-host + app-base；connection 剥离。
    let captured = String::from_utf8(captured.lock().expect("capture").clone()).expect("utf8");
    assert!(captured.contains("POST /handle?x=1 HTTP/1.1\r\n"));
    assert!(captured.contains("host: vector.app.iweb.test\r\n"));
    assert!(captured.contains("x-iweb-original-host: vector.app.iweb.test\r\n"));
    assert!(captured.contains("x-iweb-app-base: /vector/app/\r\n"));
    assert!(captured.contains("content-length: 7\r\n"));
    assert!(!captured.contains("connection:\r\nignore") && !captured.starts_with("connection"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn sandbox_ingress_failures_are_generic_502_unavailable() {
    // (a) socket 缺失（沙箱未运行/已停止）→ 泛化 502。
    let response = iweb_kernel::proxy::sandbox_forward_to(
        std::path::Path::new("/nonexistent/gw/sbx-gone/ingress.sock"),
        axum::http::Method::GET,
        "/",
        &request_headers("vector.app.iweb.test"),
        axum::body::Bytes::new(),
        &sandbox_target("vector", "sbx-gone", None),
        "iweb.test",
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("json")["error"],
        json!("application unavailable")
    );

    // (b) 非法 sandboxId（路径逃逸尝试）→ 不连 socket，直接泛化 502。
    assert!(iweb_kernel::proxy::sandbox_ingress_socket("../escape").is_none());
    assert!(iweb_kernel::proxy::sandbox_ingress_socket("with/slash").is_none());
    assert!(iweb_kernel::proxy::sandbox_ingress_socket("").is_none());
    assert!(iweb_kernel::proxy::sandbox_ingress_socket("sbx-ok").is_some());

    // (c) 升级请求 → 泛化 502（单请求 HTTP-only ingress 无隧道语义）。
    let mut headers = request_headers("vector.app.iweb.test");
    headers.insert(
        "connection",
        axum::http::HeaderValue::from_static("upgrade"),
    );
    headers.insert("upgrade", axum::http::HeaderValue::from_static("websocket"));
    let response = iweb_kernel::proxy::sandbox_forward_to(
        std::path::Path::new("/nonexistent/gw/sbx-one/ingress.sock"),
        axum::http::Method::GET,
        "/",
        &headers,
        axum::body::Bytes::new(),
        &sandbox_target("vector", "sbx-one", None),
        "iweb.test",
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("json")["error"],
        json!("application unavailable")
    );
}
