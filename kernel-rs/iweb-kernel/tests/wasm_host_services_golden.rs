//! add-wasm-host-services 任务 7.5（跨实现 golden）：TS contracts
//! （packages/contracts/wasm-host-{policy,kv,sql,logging}.ts）与 Rust 数据面权威层
//! 的共享语义向量互锁。本文件是 Kernel 侧消费者，吃与 bun 侧
//! tests/wasm-host-services-golden.test.ts 同一份 fixture：
//! tests/fixtures/wasm/host-services-golden-vectors.json（值由 TS 侧现算生成钉死）。
//! 覆盖 Kernel 模块拥有的语义：digestV2 原语（ASCII domain || 0x00 || payload，
//! 绝不 hex 二次摘要）、16 个 V2 hash domain 闭表、quota reservation proof
//! （state 归一 "reserved"、proof 字段省略）；正/负向量双向各至少一组。

use iweb_kernel::wasm_host_services::{
    compute_reservation_proof_digest, digest_v2, verify_reservation_proof, QuotaBackend,
    QuotaReservationV2, ReservationState, WASM_DIGEST_V2_DOMAINS,
    WASM_HOST_SERVICE_CANONICAL_INVALID, WASM_HOST_SERVICE_RESERVATION_PROOF_MISMATCH,
};
use serde_json::Value;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenDoc {
    version: u32,
    digest_v2_domains: Vec<String>,
    digest_v2_negative_domains: Vec<String>,
    digest_v2_primitive: Vec<DigestPrimitiveVector>,
    quota_reservation_proof: Vec<ReservationProofVector>,
    quota_proof_negative: QuotaProofNegative,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DigestPrimitiveVector {
    name: String,
    domain: String,
    payload_text: String,
    expected_hex: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReservationProofVector {
    name: String,
    reservation: Value,
    expected_proof_digest: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuotaProofNegative {
    #[allow(dead_code)]
    name: String,
    base_vector: String,
    tampered_reservation: Value,
}

fn load_doc() -> GoldenDoc {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/wasm/host-services-golden-vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text).expect("golden fixture JSON must parse")
}

/// fixture 的 reservation JSON（12 字段、无 proof）补一个占位 proof 后反序列化为
/// Kernel 行；compute/verify 会按公式忽略/改写该占位（proof 输入恒省略自身）。
fn reservation_from_json(mut value: Value, proof_digest: &str) -> QuotaReservationV2 {
    value
        .as_object_mut()
        .expect("reservation vector must be an object")
        .insert("reservationProofDigest".into(), Value::String(proof_digest.to_string()));
    serde_json::from_value(value).expect("reservation vector must deserialize into QuotaReservationV2")
}

#[test]
fn golden_version_and_domain_table_are_pinned() {
    let doc = load_doc();
    assert_eq!(doc.version, 1);
    assert_eq!(doc.digest_v2_domains.len(), 16, "design.md「Decisions 1」列了恰好 16 个 V2 domain");
    assert_eq!(doc.digest_v2_domains.as_slice(), WASM_DIGEST_V2_DOMAINS);
    assert!(doc.digest_v2_primitive.len() >= 4);
    assert!(doc.quota_reservation_proof.len() >= 2);
}

#[test]
fn golden_digest_v2_primitive_vectors_match() {
    let doc = load_doc();
    for vector in &doc.digest_v2_primitive {
        let computed = digest_v2(&vector.domain, vector.payload_text.as_bytes())
            .unwrap_or_else(|error| panic!("vector {}: {error}", vector.name));
        assert_eq!(
            computed, vector.expected_hex,
            "vector {} diverged from the TS authority",
            vector.name
        );
    }
}

#[test]
fn golden_digest_v2_rejects_domains_outside_the_table() {
    let doc = load_doc();
    assert!(doc.digest_v2_negative_domains.len() >= 3);
    for bad in &doc.digest_v2_negative_domains {
        let rejected = digest_v2(bad, b"payload").expect_err("unknown domain must be rejected");
        assert_eq!(rejected.code, WASM_HOST_SERVICE_CANONICAL_INVALID, "domain {bad:?}");
    }
    // V1 系（"\n" 分隔）与 V2 互不解释：同一 payload 两种框架摘要必须不同。
    use sha2::Digest as _;
    let mut v1_style = sha2::Sha256::new();
    v1_style.update(b"iweb-wasm-host-policy-v2\n");
    v1_style.update(br#"{"a":1}"#);
    let v2 = digest_v2("iweb-wasm-host-policy-v2", br#"{"a":1}"#).expect("v2 digest");
    assert_ne!(v2, hex::encode(v1_style.finalize()));
}

#[test]
fn golden_quota_reservation_proof_vectors_match() {
    let doc = load_doc();
    for vector in &doc.quota_reservation_proof {
        // 占位 proof 不影响计算（公式恒省略 proof 并把 state 归一为 reserved）。
        let reservation = reservation_from_json(vector.reservation.clone(), &"0".repeat(64));
        let computed = compute_reservation_proof_digest(&reservation)
            .unwrap_or_else(|error| panic!("vector {}: {error}", vector.name));
        assert_eq!(
            computed, vector.expected_proof_digest,
            "vector {} diverged from the TS-side formula",
            vector.name
        );
        // 用期望 digest 封口后 verify 必须通过（含 committed 行：proof 按 reserved 形状复算）。
        let sealed = reservation_from_json(vector.reservation.clone(), &vector.expected_proof_digest);
        verify_reservation_proof(&sealed).unwrap_or_else(|error| panic!("vector {} must verify: {error}", vector.name));
    }
}

#[test]
fn golden_quota_proof_negative_tampering_is_detected() {
    let doc = load_doc();
    let base = doc
        .quota_reservation_proof
        .iter()
        .find(|entry| entry.name == doc.quota_proof_negative.base_vector)
        .expect("base vector referenced by the negative case must exist");
    // 篡改行（delta +1）携带原 proof → proof 复算失配，fail-closed。
    let tampered = reservation_from_json(
        doc.quota_proof_negative.tampered_reservation.clone(),
        &base.expected_proof_digest,
    );
    let rejected = verify_reservation_proof(&tampered).expect_err("tampered reservation must fail the durable proof");
    assert_eq!(rejected.code, WASM_HOST_SERVICE_RESERVATION_PROOF_MISMATCH);
}

#[test]
fn golden_fixture_backends_and_states_stay_in_the_closed_set() {
    let doc = load_doc();
    for vector in &doc.quota_reservation_proof {
        let reservation = reservation_from_json(vector.reservation.clone(), &"0".repeat(64));
        assert!(matches!(reservation.backend, QuotaBackend::Kv | QuotaBackend::Sql));
        assert!(matches!(
            reservation.state,
            ReservationState::Reserved | ReservationState::Committed | ReservationState::Released
        ));
        // wire 精确键集：deny_unknown_fields 下多余字段必须反序列化失败。
        let mut tainted = vector.reservation.clone();
        tainted
            .as_object_mut()
            .expect("object")
            .insert("controlRevision".into(), Value::from(3u64));
        assert!(serde_json::from_value::<QuotaReservationV2>(tainted).is_err());
    }
}
