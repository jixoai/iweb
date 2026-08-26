//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1/3.3）：wasmd 的身份/绑定/
//! readiness health v2 wire——Rust 手写同形状 JSON，digest 公式对齐
//! packages/contracts/wasm-health.ts（15 字段精确形状；唯一合法形态 ok:true）。
//! 规范权威：spec "Wasm readiness is a full identity attestation" 与
//! "Every wasm execution uses a typed dual-generation fence"。
//!
//! 正交意图：
//! 1. RuntimeBindingIdentityV1 七字段完整绑定（不得以 image digest/catalog 子集替代）；
//! 2. WasmdIdentityV1：argv 携带的身份 tuple（= health v2 的 13 个身份字段减去
//!    schemaVersion/ok；含 capability pin、secret/config 快照 digest 与 P/E 双代次）；
//! 3. WasmReadinessHealthV2：唯一对外健康载荷；JCS 字节与 contracts
//!    exampleWasmReadinessHealthV2 的 golden 向量逐字节一致；
//! 4. SnapshotValuesPayloadV1：FD 3/4 的 canonical 值载荷（键集精确、keys 排序去重、
//!    values 与 keys 集合相等）。
//!
//! 不可调和原因：2/3 共享同一身份文法与 config 耦合法则；4 是同一身份的快照对面，
//! 拆分会重引入字段漂移。celld sequence/generation 绝不作为 wasm 代次（WASM_IDENTITY_INCOMPLETE）。

use crate::jcs::{
    err, jcs_bytes, parse_canonical, require_u53, validate_entry_key, validate_oci_sha256,
    validate_sandbox_id, validate_sha256_hex, validate_version_id, WireError, WASM_U53_MAX,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// spec 已命名：celld 单字段信号/缺双代次的 wasm 信号判负。
pub const WASM_IDENTITY_INCOMPLETE: &str = "WASM_IDENTITY_INCOMPLETE";
/// wasmd 补充稳定码：argv 携带的 wire（binding/identity/resources）不合法。
pub const WASMD_ARGV_WIRE_INVALID: &str = "WASMD_ARGV_WIRE_INVALID";
/// wasmd 补充稳定码：快照值载荷不合法（键集/排序/文法）。
pub const WASMD_SNAPSHOT_PAYLOAD_INVALID: &str = "WASMD_SNAPSHOT_PAYLOAD_INVALID";

/// 矩阵字面量（NodeCapabilityRecordV1.matrix 的 revision-1 权威值）。
pub const MATRIX_WORLD: &str = "wasi:http/proxy@0.2.8";
pub const MATRIX_HOST_ABI: &str = "iweb-wasmd-abi@1.0.0";
pub const WASMD_RUNTIME_KIND: &str = "wasm";

/// RuntimeBindingIdentityV1（七字段；catalogRevision/catalogHash 也是身份的一部分）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingIdentityV1 {
    pub kind: String,
    #[serde(rename = "catalogRevision")]
    pub catalog_revision: u64,
    #[serde(rename = "catalogHash")]
    pub catalog_hash: String,
    #[serde(rename = "entryKey")]
    pub entry_key: String,
    #[serde(rename = "imageDigest")]
    pub image_digest: String,
    #[serde(rename = "hostABI")]
    pub host_abi: String,
    pub world: String,
}

impl RuntimeBindingIdentityV1 {
    /// 七字段精确校验（kind/catalog/entry/image/ABI/world 字面量与文法）。
    pub fn validate(&self) -> Result<(), WireError> {
        if self.kind != WASMD_RUNTIME_KIND {
            return Err(err(WASMD_ARGV_WIRE_INVALID, "runtime binding kind must be the literal wasm"));
        }
        require_u53(self.catalog_revision, 1, WASM_U53_MAX, "catalogRevision")?;
        validate_sha256_hex(&self.catalog_hash, "catalogHash")?;
        validate_entry_key(&self.entry_key)?;
        validate_oci_sha256(&self.image_digest, "imageDigest")?;
        if self.host_abi != MATRIX_HOST_ABI {
            return Err(err(WASMD_ARGV_WIRE_INVALID, "runtime binding hostABI must equal the matrix ABI literal"));
        }
        if self.world != MATRIX_WORLD {
            return Err(err(WASMD_ARGV_WIRE_INVALID, "runtime binding world must equal the matrix world literal"));
        }
        Ok(())
    }
}

/// configRevision:0 ⇔ configSnapshotRef:null ⇔ configValuesDigest:null；非零三者齐全。
/// readiness v2 / lease v2 / metrics v1 共用的耦合法则（contracts checkConfigSnapshotCoupling）。
pub fn check_config_snapshot_coupling(
    config_revision: u64,
    config_snapshot_ref: &Option<String>,
    config_values_digest: &Option<String>,
) -> Result<(), WireError> {
    if config_revision == 0 && (config_snapshot_ref.is_some() || config_values_digest.is_some()) {
        return Err(err(WASMD_ARGV_WIRE_INVALID, "configRevision 0 requires both configSnapshotRef and configValuesDigest null"));
    }
    if config_revision > 0 && (config_snapshot_ref.is_none() || config_values_digest.is_none()) {
        return Err(err(WASMD_ARGV_WIRE_INVALID, "a non-zero configRevision requires both configSnapshotRef and configValuesDigest"));
    }
    if let Some(reference) = config_snapshot_ref {
        validate_sha256_hex(reference, "configSnapshotRef")?;
    }
    if let Some(digest) = config_values_digest {
        validate_sha256_hex(digest, "configValuesDigest")?;
    }
    Ok(())
}

/// argv 携带的身份 tuple（health v2 的全部身份字段；supervisor 独占生成）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmdIdentityV1 {
    #[serde(rename = "sandboxId")]
    pub sandbox_id: String,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "secretValuesDigest")]
    pub secret_values_digest: String,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
    #[serde(rename = "configSnapshotRef")]
    pub config_snapshot_ref: Option<String>,
    #[serde(rename = "configValuesDigest")]
    pub config_values_digest: Option<String>,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    #[serde(rename = "executionGeneration")]
    pub execution_generation: u64,
}

impl WasmdIdentityV1 {
    /// 全字段精确校验（含双代次 >= 1 与 config 耦合；celld 信号在键集层面已由
    /// deny_unknown_fields 拒绝——generation/sequence 字段永远进不来）。
    pub fn validate(&self) -> Result<(), WireError> {
        validate_sandbox_id(&self.sandbox_id)?;
        validate_version_id(&self.version_id)?;
        validate_sha256_hex(&self.package_digest, "packageDigest")?;
        self.runtime_binding.validate()?;
        require_u53(self.capability_record_revision, 1, WASM_U53_MAX, "capabilityRecordRevision")?;
        validate_sha256_hex(&self.capability_record_hash, "capabilityRecordHash")?;
        require_u53(self.secret_revision, 0, WASM_U53_MAX, "secretRevision")?;
        validate_sha256_hex(&self.secret_values_digest, "secretValuesDigest")?;
        require_u53(self.config_revision, 0, WASM_U53_MAX, "configRevision")?;
        // 存活/报告健康的 execution 双代次必须 >= 1（executionGeneration:0 只在首次分配前）。
        require_u53(self.preparation_generation, 1, WASM_U53_MAX, "preparationGeneration")
            .map_err(|_| err(WASM_IDENTITY_INCOMPLETE, "an alive wasmd execution must carry preparationGeneration >= 1"))?;
        require_u53(self.execution_generation, 1, WASM_U53_MAX, "executionGeneration")
            .map_err(|_| err(WASM_IDENTITY_INCOMPLETE, "an alive wasmd execution must carry executionGeneration >= 1"))?;
        check_config_snapshot_coupling(self.config_revision, &self.config_snapshot_ref, &self.config_values_digest)
    }
}

/// readiness health v2：唯一合法形态是 ok:true 的精确 15 字段 JCS 对象。
/// 字段集与 packages/contracts/wasm-health.ts WasmReadinessHealthV2 逐字对齐。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmReadinessHealthV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub ok: bool,
    #[serde(rename = "sandboxId")]
    pub sandbox_id: String,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    #[serde(rename = "capabilityRecordRevision")]
    pub capability_record_revision: u64,
    #[serde(rename = "capabilityRecordHash")]
    pub capability_record_hash: String,
    #[serde(rename = "secretRevision")]
    pub secret_revision: u64,
    #[serde(rename = "secretValuesDigest")]
    pub secret_values_digest: String,
    #[serde(rename = "configRevision")]
    pub config_revision: u64,
    #[serde(rename = "configSnapshotRef")]
    pub config_snapshot_ref: Option<String>,
    #[serde(rename = "configValuesDigest")]
    pub config_values_digest: Option<String>,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    #[serde(rename = "executionGeneration")]
    pub execution_generation: u64,
}

impl WasmReadinessHealthV2 {
    /// 从身份 tuple 构造（schemaVersion 字面量 2；ok 恒 true——not-ready 由不监听/
    /// 拨号失败体现，绝不引入第二健康状态位）。
    pub fn from_identity(identity: &WasmdIdentityV1) -> Self {
        Self {
            schema_version: 2,
            ok: true,
            sandbox_id: identity.sandbox_id.clone(),
            version_id: identity.version_id.clone(),
            package_digest: identity.package_digest.clone(),
            runtime_binding: identity.runtime_binding.clone(),
            capability_record_revision: identity.capability_record_revision,
            capability_record_hash: identity.capability_record_hash.clone(),
            secret_revision: identity.secret_revision,
            secret_values_digest: identity.secret_values_digest.clone(),
            config_revision: identity.config_revision,
            config_snapshot_ref: identity.config_snapshot_ref.clone(),
            config_values_digest: identity.config_values_digest.clone(),
            preparation_generation: identity.preparation_generation,
            execution_generation: identity.execution_generation,
        }
    }

    /// 健康载荷的 JCS 字节（gateway 原样读取；不合成、不改写）。
    pub fn jcs(&self) -> Result<Vec<u8>, WireError> {
        jcs_bytes(self)
    }
}

/// NormalizedWasmManifestV1.resources 的精确形状（wasmd 只消费 memoryBytes 推导
/// guest 线性内存上限；其余字段做同界校验后原样入 fence）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmResourcesV1 {
    #[serde(rename = "cpuMillis")]
    pub cpu_millis: u64,
    #[serde(rename = "memoryBytes")]
    pub memory_bytes: u64,
    #[serde(rename = "pidLimit")]
    pub pid_limit: u64,
    #[serde(rename = "storageBytes")]
    pub storage_bytes: u64,
}

impl WasmResourcesV1 {
    /// manifest 资源界（含端点）：cpuMillis 1..1000000、memoryBytes 1..68719476736、
    /// pidLimit 1..1000000、storageBytes 0..1099511627776。
    pub fn validate(&self) -> Result<(), WireError> {
        require_u53(self.cpu_millis, 1, 1_000_000, "cpuMillis")?;
        require_u53(self.memory_bytes, 1, 68_719_476_736, "memoryBytes")?;
        require_u53(self.pid_limit, 1, 1_000_000, "pidLimit")?;
        require_u53(self.storage_bytes, 0, 1_099_511_627_776, "storageBytes")?;
        Ok(())
    }
}

/// FD 3/4 携带的 canonical 值载荷：{applicationId,versionId,preparationGeneration,
/// (secret|config)Revision,keys,values}；JCS 字节是 FD 的唯一内容。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotValuesPayloadV1 {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    pub revision: u64,
    pub keys: Vec<String>,
    pub values: BTreeMap<String, String>,
}

/// 快照值域上界（spec：keys 0..256；单值 0..65536 UTF-8 字节）。
pub const SNAPSHOT_MAX_KEYS: usize = 256;
pub const SNAPSHOT_MAX_VALUE_BYTES: usize = 65_536;

impl SnapshotValuesPayloadV1 {
    /// 精确键集 + 文法 + 排序 + keys/values 集合相等 + 值域界（domain 参数仅用于错误文案）。
    pub fn validate(&self, domain: &str) -> Result<(), WireError> {
        if self.keys.len() > SNAPSHOT_MAX_KEYS {
            return Err(err(WASMD_SNAPSHOT_PAYLOAD_INVALID, format!("{domain} keys must have at most {SNAPSHOT_MAX_KEYS} items")));
        }
        let mut previous: Option<&str> = None;
        for key in &self.keys {
            crate::jcs::validate_application_key(key)?;
            match previous {
                Some(previous_key) if previous_key.as_bytes() >= key.as_bytes() => {
                    // JCS 数组本身有序；重复或逆序都是非 canonical 输入。
                    return Err(err(WASMD_SNAPSHOT_PAYLOAD_INVALID, format!("{domain} keys must be sorted and unique")));
                }
                _ => previous = Some(key),
            }
        }
        if self.values.len() != self.keys.len() {
            return Err(err(WASMD_SNAPSHOT_PAYLOAD_INVALID, format!("{domain} values key set must equal keys")));
        }
        for key in &self.keys {
            if !self.values.contains_key(key) {
                return Err(err(WASMD_SNAPSHOT_PAYLOAD_INVALID, format!("{domain} values key set must equal keys")));
            }
        }
        for value in self.values.values() {
            if value.len() > SNAPSHOT_MAX_VALUE_BYTES {
                return Err(err(WASMD_SNAPSHOT_PAYLOAD_INVALID, format!("{domain} value exceeds {SNAPSHOT_MAX_VALUE_BYTES} UTF-8 bytes")));
            }
        }
        Ok(())
    }

    /// 从 FD 原始字节解析（规范 JCS：原始字节等于 JCS(解析值)）。
    pub fn parse(bytes: &[u8], domain: &str) -> Result<Self, WireError> {
        let parsed: Self = parse_canonical(bytes, WASMD_SNAPSHOT_PAYLOAD_INVALID)
            .map_err(|e| err(e.code, format!("{domain}: {}", e.detail)))?;
        parsed.validate(domain)?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn vector_binding() -> RuntimeBindingIdentityV1 {
        RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: MATRIX_HOST_ABI.into(),
            world: MATRIX_WORLD.into(),
        }
    }

    fn vector_identity() -> WasmdIdentityV1 {
        WasmdIdentityV1 {
            sandbox_id: "sbx-vector".into(),
            version_id: format!("{}-1", "a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532"),
            package_digest: "0".repeat(64),
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            secret_revision: 3,
            secret_values_digest: "6".repeat(64),
            config_revision: 2,
            config_snapshot_ref: Some("7".repeat(64)),
            config_values_digest: Some("8".repeat(64)),
            preparation_generation: 1,
            execution_generation: 1,
        }
    }

    /// golden：与 packages/contracts/wasm-health.ts exampleWasmReadinessHealthV2 的
    /// jcsCanonicalBytes 逐字节一致（999 字节；由 bun 现场生成后固化）。
    #[test]
    fn health_v2_jcs_matches_contracts_golden() {
        let identity = vector_identity();
        let health = WasmReadinessHealthV2::from_identity(&identity);
        let bytes = health.jcs().expect("health jcs");
        let expected = r#"{"capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"configRevision":2,"configSnapshotRef":"7777777777777777777777777777777777777777777777777777777777777777","configValuesDigest":"8888888888888888888888888888888888888888888888888888888888888888","executionGeneration":1,"ok":true,"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","preparationGeneration":1,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"sandboxId":"sbx-vector","schemaVersion":2,"secretRevision":3,"secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}"#;
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(bytes.len(), 999);
    }

    #[test]
    fn identity_rejects_zero_generation_and_config_coupling_violation() {
        let mut identity = vector_identity();
        identity.execution_generation = 0;
        assert_eq!(identity.validate().expect_err("E=0").code, WASM_IDENTITY_INCOMPLETE);
        identity.execution_generation = 1;
        identity.config_revision = 0;
        assert!(identity.validate().is_err(), "configRevision 0 with refs must fail");
        identity.config_snapshot_ref = None;
        identity.config_values_digest = None;
        identity.validate().expect("revision-0 coupling now consistent");
        // celld 信号在键集层面拒绝：serde deny_unknown_fields。
        let raw = br#"{"sandboxId":"s","versionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1","packageDigest":"0","runtimeBinding":{"kind":"wasm","catalogRevision":1,"catalogHash":"ab","entryKey":"k","imageDigest":"sha256:x","hostABI":"iweb-wasmd-abi@1.0.0","world":"wasi:http/proxy@0.2.8"},"capabilityRecordRevision":1,"capabilityRecordHash":"2","secretRevision":0,"secretValuesDigest":"6","configRevision":0,"configSnapshotRef":null,"configValuesDigest":null,"preparationGeneration":1,"executionGeneration":1,"generation":7}"#;
        let parsed: Result<WasmdIdentityV1, _> = serde_json::from_slice(raw);
        assert!(parsed.is_err(), "unknown generation field must be rejected");
    }

    #[test]
    fn snapshot_payload_validates_keys_values_equality() {
        let payload = SnapshotValuesPayloadV1 {
            application_id: "alpha".into(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            revision: 3,
            keys: vec!["db.password".into(), "token".into()],
            values: BTreeMap::from([("db.password".to_string(), "v1".into()), ("token".to_string(), "v2".into())]),
        };
        payload.validate("secret").expect("valid snapshot");
        let mut bad = payload.clone();
        bad.keys = vec!["token".into(), "db.password".into()];
        assert_eq!(bad.validate("secret").expect_err("unsorted").code, WASMD_SNAPSHOT_PAYLOAD_INVALID);
        let mut bad = payload.clone();
        bad.values.remove("token");
        assert!(bad.validate("secret").is_err(), "values key set must equal keys");
        let mut bad = payload.clone();
        bad.keys = vec!["UPPER".into()];
        assert!(bad.validate("secret").is_err(), "key grammar");
    }

    #[test]
    fn binding_rejects_subset_substitution() {
        let mut binding = vector_binding();
        binding.world = "wasi:http/proxy@0.2.7".into();
        assert!(binding.validate().is_err(), "world literal");
        binding.world = MATRIX_WORLD.into();
        binding.image_digest = format!("sha256:{}", "cd".repeat(31));
        assert!(binding.validate().is_err(), "image digest grammar");
    }
}
