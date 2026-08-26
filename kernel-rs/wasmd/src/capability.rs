//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.2）：wasmd 的宿主上限唯一来源
//! 是 pinned NodeCapabilityRecordV1——HTTP 请求/响应/头部/并发上限、引擎 epoch/fuel/
//! 实例上限、drain 期限与 runtimeReserves 全部从 record 读取；缺失或 mismatch 一律
//! fail-closed 拒绝启动，无环境变量可替换。
//! 规范权威：spec "Node capability records are canonical revisioned bounds" 与
//! "Wasmd has a fixed command and host-mediated network contract"。
//! 结构/recordHash 契约唯一权威：packages/contracts/wasm-catalog.ts
//! validateNodeCapabilityRecordV1（本模块逐字段对齐；不复制 TS 的 CAS/append 逻辑，
//! 那是 Kernel 侧职责，wasmd 只读验证）。
//!
//! 正交意图：
//! 1. 全字段精确键集 + 界校验（policyMaxima/http/engine/admission/restart/
//!    drainDeadlineMs/runtimeReserves/matrix）；
//! 2. recordHash 复算（域前缀单次 SHA-256 over 去掉 recordHash 的 JCS 记录）；
//! 3. revision-1 matrix 字面量精确匹配（world/ABI/requiredRootExport/hostImports）；
//! 4. runtimeReserves 的 (JCS(binding), architecture) 查找与 guest 线性内存上限
//!    推导：memoryBytes - reserveBytes（reserve 缺失或 >= memoryBytes 即
//!    WASM_RESOURCE_RECORD_INVALID，绝不代以默认值或零）。

use crate::jcs::{err, jcs_bytes, parse_canonical, require_u53, validate_architecture, domain_digest, WireError};
use crate::wire::{
    RuntimeBindingIdentityV1, MATRIX_HOST_ABI, MATRIX_WORLD,
};
use serde::{Deserialize, Serialize};

/// wasmd 补充稳定码：capability record 结构/界/hash/pin 不合法。
pub const WASMD_CAPABILITY_RECORD_INVALID: &str = "WASMD_CAPABILITY_RECORD_INVALID";
/// spec 已命名（Reserve is missing or consumes the total memory limit 场景）。
pub const WASM_RESOURCE_RECORD_INVALID: &str = "WASM_RESOURCE_RECORD_INVALID";

/// recordHash 域前缀（spec：iweb-node-capability-record-v1）。
pub const NODE_CAPABILITY_RECORD_HASH_DOMAIN: &str = "iweb-node-capability-record-v1";

/// reserveBytes 上界（刻意比 policyMaxima.memoryBytes 上界小 1）。
const MAX_RESERVE_BYTES: u64 = 68_719_476_735;
/// runtimeReserves 条目上界。
const MAX_RESERVE_ENTRIES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodePolicyMaximaV1 {
    #[serde(rename = "cpuMillis")]
    pub cpu_millis: u64,
    #[serde(rename = "memoryBytes")]
    pub memory_bytes: u64,
    #[serde(rename = "pidLimit")]
    pub pid_limit: u64,
    #[serde(rename = "storageBytes")]
    pub storage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeHttpLimitsV1 {
    #[serde(rename = "maxRequestBytes")]
    pub max_request_bytes: u64,
    #[serde(rename = "maxResponseBytes")]
    pub max_response_bytes: u64,
    #[serde(rename = "maxRequestHeaderBytes")]
    pub max_request_header_bytes: u64,
    #[serde(rename = "maxResponseHeaderBytes")]
    pub max_response_header_bytes: u64,
    #[serde(rename = "maxRequestHeaderCount")]
    pub max_request_header_count: u64,
    #[serde(rename = "maxResponseHeaderCount")]
    pub max_response_header_count: u64,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeEngineLimitsV1 {
    #[serde(rename = "maxEpochDeadlineMs")]
    pub max_epoch_deadline_ms: u64,
    #[serde(rename = "fuelPerRequest")]
    pub fuel_per_request: Option<u64>,
    #[serde(rename = "maxLiveInstances")]
    pub max_live_instances: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeAdmissionLimitsV1 {
    #[serde(rename = "maxPackageBytes")]
    pub max_package_bytes: u64,
    #[serde(rename = "maxBlobBytes")]
    pub max_blob_bytes: u64,
    #[serde(rename = "maxLayerCount")]
    pub max_layer_count: u64,
    #[serde(rename = "maxClosureNodes")]
    pub max_closure_nodes: u64,
    #[serde(rename = "maxClosureEdges")]
    pub max_closure_edges: u64,
    #[serde(rename = "maxClosureDepth")]
    pub max_closure_depth: u64,
    #[serde(rename = "stagingTtlSeconds")]
    pub staging_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeRestartBudgetV1 {
    #[serde(rename = "maxRestarts")]
    pub max_restarts: u64,
    #[serde(rename = "windowMs")]
    pub window_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReserveEntryV1 {
    #[serde(rename = "runtimeBinding")]
    pub runtime_binding: RuntimeBindingIdentityV1,
    pub architecture: String,
    #[serde(rename = "reserveBytes")]
    pub reserve_bytes: u64,
}

/// ImportCapability：{package, interface, direction}（spec 键集精确）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ImportCapability {
    pub package: String,
    pub interface: String,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WasmCapabilityMatrixV1 {
    pub world: String,
    #[serde(rename = "hostABI")]
    pub host_abi: String,
    #[serde(rename = "requiredRootExport")]
    pub required_root_export: ImportCapability,
    #[serde(rename = "hostImports")]
    pub host_imports: Vec<ImportCapability>,
}

/// NodeCapabilityRecordV1（recordHash 含在结构中；hash 输入为去掉它的 payload）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilityRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub revision: u64,
    #[serde(rename = "recordHash")]
    pub record_hash: String,
    #[serde(rename = "policyMaxima")]
    pub policy_maxima: NodePolicyMaximaV1,
    pub http: NodeHttpLimitsV1,
    pub engine: NodeEngineLimitsV1,
    pub admission: NodeAdmissionLimitsV1,
    pub restart: NodeRestartBudgetV1,
    #[serde(rename = "drainDeadlineMs")]
    pub drain_deadline_ms: u64,
    #[serde(rename = "runtimeReserves")]
    pub runtime_reserves: Vec<RuntimeReserveEntryV1>,
    pub matrix: WasmCapabilityMatrixV1,
}

/// 去 recordHash 的 payload（hash 输入）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilityRecordPayloadV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub revision: u64,
    #[serde(rename = "policyMaxima")]
    pub policy_maxima: NodePolicyMaximaV1,
    pub http: NodeHttpLimitsV1,
    pub engine: NodeEngineLimitsV1,
    pub admission: NodeAdmissionLimitsV1,
    pub restart: NodeRestartBudgetV1,
    #[serde(rename = "drainDeadlineMs")]
    pub drain_deadline_ms: u64,
    #[serde(rename = "runtimeReserves")]
    pub runtime_reserves: Vec<RuntimeReserveEntryV1>,
    pub matrix: WasmCapabilityMatrixV1,
}

/// revision-1 matrix 的 hostImports 精确集合（spec "Capability record revision 1"）。
pub const MATRIX_HOST_IMPORTS: &[(&str, &str)] = &[
    ("wasi:http@0.2.8", "types"),
    ("wasi:http@0.2.8", "outgoing-handler"),
    ("wasi:clocks@0.2.8", "monotonic-clock"),
    ("wasi:clocks@0.2.8", "wall-clock"),
    ("wasi:random@0.2.8", "random"),
    ("wasi:io@0.2.8", "streams"),
    ("wasi:io@0.2.8", "error"),
    ("wasi:io@0.2.8", "poll"),
    ("wasi:cli@0.2.8", "stdin"),
    ("wasi:cli@0.2.8", "stdout"),
    ("wasi:cli@0.2.8", "stderr"),
    ("iweb:config@1.0.0", "store"),
    ("iweb:secrets@1.0.0", "store"),
];

impl NodeCapabilityRecordV1 {
    /// 完整校验：结构 + 界 + recordHash 复算 + revision-1 matrix 字面量。
    pub fn validate(&self) -> Result<(), WireError> {
        if self.schema_version != 1 {
            return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "schemaVersion must be the literal 1"));
        }
        require_u53(self.revision, 1, u64::MAX, "revision")?;
        validate_record_sections(self)?;
        // recordHash = hex(SHA-256(UTF8("iweb-node-capability-record-v1\n" || JCS(record with recordHash omitted))))。
        let payload = NodeCapabilityRecordPayloadV1 {
            schema_version: self.schema_version,
            revision: self.revision,
            policy_maxima: self.policy_maxima.clone(),
            http: self.http.clone(),
            engine: self.engine.clone(),
            admission: self.admission.clone(),
            restart: self.restart.clone(),
            drain_deadline_ms: self.drain_deadline_ms,
            runtime_reserves: self.runtime_reserves.clone(),
            matrix: self.matrix.clone(),
        };
        let expected = domain_digest(
            NODE_CAPABILITY_RECORD_HASH_DOMAIN,
            &jcs_bytes(&payload).map_err(|e| err(WASMD_CAPABILITY_RECORD_INVALID, e.detail))?,
        );
        if self.record_hash != expected {
            return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "recordHash does not equal the domain-prefixed digest of the payload"));
        }
        validate_matrix(&self.matrix)?;
        validate_reserves(&self.runtime_reserves)?;
        Ok(())
    }

    /// 从原始字节解析并完整校验（规范 JCS：原始字节等于 JCS(解析值)）。
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let parsed: Self = parse_canonical(bytes, WASMD_CAPABILITY_RECORD_INVALID)?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// 按完整 binding + 架构查 reserve；缺失即 WASM_RESOURCE_RECORD_INVALID（无默认值）。
    pub fn find_runtime_reserve(
        &self,
        binding: &RuntimeBindingIdentityV1,
        architecture: &str,
    ) -> Result<&RuntimeReserveEntryV1, WireError> {
        let binding_bytes = jcs_bytes(binding)
            .map_err(|e| err(WASM_RESOURCE_RECORD_INVALID, e.detail))?;
        self.runtime_reserves
            .iter()
            .find(|entry| {
                entry.architecture == architecture
                    && jcs_bytes(&entry.runtime_binding)
                        .map(|bytes| bytes == binding_bytes)
                        .unwrap_or(false)
            })
            .ok_or_else(|| {
                err(
                    WASM_RESOURCE_RECORD_INVALID,
                    format!("no measured reserve exists for the selected binding on {architecture}; no default or zero reserve is substituted"),
                )
            })
    }

    /// guest 线性内存上限 = memoryBytes - reserveBytes；reserve >= memoryBytes 拒绝。
    pub fn guest_memory_limit_bytes(
        &self,
        binding: &RuntimeBindingIdentityV1,
        architecture: &str,
        memory_bytes: u64,
    ) -> Result<u64, WireError> {
        let reserve = self.find_runtime_reserve(binding, architecture)?;
        if reserve.reserve_bytes >= memory_bytes {
            return Err(err(WASM_RESOURCE_RECORD_INVALID, "reserveBytes is greater than or equal to resources.memoryBytes; admission or preparation must fail closed"));
        }
        Ok(memory_bytes - reserve.reserve_bytes)
    }
}

fn validate_record_sections(record: &NodeCapabilityRecordV1) -> Result<(), WireError> {
    let policy = &record.policy_maxima;
    require_u53(policy.cpu_millis, 1, 1_000_000, "policyMaxima/cpuMillis")?;
    require_u53(policy.memory_bytes, 1, 68_719_476_736, "policyMaxima/memoryBytes")?;
    require_u53(policy.pid_limit, 1, 1_000_000, "policyMaxima/pidLimit")?;
    require_u53(policy.storage_bytes, 0, 1_099_511_627_776, "policyMaxima/storageBytes")?;

    let http = &record.http;
    require_u53(http.max_request_bytes, 1, 16_777_216, "http/maxRequestBytes")?;
    require_u53(http.max_response_bytes, 1, 67_108_864, "http/maxResponseBytes")?;
    require_u53(http.max_request_header_bytes, 1, 65_536, "http/maxRequestHeaderBytes")?;
    require_u53(http.max_response_header_bytes, 1, 65_536, "http/maxResponseHeaderBytes")?;
    require_u53(http.max_request_header_count, 1, 256, "http/maxRequestHeaderCount")?;
    require_u53(http.max_response_header_count, 1, 256, "http/maxResponseHeaderCount")?;
    require_u53(http.max_concurrent_requests, 1, 4_096, "http/maxConcurrentRequests")?;

    let engine = &record.engine;
    require_u53(engine.max_epoch_deadline_ms, 1, 300_000, "engine/maxEpochDeadlineMs")?;
    if let Some(fuel) = engine.fuel_per_request {
        require_u53(fuel, 1, 1_000_000_000_000, "engine/fuelPerRequest")?;
    }
    require_u53(engine.max_live_instances, 1, 4_096, "engine/maxLiveInstances")?;

    let admission = &record.admission;
    require_u53(admission.max_package_bytes, 1, 536_870_912, "admission/maxPackageBytes")?;
    require_u53(admission.max_blob_bytes, 1, 134_217_728, "admission/maxBlobBytes")?;
    require_u53(admission.max_layer_count, 1, 128, "admission/maxLayerCount")?;
    require_u53(admission.max_closure_nodes, 1, 4_096, "admission/maxClosureNodes")?;
    require_u53(admission.max_closure_edges, 1, 16_384, "admission/maxClosureEdges")?;
    require_u53(admission.max_closure_depth, 1, 64, "admission/maxClosureDepth")?;
    require_u53(admission.staging_ttl_seconds, 1, 3_600, "admission/stagingTtlSeconds")?;

    let restart = &record.restart;
    require_u53(restart.max_restarts, 0, 100, "restart/maxRestarts")?;
    require_u53(restart.window_ms, 1_000, 86_400_000, "restart/windowMs")?;

    require_u53(record.drain_deadline_ms, 1, 300_000, "drainDeadlineMs")?;
    Ok(())
}

fn validate_matrix(matrix: &WasmCapabilityMatrixV1) -> Result<(), WireError> {
    if matrix.world != MATRIX_WORLD || matrix.host_abi != MATRIX_HOST_ABI {
        return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "matrix world/hostABI must equal the revision-1 literals"));
    }
    if matrix.required_root_export.package != "wasi:http@0.2.8"
        || matrix.required_root_export.interface != "incoming-handler"
        || matrix.required_root_export.direction != "export"
    {
        return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "matrix requiredRootExport must be the exact typed export object"));
    }
    // hostImports：与 revision-1 集合完全一致（排序数组、无重复；spec "matrix has
    // exactly the revision-1 matrix above"）。绑定方向除根导出外一律 import。
    let mut expected: Vec<(&str, &str)> = MATRIX_HOST_IMPORTS.to_vec();
    expected.sort_unstable();
    if matrix.host_imports.len() != expected.len() {
        return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "matrix hostImports must equal the revision-1 import set"));
    }
    let mut sorted = matrix.host_imports.clone();
    sorted.sort();
    if sorted != matrix.host_imports {
        return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "matrix hostImports must be sorted and duplicate-free"));
    }
    for (index, import) in matrix.host_imports.iter().enumerate() {
        if import.direction != "import"
            || import.package != expected[index].0
            || import.interface != expected[index].1
        {
            return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "matrix hostImports must equal the revision-1 import set"));
        }
    }
    Ok(())
}

fn validate_reserves(reserves: &[RuntimeReserveEntryV1]) -> Result<(), WireError> {
    if reserves.is_empty() || reserves.len() > MAX_RESERVE_ENTRIES {
        return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "runtimeReserves must be a non-empty array of at most 256 entries"));
    }
    let mut previous: Option<(Vec<u8>, &str)> = None;
    for entry in reserves {
        entry.runtime_binding.validate()?;
        validate_architecture(&entry.architecture)?;
        require_u53(entry.reserve_bytes, 1, MAX_RESERVE_BYTES, "runtimeReserves/reserveBytes")?;
        // 排序：先 raw JCS UTF-8 字节再 architecture；(JCS(binding), architecture) 唯一。
        let binding_bytes = jcs_bytes(&entry.runtime_binding)
            .map_err(|e| err(WASMD_CAPABILITY_RECORD_INVALID, e.detail))?;
        if let Some((previous_bytes, previous_arch)) = previous {
            let ordering = binding_bytes.cmp(&previous_bytes).then(entry.architecture.as_bytes().cmp(previous_arch.as_bytes()));
            if ordering != std::cmp::Ordering::Greater {
                return Err(err(WASMD_CAPABILITY_RECORD_INVALID, "runtimeReserves must be sorted by raw JCS binding bytes then architecture without duplicates"));
            }
        }
        previous = Some((binding_bytes, entry.architecture.as_str()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> RuntimeBindingIdentityV1 {
        RuntimeBindingIdentityV1 {
            kind: crate::wire::WASMD_RUNTIME_KIND.into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: MATRIX_HOST_ABI.into(),
            world: MATRIX_WORLD.into(),
        }
    }

    /// 构造完整合法 record（payload + 复算 recordHash）。
    fn valid_record() -> NodeCapabilityRecordV1 {
        let payload = NodeCapabilityRecordPayloadV1 {
            schema_version: 1,
            revision: 5,
            policy_maxima: NodePolicyMaximaV1 {
                cpu_millis: 1000,
                memory_bytes: 536_870_912,
                pid_limit: 512,
                storage_bytes: 1_073_741_824,
            },
            http: NodeHttpLimitsV1 {
                max_request_bytes: 1_048_576,
                max_response_bytes: 8_388_608,
                max_request_header_bytes: 8_192,
                max_response_header_bytes: 8_192,
                max_request_header_count: 64,
                max_response_header_count: 64,
                max_concurrent_requests: 16,
            },
            engine: NodeEngineLimitsV1 {
                max_epoch_deadline_ms: 30_000,
                fuel_per_request: None,
                max_live_instances: 8,
            },
            admission: NodeAdmissionLimitsV1 {
                max_package_bytes: 134_217_728,
                max_blob_bytes: 67_108_864,
                max_layer_count: 16,
                max_closure_nodes: 512,
                max_closure_edges: 2_048,
                max_closure_depth: 32,
                staging_ttl_seconds: 600,
            },
            restart: NodeRestartBudgetV1 { max_restarts: 3, window_ms: 60_000 },
            drain_deadline_ms: 20_000,
            runtime_reserves: vec![RuntimeReserveEntryV1 {
                runtime_binding: binding(),
                architecture: "linux/arm64".into(),
                reserve_bytes: 33_554_432,
            }],
            matrix: matrix_record(),
        };
        let record_hash = domain_digest(
            NODE_CAPABILITY_RECORD_HASH_DOMAIN,
            &jcs_bytes(&payload).expect("payload jcs"),
        );
        NodeCapabilityRecordV1 { record_hash, ..payload_to_record(payload) }
    }

    fn payload_to_record(payload: NodeCapabilityRecordPayloadV1) -> NodeCapabilityRecordV1 {
        NodeCapabilityRecordV1 {
            schema_version: payload.schema_version,
            revision: payload.revision,
            record_hash: String::new(),
            policy_maxima: payload.policy_maxima,
            http: payload.http,
            engine: payload.engine,
            admission: payload.admission,
            restart: payload.restart,
            drain_deadline_ms: payload.drain_deadline_ms,
            runtime_reserves: payload.runtime_reserves,
            matrix: payload.matrix,
        }
    }

    fn matrix_record() -> WasmCapabilityMatrixV1 {
        let mut host_imports: Vec<ImportCapability> = MATRIX_HOST_IMPORTS
            .iter()
            .map(|(package, interface)| ImportCapability {
                package: (*package).into(),
                interface: (*interface).into(),
                direction: "import".into(),
            })
            .collect();
        host_imports.sort();
        WasmCapabilityMatrixV1 {
            world: MATRIX_WORLD.into(),
            host_abi: MATRIX_HOST_ABI.into(),
            required_root_export: ImportCapability {
                package: "wasi:http@0.2.8".into(),
                interface: "incoming-handler".into(),
                direction: "export".into(),
            },
            host_imports,
        }
    }

    #[test]
    fn valid_record_round_trips_and_hash_recomputes() {
        let record = valid_record();
        record.validate().expect("valid record");
        let bytes = jcs_bytes(&record).expect("record jcs");
        let parsed = NodeCapabilityRecordV1::parse(&bytes).expect("canonical parse");
        assert_eq!(parsed, record);
    }

    #[test]
    fn hash_mismatch_and_bound_violations_fail_closed() {
        let mut record = valid_record();
        record.revision += 1;
        assert_eq!(record.validate().expect_err("stale hash").code, WASMD_CAPABILITY_RECORD_INVALID);

        let mut record = valid_record();
        record.http.max_concurrent_requests = 4_097;
        // 界超限在 hash 复算前即拒绝。
        assert!(record.validate().is_err());

        let mut record = valid_record();
        record.engine.max_epoch_deadline_ms = 0;
        assert!(record.validate().is_err());

        let mut record = valid_record();
        record.drain_deadline_ms = 300_001;
        assert!(record.validate().is_err());
    }

    #[test]
    fn matrix_must_equal_revision_one() {
        let mut record = valid_record();
        record.matrix.host_imports.pop();
        // 结构变化会先撞 hash；重新封口后按 matrix 差异拒绝。
        let payload = record_payload(&record);
        record.record_hash = domain_digest(NODE_CAPABILITY_RECORD_HASH_DOMAIN, &jcs_bytes(&payload).expect("jcs"));
        assert!(record.validate().is_err(), "hostImports must equal the revision-1 set");

        let mut record = valid_record();
        record.matrix.world = "wasi:http/proxy@0.2.12".into();
        let payload = record_payload(&record);
        record.record_hash = domain_digest(NODE_CAPABILITY_RECORD_HASH_DOMAIN, &jcs_bytes(&payload).expect("jcs"));
        assert!(record.validate().is_err(), "world literal");
    }

    fn record_payload(record: &NodeCapabilityRecordV1) -> NodeCapabilityRecordPayloadV1 {
        NodeCapabilityRecordPayloadV1 {
            schema_version: record.schema_version,
            revision: record.revision,
            policy_maxima: record.policy_maxima.clone(),
            http: record.http.clone(),
            engine: record.engine.clone(),
            admission: record.admission.clone(),
            restart: record.restart.clone(),
            drain_deadline_ms: record.drain_deadline_ms,
            runtime_reserves: record.runtime_reserves.clone(),
            matrix: record.matrix.clone(),
        }
    }

    #[test]
    fn reserve_lookup_and_memory_limit_boundary() {
        let record = valid_record();
        // 33554432 reserve、memoryBytes 33554433 → guest 上限恰为 1。
        assert_eq!(record.guest_memory_limit_bytes(&binding(), "linux/arm64", 33_554_433).expect("boundary"), 1);
        // reserve >= memoryBytes 拒绝（spec 场景：WASM_RESOURCE_RECORD_INVALID）。
        assert_eq!(
            record.guest_memory_limit_bytes(&binding(), "linux/arm64", 33_554_432).expect_err("reserve == memory").code,
            WASM_RESOURCE_RECORD_INVALID
        );
        // 缺失架构的 reserve 拒绝，绝不代默认。
        assert_eq!(
            record.guest_memory_limit_bytes(&binding(), "linux/amd64", 268_435_456).expect_err("missing arch reserve").code,
            WASM_RESOURCE_RECORD_INVALID
        );
    }

    #[test]
    fn unsorted_or_duplicate_reserves_rejected() {
        let mut record = valid_record();
        record.runtime_reserves.push(RuntimeReserveEntryV1 {
            runtime_binding: binding(),
            architecture: "linux/amd64".into(),
            reserve_bytes: 16_777_216,
        });
        let payload = record_payload(&record);
        record.record_hash = domain_digest(NODE_CAPABILITY_RECORD_HASH_DOMAIN, &jcs_bytes(&payload).expect("jcs"));
        // amd64 < arm64 的字节序：插入顺序非法（先 arm64 后 amd64）。
        assert!(record.validate().is_err(), "runtimeReserves must be sorted");
    }

    #[test]
    fn non_canonical_bytes_rejected() {
        let record = valid_record();
        let mut bytes = jcs_bytes(&record).expect("record jcs");
        bytes.push(b' ');
        assert!(NodeCapabilityRecordV1::parse(&bytes).is_err(), "raw bytes must equal JCS(parse(bytes))");
    }
}
