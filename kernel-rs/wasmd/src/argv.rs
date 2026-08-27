//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1）：固定启动契约——supervisor
//! 独占生成 wasmd 的每一个 argv 元素（组件快照挂载路径、监听地址、网关地址、限额
//! 来源=node capability record 路径、runtime binding、身份 tuple、resources、节点
//! 架构）；未知/缺失/多余参数一律 fail-closed（EX_USAGE），manifest 携带可执行权威
//! 属 WASM_MANIFEST_EXECUTABLE_AUTHORITY 的对面（本进程不读 manifest、不读环境变量）。
//!
//! argv v1 精确形状（含 argv[0] 共 10 个元素；无选项语法、无可选参数）：
//! ```text
//! iweb-wasmd --iweb-wasmd-argv@1 <component-path> <listen> <gateway> <capability-record-path> <architecture> <binding-json> <identity-json> <resources-json>
//! ```
//! - 标记必须逐字节等于 `--iweb-wasmd-argv@1`；
//! - listen/gateway 必须是 ip:port 字面量（SocketAddr 解析；拒绝 DNS 名、端口 0、
//!   通配地址——出网只拨固定网关 ip，不引入解析器）；
//! - architecture ∈ {linux/amd64, linux/arm64}（reserve 查找维度）；
//! - binding/identity/resources 是 JCS JSON（精确键集 + 文法 + 耦合法则，见 wire.rs）。
//!
//! argv v2（add-wasm-host-services，2026-08-27）：service-enabled 执行追加第 11 个
//! 元素 host-services context（JCS：{schemaVersion:2, applicationId, fenceNonce,
//! hostServicePolicy}）；binding.hostABI 钉 iweb-wasmd-abi@1.1.0（@1 恒 1.0.0，标记
//! 与 ABI 严格耦合）；policy reserveBytes 满足 1 <= reserve < memoryBytes
//! （design §3 资源门）。无 service 的执行继续走 argv@1——V2 绝不解释为 V1，反之亦然。

use crate::host_services::policy::WasmdHostServicesContextV2;
use crate::jcs::{err, parse_canonical, validate_architecture, WireError};
use crate::wire::{
    RuntimeBindingIdentityV1, WasmdIdentityV1, WasmResourcesV1, MATRIX_HOST_ABI, MATRIX_HOST_ABI_V2,
    WASMD_ARGV_WIRE_INVALID,
};
use std::net::SocketAddr;
use std::path::PathBuf;

/// argv 协议标记（版本变化必须换标记，绝不宽松解析旧形状）。
pub const ARGV_MARKER: &str = "--iweb-wasmd-argv@1";
/// 含 argv[0] 的精确元素数。
pub const ARGV_ELEMENT_COUNT: usize = 10;
/// add-wasm-host-services：argv v2 标记与元素数（追加 host-services context）。
pub const ARGV_MARKER_V2: &str = "--iweb-wasmd-argv@2";
pub const ARGV_V2_ELEMENT_COUNT: usize = 11;

/// wasmd 补充稳定码：argv 形状不合法（未知标记/数量/地址文法）。
pub const WASMD_ARGV_INVALID: &str = "WASMD_ARGV_INVALID";

/// 解析后的固定启动参数。
#[derive(Debug, Clone, PartialEq)]
pub struct WasmdInvocation {
    /// 组件快照挂载路径（supervisor 物化的 entry layer 组件文件）。
    pub component_path: PathBuf,
    /// 监听地址：唯一 listener，即配对 gateway ingress 拨打的沙箱内地址。
    pub listen: SocketAddr,
    /// 网关地址：本进程唯一允许拨出的对端（HTTP 与 HTTPS CONNECT 均经它）。
    pub gateway: SocketAddr,
    /// pinned node capability record 文件路径（宿主上限唯一来源）。
    pub capability_record_path: PathBuf,
    /// 节点架构（linux/amd64|linux/arm64；runtimeReserves 查找维度）。
    pub architecture: String,
    pub binding: RuntimeBindingIdentityV1,
    pub identity: WasmdIdentityV1,
    pub resources: WasmResourcesV1,
    /// argv@2 携带的 host-service 执行上下文（argv@1 恒 None——绝不合成空策略）。
    pub host_services: Option<WasmdHostServicesContextV2>,
}

/// 校验 ip:port 字面量（拒绝 DNS、端口 0、通配地址）。
fn parse_socket_address(value: &str, field: &str) -> Result<SocketAddr, WireError> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| err(WASMD_ARGV_INVALID, format!("{field} must be an ip:port literal (DNS names are not accepted)")))?;
    if address.port() == 0 {
        return Err(err(WASMD_ARGV_INVALID, format!("{field} port must be non-zero")));
    }
    if address.ip().is_unspecified() {
        return Err(err(WASMD_ARGV_INVALID, format!("{field} must not use an unspecified/wildcard address")));
    }
    Ok(address)
}

/// 从 argv（含 argv[0]）解析；任何偏差 fail-closed。
pub fn parse_argv(argv: &[String]) -> Result<WasmdInvocation, WireError> {
    if argv.len() < 2 {
        return Err(err(WASMD_ARGV_INVALID, "argv must carry at least a marker"));
    }
    let marker = argv[1].as_str();
    let (expected_elements, expected_abi, is_v2) = match marker {
        ARGV_MARKER => (ARGV_ELEMENT_COUNT, MATRIX_HOST_ABI, false),
        ARGV_MARKER_V2 => (ARGV_V2_ELEMENT_COUNT, MATRIX_HOST_ABI_V2, true),
        other => {
            return Err(err(WASMD_ARGV_INVALID, format!(
                "argv[1] must be the exact marker {ARGV_MARKER} or {ARGV_MARKER_V2}; refusing {other}"
            )))
        }
    };
    if argv.len() != expected_elements {
        return Err(err(WASMD_ARGV_INVALID, format!(
            "argv must have exactly {expected_elements} elements including argv[0] for marker {marker}; refusing len {}",
            argv.len()
        )));
    }
    let component_path = PathBuf::from(&argv[2]);
    if component_path.as_os_str().is_empty() || !component_path.is_absolute() {
        return Err(err(WASMD_ARGV_INVALID, "component path must be a non-empty absolute path"));
    }
    let listen = parse_socket_address(&argv[3], "listen address")?;
    let gateway = parse_socket_address(&argv[4], "gateway address")?;
    let capability_record_path = PathBuf::from(&argv[5]);
    if capability_record_path.as_os_str().is_empty() || !capability_record_path.is_absolute() {
        return Err(err(WASMD_ARGV_INVALID, "capability record path must be a non-empty absolute path"));
    }
    let architecture = argv[6].clone();
    validate_architecture(&architecture).map_err(|error| err(WASMD_ARGV_INVALID, error.detail))?;
    // 三个 JSON 参数都必须是规范 JCS（原始字节等于 JCS(解析值)），杜绝
    // “解析后等价”的宽松输入。ABI 与 argv 标记严格耦合（@1=1.0.0、@2=1.1.0）。
    let binding: RuntimeBindingIdentityV1 = parse_canonical(argv[7].as_bytes(), WASMD_ARGV_WIRE_INVALID)?;
    binding.validate_with_host_abi(expected_abi)?;
    let identity: WasmdIdentityV1 = parse_canonical(argv[8].as_bytes(), WASMD_ARGV_WIRE_INVALID)?;
    identity.validate_with_host_abi(expected_abi)?;
    let resources: WasmResourcesV1 = parse_canonical(argv[9].as_bytes(), WASMD_ARGV_WIRE_INVALID)?;
    resources.validate()?;
    let host_services = if is_v2 {
        let context: WasmdHostServicesContextV2 = parse_canonical(argv[10].as_bytes(), WASMD_ARGV_WIRE_INVALID)?;
        context.validate()?;
        // design §3 资源门：1 <= reserveBytes < resources.memoryBytes（缺失/零替换拒绝）。
        context.cross_check(resources.memory_bytes)?;
        Some(context)
    } else {
        None
    };
    Ok(WasmdInvocation {
        component_path,
        listen,
        gateway,
        capability_record_path,
        architecture,
        binding,
        identity,
        resources,
        host_services,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_argv() -> Vec<String> {
        vec![
            "iweb-wasmd".to_string(),
            ARGV_MARKER.to_string(),
            "/run/iweb-sandbox/component.wasm".to_string(),
            "127.0.0.1:8787".to_string(),
            "10.88.0.1:8081".to_string(),
            "/data/kernel/node-capability.json".to_string(),
            "linux/arm64".to_string(),
            // binding-json（JCS）
            r#"{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"}"#.to_string(),
            // identity-json（JCS；revision-0 config 耦合）
            r#"{"capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"configRevision":0,"configSnapshotRef":null,"configValuesDigest":null,"executionGeneration":1,"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","preparationGeneration":1,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"sandboxId":"sbx-vector","schemaVersion2Unused":null,"secretRevision":0,"secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}"#.to_string(),
            // resources-json（JCS）
            r#"{"cpuMillis":500,"memoryBytes":268435456,"pidLimit":256,"storageBytes":1073741824}"#.to_string(),
        ]
    }

    #[test]
    fn valid_argv_parses() {
        // 先修正 identity-json（上面混入的假字段会导致 deny_unknown_fields；此处给正例）。
        let mut argv = valid_argv();
        argv[8] = r#"{"capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"configRevision":0,"configSnapshotRef":null,"configValuesDigest":null,"executionGeneration":1,"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","preparationGeneration":1,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"sandboxId":"sbx-vector","secretRevision":0,"secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}"#.to_string();
        let invocation = parse_argv(&argv).expect("valid argv");
        assert_eq!(invocation.listen, "127.0.0.1:8787".parse::<SocketAddr>().expect("addr"));
        assert_eq!(invocation.identity.config_revision, 0);
        assert!(invocation.host_services.is_none(), "argv@1 never synthesizes a service policy");
    }

    fn vector_host_services_context_json() -> String {
        let policy = crate::host_services::policy::vector_policy();
        let context = serde_json::json!({
            "schemaVersion": 2,
            "applicationId": "alpha",
            "fenceNonce": "ab".repeat(16),
            "hostServicePolicy": policy,
        });
        // 规范 JCS（键排序、无空白）——与 parse_canonical 的逐字节比对对齐。
        crate::jcs::jcs_bytes(&context).map(|bytes| String::from_utf8(bytes).expect("ascii")).expect("jcs")
    }

    #[test]
    fn argv_v2_parses_with_host_services_context_and_pins_abi() {
        let mut argv = valid_argv();
        argv[8] = r#"{"capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"configRevision":0,"configSnapshotRef":null,"configValuesDigest":null,"executionGeneration":1,"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","preparationGeneration":1,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"sandboxId":"sbx-vector","secretRevision":0,"secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}"#.to_string();
        argv[1] = ARGV_MARKER_V2.to_string();
        // binding ABI 换到 1.1.0（@2 标记与 ABI 耦合）。
        argv[7] = argv[7].replace("iweb-wasmd-abi@1.0.0", "iweb-wasmd-abi@1.1.0");
        argv[8] = argv[8].replace("iweb-wasmd-abi@1.0.0", "iweb-wasmd-abi@1.1.0");
        argv.push(vector_host_services_context_json());
        let invocation = parse_argv(&argv).expect("argv@2 parses");
        let context = invocation.host_services.expect("context present");
        assert_eq!(context.application_id, "alpha");
        assert_eq!(context.fence_nonce, "ab".repeat(16));

        // @2 + 1.0.0 ABI 拒绝（标记与 ABI 耦合 fail-closed）。
        let mut stale_abi = argv.clone();
        stale_abi[7] = stale_abi[7].replace("iweb-wasmd-abi@1.1.0", "iweb-wasmd-abi@1.0.0");
        assert_eq!(parse_argv(&stale_abi).expect_err("v2 marker demands abi 1.1.0").code, WASMD_ARGV_WIRE_INVALID);

        // @2 元素数不足拒绝。
        let mut missing = argv.clone();
        missing.pop();
        assert_eq!(parse_argv(&missing).expect_err("v2 element count").code, WASMD_ARGV_INVALID);

        // 篡改策略（reserveBytes 改成 memoryBytes 上界）——policy digest 复算/资源门
        // 至少其一 fail-closed（policyDigest 未重封时 digest 先拒；重封后资源门拒）。
        let mut reserve_bad = argv.clone();
        reserve_bad[10] = {
            let mut context: serde_json::Value = serde_json::from_str(&argv[10]).expect("json");
            context["hostServicePolicy"]["reserveBytes"] = serde_json::json!(68_719_476_736u64);
            crate::jcs::jcs_bytes(&context).map(|b| String::from_utf8(b).expect("ascii")).expect("jcs")
        };
        assert!(parse_argv(&reserve_bad).is_err(), "tampered policy must fail closed (digest recompute or reserve gate)");
    }

    #[test]
    fn unknown_marker_extra_and_missing_elements_fail_closed() {
        let mut argv = valid_argv();
        argv[8] = r#"{"capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"configRevision":0,"configSnapshotRef":null,"configValuesDigest":null,"executionGeneration":1,"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","preparationGeneration":1,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"sandboxId":"sbx-vector","secretRevision":0,"secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}"#.to_string();
        let baseline = argv.clone();

        let mut wrong_marker = baseline.clone();
        wrong_marker[1] = "--iweb-wasmd-argv@2".into();
        assert_eq!(parse_argv(&wrong_marker).expect_err("marker").code, WASMD_ARGV_INVALID);

        let mut extra = baseline.clone();
        extra.push("--extra".into());
        assert_eq!(parse_argv(&extra).expect_err("extra arg").code, WASMD_ARGV_INVALID);

        let mut missing = baseline.clone();
        missing.pop();
        assert_eq!(parse_argv(&missing).expect_err("missing arg").code, WASMD_ARGV_INVALID);

        let mut dns_addr = baseline.clone();
        dns_addr[4] = "gateway.internal:8081".into();
        assert_eq!(parse_argv(&dns_addr).expect_err("dns gateway").code, WASMD_ARGV_INVALID);

        let mut wildcard = baseline.clone();
        wildcard[3] = "0.0.0.0:8787".into();
        assert_eq!(parse_argv(&wildcard).expect_err("wildcard listen").code, WASMD_ARGV_INVALID);

        let mut zero_port = baseline.clone();
        zero_port[3] = "127.0.0.1:0".into();
        assert_eq!(parse_argv(&zero_port).expect_err("zero port").code, WASMD_ARGV_INVALID);

        let mut bad_arch = baseline.clone();
        bad_arch[6] = "linux/riscv64".into();
        assert_eq!(parse_argv(&bad_arch).expect_err("arch").code, WASMD_ARGV_INVALID);

        // 未知身份字段（schemaVersion2Unused）由 deny_unknown_fields 拒绝。
        let mut unknown_field = baseline.clone();
        unknown_field[8] = valid_argv()[8].clone();
        assert_eq!(parse_argv(&unknown_field).expect_err("unknown identity field").code, WASMD_ARGV_WIRE_INVALID);

        // 非 canonical JSON（键序）拒绝。
        let mut unsorted = baseline.clone();
        unsorted[9] = r#"{"memoryBytes":268435456,"cpuMillis":500,"pidLimit":256,"storageBytes":1073741824}"#.into();
        assert_eq!(parse_argv(&unsorted).expect_err("non-jcs resources").code, WASMD_ARGV_WIRE_INVALID);
    }
}
