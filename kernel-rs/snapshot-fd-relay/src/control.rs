//! 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 3；R2 修复轮 2026-08-30
//! tasks 9.2 直执行）：snapshot FD 原生 relay 的控制通道 wire——supervisor（Node
//! 父进程）经 SOCK_STREAM 控制 socket 以「每行一个 JSON 请求/响应」驱动代持描述符的
//! 查询、直执行 spawn（execArgv 含 argv[0]，须等于 relay 固定的 `--exec` 路径）、
//! 子进程退出等待（wait）与释放。
//!
//! 正交意图：wire 形状是 relay 私有契约（0600 同 UID 对端，非 spec 稳定 wire）；键名一律
//! camelCase 对位 supervisor 侧 TS 判定层（snapshot-fd.ts 的 SecretSnapshotFdHandoffV1 /
//! ConfigSnapshotFdHandoffV1），fd 字节以 base64 回传让 Node 以同一套
//! validateSnapshotHandoffAcceptance 复核摘要链（relay 不引入第二套比对语义）。

use serde::{Deserialize, Serialize};

/// 单行最大请求数据（base64 后的 fd 字节上限 64 KiB → ~87 KiB；预留 argv 余量）。
pub const CONTROL_MAX_LINE_BYTES: usize = 2 * 1024 * 1024;

/// Node → relay 请求（`op` 内联标签；未知 op 由 serde 解析失败拒绝）。
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum ControlRequest {
    /// 查询某 commandId 已接受的 handoff（含 fd 字节与描述符事实，供 Node 复核）。
    Lookup {
        #[serde(rename = "commandId")]
        command_id: String,
    },
    /// 以代持的 FD 3（secret）/FD 4（config，存在时）**直接 execv** 目标二进制。
    /// `execArgv` 是完整 argv（**含 argv[0]**），且 argv[0] 必须逐字等于 relay 启动时
    /// 固定的 `--exec` 路径；relay 不经 /bin/sh、不组合 launcher、不拼接参数。
    /// spawn 立即返回 pid（wasmd 是长驻进程）；退出码经 `wait` 指令上报。
    Spawn {
        #[serde(rename = "commandId")]
        command_id: String,
        #[serde(rename = "execArgv")]
        exec_argv: Vec<String>,
    },
    /// 等待某 commandId 的子进程退出（父进程保持 wait/reap 关系；reaper 线程已
    /// 回收并记录）。`timeoutMs` 到时返回运行中事实；未知 commandId 是 Error。
    Wait {
        #[serde(rename = "commandId")]
        command_id: String,
        #[serde(rename = "timeoutMs", default)]
        timeout_ms: u64,
    },
    /// 丢弃某 commandId 的全部代持描述符与台账（stop/reject 清理路径）。
    Discard {
        #[serde(rename = "commandId")]
        command_id: String,
    },
}

/// 单个 handoff 的回传视图：字段逐一对位 TS 侧 handoff 契约（camelCase），revision 按
/// kind 映射回 secretRevision/configRevision 由 Node 组装。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HandoffView {
    #[serde(rename = "commandId")]
    pub command_id: String,
    /// "secret" | "config"（与帧 frameType 的 JCS kind 一致）。
    pub kind: String,
    /// Kernel 在帧 payload 中给出的命令摘要（Node 侧命令相关性核验的绑定证明）。
    #[serde(rename = "commandDigest")]
    pub command_digest: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "preparationGeneration")]
    pub preparation_generation: u64,
    /// 按 kind 即 secretRevision（kind=secret）或 configRevision（kind=config）。
    pub revision: u64,
    #[serde(rename = "valuesDigest")]
    pub values_digest: String,
    #[serde(rename = "fdDigest")]
    pub fd_digest: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    /// fd 字节 base64（Node 侧以同域前缀公式复核 valuesDigest 链）。
    #[serde(rename = "fdBytesBase64")]
    pub fd_bytes_base64: String,
    /// relay 侧 fstat/F_GETFL 事实（Node 喂给 validateSnapshotHandoffAcceptance）。
    #[serde(rename = "descriptorRegularFile")]
    pub descriptor_regular_file: bool,
    #[serde(rename = "descriptorReadOnly")]
    pub descriptor_read_only: bool,
}

/// relay → Node 响应（请求-响应逐行配对，无需标签区分；未识别请求回 Error）。大的
/// HandoffView 以 Box 装载（clippy large_enum_variant；单响应逐行发送，非热路径）。
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ControlResponse {
    Lookup {
        ok: bool,
        secret: Option<Box<HandoffView>>,
        config: Option<Box<HandoffView>>,
    },
    /// 直执行已派发：pid 立即返回（wasmd 长驻；退出码经 Wait 上报）。
    Spawn {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pid: Option<i32>,
    },
    /// wait 结果：`running:true`（时限内未退出）或 `exitCode`（已回收的退出码，
    /// 信号终止记 128+signal）。
    Wait {
        ok: bool,
        pid: i32,
        running: bool,
        #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
    Discard {
        ok: bool,
        dropped: u32,
    },
    Error {
        ok: bool,
        code: String,
        message: String,
    },
}

/// 控制通道内部失败码（非 spec wire 稳定码；沿用 SNAPSHOT_* 命名风格）。
pub const RELAY_SPAWN_FAILED: &str = "SNAPSHOT_SPAWN_FAILED";
pub const RELAY_REQUEST_INVALID: &str = "SNAPSHOT_CONTROL_REQUEST_INVALID";
/// wait/spawn 引用未知 commandId（台账无条目）。
pub const SNAPSHOT_CHILD_UNKNOWN: &str = "SNAPSHOT_CHILD_UNKNOWN";

/// 行编解码：以 `\n` 分帧的单请求/单响应。解析层不吞错——非法 JSON/超长行交给调用方
/// 以 RELAY_REQUEST_INVALID 拒绝（fail-closed，不静默降级）。
pub fn encode_response_line(response: &ControlResponse) -> String {
    serde_json::to_string(response).unwrap_or_else(|_| {
        serde_json::to_string(&ControlResponse::Error {
            ok: false,
            code: "SNAPSHOT_CONTROL_RESPONSE_INVALID".to_string(),
            message: "the relay failed to serialize its response".to_string(),
        })
        .unwrap_or_else(|_| "{\"ok\":false}".to_string())
    }) + "\n"
}

pub fn parse_request_line(line: &str) -> Result<ControlRequest, String> {
    serde_json::from_str(line).map_err(|error| format!("control request line is not a typed request: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_with_camel_case_keys() {
        let lookup = parse_request_line("{\"op\":\"lookup\",\"commandId\":\"018f1e2c-3d4b-7a5e-9f01-23456789abcd\"}").unwrap();
        assert_eq!(
            lookup,
            ControlRequest::Lookup {
                command_id: "018f1e2c-3d4b-7a5e-9f01-23456789abcd".to_string()
            }
        );
        // spawn：execArgv 是完整 argv（含 argv[0]）。
        let spawn = parse_request_line(
            "{\"op\":\"spawn\",\"commandId\":\"c1\",\"execArgv\":[\"/opt/iweb/wasmd/iweb-wasmd\",\"--listen\",\"127.0.0.9:9101\"]}",
        )
        .unwrap();
        assert_eq!(
            spawn,
            ControlRequest::Spawn {
                command_id: "c1".to_string(),
                exec_argv: vec![
                    "/opt/iweb/wasmd/iweb-wasmd".to_string(),
                    "--listen".to_string(),
                    "127.0.0.9:9101".to_string()
                ]
            }
        );
        let wait = parse_request_line("{\"op\":\"wait\",\"commandId\":\"c1\",\"timeoutMs\":5000}").unwrap();
        assert_eq!(
            wait,
            ControlRequest::Wait {
                command_id: "c1".to_string(),
                timeout_ms: 5000
            }
        );
        let discard = parse_request_line("{\"op\":\"discard\",\"commandId\":\"c1\"}").unwrap();
        assert_eq!(discard, ControlRequest::Discard { command_id: "c1".to_string() });
    }

    #[test]
    fn unknown_operation_and_malformed_lines_are_rejected() {
        assert!(parse_request_line("{\"op\":\"explode\"}").is_err());
        assert!(parse_request_line("not json").is_err());
        assert!(parse_request_line("{\"op\":\"spawn\"}").is_err(), "a spawn without its required fields is rejected");
        // 旧 podman 语义（podmanArgv）在新 wire 下解析失败：fail-closed，不静默兼容。
        assert!(
            parse_request_line("{\"op\":\"spawn\",\"commandId\":\"c1\",\"podmanArgv\":[\"run\"]}").is_err(),
            "the retired podmanArgv wire must not parse as a spawn"
        );
    }

    #[test]
    fn responses_serialize_as_single_lines() {
        let line = encode_response_line(&ControlResponse::Discard { ok: true, dropped: 2 });
        assert!(line.ends_with('\n'));
        assert_eq!(line.trim(), "{\"ok\":true,\"dropped\":2}");
        let spawn = encode_response_line(&ControlResponse::Spawn { ok: true, pid: Some(4242) });
        assert_eq!(spawn.trim(), "{\"ok\":true,\"pid\":4242}");
        let wait_running = encode_response_line(&ControlResponse::Wait { ok: true, pid: 4242, running: true, exit_code: None });
        assert_eq!(wait_running.trim(), "{\"ok\":true,\"pid\":4242,\"running\":true}");
        let wait_exited = encode_response_line(&ControlResponse::Wait { ok: true, pid: 4242, running: false, exit_code: Some(0) });
        assert_eq!(wait_exited.trim(), "{\"ok\":true,\"pid\":4242,\"running\":false,\"exitCode\":0}");
        let error = encode_response_line(&ControlResponse::Error {
            ok: false,
            code: "SNAPSHOT_HANDOFF_MISSING".to_string(),
            message: "no held descriptor".to_string(),
        });
        assert!(error.contains("\"code\":\"SNAPSHOT_HANDOFF_MISSING\""));
    }

    #[test]
    fn handoff_view_uses_contract_key_names() {
        let view = HandoffView {
            command_id: "c1".to_string(),
            kind: "secret".to_string(),
            command_digest: "1".repeat(64),
            reference: "5".repeat(64),
            application_id: "vector".to_string(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            revision: 3,
            values_digest: "6".repeat(64),
            fd_digest: "9".repeat(64),
            expires_at: "2026-09-01T00:00:00Z".to_string(),
            fd_bytes_base64: "e30=".to_string(),
            descriptor_regular_file: true,
            descriptor_read_only: true,
        };
        let encoded = serde_json::to_string(&view).unwrap();
        for key in [
            "\"commandId\"",
            "\"kind\"",
            "\"commandDigest\"",
            "\"ref\"",
            "\"applicationId\"",
            "\"versionId\"",
            "\"preparationGeneration\"",
            "\"revision\"",
            "\"valuesDigest\"",
            "\"fdDigest\"",
            "\"expiresAt\"",
            "\"fdBytesBase64\"",
            "\"descriptorRegularFile\"",
            "\"descriptorReadOnly\"",
        ] {
            assert!(encoded.contains(key), "handoff view must carry {key}: {encoded}");
        }
        assert!(!encoded.contains("command_id"), "snake_case keys must not leak to the supervisor wire");
    }
}
