//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1）：二进制入口的 argv
//! fail-closed——未知标记/元素数量不匹配时以 EX_USAGE(64) 退出，且不绑定 listener、
//! 不打印秘密。规范权威：spec "Wasmd has a fixed command and host-mediated network
//! contract"（Supervisor alone generates every argv element）。

use std::process::Command;

#[test]
fn bin_rejects_unknown_argv_with_usage_exit_code() {
    let binary = env!("CARGO_BIN_EXE_iweb-wasmd");
    // 完全空 argv（仅 argv[0]）→ 数量不匹配 → 64。
    let output = Command::new(binary).env_clear().output().expect("spawn");
    assert_eq!(output.status.code(), Some(64), "argv element-count mismatch must exit 64");
    assert!(String::from_utf8_lossy(&output.stderr).contains("WASMD_ARGV_INVALID"));

    // 未知标记 → 64。
    let output = Command::new(binary)
        .env_clear()
        .args(["--unknown-flag", "a", "b", "c", "d", "e", "f", "g"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(64), "unknown marker must exit 64");

    // 合法标记但数据错误（record 缺失）→ 数据级 fail-closed 65（EX_DATAERR），
    // 不是 usage 错。
    let marker = "--iweb-wasmd-argv@1";
    let output = Command::new(binary)
        .env_clear()
        .args([
            marker,
            "/nonexistent/component.wasm",
            "127.0.0.1:18787",
            "127.0.0.1:18081",
            "/nonexistent/node-capability.json",
            "linux/arm64",
            r#"{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"}"#,
            r#"{"capabilityRecordHash":"2222222222222222222222222222222222222222222222222222222222222222","capabilityRecordRevision":5,"configRevision":0,"configSnapshotRef":null,"configValuesDigest":null,"executionGeneration":1,"packageDigest":"0000000000000000000000000000000000000000000000000000000000000000","preparationGeneration":1,"runtimeBinding":{"catalogHash":"abababababababababababababababababababababababababababababababab","catalogRevision":9,"entryKey":"iweb-wasmd","hostABI":"iweb-wasmd-abi@1.0.0","imageDigest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"sandboxId":"sbx-vector","secretRevision":0,"secretValuesDigest":"6666666666666666666666666666666666666666666666666666666666666666","versionId":"a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532-1"}"#,
            r#"{"cpuMillis":500,"memoryBytes":268435456,"pidLimit":256,"storageBytes":1073741824}"#,
        ])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(65), "identity fd/record failure must exit 65");
}
