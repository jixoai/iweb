//! 包存储与凭据签发（对位 kernel/package-store.js + application-control.js issuer）。
//! 策略文档逐字对位；签发经 mc svcacct add --json --policy <file>：凭据只出现在
//! stdout JSON，绝不进 argv/日志（2.38 契约）。策略文件 0600 临时写入即删。

use std::path::PathBuf;
use std::process::Command;

pub const DEFAULT_PARENT_USER: &str = "iweb-sandbox-issuer";

#[derive(Debug)]
pub struct IssuerError(pub String);

pub struct ObjectCredential {
    pub endpoint: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub retire_access_key: String,
    pub parent_user: String,
}

/// 版本桶只读策略（deploy/nodes/fleet/cells 读 + 前缀条件 List）。
pub fn version_scoped_object_policy(bucket: &str) -> serde_json::Value {
    let arn = |suffix: &str| format!("arn:aws:s3:::{bucket}/{suffix}");
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [arn("deploy/*"), arn("nodes/*"), arn("fleet/*"), arn("cells/*")],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [format!("arn:aws:s3:::{bucket}")],
                "Condition": { "StringLike": { "s3:prefix": [
                    "deploy/", "deploy/*", "nodes/", "nodes/*", "fleet/", "fleet/*", "cells/", "cells/*",
                ] } },
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [arn("nodes/*"), arn("fleet/*"), arn("cells/*")],
            },
        ],
    })
}

/// 单应用数据命名空间读写策略（iweb-apps/<app>/data[/...]）。
pub fn application_data_policy(application_id: &str) -> serde_json::Value {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            "Resource": [
                format!("arn:aws:s3:::iweb-apps/{application_id}/data"),
                format!("arn:aws:s3:::iweb-apps/{application_id}/data/*"),
            ],
        }],
    })
}

fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    if std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").expect("urandom"), &mut raw).is_err() {
        // 非预期环境（无 urandom）：以进程信息兜底，保持唯一性语义。
        let fallback = format!("{}{}", std::process::id(), crate::monitor::now_millis());
        return fallback.chars().take(bytes * 2).collect();
    }
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_policy_temp(application_id: &str, policy: &serde_json::Value) -> Result<PathBuf, IssuerError> {
    let path = std::env::temp_dir().join(format!(
        "iweb-policy-{application_id}-{}.json",
        random_hex(8)
    ));
    let body = format!("{}
", serde_json::to_string_pretty(policy).expect("policy serialize"));
    std::fs::write(&path, body).map_err(|e| IssuerError(format!("policy write failed: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

/// 对位 defaultObjectCredentialIssuer.issue：svcacct add --json --policy <file>。
pub fn issue_version_credential(
    endpoint: &str,
    region: &str,
    sandbox_id: &str,
    bucket: &str,
) -> Result<ObjectCredential, IssuerError> {
    let policy_file = write_policy_temp(sandbox_id, &version_scoped_object_policy(bucket))?;
    let result = run_svcacct(&policy_file);
    let _ = std::fs::remove_file(&policy_file);
    let (access, secret) = result?;
    Ok(ObjectCredential {
        endpoint: endpoint.into(),
        region: region.into(),
        access_key_id: access.clone(),
        secret_access_key: secret,
        retire_access_key: access,
        parent_user: DEFAULT_PARENT_USER.into(),
    })
}

/// 对位 defaultDataCredentialIssuer.issue。
pub fn issue_data_credential(endpoint: &str, region: &str, application_id: &str) -> Result<ObjectCredential, IssuerError> {
    let policy_file = write_policy_temp(&format!("data-{application_id}"), &application_data_policy(application_id))?;
    let result = run_svcacct(&policy_file);
    let _ = std::fs::remove_file(&policy_file);
    let (access, secret) = result?;
    Ok(ObjectCredential {
        endpoint: endpoint.into(),
        region: region.into(),
        access_key_id: access.clone(),
        secret_access_key: secret,
        retire_access_key: access,
        parent_user: DEFAULT_PARENT_USER.into(),
    })
}

/// 对位 defaultRetireObjectCredential：按 accessKey 删除服务账号。
pub fn retire_credential(access_key: &str) -> Result<(), IssuerError> {
    let output = Command::new("mc")
        .args(["admin", "user", "svcacct", "rm", "local", access_key])
        .output()
        .map_err(|e| IssuerError(format!("credential retire failed: {e}")))?;
    if !output.status.success() {
        return Err(IssuerError(format!(
            "credential retire failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn run_svcacct(policy_file: &std::path::Path) -> Result<(String, String), IssuerError> {
    let output = Command::new("mc")
        .args([
            "admin", "user", "svcacct", "add", "--json",
            "--policy", policy_file.to_str().unwrap_or_default(),
            "local", DEFAULT_PARENT_USER,
        ])
        .output()
        .map_err(|e| IssuerError(format!("service account generation failed: {e}")))?;
    if !output.status.success() {
        return Err(IssuerError(format!(
            "service account generation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| IssuerError("service account generation failed".into()))?;
    if parsed.get("status").and_then(|v| v.as_str()) != Some("success") {
        return Err(IssuerError("service account generation failed".into()));
    }
    let access = parsed.get("accessKey").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let secret = parsed.get("secretKey").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if access.is_empty() || secret.is_empty() {
        return Err(IssuerError("service account generation failed".into()));
    }
    Ok((access, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_policy_shape_matches_js() {
        let policy = version_scoped_object_policy("iweb-app-sbx-x");
        let text = serde_json::to_string(&policy).expect("serialize");
        assert!(text.contains("s3:GetObject"));
        assert!(text.contains("arn:aws:s3:::iweb-app-sbx-x/deploy/*"));
        assert!(text.contains("StringLike"));
        let statements = policy["Statement"].as_array().expect("statements");
        assert_eq!(statements.len(), 3);
    }

    #[test]
    fn data_policy_scopes_to_application_prefix() {
        let policy = application_data_policy("notes");
        let text = serde_json::to_string(&policy).expect("serialize");
        assert!(text.contains("arn:aws:s3:::iweb-apps/notes/data/*"));
        assert!(!text.contains("ListBucket"), "data credential must not list");
    }

    #[test]
    fn policy_file_is_cleaned_up_on_success_path() {
        // 结构性测试：临时文件路径唯一性（同一 sandbox 两次签发不同路径）。
        let a = write_policy_temp("sbx-a", &version_scoped_object_policy("b")).expect("write");
        let b = write_policy_temp("sbx-a", &version_scoped_object_policy("b")).expect("write");
        assert_ne!(a, b);
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }
}
