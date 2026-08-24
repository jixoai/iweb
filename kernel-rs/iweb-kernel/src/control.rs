//! 控制状态读取与投影（对位 contracts/control-db.ts 状态形状 + kernel/index.js
//! controlApplicationProjection）。写入路径（admit/activate）属 §4.3 后续；
//! 本模块先提供持久状态的读取投影——恢复语义的地基。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStateFile {
    pub version: u32,
    pub applications: BTreeMap<String, ApplicationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationRecord {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub active: ActiveVersionRecord,
    pub versions: Vec<VersionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
// serde tag 值保持 wire 形状 "active"（TS 契约），变体名走 Rust 惯例。
#[allow(non_camel_case_types)]
#[serde(tag = "kind")]
pub enum ActiveVersionRecord {
    #[serde(rename = "active")]
    Active {
        version: ActiveVersion,
        #[serde(rename = "routeGeneration", default = "default_generation_zero")]
        route_generation: u64,
    },
    #[serde(other)]
    None,
}

fn default_generation_zero() -> u64 {
    0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveVersion {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub digest: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRecord {
    #[serde(rename = "versionId")]
    pub version_id: String,
    pub identity: VersionIdentity,
    #[serde(rename = "packageDigest")]
    pub package_digest: String,
    pub lifecycle: String,
    #[serde(rename = "admittedAt")]
    pub admitted_at: String,
    #[serde(rename = "readinessExpiresAt")]
    pub readiness_expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionIdentity {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    pub digest: String,
    pub sequence: u64,
}

/// 读取并校验控制状态文件；缺失/损坏返回 None（对位 validateControlStateFile 的 null）。
pub fn read_state(path: &Path) -> Option<ControlStateFile> {
    let text = std::fs::read_to_string(path).ok()?;
    let parsed: ControlStateFile = serde_json::from_str(&text).ok()?;
    (parsed.version == 1).then_some(parsed)
}

/// 对位 deriveSandboxId：sbx- + sha256(app\0versionDigest\0sequence) 前 40 hex。
pub fn derive_sandbox_id(application_id: &str, version_digest: &str, sequence: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(application_id.as_bytes());
    hasher.update([0]);
    hasher.update(version_digest.as_bytes());
    hasher.update([0]);
    hasher.update(sequence.to_string().as_bytes());
    let hex = hex::encode(hasher.finalize());
    format!("sbx-{}", &hex[..40])
}

/// /v1/status 的应用投影（对位 controlApplicationProjection）：无采样时
/// resources 为 null（浏览器契约经 preprocess 归一化，绝不能缺键）。
pub fn project_application(app: &ApplicationRecord) -> serde_json::Value {
    let (active, route_generation) = match &app.active {
        ActiveVersionRecord::Active { version, route_generation } => (Some(version), *route_generation),
        ActiveVersionRecord::None => (None, 0),
    };
    let sandbox_id = active
        .map(|v| derive_sandbox_id(&v.application_id, &v.digest, v.sequence));
    let lifecycle = active
        .map(|v| {
            app.versions
                .iter()
                .find(|version| version.version_id == v.digest)
                .map(|version| version.lifecycle.clone())
                .unwrap_or_else(|| "failed".into())
        })
        .unwrap_or_else(|| "unavailable".into());
    serde_json::json!({
        "id": app.application_id,
        "sandboxId": sandbox_id,
        "activeVersion": active.map(|v| serde_json::json!({ "digest": v.digest, "sequence": v.sequence })),
        "routeGeneration": route_generation,
        "lifecycle": lifecycle,
        "lifecycle": lifecycle,
        "versions": app.versions.iter().map(|v| serde_json::json!({
            "versionId": v.version_id,
            "sequence": v.identity.sequence,
            "lifecycle": v.lifecycle,
            "admittedAt": v.admitted_at,
            "readinessExpiresAt": v.readiness_expires_at,
        })).collect::<Vec<_>>(),
        "resources": null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_sandbox_id_matches_js_shape() {
        // 与 TS deriveSandboxId("notes", <64 hex>, 1) 的形状对位（前缀 + 40 hex）。
        let id = derive_sandbox_id("notes", &"a".repeat(64), 1);
        assert!(id.starts_with("sbx-"));
        assert_eq!(id.len(), 4 + 40);
    }

    #[test]
    fn reads_seeded_state_file() {
        let text = r#"{"version":1,"applications":{"notes":{"applicationId":"notes","active":{"kind":"active","version":{"applicationId":"notes","digest":"a","sequence":1}},"versions":[{"versionId":"a","identity":{"applicationId":"notes","digest":"a","sequence":1},"packageDigest":"a","lifecycle":"active","admittedAt":"t","readinessExpiresAt":null}]}}}"#;
        let dir = std::env::temp_dir().join("iweb-kernel-test-state");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control-db.json");
        std::fs::write(&path, text).unwrap();
        let state = read_state(&path).expect("state must parse");
        let notes = state.applications.get("notes").unwrap();
        let projection = project_application(notes);
        assert_eq!(projection["lifecycle"], "active");
        assert_eq!(projection["activeVersion"]["digest"], "a");
        let _ = std::fs::remove_file(&path);
    }
}
