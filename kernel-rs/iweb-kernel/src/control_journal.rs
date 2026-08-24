//! 控制日志写路径（对位 contracts/control-db.ts 纯函数状态机）。
//! 契约：DUPLICATE_VERSION/UNKNOWN_APPLICATION/UNKNOWN_VERSION/NOT_READY 错误码、
//! content-addressed versionId（sha256("package:"+d+"\0"+"manifest:"+canonical)）、
//! 原子 active 指针切换 + routeGeneration 递增 + 旧版本保留（回滚即重激活）。

use crate::control::{ActiveVersion, ActiveVersionRecord, ApplicationRecord, VersionIdentity, VersionRecord};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ControlState {
    pub applications: BTreeMap<String, ApplicationRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdmissionOk {
    pub state: ControlState,
    pub version: VersionRecord,
}

/// 对位 canonicalSerializeManifest：键排序 + 2 空格缩进（serde_json BTreeMap 天然有序）。
pub fn canonical_serialize_manifest(manifest: &serde_json::Value) -> String {
    serde_json::to_string_pretty(manifest).expect("manifest serialize")
}

/// 对位 versionDigest：sha256("package:"+packageDigest+"\0"+"manifest:"+canonical)。
pub fn version_digest(package_digest: &str, manifest: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("package:{package_digest}"));
    hasher.update([0]);
    hasher.update(format!("manifest:{}", canonical_serialize_manifest(manifest)));
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 对位 admitVersion。lifecycle 起点恒 "admitted"。
pub fn admit_version(state: &ControlState, application_id: &str, package_digest: &str, manifest: &serde_json::Value, admitted_at: &str) -> Result<AdmissionOk, &'static str> {
    let digest = version_digest(package_digest, manifest);
    if let Some(existing) = state.applications.get(application_id) {
        if existing.versions.iter().any(|version| version.version_id == digest) {
            return Err("DUPLICATE_VERSION");
        }
    }
    let existing = state.applications.get(application_id);
    let sequence = existing.map(|app| app.versions.len()).unwrap_or(0) as u64 + 1;
    let identity = VersionIdentity { application_id: application_id.into(), digest: digest.clone(), sequence };
    let version = VersionRecord {
        version_id: digest.clone(),
        identity,
        package_digest: package_digest.into(),
        lifecycle: "admitted".into(),
        admitted_at: admitted_at.into(),
        readiness_expires_at: None,
    };
    let mut applications = state.applications.clone();
    let application = match existing {
        Some(app) => {
            let mut versions = app.versions.clone();
            versions.push(version.clone());
            ApplicationRecord { application_id: app.application_id.clone(), active: clone_active(&app.active), versions }
        }
        None => ApplicationRecord {
            application_id: application_id.into(),
            active: ActiveVersionRecord::None,
            versions: vec![version.clone()],
        },
    };
    applications.insert(application_id.into(), application);
    Ok(AdmissionOk { state: ControlState { applications }, version })
}

fn clone_active(active: &ActiveVersionRecord) -> ActiveVersionRecord {
    match active {
        ActiveVersionRecord::Active { version, route_generation } => ActiveVersionRecord::Active { version: version.clone(), route_generation: *route_generation },
        ActiveVersionRecord::None => ActiveVersionRecord::None,
    }
}

/// 对位 markVersionReady。
pub fn mark_version_ready(state: &ControlState, application_id: &str, version_id: &str, expires_at: &str) -> Result<(ControlState, VersionRecord), &'static str> {
    let Some(application) = state.applications.get(application_id) else {
        return Err("UNKNOWN_APPLICATION");
    };
    let Some(candidate) = application.versions.iter().find(|version| version.version_id == version_id) else {
        return Err("UNKNOWN_VERSION");
    };
    let mut updated = candidate.clone();
    updated.lifecycle = "ready".into();
    updated.readiness_expires_at = Some(expires_at.into());
    let state = with_version(state, application_id, &updated);
    Ok((state, updated))
}

/// 对位 activateVersion（rollbackVersion 同函数）：原子指针切换 + generation+1 + 旧版本 retired。
pub fn activate_version(state: &ControlState, application_id: &str, version_id: &str) -> Result<(ControlState, Option<VersionRecord>), &'static str> {
    let Some(application) = state.applications.get(application_id) else {
        return Err("UNKNOWN_APPLICATION");
    };
    let Some(candidate) = application.versions.iter().find(|version| version.version_id == version_id) else {
        return Err("UNKNOWN_VERSION");
    };
    if candidate.lifecycle != "ready" {
        return Err("NOT_READY");
    }
    let previous_digest = match &application.active {
        ActiveVersionRecord::Active { version, .. } => Some(version.digest.clone()),
        ActiveVersionRecord::None => None,
    };
    let retired = previous_digest.as_deref().and_then(|digest| {
        application.versions.iter().find(|version| version.version_id == digest).cloned()
    });
    let generation = route_generation(&application.active) + 1;
    let active = ActiveVersionRecord::Active {
        version: ActiveVersion { application_id: application_id.into(), digest: candidate.identity.digest.clone(), sequence: candidate.identity.sequence },
        route_generation: generation,
    };
    let mut versions = Vec::with_capacity(application.versions.len());
    for version in &application.versions {
        let mut next = version.clone();
        if version.version_id == version_id {
            next.lifecycle = "active".into();
        } else if Some(version.version_id.as_str()) == previous_digest.as_deref() {
            next.lifecycle = "retired".into();
        }
        versions.push(next);
    }
    let mut applications = state.applications.clone();
    applications.insert(application_id.into(), ApplicationRecord { application_id: application_id.into(), active, versions });
    Ok((ControlState { applications }, retired))
}

pub fn rollback_version(state: &ControlState, application_id: &str, version_id: &str) -> Result<(ControlState, Option<VersionRecord>), &'static str> {
    activate_version(state, application_id, version_id)
}

/// 单写者持久化：原子写（tmp + rename）。wire 形状 = contracts ControlStateFile。
pub fn persist_state(path: &std::path::Path, state: &ControlState) -> Result<(), String> {
    let file = crate::control::ControlStateFile { version: 1, applications: state.applications.clone() };
    let body = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    let temporary = path.with_extension(format!("tmp-{}", crate::monitor::now_millis()));
    std::fs::write(&temporary, body + "\n").map_err(|e| e.to_string())?;
    std::fs::rename(&temporary, path).map_err(|e| e.to_string())
}

fn route_generation(active: &ActiveVersionRecord) -> u64 {
    match active {
        ActiveVersionRecord::Active { route_generation, .. } => *route_generation,
        ActiveVersionRecord::None => 0,
    }
}

fn with_version(state: &ControlState, application_id: &str, updated: &VersionRecord) -> ControlState {
    let mut applications = state.applications.clone();
    if let Some(application) = applications.get_mut(application_id) {
        for version in application.versions.iter_mut() {
            if version.version_id == updated.version_id {
                *version = updated.clone();
            }
        }
    }
    ControlState { applications }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> serde_json::Value {
        serde_json::json!({ "name": "notes", "runtime": { "entrypoint": "index.js" }, "assets": { "root": "app" } })
    }

    #[test]
    fn version_digest_is_content_addressed_and_stable() {
        let a = version_digest(&"a".repeat(64), &manifest());
        let b = version_digest(&"a".repeat(64), &manifest());
        let c = version_digest(&"b".repeat(64), &manifest());
        assert_eq!(a, b, "same inputs same digest");
        assert_ne!(a, c, "digest changes with package digest");
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn admit_duplicate_rejected_and_sequence_increments() {
        let state = ControlState::default();
        let first = admit_version(&state, "notes", &"a".repeat(64), &manifest(), "t1").expect("admit");
        assert_eq!(first.version.identity.sequence, 1);
        assert_eq!(first.version.lifecycle, "admitted");
        assert!(matches!(first.state.applications["notes"].active, ActiveVersionRecord::None));
        let dup = admit_version(&first.state, "notes", &"a".repeat(64), &manifest(), "t2");
        assert_eq!(dup.unwrap_err(), "DUPLICATE_VERSION");
        let second = admit_version(&first.state, "notes", &"b".repeat(64), &manifest(), "t3").expect("admit2");
        assert_eq!(second.version.identity.sequence, 2);
    }

    #[test]
    fn activate_requires_ready_and_retires_previous() {
        let state = ControlState::default();
        let admitted = admit_version(&state, "notes", &"a".repeat(64), &manifest(), "t").expect("admit");
        let not_ready = activate_version(&admitted.state, "notes", &admitted.version.version_id);
        assert_eq!(not_ready.unwrap_err(), "NOT_READY");
        let (ready_state, _) = mark_version_ready(&admitted.state, "notes", &admitted.version.version_id, "2099-01-01T00:00:00Z").expect("ready");
        let (active_state, retired) = activate_version(&ready_state, "notes", &admitted.version.version_id).expect("activate");
        assert!(retired.is_none(), "first activation retires nothing");
        assert!(matches!(active_state.applications["notes"].active, ActiveVersionRecord::Active { .. }));
        // 再 admit 第二版本 → ready → 激活：旧版本 retired
        let second = admit_version(&active_state, "notes", &"c".repeat(64), &manifest(), "t2").expect("admit2");
        let (ready2, _) = mark_version_ready(&second.state, "notes", &second.version.version_id, "2099-01-01T00:00:00Z").expect("ready2");
        let (second_active, _) = activate_version(&ready2, "notes", &second.version.version_id).expect("activate-second");
        // 7.3 语义：回滚目标也要先过同一 ready 门（重新探活）。
        let (ready3, _) = mark_version_ready(&second_active, "notes", &admitted.version.version_id, "2099-01-01T00:00:00Z").expect("ready-first");
        let (rolled, retired2) = rollback_version(&ready3, "notes", &admitted.version.version_id).expect("rollback");
        let retired_record = retired2.expect("second activation retires previous");
        assert_eq!(retired_record.version_id, second.version.version_id);
        assert!(matches!(rolled.applications["notes"].active, ActiveVersionRecord::Active { .. }));
    }

    #[test]
    fn unknown_application_and_version_codes() {
        let state = ControlState::default();
        assert_eq!(activate_version(&state, "ghost", "x").unwrap_err(), "UNKNOWN_APPLICATION");
        let admitted = admit_version(&state, "app", &"a".repeat(64), &manifest(), "t").expect("admit");
        assert_eq!(activate_version(&admitted.state, "app", "ghost").unwrap_err(), "UNKNOWN_VERSION");
    }
}
