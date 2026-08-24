//! Notes 迁移（对位 contracts/notes-migration.ts）。
//! digest = sha256(排序后 id \0 content \0 串联)；排序取 UTF-8 字节序
//! （与 package digest 同一加固决策；对 ASCII id 与 localeCompare 等价，
//! 跨语言 golden 用 bun 侧同输入证明一致）。dry-run 永不写入。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotesRecord {
    pub id: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct NotesExport {
    pub records: Vec<NotesRecord>,
    pub count: usize,
    pub digest: String,
}

pub fn notes_digest(records: &[NotesRecord]) -> String {
    let mut sorted: Vec<&NotesRecord> = records.iter().collect();
    sorted.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
    let mut hasher = Sha256::new();
    for record in sorted {
        hasher.update(record.id.as_bytes());
        hasher.update([0]);
        hasher.update(record.content.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn export_notes(records: Vec<NotesRecord>) -> NotesExport {
    let count = records.len();
    let digest = notes_digest(&records);
    NotesExport { records, count, digest }
}

pub fn verify_notes_equality(exported: &NotesExport, imported: &[NotesRecord]) -> (bool, usize) {
    let equal = imported.len() == exported.count && notes_digest(imported) == exported.digest;
    (equal, imported.len())
}

#[derive(Debug, Serialize)]
pub struct DryRunReport {
    pub count: usize,
    pub digest: String,
    pub repeatable: bool,
    #[serde(rename = "rollbackInputs")]
    pub rollback_inputs: RollbackInputs,
    pub destructive: bool,
}

#[derive(Debug, Serialize)]
pub struct RollbackInputs {
    #[serde(rename = "backupDigest")]
    pub backup_digest: String,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
}

/// 非破坏验证：读两次证明可重复；导出即回滚备份。绝不写入。
pub fn dry_run_verification(records: &[NotesRecord]) -> DryRunReport {
    let first = export_notes(records.to_vec());
    let second = notes_digest(records);
    DryRunReport {
        count: first.count,
        digest: first.digest.clone(),
        repeatable: first.digest == second,
        rollback_inputs: RollbackInputs { backup_digest: first.digest, record_count: first.count },
        destructive: false,
    }
}

#[derive(Debug, Serialize)]
pub struct MigrationReport {
    pub mode: &'static str,
    pub count: usize,
    pub digest: String,
    pub repeatable: bool,
    #[serde(rename = "rollbackInputs")]
    pub rollback_inputs: RollbackInputs,
    pub imported: Option<ImportedReport>,
}

#[derive(Debug, Serialize)]
pub struct ImportedReport {
    pub equal: bool,
    pub count: usize,
}

/// 对位 migrateNotes：dry-run 只读；migrate 写目标并回读校验相等。
pub fn migrate_notes(
    source: &[NotesRecord],
    target: Option<(&mut Vec<NotesRecord>, Option<&[NotesRecord]>)>,
    dry_run: bool,
) -> MigrationReport {
    let verification = dry_run_verification(source);
    if dry_run {
        return MigrationReport { mode: "dry-run", count: verification.count, digest: verification.digest, repeatable: verification.repeatable, rollback_inputs: verification.rollback_inputs, imported: None };
    }
    let Some((write_target, read_target)) = target else {
        return MigrationReport { mode: "dry-run", count: verification.count, digest: verification.digest, repeatable: verification.repeatable, rollback_inputs: verification.rollback_inputs, imported: None };
    };
    let exported = source.to_vec();
    let exported_digest = notes_digest(&exported);
    *write_target = exported.clone();
    let target_records: Vec<NotesRecord> = read_target.map(|slice| slice.to_vec()).unwrap_or(exported);
    let (equal, count) = verify_notes_equality(
        &NotesExport { records: source.to_vec(), count: source.len(), digest: exported_digest },
        &target_records,
    );
    MigrationReport {
        mode: "migrate",
        count: verification.count,
        digest: verification.digest,
        repeatable: verification.repeatable,
        rollback_inputs: verification.rollback_inputs,
        imported: Some(ImportedReport { equal, count }),
    }
}

/// 对位 createDurableObjectExportSource：严格记录校验（id 1..=512、content 字符串），
/// 任何非法记录中止读取——半份数据绝不进导入。
pub fn validate_durable_object_state(raw: &[serde_json::Value]) -> Result<Vec<NotesRecord>, String> {
    let mut records = Vec::with_capacity(raw.len());
    for entry in raw {
        let Some(object) = entry.as_object() else {
            return Err("durable object record is malformed".into());
        };
        let id = object.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        if id.is_empty() || id.len() > 512 {
            return Err("durable object record id is invalid".into());
        }
        let Some(content) = object.get("content").and_then(|v| v.as_str()) else {
            return Err("durable object record content is invalid".into());
        };
        records.push(NotesRecord { id: id.into(), content: content.into() });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<NotesRecord> {
        vec![
            NotesRecord { id: "b-uuid".into(), content: "second".into() },
            NotesRecord { id: "a-uuid".into(), content: "first".into() },
        ]
    }

    #[test]
    fn digest_matches_ts_golden() {
        // bun notesDigest 同输入向量（含非 ASCII）：跨语言字节一致。
        let records = vec![
            NotesRecord { id: "b-uuid".into(), content: "second".into() },
            NotesRecord { id: "a-uuid".into(), content: "first".into() },
            NotesRecord { id: "c-键".into(), content: "内容".into() },
        ];
        assert_eq!(notes_digest(&records), "e15b59da3ae494be5ccac2217c5cd502f2ef94c3cc851d7763d7e19d498d18ae");
    }

    #[test]
    fn digest_is_order_independent_and_stable() {
        assert_eq!(notes_digest(&sample()), notes_digest(&sample()));
        let mut reordered = sample();
        reordered.reverse();
        assert_eq!(notes_digest(&sample()), notes_digest(&reordered));
        assert_eq!(notes_digest(&sample()).len(), 64);
    }

    #[test]
    fn dry_run_is_non_destructive_and_repeatable() {
        let report = dry_run_verification(&sample());
        assert!(!report.destructive);
        assert!(report.repeatable);
        assert_eq!(report.count, 2);
        assert_eq!(report.rollback_inputs.record_count, 2);
    }

    #[test]
    fn migrate_verifies_equality_and_detects_tamper() {
        let source = sample();
        let mut target = Vec::new();
        let report = migrate_notes(&source, Some((&mut target, None)), false);
        assert_eq!(report.mode, "migrate");
        assert_eq!(report.imported.as_ref().expect("imported").count, 2);
        assert!(report.imported.as_ref().expect("imported").equal);
        // 回读被篡改的目标 → equal=false
        let tampered = vec![NotesRecord { id: "a-uuid".into(), content: "TAMPERED".into() }];
        let (equal, _) = verify_notes_equality(
            &NotesExport { records: source.clone(), count: 2, digest: notes_digest(&source) },
            &tampered,
        );
        assert!(!equal);
    }

    #[test]
    fn durable_object_validation_aborts_on_bad_record() {
        let good = serde_json::json!([{ "id": "x", "content": "c" }]);
        assert!(validate_durable_object_state(good.as_array().unwrap()).is_ok());
        let bad_id = serde_json::json!([{ "id": "", "content": "c" }]);
        assert!(validate_durable_object_state(bad_id.as_array().unwrap()).is_err());
        let bad_content = serde_json::json!([{ "id": "x", "content": 5 }]);
        assert!(validate_durable_object_state(bad_content.as_array().unwrap()).is_err());
    }
}
