//! rust-kernel-rustfs-storage §3.2：cargo 侧消费 contracts/fixtures/digest-vectors.json。
//! bun 侧（tests/digest-vectors.test.ts）吃同一份文件——跨实现摘要逐字节一致的直接证明。

use iweb_kernel::digest::{package_files_digest, PackageFile};
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    files: Vec<PackageFile>,
    digest: String,
}

#[derive(serde::Deserialize)]
struct FixtureDoc {
    version: u32,
    cases: Vec<Vector>,
}

fn load_vectors() -> FixtureDoc {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/contracts/fixtures/digest-vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("fixture JSON must parse")
}

#[test]
fn fixture_version_is_pinned() {
    let doc = load_vectors();
    assert_eq!(doc.version, 1);
    assert!(doc.cases.len() >= 6, "expected at least 6 vectors");
}

#[test]
fn all_golden_digests_match() {
    let doc = load_vectors();
    for vector in &doc.cases {
        let digest = package_files_digest(&vector.files)
            .unwrap_or_else(|e| panic!("vector {}: {e}", vector.name));
        assert_eq!(
            digest, vector.digest,
            "vector {} diverged from the TS authority",
            vector.name
        );
    }
}

#[test]
fn vectors_cover_collation_divergence() {
    let doc = load_vectors();
    let names: Vec<&str> = doc.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"collation-divergence-punctuation"));
    assert!(names.contains(&"collation-divergence-case"));
    assert!(names.contains(&"collation-divergence-accent"));
}
