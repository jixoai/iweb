//! 用户原始需求（2026-08-15）：canonical 包摘要是跨实现契约（rust-kernel-rustfs-storage §3.2）。
//! TS 权威（contracts/package-collection.ts）的规则：sha256 依次更新每个文件的
//! (path, NUL 字节, 十进制长度, NUL 字节, content)，文件按 path 的 UTF-8 字节序排序（NOT localeCompare）。
//! 本模块必须与 golden vectors 逐字节一致——见 tests/golden_digest.rs（bun 侧吃同一份文件）。

use sha2::{Digest, Sha256};

/// 单个 canonical 包文件（与 fixtures JSON 的形状一致）。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PackageFile {
    pub path: String,
    #[serde(rename = "contentBase64")]
    pub content_base64: String,
}

/// 计算 canonical 摘要。排序键 = path 的 UTF-8 字节序（与 TS 的 Buffer.compare 一致）。
pub fn package_files_digest(files: &[PackageFile]) -> Result<String, &'static str> {
    use base64::Engine as _;
    if files.is_empty() {
        return Err("package must contain at least one file");
    }
    let mut decoded: Vec<(String, Vec<u8>)> = Vec::with_capacity(files.len());
    for file in files {
        if file.path.is_empty() || file.path.len() > 512 || file.path.starts_with('/') {
            return Err("unsafe package path");
        }
        let content = base64::engine::general_purpose::STANDARD
            .decode(file.content_base64.as_str())
            .map_err(|_| "invalid base64 content")?;
        decoded.push((file.path.clone(), content));
    }
    decoded.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut hasher = Sha256::new();
    for (path, content) in &decoded {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(content.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(content);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(data: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[test]
    fn rejects_empty_package() {
        assert!(package_files_digest(&[]).is_err());
    }

    #[test]
    fn ordering_is_byte_order_not_collation() {
        // ICU collation would order "ab" before "a-b" (dash is secondary-weighted);
        // the contract is byte order: '-' (0x2D) < 'b' (0x62), so "a-b" comes first.
        let files = vec![
            PackageFile { path: "ab.txt".into(), content_base64: b64(b"plain") },
            PackageFile { path: "a-b.txt".into(), content_base64: b64(b"dash") },
        ];
        let digest = package_files_digest(&files).unwrap();
        // Recompute with explicitly ordered input to prove the sort direction:
        // if sorting used collation, the digest would differ.
        let mut manual = Sha256::new();
        manual.update(b"a-b.txt");
        manual.update([0]);
        manual.update(b"4");
        manual.update([0]);
        manual.update(b"dash" as &[u8]);
        manual.update(b"ab.txt");
        manual.update([0]);
        manual.update(b"5");
        manual.update([0]);
        manual.update(b"plain" as &[u8]);
        assert_eq!(digest, hex::encode(manual.finalize()));
    }
}
