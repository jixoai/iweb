//! 凭据扫描（对位 contracts/credential-scan.ts）。
//! 只输出 <kind>:<label 哈希前 12 位> 与类别；绝不输出 secret 值/原始标签。
//! 九类位置 kind 全量（12.3 契约）；扫描永不抛错。

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

pub const MAX_SCAN_SECRETS: usize = 256;
pub const MAX_SCAN_LOCATIONS: usize = 10_000;
pub const LOCATION_DIGEST_LENGTH: usize = 12;

pub const LOCATION_KINDS: [&str; 9] = [
    "package", "sandbox-fs", "env-projection", "object-store", "admin-assets",
    "log", "monitor-frame", "test-output", "image-layer",
];

#[derive(Debug, Clone)]
pub struct ScanSecret {
    pub value: String,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct ScanLocation {
    pub kind: &'static str,
    pub label: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ScanFinding {
    pub location: String,
    pub category: String,
}

#[derive(Debug, serde::Serialize)]
pub struct CredentialScanResult {
    pub clean: bool,
    pub findings: Vec<ScanFinding>,
}

fn sanitize_location(kind: &str, label: &str) -> String {
    let digest = Sha256::digest(label.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{kind}:{}", &hex[..LOCATION_DIGEST_LENGTH])
}

/// 对位 scanForSecrets：值包含匹配（content 或 label），上限截断，确定性排序。
pub fn scan_for_secrets(secrets: &[ScanSecret], locations: &[ScanLocation]) -> CredentialScanResult {
    let mut findings: Vec<(String, String)> = Vec::new();
    for location in locations.iter().take(MAX_SCAN_LOCATIONS) {
        let mut found: Vec<&str> = Vec::new();
        for secret in secrets.iter().take(MAX_SCAN_SECRETS) {
            if secret.value.is_empty() {
                continue;
            }
            if (location.content.contains(&secret.value) || location.label.contains(&secret.value))
                && !found.contains(&secret.category.as_str())
            {
                found.push(&secret.category);
            }
        }
        if found.is_empty() {
            continue;
        }
        let sanitized = sanitize_location(location.kind, &location.label);
        for category in found {
            findings.push((sanitized.clone(), category.to_string()));
        }
    }
    findings.sort();
    findings.dedup();
    let clean = findings.is_empty();
    CredentialScanResult { clean, findings: findings.into_iter().map(|(location, category)| ScanFinding { location, category }).collect() }
}

static PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        ("aws-access-key-id", Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("aws pattern")),
        ("private-key-block", Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----").expect("key pattern")),
		("credential-url", Regex::new(r#"://[^\s/:@]+:[^\s/@]+@[^\s/"']+[:/]"#).expect("url pattern")),
		("owner-token-assignment", Regex::new(r#"\bIWEB_API_TOKEN\b[^\n]{0,40}[:=][^\n]{0,4}["']?[^\s"']{8,}"#).expect("token pattern")),
        ("mc-host-secret", Regex::new(r"(?i)\bMC_HOST[A-Z_]*=https?://[^\s@]+:[^\s@]+@").expect("mc pattern")),
    ]
});

/// 对位 scanForCredentialPatterns：已知凭据形状探测。
pub fn scan_for_credential_patterns(locations: &[ScanLocation]) -> CredentialScanResult {
    let mut findings: Vec<(String, String)> = Vec::new();
    for location in locations.iter().take(MAX_SCAN_LOCATIONS) {
        let sanitized = sanitize_location(location.kind, &location.label);
        for (id, pattern) in PATTERNS.iter() {
            if pattern.is_match(&location.content) {
                findings.push((sanitized.clone(), (*id).to_string()));
            }
        }
    }
    findings.sort();
    findings.dedup();
    let clean = findings.is_empty();
    CredentialScanResult { clean, findings: findings.into_iter().map(|(location, category)| ScanFinding { location, category }).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nine_location_kinds_are_declared() {
        assert_eq!(LOCATION_KINDS.len(), 9);
        assert!(LOCATION_KINDS.contains(&"sandbox-fs"));
    }

    #[test]
    fn sanitized_location_matches_ts_golden() {
        // bun scanForSecrets 同输入：location = log:e9e4927eb6a9（跨语言一致）。
        let locations = vec![ScanLocation { kind: "log", label: "kernel.log".into(), content: "token abc123XYZ inside".into() }];
        let secrets = vec![ScanSecret { value: "abc123XYZ".into(), category: "owner-token".into() }];
        let result = scan_for_secrets(&secrets, &locations);
        assert_eq!(result.findings[0].location, "log:e9e4927eb6a9");
    }

    #[test]
    fn secret_scan_finds_and_sanitizes() {
        let locations = vec![ScanLocation { kind: "log", label: "kernel.log".into(), content: "token abc123XYZ inside".into() }];
        let secrets = vec![ScanSecret { value: "abc123XYZ".into(), category: "owner-token".into() }];
        let result = scan_for_secrets(&secrets, &locations);
        assert!(!result.clean);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].location.starts_with("log:"));
        assert_eq!(result.findings[0].location.len(), 4 + LOCATION_DIGEST_LENGTH);
        assert!(!result.findings[0].location.contains("kernel.log"), "raw label never emitted");
        // clean case
        let clean_locations = vec![ScanLocation { kind: "package", label: "app.tgz".into(), content: "nothing".into() }];
        assert!(scan_for_secrets(&secrets, &clean_locations).clean);
    }

    #[test]
    fn pattern_scan_catches_known_shapes() {
        let locations = vec![
            ScanLocation { kind: "test-output", label: "a".into(), content: "AKIAIOSFODNN7EXAMPLE key".into() },
            ScanLocation { kind: "image-layer", label: "b".into(), content: "-----BEGIN RSA PRIVATE KEY-----".into() },
            ScanLocation { kind: "monitor-frame", label: "c".into(), content: "https://user:pass@example.com:8080/x".into() },
        ];
        let result = scan_for_credential_patterns(&locations);
        assert!(!result.clean);
        let categories: Vec<&str> = result.findings.iter().map(|f| f.category.as_str()).collect();
        assert!(categories.contains(&"aws-access-key-id"));
        assert!(categories.contains(&"private-key-block"));
        assert!(categories.contains(&"credential-url"));
    }

    #[test]
    fn caps_are_enforced() {
        let secrets: Vec<ScanSecret> = (0..MAX_SCAN_SECRETS + 10).map(|i| ScanSecret { value: format!("v{i}"), category: "c".into() }).collect();
        let locations: Vec<ScanLocation> = (0..MAX_SCAN_LOCATIONS + 5).map(|i| ScanLocation { kind: "log", label: format!("l{i}"), content: format!("hit v{}", i % 50) }).collect();
        let result = scan_for_secrets(&secrets, &locations);
        assert!(result.findings.len() <= MAX_SCAN_LOCATIONS, "location cap");
    }
}
