//! Workspace 文件面（对位 kernel/index.js listWorkspaceFiles/readWorkspaceFile/
//! writeWorkspaceFile/deleteWorkspaceFile）。经 mc 子进程访问对象存储——与 JS 同构；
//! §6 存储切换只改端点配置，不改本模块语义。

use std::process::Command;

pub struct Workspace {
    pub object: String,
}

#[derive(Debug)]
pub struct WorkspaceError(pub String);

impl Workspace {
    /// 列出（可选前缀）文件；返回 (path, size, lastModified)。
    pub fn list(&self, prefix: &str) -> Result<Vec<(String, u64, String)>, WorkspaceError> {
        let output = Command::new("mc")
            .args(["ls", "--json", "--recursive", &self.object])
            .output()
            .map_err(|e| WorkspaceError(format!("workspace listing failed: {e}")))?;
        if !output.status.success() {
            return Err(WorkspaceError(format!(
                "workspace listing failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut files = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            if record.get("status").and_then(|v| v.as_str()) != Some("success") { continue; }
            if record.get("type").and_then(|v| v.as_str()) != Some("file") { continue; }
            let Some(key) = record.get("key").and_then(|v| v.as_str()) else { continue };
            if !prefix.is_empty() && key != prefix && !key.starts_with(&format!("{prefix}/")) { continue; }
            let size = record.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let modified = record.get("lastModified").and_then(|v| v.as_str()).unwrap_or("").to_string();
            files.push((key.to_string(), size, modified));
        }
        Ok(files)
    }

    pub fn read(&self, path: &str) -> Result<String, WorkspaceError> {
        let output = Command::new("mc")
            .args(["cat", &format!("{}/{}", self.object, path)])
            .output()
            .map_err(|e| WorkspaceError(format!("workspace read failed: {e}")))?;
        if !output.status.success() {
            return Err(WorkspaceError(format!(
                "workspace read failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// 对位 writeWorkspaceFile：正文 ≤1MiB，经临时文件 + mc cp（原子替换）。
    pub fn write(&self, path: &str, content: &str) -> Result<u64, WorkspaceError> {
        let bytes = content.len();
        if bytes > 1024 * 1024 {
            return Err(WorkspaceError("workspace file is limited to 1 MiB".into()));
        }
        let temporary = std::env::temp_dir().join(format!(
            "iweb-workspace-{}-{}",
            std::process::id(),
            crate::monitor::now_millis()
        ));
        let result = (|| {
            std::fs::write(&temporary, content)
                .map_err(|e| WorkspaceError(format!("workspace write failed: {e}")))?;
            let output = Command::new("mc")
                .args(["cp", temporary.to_str().unwrap_or_default(), &format!("{}/{}", self.object, path)])
                .output()
                .map_err(|e| WorkspaceError(format!("workspace write failed: {e}")))?;
            if !output.status.success() {
                return Err(WorkspaceError(format!(
                    "workspace write failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            Ok(bytes as u64)
        })();
        let _ = std::fs::remove_file(&temporary);
        result
    }

    /// 对位 deleteWorkspaceFile。
    pub fn delete(&self, path: &str) -> Result<(), WorkspaceError> {
        let output = Command::new("mc")
            .args(["rm", &format!("{}/{}", self.object, path)])
            .output()
            .map_err(|e| WorkspaceError(format!("workspace delete failed: {e}")))?;
        if !output.status.success() {
            return Err(WorkspaceError(format!(
                "workspace delete failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }
}

/// 对位 normalizeWorkspacePath：相对安全路径（无 ..、绝对、控制字符），≤512。
pub fn normalize_workspace_path(input: &str) -> Result<String, String> {
    if input.is_empty() {
        return Err("workspace path must not be empty".into());
    }
    if input.len() > 512 || input.starts_with('/') || input.contains('\u{0}') {
        return Err("workspace path is not a safe relative path".into());
    }
    for segment in input.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("workspace path is not a safe relative path".into());
        }
    }
    Ok(input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_and_rejects() {
        assert!(normalize_workspace_path("admin/app/index.html").is_ok());
        assert!(normalize_workspace_path("../etc/passwd").is_err());
        assert!(normalize_workspace_path("/abs").is_err());
        assert!(normalize_workspace_path("a//b").is_err());
        assert!(normalize_workspace_path("").is_err());
    }
}
