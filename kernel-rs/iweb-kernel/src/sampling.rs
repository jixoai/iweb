//! 采样面（对位 kernel/index.js refreshCelldRss + memorySnapshot）：
//! - celld per-app 进程 RSS：pidfile → /proc/<pid>/status VmRSS；缺失/退出 → 无采样
//!   （绝不伪造 0，10.4 语义）。
//! - 节点容器内存：cgroup v2 memory.current / memory.max（不可用 → unavailable）。

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub bytes: u64,
    pub sampled_at: String,
}

#[derive(Default)]
pub struct CelldSamples {
    inner: Mutex<HashMap<String, Sample>>,
}

impl CelldSamples {
    pub fn current(&self, app: &str) -> Option<Sample> {
        self.inner.lock().expect("sample lock").get(app).cloned()
    }

    fn set(&self, app: &str, sample: Sample) {
        self.inner.lock().expect("sample lock").insert(app.into(), sample);
    }

    fn clear(&self, app: &str) {
        self.inner.lock().expect("sample lock").remove(app);
    }
}

/// 对位 refreshCelldRss：对 CELLD_PORTS 的每个 app（notes 除外）读 pidfile RSS。
pub fn refresh_celld_rss(samples: &CelldSamples, ports: &HashMap<String, u16>, pids_dir: &str) {
    for app in ports.keys() {
        if app == "notes" {
            continue; // 沙箱迁移前默认不运行
        }
        let rss = read_process_rss(Path::new(pids_dir).join(format!("celld-{app}.pid")));
        match rss {
            Some(bytes) => samples.set(app, Sample { bytes, sampled_at: crate::monitor::iso_now() }),
            None => samples.clear(app),
        }
    }
}

/// pidfile → /proc/<pid>/status VmRSS（字节）。任一步失败返回 None。
pub fn read_process_rss(pidfile: std::path::PathBuf) -> Option<u64> {
    let text = std::fs::read_to_string(pidfile).ok()?;
    let pid: u32 = text.trim().parse().ok()?;
    if pid == 0 {
        return None;
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryValue {
    Bytes(u64),
    Unavailable,
}

/// 容器内存封套（对位 memorySnapshot 的 cgroup 读法）。
pub fn container_memory() -> (MemoryValue, MemoryValue) {
    (cgroup_value("/sys/fs/cgroup/memory.current"), cgroup_value("/sys/fs/cgroup/memory.max"))
}

fn cgroup_value(path: &str) -> MemoryValue {
    match std::fs::read_to_string(path) {
        Ok(text) => match text.trim().parse::<u64>() {
            Ok(bytes) => MemoryValue::Bytes(bytes),
            Err(_) => MemoryValue::Unavailable, // "max" 等
        },
        Err(_) => MemoryValue::Unavailable,
    }
}

/// 周期采样循环（15s，对位 setInterval(refreshSandboxSamples, 15_000)）。
pub fn spawn_refresh_loop(samples: std::sync::Arc<CelldSamples>) {
    std::thread::spawn(move || loop {
        let ports = crate::routes::celld_ports();
        let pids_dir = std::env::var("IWEB_CELLD_PIDS_DIR").unwrap_or_default();
        if !pids_dir.is_empty() {
            refresh_celld_rss(&samples, &ports, &pids_dir);
        }
        std::thread::sleep(Duration::from_secs(15));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_pidfile_yields_none() {
        assert!(read_process_rss(Path::new("/nonexistent/dir/celld-x.pid").to_path_buf()).is_none());
    }

    #[test]
    fn refresh_clears_on_missing_and_sets_on_present() {
        let samples = CelldSamples::default();
        let dir = std::env::temp_dir().join(format!("iweb-sampling-{}", line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let ports = HashMap::from([("admin".to_string(), 8787u16), ("notes".to_string(), 8807u16)]);
        // 无 pidfile：admin 清空、notes 跳过
        refresh_celld_rss(&samples, &ports, dir.to_str().unwrap());
        assert!(samples.current("admin").is_none());
        // /proc 只在 Linux 存在：macOS 开发机上跳过正采样断言（CI/容器内执行）。
        if Path::new("/proc/self/status").exists() {
            std::fs::write(dir.join("celld-admin.pid"), format!("{}", std::process::id())).unwrap();
            refresh_celld_rss(&samples, &ports, dir.to_str().unwrap());
            let sample = samples.current("admin").expect("self sample present");
            assert!(sample.bytes > 0);
            assert!(sample.sampled_at.ends_with('Z'));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cgroup_unavailable_on_missing_file() {
        assert_eq!(cgroup_value("/nonexistent/memory.current"), MemoryValue::Unavailable);
    }
}
