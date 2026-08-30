//! 采样面与看门狗（对位 kernel/index.js refreshCelldRss + memorySnapshot；
//! two-tier-runtime-trust 扩展；R2 修复轮 2026-08-30 tasks 9.4/9.11）：
//! - celld per-app 进程 RSS + CPU：pidfile → /proc/<pid>/status VmRSS 与
//!   /proc/<pid>/stat utime+stime 差分（×1000/CLK_TCK 得 ms）；缺失/退出 → 无采样
//!   （绝不伪造 0，零值法律）。cpuMillis 是窗口差分值：首个窗口无上次基线 →
//!   unavailable，绝不以 0 冒充。fleet 应用一律监督（notes 跳过硬编码已删除）。
//! - wasmd（wasm tier 执行进程）同样按 pidfile 采样：`IWEB_WASMD_PIDS_DIR`
//!   （缺省 /run/iweb-sandbox）下的 `wasmd-<applicationId>.pid`（supervisor 侧约定）。
//!   wasmd 采样只驱动看门狗执行与事件（runtimeKind:"wasm"）；wasm 应用的资源投影
//!   仍走 engine metrics 口径（/v1/wasm/status），绝不以进程 VmRSS 冒充。
//! - 节点容器内存：cgroup v2 memory.current / memory.max（不可用 → unavailable）。
//! - 资源看门狗（用户态软限，非内核硬限）：采样循环（15s）按策略文件
//!   （IWEB_CELLD_RESOURCE_POLICY 指定路径，缺省 /opt/iweb/config/celld-resource-policy.json；
//!   形状 `{"defaultBytes":N,"apps":{...},"wasmdDefaultBytes":N,"wasmdApps":{...}}`，
//!   旧格式缺 wasmd 键时 wasmd 缺省复用 defaultBytes）检查 VmRSS，越限对 pidfile
//!   指向进程 SIGKILL。kill 前双防线（PID 复用防护，tasks 9.11）：
//!   (1) /proc/<pid>/cmdline 含进程特征（celld / wasmd）；
//!   (2) /proc/<pid>/stat 的 starttime（字段 22）与采样时记录的 starttime 一致——
//!   不一致说明 pid 已被另一进程复用：放弃 kill 并记一次有界事件（不杀）。
//!   策略文件缺失/损坏 → 用保守默认并记录一次有界日志（fail-open-to-default，
//!   不 panic）。kill/复用拒绝事件入有界环形（last 20），进入 /v1/status 与
//!   monitor 投影（每条携带 runtimeKind 与 outcome）。

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// 看门狗采样/执行间隔（ms；对位 setInterval(refreshSandboxSamples, 15_000)）。
pub const WATCHDOG_INTERVAL_MS: u64 = 15_000;
/// kill 事件环容量（有界；超过即淘汰最旧事件）。
pub const WATCHDOG_EVENT_RING_MAX: usize = 20;
/// 保守默认软限：512 MiB/应用（design 决策 1 / 风险 R3；celld 与 wasmd 同缺省）。
pub const DEFAULT_CELLD_MEMORY_LIMIT_BYTES: u64 = 536_870_912;
/// 策略文件路径覆盖变量（非空值即生效；空值按未设置处理）。
pub const CELLD_RESOURCE_POLICY_ENV: &str = "IWEB_CELLD_RESOURCE_POLICY";
/// 策略文件缺省路径（owner 可调；镜像内置）。
pub const DEFAULT_CELLD_RESOURCE_POLICY_PATH: &str = "/opt/iweb/config/celld-resource-policy.json";
/// 投影里的 enforcement 标签：软限（非 engine-enforced 硬限）。
pub const CELLD_LIMIT_ENFORCEMENT_LABEL: &str = "watchdog-soft";
/// wasmd pidfile 目录覆盖变量（缺省 /run/iweb-sandbox；supervisor 同名约定）。
pub const WASMD_PIDS_DIR_ENV: &str = "IWEB_WASMD_PIDS_DIR";
/// wasmd pidfile 缺省目录（容器内 supervisor runtime 目录）。
pub const DEFAULT_WASMD_PIDS_DIR: &str = "/run/iweb-sandbox";
/// wasmd pidfile 文件名模式：`wasmd-<applicationId>.pid`（supervisor 侧约定）。
pub const WASMD_PIDFILE_PREFIX: &str = "wasmd-";
pub const WASMD_PIDFILE_SUFFIX: &str = ".pid";
/// celld pidfile 文件名模式：`celld-<app>.pid`（entrypoint 既有约定）。
pub const CELLD_PIDFILE_PREFIX: &str = "celld-";
pub const CELLD_PIDFILE_SUFFIX: &str = ".pid";

/// pidfile 文件名 → 应用名（前缀/后缀剥离 + 应用 id 文法校验；不符 → None）。
fn app_name_of_pidfile(file_name: &str, prefix: &str, suffix: &str) -> Option<String> {
    let app = file_name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    crate::routes::valid_app_id(app).then(|| app.to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub bytes: u64,
    /// 窗口内 CPU 差分（ms）；`cpu_available=false` 表示本窗口无上次基线。
    pub cpu_millis: u64,
    pub cpu_available: bool,
    /// 累计 CPU ticks（差分基线；不进投影）。
    pub total_ticks: u64,
    /// /proc/<pid>/stat 的 starttime（字段 22）：PID 复用防护的进程世代标识
    /// （tasks 9.11；kill 前重读比对，不一致绝不杀）。
    pub start_ticks: u64,
    pub sampled_at: String,
}

/// 按应用名索引的进程采样表（celld fleet 与 wasmd 进程各持一份）。
#[derive(Default)]
pub struct ProcessSamples {
    inner: Mutex<HashMap<String, Sample>>,
}

impl ProcessSamples {
    pub fn current(&self, app: &str) -> Option<Sample> {
        self.inner.lock().expect("sample lock").get(app).cloned()
    }

    fn set(&self, app: &str, sample: Sample) {
        self.inner.lock().expect("sample lock").insert(app.into(), sample);
    }

    fn clear(&self, app: &str) {
        self.inner.lock().expect("sample lock").remove(app);
    }

    fn app_names(&self) -> Vec<String> {
        self.inner.lock().expect("sample lock").keys().cloned().collect()
    }
}

/// 单次进程采样（pidfile → /proc/<pid>）。
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessSample {
    pub pid: u32,
    pub rss_bytes: u64,
    /// /proc/<pid>/stat 的 utime+stime 累计 ticks（字段 14+15）。
    pub cpu_ticks: u64,
    /// /proc/<pid>/stat 的 starttime ticks（字段 22；PID 世代标识）。
    pub start_ticks: u64,
}

/// pidfile → pid（缺失/非数字/0 → None）。
fn read_pid(pidfile: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(pidfile).ok()?;
    let pid: u32 = text.trim().parse().ok()?;
    (pid != 0).then_some(pid)
}

/// pidfile → /proc/<pid>/status VmRSS（字节）。任一步失败返回 None。
pub fn read_process_rss(pidfile: PathBuf) -> Option<u64> {
    read_process_sample(pidfile).map(|sample| sample.rss_bytes)
}

/// pidfile → {pid, VmRSS, 累计 CPU ticks, starttime}。任一步失败返回 None。
pub fn read_process_sample(pidfile: PathBuf) -> Option<ProcessSample> {
    let pid = read_pid(&pidfile)?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut rss_bytes = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            rss_bytes = Some(kb * 1024);
            break;
        }
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let cpu_ticks = parse_stat_cpu_ticks(&stat)?;
    let start_ticks = parse_stat_start_ticks(&stat)?;
    Some(ProcessSample { pid, rss_bytes: rss_bytes?, cpu_ticks, start_ticks })
}

/// /proc/<pid>/stat 的 utime+stime（字段 14/15）。comm 字段可含空格与括号：
/// 从最后一个 ')' 之后切分；remainder[0]=state（字段 3），utime=index 11，
/// stime=index 12。
pub fn parse_stat_cpu_ticks(stat_text: &str) -> Option<u64> {
    let after_comm = stat_text.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime + stime)
}

/// /proc/<pid>/stat 的 starttime（字段 22；after-comm index 19）。PID 复用防护的
/// 世代标识：同一 pid 的两个进程世代 starttime 必不同。
pub fn parse_stat_start_ticks(stat_text: &str) -> Option<u64> {
    let after_comm = stat_text.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// CLK_TCK（sysconf(_SC_CLK_TCK)；不可用 → 100，Linux 容器惯例值）。
pub fn clock_ticks_per_sec() -> u64 {
    static TICKS: OnceLock<u64> = OnceLock::new();
    *TICKS.get_or_init(|| {
        let raw = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let ticks: u64 = match u64::try_from(raw) {
            Ok(value) if value > 0 => value,
            _ => 100,
        };
        ticks.clamp(1, 1_000_000)
    })
}

/// 窗口差分：累计 ticks 差 ×1000/CLK_TCK（基线缺失 → None，绝不以 0 冒充）。
pub fn cpu_millis_delta(previous_ticks: u64, current_ticks: u64) -> Option<u64> {
    if current_ticks < previous_ticks {
        // 基线来自另一进程世代（pid 复用/重启）：本窗口不可比 → unavailable。
        return None;
    }
    let delta = current_ticks - previous_ticks;
    Some(delta.saturating_mul(1000) / clock_ticks_per_sec())
}

/// 把一次新采样并入窗口差分（共享 celld/wasmd 的同一定义）。
fn record_window_sample(samples: &ProcessSamples, app: &str, current: ProcessSample) {
    let previous = samples.current(app);
    let (cpu_millis, cpu_available) = previous
        .and_then(|prev| cpu_millis_delta(prev.total_ticks, current.cpu_ticks))
        .map(|millis| (millis, true))
        .unwrap_or((0, false));
    samples.set(app, Sample {
        bytes: current.rss_bytes,
        cpu_millis,
        cpu_available,
        total_ticks: current.cpu_ticks,
        start_ticks: current.start_ticks,
        sampled_at: crate::monitor::iso_now(),
    });
}

/// 对位 refreshCelldRss：对 CELLD_PORTS 的每个 app 读 pidfile RSS+CPU。
/// fleet 应用一律监督（R2 修复轮 9.4：notes 硬编码跳过已删除）。
pub fn refresh_celld_rss(samples: &ProcessSamples, ports: &HashMap<String, u16>, pids_dir: &str) {
    for app in ports.keys() {
        let pidfile = Path::new(pids_dir).join(format!("{CELLD_PIDFILE_PREFIX}{app}{CELLD_PIDFILE_SUFFIX}"));
        match read_process_sample(pidfile) {
            Some(current) => record_window_sample(samples, app, current),
            None => samples.clear(app),
        }
    }
}

/// wasmd 进程采样：`IWEB_WASMD_PIDS_DIR`（缺省 /run/iweb-sandbox）目录枚举
/// `wasmd-<applicationId>.pid`。pidfile 是 supervisor 写入的进程地址权威；目录
/// 不可枚举（如开发宿主无 /run）→ 无采样（零值法律）。
pub fn refresh_wasmd_rss(samples: &ProcessSamples, pids_dir: &str) {
    let Ok(entries) = std::fs::read_dir(pids_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(app) = entry.file_name().to_str().and_then(|name| {
            app_name_of_pidfile(name, WASMD_PIDFILE_PREFIX, WASMD_PIDFILE_SUFFIX)
        }) else {
            continue;
        };
        match read_process_sample(entry.path()) {
            Some(current) => record_window_sample(samples, &app, current),
            None => samples.clear(&app),
        }
    }
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

// ---------------------------------------------------------------------------
// 资源看门狗（用户态软限；two-tier-runtime-trust design 决策 1；R2 修复轮
// 9.4 覆盖 wasmd + 9.11 PID 复用防护）
// ---------------------------------------------------------------------------

/// 软限策略：celld 与 wasmd 各一组 default + 每应用覆盖
/// （`{"defaultBytes":N,"apps":{...},"wasmdDefaultBytes":N,"wasmdApps":{...}}`；
/// 旧格式缺 wasmd 键 → wasmd 缺省复用 defaultBytes）。
#[derive(Debug, Clone, PartialEq)]
pub struct ResourcePolicy {
    pub default_bytes: u64,
    pub apps: BTreeMap<String, u64>,
    pub wasmd_default_bytes: u64,
    pub wasmd_apps: BTreeMap<String, u64>,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            default_bytes: DEFAULT_CELLD_MEMORY_LIMIT_BYTES,
            apps: BTreeMap::new(),
            wasmd_default_bytes: DEFAULT_CELLD_MEMORY_LIMIT_BYTES,
            wasmd_apps: BTreeMap::new(),
        }
    }
}

impl ResourcePolicy {
    /// 解析策略文件字节；任何必需字段缺失/非正数/形状非法 → None
    /// （fail-open-to-default；wasmd 键缺省回退 defaultBytes，旧格式兼容）。
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        #[derive(serde::Deserialize)]
        struct Wire {
            #[serde(rename = "defaultBytes")]
            default_bytes: u64,
            #[serde(default)]
            apps: BTreeMap<String, u64>,
            #[serde(rename = "wasmdDefaultBytes", default)]
            wasmd_default_bytes: Option<u64>,
            #[serde(rename = "wasmdApps", default)]
            wasmd_apps: Option<BTreeMap<String, u64>>,
        }
        let wire: Wire = serde_json::from_slice(bytes).ok()?;
        if wire.default_bytes == 0 {
            return None;
        }
        if wire.apps.values().any(|bytes| *bytes == 0) {
            return None;
        }
        let wasmd_default_bytes = wire.wasmd_default_bytes.unwrap_or(wire.default_bytes);
        if wasmd_default_bytes == 0 {
            return None;
        }
        let wasmd_apps = wire.wasmd_apps.unwrap_or_default();
        if wasmd_apps.values().any(|bytes| *bytes == 0) {
            return None;
        }
        Some(Self { default_bytes: wire.default_bytes, apps: wire.apps, wasmd_default_bytes, wasmd_apps })
    }

    /// celld 应用生效软限（覆盖 > 默认）。
    pub fn limit_for(&self, app: &str) -> u64 {
        self.apps.get(app).copied().unwrap_or(self.default_bytes)
    }

    /// wasmd 进程生效软限（覆盖 > wasmd 默认 > celld 默认）。
    pub fn wasmd_limit_for(&self, app: &str) -> u64 {
        self.wasmd_apps.get(app).copied().unwrap_or(self.wasmd_default_bytes)
    }
}

/// 看门狗事件（有界环；owner 可见投影，不含秘密）。`runtimeKind` 区分 celld/wasm
/// tier（tasks 9.4）；`outcome` 区分真正处决与 PID 复用拒绝（tasks 9.11：拒绝也
/// 必须可见，绝不静默放过也绝不误杀）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WatchdogEvent {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    /// "celld" | "wasm"（事件归属 tier）。
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: &'static str,
    /// "killed"（软限处决）| "pid-reuse-refused"（PID 复用防线放弃处决）。
    pub outcome: &'static str,
    #[serde(rename = "sampledBytes")]
    pub sampled_bytes: u64,
    #[serde(rename = "limitBytes")]
    pub limit_bytes: u64,
    #[serde(rename = "terminatedAt")]
    pub terminated_at: String,
}

pub const EVENT_OUTCOME_KILLED: &str = "killed";
pub const EVENT_OUTCOME_PID_REUSE_REFUSED: &str = "pid-reuse-refused";

#[derive(Default)]
struct WatchdogInner {
    policy: ResourcePolicy,
    /// 策略文件损坏的有界日志只记一次（进程生命周期内）。
    policy_failure_logged: bool,
    events: VecDeque<WatchdogEvent>,
}

/// 看门狗状态：最新策略 + 有界事件环。采样循环每轮 reload_policy →
/// refresh（celld + wasmd）→ enforce（celld + wasmd）。
#[derive(Default)]
pub struct Watchdog {
    inner: Mutex<WatchdogInner>,
}

/// 单应用处决判定的输入束（celld/wasmd 同一定义；限值由调用方按 tier 策略先取）。
struct EnforcementTarget<'a> {
    samples: &'a ProcessSamples,
    app: &'a str,
    runtime_kind: &'static str,
    cmdline_marker: &'static str,
    pidfile: PathBuf,
    limit: u64,
}

impl Watchdog {
    pub fn new() -> Self {
        Self::default()
    }

    /// 重读策略文件；缺失/损坏 → 回退保守默认并记录一次有界日志（不 panic）。
    pub fn reload_policy(&self, path: &Path) {
        let mut inner = self.inner.lock().expect("watchdog lock");
        match std::fs::read(path).ok().and_then(|bytes| ResourcePolicy::parse(&bytes)) {
            Some(policy) => inner.policy = policy,
            None => {
                if !inner.policy_failure_logged {
                    eprintln!(
                        "iweb-kernel: celld resource policy {} is missing or invalid; the watchdog falls back to the default soft limit",
                        path.display()
                    );
                    inner.policy_failure_logged = true;
                }
                inner.policy = ResourcePolicy::default();
            }
        }
    }

    /// 当前生效软限（/v1/status 与 monitor 投影的 per-app limits 用）。
    pub fn limit_for(&self, app: &str) -> u64 {
        self.inner.lock().expect("watchdog lock").policy.limit_for(app)
    }

    /// wasmd 进程生效软限（投影用）。
    pub fn wasmd_limit_for(&self, app: &str) -> u64 {
        self.inner.lock().expect("watchdog lock").policy.wasmd_limit_for(app)
    }

    fn record_event(&self, event: WatchdogEvent) {
        let mut inner = self.inner.lock().expect("watchdog lock");
        if inner.events.len() >= WATCHDOG_EVENT_RING_MAX {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
    }

    /// 生产执行路径：celld 越限进程 SIGKILL（libc::kill；只杀 pidfile 指向进程）。
    pub fn enforce(&self, samples: &ProcessSamples, ports: &HashMap<String, u16>, pids_dir: &str) {
        self.enforce_with(samples, ports, pids_dir, Path::new("/proc"), &|pid| unsafe {
            libc::kill(pid, libc::SIGKILL) == 0
        });
    }

    /// 生产执行路径：wasmd 越限进程 SIGKILL（runtimeKind:"wasm" 事件）。
    pub fn enforce_wasmd(&self, samples: &ProcessSamples, pids_dir: &str) {
        self.enforce_wasmd_with(samples, pids_dir, Path::new("/proc"), &|pid| unsafe {
            libc::kill(pid, libc::SIGKILL) == 0
        });
    }

    /// 可注入内核：`proc_root` 与 `kill_pid` 供单测伪 /proc 与假 kill（不真杀）。
    fn enforce_with(
        &self,
        samples: &ProcessSamples,
        ports: &HashMap<String, u16>,
        pids_dir: &str,
        proc_root: &Path,
        kill_pid: &dyn Fn(i32) -> bool,
    ) {
        for app in ports.keys() {
            let pidfile = Path::new(pids_dir).join(format!("{CELLD_PIDFILE_PREFIX}{app}{CELLD_PIDFILE_SUFFIX}"));
            self.enforce_one(
                EnforcementTarget {
                    samples,
                    app,
                    runtime_kind: crate::wasm_kind_registry::RUNTIME_KIND_CELLD,
                    cmdline_marker: "celld",
                    pidfile,
                    limit: self.limit_for(app),
                },
                proc_root,
                kill_pid,
            );
        }
    }

    fn enforce_wasmd_with(
        &self,
        samples: &ProcessSamples,
        pids_dir: &str,
        proc_root: &Path,
        kill_pid: &dyn Fn(i32) -> bool,
    ) {
        let apps = samples.app_names();
        for app in apps {
            let pidfile = Path::new(pids_dir).join(format!("{WASMD_PIDFILE_PREFIX}{app}{WASMD_PIDFILE_SUFFIX}"));
            self.enforce_one(
                EnforcementTarget {
                    samples,
                    app: &app,
                    runtime_kind: crate::wasm_kind_registry::RUNTIME_KIND_WASM,
                    cmdline_marker: "wasmd",
                    pidfile,
                    limit: self.wasmd_limit_for(&app),
                },
                proc_root,
                kill_pid,
            );
        }
    }

    /// 单应用处决判定（celld/wasmd 共用）：缺采样不行动（零值法律）；越限后
    /// pidfile → cmdline 特征 → starttime 世代一致 → SIGKILL；任何一步不能证明
    /// 目标仍是采样时的进程 → 放弃 kill（复用拒绝事件，tasks 9.11）。
    fn enforce_one(
        &self,
        target: EnforcementTarget<'_>,
        proc_root: &Path,
        kill_pid: &dyn Fn(i32) -> bool,
    ) {
        let EnforcementTarget { samples, app, runtime_kind, cmdline_marker, pidfile, limit } = target;
        // 缺采样不行动（零值法律：绝不以 0 或替代值触发处决）。
        let Some(sample) = samples.current(app) else { return };
        if sample.bytes <= limit {
            return;
        }
        // pidfile 消失/不可读 → 不杀（entrypoint 监督循环 / supervisor 负责重启）。
        let Some(pid) = read_pid(&pidfile) else { return };
        // pid 复用防线一：cmdline 必须含 tier 进程特征。
        let cmdline = std::fs::read_to_string(proc_root.join(format!("{pid}/cmdline"))).unwrap_or_default();
        if !cmdline.contains(cmdline_marker) {
            return;
        }
        // pid 复用防线二：starttime 世代必须与采样时一致（不一致 → 有界事件，不杀）。
        let current_start = std::fs::read_to_string(proc_root.join(format!("{pid}/stat")))
            .ok()
            .and_then(|stat| parse_stat_start_ticks(&stat));
        if current_start != Some(sample.start_ticks) {
            self.record_event(WatchdogEvent {
                application_id: app.to_string(),
                runtime_kind,
                outcome: EVENT_OUTCOME_PID_REUSE_REFUSED,
                sampled_bytes: sample.bytes,
                limit_bytes: limit,
                terminated_at: crate::monitor::iso_now(),
            });
            return;
        }
        if kill_pid(pid as i32) {
            self.record_event(WatchdogEvent {
                application_id: app.to_string(),
                runtime_kind,
                outcome: EVENT_OUTCOME_KILLED,
                sampled_bytes: sample.bytes,
                limit_bytes: limit,
                terminated_at: crate::monitor::iso_now(),
            });
        }
    }

    /// /v1/status 与 monitor snapshot 的 watchdog 投影。
    pub fn projection(&self) -> serde_json::Value {
        let inner = self.inner.lock().expect("watchdog lock");
        let apps: serde_json::Map<String, serde_json::Value> = inner
            .policy
            .apps
            .iter()
            .map(|(app, bytes)| (app.clone(), serde_json::json!(bytes)))
            .collect();
        let wasmd_apps: serde_json::Map<String, serde_json::Value> = inner
            .policy
            .wasmd_apps
            .iter()
            .map(|(app, bytes)| (app.clone(), serde_json::json!(bytes)))
            .collect();
        serde_json::json!({
            "intervalMs": WATCHDOG_INTERVAL_MS,
            "defaultBytes": inner.policy.default_bytes,
            "apps": apps,
            "wasmdDefaultBytes": inner.policy.wasmd_default_bytes,
            "wasmdApps": wasmd_apps,
            "events": inner.events.iter().collect::<Vec<_>>(),
        })
    }
}

/// wasmd pidfile 目录解析（env 覆盖；空值按未设置处理）。
pub fn wasmd_pids_dir() -> String {
    std::env::var(WASMD_PIDS_DIR_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WASMD_PIDS_DIR.to_string())
}

/// 周期采样循环（15s，对位 setInterval(refreshSandboxSamples, 15_000)）+
/// 看门狗软限执行（celld fleet + wasmd 进程）。策略文件每轮重读（owner 可热调）。
pub fn spawn_refresh_loop(
    celld_samples: std::sync::Arc<ProcessSamples>,
    wasmd_samples: std::sync::Arc<ProcessSamples>,
    watchdog: std::sync::Arc<Watchdog>,
) {
    std::thread::spawn(move || loop {
        let ports = crate::routes::celld_ports();
        let policy_path = std::env::var(CELLD_RESOURCE_POLICY_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CELLD_RESOURCE_POLICY_PATH.to_string());
        watchdog.reload_policy(Path::new(&policy_path));
        let pids_dir = std::env::var("IWEB_CELLD_PIDS_DIR").unwrap_or_default();
        if !pids_dir.is_empty() {
            refresh_celld_rss(&celld_samples, &ports, &pids_dir);
            watchdog.enforce(&celld_samples, &ports, &pids_dir);
        }
        // wasmd：pidfile 目录缺省即容器约定路径；开发宿主无该目录 → 无采样无行动。
        let wasmd_dir = wasmd_pids_dir();
        refresh_wasmd_rss(&wasmd_samples, &wasmd_dir);
        watchdog.enforce_wasmd(&wasmd_samples, &wasmd_dir);
        std::thread::sleep(Duration::from_millis(WATCHDOG_INTERVAL_MS));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// celld 与 wasmd 共用的样本写入助手。
    fn set_sample(samples: &ProcessSamples, app: &str, bytes: u64, start_ticks: u64) {
        samples.set(app, Sample {
            bytes,
            cpu_millis: 0,
            cpu_available: true,
            total_ticks: 0,
            start_ticks,
            sampled_at: "2026-08-30T00:00:00.000Z".into(),
        });
    }

    #[test]
    fn missing_pidfile_yields_none() {
        assert!(read_process_rss(Path::new("/nonexistent/dir/celld-x.pid").to_path_buf()).is_none());
        assert!(read_process_sample(Path::new("/nonexistent/dir/celld-x.pid").to_path_buf()).is_none());
    }

    #[test]
    fn refresh_clears_on_missing_and_sets_on_present() {
        let samples = ProcessSamples::default();
        let dir = std::env::temp_dir().join(format!("iweb-sampling-{}", line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let ports = HashMap::from([("admin".to_string(), 8787u16), ("notes".to_string(), 8807u16)]);
        // 无 pidfile：admin 清空、notes 同样参与采样（硬编码跳过已删除）。
        refresh_celld_rss(&samples, &ports, dir.to_str().unwrap());
        assert!(samples.current("admin").is_none());
        assert!(samples.current("notes").is_none());
        // /proc 只在 Linux 存在：macOS 开发机上跳过正采样断言（CI/容器内执行）。
        if Path::new("/proc/self/status").exists() {
            std::fs::write(dir.join("celld-admin.pid"), format!("{}", std::process::id())).unwrap();
            // notes 也写 pidfile：fleet 应用一律监督。
            std::fs::write(dir.join("celld-notes.pid"), format!("{}", std::process::id())).unwrap();
            refresh_celld_rss(&samples, &ports, dir.to_str().unwrap());
            let first = samples.current("admin").expect("self sample present");
            assert!(first.bytes > 0);
            assert!(first.start_ticks > 0, "starttime 必须随采样记录（PID 复用防护）");
            assert!(!first.cpu_available, "首个窗口无差分基线 → unavailable（绝不以 0 冒充）");
            assert!(samples.current("notes").is_some(), "notes 无跳过：同样被监督");
            // 第二轮：有基线 → cpu 可用且为非负差分。
            std::thread::sleep(Duration::from_millis(20));
            refresh_celld_rss(&samples, &ports, dir.to_str().unwrap());
            let second = samples.current("admin").expect("second sample present");
            assert!(second.cpu_available);
            assert!(second.total_ticks >= first.total_ticks);
            assert!(second.sampled_at.ends_with('Z'));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wasmd_refresh_walks_pidfiles_and_ignores_foreign_names() {
        let samples = ProcessSamples::default();
        let dir = std::env::temp_dir().join(format!("iweb-sampling-wasmd-{}", line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["wasmd-vector.pid", "wasmd-notes-app.pid", "wasmd-..escape.pid", "wasmd-UPPER.pid", "celld-admin.pid", "wasmd-orphan.pid.bak"] {
            std::fs::write(dir.join(name), "1").unwrap();
        }
        // pid=1 的 /proc 采样在 macOS 开发机不可读 → 全部 clear（无伪造）；
        // 在 Linux 容器内 pid=1 存在但属 init——不以此断言采样值，只断言应用集与
        // 目录遍历不把非法文件名当应用。
        refresh_wasmd_rss(&samples, dir.to_str().unwrap());
        // /proc 平台差异使采样值不可跨平台断言；文件名→应用名的纯函数断言在下方。
        let _ = std::fs::remove_dir_all(&dir);
        // 文件名解析的纯函数断言（跨平台稳定）。
        assert_eq!(app_name_of_pidfile("wasmd-vector.pid", WASMD_PIDFILE_PREFIX, WASMD_PIDFILE_SUFFIX).as_deref(), Some("vector"));
        assert_eq!(app_name_of_pidfile("wasmd-..escape.pid", WASMD_PIDFILE_PREFIX, WASMD_PIDFILE_SUFFIX), None);
        assert_eq!(app_name_of_pidfile("wasmd-UPPER.pid", WASMD_PIDFILE_PREFIX, WASMD_PIDFILE_SUFFIX), None, "应用 id 必须是小写 DNS-label 文法");
        assert_eq!(app_name_of_pidfile("celld-admin.pid", WASMD_PIDFILE_PREFIX, WASMD_PIDFILE_SUFFIX), None);
        assert_eq!(app_name_of_pidfile("celld-admin.pid", CELLD_PIDFILE_PREFIX, CELLD_PIDFILE_SUFFIX).as_deref(), Some("admin"));
    }

    #[test]
    fn cgroup_unavailable_on_missing_file() {
        assert_eq!(cgroup_value("/nonexistent/memory.current"), MemoryValue::Unavailable);
    }

    // ---- /proc/<pid>/stat 解析与差分 ----

    #[test]
    fn stat_cpu_ticks_parses_fields_14_and_15() {
        // 真实 stat 形状：comm 含空格（"(celld worker)"）时仍从最后一个 ')' 切分。
        // ')' 之后：state(idx0) + 10 个填充字段(idx1..10) + utime=250(idx11) + stime=750(idx12)。
        let stat = "1234 (celld worker) S 1 2 3 4 5 6 7 8 9 10 250 750 0 0 0 0 0 0 999";
        assert_eq!(parse_stat_cpu_ticks(stat), Some(1000), "utime(字段14)+stime(字段15)");
        // starttime 是字段 22（after-comm idx19）。
        assert_eq!(parse_stat_start_ticks(stat), Some(999));
        // comm 无空格的最小形状。
        let minimal = "42 (celld) R 0 0 0 0 0 0 0 0 0 0 3 7";
        assert_eq!(parse_stat_cpu_ticks(minimal), Some(10));
        // 缺字段 → None。
        assert_eq!(parse_stat_cpu_ticks("42 (celld) R 0"), None);
        assert_eq!(parse_stat_start_ticks("42 (celld) R 0"), None);
        assert_eq!(parse_stat_cpu_ticks("no comm field"), None);
    }

    #[test]
    fn cpu_delta_is_window_millis_and_unavailable_on_regression() {
        // CLK_TCK=100 惯例下：150 ticks 差 → 1500ms。
        let ticks = clock_ticks_per_sec();
        assert_eq!(cpu_millis_delta(0, ticks + ticks / 2).map(|ms| ms * ticks), Some(1500 * ticks));
        assert_eq!(cpu_millis_delta(0, 0), Some(0), "已证实的零差分是合法零值");
        assert_eq!(cpu_millis_delta(500, 100), None, "基线来自另一进程世代 → 不可比");
    }

    // ---- 策略解析：fail-open-to-default + wasmd 扩展键 ----

    #[test]
    fn resource_policy_parse_fail_open_to_default() {
        assert_eq!(ResourcePolicy::parse(b"{ not json"), None);
        assert_eq!(ResourcePolicy::parse(b"{}"), None, "缺 defaultBytes → None");
        assert_eq!(
            ResourcePolicy::parse(br#"{"defaultBytes":0}"#),
            None,
            "零默认限会立刻处决一切 → 拒绝并回退"
        );
        assert_eq!(ResourcePolicy::parse(br#"{"defaultBytes":100,"apps":{"admin":0}}"#), None);
        // wasmd 键：零值拒绝；缺省回退 defaultBytes（旧格式兼容）。
        assert_eq!(ResourcePolicy::parse(br#"{"defaultBytes":100,"wasmdDefaultBytes":0}"#), None);
        assert_eq!(ResourcePolicy::parse(br#"{"defaultBytes":100,"wasmdApps":{"vector":0}}"#), None);
        let policy = ResourcePolicy::parse(br#"{"defaultBytes":536870912,"apps":{"search":1048576}}"#)
            .expect("valid policy parses");
        assert_eq!(policy.default_bytes, 536_870_912);
        assert_eq!(policy.limit_for("search"), 1_048_576, "覆盖优先");
        assert_eq!(policy.limit_for("admin"), 536_870_912, "未覆盖走默认");
        assert_eq!(policy.wasmd_limit_for("vector"), 536_870_912, "旧格式：wasmd 复用 defaultBytes");
        let policy = ResourcePolicy::parse(
            br#"{"defaultBytes":536870912,"apps":{"search":1048576},"wasmdDefaultBytes":268435456,"wasmdApps":{"vector":1048576}}"#,
        )
        .expect("extended policy parses");
        assert_eq!(policy.wasmd_limit_for("vector"), 1_048_576, "wasmd 覆盖优先");
        assert_eq!(policy.wasmd_limit_for("notes-app"), 268_435_456, "wasmd 默认独立于 celld 默认");
        assert_eq!(policy.limit_for("search"), 1_048_576, "celld 键不受 wasmd 键影响");
        // reload：损坏文件 → 默认策略 + 只记一次日志。
        let dir = std::env::temp_dir().join(format!("iweb-watchdog-policy-{}", line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.json");
        let watchdog = Watchdog::new();
        watchdog.reload_policy(&path); // 缺失 → 默认
        assert_eq!(watchdog.limit_for("anyone"), DEFAULT_CELLD_MEMORY_LIMIT_BYTES);
        assert_eq!(watchdog.wasmd_limit_for("anyone"), DEFAULT_CELLD_MEMORY_LIMIT_BYTES);
        std::fs::write(&path, br#"{"defaultBytes":2048,"wasmdDefaultBytes":4096}"#).unwrap();
        watchdog.reload_policy(&path);
        assert_eq!(watchdog.limit_for("anyone"), 2048);
        assert_eq!(watchdog.wasmd_limit_for("anyone"), 4096);
        std::fs::write(&path, b"{ broken").unwrap();
        watchdog.reload_policy(&path);
        assert_eq!(watchdog.limit_for("anyone"), DEFAULT_CELLD_MEMORY_LIMIT_BYTES, "损坏回退默认");
        assert_eq!(watchdog.wasmd_limit_for("anyone"), DEFAULT_CELLD_MEMORY_LIMIT_BYTES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- kill 判定（伪 pid + 假 /proc，不真杀）----

    /// 构造可注入的采样/执行环境：pids_dir 写 pidfile，proc_dir 写假 cmdline/stat。
    fn fake_proc_fixture(
        pidfile_prefix: &str,
        app: &str,
        pid: u32,
        rss: u64,
        cmdline: &str,
        start_ticks: u64,
    ) -> (PathBuf, PathBuf, ProcessSamples) {
        // 每次调用唯一目录：cargo 并行测试共享 line!() 同值目录会互相删除。
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let tag = format!("iweb-watchdog-{pidfile_prefix}-{app}-{pid}-{sequence}");
        let dir = std::env::temp_dir().join(&tag);
        let pids_dir = dir.join("pids");
        let proc_dir = dir.join("proc");
        std::fs::create_dir_all(&pids_dir).unwrap();
        std::fs::create_dir_all(proc_dir.join(format!("{pid}"))).unwrap();
        let suffix = if pidfile_prefix == CELLD_PIDFILE_PREFIX { CELLD_PIDFILE_SUFFIX } else { WASMD_PIDFILE_SUFFIX };
        std::fs::write(pids_dir.join(format!("{pidfile_prefix}{app}{suffix}")), pid.to_string()).unwrap();
        std::fs::write(proc_dir.join(format!("{pid}/cmdline")), cmdline).unwrap();
        // 假 stat：after-comm idx0=state；idx1..18 填零（含 utime/stime），idx19=starttime。
        let filler = " 0".repeat(18);
        std::fs::write(proc_dir.join(format!("{pid}/stat")), format!("{pid} (proc) R{filler} {start_ticks}")).unwrap();
        let samples = ProcessSamples::default();
        set_sample(&samples, app, rss, start_ticks);
        (pids_dir, proc_dir, samples)
    }

    #[test]
    fn watchdog_kills_only_over_limit_celld_cmdline_processes() {
        let watchdog = Watchdog::new();
        let ports = HashMap::from([("admin".to_string(), 8787u16)]);
        let killed = std::sync::Arc::new(Mutex::new(Vec::<i32>::new()));

        // (a) 越限 + cmdline 含 celld + starttime 一致 → kill + 事件（runtimeKind=celld）。
        let (pids, proc_root, samples) = fake_proc_fixture(
            CELLD_PIDFILE_PREFIX,
            "admin",
            4242,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/usr/local/bin/celld\0run\0admin",
            700,
        );
        let sink = killed.clone();
        watchdog.enforce_with(&samples, &ports, pids.to_str().unwrap(), &proc_root, &move |pid| {
            sink.lock().unwrap().push(pid);
            true
        });
        assert_eq!(*killed.lock().unwrap(), vec![4242]);
        let projection = watchdog.projection();
        assert_eq!(projection["events"].as_array().unwrap().len(), 1);
        assert_eq!(projection["events"][0]["applicationId"], serde_json::json!("admin"));
        assert_eq!(projection["events"][0]["runtimeKind"], serde_json::json!("celld"));
        assert_eq!(projection["events"][0]["outcome"], serde_json::json!("killed"));
        assert_eq!(projection["events"][0]["sampledBytes"], serde_json::json!(DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1));
        assert_eq!(projection["events"][0]["limitBytes"], serde_json::json!(DEFAULT_CELLD_MEMORY_LIMIT_BYTES));
        assert!(projection["events"][0]["terminatedAt"].as_str().unwrap().ends_with('Z'));

        // (b) 未越限 → 不杀。
        killed.lock().unwrap().clear();
        let (pids, proc_root, samples) = fake_proc_fixture(CELLD_PIDFILE_PREFIX, "admin", 4243, 1024, "/usr/local/bin/celld", 701);
        watchdog.enforce_with(&samples, &ports, pids.to_str().unwrap(), &proc_root, &|pid| {
            killed.lock().unwrap().push(pid);
            true
        });
        assert!(killed.lock().unwrap().is_empty(), "未越限绝不处决");

        // (c) 越限但 cmdline 不含 celld（pid 复用为无关进程）→ 不杀、无事件。
        let (pids, proc_root, samples) = fake_proc_fixture(
            CELLD_PIDFILE_PREFIX,
            "admin",
            4244,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/usr/bin/tail\0-f\0log",
            702,
        );
        watchdog.enforce_with(&samples, &ports, pids.to_str().unwrap(), &proc_root, &|pid| {
            killed.lock().unwrap().push(pid);
            true
        });
        assert!(killed.lock().unwrap().is_empty(), "pid 复用防线：cmdline 无 celld 特征不杀");
        assert_eq!(watchdog.projection()["events"].as_array().unwrap().len(), 1, "cmdline 拒绝不产生事件（starttime 未见）");

        // (d) 越限但 pidfile 消失 → 不杀（entrypoint 监督负责）。
        let (pids, proc_root, samples) = fake_proc_fixture(
            CELLD_PIDFILE_PREFIX,
            "admin",
            4245,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/usr/local/bin/celld",
            703,
        );
        std::fs::remove_file(pids.join("celld-admin.pid")).unwrap();
        watchdog.enforce_with(&samples, &ports, pids.to_str().unwrap(), &proc_root, &|pid| {
            killed.lock().unwrap().push(pid);
            true
        });
        assert!(killed.lock().unwrap().is_empty(), "pidfile 消失不杀");

        // (e) 无采样 → 不行动（零值法律）。
        let (pids, proc_root, _) = fake_proc_fixture(CELLD_PIDFILE_PREFIX, "admin", 4246, 0, "/usr/local/bin/celld", 704);
        let empty = ProcessSamples::default();
        watchdog.enforce_with(&empty, &ports, pids.to_str().unwrap(), &proc_root, &|pid| {
            killed.lock().unwrap().push(pid);
            true
        });
        assert!(killed.lock().unwrap().is_empty());

        for d in [pids, proc_root] {
            let _ = std::fs::remove_dir_all(d.parent().unwrap());
        }
    }

    #[test]
    fn watchdog_wasmd_events_carry_the_wasm_runtime_kind() {
        let watchdog = Watchdog::new();
        let (pids, proc_root, samples) = fake_proc_fixture(
            WASMD_PIDFILE_PREFIX,
            "vector",
            5353,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/opt/iweb/wasmd/iweb-wasmd\0--listen\0",
            800,
        );
        let killed = std::sync::Arc::new(Mutex::new(Vec::<i32>::new()));
        let sink = killed.clone();
        watchdog.enforce_wasmd_with(&samples, pids.to_str().unwrap(), &proc_root, &move |pid| {
            sink.lock().unwrap().push(pid);
            true
        });
        assert_eq!(*killed.lock().unwrap(), vec![5353], "越限 wasmd 进程被处决");
        let events = watchdog.projection()["events"].as_array().unwrap().clone();
        assert_eq!(events[0]["runtimeKind"], serde_json::json!("wasm"));
        assert_eq!(events[0]["outcome"], serde_json::json!("killed"));
        assert_eq!(events[0]["applicationId"], serde_json::json!("vector"));
        // cmdline 无 wasmd 特征（复用为无关进程）→ 不杀。
        let (pids2, proc_root2, samples2) = fake_proc_fixture(
            WASMD_PIDFILE_PREFIX,
            "vector",
            5354,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/usr/bin/python3\0server.py",
            801,
        );
        watchdog.enforce_wasmd_with(&samples2, pids2.to_str().unwrap(), &proc_root2, &|_| true);
        assert_eq!(watchdog.projection()["events"].as_array().unwrap().len(), 1, "cmdline 复用拒绝不产生事件");
        let _ = std::fs::remove_dir_all(pids.parent().unwrap());
        let _ = std::fs::remove_dir_all(pids2.parent().unwrap());
    }

    #[test]
    fn starttime_mismatch_refuses_the_kill_with_a_bounded_event() {
        // tasks 9.11：采样后 pid 被另一进程复用（starttime 变化）→ 放弃 kill +
        // 有界 pid-reuse-refused 事件（不杀）。celld 与 wasmd 同一防线。
        let watchdog = Watchdog::new();
        let killed = std::sync::Arc::new(Mutex::new(Vec::<i32>::new()));
        let (pids, proc_root, samples) = fake_proc_fixture(
            CELLD_PIDFILE_PREFIX,
            "admin",
            6161,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/usr/local/bin/celld",
            900,
        );
        // fixture 里采样记录 start_ticks=900；改写假 stat 为 901（复用世代）。
        std::fs::write(proc_root.join("6161/stat"), format!("6161 (proc) R{} 901", " 0".repeat(18))).unwrap();
        let sink = killed.clone();
        watchdog.enforce_with(&samples, &HashMap::from([("admin".to_string(), 8787u16)]), pids.to_str().unwrap(), &proc_root, &move |pid| {
            sink.lock().unwrap().push(pid);
            true
        });
        assert!(killed.lock().unwrap().is_empty(), "starttime 不一致绝不杀");
        let events = watchdog.projection()["events"].as_array().unwrap().clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["outcome"], serde_json::json!("pid-reuse-refused"));
        assert_eq!(events[0]["runtimeKind"], serde_json::json!("celld"));

        // stat 不可读（无法证明世代一致）同样拒绝：fail-closed 到「不杀」。
        let (pids2, proc_root2, samples2) = fake_proc_fixture(
            WASMD_PIDFILE_PREFIX,
            "vector",
            6262,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/opt/iweb/wasmd/iweb-wasmd",
            910,
        );
        std::fs::remove_file(proc_root2.join("6262/stat")).unwrap();
        watchdog.enforce_wasmd_with(&samples2, pids2.to_str().unwrap(), &proc_root2, &|pid| {
            killed.lock().unwrap().push(pid);
            true
        });
        assert!(killed.lock().unwrap().is_empty(), "无法证明 starttime 一致 → 不杀");
        let events = watchdog.projection()["events"].as_array().unwrap().clone();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["outcome"], serde_json::json!("pid-reuse-refused"));
        assert_eq!(events[1]["runtimeKind"], serde_json::json!("wasm"));
        let _ = std::fs::remove_dir_all(pids.parent().unwrap());
        let _ = std::fs::remove_dir_all(pids2.parent().unwrap());
    }

    #[test]
    fn watchdog_event_ring_is_bounded_to_twenty() {
        let watchdog = Watchdog::new();
        let ports = HashMap::from([("admin".to_string(), 8787u16)]);
        let (pids, proc_root, samples) = fake_proc_fixture(
            CELLD_PIDFILE_PREFIX,
            "admin",
            9999,
            DEFAULT_CELLD_MEMORY_LIMIT_BYTES + 1,
            "/usr/local/bin/celld",
            1000,
        );
        for _ in 0..30 {
            watchdog.enforce_with(&samples, &ports, pids.to_str().unwrap(), &proc_root, &|_| true);
        }
        let events = watchdog.projection()["events"].as_array().unwrap().clone();
        assert_eq!(events.len(), WATCHDOG_EVENT_RING_MAX, "事件环有界");
        assert_eq!(events[0]["applicationId"], serde_json::json!("admin"));
        let _ = std::fs::remove_dir_all(pids.parent().unwrap());
    }
}
