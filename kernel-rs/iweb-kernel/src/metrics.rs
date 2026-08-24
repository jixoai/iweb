//! 每应用请求指标（对位 kernel/index.js appMetrics）：§4.2 monitor 帧接入。
//! 只做真实计数——无流量时 requests=0 是可证明的零；绝不用估计值填充。
//! 每次指标落账后广播通知，monitor 连接据此推送新快照（对位 JS broadcastMonitorSnapshot）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Entry {
    requests: u64,
    errors: u64,
    in_flight: i64,
    total_latency_millis: f64,
    last_request_at: Option<String>,
}

struct Inner {
    entries: Mutex<HashMap<String, Entry>>,
    /// 指标落账通知；monitor 连接经 watch::Receiver 收到变更后重发快照。
    /// watch（而非 Notify）：带值语义，select 重挂窗口内的事件不会丢失。
    version: tokio::sync::watch::Sender<()>,
}

/// 进程级共享指标表；Clone 共享同一底层存储。
#[derive(Clone)]
pub struct AppMetrics(Arc<Inner>);

impl Default for AppMetrics {
    fn default() -> Self {
        let (version, _) = tokio::sync::watch::channel(());
        Self(Arc::new(Inner { entries: Mutex::new(HashMap::new()), version }))
    }
}

/// 单应用指标快照（帧字段逐一平价 JS monitorSnapshot 的 apps[]）。
pub struct Snapshot {
    pub requests: u64,
    pub errors: u64,
    pub in_flight: i64,
    /// JS 对位：requests=0 时为 0，否则四舍五入到 0.1ms。
    pub average_latency_ms: f64,
    pub last_request_at: Option<String>,
}

impl AppMetrics {
    fn with<R>(&self, app: &str, update: impl FnOnce(&mut Entry) -> R) -> R {
        let mut entries = self.0.entries.lock().expect("metrics lock");
        let entry = entries.entry(app.to_owned()).or_default();
        update(entry)
    }

    /// 请求进入代理时调用；必须与 observe 配对（observe 内饱和递减 in_flight）。
    pub fn in_flight_enter(&self, app: &str) {
        self.with(app, |entry| entry.in_flight += 1);
    }

    /// 请求离开代理时调用：计数、累计时延、记录完成时刻并广播。
    /// error 语义对位 JS：上游状态 ≥500 或传输/转换失败。
    pub fn observe(&self, app: &str, started: std::time::Instant, error: bool) {
        self.with(app, |entry| {
            entry.requests += 1;
            if error {
                entry.errors += 1;
            }
            entry.total_latency_millis += started.elapsed().as_secs_f64() * 1000.0;
            entry.last_request_at = Some(crate::monitor::iso_now());
            entry.in_flight = (entry.in_flight - 1).max(0);
        });
        let _ = self.0.version.send(());
    }

    /// monitor 连接的变更订阅句柄（watch：错过的变更在 changed() 里仍可见）。
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.0.version.subscribe()
    }

    pub fn snapshot(&self, app: &str) -> Snapshot {
        let entries = self.0.entries.lock().expect("metrics lock");
        let entry = entries.get(app);
        Snapshot {
            requests: entry.map(|e| e.requests).unwrap_or(0),
            errors: entry.map(|e| e.errors).unwrap_or(0),
            in_flight: entry.map(|e| e.in_flight).unwrap_or(0),
            average_latency_ms: entry
                .filter(|e| e.requests > 0)
                .map(|e| (e.total_latency_millis / e.requests as f64 * 10.0).round() / 10.0)
                .unwrap_or(0.0),
            last_request_at: entry.and_then(|e| e.last_request_at.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_average_round_to_tenth() {
        let metrics = AppMetrics::default();
        metrics.in_flight_enter("admin");
        let started = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        metrics.observe("admin", started, false);
        let snapshot = metrics.snapshot("admin");
        assert_eq!(snapshot.requests, 1);
        assert_eq!(snapshot.errors, 0);
        assert_eq!(snapshot.in_flight, 0);
        assert!(snapshot.average_latency_ms >= 1.9);
        assert!(snapshot.last_request_at.is_some());
        // 未记录过的应用：可证明的零，无捏造值。
        let unknown = metrics.snapshot("mcp");
        assert_eq!((unknown.requests, unknown.errors, unknown.in_flight), (0, 0, 0));
        assert_eq!(unknown.average_latency_ms, 0.0);
        assert!(unknown.last_request_at.is_none());
    }

    #[test]
    fn in_flight_never_goes_negative() {
        let metrics = AppMetrics::default();
        let started = std::time::Instant::now();
        // 无配对 enter 的 observe：饱和递减到 0，绝不出现负并发（对位 JS Math.max(0, x-1)）。
        metrics.observe("admin", started, false);
        assert_eq!(metrics.snapshot("admin").in_flight, 0);
    }
}
