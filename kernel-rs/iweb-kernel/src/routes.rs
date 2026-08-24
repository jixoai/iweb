//! 路由注册表（对位 kernel/index.js loadRouteStore/routeForHost/routeForApp/
//! routeFromRequest）：持久 JSON（version 1 + routes[]）、host/path 别名解析。
//! §4.1：system 目标代理到 per-app celld 端口；sandbox 目标（routeAction）待 §4.5 接入。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteTarget {
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "appName", skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(rename = "sandboxId", skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteRecord {
    #[serde(rename = "hostId")]
    pub host_id: String,
    pub target: RouteTarget,
    #[serde(default)]
    pub system: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStoreFile {
    pub version: u32,
    pub routes: Vec<RouteRecord>,
}

pub struct RouteStore {
    path: PathBuf,
    inner: RwLock<RouteStoreFile>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RouteAction {
    System { app_name: String },
    Sandbox { sandbox_id: String },
}

impl RouteStore {
    /// 加载持久注册表；形状不合法直接 panic-fail-closed（对位 JS throw）。
    pub fn load(path: &Path) -> Self {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read route registry {}: {e}", path.display()));
        let parsed: RouteStoreFile = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("invalid iweb route registry: {e}"));
        if parsed.version != 1 {
            panic!("invalid iweb route registry: unsupported version");
        }
        Self { path: path.to_path_buf(), inner: RwLock::new(parsed) }
    }

    pub fn snapshot(&self) -> Vec<RouteRecord> {
        self.inner.read().expect("route lock").routes.clone()
    }

    fn find_enabled(&self, host_id: &str) -> Option<RouteRecord> {
        self.snapshot().into_iter().find(|route| route.enabled && route.host_id == host_id)
    }

    fn find_app(&self, app_name: &str) -> Option<RouteRecord> {
        self.snapshot()
            .into_iter()
            .find(|route| route.enabled && route.target.app_name.as_deref() == Some(app_name))
    }

    /// routeAction 对位：system → System；sandbox 目标 → Sandbox；其它 → None（502）。
    /// managed-applications 法律：只有受保护的 system 记录可直连 per-app celld；
    /// 用户路由（system:false）永不回退共享运行时——无 ready sandbox 即 fail-closed。
    pub fn action_for(&self, route: &RouteRecord) -> Option<RouteAction> {
        match route.target.kind.as_str() {
            "celld-app" if route.system => {
                route.target.app_name.clone().map(|app_name| RouteAction::System { app_name })
            }
            "sandbox" => route.target.sandbox_id.clone().map(|sandbox_id| RouteAction::Sandbox { sandbox_id }),
            _ => None,
        }
    }

    pub fn record(&self, route: RouteRecord) -> bool {
        let mut store = self.inner.write().expect("route lock");
        let replaced = store
            .routes
            .iter_mut()
            .find(|candidate| candidate.host_id == route.host_id);
        match replaced {
            Some(slot) => {
                *slot = route;
                true
            }
            None => {
                store.routes.push(route);
                false
            }
        }
    }

    pub fn delete(&self, host_id: &str) -> bool {
        let mut store = self.inner.write().expect("route lock");
        let before = store.routes.len();
        store.routes.retain(|route| route.host_id != host_id);
        store.routes.len() != before
    }

    /// 持久化（原子写；mc 备份同步待 §4.4 存储切换接入）。
    pub fn persist(&self) {
        let store = self.inner.read().expect("route lock").clone();
        let body = serde_json::to_string_pretty(&store).expect("routes serialize");
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, format!("{body}\n")).expect("routes write");
        std::fs::rename(&temporary, &self.path).expect("routes rename");
    }
}

/// 单个入口请求的解析结果。
pub struct Resolved {
    pub route: RouteRecord,
    pub upstream_path: String,
    pub app_base_path: Option<String>,
}

/// 对位 routeFromRequest：base host 的 /<app>/app 路径别名 + <hostId>.<base> 主机路由。
/// 返回 None 表示无路由（404）。
pub fn resolve(store: &RouteStore, base_host: &str, host: &str, path_and_query: &str) -> Option<Resolved> {
    let path = path_and_query.split('?').next().unwrap_or("");
    let query = path_and_query.split_once('?').map(|(_, q)| format!("?{q}")).unwrap_or_default();

    if host == base_host {
        // /<app>/app(/...)?
        let rest = path.strip_prefix('/')?;
        let mut segments = rest.splitn(3, '/');
        let app = segments.next()?;
        if !valid_app_id(app) {
            return None;
        }
        let second = segments.next()?;
        if second != "app" {
            return None;
        }
        let tail = segments.next();
        let route = store.find_app(app)?;
        let upstream_path = match tail {
            Some(t) if !t.is_empty() => format!("/{t}{query}"),
            _ => format!("/{query}"),
        };
        return Some(Resolved { route, upstream_path, app_base_path: Some(format!("/{app}/app/")) });
    }

    let suffix = format!(".{base_host}");
    let host_id = host.strip_suffix(&suffix)?;
    let route = store.find_enabled(host_id)?;
    Some(Resolved { route, upstream_path: format!("{path}{query}"), app_base_path: None })
}

pub fn valid_app_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| alnum(b) || b == b'-')
}

/// per-app celld 端口（对位 JS parseCelldPorts：IWEB_CELLD_PORTS 缺省回退固定端口表）。
pub fn celld_ports() -> HashMap<String, u16> {
    match std::env::var("IWEB_CELLD_PORTS") {
        Ok(raw) => serde_json::from_str::<HashMap<String, u16>>(&raw).unwrap_or_default(),
        Err(_) => HashMap::from([("admin".into(), 8787), ("mcp".into(), 8797), ("notes".into(), 8807), ("hello".into(), 8817), ("search".into(), 8827), ("collab".into(), 8837), ("collab-b".into(), 8847)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> RouteStore {
        let file = RouteStoreFile {
            version: 1,
            routes: vec![
                RouteRecord { host_id: "admin".into(), target: RouteTarget { kind: "celld-app".into(), app_name: Some("admin".into()), sandbox_id: None }, system: true, enabled: true },
                RouteRecord { host_id: "admin.app".into(), target: RouteTarget { kind: "celld-app".into(), app_name: Some("admin".into()), sandbox_id: None }, system: true, enabled: true },
                RouteRecord { host_id: "notes.app".into(), target: RouteTarget { kind: "celld-app".into(), app_name: Some("notes".into()), sandbox_id: None }, system: false, enabled: true },
                RouteRecord { host_id: "disabled.app".into(), target: RouteTarget { kind: "celld-app".into(), app_name: Some("notes".into()), sandbox_id: None }, system: false, enabled: false },
            ],
        };
        // 每个测试独立目录：cargo 并行测试共享同一个临时文件会互相截断。
        // 唯一目录：原子计数器（line!() 在共享 helper 内对所有调用者同值，曾致并行竞争）。
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("iweb-kernel-routes-{sequence}", ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("routes.json");
        std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();
        RouteStore::load(&path)
    }

    const BASE: &str = "iweb.test";

    #[test]
    fn host_route_resolves() {
        let s = store();
        let resolved = resolve(&s, BASE, "admin.iweb.test", "/x?q=1").unwrap();
        assert_eq!(resolved.route.target.app_name.as_deref(), Some("admin"));
        assert_eq!(resolved.upstream_path, "/x?q=1");
    }

    #[test]
    fn path_alias_resolves() {
        let s = store();
        let resolved = resolve(&s, BASE, BASE, "/notes/app/sub/page").unwrap();
        assert_eq!(resolved.route.target.app_name.as_deref(), Some("notes"));
        assert_eq!(resolved.upstream_path, "/sub/page");
        assert_eq!(resolved.app_base_path.as_deref(), Some("/notes/app/"));
    }

    #[test]
    fn unknown_and_disabled_do_not_resolve() {
        let s = store();
        assert!(resolve(&s, BASE, "nope.iweb.test", "/").is_none());
        assert!(resolve(&s, BASE, "disabled.app.iweb.test", "/").is_none());
        assert!(resolve(&s, BASE, BASE, "/notanapp/app").is_none());
    }

    #[test]
    fn user_routes_never_reach_the_shared_celld_runtime() {
        let s = store();
        // system 记录：受保护控制面，允许直连 per-app celld。
        let admin = resolve(&s, BASE, "admin.iweb.test", "/").unwrap();
        assert!(matches!(s.action_for(&admin.route), Some(RouteAction::System { .. })));
        // 用户路由（system:false，无 ready sandbox）：fail-closed，绝不回退共享运行时。
        let notes = resolve(&s, BASE, "notes.app.iweb.test", "/").unwrap();
        assert!(s.action_for(&notes.route).is_none());
    }
}
