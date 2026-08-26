//! 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.2）：矩阵中的 iweb 宿主接口
//! iweb:secrets@1.0.0/store 与 iweb:config@1.0.0/store——组件只拿到 host `store.get`
//! 绑定（由 FD 3/4 快照支撑），没有宿主路径、没有枚举、没有写/删。
//! 规范权威：spec "The iweb secrets host interface is fixed and allowlisted" 与
//! "The iweb config host interface is fixed and non-secret"；WIT 本体在 crate wit/
//! 目录（逐字节来自 packages/contracts/wit，bindgen 锚点 world 为 host-imports）。
//!
//! 错误语义（closed variant；不含 key/value 回显）：
//! - key 文法不合法 → denied；
//! - key 不在快照键集（= allowlist）→ not-assigned（revision 0 空快照同样）；
//! - snapshot-expired / revision-stale 在一次执行生命周期内不可达（spec：激活采纳的
//!   快照在该执行存续期一直可读；过期只约束 handoff/adoption 窗口）；
//! - internal 仅保留给宿主自身不变式破坏。

use crate::jcs::validate_application_key;
use crate::wire::SnapshotValuesPayloadV1;
use wasmtime::component::bindgen;

bindgen!({
    path: "wit",
    world: "iweb:host/host-imports",
    // 宿主实现走可捕获错误路径（Host trait 返回 Result）。
    imports: { default: trappable },
});

/// 由快照载荷支撑的只读 store（secrets 与 config 共用同一实现；错误码前缀区分）。
#[derive(Debug, Clone, Default)]
pub struct HostStore {
    payload: Option<SnapshotValuesPayloadV1>,
}

impl HostStore {
    pub fn new(payload: Option<SnapshotValuesPayloadV1>) -> Self {
        Self { payload }
    }

    fn get(&self, key: &str) -> Result<String, iweb::secrets::store::Error> {
        // 键文法先行：不合法键既不命中也不回显。
        if validate_application_key(key).is_err() {
            return Err(iweb::secrets::store::Error::Denied);
        }
        match &self.payload {
            None => Err(iweb::secrets::store::Error::NotAssigned),
            Some(payload) => match payload.values.get(key) {
                // revision 0 的空快照：任何合法键都是 not-assigned（无分配状态）。
                None => Err(iweb::secrets::store::Error::NotAssigned),
                Some(value) => Ok(value.clone()),
            },
        }
    }
}

/// iweb:secrets/store 宿主实现（错误类型与 config 同构；bindgen 生成各自类型）。
pub struct SecretsHost(pub HostStore);

impl iweb::secrets::store::Host for SecretsHost {
    fn get(&mut self, key: String) -> Result<Result<String, iweb::secrets::store::Error>, wasmtime::Error> {
        Ok(self.0.get(&key))
    }
}

/// iweb:config/store 宿主实现。
pub struct ConfigHost(pub HostStore);

impl iweb::config::store::Host for ConfigHost {
    fn get(&mut self, key: String) -> Result<Result<String, iweb::config::store::Error>, wasmtime::Error> {
        Ok(self.0.get(&key).map_err(|error| match error {
            // secrets/config 的 closed variant 同构；逐 case 映射，不引入第二套语义。
            iweb::secrets::store::Error::NotAssigned => iweb::config::store::Error::NotAssigned,
            iweb::secrets::store::Error::Denied => iweb::config::store::Error::Denied,
            iweb::secrets::store::Error::SnapshotExpired => iweb::config::store::Error::SnapshotExpired,
            iweb::secrets::store::Error::RevisionStale => iweb::config::store::Error::RevisionStale,
            iweb::secrets::store::Error::Internal => iweb::config::store::Error::Internal,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> SnapshotValuesPayloadV1 {
        SnapshotValuesPayloadV1 {
            application_id: "alpha".into(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            revision: 3,
            keys: vec!["token".into()],
            values: [("token".to_string(), "v".into())].into_iter().collect(),
        }
    }

    #[test]
    fn assigned_key_reads_value_and_unknown_key_is_not_assigned() {
        let store = HostStore::new(Some(payload()));
        assert_eq!(store.get("token").expect("assigned"), "v");
        assert!(matches!(store.get("other"), Err(iweb::secrets::store::Error::NotAssigned)));
        // revision 0 空快照：一切合法键 not-assigned。
        let empty = HostStore::new(Some(SnapshotValuesPayloadV1 {
            revision: 0,
            keys: vec![],
            values: Default::default(),
            ..payload()
        }));
        assert!(matches!(empty.get("token"), Err(iweb::secrets::store::Error::NotAssigned)));
    }

    #[test]
    fn malformed_key_is_denied_without_echo() {
        let store = HostStore::new(Some(payload()));
        for bad in ["UPPER", "a/b", "a b", ""] {
            assert!(matches!(store.get(bad), Err(iweb::secrets::store::Error::Denied)), "key {bad:?}");
        }
    }
}
