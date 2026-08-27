<!-- 用户原始需求（2026-08-27）：起草 OpenSpec 变更 add-wasm-host-services，为 wasm 应用增加 iweb:kv、iweb:sql、iweb:logging 三个宿主能力；首轮只产出设计提案，不写实现。 -->
<!-- 正交意图：声明三个 wasm host capability 的产品动机、边界与影响；把能力矩阵升级和既有 wasm runtime 规范的关系登记清楚。 -->

## Why

Wasm 应用目前只能获得 HTTP、配置和秘密读取能力，无法在不穿透应用沙箱边界的前提下保存应用状态、执行受控关系查询或发出可运营的诊断事件。为保持应用互不信任、节点 240MB envelope 与 Kernel 权威不变，需要把这些能力定义为逐版本 allowlist 的宿主接口，并把隔离、配额、durability 和 fail-closed 语义写成可测试的 OpenSpec 契约。

## What Changes

- 新增 `iweb:kv@1.0.0` import store WIT：提供应用级键值读写与删除；`list`、跨键原子性和一致性范围按 owner 决策项锁定后实现。
- 新增 `iweb:sql@1.0.0` import store WIT：提供参数化 SQL、受控事务边界、行/字节/语句配额和错误分类；不向组件暴露任意文件、Socket 或宿主数据库连接。
- 新增 `iweb:logging@1.0.0` import logger WIT：提供结构化等级写入、有界背压/丢弃和诊断投影；日志不得进入 Kernel audit，也不得把 wasmd stdout/stderr 重新解释为应用日志。
- 将 wasm 能力矩阵从 revision 1 扩展为 revision 2，逐版本记录三个新接口及其策略、配额和 capability hash；缺失或不匹配时发布门继续关闭，revision 1 不作隐式 fallback。
- 将 host-service 绑定写入 wasm admission proof、catalog entry、`wasm-control-state-v2` 的同一 `controlRevision` CAS 链；运行时 KV/SQL 数据和 logging 事件不推进控制态 revision。
- 为 KV/SQL/日志定义每应用隔离、配额超限、重启/快照、错误码和观测边界，并复用现有秘密/config 的无枚举、FD 通道隔离、Kernel 权威与应用 sandbox 法。
- **BREAKING**：声明新接口但没有对应 allowlist、capability record、后端分区或配额绑定的版本不得物化、启动或激活；旧 revision 记录不能启用新接口。

## Capabilities

### New Capabilities

- `wasm-host-kv`：wasm 应用的隔离键值存储接口、原子性/一致性、配额、durability 和错误契约。
- `wasm-host-sql`：wasm 应用的受控 SQL 查询与事务接口、SQLite 方言边界、资源配额和恢复语义。
- `wasm-host-logging`：wasm 应用的结构化日志接口、有界丢弃、诊断投影和与 Kernel audit 的隔离。

### Modified Capabilities

- `wasm-application-runtime`：能力矩阵升级到 revision 2；admission/catalog/capability record、host-service policy hash、v2 CAS 与发布门必须共同绑定三个新接口。

## Impact

影响 `packages/contracts` 中的 WIT/共享 wire 记录、`wasm-catalog` 与 capability record 校验、Kernel 的 wasm admission/control-state 投影、supervisor/wasmd 的 host implementation、每应用存储配额与观测投影，以及 `tests/` 的跨实现 golden/负向测试。RustFS 继续承担节点对象存储和备份，不成为事务型 SQL/KV 的共享权威；现有 secrets/config FD handoff socket 不扩展为通用数据通道。发布门、应用 sandbox 隔离法、owner Bearer 权限和 `IWEB_API_TOKEN` 保持不变。

