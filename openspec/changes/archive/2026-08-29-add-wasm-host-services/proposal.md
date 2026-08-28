<!-- 用户原始需求（2026-08-27）：硬化 add-wasm-host-services 提案，闭合 V2 wire、统一配额原子权威和 wasmd host-call 传输；只改 OpenSpec 四件套，不写实现。 -->
<!-- 正交意图：声明三个宿主能力的产品边界；声明跨层身份/回放契约；声明 owner 决策与发布门边界。 -->

## Why

Wasm 应用目前只有 HTTP、config 和 secrets 宿主面，无法在不获得文件系统或 RustFS 凭证的情况下保存应用状态、执行受限关系查询或输出可审计的诊断事件。本变更为不可信应用增加隔离的 KV、SQL 和 logging 能力，并把它们绑定到同一份 admission、catalog、execution fence 与 publication gate 身份，避免“服务已开但版本身份、配额或回放语义未闭合”。

## What Changes

- 新增 `iweb:kv@1.0.0/store`、`iweb:sql@1.0.0/store` 和 `iweb:logging@1.0.0/logger` 三个 import-only Component Model 能力，固定 WIT 值域、上限、错误 wire 和隔离边界。
- 定义 `HostServicePolicyV2`、`HostServiceBindingV2` 及 admission proof、catalog、control state、execution command、readiness、metrics、activation、rollback 的版本化投影；policy digest 使用明确的字节序列和 hash domain，并绑定 `iweb-wasmd-abi@1.1.0`。
- 规定 V1 与 V2 共存：只使用旧 imports 的版本继续走 V1；声明任一新服务的版本必须具备完整 V2 record/catalog/acceptance 证据，V1 不得 fallback 或被解释为 V2。
- 采用每应用独立 SQLite 后端和共享 quota ledger。控制态只保存静态策略摘要；动态用量、reservation、finalize 和恢复记录由数据面权威，监控只投影，不推进 `controlRevision`。
- 定义 wasmd 内嵌 host provider 的 canonical host-call frame、身份注入、帧上限、deadline/cancel、稳定错误、幂等重放和 response-lost 语义；不得通过 supervisor 外部 RPC、snapshot FD 或应用提供的路径绕过绑定。
- 把 `guestMemoryBytes = resources.memoryBytes - reserveBytes`、每应用数据目录与权限、`sqlite-full-fsync-v1` durability、KV cursor/tombstone、logging bounded drop 与敏感字段 redaction 纳入发布门可验证契约。
- 保持应用 sandbox、Kernel v2 CAS、secrets/config 独立 FD 通道、Kernel audit、公开路由和现有发布门 fail-closed；本轮不写实现、不生成 acceptance record、不同步主规范。

## Capabilities

### New Capabilities

- `wasm-host-kv`: 应用隔离的有界 KV import、单 key CAS、可选有界 list、共享配额和持久语义。
- `wasm-host-sql`: 应用隔离的参数化 SQLite import、固定方言 profile、per-call 事务、结果/资源上限和恢复语义。
- `wasm-host-logging`: 结构化等级写入、有界 accepted/dropped 结果、owner diagnostics 投影与 Kernel audit/stdio 分离。

### Modified Capabilities

- `wasm-application-runtime`: 增加 host-service V2 身份、wire schema、catalog/acceptance 绑定、V1/V2 共存、quota authority 和 embedded host-call 传输契约。

## Impact

- Contracts/WIT：新增三个 import world、V2 policy/binding/error/quota/frame 类型及跨实现 golden vectors。
- Kernel：扩展 capability matrix、admission proof、`wasm-control-state-v2` 静态服务摘要、execution/readiness/metrics/activation/rollback 投影与发布门选择；数据面 mutation 不改变控制 revision。
- supervisor/wasmd：在 execution identity 下以内嵌 provider 打开每应用 SQLite 和 bounded logger，执行 host-call framing、幂等和恢复检查，不提供第二个无认证入口。
- 测试/部署文档：覆盖身份错代次、跨应用、伪造字段、quota 崩溃恢复、response-lost、cursor/tombstone、logging redaction、reserve 与数据目录证明。
- Owner 需要在实现前裁决 K1（KV list）、S1（SQL 方言广度）、L1（日志是否 RustFS 归档）和 H1（ABI minor bump 的发布节奏）。K2（单 key 线性化 CAS）、S2（单调用隐式事务）和 Q1（共享 `resources.storageBytes` envelope）在本 Change 中收敛，不再作为决策项。
