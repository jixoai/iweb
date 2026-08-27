<!-- 用户原始需求（2026-08-27）：起草 add-wasm-host-services 设计，增加 iweb:kv、iweb:sql、iweb:logging 三个 wasm 宿主能力；首轮仅产出提案，不写实现。 -->
<!-- 正交意图：确定宿主接口与后端边界；确定隔离、配额、durability 与观测语义；确定 revision 2、catalog、FD 通道和 v2 CAS 的接线。 -->
<!-- 不可调和原因：三个服务共享同一 wasm admission、sandbox 和控制态契约，若拆开会重复定义能力矩阵、身份围栏和失败语义。 -->

# add-wasm-host-services Design

## Context

现有 `wasm-application-runtime` 只允许 HTTP、`iweb:config` 与 `iweb:secrets` host imports。组件没有文件系统、socket 或宿主数据库权限；Kernel 是应用身份、准入、active pointer 和 `wasm-control-state-v2` 的权威，supervisor/wasmd 只执行被围栏的命令。秘密/config 的启动快照走独立的只读 FD raw-UDS，不能把该通道泛化为应用数据通道。

本变更要增加持久应用状态和诊断能力，同时保持每应用互不信任、节点 240MB envelope、owner 凭证隔离和发布门 fail-closed。参考 `proposal.md` 的动机与范围；本文件只说明落点和取舍。

## Goals / Non-Goals

**Goals:**

- 用固定版本的 Component Model `import` world 为 KV、SQL、logging 建立跨 Rust/TypeScript/wasmd 的可验证 ABI。
- 让每个服务的 allowlist、策略、上限和 capability hash 进入不可变 admission identity，并由 revision 2 capability record 约束。
- 让数据面操作在应用专属后端内完成，成功返回只代表持久提交；服务数据不冒充 Kernel 控制态或 audit。
- 对超限、后端不可用、版本/租约不匹配和重启恢复定义稳定的 fail-closed 行为。
- 保留旧 wasm revision 1 版本的行为；新接口没有 v2 record、catalog binding 和 acceptance evidence 时不可物化或启动。

**Non-Goals:**

- 不向组件开放 WASI filesystem、socket、`wasi:tls`、RustFS 凭证、Kernel API 或任意宿主数据库连接。
- 不把 KV/SQL 事务状态、日志正文或运行时数据写入 `wasm-control-state-v2`、admission proof、supervisor journal 或 Kernel audit。
- 不承诺跨应用查询、跨应用事务、跨节点复制、Durable Objects 等有状态运行时。
- 不在本轮实现代码、生成 acceptance record、打开发布门或修改主规范。

## Decisions

### 1. Host boundary and wire shape

三个包都使用 `import` 型 world，并把方法、参数、返回值和错误集合固定在各自 delta spec 中。WIT 方法只传值，不传路径、FD、socket、owner token 或宿主对象句柄。宿主为每次调用附加当前应用/版本/执行代次，但这些身份不由组件提交。

推荐的 v1 形状如下：

| 服务 | 接口 | 推荐语义 |
| --- | --- | --- |
| KV | `iweb:kv/store` | `get/set/delete` 加有界 prefix/cursor `list`；单 key 原子操作，版本号用于 CAS |
| SQL | `iweb:sql/store` | 参数化单语句 `query/execute`；默认每调用一个隐式事务；禁止多语句和外部附着 |
| logging | `iweb:logging/logger` | `write(event)`，结构化等级和有界字段；返回 `accepted` 或 `dropped` |

`list`、SQL 方言/显式事务、日志持久化和配额口径见“Owner decisions required”。在 owner 选择前，发布门必须保持关闭；不得通过运行时猜测一个 profile。

### 2. Storage backend

采用 supervisor/wasmd 管辖的每应用独立 SQLite 文件，而不是 RustFS 桶投影或 Kernel 内嵌数据库：

```text
/data/kernel/wasm-data/<applicationId>/kv.sqlite3
/data/kernel/wasm-data/<applicationId>/sql.sqlite3
```

路径由 Kernel 记录的 application identity 派生，组件不能提供路径；目录和文件由 host service 身份创建，应用进程只通过 WIT 调用访问。KV 与 SQL 使用不同文件，避免 SQL 查询窥探 KV 内部表或借内部表绕过配额。RustFS 只承担节点备份/导出对象，不是在线事务权威；Kernel 不在控制进程内嵌入应用数据库。

每应用目录只挂载到对应 sandbox 的 host service；另一个 sandbox、Kernel、gateway 和 celld operator listener 均无读取权限。应用删除、迁移和备份遵循既有 owner-authorized 生命周期，不因一次版本激活而重建或清空数据。

### 3. Isolation and quota accounting

`resources.storageBytes` 继续是应用总持久数据预算。KV 与 SQL 的逻辑占用按 canonical key/row bytes、SQLite page 使用量和固定 metadata overhead 计入同一 aggregate envelope；每次写入先计算 post-commit usage，超限则整次拒绝，不产生部分写入。服务级上限只能收紧 aggregate envelope，不能扩大它。

节点 `CapabilityMatrixV2` 记录每个服务的最大 key/value/statement/result/event/buffer 参数。版本请求的 host-service policy 必须逐字段不超过 node maxima；缺失、非整数、单位不一致或 reserve 无法证明时 fail-closed。内存预算仍遵循既有 `memoryBytes - reserveBytes` 规则；数据库磁盘配额不从镜像标签、RustFS 对象大小或进程 RSS 推断。

### 4. Durability and recovery

KV/SQL 成功返回的线性化点是对应 SQLite 事务提交并完成节点 durability profile 要求的 flush；读操作只读取已提交版本。应用重启、wasmd 重启、execution generation 替换和版本 rollback 默认保留应用数据；rollback 只切换代码/route identity，不隐式回滚数据。节点备份在 quiesce 后纳入每应用数据库，恢复时校验 applicationId、文件 digest 和 schema record，不能把一个应用的数据恢复到另一个 ID。

服务数据不走 secrets/config 快照 FD，不进入 activation lease，也不推进 `wasm-control-state-v2.controlRevision`。控制态只记录 service policy、capability pins、数据 schema/backup references（如需要）和命令投影；每次 `get/set/query/write` 都是实时 host call。后端损坏、锁超时、恢复中的文件或 quota ledger 不一致时，host 返回 `unavailable`/`internal`，不以空数据代替。

### 5. SQL safety profile

默认推荐 `minimal-sqlite-v1`：参数化单语句，允许受控的 `SELECT`、`INSERT`、`UPDATE`、`DELETE` 及有限 schema DDL；拒绝 `ATTACH`、`DETACH`、`load_extension`、外部 virtual table、任意 `PRAGMA`、多语句脚本和宿主文件路径。每次调用一个隐式事务；如需批量原子操作，使用一个有界 batch 请求，而不是跨请求持有事务句柄。

完整 SQLite 方言和跨调用显式事务会增加锁持有、长查询、schema 漂移和资源 DoS 面，因此不作为默认 profile。若 owner 选择它，仍必须保留参数绑定、语句/结果/时间/锁等待上限以及禁用外部附着的硬边界，并以新的 policy profile/hash 记录，不能改变已激活版本的语义。

### 6. Logging path and audit separation

默认 logging 是每应用有界内存 ring buffer 加 monitor projection。队列满时立即返回 `dropped`，不阻塞应用、不重试、不把 stdout/stderr 变成应用日志；host 只记录经过 schema 校验的 level/message/fields，并由 host 补充时间和 execution identity。日志正文不进入 Kernel audit、admission proof、owner token 记录或 supervisor command journal。

RustFS 持久归档可作为单独 profile，但必须有独立 retention、大小上限、写入失败语义和 owner-visible opt-in；不能让“日志持久化”默认为控制面审计。所有 profile 都禁止 host 主动注入 secret/config 值、Authorization、请求正文和其他 sandbox 的身份。

### 7. Matrix, catalog and v2 CAS

新增 `CapabilityMatrixV2`，在 v1 imports 基础上精确增加：

```text
{package:"iweb:kv@1.0.0", interface:"store", direction:"import"}
{package:"iweb:sql@1.0.0", interface:"store", direction:"import"}
{package:"iweb:logging@1.0.0", interface:"logger", direction:"import"}
```

建议 host ABI 升为 `iweb-wasmd-abi@1.1.0`，并以 `wasmVersionDigestV2` 将 `runtime.hostServices` policy 纳入 version identity。v1 capability record、catalog binding、acceptance record 不能为 v2 import 提供 fallback。每个 v2 binding 同时钉住 matrix revision、ABI、node capability revision/hash、service policy digest 和 catalog revision/hash。

Kernel 在 admission、outbox append、ack projection、service policy mutation、route pointer CAS 和恢复投影中继续使用同一个 `controlRevision` CAS；服务数据面 mutation 不改变该 revision。supervisor journal 只保存 identity/policy digest/结果，不保存 KV 值、SQL 参数、结果行或日志正文。

### 8. FD channel reuse rule

不复用 `/run/iweb-sandbox/snapshot-fd.sock`。该 socket 继续只承载 secrets/config 的固定槽位、单 FD、单帧 handoff；KV/SQL/logging 使用 wasmd host call，任何 `SCM_RIGHTS`、路径字符串或 raw snapshot magic 出现在 execution HTTP 或 service call 中都拒绝。这样可保持 secrets/config 的三方 digest 链和应用数据的实时 durability 互不污染。

## Risks / Trade-offs

- **[SQLite host CPU/磁盘争用]** → 每服务限制 statement、rows、bytes、lock wait 和 concurrency；节点 capability record 缺失时不开服务，并在 240MB envelope 之外单独记录磁盘/CPU测量。
- **[KV/SQL 共用 aggregate quota 造成服务间竞争]** → 写入前按 post-commit usage 原子检查；可选 service soft caps 只能收紧总额，quota ledger 与文件状态不一致时 fail-closed。
- **[日志丢弃导致诊断缺口]** → 返回显式 `dropped`、维护 per-app dropped counter，并在 monitor projection 展示；审计仍由 Kernel 独立产生。
- **[完整 SQLite/显式事务扩大攻击面]** → 默认不启用；若 owner 选择，必须使用新的 policy profile/hash、独立测试矩阵和更低的 resource maxima。
- **[版本 rollback 与数据 schema 不匹配]** → 数据不自动回滚；版本发布必须携带 schema compatibility metadata，host 对不兼容迁移返回稳定错误，owner 通过独立迁移流程处理。
- **[RustFS 备份与在线提交不一致]** → 备份前 quiesce sandbox 并等待事务 drain；恢复只接受带 application identity/digest 的完整集，不能宣称跨服务原子快照。

## Migration Plan

1. 先由 owner 选择下方决策项并冻结 `CapabilityMatrixV2`、ABI、service policy profile 和配额模式；未冻结前保持 wasm v2 gate 关闭。
2. 发布同时包含 v2 contracts/WIT、node capability record、catalog entry、acceptance record 和跨实现 golden vectors；现有 v1 record/version 不改写。
3. Kernel 启动时验证 v1/v2 两套 record，旧版本继续走 v1；声明任一新 import 的版本必须使用 v2 digest/proof、v2 binding 和 v2 gate。
4. 新版本首次启动时创建空的 per-app KV/SQL 后端和 bounded logging buffer；创建失败则 preparation 不 ready，不影响旧 active execution。
5. 回滚仅回到保留的同一 runtime-kind/version binding，保留应用数据；若 owner 要恢复历史数据，走 quiesced backup restore 并产生独立审计事件。
6. 若 v2 后端或 host ABI 发布失败，关闭 `IWEB_WASM_PUBLICATION_ENABLED` 或撤销对应 catalog entry；v1 版本仍按原 gate 运作，不能把 v1 记录解释为 v2。

## Owner Decisions Required

以下选项会改变 WIT 或可观察语义，不能由实现阶段自行猜测：

| 编号 | 分歧 | 推荐方案 | 需要 owner 选择 |
| --- | --- | --- | --- |
| K1 | KV 是否暴露 `list` | 暴露有界 prefix + cursor + limit，按 key UTF-8 排序；无全量无界枚举 | `list` 或 `get/set/delete` only |
| K2 | KV 一致性范围 | 单 key 线性化 CAS；不提供跨 key 事务 | 单 key CAS 或更弱/更强模型 |
| S1 | SQL 方言 | `minimal-sqlite-v1`，单语句、参数化、隐式 per-call transaction | 最小子集或完整 SQLite profile |
| S2 | SQL 事务 | 默认无跨调用句柄；有界 batch 作为一次调用 | per-call only 或显式 transaction handle |
| L1 | logging 持久化 | 仅 bounded memory + monitor projection | 是否另开 RustFS 归档 profile |
| Q1 | 配额口径 | KV+SQL 共享 `resources.storageBytes` aggregate，服务级仅能收紧 | 共享 envelope 或分别计费/配额 |
| H1 | host ABI | 新接口使用 `iweb-wasmd-abi@1.1.0` | ABI minor bump 或维持 1.0.0 的 additive 解释 |

在这些选择被记录前，本 Change 只作为审批提案；任务清单不得被视为已授权实现。

