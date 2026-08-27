<!-- 用户原始需求（2026-08-27）：为 add-wasm-host-services 起草可执行任务清单；首轮仅产出提案，所有实现任务保持未勾选。 -->
<!-- 正交意图：按依赖拆解 contracts、Kernel、supervisor/wasmd、测试与部署工作；显式把 owner 决策作为实现前置。 -->

## 1. Owner Decisions And Contract Freeze

- [ ] 1.1 记录 K1：确认 `iweb:kv/store` 是否包含有界 prefix/cursor `list`，并冻结 WIT/profile revision
- [ ] 1.2 记录 K2：确认 KV 单 key 线性化 CAS 是否为 v1 一致性边界
- [ ] 1.3 记录 S1：选择 `minimal-sqlite-v1` 或 owner 批准的完整 SQLite 方言 profile
- [ ] 1.4 记录 S2：确认 SQL 仅 per-call 隐式事务，或定义独立的跨调用 transaction-handle profile
- [ ] 1.5 记录 L1：确认 logging 仅 bounded memory/monitor，或批准独立 RustFS 归档 profile
- [ ] 1.6 记录 Q1：确认 KV+SQL 共享 `resources.storageBytes` aggregate，或冻结分别配额的计费/拒绝语义
- [ ] 1.7 记录 H1：确认 `iweb-wasmd-abi@1.1.0` minor bump，或批准 additive `1.0.0` 兼容解释

## 2. Contracts And WIT

- [ ] 2.1 在 `packages/contracts/wit/` 增加冻结后的 `iweb-kv.wit`、`iweb-sql.wit`、`iweb-logging.wit`，并为每个方法生成 import/export 方向负例
- [ ] 2.2 在 `packages/contracts/` 增加 host-service policy、error、quota、digest 和 diagnostic wire 类型，拒绝未知字段与非 JCS 输入
- [ ] 2.3 生成 Rust/TypeScript/wasmd 可复用的类型绑定与跨语言 golden vectors，验证字节级相等和 UTF-8/长度边界

## 3. Capability Matrix And Admission Identity

- [ ] 3.1 实现 `CapabilityMatrixV2`/node capability record 的精确 schema、hash、owner CAS 与 v1/v2 隔离
- [ ] 3.2 将 `hostServices` profile、matrix revision、host ABI、capability record pin 和 `hostServicePolicyDigest` 纳入 v2 normalized policy/proof/version digest
- [ ] 3.3 扩展 wasm catalog entry、acceptance record 与 publication gate，缺失或不匹配时保持 fail-closed 且不从 v1 fallback
- [ ] 3.4 在 admission/closure scanner 中校验三种 import 的声明集合、方向、版本和 profile 一一对应

## 4. Kernel Authority And Persistent Data Plane

- [ ] 4.1 在 Kernel wasm registry/control-state 中加入 service policy、schema/backup reference 与 aggregate quota ledger digest，并让所有控制变更走同一 `controlRevision` CAS
- [ ] 4.2 实现每应用独立 KV backend、key/version CAS、bounded prefix cursor（若 K1 选择）及 post-commit quota 检查
- [ ] 4.3 实现每应用独立 SQL backend、参数绑定、方言/事务 profile、结果/锁/时间限制和原子 quota 检查
- [ ] 4.4 保证 KV/SQL 数据面 mutation 不推进 control revision、不写 supervisor journal、admission proof、route 或 audit
- [ ] 4.5 实现应用级数据备份/恢复身份校验、quiesce 顺序和损坏/恢复中 fail-closed 语义

## 5. Supervisor And Wasmd Host Services

- [ ] 5.1 将 KV/SQL/logger host imports 接入 wasmd，绑定完整 execution identity、policy digest 和 sandbox-local backend
- [ ] 5.2 实现 logging 结构化字段校验、bounded buffer、`accepted`/`dropped` outcome 与 dropped counter
- [ ] 5.3 保持 stdout/stderr bounded discard，拒绝把日志或服务数据转入 snapshot FD/HTTP socket/通用 ancillary 通道
- [ ] 5.4 接线 owner diagnostic/monitor projection，隐藏跨应用数据、SQL 参数/结果、KV 值、secret/config 与 owner credentials
- [ ] 5.5 对 supervisor/wasmd 重启、execution generation 替换、旧 policy 和后端损坏执行精确恢复/拒绝路径

## 6. Isolation And Resource Evidence

- [ ] 6.1 验证每应用目录/文件属主、权限、路径派生和 sandbox 访问边界；证明不能跨应用或访问 RustFS/Kernel socket
- [ ] 6.2 为 service profile 建立 CPU、内存、磁盘、并发、语句/结果/事件边界，复用 node capability record 的 reserve/maximum 规则
- [ ] 6.3 在受控 Linux 拓扑测量 host service reserve、240MB node envelope、SQLite/WAL 峰值和日志丢弃行为；缺失 arch 证据保持 gate 关闭

## 7. Contract And Failure Testing

- [ ] 7.1 增加 WIT import-direction、unknown package/version、profile/import mismatch 和 digest/CAS 负向测试
- [ ] 7.2 增加 KV 正/负向测试：单 key CAS、list cursor 绑定、quota 原子拒绝、跨应用拒绝、重启持久化
- [ ] 7.3 增加 SQL 正/负向测试：参数绑定、方言边界、禁止 ATTACH/load_extension/多语句、事务原子性、结果/锁上限和恢复
- [ ] 7.4 增加 logging 正/负向测试：结构化边界、bounded drop、审计/stdio 隔离、重启 retention 和归档 profile gate
- [ ] 7.5 增加跨实现 Kernel/supervisor/wasmd golden 与端到端链路测试，验证 data-plane mutation 不改变 v2 controlRevision

## 8. Deployment, Documentation And Release Gate

- [ ] 8.1 更新节点镜像/installer/packaging 的 per-app data 目录、只读/读写挂载、备份与恢复说明，不向应用暴露宿主路径
- [ ] 8.2 生成与校验 v2 capability/catalog/acceptance evidence；任何 profile/ABI/arch 缺证据均保持 publication gate 关闭
- [ ] 8.3 运行 contracts/supervisor/Kernel 全量测试、clippy deny-all、Bun/typecheck 和 `openspec validate --strict`
- [ ] 8.4 由 owner 验收隔离、配额、durability、日志诊断与回滚数据语义后，才允许同步主规范、归档 change 或打开发布门

