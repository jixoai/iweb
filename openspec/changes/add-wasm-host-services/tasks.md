<!-- 用户原始需求（2026-08-27）：为 add-wasm-host-services 硬化轮生成可执行任务清单；只改 OpenSpec 四件套，不写实现。 -->
<!-- 正交意图：按 V2 contracts、Kernel 权威、wasmd provider、测试和部署证据拆解；所有实现任务保持未勾选。 -->

## 1. Owner Decision And Contract Freeze

- [x] 1.1 记录 K1：确认首个 KV profile 是否包含有界 list(prefix,cursor,limit)，并冻结 WIT/profile revision
- [ ] 1.2 记录 S1：确认 minimal-sqlite-v1 方言边界与允许的 schema DDL 子集
- [ ] 1.3 记录 L1：确认 logging 是否只保留 bounded memory + monitor，或批准独立 RustFS archive profile
- [ ] 1.4 记录 H1：确认发布 iweb-wasmd-abi@1.1.0 与 V2 catalog/acceptance 记录
- [ ] 1.5 将已收敛的 K2（单 key 线性化 CAS + delete tombstone）、S2（单调用隐式事务）和 Q1（共享 resources.storageBytes envelope）写入冻结记录；三者是设计约束，不是 owner 决策项

## 2. V2 Wire, Identity And Catalog

- [x] 2.1 定义严格 JCS 的 HostServicePolicyPayloadV2/HostServicePolicyV2、HostServiceIdentityV2、Digest32 与 digestV2 domain，拒绝未知字段、重复键和 hex 二次哈希
- [ ] 2.2 定义 AdmissionProofV2、CatalogBindingV2、ControlStateApplicationV2、ExecutionCommandV2、ReadinessLeaseV2、MetricsSampleV2、Activation/RouteEventV2、RollbackRecordV2 的完整字段、self-digest 与 authority
- [ ] 2.3 将 matrixRevision:2、iweb-wasmd-abi@1.1.0、policy/capability/catalog/acceptance pins 接入 versionDigest、versionId 和所有 P/E/route 投影
- [ ] 2.4 实现 V1/V2 parser 与 gate 隔离：仅旧 imports 走 V1；任一新 import 缺 V2 证据时 fail-closed，禁止 fallback
- [x] 2.5 为 command/activation/rollback/host-call 实现 byte-identical replay、ID conflict、stale fence、response-lost 和 unknown schema/domain 负例
- [ ] 2.6 生成 Rust/TypeScript/wasmd golden vectors，验证 JCS 字节、摘要、catalog/acceptance 绑定和跨层 identity byte equality

## 3. Capability, Admission And Kernel Authority

- [ ] 3.1 扩展 CapabilityMatrixV2/node capability record，精确 allowlist 三个 import、profile maxima、reserve 与 architecture binding
- [ ] 3.2 将 hostServices policy 与 digest 纳入 admission proof、visible predicate、materializer receipt 和 wasm version identity
- [ ] 3.3 扩展 catalog/acceptance validator 与 publication gate；缺 evidence、owner decision、reserve 或 profile 时保持关闭
- [ ] 3.4 在 wasm-control-state-v2 中仅保存静态 service profile、limits、policy digest、data-directory/durability profile 与 schema/backup references
- [ ] 3.5 确保 admission、service-policy mutation、outbox、ack、route CAS、activation、rollback 和 recovery repair 共用 expectedControlRevision；数据面不推进该 CAS
- [ ] 3.6 将 guestMemoryBytes = resources.memoryBytes - reserveBytes 纳入 admission/preparation gate，缺失或 reserveBytes >= memoryBytes 时拒绝

## 4. Quota Ledger And Per-Application Data

- [ ] 4.1 创建由 applicationId 派生的 0700 per-app 目录与 kv.sqlite3、sql.sqlite3、quota.sqlite3，执行 no-symlink/owner/mode/integrity 校验
- [ ] 4.2 实现单一 quota ledger 的 serialized reserve、backend operation marker、finalize/release 与 shared envelope/service cap 检查
- [ ] 4.3 实现 KV backend：单 key CAS、版本不回绕、delete tombstone、K1 有界 cursor、cursor 绑定与 expiry
- [ ] 4.4 实现 SQL backend：参数绑定、S1 方言 denylist、单调用隐式事务、结果/锁/时间/并发上限
- [ ] 4.5 按 sqlite-full-fsync-v1 定义提交成功边界、WAL/page usage 测量、备份 quiesce、schema/identity restore 校验
- [ ] 4.6 实现崩溃恢复表：reserved 无 marker、reserved 有 marker、孤立 marker、committed replay、impossible ledger state 的确定性处理
- [ ] 4.7 保证配额/数据 mutation 不写 control state、admission proof、route、readiness、supervisor journal 或 Kernel audit

## 5. Embedded Wasmd Host Provider

- [x] 5.1 接入 embedded-host-services-v2 provider，使用 Kernel/supervisor 注入的 opaque execution context 和 host-managed backend handles
- [ ] 5.2 实现 length-prefixed u32 big-endian canonical JCS frame、1..1048576 上限、base64url payload 与 closed HostCallErrorV2 wire
- [ ] 5.3 实现 deadline/cancel、SQLite progress checkpoint、timeout rollback、bounded error detail 和 no-payload leakage
- [ ] 5.4 实现 identity/policy/P-E fence 校验、application isolation、backend selector 拒绝和 no second unauthenticated entrance
- [ ] 5.5 实现 requestId at-most-once marker、identical replay、REQUEST_ID_CONFLICT、STALE_EXECUTION 与 REPLAY_UNAVAILABLE
- [ ] 5.6 将 KV/SQL/logging WIT imports 绑定到 provider；secrets/config 仍只走 snapshot FD，服务调用禁止 FD/path/ancillary data

## 6. Logging And Diagnostics

- [x] 6.1 实现结构化 level/message/field 校验、reserved sensitive key redaction、host-added identity/timestamp
- [ ] 6.2 实现 per-app bounded ring、accepted/dropped outcome、drop counter 与非阻塞满队列语义
- [ ] 6.3 保持 wasi:cli/stdout/stderr bounded discard，禁止日志进入 Kernel audit、owner token、SQL/KV payload 或跨应用 projection
- [ ] 6.4 若 L1 批准 archive，单独实现 retention/size/encryption/failure/recovery profile 与 owner-only read path；否则拒绝隐式 RustFS fallback
- [ ] 6.5 接线 owner-authorized monitor projection，只暴露本应用 bounded diagnostics、quota/recovery counters 和稳定 reason codes

## 7. Isolation, Recovery And Deployment Evidence

- [ ] 7.1 验证 host provider、数据库目录、RustFS、Kernel socket、celld operator listener 和其他 sandbox 的访问边界
- [ ] 7.2 覆盖 supervisor/wasmd restart、execution generation replacement、activation、rollback、route recovery 与 data retention
- [ ] 7.3 更新 installer/packaging/mount 文档：per-app data directory、只读/读写边界、备份/quiesce、V2 acceptance evidence；不得向组件暴露宿主路径
- [ ] 7.4 在受控 Linux 拓扑测量 reserve、240MB envelope、SQLite/WAL 峰值、quota contention、host-call deadline 和 logging drop；证据缺失保持 gate 关闭

## 8. Contract And Failure Tests

- [ ] 8.1 增加 WIT import-only、unknown package/version、V1/V2 fallback、profile/import mismatch、JCS/hash-domain 和 catalog/acceptance mismatch 测试
- [ ] 8.2 增加 V2 cross-layer golden、P/E fence、forged identity、wrong generation、cross-application、response-lost/replay 测试
- [ ] 8.3 增加 KV CAS、tombstone、cursor scope/expiry、shared quota race、crash finalize、restart persistence 测试
- [ ] 8.4 增加 SQL parameter binding、dialect denylist、implicit transaction、result/lock limits、quota/crash recovery 测试
- [ ] 8.5 增加 logging validation、redaction、bounded drop、stdout/stderr isolation、archive-gate 与 monitor projection 测试
- [ ] 8.6 增加 data-plane mutation 不改变 controlRevision、route generation、readiness lease、admission sequence 和 audit 的回归测试

## 9. Verification And Release Gate

- [ ] 9.1 运行 contracts/supervisor/Kernel 全量测试、clippy deny-all、Bun/typecheck 与 OpenSpec strict validation
- [ ] 9.2 核对 V1 既有 migration/golden 测试保持通过，V2 证据与跨架构 reserve 记录完整
- [ ] 9.3 由 owner 验收 isolation、quota、durability、logging diagnostics、rollback data semantics 后，才允许同步主规范、归档 change 或打开 publication gate
