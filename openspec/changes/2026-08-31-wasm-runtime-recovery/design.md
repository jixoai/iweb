# Design: wasm runtime recovery

## 现状与证据（2026-08-31 真实节点）

- 演示链路（版本 e1f03cbe…-19/-21/-22，应用 `demo`）证明：MCP admit → 自动
  prepare/start → relay FD 交接 → wasmd（Wasmtime）spawn → fence 投影
  （9e139a3）→ activation CAS（lease 消费、routeGeneration 递增）→
  `iweb_domain_register` → `demo.app.<base>` 与 `<base>/demo/app` 公网 200。
- 容器重建后：wasmd 全灭、无任何恢复；`demo.app` 路由被启动路径清除
  （`scripts/iweb-entrypoint.sh:370` 无条件 `mc cp local/iweb-system/routes.json
  → ${kernel_state}/routes.json`）；重新准入 -22 + 重注册路由后恢复。
- admission join 幽灵：`wasm_admission.rs:1285` join 分支返回 journal 行
  `state`；部分状态丢失（objects 在、DB 行无）时 MCP 收到 `state:"visible"`
  而 `AdmittedVisible` 为假；且 `wasm_runtime.rs` `load_admitted_visible_proofs`
  对任一行谓词 Err 整轮 `?` 中止——幽灵行会让后续所有 admission 提交 503。
- policyless reserve：`wasm_runtime.rs` `preparation_reserve_gate` 仅对携带
  host-service policy 的 proof 生效（V1 恒过）；-20（memoryBytes 256 MiB ≤
  对位 reserve）通过编排、spawn 阶段被 wasmd 以 `WASM_RESOURCE_RECORD_INVALID`
  拒绝（`wasmd/src/capability.rs`，匹配逻辑为 binding 工件身份+架构的
  `runtimeReserves` 精确查找，注释明言「无默认值」）。
- Kernel 侧能力数据缺失：`gate-node-identity.json`（`wasm_runtime.rs`
  GateNodeIdentityFileV1）只 pin 架构与各 hash；`runtimeReserves` 与
  `restart` 预算内容仅存在于 contracts 默认值与 wasmd 侧加载器。

## Spec 条款对照（本变更不新立信任模型，只兑现既有条款）

| 缺口 | 已归档条款（openspec/specs/wasm-application-runtime/spec.md） |
| --- | --- |
| 死亡检测/有界恢复 | 「Lifecycle keeps one routed execution…」："If an active execution dies or exceeds an engine limit, Kernel atomically changes the active route to unavailable … allocates a higher preparationGeneration … then a higher executionGeneration … applies restart.maxRestarts within restart.windowMs"；restart 预算定义于 NodeCapabilityRecordV1（`restart.maxRestarts` 0..100 / `windowMs` 1000..86400000） |
| lease 生产签发 | 「Wasm readiness is a full identity attestation」："The probe grants a readiness lease only from an exact v2 200…"；lease wire 条款（现文定义基础 ReadinessLeaseV2；激活面实际消费 ServiceReadinessLeaseV2——本变更同步法条，见 D3） |
| join 可见性 | 「Kernel-owned admission uses one visible-state predicate」："AdmittedVisible(version) is the only visibility predicate"；恢复表 "visible DB row, missing marker/receipt on verification → fail closed … require owner recovery" |
| reserve 前置 | 能力记录条款的 admission/preparation 规则（spec ~241 行）："reserveBytes >= resources.memoryBytes rejects"、无默认/零值替换；wasmd 错误契约（"admission or preparation must fail closed"） |
| 路由持久 | AGENTS.md「Kernel route registry 是唯一权威」+ workspace-and-routes「registration is explicit」（本变更为其补持久性场景） |

## 决策

### D0 能力内容投影（前置子任务，阻塞 D2/D6）

- `gate-node-identity.json` 升 schema 2：在既有 hash 投影上新增
  `runtimeReserves[]`（完整 binding 工件身份 + 架构 → `reserveBytes`）与
  `restart{maxRestarts,windowMs}`。**写入端是新代码**（今天该文件没有任何
  写入者——演示期为手工创建）：新增一个供给步骤（entrypoint 阶段或
  scripts 工具），读取与 supervisor/wasmd 同一
  `IWEB_SANDBOX_WASM_CAPABILITY_RECORD`（NodeCapabilityRecordV1 宿主文件），
  从中**计算派生** `runtimeReserves`/`restart`/`capabilityRecordRevision/
  Hash`（绝不手工拷贝，pin 不可漂移），root-only 写出。
- Kernel 读取 fail-closed（字段缺失/越界 → 恢复与 reserve 门拒绝启用并报
  owner 可见错误，绝不回退 contracts 默认值）。
- 不引入第二真相源：写端与 wasmd 侧 `capability.rs` 读同一记录文件派生。

### D1 存活 probe 由 Kernel 亲手做，经 gw ingress socket

- Kernel 拨 `${IWEB_SANDBOX_GATEWAY_DIR:-/run/iweb-sandbox/gw}/<sbx>/ingress.sock`
  （寻址复用 `proxy.rs sandbox_ingress_socket`；wasmd listener 的 health 面
  经 gw 字节前置可达），GET v2 health attestation，与 **fence 记录 ⋈ 版本
  registry 行/outbox start 命令**（联合携带全部比对字段：sandboxId/
  versionId/package/binding/capability/secret/config/P/E）逐字段比对。判死
  判据：socket 缺失、拨号超时、非 200、**连接成功后复位/EOF**（wasmd 被
  SIGKILL 后前置 socket 仍在——前置与 wasmd 非同生共死）、或任一字段失配
  （失配=陈旧执行，同样不可路由）。
- 阈值：连续 N 次（缺省 3）失败才判死，周期 = 收敛循环 10s；成功一次即清零。
- **锁协议（评审阻塞项）**：本变更引入的每一次 supervisor/沙箱网络往返
  （存活 probe 与 readiness 采纳 query）都在锁外有界轮内执行，并入同一
  「锁内快照 → 锁外并发探测（单 probe 超时 ≤2s，总预算 < 收敛周期）→ 重取
  锁应用计数/翻转」序列；既有 outbox 投递循环维持锁内现状（其代价是
  per-pending-command 且自排空，与收敛周期同阶）。容器重启场景（全部
  socket 缺失、全部 probe 超时）下控制面互斥锁持有时长与现状持平。
- 独立 dialer（R3 已决）：UDS 上裸 HTTP/1.1 手写请求（对位 `proxy.rs` 既有
  转发层做法；reqwest 不支持 UDS）；不合成、不缓存：probe 结果只驱动
  「判死 + unavailable 翻转」，不写 fence.alive（其写者仍只有 start/stop/
  drain 投影路径），不从 probe 合成健康/指标值（`unavailable`/零值诚实法
  不变）。
- 备选（否决）：supervisor 上报死亡事件。否决理由：路由翻转是 Kernel 单一
  CAS 权威，判据必须与 fence/registry 事实同源；上报引入第二真相源与投递
  可靠性问题。

### D2 恢复序列：先 unavailable，后预算内重 preparation

1. 判死（或越引擎限）→ 同一 controlRevision CAS：active 指针翻
   `WasmActivePointerV1::Unavailable`（`WasmActivePointerV1::Unavailable` 与
   诚实 502 分发路径已存在），运维事件载体经 R1 spike 定稿。
2. 预算检查：`restart.maxRestarts/windowMs`（D0 投影）窗口滚动账本，持久化
   于 Kernel 自有 sidecar（对位 retirements/journal-head-hint 的 sidecar 模
   式，不碰 v2 控制态的 spec-exact 键集）；崩溃重放幂等不双计。
3. 有余量 → 走既有双代次迁移（`wasm_commands.rs` planner 语义）：prepare 于
   (P+1, **E+1**)，applied 后 start 于 (P+1, **E+2**)；secret snapshot 复用
   `ensure_initial_secret_snapshot`（P 参数化，已支持）。恢复命令走既有
   outbox/投递/ack 投影闭环（9e139a3 fence 翻转自动跟进）。
4. 重新激活：恢复 spawn 成功 + readiness 后，仍需 kernel-minted lease +
   一次 activation CAS 翻回 active（与首次激活同一 wire；恢复不自行路由。
   R2 讨论是否允许同版本自动重激活）。
5. 预算耗尽 → 版本 `stopped` + owner 可见崩溃/资源类别；无自动重试。
- 容器重启：Kernel 启动对全部 alive fence 跑同一 probe 判死路径，逐应用进入
  恢复；journal/outbox 幂等保证不双驱动。

### D3 lease 铸造：Kernel 权威，采纳可再生产

- wire 对齐（法条缺口）：现 spec lease 条款只定义基础 `ReadinessLeaseV2`（
  `iweb-readiness-lease-v2\n` digest 域）；激活面实际消费的是 service 形态
  `ServiceReadinessLeaseV2`（多 `hostServicePolicyDigest`、binding V2、
  `digestV2("iweb-wasm-readiness-v2", …)` 0x00 域——`wasm-health.ts` /
  `wasm_activation.rs` 292-315）。本变更 delta 把 service 形态立为激活面
  wire 并写明两域互不兼容；CAS 语义零变更（演示已验证消费路径）。
- 采纳输入的持久性（评审阻塞项）：现 probe 在 effectStart 内一次性执行、
  采纳态存内存 Map、`IWEB_SANDBOX_WASM_READINESS_PROBE` 缺省关。三项修正：
  (a) probe 缺省开启（节点缺省 `=1`）；(b) execution-rpc query 面新增只读
  采纳记录投影；(c) **lazy 重探**——query 到达时若目标执行仍为当前 in-place
  执行且未采纳（或 supervisor 重启后内存丢失），触发一次探测并更新采纳态。
  采纳不再因一次 not-ready/重启而永久丢失。
  缝合点（executor 契约）：`createExecutionRpcHandler` 的 executor 契约今天
  只有 `execute()`；扩展为携带 readiness 投影方法（在 effectStart 同层实现，
  fence/probe 选项所在闭包内；probe base URL 经 fence 记录的 listenIndex 以
  `wasmdIngressTarget` 确定性推导），RPC handler 保持纯传输、投影随
  query-result 携带。fence 本身构造时即从 journal 重建，重启后重探可复原。
- Kernel 收敛循环对「applied start + fence preparing 且未激活」的候选：读到
  exact-match 采纳 → 铸 `ServiceReadinessLeaseV2`（nonce=16 随机字节 hex；
  `expiresAt ≤ issuedAt + stagingTtlSeconds`；
  `leaseDigest = digestV2("iweb-wasm-readiness-v2", JCS(record with leaseDigest
  omitted))`，0x00 分隔、与基础域互不兼容），JCS 追加进
  `/data/kernel/wasm/readiness-leases.json`（0600 root-only）。
- **mint 即既有 probe grant 的 Kernel 侧执行**（不是第二签发面）：不复活已
  消费/已过期的 lease——CAS 时点已过期者按既有条款要求 fresh preparation +
  exact health；未激活候选在过期窗口外的重复 mint 仅刷新未消费 lease。
- 台账卫生（演示教训进实现约束）：写路径「读-过滤-写」整形为规范包络（防
  旧格式/自嵌套脏数据复活）；`wasm_runtime.rs` 模块头 readiness-leases 的
  writer-authority 注释同步翻转为 Kernel。
- owner 手工铸造脚本（/tmp 工具）退役，不入库。

### D4 路由种子 merge-only，Kernel 注册表唯一写权威

- 现状根因：entrypoint 每次启动用 MinIO 旧快照覆盖持久卷上的 Kernel 路由
  文件；`iweb_domain_register` 只写 Kernel 文件 → 重启即丢。
- 决策：装载权威 = Kernel `routes.rs`（owner 写路径 `record()` 已是 hostId
  upsert，无既有 merge 逻辑——本变更新增种子 merge）：
  - 路由文件不存在（首启）→ 从 `IWEB_ROUTES_SEED_FILE` 整体装载；
  - 文件存在 → 种子仅系统行（`system:true`）hostId 级 upsert；同 hostId
    用户行优先（种子行丢弃 + owner 日志），用户行永不删除；
  - 文件缺失且种子缺失 → fail-closed 启动失败（无系统路由的空注册表不是
    合法节点态）；
  - 种子不可解析 → owner 日志 + 跳过种子（绝不 panic、绝不半套应用）。
- entrypoint 删除无条件 `mc cp`；传 `IWEB_ROUTES_SEED_FILE=/opt/iweb/kernel/
  routes.seed.json`。MinIO `iweb-system/routes.json` 退役为遗留对象（不主动
  清理）。
- 备选（否决）：Kernel 写穿回 MinIO。否决理由：双写一致性；持久卷已是
  durable 面，镜像种子才是升级语义的正确来源。

### D5 admission 诚实化：谓词应答 + 受批准的验证转移

- join/读取面：可见性回答 = `admitted_visible(objects, db, materializer, …)`
  三段谓词；缝合点在 stores 包装/响应装配层（`find_join_candidate` 无 store
  访问权），响应状态由谓词导出，不再透传 `row.state`。
- journal 状态机协调（评审阻塞项）：`visible` 是终态、法条禁回归——本变更
  **批准唯一的验证转移** `visible → failed`（journal-revision CAS；
  `WASM_ADMISSION_WITNESS_MISSING` + owner 日志），其后走既有
  `failed → collected` GC。转移只能由 witness 验证失败触发，不开放任何
  其他 visible 出口。
- 行级降级（评审阻塞项）：`load_admitted_visible_proofs` 对单行谓词 Err 降级
  为「排除该行 + owner 日志」，绝不中止整轮 reconcile——一个幽灵行不再 503
  全部后续 admission；排除行不可参与 preparation/路由选择。
- 不自动重建 witness（"never recreate from mutable workspace bytes"）；手工
  修复是 owner 运维动作。

### D6 policyless runtime reserve 前置门

- 数据源：D0 投影的 `runtimeReserves`（完整 binding 工件身份 + 架构精确匹配；
  **无默认、无零值替换**——与 wasmd `capability.rs` 同一语义）。
- 判据：无 policy proof 在 admission 校验与 preparation gate 校验
  `memoryBytes > reserveBytes`（guest = memoryBytes − reserveBytes > 0）；
  违规以 `WASM_RESOURCE_RECORD_INVALID` 在 admission 响应拒绝（同码前移，
  外部可观察一致）。
- 有 policy proof 的既有 `WASM_GUEST_MEMORY_RESERVE_INVALID` 门
  （`checkWasmGuestMemoryReserve`）不变；两门并存、各自错误码、不合并判据。

## 状态面（D7）

`GET /v1/wasm/status` 投影扩展：每候选 readiness 采纳态（unprobed/not-ready/
adopted-stale/adopted）与采纳时间、lease 铸造/消费/到期态、应用级
unavailable/recovering/stopped 与剩余 restart 预算。死亡/恢复中的 per-app
资源行保持 `unavailable`（monitor 法：零值只属于被证明的零测量/限额，绝不
顶替缺失采样或重启态）。

## 风险与对策

- **恢复编排与激活的权限边界**：自动重 preparation/start 是 Kernel 自权
  （既有 outbox 机器），但翻回 active 仍需 lease+activation——无人激活则停在
  unavailable（诚实）。R2 讨论同版本自动重激活。
- **锁协议失效风险**：本变更新增的任何锁内网络往返（probe 或采纳 query）
  都是回归——task 1.2/3.2 把「锁外探测」列为验收标准（压力测试：容器重启
  场景下 admission 提交延迟不劣化）。
- **种子 merge 的系统/用户冲突**：用户先行、种子行丢弃 + owner 日志，绝不
  静默覆盖。
- **query 面扩展向后兼容**：采纳记录为新增字段；镜像一体发布，旧读新不
  发生；字段缺席 = 无采纳（缺省安全）。
- **验证转移的滥用面**：`visible→failed` 仅由 witness 验证失败触发，一次性
  journal CAS；不构成「删除版本」的侧门（删除仍走既有 owner 生命周期面）。

## 开放问题（实现批次内决策，不阻塞 proposal）

- **R1 运维事件面**：unavailable 翻转用独立 owner 审计事件流还是 RouteEvent
  扩展？倾向独立流（RouteEvent 保持 owner-command 语义），task 2.1 spike。
- **R2 同版本自动重激活**：恢复 spawn + readiness 后，是否允许 Kernel 在
  「应用曾有 active 指针且版本未变」时自动重激活（等效 owner 重放）？倾向
  自动（个人节点可用性优先），需 activation journal 可区分来源。
- ~~R3 probe 拨号实现~~（已决）：独立 dialer，UDS 裸 HTTP/1.1（见 D1）。

## 回滚

- 全部变更在节点镜像内；回滚 = 上一镜像 tag 重部署。路由 merge 首启装载以
  「文件不存在」为界，回滚不产生额外迁移；readiness-leases 台账新增行由
  expiry 自然收敛；恢复编排新增命令幂等可重放，回滚后旧 Kernel 只是不再
  主动探测（回到现状缺口，无损坏面）；`visible→failed` 转移单调，回滚后
  旧行为 = 幽灵行继续被谓词拒绝（与现状同）。

## 验证策略

- cargo：liveness 判死矩阵（socket 缺失/超时/非 200/失配/**连接后复位**/
  阈值内恢复/阈值耗尽）、锁外探测压力、恢复编排（P/E 经双迁移严格递增、
  预算窗口滚动、账本崩溃重放、耗尽→stopped）、join 谓词化（幽灵回归 +
  **后续 admission 不 503**）、visible→failed 转移、policyless reserve、
  路由 merge（首启装载/系统 upsert/用户保全/冲突用户优先/坏种子跳过/
  双缺失 fail-closed）、status 投影形状。
- bun：query 面采纳投影形状与缺省、lazy 重探、重启后采纳再现。
- 真实节点验收（tasks.md 6 详列）：kill 单 wasmd → unavailable → 自动恢复 →
  激活后 200；容器重启 → 路由存活 + 全灭恢复；MCP 全新部署无手工铸 lease；
  越界准入被拒；幽灵 join 得 failed 且后续 admission 正常。
