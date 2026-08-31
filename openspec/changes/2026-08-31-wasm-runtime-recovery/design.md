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
- readiness 探测链路双重断裂（Codex R1 B2/B3，已亲自核验）：
  (a) 端点——supervisor `READINESS_PATH="/iweb-health"`
  （`wasm-shared.ts:81`）而 wasmd 只应答 `GET /healthz`
  （`wasmd/src/ingress.rs:32`），gw 网关纯字节转发不改写路径，真实链路
  probe 必 404；(b) wire——wasmd 唯一产出 base 形态
  `WasmReadinessHealthV2`（ABI 1.0.0、无 `hostServicePolicyDigest`，
  `wasmd/src/main.rs:187`），supervisor correlate 先过
  `validateServiceReadinessHealthV2`（ABI 1.1.0 + policy pin），base 形态
  必 `WASM_EXECUTION_WIRE_INVALID`。演示未暴露因 probe 缺省关 +
  owner 手工铸 lease。D3 的「probe 缺省开启并采纳 exact v2 200」前提
  因此不成立，须先修链路（D8）。
- 既有偏差声明（非本变更引入，Codex R1 B4 核验为既有）：现行 spec
  `AdmissionProofV1` 已是 `schemaVersion: 2`（specs :258/:266），Rust
  实现 `wasm_admission.rs:801/:818` 生成与消费同为 1（自洽故演示未
  暴露）。本变更 delta 系复刻现行法条；实现侧 1→2 对齐作为 task 5.1
  的附带子项处理（witness 读写两侧同步升版 + golden fixture），不
  扩大为独立格式迁移变更。

## Spec 条款对照（本变更不新立信任模型，只兑现既有条款）

| 缺口 | 已归档条款（openspec/specs/wasm-application-runtime/spec.md） |
| --- | --- |
| 死亡检测/有界恢复 | 「Lifecycle keeps one routed execution…」："If an active execution dies or exceeds an engine limit, Kernel atomically changes the active route to unavailable … allocates a higher preparationGeneration … then a higher executionGeneration … applies restart.maxRestarts within restart.windowMs"；restart 预算定义于 NodeCapabilityRecordV1（`restart.maxRestarts` 0..100 / `windowMs` 1000..86400000） |
| lease 生产签发 | 「Wasm readiness is a full identity attestation」："The probe grants a readiness lease only from an exact v2 200…"；lease wire 条款（现文定义基础 ReadinessLeaseV2；激活面实际消费 ServiceReadinessLeaseV2——本变更同步法条，见 D3） |
| readiness 探测链路本身 | 同条款"Gateway … obtains the raw v2 attestation from wasmd over the fixed sandbox-local ingress target"——实现端点/wire 均未接通（见现状节双重断裂）；Service health 形态尚无法条（contracts 2026-08-28 引入 wire 未立法），本变更补立（D8） |
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
- **消费时重读 + pin 比对（R1 M7）**：Kernel 在 admission、recovery 编排、
  reserve 门每一次消费投影时重读文件并比对投影携带的
  `capabilityRecordRevision/Hash` 与既有 pin（对位
  `verify_admission_node_identity` 每次重读模式）；读取与 spawn 之间投影
  被替换/篡改即 fail-closed 拒绝，不做 TOCTOU 宽恕。投影内
  `runtimeReserves/restart` 与 hash 的一致性由写入端从同一 sealed record
  派生保证（Kernel 不复算全 record hash——投影只含子集；写入端派生 +
  pin 比对是可信链）。
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
- **晚到结果的代次绑定（R1 M1）**：锁内快照携带每目标的 route generation
  与完整执行身份（sandbox/version/binding/capability/secret/config/P/E）；
  重取锁应用计数/翻转前先与当前值比对，任一漂移即丢弃该轮结果（陈旧
  probe 不折算成新执行的失败计数，也不把旧执行的健康采样成新执行）。
  比对按**目标粒度**（该应用的 route generation + 执行身份），不用全局
  `controlRevision`——后者是全态计数器，无关 owner 操作会令其恒变，
  按它丢弃会废掉整轮探测。测试覆盖「probe 在途、activation/recovery 已
  推进」的交错。
- 独立 dialer（R3 已决）：UDS 上裸 HTTP/1.1 手写请求（对位 `proxy.rs` 既有
  转发层做法；reqwest 不支持 UDS）；不合成、不缓存：probe 结果只驱动
  「判死 + unavailable 翻转」，不写 fence.alive（其写者仍只有 start/stop/
  drain 投影路径），不从 probe 合成健康/指标值（`unavailable`/零值诚实法
  不变）。
- 备选（否决）：supervisor 上报死亡事件。否决理由：路由翻转是 Kernel 单一
  CAS 权威，判据必须与 fence/registry 事实同源；上报引入第二真相源与投递
  可靠性问题。

### D2 恢复序列：先 unavailable，后预算内重 preparation

1. 判死（或越引擎限）→ **先持久化 recovery intent（write-ahead，R3 #6）**：
   Kernel 在自有 sidecar（与预算账本同目录族）写入 recovery intent——目标
   applicationId/versionId、判死时的 P/E、route generation、失败类别
   （crash/resource/unresponsive）——**intent 落盘成功后才做** 同一
   controlRevision CAS：active 指针翻 `WasmActivePointerV1::Unavailable`
   （诚实 502 分发路径已存在）。崩溃窗口分析：intent 后 CAS 前崩溃 →
   指针仍 active 但下轮 probe 再判死、intent 幂等重写；CAS 后 → intent
   已在。恢复绝不从裸 Unavailable 指针反推目标。**intent 有效性
   （R3 #6）**：读取时当前 route generation 仍等于 intent 记录值、且目标
   版本仍是该应用最新 admitted 版本；owner stop/replace/activation/新
   准入任一使上述不成立即失效。
   运维事件载体已定稿（见 R1 spike 结论）：**独立 owner 审计事件流**
   （recovery audit events sidecar），不碰 RouteEvent exact wire。
2. 预算检查：`restart.maxRestarts/windowMs`（D0 投影）窗口滚动账本，持久化
   于 Kernel 自有 sidecar（对位 retirements/journal-head-hint 的 sidecar 模
   式，不碰 v2 控制态的 spec-exact 键集）；**记账协议（R1 M2）**：每次恢复
   尝试以该次恢复 `prepare` 的 command ID 为唯一 attempt 键（outbox 幂等
   键既定），sidecar 先持久 reserve 该键再发出命令，命令 applied/rejected
   或判死放弃时提交终态；崩溃重放按「键已存在即不重复计数」收敛——漏计
   不可能（未 reserve 不发命令）、双计不可能（键唯一），账本写入与
   unavailable CAS 的先后为「先翻 unavailable（CAS）再 reserve+发令」，
   中间崩溃的窗口由重放走同键幂等。**孤儿 reserve 键终态（R1' m5）**：
   reserve 后、outbox 追加前崩溃的键，重放时以「该 command ID 不在
   outbox/命令面」判为孤儿并落 failed 终态（不占预算、不再发令）；恢复
   重放定位一律按 sidecar 键 → command ID，不复用无代次的 version+
   operation 扫描。
3. 有余量 → **先按 gate 身份重验 catalog entry 状态（R2 #5）**：entry
   `revoked` → 不发恢复命令，直接走第 5 步（stopped + owner 可见
   revocation 类别）；active → 走既有双代次迁移（`wasm_commands.rs`
   planner 语义）：prepare 于 (P+1, **E+1**)，applied 后 start 于
   (P+1, **E+2**)。**secret/config 快照按现行 rotation 法条的 crash
   recovery 语义（R3 修正 R2 #4 的方向）**：现行法条明文「A crash
   recovery preparation snapshots the current revision」且 activation
   CAS 要求 candidate secretRevision == current store revision——恢复
   preparation（P+1）对 secret store 的 **current revision** 做新快照
   （从未分配 secret 时才是 initial/revision 0，复用
   `ensure_initial_secret_snapshot`；config authority 同理）。fence 身份
   随新 preparation 重建，新 revision 不破坏 health 比对；「按 pin 旧
   revision 重演」反而会被 activation CAS 按现行法条拒绝。测试覆盖
   恢复期间 owner 轮换 secret 的竞态（轮换使进行中的恢复候选失效并
   触发再一轮 current-revision re-prepare，最终激活的必是最新 revision）。
   恢复命令走既有 outbox/投递/ack 投影闭环（9e139a3 fence 翻转自动跟进）。
4. 重新激活：恢复 spawn 成功 + readiness 后，仍需 kernel-minted lease +
   一次 activation CAS 翻回 active（与首次激活同一 wire；恢复不自行路由）。
   **R2 已决（2026-09-01，采纳自动重激活）**：当 recovery intent 仍有效且
   目标版本未变时，Kernel 在恢复 spawn 的 readiness 采纳 + lease 铸造完成
   后自动发起同版本 activation CAS（等效 owner 重放）。**来源审计不碰
   activation wire（R3 #10）**：`RouteEvent` 是法条 exact wire，不加
   source 字段；kernel-recovery 引发的激活记录进**独立 owner 审计事件流**
   （recovery audit event 携带关联的 activationId/routeGeneration，owner
   可区分 owner-command 与 kernel-recovery 激活）；重放/CAS 语义不变。
   owner stop/replace/新准入优先于自动激活（intent 失效即不发）。个人
   节点可用性优先——无人值守的崩溃恢复必须回到可用态。
5. 预算耗尽 → 版本 `stopped` + owner 可见崩溃/资源类别；无自动重试。
- **「越引擎限」触发面澄清（R1 M3）**：wasmd 为 per-request 引擎模型
  （每请求新 Store+新实例；epoch/fuel 超限终止该请求、进程与执行存活，
  `wasmd/src/host.rs` 头注）。因此本变更的死亡判据统一为 D1 liveness
  probe：请求级引擎错误（`GuestTrap{epoch_timeout}` 等）是 metrics 可见
  的请求失败，**不**触发 unavailable 翻转；「execution exceeds an engine
  limit」仅在表现为执行不可服务（进程退出、listener 消失、健康面失配）
  时成立，并由 probe 判死路径收敛。不新增 wasmd → Kernel 的引擎限事件
  通道（避免第二真相源）；引擎限的可观测性走既有 metrics 投影。
- 容器重启：Kernel 启动对全部 alive fence 跑同一 probe 判死路径，逐应用进入
  恢复；journal/outbox 幂等保证不双驱动。

### D3 lease 铸造：Kernel 权威，采纳可再生产（前置 D8）

- 前置：D8 修复探测链路后，「probe 缺省开启 + exact v2 200 采纳」才在
  真实 wasmd 链路上成立；D8 落地前本节机制无法端到端兑现。

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
- Kernel 收敛循环对「start 命令 applied + fence 记录 alive + 生命周期未激活
  （preparing/ready；**不以 fence 处于任何瞬态 preparing 子状态为触发条件**——
  实现在 start-ack 投影时即翻 alive+ready，稳态待激活候选正是此态）」的候选：读到
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
    合法节点态）；**种子存在但不可解析且注册表文件缺失 → 同为 fail-closed
    启动失败（R1 m1）**：首启没有任何有效系统路由可装载，不是合法节点态；
    注册表文件已存在时坏种子才走「owner 日志 + 跳过」；
  - 种子不可解析（且注册表文件已存在）→ owner 日志 + 跳过种子（绝不
    panic、绝不半套应用）。
- entrypoint 删除无条件 `mc cp`；传 `IWEB_ROUTES_SEED_FILE=/opt/iweb/kernel/
  routes.seed.json`。MinIO `iweb-system/routes.json` 退役为遗留对象（不主动
  清理）。
- **supervisor env allowlist 补 `IWEB_SANDBOX_GATEWAY_DIR`（R1 M6）**：
  supervisor（`wasm-ingress-gateway.ts:19`）与 Kernel（`proxy.rs:275`）都读
  该 env，但 entrypoint `supervisor_env()` allowlist 未透传——非默认目录时
  两侧寻址分裂、一切 probe 表现为 socket missing。补入 allowlist 并在
  法条写明「Kernel 与 supervisor 的 gateway 目录 env 语义一致（同值同缺省
  `/run/iweb-sandbox/gw`）」。
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

### D8 readiness 探测链路统一（D3 前置；Codex R1 B2/B3）

- **端点统一**：supervisor `READINESS_PATH` 从 `/iweb-health` 改为 wasmd
  固定的 `GET /healthz`（`wasmd/src/ingress.rs` HEALTH_PATH；gw ingress
  网关纯字节转发、不改写路径的事实既定）。路径常量属
  `wasm-shared.ts`，单点修改。
- **wire 统一**：service 代际（`matrixRevision:2`）下 wasmd 产出
  `ServiceReadinessHealthV2`（base V2 全字段 + binding V2（ABI 1.1.0）+
  `hostServicePolicyDigest`；argv 第 11 元素已携带 policy digest，
  `wasmd/src/argv.rs` → `host_services/policy.rs` 解析且已定义「空串=精确
  零值策略」；producer 落点是 `main.rs` 单点构造替换）。**policyless 语义
  对齐激活面文法**：`hostServicePolicyDigest` 为 `sha256-hex` **或空串**（与
  ExecutionCommand/ActivationCommand 的 policyless 空串闭环一致）；
  contracts 侧同步扩两处——`validateServiceReadinessHealthV2` 与
  **metrics 姊妹族 `validateServiceEngineMetricsV2`**（后者同为 sha256-only
  文法，且 `sampleWasmEngineMetrics` 对 policyless 执行填空串后自校验恒
  null——同批修复，各换用现成 `requirePolicyDigestOrEmpty` helper）。
  supervisor correlate 语义不变（先 wire 校验再全字段比对 policy pin）。
  base 形态 golden 保留（历史代际语义），**新增** Service 形态 golden；
  既有断裂声明：Kernel 拉取侧引擎 metrics 消费仍为 V1-only（无生产调用
  方），按 B4 先例声明不在本变更修。
- **法条补立**：Service health 形态此前只有 contracts wire（2026-08-28
  add-wasm-host-services 引入）没有 spec 法条；本变更 delta 为其补立
  （对位 D3 给 Service lease 补立）——health 面在 service 代际由 base
  `WasmReadinessHealthV2` 升为 `ServiceReadinessHealthV2` 形态，policyless
  空串、两形态 digest/键集、producer（wasmd）与消费者（supervisor
  correlate、Kernel 采纳查询）各自义务。
- **golden 与验收**：wasmd Rust golden 向量与 contracts example 对齐；
  真实 relay → wasmd 链路验证 exact v2 200 / 非 200 / EOF / 连接后 reset /
  body 上限（进 tasks 3.0 测试与 6.3 节点验收）。
- 备选（否决）：supervisor 接受 base V2 再从 fence 拼 Service 比对。否决
  理由：policy pin 的执行体侧证明消失（fence 自证自），且 contracts 已
  定义 Service 形态为 service 代际 health 权威，producer 侧补齐是唯一
  不引入第二真相源的方向。

## 状态面（D7）

`GET /v1/wasm/status` 投影扩展：每候选 readiness 采纳态（unprobed/not-ready/
adopted-stale/adopted）与采纳时间、lease 铸造/消费/到期态、应用级
unavailable/recovering/stopped 与剩余 restart 预算。死亡/恢复中的 per-app
资源行保持 `unavailable`（monitor 法：零值只属于被证明的零测量/限额，绝不
顶替缺失采样或重启态）。

## 风险与对策

- **恢复编排与激活的权限边界**：自动重 preparation/start 是 Kernel 自权
  （既有 outbox 机器）；翻回 active 恒需 lease + activation CAS。R2 已决
  （2026-09-01）：intent 有效且版本未变时 Kernel 自动发起该 CAS（见 D2
  第 4 步；来源审计走独立 recovery audit 事件流，activation wire 与
  RouteEvent 不变）；intent 失效（owner stop/replace/新准入）则停在
  unavailable 等 owner——这是唯一的「无人激活」停留面。
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

- ~~R1 运维事件面~~（**已决 2026-09-01**，R3 冲突定稿）：**独立 owner
  审计事件流**（recovery audit events；`RouteEvent` 是法条 exact wire，
  不加字段，保持 owner-command 语义）；task 2.1 按此实现。
- ~~R2 同版本自动重激活~~（**已决 2026-09-01**，采纳自动：见 D2 第 4 步——
  intent 有效且版本未变时 Kernel 自动重激活，来源记独立 recovery audit
  事件；tasks 2.4/6.1 按此断言）。
- ~~R3 probe 拨号实现~~（已决）：独立 dialer，UDS 裸 HTTP/1.1（见 D1）。

## 回滚

- 全部变更在节点镜像内；回滚 = 上一镜像 tag 重部署。路由 merge 首启装载以
  「文件不存在」为界，回滚不产生额外迁移；readiness-leases 台账新增行由
  expiry 自然收敛；恢复编排新增命令幂等可重放，回滚后旧 Kernel 只是不再
  主动探测（回到现状缺口，无损坏面）；`visible→failed` 转移单调，回滚后
  旧行为 = 幽灵行继续被谓词拒绝（与现状同）。

## 验证策略

- cargo：liveness 判死矩阵（socket 缺失/超时/非 200/失配/**连接后复位**/
  阈值内恢复/阈值耗尽/**probe 在途 activation 交错（晚到结果丢弃）**）、
  锁外探测压力、恢复编排（P/E 经双迁移严格递增、预算窗口滚动、**attempt
  键崩溃重放不漏不双计**、耗尽→stopped）、join 谓词化（幽灵回归 +
  **后续 admission 不 503**）、visible→failed 转移、policyless reserve、
  路由 merge（首启装载/系统 upsert/用户保全/冲突用户优先/坏种子跳过/
  双缺失 fail-closed/**注册表缺失+坏种子 fail-closed**）、status 投影形状。
- bun：query 面采纳投影形状与缺省、lazy 重探、重启后采纳再现；
  **readiness 链路统一（3.0）——端点 `/healthz` 命中、Service 形态 wire
  校验（含 policyless 空串）、correlate 全字段、golden 对齐**。
- 真实节点验收（tasks.md 6 详列）：kill 单 wasmd → unavailable → 自动恢复 →
  激活后 200；容器重启 → 路由存活 + 全灭恢复；MCP 全新部署无手工铸 lease
  （**readiness 经真实 relay→wasmd `/healthz` 链路采纳**）；越界准入被拒；
  幽灵 join 得 failed 且后续 admission 正常。
