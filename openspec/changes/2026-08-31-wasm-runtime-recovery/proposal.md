# Change: wasm runtime recovery — liveness, lease minting, durable routes, honest admission

## Why

2026-08-31 的真实节点演示第一次把 wasm 层「AI 经 MCP 部署 → 引擎执行 → 公网路由」
全链路跑通（demo.app 公网 200，组件在 Wasmtime 中真实执行），同时暴露了四处
「spec 已立约、运行时未兑现」的连续性缺口——它们都不是新需求，而是把已归档的
`two-tier-runtime-trust` 产品法在运行节点上补齐：

1. **活动执行死亡无人接管**。spec 规定「active 执行死亡或越引擎限 → Kernel 先把
   路由翻 `unavailable`，再以更高 preparation/execution generation 有界恢复，受
   capability record 的 `restart.maxRestarts/windowMs` 预算约束」。现状：容器
   重启后所有 wasmd 进程消失，fence 文件仍 `alive:true`、路由仍 active，访客
   永远 502；唯一恢复手段是 owner 重新准入一个新版本（演示中即如此）。运行期
   单进程死亡同样无人检测。
2. **readiness lease 无生产签发面**。spec 规定「probe 在 exact v2 200 时签发
   lease，由 Kernel 为每次成功 v2 探测生成」。现状：生产链路中没有任何角色
   签发 `ServiceReadinessLeaseV2`，演示靠 owner 手工铸造并落盘——AI 部署闭环
   在「激活」前断裂。
3. **节点重启丢失用户路由**。entrypoint 启动时无条件
   `mc cp iweb-system/routes.json → /data/kernel/routes.json`，用 MinIO 里的
   旧快照覆盖 Kernel 的持久路由注册表；`iweb_domain_register` 注册的
   `demo.app` 在容器重建后即消失（演示中复现并二次注册）。AGENTS.md 明言
   「Kernel route registry 是唯一应用身份权威」，启动路径却破坏它。
4. **admission join 的幽灵 visible**。spec 规定可见性只能由三段 witness
   （object marker + visible DB 行 + materializer receipt）的
   `AdmittedVisible` 谓词判定。现状：create-or-join 的 join 分支直接把
   admission journal 行的 `state` 回给调用方——部分状态丢失后（演示中 -15：
   objects 在、DB 行无），MCP admit 返回 `state:"visible"` 而谓词为假；更糟，
   `load_admitted_visible_proofs` 对任一行的谓词错误整轮 fail-closed，一个
   幽灵行会让后续所有 admission 提交 503。
5. **policyless 准入的 runtime reserve 门缺失（次要）**。无 policy 行的
   `memoryBytes ≤ 能力记录 runtimeReserves 对位 reserveBytes`（按 binding+架构
   匹配，无默认替换）能通过 Kernel 编排，直到 wasmd 引擎初始化才以
   `WASM_RESOURCE_RECORD_INVALID` 拒绝（演示中 -20 即此）。wasmd 的错误文案
   自己写明「admission or preparation must fail closed」——该失败应前移到准入。
   附带事实：Kernel 当前只 pin 能力记录的 hash，不加载其内容
   （`gate-node-identity.json` 仅 hash/架构投影）——reserve 门与 restart 预算
   都需要内容投影，这是本变更的一个前置子任务。

以上 1/2/4 均有已归档 spec 条款（见 design.md 条款对照表）；3 违反
workspace-and-routes 的显式注册模型与 AGENTS.md 的注册表权威；5 违反准入
fail-closed 意图。本变更不改两层信任模型、不触碰发布门与验收记录语义。

## What Changes

- **能力内容投影前置**：`gate-node-identity.json` 升级为携带 pinned 能力记录
  的 `runtimeReserves[]`（binding+架构 → reserveBytes）与
  `restart{maxRestarts,windowMs}`（schema 2；由节点供给面从同一 pinned 记录
  写出；Kernel 读取 fail-closed）。这是恢复预算与 reserve 门的数据源。
- **Kernel 观测执行存活性**：Kernel 收敛循环（现 10s 周期，9e139a3 已落地）
  对每个 `alive` fence 做活性判定——经
  `/run/iweb-sandbox/gw/<sandboxId>/ingress.sock` 读取 wasmd 的 v2 health
  attestation，与 fence 记录 ⋈ registry 行（联合携带全部比对字段）逐字段比对；
  socket 缺失/拨号超时/非 200/连接后复位/身份失配按有界阈值判死。锁协议：
  锁内快照事实 → 放锁并发探测（总预算受收敛周期约束）→ 重取锁应用计数与
  翻转，绝不把探测时长叠加进控制面互斥锁。判定不合成数据、不采纳陈旧样本、
  不写 fence.alive。
- **死亡先翻 unavailable，再有界恢复**：路由中的执行被判死（或越引擎限）→
  Kernel 先把该应用 active 指针翻 `unavailable`（访客看到诚实的
  `application unavailable`），再在 `restart.maxRestarts/windowMs` 预算内走
  既有双代次迁移：prepare 于 (P+1, E+1)，applied 后 start 于 (P+1, E+2)；
  全部经既有 outbox/ack/fence 投影闭环。预算账本持久化于 Kernel 自有 sidecar
  （对位 retirements 模式），窗口滚动读，崩溃重放不双计。预算耗尽 →
  `stopped` + owner 可见崩溃/资源类别。容器重启 = 全部执行死亡，走同一逐应用
  幂等路径。翻回 active 恒需 readiness lease + 一次 activation CAS——恢复不
  自行路由。
- **Kernel 签发 readiness lease**：readiness 探测（exact v2 correlate）成为
  节点缺省（`IWEB_SANDBOX_WASM_READINESS_PROBE=1` 缺省开启）；supervisor 的
  readiness 采纳经 execution-rpc query 面暴露给 Kernel，且采纳可再生产生
  （执行仍在而未采纳时 query 触发 lazy 重探——采纳不再是一次性内存态）。
  Kernel 收敛循环据此铸造 `ServiceReadinessLeaseV2`（nonce 随机、expiry 受
  `stagingTtlSeconds` 约束、digest 用
  `digestV2("iweb-wasm-readiness-v2", …)` 域），写入 root-only 台账（写路径
  含读-过滤-写整形）。owner 手工铸造路径退役；激活 wire 与 CAS 语义零变更。
  同时把 lease wire 法条与实现对齐（spec 现文只定义基础 `ReadinessLeaseV2`，
  激活面实际消费的是 service 形态——delta 明确两种形态与各自 digest 域）。
- **路由种子 merge-only**：entrypoint 不再无条件覆盖 Kernel 路由文件；镜像
  种子仅做系统路由的 hostId 级 upsert（同 hostId 用户行优先并记 owner 日志），
  用户路由永不删除；路由文件不存在（首启）才整体落种子；种子缺失且文件缺失
  → fail-closed 启动失败；种子不可解析 → owner 日志 + 跳过（绝不 panic、绝不
  半套应用）。Kernel 路由注册表（持久卷文件）是唯一写权威。
- **admission 诚实化**：join/读路径的可见性回答一律来自三段 `AdmittedVisible`
  谓词；journal 行 `visible` 而谓词为假 → 经一次 journal-revision CAS 的
  **验证转移** `visible → failed`（`WASM_ADMISSION_WITNESS_MISSING` + owner
  日志），此后走既有 `failed → collected` GC；谓词错误在
  `load_admitted_visible_proofs` 中降级为「排除该行 + owner 日志」，绝不中止
  整轮 reconcile（一个幽灵行不再 503 全部后续 admission）。
- **policyless 准入 runtime reserve 门**：无 host-service policy 的准入事务在
  admission/preparation 阶段即按 pinned `runtimeReserves`（binding+架构精确
  匹配，无默认/零值替换）校验 `memoryBytes > reserveBytes`，以
  `WASM_RESOURCE_RECORD_INVALID` 拒绝；有 policy 行的既有
  `WASM_GUEST_MEMORY_RESERVE_INVALID` 门不变。
- **状态面补全**：`GET /v1/wasm/status` 投影扩展——每候选 readiness 采纳态、
  lease 铸造/到期态、unavailable/recovering/stopped 与剩余 restart 预算；
  死亡/恢复中的 per-app 资源行保持 `unavailable`（零值诚实法，绝不用 0 顶替
  缺失采样）。

## Capabilities

### Modified Capabilities

- `wasm-application-runtime`：
  - 新增「Kernel 经沙箱 ingress 观测执行存活性」条款（probe 判据、锁协议、
    阈值、不合成原则、连接后复位场景）；
  - 修改生命周期条款：死亡/越限检测 → unavailable 优先 → 有界重
    preparation/spawn 的完整场景（含容器重启全灭路径与预算耗尽路径）；
  - 修改 lease wire 条款：service 形态为激活面 wire，digest 域与基础形态
    互不兼容；
  - 新增「readiness lease 由 Kernel 从采纳的 readiness 铸造」条款（mint 判据
    = 既有 exact-v2-200 probe grant 的 Kernel 侧执行、台账权限与整形、不复活
    已消费/已过期 lease、owner 手工面退役）；
  - 修改 execution-rpc 条款：`CommandQueryV1` 结果新增只读
    `readinessAdoption` 投影（采纳记录；非 start 或无采纳为 null；当前
    in-place 执行未采纳时可先做一次 fresh probe）；
  - 修改准入谓词条款：join/读路径可见性 = 三段谓词、`visible→failed` 验证
    转移、幽灵行排除不中止 reconcile；
  - 修改准入校验条款：policyless 行的 runtimeReserves 前置校验场景。
- `workspace-and-routes`：
  - 修改「Application hostname registration is explicit」条款：注册表跨节点
    重启持久；种子 merge-only；用户路由不可被启动路径删除。

## Impact

- Rust Kernel（`kernel-rs/iweb-kernel/src/`）：
  - `wasm_runtime.rs`：gate 节点身份投影 schema 2 装载；收敛循环扩展（存活
    probe + 锁协议、unavailable 翻转、预算账本 sidecar 与恢复编排——复用
    `ensure_initial_secret_snapshot`/命令规划既有机器）；join/读取面谓词化与
    `load_admitted_visible_proofs` 行级降级；policyless reserve 门；台账写
    整形；模块头 writer-authority 注释更新（readiness-leases 写者翻转为
    Kernel）；
  - `wasm_admission.rs`：`visible→failed` 验证转移 + join 应答谓词化（缝合点
    在 stores 包装/响应装配层——`find_join_candidate` 无 store 访问权）；
  - `routes.rs`：种子 merge 装载（系统行 upsert、用户行保全、fail-closed
    缺省、坏种子跳过）；
  - `proxy.rs`/新模块 + `http.rs`：health probe 独立 dialer（UDS 上裸
    HTTP/1.1，复用 `sandbox_ingress_socket` 寻址；reqwest 不支持 UDS）；
    `/v1/wasm/status` 投影扩展。
- TypeScript supervisor（`supervisor/`）：execution-rpc query 面携带 readiness
  采纳记录（未采纳且执行在位时 lazy 重探；`wasm-control.ts` query envelope
  只读扩展 + `wasm-executor.ts` 采纳态投影）；readiness probe 缺省开启
  （`wasm-serve.ts`）。
- 节点供给（镜像/安装脚本）：`gate-node-identity.json` 写入端升级为携带
  `runtimeReserves` 与 `restart` 预算。
- `scripts/iweb-entrypoint.sh`：删除无条件 `mc cp` 路由覆盖，改为传种子路径。
- MCP（`apps/workers/mcp`）：部署引导更新（admit → 等 readiness 状态面 →
  activate；owner 手工铸 lease 引导删除）。
- 测试：Kernel cargo（liveness 矩阵含连接后复位、恢复编排/预算账本/崩溃重放、
  join 幽灵回归 + 后续 admission 不 503、reserve、路由 merge、status 投影）、
  supervisor bun（query 面扩展、重启后采纳再现）；真实节点验收步骤见 tasks.md。
- 不变更：发布门与验收记录语义、activation wire 与 CAS 语义、命令/
  确认/重放的 execution-rpc 主体（仅 query 结果新增只读字段）、gw ingress
  socket 契约（f2254ee 已实现）、celld 层任何行为。
