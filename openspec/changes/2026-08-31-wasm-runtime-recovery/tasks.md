# Tasks: wasm runtime recovery

约定：每项独立可验证；实现门禁 = 对应测试绿 + `cargo clippy -p iweb-kernel
--all-targets` / `bun test` 干净；涉及镜像的项以真实节点验收为准（见 6）。
共享文件（spec.md、AGENTS.md、README）由 ZCode 统一落盘，子代理只改各自
批次文件（Owner 编排指令 2026-08-24）。依赖：1.x/2.x/5.3 依赖 0.x。

## 0. 能力内容投影（D0；阻塞 2.2 与 5.3）

- [ ] 0.1 `gate-node-identity.json` schema 2：新增 `runtimeReserves[]`
  （binding 工件身份+架构 → reserveBytes）与 `restart{maxRestarts,windowMs}`；
  **写入端是新代码**（该文件今天无任何写入者）：新增供给步骤（entrypoint
  阶段或 scripts 工具）读取与 supervisor/wasmd 同一
  `IWEB_SANDBOX_WASM_CAPABILITY_RECORD`，计算派生（绝不手工拷贝），
  root-only 写出。
- [ ] 0.2 Kernel 装载 fail-closed：字段缺失/越界 → 恢复编排与 reserve 门
  拒绝启用 + owner 可见错误；绝不回退 contracts 默认值。测试覆盖缺字段/
  越界/完整三态。

## 1. Kernel 存活 probe 与判死（wasm-application-runtime / D1）

- [ ] 1.1 独立 health dialer（新模块或 `proxy.rs`）：经
  `sandbox_ingress_socket` 的 UDS 裸 HTTP/1.1 v2 health 拨号（单次连接、
  超时上界 ≤2s、不解析多余体；与 `sandbox_forward` 职责分离）。
- [ ] 1.2 收敛循环存活判定：锁内快照目标清单（fence ⋈ registry 行/outbox
  start 命令）→ **放锁并发探测**（总预算 < 周期）→ 重取锁应用计数与翻转；
  连续失败阈值（缺省 3）、成功清零；判死只翻 unavailable，不写 fence.alive。
  验收含压力测试：全 socket 缺失场景下 admission 提交延迟不劣化（锁外探测
  是硬约束）。
- [ ] 1.3 判死矩阵测试：socket 缺失 / 拨号超时 / 非 200 / **连接成功后复位
  或 EOF（wasmd 被 SIGKILL、前置 socket 仍在）** / 身份失配 / 阈值内恢复 /
  阈值耗尽，各自到 unavailable 或维持。

## 2. 有界恢复编排（wasm-application-runtime / D2）

- [ ] 2.1 R1 spike（半天内出结论记录进 design.md）：unavailable 运维事件
  载体选型（独立 owner 审计事件流 vs RouteEvent 扩展），定稿后实现事件落盘
  与 owner 状态投影（崩溃/资源类别）。
- [ ] 2.2 恢复编排：判死/越限 → active 指针 unavailable（同 controlRevision
  CAS）→ D0 预算窗口滚动检查 → 既有双代次迁移规划（prepare 于 (P+1,E+1)、
  applied 后 start 于 (P+1,E+2)；secret snapshot 复用
  `ensure_initial_secret_snapshot`）；预算账本持久化于 Kernel 自有 sidecar
  （retirements 同款模式），崩溃重放不双计。
- [ ] 2.3 预算耗尽 → 版本 `stopped` + owner 可见类别；无自动重试。
- [ ] 2.4 测试：P/E 严格递增单调、窗口滚动预算、账本崩溃重放幂等、容器
  重启全灭幂等（两轮 converge 不双驱动）、恢复与 owner 操作并发（owner 停用
  期间不恢复）。

## 3. readiness lease 生产签发（wasm-application-runtime / D3）

- [ ] 3.1 `wasm-control.ts`/`wasm-executor.ts`：execution-rpc query 结果
  新增 readiness 采纳记录只读投影；**lazy 重探**（query 到达、执行仍为当前
  in-place 且未采纳/采纳丢失时触发一次探测）；缝合点 = 扩展
  `WasmExecutionExecutor` 契约携带 readiness 投影方法（effectStart 同层
  实现——fence/probe 选项所在闭包，probe base URL 经 fence 的 listenIndex
  以 `wasmdIngressTarget` 推导；RPC handler 保持纯传输）；
  `IWEB_SANDBOX_WASM_READINESS_PROBE=1` 成为节点缺省。bun 测试：投影形状
  与缺省、重启后采纳再现（fence 构造时自 journal 重建）。
- [ ] 3.2 `wasm_runtime.rs`：收敛循环读采纳 → exact-match（fence+registry
  全等）→ 铸 `ServiceReadinessLeaseV2`（nonce 随机、
  `expiresAt ≤ issuedAt + stagingTtlSeconds`、
  `leaseDigest = digestV2("iweb-wasm-readiness-v2", JCS(record with
  leaseDigest omitted))`）→ JCS 追加台账（0600 root-only；写路径读-过滤-写
  整形防旧格式脏数据）；**采纳 query 并入锁外有界轮**（与存活 probe 同一
  快照→探测→应用序列，绝不新增锁内网络往返）；`wasm_runtime.rs` 模块头
  readiness-leases writer-authority 注释翻转为 Kernel。
- [ ] 3.3 测试：铸 lease 全字段与 digest 域、过期窗口上界、身份失配不铸、
  台账整形（预置自嵌套脏数据 → 写后规范）、已消费/过期 lease 不复活、
  激活消费闭环（铸→activate→consumed）。
- [ ] 3.4 MCP 部署引导更新：admit → 等 readiness（状态面）→ activate；
  owner 手工铸造引导删除。
- [ ] 3.5 状态面（D7）：`GET /v1/wasm/status` 投影扩展——候选 readiness
  采纳态与时间、lease 铸造/消费/到期态、应用 unavailable/recovering/stopped
  与剩余 restart 预算；死亡/恢复中 per-app 资源行保持 `unavailable`（零值
  诚实法）。cargo 测试投影形状。

## 4. 路由种子 merge-only（workspace-and-routes / D4）

- [ ] 4.1 `routes.rs`：装载合并——**在启动装载点执行一次**（kind-claim
  启动路径；稳态请求路径的 `RouteStore::load` 保持只读、无种子访问）——
  文件不存在 → 从 `IWEB_ROUTES_SEED_FILE` 整体装载；存在 → 种子系统行
  hostId 级 upsert（同 hostId 用户行优先 + owner 日志），用户行永不删除；
  文件与种子双缺失 → fail-closed 启动失败；种子不可解析 → owner 日志 +
  跳过（绝不 panic、绝不半套应用）。
- [ ] 4.2 `scripts/iweb-entrypoint.sh`：删除无条件 `mc cp` 路由覆盖；改为
  传 `IWEB_ROUTES_SEED_FILE=/opt/iweb/kernel/routes.seed.json`。
- [ ] 4.3 测试：首启装载、系统 upsert（新增/变更）、用户行保全、系统/用户
  hostId 冲突（用户优先+日志）、坏种子跳过、双缺失 fail-closed、无种子且
  文件在（仅装载自身）。

## 5. admission 诚实化（wasm-application-runtime / D5、D6）

- [ ] 5.1 `wasm_admission.rs`/`wasm_runtime.rs`：join/读取面可见性由三段
  谓词导出（缝合点在 stores 包装/响应装配层）；journal 行 `visible` + 谓词
  为假 → 一次 journal-revision CAS 的验证转移 `visible → failed`
  （`WASM_ADMISSION_WITNESS_MISSING` + owner 日志），后续走既有
  `failed → collected`；**观察到谓词为假 visible 行的每一个面（join、
  reconcile 轮、读取面）都执行同一次幂等验证转移**（不只是 join——否则
  幽灵行永远停在 journal visible）；`load_admitted_visible_proofs` 单行
  谓词 Err 降级为排除 + owner 日志，绝不中止整轮 reconcile。
  实现触点：`transition_allowed`（`wasm_admission.rs` ~641）现拒绝
  (Visible, Failed)，需按批准的验证转移扩展。
- [ ] 5.2 测试：复刻幽灵场景（objects 在、DB 行无、journal visible）→
  failed + 不编排 + 不自动重建 witness；**同一状态下新 admission 提交正常
  （不 503）**；`visible→failed` 转移后 GC 路径可达。
- [ ] 5.3 policyless runtime reserve 前置门：admission 校验与 preparation
  gate 取 D0 投影 `runtimeReserves`（binding 工件身份+架构精确匹配，无默认/
  零值替换）校验 `memoryBytes > reserveBytes`；越界以
  `WASM_RESOURCE_RECORD_INVALID` 在 admission 拒绝。有 policy 行的
  `WASM_GUEST_MEMORY_RESERVE_INVALID` 门不回归。
- [ ] 5.4 测试：256MiB/256MiB 拒于 admission（对位演示 -20）、512MiB 通过、
  reserve 行缺失时 fail-closed（不代默认）、V2 policy 行为不回归。

## 6. 真实节点验收（阻塞项=需要一次性 owner 参与的操作）

- [ ] 6.1 部署新镜像；既有 `demo` 应用（e1f03cbe…-22）在不重准入的前提下：
  kill wasmd → 10–40s 内路由 unavailable → 预算内自动恢复 → readiness →
  激活后 `demo.app.<base>` 200。
- [ ] 6.2 容器重启：路由 `demo.app` 存活（不重注册），应用走全灭恢复路径；
  重启窗口内 admission 提交延迟不劣化（锁协议实证）。
- [ ] 6.3 MCP 全新部署一个新应用（新组件包）：admit → readiness 状态面就绪
  → activate（kernel-minted lease）→ 域名注册 → 公网 200；全程无 owner
  手工铸造。
- [ ] 6.4 越界 policyless 准入被拒（响应码断言）；幽灵 join 场景在测试桶
  复刻并断言 failed，且后续 admission 正常。

## 7. 文档与收尾

- [ ] 7.1 AGENTS.md/README：恢复语义、路由持久语义、lease 生产签发、
  readiness probe 新缺省一句话更新；monitor 断言（死亡/恢复中执行的资源行
  `unavailable`，绝不用 0 顶替）（ZCode 统一落盘）。
- [ ] 7.2 openspec 校验（若 CLI 可用 `openspec validate`；否则人工对照
  delta 格式：MODIFIED 全文复刻既有法条 + 有意增改）；归档前的 Codex review
  记录进 records/。
