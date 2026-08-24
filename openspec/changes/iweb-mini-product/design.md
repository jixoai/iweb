<!-- 用户原始需求（2026-08-24）：iweb-mini 独立产品线；先经 Codex grilling（Q1–Q26）固化边界再立法；开发排在 typescript-monorepo 之后；本变更只立法不实现。 -->
<!-- Codex 审稿 R1（评分 6.0）：阅读规则改为「双产品适用 + 显式替换清单」；新增 version-ledger 共享 capability；路由顺序修正（先注册后准入）；快照无条件化；委托 denylist；亲证/披露/无 latest/迁移向导落 requirement；拓扑前置。 -->
<!-- Codex 审稿 R2（评分 6.8）：替换映射升级为 requirement 级（混合 capability 不得整体归类）；version-ledger 差异闭环清单含 mini 路由前置；候选预检 fleet 能力边界（最小凭证+负向 e2e）；迁移归档携带不可变包快照按摘要校验；OCI 拉取语义如实化（入口校验而非 registry 阻止）；失败更新快照入轮转；正向开工授权措辞。 -->
<!-- Codex 审稿 R3（评分 5.8，新发现跨 capability 错配）：owner-key-management 活跃变更纳入序门与替换映射（mini 委托 workspace-only 替换其同等全权法）；version-ledger 场景与闭环清单对齐 + 路由前置双档用例；迁移向导只处理非控制面应用（admin/mcp 随 full 镜像恢复）；移除语义强断言；新增 mini 监听器边界 requirement；候选隔离如实降级为凭证域隔离；proposal 亲证措辞与 latest 措辞统一；新增 shared-core 一致性 requirement。 -->
<!-- 正交意图：①mini 产品拓扑与信任模型 ②准入/composition/快照三契约 ③双产品构建与发布工程 ④顺序门与 owner 待决。 -->

## Context

标准版（更名 iweb-full）当前是每应用一个 celld 进程的 fleet（admin/mcp/hello/search/collab/collab-b）+ Kernel + RustFS 单容器。实测整节点闲时 RssAnon：cloud amd64 162.3 MB、arm64 148.1 MB、iMac 231.3 MB（跨机偏差未解释）；celld 进程基线 RssAnon 8–40 MB。celld 官方模型是一个 fleet 只跑一个应用一个当前 deployment；仓库历史上的共享 Dispatcher 形态（admin/mcp/notes 同部署分支）真实运行过，是 mini 拓扑的可行性证据。

现行产品法把「应用互不信任、共享 Dispatcher 不得接受任意应用包」定为底线；mini 的合法性来自把信任边界换成「节点只运行 owner 亲自选择的代码」，此时共享是诚实的。

```text
iweb-mini 节点（单容器，无外网出口拓扑）
┌────────────────────────────────────────────────┐
│ Kernel (product-mini 二进制, :8080 发布入口)     │
│   ├ <base> / api.<base>     Kernel 直有         │
│   ├ admin.<base> 等 → 共享 fleet celld :8787    │
│   ├ 版本账本 + admission ledger + composition   │
│   ├ 快照引擎（Kernel 凭证，快照 bucket）        │
│   └ 审计 JSONL（/data/kernel，fleet 外）        │
│ celld 共享 fleet（单进程，fleet bucket 凭证窄域）│
│   └ admin@img + mcp@img + appA@v2 + …          │
│ RustFS :9000（回环）                            │
└────────────────────────────────────────────────┘
宿主侧：docker pull 更新镜像（不在容器 egress 语义内）
```

## Goals / Non-Goals

**Goals**

- 让不安装第三方应用的 owner 获得密度收益（省约 40–150 MB RssAnon，实测为准）与更简单的运维
- mini 的每一条安全声明都可机械执行或如实降级：fail-closed 缺席、双层 egress 禁止、恢复权威独立于 fleet
- 两档产品共享 contracts/MCP 语法/API 骨架而不漂移：mode matrix 发布阻断
- 更新安全：失败的更新伤不到健康旧 composition（含状态），代价是有界中断窗口

**Non-Goals**

- 不修复 celld 无 per-branch RSS 归因的现实，而是禁止伪造（node overhead 标注）
- 不提供 preview/canary/按应用灰度（两档 v1 均无；preview-versions 是未来独立变更，主战场 full）
- 不做 mini→full 一键无损升档或降级（并行节点迁移 + 重新亲证）
- 不在 v1 交付：应用删除（清 ledger+数据）、状态迁移 adapter（v1 零）、审计防篡改（宿主级攻击者不在威胁模型内）
- 不修改 typescript-monorepo 变更（目录引用以其归档实现为准）

## 核心机制

### 准入（两阶段冻结收据）

```text
workspace 暂存（agent/owner 写入，普通文件，永不执行）
  → Kernel 原子收集+校验+冻结 → 不可变候选快照 + 收据
     {applicationId, packageDigest, manifestDigest, versionId 预计算,
      route-registry generation(仅审计上下文)}
  → Admin 双区块展示：包内容(manifest) × 已注册路由(注册表派生)
  → bootstrap owner 确认收据 ID
  → 仅对冻结快照执行 admission → ledger 记录
过期/篡改/身份不一致/预计算变化 → fail-closed 拒绝
```

applicationId === manifest.name 严格绑定；versionId 内容寻址以 applicationId 为命名空间；admin/mcp 为受保护系统应用，亲证流程不可替换（控制面更新权威 = mini 镜像发布）。

### 更新事务（有界中断，自动恢复）

```text
编辑: expected-generation 提交 ──409 stale──→ 重审再交
部署: 候选 fleet(独立 bucket,零状态)代码级预检
      → 停流量 → quiesce(排空在飞 DO/WebSocket)
      → 可验证快照(稳态 fleet bucket + composition 注册表)
      → 新 composition 重部署稳态 bucket → 重启 celld
      → readiness 门未过不恢复路由
      → 过门 → composition 指针原子翻转
      └ 门失败 → 自动恢复本次快照 → 重部署旧 composition → 旧 readiness 复验
生效后回退: code-only(新 composition 选旧版本, 数据兼容 owner 负责)
           或 破坏性: 恢复指定快照(丢弃其后写入)
```

部署事务是 Kernel 单写者串行：同一时刻至多一个 in-flight 更新，期间新编辑提交 409「节点更新中」。零停机被明确否定：celld 的 DO/D1 状态绑定 bucket，空状态候选不能承载有状态真实流量，无跨 bucket 状态迁移。

### 凭据域（co-trust 的精确边界）

共享的是 fleet 执行、状态与可用性命运；**不共享** owner 恢复凭据域：IWEB_API_TOKEN、委托 key 账本、Kernel 控制状态、workspace 授权、快照凭证永不进入 fleet；fleet 进程 S3 凭证仅覆盖稳态 fleet bucket；Kernel 不提供无鉴权的 fleet→控制面路径。坏应用的上限是毁 fleet；`api.<base>`（Kernel，fleet 外）始终能重部署已记录 composition 或恢复快照。

## 决策表（grilling Q1–Q26 收敛，30 项）

| # | 决策 | 源 |
|---|---|---|
| D1 | owner 亲证准入（非镜像封闭目录）；owner-confirmation point | Q1 |
| D2 | 准入权威 = bootstrap key（API 仅证明 key 持有，不证明人类点击）；不可委托；MCP 生命周期工具在 mini 缺席；iwb_* 逐类禁权 403（denylist 可测试）。与 owner-key-management 的「delegated 同等全权」法构成显式替换：mini 委托 = workspace-only，该变更先归档 | Q1/Q2/Q25 + R1/R3 |
| D3 | 协议不分叉：准入契约复用 full 的不可变版本法；产品差异限于闭环清单（确认权威/执行拓扑/mini 首次准入路由前置）入 mode matrix | Q2/Q17 + R2 |
| D4 | MCP 保留 workspace 写入（agent 备包、owner 亲证的产品流） | Q2 |
| D5 | 激活/回退单位 = fleet composition；per-app 版本台账保留 | Q3 |
| D6 | 否决双 fleet 零停机（状态绑定 bucket）；候选只做零状态预检；接受有界中断 | Q3/Q10 |
| D7 | 回退权威 = Kernel 经 api.<base>，不是 fleet 内的 Admin | Q3/Q5 |
| D8 | 快照事务：每次 composition 更新无条件 quiesce + 可验证快照 + 自动恢复（无状态捷径）；生效后 code-only 回退与破坏性恢复分离 | Q4/Q21 + R1 |
| D9 | 快照排除 workspace/版本对象区/审计账本；流量门在 readiness 之后 | Q4/Q20 |
| D10 | 凭据域底线 + 诚实披露升为 requirement：Admin 凭据捕获风险、亲证=key 持有语义、co-trust 披露进准入 UI 与文档 | Q5 + R1 |
| D11 | mini→full 并行迁移：ledger 驱动预暂存向导 + 逐应用重准入、无状态 adapter（v1 零）、凭据全轮换、DNS 切换后就绪验证、不支持降级 | Q6 + R1 |
| D12 | 三层治理：shared core / full law / mini law；现有 specs 双产品适用，仅 mini-* 显式替换（替换映射入 mode matrix），full 法不写 mini 例外 | Q7 + R1 |
| D13 | 同源码双互斥二进制；模式由镜像构建固化，fail-closed；排除环境变量开关 | Q7/Q8 |
| D14 | feature 边界在模块/路由组合层；共享核心行为同一性由共同契约套件验证；version-ledger 为独立共享 capability（收据/版本身份/拒绝形状/双镜像套件） | Q8 + R1 |
| D15 | Admin 双构建 profile；mini 以 Fleet composition 为信息架构核心；per-app 操作框定为 composition 编辑 | Q9 |
| D16 | v1 无 preview/canary（两档对称缺席）；候选验证命名「预检」 | Q10 |
| D17 | 内存合同：出厂 composition 整节点 RssAnon gate，目标 160 MiB，实测超限 owner 重批准 | Q11 |
| D18 | 顺序门：typescript-monorepo 归档 commit + owner 信号，双硬条件 | Q12 |
| D19 | 发布身份：iweb-full/iweb-mini 双 slug、双仓库、双 tag 线、身份字段含 contracts revision；两仓库均不发布/移动 latest（v1 全禁）；标准版更名断代 | Q13 + R1 |
| D20 | 两阶段发布：无任何自动正式版本（含 patch）；RssAnon gate 由 self-hosted/owner 节点出证据 | Q14 |
| D21 | hostIds 不进 manifest；新应用顺序固化为路由注册先于首次准入（无路由拒发收据）；准入/composition 操作永不触碰路由注册表 | Q15 + R1 |
| D22 | 身份严格绑定；系统应用不可亲证替换；versionId 按 applicationId 命名空间 | Q16 |
| D23 | OCC：expected generation、409 带当前 composition、部署事务单写者串行 | Q18 |
| D24 | 成员规则：api 永不入 composition；admin/mcp 强制固定；内置应用可选；移除不删数据、路由保持 502 | Q19 |
| D25 | 审计：Kernel 独立 JSONL；追加落盘 = 高风险操作提交前置（含自动恢复，无例外）；快照永不回滚审计 | Q20 |
| D26 | 快照 N=3 产品常数（无配置、无手动删除 API）；in-flight 钉住；Kernel 凭证域 | Q21 |
| D27 | egress 双层禁止：契约拒绝(unsupported-policy) + compose 无出口拓扑（缺失即 release blocker，先于一切可执行化）；未断网时如实提示降级 | Q22 + R1 |
| D28 | 包必须自包含（celld 项目形态）；唯一允许变换 = 镜像钉版 celld 固定参数管线 | Q23 |
| D29 | manifest resources/storage 在 mini 降级为审阅元数据；真实资源边界仅 fleet 级 | Q24 |
| D30 | API 两族：version-ledger（共享）+ 运行单位族（full: sandbox lifecycle；mini: composition）；401/403/404 决定论（存在性由编译期模式决定，先于鉴权） | Q2/Q26 |

## 妥协声明（写进 mini 产品文档与 Admin 准入界面）

1. 被准入应用与 admin/mcp 同进程同凭证域（co-trust）：owner 准入即选择共命运；不可信应用托管的产品答案是 full
2. fleet 被攻破时可篡改 fleet 服务的 Admin UI、捕获登录输入的凭据——api.<base> 保护的是恢复机制可用性，不是该场景下的凭据保密性（v1 接受；Kernel 内嵌极简登录页为未来加固备忘）
3. mini 应用更新存在有界中断窗口；无 preview；无 per-app 内存归因（node overhead 标注）
4. 部署未启用无出口拓扑时，被准入应用共享 fleet 进程原始网络能力——manifest 从不控制它，准入摘要明确展示「egress：不可强制，本产品不支持」

## 顺序与回滚

- 本变更只产出 OpenSpec 文件；Apply 双硬门见 proposal 序门。tasks 1.1 回填 typescript-monorepo 归档 commit 后，后续任务才可开工
- mini 镜像交付回滚：mini 各版本是不可变 digest，回滚 = 重新部署上一 digest 的 compose（full 完全不受影响；两档不同仓库路径消除工具链引用歧义；产品感知的部署/升级入口在替换容器前校验期望 slug/repository——原始 docker pull 无法也无需在 registry 层阻止，如实声明）
- mini→full 迁移回旋余地：mini 节点保留为归档直到 owner 主动退役；「不可逆」仅指不存在控制状态原地转换
- 本变更自身回滚：未 Apply 前删除 changes/iweb-mini-product/ 目录即可，不触及任何产品代码

## 实现选型留白（design 后续在实现任务中细化，不得违背已定边界）

- product feature 的具体 cargo 组织（bin 目标 vs feature 组合）与镜像内模式描述文件形态
- composition 与 version-ledger 端点具体路径：实现前必须先在 mode matrix 中固定其 owner / delegated / unauthenticated / 404-absent 格子（路径与授权矩阵先行，两族边界不可违背）
- 快照引擎实现（mc mirror vs RustFS 服务端 copy）与 quiesce 信号机制
- mode matrix 工件的机器可读格式（从 contracts 推导的生成方式）
