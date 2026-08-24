<!-- 用户原始需求（2026-08-24）：另立 iweb-mini 产品线，独立发布，只与标准版共享主要标准；开发排在 typescript-monorepo 完成之后；先经 Codex grill-me 访谈固化边界，再起草本变更；不开工实现，等 owner 信号。 -->
<!-- 访谈 provenance（2026-08-24）：Codex（gpt-5.6-terra，xhigh）经 herdr 完成 26 轮 grilling（Q1–Q26），收敛 30 项决策与 5 项 owner 待决，全文见 design.md 决策表；本 proposal 只陈述已定边界。 -->
<!-- Codex 审稿 R1（6.0/10）：新增 version-ledger 共享 capability；阅读规则改为双产品适用+显式替换；路由顺序/快照无条件/委托 denylist/披露条款/无 latest/迁移向导/拓扑前置均已落入 specs 与 tasks。 -->

## Why

标准版 iweb 的产品法是「应用互不信任、每应用独立沙箱」，这是面向「普通人让 AI 部署来路不明代码」的安全底线，但它让永不安装第三方应用的 owner 也为隔离付全部内存与复杂度成本（每应用独立 celld 进程 + rootless OCI supervisor）。存在一个诚实的更轻档位：节点只运行镜像内置与 owner 亲证（owner-attested：持有 bootstrap key 的显式确认，不宣称证明人类审核）的应用，全部应用共享一个 celld fleet（回到仓库历史上已验证过的共享 Dispatcher 形态），用密度换边界。

该档位不能做成「一个程序的安全开关」——开关不会只关掉安全，会关掉产品承诺。因此 mini 是独立产品线：独立构建、独立镜像、独立版本线、独立产品法，只与标准版共享契约（contracts）、Kernel 核心、Admin 源码与 MCP/API 语法。

## What Changes

- **BREAKING** 标准版更名为 **iweb-full**（镜像名断代，不做兼容重定向），与 **iweb-mini** 构成对称产品族；仓库仍为 jixoai/iweb 单仓
- 同源码、互斥 `product-full` / `product-mini` cargo feature 双 Kernel 二进制（缺失或同启即编译失败）；full-only 路由不编入 mini（统一 404 absent）；Admin 双构建 profile；双 OCI 仓库、`full-v*` / `mini-v*` 独立 tag 线、两仓库 v1 均不发布 latest 或任何移动别名
- mini 运行拓扑：单 celld 共享 fleet + Kernel + RustFS，无 sandbox supervisor；compose 默认无外网出口网络（egress 双层禁止：契约拒绝 + 拓扑断网）
- mini 准入法：**owner 亲证准入**（owner-attested admission）——bootstrap owner key 是唯一代码可执行化权威，不可委托（API 仅证明 key 持有，不证明人类点击）；冻结收据两阶段流程；身份严格绑定；委托 key 仅 workspace scope（与 owner-key-management 的 full 法「同等全权」构成显式产品差异，见 product-tiers 替换映射）
- mini 运行单位：版本化 **fleet composition**（不可变 compositionId + generation + OCC）；更新 = 预检（零状态候选）→ quiesce → 快照 → 稳态 bucket 重部署 → 重启 → readiness 门，诚实包含有界中断；失败自动恢复快照与旧 composition
- mini 恢复法：快照保留 N=3（产品常数）；显式破坏性恢复；`api.<base>` Kernel API 是唯一恢复权威；Kernel 独立 JSONL 审计账本，追加落盘是高风险操作提交前置
- mini→full 是并行节点安全迁移（重暂存、逐应用重准入、凭据全轮换、状态仅经应用专用 adapter，v1 零 adapter），不支持降级
- 治理：现有 specs 双产品适用、仅 mini-* 显式替换（替换映射入 mode matrix，发布阻断）；发布两阶段（候选 digest → owner 批准）；两仓库 v1 均不发布 latest；mini 出厂 composition 整节点 RssAnon release gate，目标 160 MiB（实测超限须 owner 重批准）；无外网出口拓扑是发布阻断项且先于一切可执行化
- v1 两档均无 preview/canary：候选验证只称「预检」（pre-check），不承载真实状态流量

## Capabilities

### New Capabilities

- **product-tiers**：两档产品的身份、构建、发布、阅读规则与迁移合同——谁在哪个二进制里、哪个法管哪个产品、版本线如何互不混淆、mini 如何升档
- **version-ledger**：共享的版本账本族契约——冻结收据、版本身份、拒绝形状、双镜像共同契约套件（两档同文法，差异仅授权与拓扑）
- **mini-admission**：closed 档的代码可执行化唯一路径——owner 亲证准入、冻结收据、身份绑定、包形状、egress 拒绝、字段降级、委托 scope 与可测试 denylist
- **mini-fleet-composition**：composition 作为运行单位——成员规则、OCC、部署事务与有界中断、自动恢复、监控降级、Admin 信息架构
- **mini-recovery**：快照范围与保留（每次更新无条件）、破坏性恢复、恢复权威、审计账本独立性

## 序门（Apply 前置，缺一不可）

1. `typescript-monorepo` 变更全部任务完成、owner 验收、归档于固定 commit（本变更 tasks 1.1 回填；期间不修改该变更，设计中的目录引用以其归档实现为准）
2. `owner-key-management` 变更归档于固定 commit（mini 的委托 scope 法与该变更的「同等全权」法构成显式替换关系，须在其归档基线上声明，见 product-tiers 替换映射；任务 1.1 一并回填）
3. owner 明确的正向开工信号（「不要开工」类否定指令不满足此条件；2026-08-24 指令：「不要开工，等我信号」）

## Owner 待决（评审时裁决）

- 准入模式最终确认：按「owner 亲证准入」推进，或降级为「镜像封闭目录」（Q1，见 design.md D1）
- 160 MiB gate：任一架构实测地板超限时须显式重批准（Q11）
- 正式 OCI registry namespace：release manifest 填定（Q13）
- composition 与 version-ledger 端点具体路径：design.md 细化，不得违背两族边界（Q26）
- 序门第 3 项的开工信号：双基线 commit 回填后由 owner 显式给出正向授权（见下）
