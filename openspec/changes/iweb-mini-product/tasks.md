<!-- 用户原始需求（2026-08-24）：mini 变更任务分期；全部任务在序门通过前不开工；目录引用以 typescript-monorepo 归档实现为准。 -->
<!-- Codex 审稿 R1：无出口拓扑前置到可执行化之前；部署事务写全序列；拆分混合任务；补 version-ledger 契约与 DNS 切换验收。 -->

## 1. 序门与契约（P0）

- [ ] 1.1 前置基线确认：typescript-monorepo 与 owner-key-management 两个变更全任务完成、owner 验收、openspec 归档，分别回填固定 commit X/Y 到本行与 proposal；期间不改这两个变更；Apply 还需 owner 明确的正向开工授权（「不要开工」类否定指令不满足此条件，须引用可查的正向授权会话） —验收：`openspec` 归档记录 + git log 定位 + 正向授权引用
- [ ] 1.2 scope 词汇表语法进 contracts（共享文法；mini 可签发集合={workspace}） —验收：contracts 导出 + 单测
- [ ] 1.3 mode matrix 工件 schema（API/MCP/Admin 操作 × 产品 × 身份 × 401/403/404-absent × 审计事件 × requirement 替换映射） —验收：schema 定义 + 生成器骨架
- [ ] 1.4 version-ledger 共享契约：收据字段/版本身份（applicationId 命名空间）/拒绝形状 schema + 双镜像共同黑盒契约套件骨架 —验收：同一 fixture 在双镜像跑通的 CI 骨架
- [ ] 1.5 composition 文档类型（compositionId/内容寻址/generation/条目校验）与部署事务状态机类型进 contracts —验收：纯函数单测覆盖成员校验/拒绝原因

## 2. Kernel 双构建（P1）

- [ ] 2.1 `product-full`/`product-mini` cargo feature 互斥守卫（缺失/同启编译失败）＋ 空路由组合壳 —验收：守卫编译测试
- [ ] 2.2 模块/路由组合层切分：共享核心为主体；full-only 路由与 supervisor 客户端不编入 mini；mini-only composition/准入/快照路由不编入 full —验收：两份二进制符号级差异审计
- [ ] 2.3 镜像产品描述与启动一致性校验（fail-closed 拒绝启动；/v1/status 只读投影 product slug/版本/三 digest/contracts revision） —验收：错配镜像启动失败 e2e
- [ ] 2.4 审计账本扩展：新事件类型与字段（nullable/applicable 语义）＋ 追加落盘作为高风险操作提交前置（失败 503，含自动恢复路径无例外） —验收：注入写盘失败的事务中止测试
- [ ] 2.5 401/403/404 决定论与委托 denylist：路由存在性由编译期模式决定先于鉴权；409 stale 响应携带当前 composition；iwb_* 对逐类禁权操作 403 断言 —验收：矩阵逐格断言测试（mini 侧 404-absent 断言必含）

## 3. mini 运行时（P1，拓扑先行）

- [ ] 3.1 无外网出口拓扑默认 + 容器内出网探测全拒 + mini 监听器边界验收（仅 Kernel ingress 发布；RustFS/celld public/operator 回环不可外达；api.<base> 在 fleet 停止时仍可达）（缺失拓扑 = release blocker，先于一切准入/fleet 可执行化） —验收：探测 e2e + release 断言 + fleet 停止时 api 可达 e2e
- [ ] 3.2 entrypoint mini 拓扑：单共享 fleet celld（factory composition = 强制控制面 + 产品描述声明的内置集合与初始 ledger）、RustFS、Kernel；fleet 凭证窄域（仅稳态 fleet bucket） —验收：容器内进程/监听/凭证投影审计
- [ ] 3.3 快照引擎：quiesce（停流量+排空在飞 DO/WebSocket）→ 可验证快照（稳态 bucket + composition 注册表；排除清单显式）→ N=3 轮转（in-flight 钉住、无手动删除 API） —验收：四连更新的轮转断言 + 快照校验和验证
- [ ] 3.4 部署事务（完整序列）：候选 fleet 零状态预检（候选 bucket 最小凭证；负向 e2e：候选代码以候选凭证触达稳态 bucket/workspace/版本区/快照被授权拒绝、无 Kernel/owner 凭证可用、无生产路由指向候选——凭证域隔离语义）→ 停路由 → quiesce → 快照 → 新 composition 重部署稳态 bucket → 重启 → readiness 门后恢复路由 → 指针翻转；门失败自动恢复（快照回滚 + 旧 composition + 旧 readiness 复验）；单写者串行 + 更新中编辑 409 —验收：注入坏 composition 的自动恢复演练 e2e（含审计事件链）+ 候选凭证域负向 e2e
- [ ] 3.5 准入执行：两阶段冻结收据（过期/篡改/身份不一致/无注册路由 fail-closed）、egress 非空拒绝（unsupported-policy）、包形状拒绝清单（scripts/install/远程 import/Worker Loader 入口）、受保护系统应用拒绝 —验收：拒绝矩阵夹具

## 4. Admin 与 MCP（P2）

- [ ] 4.1 Admin 构建 profile：mini bundle tree-shake full-only 视图；运行期 /v1/status 一致性硬停 —验收：双 bundle 差异审计 + 错配硬停 e2e
- [ ] 4.2 mini 信息架构：Fleet composition 主视图（当前 composition/ledger/更新态/亲证入口）；per-app 操作框定为 composition 编辑；预检措辞规范；bootstrap-only 入口对 delegated 不渲染 —验收：浏览器契约夹具（delegated 登录无准入/恢复入口）
- [ ] 4.3 准入 UI：双区块摘要（manifest × 注册表派生路由）＋ 披露条款（co-trust/凭据捕获/用 full）＋ 免责勾选 + 收据确认流；快照破坏性恢复区（cutoff 警示） —验收：契约测试 + 状态机 8 态覆盖 + 披露文案存在性断言
- [ ] 4.4 MCP mini 工具面：workspace + 只读投影工具；生命周期工具在任何 caller 下缺席 —验收：tools/list 快照测试（bootstrap/delegated 两身份）

## 5. 镜像与发布（P2）

- [ ] 5.1 双 Dockerfile（arm64/amd64 × full/mini）、发布身份字段集（slug/版本/三 digest/contracts revision）、gaubee/iweb-full 与 gaubee/iweb-mini 本地默认（正式 registry 待 owner 填定）；latest/移动别名发布即流水线拒绝 —验收：镜像 labels/manifest 检查 + 别名拒绝断言
- [ ] 5.2 CI 从头建立两阶段流水线：tag-产品匹配失败即拒；托管部分（契约套件/mode matrix 含替换映射/双架构交叉构建/SBOM/provenance/候选 digest）；正式版本一律 owner 批准（无自动含 patch） —验收：干跑全链 + 批准前不产生版本 tag 的断言
- [ ] 5.3 RssAnon gate 执行载体：self-hosted runner 或 owner 本地验收脚本（smaps_rollup 求和、静置窗口、同格式 evidence 工件）；160 MiB 目标，实测超限上报 owner 重批准 —验收：双架构 evidence 入 .agents/evidence/

## 6. 验收与文档（P3）

- [ ] 6.1 内存 gate 实测：出厂 composition 双架构 RssAnon；full 对照（同机同窗同法，描述性） —验收：evidence 文件 + gate 通过/重批准记录
- [ ] 6.2 fail-closed 全矩阵：mini 二进制 404-absent 断言；401/403/404 决定论；委托 denylist 逐类断言；矩阵与行为一致性（漂移即阻断） —验收：CI 报告
- [ ] 6.3 恢复演练：坏更新自动恢复、破坏性恢复（数据丢失 cutoff）、fleet 死亡时 api.<base> 回退、审计不回卷 —验收：演练记录 + 审计链检查
- [ ] 6.4 迁移演练：mini→full 并行迁移（迁移归档含不可变包快照 + ledger 摘要校验后才预暂存、逐应用重准入、凭据轮换、ledger 只读归档、DNS/hostname 切换后应用就绪验证、原 workspace 已变化时缺包/摘要不符拒绝路径）；不支持降级验证 —验收：迁移指南 + 演练 evidence（含缺包与摘要不符两个负向路径）
- [ ] 6.5 文档：mini README（妥协声明、序门、egress 降级、亲证=key 持有非人类点击）、mode matrix 发布文档、README-full 更名说明（一句带过拉新镜像）；AGENTS.md 增补 mini 产品法导读与阅读规则 —验收：文档评审
- [ ] 6.6 Codex 代码/安全 review 闭环（实现完成后整变更 review，评分与阻塞项处理记录）
