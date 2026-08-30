# Design — two-tier-runtime-trust

## 决策 1：celld 层的边界是「每应用独立进程 + 用户态软限看门狗」，不是沙箱

- celld fleet 应用（admin/mcp/notes/hello/search/collab/collab-b）已经是每应用一个 celld 进程（entrypoint `run_celld` 写 pidfile，Kernel `sampling.rs` 已按 `/proc/<pid>/status VmRSS` 采样）。
- 信任来源是镜像出处：owner/AI 构建、镜像内置。对这一层，进程边界 + 崩溃隔离 + 软限处决已足够；内核级同步硬限（cgroup memory.max）被明确放弃，取而代之：
  - Kernel 采样循环（15s）按 `/opt/iweb/config/celld-resource-policy.json`（默认值 + 每应用覆盖）检查 VmRSS，越限对 pidfile 目标 SIGKILL；
  - entrypoint 监督循环检测 celld 进程退出并按 1s 退避重启（单应用重启，邻居无感；`/data/run/celld-<app>.disabled` 标记可停用单应用）；
  - kill 事件记录在 Kernel 有界事件环里，进入 `/v1/status` 与 monitor 投影。
- 采样口径的诚实性：VmRSS 不含页缓存，是低估；文档与 Admin 文案必须写明「进程驻留内存，非 cgroup 全口径」。无采样仍为 `null`，禁止补 0（现行法律不变）。

## 决策 2：celld 运行时准入删除的范围与依据

- Rust Kernel 从未实现 celld 生命周期端点（勘查证实：http.rs 只有静态 503 `applications_gate` 与硬编码 `applicationPublication`）；完整实现只存在于**已不进镜像**的 JS reference kernel。因此删除是无损的：没有生产路径依赖它。
- 删除面：JS `kernel/` 目录、`tests/application-publication-gate.test.ts` 等 JS 遗留测试、Rust `applications_gate` 路由、`applicationPublication` 状态键、`wasm_publication.rs` 的 celld gate 半边（`evaluate_celld_publication_gate_v1`、`PublicationGateSetV1.celld`、`select_publication_gate` celld 臂、`CELLD_ACCEPTANCE_FILE`）与对应测试、`control_journal.rs`、`control.rs`、`/v1/recover/sandboxes` stub、`/v1/status` celld applications 投影、monitor `sandboxes` 数组。
- 保留面：celld 流量面全部不动（`routes.rs` 端口表、System 代理、per-app 请求指标、RSS 采样）。
- 生产卷上的存量 `control-db.json`：破坏性更新，不迁移、不读取；文档注明可手工删除。

## 决策 3：kind-claim 从路由注册表派生，消灭 PENDING 失败模式

- 现状：`wasm_kind_registry` 从 celld 控制状态文件派生终身 claim；文件损坏 → wasm 准入整体 503 `WASM_KIND_BOOTSTRAP_PENDING`（fail-closed）。控制状态删除后此链路必然重写。
- 新源：启动时从路由注册表读取所有 `target.kind == "celld-app"` 的 `appName`，作为终身 celld claim 与 wasm-control-state-v2 持久 claim 合并。路由注册表是镜像种子 + owner 写入的唯一应用身份权威，与「route registry is the sole app identity」现行法一致。
- 效果：bootstrap 成为确定性步骤（路由文件不可读才失败），`WASM_KIND_BOOTSTRAP_PENDING`、`celld-control-state-v1` 迁移源、`ensure_bootstrap_current` 的 raw-digest 重验证链全部删除。
- 跨 kind 复用保护不变：wasm admission 对已 claim 的 applicationId 仍 409 `APPLICATION_RUNTIME_KIND_CONFLICT`。

## 决策 4：wasm 执行去 Podman 化，supervisor 进节点容器

- 勘查证实 wasm spawn 现在是完整 rootless Podman 容器参数（`wasm-spawn.ts:927-957`），资源强制依赖宿主 cgroup。这与「wasm 边界在引擎内」的新模型重复且引入全部宿主前提。
- 新执行链：Kernel（容器内）→ `/run/iweb-sandbox/supervisor.sock`（snapshot-fd-relay 前置，SO_PEERCRED 校验不变）→ supervisor（容器内、专用非 root 用户 `iweb-sandbox`）→ 直接 spawn `iweb-wasmd` 子进程，argv@2 与 FD 3/4 直通（Node `spawn` stdio fd 传递），无 OCI 参数、无 seccomp、无 Podman 网络。
- 资源强制：引擎内 fuel/epoch/ResourceLimiter（已在 wasmd 实现，跨平台）；wasmd 进程自身 RSS 纳入看门狗软限（与 celld 同一套机制）。
- 出口约束不变：组件无 socket import（能力矩阵拒绝），出站 HTTP 仅经 wasmd 宿主中介网关。wasmd 是受信宿主代码；「Wasmtime/wasmd 自身漏洞」为已接受的残余风险（行业共识口径，写入 spec）。
- 随之删除：`supervisor/adapter.ts`、`runtime.ts`、`sandbox-spec.ts`（共享常量先迁入 wasm 侧）、`desired-state.ts` celld 部分、`gateway.ts`/`gateway-main.ts`、`snapshot-materialize.ts`、`metrics.ts`、`subordinate-ids.ts`、`readiness.ts`、`packaging/*`（systemd 单元、两个 runtime Dockerfile、seccomp.json）、`scripts/install-sandbox-supervisor.bun.ts`、`docker-compose.sandbox.yml`。
- 容器内布局：镜像创建 `iweb-sandbox` 用户；entrypoint 创建 `/run/iweb-sandbox`（0711）；supervisor 状态目录固定 `/data/wasm-supervisor`（持久卷顶层；/data/kernel 是 0700 root 私密态，服务用户不可穿越）；relay 二进制由 Dockerfile 构建（cargo cache mount 后增量成本可忽略）；supervisor 以 bun build --compile 的单可执行运行（glibc builder 编译）。
- supervisor 健康投影 `sandboxSupervisor` 因 socket 容器内可达而首次真实反映状态。

## 决策 5：监控契约按层定义「可信来源」

- celld：memoryBytes=VmRSS 采样（现行为真）、cpuMillis=/proc stat 差分（新增，available:true）、pidCount 可用 /proc 子进程枚举（可选实现，默认 unavailable）、limits=软限策略值（新增 wire 字段）。
- wasm：引擎指标（guestMemoryBytesInstant 等，已有 wire 契约）+ wasmd 进程采样；limits=引擎硬限。
- `unavailable`/零值法律逐字保留；「enforceable limit」措辞按层改为「engine-enforced limit（wasm）/ watchdog soft limit（celld）」。

## 决策 6：验收记录与发布门的去留

- celld v1 验收记录与 `IWEB_APPLICATION_PUBLICATION_ENABLED` 语义删除（连同 JS gate 遗留）。
- wasm 验收记录保留但口径改为「wasmd 进程 + 引擎强制」：v3 记录中 Podman/双容器表述从 spec 移除；`IWEB_WASM_PUBLICATION_ENABLED` 默认关不变，记录创建/seal 仍是 owner 停止点（本 change 不开启、不创建记录）。

## 决策 7：MCP 的 AI 引导

- MCP 工具面：应用包校验/发布/生命周期工具全部指向 wasm 准入；无 celld 发布工具。
- 工具描述中加入两层引导：不可信/来源不明代码 → 编译为 wasi:http 组件（QuickJS/StarlingMonkey 承载 JS、MoonBit 原生）经 wasm 准入；可信且需原生能力 → 构建进节点镜像。工具链选型调研（componentize-js vs StarlingMonkey）是独立后续任务，不阻塞本 change。

## 风险与对策

- **R1 大删除误伤流量面**：代理/端口表/指标与准入面在不同模块，实现批次按文件清单走，门禁含远端部署全链路探针。
- **R2 supervisor 进容器后 socket 契约破绽**：SO_PEERCRED/固定路径/inode 校验保留且 preflight 在容器内跑；kernel peer 0/0 语义在容器内不变（Kernel 为 root）。
- **R3 看门狗误杀**：软限默认保守（如 512 MiB/应用），策略文件 owner 可调；kill 事件可审计。
- **R4 生产卷存量文件**：`control-db.json` 不再被读取；文档注明可删。旧 `/run/iweb-sandbox` 宿主挂载作废无副作用（容器内自建）。
