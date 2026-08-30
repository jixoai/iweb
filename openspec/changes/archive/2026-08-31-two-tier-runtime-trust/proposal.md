## Why

iweb 的应用隔离至今按「双运行时准入 + per-app OCI 沙箱」单一模型推进：celld 与 wasm 都承诺运行时包准入，celld 侧依赖宿主机 supervisor、rootless Podman、cgroup v2 与验收记录，跨平台代价高且从未在真实 Linux 主机上完成验收；而 wasm 的隔离本质是结构性的（组件无 socket 能力、出口仅宿主网关、引擎内 fuel/epoch/内存硬限），不需要容器边界。

Owner 决策（2026-08-30）：确立两层信任模型。celld 层是**信任层**——应用只能经 owner 构建的节点镜像进入，边界是每应用独立进程 + 用户态软限看门狗；wasm 层是**唯一运行时准入路径**——隔离由 Wasmtime 引擎结构性地强制，执行链自包含在节点容器内，不依赖宿主机 systemd/Podman/cgroup。原 celld 侧 OCI 沙箱机器整体退役。

## What Changes

- **BREAKING**：celld 运行时准入与版本生命周期永久移除。Rust Kernel 删除 `applications_gate` 503 门、`applicationPublication` 状态键与 celld 侧 gate 评估；未进镜像的 JS reference kernel 遗留（`kernel/index.js`、`kernel/application-control.js`、`kernel/application-publication-gate.js` 及其测试）删除。
- celld 控制状态（`control-db.json`）不再存在：`control.rs` 读投影、`control_journal.rs` 写路径、`/v1/status` 的 celld applications 投影与 monitor `sandboxes` 数组全部删除。celld 应用清单的唯一权威是路由注册表（镜像种子）。
- wasm kind-claim bootstrap 改从**路由注册表**派生（所有 `celld-app` 目标的应用名是终身 celld claim），`WASM_KIND_BOOTSTRAP_PENDING` 状态与 celld-control-state 迁移源删除——bootstrap 成为确定性步骤，不再有 pending 失败模式。
- **BREAKING**：wasm 执行链去 Podman 化。supervisor 直接以受管子进程拉起 `iweb-wasmd`（FD 3/4 直通），资源强制完全由引擎承担（fuel/epoch/ResourceLimiter，跨平台）；seccomp/Podman 网络参数、宿主 systemd 单元、宿主安装器、`docker-compose.sandbox.yml`、celld/gateway runtime 镜像与 supervisor 的 celld adapter 全部删除。
- supervisor 与 snapshot-fd-relay 移入节点镜像，作为容器内进程运行（supervisor 仍以专用非 root 用户运行，socket 的 SO_PEERCRED 双边契约保留）；节点不再要求任何宿主机沙箱前提。
- 新增 **celld 资源看门狗**：Kernel 采样循环（15s）按策略软上限检查每应用 celld 进程 VmRSS，越限 SIGKILL 该进程；entrypoint 监督循环按退避重启单应用（不影响邻居）；kill 事件与软上限进入监控投影。新增每应用 CPU 观测（`/proc/<pid>/stat` utime+stime 差分）。
- `unavailable`/零值诚实语义原样保留，但「可信来源」按层重定义：celld = 进程采样 + 软限；wasm = 引擎指标 + 硬限。`sandboxSupervisor` 状态投影因 supervisor 进容器而首次真实可用。
- Admin 删除 celld 版本生命周期 UI（admit/prepare/start/readiness/activate/rollback/stop/delete）与 `applicationPublication` schema 键；资源表新增软上限与看门狗动作列。
- MCP 的应用发布/生命周期工具收窄为 wasm-only；对 AI 的部署引导明确：不可信代码走 wasm（QuickJS/StarlingMonkey/MoonBit 编译为 wasi:http 组件），可信代码构建进镜像。

## Capabilities

### Modified Capabilities

- `application-sandbox`：从「双 kind 运行时准入 + OCI 沙箱」总纲改为两层信任模型总纲；新增 celld 镜像-only 供给条款与看门狗条款。
- `wasm-application-runtime`：边界来源从宿主沙箱/cgroup 改为引擎内强制；supervisor 拓扑改为节点容器内；双 gate 收敛为 wasm 单 gate；验收记录语义改为 wasmd 进程口径。
- `kernel-control-plane`：版本权威与生命周期操作面收窄为 wasm-only；celld 进程监督归 entrypoint/看门狗。
- `mcp-control`：发布与生命周期工具限定 wasm 包。
- `node-boundary`：节点不再承诺宿主沙箱前提；不可信包唯一执行路径是 wasm。
- `managed-applications`：celld 应用=镜像种子内置面，非过渡态。
- `workspace-and-routes`：用户路由目标仅 wasm；`celld-app` 路由为系统/镜像专属。
- `runtime-observability`：per-app 资源计量按层定义来源；看门狗动作可见。
- `administration-console`：术语跟随（运行时与监督状态展示）。

## Impact

- Rust：`kernel-rs/iweb-kernel/src/`（http.rs 端点与状态投影、wasm_publication.rs celld gate 半边、wasm_kind_registry.rs bootstrap 源、control.rs/control_journal.rs 删除、sampling.rs 扩展为看门狗+CPU、supervisor.rs 健康语义）及 `kernel-rs/snapshot-fd-relay`（进镜像）。
- TypeScript：`supervisor/`（删 celld adapter 族、wasm-spawn 去 Podman、装配进容器）、`scripts/iweb-entrypoint.sh`（监督循环 + supervisor/relay 启动）、`Dockerfile`（supervisor 构建阶段）、删除 `packaging/iweb-sandbox-supervisor.service`、`packaging/celld-runtime.Dockerfile`、`packaging/gateway-runtime.Dockerfile`、`packaging/seccomp.json`、`scripts/install-sandbox-supervisor.bun.ts`、`docker-compose.sandbox.yml`、`kernel/`（JS 遗留）。
- Admin：`apps/admin-console/src/lib/`（contracts/api/route-manager/application-resource-table 及测试）。
- MCP：`apps/workers/mcp`（工具面与文案）。
- 文档：`AGENTS.md`、`README.md`、`README-zh.md`。
- 不开启 wasm publication（`IWEB_WASM_PUBLICATION_ENABLED` 仍默认关；验收记录的创建与 seal 仍是 owner 停止点）。
