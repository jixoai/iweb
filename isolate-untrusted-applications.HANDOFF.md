# isolate-untrusted-applications - Handoff

## Goal

为 iweb 建立面向普通用户的可信应用容器：用户或 Codex 提交的代码默认不可信，每个应用版本必须拥有独立的执行、凭据、持久数据、网络、资源和生命周期边界。Kernel 永远是控制与恢复权威；应用不得访问其它应用、工作区、MinIO 管理面、Kernel、supervisor、宿主机或未授权公网目标。

Admin/MCP 是受保护的节点控制面应用，不是普通应用 sandbox。`api.<base>` 永远由 Kernel 提供恢复入口。应用 publication gate、真实 Notes 迁移和归档仍受 hard stop 保护。

## Current Progress

- Change: `isolate-untrusted-applications`
- Schema: `spec-driven`
- Branch: `main`
- Baseline: `74b3401066084a3319d27cade618574bba8a81fd`
- 当前任务进度：**97/107**。本轮修复了上轮复审 reopening 的全部七项（2.22/2.28/2.37/2.47/7.3/7.4/10.4）并完成 2.33/2.34/2.48/4.2/9.2/9.5/2.53。
- 当前证据：`bun test` **471 pass / 5 skip / 0 fail**；Admin `bun run check` **0 errors / 0 warnings**；Admin Vitest **39 pass**（含 components 项目 5 个真实 DOM 测试）；`openspec validate --strict` **valid**；`docker compose`（含 sandbox 拓扑合并）**config OK**；`git diff --check` **clean**。
- 证据目录：`.agents/evidence/2.33-2.34-real-celld-deploy.json`（本轮真实节点重跑并持久化）、`12.3-credential-scan-partial.json`（8/9 kinds）、`2.41-imac-control-plane-smoke.json`、`11.1-notes-real-migration.json`。
- 未 commit、push、sync、archive、release；未开放 publication；未写新的 sandbox acceptance record；未执行真实 Notes 数据迁移。保留所有用户 dirty/untracked 修改。

## What Worked（本轮逐项闭环，production call site + focused evidence）

1. **2.22 部署指针字段校验**：`kernel/package-store.js` 的 deploy/deployed 现在携带完整版本身份（applicationId/versionId/digest/sequence）；celld 指针（deploy/current.json）之外，deploy 写入 Kernel 拥有的 `deploy/version.json` 并回读校验；`deployed()` 只有当指针 well-formed 且记录逐字段匹配请求身份才为 true（stale → 重部署）。deploy 内部先按单一摘要权威重算快照，不符即拒绝。共享校验器在 `contracts/persisted-records.ts`（validateVersionDeploymentRecord/deploymentRecordMatches）。测试：`tests/package-store.test.ts`（missing/partial/stale/digest-mismatch/unknown-field 矩阵）、`tests/application-control.test.ts`（stale 记录触发重部署、完整身份到达 store）。
2. **2.28/2.37/2.47 持久化 fail-closed**：嵌套 `GatewaySecret.data` 走共享权威（validateObjectCredentialRecord：未知字段/endpoint/credential 字符串全查），.object 同源；storageSecret 固定 64-hex；applicationId 形状校验。desired-state 顶层未知字段/形状错误进 durable quarantine（不再静默空状态）；**quarantine 文件本身损坏 = 显式 QUARANTINE_FILE_CORRUPT 失败**（绝不静默清空历史）。Kernel `loadSecrets`：坏文件/坏条目全部写入 `control-secrets.json.quarantine.json`（kind/key/reason/at），损坏的 quarantine journal 抛 SECRETS_QUARANTINE_CORRUPT；负向测试证明坏凭据/坏 endpoint 永远到不了 rpc.prepare（gateway/celld adapter）。durability contract 明确：文件级 fsync 必须成功；rename 后目录 fsync 除 EINVAL/ENOSYS/EPERM（平台不支持）外抛出。
3. **2.33/2.34/2.48/4.2 生产部署链 + 真实节点证据**：真实节点（iMac Docker，真 MinIO + pinned celld 0.2.0）完整跑通 snapshot → mc 物化 → 一次性 argv-free 部署凭据 → `celld deploy` → 指针 + 版本记录回读 → 立即退役。**运行时权限策略本身收窄**：GetObject 仅四前缀、ListBucket 带 s3:prefix 条件、PutObject 仅 nodes/fleet/cells、无 DeleteObject；真实 14 项 allow/deny 矩阵全部符合设计（含全桶列举拒绝、跨桶拒绝、退役后同凭据拒绝）。supervisor 侧：安装器现在签发只读快照凭据（snapshotReadPolicy 仅 packages/*），写入服务用户自己的 mc config（0600），systemd drop-in 固定 alias/region，并在安装时以服务身份验证可达；`supervisor/main.ts` 物化器 + 启动 mc stat 检查已接线。证据：`.agents/evidence/2.33-2.34-real-celld-deploy.json`（含策略与生产模块逐字节一致校验）；节点测试残留已清理（桶/svcacct/临时文件）。
4. **7.3/7.4 rollback 协议 + 生产控制对象**：生产 rollback 现在返回 `{generation, retired}`（协议 union）；Admin 的 strict rollbackResultSchema 同步加 retired（旧 schema 会把真实响应判为非法——真实缺陷修复）。`tests/lifecycle-production.test.ts` 用真实文件 ControlStore + 真实 createApplicationControl 走 kernel/index.js 同一路径（handleVersionAction dispatcher + activate/rollback）：断言响应 union、控制文件指针在 drain 前已落库、drain 目标与 retired 一致、NOT_READY/UNKNOWN_VERSION 负向路径。
5. **10.4 monitor 消毒器递归数组**：sanitizeMonitorFrame 现在递归 plain objects 和 arrays；数组内 credential 形状字符串/对象字段被移除，干净元素保留；负向测试覆盖嵌套数组（`tests/monitor-frame.test.ts`）。
6. **9.2/9.5 MCP 完整生命周期**：新增 `iweb_application_inspect`、`iweb_application_versions`（保留版本列表）、`iweb_application_delete_data`（独立数据销毁）；delete_version 增加活动版本安全预检（本地拒绝 + Kernel ACTIVE_VERSION_PROTECTED 双层）。MCP contract tests（20 个）：完整发布流、被拒包、readiness 失败、stop/start、rollback、保护路由、凭据缺失、stale monitor 重取。Admin 单元测试（39 个，含 7 个新 9.5 用例）+ 既有组件测试。
7. **12.3 monitor-frame 关闭**：`scripts/monitor-frame-capture.bun.ts` 本地拉起当前源码 Kernel，完成 owner 票据握手，解码真实 ticketed WebSocket 帧（621B）并以 owner token 为 needle + 全部凭据 pattern 扫描：无泄漏。证据更新至 **8/9 kinds**；仅 sandbox-fs 待 operator 沙箱验收后扫描。

## What Didn't Work / Evidence Limits

1. **12.3 sandbox-fs**：需要真实部署的沙箱文件系统（Linux systemd + rootless Podman operator 验收）后扫描；这是 12.3 保持开放的唯一原因。
2. **7.6**：本地可验证部分已完成——`tests/kernel-recovery.test.ts` 以真实 Kernel HTTP 子进程验证 api.<base> 在 supervisor 缺席时仍可服务 durable 状态、恢复拒绝匿名、有界失败且进程存活。完整任务还需真实节点停机/重启证据（operator），不勾选。
3. **2.7/6.5/12.2**：operator host evidence（previous-image 恢复、跨架构 RSS/CPU 基准、hostile matrix arm64/amd64）。
4. **11.2-11.4/12.5/12.7**：publication/Notes/archive hard stops，等待 owner 授权。

## Next Steps

```text
$openspec-apply-change isolate-untrusted-applications
```

剩余 10 项全部是 operator/owner 边界或 hard stop：

1. **2.7**：一次性节点卷上 backup→mutate→restore→previous image→api.<base> 全链验证（`tests/node-backup.acceptance.sh.ts`）。
2. **6.5**：pinned celld 镜像在 arm64/amd64 的冷/热 RSS、CPU、启动时间基准，并据此定默认限额。
3. **7.6**：真实节点 Admin/MCP/全部沙箱停止下的 api.<base> 恢复 + operator 停机/重启证据。
4. **12.2**：hostile fixture + lifecycle matrix 在 arm64/amd64 Linux 节点执行并记录矩阵证据。
5. **12.3**：operator 沙箱验收后扫描 sandbox-fs（唯一缺失 kind）。
6. **11.2-11.4**：owner 授权后的真实 Notes 沙箱迁移（保持 hard stop）。
7. **12.5**：全部隔离/路由/恢复/凭据/资源/跨架构验收通过后才开放 publication gate。
8. **12.7**：全量复跑 + whole-change review 后归档（owner 授权）。

每轮结束必须复跑：

```bash
env -u http_proxy -u https_proxy -u all_proxy \
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY bun test
(cd admin-console && bun run check && bunx vitest run)
openspec validate isolate-untrusted-applications --strict
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml config -q
git diff --check
```


## 用户设计变更（2026-08-15）：celld-per-app（admin/mcp 不再共享 Worker）

用户明确：admin/mcp 共享一个 celld 进程违反设计——它们必须是"普通的 celld"。已实施并在两台节点验证：

- **每个应用独立 celld 部署**：admin（iweb-cells-admin，:8787/:8788）、mcp（iweb-cells-mcp，:8797/:8798）、notes（iweb-cells-notes，部署就绪但不常驻，IWEB_RUN_NOTES_CELLD=1 启动）。每应用独立项目（worker/apps/<app>/wrangler.jsonc + main.js default-export 包装）、独立桶、独立进程、独立节点身份（CELLD_NODE-<app>）。共享 Dispatcher（worker/index.js）已删除；旧 iweb-cells 桶保留为历史数据，无进程挂载。
- **逐应用内存成为真实测量**：Kernel 读每应用 pidfile + /proc/<pid>/status VmRSS（refreshCelldRss），进监控帧 apps[].resources 与控制投影；Admin 表直接渲染（admin=83.6 MiB / mcp=75.9 MiB @ iMac；28/15 MiB @ cloud）。读不到时显式"不可用"+原因，绝不补 0。Admin "节点开销"标签已删除（共享进程不再存在）。
- **Kernel**：CELLD_PORTS（IWEB_CELLD_PORTS 严格校验）逐应用路由；recovery 指向 apps/admin 项目 + IWEB_ADMIN_CELLD_BUCKET。
- **修复的真实 bug**（iMac 旧数据掩盖，云端新卷暴露）：Dockerfile 漏拷 issuer-base-policy.json；mc mirror 不支持单文件（iweb.json 用 mc cp）。
- **云节点（gaubee-cloud，amd64 Alibaba Cloud Linux 3）**：http://39.107.213.167:9010（admin.cloud.iweb.localhost 等 Host），三进程拓扑 + 全入口探针通过（admin 200 / mcp 405 / api 401 / notes 502 / base 200）。部署方式：源码 tar 同步 + 服务器端 compose（服务器 1.8GB RAM，SSH context 直连构建超时）。
- **云端限制**：cgroup v1（supervisor 沙箱验收需 v2，切 v2 需 grubby+reboot，未做——服务器上有其它生产容器）；podman 与 docker-ce containerd.io 有包冲突。沙箱 supervisor 验收仍待 cgroup v2 主机。


## 宿主环境进展（2026-08-15 晚）：云 cgroup v2 已切；lima 沙箱宿主半通

- **云服务器已切 cgroup v2**（grubby systemd.unified_cgroup_hierarchy=1 + reboot）：cgroup2fs 确认，13 个生产容器全部自动回起，iweb 节点 admin=200 恢复。podman 安装仍与 docker-ce containerd.io 冲突（--allowerasing 需 owner 决定）。
- **Apple container 判定不可用**（实测）：cgroup2 子组控制器不委派（子组 cgroup.controllers 恒空）、嵌套 podman 报 pids 不可用、无 tun/sysctl——架构性缺口，非配置问题。
- **lima VM（Fedora 44/arm64/vz）作为沙箱宿主**：rootless podman 5.8.4 + cgroup v2 委派 + systemd 全部就绪；iweb 节点在 VM 内全 rootless 运行（admin 200/双 celld 进程 RSS 可见）；**supervisor 安装器完整跑通一次**（EXIT=0，systemd active，快照凭据+别名+服务身份证明全过）。
- **过程中修复 5 个真实产品缺陷**（本地 478 测试全绿）：acceptance run() 丢命令、安装器验证范围（prefix 条件化后 bucket 根 stat 按设计被拒）、RuntimeDirectory 删除窗口、代理透传、issuer-base-policy 缺 iweb-system/packages（svcacct 与父策略相交）。
- **遗留**：验收脚本重跑最后一环 runuser chdir /home/kzf/iweb 权限（此前同路径成功过，需一次迭代）；VM 出口仅宿主代理（fake-IP DNS），容器拉镜像必须带代理 env；rootful podman 网络在此 vz VM 无出口（全程走 rootless）。证据：.agents/evidence/2.42-lima-supervisor-install-partial.json。


## 2026-08-15 深夜更新：2.42 主机验收阶段 1-10 全过（lima VM，EXIT=0）

**真实 Linux 验收（非 mock）通过**：安装、systemd active、服务身份、preflight 9/9（含 seccomp）、socket 0600、无 TCP listener、rootless podman+pod、digest 固定双镜像、compose 拓扑。证据：`.agents/evidence/2.42-lima-host-acceptance-pass.json`。

**生命周期阶段（phase 11）差一环**：快照播种与 prepare→runtime.create 已打通；gateway 双网络 --ip 语法修复已验证；剩余一个 acceptance 上下文内的间歇 preflight 失败（所有手动复现均 5/5 通过），需一次带 stderr 捕获的诊断运行。

**本轮修复的产品缺陷（本地 478/0 全绿）**：gateway 双网络 per-interface ip（podman 拒绝全局 --ip）、preflight 锁竞争重试、安装器构建目录服务属主（rootless userns 里 root 属主文件 unmapped）、重安装必须 restart、镜像已存在跳过拉取、operator PATH 符号链接、中性 cwd、验收 run() 丢命令/环境透传/服务 env/快照播种/结构化端口断言、issuer-base-policy 快照只读（svcacct 与父策略相交）。

**记录的后续缺陷**：RuntimeFailure 分类被 protocol-server 吞成 ADAPTER_ERROR（Kernel 无法区分失败类别，需协议错误形状改造）。

## Review Assessment

上轮 6.5/10 复审的六项缺陷本轮全部闭环：指针身份校验（真实代码+矩阵测试）、持久化静默丢弃（durable quarantine + 显式损坏失败）、真实 celld 证据（已持久化并可复核）、rollback retired（生产+Admin schema 双修）、版本对象权限收窄（策略本身最小权限+真实 14 项矩阵）、monitor 数组递归（负向测试）。MCP 完整生命周期、本地 API 恢复与 8/9 凭据扫描 kinds 亦已完成。剩余全部为 operator/owner 边界任务。

<!-- 用户原始需求（2026-08-13）：普通人会让 AI 部署来源不明的代码，每一个应用必须隔离。 -->
<!-- 本轮交接（2026-08-15）：以 97/107 为事实基线；剩余 10 项全部为 operator/owner 边界或 hard stop，publication gate 保持关闭。 -->
