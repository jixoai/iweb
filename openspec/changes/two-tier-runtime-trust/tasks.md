## 1. Kernel：删除 celld 准入路径（破坏性）

- [x] 1.1 删除 JS reference kernel 遗留：`kernel/index.js`、`kernel/application-control.js`、`kernel/application-publication-gate.js` 及仅引用它们的测试（`tests/application-publication-gate.test.ts` 等）；保留 `kernel/routes.seed.json`（entrypoint 仍引用）。全仓 grep 证明无残留 import。
- [x] 1.2 Rust http.rs：删除 `/v1/applications` 与 `/v1/applications/{*rest}` 路由及 `applications_gate`（改为对已移除路径返回稳定的终态错误码 `CELLD_ADMISSION_REMOVED`，无路由穿透）；删除 `/v1/status` 的 `applicationPublication` 键与 `/v1/recover/sandboxes` stub；删除 celld applications 投影与 monitor `sandboxes` 数组。
- [x] 1.3 Rust wasm_publication.rs：删除 celld gate 半边（`evaluate_celld_publication_gate_v1`、`celld_v1_record_accepted`、`PublicationGateSetV1.celld`、`select_publication_gate` celld 臂、`CELLD_ACCEPTANCE_FILE`、`ENV_APPLICATION_PUBLICATION_ENABLED`），gate 收敛为 wasm 单臂；status 的 `celldPublicationGate` 投影删除；重写受影响测试（七个 celld 断言 + 双 gate wire 测试改为单 gate 契约）。
- [x] 1.4 Rust control 删除：`control_journal.rs` 整模块、`control.rs`、`IWEB_CONTROL_DB_FILE` 读取与所有调用点；生产卷存量 `control-db.json` 不读不迁（文档注明可删）。
- [x] 1.5 kind-claim bootstrap 改源：`wasm_kind_registry.rs` 从路由注册表派生 celld claims（`target.kind=="celld-app"` 的 appName 合并持久 claims）；删除 `bootstrap_from_celld(_raw)`、`WASM_KIND_BOOTSTRAP_PENDING` 状态、`MigrationRecordV1`、`WASM_CONTROL_MIGRATION_SOURCE` 与 raw-digest 重验证链；admission 409 `APPLICATION_RUNTIME_KIND_CONFLICT` 语义保留并加路由派生 claim 的单测。

## 2. Kernel：看门狗 + CPU 观测

- [x] 2.1 `sampling.rs` 扩展：周期采样每应用 VmRSS（既有）+ `/proc/<pid>/stat` utime+stime 差分 cpuMillis；读取 `/opt/iweb/config/celld-resource-policy.json`（默认 512MiB + 每应用覆盖，损坏 fail-closed 回默认并记事件）；越限对 pidfile 进程 `SIGKILL`，事件入有界环（app、RSS、limit、时间戳）。
- [x] 2.2 投影接线：`/v1/status` 与 monitor 每应用 resources 携带 `limits`（软限值+`enforcement:"watchdog-soft"`）与 cpuMillis；watchdog 事件投影给授权监控；无采样仍 `unavailable`，零值规则不变。
- [x] 2.3 单测：策略解析与 fail-closed、越限 kill 精确命中单进程（伪 pidfile + 可控 /proc fixture）、差分计算、事件有界。

## 3. entrypoint：监督循环

- [x] 3.1 `run_celld` 后插监督：celld 进程退出（非停机清理）按 1s 退避重启该应用（重跑启动+就绪探测单应用超时），`/data/run/celld-<app>.disabled` 标记停用单应用；`cleanup` 与监督不竞争（停机时不重启）。
- [x] 3.2 主等待循环替换 `wait kernel_pid`：轮询 kernel 与各 celld 存活，kernel 死则触发既有 cleanup 退出（容器重启策略接管）。
- [x] 3.3 容器内启动 supervisor+relay：创建 `iweb-sandbox` 用户（镜像层）与 `/run/iweb-sandbox`（0711 目录、0700 属主对齐）；bun 起 supervisor（工作目录/状态目录 `/data/kernel/wasm-supervisor`）与 relay 子进程；supervisor 崩溃按退避重启。

## 4. supervisor：去 Podman + 进容器

- [x] 4.1 删除 celld adapter 族：`adapter.ts`、`runtime.ts`、`desired-state.ts`、`gateway.ts`、`gateway-main.ts`、`snapshot-materialize.ts`、`metrics.ts`、`subordinate-ids.ts`、`readiness.ts`；先把 `sandbox-spec.ts` 中被 wasm 侧 import 的常量/函数迁入 wasm 模块或新共享模块，再删 `sandbox-spec.ts`。
- [x] 4.2 `wasm-spawn.ts`/`wasm-runtime.ts` 去 Podman：spawn 直接以子进程拉起 `iweb-wasmd`（argv@2 生成保留；FD 3/4 经 Node spawn fd 映射直通；无 OCI 参数/seccomp/网络参数）；stop/kill/rm 改为进程信号 + 等待；保留 readiness/metrics/journal 语义。
- [x] 4.3 宿主机器删除：`packaging/iweb-sandbox-supervisor.service`、`packaging/celld-runtime.Dockerfile`、`packaging/gateway-runtime.Dockerfile`、`packaging/seccomp.json`、`scripts/install-sandbox-supervisor.bun.ts`、`docker-compose.sandbox.yml`；`preflight.ts` 改容器内检查（socket 目录/用户/relay 二进制/RustFS 可达），删除 podman/subuid/cgroup 宿主探测。
- [x] 4.4 supervisor 测试更新：spawn/stop 契约改为进程口径；celld envelope 互斥分支保留（负向量）；删除 celld adapter 相关测试。

## 5. Dockerfile：镜像内 supervisor + relay

- [x] 5.1 新增 relay 构建产物进镜像（复用 kernel cargo cache mount 阶段构建 `snapshot-fd-relay`，COPY 到固定路径）；`iweb-sandbox` 用户/组在镜像创建；supervisor 源码与依赖进镜像（bun install 层缓存）。
- [x] 5.2 supervisor 状态/投影路径容器内化核对：`/data/kernel/wasm`（kernel 侧）、`/data/kernel/wasm-supervisor`（supervisor 侧）持久卷语义；mc alias 对容器内 RustFS 回环。

## 6. Admin UI

- [x] 6.1 删除 celld 版本生命周期：`route-manager.svelte` 的生命周期按钮/对话框/admit 流与 `api.ts` 8 个方法、`contracts.ts` 4 个结果 schema 及 import、`api.test.ts` 对应测试段；`applicationPublication`/`sandboxes` schema 键删除并同步 fixture。
- [x] 6.2 资源表加「软上限/看门狗」列：wire 契约（limits.enforcement/softLimitBytes、watchdog 事件）、`application-resource-table` 行模型与文案（「软上限（采样 15s）」）、两个测试文件断言。
- [x] 6.3 概览/详情口径文案：celld=进程驻留内存（VmRSS 口径注明）、wasm=引擎硬限；`sandboxSupervisor` 展示因 supervisor 进容器而真实可用（连通性/版本）。

## 7. MCP

- [x] 7.1 工具面收窄 wasm-only：发布/生命周期工具对 celld 目标返回有界引导（不可信→wasm 组件、可信→镜像）；工具描述加入两层引导文案；契约测试同步。

## 8. 文档与门禁

- [x] 8.1 `AGENTS.md` 重写旧模型段落（勘查清单 L8-9/L58-67/L83-109/L165-176/L215-231/L242-249）；README/README-zh 同步（What's inside、supervisor 段、Security boundary、Current limitations）。
- [x] 8.2 全测门禁：cargo 全绿 + bun 全绿 + `openspec validate`；远端重建部署，全链路探针（admin/api/app hosts/wasm status/supervisor 健康/看门狗事件路径）。
- [ ] 8.3 Codex 复核（gpt-5.6-terra xhigh）：按结论迭代至无阻塞项，评分与依据入档。

## 9. R2 修复轮（Codex 复核 2026-08-30 阻塞项，全部完成后才可勾 8.2/8.3）

- [x] 9.1 Dockerfile.amd64 迁移新拓扑（supervisor 编译/relay/用户/策略对齐 arm64）
- [x] 9.2 relay 直执行 wasmd：去 shell launcher 与 --podman/generic execv 语义（Rust relay + supervisor spawn 协同改）
- [x] 9.3 凭据最小化：supervisor/relay/wasmd 环境改 allowlist 注入；celld 进程环境显式化（不得继承 owner/RustFS/S3 变量）
- [x] 9.4 看门狗覆盖 wasmd（pidfile 目录 + 策略）并移除 notes 跳过硬编码
- [x] 9.5 wasm-data 根统一（wasmd 数据根经 env 对齐 supervisor 生成路径；entrypoint chown 失败不得吞）
- [x] 9.6 Admin route schema 接受用户 sandbox kind + Admin 并入 /v1/wasm/status 应用投影
- [x] 9.7 wasm 发布门收敛为单 gate（删 service_gate 代际选择与 servicePublicationGate 投影；reasons 对齐 delta 集合）
- [x] 9.8 supervisor 崩溃清理 relay/wasmd 孤儿 + relay readiness 验进程/inode 而非仅 socket 存在
- [x] 9.9 路由供给法收敛：seed 去 notes.app 用户 celld-app 路由；load 时过滤用户 celld-app 路由并记录；POST /v1/routes 对 sandbox target 要求已准入 wasm 应用
- [x] 9.10 备份/验收脚本去除对已删 docker-compose.sandbox.yml 的引用
- [x] 9.11 看门狗与 wasm stop 的 PID 复用防护（starttime 绑定）；entrypoint 重启改递增封顶 backoff
- [x] 9.12 运行时路由注册表损坏不得静默空投影（fail-closed 与启动一致）
- [x] 9.13 非阻塞项：wasmd-acceptance-record 脚本容器化口径、iweb-native-assets 断言更新

## 10. R3 修复轮（Codex 二轮阻塞项）

- [x] 10.1 首启孤儿清理先于 supervisor 启动（杀竞态窗口）；supervisor 退避账目不再被启动清零
- [x] 10.2 relay 非预期退出 → supervisor fail-fast（exit 75），由入口按退避清理重启
- [x] 10.3 wasm stop/remove/isRunning 的 PID 复用栅栏（spawn 记录 /proc starttime，信号前复核；无 /proc 开发平台退回 isAlive）
- [x] 10.4 wasmd 数据根必填（IWEB_WASM_DATA_ROOT 无回退）；HOST_SERVICES_DATA_ROOT 常量改指 /data/wasm-data
- [x] 10.5 备份验收断言去 applicationPublication（改 wasmPublication + 旧键不存在断言）
- [x] 10.6 验收手册/amd64 注释去除 systemd/双开关/podman 旧语义
- [ ] 10.7 主 spec 同步（archive 时由 openspec archive 执行 delta 合入——流程内闭合，非独立任务）
