# two-tier-runtime-trust Codex 复核轨迹（gpt-5.6-terra / xhigh，Herdr 闭环）

> 会话：zcode-iweb-two-tier-runtime-trust / codex-two-tier-review。只读复核基于当时
> 真实工作区 diff、测试结果与远端部署证据。最终 HEAD 见文末。

| 轮 | HEAD | 综合 | 结论 | 决定性事件 |
|---|---|---:|---|---|
| R1 | （拆批后） | 3.6 | 12 阻塞 | 首轮架构对齐：socket 权威、gate、claims 逐项开列 |
| R2 | decb8e0 | 5.8 | 9/12 闭合，新 6 阻塞 | 生命周期 4 + 归档/验收 2 |
| R3 | d8f6dee | 6.5 | — | 首启竞态/退避清零/relay fail-fast/PID 栅栏修复 |
| R4 | c02fb34 | 6.7 | 1 P1 | 回收仅“表层流程”，无可验证成功条件 |
| R5 | 0c884e3 | 5.5 | 2 P1（回归） | 元组分词破坏 pid:starttime；cleanup 悬空引用 |
| R6 | 3b634ff | 6.9 | 1 P1 | 两 R5 P1 闭合；Linux 实机崩溃验收归类已关闭；新发现 TERM 阶段无栅栏 |
| R7 | 70235e0(+微修) | **7.5** | **零阻塞** | TERM/KILL/等待三阶段全栅栏；token 完整性 fail-closed；9 dash 场景 |

## R7 终审三轴（原文要点）

- **archive：GO（条件）**——无实现阻塞；归档流程内同步 delta 到主 spec（即 10.7）。
- **release：GO**——范围限定为 wasm publication 保持关闭的节点镜像。
- **publication：按产品法维持关闭**——owner acceptance record、真实 wasm 执行链与
  网关条件未满足前，开启判定为 NO-GO（法律状态，非缺陷）。

R7 非阻塞项处理：malformed 状态入口复位与 stop_sandbox_processes 二次 command -v
防御已落（本提交）；pidfd 消除 TOCTOU 微窗口、世代档案字段命名留作后续演进。

## 实机验收（R6/R7，gaubee-cloud x86_64 节点）

- amd64 镜像 Dockerfile.amd64 真实构建（CRATES_MIRROR=rsproxy、CARGO_BUILD_JOBS=1、
  at 队列脱离会话），替换运行 7 天的 R2 时代容器；同卷同端口同 env。
- 稳态探针：supervisor `/v1/health` ready；路由派生舰队 6 应用 live 采样
  （watchdog-soft 512MiB）；`/v1/applications` 410；wasm status claims=6
  source=route-registry；publicationGate fail-closed；watchdog 投影 intervalMs 15000；
  世代台账原子写入；supervisor/relay `/proc/<pid>/environ` 凭据计数 0（allowlist 11 变量）；
  admin 资产重发布 200（21557B）；Kernel /health 200。
- **SIGKILL 崩溃重启验收**（R6 首过、R7 复验，三 pid 口径）：kill -9 supervisor 后
  ~8s 内旧 relay 被按 pid+starttime 栅栏回收，launcher/supervisor/relay 三者换代，
  台账原子更新，新世代 health ready，kernel/admin 全程 200。socket inode 数值不作为
  不变量（tmpfs 复用）；不变量 = 旧监听者死亡 + 新绑定成功 + health 应答。
  幸存者拒绝启动路径由 dash 行为测试（rc=1、socket 保留、stderr 点名）覆盖。

## 开放项（环境依赖，非阻塞）

真实 wasm 执行链验收（需 owner-sealed acceptance record）、MCP activation 级工具、
egress gateway 监听者（publication 关闭期 fail-closed 正确）、pidfd 化。
