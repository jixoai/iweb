# rust-kernel-rustfs-storage Tasks

## 1. 治理与冻结
- [x] 1.1 在 isolate-untrusted-applications/tasks.md 顶部标注冻结与移植去向
- [x] 1.2 openspec validate --strict 通过本 change

## 2. RustFS 验证 spike（G1–G6，可与 3/4 并行）
- [x] 2.1 G1 单节点运行（lima VM，1.0.0-beta.12 钉版；证据 .agents/evidence/rustfs-g1-g6.json）
- [x] 2.2 G2 celld deploy/watch 全链：部署格式写入、运行时加载服务（405/401 与 MinIO 平价）、node lease 写入 nodes/
- [x] 2.3 G3 mc + IAM：prefix 条件策略真执法（5/5 允许/拒绝矩阵），svcacct MinIO 兼容——零重构迁移定案
- [x] 2.4 G4 一次性卷备份/恢复：销毁→恢复循环数据逐字节完好
- [x] 2.5 G5 基准（同节点对照）：RssAnon 真实地板 70.6MB vs MinIO 121.2MB（−42%）；RssFile≈58MB 可回收不计预算；节点 RssAnon 投影 ≈150MB 达标
- [x] 2.6 G6 双架构：amd64/linux + arm64/linux 官方 manifest 确认
- [x] 2.7 六门全过（.agents/evidence/rustfs-g1-g6.json）：RustFS 1.0.0-beta.12 放行存储替换，无需分离回退

## 3. kernel-rs 骨架与契约向量
- [x] 3.1 kernel-rs cargo workspace（rust-toolchain.toml 钉 1.90.0；clippy -D all 零警告；cargo test 绿；--version 契约实现；cargo-deny 留待 CI 接入）
- [x] 3.2 摘要 golden vectors：contracts/fixtures/digest-vectors.json（6 向量含三类排序分歧对）由 TS 权威生成，bun 8 测试 + cargo 3 测试双侧绿；前置修复：TS 摘要排序从 localeCompare 硬化为 UTF-8 字节序（contracts/package-collection.ts）
- [x] 3.3 黑盒协议套件参数化：KERNEL_TEST_COMMAND 驱动任一实现；Rust 二进制已全量通过 kernel-recovery（401 墙/持久状态投影/闸门 503/有界恢复/失败后存活，11 断言）

## 4. 模块移植（对位 kernel/*.js）
- [x] 4.1 控制端点全数完成：status、routes CRUD（201/400/409/204/404）、workspace list/read/**PUT/DELETE**（写面 201/超限 400/删除 204/越界路径 400 实测；≤1MiB + 临时文件原子写对位 JS）、monitor WS（4.2）；key 端点形式化并归 §4.4 凭据签发
- [x] 4.2 WS monitor：票据（24B base64url/30s/一次性，复用实测 400）、101 升级、首帧 JSON 快照（unavailable 语义保留）、帧编码/握手 6 单测含 RFC6455 官方向量；ping-pong 由 axum ws（tungstenite）库层应答
- [x] 4.3 控制日志状态机完成：admit/mark-ready/activate/rollback 纯函数（错误码与 7.3 回滚 ready 门逐字对位）、versionDigest 跨语言字节一致（bun 与 cargo 同输入同输出 099ee657…）、原子持久化（tmp+rename）；端点接线随发布闸门开启决策（owner 硬停点）——.agents/evidence/control-journal-parity.md
- [x] 4.4 凭据签发原语完成：package_store.rs 策略文档（version 只读 + app-data rw）逐字对位 JS；svcacct 签发 argv-free（0600 临时策略文件即删）；真机 RustFS 节点实测矩阵 签发→前缀内 ALLOW→越桶 DENY→写 DENY→回收 全链（.agents/evidence/credential-issuance-live.md）；canonical 快照物化与 admit/activate 接线随 §4.3 控制日志一并落地
- [x] 4.5 supervisor 客户端完成：UDS 上手写最小 HTTP/1.1（零新依赖）、16KiB/500ms 上限、service/version/ready 三重严格校验；真 socket 实测三态语义（健康 available:true / 坏 socket configured+unavailable / 未配置 configured:false）进 /v1/status——.agents/evidence/supervisor-client-live.md；supervisor-rpc 其余方法随沙箱迁移（§9）按需补
- [x] 4.6 celld 反向代理 + 采样闭环：代理头部平价（kernel-rs-ingress.txt）；/proc RSS 采样在 lima 真机验证（rustfs 进程 92.8MB 实测进入 /v1/status 投影，unavailable 语义保持，kernel-rs-linux-sampling.md）；剩余：Kernel 侧 celld 进程拉起（entrypoint 交接随 §5.2/§7 镜像改造落定）

## 5. 入口合并（废 Caddy）
- [x] 5.1 kernel-rs 双监听器：:8080 入口 host 路由（api 直达/已知应用 502 待代理/未知 404/_iweb/health 200）+ 回环控制面；探针矩阵见 .agents/evidence/kernel-rs-ingress.txt（下一轮接 celld 代理后 502→200）
- [x] 5.2 entrypoint：caddy 进程/等待/Caddyfile 拷贝全删（bash -n 过）；Kernel 直接 exec iweb-kernel 拥有 :8080，容器主进程=Kernel（wait kernel_pid）；CONTROL_ORIGIN 默认回环 http://127.0.0.1:7070，不再强制穿越发布入口
- [x] 5.3 头部路由戏法不存在于 Rust Kernel（api.<base> host 判定即控制入口）；断言侧无 Internal-Control 测试需要删除——恢复套件黑盒通过即为平价证明（KERNEL_TEST_COMMAND=rust 11/11）

## 6. 存储切换
- [x] 6.1 entrypoint MinIO→RustFS：rustfs server 回环 9000（console 关闭省 7MB 进预算），镜像钉 arm64 manifest digest；数据目录名不变（升级不迁移布局，回滚兼容）
- [x] 6.2 桶/策略/凭据路径切换：节点容器首启实测——6 桶创建、workspace 私有、celldkey 用户+iweb-celld 策略 attach、iweb-sandbox-issuer+base 策略 attach，celld 双应用部署运行于 RustFS 之上（.agents/evidence/rustfs-node-live.md）；无需桶分离重构（G3 全兼容）
- [x] 6.3 supervisor 物化别名同步：G3 判定无需桶分离（IAM 全兼容），前提条件不成立——无别名需要同步；若未来分离再立任务

## 7. 镜像与构建
- [x] 7.1 Dockerfile：rust 构建阶段（arm64 manifest 钉版）、去 node/caddy/Caddyfile；镜像 gaubee/iweb:rust-kernel 在 lima 全矩阵实测（health/admin 200 真实 HTML/alias/api 401→200/mcp 405/unknown 404，kernel RSS 4.4MB），见 .agents/evidence/rust-kernel-image-live.md；RustFS 钉版随 §6 存储切换落
- [x] 7.2 arm64 完成（33s warm/5min cold，396MB，已部署 iMac）；amd64 半场 2026-08-20 随 §8.3 在 cloud 原生构建完成（406MB，构建knob：CARGO_BUILD_JOBS/CRATES_MIRROR 见 Dockerfile.amd64）——.agents/evidence/dual-arch-build.md、cloud-deploy-probe-matrix.md

## 8. 验证与部署
- [x] 8.6 文档事实同步：README（原型段落/节点模型图/端口拓扑/CONTROL_ORIGIN 语义/TLS 边界说明）、.env.example（CONTROL_ORIGIN 注释为可选+回环默认、RustFS 凭据注释）、AGENTS.md 节点模型图（Rust 入口/per-app celld/RustFS 监听器）全部与部署现实一致
- [x] 8.1 lima 全探针矩阵 + monitor frame：7 项探针全过（401/200/405/404 语义完整）；monitor 经发布入口全链（票据→101→首帧含真实 cgroup 内存 + per-app celld RSS 43.8MB 实测→单次消费 400）；14 项 allow/deny 属 §2 G3 已覆盖（5/5 强制执行矩阵 + svcacct），证据 .agents/evidence/node-probe-matrix.md
- [x] 8.2 iMac 部署 + 回滚演练：真机就地升级（同名容器/卷/网络/端口），全矩阵绿（admin 200 真实 HTML/api 401→200/alias/mcp 405/unknown 404）；回滚演练完整——旧 JS+Caddy+MinIO 容器原卷原端口复活（admin 200/api 200，15s 就绪），数据持久跨切换，随后前滚恢复 rust 终态；.agents/evidence/imac-deploy-rollback.md
- [x] 8.3 cloud 部署（owner 2026-08-20 批准）：amd64 原生构建→原地升级（JS 验证节点改名保留为回滚，新卷 iweb_iweb-data-rust，9010 发布）→探针矩阵全绿（含 monitor 链）→回滚演练 A→B→A（JS 复活 7s / 回切 7s）→冷启 9s——.agents/evidence/cloud-deploy-probe-matrix.md
- [x] 8.4 内存封套基准证据：**冷启后 ≤2min 内 148.1MB ≤ 150MB 成立**（rustfs 129.3 + celld 19.7 + kernel 0.6 + sh 0.2；console 关闭决策依据在案），cgroup 213.9MB 含可回收缓存非预算口径——.agents/evidence/rustfs-node-live.md；**稳态 caveat（round 23 实测）**：celld 租约周期写驱动 RustFS 匿名内存持续增长（6min 至 ~175MB 未平台，单一 celld 后趋平 174MB），属 RustFS beta 行为，缓解选项（租约节奏/RustFS 调参/预算措辞修订）入 .agents/evidence/memory-envelope-steady-state.md 待 owner 裁决
- [x] 8.5 本地电池绿（bun + cargo 双侧）：bun 486/0；黑盒恢复套件对 JS kernel 与 Rust kernel 双实现同绿（11/11 各）；cargo 40+3 全绿 + clippy 0 警告——KERNEL_TEST_COMMAND 参数化使恢复语义对实现中立于每轮验证

## 9. 继承 isolate-untrusted-applications 的 kernel 侧工作
- [x] 9.0 owner 决策包已备（.agents/evidence/OWNER-DECISIONS.md）：8.3 cloud 部署（含 amd64 构建/基准）与 9.4 归档评估两项硬停点的完整决策材料——批准即执行，延期则按包内选项 b 记录收尾
- [x] 9.1 Notes 迁移机制 Rust 化：notes_migration.rs（digest/export/verify/dry-run/migrate/DO 严格校验）；跨语言 golden——bun 与 cargo 同输入（含 CJK）digest 字节一致 e15b59da…；真源执行（celld DO 读取接线）属沙箱迁移阶段 owner 决策
- [x] 9.2 凭据扫描 Rust 化：credential_scan.rs 九类位置 kind 全量（含 sandbox-fs）、值扫描+五类模式探测（AKIA/私钥/凭据 URL/token 赋值/MC_HOST）、上限截断、确定性排序；sanitized location 跨语言一致 golden log:e9e4927eb6a9；真实九类位置扫描执行随 §8.3/发布开启落
- [x] 9.3 基准重测（arm64 半场）：真实节点进程画像——admin celld 负载后 RssAnon +1.1MB 稳定、kernel 3.4MB 平坦、1000 请求 2471ms（~405 rps）、节点冷启 6–9s、rustfs 空载 129MB/负载后 181MB 区分记录；amd64 半场 2026-08-20 cloud 完成：190 rps（共享 VPS）、celld-admin 负载 +7.7MB、kernel +0.45MB、rustfs 平坦、冷启 9s、闲时 162.3MB/负载后 170.5MB——.agents/evidence/celld-benchmark-arm64.md、celld-benchmark-amd64.md
- [x] 9.4 解锁旧 change 归档评估（owner 硬停点）——owner 2026-08-20 授权现在归档；`openspec archive isolate-untrusted-applications` 完成（specs 合入 +17/~13/-3，validate --all --strict 10/10），rust change 两个 MODIFIED 块补齐归档合并引入的场景后全绿

## 10. Codex R1 复核整改（2026-08-20，gpt-5.6-terra xhigh，首轮评分 3.5/10）

- [x] 10.1 【阻塞1】.env.cloud-node（真实凭据）未忽略：.gitignore 增补 `.env.cloud-node`/`.env.deploy-*`，`git check-ignore` 验证通过、git status 不再出现；凭据轮换属 owner 决策（文件从未进入 git 历史，未发生实际泄露），随放行门呈报
- [x] 10.2 【阻塞2】compose 可令 celld 经公网入口回调 Kernel：docker-compose.cloud.yml `environment:` 钉死 IWEB_CONTROL_ORIGIN=127.0.0.1:7070（覆盖 env_file），entrypoint 对非回环 origin 落警告日志，云端 .env.cloud-node 已删残留行——.agents/evidence/cloud-deploy-probe-matrix.md 更正记录
- [x] 10.3 【阻塞3】proxy.rs 泄露底层连接诊断：公开 502 固定 `{"error":"application unavailable"}`，detail 只进容器日志（eprintln）；JS 参考实现 line 544 同病，随冻结参考保留不在生产镜像（kernel/ 源码 §5.2 已不入镜像）
- [x] 10.4 【阻塞4】用户路由未 fail-closed：action_for 仅 system 记录可直连 per-app celld；http.rs 未知 appName 不再回退 admin 端口（`let ... else unavailable()`）；新增路由门控测试 user_routes_never_reach_the_shared_celld_runtime（对位 routing.test.ts 契约：无 ready sandbox → unavailable）
- [x] 10.5 【阻塞5】预算证据措辞：cloud 162.3MB 是超限（+2.3MB）非"marginally"；160MB 预算与三节点实测的矛盾如实呈报 owner 再裁决（lima 159 / cloud 162.3 / iMac 231.3 settled）——.agents/evidence/memory-budget-amendment.md
- [x] 10.6 【阻塞6】profile"钉死"可被 env 覆盖：entrypoint 改无条件 `export RUSTFS_BUFFER_PROFILE=IndustrialIoT`（复测需改行重建镜像），.env.example 注释同步
- [x] 10.7 【阻塞7】workspace delta 正文丢沙箱隔离 SHALL 句：补回 "application sandboxes MUST NOT receive workspace-wide credentials or direct workspace-wide access"（归档合并后的安全语义不再回退）；归档时机本身为 owner 明示授权（决策材料已列未移植项），维持归档
- [x] 10.8 【非阻塞】探针脚本 token 改 stdin curl config（不进 argv）；bunfig.toml + preload 固定回环 no_proxy（电池对宿主代理免疫，敌意环境 487/0 实证）

## 11. Codex R2 复核整改（2026-08-20，第二轮评分 5.0/10，R1 七项核销五项）

- [x] 11.1 【阻塞2 续】控制面强制回环：entrypoint 对任何非默认 IWEB_CONTROL_ORIGIN（含回环端口变体）fail-closed 拒绝启动且不回显值；本地 .env 与云端 env 残留值已清；.env.example 标注废除
- [x] 11.2 【阻塞2 续】MCP 移除已废除的 X-Iweb-Internal-Control 头（worker/apps/mcp/app/index.js）；控制调用只凭 owner Bearer 打回环控制监听器
- [x] 11.3 【新阻塞】publication gate reason 对齐契约：Rust reasons 改为 ["publication-not-requested","sandbox-acceptance-missing"]（对位 JS application-publication-gate.js 与验收脚本断言）
- [x] 11.4 【新阻塞】验收脚本 rust 时代化：默认镜像改 gaubee/iweb:rust-kernel、docker run 移除 IWEB_CONTROL_ORIGIN=:8080 残留、头注去 Caddy；脚本文件名无 .test. 不入电池，属手动验收
- [x] 11.5 【非阻塞】memory-budget-amendment.md 的"env-overridable"描述标注为被 R1 取代的历史记录
- [x] 11.6 【R2 验收链闭合】`/v1/applications/*` 任意方法/子路径补齐 503 APPLICATION_PUBLICATION_DISABLED gate（对位 JS index.js:746 通配语义；验收脚本曾抓到 Rust 404 缺口）；iweb-native-assets.acceptance.sh.ts 以 IWEB_ACCEPTANCE_IMAGE=gaubee/iweb:rust-kernel 复跑全绿：三入口 200、immutable 缓存、登录 401/200、发布 503、密钥扫描 clean（DOCKER_HOST=ssh 经 iMac docker 执行）
- [x] 11.8 【R3】monitor-frame 采集链去废除头：session 签发改裸 socket + 显式 Host: api.<base> + Bearer（双实现兼容），Rust 链路 2026-08-20T12:09Z 重采全绿（token 不在帧/URL/子协议，扫描清洁）；本地与云端 .env.cloud-node 残留 origin 全清；.env.portless-imac.example 移除 Caddy 时代死配置 IWEB_CONTROL_ORIGIN
- [x] 11.9 【R4】归档合并后的 Caddy 规范残留收敛：managed-applications 与 developer-ingress 两个 capability 补 MODIFIED delta（入口统一为 Kernel ingress），openspec/config.yaml 上下文去 Caddy；README 部署注释、cloud 证据措辞（warns→fail-closed）同步；.env.portless-cloud 残留删除；config/Caddyfile 随"废 Caddy"删除（无引用）
- [x] 11.7 【阻塞5 闭合】owner 二轮裁决（2026-08-20）：不追数字——正确技术（无条件钉 profile）+ 能省尽省后，实测即事实。spec 封套修订为 ≤240MB（覆盖三节点实测），测量协议与不可覆盖钉死保持 MUST，160MB 中间值作废——memory-budget-amendment.md 终裁记录
