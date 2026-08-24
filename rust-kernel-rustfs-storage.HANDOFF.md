# rust-kernel-rustfs-storage - Handoff

> 交接时间：2026-08-16（goal 第 29 轮，blocked 于 owner 决策）
> 接手会话：2026-08-20（ZCode）——四项 owner 裁决全部执行；Codex 六轮复核闭环（3.5→5.0→6.0→7.0→7.5→**8.5/10 技术与安全收口通过**）；整改清单 tasks.md 第 10/11 节；**唯一剩余停止条件 = 11.7 预算 owner 裁决**（lima 159 / cloud 162.3 / iMac 231.3MB vs 160MB spec，选项见 memory-budget-amendment.md）。commit/归档/release 仍待 owner 放行。
> 交接原因：owner 决定由其他 Agent 完成后续开发。本文件自包含：新 Agent 从这里 + OWNER-DECISIONS.md 即可接手，无需读旧对话。

## Goal

Kernel 以 Rust 重写为单一静态二进制 `iweb-kernel`，直接拥有唯一发布端口 :8080（**废除 Caddy**，破坏性更新）；MinIO 替换为 RustFS（G1–G6 验收门全过）；节点闲时内存封套入规范；两台真机（iMac + cloud）部署验证且回滚可用；旧 change `isolate-untrusted-applications` 冻结、其 kernel 侧遗留工作在本 change §9 完成后解锁归档。

Owner 原话决策（不可协商）：Rust 重写（"竞品一天就能克隆一个更便宜的 Rust 版"）、选 RustFS 尽管 beta（"核心的 S3 协议基本稳定可用"）、大胆废 Caddy（"直接废除"）。

## Current Progress

- Change: `rust-kernel-rustfs-storage`；任务 **37/37 勾选**（2026-08-20：7.2-amd64、8.3-cloud、9.4-归档全部完成）
- 电池（每轮全绿）：bun **487/0**；cargo **43 tests + clippy 0 警告**；黑盒恢复套件对 **JS 与 Rust 双实现同绿**（`tests/kernel-recovery.test.ts`，`KERNEL_TEST_COMMAND` 参数化，22+22 断言）；`openspec validate --all --strict` 10/10（含已归档 specs 合入后）；`git diff --check` clean
- 跨语言字节级 golden ×3：versionDigest（`099ee657…`）、notesDigest（`e15b59da…` 含 CJK）、credential-scan sanitized location（`log:e9e4927eb6a9`）
- 部署现状（2026-08-20 后）：
  - **iMac 生产节点**：`iweb-local`（gaubee/iweb:rust-kernel 新镜像含 profile 钉死，:9010→8080，卷 iweb_iweb-data，矩阵全绿）；部署 env 固化 `.env.deploy-imac`（600）；`iweb-local-rollback-js` 保留（stopped）
  - **cloud 节点**（gaubee-cloud，amd64 VPS）：`iweb-local` 运行同镜像（新卷 iweb_iweb-data-rust，9010）；原 JS 验证节点改名 `iweb-local-rollback-js` 保留（stopped）；矩阵全绿 + 回滚演练 A→B→A 完成；部署 env `.env.deploy-cloud`（600）
  - **lima 验证节点**（iMac 上 `limactl shell default` 内 podman）：`iweb-local` 运行中
  - amd64 镜像在 cloud 原生构建（406MB；Dockerfile.amd64 新增构建knob：`CARGO_BUILD_JOBS` 默认 2、`CRATES_MIRROR=rsproxy` 供国内构建器）

## 架构现状（全部实测）

```
HTTP → iweb-kernel :8080（唯一发布端口，Rust，4.4MB RSS）
  ├─ api.<base>        → 同一 control Router（与回环 :7070 同鉴权，无头部戏法）
  ├─ admin.<base>      → per-app celld :8787（reqwest 代理，头部契约逐项平价 JS）
  ├─ mcp.<base>/mcp    → per-app celld :8797
  ├─ <app>.app.<base>  → IWEB_CELLD_PORTS 映射
  └─ <base>/<app>/app  → 路径别名（app_base 重写）
RustFS :9000（回环，console 不发布）｜celld peer :8788/:8798（回环，Kernel 不路由）
```

kernel-rs 模块（`kernel-rs/iweb-kernel/src/`）：digest（共享向量）、config/auth（ConstantTimeEq）、control+control_journal（admit/activate/rollback 纯函数 + 原子持久化）、routes（host/别名解析 + CRUD）、proxy（celld 反代，帧头去重、x-iweb-via 防环、no_proxy）、workspace（mc 子进程 + spawn_blocking）、monitor（票据/WS 帧）、sampling（pidfile RSS + cgroup）、supervisor（UDS 手写 HTTP/1.1）、package_store（svcacct 凭据）、notes_migration、credential_scan。

## Pending Owner Decisions（⚠️ 新 Agent 第一件事：向 owner 索要这三项裁决）

材料：`.agents/evidence/OWNER-DECISIONS.md`（含最新数据）。连续 9 轮（20–28）未获答复后 goal 已标记 blocked。

1. **§8.3 cloud 部署**（连带 7.2-amd64 构建 + 9.3-amd64 基准）：本地 amd64 不可行（qemu rustc SIGSEGV，已归因 dual-arch-build.md）；方案 = cloud 节点（`ssh gaubee-cloud`，x86_64 + docker 现成）原生构建 Dockerfile.amd64（digest 已验证入库）→ 部署 → 探针矩阵 → amd64 基准。或 owner 选延期 → 按包内选项 b 记录收尾。
2. **§9.4 旧 change 归档**：交叉表（archive-readiness-crosswalk.md）证明无 kernel 侧实现缺口；归档 = spec 同步操作，必须 owner 明确授权。
3. **内存预算处置**：稳态实测 159–224MB > 150MB 规格线（celld 租约周期写驱动 RustFS beta 匿名内存增长；A/B 证明 `RUSTFS_BUFFER_PROFILE=WebWorkload/IndustrialIoT` 可平坦至 ~137–140MB）。三选项：改 160MB+钉 profile / 等 RustFS 上游 / 拓扑调整。**spec 预算文字未擅动**（法律文本）。

## Hard Stops（owner 专属，绝不越权）

publication-gate 开启 · acceptance-record 创建 · spec sync/archive · commit · release · 任何 cloud 变更。发布闸门现状：`/v1/applications` → 503（与 JS 同）。

## 必背命令与环境陷阱

```bash
# bun 电池（本机代理会毒化，必须剥）
env -u http_proxy -u https_proxy -u all_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY bun test
# cargo
cd kernel-rs && cargo clippy --all-targets && cargo test
# 黑盒双实现
KERNEL_TEST_COMMAND=$PWD/kernel-rs/target/debug/iweb-kernel bun test tests/kernel-recovery.test.ts
KERNEL_TEST_COMMAND="node $PWD/kernel/index.js"     bun test tests/kernel-recovery.test.ts
# change 校验
openspec validate rust-kernel-rustfs-storage --type change --strict
```

陷阱（每条都花过时间，详见各 evidence 文件）：
- 本机 `proxy-vie` 蹲 127.0.0.1:18080/18090，curl 一律 `--noproxy '*'`，测试端口用 5xxxx/38xxx
- **reqwest Client 必须在使用它的 runtime 内构造**（跨 runtime send() 永久死锁且超时不触发）
- podman 默认注入宿主代理 env（--http-proxy）毒化容器内回环 S3；entrypoint 已统一 unset，运行时加 `--http-proxy=false`
- 镜像 digest 必须按**目标架构 manifest** 钉（`docker manifest inspect` 首条目是 amd64！arm64: rust 93717e49 / rustfs 186743df；见 Dockerfile vs Dockerfile.amd64）
- **podman save → docker load 标签陷阱（2026-08-20 实证）**：load 产物是 `localhost/gaubee/iweb:rust-kernel`，docker 非限定名 `gaubee/iweb:rust-kernel` 是另一个独立标签，不 retag 会一直跑旧镜像；每次 load 后必须 retag 并用镜像内文件内容（如 entrypoint 行号）验证
- rust-toolchain 钉 1.88（rustup 侧有 linux 交叉 std；1.90 仅 Homebrew）
- 容器内 IWEB_HTTP_PORT 恒 8080（宿主端口由 Docker 映射；env 带入会绑错端口——entrypoint 已钉死）
- iMac 上部署脚本经 ssh 引号地狱：一律 base64 打包脚本再执行（本会话成熟模式）
- JS kernel 启动依赖 mc 子进程（本机无 mc）；测试里用 no-op shim（recovery 套件内有现成写法）
- **工具会话 cwd 漂移事故（2026-08-20 两次实证）**：持久 shell 的 cwd 会停在上一条 `cd kernel-rs`——rsync/tar 的 `./` 源路径必须配显式 `cd /abs/repo &&` 或绝对路径。曾因此把 iMac 仓库副本 `--delete` 成 kernel-rs 内容（.env* 因排除保护幸存），并在 cloud 根散落 kernel-rs 文件；两者均已全量重传恢复。podman build 的 `-f Dockerfile` 相对路径同理用绝对路径。

## 证据索引（.agents/evidence/）

rustfs-g1-g6.json（六门）｜rustfs-node-live.md（内存预算+存储切换）｜rust-kernel-image-live.md（镜像全矩阵）｜imac-deploy-rollback.md（部署+回滚演练）｜node-probe-matrix.md（7 探针+monitor 链）｜celld-benchmark-arm64.md（基准）｜dual-arch-build.md（amd64 受阻归因）｜memory-envelope-steady-state.md + rustfs-buffer-profile-ab.md（稳态发现+A/B）｜control-journal-parity.md（跨语言 golden）｜credential-issuance-live.md / credential-scan-live-run.md｜supervisor-client-live.md｜section9-modules-parity.md｜archive-readiness-crosswalk.md｜blocking-io-fix.md｜monitor-capture-parameterized.md｜OWNER-DECISIONS.md（**先读这个**）

## 下一步（按序）

1. 向 owner 索要三项裁决（措辞模板在 OWNER-DECISIONS.md 尾部）
2. 按裁决执行：cloud 全链（构建→部署→矩阵→amd64 基准→7.2/9.3 勾选）或延期收尾；归档操作（若授权）；预算 spec 修订（若授权）
3. 收尾整 change：全量复审（AGENTS.md 的 next-review 约定）→ owner 放行后 commit/archive
4. 未接线的已备能力（随发布闸门开启一起做）：admit/activate HTTP 端点（control_journal 已就绪）、Notes 真源迁移执行（notes_migration 已就绪）、九类扫描补全 package/sandbox-fs/object-store/image-layer（引擎已就绪）
