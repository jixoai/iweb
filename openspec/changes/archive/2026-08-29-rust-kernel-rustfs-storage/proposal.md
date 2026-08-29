<!-- 用户原始需求（2026-08-15）：长期主义成本结构——1000 个客户时节点资源封套决定成本；AI 时代若不站在正确路径上，竞品可一天复刻更低成本的 Rust 实现。 -->
<!-- 用户决定（2026-08-15）：Kernel 必须用 Rust 重写；MinIO 替换为 RustFS（接受其未完全稳定，核心 S3 协议可用）；直接废除 Caddy（破坏性更新）；JS Kernel 冻结，剩余 kernel 侧工作直接在 Rust 上实现。 -->

## Why

iweb 单节点内存封套实测 232–379MB：MinIO 闲时地板 129–306MB（受控 A/B 实测，MINIO_BROWSER=off 无效）、node 运行时镜像层 ~200MB、Caddy 14–48MB。按 1000 客户的成本结构与"正确路径"的长期判断，控制面必须是单个静态 Rust 二进制，对象存储换成 Rust 实现，入口进程合并。MinIO 每次重启存在 ~300MB 启动峰值，在小内存宿主上与业务容器直接竞争内存。

## What Changes

- **BREAKING**：Kernel 以 Rust 重写为单一静态二进制 `iweb-kernel`，直接拥有唯一发布端口的入口路由；Caddy 进程、Caddyfile 与 caddy 二进制从节点镜像删除。
- **BREAKING**：`X-Iweb-Internal-Control` 头路由技巧废除；celld→Kernel 控制调用改走回环控制监听器，不再穿越发布入口。
- 对象存储引擎由 MinIO 替换为 RustFS（钉版本），须通过 G1–G6 验收门；任一门失败即 fail-closed 并按分离回退执行（存储留 MinIO 不阻塞 Kernel 重写）。
- 节点资源封套成为规范要求：闲时 ≤160MB（owner 裁决 2026-08-20；含存储引擎 buffer profile 钉死，稳态实测依据见 .agents/evidence/memory-budget-amendment.md）、闲时近零 CPU，按进程真实 RSS 计量，缺测值不得以零冒充。
- Kernel 行为由跨实现共享的 golden contract vectors 钉死（含 canonical 摘要逐字节一致）；JS Kernel 冻结为参考实现与回滚路径。
- `isolate-untrusted-applications` 保持 open 但冻结：其剩余 kernel 侧工作（Notes 真实迁移、sandbox-fs 扫描、基准重测）在本 change 的 Rust Kernel 上完成后解锁归档。

## Capabilities

### Modified Capabilities

- `node-boundary`：入口所有权从 Caddy 移交 Kernel；存储引擎 MinIO→RustFS；新增资源封套预算与回环控制调用边界。
- `workspace-and-routes`：统一工作区的存储后端措辞由 MinIO 改为 RustFS 对象存储。
- `kernel-control-plane`：新增控制面自包含静态二进制契约与跨实现契约向量要求。
