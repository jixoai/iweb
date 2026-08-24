# rust-kernel-rustfs-storage 设计

## 用户决定（不可重议）

1. Kernel 用 Rust 重写（长期成本结构 + 竞品一日复刻论）。
2. MinIO → RustFS（接受未完全稳定；核心 S3 协议可用即换）。
3. 直接废除 Caddy，Kernel 拥有唯一发布端口（破坏性更新，入口层无过渡双跑期）。
4. 直接转向 Rust：JS Kernel 冻结；旧 change 剩余 kernel 侧工作在 Rust 上实现。

## 备选与否决记录

- Pingora：否决——入口折叠进 Kernel 后不存在独立边缘代理层；多 upstream LB 属未来 Kernel→多 celld 一跳，届时再议。
- axum+tower 自写独立代理：否决（作为独立边缘服务）；axum 作为 Kernel HTTP 框架采用。
- Garage/SeaweedFS：否决——owner 指定 RustFS。
- Go 重写：否决——owner 指定 Rust。

## 架构

- `kernel-rs/` cargo workspace：tokio + axum/hyper + tokio-tungstenite。模块对位移植 kernel/*.js（index、application-control、package-store、deploy-hooks、supervisor-client/rpc、publication-gate）。
- 监听：唯一发布端口承载公网入口（host 路由：api/admin/mcp/*.app/base/path-alias + /_iweb/health）+ 127.0.0.1 控制监听器（celld 与内部调用直达，端口沿用 7070 约定）。
- 契约：TS contracts 保持 supervisor/admin 权威；新增 `contracts/fixtures/*.json` golden vectors 被 bun 与 cargo 双侧测试消费；`sha256(path\0len\0content)` 排序摘要跨语言逐字节一致（显式向量断言）。
- 凭据与策略：Kernel 经 mc/RustFS 管理 API 签发。若 RustFS 不支持 prefix 条件策略 → 重构为"快照独立桶 + 桶级凭据"（影响 supervisor 物化别名，同步改验收）。

## RustFS 验收门（G1–G6，fail-closed）

- G1 单节点可运行（无多节点强制下限）。
- G2 celld deploy --bucket s3:// + 运行时 watch 全链。
- G3 mc 全链 + IAM（user/policy/svcacct、prefix 条件或桶分离方案定案）。
- G4 一次性卷真实备份/恢复。
- G5 基准：闲时 RSS 目标 ≤50MB、启动峰值记录（对照 MinIO 129–306MB 实测基线）。
- G6 arm64+amd64 官方产物确认。

分离回退：Kernel 重写与存储替换是两条可分离的流。RustFS 任一门失败时：存储暂留 pinned MinIO，仅交付 Rust Kernel + 废 Caddy（仍得 −14~48MB 与镜像瘦身），门证据留档后另议存储。

## 构建/镜像/回滚

- Dockerfile 增 rust 构建阶段（cargo-chef 分层缓存）；最终镜像去 node 层与 caddy。
- 构建矩阵：arm64=lima/iMac；amd64=cloud（cargo -j1 + 已有 swap，实测时长记录在案）。
- 回滚：两节点保留最后 JS+MinIO 镜像 tag，单命令切回。
- 部署顺序：lima 先导 → iMac → cloud；cloud 启用前安全 review 为 owner 硬停点。

## 风险

- RustFS 不成熟：钉版本 + G4 强制 + 分离回退。
- TS/Rust 契约漂移：golden vectors 双侧强制（无 CI 期间靠两侧电池纪律）。
- 云机构建内存：-j1/swap 实测，必要时 amd64 交 CI。
- celld CONTROL_ORIGIN 语义变化与 notes 502 语义：进平价探针矩阵逐项断言。
