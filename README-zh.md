<div align="center">

<img src="./apps/admin-console/src/lib/assets/favicon.svg" width="120" alt="iweb logo" />

# iweb

</div>

**iweb** 是一个面向普通人的开源个人应用节点：你不需要理解容器、数据库或网络运维，
把 MCP 端点和一把密钥交给 AI 编程代理（Codex、Claude Code……），应用就部署和运行在
你自己的节点上；你用一个浏览器控制台和一把密钥管理一切。

应用代码可能来自网络复制或 AI 生成，因此**默认不可信**——把每个应用与节点控制面、
与其他应用隔离开，是本产品的安全底线。

```text
公网
  |
iweb-kernel :8080           唯一发布端口（单个 Rust 静态二进制）
  +-- api.<base>                  -> Kernel 控制 API（与回环监听同鉴权）
  +-- admin.<base>                -> 独立 celld :8787（管理控制台）
  +-- mcp.<base>/mcp              -> 独立 celld :8797（MCP 端点）
  +-- <app>.<base>                -> 各应用独立 celld（IWEB_CELLD_PORTS）
  +-- <base>/<app>/app            -> 同一应用的路径别名
                                      |
                    RustFS（S3 兼容，仅回环，不开 console）
                                      |
                  iweb-workspace / iweb-cells-<app> / iweb-apps / iweb-system
```

一台 iweb 安装 = 一个 owner 的个人节点。除 Kernel 入口外的所有监听（RustFS、控制
API、每个 celld）都只在容器内回环，绝不发布。

## 技术选型

| 层 | 选择 | 理由 |
|---|---|---|
| 入口与控制面 | **Rust 内核**（`kernel-rs/`，~4MB 静态二进制） | 单发布端口、Host 路由、恢复权威、owner-key 鉴权、带 WebSocket 升级隧道的逐应用代理 |
| 应用运行时 | **[celld](https://github.com/denoland/celld) v0.3**（Cloudflare Workers API：fetch handler、Durable Objects、D1、wrangler assets） | 标准化（Workers 生态代码可直接迁移）、自托管、SQLite 支持有状态对象 |
| 对象存储 | **RustFS**（S3 兼容，MinIO 血统） | 单节点友好、低内存封套、仅回环 |
| 控制台 | **SvelteKit + shadcn-svelte** 静态应用，以 celld 原生资产服务 | 和普通应用一样可替换；永远不是密钥配置界面 |

闲时内存封套：整节点 **≤ 240 MB** RssAnon（规格见
[`openspec/specs/node-boundary/`](./openspec/specs/node-boundary/spec.md)）。

## 快速开始

```bash
cp .env.example .env
# 设置唯一的 CELLD_NODE、IWEB_BASE_HOST、足够长的随机 IWEB_API_TOKEN，
# 以及 MinIO 兼容的 root 与 celld S3 凭据。
docker compose up -d --build
curl -H "Host: $IWEB_BASE_HOST" http://127.0.0.1:9010/_iweb/health
```

- `IWEB_BASE_HOST` 只是一个主机名后缀（不含协议/端口/路径）。
- 容器内只发布一个端口（8080，映射随意）。TLS 由前置层终止（1Panel、Caddy、nginx
  ……），内核只按 HTTP `Host` 头路由。
- 打开 `https://admin.<base>/`，用任意有效 owner 密钥登录（bootstrap
  `IWEB_API_TOKEN`，或控制台签发的委托密钥，见下）。

## 演示应用

镜像内置三个参考应用，端到端验证运行时能力：

| 应用 | 域名 | 演示内容 |
|---|---|---|
| **hello** | `hello.<base>` | 纯静态站：只用 celld 的 wrangler `assets` 文件接口，无 Worker 代码 |
| **search** | `search.<base>` | D1（SQLite）数据库搜索：参数化 SQL、中文检索 |
| **collab** | `collab.<base>`、`collab-b.<base>` | 前后端分离；两个 celld 实例共享同一个 Durable Object，WebSocket 跨实例实时协作白板 |

在 collab 的两个域名各开一个浏览器窗口，一边发消息另一边实时跳动——这就是
Durable Object 跨实例一致性的直观演示。

## 密钥与审计

一个身份，多把可吊销令牌（GitHub PAT 模式）。在控制台的**密钥与审计**视图：

- **签发委托密钥**（`iwb_<id>_<secret>`），可设置绝对过期时间（1/7/30 天/永久）
- **一键复制部署提示词**——MCP 端点 + 密钥已模板化的中文 Agent 指令，直接粘给任何 AI 代理
- **即时吊销**：确认后立即生效（票据失效、监控 WebSocket 主动关闭、后续请求 401）
- **审计追踪**：每次控制面操作按密钥归因（含被拒的 401 尝试），append-only、4 MiB 封顶轮转

bootstrap `IWEB_API_TOKEN` 永远有效且不可吊销——它是 `api.<base>` 独立恢复法律的
凭据面：即使所有委托密钥与 Admin 应用全部失守，owner 仍能直达 Kernel 控制 API。

## MCP

`mcp.<base>/mcp` 是受保护的系统应用。每个 JSON-RPC 请求——包括 `initialize` 和
`tools/list`——都必须携带 `Authorization: Bearer <owner-key>`（bootstrap 或委托密钥
均可）。工具覆盖工作区读写删与域名清单/注册。Worker 逐请求转发凭据，绝不存储。

给 AI 代理的接入配置长这样：

```json
{ "mcpServers": { "iweb": { "url": "https://mcp.<base>/mcp",
  "headers": { "Authorization": "Bearer <owner-key>" } } } }
```

## 开发

```bash
bun install          # 工作区工具（测试为 bun 原生）
bun test             # 全量电池（489 项；bunfig preload 使电池对宿主代理免疫）
cd kernel-rs && cargo test && cargo clippy --all-targets   # Rust 电池
KERNEL_TEST_COMMAND=$PWD/kernel-rs/target/debug/iweb-kernel \
  bun test tests/kernel-recovery.test.ts    # 黑盒契约套件（也支持 node kernel/index.js）
openspec validate --all --strict           # 规格纪律
```

跨实现契约测试用同一黑盒套件驱动 Rust 内核与冻结的 JS 参考内核
（`tests/kernel-recovery.test.ts`、`tests/kernel-browser-contract.test.ts`、
`tests/owner-keys.test.ts`），wire 格式漂移无法静默上线；另有一套专用测试用
Admin 控制台自己的 zod schema 逐字段验证内核响应。

多架构镜像：`Dockerfile`（arm64）与 `Dockerfile.amd64`（x86_64；含受限构建器旋钮
`CARGO_BUILD_JOBS` 与 `CRATES_MIRROR=rsproxy`）。

## 目录结构

```text
kernel-rs/               Rust 内核（入口、控制 API、代理、密钥、审计、监控）
kernel/                  冻结的 JS 参考内核（回滚平价，不进镜像）
apps/workers/            celld 应用：admin、mcp、notes、hello、search、collab
apps/admin-console/      SvelteKit 控制台（构建为 celld 原生资产进镜像）
supervisor/              沙箱 supervisor（见下）
packages/contracts/      跨实现共享契约向量
packages/worker-shared/  Worker 安全共享工具（HTML 转义、JSON 响应）
scripts/                 节点运维（探针矩阵、备份、迁移、portless……）
openspec/                产品法律：specs/、进行中变更、归档
tests/                   bun 原生电池（含浏览器契约套件）
```

## 安全边界

应用包是不可信输入，无论谁选择了它。当前过渡舰队（admin、mcp、notes、hello、
search、collab）是镜像内置的受信应用；通用应用发布在沙箱验收记录存在之前保持
关闭（发布闸门返回 503）。celld/workerd 自身明确不承诺对抗性多租户安全——目标
边界是每个应用一个独立强制的沙箱（执行、凭据、存储、网络、资源、生命周期），
规格见
[`openspec/specs/application-sandbox/`](./openspec/specs/application-sandbox/spec.md)。

**绝不把密钥放进工作区**：凭据只存在于节点环境变量或 Kernel 签发的密钥。

## 当前限制

- TLS/泛域名证书是部署侧事务（容器内内核只做 HTTP Host 路由）。
- 监控指标是 Kernel 进程生命周期内的，不是持久历史。
- `notes` 已部署但未路由（回滚权威，等待沙箱迁移）。
- JS 参考内核只实现 bootstrap token 契约；委托密钥与审计是 Rust 专属能力。

English documentation: [README.md](./README.md)。完整行为规格见
[`openspec/specs/`](./openspec/specs/)。
