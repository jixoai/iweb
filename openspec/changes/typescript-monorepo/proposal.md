<!-- 用户原始需求（2026-08-24）：worker 应用升级为 ESM+TS 包（@cloudflare/workers-types 上下文安全）；移除冗余的 worker seed 清单 iweb.json；项目按 docker+rust+monorepo 行业标准重构目录。 -->
<!-- 用户决策（2026-08-24）：未正式发布，不考虑向下兼容；seed iweb.json 判定为过度设计。 -->
<!-- 边界澄清（Codex 审稿 R1）：本变更只删除 image-seeded worker 元数据清单（id/entry/hostIds/runtime）；沙箱准入 application manifest（contracts/manifest.ts：runtime/resources/storage/egress）是另一套契约，保持不动。 -->

## Why

worker 应用是手写 JS 单文件，无类型安全；seed `iweb.json` 与路由注册表/wrangler.jsonc 三处重复；目录结构不符合 apps/packages monorepo 惯例。celld deploy 内置 esbuild（同 wrangler 机制），TS 源码直接部署，类型检查只需开发期 tsc --noEmit。

## What Changes

- **BREAKING** 目录重构：`apps/workers/*`（celld 应用包）、`apps/admin-console`、`packages/contracts`（共享契约，Node/Worker 安全边界显式声明）、`packages/worker-shared`（Worker 安全工具）；根 `package.json`（bun workspaces，显式 glob 集合）+ `tsconfig.base.json`（strict，types 默认空、由各包自声明运行时类型面——Worker 包声明 @cloudflare/workers-types）
- **BREAKING** 五个有 Worker 代码的应用（admin/mcp/notes/search/collab）以 ESM+TS 重写为独立包（Env 接口化绑定）；hello 保持 static-only wrangler 项目；collab-b 复用 collab 包（部署变体，不新增第七个包）；行为零变化由黑盒契约套件锁定；tsc --noEmit 进电池
- **BREAKING** image-seeded worker 元数据清单废除：应用身份唯一权威是 Kernel 路由注册表；`/v1/workspace` 与 monitor 的 apps 投影改为纯路由派生（只含 id/domains/deployed/system，删除 sourcePath/manifestPath 语义）；entrypoint 停止 workspace 种子（iweb.json + 陈旧 app/ 代码镜像）；镜像内置 fleet 的源码只存在于 celld 部署项目（workspace 可承载 owner/agent 写入的准入暂存包，属普通文件）
- Dockerfile（arm64/amd64）/entrypoint（/opt/iweb 新布局）/.dockerignore/portless/credential-scan/文档全部随新结构更新

## Capabilities

### Modified Capabilities

- workspace-and-routes：应用目录约定与清单约定废除（路由注册表唯一权威）；workspace 回归 owner 普通文件区
