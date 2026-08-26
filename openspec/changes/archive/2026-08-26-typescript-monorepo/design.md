<!-- 用户原始需求（2026-08-24）：docker+rust+monorepo 行业标准结构。正交意图：目标树/包图/TS 继承/Docker 依赖策略一次定清。 -->

## 目标树

```text
iweb/
├── Dockerfile / Dockerfile.amd64 / docker-compose*.yml
├── package.json              # bun workspaces + 共享 devDeps
├── tsconfig.base.json        # strict + 默认空 types；Worker 包自声明 workers-types
├── bunfig.toml
├── apps/
│   ├── admin-console/        # SvelteKit（原 admin-console/，git mv）
│   └── workers/
│       ├── admin/            # @iweb/worker-admin（薄壳：delegates to src）
│       ├── mcp/              # @iweb/worker-mcp
│       ├── notes/            # @iweb/worker-notes
│       ├── hello/            # static-only：site/ + wrangler.jsonc，无 package 代码
│       ├── search/           # @iweb/worker-search
│       └── collab/           # @iweb/worker-collab（collab-b 部署变体复用此包）
├── packages/
│   ├── contracts/            # @iweb/contracts（Node/Worker 安全边界见 exports）
│   └── worker-shared/        # @iweb/worker-shared（HTML 转义、JSON 响应）
├── kernel-rs/                # cargo workspace（不变）
├── kernel/                   # JS 参考内核（不变）
├── supervisor/ scripts/ tests/ config/ packaging/ openspec/
```

## 包图与边界

- `@iweb/worker-shared`：Worker-safe 纯函数（escapeHtml、json 响应），零 Node 依赖，Worker 可直接 import。
- `@iweb/contracts`：跨实现契约向量。根入口是 marker（决策修订：全量 re-export 会因模块间循环依赖不可行——消费方一律子路径直连 `.../contracts/<module>.ts`，tsconfig 只做类型门禁）；`./worker` 子集真实导出 manifest 验证器。运行时统一相对源码 import——bare 包名仅为开发期 workspace 语义，不参与 celld deploy 解析。
- **共享代码解析策略（Codex R2 裁决）：运行时一律相对源码 import**（从 `apps/workers/<app>/src/main.ts` 出发为 `../../../../packages/worker-shared/src/html.ts`——src 上升四级到仓库根）。理由：celld deploy 的 esbuild 在镜像内运行且无 node_modules——bare `@iweb/*` 在镜像内不可解析；相对路径在开发（bun/tsc）与镜像（esbuild 跟随文件系统）两侧零机制差异。workspace package.json 仅服务于开发期工具链（typecheck/测试/workspace 语义），不参与运行时解析。验收：真实 `celld deploy --dry-run` 对含跨包相对 import 的 Worker 成功打包。
- Worker 包：`type: module` + `exports: { ".": "./src/main.ts" }`；wrangler `main` 指向 `src/main.ts`；镜像内无需 node_modules——类型包 zero-runtime，共享代码以相对源码 import 被 esbuild 内联。
- 根 workspaces（显式集合，不叠 glob）：
  `["apps/admin-console", "apps/workers/*", "packages/*"]`

## TS 继承分层

- `tsconfig.base.json`：`strict`、`moduleResolution: "bundler"`、`noEmit`、`types: []`（默认空——由各包自声明运行时类型面）、`isolatedModules`、`skipLibCheck`。
- Worker 包 tsconfig：`extends base` + `types: ["@cloudflare/workers-types"]`，`include: ["src"]`。
- `packages/contracts` 双入口双 tsconfig：根入口是 marker（全量 re-export 因循环依赖不可行；Node tsconfig 只做全量源码类型门禁，运行时消费子路径直连）与 `./worker` 入口（Worker-safe，仅 workers-types，manifest 验证器真实导出）。
- admin-console 保留自身 SvelteKit tsconfig 体系（`.svelte-kit/tsconfig.json` 与根 base 无继承关系——框架自管）。
- celld 与 workers-types 的 API 差异（如 `acceptWebSocket` Hibernation 形态）在 `packages/worker-shared/src/celld.d.ts` 本地声明补齐，不 fork workers-types。

## Docker 依赖策略

- 镜像构建上下文不变（仓库根）；`.dockerignore` 增补：根/各 workspace `node_modules`、`.svelte-kit`、`build`、`.wrangler`、Bun 缓存、Rust `target`。
- **Admin builder workspace 化**（Codex R2）：Dockerfile 的 admin-console 构建阶段改为 COPY 根 `package.json` + `bun.lock` + 全部 workspace manifests + `apps/admin-console` + 所需 `packages/*`，在阶段内 `bun install --frozen-lockfile`（以 workspace 根为安装上下文）再 `bun run build`；双架构 `docker build` 列为验收。
- 镜像内 `/opt/iweb` 新布局：`/opt/iweb/apps/workers/<app>`（celld 项目）、`/opt/iweb/packages`（共享源，供 esbuild 相对 import 跟随）；Admin 产物进 `/opt/iweb/apps/workers/admin/admin-assets`（现路径平移）。
- 镜像内不执行 npm/bun install：workers-types 是类型包不出现在运行时；worker-shared/contracts 以源码形式被 esbuild 内联进部署产物。
- `IWEB_RECOVERY_WORKER` 指向 `/opt/iweb/apps/workers/admin`。

## 风险与回退

- 行为锁定：现有黑盒契约套件（recovery/browser-contract/owner-keys）+ Admin 三入口验收 + probe matrix 在部署后必须全绿。
- notes 迁移链路（migration/real-migrate 脚本 + DO 绑定 + IWEB_RUN_NOTES_CELLD）显式回归验证，不受 manifest 删除影响（它不读 seed iweb.json）。
- 历史 volume 中已存在的 seed 对象（iweb.json/app/ 镜像）不主动清理——它们退化为 owner 普通文件，无投影语义。
