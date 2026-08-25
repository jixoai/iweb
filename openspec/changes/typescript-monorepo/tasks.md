## 1. Workspace 基础（design.md 目标树）

- [x] 1.1 根 package/bun.lock/tsconfig.base + 根 typecheck/check 门禁（fail-closed） —根 `package.json`（bun workspaces 显式集合 `["apps/admin-console","apps/workers/*","packages/*"]`、共享 devDeps：typescript/@cloudflare/workers-types/@types/node）+ 根 bun.lock + `tsconfig.base.json`（strict/bundler/noEmit/默认空 types——各包自声明）+ 根 scripts（check/typecheck/test 编排）
- [x] 1.2 worker-shared（escapeHtml/jsonResponse/celld.d.ts）+ contracts 迁移与双 tsconfig（Node 全量 0 错误 + worker 子集） —`packages/worker-shared`（escapeHtml/json 响应/celld.d.ts 本地 API 差异声明）；`packages/contracts` 迁移（git mv）+ exports 分层（`./worker` Worker-safe 子集 / 根 marker + 全量源码类型门禁双 tsconfig），验收 `./worker` 闭包无 node builtin；Kernel CJS/Rust fixture/scripts/tests 的 import 路径同步

## 2. 目录迁移与 TS 化

- [x] 2.1 git mv 完成 + 五 package manifests + tsconfig（extends base） —git mv：`worker/apps/*`→`apps/workers/*`、`admin-console`→`apps/admin-console`；每个代码 Worker 一个 package.json（name/private/type:module/exports）+ tsconfig（extends base, include src）
- [x] 2.2 五 Worker TS 化（Env 接口化）；hello static-only；collab-b 复用；wrangler main→src/main.ts —五个 Worker TS 重写（Env 接口化绑定：D1Database/DurableObjectNamespace/Fetcher）；hello 保持 static-only；collab-b 复用 collab 包；wrangler main→src/main.ts；含 workers-types 与 celld 扩展 API 的类型声明验收
- [x] 2.3 bun run typecheck 全清（0 错误） —`tsc --noEmit` 门禁进电池（根 `bun run typecheck`）

## 3. 路由唯一权威投影

- [x] 3.1 Rust route_app_ids + JS workspaceApps 纯路由派生；sourcePath/manifestPath 全链清除 —Kernel（Rust http.rs derived_app_ids/monitor + JS workspaceApps）apps 投影改纯路由派生——**apps projection 不再扫描 workspace 对象**（普通 owner 文件列表保留不变）；删除 sourcePath/manifestPath 字段；沙箱准入输入（kernel/index.js admitWorkspacePackage 读 workspace 暂存包）按修订后 spec 保留——那是 owner/agent 普通写入的显式发布暂存，非节点种子
- [x] 3.2 Admin schema/UI/测试夹具四项断言（双实现 25+25 绿） —Admin 契约（workspaceSchema/monitorAppSchema 去 sourcePath/manifestPath）+ route-manager/application-resource-table UI + 浏览器契约夹具；四项断言：①route-only 应用（workspace 无任何对象）仍投影 ②workspace-only 目录（无 route）不出现在 apps ③workspace 对象增删不改变任何 apps 投影 ④Workspace/monitor/Admin 三处投影均等于 route registry 且无 sourcePath/manifestPath
- [x] 3.3 entrypoint 停止种子；沙箱准入 manifest 不动 —entrypoint 停止 workspace 种子（iweb.json + app/ mirror）；保留 route seed；沙箱准入 manifest 契约（contracts/manifest.ts）不动；历史 volume 中旧 seed 对象不清理（退化为普通文件，注释说明）

## 4. 接线与运维

- [x] 4.1 Dockerfile 双架构 workspace 化 builder（frozen-lockfile 无回退）+ 新 COPY 布局 + .dockerignore 增补；ARM 镜像 lima 实建实证 —Dockerfile/Dockerfile.amd64：Admin builder 改 workspace 化安装（根 package.json+bun.lock+workspace manifests COPY → `bun install --frozen-lockfile` → build）；COPY 路径与 `/opt/iweb` 新布局；IWEB_RECOVERY_WORKER→/opt/iweb/apps/workers/admin；.dockerignore 增补（根/workspace node_modules、.svelte-kit、build、.wrangler、Bun 缓存、target）；entrypoint 注释同步；双架构 docker build 验收
- [ ] 4.2 scripts：portless 已知 host 列表含 hello/search/collab/collab-b 验证；credential-scan 九位置（含 image-layer）（实际有效 kind:path 九种：`package`、`sandbox-fs`、`env-projection`、`object-store`、`admin-assets`、`image-layer`、`log`、`monitor-frame`、`test-output`）+ 脱敏报告入 .agents/evidence/；含真实 `celld deploy --dry-run` 跨包相对 import 打包验收
- [ ] 4.3 notes 迁移链路回归（DO 绑定/独立 bucket/IWEB_RUN_NOTES_CELLD/真实 export-import-equality）；README/README-zh/AGENTS.md/admin-console README 路径全部更新 —2026-08-26 进展：静态接线核查（DO 绑定/独立 bucket/IWEB_RUN_NOTES_CELLD 门控/Kernel 端口映射）+ 本地合成迁移与 real-migrate 执行器（格式夹具，equal=true）+ 远程节点 502/404 fail-closed 语义实证完成；README/README-zh 目录树补齐 worker-shared。真实 DO 数据 export-import-equality 与 AGENTS.md 拓扑叙事归 5.2 重部署时合并（IWEB_RUN_NOTES_CELLD=1）

## 5. 验证

- [ ] 5.1 全电池：bun + cargo + tsc + 双 Kernel 黑盒（recovery/browser-contract/owner-keys）+ Admin 三入口资产验收 + probe matrix
- [ ] 5.2 重建镜像部署 iMac（admin 强制 republish）+ 浏览器契约验证；Codex 代码 review 闭环
