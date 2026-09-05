<!-- Orthogonal intents (2026-09-06): [official-site] apps/website 使用说明；
[base-path] 两种服务形态的构建开关；[registry] registry 消费与升级入口。
Original request (2026-09-06, Asia/Shanghai): 新增 ./openiweb 官网站点。 -->

# iweb website（`apps/website`）

iweb 的官方静态站点：SvelteKit 2 + adapter-static + Tailwind v4（CSS-first），
视觉身份整体来自 [ui.jixoai.com](https://ui.jixoai.com) registry（jixoai
design language，`--brand-hue: 253`，源自 logo 蓝 `#0b81fd`）。零 runtime
依赖；`dependencies` 为空，全部工具链在 `devDependencies`。

## 命令

```bash
bun install                      # 仓库根执行（workspaces + 根 bun.lock）
bun run dev                      # 开发服务器（端口 13222）
SITE_BASE=/iweb bun run build    # 子路径形态构建 → dist/
SITE_BASE=/iweb bun run check    # 产物静态抽查（链接/base 前缀/llms 导出）
bun run preview                  # vite 预览
```

## 两种服务形态（一份代码）

| 形态 | 构建环境 | 产物 | 说明 |
| --- | --- | --- | --- |
| 项目页子路径 | `SITE_BASE=/iweb`（默认 workflow 形态） | 链接全部落在 `/iweb/…`，无 CNAME | DNS 就绪前的起步形态：`https://jixoai.github.io/iweb` |
| 自定义域名 | `SITE_CNAME=1`（+ `SITE_CNAME_DOMAIN=<域名>`，默认 `iweb.jixoai.com`；`SITE_BASE` 留空，按需 `SITE_URL=https://<域名>`） | 写 `dist/CNAME`，根路径服务 | Owner 配好 DNS 后在 workflow 里改环境即可，无代码变更 |

- `SITE_BASE` 由 `svelte.config.js` 读入 `kit.paths.base`；站内链接一律经
  `$app/paths` 的 `base` 解析（`src/routes/+layout.svelte`），严禁硬编码前缀。
- AI 导出（llms.txt / llms-full.txt / 每页 `.md` 镜像）由 vite 插件
  `vite-plugins/llms-txt.mjs` 在构建末尾一次性生成；`siteUrl` 随
  `SITE_URL`/`SITE_BASE` 推导，产物字节级幂等。

## Registry 消费

`components.json`（先手写，`tsx: true` 为 schema 强制）注册
`@jixoai = https://ui.jixoai.com/r/{name}.json`；`jixoai-ui.lock` 锁定全部
已安装项（站点项 + 依赖闭包），升级入口：

```bash
npx jixoai-ui upgrade   # 只刷新 lock 内条目并重放 hue（253）
```

依赖闭包的取舍与排除项见 [NOTES.md](./NOTES.md)。

## 部署

`.github/workflows/deploy-website.yml`：push `main` 或手动触发 →
`bun install --frozen-lockfile`（根锁）→ `SITE_BASE=/iweb` 构建 → 静态检查
→ `actions/deploy-pages`。新增依赖时在本地 `bun install` 后把根
`bun.lock` 同 commit 提交。
