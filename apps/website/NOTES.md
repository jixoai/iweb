# iweb website 实施记录（NOTES）

`apps/website`（包名 `website`）——iweb 官方静态站点，2026-09-06 从零建立。
结构先例：unipty `packages/www`；视觉信源：jixoai-website skill +
ui.jixoai.com registry（jixoai-ui 0.3.0）。

## Registry 消费（2026-09-06）

- `components.json` 先于 CLI 手写（`jixoai-ui init` 无 components.json 直接
  fail）：style new-york、`tsx: true`（shadcn schema 强制，Svelte 项目同样
  必填）、aliases `ui → src/lib/ui`、`lib → src/lib`、css `src/app.css`、
  `registries.@jixoai`、`jixoai.brandHue: 253`。
- `npx jixoai-ui init --hue 253` 安装 `jixoai-theme` → `src/lib/jixoai.css`
  （92KB token 表，0.3.0 已自带 popover/destructive/input/ring/shadow 的
  `@theme inline` 映射与滚动驱动 reveal 法则）。
- 站点项：`scrollbar-measure`、`website-scaffold`、`terminal-header`、
  `terminal-footer`、`theme-toggle`、`hero-section`、`section-card`、
  `press-button`、`terminal-card`、`card-grid`、`llms-txt`。
- **依赖闭包显式 add 入锁**（shadcn 装依赖文件但只有显式名字进
  `jixoai-ui.lock`；`upgrade` 只刷 locked 项）：`icons`、`defaults`、
  `utils`、`jixoai-theme`、`navigation-menu`、`popover`、`density`、
  `paint`、`separator`、`figure`、`context-plugin`。
- **排除项**：`toc-engine` / `toc`——本站无文档页 ToC，没有任何已装项拉入
  它，磁盘上不存在，不入锁。`surface-motion.ts` 随 `popover` 项发行
  （`@lib/surface-motion.ts`），不单独成项。
- 0.3.0 布局为目录式（`src/lib/ui/<item>/<file>` + `index.ts` barrel），
  与 unipty 时代的扁平布局（0.2.0，`src/lib/ui/<item>.svelte`）不同；
  组件内部 import 已是 `$lib/...`（SvelteKit 原生别名），无需 unipty
  NOTES 记录的 import 修正。
- `llms-txt` 项的 target 是项目相对路径 `vite-plugins/llms-txt.mjs`，但
  shadcn 在 svelte-kit 框架下把它放进了 `src/vite-plugins/`；已移回
  `vite-plugins/` 以对齐 lock 记录与 skill 文档的路径契约。

## app.css 补充映射（tasks 2.4 的核验结果）

unipty NOTES 的坑（registry 主题表留空 popover/destructive/input/ring/
radius/shadows 映射）在 jixoai-theme 0.3.0 已消除：除 `--radius-*:
initial`（封杀 Tailwind 默认 rounded 刻度）外全部由 registry 表自带映射；
`src/app.css` 只补 radius 封杀 + `@layer base` 规则 + 站点表面
（data-table / readonly-code）。

## 与 skill 的已记录分歧

- **theme-color = `#008bff`**（proposal 裁定：favicon/theme-color 携带项目
  图标色），而非 skill tech-stack 建议的暗色画布 `#000000`。favicon /
  header logo 直接复用 `apps/admin-console/src/lib/assets/favicon.svg`
  （多彩项目图标，蓝 `#0b81fd` ≈ oklch hue 253.4）。
- **reveal 为 0.3.0 滚动驱动 CSS**（`animation-timeline: view()`，静态
  `data-reveal=""` 标注，无运行时 action、无 html.js 门）；skill motion.md
  描述的 IntersectionObserver action 是 0.2.0 时代实现。`app.html` 仍保留
  `html.js` 标记（表面族的 no-JS 回退分支依旧门控于它）。

## 构建与服务形态

- `SITE_BASE=/openiweb` → `kit.paths.base`（`paths.relative: false`，绝对资源
  URL 带 `/iweb` 前缀）；站内链接经 `$app/paths` 的 `base`。
- `scripts/postbuild.mjs`：`SITE_CNAME=1`（域名取 `SITE_CNAME_DOMAIN`，
  默认 `iweb.jixoai.com`——Owner 未定 DNS 前的占位约定，切换时改环境即可）
  写 `dist/CNAME`；其余构建零写入。
- `scripts/check-static.mjs`：产物存在性、绝对 URL base 前缀、本地链接
  落盘可解析、llms 导出三件套 + 绝对链接、CNAME 门控。
- 本地抽查法：`dist` 符号链接为 `iweb` 后 `python3 -m http.server` 起根目录，
  `/iweb/`、`/iweb/favicon.svg`、`/iweb/llms.txt`、`/iweb/index.md`、
  `/iweb/_app/...`（js/css/woff2）全部 200。

## 内容信源

全部文案取自仓库 `README.md` / `README-zh.md`（定位、技术选型、入口矩阵、
演示应用、快速开始、MCP 接入、两层信任、当前限制）；未虚构任何能力；
许可证信息仓库未声明，站点不做许可声明（footer 仅 `© iweb contributors`）。
