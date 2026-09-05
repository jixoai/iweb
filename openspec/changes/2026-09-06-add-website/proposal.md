> Orthogonal intents (maintained 2026-09-06 Asia/Shanghai): official-site
> capability; jixoai design-language adoption; GitHub Pages delivery.
>
> Original request (2026-09-06 Asia/Shanghai): 新增 ./openiweb 官网站点
> （背景：./jixoai-ui 发布了新版本 0.3.0）。

## Why

iweb has no official site — the README is the only public surface, and the
project is about to be listed on jixoai.com with a `site` link that has no
target. jixoai-ui 0.3.0 published a complete website surface to the registry
(`website-scaffold`, `terminal-header/footer`, `hero-section`, `llms-txt`),
which makes a family-conformant static site a bootstrap operation instead of
a design project.

## What Changes

- Add `apps/website` — a SvelteKit + adapter-static site in the shared jixoai
  identity, bootstrapped from the official registry
  (`npx jixoai-ui init --hue 253`), hue sourced from the logo's blue
  `#0b81fd` (oklch 253.4°). Rendered primaries: light `#008bff`, dark
  `#1aa4ff`. The site is independent of `apps/admin-console` (no shared
  imports; different purposes).
- Content: hero (personal application node for normal people — hand your MCP
  endpoint and one key to an AI coding agent), features grid (single-port
  Rust kernel, MCP-operations via owner keys, two-tier runtime trust
  celld/wasmd, built-in RustFS, revocable owner keys, static console,
  ≤240 MB idle, demo apps hello/search/collab), quick-start terminal
  (docker compose up + console URL + owner key), links (GitHub jixoai/iweb,
  README-zh).
- Assets: favicon/theme-color carry the project icon hex `#008bff`; logo
  source `apps/admin-console/src/lib/assets/favicon.svg`.
- AI export layer: `llms.txt` / `llms-full.txt` / per-page `.md` mirrors via
  the registry `llms-txt` item, one generation point in the vite pipeline.
- Delivery: GitHub Pages via a new deploy workflow (push-to-main +
  workflow_dispatch). Custom-domain CNAME is Owner-managed and gated behind
  a build flag — until DNS exists the site serves from
  `jixoai.github.io/iweb`, so the build supports a configurable base path.
- No changes to kernel, runtime, console, or Docker surfaces.

## Capabilities

### New Capabilities

- `website`: the official static site, its registry lock, content surface,
  AI export, and Pages delivery.
