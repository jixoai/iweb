<!---
  Orthogonal intents (2026-09-06): [official-site] 首页叙事——hero（面向
  普通人的个人应用节点）→ What's inside 特性栅格 → 单端口入口矩阵 → 演示
  应用 → quick-start 终端 → MCP 接入 → 安全边界 → 当前限制 → 生态链接；
  [content-source] 全部文案取自仓库 README.md，不虚构任何能力；
  [motion-law] data-reveal 静态标注（滚动驱动 CSS 法则，无运行时 action）。

  Original request (2026-09-06, Asia/Shanghai): 新增 ./openiweb 官网站点。
-->
<script lang="ts">
  import CardGrid from "$lib/ui/card-grid/card-grid.svelte";
  import HeroSection from "$lib/ui/hero-section/hero-section.svelte";
  import PressButton from "$lib/ui/press-button/press-button.svelte";
  import SectionCard from "$lib/ui/section-card/section-card.svelte";
  import TerminalCard from "$lib/ui/terminal-card/terminal-card.svelte";
  import { GITHUB_URL, README_URL, README_ZH_URL, SPECS_URL } from "$lib/site";

  const features = [
    {
      id: "kernel",
      eyebrow: "Ingress · 01",
      title: "Single-port Rust kernel",
      body: "kernel-rs is a ~4MB static Rust binary and the node's only published port. It owns host routing, the recovery authority, owner-key auth, and a per-app proxy with WebSocket upgrade tunnels. Everything else — RustFS, the control API, every celld listener — stays on container-internal loopback.",
    },
    {
      id: "mcp",
      eyebrow: "Operations · 02",
      title: "MCP is the operator",
      body: "mcp.<base>/mcp is a protected system application: every JSON-RPC request — including initialize and tools/list — must carry an owner key as a Bearer token. Tools cover workspace read/write/delete and domain listing/registration. The worker forwards the credential per request and never stores it.",
    },
    {
      id: "runtime",
      eyebrow: "Trust · 03",
      title: "Two-tier runtime trust",
      body: "celld v0.3 (Cloudflare Workers API) is the trusted tier: image-seeded fleet apps, one process per app, watchdog soft limits. iweb-wasmd is the untrusted tier and the only runtime admission path: arbitrary or AI-generated packages execute as wasi:http 0.2 components under Wasmtime — engine-enforced isolation, host services, no socket capability.",
    },
    {
      id: "storage",
      eyebrow: "Storage · 04",
      title: "Built-in RustFS",
      body: "S3-compatible object storage (MinIO lineage), single-node friendly with a low memory envelope, loopback-only with no console. Buckets: iweb-workspace, iweb-cells-<app>, iweb-apps, iweb-system.",
    },
    {
      id: "keys",
      eyebrow: "Identity · 05",
      title: "Revocable owner keys",
      body: "One identity, many revocable tokens (the GitHub PAT model). Issue delegated keys (iwb_<id>_<secret>) with absolute expiry, copy a ready-to-paste deployment prompt for an AI agent, ban a key instantly, and read an append-only, per-key-attributed audit trail of every control-plane operation. The bootstrap IWEB_API_TOKEN cannot be banned — it is the credential face of the recovery law.",
    },
    {
      id: "console",
      eyebrow: "Console · 06",
      title: "Static console, tight envelope",
      body: "A SvelteKit + shadcn-svelte static app served as celld native assets — replaceable like any app, never a secret configuration screen. The whole node idles within ≤ 240 MB RssAnon (spec: openspec/specs/node-boundary/).",
    },
  ];

  const ingress = [
    { route: "api.<base>", serves: "Kernel control API (same router/auth as loopback)" },
    { route: "admin.<base>", serves: "per-app celld :8787 (Admin console)" },
    { route: "mcp.<base>/mcp", serves: "per-app celld :8797 (MCP endpoint)" },
    { route: "<app>.<base>", serves: "per-app celld (IWEB_CELLD_PORTS)" },
    { route: "<base>/<app>/app", serves: "path alias for the same application" },
  ];

  const demos = [
    {
      app: "hello",
      host: "hello.<base>",
      demonstrates: "Pure static site via celld's wrangler assets interface — no worker code.",
    },
    {
      app: "search",
      host: "search.<base>",
      demonstrates: "D1 (SQLite) database search with parameterized SQL.",
    },
    {
      app: "collab",
      host: "collab.<base>, collab-b.<base>",
      demonstrates:
        "Frontend/backend split; two celld instances share one Durable Object for cross-instance realtime collaboration over WebSocket.",
    },
  ];

  const limitations = [
    "TLS/wildcard certificates are a deployment concern (the kernel is HTTP Host-routing inside the container).",
    "Monitor metrics are per-Kernel-lifecycle, not durable history.",
    "notes is deployed but not routed (user routes target the wasm tier only).",
    "wasm publication stays fail-closed behind its acceptance record and switch; celld publication does not exist (image-only supply).",
  ];
</script>

<svelte:head>
  <title>iweb — a personal application node</title>
  <meta
    name="description"
    content="iweb is an open-source personal application node for people who don't want to learn containers, databases, or network operations. An AI coding agent deploys and operates applications over MCP; you manage everything from a browser console."
  />
</svelte:head>

<!-- Hero：Broadside 开放式导语 + quick-start 终端。 -->
<HeroSection
  eyebrow="iweb · open-source personal application node"
  summary="You don't need to learn containers, databases, or network operations. Hand your MCP endpoint and one owner key to an AI coding agent (Codex, Claude Code, …) — it deploys and operates applications on your own node. You manage everything from a browser console with a single key."
  copyCommand="docker compose up -d --build"
>
  {#snippet title()}
    A personal application node. <em>Operated by your AI agent.</em>
  {/snippet}
  {#snippet badges()}
    <span>Single-port Rust kernel</span>
    <span>MCP operations</span>
    <span>Two-tier trust runtime</span>
    <span>≤ 240 MB idle</span>
  {/snippet}
  {#snippet secondary()}
    <PressButton variant="outline" href="#quick-start">Quick start</PressButton>
    <PressButton variant="outline" href={GITHUB_URL} external>GitHub ↗</PressButton>
  {/snippet}
  {#snippet terminal()}
    <TerminalCard
      barTitle="quick-start — zsh"
      command="docker compose up -d --build"
      outputs={[
        "iweb-kernel listening :8080 — the only published port",
        'health: curl -H "Host: $IWEB_BASE_HOST" http://127.0.0.1:9010/_iweb/health',
        "console: https://admin.<base>/ — log in with an owner key",
      ]}
    />
  {/snippet}
</HeroSection>

<!-- What's inside：特性栅格。 -->
<section class="mx-auto w-full max-w-[90rem] px-4 sm:px-6 lg:px-8" aria-label="What's inside">
  <h2
    class="font-nav flex items-baseline gap-4 text-lg uppercase tracking-[0.3em]"
    data-reveal=""
  >
    What&rsquo;s inside
    <span class="bg-border h-px flex-1" aria-hidden="true"></span>
  </h2>
  <CardGrid class="mt-6">
    {#each features as feature (feature.id)}
      <div data-reveal="">
        <SectionCard eyebrow={feature.eyebrow} title={feature.title}>
          <p class="text-muted-foreground text-pretty text-[13px] leading-6">{feature.body}</p>
        </SectionCard>
      </div>
    {/each}
  </CardGrid>
</section>

<!-- 单端口入口矩阵。 -->
<div
  class="mx-auto w-full max-w-[90rem] px-4 pt-8 sm:px-6 lg:px-8"
  data-reveal=""
>
  <SectionCard
    eyebrow="Ingress"
    title="One published port routes the whole node"
    summary="iweb-kernel :8080 is the only published port (a single Rust binary). Everything except the Kernel ingress — RustFS, the control API, every celld listener — stays on container-internal loopback and is never published. One installation is one owner's personal node."
  >
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>Route</th>
            <th>Serves</th>
          </tr>
        </thead>
        <tbody>
          {#each ingress as row (row.route)}
            <tr>
              <td><code>{row.route}</code></td>
              <td>{row.serves}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="text-muted-foreground mt-4 text-[13px] leading-5">
      Behind the proxy: <code>RustFS</code> (S3-compatible, loopback-only, no console) backing the
      iweb-workspace / iweb-cells-&lt;app&gt; / iweb-apps / iweb-system buckets.
    </p>
  </SectionCard>
</div>

<!-- 演示应用。 -->
<div
  class="mx-auto w-full max-w-[90rem] px-4 pt-8 sm:px-6 lg:px-8"
  data-reveal=""
>
  <SectionCard
    eyebrow="Demo apps"
    title="Three reference applications ship in the image"
    summary="They exercise the runtime end-to-end. Open collab on both of its domains in two browser windows — a message sent on one side jumps live on the other: the Durable Object cross-instance consistency demo."
  >
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>App</th>
            <th>Host</th>
            <th>Demonstrates</th>
          </tr>
        </thead>
        <tbody>
          {#each demos as demo (demo.app)}
            <tr>
              <td><code>{demo.app}</code></td>
              <td class="dim">{demo.host}</td>
              <td>{demo.demonstrates}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </SectionCard>
</div>

<!-- Quick start。 -->
<div
  id="quick-start"
  class="mx-auto w-full max-w-[90rem] scroll-mt-24 px-4 pt-8 sm:px-6 lg:px-8"
  data-reveal=""
>
  <SectionCard
    eyebrow="Quick start"
    title="One compose command, one health check"
    summary="IWEB_BASE_HOST is a hostname suffix only (no scheme/port/path). The container publishes one port (8080 — map it however you like); TLS is terminated in front of the node (1Panel, Caddy, nginx, …) and the kernel routes by HTTP Host header only."
  >
    <div class="flex flex-col gap-5">
      <div class="readonly-code">
        <div class="readonly-code-meta"><span class="prompt">$</span><span>shell</span></div>
        <pre><code>cp .env.example .env
<span class="tok-comment"># Set a unique CELLD_NODE, IWEB_BASE_HOST, a long random IWEB_API_TOKEN,
# and the MinIO-compatible root + celld S3 secrets.</span>
docker compose up -d --build
curl -H "Host: $IWEB_BASE_HOST" http://127.0.0.1:9010/_iweb/health</code></pre>
      </div>
      <p class="text-muted-foreground text-[13px] leading-5">
        Open the console at <code>https://admin.&lt;base&gt;/</code> and log in with any valid owner
        key — the bootstrap <code>IWEB_API_TOKEN</code>, or a delegated key issued in the console.
        From the Keys &amp; Audit view you can copy a ready-to-paste deployment prompt containing
        the MCP endpoint and key for an AI agent.
      </p>
    </div>
  </SectionCard>
</div>

<!-- MCP 接入。 -->
<div
  class="mx-auto w-full max-w-[90rem] px-4 pt-8 sm:px-6 lg:px-8"
  data-reveal=""
>
  <SectionCard
    eyebrow="MCP"
    title="Point an agent at your node"
    summary="Every JSON-RPC request — including initialize and tools/list — must carry Authorization: Bearer <owner-key> (bootstrap or delegated). Tools cover workspace read/write/delete and domain listing/registration."
  >
    <div class="readonly-code">
      <div class="readonly-code-meta"><span>mcp.json</span></div>
      <pre><code>{ `{ "mcpServers": { "iweb": { "url": "https://mcp.<base>/mcp",
  "headers": { "Authorization": "Bearer <owner-key>" } } } }` }</code></pre>
    </div>
  </SectionCard>
</div>

<!-- 安全边界。 -->
<div
  id="security"
  class="mx-auto w-full max-w-[90rem] scroll-mt-24 px-4 pt-8 sm:px-6 lg:px-8"
  data-reveal=""
>
  <SectionCard
    eyebrow="Security boundary"
    title="Untrusted by default, isolated by design"
    summary="Applications may be copied from the internet or generated by AI, so they are untrusted by default — isolating every application from the node control plane and from each other is the product's security bottom line."
  >
    <ul class="flex flex-col gap-2.5 text-[13px] leading-6">
      <li>
        <strong>celld is the trusted tier.</strong> Fleet applications (admin, mcp, notes, hello,
        search, collab) enter the node only through node images you build, run one process per app,
        and are bounded by a userspace resource watchdog (soft-limit SIGKILL plus per-app restart).
        There is no celld runtime admission; celld is never a hostile multi-tenant boundary.
      </li>
      <li>
        <strong>wasm is the untrusted tier and the only runtime admission path.</strong> Arbitrary,
        network-sourced, or AI-generated packages execute as wasi:http 0.2 components under
        Wasmtime with engine-enforced limits (no socket/TLS/fs capability, host-mediated egress,
        fuel/epoch/store caps) and host services (KV/SQL/Logging) as the data plane.
      </li>
      <li>
        <strong>Never place secrets in the workspace.</strong> Credentials live only in node
        environment or Kernel-issued keys. The law lives in
        <a
          href="https://github.com/jixoai/iweb/tree/main/openspec/specs/application-sandbox"
          class="text-primary underline underline-offset-2"
          >openspec/specs/application-sandbox</a
        >.
      </li>
    </ul>
  </SectionCard>
</div>

<!-- 当前限制 + 生态链接。 -->
<div
  class="mx-auto w-full max-w-[90rem] px-4 pt-8 sm:px-6 lg:px-8"
  data-reveal=""
>
  <SectionCard eyebrow="Honesty" title="Current limitations">
    <ul class="text-muted-foreground flex list-disc flex-col gap-1.5 ps-5 text-[13px] leading-6">
      {#each limitations as limitation (limitation)}
        <li>{limitation}</li>
      {/each}
    </ul>
    <div class="mt-5 flex flex-wrap gap-3">
      <PressButton variant="outline" href={GITHUB_URL} external>GitHub ↗</PressButton>
      <PressButton variant="outline" href={README_ZH_URL} external>中文文档 ↗</PressButton>
      <PressButton variant="outline" href={README_URL} external>README ↗</PressButton>
      <PressButton variant="outline" href={SPECS_URL} external>openspec specs ↗</PressButton>
    </div>
  </SectionCard>
</div>
