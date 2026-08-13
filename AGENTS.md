# iweb Agent Guide

<!-- 用户原始需求（2026-08-13）：把个人节点的架构、当前能力和后续工作沉淀为 AI 可执行的规范。 -->
<!-- 架构诊断（2026-08-13）：Admin 已切换为 celld v0.2 原生静态资产；Dispatcher 只分发应用，ADMIN_ASSETS 是唯一浏览器资产权威。 -->
<!-- 架构诊断（2026-08-13）：celld fleet 原生边界是一份 application deployment；当前 iweb 把整套 Dispatcher 作为该 application，工作区应用只是其内部路由模块。 -->
<!-- 架构诊断（2026-08-13）：总览“容器内存”直接读取 cgroup memory.current，包含 MinIO、celld、Kernel、Caddy 与容器缓存；celld 官网 0.47 MB 是 trivial resident cell 的基准增量，不是应用或 celld 进程启动内存。 -->

## Start here

Before changing iweb, read these in order:

1. `openspec/specs/` — current behavior contract; this is the primary product law.
2. Any active `openspec/changes/<name>/` — approved future behavior and its task boundary.
3. `README.md` — operator-facing setup and current limitations.
4. The affected source files — implementation truth and local intent comments.

Do not start implementation from a chat summary alone. Treat existing dirty
worktree changes as user-owned unless they are explicitly in the active change.

## Node model

```text
public Internet
      |
   Caddy :8080                 only published container port
      +-- <base>               -> MinIO iweb-workspace objects
      +-- api.<base>           -> Kernel :7070 (permanent control/recovery)
      +-- admin.<base>         -> Kernel -> celld :8787 -> admin app
      +-- mcp.<base>/mcp       -> Kernel -> celld :8787 -> MCP app
      +-- <app>.app.<base>     -> Kernel -> celld Dispatcher
      +-- <base>/<app>/app     -> Kernel path alias -> same application
                                      |
                       MinIO workspace / celld Durable Object SQLite
```

One iweb installation is one personal-node tenancy boundary. It is not a
hostile multi-tenant sandbox. Do not claim otherwise or introduce a
product-level public/private storage split.

celld and iweb use different application boundaries:

```text
celld fleet application (one committed deployment)
└── iweb Dispatcher
    ├── iweb workspace application: admin
    ├── iweb workspace application: mcp
    └── iweb workspace application: notes
```

This is a deliberate low-cost aggregation for one trusted personal node, not a
claim that celld natively treats each Dispatcher branch as an application. If
an iweb application needs independent deployment, process accounting, failure
isolation, or rollout, it requires its own celld fleet (bucket or prefix,
deployment pointer, state directory, listener, and node lifecycle) or a future
validated Worker Loader design. Worker Loader remains experimental in v0.2.

Internal listeners and authority:

- MinIO `127.0.0.1:9000`, Kernel `127.0.0.1:7070`, celld public
  `127.0.0.1:8787`, and celld operator/peer `127.0.0.1:8788` are never Docker
  published.
- The operator/peer listener is loopback-only and Caddy must never route to it.
- `api.<base>` is Kernel-owned forever; no manifest or celld route can replace
  it.
- `admin` and `mcp` are visible celld system applications. Their routes are
  protected, but they are not the recovery control plane.
- `IWEB_API_TOKEN` is the bootstrap owner credential. It must never enter a
  URL, browser bundle, workspace object, log, test fixture, or handoff.

## Workspace and application law

```text
iweb-workspace/
├── index.html
├── admin/{iweb.json,app/}
├── mcp/{iweb.json,app/}
├── notes/{iweb.json,app/}
└── arbitrary files
```

- There is one MinIO-backed workspace root. Application directories follow
  `<app>/iweb.json` and `<app>/app/`, but directories do not publish routes.
- The Kernel route registry is the source of truth for host IDs, enabled state,
  target applications, and system protection.
- v1 user routes use `<app>.app.<base>` only; do not add a wildcard
  `*.BASE_HOST -> *.app.BASE_HOST` rewrite.
- `<base>/<app>/app` is an explicit alias. Preserve correct application static
  asset resolution under that base path.
- Workspace writes are real MinIO writes but do not dynamically compile,
  deploy, or replace celld code. Do not promise dynamic deployment until a
  separate OpenSpec capability exists.
- An unknown host is `404`; a registered application without an implemented
  Dispatcher handler is generic `502 application unavailable`. Never expose
  celld or Durable Object diagnostic state in these responses.

## Control, Admin, MCP, and monitoring law

- Every Kernel control operation needs `Authorization: Bearer <owner-key>`.
  Kernel text writes are limited to 1 MiB and paths must remain in the workspace.
- `api.<base>` provides the independent recovery route. Changing Admin must
  not weaken it.
- Admin asks for the owner key at login and keeps it in tab-scoped
  `sessionStorage` only. Never turn the UI into a secret-configuration screen.
- Admin uses one page-level header per primary view. That header owns the view
  title, description, status, and primary refresh action; content modules must
  not repeat them. Login identity, connection state, and logout belong in the
  sidebar footer rather than the page header.
- Admin primary views are separate: **Workspace** owns file tree, file detail,
  and editing; **Application routes** owns applications and domain projections.
- MCP authenticates every JSON-RPC request, including `initialize` and
  `tools/list`. It forwards the request credential only and never stores it.
- Monitoring uses a short-lived owner-authorized ticket followed by a WebSocket.
  Never put the owner key in a monitor URL, fragment, or WebSocket subprotocol.
  Current metrics are in-memory per Kernel lifecycle, not durable history.
- Application monitoring may attribute request counts, errors, in-flight work,
  and proxy latency by routed application. It must not report per-application
  memory: iweb runs one celld process and one Dispatcher deployment, while V8
  isolates and resident cells are pooled/reused below the application route.
- The overview's container-memory value is the container cgroup-v2
  `memory.current`, read directly by Kernel. Its scope matches Docker's
  container memory envelope and includes every process plus charged kernel and
  file-cache memory; it is not celld RSS or Worker heap. celld's own node sample
  may report process RSS, but v0.2 does not attribute RSS to Dispatcher branches.
- Do not interpret celld's published `0.47 MB RAM per resident cell` benchmark
  as application startup memory. It is a trivial-cell density measurement;
  inactive cells cost nearly zero, isolates can hold up to 32 resident cells,
  and the v0.2 default per-isolate V8 heap limit is 128 MiB without preallocating
  that amount. Capacity decisions require measurements against the actual app.

## Admin asset delivery law

SvelteKit writes `admin-console/build`. The image build copies that output to
`/opt/iweb/worker/admin-assets`, which must remain inside the Wrangler project
because celld v0.2 rejects an `assets.directory` outside the project root.

`worker/wrangler.jsonc` declares `ADMIN_ASSETS` with `run_worker_first: true`.
The Dispatcher must select the Admin application before the handler delegates
GET/HEAD resource reads to `env.ADMIN_ASSETS.fetch()`. This preserves one
Dispatcher deployment while keeping browser bytes outside its source bundle.

There is one asset authority. Never restore `assets.generated.js`, a base64
conversion script, or a dual-serving bridge. Preserve all three origins and
their relative-resource behavior: `admin.<base>`, `admin.app.<base>`, and
`<base>/admin/app`.

## Engineering and verification

- Prefer TypeScript for new tooling and UI code. Avoid `any`, `as any`, and
  unchecked runtime inputs; validate external inputs explicitly.
- Use `shadcn-svelte` conventions for Admin UI. Keep one intentional scroll
  owner per view; editor panes scroll internally rather than expanding the page.
- Use `IWEB_BASE_HOST` for the hostname suffix. It contains no scheme, port,
  path, or username. DNS and wildcard certificates remain deployment concerns.
- celld v0.2 must never run beside celld v0.1 against the same `iweb-cells`
  bucket. The runtime-version marker intentionally triggers one republish after
  a node-image runtime upgrade.
- For local iMac development, the remote node executes iweb; the developer
  machine only uses Portless plus a loopback SSH forward. The helper must prove
  base and known nested hostnames before reporting success.

Use the narrowest validation relevant to a change. Any Admin delivery change
must validate direct and path-alias origins, GET/HEAD, asset MIME/cache behavior,
secret absence, and the independent API recovery path. The repeatable fixtures
live under `tests/`; measured migration evidence lives in the corresponding
OpenSpec change.
