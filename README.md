# iweb

![iweb Node Mesh](./admin-console/src/lib/assets/favicon.svg)

`iweb` 是一个面向个人与家庭的单节点：一次安装服务一个信任边界。
它把 Caddy、MinIO、celld 和一个小型 Kernel API 放进同一个容器；这不是给互不信任的租户运行代码的多租户沙箱。

```text
HTTP
  |
Caddy
  +-- api.<base>                  -> Kernel API (not a celld deployment)
  +-- admin.<base>                -> registered admin celld app
  +-- <app>.app.<base>            -> registered celld app
  +-- <base>/<app>/app            -> path alias for <app>.app.<base>
  +-- <base>                      -> MinIO workspace files
                                      |
                                  celld Dispatcher
                                      |
                                Durable Object SQLite
                                      |
                                  MinIO iweb-cells
```

## Run on iMac

```bash
cp .env.example .env
# Set a unique CELLD_NODE, long random secrets, IWEB_BASE_HOST, IWEB_CONTROL_ORIGIN, and IWEB_API_TOKEN.
docker compose up -d --build
```

`IWEB_BASE_HOST` is a hostname only. Do not include `http://`, a port, or a
path. `IWEB_API_TOKEN` is independent from the admin application and is the
recovery credential for the Kernel API.

The internal port topology is:

```text
MinIO API             127.0.0.1:9000   container-internal
Kernel API            127.0.0.1:7070   container-internal
celld public Worker   127.0.0.1:8787   container-internal
celld peer/operator   127.0.0.1:8788   container-internal, never published
Caddy                 :8080            the only published container port
```

MinIO, Kernel API, and celld are deliberately not published by Docker. Caddy
is the only external ingress and routes by hostname.

`IWEB_CONTROL_ORIGIN` is the node address (including the published Caddy port)
that celld uses for authenticated MCP control calls back into the Kernel. For a
LAN iMac it can be `http://192.168.2.13:9010`; it is not a second published
service port.

## Admin Console

`admin.<base>` and `admin.app.<base>` serve the same replaceable celld app.
It is implemented in [`admin-console/`](./admin-console) as a SvelteKit static
application using shadcn-svelte. It opens on an administrator login screen:
the bootstrap owner key from `IWEB_API_TOKEN` is entered once to establish an
administrator session. The browser derives `api.<base>` from its current
origin and stores that key only in the current tab's `sessionStorage`.

Admin 的 SvelteKit 构建产物由 celld v0.2 作为原生静态资产部署。
`ADMIN_ASSETS` binding 是唯一的浏览器资产权威；Dispatcher 只选择应用，Admin
handler 只负责 GET/HEAD 资源查找及 `/admin/app/` HTML base 适配。指纹资源通过
`_headers` 使用 immutable 缓存，入口 HTML 使用 `no-cache`。仓库与镜像都不再包含
generated base64 asset module 或转换脚本。

该架构由
[`serve-admin-with-native-assets`](./openspec/changes/archive/2026-08-13-serve-admin-with-native-assets/)
定义，并保留 `admin.<base>`、`admin.app.<base>` 与 `<base>/admin/app` 三个入口。

Run the console independently while developing it:

```bash
cd admin-console
bun install
bun run dev
bun run check
bun test
```

To generate the native static output locally:

```bash
cd admin-console
bun run build
```

Docker performs the same build from the lockfile in a Linux stage, copies
`admin-console/build` to `/opt/iweb/worker/admin-assets`, and lets `celld deploy`
upload that directory separately from the Dispatcher bundle. The output is not
checked into `worker/`; no administrator key or node configuration may be
compiled into browser assets.

## Portless Development

Portless can provide a stable HTTPS development origin in front of Caddy. The
repository includes a Compose override that changes only the base hostname:

```bash
portless alias test.iweb 9010
portless proxy stop
portless proxy start --wildcard
docker compose -f docker-compose.yml -f docker-compose.portless.yml up -d --build
```

Then use:

```text
https://test.iweb.localhost/
https://admin.test.iweb.localhost/
https://api.test.iweb.localhost/v1/status
https://notes.app.test.iweb.localhost/
https://test.iweb.localhost/notes/app
```

`--wildcard` is required for the nested `admin.test...` and
`notes.app.test...` hosts to fall back to the `test.iweb` alias. Portless
usually syncs these names automatically; Safari may require:

```bash
portless hosts sync
```

### Remote iMac Node

Portless aliases only local ports; it cannot directly target an iMac hostname.
Use the included script to create a loopback-only forward, then make Portless
route the local HTTPS names into that forward:

```bash
cp .env.portless-imac.example .env.portless-imac
# Confirm IWEB_REMOTE_HOST, then remotely deploy and connect.
bun scripts/portless-imac.bun.ts
```

The default `up` command uses the local `remote-mini` Docker context to build
and start iweb on the iMac, with `IWEB_BASE_HOST` injected into the Compose
override. It then starts an SSH local forward from `127.0.0.1:19010` to the
iMac's `127.0.0.1:9010`. The script itself is Bun/TypeScript and uses Bun's
shell API for Docker, Portless, curl, and process orchestration; SSH is only
the persistent authenticated transport. The local forward remains private.
The script enables
Portless wildcard mode, registers
`test.iweb.localhost -> 127.0.0.1:19010`, and keeps the forward alive until
you press `Ctrl-C`. On the first run, macOS may ask for your password to
restart the root-owned Portless listener on `443` in wildcard mode. Use
`bun scripts/portless-imac.bun.ts connect` when the remote container is already
current and only the local ingress needs to be recreated. The script exits
unless it can reach all nested routes through HTTPS.

If Portless was previously started without wildcard mode, run the Bun script
from your interactive Terminal once so it can answer the `sudo` prompt. It
stops the old listener and restarts it with `--wildcard`; there is no manual
host-file editing step. The script does not rely on `portless service status`
for wildcard detection; it confirms that `admin.<base>` reaches iweb over
HTTPS before declaring the ingress ready. Chrome and Firefox resolve nested
`.localhost` names without `/etc/hosts`; if Safari does not, run
`sudo portless hosts sync` separately.

The script explicitly registers the base, `admin`, `api`, `mcp`, `admin.app`,
and `notes.app` hostnames to the same local forward. Therefore `portless list`
shows the known iweb routes; wildcard mode remains enabled for future dynamic
application hostnames.

To return to the LAN `.test` setup, run the normal Compose command without the
override file.

For local acceptance, send the host header explicitly:

```bash
curl -H 'Host: family.iweb.test' http://127.0.0.1:9010/
curl -H 'Host: notes.app.family.iweb.test' http://127.0.0.1:9010/
curl -H 'Host: family.iweb.test' http://127.0.0.1:9010/notes/app
curl -H 'Host: admin.family.iweb.test' http://127.0.0.1:9010/
curl -H 'Host: family.iweb.test' http://127.0.0.1:9010/admin/app
```

The first command returns an object from MinIO. The next two open the Notes Web
application through its hostname and path alias. Notes serves HTML at `/` and
JSON at `/api/notes`; it persists notes in its own Durable Object SQLite and
does not expose runtime debug counters. A registered application without an
implemented handler returns `502 application unavailable`; an unknown host
returns `404`. The admin response starts at an administrator login screen;
enter the bootstrap owner key from `.env` to open the management console.

The Kernel API is available through the reserved host:

```bash
curl -H 'Host: api.family.iweb.test' \
  -H 'Authorization: Bearer <IWEB_API_TOKEN>' \
  http://127.0.0.1:9010/v1/routes
```

To restore the image-seeded Dispatcher, including the `admin` application,
publish it again and restart the node through the Kernel API:

```bash
curl --request POST -H 'Host: api.family.iweb.test' \
  -H 'Authorization: Bearer <IWEB_API_TOKEN>' \
  http://127.0.0.1:9010/v1/recover/admin
```

The route registry is persisted as `iweb-system/routes.json` in MinIO. The
image seeds protected `admin`, `admin.app`, `mcp`, and `mcp.app` mappings when
missing, plus the `notes.app` demo route. It seeds application files only when
the corresponding `<app>/iweb.json` is absent from the workspace.

## Host IDs

The full hostname is always constructed as:

```text
<host_id>.<IWEB_BASE_HOST>
```

`api`, `admin`, and `mcp` are reserved host ID prefixes. The Kernel API owns
`api` directly; `admin` is a system alias for the `admin.app` celld application.
Unknown host IDs return `404`; there is no implicit wildcard execution.

User celld routes currently use the explicit `<app>.app` namespace. The
registry maps that host ID to an app name, so aliases and future namespaces can
be added without changing DNS semantics. DNS and certificates remain an
external deployment concern: a `*.app.<base>` wildcard is required for app
hosts, in addition to `*.<base>` for one-label system hosts.

## Project Shape

The node owns one MinIO-backed workspace. There is no product-level
"private/public bucket" split: application source, web assets, and ordinary
files live together. Secrets remain environment variables or Kernel API
credentials and must never be placed in the workspace.

```text
/
├── index.html                 root-site object served by <base>
├── admin/{iweb.json,app/}
├── mcp/{iweb.json,app/}
├── notes/{iweb.json,app/}
└── arbitrary files
```

Each application directory has an explicit manifest and an `app/` directory:

```text
<app>/
├── iweb.json
└── app/
    ├── index.js
    └── public/
```

The directory is a packaging convention, not an implicit route. The manifest
and Kernel registry remain the source of truth for entrypoints, host IDs,
permissions, and aliases. The current Dispatcher is image-deployed: workspace
edits are real object storage edits, but do not dynamically compile or publish
an app yet.

## Current Capability Boundary

目前已经实现的能力包括：统一 MinIO 工作区、显式应用路由、`admin` 和 `mcp`
系统应用、owner-key 控制面、Notes 示例应用，以及基于 WebSocket 的进程生命周期监控。以下边界同样重要：

- `api.<base>` 是不可替换的 Kernel 恢复与控制入口；`admin` / `mcp` 是受保护但可见的系统应用。
- 管理员需要在 Admin 登录页输入 `IWEB_API_TOKEN`；浏览器只在当前标签页的 `sessionStorage` 保存它。
- 指标是当前 Kernel 生命周期内的内存、工作区与应用请求投影，不是历史监控系统。
- 写入工作区不会自动部署应用代码；通用发布工作流尚未实现。
- 公开部署仍需要由运营者准备 DNS、`*.<base>` 与 `*.app.<base>` 的通配证书，以及 Caddy/1Panel 对 80、443 的入口归属。

完整、可验证的现状规格在 [`openspec/specs/`](./openspec/specs/)；Admin 原生静态资产迁移及无凭据验收证据见 [`serve-admin-with-native-assets`](./openspec/changes/archive/2026-08-13-serve-admin-with-native-assets/)。

## MCP

`mcp.<base>/mcp` is an ordinary celld application exposed through a protected
system route. Every request must carry the owner key as `Authorization: Bearer
<IWEB_API_TOKEN>`; unauthenticated `initialize`, `tools/list`, and `tools/call`
requests are rejected with `401` before JSON-RPC capabilities are returned.
The tools list/read/write/delete workspace objects and list/register domain
mappings. The Worker forwards the key to the Kernel per request and never
stores it. The workspace view therefore shows `admin` and `mcp` alongside user
applications.

The Node Mesh icon is the production iweb identity and is shared by the
favicon, login screen, sidebar, and this README.

## Security Boundary

The installation, not the container, is the tenant boundary. Do not run
mutually untrusted code in this image: celld's S3 bucket is fleet
administrator authority. The MinIO API, Console, celld peer port, Caddy Admin
API, and Docker socket are not published.

The Kernel API is intentionally outside the celld deployment. Replacing the
admin app cannot remove the API recovery path. Kernel changes require an image
rebuild and restart. The current API manages host routes and image-seed
recovery; generic application package publishing is the next control-plane
slice.

## Release Model

celld currently runs one Worker deployment per fleet. The Dispatcher is the
single deployment entrypoint and dispatches registered apps. In this v1 model,
the future generic publishing flow will rebuild the Dispatcher bundle, run
`celld deploy`, and restarts the node. celld Worker Loader remains an
experimental future path and is not the management-plane trust root.

The Caddyfile is intentionally HTTP-only for local acceptance. Publishing
`*.app.<base>` requires DNS-01 wildcard certificate automation and a clear
decision about whether Caddy or 1Panel owns ports 80 and 443.

## celld Runtime

iweb pins celld `v0.2.0`. celld now separates its public Worker listener from
its unauthenticated peer/operator listener; iweb binds both to loopback and
publishes only Caddy. During a v0.1-to-v0.2 image upgrade, iweb republishes its
single Dispatcher once after the old container has stopped. Do not operate a
mixed v0.1/v0.2 celld fleet against the same `iweb-cells` bucket.
