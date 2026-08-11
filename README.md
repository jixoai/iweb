# iweb

`iweb` is a single-tenant personal node: one installation serves one family.
It packages Caddy, MinIO, celld, and a small Kernel API in one container.

```text
HTTP
  |
Caddy
  +-- api.<base>                  -> Kernel API (not a celld deployment)
  +-- admin.<base>                -> registered admin celld app
  +-- <app>.app.<base>            -> registered celld app
  +-- <base>/<app>/app            -> path alias for <app>.app.<base>
  +-- <base>                      -> MinIO bucket iweb-public
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
# Set a unique CELLD_NODE, long random secrets, IWEB_BASE_HOST, and IWEB_API_TOKEN.
docker compose up -d --build
```

`IWEB_BASE_HOST` is a hostname only. Do not include `http://`, a port, or a
path. `IWEB_API_TOKEN` is independent from the admin application and is the
recovery credential for the Kernel API.

For local acceptance, send the host header explicitly:

```bash
curl -H 'Host: family.iweb.test' http://127.0.0.1:9010/
curl -H 'Host: notes.app.family.iweb.test' http://127.0.0.1:9010/
curl -H 'Host: family.iweb.test' http://127.0.0.1:9010/notes/app
curl -H 'Host: admin.family.iweb.test' http://127.0.0.1:9010/
```

The first command returns an object from MinIO. The next two invoke the celld
Worker and the same `notes` Durable Object. The admin response is a Web UI;
enter the API token from `.env` there to manage routes.

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

The registry is persisted as `iweb-system/routes.json` in MinIO. The image
seeds `admin`, `admin.app`, and the `notes.app` demo route only when that object
does not exist.

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

Each application package has an explicit manifest and an `app/` directory:

```text
projects/<project>/
├── iweb.json
└── app/
    ├── index.js
    └── public/
```

The directory is a packaging convention, not an implicit route. The manifest
and Kernel registry remain the source of truth for entrypoints, host IDs,
permissions, and aliases.

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
