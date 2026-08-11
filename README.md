# iweb

`iweb` is a single-tenant personal node: one installation serves one family.
It packages Caddy, MinIO, and [celld](https://github.com/denoland/celld) in one
container, with one Docker volume as its durable state.

```text
HTTP
  |
Caddy
  +-- <domain>                 -> MinIO bucket iweb-public
  +-- <app>.app.<domain>       -> celld Worker
                                      |
                                 Durable Object SQLite state
                                      |
                                 MinIO bucket iweb-cells
```

## Run on iMac

```bash
cp .env.example .env
# Set long random secrets, a domain, and a unique permanent CELLD_NODE in .env.
docker compose up -d --build
```

For the checked-in local configuration, use host headers because
`family.iweb.test` is not a public DNS name:

```bash
curl -H 'Host: family.iweb.test' http://127.0.0.1:9010/
curl -H 'Host: notes.app.family.iweb.test' http://127.0.0.1:9010/
```

The first command returns an object from MinIO. The second invokes the celld
Worker and increments the Durable Object SQLite counter named `notes`.

`CELLD_NODE` is an installation identity, not a secret. It must remain stable
across restarts so celld can renew the same Durable Object ownership lease.
Choose a different value for every independently deployed iweb node.

## Security Boundary

The installation, not the container, is the tenant boundary. Do not run
mutually untrusted code in this image: celld's S3 bucket is fleet administrator
authority. The MinIO API, Console, celld peer port, Caddy Admin API, and Docker
socket are not published.

## Current Scope

celld currently runs one Worker deployment per fleet. `worker/` is therefore the
node's application bundle. A future manual deployment command can compile an
`apps/` directory into this dispatcher and publish a new celld release; it must
restart the node because celld nodes load deployments at startup.

The Caddyfile is intentionally HTTP-only for local acceptance. Publishing
`*.app.<username>.iweb.xin` requires DNS-01 wildcard certificate automation
and a clear decision about whether Caddy or 1Panel owns ports 80 and 443.
