<!-- 用户原始需求（2026-08-13）：记录 Admin 原生静态资产迁移的可复验、无凭据验收证据。 -->
<!-- 正交意图：记录本地构建证据；记录隔离节点行为；记录 iMac 部署与恢复入口。 -->

# Acceptance evidence

Measured on 2026-08-13 against celld v0.2.0, OCI revision
`3f22aedd1ea4d413b93e84afb1ce385f04be84f1`.

## Build and isolated runtime

```text
Admin svelte-check       0 errors, 0 warnings
Admin unit tests         4 passed, 0 failed
Admin handler tests      6 passed, 0 failed
celld asset fixture      passed
iweb image build         passed

Dispatcher bundle        16.54 KiB (gzip 5.09 KiB)
Native Admin assets      25 files / 1311.97 KiB
Asset binding            env.ADMIN_ASSETS (Assets)
Generated base64 module  absent
Conversion script        absent
```

The isolated full-node acceptance used a random node identity, random test
credentials, a temporary volume, no published host port, and automatic cleanup.

```text
admin.<base>             200 HTML
admin.app.<base>         200 HTML
<base>/admin/app         200 HTML, base=/admin/app/
immutable JS direct      200, text/javascript, immutable cache
immutable JS path alias  200, text/javascript, immutable cache
immutable JS HEAD        200, ETag present, no body
API without owner key    401
API with owner key       200
browser asset scan       clean
```

## iMac test node

The existing Compose service `iweb-local` was inspected before replacement. It
was the sole celld v0.2 node using the `iweb_iweb-data` volume. The reserved API
status route returned `200` with owner authorization before deployment.

Compose then replaced that single container with the native-assets image; the
persistent volume remained mounted at `/data`, and no old/new celld processes
were run concurrently against its bucket.

```text
post-deploy API without owner key  401
post-deploy API with owner key     200, runtime=celld
admin.<base>                       200
admin.app.<base>                   200
<base>/admin/app                   200, base=/admin/app/
immutable JS direct/path alias     200 / 200
immutable JS content type          text/javascript; charset=utf-8
immutable JS cache                 public, max-age=31536000, immutable
immutable JS HEAD                  200, ETag present
persistent data volume             preserved
```

No credential value is recorded in this file, command output, URL, or fixture.
