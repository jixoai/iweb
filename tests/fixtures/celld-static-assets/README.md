<!-- 用户原始需求（2026-08-13）：以可复验的本地 fixture 证明 pinned celld v0.2 静态资产行为。 -->

# celld v0.2 static-assets fixture

This fixture is intentionally independent from the Admin build. It proves the
configuration and runtime assumptions required by
`serve-admin-with-native-assets` against the exact celld v0.2.0 image pinned in
the root `Dockerfile`:

- `assets.directory` uploads a native static asset set;
- `assets.binding` exposes `env.ASSETS.fetch(request)`;
- `run_worker_first: true` keeps the Dispatcher in front of existing assets;
- the binding preserves GET/HEAD, content type, ETag, and `_headers` overrides.

Run it against an isolated test bucket. Never point this fixture at the iweb
node's `iweb-cells` bucket because a celld fleet has one active deployment.
