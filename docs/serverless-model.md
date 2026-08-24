# iweb Serverless Model

This note records the first-party references used for the iweb project shape.
The common abstraction is explicit rather than directory-discovered:

```text
project
  -> entrypoint
  -> route table
  -> static asset root
  -> deployment unit
```

## Cloudflare Workers

Cloudflare's [CLI guide](https://developers.cloudflare.com/workers/get-started/guide/)
(updated 2026-04-23) scaffolds `wrangler.jsonc` and a module Worker entrypoint
such as `src/index.js`; the `main` field names the entrypoint.

The [Static Assets documentation](https://developers.cloudflare.com/workers/static-assets/)
(updated 2026-07-03) configures an explicit `assets.directory` and deploys
Worker code plus static assets as one tightly integrated deployment unit. Its
[routing guide](https://developers.cloudflare.com/workers/static-assets/routing/)
(updated 2026-04-23) distinguishes asset-only and Worker-first routing, so
asset precedence is an explicit architectural choice.

The [Routes documentation](https://developers.cloudflare.com/workers/configuration/routing/routes/)
(updated 2026-06-01) models URL patterns as mappings to Workers. It recommends
Custom Domains when the Worker is the application origin.

## Vercel Functions

The [Functions documentation](https://vercel.com/docs/functions) (modified
2026-07-15) shows file-convention entrypoints such as `api/hello.ts` and
framework entrypoints such as `app/api/hello/route.ts`.

The [Project Configuration](https://vercel.com/docs/project-configuration)
(modified 2026-06-16) keeps build, function, rewrite, output, and region
overrides in one versioned `vercel.json` or `vercel.ts` file.

## Deno Deploy

The current [Deno Deploy documentation](https://docs.deno.com/deploy/) is on a
new platform. The legacy [Classic documentation](https://docs.deno.com/deploy/classic/)
(modified 2026-03-19) says Classic is sunsetting on 2026-07-20, so its old
single-file `main.ts` convention is historical context rather than an iweb
target constraint.

## iweb Decision

iweb keeps an explicit `iweb.json`, an `app/` implementation directory, and a
Kernel-owned host registry. The checked-in Dispatcher is one transitional celld
deployment unit for image-seeded prototype handlers; the registry decides which
registered host ID can reach it. Arbitrary packages must not be added to that
shared deployment. Future publishing requires one independently enforceable
application sandbox while leaving DNS and certificate management outside the
application boundary.
