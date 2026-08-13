## Context

See [proposal.md](./proposal.md) for the motivation and [the Administration Console delta](./specs/administration-console/spec.md) for the required behavior. The current image invokes `scripts/build-admin.sh.ts`, turns the SvelteKit output into `assets.generated.js`, and imports that generated map from the Admin Worker. This duplicates and decodes every asset in JavaScript memory.

celld v0.2 supports a Wrangler-compatible static asset directory with a binding, HTML handling, 404 behavior, `run_worker_first`, `_headers`, and `_redirects`. The node already deploys one Dispatcher to a fleet bucket and must retain the existing system-host and path-alias routing behavior.

## Goals / Non-Goals

**Goals:**

- Deploy Admin build output as celld-native static assets.
- Preserve direct system host, explicit app host, and path-alias access.
- Maintain correct MIME/cache semantics and the no-secret browser-asset boundary.
- Remove generated base64 asset source and its image-build conversion.

**Non-Goals:**

- Dynamically publish arbitrary workspace code.
- Alter the single-Dispatcher deployment model.
- Change the owner-key login, Kernel API, route registry, or MinIO workspace model.
- Add durable monitoring or tenant isolation.

## Decisions

### Use celld native static assets as the Admin asset authority

The SvelteKit static build directory becomes the deployment input configured in `wrangler.jsonc`. A Worker asset binding serves Admin resources and lets application code perform only route/base-path adaptation where needed.

Alternative considered: keep the generated JavaScript map and decode lazily. Rejected because it still duplicates build artifacts in source, adds JavaScript parse/decode work, and gives no native cache/store semantics.

### Keep the Dispatcher responsible only for application selection

The Dispatcher continues to select `admin`, `mcp`, `notes`, or an unavailable application from the registered host. The Admin handler delegates resource lookup to the native asset binding and only resolves the root and `/admin/app` base-path behavior.

Alternative considered: create a second celld deployment for Admin. Rejected because iweb v1 intentionally has one Dispatcher deployment and central host-to-app dispatch.

### Preserve external origin and alias behavior explicitly

The deployed Admin output must support a root origin (`admin.<base>` and `admin.app.<base>`) and a mounted origin (`<base>/admin/app`). The asset lookup and generated HTML base path must be tested for both forms; an implementation must not rely on a hidden browser redirect that changes the administrator's visible origin.

Alternative considered: support only `admin.app.<base>`. Rejected because `admin.<base>` is the operator-facing system alias and the path alias is part of the documented project layout.

### Remove the conversion build path atomically

Once the native asset deployment is proven, delete `assets.generated.js`, remove the conversion script from Docker build stages, and remove all imports/references. The repository must not keep both delivery systems active because that obscures the source of truth and restores unnecessary image size.

## Risks / Trade-offs

- [Asset binding semantics differ from the current hand-written responder] → verify HTTP GET/HEAD, MIME, immutable cache behavior, unknown paths, direct app hosts, and path aliases against the OpenSpec scenarios.
- [SvelteKit output assumes root-relative paths] → configure its static adapter/base behavior or perform narrowly scoped HTML-base adaptation; test a cold page load at every supported origin.
- [A failed migration could make Admin unavailable] → retain `api.<base>` recovery, validate the staged image before replacement, and roll back by redeploying the prior known-good image/data combination.
- [Static assets become part of the celld deployment payload] → accept deployment-time asset upload in exchange for avoiding Dispatcher bundle duplication and Worker-memory decoding.

## Migration Plan

1. Inspect celld v0.2 static-asset behavior against the exact pinned runtime and add the asset configuration plus binding.
2. Adapt the Admin application to resolve the supported origins through the binding; remove base64 asset lookup.
3. Remove generation from the image build and delete the generated module only after direct, app-host, and path-alias acceptance passes.
4. Build and deploy the image to the iMac node after the prior container has stopped; verify API recovery remains reachable, then verify Admin login and static resource loading.
5. If acceptance fails, redeploy the previous image with the existing persistent data volume and use `api.<base>` recovery as needed. Do not mix different celld runtime formats against the same fleet bucket concurrently.
