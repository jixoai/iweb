## 1. Confirm celld static-asset integration

- [x] 1.1 Verify the pinned celld v0.2 static-asset configuration, binding behavior, cache behavior, and `run_worker_first` semantics against upstream documentation and a focused local fixture.
- [x] 1.2 Define the Admin build output directory and SvelteKit asset/base-path settings for direct hosts and `/admin/app` without generating JavaScript asset data.

## 2. Replace the Admin delivery path

- [x] 2.1 Configure the Dispatcher deployment to include the Admin static-asset directory and expose a typed native asset binding to the Admin application handler.
- [x] 2.2 Update the Admin application handler to serve root, direct-host, and path-alias resources through the native asset store while preserving GET/HEAD, MIME, and cache behavior.
- [x] 2.3 Remove `assets.generated.js`, `scripts/build-admin.sh.ts`, all generated-asset imports, and Docker build stages that only support base64 conversion.

## 3. Validate node behavior and security

- [x] 3.1 Run Admin console type checks, unit tests, and static build; build the iweb image and inspect it to confirm no generated base64 Admin asset module remains.
- [x] 3.2 Verify `admin.<base>`, `admin.app.<base>`, and `<base>/admin/app` including cold-load immutable assets, correct content types, cache headers, and login flow.
- [x] 3.3 Verify no owner key or node secret appears in Admin HTML, JavaScript, CSS, source maps, image layers, or request URLs.
- [x] 3.4 Deploy to the iMac test node, verify the reserved API recovery path before and after Admin acceptance, and record the measured result without credentials.

## 4. Synchronize project documentation

- [x] 4.1 Update README and AGENTS to describe native static asset delivery after the implementation is accepted.
- [x] 4.2 Re-run strict OpenSpec validation and archive this change only after its implementation tasks and acceptance evidence are complete.
