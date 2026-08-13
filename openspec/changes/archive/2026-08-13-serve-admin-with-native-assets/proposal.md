## Why

Admin is currently compiled into a generated JavaScript module as base64 data. That delivery path duplicates asset bytes, incurs JavaScript parsing and base64 decoding in Worker memory, and makes a large console build part of the Dispatcher bundle rather than a static-resource deployment.

## What Changes

- Deliver Admin static resources through celld's native static-asset facility instead of an embedded base64 JavaScript map.
- Preserve the three Admin entry routes: `admin.<base>`, `admin.app.<base>`, and `<base>/admin/app`.
- Preserve the browser credential boundary: no owner key or node secret is included in deployed Admin assets.
- Remove the generated asset module and its conversion step from the final node-image build.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `administration-console`: change the Admin resource-serving contract from embedded Dispatcher data to native deployed static assets while retaining all supported origins and credential protections.

## Impact

- `admin-console/`: static build output contract and route-base verification.
- `worker/wrangler.jsonc`, Admin application routing, and Dispatcher build: native asset configuration and asset lookup.
- `scripts/build-admin.sh.ts`, `worker/apps/admin/app/assets.generated.js`, and `Dockerfile`: remove the base64 conversion path.
- `README.md` and `AGENTS.md`: document the new delivery architecture after implementation.
