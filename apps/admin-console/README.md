# iweb Admin Console

The browser administration surface for an iweb node.

```text
SvelteKit + shadcn-svelte
        |
        +-- sessionStorage: administrator owner key for this browser tab only
        +-- api.<base>: reserved Kernel API
        +-- <app>.app.<base>: registered celld applications
```

## Development

```bash
bun install
bun run dev
bun run check
bun test
bun run build
```

The static build output is `build/`. SvelteKit emits relative resource URLs so
the same output can load at both direct Admin hosts and the `/admin/app/`
mount. The celld Admin handler adds the mounted base to HTML only for path-alias
requests; immutable resource cache policy is deployed from `static/_headers`.

```bash
bun run build
```

The image build copies this output to `apps/workers/admin/admin-assets/`, the in-project
native static-asset input configured by `../workers/admin/wrangler.jsonc` (celld v0.2
requires `assets.directory` to remain inside the Wrangler project). Do not
convert it into JavaScript source or keep a second asset authority in `apps/workers/`.

Do not use build-time environment variables for `IWEB_API_TOKEN` or any other
node secret. The client derives the API origin from the active Admin host and
keeps the administrator login key only in the current tab's `sessionStorage`.
