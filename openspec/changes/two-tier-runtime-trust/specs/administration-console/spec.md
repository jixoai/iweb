## MODIFIED Requirements

### Requirement: Admin console application reachability
The Admin console SHALL remain reachable on its three origins (`admin.<base>`, `admin.app.<base>`, `<base>/admin/app`) with relative-resource behavior preserved. Application lists and detail views label each application's runtime kind (celld image-seeded vs wasm admitted); celld entries present their supervised process state and watchdog soft limits, and no celld version-lifecycle controls exist.

#### Scenario: Administrator opens the system hostname
- **WHEN** an administrator opens `admin.<base>`
- **THEN** the console serves from the celld admin assets with relative resources resolving under that origin

#### Scenario: Administrator opens the path alias
- **WHEN** an administrator opens `<base>/admin/app`
- **THEN** the console serves the same application with assets resolving under the alias base path

#### Scenario: Browser requests an immutable Admin resource
- **WHEN** the browser requests a hashed immutable asset
- **THEN** it is served with its immutable cache semantics and no worker-side asset duplication

#### Scenario: Administrator distinguishes runtime tiers
- **WHEN** an administrator opens the application routes view
- **THEN** each application row and its detail show the runtime kind, and celld entries expose supervision/limit state instead of version lifecycle controls
