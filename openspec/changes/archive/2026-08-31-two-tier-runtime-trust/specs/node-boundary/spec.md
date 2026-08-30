## MODIFIED Requirements

### Requirement: Node services have distinct responsibilities
The node container SHALL run the trusted control plane and the two application tiers: the Rust Kernel owns routing, admission, recovery, and control; RustFS serves storage; per-app celld processes serve image-seeded trusted applications; the wasm supervisor and `iweb-wasmd` processes serve admitted untrusted components. The supervisor and its relay run inside the node container as a dedicated non-root service user; the node requires no host-machine sandbox prerequisites (no host systemd unit, no host Podman, no host socket mounts, no host-installed binaries).

#### Scenario: Node starts without host sandbox prerequisites
- **WHEN** the node container starts on a Docker host that provides only the published port and the data volume
- **THEN** the Kernel, RustFS, celld fleet, supervisor, and relay all start from image content, and wasm execution readiness reflects only in-container state

#### Scenario: Administration application is unavailable
- **WHEN** the admin console assets or the admin celld process are unavailable
- **THEN** the Kernel keeps routing every other host and the independent api recovery route remains reachable

#### Scenario: Application runtime is unavailable
- **WHEN** a celld process or wasm execution is down
- **THEN** its hosts return the generic bounded 502 and unrelated applications are unaffected

#### Scenario: Storage engine replacement is verifiable
- **WHEN** the object storage engine is replaced by a compatible implementation behind the same loopback endpoint and bucket contract
- **THEN** node services keep their responsibilities and no application-facing boundary changes

### Requirement: Transitional runtime does not execute arbitrary packages
The node's law SHALL be permanent two-tier trust, not a transitional state: arbitrary, network-sourced, or AI-generated application packages execute only after wasm admission into the engine-enforced tier. celld applications execute only from image-seeded deployments built by the owner; there is no future celld package-admission capability to unlock.

#### Scenario: Deployment agent publishes an untrusted package
- **WHEN** an agent submits an arbitrary package for admission
- **THEN** it must go through wasm admission with the capability matrix and engine limits; no celld path exists

#### Scenario: Owner upgrades trusted fleet applications
- **WHEN** the owner wants new celld application code
- **THEN** the owner builds it into a new node image; runtime admission is not involved

#### Scenario: Deployment agent requests arbitrary publishing before isolation exists
- **WHEN** an agent asks for package admission while wasm publication gates are closed
- **THEN** admission stays fail-closed with the stable gate reasons; there is no less-isolated fallback path

#### Scenario: Deployment agent publishes after sandbox capability exists
- **WHEN** wasm publication is enabled and a package passes the capability matrix
- **THEN** it executes under engine-enforced limits as a wasm application, never as celld

#### Scenario: Sandbox facility is unavailable
- **WHEN** the wasm execution supervisor is unreachable
- **THEN** wasm admission and lifecycle operations fail bounded and visitor traffic for wasm hosts is the generic 502; celld fleet applications keep serving

### Requirement: Application sandboxes cannot reach internal node authority
A wasm application SHALL have no capability path to internal node authority: components receive no socket, TLS, or filesystem capability, their egress is host-mediated, and their data plane is the host service interfaces. The Kernel control API, RustFS, and operator listeners are loopback-only inside the node container and never routed to applications. The residual trust in the wasmd/Wasmtime host is explicit and recorded; no second container boundary is claimed.

#### Scenario: Component attempts a direct internal connection
- **WHEN** a component attempts any non-matrix import or a direct dial
- **THEN** admission or instantiation fails closed and no path to internal authority exists

#### Scenario: Application probes node-local endpoints
- **WHEN** a wasm application's permitted outbound request targets a node-internal address through the host-mediated path
- **THEN** the mediation applies reserved-address policy and the request fails closed; the component never obtains a raw socket to retry with
