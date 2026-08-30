<!-- 用户原始需求（2026-08-13）：以一个容器交付适合个人/家庭的低成本 iweb 节点，并先沉淀规范。 -->

## Purpose

定义 iweb 单节点的信任边界、进程入口与网络暴露规则，使个人部署既可维护又不会意外暴露节点内部能力。

## Requirements

### Requirement: Internal operator listener remains isolated
The system SHALL bind celld's operator/peer listener to loopback only. The Kernel ingress MUST NOT route a public hostname or path to that listener.

#### Scenario: External caller attempts operator access
- WHEN a caller uses a public iweb hostname
- THEN the caller cannot reach celld's internal/operator listener through the Kernel ingress or a published Docker port

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

### Requirement: Kernel is the only published ingress
The system SHALL publish the Kernel process as the only container network ingress, owning the single published port and performing host-based public routing itself. The object storage service, the Kernel control listener, and both celld listeners MUST remain un-published. The node image MUST NOT contain a Caddy binary or Caddyfile.

#### Scenario: External connection reaches node services
- WHEN a client connects through the node's published container port
- THEN the request first reaches the Kernel ingress router and no direct Docker mapping exists for object storage, the Kernel control listener, or either celld listener

#### Scenario: Node image is free of the retired ingress process
- WHEN an operator inspects the node image
- THEN no Caddy binary or Caddyfile is present and public routing is served by the Kernel binary

### Requirement: Internal control-plane calls stay on loopback
The system SHALL route celld-to-Kernel control calls through the Kernel's loopback control listener directly. Header-based internal-control routing through the published ingress MUST NOT exist.

#### Scenario: Worker outbound control call
- WHEN a celld Worker calls a Kernel control endpoint
- THEN the call targets the loopback control listener and does not transit the published ingress or rely on an internal-control header

### Requirement: Node resource envelope budget
The system SHALL keep the node's idle memory envelope at or below 240MB, measured as the sum of per-process anonymous resident memory (RssAnon) sampled while the node is idle (no in-flight requests) after at least one fresh storage-lease renewal cycle, and idle CPU near zero. Reclaimable file-backed page cache (RssFile) MUST NOT be counted toward the budget. The node image MUST pin the storage engine's adaptive buffer profile (RUSTFS_BUFFER_PROFILE) to a deployment-chosen value so lease-renewal writes do not grow steady-state anonymous memory without bound; the pin MUST NOT be overridable by environment at runtime. Per-process memory MUST be a real measurement, never a synthesized value; zero is valid only for a proven zero. (Owner ruling 2026-08-20: the envelope describes nodes that use the right technique and every savable byte saved — measured reality settles the number; the previous 160MB figure was calibrated on a verification node and is superseded by lima 159 / cloud 162.3 / iMac 231.3MB measurements in .agents/evidence/memory-budget-amendment.md.)

#### Scenario: Idle node memory measurement
- WHEN the node is idle and an operator samples per-process anonymous RSS
- THEN the sum is at or below the budget and each value is a real RssAnon measurement from the process table, with file-backed page cache excluded

#### Scenario: Storage engine buffer profile is pinned
- WHEN the node's storage engine process starts
- THEN its adaptive buffer profile is the deployment-pinned value rather than the upstream default, keeping steady-state anonymous memory flat under lease-renewal writes
