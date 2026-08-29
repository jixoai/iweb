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
The system SHALL use the Kernel for public ingress, node control, and recovery; RustFS for persistent objects; and celld for Worker execution. A failure in an application route MUST NOT remove the Kernel recovery capability.

#### Scenario: Administration application is unavailable
- WHEN the Admin application cannot serve a request
- THEN the reserved Kernel API hostname remains independently reachable with a valid owner key

#### Scenario: Application runtime is unavailable
- WHEN one or all application sandboxes cannot serve requests
- THEN the reserved Kernel API hostname remains independently reachable with a valid owner key

#### Scenario: Storage engine replacement is verifiable
- WHEN an operator inspects the running node
- THEN persistent objects are served by RustFS at the pinned version recorded for the node, and MinIO is absent from the image

### Requirement: Transitional runtime does not execute arbitrary packages
The system SHALL restrict the shared celld Dispatcher to trusted image-seeded control-plane applications during migration. Arbitrary application packages MUST execute only after admission into an application sandbox and MUST NOT be compiled, loaded, or routed through the shared Dispatcher.

#### Scenario: Deployment agent requests arbitrary publishing before isolation exists
- **WHEN** MCP receives a request to execute a new application package while only the shared Dispatcher runtime is available
- **THEN** the node rejects executable publication rather than running the package in the shared deployment

#### Scenario: Deployment agent publishes after sandbox capability exists
- **WHEN** an owner-authorized deployment agent submits a valid application package
- **THEN** the node admits and executes it through an application-specific sandbox rather than the shared Dispatcher

#### Scenario: Sandbox facility is unavailable
- **WHEN** a deployment request arrives while the node cannot enforce the required application boundary
- **THEN** the node rejects executable publication rather than falling back to shared execution

### Requirement: Application sandboxes cannot reach internal node authority
The system SHALL enforce a boundary that prevents application sandboxes from directly reaching Kernel, object-store administration, runtime operator or peer listeners, host loopback services, and private endpoints of other application sandboxes. Application-controlled code MUST NOT be able to weaken this boundary.

#### Scenario: Application probes node-local endpoints
- **WHEN** an application attempts to connect to a protected node-local address or listener
- **THEN** the connection is denied without relying on cooperation from the application code

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
