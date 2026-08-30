# application-sandbox Specification

## Purpose
定义不可信应用从包准入到运行、更新和回滚的强制安全边界，使任一应用都不能越权影响其他应用或节点控制面。

## Requirements

### Requirement: Publication admits an immutable application version
The system SHALL validate a wasm application package and its declared runtime policy before creating an immutable application version. A rejected package MUST NOT create or replace an active version, start executable code, or receive application traffic. Runtime admission exists for runtime kind `wasm` only; celld applications have no runtime admission path and enter the node exclusively through the node image. For `wasm`, the validated policy SHALL include the component world, the import capability matrix, and the complete admission transaction defined by `wasm-application-runtime`; the Kernel remains the authority that creates the admitted version and records its policy.

A wasm submission's staging object or content-addressed object prefix alone SHALL NOT be an immutable application version. A wasm version is visible to any preparation, route selection, rollback selection, or ordinary version read only when the wasm admission transaction's single `AdmittedVisible` predicate is true, exactly as defined by `wasm-application-runtime`. The Kernel SHALL use the admission journal to replay or collect incomplete work; it MUST NOT expose an intermediate state as a version.

#### Scenario: Package admission succeeds
- **WHEN** an owner-authorized deployment request supplies a wasm package and policy that satisfy the node's admission contract and `AdmittedVisible` becomes true
- **THEN** the Kernel creates one immutable visible version identity that can be prepared for that application

#### Scenario: Package admission fails
- **WHEN** the package, manifest, requested policy, or any admission transaction step fails validation
- **THEN** the system returns structured rejection details without executing the package or changing the active version

#### Scenario: Wasm package fails the capability matrix
- **WHEN** a wasm package declares or embeds imports outside the node's allowed capability matrix, or its declaration differs from the discovered closure
- **THEN** the system returns structured rejection details and no version becomes visible, nothing is materialized for execution, and nothing is executed

#### Scenario: Completion marker exists without a control-database version
- **WHEN** a node restarts after a wasm object completion marker was written but before the Kernel control-database version row committed
- **THEN** the prefix is not a visible version; the admission journal either completes the same token idempotently or garbage-collects it after proving no committed row references it, and no route, preparation, or rollback may observe the hidden row

#### Scenario: Database version commits before materializer handoff completes
- **WHEN** a node restarts after the Kernel has committed the hidden admission row but before a matching materializer receipt is durable
- **THEN** the Kernel replays exactly that handoff; only a terminal integrity failure or expired admission lease can mark the admission failed and collect its unreferenced object, and no route, preparation, or rollback may observe the hidden row

#### Scenario: Celld package is submitted for runtime admission
- **WHEN** a deployment request supplies a package whose declared runtime kind is `celld`
- **THEN** the system rejects it with a terminal error naming celld image-only supply; no admission machinery, sandbox, or version lifecycle is invoked

### Requirement: Every application has an exclusive security boundary
The node SHALL operate a two-tier trust model. Every application executes as a security principal distinct from the node control plane; the boundary mechanism is fixed by runtime tier:

- **Wasm tier (untrusted admission):** a component cannot escape its linear-memory sandbox, receives no socket, TLS, or filesystem capability, and its only data plane is the host service interfaces. Resource limits are enforced inside the engine (fuel/epoch deadline, store/instance limits, guest linear-memory limit). The residual risk that a wasmd or Wasmtime host defect breaks this boundary is accepted and recorded, not defended by a second container boundary.
- **Celld tier (trusted, image-only):** each application runs as its own celld process started by the node entrypoint from the image-seeded fleet. Processes are mutually separate for fault isolation; trust comes from image provenance, not from an isolation boundary. A celld application MUST NOT receive the owner key, MinIO/RustFS root credentials, the Kernel control credential, or another application's celld operator listener.

An application MUST receive only its own package snapshot or seeded deployment and application-scoped storage; it MUST NOT read or mutate the owner workspace as an application data plane, another application's package or storage, the owner key, or infrastructure credentials.

#### Scenario: Compromised wasm application probes another security principal
- **WHEN** a wasm component attempts to reach another application's data, the owner workspace, or node credentials through any import outside the matrix
- **THEN** instantiation or admission fails closed and no such capability is granted

#### Scenario: Compromised celld application probes infrastructure
- **WHEN** a celld application reads process environments or dials internal listeners
- **THEN** this is a documented accepted risk of the trusted tier, not a boundary violation the system claims to prevent; its blast radius is bounded by per-process supervision and the resource watchdog

#### Scenario: Compromised application probes another security principal
- **WHEN** application `alpha` attempts to read application `beta` data, owner workspace objects, or node credentials
- **THEN** the wasm tier's engine boundary denies access without exposing the target; in the celld tier this attempt is an accepted documented risk of image-provenance trust, bounded by process supervision and the watchdog

#### Scenario: Application inspects its runtime environment
- **WHEN** any application enumerates its capabilities
- **THEN** it finds only its tier's contract: engine-scoped host interfaces (wasm) or its own process's seeded deployment (celld)

### Requirement: Application network access is policy-bound
For the wasm tier, network access SHALL be structural: components have no socket capability, `wasi:http/outgoing-handler` through the host-mediated gateway is the only egress interface, and DNS, reserved-address checks, and TLS termination happen on trusted host code exactly as defined by `wasm-application-runtime`.

For the celld tier, applications share the node container network as a documented consequence of the trusted, image-seeded model. `HTTP_PROXY`-style variables and cooperative-client configuration remain supporting controls, not enforced boundaries; the node law records that celld-tier network isolation is not provided. Kernel, RustFS, and operator listeners remain loopback-only inside the node container, and the operator/peer listener is never routed.

#### Scenario: Component requests a denied network interface
- **WHEN** a wasm component requires `wasi:sockets`, `wasi:tls`, or any non-matrix import
- **THEN** admission or instantiation fails closed and no direct network path is granted

#### Scenario: Celld egress posture is reported honestly
- **WHEN** an administrator inspects node documentation or status projections
- **THEN** the celld tier's shared-network posture is stated as a trust-tier property, never as an enforced network boundary

#### Scenario: Application targets an internal node service
- **WHEN** a wasm application's outbound request targets a node-internal address through the host-mediated path
- **THEN** reserved-address policy rejects it and no raw socket exists to retry with

#### Scenario: Application requests undeclared external access
- **WHEN** a component requires any network import outside the matrix
- **THEN** admission or instantiation fails closed and the capability is never granted

### Requirement: Resource and failure effects are contained per application
For the wasm tier, the engine SHALL enforce finite per-application CPU (epoch deadline, optional fuel), memory (linear-memory and store limits), and concurrency limits before damage; an over-limit component fails alone and neighbors keep running.

For the celld tier, the resource watchdog enforces soft limits: the Kernel samples each application's process RSS on a fixed interval, and a process above its configured soft limit is terminated with SIGKILL by the Kernel. The node entrypoint supervises each celld process and restarts a terminated application with bounded backoff without restarting neighboring applications or the node. Watchdog termination is an after-the-fact containment with a sampling-window trade-off, not a synchronous kernel-level limit; monitoring MUST present it as a soft limit.

#### Scenario: Application exceeds its memory limit
- **WHEN** a wasm component exceeds its engine memory limit or a celld process exceeds its watchdog soft limit
- **THEN** that application alone fails or is terminated; neighboring applications and the control plane keep running, and the event is visible to authorized monitoring

#### Scenario: Watchdog kills a leaking celld application
- **WHEN** a celld process stays above its soft limit across a sampling interval
- **THEN** the Kernel terminates exactly that process, records a bounded watchdog event, and the entrypoint restarts the application with backoff while other applications never restart

#### Scenario: Owner stops an application
- **WHEN** the owner stops a wasm execution through the authorized lifecycle
- **THEN** that execution drains or terminates alone under the wasm lifecycle contract and neighboring applications are unaffected

### Requirement: Version activation and rollback are atomic
For runtime kind `wasm`, activation and rollback SHALL swap the active route pointer in one Kernel control-state CAS bound to the admitted version identity, readiness lease, and route generation, exactly as defined by `wasm-application-runtime`. A failed activation leaves the previous pointer active. celld has no version lifecycle; its fleet processes are managed by the entrypoint and are not activation targets.

#### Scenario: Owner rolls back an application
- **WHEN** the owner rolls back a wasm application to a retained admitted version
- **THEN** the route pointer CAS commits atomically and the retired version's execution is drained under the wasm lifecycle contract

#### Scenario: Activation fails midway
- **WHEN** a wasm activation cannot complete its CAS or readiness adoption
- **THEN** the previously active pointer remains authoritative and no partial state becomes routable

#### Scenario: Replacement version becomes ready
- **WHEN** a prepared wasm version passes its readiness attestation
- **THEN** it becomes eligible as the activation target with its lease digest recorded

#### Scenario: Readiness lease expires during activation CAS
- **WHEN** the readiness lease expires between the activation decision and the pointer CAS
- **THEN** the CAS refuses and the previously active pointer stays authoritative

#### Scenario: Replacement version fails before activation
- **WHEN** a candidate version fails preparation or readiness before any activation
- **THEN** no pointer change occurs and the failed version never receives traffic

#### Scenario: Supervisor journal commits but Kernel projection fails
- **WHEN** a lifecycle acknowledgement is durable on the supervisor side but the Kernel projection CAS fails
- **THEN** reconciliation replays the exact command and never routes from the journal alone

### Requirement: Kernel runtime-kind records are wasm-only with route-derived claims
The Kernel owns exactly one runtime-admission registry and SHALL keep it wasm-only: the `runtimeKind:"wasm"` records of `/data/kernel/wasm-control-state-v2.json`. There is no celld control-state file, celld version validator, or cross-kind migration; celld application identity exists only in the route registry.

An applicationId is bound to one runtime kind for life. Lifetime celld claims are derived deterministically at startup from the route registry: every route whose `target.kind` is `celld-app` contributes its target application name as a celld claim, merged with the claims persisted in the wasm control state. Wasm admission of an applicationId that is celld-claimed returns `APPLICATION_RUNTIME_KIND_CONFLICT`. There is no bootstrap-pending state: derivation fails only when the route registry itself is unreadable, which is a node startup failure, not a wasm-admission mode.

#### Scenario: Wasm admission reuses a celld fleet identity
- **WHEN** wasm admission is requested for an applicationId that a `celld-app` route targets
- **THEN** the Kernel returns `APPLICATION_RUNTIME_KIND_CONFLICT`, writes no registry record, and requires a new applicationId

#### Scenario: Route registry is unreadable at startup
- **WHEN** the route registry file cannot be parsed at Kernel startup
- **THEN** startup fails closed with the route-store error; the node does not enter a partial-admission mode

#### Scenario: Wasm route appears without a registry record
- **WHEN** routing resolves a wasm application with no matching registry record or pointer
- **THEN** the host serves the generic bounded 502 and no record is fabricated

### Requirement: Celld applications enter the node only through the node image
The system SHALL provide no runtime admission, upload, or publication path for celld applications. A celld application exists on the node only because its deployment was built into the node image and started by the image entrypoint. Workspace writes, MCP tools, and Kernel control endpoints MUST NOT create, replace, or retire celld application code. Upgrading a celld application is performed by building a new node image and restarting the node.

#### Scenario: Owner upgrades a celld application
- **WHEN** the owner wants a newer version of an image-seeded application
- **THEN** the owner builds a new node image containing it and redeploys the node; no in-place celld publication occurs

#### Scenario: MCP is asked to deploy a celld package
- **WHEN** a deployment agent submits a celld package through any MCP tool
- **THEN** the tool rejects the request with guidance toward wasm admission or image supply, and no celld deployment changes

### Requirement: The resource watchdog enforces soft limits for process-runtime applications
The Kernel SHALL sample the RSS of every supervised application process (celld fleet and wasmd) on a fixed interval from pidfiles, compare each sample against the application's configured soft limit, and terminate exactly the offending process with SIGKILL when the limit is exceeded. Soft limits come from a node configuration file with a conservative default and per-application overrides; they are advisory thresholds for containment, not guaranteed ceilings, and monitoring MUST label them as soft limits with the sampling interval stated.

The node entrypoint SHALL supervise each celld process: on unexpected exit it restarts that application alone with bounded backoff, and a disable marker under the run directory stops supervision for that application without affecting others. The Kernel SHALL record every watchdog termination as a bounded, authorized-visible event naming the application, sampled RSS, configured limit, and timestamp. A missing sample remains `unavailable`; the watchdog MUST NOT act on zero or substituted values.

#### Scenario: Soft limit configuration is applied
- **WHEN** the node starts with a per-application soft limit override
- **THEN** the watchdog uses that value for that application and the default for the rest, and the effective limits are visible in monitoring projections

#### Scenario: Process pidfile disappears
- **WHEN** an application's pidfile is absent or its process has already exited
- **THEN** the watchdog takes no kill action, its resources projection reports `unavailable`, and the entrypoint supervision governs restart
