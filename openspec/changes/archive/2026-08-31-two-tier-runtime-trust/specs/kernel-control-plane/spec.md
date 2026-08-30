## MODIFIED Requirements

### Requirement: Owner credential protects control operations
Every Kernel control operation under `/v1/*` SHALL require a valid `Authorization: Bearer` credential accepted by the owner-key law. Unauthenticated or unauthorized requests receive a uniform rejection without distinguishing valid paths. Wasm admission, activation, and recovery endpoints are owner-authorized control operations; celld publication endpoints do not exist, and any request to a removed celld admission path receives a stable, bounded terminal error naming celld image-only supply instead of a router fallthrough.

#### Scenario: Unauthenticated control request
- **WHEN** a control request arrives without a valid credential
- **THEN** it is rejected uniformly and no path existence or state is revealed

#### Scenario: Authorized publication creates a sandbox
- **WHEN** an owner-authorized request supplies a valid wasm admission transaction
- **THEN** the Kernel executes the admission contract and the execution lifecycle may proceed; without the credential the same request is rejected uniformly

#### Scenario: Removed celld admission path is addressed
- **WHEN** a caller posts to a former celld admission or sandbox lifecycle path
- **THEN** the response is a stable terminal error naming celld image-only supply; no admission machinery runs

### Requirement: Kernel retains an administration recovery action
The independent recovery route on the api hostname SHALL remain the owner's way to reconcile wasm business records (admission journal, control state, route pointers) and node supervision state after faults without executing mutable workspace packages and without routing unadmitted code. Recovery never creates a celld deployment and never bypasses the wasm admission transaction.

#### Scenario: Administrator recovers the seeded Dispatcher
- **WHEN** recovery reconciles routing after fault
- **THEN** image-seeded celld routes are restored from the route registry seed and no admission machinery is involved

#### Scenario: Administrator recovers the node control plane
- **WHEN** the control plane is recovered through the api hostname
- **THEN** the Kernel reconciles wasm journals and pointers per `wasm-application-runtime` and no partial version becomes visible

### Requirement: Kernel owns application versions and active routing state
The Kernel SHALL be the sole authority for wasm application version identities, lifecycle states, and the active route pointer, exactly as defined by `wasm-application-runtime`. celld applications have no Kernel-managed versions: their identity is the route registry entry seeded from the node image, and the Kernel routes registered celld hosts to their per-app processes without an admission lifecycle.

#### Scenario: Kernel activates a ready version
- **WHEN** the owner activates a ready admitted wasm version
- **THEN** the Kernel performs the single route-pointer CAS and the previous pointer retires atomically

#### Scenario: Application attempts to activate itself
- **WHEN** any non-Kernel component claims to activate a version or publish a pointer
- **THEN** the claim has no authority; activation state changes only through the Kernel control plane

#### Scenario: Active wasm pointer is the only routing authority
- **WHEN** a wasm application's route is resolved
- **THEN** routing follows the Kernel control-state active pointer and never a static sandbox identity

#### Scenario: celld route resolution
- **WHEN** a registered celld host is resolved
- **THEN** the Kernel forwards to that application's own celld process port from the route registry, with no version lifecycle involved

### Requirement: Kernel controls sandbox lifecycle without joining the sandbox
The Kernel SHALL drive wasm execution lifecycle (prepare, start, drain, stop) exclusively through the authorized supervisor execution channel and journal reconciliation defined by `wasm-application-runtime`; it never executes application code itself and never enters an execution process. celld process lifecycle is entrypoint supervision plus the Kernel resource watchdog: the Kernel may terminate exactly one offending celld process by pidfile, and restarting is the entrypoint's responsibility, not a control-plane operation.

#### Scenario: Wasm lifecycle flows through the execution channel
- **WHEN** the Kernel prepares, starts, drains, or stops a wasm execution
- **THEN** the command, acknowledgement, and reconciliation follow the execution-rpc contract and the Kernel never spawns application processes itself

#### Scenario: Sandbox start fails
- **WHEN** a wasm execution start fails on the supervisor side
- **THEN** the bounded failure code returns through the acknowledgement contract and no route pointer changes

#### Scenario: Application sandbox is deleted
- **WHEN** the owner deletes a retained wasm version or its execution through the control plane
- **THEN** the Kernel and supervisor retire exactly that execution's records and processes; other applications are untouched

#### Scenario: Watchdog termination is bounded to one process
- **WHEN** the Kernel's watchdog kills a celld process above its soft limit
- **THEN** exactly that pidfile's process is terminated and the entrypoint, not the Kernel, performs the restart

### Requirement: Kernel implementations are pinned by shared contract vectors
Contract tests SHALL pin Kernel behavior with canonical digest vectors for wasm package layouts, admission digests, snapshot digests, and the wasm gate wire. The celld-era package digest vectors are retired with the celld admission path; no test may assert a celld admission contract.

#### Scenario: Canonical digest parity across implementations
- **WHEN** the contract suite runs against the Kernel
- **THEN** wasm digest and gate vectors pass with byte-exact parity and no celld admission vector exists to drift against
