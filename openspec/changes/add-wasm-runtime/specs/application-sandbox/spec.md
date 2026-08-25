<!-- 用户原始需求（2026-08-25）：准入法必须先知道包的执行形态，才能校验对应的能力契约。 -->
<!-- 正交意图：把 wasm 准入可见性纳入不可变版本法；统一激活 lease/CAS；不转移 Kernel 的版本与路由权威。 -->
<!-- R5（2026-08-26）：按 R4 修正 admission durable-state 表述与 lifecycle authority；wasm 细节由 wasm-application-runtime delta 定义。 -->
<!-- R6（2026-08-26）：明确 retiring 仅为 supervisor execution substate；Kernel LifecycleState 保持 celld validator 可接受集合。 -->
<!-- R7（2026-08-26）：按真实 supervisor socket/Kernel 拓扑与 per-kind business registry 接线；wasm activation/drain replay 由 wasm-application-runtime delta 定义。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner 评分回落升级政策。 -->

## MODIFIED Requirements

### Requirement: Publication admits an immutable application version
The system SHALL validate an application package and its declared runtime policy before creating an immutable application version. A rejected package MUST NOT create or replace an active version, start executable code, or receive application traffic. The declared runtime policy SHALL include the runtime kind (`celld` or `wasm`). For `wasm`, the validated policy SHALL include the component world, the import capability matrix, and the complete admission transaction defined by `wasm-application-runtime`; the Kernel remains the authority that creates the admitted version and records its policy.

For a wasm submission, a staging object or a content-addressed object prefix alone SHALL NOT be an immutable application version. A wasm version is visible to any preparation, route selection, rollback selection, or ordinary version read only when the wasm admission transaction's single `AdmittedVisible` predicate is true. The predicate requires one matching immutable object completion marker, one matching committed Kernel control-database version row, and one matching materializer handoff receipt, all bound to the same application ID, package digest, complete `versionId`/sequence, normalized policy, runtime binding identity, capability-record revision/hash, lifecycle admission record, and opaque admission commit-token hash as defined by `wasm-application-runtime`. The Kernel SHALL use the admission journal to replay or collect incomplete work; it MUST NOT expose an intermediate state as a version.

#### Scenario: Package admission succeeds
- **WHEN** an owner-authorized deployment request supplies a package and policy that satisfy the node's admission contract and `AdmittedVisible` becomes true
- **THEN** the Kernel creates one immutable visible version identity that can be prepared for that application

#### Scenario: Package admission fails
- **WHEN** the package, manifest, requested policy, or any admission transaction step fails validation
- **THEN** the system returns structured rejection details without executing the package or changing the active version

#### Scenario: Wasm package fails the capability matrix
- **WHEN** a wasm package declares or embeds imports outside the node's allowed capability matrix, or its declaration differs from the discovered closure
- **THEN** the system returns structured rejection details and no version becomes visible, nothing is materialized for execution, and nothing is executed

#### Scenario: Completion marker exists without a control-database version
- **WHEN** a node restarts after a wasm object completion marker was written but before the Kernel control-database version row committed
- **THEN** the prefix is not a visible version; the admission journal either completes the same token idempotently or garbage-collects it after proving no committed row references it

#### Scenario: Database version commits before materializer handoff completes
- **WHEN** a node restarts after the Kernel has committed the hidden admission row but before a matching materializer receipt is durable
- **THEN** the Kernel replays exactly that handoff; only a terminal integrity failure or expired admission lease can mark the admission failed and collect its unreferenced object after its retention checks, and no route, preparation, or rollback may observe the hidden row

### Requirement: Version activation and rollback are atomic
The Kernel SHALL direct new traffic to exactly one active admitted version per application and remains the authority for its active route pointer. An update MUST become active only after its sandbox is ready and the readiness lease is unexpired at the **Kernel route-pointer compare-and-swap linearization point**. The CAS SHALL match the expected active route generation, the candidate version identity, its runtime binding identity, and for wasm its `(sandboxId, versionId, preparationGeneration, executionGeneration)` tuple plus the readiness-attested `secretRevision`, `configRevision`, and `configSnapshotRef`. Failed preparation or activation MUST preserve the previous healthy active version. An owner-authorized rollback SHALL reactivate a retained admitted version through the same readiness gate and SHALL persist the rollback target's runtime binding identity with the rollback event. The wasm `ActivationCommandV1`/`RouteEventV1` query-replay result is the durable record of this CAS; a consumed lease or supervisor journal alone cannot activate.

The supervisor may execute a Kernel-authorized prepare/start/drain command and durably acknowledge it, but it MUST NOT create a version, choose a rollback target, or flip an active route pointer. A supervisor journal completion not yet projected into the Kernel control DB SHALL be replayed to the Kernel; it SHALL NOT cause routing by itself. During replacement, `retiring` is a supervisor-only execution substate recorded in the wasm execution journal; it is not a `LifecycleState` value and is projected to Kernel as the old version's `retired` state only after the route CAS and drain receipt. Existing celld state validators therefore remain unchanged.

#### Scenario: Replacement version becomes ready
- **WHEN** a newly admitted version reaches its required ready state and its lease remains unexpired when the Kernel route CAS linearizes
- **THEN** the Kernel atomically makes it active for new requests and retires the previous version from new traffic

#### Scenario: Readiness lease expires during activation CAS
- **WHEN** the lease is valid when activation starts but expires before the Kernel route-pointer CAS linearizes
- **THEN** the CAS does not update the route, the previous active version keeps serving, and the candidate must re-prepare

#### Scenario: Replacement version fails before activation
- **WHEN** a newly admitted version fails to become ready or its fenced execution dies before the Kernel route CAS
- **THEN** the system reports the failure and continues routing new requests to the previous healthy active version

#### Scenario: Supervisor journal commits but Kernel projection fails
- **WHEN** a supervisor records a completed Kernel-authorized execution transaction but the Kernel fails before recording its corresponding projection
- **THEN** restart reconciliation replays the exact command and acknowledgement; the Kernel retains the previous active route until its own route CAS succeeds

#### Scenario: Owner rolls back an application
- **WHEN** an owner-authorized caller selects a retained admitted version and that version becomes ready with its retained runtime binding identity
- **THEN** the Kernel atomically makes the selected version active without rebuilding it from mutable workspace content

### Requirement: Kernel business records are isolated by runtime kind
The Kernel SHALL preserve its active-route and lifecycle authority while storing wasm business records in the strict per-kind `WasmKernelRouteRegistryV1` defined by `wasm-application-runtime`. The registry records `runtimeKind:"wasm"`, the complete `RuntimeBindingIdentityV1`, and both the `AdmissionProofV1` reference/digest for every version; the existing celld `ControlStateFile` and `VersionRecord` remain their v1 schema and never parse or allocate wasm identities. A same-named application may exist in both registries, but no pointer, sequence, route generation, lifecycle row, or migration operation may cross the kind boundary. A migration MUST carry explicit source revision/digest, target digest, and a durable receipt; idempotent replay returns that receipt and any failed target is quarantined without changing an active pointer.

#### Scenario: Supervisor reports a wasm route without a Kernel registry record
- **WHEN** a supervisor journal or gateway health message names a wasm version/binding that is absent from the Kernel wasm registry or lacks its admission-proof reference
- **THEN** Kernel rejects the projection as `WASM_BUSINESS_RECORD_MISSING` and retains the existing active pointer

#### Scenario: Migration source changes during replay
- **WHEN** a migration retry sees the same source revision with a different source digest
- **THEN** Kernel returns `MIGRATION_SOURCE_CONFLICT`, quarantines any target, and leaves both celld and wasm active routes unchanged
