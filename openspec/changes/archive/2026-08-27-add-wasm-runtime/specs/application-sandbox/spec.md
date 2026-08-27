<!-- 用户原始需求（2026-08-25）：准入法必须先知道包的执行形态，才能校验对应的能力契约。 -->
<!-- 正交意图：把 wasm 准入可见性纳入不可变版本法；统一激活 lease/CAS；不转移 Kernel 的版本与路由权威。 -->
<!-- R5（2026-08-26）：按 R4 修正 admission durable-state 表述与 lifecycle authority；wasm 细节由 wasm-application-runtime delta 定义。 -->
<!-- R6（2026-08-26）：明确 retiring 仅为 supervisor execution substate；Kernel LifecycleState 保持 celld validator 可接受集合。 -->
<!-- R7（2026-08-26）：按真实 supervisor socket/Kernel 拓扑与 per-kind business registry 接线；wasm activation/drain replay 由 wasm-application-runtime delta 定义。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner 评分回落升级政策。 -->
<!-- R8（2026-08-26）：按 owner 最终裁决固定 applicationId/runtimeKind 终身绑定与跨 registry CAS 互斥；补双 active fail-closed 场景。作者：codex-wasm-author，gpt-5.6-terra max。 -->

## MODIFIED Requirements

`ApplicationId` is the shared route identity grammar for both runtime kinds: `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`, at most 63 ASCII bytes. A runtime-kind claim is made before the first admitted version; leading/trailing hyphens, uppercase, empty IDs, and IDs longer than 63 bytes are invalid for both registries.

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

## ADDED Requirements

### Requirement: Kernel business records are isolated by runtime kind
The Kernel SHALL preserve its active-route and lifecycle authority while storing wasm business records in the strict per-kind `WasmKernelRouteRegistryV1` defined by `wasm-application-runtime`. The registry records `runtimeKind:"wasm"`, the complete `RuntimeBindingIdentityV1`, and both the `AdmissionProofV1` reference/digest for every version; the existing celld `ControlStateFile` and `VersionRecord` remain their v1 schema and never parse or allocate wasm identities. An `applicationId` is permanently bound to exactly one runtime kind at its first successful registration. A celld and wasm registry MUST NOT both claim the same `applicationId`; changing runtime kind requires a new `applicationId`, with no cross-kind route, sequence, lifecycle, or active-pointer migration. A migration MUST carry explicit source/target application IDs, source revision/digest, target digest, and a durable receipt; for a cross-kind source it MUST prove `sourceApplicationId != targetApplicationId`. Idempotent replay returns that receipt and any failed target is quarantined without changing an active pointer.

The binding is the exact `ApplicationRuntimeKindBindingV1` record `{schemaVersion:1,applicationId,runtimeKind,bindingRevision,bindingDigest}` at `/data/kernel/application-kind-registry-v1/<applicationId>.json`; `runtimeKind` is `celld` or `wasm`, `bindingRevision` starts at `1` and never changes, and `bindingDigest = hex(SHA-256(UTF8("iweb-application-kind-binding-v1\n" || JCS(record with bindingDigest omitted))))`. The shared CAS index at `/data/kernel/application-kind-registry-v1/index.json` is exactly `{schemaVersion:1,registryRevision:u53,claims:[{applicationId,runtimeKind,bindingRevision,bindingDigest}]}` with bytewise-sorted, unique `applicationId` claims; an empty index starts at revision `0`, and every claim mutation increments `registryRevision` by exactly one. Every write to either per-kind registry includes `expectedKindRegistryRevision` for this index CAS and the binding digest, taking the global claim CAS before the kind-specific registry write and never acquiring those locks in reverse order. The first writer atomically creates the binding and its kind-specific registry row; a same-kind retry is idempotent, while a different kind returns `APPLICATION_RUNTIME_KIND_CONFLICT` without touching either registry. Recovery that observes two kind registries claiming the same application ID, two active pointers, or a binding/index revision disagreement enters `APPLICATION_KIND_SPLIT_BRAIN` fail-closed: it serves no route and never chooses one registry heuristically until an owner-authorized repair CAS removes the conflict.

#### Scenario: Supervisor reports a wasm route without a Kernel registry record
- **WHEN** a supervisor journal or gateway health message names a wasm version/binding that is absent from the Kernel wasm registry or lacks its admission-proof reference
- **THEN** Kernel rejects the projection as `WASM_BUSINESS_RECORD_MISSING` and retains the existing active pointer

#### Scenario: Migration source changes during replay
- **WHEN** a migration retry sees the same source revision with a different source digest
- **THEN** Kernel returns `MIGRATION_SOURCE_CONFLICT`, quarantines any target, and leaves both celld and wasm active routes unchanged

#### Scenario: An application changes runtime kind
- **WHEN** an existing celld-bound `applicationId` is submitted to the wasm registry, or a wasm-bound ID is submitted to celld
- **THEN** Kernel returns `APPLICATION_RUNTIME_KIND_CONFLICT`, leaves the original binding and active route unchanged, and requires a new application ID

#### Scenario: Two registries claim active after recovery
- **WHEN** a crash leaves both celld and wasm registry records claiming the same `applicationId` as active, or their shared kind-claim CAS revisions disagree
- **THEN** Kernel returns `APPLICATION_KIND_SPLIT_BRAIN`, fences all traffic for that ID, and waits for an owner repair receipt; it never selects one pointer by timestamp or journal order

#### Scenario: Kind claim and registry write are interrupted
- **WHEN** recovery sees the global kind claim without its kind-specific row, or a kind-specific row without the matching claim
- **THEN** it replays the byte-identical owner transaction under the same `expectedKindRegistryRevision` or quarantines the orphan; neither partial state can become active and no cross-kind fallback is attempted

On an upgraded node whose celld control state predates the kind index, the Kernel SHALL complete a one-time celld kind-claim bootstrap before any wasm write path opens: it derives the complete bytewise-sorted claim set from the current celld control state and durably records `KindClaimBootstrapV1` `{schemaVersion:1, bootstrapRevision:u53, sourceKind:"celld", controlStateRawDigest, sourceRevision, sortedClaims, completionReceiptDigest}`, where `completionReceiptDigest = hex(SHA-256(UTF8("iweb-kind-claim-bootstrap-v1\n" || JCS(record with completionReceiptDigest omitted))))` and `sourceRevision` is the celld control revision or `0` where the legacy file has none. The bootstrap commits every derived claim into the shared index in one startup sequence; a crash at any point replays idempotently, and a current celld control state whose raw digest no longer matches the last bootstrap record forces a re-derivation before any wasm write is accepted. Until a bootstrap record exists and verifies against the current celld control state, wasm admission and the wasm publication gate remain closed with `WASM_KIND_BOOTSTRAP_PENDING`.

#### Scenario: Wasm admission before bootstrap is closed
- **WHEN** a wasm admission or wasm publication gate evaluation arrives while no verified bootstrap record exists
- **THEN** the node fails closed with `WASM_KIND_BOOTSTRAP_PENDING` and no wasm identity or claim is allocated

#### Scenario: Bootstrap crash and replay
- **WHEN** the Kernel crashes mid-bootstrap and restarts
- **THEN** replay either completes the identical claim set from the same source digest or fails closed; a partial index never opens the wasm path

#### Scenario: Same-name wasm admission after bootstrap is rejected
- **WHEN** a wasm admission names an `applicationId` present in the bootstrap celld claim set
- **THEN** Kernel returns `APPLICATION_RUNTIME_KIND_CONFLICT` and the celld binding is untouched

#### Scenario: Bootstrap records disagree
- **WHEN** two bootstrap records exist for the same source digest with different claim sets, or a celld registry entry is absent from the verified claim set
- **THEN** Kernel enters `APPLICATION_KIND_SPLIT_BRAIN` fail-closed pending owner repair
