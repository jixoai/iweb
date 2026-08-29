<!-- 用户原始需求（2026-08-24）：mini 运行单位与更新事务立法（grilling Q3/Q4/Q9/Q18/Q19/Q24 监控与 Admin 部分）。 -->
<!-- Codex 审稿 R1-R3：成员规则补路由注册表不可变断言与 factory 定义；候选隔离如实降级为凭证域隔离；移除语义强断言；新增监听器边界 requirement。 -->

## ADDED Requirements

### Requirement: Mini node listener boundary
The iweb-mini node SHALL publish exactly one listener: the Kernel ingress. RustFS on its loopback address, the shared fleet celld public listener, and the celld operator/peer listener SHALL remain container-internal loopback services that are never Docker-published, and the Kernel MUST NOT route to the operator listener. `api.<base>` SHALL be served by the Kernel directly and remain reachable independently of the fleet's state, including while the fleet is stopped or broken.

#### Scenario: Internal listeners are unreachable from outside the node
- **WHEN** an external probe targets the node's published address on the RustFS, celld public, or celld operator ports
- **THEN** no path exists to those listeners, because only the Kernel ingress is published

#### Scenario: Fleet down does not take the recovery surface with it
- **WHEN** the shared fleet process is stopped or failing
- **THEN** `api.<base>` and the Kernel status and recovery endpoints remain fully functional

### Requirement: Composition is the versioned run unit
The iweb-mini system SHALL run applications through versioned fleet compositions: immutable, content-addressed documents with monotonically increasing generations, whose entries are application-at-version references into the admission ledger. Composition validation SHALL reject unknown applications, duplicate identities, missing mandatory control-plane entries, and references to nonexistent ledger versions. Activation and rollback operate on compositions; per-application version history remains queryable in the ledger.

#### Scenario: Edit references a missing version
- **WHEN** a submitted composition references an application version that is not in the ledger
- **THEN** the submission is rejected and neither a new composition nor any runtime change is produced

### Requirement: Composition membership rules
The `api` host SHALL never be a composition entry; it is the Kernel's permanent external recovery surface. The `admin` and `mcp` applications SHALL be mandatory fixed entries whose versions change only with iweb-mini image releases. Non-control-plane built-in applications SHALL be optional entries the owner can include, remove, or replace through attested admission. The factory composition and the initial ledger entries for built-in applications SHALL be defined by the image's product descriptor. Removing an application removes only its fleet run entry: workspace files, admission ledger, and persistent data are retained, composition operations MUST NOT create, modify, delete, or disable any route registry record, and a removed application's registered routes serve the generic 502 application-unavailable response until the owner changes routing separately. Deleting an application's ledger and data is an explicit destructive operation reserved for a later change.

#### Scenario: Composition edit never touches the route registry
- **WHEN** a composition update that adds or removes an application activates
- **THEN** the route registry records are byte-identical before and after, and any reachability change comes only from what the fleet serves

#### Scenario: Owner removes an optional built-in app
- **WHEN** a new composition excluding a previously included application activates
- **THEN** the route registry records, host IDs, and route generation are unchanged, the retained ledger and data are untouched, and the removed application's hosts deterministically return the generic 502 application-unavailable response

### Requirement: Optimistic concurrency for composition edits
Composition edits SHALL carry the expected composition identity or generation and SHALL be rejected with 409 stale — returning the current composition — on mismatch, without partial effects. The deployment transaction SHALL be a single-writer Kernel-serialized operation: at most one in-flight update at a time, and edit submissions during an update SHALL be rejected with 409 marked as node-updating.

#### Scenario: Two editors race
- **WHEN** two owners submit edits against the same generation
- **THEN** the first succeeds and the second receives 409 with the new current composition for re-review

### Requirement: Deploy transaction with bounded interruption
Activating a new composition SHALL run: code-level pre-check on a zero-state candidate fleet (separate bucket and process, no production state); stop routing to the fleet; quiesce in-flight Durable Object and WebSocket work; create a verifiable snapshot; redeploy the steady fleet bucket with the new composition and restart the shared celld; pass a post-restart readiness gate before routing resumes; then flip the composition pointer atomically. The candidate pre-check fleet SHALL operate with minimal credentials scoped to its own candidate bucket only; it MUST NOT access the steady fleet bucket, the workspace, the version-object zone, snapshots, Kernel or owner credentials, or production traffic. Candidate isolation is credential-scoped, not network-scoped: the candidate shares the node container's network namespace, so loopback reachability to Kernel and object storage exists by topology, and enforcement is authorization — the candidate's storage policy covers only its candidate bucket, no Kernel or owner credential is present in the candidate, and the Kernel accepts no unauthenticated control. This degradation is explicit product semantics, mirroring the fleet's own credential-domain law. The system MUST NOT promise zero-downtime updates: the interruption window is sized by actual state volume and is shown honestly in the Admin update state, which also disables control-state-changing interactions during the transaction.

#### Scenario: Candidate cannot exercise production surfaces
- **WHEN** code loaded into the candidate pre-check fleet attempts to read the steady fleet bucket, workspace objects, or any Kernel control surface, or to receive production traffic
- **THEN** every storage attempt fails authorization against the candidate-only policy, every control attempt fails for lacking credentials, and no route ever points at the candidate

#### Scenario: Update in progress
- **WHEN** a composition update transaction is running
- **THEN** applications are unavailable for the bounded window, Admin displays the node-updating state, and new composition edits return 409

### Requirement: Automatic rollback protects the old composition
When the post-restart readiness gate fails, the Kernel SHALL automatically stop the fleet, restore this transaction's snapshot, redeploy the previous composition, and re-verify old readiness before routing resumes. The product promise is that a failed update cannot harm the healthy old composition, including its persistent state. After activation, ordinary rollback is code-only (a new composition selecting previous versions) with data compatibility the owner's responsibility; returning to old data is only the explicit destructive snapshot restore.

#### Scenario: New composition fails readiness
- **WHEN** the restarted fleet fails the post-restart readiness gate
- **THEN** the previous composition and its pre-update state are restored automatically and serve traffic again, with audit events recording the failure and recovery

### Requirement: Fleet shares fate, not credentials
The shared fleet SHALL share execution, state, and availability fate among its applications, but MUST NOT share the owner recovery credential domain: the bootstrap token, delegated-key ledger, Kernel control state, workspace authorization, and snapshot credentials never enter the fleet. The fleet process's storage credential SHALL cover only the steady fleet bucket; snapshot, workspace, and version-object zones are Kernel-credential domains. The Kernel SHALL provide no unauthenticated fleet-to-control-plane path, so application code cannot act as the owner even when it can reach internal addresses.

#### Scenario: Compromised fleet application probes control authority
- **WHEN** admitted application code attempts to perform admission, composition, or snapshot operations
- **THEN** it lacks the required bootstrap credentials and cannot act as the owner, while `api.<base>` remains available to the real owner for recovery

### Requirement: Monitoring without per-application attribution
Mini monitoring SHALL retain per-route request, error, and latency attribution and process restart counts, and SHALL report resources only as node and fleet totals with the container memory envelope observed separately. Application rows SHALL be labeled as shared-fleet or node-overhead and MUST NOT display fabricated per-application memory, resource limits, or sandbox identities; where trustworthy per-application accounting does not exist, the value is unavailable rather than estimated.

#### Scenario: Owner opens the mini monitoring view
- **WHEN** the monitoring snapshot arrives for a shared fleet
- **THEN** each application row shows route-level traffic metrics and a node-overhead resource label, with node totals displayed separately from any per-row value

### Requirement: Mini Admin information architecture
The mini Admin bundle SHALL be built from the same source under a product build profile with the full-only views tree-shaken away, and SHALL hard-stop management operations with a deployment error when the runtime product mode does not match its compiled expectation. Its primary application view SHALL be the fleet composition view — current composition, per-application admission ledger, update state, and the owner-attested admission entry — with per-application actions framed as composition edits (no per-application restart, independent rollback, or sandbox wording). Bootstrap-owner-only entries, including attested admission and destructive recovery, SHALL NOT be rendered for delegated identities, and delegated logins never receive render-then-403 surfaces.

#### Scenario: Delegated key opens mini Admin
- **WHEN** a delegated key authenticates to the mini Admin
- **THEN** the composition view renders read-only with workspace tooling, and admission or recovery entries are absent from the interface
