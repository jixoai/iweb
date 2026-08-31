## ADDED Requirements

### Requirement: Kernel observes execution liveness through the sandbox ingress
The Kernel SHALL determine whether a routed wasm execution is alive by dialing that sandbox's ingress socket (`/run/iweb-sandbox/gw/<sandboxId>/ingress.sock`, resolved by the existing gateway ingress socket addressing) and reading the wasmd v2 health attestation. The gateway directory is one deployment fact shared by every reader: the Kernel and the supervisor resolve `IWEB_SANDBOX_GATEWAY_DIR` with the same value and the same default (`/run/iweb-sandbox/gw`), and the node entrypoint passes that variable through to the supervisor unchanged; a deployment where the two sides resolve different directories is a wiring defect, not a probe outcome. The Kernel compares every field (sandbox ID, version ID, package digest, binding including catalog revision/hash, capability pin, secret revision/digest, config revision/reference/digest, preparation generation, execution generation, and — for a service execution — `hostServicePolicyDigest` and the matrix revision the fence carries) against the Kernel fence record joined with that version's registry row and the outbox start command that spawned it, which together carry every named field (the capability pin and policy digest travel in the start command, not in the fence or registry row). A service-form liveness probe correlates the service health form exactly as readiness does; a base-form answer for a fenced service execution, or a policy digest disagreeing with the start command, counts as one failed probe like any other field mismatch. A missing socket, a dial timeout, a non-200 response, a connection that succeeds and then resets or reaches EOF while the forwarder outlives a killed wasmd, or any field mismatch each count as one failed probe; an execution is declared lost only after a bounded number of consecutive failed probes (default 3 on the Kernel convergence cadence), and one successful exact-match probe resets the count. Liveness probing SHALL NOT hold the wasm control-plane mutex while dialing: each round snapshots the probe targets under the lock, probes concurrently outside it within a total budget below the convergence cadence, and re-acquires the lock only to apply failure counts and availability transitions — a probe result is applied only if the target's route generation and complete execution identity still equal the snapshot it was taken against, and is discarded otherwise. The Kernel MUST NOT synthesize liveness from a successful TCP dial, cached samples, or supervisor bookkeeping, and MUST NOT write fence `alive` from probe results: the probe outcome only drives the route-availability transition defined by the lifecycle requirement.

#### Scenario: Ingress socket missing after a container restart
- **WHEN** the node restarts and a fence record says `alive` while the sandbox ingress socket does not exist
- **THEN** probes fail on the missing socket, the bounded threshold declares the execution lost, and the route transitions per the lifecycle recovery requirement instead of serving traffic

#### Scenario: Forwarder socket outlives a killed wasmd
- **WHEN** the wasmd process is killed while its ingress forwarder socket still accepts connections, and a probe connects but the upstream resets or the response never arrives
- **THEN** the probe counts as failed, the bounded threshold eventually declares the execution lost, and no traffic is served through the half-open forwarder

#### Scenario: Health payload names a stale execution
- **WHEN** the ingress answers 200 but the attestation fields disagree with the fence-joined registry facts (for example an older execution generation)
- **THEN** the probe counts as failed, the execution is treated as not routable, and no stale attestation is adopted as current health or metrics

#### Scenario: Transient dial failure inside the threshold
- **WHEN** a single probe times out but the next probe returns an exact v2 match
- **THEN** the failure count resets, the route stays active, and no recovery preparation is planned

#### Scenario: Probing never blocks the control plane
- **WHEN** every sandbox socket is missing and each probe waits out its full dial timeout
- **THEN** admission, activation, and status requests on the wasm mutex observe no added latency, because all probes run outside the lock within the round budget

### Requirement: Kernel mints readiness leases from adopted readiness
The Kernel SHALL be the only production issuer of `ServiceReadinessLeaseV2`. For a version whose start command is applied, whose fence record shows the execution alive, and whose lifecycle is not yet `active` (a steady-state candidate awaiting activation sits in lifecycle `preparing` or `ready` with an alive fence — the mint trigger MUST NOT require the fence itself to be in any transient preparing substate), the Kernel convergence loop reads the supervisor's readiness adoption record over the execution-rpc query face (an exact-match v2 health adoption carried as a read-only projection; absence means no adoption) and, when the adoption identity equals the fence, registry, and start-command facts field-for-field, mints the lease: a fresh random 16-byte `leaseNonce`, `issuedAt` at mint time, `expiresAt` no later than `issuedAt` plus the admission `stagingTtlSeconds`, and `leaseDigest = digestV2("iweb-wasm-readiness-v2", JCS(record with leaseDigest omitted))` (single `0x00` domain separator, deliberately incompatible with the base `iweb-readiness-lease-v2` newline domain). Minted leases append into the root-owned readiness lease ledger (`/data/kernel/wasm/readiness-leases.json`, mode 0600, kernel-writable only), and every ledger write re-shapes the file to the canonical envelope, dropping any entry that is not a well-formed lease. Activation consumes kernel-minted leases through the existing activation wire unchanged; owner-side manual lease minting is not a supported path and MUST NOT be required by any deployment guidance.

Minting under this requirement is the Kernel-side execution of the exact-v2-200 probe grant defined by the readiness requirements: the supervisor adoption record is the durable record of that one successful v2 probe, and no other issuance path exists. Adoption reads ride the same lock-free bounded round as liveness probing; minting adds no in-lock network round trip. The readiness probe is enabled by node default. Adoption is re-producible: when a query arrives for a current in-place execution that is not yet adopted (including after a supervisor restart), the supervisor runs one probe and answers with the resulting adoption state. Minting never revives a consumed or CAS-expired lease: a lease that expired before the route CAS linearizes still requires a fresh preparation and exact health attestation per the readiness requirement.

#### Scenario: Deployment reaches activation without owner-minted leases
- **WHEN** an owner-authorized AI admits a package, the supervisor adopts exact v2 readiness, and the owner sends an activation command
- **THEN** the Kernel has already minted the lease for that candidate, the activation consumes it, and no manual lease bytes were produced outside the Kernel

#### Scenario: Adoption is regained after a supervisor restart
- **WHEN** the supervisor restarts, loses its in-memory adoption state, and the Kernel queries a still-current execution
- **THEN** the query triggers one fresh probe and the adoption record becomes available again, so minting is not permanently blocked

#### Scenario: Adoption identity disagrees with the fence
- **WHEN** the readiness adoption record names another sandbox ID, version, or generation than the current fence record
- **THEN** the Kernel mints nothing, the candidate stays preparing, and activation remains blocked with no lease to present

#### Scenario: Ledger write encounters legacy malformed entries
- **WHEN** the ledger file contains self-nested or non-lease entries from an earlier writer and the Kernel appends a new minted lease
- **THEN** the write persists only the canonical envelope with well-formed leases, and activation reads the clean ledger

### Requirement: The reserved health path is private to the node
The wasmd health attestation is an internal identity fact, never a public response. Public application routing — the `<app>.app.<base>` host and the `<base>/<app>/app` path alias, for every method including GET and HEAD — SHALL answer the reserved paths `/healthz` and the legacy `/iweb-health` with the generic bounded `404` of an unknown resource, without forwarding the request to the sandbox and without exposing any attestation byte, status code distinction, or header that reveals the path is reserved. Only the Kernel's private probe path over the sandbox gateway ingress socket may reach the health answer. A request that never routes to a sandbox cannot leak an execution identity.

#### Scenario: A visitor requests the health path on a public app host
- **WHEN** any unauthenticated visitor sends `GET /healthz` or `GET /iweb-health` to a routed wasm application host or its path alias
- **THEN** the response is the generic 404 with no attestation bytes and no routing side effect, and the Kernel liveness probe over the private ingress socket still succeeds

#### Scenario: Non-GET methods fare no better
- **WHEN** a visitor sends POST or HEAD to the reserved paths on a public app host
- **THEN** the same generic 404 applies and no method distinction leaks path existence

### Requirement: Wasm status projection is tier-honest
`GET /v1/wasm/status` (owner-authorized) SHALL project, per unactivated candidate: the readiness adoption state (`unprobed`, `not-ready`, `adopted-stale`, or `adopted` with its `adoptedAt`), and the lease state (none, minted with expiry, consumed at its route event, or expired). Per application it SHALL project the availability class (`active`, `unavailable`, `recovering`, or `stopped`) with the remaining restart budget as used-within-window versus `maxRestarts` and the owner-visible crash or resource category when stopped. Per-application resource rows for dead or recovering executions SHALL report `unavailable`, never a zero value standing in for a missing sample: zero is reserved for proven zero measurements and limits. The projection reads only Kernel-owned state and adds no new authority.

#### Scenario: Recovering application reports unavailable resources
- **WHEN** an application's execution is declared lost and bounded recovery is in progress
- **THEN** its per-app resource rows report `unavailable` (not zero) while its availability class reports `recovering` with the restart budget consumed so far

#### Scenario: Budget exhaustion is visible with its category
- **WHEN** recovery attempts exhaust `restart.maxRestarts` within `restart.windowMs`
- **THEN** the application projects `stopped` with the owner-visible crash or resource category and no further preparation is planned

#### Scenario: A stale adoption is labeled stale, not adopted
- **WHEN** the recorded adoption identity no longer equals the current fence facts
- **THEN** the candidate projects `adopted-stale` and activation remains blocked with no lease to present

## MODIFIED Requirements

### Requirement: Wasm readiness is a full identity attestation
The system SHALL emit the wasm internal health payload only in the exact v2 shapes below, as JCS, and only after wasmd loaded and verified the stated package bytes, binding, capability pin, secret snapshot revision/digest, config snapshot revision/digest, and live execution. The health wire has exactly two v2 forms and the served form follows the execution's matrix revision: a non-service execution (`matrixRevision` below 2) serves the base form, and a service execution (`matrixRevision` 2) serves the service form; an execution MUST NOT serve the other form, and a consumer MUST reject a form that disagrees with the fenced matrix revision.

```text
{
  schemaVersion: 2,
  ok: true,
  sandboxId: SandboxId,
  versionId: VersionId,
  packageDigest: sha256-hex,
  runtimeBinding: RuntimeBindingIdentityV1,
  capabilityRecordRevision: u53,
  capabilityRecordHash: sha256-hex,
  secretRevision: u53,
  secretValuesDigest: sha256-hex,
  configRevision: u53,
  configSnapshotRef: sha256-hex|null,
  configValuesDigest: sha256-hex|null,
  preparationGeneration: u53 >= 1,
  executionGeneration: u53 >= 1
}
```

The service form (`ServiceReadinessHealthV2`) is the base record with `runtimeBinding` replaced by the service binding `RuntimeBindingIdentityV2` (hostABI exactly `iweb-wasmd-abi@1.1.0`) plus one additional field `hostServicePolicyDigest`, which is the admitted `HostServicePolicyV2.policyDigest` `sha256-hex` pin or exactly the empty string for a policyless version (the same policyless grammar as the execution command and activation wire). The wasmd process is the only producer of either form: it answers health on exactly one fixed path, `GET /healthz`, on its single sandbox-local listener; no gateway, forwarder, or supervisor rewrites that path, and a readiness probe dials exactly that path. Two different defects must not be confused: a probe dialing any path other than `/healthz` is a caller-side wire defect (it never reaches a valid health answer), while a probe dialing the correct `/healthz` and receiving a non-200 (including a 404 from a stale forwarder) is one failed liveness probe like any other failed probe — it counts toward the bounded threshold and recovery is capped by the restart budget, so even a persistent misconfiguration cannot loop unboundedly.

Gateway receives an expected full attestation from the supervisor command and obtains the raw v2 attestation from wasmd over the fixed sandbox-local ingress target; it MUST NOT synthesize v2 health from gateway configuration or a successful TCP dial. It may return health 200 only if that ingress dial succeeds and every field exactly matches. A query or payload mismatch in sandbox ID, version ID, package digest, binding including catalog revision/hash, capability revision/hash, secret revision/digest, config revision/reference/digest, preparation generation, execution generation, schema version, `hostServicePolicyDigest` where the service form applies, or unknown field is a 409 internal mismatch; malformed/missing fields are 503 not-ready. The probe grants a readiness lease only from an exact v2 200 and records the same full identity, secret/config revisions, values digests, and snapshot references, `leaseNonce`, and `expiresAt`. A v1 celld health payload is parsed only by the celld route and can never ready wasm.

#### Scenario: Matching listener has the wrong package digest
- **WHEN** gateway can dial a wasmd listener but its health payload names another package digest
- **THEN** gateway returns mismatch, Kernel creates no readiness lease, and activation cannot proceed

#### Scenario: Matching package has a stale catalog binding
- **WHEN** health names the right version and package but a different catalog revision, catalog hash, entry key, image digest, ABI, or world
- **THEN** gateway returns mismatch and the candidate must be stopped or re-prepared with the pinned binding

#### Scenario: Readiness lease expires during CAS
- **WHEN** the exact health attestation once produced a lease but the lease expires before the Kernel route CAS linearizes
- **THEN** the route remains on the previous active identity and a fresh preparation plus exact health attestation is required

#### Scenario: Policyless service execution reports the empty policy digest
- **WHEN** a policyless service execution (`matrixRevision` 2) answers `GET /healthz` with the service form and `hostServicePolicyDigest` is exactly the empty string
- **THEN** the probe validates the form, correlates every remaining field, and readiness can be adopted exactly as for a policy-bearing execution

#### Scenario: Health is served on or dialed at any path other than /healthz
- **WHEN** a readiness probe or forwarder sends the health request to a path other than `/healthz`
- **THEN** the dial does not produce readiness: a non-200 answer or 404 counts as a failed probe, and no lease is minted from any other path or from configuration

### Requirement: Lifecycle keeps one routed execution while allowing bounded drain
The Kernel lifecycle state machine for wasm remains `admitted -> preparing -> ready -> active -> retired`, with `failed` and `stopped` terminal until another owner/recovery command. `retiring` is a supervisor-only execution substate (`executionSubstate:"retiring"`) recorded in the wasm execution journal and never written into Kernel `LifecycleState`; Kernel writes the old version's ordinary lifecycle as `retired` only after the route CAS and its drain receipt. This deliberate boundary preserves the existing `packages/contracts/records.ts` validator and celld state vocabulary. Every activation uses the `application-sandbox` Kernel route-pointer CAS and exact readiness lease. On successful activation, the new tuple becomes the only identity that gateway accepts for **new** traffic. The previous tuple enters supervisor `retiring`; it may complete only requests that gateway recorded as admitted before the pointer flip, receives no new request, and is forcibly stopped at `drainDeadlineMs`. Health/metrics from the retiring tuple may be retained as historical diagnostics but MUST NOT be adopted as current active measurements.

If a ready candidate dies before Kernel CAS, its activation aborts and the prior active route remains. If an active execution dies, exceeds an engine limit in a way that leaves it unable to serve (a whole-process exit, a vanished listener, or any state the bounded liveness probes declare lost — per-request engine errors such as an epoch or fuel trap on one request do not, by themselves, flip availability), or is declared lost by the liveness requirement, the Kernel first flips the active route pointer to `unavailable` in one controlRevision CAS (visitors then receive only the generic `application unavailable`), records a recovery intent naming the application, version, generations at loss, and a failure category, and then performs bounded recovery while the pinned capability record's `restart.maxRestarts` within `restart.windowMs` budget is not exhausted: it re-verifies the pinned catalog entry status (a revoked entry stops recovery into `stopped` with an owner-visible revocation category), allocates the next higher `preparationGeneration`, re-prepares with the snapshot at the version's pinned secret/config revision (identity-faithful recovery: the initial snapshot only when that is what the version pinned; never a newer revision and never a fresh empty one), and after that prepare is applied plans the next higher `executionGeneration` spawn, all through the existing command outbox and acknowledgement projection, with the restart attempt ledger persisted by the Kernel so crash replay never double-counts a window. A whole-node restart (every execution dead at once) enters the same per-application path idempotently. Budget exhaustion leaves the version `stopped` with an owner-visible crash or resource category and no automatic retry. Returning the application to `active` requires a readiness lease and one activation route CAS on the recovered execution: when the recovery intent is still valid and names the same version, the Kernel performs that activation itself after minting the lease (recorded with a `kernel-recovery` source so owner commands remain distinguishable); recovery never routes traffic before that CAS. A supervisor journal command completion followed by projection failure follows the authority/replay requirement and cannot create a half-active route.

#### Scenario: Active replacement leaves old execution alive
- **WHEN** the replacement tuple activates while the old execution still has in-flight work
- **THEN** gateway fences all new traffic to the new tuple, lets only pre-flip work drain on the old tuple until deadline, and force-stops it thereafter

#### Scenario: Active execution crashes
- **WHEN** the currently routed wasmd execution is declared lost by the bounded liveness probes
- **THEN** Kernel first makes the route unavailable, increments preparation and then execution generations for the recovery spawn within the restart budget, and no stale old health or metrics can restore traffic

#### Scenario: Whole node restarts while an application is active
- **WHEN** the container restarts, every wasmd process is gone, and the fence ledger still records the executions alive
- **THEN** Kernel boot probes declare each routed execution lost, each application's route becomes unavailable before recovery, recovery re-preparation and spawn run within the restart budget, and reactivation requires a fresh kernel-minted lease and activation CAS

#### Scenario: Restart budget exhausted
- **WHEN** recovery attempts exceed `restart.maxRestarts` within `restart.windowMs`
- **THEN** the version becomes `stopped` with an owner-visible crash or resource category, the route remains unavailable, and no further automatic preparation is planned

#### Scenario: Journal completion projection fails
- **WHEN** a prepare/start journal entry is durable but Kernel fails before its lifecycle projection or route CAS
- **THEN** replay produces one acknowledged command and Kernel either completes its own CAS or retains the old route; it never exposes two active routes or routes from journal state alone

### Requirement: Readiness leases use a nonce-bound canonical wire
The system SHALL represent every wasm readiness lease as the canonical `ReadinessLeaseV2` family (the base record below or its service form), not the existing celld `{versionId,expiresAt}` record. Its exact JCS object is:

```text
{
  schemaVersion: 2,
  leaseNonce: /^[a-f0-9]{32}$/,
  sandboxId: SandboxId,
  versionId: VersionId,
  packageDigest: sha256-hex,
  runtimeBinding: RuntimeBindingIdentityV1,
  capabilityRecordRevision: u53,
  capabilityRecordHash: sha256-hex,
  secretRevision: u53,
  secretValuesDigest: sha256-hex,
  configRevision: u53,
  configSnapshotRef: sha256-hex|null,
  configValuesDigest: sha256-hex|null,
  preparationGeneration: u53 >= 1,
  executionGeneration: u53 >= 1,
  issuedAt: RFC3339-UTC,
  expiresAt: RFC3339-UTC,
  leaseDigest: sha256-hex
}
```

`leaseNonce` is exactly 16 random bytes rendered as 32 lower-case hexadecimal characters; it is generated by Kernel for each successful v2 probe and is never derived from a timestamp or version ID. `secretValuesDigest` must equal the adopted `SnapshotRefV1.valuesDigest`; `configRevision:0` requires both `configSnapshotRef:null` and `configValuesDigest:null`, while a non-zero revision requires both non-null values and exact ref/digest equality. `expiresAt` must be later than `issuedAt` and no farther than the node capability `stagingTtlSeconds` from `issuedAt`. `leaseDigest = hex(SHA-256(UTF8("iweb-readiness-lease-v2\n" || JCS(record with leaseDigest omitted))))`. The persisted version candidate stores the complete lease bytes (or an exact content-addressed reference plus its digest), not merely `versionId` and `expiresAt`; a restart must either reload and validate this canonical record or mark the candidate not-ready.

The activation wire carries the service form of the lease, `ServiceReadinessLeaseV2`, which extends the base record with `hostServicePolicyDigest` (the admitted policy pin or the empty string for a policyless version) and uses the normalized service binding (`RuntimeBindingIdentityV2`); its digest is `digestV2("iweb-wasm-readiness-v2", JCS(record with leaseDigest omitted))` with a single `0x00` domain separator, deliberately incompatible with the base `iweb-readiness-lease-v2` newline domain so one family's digests can never validate in the other's. Every minting, storage, expiry, and CAS rule of this requirement applies verbatim to the service form. Kernel mints `ServiceReadinessLeaseV2` only as defined by the kernel-minting requirement; the readiness lease ledger stores exactly the canonical service-form envelope.

The Kernel route CAS matches `expectedRouteGeneration`, `applicationId`, the complete wasm `versionId`/package/binding/capability/secret/config/P/E identity, and `leaseNonce` plus `leaseDigest`. At the CAS linearization instant it compares the monotonic clock to `expiresAt`; an equal or later instant rejects with `READINESS_LEASE_EXPIRED`. A successful CAS consumes the nonce by recording `consumedAt` in the Kernel route event; the same nonce cannot activate, rollback, or rebind twice. Query/replay of an activation command returns the original consumed/rejected result. A lease from celld health v1, a lease with a missing nonce, a duplicate nonce for another tuple, a config reference inconsistent with `configRevision`, or a payload whose query parameters disagree with the record is rejected as `READINESS_LEASE_MISMATCH`.

#### Scenario: Lease replay after a successful route CAS
- **WHEN** a client retries an activation request carrying a previously consumed `leaseNonce`
- **THEN** Kernel returns the original route-CAS result and does not increment route generation or activate a second version

#### Scenario: Lease record is lost on restart
- **WHEN** a candidate's old control row contains only `versionId` and `expiresAt`, without a valid v2 nonce/digest
- **THEN** Kernel treats it as celld-only/invalid for wasm, retains the current route, and requires a fresh v2 probe

### Requirement: Kernel-owned admission uses one visible-state predicate
The Kernel SHALL own wasm admission authorization, version creation, and admission journal. A staging area and an admission-journal row are temporary execution-independent state, not an admitted version. The opaque admission commit token is 256 random bits generated by Kernel, never supplied by a package, and persisted only as `commitTokenHash = hex(SHA-256(UTF8("iweb-wasm-admission-token-v1\n" || tokenBytes)))`.

`AdmissionProofV1` is the exact JCS object shared by every durable admission witness:

```text
{
  schemaVersion: 2,
  applicationId: /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
  packageDigest: sha256-hex,
  versionDigest: sha256-hex,
  sequence: integer 1..9007199254740991,
  versionId: /^[a-f0-9]{64}-[1-9][0-9]{0,15}$/ where versionId = versionDigest || "-" || decimal(sequence),
  normalizedPolicy: NormalizedWasmManifestV1,
  lifecycleAdmissionRecord: {
    schemaVersion: 2,
    state: "admitted",
    admittedAt: RFC3339-UTC,
    admissionJournalRevision: u53
  },
  runtimeBinding: RuntimeBindingIdentityV1,
  capabilityRecordRevision: u53 >= 1,
  capabilityRecordHash: sha256-hex,
  commitTokenHash: sha256-hex
}
```

`normalizedPolicy` is the complete normalized manifest from the digest requirement, not a mutable user manifest or a subset. It SHALL have `name = applicationId`; `lifecycleAdmissionRecord` is the immutable admission-time projection used to create the Kernel wasm registry row and has no later lifecycle states; `versionDigest` SHALL equal `wasmVersionDigestV1(packageDigest, JCS(normalizedPolicy))`; and `versionId` is the only version identity carried into object markers, database rows, materializer receipts, execution commands, leases, active pointers, and rollback records. The version key is `(applicationId, versionId)`, not merely `(applicationId, versionDigest)`: a retry joins an existing exact proof; a later owner-authorized admission of the same digest allocates a higher sequence and therefore a different proof/versionId. Sequence allocation is a Kernel control-state CAS and never inferred from an array length.

For one `(applicationId, versionId)`, the normal journal path is exactly `staging -> validated -> object-complete -> db-hidden -> materializer-acknowledged -> visible`. `visible`, `failed`, and `collected` are terminal; a nonterminal state may transition to `failed`, and only `failed` may transition to `collected`. No other transition or regression is valid, with exactly one sanctioned exception: a journal row in `visible` whose `AdmittedVisible` predicate is false transitions once to `failed` (a journal-revision CAS verification transition triggered by the structured code `WASM_ADMISSION_WITNESS_MISSING`, with an owner-visible log), after which the existing `failed -> collected` path applies. Its exact durable object is `{schemaVersion:1,proof:AdmissionProofV1,state,journalRevision,leaseExpiresAt}`; `state` is one of those literals, `journalRevision` starts at `0` and increases by exactly one for each committed transition, and `leaseExpiresAt` is `RFC3339-UTC` for a nonterminal state or `null` for a terminal state. When it creates a journal, Kernel derives `leaseExpiresAt` from the proof-pinned `admission.stagingTtlSeconds`; it may extend the lease only with a successful journal-revision CAS before expiry. An expired nonterminal row may only transition to `failed` and then collection; it MUST NOT continue toward `visible`. Kernel atomically creates-or-joins the one journal row keyed by `(applicationId, versionId)`: it generates the 256-bit token only for the winning insert, and every concurrent retry of that exact proof receives that same persisted proof and token hash. Each later mutation is idempotent by `(applicationId, versionId, commitTokenHash)`. The object completion marker is exactly `{schemaVersion:1,proof:AdmissionProofV1}`. The hidden or visible Kernel DB row is exactly `{schemaVersion:1,proof:AdmissionProofV1,visibility:"hidden"|"visible"}`. The materializer receipt is exactly `{schemaVersion:1,proof:AdmissionProofV1,materializationTarget}` where `materializationTarget` is `mat-` followed by the first 40 lower-case hex characters of `SHA-256(UTF8("iweb-wasm-materializer-target-v1\n" || JCS(proof)))`. All three witnesses must use byte-identical `proof`; materialization may cache bytes but MUST NOT start an execution while the row is hidden.

Every visibility answer — including the create-or-join response for an existing row and every reader, prepare, route selection, rollback selection, and ordinary version API — SHALL be derived from the `AdmittedVisible` predicate below, never from the admission journal row's `state` alone. Every surface that observes a journal row in `visible` whose predicate is false (any witness missing or non-identical) — join, reconcile pass, or reader — performs the same one-time idempotent `visible -> failed` verification transition defined above; the row is removed from all eligible routing and preparation and requires owner recovery, and the Kernel never recreates a missing witness from mutable bytes. A witness-verification failure for one row excludes exactly that row with an owner-visible log; it MUST NOT abort the reconcile pass or fail other versions' admissions.

When projected to the Kernel-owned wasm `WasmKernelRouteRegistryV1`, the record uses `runtimeKind:"wasm"`, `versionId = proof.versionId`, `identity = {applicationId: proof.applicationId, digest: proof.versionDigest, sequence: proof.sequence}`, `packageDigest = proof.packageDigest`, `normalizedPolicy = proof.normalizedPolicy`, `runtimeBinding = proof.runtimeBinding`, `admissionProofRef = "admission-proof/" || proof.applicationId || "/" || proof.versionId`, `admissionProofDigest = hex(SHA-256(UTF8("iweb-admission-proof-v1\n" || JCS(proof))))`, and lifecycle `admitted`/later Kernel-valid values. The existing celld `VersionRecord` projection remains available only for celld records; its `policy` projection rule is not a wasm parser. The wasm active pointer names the same `{applicationId,digest,sequence}` plus complete binding/proof reference; no implementation may use the legacy celld `VersionRecord.versionId = digest` representation for wasm.

For any proof, admitted or joined, admission SHALL fail closed on the pinned node capability record's runtime reserve exactly as the capability-record requirement's admission and preparation rule requires: the `runtimeReserves` entry for the selected runtime binding artifact identity plus host architecture must exist (no default or zero reserve is substituted), and `reserveBytes >= resources.memoryBytes` rejects so that the guest linear-memory limit `memoryBytes - reserveBytes` is positive. The reserve lookup key is the binding artifact identity — kind, catalog revision and hash, entry key, image digest, and world, plus architecture — and deliberately excludes the `hostABI` wire-generation label, exactly as the wasmd runtime-reserve matcher does: a service command binding (`iweb-wasmd-abi@1.1.0`) matches a reserve entry pinned to the v1 label (`iweb-wasmd-abi@1.0.0`) when every artifact field agrees, and no literal full-field match is performed. A violation is rejected at admission with `WASM_RESOURCE_RECORD_INVALID` and MUST NOT surface first at spawn time. The host-service policy reserve check for policy-bearing proofs is unchanged.

`AdmittedVisible(version)` is the only visibility predicate and is true exactly when all of these hold simultaneously:

```text
1. verified content-addressed object + matching completion marker exists;
2. one Kernel control-DB row is committed with visibility "visible";
3. one durable materializer receipt exists;
4. the complete `AdmissionProofV1`, including `versionId`, `sequence`, and `normalizedPolicy`, is byte-identical in all three records.
```

Readers, prepare, route selection, rollback selection, and ordinary version APIs MUST use this predicate. They MUST NOT treat an object marker, a hidden DB row, a materializer cache, a supervisor journal entry, or an admission journal row state as a visible version. The durable sequence is: stream/validate staging under record budgets; write all content-addressed blobs and verified marker; insert hidden DB row; send idempotent materializer handoff and receive receipt; atomically change the Kernel row to `visible`; record journal `visible`. This is a recovery protocol, not a claim of cross-store atomic write.

Recovery and collection SHALL be deterministic:

| Observed durable state after interruption | Required recovery / GC result |
| --- | --- |
| staging only | resume same upload only while its journal lease is valid; otherwise transition it to failed and collect staging at `stagingTtlSeconds` |
| complete marker, no DB row | only while the validated journal/token lease remains valid, insert the same hidden row; otherwise transition failed and collect the unreferenced prefix after TTL |
| hidden DB row, no receipt | while the journal lease remains valid, resend the same handoff; a missing/corrupt object or lease expiry marks the hidden row failed and then collects only after no replay owner remains |
| receipt, hidden DB row | retry only the DB `hidden -> visible` CAS; the materialized bytes remain non-executable until it succeeds |
| visible DB row, missing marker/receipt on verification | fail closed, remove it from eligible routing, and require owner recovery; never recreate from mutable workspace bytes |
| journal row `visible`, predicate false (witness missing or non-identical) | the sanctioned `visible -> failed` verification transition (`WASM_ADMISSION_WITNESS_MISSING`, owner-visible log); no execution, routing, or preparation may observe the version; existing `failed -> collected` GC then applies; owner recovery only |
| visible DB row, journal still `materializer-acknowledged` | verify the complete proof and append the idempotent terminal journal `visible` transition; readers already use the predicate and never use journal state alone |
| client response lost | query by application/versionId returns the one journal outcome; retry with the exact proof cannot create another version or materializer target |

GC MUST retain any object, hidden row, receipt, or journal record still reachable by a nonterminal token. It may delete only terminal collected staging/prefixes or failed records whose retention window expired and whose object/DB/materializer references have all been checked. Concurrent retries of the same proof join `(applicationId, versionId)`; a new sequence is never silently allocated by a retry.

#### Scenario: Completion marker exists with no DB record
- **WHEN** the object-store marker is durable but the node loses power before the hidden DB insert
- **THEN** the version is not visible; replay either inserts the same hidden row using its token or garbage-collects the marker after its journal expires

#### Scenario: DB commit succeeds but materializer handoff fails
- **WHEN** a hidden DB row commits and the handoff request or acknowledgement is lost
- **THEN** replay resends the same token-bound handoff, and the row cannot become visible or executable until one matching receipt exists

#### Scenario: Concurrent duplicate admission
- **WHEN** two owner-authorized callers submit the same layout and normalized manifest for one application
- **THEN** they converge on one token-bound version transaction and one immutable visible version, without duplicate object or materializer ownership

#### Scenario: Join answers from a journal-only visible row
- **WHEN** an admission retry joins a row whose journal says `visible` but the control-DB row (or any other witness) is missing
- **THEN** the row takes the sanctioned `visible -> failed` verification transition with `WASM_ADMISSION_WITNESS_MISSING`, the response reports `failed`, no preparation or outbox command is planned for it, and the Kernel does not recreate the missing witness

#### Scenario: One ghost row does not block other admissions
- **WHEN** the reconcile pass encounters a version whose witnesses fail verification while another application submits a valid admission
- **THEN** the ghost version is excluded with an owner-visible log and the valid admission proceeds normally

#### Scenario: Policyless admission does not exceed the runtime reserve
- **WHEN** an admission transaction without a host-service policy requests `memoryBytes` equal to or below the `runtimeReserves` entry for the selected binding and architecture
- **THEN** admission is rejected with `WASM_RESOURCE_RECORD_INVALID` at submission, and no prepare or start command is ever planned or spawn-rejected later

### Requirement: Kernel authorizes lifecycle while supervisor journals execution only
The Kernel SHALL remain the authority for admitted version identities, policies, lifecycle business state, owner authorization, and the active route pointer. The supervisor SHALL keep a durable **execution transaction journal** only: it receives a Kernel-authorized `ExecutionCommand`, starts, checks, drains, or stops a concrete execution, and records an acknowledgement. It SHALL NOT create an admitted version, choose a rollback target, update a Kernel lifecycle state, or make a route pointer visible.

The execution transport speaks exactly one protocol. Wasm uses only `POST /v1/execution-rpc` with a raw JCS `ExecutionRpcEnvelopeV1`; an envelope carrying celld-era `version`/`operation` fields, `protocol` markers outside the v1 literal, or any unknown protocol shape MUST be rejected (`EXECUTION_PROTOCOL_MISMATCH` / `CELLD_PROTOCOL_MISMATCH`) without fallback parsing or retry through another path. The execution HTTP socket carries HTTP request/response bytes only: it MUST reject the raw snapshot magic, any `SCM_RIGHTS` ancillary data, and any non-HTTP preamble before parsing the body. Snapshot descriptors use the separate `SnapshotFdTransportV1` socket defined below; a receiver MUST never switch sockets or reinterpret one transport as the other.

`ExecutionRpcEnvelopeV1` has exactly `{protocol,requestId,body}`. `protocol` is the literal `"iweb-execution-rpc-v1"`; `requestId` is a lower-case UUIDv7; and `body` is exactly one of the three typed payloads below. The response has exactly `{protocol,requestId,body}` with the same protocol and requestId. This transport is carried only over the fixed `/run/iweb-sandbox/supervisor.sock` Unix-domain socket. In the current deployment the **native snapshot-fd relay** (a supervised child of the supervisor process, both running as the in-container service user `iweb-sandbox` started by the node entrypoint) is the sole creator and listener of the public socket: it calls `listen`, creates the inode, applies mode `0600`, enforces the per-connection `SO_PEERCRED` and inode re-checks on that public socket, and proxies authorized connections to the Node supervisor's private upstream socket with a process-lifetime authorization token; the Node supervisor never binds the public socket. Kernel is the connecting peer and runs as UID/GID `0/0` in the same node container. The socket is never container-published, and neither envelope carries an owner bearer token. The precise peer and path authorization is specified by `SupervisorSocketAuthV1` below; a caller unable to pass both filesystem and peer-credential checks cannot submit, query, or replay a command. A future non-root Kernel deployment or cross-host transport requires a new deployment/protocol revision and explicit mutual authentication; it may not weaken this v1 by changing an environment path or adding an optional header.

`ExecutionCommand` has exactly `schemaVersion:2`, `commandId`, `expectedControlRevision`, `expectedJournalRevision`, `operation`, `identity`, `applicationId`, `packageDigest`, `runtimeBinding`, `matrixRevision`, `hostServicePolicyDigest`, `fenceNonce`, `capabilityRecordRevision`, `capabilityRecordHash`, `secretRevision`, `secretSnapshotRef`, `secretValuesDigest`, `configRevision`, `configSnapshotRef`, and `configValuesDigest`. `commandId` is a lower-case UUIDv7; `operation` is one of `prepare`, `start`, `drain`, `stop`; `expectedControlRevision` is the expected single `wasm-control-state-v2` `controlRevision`, and with `expectedJournalRevision`, `secretRevision`, and `configRevision` is `u53`; `identity` is the full execution identity below; `applicationId` is the host-injected execution identity; `runtimeBinding` is the complete `RuntimeBindingIdentityV1` field set with `hostABI` exactly `iweb-wasmd-abi@1.1.0`; `matrixRevision` is the literal `2`; `hostServicePolicyDigest` is the admitted `HostServicePolicyV2.policyDigest` `sha256-hex` pin, or exactly the empty string when the admitted version carries no host-service policy (the policyless zero-value policy: `kv`, `sql`, and `logging` all `null`, `storageBytes:0`, `reserveBytes:0`, `policyDigest:""`); `fenceNonce` is `/^[a-f0-9]{32}$/`; `secretSnapshotRef` is a `sha256-hex` opaque Kernel reference that contains no value; `secretValuesDigest` is the exact `SnapshotRefV1.valuesDigest` for that ref; `configSnapshotRef` is a `sha256-hex` opaque Kernel reference or `null` exactly when `configRevision` is `0`; and `configValuesDigest` is the exact config snapshot `valuesDigest` or `null` exactly when `configSnapshotRef` is `null`. For `prepare`/`start`, both digest bindings are checked before execution; for `drain`/`stop`, the command still carries the adopted snapshot digests and they remain part of the identity fence. `CommandRequestV1` is exactly `{kind:"command",command:ExecutionCommand}`.

`ExecutionAcknowledgement` has exactly `{schemaVersion:2,commandId,operation,identity,applicationId,packageDigest,runtimeBinding,matrixRevision,hostServicePolicyDigest,fenceNonce,capabilityRecordRevision,capabilityRecordHash,secretRevision,secretSnapshotRef,secretValuesDigest,configRevision,configSnapshotRef,configValuesDigest,drainReceiptDigest,result,failureCode,journalRevision}`. All echoed identity, config, snapshot, and values-digest fields must exactly equal the command; `drainReceiptDigest` is non-null only when `operation:"drain"` and `result:"applied"`, and then is the digest of the exact `DrainReceiptV1`; a rejected drain has `drainReceiptDigest:null`. `result` is `applied` or `rejected`; `failureCode` is `null` if and only if result is `applied`, otherwise it matches `/^[A-Z][A-Z0-9_]{0,63}$/`; and `journalRevision` is the durable revision that recorded this terminal command result. `CommandResponseV1` is exactly `{kind:"acknowledgement",acknowledgement:ExecutionAcknowledgement}`.

`CommandQueryV1` is exactly `{kind:"query",commandId:UUIDv7}` and returns exactly `{kind:"query-result",commandId,status,received,acknowledgement,readinessAdoption}`. `status` is `"missing"`, `"received"`, or `"completed"`; `received` is `null` only for `missing`, otherwise its exact `CommandReceivedV1`; `acknowledgement` is non-null if and only if `status:"completed"`; and `readinessAdoption` is the read-only readiness adoption projection (`ReadinessAdoptionProjectionV1`, below) consumed by the kernel-minting requirement — `null` when the queried command is not a `start` or no exact-match v2 adoption exists, except that the supervisor may first run one fresh probe for a current in-place execution per that requirement.

`ReadinessAdoptionProjectionV1` is the exact JCS object a non-null `readinessAdoption` carries, with exactly these keys and no others:

```text
{
  schemaVersion: 1,
  sandboxId: SandboxId,
  versionId: VersionId,
  packageDigest: sha256-hex,
  runtimeBinding: RuntimeBindingIdentityV2,
  hostServicePolicyDigest: sha256-hex | "",
  capabilityRecordRevision: u53,
  capabilityRecordHash: sha256-hex,
  secretRevision: u53,
  secretValuesDigest: sha256-hex,
  configRevision: u53,
  configSnapshotRef: sha256-hex|null,
  configValuesDigest: sha256-hex|null,
  preparationGeneration: u53 >= 1,
  executionGeneration: u53 >= 1,
  adoptedAt: RFC3339-UTC
}
```

The identity fields are byte-equal to the `ServiceReadinessHealthV2` the adoption was correlated from, and `hostServicePolicyDigest` follows the same policyless empty-string grammar. `adoptedAt` is the supervisor clock instant the adopting probe answered 200 on the fixed `/healthz` path; the Kernel treats an adoption as current only while its identity equals the fence, registry, and start-command facts field-for-field — `adoptedAt` age alone never validates or invalidates an adoption. A malformed projection, an unknown key, or a projection whose identity disagrees with the current fence is `null`-equivalent for minting (the Kernel mints nothing) and the query itself never fails from adoption content. Wire integrity rides the `SupervisorSocketAuthV1` transport (peer credential plus fixed-path checks) like every other execution-rpc payload; the projection carries no independent digest. `CommandReplayV1` is exactly `{kind:"replay",command:ExecutionCommand}` and returns the same `CommandResponseV1` for that command ID. Replay accepts only a byte-identical command JCS body: a known command ID with any differing field returns `EXECUTION_COMMAND_ID_CONFLICT`; a completed command returns its stored acknowledgement without repeating the execution side effect; a received but incomplete command resumes exactly its recorded operation under its stored fence. Kernel writes its outbox in the same wasm control-state CAS that authorizes the command, delivers it through this channel, and uses query/replay after any uncertain response; no owner key travels in this channel.

The supervisor first CAS-writes a `command-received` journal entry at `expectedJournalRevision`, performs the idempotent execution side effect, then CAS-writes this completion acknowledgement before returning it. It accepts no command unless both expected revisions and the identity fence match. Kernel accepts an acknowledgement only when command ID, every echoed command field, result wire, and current Kernel control revision still match; otherwise it treats it as stale, reconciles it, and never routes from it.

A supervisor completion that arrives before or after a Kernel crash is replay evidence, not routing authority. On reconciliation Kernel queries/replays the exact command ID, validates its acknowledgement, writes its own projection with CAS, and only then may issue the Kernel route-pointer CAS required by `application-sandbox`.

#### Scenario: Supervisor journal commits before Kernel projection
- **WHEN** a supervisor has durably acknowledged an execution command and Kernel crashes before persisting its projection
- **THEN** restart reconciliation replays the same command ID and never routes from the journal alone

#### Scenario: Unauthorised supervisor mutation is attempted
- **WHEN** a supervisor journal entry attempts to name a new version, replacement binding, or active route without a matching Kernel command
- **THEN** the Kernel rejects it and retains its own authoritative version and route records

#### Scenario: Celld RPC envelope is sent to the wasm endpoint
- **WHEN** a caller sends `{version:1,operation:"prepare",...}` to `POST /v1/execution-rpc`
- **THEN** the receiver rejects it with `CELLD_PROTOCOL_MISMATCH`, performs no side effect, and never falls back to another parser

#### Scenario: Kernel loses the command response
- **WHEN** a supervisor may have received a command but Kernel loses the HTTP response or restarts before projection
- **THEN** Kernel sends `CommandQueryV1` and, if needed, byte-identical `CommandReplayV1`; one stored acknowledgement and at most one execution side effect result
