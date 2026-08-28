<!-- 用户原始需求（2026-08-27）：扩展归档 wasm-application-runtime，硬化 add-wasm-host-services 的 V2 identity/wire、quota authority、host-call 传输与 V1 共存；只改 OpenSpec change，不写实现。 -->
<!-- 正交意图：定义 service-enabled wasm 的不可变身份；定义跨层 wire/replay；定义控制态与数据面边界及发布门。 -->
<!-- 不可调和原因：admission、execution、route、quota 和服务调用必须共享同一 identity/fence，拆分会允许部分绑定。 -->

## MODIFIED Requirements

### Requirement: Capability record revision 1 is a typed exact matrix

The existing revision-1 matrix SHALL remain valid for versions that import only the original HTTP/config/secrets surface. A version that imports any new host service SHALL use an exact capability record with a distinct schema marker and matrixRevision:2; a revision-1 record, catalog binding, acceptance record, or parser MUST NOT be interpreted as revision 2 by fallback. The revision-2 record contains the complete revision-1 entries and the exact additional imports:

~~~text
{package:"iweb:kv@1.0.0", interface:"store", direction:"import"}
{package:"iweb:sql@1.0.0", interface:"store", direction:"import"}
{package:"iweb:logging@1.0.0", interface:"logger", direction:"import"}
~~~

The revision-1 world, required export, and original imports remain unchanged. Service-enabled V2 uses hostABI:"iweb-wasmd-abi@1.1.0"; V1 keeps iweb-wasmd-abi@1.0.0. The revision-2 matrix is the bytewise sorted union of the exact revision-1 imports and the declared new imports. It adds no wildcard, range, socket/filesystem/TLS interface, RustFS credential, or untyped core import.

Each V2 version carries exactly hostServices:{kv,sql,logging}, where each member is null or {profile,limits,consistency,durability,retention}. A non-null member requires the matching exact import, an owner-recorded profile, and a policy digest; a null member forbids that import. The node capability record supplies maxima for every selected limit. Missing/unknown fields, a limit above node maxima, an import/profile mismatch, or absent V2 catalog/acceptance evidence fails closed before materialization. The decoded closure, required export, internal provider resolution, graph budgets, and V1 rejection codes remain in force.

#### Scenario: A V1 version continues without new services
- **WHEN** an admitted version imports only the original revision-1 capabilities and matches the V1 capability, catalog, and acceptance records
- **THEN** it remains eligible under the V1 gate and no V2 service binding is inferred

#### Scenario: A new service is presented to a V1 record
- **WHEN** a version declares any of the three new imports while the selected record, catalog, or acceptance evidence is revision 1
- **THEN** admission fails closed with a capability/matrix mismatch before materialization or execution

#### Scenario: Declared and discovered imports differ
- **WHEN** a service policy enables an import absent from the decoded closure, or the closure contains an import whose policy member is null
- **THEN** admission returns WASM_DECLARATION_MISMATCH and creates no visible version

#### Scenario: A service import has the wrong package revision
- **WHEN** a component imports iweb:kv@1.0.1/store, iweb:sql@1.0.1/store, or iweb:logging@1.0.1/logger
- **THEN** admission returns WASM_INTERFACE_VERSION_UNLISTED and does not try the V1 parser

#### Scenario: Nested component and re-export resolve internally
- **WHEN** an entry component imports a type-identical interface re-exported from one reachable nested component
- **THEN** the scanner records no host capability for that edge and accepts it only if the provider is unique and the complete graph remains within budget

#### Scenario: Adapter attempts to smuggle a host import
- **WHEN** an adapter or core module has an external import that cannot be proven to resolve internally through decoded Component Model linkage
- **THEN** admission rejects with WASM_ADAPTER_EXTERNAL_IMPORT or WASM_IMPORT_UNMAPPABLE

#### Scenario: Known interface has the wrong patch
- **WHEN** a component imports wasi:http/outgoing-handler@0.2.7 or any non-0.2.8 revision
- **THEN** admission rejects with WASM_INTERFACE_VERSION_UNLISTED

### Requirement: Wasm publication requires a canonical kind-bound acceptance record

The wasm publication gate SHALL keep the archived V1 acceptance contract for versions that import only the original revision-1 surface, and SHALL use a distinct V2 host-service acceptance contract for any version that imports KV, SQL, or logging. Both records are read only from the immutable Kernel-owned fixed path `/opt/iweb/release/wasm-sandbox-acceptance.json`; no application package, image mount, runtime path, or environment variable may provide or redirect the record. A V1 record has the existing exact fields and `version:2`, `hostABI:"iweb-wasmd-abi@1.0.0"`; a service-enabled record has `version:3`, `matrixRevision:2`, `hostABI:"iweb-wasmd-abi@1.1.0"`, `hostServicePolicyDigest`, `catalogRevision`, `catalogHash`, `capabilityRecordRevision`, `capabilityRecordHash`, `runtimeImageDigest`, `world`, `arch`, `evidenceDigest`, and `recordDigest` in addition to `result:"passed"`, `gate:"application-sandbox"`, and `runtimeKind:"wasm"`. Each record is strict JCS with no unknown fields; its recordDigest is computed over the exact record with only recordDigest omitted under its versioned acceptance hash domain.

The celld V1 acceptance record and `IWEB_APPLICATION_PUBLICATION_ENABLED` switch cannot open a service-enabled wasm gate. The service-enabled gate additionally requires `IWEB_WASM_PUBLICATION_ENABLED=1`, the application publication switch, a matching V2 catalog binding, capability record, HostServiceIdentityV2 and independent sandbox evidence. Missing, malformed, stale, owner-undecided or mismatched evidence fails closed before materialization or execution; the validator never falls through to the other record version.

#### Scenario: Canonical record has an unknown field
- **WHEN** an otherwise passed wasm acceptance record contains an extra field or a digest computed over a different field set
- **THEN** the gate rejects it before checking enablement and wasm publication remains closed

#### Scenario: Acceptance record does not match current node identity
- **WHEN** record catalog/capability revision or hash, architecture, entry key, image digest, ABI, world, matrix revision, or service policy digest differs from the selected binding
- **THEN** wasm publication fails closed until a matching fixed-image record exists

#### Scenario: Celld-era record is the only record
- **WHEN** the node has only a valid v1 application-sandbox acceptance record
- **THEN** celld follows its existing gate while service-enabled wasm publication remains disabled

## ADDED Requirements

### Requirement: Host-service V2 identity is exact and immutable

For every service-enabled version, Kernel SHALL construct HostServicePolicyV2 and HostServiceIdentityV2 with strict exact-key JCS encoding. JSON digest fields are 64 lower-case hex characters; binary host-call digest fields are exactly 32 octets. Unknown fields, duplicate keys, non-canonical JSON, alternate encodings, or a hash over hex text instead of raw payload bytes are invalid.

~~~text
HostServicePolicyPayloadV2 = {
  schemaVersion: 2,
  matrixRevision: 2,
  hostAbi: "iweb-wasmd-abi@1.1.0",
  hostServices: {
    kv: null | {profile,limits,consistency,durability,retention},
    sql: null | {profile,limits,consistency,durability,retention},
    logging: null | {profile,limits,consistency,durability,retention}
  },
  storageBytes,
  reserveBytes,
  dataDirectoryProfile: "per-app-sqlite-v1",
  durabilityProfile: "sqlite-full-fsync-v1"
}
HostServicePolicyV2 = HostServicePolicyPayloadV2 + {
  policyDigest: digestV2("iweb-wasm-host-policy-v2", JCS(payload))
}
~~~

digestV2(domain,payloadBytes) is SHA-256(ASCII(domain) || 0x00 || payloadBytes); the domain is an exact ASCII literal and the payload is the raw UTF-8 JCS bytes. HostServiceIdentityV2 has exactly {schemaVersion:2,applicationId,versionId,packageDigest,versionDigest,matrixRevision:2,hostAbi,capabilityRecordRevision,capabilityRecordHash,catalogRevision,catalogHash,hostServicePolicyDigest}. V2 versionDigest hashes JCS({schemaVersion:2,packageDigest,normalizedPolicy,hostServicePolicyDigest,matrixRevision:2,hostAbi}) under iweb-wasm-host-identity-v2; V2 versionId is <versionDigest>-<positive-sequence>. V1 digests and IDs are never rewritten or treated as V2. JSON/JCS policyDigest and catalogHash fields are 64 lower-case hex characters; binary host-call digests are 32 raw octets represented as unpadded base64url and must decode to the same bytes.

HostServiceBindingV2 is exactly {schemaVersion:2,identity,hostServicePolicyDigest,matrixRevision:2,hostAbi,capabilityRecordRevision,capabilityRecordHash,catalogRevision,catalogHash,catalogEntryKey,acceptanceRecordDigest,runtimeImageDigest,architecture,executionFence,bindingDigest}; its policy/capability/catalog/acceptance fields MUST equal the identity and its bindingDigest is digestV2("iweb-wasm-catalog-binding-v2", JCS(binding without bindingDigest)). The executionFence is exactly {sandboxId,preparationGeneration,executionGeneration,fenceNonce}; fenceNonce is a host-issued opaque 16-byte value rendered as 32 lower-case hex characters.

The V2 records are exact JCS objects (no omitted or extra fields):

~~~text
AdmissionProofV2 = {
  schemaVersion: 2, identity, normalizedPolicy, hostServicePolicy,
  capabilityRecord, catalogBinding, sequence, lifecycleAdmissionRecord,
  commitTokenHash, proofDigest
}
CatalogBindingV2 = {
  schemaVersion: 2, identity, hostServicePolicyDigest, matrixRevision: 2,
  hostAbi, capabilityRecordRevision, capabilityRecordHash,
  catalogRevision, catalogHash, catalogEntryKey, runtimeImageDigest,
  acceptanceRecordDigest, architecture,
  bindingDigest
}
ControlStateApplicationV2 = {
  schemaVersion: 2, identity, controlRevision, servicePolicySummary,
  schemaReferences, backupReferences, routePointer, lifecycle, controlStateDigest
}
ExecutionCommandV2 = {
  schemaVersion: 2, commandId, expectedControlRevision, expectedJournalRevision,
  operation, identity, executionFence, secretRevision, secretSnapshotRef,
  secretValuesDigest, configRevision, configSnapshotRef, configValuesDigest,
  commandDigest
}
ExecutionAcknowledgementV2 = {
  schemaVersion: 2, commandId, operation, identity, executionFence,
  policyDigest, capabilityRecordRevision, capabilityRecordHash,
  catalogRevision, catalogHash, proofDigest, secretValuesDigest,
  configValuesDigest, result, failureCode, journalRevision,
  acknowledgementDigest
}
ReadinessLeaseV2 = {
  schemaVersion: 2, leaseNonce, identity, executionFence, listenerProof,
  policyDigest, capabilityRecordRevision, capabilityRecordHash,
  catalogRevision, catalogHash, proofDigest, issuedAt, expiresAt,
  leaseDigest
}
MetricsSampleV2 = {
  schemaVersion: 2, sampleId, identity, executionFence, sampledAt,
  availability, engine, hostServiceUsage, loggingDropped, metricsDigest
}
ActivationCommandV2 = {
  schemaVersion: 2, activationId, applicationId, operation,
  expectedRouteGeneration, candidate, expectedControlRevision, requestedAt,
  commandDigest
}
RouteEventV2 = {
  schemaVersion: 2, eventId, activationId, applicationId, operation,
  expectedRouteGeneration, previous, next, leaseConsume, controlRevision,
  result, reasonCode, routeGeneration, createdAt, eventDigest
}
RollbackRecordV2 = {
  schemaVersion: 2, rollbackId, applicationId, from, to,
  expectedRouteGeneration, expectedControlRevision, reasonCode, routeEvent,
  result, createdAt, rollbackDigest
}
~~~

The fields above have these exact constraints: identifiers use the existing ApplicationId/VersionId/SandboxId/UUIDv7 types; revisions, generations, route/control revisions and sequence are non-negative safe integers with the existing lower bounds; `operation` is `prepare|start|drain|stop` for execution and `activate|rollback` for route commands; `result` is `applied|rejected` for commands and `activated|rejected` for route events; `reasonCode` is null exactly on success or a bounded upper-case code on rejection. `secretSnapshotRef`, `configSnapshotRef`, and their values digests retain the V1 null/equality rules. `listenerProof` is the full attested listener/binding object, `servicePolicySummary` is the static policy projection without dynamic usage, `schemaReferences` and `backupReferences` are sorted opaque content references, `routePointer` and `previous/next/candidate` carry the complete identity plus execution fence, and `engine`/host-service usage are null exactly when `availability:"unavailable"`. `hostServiceUsage` contains only bounded committed/reserved bytes and usage revision; it contains no payload. `ExecutionAcknowledgementV2` uses `iweb-wasm-execution-ack-v2`, `ActivationCommandV2` uses `iweb-wasm-activation-v2`, and `RouteEventV2` uses `iweb-wasm-route-event-v2`. Every self-digest covers the complete object with only its own digest field omitted and uses the named V2 domain.

The identity object, or a byte-identical projection of it, SHALL be present in every V2 record above. Receivers MUST recompute each digest and compare matrix/ABI/policy/capability/catalog/acceptance pins, application/version identity, route/control revision and P/E fence before side effects. Later records echo the policy/identity digest rather than copying mutable data.

#### Scenario: Policy mutation cannot change an admitted identity
- **WHEN** an owner changes a service profile, limit, SQL dialect, transaction boundary, retention, or quota after admission
- **THEN** the existing version keeps its original policy digest and a new version identity is required

#### Scenario: One projection disagrees with the identity
- **WHEN** command, readiness, metrics, activation, rollback, catalog, or control state reports a different policy/capability/catalog/ABI digest
- **THEN** Kernel rejects the record as a stale identity and does not start, activate, route, or project it

### Requirement: Service-enabled lifecycle uses V2 projections end to end

For a version whose discovered imports contain KV, SQL, or logging, every lifecycle wire SHALL use the V2 projection below; the V1 command, readiness, metrics, activation, rollback, and admission-proof shapes remain available only to versions with no new service import. This requirement supersedes any baseline reference to a V1 wire for a service-enabled version. No receiver may infer V2 from a missing field or downgrade V2 to V1.

The V2 projections have exact fields and authority:

| Wire | Exact required fields |
| --- | --- |
| AdmissionProofV2 | schemaVersion:2, identity, normalizedPolicy, hostServicePolicy, capabilityRecord, catalogBinding, sequence, lifecycleAdmissionRecord, commitTokenHash, proofDigest |
| CatalogBindingV2 | schemaVersion:2, identity, catalogRevision, catalogHash, catalogEntryKey, runtimeImageDigest, acceptanceRecordDigest, architecture, bindingDigest |
| ControlStateApplicationV2 | schemaVersion:2, identity, controlRevision, servicePolicySummary, schemaReferences, backupReferences, routePointer, lifecycle, controlStateDigest |
| ExecutionCommandV2 | schemaVersion:2, commandId, expectedControlRevision, expectedJournalRevision, operation, identity, executionFence, secretRevision, secretSnapshotRef, secretValuesDigest, configRevision, configSnapshotRef, configValuesDigest, commandDigest |
| ExecutionAcknowledgementV2 | schemaVersion:2, commandId, operation, identity, executionFence, policy/capability/catalog/proof digests, snapshot digests, result, failureCode, journalRevision, acknowledgementDigest |
| ReadinessLeaseV2 | schemaVersion:2, leaseNonce, identity, executionFence, listenerProof, policyDigest, capabilityRecordRevision/hash, catalogRevision/hash, proofDigest, issuedAt, expiresAt, leaseDigest |
| MetricsSampleV2 | schemaVersion:2, sampleId, identity, executionFence, sampledAt, availability, engine, hostServiceUsage, loggingDropped, metricsDigest |
| ActivationCommandV2 | schemaVersion:2, activationId, applicationId, operation, expectedRouteGeneration, expectedControlRevision, candidate, requestedAt, commandDigest |
| RouteEventV2 | schemaVersion:2, eventId, activationId, applicationId, operation, expectedRouteGeneration, previous, next, leaseConsume, controlRevision, result, reasonCode, routeGeneration, createdAt, eventDigest |
| RollbackRecordV2 | schemaVersion:2, rollbackId, applicationId, from, to, expectedRouteGeneration, expectedControlRevision, routeEvent, reasonCode, result, createdAt, rollbackDigest |

Every field above is required and exact-key JCS. identity, executionFence, policy/capability/catalog/proof digests and snapshot digest equality are checked before a side effect. A successful command/route result has null failure/reason code; a rejected result has a bounded upper-case code. availability unavailable requires engine and hostServiceUsage null; available requires both complete and bounded. Each self-digest hashes the complete object with only that digest omitted using its named V2 domain. All Kernel mutations in these wires use expectedControlRevision in one CAS; data-plane host calls, quota reservations/finalize and metrics observations do not advance it.

V2 command, activation, rollback and host-call IDs are idempotency keys. A query or replay with byte-identical body returns the stored terminal result without another side effect; a changed body returns the corresponding ID_CONFLICT. A lost response is recovered by query/replay, a lower or different P/E fence returns a stale error, an expired readiness nonce cannot be consumed, and an unknown schema/protocol/domain is rejected without trying a V1 parser.

#### Scenario: A V2 command is replayed after its response is lost
- **WHEN** Kernel loses the response for a service-enabled prepare, start, drain, or stop command and replays the same command ID and bytes
- **THEN** supervisor returns the one stored acknowledgement and performs no second execution side effect

#### Scenario: A V1 lifecycle wire is sent for a service-enabled version
- **WHEN** a service-enabled version receives a V1 execution command, readiness lease, metrics sample, activation command, or rollback record
- **THEN** the receiver returns a protocol/schema mismatch and does not parse, execute, route, or downgrade the request

#### Scenario: A readiness or metrics projection has a stale fence
- **WHEN** a V2 readiness lease or metrics sample names a lower preparation/execution generation or a different policy/catalog hash
- **THEN** Kernel rejects it as stale, keeps the candidate unavailable, and leaves route/control state unchanged

#### Scenario: Route activation response is lost
- **WHEN** Kernel commits one V2 route event, lease consume and controlRevision CAS but the client loses the response
- **THEN** an identical activation query/replay returns that event without a second route-generation increment or lease consume

### Requirement: V2 catalog and acceptance bind the host ABI without V1 fallback

A service-enabled version SHALL have a V2 catalog binding and a kind-specific host-service acceptance record containing exactly the V2 matrix revision, iweb-wasmd-abi@1.1.0, runtime image digest, architecture, capability record revision/hash, catalog revision/hash, catalogEntryKey, host-service policy digest, evidence digest, and record digest. The record version is distinct from the archived V1 acceptance record (V3 for this change). Its `recordDigest` is `digestV2("iweb-wasm-acceptance-record-v3", JCS(record without recordDigest))`; the capability record hash uses `iweb-wasm-capability-record-v2`. The fixed Kernel-owned acceptance path and publication switch are evaluated by the wasm-specific validator; the celld V1 record or switch cannot satisfy this gate.

Catalog binding, acceptance record, admission proof, and control state MUST recompute the same HostServiceIdentityV2. Missing evidence, an owner decision not recorded, a hash mismatch, unsupported architecture, or a stale catalog keeps the gate disabled. V2 never downgrades to V1, and V1 never receives a synthetic V2 null service policy.

#### Scenario: Only a valid V1 record exists
- **WHEN** a service-enabled version is submitted while only the old V1 acceptance and catalog records are available
- **THEN** publication remains closed and no service-enabled execution starts

#### Scenario: All V2 pins match
- **WHEN** ABI, matrix, capability, catalog, acceptance, architecture, image, policy and proof digests all match
- **THEN** the V2 gate may proceed to normal sandbox and readiness checks

### Requirement: Host-service data uses one data-plane quota authority outside control CAS

The application's KV and SQL writes SHALL share one aggregate resources.storageBytes envelope. The canonical control state stores only static service profiles, limits, policy digest, dataDirectoryProfile, durabilityProfile, and optional schema/backup references. It SHALL NOT store dynamic ledger digest, mutable usage, KV/SQL payload, cursor bytes, log bodies, or per-request samples. Any mutation of those static control records uses the existing expectedControlRevision CAS and advances controlRevision exactly once.

The host-managed quota.sqlite3 ledger is the single dynamic authority for one application. A serialized reservation verifies committedBytes + outstandingReservedBytes + delta <= aggregateEnvelope and service cap, records a reservation with reservationId, operationId, ledger revision, expected usage revision, projected bytes, expiry, state and a `reservationProofDigest` under `iweb-wasm-quota-reservation-v2`, then performs the KV or SQL transaction with the same proof and operation marker. `reservedDeltaBytes` is a finite conservative upper bound computed before the backend write; if it cannot fit, the request is rejected before any data mutation. The provider refuses a backend write without the durable proof. The ledger finalizes only after the backend commit and durability profile succeed; backend failure releases the reservation. A post-commit measurement/finalize interruption enters the prescribed recovery/quarantine path rather than claiming a quota no-op. KV/SQL operations never advance control revision, route generation, readiness lease, admission sequence, journal revision, or audit.

Recovery SHALL inspect both ledger and backend markers: an uncommitted reservation with no marker is released; a reservation with a committed marker is finalized exactly once; a backend marker without a ledger row quarantines the service until a reconstructed reservation is checked; impossible revision/state combinations return unavailable and require owner recovery. Monitor may project usage/revision/reserved bytes and WAL/page measurements, but those are observations, not control authority.

#### Scenario: Concurrent KV and SQL writes race for remaining quota
- **WHEN** KV and SQL requests reserve space concurrently near the shared limit
- **THEN** the ledger serializes reservations so at most the post-commit envelope fits; a rejected request changes neither backend and controlRevision is unchanged

#### Scenario: Crash occurs between backend commit and finalize
- **WHEN** the process stops after a backend marker is durable but before ledger finalize
- **THEN** recovery recomputes usage, finalizes that operation once, and an identical replay returns the stored result without double charging

#### Scenario: Ledger and backend disagree
- **WHEN** a released reservation has a committed marker or a usage revision regresses
- **THEN** the service is unavailable, no empty backend is selected, and owner recovery is required

### Requirement: Embedded host-call transport binds identity and has stable replay semantics

wasmd SHALL use an embedded-host-services-v2 provider; supervisor does not expose an external host-service RPC. Kernel/supervisor injects an opaque execution context, and the component cannot supply or replace application/version/fence identity or a backend path.

Each call uses exactly one length-prefixed u32 big-endian frame: length 1..1048576, followed by one UTF-8 JCS request object and no trailing bytes. The request object is exactly:

~~~text
{
  schemaVersion: 2,
  protocol: "iweb-wasmd-host-call-v2",
  kind: "request",
  requestId,
  service: "kv" | "sql" | "logging",
  method,
  execution: {applicationId,versionId,preparationGeneration,executionGeneration,fenceNonce},
  hostServicePolicyDigest,
  deadlineMs,
  payload: base64url
}
~~~

WIT values are canonical Component Model ABI bytes represented as unpadded base64url in the JSON projection. The provider-created response is exactly {schemaVersion:2,protocol,kind:"response",requestId,execution,hostServicePolicyDigest,outcome:"ok"|"error",result:base64url|null,error:HostCallErrorV2|null}. The closed error codes are INVALID_FRAME, IDENTITY_MISMATCH, POLICY_MISMATCH, STALE_EXECUTION, APP_ISOLATION, INVALID_ARGUMENT, NOT_FOUND, CONFLICT, QUOTA_EXCEEDED, LIMIT_EXCEEDED, BUSY, TIMEOUT, CANCELLED, UNAVAILABLE, INTERNAL, REQUEST_ID_CONFLICT, and REPLAY_UNAVAILABLE; detail is a bounded opaque code and never payload/path text.

deadlineMs is relative to provider entry and bounded by the pinned profile. Cancellation is a host-owned token observed before allocation and at SQLite progress checkpoints. Timeout/cancel rolls back the current transaction and returns a stable error. A mutating request is at-most-once for (HostServiceIdentityV2,preparationGeneration,executionGeneration,requestId) until replay expiry; identical replay returns the stored response, changed bytes return REQUEST_ID_CONFLICT, and a lower/different fence returns STALE_EXECUTION. A response lost after commit is recovered by replay/query; a response lost before commit can be retried with the same request ID. The execution HTTP socket, snapshot FD socket, and supervisor RPC endpoint reject host-call frames, so Node has no second unauthenticated entrance.

#### Scenario: A caller forges another application's identity
- **WHEN** an application changes applicationId, versionId, fenceNonce, policy digest, or backend selector in a host-call frame
- **THEN** the embedded provider returns IDENTITY_MISMATCH or APP_ISOLATION before backend access and records no mutation

#### Scenario: A stale execution replays a valid request
- **WHEN** execution generation 4 sends a request after generation 5 is accepted for the same version
- **THEN** the provider returns STALE_EXECUTION and does not read or mutate the generation-5 backend

#### Scenario: Response is lost after a successful write
- **WHEN** the client times out after the backend commit but before receiving the response
- **THEN** replay with identical identity and requestId returns the original result exactly once and does not repeat the write

#### Scenario: An unknown or cross-protocol frame arrives
- **WHEN** a V1 envelope, snapshot FD magic, supervisor command, trailing bytes, oversized frame, or ancillary FD is sent to the host-call provider
- **THEN** it returns INVALID_FRAME or protocol mismatch, closes or drains the frame, and performs no service operation

### Requirement: Resource, directory, durability and failure boundaries are explicit

The selected runtime binding SHALL prove guestMemoryBytes = resources.memoryBytes - reserveBytes. Reserve is in the same byte unit, exists for the selected architecture/binding, and satisfies 1 <= reserveBytes < resources.memoryBytes. Missing, zero-substituted, or consuming reserve fails closed.

The host creates only /data/kernel/wasm-data/<applicationId>/{kv.sqlite3,sql.sqlite3,quota.sqlite3}, with application-derived identity, directory mode 0700, no symlink and no caller-supplied path. The fixed sqlite-full-fsync-v1 profile defines successful durability. Committed data survives supervisor/wasmd restart, execution-generation replacement, activation, rollback and route recovery; backup/restore quiesces and checks identity, schema and file integrity. Corrupt, recovering, locked-beyond-bound, missing or cross-application storage returns unavailable/internal and never becomes an empty store.

#### Scenario: Reserve proof is absent
- **WHEN** a service-enabled preparation lacks the selected architecture reserve or reserve is greater than or equal to memoryBytes
- **THEN** admission/preparation fails closed and no zero/default reserve is substituted

#### Scenario: A component attempts a filesystem escape
- **WHEN** a component supplies a path, symlink target, attached database, or another application ID to address storage
- **THEN** the host rejects it with APP_ISOLATION/INVALID_ARGUMENT and does not reveal target existence

#### Scenario: A committed value is followed by restart and rollback
- **WHEN** an operation returns success and the owner restarts the runtime or activates a retained version
- **THEN** the same application observes committed data under its schema contract, while another application cannot access it

### Requirement: Service failures remain generic outside owner diagnostics

Public Kernel/gateway routes SHALL preserve generic 502 application unavailable for host-service failure or identity mismatch. Owner-authorized diagnostics MAY expose bounded reason codes, quota counters, usage/recovery state and logging drop counters, but MUST NOT expose another application's keys, SQL text/parameters/results, logging payloads, filesystem paths, credentials, secret/config values or socket addresses. Service errors cannot fall back to another runtime kind or silently substitute an empty backend.

#### Scenario: SQL backend is unavailable
- **WHEN** a selected SQL backend is corrupt, recovering or identity-mismatched
- **THEN** the public route returns only generic unavailability and the host reports bounded unavailable/internal diagnostics

#### Scenario: Logging is full
- **WHEN** a valid logging event exceeds its bounded buffer
- **THEN** the host returns explicit dropped, increments the owner-visible counter, and does not block traffic or alter Kernel audit
