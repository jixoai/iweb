<!-- 用户原始需求（2026-08-27）：扩展归档 wasm-application-runtime，增加 iweb:kv、iweb:sql、iweb:logging，并把能力矩阵升级到 revision 2。 -->
<!-- 正交意图：定义新 host-service 的 admission/catalog/capability 绑定；定义 v2 CAS 与执行围栏；保持 v1 wasm、FD 通道、sandbox 和发布门不回退。 -->
<!-- 不可调和原因：host-service policy、版本身份、执行 fence 与发布门必须作为同一准入契约验证，拆分会允许部分绑定或隐式 fallback。 -->

## MODIFIED Requirements

### Requirement: Capability record revision 1 is a typed exact matrix

The existing revision-1 matrix SHALL remain valid for versions that import only the original HTTP/config/secrets surface. A version that imports any new host service SHALL use a new exact capability record and matrix revision 2; a revision-1 record, catalog binding, or acceptance record MUST NOT be interpreted as a revision-2 record by fallback. The revision-2 record has a distinct schema/version marker, a `matrixRevision` literal `2`, the complete original revision-1 entries, and these additional exact imports:

```text
{package:"iweb:kv@1.0.0", interface:"store", direction:"import"}
{package:"iweb:sql@1.0.0", interface:"store", direction:"import"}
{package:"iweb:logging@1.0.0", interface:"logger", direction:"import"}
```

The original revision-1 world, required export, and imports remain:

```text
world                 wasi:http/proxy@0.2.8
required root export  {package:"wasi:http@0.2.8", interface:"incoming-handler", direction:"export"}
host ABI              iweb-wasmd-abi@1.0.0 (or the owner-approved additive v2 ABI)
```

The revision-2 matrix is the bytewise sorted union of the exact revision-1 imports and the three entries above. It SHALL add no wildcard, semantic-version range, socket/filesystem/TLS interface, RustFS credential, or untyped core import. The package/interface/version and direction rules, decoded Component Model closure, internal-provider resolution, graph budgets, required root export, and stable rejection codes from revision 1 continue unchanged. A discovered set must equal both the declared set and the selected matrix revision; an import present only in a policy profile or only in a catalog entry is insufficient.

Each revision-2 admitted version SHALL carry an exact `hostServices` policy projection:

```text
hostServices: {
  kv: null | {profile, policyDigest},
  sql: null | {profile, policyDigest},
  logging: null | {profile, policyDigest}
}
```

The object has exactly these three keys. A non-null service requires the matching import, an owner-approved profile name, and a `policyDigest` over the complete profile limits and durability/retention semantics. A null service forbids its import. The selected node record supplies maxima for every profile field; a request above a maximum, a missing profile, an unknown field, a missing digest, or a service/import mismatch fails closed before object materialization. The proposed profiles and their exact WIT method shapes are defined by the `wasm-host-kv`, `wasm-host-sql`, and `wasm-host-logging` capabilities; changing a profile or WIT shape requires a new profile/package revision and a new digest.

The revision-2 capability record SHALL pin the selected host ABI, matrix revision, complete sorted import set, and profile maxima. Its record hash and owner CAS follow the canonical record hashing and revision rules already defined for node capability records. A v2 preparation pins both the record revision/hash and `matrixRevision:2`; missing or stale pins return `WASM_CAPABILITY_RECORD_MISMATCH`. The old v1 record remains usable only for versions whose declared imports and `hostServices` are entirely within revision 1.

#### Scenario: A v1 version continues without new services
- **WHEN** an admitted version imports only the original revision-1 capabilities and the node has a valid revision-1 record
- **THEN** the version remains eligible under the existing v1 gate and no revision-2 service binding is inferred

#### Scenario: A new service is presented to a v1 record
- **WHEN** a version declares `iweb:kv/store`, `iweb:sql/store`, or `iweb:logging/logger` while the selected capability record or acceptance evidence is revision 1
- **THEN** admission fails closed with a capability-record/matrix mismatch before materialization or execution

#### Scenario: Declared service and discovered import differ
- **WHEN** `hostServices.sql` is non-null but the decoded component closure lacks the exact SQL import, or the closure contains the import while the policy is null
- **THEN** admission returns `WASM_DECLARATION_MISMATCH` and creates no visible version

#### Scenario: Nested component and re-export resolve internally
- **WHEN** an entry component imports a type-identical interface re-exported from one reachable nested component
- **THEN** the scanner records no host capability for that edge and accepts it only if the provider is unique and the complete graph remains within budget

#### Scenario: Adapter attempts to smuggle a host import
- **WHEN** an adapter or core module has an external import that cannot be proven to resolve internally through decoded Component Model linkage
- **THEN** admission rejects with `WASM_ADAPTER_EXTERNAL_IMPORT` or `WASM_IMPORT_UNMAPPABLE`

#### Scenario: Known interface has the wrong patch
- **WHEN** a component imports `wasi:http/outgoing-handler@0.2.7` or any non-`0.2.8` revision
- **THEN** admission rejects with `WASM_INTERFACE_VERSION_UNLISTED`

## ADDED Requirements

### Requirement: Host-service policy is part of immutable wasm identity

For every version that enables one or more new host services, Kernel SHALL include the exact `hostServices` projection, `matrixRevision:2`, host ABI, capability-record revision/hash, and a combined `hostServicePolicyDigest` in the normalized admission policy and `AdmissionProofV1` successor used by the version. The digest SHALL cover the sorted service names, profile names, complete profile limits, consistency/durability/retention choices, and the matrix revision; it SHALL not include mutable runtime values or any secret/config/KV/SQL/log payload. The same bytes MUST be present in the catalog binding, wasm control-state application/version record, execution command, readiness lease, metrics identity, active pointer event, and rollback record.

The version identity is immutable: changing a service profile, quota, consistency level, SQL dialect, transaction boundary, logging retention, or archival setting requires a new admission/version identity. Runtime data mutations do not change the version identity or `wasm-control-state-v2.controlRevision`.

#### Scenario: Service policy changes after admission
- **WHEN** an owner changes a KV/SQL/logging profile or quota for an already admitted version
- **THEN** the existing version remains bound to its original policy digest, and the owner must admit a new version before the new policy can execute

#### Scenario: Execution reports a different service policy
- **WHEN** a supervisor, wasmd, readiness probe, or metrics payload names a service policy digest or matrix revision different from the Kernel record
- **THEN** Kernel rejects the payload as a stale/mismatched execution and does not activate, route, or project it

### Requirement: Host-service data is outside the control-state CAS but bound to its authority

The canonical `wasm-control-state-v2.json` SHALL store service enablement, profile names, policy digests, schema/backup references, and the current aggregate quota ledger digest (when used) in the same application/version record that stores runtime binding and admission proof. Any mutation of those control records SHALL use the existing `expectedControlRevision` compare-and-swap and advance `controlRevision` exactly once. The CAS SHALL cover admission, outbox append, acknowledgement projection, service-policy projection, route-pointer CAS, and recovery replay as one authority chain.

KV values, SQL statements/parameters/results, database pages, cursors, logging messages/fields, dropped-event bodies, and per-request usage samples SHALL remain data-plane state. Their successful operations MUST NOT advance `controlRevision`, allocate an admission sequence, alter a route generation, consume a readiness lease, or write a supervisor command/journal entry. A data-plane operation is accepted only after its own backend commit/queue decision; it is never made durable by a control-state write.

#### Scenario: Data mutation races a route CAS
- **WHEN** a KV/SQL write or logging event completes while a route-pointer CAS is in flight
- **THEN** the data-plane result follows its own backend/queue commit semantics, while the route CAS increments control revision only for its route record and cannot be forged by the data result

#### Scenario: Control-state revision is stale
- **WHEN** a service-policy or schema-reference update supplies an old `expectedControlRevision`
- **THEN** Kernel returns `CONTROL_REVISION_CONFLICT`, writes neither policy nor route projection, and leaves service data untouched

### Requirement: New host services do not reuse the snapshot FD transport

The existing `/run/iweb-sandbox/snapshot-fd.sock` and its `SnapshotFdTransportV1` framing SHALL remain exclusively for the fixed secrets/config read-only descriptors and their command-bound digest chain. KV, SQL, and logging calls SHALL use the typed host ABI over the wasmd execution boundary and SHALL NOT carry `SCM_RIGHTS`, filesystem paths, RustFS credentials, raw snapshot magic, or a generic data-channel envelope. The execution HTTP socket and snapshot FD socket continue to reject cross-protocol frames and ancillary data exactly as specified by the existing runtime capability.

#### Scenario: A service call carries an FD or path
- **WHEN** an application or supervisor sends an ancillary FD, a host filesystem path, or a snapshot frame while invoking KV, SQL, or logging
- **THEN** the receiver rejects the call before it reaches the service backend and records no data-plane mutation

#### Scenario: Secret/config handoff and service calls coexist
- **WHEN** a `prepare`/`start` command performs the required secret/config FD handoff and then invokes a host service
- **THEN** the fixed secret/config frames remain independently validated, and the service call cannot read or alter their descriptor payloads

### Requirement: The v2 publication gate requires host-service evidence

The wasm v2 acceptance record and catalog binding SHALL include the selected matrix revision, host ABI, complete host-service policy digest, and the exact profile names/limits for every enabled service. A record that validates under the original revision-1 shape or omits service evidence MUST NOT open a service-enabled version. The publication gate SHALL remain fail-closed when any service profile is unknown, the capability record lacks a matching maximum, the acceptance evidence is missing, or the owner-approved profile decision has not been recorded.

#### Scenario: Valid v1 acceptance record lacks service evidence
- **WHEN** a service-enabled version is submitted while only a valid revision-1 acceptance record and switch are present
- **THEN** the selected wasm gate returns a stable capability/service mismatch and no service-enabled runtime starts

#### Scenario: Service evidence matches all pins
- **WHEN** matrix revision, host ABI, profile digests, capability record hash, catalog binding, and acceptance record all match the immutable version
- **THEN** the v2 gate may enable publication, subject to the independent application-sandbox acceptance record and normal readiness/lease checks

### Requirement: Host-service failures are generic outside the owner diagnostic surface

Kernel, gateway, and public routes SHALL preserve the existing generic `502 application unavailable` behavior for an unavailable or mismatched wasm execution. Owner-authorized diagnostics MAY expose bounded service-specific reason codes, quota counters, and dropped-log counters, but MUST NOT expose KV keys from another namespace, SQL text/parameters/results, logging payloads, filesystem paths, owner credentials, secret/config values, or internal socket addresses. A service error cannot be translated into a successful celld response or a fallback to another runtime kind.

#### Scenario: SQL backend becomes unavailable
- **WHEN** the selected application's SQL backend is corrupt, recovering, or unavailable
- **THEN** the host returns its bounded `unavailable`/`internal` error, Kernel/gateway expose only generic application unavailability publicly, and no empty replacement database is selected

#### Scenario: Logging queue is full
- **WHEN** a valid event exceeds the bounded logging queue
- **THEN** the host returns the logging capability's explicit `dropped` outcome, owner diagnostics may count the drop, and public traffic/audit state is unchanged
