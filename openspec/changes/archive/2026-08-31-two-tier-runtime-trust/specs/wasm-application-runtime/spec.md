## MODIFIED Requirements

### Requirement: Wasm applications inherit the application sandbox law
Wasm applications SHALL inherit the wasm tier of the two-tier trust model: the boundary is enforced inside the engine (no socket/TLS/filesystem capability, host-mediated egress, fuel/epoch and store/instance limits), and execution runs as a supervised `iweb-wasmd` process inside the node container. Wasm no longer inherits any celld-era OCI/Podman/cgroup boundary requirement, and the supervisor requires no host-machine sandbox prerequisites.

#### Scenario: Engine boundary fails closed
- **WHEN** a component instantiation would exceed an engine limit or request a non-matrix import
- **THEN** the instantiation fails and no partial capability is granted, on any host OS the node container runs on

#### Scenario: Compromised wasm application probes another principal
- **WHEN** a wasm component attempts to reach another application's data, the owner workspace, or node credentials through any import outside the matrix
- **THEN** instantiation or admission fails closed and no such capability is granted

### Requirement: Kernel authorizes lifecycle while supervisor journals execution only
The Kernel SHALL remain the authority for admitted version identities, policies, lifecycle business state, owner authorization, and the active route pointer. The supervisor SHALL keep a durable **execution transaction journal** only: it receives a Kernel-authorized `ExecutionCommand`, starts, checks, drains, or stops a concrete execution, and records an acknowledgement. It SHALL NOT create an admitted version, choose a rollback target, update a Kernel lifecycle state, or make a route pointer visible.

The execution transport speaks exactly one protocol. Wasm uses only `POST /v1/execution-rpc` with a raw JCS `ExecutionRpcEnvelopeV1`; an envelope carrying celld-era `version`/`operation` fields, `protocol` markers outside the v1 literal, or any unknown protocol shape MUST be rejected (`EXECUTION_PROTOCOL_MISMATCH` / `CELLD_PROTOCOL_MISMATCH`) without fallback parsing or retry through another path. The execution HTTP socket carries HTTP request/response bytes only: it MUST reject the raw snapshot magic, any `SCM_RIGHTS` ancillary data, and any non-HTTP preamble before parsing the body. Snapshot descriptors use the separate `SnapshotFdTransportV1` socket defined below; a receiver MUST never switch sockets or reinterpret one transport as the other.

`ExecutionRpcEnvelopeV1` has exactly `{protocol,requestId,body}`. `protocol` is the literal `"iweb-execution-rpc-v1"`; `requestId` is a lower-case UUIDv7; and `body` is exactly one of the three typed payloads below. The response has exactly `{protocol,requestId,body}` with the same protocol and requestId. This transport is carried only over the fixed `/run/iweb-sandbox/supervisor.sock` Unix-domain socket. In the current deployment the **native snapshot-fd relay** (a supervised child of the supervisor process, both running as the in-container service user `iweb-sandbox` started by the node entrypoint) is the sole creator and listener of the public socket: it calls `listen`, creates the inode, applies mode `0600`, enforces the per-connection `SO_PEERCRED` and inode re-checks on that public socket, and proxies authorized connections to the Node supervisor's private upstream socket with a process-lifetime authorization token; the Node supervisor never binds the public socket. Kernel is the connecting peer and runs as UID/GID `0/0` in the same node container. The socket is never container-published, and neither envelope carries an owner bearer token. The precise peer and path authorization is specified by `SupervisorSocketAuthV1` below; a caller unable to pass both filesystem and peer-credential checks cannot submit, query, or replay a command. A future non-root Kernel deployment or cross-host transport requires a new deployment/protocol revision and explicit mutual authentication; it may not weaken this v1 by changing an environment path or adding an optional header.

`ExecutionCommand` has exactly `schemaVersion:2`, `commandId`, `expectedControlRevision`, `expectedJournalRevision`, `operation`, `identity`, `applicationId`, `packageDigest`, `runtimeBinding`, `matrixRevision`, `hostServicePolicyDigest`, `fenceNonce`, `capabilityRecordRevision`, `capabilityRecordHash`, `secretRevision`, `secretSnapshotRef`, `secretValuesDigest`, `configRevision`, `configSnapshotRef`, and `configValuesDigest`. `commandId` is a lower-case UUIDv7; `operation` is one of `prepare`, `start`, `drain`, `stop`; `expectedControlRevision` is the expected single `wasm-control-state-v2` `controlRevision`, and with `expectedJournalRevision`, `secretRevision`, and `configRevision` is `u53`; `identity` is the full execution identity below; `applicationId` is the host-injected execution identity; `runtimeBinding` is the complete `RuntimeBindingIdentityV1` field set with `hostABI` exactly `iweb-wasmd-abi@1.1.0`; `matrixRevision` is the literal `2`; `hostServicePolicyDigest` is the admitted `HostServicePolicyV2.policyDigest` `sha256-hex` pin, or exactly the empty string when the admitted version carries no host-service policy (the policyless zero-value policy: `kv`, `sql`, and `logging` all `null`, `storageBytes:0`, `reserveBytes:0`, `policyDigest:""`); `fenceNonce` is `/^[a-f0-9]{32}$/`; `secretSnapshotRef` is a `sha256-hex` opaque Kernel reference that contains no value; `secretValuesDigest` is the exact `SnapshotRefV1.valuesDigest` for that ref; `configSnapshotRef` is a `sha256-hex` opaque Kernel reference or `null` exactly when `configRevision` is `0`; and `configValuesDigest` is the exact config snapshot `valuesDigest` or `null` exactly when `configSnapshotRef` is `null`. For `prepare`/`start`, both digest bindings are checked before execution; for `drain`/`stop`, the command still carries the adopted snapshot digests and they remain part of the identity fence. `CommandRequestV1` is exactly `{kind:"command",command:ExecutionCommand}`.

`ExecutionAcknowledgement` has exactly `{schemaVersion:2,commandId,operation,identity,applicationId,packageDigest,runtimeBinding,matrixRevision,hostServicePolicyDigest,fenceNonce,capabilityRecordRevision,capabilityRecordHash,secretRevision,secretSnapshotRef,secretValuesDigest,configRevision,configSnapshotRef,configValuesDigest,drainReceiptDigest,result,failureCode,journalRevision}`. All echoed identity, config, snapshot, and values-digest fields must exactly equal the command; `drainReceiptDigest` is non-null only when `operation:"drain"` and `result:"applied"`, and then is the digest of the exact `DrainReceiptV1`; a rejected drain has `drainReceiptDigest:null`. `result` is `applied` or `rejected`; `failureCode` is `null` if and only if result is `applied`, otherwise it matches `/^[A-Z][A-Z0-9_]{0,63}$/`; and `journalRevision` is the durable revision that recorded this terminal command result. `CommandResponseV1` is exactly `{kind:"acknowledgement",acknowledgement:ExecutionAcknowledgement}`.

`CommandQueryV1` is exactly `{kind:"query",commandId:UUIDv7}` and returns exactly `{kind:"query-result",commandId,status,received,acknowledgement}`. `status` is `"missing"`, `"received"`, or `"completed"`; `received` is `null` only for `missing`, otherwise its exact `CommandReceivedV1`; and `acknowledgement` is non-null if and only if `status:"completed"`. `CommandReplayV1` is exactly `{kind:"replay",command:ExecutionCommand}` and returns the same `CommandResponseV1` for that command ID. Replay accepts only a byte-identical command JCS body: a known command ID with any differing field returns `EXECUTION_COMMAND_ID_CONFLICT`; a completed command returns its stored acknowledgement without repeating the execution side effect; a received but incomplete command resumes exactly its recorded operation under its stored fence. Kernel writes its outbox in the same wasm control-state CAS that authorizes the command, delivers it through this channel, and uses query/replay after any uncertain response; no owner key travels in this channel.

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

### Requirement: The execution socket has an explicit two-sided peer-credential contract
`SupervisorSocketAuthV1` is the only authentication envelope for the local execution transport. Its canonical deployment object is:

```text
{
  schemaVersion: 2,
  socketPath: "/run/iweb-sandbox/supervisor.sock",
  // socketCreator 指公开 socket 的实际 bind/listen 方：native relay（supervisor 子进程）。
  socketCreator: { uidName: "iweb-sandbox", gidName: "iweb-sandbox", mode: "0600" },
  kernelPeer: { uid: 0, gid: 0 },
  supervisorPeer: { uidName: "iweb-sandbox", gidName: "iweb-sandbox" },
  credentialMechanism: "linux-so-peercred",
  pathPolicy: "fixed-no-symlink-no-fallback"
}
```

The names `iweb-sandbox` resolve to the numeric UID/GID created in the node image; the current image topology fixes the Kernel peer to numeric UID/GID `0/0` in the same container. The relay is the public socket creator, not Kernel and not the Node supervisor: the node entrypoint creates `/run/iweb-sandbox` owned by the `iweb-sandbox` pair with mode `0700` before starting the supervisor, the supervisor spawns the relay as its child, and the relay binds the public socket and applies `chmod 0600` while the Node supervisor binds only the private upstream socket (`supervisor-internal.sock`, also mode `0600` under the same pair); the relay injects its process-lifetime authorization token into proxied upstream connections, so an unauthenticated local process cannot reach the Node listener even if it reaches the directory. Kernel may connect as root despite the mode, but a non-root Kernel is not a supported v1 deployment. A deployment that wants a non-root Kernel MUST introduce a new socket-auth revision with an explicit group/mode policy; it MUST NOT silently change `0600`.

Before connecting, Kernel MUST `lstat` the exact path and require a socket inode, owner UID/GID equal to the resolved `iweb-sandbox` pair, mode exactly `0600`, a non-symlink parent `/run/iweb-sandbox` owned by the same pair with mode `0700`, and the configured path equal byte-for-byte to the fixed literal. `IWEB_SANDBOX_SOCKET` may only repeat that literal; empty, alternate, relative, symlinked, bind-mounted-at-another-path, or TCP paths are `SUPERVISOR_SOCKET_PATH_REJECTED`. Kernel MUST perform the same checks again after connect to defeat path replacement.

The supervisor obtains `SO_PEERCRED` (Linux `getsockopt(SOL_SOCKET, SO_PEERCRED)`) on every accepted HTTP connection and requires peer UID/GID `0/0` in the current topology. Kernel obtains the peer credentials on its connected socket and requires the resolved `iweb-sandbox` UID/GID. A missing, unavailable, or mismatched credential is `SUPERVISOR_PEER_CREDENTIALS_REJECTED`; the HTTP body is not parsed and no journal entry is written. The supervisor also rejects a connection whose local socket inode/path identity changed after bind. These checks are mandatory even when the caller is root: filesystem access proves access to the inode, while peer credentials prove the service at the other end. The v1 trust assumption is that the node container's root account is a trusted principal; `SO_PEERCRED=0/0` cannot distinguish Kernel from any other root process in the same container, so this is not a claim of root-process identity isolation. A non-root Kernel MUST use a new socket-auth revision with an explicit credential/group policy. The HTTP socket rejects every `SCM_RIGHTS` ancillary message and every raw snapshot magic.

After peer authorization, Kernel is authorized to send only a command that it created under owner authentication, the expected control/journal revisions, the complete execution identity, and the command digest. Supervisor accepts only that command and records `command-received`; Kernel accepts a response only from the peer-credential-checked socket whose command ID, digest, full identity, and journal revision match. Thus the in-container topology has bidirectional authorization without an owner bearer token on the socket: service-user identity + fixed inode authorize the channel, and command/ack CAS fences authorize each operation. A socket copied to another path, a process running under the wrong UID, or a syntactically valid envelope from an unapproved peer is rejected before side effects.

#### Scenario: A replacement path is supplied
- **WHEN** Kernel is configured with `/tmp/supervisor.sock`, a relative path, a symlink, or a second bind-mounted path
- **THEN** startup fails with `SUPERVISOR_SOCKET_PATH_REJECTED`; it does not try the fixed path as a fallback and does not open a TCP listener

#### Scenario: A process connects with the wrong UID
- **WHEN** a peer reaches the fixed socket but `SO_PEERCRED` is not the configured Kernel UID/GID, or Kernel sees a peer other than the resolved supervisor UID/GID
- **THEN** both sides close the connection before HTTP parsing and no command, query, replay, or journal mutation occurs

#### Scenario: The supervisor restarts between path check and connect
- **WHEN** the old socket inode is removed and a new supervisor binds the same literal path before Kernel connects
- **THEN** Kernel re-checks inode owner/mode and peer credentials after connect; a mismatch is rejected and no stale command is sent

### Requirement: Wasmd has a fixed command and host-mediated network contract
The system SHALL execute wasm applications through a catalog-selected digest-pinned `iweb-wasmd` binary run as a supervised process inside the node container. Supervisor alone generates every argv element, snapshot FD handoff, listen address, resource limit, identity field, package digest, binding, and capability-record pin. An admission manifest carrying image, command, mount, host capability, socket, TLS, or arbitrary environment authority is rejected as `WASM_MANIFEST_EXECUTABLE_AUTHORITY`.

The runtime SHALL listen only at the exact loopback address the supervisor assigned for that execution. A real in-container readiness test against a running node is required before a catalog entry is acceptance-gated. `wasi:http/outgoing-handler` is the only component egress interface; wasmd's host mediation owns policy, DNS, reserved-address checks, redirect revalidation, and outbound dialing to already-validated IPs, and it terminates origin TLS on that validated connection with SNI/certificate checks; visitor-facing TLS remains the front proxy's concern. Components never receive `wasi:sockets`, `wasi:tls`, or a filesystem capability. Wasmd MUST NOT log request bodies, authorization credentials, configuration values, or secret values.

Host limits come only from the pinned node capability record. It SHALL enforce inbound/outbound byte and header caps while streaming, concurrency, store/instance limits, guest linear-memory limit, epoch deadline, optional fuel, restart budget, and drain deadline. Absence or mismatch of a pin is failure closed; no environment variable may replace a record value.

#### Scenario: Component requests a denied network interface
- **WHEN** a component requires `wasi:sockets`, `wasi:tls`, or any non-matrix import at instantiation
- **THEN** admission or instantiation fails closed and no direct network path is granted

#### Scenario: Response exceeds its record cap
- **WHEN** a guest or upstream response exceeds `http.maxResponseBytes`
- **THEN** only that request fails with the application-attributed resource category; wasmd, Kernel, and neighboring executions remain running

### Requirement: Node capability records are canonical revisioned bounds
The system SHALL persist a `NodeCapabilityRecordV1` beside Kernel control state. It has exactly the following fields; bytes are octets, `ms` milliseconds, `s` seconds, and `fuel` Wasmtime fuel units.

| Field | Type and bound | Meaning |
| --- | --- | --- |
| `schemaVersion` | literal `1` | record wire revision |
| `revision` | `u53`, `1..9007199254740991` | strictly increasing record revision |
| `recordHash` | `sha256-hex` | hash defined below |
| `policyMaxima.cpuMillis` | integer `1..1000000` | engine CPU policy maximum in millicores (epoch/fuel budget) |
| `policyMaxima.memoryBytes` | integer `1..68719476736` | engine guest memory policy maximum in bytes |
| `policyMaxima.pidLimit` | integer `1..1000000` | per-execution process budget for host-side helper processes |
| `policyMaxima.storageBytes` | integer `0..1099511627776` | application storage maximum in bytes |
| `http.maxRequestBytes` | integer `1..16777216` | inbound request bytes |
| `http.maxResponseBytes` | integer `1..67108864` | outbound response bytes |
| `http.maxRequestHeaderBytes` | integer `1..65536` | inbound header section bytes |
| `http.maxResponseHeaderBytes` | integer `1..65536` | outbound header section bytes |
| `http.maxRequestHeaderCount` | integer `1..256` | inbound header fields |
| `http.maxResponseHeaderCount` | integer `1..256` | outbound header fields |
| `http.maxConcurrentRequests` | integer `1..4096` | per-execution concurrent requests |
| `engine.maxEpochDeadlineMs` | integer `1..300000` | per-request wall-clock epoch deadline |
| `engine.fuelPerRequest` | `null` or integer `1..1000000000000` | `null` disables fuel; numeric enables it |
| `engine.maxLiveInstances` | integer `1..4096` | live component instances |
| `admission.maxPackageBytes` | integer `1..536870912` | complete strict OCI layout bytes |
| `admission.maxBlobBytes` | integer `1..134217728` | one blob bytes |
| `admission.maxLayerCount` | integer `1..128` | OCI layers |
| `admission.maxClosureNodes` | integer `1..4096` | parsed component/core/adapter graph nodes |
| `admission.maxClosureEdges` | integer `1..16384` | graph edges |
| `admission.maxClosureDepth` | integer `1..64` | nested traversal depth |
| `admission.stagingTtlSeconds` | integer `1..3600` | stale staging and hidden admission retention |
| `restart.maxRestarts` | integer `0..100` | restarts permitted in one window |
| `restart.windowMs` | integer `1000..86400000` | restart budget window |
| `drainDeadlineMs` | integer `1..300000` | retiring execution drain time |
| `runtimeReserves` | sorted non-empty array, max 256 | per-binding/per-architecture wasmd reserve entries below |
| `matrix` | exactly the revision-1 matrix above | world, ABI, required export, host-import set |

`matrix` has exactly `{world,hostABI,requiredRootExport,hostImports}`: `world` and `hostABI` equal the literals in the revision-1 matrix above; `requiredRootExport` is its exact typed export object; and `hostImports` is the exact sorted list of its typed import objects. Each `runtimeReserves[]` object has exactly `runtimeBinding`, `architecture`, and `reserveBytes`; `runtimeBinding` is the complete `RuntimeBindingIdentityV1`, `architecture` is one of `linux/amd64` or `linux/arm64`, `(JCS(runtimeBinding), architecture)` is unique and sorted first by the raw JCS UTF-8 bytes then by architecture, and `reserveBytes` is an integer `1..68719476735` bytes measured for that exact binding on that architecture (the host-side wasmd process share). The record has exactly nested objects `policyMaxima`, `http`, `engine`, `admission`, `restart`, plus the listed scalar/array fields; every array has its specified sort order and no duplicates.

`recordHash` equals `hex(SHA-256(UTF8("iweb-node-capability-record-v1\n" || JCS(record with recordHash omitted))))`. The raw persisted record must equal JCS including its validated `recordHash`. An owner update supplies an expected `(revision, recordHash)` and a complete next record with `revision = current.revision + 1`; the Kernel validates, computes the new hash, and atomically writes it by compare-and-swap. A stale expected pair, mutation of an historical revision, or a supervisor-originated update is rejected. New preparations pin both capability revision and hash; missing pinned record, absent current-architecture reserve, or an incompatible catalog ABI fails closed.

At admission and preparation, each requested policy field is rejected if above its matching `policyMaxima` field. `resources.memoryBytes` means the application's total memory budget for the execution, and `reserveBytes` means the measured host-side wasmd share for the selected complete runtime binding identity plus host architecture. They are compared in identical byte units: `reserveBytes >= resources.memoryBytes` rejects; otherwise the guest linear-memory limit is exactly `resources.memoryBytes - reserveBytes` and is enforced by the engine's resource limiter. Catalog never supplies a reserve; no reserve is inferred from an image label, process RSS, another catalog revision, or another architecture.

#### Scenario: Owner races a node capability update
- **WHEN** two owner-authorized updates use the same expected record revision and hash
- **THEN** exactly one CAS writes revision `current + 1`; the other receives a revision conflict and cannot silently overwrite limits or the matrix

#### Scenario: Reserve is missing or consumes the total memory limit
- **WHEN** the selected binding has no reserve for the node architecture, or its reserve is greater than or equal to `resources.memoryBytes`
- **THEN** admission or preparation fails closed with `WASM_RESOURCE_RECORD_INVALID` and no default or zero reserve is substituted

### Requirement: Secret snapshot references have one Kernel-resolved, read-only FD
The system SHALL use `SnapshotRefV1` as the exact Kernel record for every `secretSnapshotRef`, including the canonical empty revision-0 snapshot:

```text
{
  schemaVersion: 2,
  kind: "iweb-secret-snapshot",
  ref: sha256-hex,
  applicationId: ApplicationId,
  versionId: VersionId,
  preparationGeneration: u53 >= 1,
  secretRevision: u53,
  valuesDigest: sha256-hex,
  expiresAt: RFC3339-UTC
}
```

`ref = hex(SHA-256(UTF8("iweb-secret-snapshot-ref-v1\n" || JCS(ref record with ref omitted))))`; the ref is the sole key of the one-to-one index entry at `/data/kernel/secrets/snapshot-index-v1/<ref>.json`, and that entry points only to `/data/kernel/secrets/snapshots/<ref>.json`. The target snapshot bytes are the exact internal `SnapshotRecordV1` above; its `valuesDigest` must equal the digest named by `SnapshotRefV1`, while its application/version/generation/revision/key set must equal the allowlist record and ref. A missing, duplicate, or differently addressed index entry is `IWEB_SECRET_SNAPSHOT_REF_INVALID`. The Kernel is the only component allowed to resolve a ref to a record; supervisor and wasmd treat `ref` as opaque and never accept a caller-supplied filesystem path.

The handoff mechanism is fixed to a **read-only `SCM_RIGHTS` file descriptor** because Kernel and supervisor share only the fixed `/run/iweb-sandbox` socket directory inside the node container and the snapshot store is Kernel-owned. Kernel writes the canonical snapshot atomically under `/data/kernel/secrets/snapshots/<ref>.json`, opens it `O_RDONLY|O_CLOEXEC`, and sends the descriptor on the independent `SnapshotFdTransportV1` raw socket. The exact payload is the `SecretSnapshotFdHandoffV1` defined by that transport:

```text
{
  schemaVersion: 2,
  kind: "secret",
  commandId: UUIDv7,
  commandDigest: sha256-hex,
  ref: sha256-hex,
  applicationId: ApplicationId,
  versionId: VersionId,
  preparationGeneration: u53 >= 1,
  secretRevision: u53,
  valuesDigest: sha256-hex,
  fdDigest: sha256-hex,
  expiresAt: RFC3339-UTC
}
```

`fdBytes` are the exact bytes read from the received descriptor and must equal the canonical `SnapshotValuesPayloadV1` JCS; the domain-separated `fdDigest` must equal both the indexed snapshot `valuesDigest` and `ExecutionCommand.secretValuesDigest`; the payload contains no value or path. The raw frame boundary, ancillary association, and order are defined by `SnapshotFdTransportV1`; no frame is placed before or on the HTTP execution envelope. Supervisor validates `fstat` regular-file identity plus `fcntl(F_GETFL)` read-only flags, canonical bytes, ref/tuple/revision/expiry, command digest, and peer credentials before accepting the handoff. It passes descriptor `3` to wasmd only through the direct-process handoff contract and never passes it to another process.

ACL is therefore explicit: Kernel UID `0` creates, resolves, opens, and deletes refs; supervisor UID `iweb-sandbox` may receive exactly one descriptor bound to an accepted `ExecutionCommand`; the wasmd process may read only pre-opened fd `3`. Any other UID, path, ref, generation, version, revision, descriptor number, or digest is denied. `expiresAt` is no later than the preparation lease and bounds the handoff window only: it is rechecked before fd handoff and before activation adoption; an execution that activated on its adopted snapshot keeps reading it through `store.get` for that execution's lifetime (until a later activation or re-preparation), and `IWEB_SECRET_SNAPSHOT_EXPIRED` applies only to handoffs and adoptions attempted after `expiresAt`. Supervisor crash closes fd `3` and no process may inherit it on restart; Kernel recovery either reuses the same unexpired ref for the same command and exact values digest or creates a higher preparation generation. A ref is never reused for another tuple.

| Snapshot interruption | Recovery and collection |
| --- | --- |
| before snapshot rename | no ref is usable; replay recreates the same ref or rejects the command without an fd |
| source durable, before supervisor command | query/replay verifies the ref and expiry; an abandoned unreferenced source is collected after its TTL |
| fd handoff created, before wasmd start | close the descriptor on supervisor restart; the source remains only while the command lease is valid |
| wasmd running, Kernel crashes | wasmd loses pre-opened fd `3` when supervisor stops it; Kernel route remains unchanged until attestation replay |
| rotation commits while old snapshot is active | old active fd remains valid; new preparations use the greater revision, and old ref becomes collectible only after drain/retired |

#### Scenario: A snapshot ref is pointed at another tuple
- **WHEN** a command supplies a valid-looking ref whose indexed record names another application, version, generation, or revision
- **THEN** supervisor refuses the fd handoff with `IWEB_SECRET_SNAPSHOT_REF_INVALID`; no wasmd process starts and no journal completion is accepted

#### Scenario: Snapshot expires during a crash recovery fd handoff
- **WHEN** the source exists but `expiresAt` is reached between ref validation and fd handoff
- **THEN** no fd is handed off, the command is rejected as `IWEB_SECRET_SNAPSHOT_EXPIRED`, and GC removes the unreferenced source after retention

## REMOVED Requirements

### Requirement: Snapshot FD content is bound across Kernel, supervisor, Podman, and wasmd
- Reason. Podman is removed from the execution chain; the binding contract survives as the ADDED requirement below with a direct-process handoff.

### Requirement: Runtime-kind publication gate selection is a dual-gate wire
- Reason. celld publication is permanently removed; gate evaluation and selection are wasm-only, specified by the ADDED requirement below.

### Requirement: Kernel business authority is partitioned by runtime kind
- Reason. The celld registry and cross-kind migration transaction are removed; the requirement is replaced by the ADDED requirement "Kernel business authority is a wasm-only registry" with route-registry-derived kind claims.

### Requirement: Wasm publication requires a canonical kind-bound acceptance record
- Reason. The dual-record/dual-switch semantics are removed; the requirement is replaced by the ADDED requirement "Wasm publication requires a canonical wasm acceptance record".

## ADDED Requirements

### Requirement: Snapshot FD content is bound across Kernel, supervisor, and wasmd
For every secret snapshot, the following equality is mandatory before a `prepare` or `start` side effect:

```text
ExecutionCommand.secretValuesDigest
  == SecretSnapshotFdHandoffV1.valuesDigest
  == SecretSnapshotRefV1.valuesDigest
  == fdDigest(SCM_RIGHTS fd bytes)
  == wasmd.readDigest(fd 3)
```

`wasmd.readDigest` uses the same single domain-prefixed SHA-256 algorithm as `fdDigest`, so it hashes bytes rather than a hexadecimal digest string. The config chain is identical with `configValuesDigest` and FD `4`; when `configRevision:0`, all config references and digests are `null` and FD `4` MUST be absent. `fdBytes` must equal the exact raw canonical values-payload bytes, and the domain-separated `fdDigest` above must equal the ref's `valuesDigest`; no parsed/re-serialized JSON or hex digest text may substitute. Supervisor treats `ref` as opaque and does not parse Kernel's private snapshot index: the Kernel-authenticated command/handoff digest is the binding proof, while the received bytes provide the independently checkable content witness. A supervisor MUST reject `SNAPSHOT_VALUES_DIGEST_MISMATCH` before journal completion if any link differs, even when the ref itself is valid.

The direct-process contract is fixed. Kernel opens the verified source `O_RDONLY|O_CLOEXEC` and sends it only through the raw socket. Supervisor verifies regular-file `fstat`, read-only `fcntl(F_GETFL)`, exact digest, and tuple, then spawns the digest-pinned `iweb-wasmd` as its own child process with exactly descriptors `3` (secret) and `4` (config, absent when `configRevision:0`) mapped into the child's fd table; no application-supplied argument, mount, environment, or path can add a descriptor. In the spawned child, `FD_CLOEXEC` is cleared only for descriptors `3` and `4`, all other inherited descriptors are closed, and wasmd verifies the slot number, `O_RDONLY` status, regular-file identity, and digest again; it closes `4` when config is absent and never passes either FD to another child. The application receives only host `store.get` bindings backed by those descriptors and no host path.

Inside the process, a write attempt on either assigned descriptor MUST fail (`EBADF` or `EROFS`), `/proc/self/fd` path resolution MUST not grant a directory or alternate path, and a child spawned by wasmd MUST inherit neither descriptor unless it is the same trusted host adapter process. A wrong FD number, writable descriptor, extra inherited descriptor, missing descriptor, wrong command ID/digest, or a descriptor visible in another process is a negative vector and leaves the command rejected with no readiness lease.

#### Scenario: A valid ref is paired with bytes from another snapshot
- **WHEN** `fdDigest` or `wasmd.readDigest(fd 3)` differs from `ExecutionCommand.secretValuesDigest` while the opaque ref exists
- **THEN** supervisor returns `SNAPSHOT_VALUES_DIGEST_MISMATCH`, closes the FD, does not start wasmd, and records no successful acknowledgement

#### Scenario: Descriptor inheritance is widened
- **WHEN** wasmd sees secret FD `4`, or another process can open FD `3`
- **THEN** the launch fails with `SNAPSHOT_FD_POLICY_REJECTED`, all child processes are stopped, and the snapshot source remains subject to normal TTL GC

#### Scenario: A replay uses a different values digest
- **WHEN** a known `commandId` is replayed with the same opaque ref but a different `secretValuesDigest` or `configValuesDigest`
- **THEN** supervisor returns `SNAPSHOT_HANDOFF_ID_CONFLICT` before execution and Kernel retains the original command/acknowledgement bytes

### Requirement: Wasm publication gate selection is a wasm-only wire
At Kernel startup the release gate SHALL evaluate the wasm kind only and expose one immutable selection result. The internal `GateResultV1` is exactly `{schemaVersion, runtimeKind:"wasm", enabled, requested, accepted, reasons}` with `reasons` duplicate-free and in the stable order `["publication-not-requested","wasm-acceptance-invalid","wasm-identity-mismatch","runtime-kind-mismatch","capability-record-mismatch","catalog-mismatch","unsupported-architecture"]`; a successful gate has an empty array. The gate-selection response projected on any wire is exactly `{schemaVersion:1, runtimeKind:"wasm", enabled, reasons}`; requesting selection for `"celld"` or any other kind returns the typed `RUNTIME_KIND_UNSUPPORTED` selection error without invoking the wasm validator.

The gate is connected at startup in this order: (1) read and validate the fixed wasm acceptance record; (2) evaluate the single `IWEB_WASM_PUBLICATION_ENABLED` switch; (3) publish the immutable selection to the Kernel runtime selector; (4) at every wasm publication request require `enabled` and pass the catalog/capability pins and record digest into the normal admission and execution fence. There is no environment-controlled path, boolean fallback, or second record path.

#### Scenario: Gate is disabled without a request
- **WHEN** the node starts without `IWEB_WASM_PUBLICATION_ENABLED=1`
- **THEN** the selection reports `enabled:false` with `publication-not-requested` and wasm admission beyond the gate is refused with the stable reason codes only

#### Scenario: Celld selection is requested
- **WHEN** a caller selects a gate for runtime kind `celld`
- **THEN** selection returns `RUNTIME_KIND_UNSUPPORTED` and no parser for any other record path runs

### Requirement: Kernel business authority is a wasm-only registry
The Kernel SHALL own exactly one runtime-admission registry: the `runtimeKind:"wasm"` records of `/data/kernel/wasm-control-state-v2.json`. There is no celld control-state file, no celld version validator, and no cross-kind migration transaction; celld application identity exists only in the route registry maintained under `workspace-and-routes`.

The canonical wasm business registry's exact application record is unchanged from the v2 shape: `{runtimeKind:"wasm", applicationId, versions:[{versionId, identity, packageDigest, normalizedPolicy, lifecycle, runtimeBinding, admissionProofRef, admissionProofDigest, readinessLeaseDigest}], active: WasmActivePointerV1, routeGeneration, secretRevision, configRevision}` with the pointer and lifecycle semantics previously fixed. `KernelLifecycleState` is the accepted validator set; `retiring` remains supervisor-only.

An applicationId is bound to one runtime kind for life. At startup the Kernel derives lifetime celld claims deterministically from the route registry — every route whose `target.kind` is `celld-app` contributes its target application name — and merges them with the wasm claims persisted in the control state. Wasm admission for a celld-claimed applicationId returns `APPLICATION_RUNTIME_KIND_CONFLICT` and writes nothing. There is no bootstrap-pending admission mode and no `MigrationRecordV1`: derivation succeeds whenever the route registry parses, and moving an application between kinds is not an offered operation.

#### Scenario: Wasm admission reuses a celld fleet identity
- **WHEN** a wasm registration is requested for an applicationId that a `celld-app` route targets or that carries a persisted celld claim
- **THEN** the Kernel returns `APPLICATION_RUNTIME_KIND_CONFLICT`, writes neither registry record nor active pointer, and requires a new application ID

#### Scenario: Route registry is unreadable at startup
- **WHEN** the route registry file cannot be parsed at Kernel startup
- **THEN** startup fails closed with the route-store error; the node does not enter a partial-admission or bootstrap-pending mode

### Requirement: Wasm publication requires a canonical wasm acceptance record
The system SHALL require an acceptance record v2 from the immutable trusted Kernel release at the fixed Kernel-owned path `/opt/iweb/release/wasm-sandbox-acceptance.json` before wasm publication can open. The record attests the selected digest-pinned wasmd binary measured as a process in the node container; it MUST NOT be read from an application package, a wasmd mount, a runtime-provided path, or an environment-selected alternate path. The raw record is JCS and has exactly:

```text
{
  version: 2,
  result: "passed",
  gate: "application-sandbox",
  runtimeKind: "wasm",
  runtimeImageDigest: "sha256:<64 lower hex>",
  hostABI: "iweb-wasmd-abi@1.0.0",
  world: "wasi:http/proxy@0.2.8",
  arch: "linux/amd64" | "linux/arm64",
  capabilityRecordRevision: u53 >= 1,
  capabilityRecordHash: "<64 lower hex>",
  catalogRevision: u53 >= 1,
  catalogHash: "<64 lower hex>",
  catalogEntryKey: /^[a-z][a-z0-9.-]{0,63}$/,
  evidenceDigest: "<64 lower hex>",
  recordDigest: "<64 lower hex>"
}
```

`recordDigest` is `hex(SHA-256(UTF8("iweb-wasm-acceptance-record-v2\n" || JCS(record with recordDigest omitted))))`; the supplied field must equal it. No unknown field, missing field, alternate digest prefix, upper-case hash, or non-JCS form is valid. The wasm gate reads only `/opt/iweb/release/wasm-sandbox-acceptance.json` and requires only `IWEB_WASM_PUBLICATION_ENABLED=1`; there is no celld record, no `IWEB_APPLICATION_PUBLICATION_ENABLED`, and no second gate. The gate requires the canonical record digest and exact equality with the selected catalog entry/binding, current node architecture, current capability record revision/hash, current catalog revision/hash, world, ABI, and runtime digest. No environment variable may redirect the path. The records are outside the catalog hash input, so neither a binary self-digest nor a catalog-record hash cycle is accepted.

#### Scenario: Canonical record has an unknown field
- **WHEN** an otherwise passed wasm acceptance record contains an extra field or a digest computed over a different field set
- **THEN** the gate rejects it before checking enablement and wasm publication remains closed

#### Scenario: Acceptance record does not match current node identity
- **WHEN** record catalog/capability revision or hash, architecture, entry key, runtime digest, ABI, or world differs from the selected node binding
- **THEN** wasm publication fails closed until a matching v2 record exists
