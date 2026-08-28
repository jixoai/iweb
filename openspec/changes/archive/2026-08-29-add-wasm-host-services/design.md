<!-- 用户原始需求（2026-08-27）：硬化 add-wasm-host-services 提案，闭合 V2 identity/wire、双后端 quota authority 与 wasmd host-call；只改 OpenSpec 四件套，不写实现。 -->
<!-- 正交意图：固定跨层身份和回放模型；固定 SQLite/ledger 数据面；固定三个 import 服务与发布门接线。 -->
<!-- 不可调和原因：三项服务共享同一 admission、sandbox、quota 和执行 fence，拆成独立设计会允许部分绑定。 -->

# add-wasm-host-services Design

## Context

现有 wasm-application-runtime 的 V1 wire 已固定 HTTP、config、secrets、execution、readiness、metrics、activation 和 rollback 的身份字段，但没有 host-service policy、动态配额或服务调用协议。新能力必须继续服从 application-sandbox：应用不可信，Kernel 是唯一业务权威，supervisor/wasmd 只执行 Kernel 授权的绑定，secrets/config 继续走独立 snapshot FD。

本设计采用每应用独立 SQLite 后端与 wasmd 内嵌 provider。V2 的服务身份是 admission 的不可变部分；动态数据和 quota ledger 是数据面状态，不伪装成控制态。详见 proposal.md 的动机和范围，以及四份 delta spec 的可测试条款。

## Goals / Non-Goals

**Goals:**

- 让 service-enabled wasm 版本拥有一套可重算的 V2 identity、digest domain、wire schema 和 replay 规则。
- 将 iweb-wasmd-abi@1.1.0、matrix revision 2、catalog、acceptance 和每条执行/路由投影绑定到同一 immutable identity。
- 在 KV 与 SQL 并发写入时，以单一 quota ledger 提供写入前原子证明，并定义两阶段提交和崩溃恢复。
- 让 wasmd 以内嵌 provider 直连 sandbox-local SQLite，拒绝外部 supervisor host-service RPC 和第二入口。
- 将 reserve 公式、数据目录权限、durability、cursor/tombstone、logging redaction 与 bounded drop 变成 gate 可验证事实。

**Non-Goals:**

- 不为应用开放 WASI filesystem、socket、RustFS credential、Kernel API、owner token 或任意 SQLite path。
- 不实现跨应用/跨节点事务、跨调用 SQL transaction handle、无界 KV enumeration 或默认日志归档。
- 不把动态用量、KV/SQL payload、日志正文或 quota ledger digest 写进 wasm-control-state-v2、admission proof 或 Kernel audit。
- 不在 owner 决策完成前打开发布门，不修改归档主规范，不在本 Change 中写实现代码。

## Decisions

### 1. V2 identity, canonical bytes and hash domains

所有 V2 类型先以严格 JCS 对象定义，再以 UTF-8 字节参与摘要。对象禁止未知字段、重复键、非整数和 alternate encoding。Digest32 在二进制 host-call 中是恰好 32 个 octets，在 JSON/JCS 投影中是恰好 64 个小写十六进制字符；两种表示不可混用。

摘要唯一算法为：

~~~text
digestV2(domain, payloadBytes) = SHA-256(ASCII(domain) || 0x00 || payloadBytes)
~~~

domain 是下列不带换行的 ASCII literal；不得对已经编码的 hex 再做第二次摘要：

~~~text
iweb-wasm-host-policy-v2
iweb-wasm-host-identity-v2
iweb-wasm-capability-record-v2
iweb-wasm-acceptance-record-v3
iweb-wasm-admission-proof-v2
iweb-wasm-catalog-binding-v2
iweb-wasm-control-state-v2
iweb-wasm-execution-command-v2
iweb-wasm-execution-ack-v2
iweb-wasm-readiness-v2
iweb-wasm-metrics-v2
iweb-wasm-activation-v2
iweb-wasm-route-event-v2
iweb-wasm-rollback-v2
iweb-wasm-host-call-v2
iweb-wasm-quota-reservation-v2
~~~

HostServicePolicyPayloadV2 是去掉 policyDigest 的完整策略对象；它精确包含 schemaVersion:2、matrixRevision:2、hostAbi:"iweb-wasmd-abi@1.1.0"、hostServices（kv/sql/logging 各为 null 或 {profile,limits,consistency,durability,retention}）、共享 storageBytes、reserveBytes、dataDirectoryProfile:"per-app-sqlite-v1" 和 durabilityProfile:"sqlite-full-fsync-v1"。HostServicePolicyV2 在此对象上追加 policyDigest = digestV2("iweb-wasm-host-policy-v2", JCS(payload))。静态摘要只覆盖策略与上限，不覆盖用量、WAL 页数、日志正文、secret/config 值或请求数据。

HostServiceIdentityV2 是所有跨层 wire 的不可变核心，字段恰好为：

~~~text
{
  schemaVersion: 2,
  applicationId,
  versionId,
  packageDigest: Digest32,
  versionDigest: Digest32,
  matrixRevision: 2,
  hostAbi: "iweb-wasmd-abi@1.1.0",
  capabilityRecordRevision,
  capabilityRecordHash: Digest32,
  catalogRevision,
  catalogHash: Digest32,
  hostServicePolicyDigest: Digest32
}
~~~

versionDigest 对 JCS({schemaVersion:2,packageDigest,normalizedPolicy,hostServicePolicyDigest,matrixRevision,hostAbi}) 使用 iweb-wasm-host-identity-v2 domain 计算；V2 versionId 仍是 <versionDigest>-<positive-sequence>。V1 wasmVersionDigestV1 和 V1 versionId 不重写、不解释为 V2。JSON/JCS 中 policyDigest 和 catalogHash 是 64 个小写十六进制字符；host-call 二进制字段是 32 个原始 octets，并以 unpadded base64url 表示，二者必须解码为同一字节串。

跨层 envelope 使用以下类型。各类型的 *Digest 都对“去掉自身 digest 的完整对象”使用对应 domain 计算，引用只指向更早的 digest，禁止循环：

| Type | Required V2 fields and authority |
| --- | --- |
| AdmissionProofV2 | schemaVersion:2、identity、complete normalizedPolicy、complete hostServicePolicy、capabilityRecord、catalogBinding、immutable sequence、lifecycle admission record、commitTokenHash、proofDigest；Kernel admission authority |
| CatalogBindingV2 | schemaVersion:2、identity、catalog revision/hash/entry key、runtime image digest、acceptance record digest、architecture、bindingDigest；catalog/acceptance authority |
| ControlStateApplicationV2 | schemaVersion:2、identity、controlRevision、static service policy summary、schema/backup references、route pointer、lifecycle state、controlStateDigest；Kernel CAS authority |
| ExecutionCommandV2 | schemaVersion:2、commandId、expectedControlRevision、expectedJournalRevision、operation、identity、P/E fence、snapshot revision/ref/digests、commandDigest；Kernel command authority |
| ExecutionAcknowledgementV2 | schemaVersion:2、commandId、operation、identity、P/E fence、policy/capability/catalog/proof digests、snapshot digests、result、failure code、journal revision、acknowledgementDigest；supervisor execution authority |
| ReadinessLeaseV2 | schemaVersion:2、leaseNonce、leaseDigest、identity、sandbox/P/E fence、listener proof、policy/capability/catalog/proof digests、expiry；supervisor attestation only |
| MetricsSampleV2 | schemaVersion:2、sampleId、identity、sandbox/P/E fence、sampledAt、availability、host-service usage/drop counters or null when unavailable、metricsDigest；observation only |
| ActivationCommandV2/RouteEventV2 | schemaVersion:2、activation ID、expected route generation、previous/next identity+fence pointers、lease consume、controlRevision、command/event digest；Kernel route CAS authority |
| RollbackRecordV2 | schemaVersion:2、rollback ID、from/to identities、expected route/control revisions、reason code、resulting route event、rollbackDigest；Kernel rollback authority |

Every V2 message carries the complete HostServiceIdentityV2 (not merely an application ID) or a byte-identical object reference to it. The receiver recomputes the relevant digest and checks matrix/ABI/policy/catalog/acceptance pins, application/version identity, and P/E fence before side effects. Static policy bytes are present in proof/catalog/control-state; later messages echo its 32-byte digest. Dynamic data never enters identity. Admission replay joins by `(applicationId,versionId,commitTokenHash)`; catalog and control-state mutations use their expected revision/hash CAS; execution uses `commandId`; readiness consumes `leaseNonce`; activation uses `activationId`; rollback uses `rollbackId`; and host calls use `(identity, P/E fence, requestId)`. Each key has one stored terminal result or conflict, so no replay path can allocate a second sequence, route generation, lease, backend mutation, or log event.

The exact V2 child objects are:

~~~text
HostServiceBindingV2 = {
  schemaVersion: 2, identity, hostServicePolicyDigest,
  matrixRevision: 2, hostAbi, capabilityRecordRevision,
  capabilityRecordHash, catalogRevision, catalogHash,
  catalogEntryKey, acceptanceRecordDigest, runtimeImageDigest,
  architecture, executionFence, bindingDigest
}
ExecutionFenceV2 = {
  sandboxId, preparationGeneration, executionGeneration, fenceNonce
}
ReadinessListenerProofV2 = {
  listenerAddress, listenerIdentityDigest, hostServiceBindingDigest
}
HostServiceUsageV2 = {
  usageRevision, committedBytes, reservedBytes, quotaState
}
ActivationCommandV2 = {
  schemaVersion: 2, activationId, applicationId,
  operation: "activate" | "rollback", expectedRouteGeneration,
  expectedControlRevision, candidate, requestedAt, commandDigest
}
RollbackRecordV2 = {
  schemaVersion: 2, rollbackId, applicationId, from, to,
  expectedRouteGeneration, expectedControlRevision, routeEvent,
  reasonCode, result, createdAt, rollbackDigest
}
~~~

HostServiceBindingV2 is the exact catalog/acceptance join object; ExecutionFenceV2.fenceNonce is 16 host-issued bytes rendered as 32 lower-case hex characters. ReadinessListenerProofV2 contains no secret or socket credential. HostServiceUsageV2 is present only in owner diagnostics/metrics and is null when availability is unavailable; it never contains KV/SQL/log payload. Activation candidate and rollback from/to each carry the complete identity plus execution fence, never a bare version ID.

Replay is deterministic and fail-closed: a known commandId, activationId, rollbackId, or host-call requestId may be replayed only with byte-identical JCS body and identity; the stored terminal result is returned without a second side effect. A changed body returns the corresponding *_ID_CONFLICT. A lower/different P/E fence, policy digest, catalog hash, capability hash, route generation, or control revision returns a stale/mismatch error and cannot be repaired by trying V1. A response lost after a committed CAS is recovered through query/replay; a response lost before a backend commit is retried with the same idempotency key. Unknown schema, hash domain, field, or protocol never falls through to a V1 parser.

### 2. V1/V2 coexistence and catalog/acceptance binding

V1 remains valid only when the decoded import set contains no new service and the old V1 capability/acceptance/catalog records match. A service-enabled version MUST use matrix revision 2, the exact service import entries that it declares, the V2 identity above, iweb-wasmd-abi@1.1.0, a V2 catalog binding, and a host-service acceptance record with version:3, runtimeKind:"wasm", matrixRevision:2, hostABI:"iweb-wasmd-abi@1.1.0", capability record revision/hash, catalog revision/hash, catalogEntryKey, hostServicePolicyDigest, architecture, runtime image digest, evidence digest and record digest. The V3 record is read from the same Kernel-owned fixed acceptance path by a kind-specific validator; a V1 record or IWEB_APPLICATION_PUBLICATION_ENABLED switch cannot satisfy it.

Catalog entries for V2 carry the same ABI, matrix revision, policy digest, capability hash and acceptance record digest. The capability record hash uses `iweb-wasm-capability-record-v2`; the V3 acceptance `recordDigest` uses `iweb-wasm-acceptance-record-v3` over the exact record with only `recordDigest` omitted. Catalog, acceptance, proof and control state must all recompute the same HostServiceIdentityV2. Missing or mismatched evidence keeps the service-enabled gate closed before materialization; it never downgrades to V1. V1 executions do not receive a synthetic null service policy, and V2 executions do not consume V1 snapshot/config or command parsers.

### 3. Storage backend, data directory and durability

Each application owns a host-created directory:

~~~text
/data/kernel/wasm-data/<applicationId>/
  kv.sqlite3
  sql.sqlite3
  quota.sqlite3
~~~

The directory is derived only from the Kernel application identity, created with mode 0700, contains no symlink, and is opened with no-follow/identity checks by the host. SQLite and ledger files are host-owned with mode 0600 and unavailable to the component as paths; the application receives only WIT imports. KV and SQL files are separate so SQL cannot address KV internals. Another application, Kernel ingress, RustFS and celld operator listener have no read permission or provider handle.

The fixed sqlite-full-fsync-v1 profile defines the success boundary: a write is successful only after the backend transaction, WAL/journal durability and required file metadata flush complete. A restart, execution-generation replacement, activation or rollback retains committed application data. Rollback changes executable identity only. Backup/restore quiesces the application, captures all three files plus identity/schema metadata, and refuses a missing, corrupt, symlinked or cross-application set; it never silently creates an empty replacement.

The resource gate is explicit: guestMemoryBytes = resources.memoryBytes - reserveBytes. reserveBytes must exist for the selected runtime binding and architecture, use the same byte unit, and satisfy 1 <= reserveBytes < resources.memoryBytes; missing, zero-substituted, or reserveBytes >= resources.memoryBytes is fail-closed. Storage limits are measured independently of RSS and image labels.

### 4. One quota authority with two-phase data-plane writes

resources.storageBytes is the one aggregate KV+SQL envelope. The quota ledger is data-plane state in quota.sqlite3, never a control-state digest. It serializes all reservations for one application and records:

~~~text
QuotaReservationV2 = {
  schemaVersion: 2,
  reservationId: UUIDv7,
  operationId: UUIDv7,
  applicationId,
  backend: "kv" | "sql",
  ledgerRevision,
  expectedUsageRevision,
  baseCommittedBytes,
  reservedDeltaBytes,
  projectedCommittedBytes,
  expiresAt,
  state: "reserved" | "committed" | "released",
  reservationProofDigest: Digest32
}
~~~

The host performs a serialized reserve transaction that verifies committedBytes + outstandingReservedBytes + delta <= aggregateEnvelope and the service cap, then atomically writes `reserved` and returns a durable `reservationProofDigest = digestV2("iweb-wasm-quota-reservation-v2", JCS(reservation with state:"reserved" and the proof omitted))`. `reservedDeltaBytes` is a finite, conservative, profile-derived upper bound computed before touching either backend; if no such bound fits, the call returns quota-exceeded before any data mutation. The provider refuses a KV or SQL write unless the ledger row, expected usage revision, identity and proof match. It then performs the backend transaction with an idempotency marker containing the reservation, proof and operation IDs. Only after that backend commit is durable does it finalize the ledger to committed using the measured post-commit bytes. A failed backend transaction releases the reservation. A post-commit measurement or finalize failure is a recovery/quarantine state, never a false no-op quota response. There is no cross-backend transaction handle; concurrent KV and SQL calls are nevertheless bounded by the same ledger lock and cannot both pass a stale pre-write check.

Recovery is prescribed, not best effort:

| Durable state after crash | Recovery |
| --- | --- |
| reserved, no backend marker | release after checking the operation was not committed; expired reservations are never charged |
| reserved, backend marker present | recompute backend usage and finalize exactly once |
| backend marker, no ledger row | quarantine the backend, reconstruct the reservation from the marker, then finalize; do not expose a partial success |
| committed, marker present | idempotent replay returns the stored result |
| released with a committed marker or impossible revision regression | mark the service unavailable and require owner recovery; never subtract another operation's usage |

The monitor may project usageRevision, committed/reserved bytes, backend page/WAL bytes and dropped counts. Those samples are not control records and do not advance controlRevision, route generation, readiness lease or admission sequence. The control state stores only static envelope/profile/policy digest and optional schema/backup references.

### 5. Embedded host-call provider and framing

wasmd links an embedded-host-services-v2 provider directly into the execution process. Kernel/supervisor supplies an opaque execution context when creating the provider; the component cannot construct or replace it. The provider opens only the pre-derived per-application handles and injects the complete execution identity into each frame.

The canonical provider frame is length-prefixed u32 big-endian length followed by one UTF-8 JCS object; length is 1..1048576 bytes and no trailing bytes are allowed. Binary WIT values use canonical Component Model ABI bytes encoded as unpadded base64url in the JSON projection. The only method pairs are kv:get|set|delete|list, sql:execute, and logging:write; a service/method mismatch is INVALID_ARGUMENT. The request object is exactly:

~~~text
{
  schemaVersion: 2,
  protocol: "iweb-wasmd-host-call-v2",
  kind: "request",
  requestId: UUIDv7,
  service: "kv" | "sql" | "logging",
  method,
  execution: { applicationId, versionId, preparationGeneration, executionGeneration, fenceNonce },
  hostServicePolicyDigest: Digest32,
  deadlineMs,
  payload: base64url
}
~~~

The provider-created response is exactly {schemaVersion:2,protocol,kind:"response",requestId,execution,hostServicePolicyDigest,outcome:"ok"|"error",result:base64url|null,error:HostCallErrorV2|null}. outcome:"ok" requires non-null result and null error; outcome:"error" requires null result and non-null error. HostCallErrorV2 is exactly {code,detailCode:null|bounded-opaque-code}. Its code is a closed set: INVALID_FRAME, IDENTITY_MISMATCH, POLICY_MISMATCH, STALE_EXECUTION, APP_ISOLATION, INVALID_ARGUMENT, NOT_FOUND, CONFLICT, QUOTA_EXCEEDED, LIMIT_EXCEEDED, BUSY, TIMEOUT, CANCELLED, UNAVAILABLE, INTERNAL, REQUEST_ID_CONFLICT, REPLAY_UNAVAILABLE. Error detail is a bounded opaque code, never SQL/KV/log payload or a path.

deadlineMs is relative to provider entry and bounded by the pinned profile. Cancellation is a host-owned token observed before allocation and at SQLite progress checkpoints; timeout/cancel rolls back the current transaction and returns a stable error. A mutating request is at-most-once for (execution identity, requestId) until its replay TTL; identical replay returns the stored response, changed payload or policy returns REQUEST_ID_CONFLICT, and a prior-generation replay returns STALE_EXECUTION. The execution HTTP socket, snapshot FD socket and supervisor RPC endpoint reject this protocol, so Node has no second unauthenticated host-service entrance.

### 6. Service-specific choices

- KV uses iweb:kv@1.0.0/store. Single-key CAS is the normative consistency boundary; delete creates a tombstone/version so a stale writer cannot resurrect an older value. A list cursor is bound to application, policy digest, prefix, snapshot token and last key, expires after the profile TTL, and never exposes tombstones or inaccessible counts. Whether list ships in the first profile remains K1.
- SQL uses iweb:sql@1.0.0/store. Every call is one parameterized statement in one implicit host-owned transaction. Semicolon-separated scripts, ATTACH, extension loading, unsafe PRAGMA and external paths are rejected. Dialect breadth remains S1; cross-call transaction handles are not part of this Change.
- Logging uses iweb:logging@1.0.0/logger. The default is a per-application bounded memory ring and monitor projection; a full queue returns dropped immediately. Reserved field keys (authorization, cookie, set-cookie, x-api-key, api-key, token, secret, password, credential, request-body, sql, kv, config, owner-key) are rejected or replaced with [REDACTED]; the original value is never emitted. Stdout/stderr remain bounded discard. RustFS archival remains L1.

### 7. CAS and release wiring

All admission, service-policy changes, outbox append, acknowledgement projection, route-pointer CAS, activation, rollback and recovery repairs use one expected controlRevision and increment it exactly once. Data-plane host calls, quota reservation/finalize and monitor samples do not touch that CAS. HostServiceIdentityV2 is copied byte-for-byte into proof, catalog, control state, command, readiness, metrics, route event and rollback record; any mismatch blocks activation and public traffic falls back to generic unavailability.

The release gate evaluates V1 and V2 independently at startup. V1 records continue unchanged. A V2 service-enabled gate requires the fixed V3 acceptance record, ABI 1.1.0, matrix revision 2, matching catalog and capability hashes, complete policy digest and owner decisions. Any missing evidence, reserve proof, data-directory proof, or profile choice leaves the gate disabled; there is no environment/path fallback.

## Risks / Trade-offs

- [Two SQLite files plus ledger increase write latency] -> serialize reservations per application, bound lock wait/concurrency, and expose usage/recovery state only to owner diagnostics.
- [Crash between backend commit and ledger finalize] -> durable operation markers plus the recovery table make finalize idempotent; impossible ledger states quarantine the service instead of guessing usage.
- [V2 identity duplicates fields across many wires] -> use one canonical HostServiceIdentityV2 and golden vectors; reject any non-byte-identical projection.
- [Embedded provider couples wasmd to SQLite] -> keep provider boundary typed and versioned, with no filesystem path in WIT; a different backend requires a new provider/profile and policy digest.
- [Bounded logging loses events] -> return explicit dropped, project a dropped counter, and keep Kernel audit independent; durable archive is opt-in only.
- [V1/V2 rollout mismatch] -> V2 catalog/acceptance uses ABI 1.1.0 and a separate record version; V1 parsers never fallback, and the gate remains closed until all pins match.

## Migration Plan

1. Owner records K1, S1, L1 and H1. Until then, service-enabled publication is disabled; K2, S2 and Q1 are already fixed by this design.
2. Publish the V2 contracts, WIT packages, matrix record, catalog binding, V3 acceptance evidence and golden vectors without rewriting V1 records.
3. On first service-enabled preparation, create and permission-check the per-application directory and empty SQLite files through the host; a failure leaves the candidate not ready and does not disturb the old active execution.
4. Upgrade/restart wasmd and supervisor with the embedded provider. Existing V1 executions remain on the V1 parser and receive no service imports.
5. Rollback changes only the executable/route identity and retains committed data. A historical data restore requires a quiesced, identity-checked backup operation and its own owner audit event.
6. If any V2 ABI, evidence, reserve or recovery check fails, close the V2 gate or revoke its catalog entry. Never reinterpret the record as V1.

## Owner Decisions Ratified (2026-08-27)

| ID | Ratified decision | Rationale / shape |
| --- | --- | --- |
| K1 | **Include bounded `list(prefix, cursor, limit)`** | KV is application-owned data — enumeration does not cross a trust boundary (unlike iweb:secrets' owner-injected data); resource abuse is bounded by cursor/limit/budgets; the WIT shape is fixed once |
| S1 | **minimal-sqlite-v1 (single statement, parameterized, implicit per-call transaction)** | Owner-approved minimal dialect surface for wasm |
| L1 | **Bounded memory ring + monitor projection + owner-authorized external forwarding (drain/stream endpoint or configured syslog/JSON-lines, default off); no in-node log persistence** | Persistence belongs to the ops ecosystem (vector/promtail et al.); consistent with the wasmd stdout bounded-discard law and the 240MB envelope; bounded drop while a collector is down is the standard tradeoff |
| H1 | **iweb-wasmd-abi@1.1.0 with V2 catalog/acceptance** | Adopted per recommendation (ABI minor bump; 1.0.0 is not reused) |

K2 is closed as per-key linearizable CAS with tombstones; S2 is closed as one implicit transaction per call with no cross-call handle; Q1 is closed as one shared resources.storageBytes envelope. These are recorded as design constraints, not owner decisions.

### Historical: Owner Decision Boundary

| ID | Decision that changes the observable contract | Recommended choice |
| --- | --- | --- |
| K1 | Include list(prefix,cursor,limit) in the first iweb:kv@1.0.0 profile | Include bounded cursor/list; no unbounded enumeration |
| S1 | SQL dialect breadth under iweb:sql@1.0.0 | minimal-sqlite-v1 with the explicit denylist |
| L1 | Persist accepted logging events to RustFS | Keep bounded memory + monitor only |
| H1 | Release the new host ABI | iweb-wasmd-abi@1.1.0 with V2 catalog/acceptance |

K2 is closed as per-key linearizable CAS with tombstones; S2 is closed as one implicit transaction per call with no cross-call handle; Q1 is closed as one shared resources.storageBytes envelope. These are recorded as design constraints, not owner decisions.
