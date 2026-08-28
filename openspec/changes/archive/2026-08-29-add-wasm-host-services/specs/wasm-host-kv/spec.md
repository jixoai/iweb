<!-- 用户原始需求（2026-08-27）：硬化 iweb:kv 宿主能力，明确 cursor/tombstone、共享配额与 host-call 绑定；只改 OpenSpec change，不写实现。 -->
<!-- 正交意图：固定 KV WIT 与调用结果；固定单 key 一致性及 list 游标；固定应用隔离、配额、durability 和恢复。 -->

## Purpose

为不可信 wasm 应用提供应用隔离、版本化且受共享配额约束的键值持久化能力，使应用无需文件系统、RustFS 凭证或其他应用数据权限即可保存和遍历自己的状态。

## ADDED Requirements

### Requirement: KV is an exact imported WIT capability

The system SHALL expose iweb:kv@1.0.0 only through import store. The proposed WIT shape is:

~~~wit
package iweb:kv@1.0.0;

interface store {
  type key = string;
  type value = list<u8>;
  type version = u64;

  record item { key: key, value: value, version: version }
  record page { items: list<item>, next-cursor: option<string> }

  variant error {
    invalid-key,
    not-found,
    conflict,
    quota-exceeded,
    limit-exceeded,
    cursor-expired,
    unavailable,
    internal,
  }

  get: func(key: key) -> result<item, error>;
  set: func(key: key, value: value, expected: option<version>) -> result<version, error>;
  delete: func(key: key, expected: option<version>) -> result<version, error>;
  %list: func(prefix: string, cursor: option<string>, limit: u32) -> result<page, error>;
}

world kv { import store; }
~~~

The component closure, matrix revision 2 and HostServicePolicyV2 must agree on this exact package/interface/direction. An export, unknown patch, untyped core import, path, FD, socket, credential or caller-supplied application identity is rejected before instantiation. If K1 selects no list, a new WIT/profile revision is required; the host MUST NOT change this shape silently.

#### Scenario: Exact KV import is enabled
- **WHEN** a component imports iweb:kv@1.0.0/store and the V2 policy enables the matching profile
- **THEN** wasmd binds the import only to the injected execution identity and its application backend

#### Scenario: KV import direction or revision is wrong
- **WHEN** a component exports store, imports iweb:kv@1.0.1, or presents an untyped core import
- **THEN** admission rejects before materialization and no KV provider is created

### Requirement: KV operations have bounded single-key linearization

The host SHALL validate key as UTF-8 1..128 bytes matching ^[a-z][a-z0-9._-]{0,127}$ and value as 0..65536 raw bytes before allocation. get reads one committed item or returns not-found. set and delete are serialized for one key: an expected version commits only when equal to the current version; absent expected is an unconditional mutation; success allocates a strictly greater u64 version. This is the complete consistency guarantee; no cross-key transaction or read-modify-write promise exists.

Delete SHALL write a tombstone/version in the KV backend. Tombstones are not returned by get/list, but remain long enough to prevent a stale writer or cursor from resurrecting an older value. Version counters never wrap; exhaustion returns unavailable.

#### Scenario: Two conditional writes race
- **WHEN** two executions set the same key with the same expected version
- **THEN** exactly one commits a higher version and the other returns conflict without changing any KV/SQL usage

#### Scenario: Delete prevents stale resurrection
- **WHEN** a stale execution writes an older version after a delete tombstone exists
- **THEN** the write returns conflict and the deleted key remains absent from reads and lists

### Requirement: KV list cursors are bounded, scoped and expiring

When K1 includes list, list SHALL accept a non-empty prefix within the key grammar, a limit in 1..min(256, profile.maxListItems), and a cursor issued by the same host. Results are sorted by raw UTF-8 key bytes and bounded by profile.maxListBytes; the host may return fewer than limit items to honor bytes. The cursor is an opaque host token whose authenticated payload is bound to applicationId, hostServicePolicyDigest, prefix, snapshot token, last returned key and cursor expiry. It contains no caller-selected path or namespace.

A cursor from another application, policy digest, prefix, or snapshot returns a stable invalid-key/limit-exceeded error without revealing matching keys or counts. An expired token or reclaimed snapshot returns cursor-expired and never restarts at the beginning. Tombstones are skipped, inaccessible namespaces are never enumerated, and next-cursor is non-null only when more visible matches exist. Frame-path cursor strings are the raw registry tokens on both the request field and the `nextCursor` response field, identical to the WIT path; no additional encoding layer is applied. The host does not promise a repeatable snapshot after cursor expiry. Tombstones are retained for at least the maximum cursor TTL plus the host-call replay TTL and are garbage-collected only when no active cursor or replay can reference their version; if that proof is unavailable they remain retained and count toward quota.

#### Scenario: Cursor crosses application or policy
- **WHEN** application beta or a new policy presents alpha's cursor
- **THEN** the host rejects it before scanning and reveals no alpha key or count

#### Scenario: Page hits the byte cap
- **WHEN** the next visible item would exceed maxListBytes
- **THEN** the host returns the prior bounded page and a continuation cursor without an unbounded allocation

#### Scenario: Cursor expires
- **WHEN** a caller presents a cursor after its profile TTL or after its snapshot is reclaimed
- **THEN** the host returns cursor-expired and does not restart at the beginning

### Requirement: KV writes use the shared quota ledger and durable profile

KV mutations SHALL use the per-application quota ledger and two-phase reservation/finalize contract from wasm-application-runtime. A finite conservative byte bound and durable reservation proof are required before the KV transaction; an over-limit or unprovable reservation changes no key, tombstone, SQL data or controlRevision. The backend marker includes the operationId, reservationId and reservation proof; finalize occurs only after the KV transaction and sqlite-full-fsync-v1 durability succeed. A post-commit measurement/finalize interruption follows ledger recovery and may quarantine the backend; it is never reported as a false no-op.

Each application uses a host-created kv.sqlite3 under its derived 0700 data directory. The component receives no path or handle. Successful set/delete survive wasmd/supervisor restart, execution-generation replacement, activation, rollback and route recovery. Missing, corrupt, recovering, identity-mismatched or locked-beyond-bound storage returns unavailable/internal and is never replaced with an empty store.

#### Scenario: Shared quota is exhausted
- **WHEN** a KV write would exceed the aggregate envelope while SQL has committed or reserved bytes
- **THEN** the ledger returns quota-exceeded atomically, leaves all backends unchanged and does not advance controlRevision

#### Scenario: Crash occurs after KV commit
- **WHEN** the KV marker is durable but ledger finalize is interrupted
- **THEN** recovery finalizes that reservation exactly once and an identical host-call replay returns the original version

#### Scenario: Other application data is addressed
- **WHEN** a component supplies another applicationId, path, or SQL namespace through a KV call
- **THEN** the provider returns APP_ISOLATION/INVALID_ARGUMENT without probing or revealing the target
