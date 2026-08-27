<!-- 用户原始需求（2026-08-27）：为 wasm 应用定义 iweb:kv 宿主能力；需要明确 WIT、原子性、配额、隔离和 durability。 -->
<!-- 正交意图：固定 KV host ABI；固定应用隔离与实时持久语义；固定错误、配额和恢复边界。 -->

## Purpose

为不可信 wasm 应用提供版本化、应用隔离且受配额约束的键值持久化能力，使应用无需获得文件系统、RustFS 凭证或另一应用数据的访问权即可保存自己的状态。

## ADDED Requirements

### Requirement: KV is an exact imported WIT capability

The system SHALL expose the proposed v1 Component Model package `iweb:kv@1.0.0` only through `import store`. Its complete proposed WIT shape is:

```wit
package iweb:kv@1.0.0;

interface store {
  type key = string;
  type value = list<u8>;
  type version = u64;

  record item {
    key: key,
    value: value,
    version: version,
  }

  record page {
    items: list<item>,
    next-cursor: option<string>,
  }

  variant error {
    invalid-key,
    not-found,
    conflict,
    quota-exceeded,
    limit-exceeded,
    unavailable,
    internal,
  }

  get: func(key: key) -> result<item, error>;
  set: func(key: key, value: value, expected: option<version>) -> result<version, error>;
  delete: func(key: key, expected: option<version>) -> result<version, error>;
  list: func(prefix: string, cursor: option<string>, limit: u32) -> result<page, error>;
}

world kv {
  import store;
}
```

The component scanner SHALL accept this package only when the final world imports the exact `store` type identity and the pinned revision-2 matrix allowlists `{package:"iweb:kv@1.0.0",interface:"store",direction:"import"}`. An export of `store`, a package/interface/patch mismatch, an untyped core import, a path, file descriptor, socket, owner credential, or a host-supplied application identifier is rejected before instantiation. The `list` method is the recommended K1 profile; its presence is contingent on the owner decision recorded in this Change. If K1 selects no-list, implementation SHALL issue a new WIT/profile revision rather than silently implementing a different shape under this package identity.

#### Scenario: Component imports the exact KV store
- **WHEN** an admitted component imports `iweb:kv@1.0.0/store` with the exact `world kv` type identity and its v2 policy enables KV
- **THEN** the host may satisfy that import only for the execution identity pinned by Kernel

#### Scenario: Component substitutes an export or unknown KV interface
- **WHEN** a component exports `store`, imports `iweb:kv@1.0.1`, or presents an untyped core import named `kv`
- **THEN** admission rejects before materialization with a stable KV WIT-direction or matrix rejection and no host capability is granted

### Requirement: KV values have bounded per-key operations and single-key atomicity

The system SHALL validate `key` as UTF-8 `1..128` bytes matching `^[a-z][a-z0-9._-]{0,127}$`. A value is `0..65536` raw bytes; all byte lengths are measured before WIT allocation. `get` returns the one committed `(key,value,version)` or `not-found`. `set` and `delete` are atomic only for their one named key: when `expected` is present, the operation commits only if the current version equals it; when absent, it is an unconditional serialized mutation. A successful mutation allocates a strictly greater key version and returns it. No KV method starts or joins a cross-key transaction, and no read-modify-write promise exists outside an explicitly supplied expected version.

The recommended K2 profile is per-key linearizability: operations on one key are observed in one total commit order, while operations on different keys have no shared atomicity guarantee. The host SHALL not advertise stronger cross-key semantics, derive a version from wall-clock time, wrap a version counter, or treat a conflict as a successful overwrite.

#### Scenario: Competing conditional writes target one key
- **WHEN** two executions call `set` for the same key with the same expected version
- **THEN** exactly one mutation commits and returns a higher version; the other returns `conflict` without changing value, usage, or another key

#### Scenario: A request exceeds a per-key bound
- **WHEN** a component supplies an invalid key or a value larger than the selected `maxValueBytes`
- **THEN** the host returns `invalid-key` or `limit-exceeded` before allocating storage, and no partial value is visible

### Requirement: KV enumeration is bounded and does not escape the application namespace

Under the recommended K1 profile, `list` SHALL return only keys in the current application's KV namespace with the requested valid prefix, sorted by raw UTF-8 key bytes. `cursor` is an opaque host-issued continuation token bound to application ID, KV policy digest, prefix, and the last returned key; a cursor from another application, versioned policy, or prefix is `invalid-key`/`internal` and returns no entries. `limit` must be in `1..min(256, selectedMaxListItems)`; the encoded page is additionally bounded by `selectedMaxListBytes`, and `next-cursor` is non-null only when more matching keys exist.

Enumeration SHALL never enumerate owner configuration, secrets, SQL tables, logging buffers, RustFS objects, filesystem paths, or keys from another application. The host may return fewer than `limit` items to honor the byte cap; it must not make an unbounded scan or expose a count of otherwise inaccessible keys.

#### Scenario: A cursor is replayed for another application
- **WHEN** a component in application `beta` supplies a cursor issued to application `alpha`
- **THEN** the host rejects the cursor without disclosing whether `alpha` has matching keys or modifying either application's state

#### Scenario: A prefix page reaches its byte budget
- **WHEN** the next matching KV item would make a page exceed its selected byte limit
- **THEN** the host returns the prior bounded page and a continuation cursor, without allocating an unbounded response buffer

### Requirement: KV storage is application-isolated, quota-accounted, and durable on success

The system SHALL store each application's KV data in a host-managed per-application backend selected by the pinned host-service policy. The component receives no file path or storage credential. The backend SHALL be distinct from every other application's KV backend and from the SQL backend's externally reachable namespace. KV logical usage, backend page usage, and fixed metadata overhead count against the application's selected `resources.storageBytes` envelope and any tighter KV service cap. Before a mutation commits, the host SHALL atomically prove that post-commit usage is within all selected limits; `quota-exceeded` performs no mutation and reports no competing application's usage.

A successful `set` or `delete` SHALL mean its transaction is committed under the node's selected durability profile. Data survives wasmd/supervisor restart, a higher execution generation, activation, rollback, and ordinary route recovery. The control-state revision, admission proof, readiness lease, snapshot FD transport, supervisor command journal, and Kernel audit SHALL NOT contain KV values, cursor bytes, or runtime KV mutations. A missing, corrupt, locked beyond its bound, or identity-mismatched backend returns `unavailable`/`internal`; it MUST NOT be replaced with an empty store.

#### Scenario: KV write would exceed aggregate application storage
- **WHEN** a KV `set` would cause the application's shared storage envelope to exceed its selected limit
- **THEN** the host returns `quota-exceeded`, leaves the prior key version and all SQL/KV data unchanged, and does not advance Kernel control revision

#### Scenario: Restart follows a committed KV write
- **WHEN** a successful KV write is followed by supervisor restart before another application lifecycle mutation
- **THEN** the next valid execution for the same application observes the committed value, while another application's namespace remains inaccessible

