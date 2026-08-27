<!-- 用户原始需求（2026-08-27）：硬化 iweb:sql 宿主能力，明确最小 SQLite 方言、隐式事务、共享配额与 host-call 绑定；只改 OpenSpec change，不写实现。 -->
<!-- 正交意图：固定 SQL WIT 与参数/结果 wire；固定方言、事务和资源边界；固定应用隔离、durability 和恢复。 -->

## Purpose

为不可信 wasm 应用提供应用专属、参数化且有界的 SQLite 查询能力，在不暴露宿主路径、数据库连接或其他应用数据的情况下支持可恢复的关系状态。

## ADDED Requirements

### Requirement: SQL is an exact imported WIT capability

The system SHALL expose iweb:sql@1.0.0 only through import store. The proposed WIT shape is:

~~~wit
package iweb:sql@1.0.0;

interface store {
  variant value { null, integer(s64), real(f64), text(string), blob(list<u8>) }
  record parameter { value: value }
  record column { name: string, value: value }
  record row { columns: list<column> }
  record query-result { rows: list<row>, affected: u64, last-insert-id: option<u64> }

  variant error {
    invalid-sql,
    invalid-parameter,
    constraint,
    busy,
    quota-exceeded,
    limit-exceeded,
    unavailable,
    internal,
  }

  execute: func(statement: string, parameters: list<parameter>) -> result<query-result, error>;
}

world sql { import store; }
~~~

The closure, matrix revision 2 and HostServicePolicyV2 must agree on this exact package/interface/direction. An export, unknown patch, untyped core import, filesystem path, database filename, FD, socket or caller-supplied application identity is rejected before execution. SQL values are only the listed WIT union; arbitrary JSON objects and host handles are not values.

#### Scenario: Exact SQL import is enabled
- **WHEN** a component imports iweb:sql@1.0.0/store and the V2 policy enables the selected profile
- **THEN** wasmd binds it only to the injected application's SQL backend

#### Scenario: SQL import is substituted
- **WHEN** a component exports store, imports iweb:sql@1.0.1, or uses an untyped core import
- **THEN** admission rejects before materialization and no statement runs

### Requirement: SQL dialect and transaction boundary are pinned

The recommended S1 profile minimal-sqlite-v1 SHALL accept exactly one parameterized SQLite statement per call, with positional parameter binding and no host string interpolation. It SHALL permit ordinary SELECT, INSERT, UPDATE and DELETE plus an owner-approved bounded schema DDL subset. It SHALL reject multiple statements, ATTACH, DETACH, load_extension, external virtual tables, arbitrary file paths, unsafe PRAGMA and extension loading with invalid-sql.

Each call is one host-owned implicit transaction: it commits in full or has no effect. S2 is closed as no cross-call transaction handle; a bounded batch, if ever introduced, requires a new profile and policy digest. The host never infers a batch from semicolon-separated text.

#### Scenario: A parameterized mutation commits atomically
- **WHEN** an admitted component executes one valid INSERT or UPDATE with bound parameters
- **THEN** the host commits one transaction and returns its complete affected count

#### Scenario: A script or external attachment is supplied
- **WHEN** a statement contains a second statement, ATTACH, load_extension or a disallowed PRAGMA
- **THEN** the host returns invalid-sql before execution and the database remains unchanged

### Requirement: SQL resources and results are bounded

The selected profile SHALL enforce maxima for statement bytes, parameter count/bytes, row count, result bytes, affected rows, execution time, lock wait and concurrent calls before and during execution. It must not return a truncated-success result. Limit violations return limit-exceeded; lock exhaustion returns busy; errors contain no SQL text, parameters, paths or credentials.

A mutation reserves shared quota before commit using the single per-application ledger, a finite conservative byte bound and a durable reservation proof, then records an operation marker. If the bound cannot fit within resources.storageBytes and any SQL cap, the host returns quota-exceeded before execution and performs no mutation. If post-commit measurement or finalize is interrupted, the ledger recovery/quarantine rules apply and the host does not claim a quota no-op. Successful commit/finalize does not advance Kernel controlRevision.

#### Scenario: Result reaches its bound
- **WHEN** a query would exceed the selected row or byte maximum
- **THEN** the host returns limit-exceeded without presenting a partial result as complete

#### Scenario: Lock wait reaches its bound
- **WHEN** another operation holds the database lock beyond the selected wait
- **THEN** the host returns busy without an unbounded wait or route change

### Requirement: SQL data is isolated, durable and recovery-safe

The host SHALL maintain one host-managed sql.sqlite3 per application under the derived 0700 directory, separate from KV and every other application. The component SHALL NOT select a path, attachment or connection. sqlite-full-fsync-v1 SHALL define successful commit. Committed mutations SHALL survive wasmd/supervisor restart, execution-generation replacement, activation, rollback and route recovery. Rollback changes executable identity only.

Backup/restore quiesces the application and verifies applicationId, schema metadata, file identity and integrity before use. Missing, corrupt, recovering, identity-mismatched or silently recreated-empty storage returns unavailable/internal. SQL text, parameters, result rows and database pages never enter control state, admission proof, readiness, snapshot FD, supervisor journal or Kernel audit.

#### Scenario: Another application's database is requested
- **WHEN** a component tries ATTACH, a path, or another application identity
- **THEN** the provider returns APP_ISOLATION/INVALID_ARGUMENT without revealing whether the target exists

#### Scenario: Committed data survives code rollback
- **WHEN** a SQL mutation commits and the owner activates a retained version of the same application
- **THEN** that version sees the data under its schema contract and no other application can read it

#### Scenario: Crash occurs between SQL commit and quota finalize
- **WHEN** the backend marker is durable but quota finalization is interrupted
- **THEN** recovery finalizes once and an identical host-call replay returns the original result without double charging
