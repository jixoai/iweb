<!-- 用户原始需求（2026-08-27）：为 wasm 应用定义 iweb:sql 宿主能力；需要明确查询模型、SQLite 方言、事务、隔离、配额和恢复。 -->
<!-- 正交意图：固定 SQL host ABI 与参数绑定；固定事务/方言边界；固定应用隔离、配额和 durability。 -->

## Purpose

为不可信 wasm 应用提供应用专属、参数化且可限流的关系查询能力，在不暴露宿主文件系统、数据库连接或其他应用数据的前提下支持可恢复的 SQLite 状态。

## ADDED Requirements

### Requirement: SQL is an exact imported WIT capability with a bounded result

The system SHALL expose the proposed v1 Component Model package `iweb:sql@1.0.0` only through `import store`. Its complete proposed WIT shape is:

```wit
package iweb:sql@1.0.0;

interface store {
  type value = variant {
    null,
    integer(s64),
    real(float64),
    text(string),
    blob(list<u8>),
  };

  record parameter {
    value: value,
  }

  record column {
    name: string,
    value: value,
  }

  record row {
    columns: list<column>,
  }

  record result {
    rows: list<row>,
    affected: u64,
    last-insert-id: option<u64>,
  }

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

  execute: func(statement: string, parameters: list<parameter>) -> result<result, error>;
}

world sql {
  import store;
}
```

The component scanner SHALL accept this package only when the exact import identity and the revision-2 matrix entry `{package:"iweb:sql@1.0.0",interface:"store",direction:"import"}` are both present. An exported store, unknown patch, host-provided path/connection, or untyped core import is rejected before execution. The method's `value` union is the only parameter/result representation; arbitrary JSON objects, pointers, file descriptors, and host handles are not SQL values.

#### Scenario: Exact SQL import is admitted
- **WHEN** a component imports `iweb:sql@1.0.0/store` and its v2 policy enables the selected SQL profile
- **THEN** the host binds the call to that application's SQL backend and no other database handle is visible

#### Scenario: SQL direction or package is wrong
- **WHEN** a component exports `store`, imports `iweb:sql@1.0.1`, or requests an unlisted SQL interface
- **THEN** admission rejects before materialization and no SQL statement is executed

### Requirement: SQL uses a pinned dialect, parameter binding, and explicit transaction boundary

The recommended `minimal-sqlite-v1` profile SHALL accept one parameterized SQLite statement per call, with parameters bound by position and no string interpolation performed by the host. It SHALL allow ordinary `SELECT`, `INSERT`, `UPDATE`, and `DELETE`, plus only the owner-approved subset of schema DDL. It SHALL reject multiple statements, `ATTACH`, `DETACH`, `load_extension`, external virtual tables, arbitrary file paths, unsafe/unknown `PRAGMA`, extension loading, and statements outside the selected profile with `invalid-sql`.

Each call SHALL execute in one host-owned implicit transaction: the statement either commits in full or has no effect. The default profile SHALL expose no transaction handle spanning calls. A bounded batch may be introduced only as a separately versioned profile with its own statement and byte limits; it must not be inferred from semicolon-separated input. The complete SQLite dialect and cross-call transaction handle are owner decisions, not implementation defaults.

#### Scenario: Parameterized mutation commits atomically
- **WHEN** an admitted component executes one valid `INSERT` with bound parameters
- **THEN** the host commits one transaction and returns its affected count; a later error cannot leave a partial statement effect

#### Scenario: Multi-statement or external attachment is supplied
- **WHEN** a statement contains a second statement, `ATTACH`, `load_extension`, or a disallowed `PRAGMA`
- **THEN** the host returns `invalid-sql` before execution and the database remains unchanged

### Requirement: SQL results and resources are bounded and fail closed

The host SHALL enforce pinned maxima before and during execution: statement bytes, parameter count/bytes, row count, result bytes, affected-row count, execution time, lock wait, and concurrent calls. It SHALL stop a statement at the selected bound and return `limit-exceeded` or `busy` without returning a partial result as if it were complete. Error responses SHALL not include SQL text, parameter values, file paths, other applications' schema, or credentials.

SQL logical storage, SQLite pages, journal/WAL bytes, and fixed metadata count against the application's aggregate `resources.storageBytes` envelope and any tighter SQL service cap. A mutation whose post-commit usage cannot be proven within quota SHALL be rejected before commit with `quota-exceeded`; it SHALL not advance the Kernel control revision.

#### Scenario: Result exceeds the pinned byte bound
- **WHEN** a query would return more rows or bytes than the selected result limit
- **THEN** the host returns `limit-exceeded`, does not emit a truncated-success result, and leaves mutations governed by the call transaction

#### Scenario: Lock wait exceeds its bound
- **WHEN** another operation holds the SQLite lock beyond the selected wait limit
- **THEN** the call returns `busy` without opening an unbounded wait or changing the active route

### Requirement: SQL data is isolated per application and durable on successful commit

The system SHALL maintain a host-managed SQL backend dedicated to one application identity and separate from the KV backend and every other application's backend. The component SHALL never select a filesystem path, database filename, schema attachment, or connection. The backend SHALL survive wasmd/supervisor restart, execution generation replacement, activation, rollback, and ordinary route recovery; rollback changes executable identity only and does not implicitly restore an older data snapshot.

A successful mutation means the SQLite transaction has committed under the selected durability profile. The Kernel may include schema version/digest and backup references in owner-authorized control records, but SHALL NOT copy SQL text, bound parameters, result rows, or database contents into `wasm-control-state-v2`, admission proof, readiness lease, snapshot FD transport, supervisor command journal, or Kernel audit. Missing, corrupt, recovering, or identity-mismatched storage returns `unavailable`/`internal` and is never silently recreated empty.

#### Scenario: An application cannot read another application's table
- **WHEN** a component attempts to address a path, attachment, or schema belonging to another application
- **THEN** the host rejects the call without revealing whether the target exists

#### Scenario: Committed SQL survives a code rollback
- **WHEN** a mutation commits and the owner later activates a retained version of the same application
- **THEN** the retained version sees the same application data subject to its schema contract, and no other application gains access

