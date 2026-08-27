<!-- 用户原始需求（2026-08-27）：硬化 iweb:logging 宿主能力，明确结构化事件、有界丢弃、审计分离和 redaction；只改 OpenSpec change，不写实现。 -->
<!-- 正交意图：固定 logging WIT 与错误/结果 wire；固定容量、丢弃和 owner diagnostics；固定敏感字段与 stdout/stderr 隔离。 -->

## Purpose

为不可信 wasm 应用提供有界的结构化诊断写入能力，使 owner 能观察运行问题，同时不把应用日志变成 Kernel 审计、秘密载体或无上限持久存储。

## ADDED Requirements

### Requirement: Logging is an exact imported structured-event capability

The system SHALL expose iweb:logging@1.0.0 only through import logger. The proposed WIT shape is:

~~~wit
package iweb:logging@1.0.0;

interface logger {
  enum level { trace, debug, info, warn, error }
  record field { key: string, value: string }
  record event { level: level, message: string, fields: list<field> }
  enum outcome { accepted, dropped }
  variant error { invalid-event, limit-exceeded, unavailable, internal }
  write: func(event: event) -> result<outcome, error>;
}

world logging { import logger; }
~~~

The closure, matrix revision 2 and HostServicePolicyV2 must agree on this exact package/interface/direction. An export, unknown patch, untyped core import, caller timestamp, identity, owner credential, request body or host handle is rejected before acceptance.

#### Scenario: Exact logger import is enabled
- **WHEN** an admitted component imports iweb:logging@1.0.0/logger under an enabled V2 policy
- **THEN** the provider binds the event to the injected execution identity and does not accept caller-supplied identity

#### Scenario: Logging ABI is substituted
- **WHEN** a component exports logger, imports iweb:logging@1.0.1, or passes a host handle through an untyped import
- **THEN** admission rejects before execution and emits no event

### Requirement: Logging validates bounded structured events and drops explicitly

The host SHALL validate message as UTF-8 0..4096 bytes, fields as at most 32 unique lowercase keys matching ^[a-z][a-z0-9._-]{0,63}$, and each field value as UTF-8 0..1024 bytes. The encoded event including host metadata SHALL fit the pinned maxEventBytes. Unknown levels, duplicate/invalid keys, invalid UTF-8, over-bound values or disabled levels return invalid-event or limit-exceeded and are not accepted.

The per-application buffer has fixed byte/event capacities from the V2 capability record. Redaction is applied before size accounting, retention or monitor projection; the original value is never retained. If a valid event would exceed capacity or bounded writer budget, write returns dropped immediately, increments that application's dropped counter, does not block/retry the request and never evicts another application's events. dropped means the event was not retained; it is not an audit confirmation.

#### Scenario: Buffer is full
- **WHEN** a valid event arrives after the application's byte or event capacity is reached
- **THEN** write returns dropped, increments the application counter and leaves request progress unblocked

#### Scenario: Event contains a sensitive or duplicate field
- **WHEN** an event includes duplicate keys or a reserved sensitive key/value
- **THEN** the host rejects invalid-event or replaces only the value with [REDACTED], retains no original, and does not reveal existing events

### Requirement: Application logging is separate from audit and stdio

Each accepted event is an application diagnostic record with host-added UTC timestamp, application ID, version ID, preparation/execution generation, level, message and validated fields. Owner-authorized monitor/diagnostic projections may expose only the bounded retained records for that application. Public routes receive no log body and visitors cannot query another application's stream.

Kernel audit remains authoritative for owner-authenticated control operations. Logging SHALL NOT create, modify, substitute for or merge into an audit event. wasi:cli/stdout and wasi:cli/stderr remain bounded discard sinks and are never aliases or fallbacks for iweb:logging. The host SHALL NOT inject or copy secret/config values, Authorization headers, request bodies, raw SQL/KV payloads or another application's identity.

#### Scenario: An error event is accepted
- **WHEN** a valid error event is written
- **THEN** owner diagnostics may identify its execution, while Kernel audit and public traffic contain no event body

#### Scenario: stderr is written
- **WHEN** a component writes bytes to wasi:cli/stderr
- **THEN** bytes go to the existing bounded discard sink and never appear in logging or audit

### Requirement: Logging retention and durability are profile-bound

The recommended L1 profile SHALL retain accepted events only in a bounded per-application in-memory ring and monitor projection for the current runtime lifecycle. It SHALL make no durable-retention claim across supervisor/wasmd restart. Backend failure SHALL return unavailable/internal and never fall back to stdout, stderr, audit or an unbounded local file.

If owner authorizes RustFS archival, it is a separately named profile and policy digest with explicit retention bytes/time, encryption and credential boundary, failure/recovery semantics and owner-only read surface. It cannot be silently enabled. The archive path remains separate from audit and must apply the same redaction boundary.

#### Scenario: Runtime restarts under default profile
- **WHEN** supervisor or wasmd restarts while the in-memory profile is active
- **THEN** buffered events may disappear, the host makes no durability claim and Kernel audit remains intact

#### Scenario: No archive evidence exists
- **WHEN** no owner-approved archival profile and matching V2 capability hash are present
- **THEN** the provider uses only bounded memory and refuses implicit object-storage persistence
