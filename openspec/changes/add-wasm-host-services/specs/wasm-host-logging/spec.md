<!-- 用户原始需求（2026-08-27）：为 wasm 应用定义 iweb:logging 宿主能力；需要明确结构化等级写、有界丢弃与审计分离。 -->
<!-- 正交意图：固定 logging host ABI；固定有界接纳/丢弃语义；固定诊断、审计与秘密边界。 -->

## Purpose

为不可信 wasm 应用提供有界的结构化诊断写入能力，使 owner 能观测应用运行问题，同时不把应用日志变成 Kernel 审计记录、秘密载体或无上限持久存储。

## ADDED Requirements

### Requirement: Logging is an exact imported structured event capability

The system SHALL expose the proposed v1 Component Model package `iweb:logging@1.0.0` only through `import logger`. Its complete proposed WIT shape is:

```wit
package iweb:logging@1.0.0;

interface logger {
  enum level {
    trace,
    debug,
    info,
    warn,
    error,
  }

  record field {
    key: string,
    value: string,
  }

  record event {
    level: level,
    message: string,
    fields: list<field>,
  }

  enum outcome {
    accepted,
    dropped,
  }

  variant error {
    invalid-event,
    limit-exceeded,
    unavailable,
    internal,
  }

  write: func(event: event) -> result<outcome, error>;
}

world logging {
  import logger;
}
```

The component scanner SHALL accept this package only when the exact `logger` import identity is declared and the revision-2 matrix allowlists `{package:"iweb:logging@1.0.0",interface:"logger",direction:"import"}`. An export of `logger`, an alternate patch/interface, untyped core import, caller-supplied timestamp, sandbox identity, owner credential, request body, or host log handle is rejected before the event is accepted.

#### Scenario: Exact structured logger is imported
- **WHEN** an admitted component imports `iweb:logging@1.0.0/logger` under an enabled revision-2 policy
- **THEN** the host binds every accepted event to the current execution identity and does not accept caller-supplied identity fields

#### Scenario: Component attempts a different logging ABI
- **WHEN** a component exports `logger`, imports a different package version, or tries to pass a host handle through an untyped core import
- **THEN** admission rejects before execution and no event is emitted

### Requirement: Logging accepts only bounded structured events and explicitly drops under pressure

The host SHALL validate `message` as UTF-8 `0..4096` bytes, fields as at most 32 unique lowercase keys matching `^[a-z][a-z0-9._-]{0,63}$`, and each field value as UTF-8 `0..1024` bytes. The encoded event, including host-added metadata, SHALL not exceed the pinned `maxEventBytes`. Unknown level, duplicate/invalid field key, invalid UTF-8, over-bound message/field/event, or a policy-disabled level is `invalid-event`/`limit-exceeded` and is not accepted.

The logging buffer SHALL have a fixed per-application byte/event capacity from the pinned v2 capability record. When accepting an event would exceed that capacity or its bounded writer budget, the host SHALL return `dropped` immediately, increment a per-application dropped counter, and neither block nor retry the application request. `dropped` is a successful observation of non-persistence, not an audit confirmation. The host must not evict another application's events to accept this application's event.

#### Scenario: Buffer reaches capacity
- **WHEN** a valid application event arrives after its logging buffer has reached the selected byte or event cap
- **THEN** `write` returns `dropped`, the dropped counter increases, and application request progress is not blocked by a logging retry

#### Scenario: Event has a duplicate field name
- **WHEN** an event contains duplicate fields or a field key outside the grammar
- **THEN** `write` returns `invalid-event`, adds no event, and does not disclose existing log contents

### Requirement: Application diagnostics remain separate from Kernel audit and stdout/stderr

Each accepted event SHALL be stored as an application diagnostic record containing host-added UTC timestamp, application ID, version ID, preparation/execution generation, level, message, and validated fields. It SHALL be exposed only through owner-authorized diagnostic/monitor projections subject to bounded retention. The public route receives no application log body, and a visitor cannot query another application's diagnostic stream.

Kernel audit remains the authoritative record of owner-authenticated control operations. Application logging SHALL NOT create, modify, substitute for, or be merged into a Kernel audit event. `wasi:cli/stdout` and `wasi:cli/stderr` remain bounded discard sinks exactly as defined by `wasm-application-runtime`; they MUST NOT become aliases, fallbacks, or ingestion paths for `iweb:logging`. The host MUST NOT automatically copy secret/config values, Authorization headers, request bodies, raw SQL/KV payloads, or another application's identity into an event.

#### Scenario: Application emits an error event
- **WHEN** a valid `error` logging event is accepted
- **THEN** the owner diagnostic projection can identify the execution that emitted it, while Kernel audit gains no application log entry and public traffic receives no event contents

#### Scenario: Application writes to stderr instead of logger
- **WHEN** a component writes bytes to `wasi:cli/stderr`
- **THEN** the bytes use the existing bounded discard sink and do not appear in `iweb:logging` or Kernel audit

### Requirement: Logging retention, recovery, and persistence are profile-bound

The recommended L1 profile SHALL retain accepted events only in a bounded per-application in-memory buffer plus monitor projection for the current runtime lifecycle. It SHALL preserve only the bounded dropped counter across the projection interval and SHALL make no durable-history claim after supervisor/wasmd restart. A logging backend failure returns `unavailable`/`internal`; it MUST NOT fall back to stdout, stderr, Kernel audit, or an unbounded local file.

If owner authorizes RustFS-backed archival, it SHALL be a separately named policy/profile and capability hash with explicit retention bytes/time, encryption/credential boundary, write-failure semantics, recovery/backup behavior, and owner-only read surface. It cannot be silently enabled under the default profile and must not include owner credentials, secrets/config values, raw request bodies, SQL parameters, KV values, or unredacted Authorization headers.

#### Scenario: Default logging process restarts
- **WHEN** supervisor or wasmd restarts while the default in-memory logging profile is active
- **THEN** prior buffered events may be unavailable after restart, the host does not claim durable retention, and Kernel audit remains intact and separate

#### Scenario: Archive profile is absent
- **WHEN** no owner-approved archival policy and matching capability hash exist
- **THEN** the host uses only the bounded default buffer and refuses any attempt to persist events through an implicit object-storage fallback

