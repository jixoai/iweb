<!-- 用户原始需求（2026-08-13）：admin 与 mcp 也是能被看见和管理的内置应用，api 例外。 -->

## Purpose

定义 celld Dispatcher 如何承载内置与用户应用，以及已注册、未实现和未知应用之间可预期的访问结果。

## Requirements

### Requirement: Application availability does not expose runtime internals
An unknown host SHALL be `404`. A registered application without a reachable execution is a generic bounded `502 application unavailable` for the visitor; runtime internals (celld state, wasm control state, supervisor journals, process identities) never appear in visitor-facing responses.

#### Scenario: Registered application is down
- **WHEN** a registered host targets an application whose process or execution is unavailable
- **THEN** the visitor receives the generic bounded 502 and no diagnostic state is exposed

#### Scenario: Unimplemented application is routed
- **WHEN** a registered host has no implemented dispatch target
- **THEN** the response is the generic bounded 502 application unavailable and no runtime internals leak

#### Scenario: Registered application has no active version
- **WHEN** a registered wasm host resolves to no active pointer
- **THEN** the visitor receives the generic bounded 502 without exposing control-state details

#### Scenario: Active sandbox fails
- **WHEN** the execution behind an active pointer fails while serving
- **THEN** the visitor receives the generic bounded 502 and the failure is visible only to authorized monitoring

### Requirement: Unknown application host is rejected
The system SHALL reject a hostname that is not a registered iweb route with HTTP 404. It MUST NOT execute an application merely because its host name matches a wildcard DNS record.

#### Scenario: Visitor requests an unknown app hostname
- **WHEN** a visitor requests `unknown.app.<base>` without a registered route
- **THEN** the node returns HTTP 404

### Requirement: Notes demonstrates a normal application response
The system SHALL include a Notes application that runs in its own application sandbox and serves an HTML notes interface and documented notes API. Its public root response MUST NOT disclose implementation counters or runtime diagnostics.

#### Scenario: Visitor opens Notes
- **WHEN** a visitor opens the registered Notes application while its sandbox version is active
- **THEN** the node returns the Notes HTML application from the Notes sandbox rather than a shared handler or runtime diagnostic

### Requirement: Dispatcher is the image-seeded prototype entrypoint
The image-seeded fleet SHALL be the permanent celld supply mechanism, not a transitional prototype: every celld application on the node was built into the node image and started by the entrypoint, one process per application. The Kernel routes their hosts to their per-app processes; no runtime admission, publication, or version lifecycle applies to them. Upgrading a fleet application means building a new node image.

#### Scenario: Fleet application serves through its own process
- **WHEN** a visitor reaches a registered fleet host
- **THEN** the Kernel forwards to that application's own celld process, and the process's identity comes only from the image seed and route registry

#### Scenario: Registered image-seeded handler reaches Dispatcher
- **WHEN** a registered image-seeded application receives a request
- **THEN** the Kernel dispatches to that application's own process port from the route registry

#### Scenario: Registered user application receives traffic
- **WHEN** a registered user route targeting a wasm application with an active pointer receives a request
- **THEN** the Kernel resolves the v2 active pointer to the live execution and forwards; without a pointer it is the generic bounded 502

### Requirement: System surfaces remain visible in current projections
Status and monitor projections SHALL keep system surfaces (admin, mcp) visible as trusted control-plane applications with their runtime kind labeled, alongside user applications; projections distinguish runtime tier without exposing internal state.

#### Scenario: Status lists applications with runtime kinds
- **WHEN** an authorized status request returns applications
- **THEN** each entry carries its runtime kind and lifecycle availability as defined by `runtime-observability`

#### Scenario: Owner inspects workspace applications
- **WHEN** an owner lists applications through Admin or MCP
- **THEN** image-seeded system surfaces and user applications are both visible with their runtime kinds and no internal runtime state is exposed
