<!-- 用户原始需求（2026-08-13）：admin 与 mcp 也是能被看见和管理的内置应用，api 例外。 -->

## Purpose

定义 celld Dispatcher 如何承载内置与用户应用，以及已注册、未实现和未知应用之间可预期的访问结果。

## Requirements

### Requirement: Application availability does not expose runtime internals
The system SHALL return the intended HTTP response only from the application's active sandbox version. A registered application without a ready active version, or whose active sandbox is unavailable, MUST return HTTP 502 with a generic `application unavailable` response and MUST NOT expose sandbox, runtime, infrastructure, or failure diagnostics to the visitor.

#### Scenario: Unimplemented application is routed
- **WHEN** an enabled route targets an application without an implemented Dispatcher handler
- **THEN** the visitor receives HTTP 502 and a generic `application unavailable` response

#### Scenario: Registered application has no active version
- **WHEN** an enabled route targets an application without a ready active sandbox version
- **THEN** the visitor receives HTTP 502 and a generic `application unavailable` response

#### Scenario: Active sandbox fails
- **WHEN** the active application sandbox cannot serve a routed request
- **THEN** the visitor receives a generic availability response while authorized control-plane inspection retains the diagnostic details

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
The system SHALL restrict the shared celld Dispatcher to trusted image-seeded control-plane handlers retained during migration. It MUST NOT load, execute, or route a user application package; registered user application traffic SHALL target that application's active sandbox version. Ingress hostnames are accepted by the Kernel ingress directly; Caddy is retired from the node image.

#### Scenario: Registered image-seeded handler reaches Dispatcher
- **WHEN** the Kernel ingress accepts a registered hostname for an image-seeded handler
- **THEN** celld receives the request through the transitional node Dispatcher

#### Scenario: Registered user application receives traffic
- **WHEN** the Kernel ingress accepts a request for a registered user application with an active sandbox version
- **THEN** the request reaches that application's sandbox without executing in the shared Dispatcher

### Requirement: System surfaces remain visible in current projections
The system SHALL represent `admin` and `mcp` in workspace and route projections as trusted, protected node control-plane applications. Their projection MUST distinguish them from untrusted user applications and MUST NOT imply that they share a user application's sandbox identity or resources.

#### Scenario: Owner inspects workspace applications
- **WHEN** an authorized caller requests the workspace application projection
- **THEN** `admin` and `mcp` appear with protected control-plane status while user applications expose their separate sandbox lifecycle status
