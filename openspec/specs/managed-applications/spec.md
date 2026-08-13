<!-- 用户原始需求（2026-08-13）：admin 与 mcp 也是能被看见和管理的内置应用，api 例外。 -->

## Purpose

定义 celld Dispatcher 如何承载内置与用户应用，以及已注册、未实现和未知应用之间可预期的访问结果。

## Requirements

### Requirement: Dispatcher is the single application deployment entrypoint
The system SHALL deploy one celld Dispatcher for the node and use it to select the application named by a routed `<app>.app.<base>` request.

#### Scenario: Registered application request reaches Dispatcher
- **WHEN** Caddy and Kernel accept a registered application hostname
- **THEN** celld receives the request through the single node Dispatcher

### Requirement: System applications are visible applications
The system SHALL treat `admin` and `mcp` as visible celld applications represented in the workspace and route registry. Their protected route records MUST be distinguishable from user application routes.

#### Scenario: Operator inspects workspace applications
- **WHEN** an authorized caller requests the workspace application projection
- **THEN** `admin` and `mcp` appear with system-route status and their mapped host IDs

### Requirement: Application availability does not expose runtime internals
The system SHALL return the application's intended HTTP response when its handler is implemented. An application name that reaches the Dispatcher without an implemented handler MUST return HTTP 502 with a generic availability message and MUST NOT expose celld or Durable Object debug state.

#### Scenario: Unimplemented application is routed
- **WHEN** an enabled route targets an application without an implemented Dispatcher handler
- **THEN** the visitor receives HTTP 502 and a generic `application unavailable` response

### Requirement: Unknown application host is rejected
The system SHALL reject a hostname that is not a registered iweb route with HTTP 404. It MUST NOT execute an application merely because its host name matches a wildcard DNS record.

#### Scenario: Visitor requests an unknown app hostname
- **WHEN** a visitor requests `unknown.app.<base>` without a registered route
- **THEN** the node returns HTTP 404

### Requirement: Notes demonstrates a normal application response
The system SHALL include a Notes application that serves an HTML notes interface and a documented notes API. Its public root response MUST NOT disclose implementation counters or runtime diagnostics.

#### Scenario: Visitor opens Notes
- **WHEN** a visitor opens the registered Notes application root
- **THEN** the node returns the Notes HTML application rather than a JSON runtime diagnostic
