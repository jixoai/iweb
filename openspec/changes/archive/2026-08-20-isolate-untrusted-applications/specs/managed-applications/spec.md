<!-- 用户原始需求（2026-08-13）：应用必须独立运行，不能继续以共享 Dispatcher handler 作为发布模型。 -->
<!-- 正交意图：限定 Dispatcher；区分控制面应用；定义可用性；迁移 Notes。 -->

## REMOVED Requirements

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

## MODIFIED Requirements

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

### Requirement: Notes demonstrates a normal application response
The system SHALL include a Notes application that runs in its own application sandbox and serves an HTML notes interface and documented notes API. Its public root response MUST NOT disclose implementation counters or runtime diagnostics.

#### Scenario: Visitor opens Notes
- **WHEN** a visitor opens the registered Notes application while its sandbox version is active
- **THEN** the node returns the Notes HTML application from the Notes sandbox rather than a shared handler or runtime diagnostic

## ADDED Requirements

### Requirement: Dispatcher is the image-seeded prototype entrypoint
The system SHALL restrict the shared celld Dispatcher to trusted image-seeded control-plane handlers retained during migration. It MUST NOT load, execute, or route a user application package; registered user application traffic SHALL target that application's active sandbox version.

#### Scenario: Registered image-seeded handler reaches Dispatcher
- **WHEN** Caddy and Kernel accept a registered hostname for an image-seeded handler
- **THEN** celld receives the request through the transitional node Dispatcher

#### Scenario: Registered user application receives traffic
- **WHEN** Caddy and Kernel accept a request for a registered user application with an active sandbox version
- **THEN** the request reaches that application's sandbox without executing in the shared Dispatcher

### Requirement: System surfaces remain visible in current projections
The system SHALL represent `admin` and `mcp` in workspace and route projections as trusted, protected node control-plane applications. Their projection MUST distinguish them from untrusted user applications and MUST NOT imply that they share a user application's sandbox identity or resources.

#### Scenario: Owner inspects workspace applications
- **WHEN** an authorized caller requests the workspace application projection
- **THEN** `admin` and `mcp` appear with protected control-plane status while user applications expose their separate sandbox lifecycle status
