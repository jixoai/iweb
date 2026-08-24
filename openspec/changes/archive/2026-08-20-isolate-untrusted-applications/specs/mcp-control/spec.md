<!-- 用户原始需求（2026-08-13）：Codex 通过 MCP 无缝部署和运维应用，但凭证不能进入不可信应用。 -->
<!-- 正交意图：凭证转发边界；路由非发布；发布工具；生命周期与回滚工具。 -->

## MODIFIED Requirements

### Requirement: MCP forwards no stored credential
The system SHALL forward the caller's owner credential to Kernel control operations only for the current request. The MCP application MUST NOT persist the credential, include it in an application package or policy, or pass it into an application sandbox.

#### Scenario: MCP tool invokes workspace control
- **WHEN** an authorized MCP client invokes a workspace tool
- **THEN** the tool calls the Kernel with the request credential and does not create a stored credential record

#### Scenario: MCP tool invokes application control
- **WHEN** an authorized MCP client invokes a workspace, route, publication, or lifecycle tool
- **THEN** MCP uses the request credential only for the corresponding Kernel operation and no application environment or stored record receives that credential

### Requirement: MCP exposes route inspection and registration tools
The system SHALL expose tools to list domain mappings and register a user application domain. Registration MUST remain subject to reserved-prefix and `.app` namespace rules and MUST report a route mapping separately from application publication or readiness.

#### Scenario: MCP registers a valid application domain
- **WHEN** an authorized MCP client registers `notes.app` for `notes`
- **THEN** the MCP response reflects the Kernel-created domain mapping without claiming that Notes is published or ready

#### Scenario: MCP registers a protected prefix
- **WHEN** an authorized MCP client attempts to register a host ID beginning with `admin`, `mcp`, or `api`
- **THEN** the MCP tool reports the Kernel rejection and does not change the route registry

## ADDED Requirements

### Requirement: MCP exposes application validation and publication tools
The system SHALL expose owner-authorized tools that validate a workspace application package, submit an immutable version for publication, and return its admission, preparation, readiness, and activation result. Failures SHALL include stable machine-readable reasons without exposing node credentials or protected infrastructure details.

#### Scenario: Deployment agent publishes a valid package
- **WHEN** an authorized MCP client validates and publishes a conforming application package
- **THEN** the tool returns the resulting version identity and whether it became active

#### Scenario: Deployment agent publishes an invalid package
- **WHEN** admission or sandbox preparation rejects the requested package
- **THEN** the tool reports the failed stage and reason while preserving the previous active version

### Requirement: MCP exposes sandbox lifecycle and rollback tools
The system SHALL expose owner-authorized tools to inspect application status and resource policy, start or stop an application, list retained admitted versions, roll back to a selected version, and delete an application sandbox or version subject to active-version safety rules.

#### Scenario: Deployment agent inspects an application
- **WHEN** an authorized MCP client requests application status
- **THEN** the tool returns the active version, lifecycle state, resource policy, and current authorized diagnostics for that application

#### Scenario: Deployment agent rolls back a failed update
- **WHEN** an authorized MCP client selects a retained admitted version for rollback
- **THEN** the tool reports readiness and atomic activation outcomes without rebuilding from mutable workspace content
