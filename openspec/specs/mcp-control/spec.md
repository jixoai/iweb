<!-- 用户原始需求（2026-08-13）：本地 Codex 能借由 mcp.<base> 和 key 管理个人节点。 -->

## Purpose

定义 iweb MCP 系统应用的鉴权和最小控制工具集，使受信任本地开发工具能够通过 owner key 管理工作区与路由。

## Requirements

### Requirement: MCP endpoint requires owner authorization
The system SHALL expose MCP at `mcp.<base>/mcp` and require a valid owner key on every MCP request, including initialization and tool discovery.

#### Scenario: Client initializes without a key
- **WHEN** an MCP client sends `initialize` without a valid owner key
- **THEN** the endpoint returns HTTP 401 before returning JSON-RPC capabilities

#### Scenario: Client initializes with a key
- **WHEN** an MCP client sends `initialize` with a valid owner key
- **THEN** the endpoint returns MCP server information and tool capability metadata

### Requirement: MCP forwards no stored credential
The system SHALL forward the caller's owner credential to Kernel control operations only for the current request. The MCP application MUST NOT persist the credential, include it in an application package or policy, or pass it into an application sandbox.

#### Scenario: MCP tool invokes workspace control
- **WHEN** an authorized MCP client invokes a workspace tool
- **THEN** the tool calls the Kernel with the request credential and does not create a stored credential record

#### Scenario: MCP tool invokes application control
- **WHEN** an authorized MCP client invokes a workspace, route, publication, or lifecycle tool
- **THEN** MCP uses the request credential only for the corresponding Kernel operation and no application environment or stored record receives that credential

### Requirement: MCP exposes bounded workspace tools
The system SHALL expose tools to list, read, write, and delete workspace objects. Each tool SHALL observe the same Kernel path validation and size limits as the HTTP API.

#### Scenario: MCP writes and reads a file
- **WHEN** an authorized MCP client writes a valid text object and then reads it
- **THEN** the read operation returns the stored content through the Kernel workspace contract

### Requirement: MCP exposes route inspection and registration tools
The system SHALL expose tools to list domain mappings and register a user application domain. Registration MUST remain subject to reserved-prefix and `.app` namespace rules and MUST report a route mapping separately from application publication or readiness.

#### Scenario: MCP registers a valid application domain
- **WHEN** an authorized MCP client registers `notes.app` for `notes`
- **THEN** the MCP response reflects the Kernel-created domain mapping without claiming that Notes is published or ready

#### Scenario: MCP registers a protected prefix
- **WHEN** an authorized MCP client attempts to register a host ID beginning with `admin`, `mcp`, or `api`
- **THEN** the MCP tool reports the Kernel rejection and does not change the route registry

### Requirement: MCP exposes application validation and publication tools
MCP SHALL expose tools that validate and publish **wasm** application packages through the Kernel admission contract. The tools report admission, preparation, readiness, and activation results exactly as the Kernel returns them. A request referencing celld as the deployment kind is rejected with bounded guidance: untrusted or network-sourced code must be compiled to a wasi:http component and admitted as wasm; trusted code with native needs belongs in a node image build. No MCP tool creates, replaces, or retires celld deployments.

#### Scenario: Deployment agent publishes a valid package
- **WHEN** an MCP tool call supplies a valid wasm package and policy under owner authorization
- **THEN** the tool forwards the admission transaction and reports the Kernel's structured result

#### Scenario: Deployment agent publishes an invalid package
- **WHEN** an MCP tool call supplies a package that fails validation or the capability matrix
- **THEN** the tool reports the Kernel's bounded rejection and nothing is admitted or executed

#### Scenario: Agent asks to deploy celld code
- **WHEN** a tool call names celld as the target runtime
- **THEN** the tool returns the bounded celld image-only guidance and performs no deployment

### Requirement: MCP exposes sandbox lifecycle and rollback tools
MCP SHALL expose wasm execution lifecycle tools (start, stop, list retained admitted versions, rollback, delete version) mapped to Kernel wasm control operations. celld lifecycle tools do not exist; a tool call targeting a celld application's lifecycle returns the bounded image-only guidance.

#### Scenario: Deployment agent inspects an application
- **WHEN** an MCP inspection call names an application
- **THEN** the tool reports its runtime kind, admitted versions, and lifecycle availability from Kernel projections

#### Scenario: Deployment agent rolls back a failed update
- **WHEN** an MCP rollback call names a retained admitted wasm version
- **THEN** the Kernel route-pointer CAS result is reported verbatim

#### Scenario: Agent stops a celld application
- **WHEN** a lifecycle tool call names a celld-seeded application
- **THEN** the tool rejects it with the image-only guidance and the fleet process is untouched
