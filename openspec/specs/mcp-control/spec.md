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
The system SHALL forward the caller's owner credential to Kernel operations only for the current request. The MCP application MUST NOT persist the credential.

#### Scenario: MCP tool invokes workspace control
- **WHEN** an authorized MCP client invokes a workspace tool
- **THEN** the tool calls the Kernel with the request credential and does not create a stored credential record

### Requirement: MCP exposes bounded workspace tools
The system SHALL expose tools to list, read, write, and delete workspace objects. Each tool SHALL observe the same Kernel path validation and size limits as the HTTP API.

#### Scenario: MCP writes and reads a file
- **WHEN** an authorized MCP client writes a valid text object and then reads it
- **THEN** the read operation returns the stored content through the Kernel workspace contract

### Requirement: MCP exposes route inspection and registration tools
The system SHALL expose tools to list domain mappings and register a user application domain. Registration MUST remain subject to reserved-prefix and `.app` namespace rules.

#### Scenario: MCP registers a valid application domain
- **WHEN** an authorized MCP client registers `notes.app` for `notes`
- **THEN** the MCP response reflects the Kernel-created domain mapping

#### Scenario: MCP registers a protected prefix
- **WHEN** an authorized MCP client attempts to register a host ID beginning with `admin`, `mcp`, or `api`
- **THEN** the MCP tool reports the Kernel rejection and does not change the route registry
