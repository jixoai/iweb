## MODIFIED Requirements

### Requirement: MCP endpoint requires owner authorization
The system SHALL expose MCP at `mcp.<base>/mcp` and require a valid bootstrap or delegated owner key on every MCP JSON-RPC request, including initialization, tool discovery, notifications that reach the server, and tool calls. Authentication SHALL complete before the server returns capabilities or invokes a tool.

#### Scenario: Client initializes without a key
- **WHEN** an MCP client sends `initialize` without a valid owner key
- **THEN** the endpoint returns HTTP 401 before returning JSON-RPC capabilities

#### Scenario: Client initializes with a key
- **WHEN** an MCP client sends `initialize` with a valid bootstrap owner key
- **THEN** the endpoint returns MCP server information and tool capability metadata

#### Scenario: Client initializes with a delegated key
- **WHEN** an MCP client sends `initialize` with a non-expired, non-banned delegated key
- **THEN** the endpoint returns MCP server information and tool capability metadata, and the Kernel can attribute subsequent control calls to that delegated `keyId`

#### Scenario: Client uses a key after ban
- **WHEN** an MCP client sends any JSON-RPC request after its delegated key has been banned
- **THEN** the endpoint returns HTTP 401 and does not return capabilities or invoke a tool

### Requirement: MCP forwards no stored credential
The system SHALL forward the caller's exact `Authorization: Bearer <owner-key>` value to Kernel control operations only for the current request. The MCP application MUST NOT persist the credential, include it in an application package or policy, or pass it into an application sandbox. MCP MUST NOT invent or accept a caller-controlled actor/key-id header; Kernel attribution is derived from the bearer it receives.

#### Scenario: MCP tool invokes workspace control
- **WHEN** an authorized MCP client invokes a workspace tool
- **THEN** the tool calls the Kernel with the request credential, Kernel audit attributes the operation to that credential's actor, and no stored credential record is created

#### Scenario: MCP tool invokes application control
- **WHEN** an authorized MCP client invokes a workspace, route, publication, or lifecycle tool
- **THEN** MCP uses the request credential only for the corresponding Kernel operation and no application environment or stored record receives that credential

#### Scenario: MCP forwards a delegated key without transformation
- **WHEN** a delegated key calls `tools/call`
- **THEN** the Kernel receives the original bearer value for that request, the MCP response contains no secret echo beyond the caller's own request context, and the audit event names the delegated `keyId`

## ADDED Requirements

### Requirement: MCP has no long-lived authorization exemption
The MCP transport SHALL treat each JSON-RPC request as an independent authorization boundary. A request already executing when its delegated key is banned MAY finish, but the next request MUST be rejected; any future streaming MCP transport MUST apply the same key-ban close semantics as the Kernel monitor contract before it is enabled.

#### Scenario: Ban races an MCP tool call
- **WHEN** a delegated tool call has passed authorization and another owner bans its key
- **THEN** that in-flight call completes or fails boundedly, while a later JSON-RPC request using the key receives HTTP 401
