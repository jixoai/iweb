## MODIFIED Requirements

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
