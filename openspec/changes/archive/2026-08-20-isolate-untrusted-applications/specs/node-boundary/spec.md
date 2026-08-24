<!-- 用户原始需求（2026-08-13）：每个不可信应用必须与节点控制面及其他应用隔离。 -->
<!-- 正交意图：替换过渡期禁令；去除运行技术绑定；封锁内部服务。 -->

## REMOVED Requirements

### Requirement: Installation is the tenancy boundary
The system SHALL treat one iweb installation as one personal-node tenancy boundary. It MUST NOT claim to sandbox mutually untrusted tenants or code within that installation.

#### Scenario: Operator evaluates isolation scope
- **WHEN** an operator deploys one iweb image for a household or personal node
- **THEN** the node documents the installation as the ownership boundary rather than a hostile multi-tenant execution environment

## MODIFIED Requirements

### Requirement: Node services have distinct responsibilities
The system SHALL use Caddy for ingress, persistent object services for owner workspace and control-plane state, an isolated sandbox facility for user application execution, and Kernel for node control and recovery. A failure in an application sandbox or application route MUST NOT remove the Kernel recovery capability.

#### Scenario: Administration application is unavailable
- **WHEN** the Admin application cannot serve a request
- **THEN** the reserved Kernel API hostname remains independently reachable with a valid owner key

#### Scenario: Application runtime is unavailable
- **WHEN** one or all application sandboxes cannot serve requests
- **THEN** the reserved Kernel API hostname remains independently reachable with a valid owner key

## ADDED Requirements

### Requirement: Transitional runtime does not execute arbitrary packages
The system SHALL restrict the shared celld Dispatcher to trusted image-seeded control-plane applications during migration. Arbitrary application packages MUST execute only after admission into an application sandbox and MUST NOT be compiled, loaded, or routed through the shared Dispatcher.

#### Scenario: Deployment agent requests arbitrary publishing before isolation exists
- **WHEN** MCP receives a request to execute a new application package while only the shared Dispatcher runtime is available
- **THEN** the node rejects executable publication rather than running the package in the shared deployment

#### Scenario: Deployment agent publishes after sandbox capability exists
- **WHEN** an owner-authorized deployment agent submits a valid application package
- **THEN** the node admits and executes it through an application-specific sandbox rather than the shared Dispatcher

#### Scenario: Sandbox facility is unavailable
- **WHEN** a deployment request arrives while the node cannot enforce the required application boundary
- **THEN** the node rejects executable publication rather than falling back to shared execution

### Requirement: Application sandboxes cannot reach internal node authority
The system SHALL enforce a boundary that prevents application sandboxes from directly reaching Kernel, object-store administration, runtime operator or peer listeners, host loopback services, and private endpoints of other application sandboxes. Application-controlled code MUST NOT be able to weaken this boundary.

#### Scenario: Application probes node-local endpoints
- **WHEN** an application attempts to connect to a protected node-local address or listener
- **THEN** the connection is denied without relying on cooperation from the application code

