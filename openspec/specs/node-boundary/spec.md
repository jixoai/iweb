<!-- 用户原始需求（2026-08-13）：以一个容器交付适合个人/家庭的低成本 iweb 节点，并先沉淀规范。 -->

## Purpose

定义 iweb 单节点的信任边界、进程入口与网络暴露规则，使个人部署既可维护又不会意外暴露节点内部能力。

## Requirements

### Requirement: Installation is the tenancy boundary
The system SHALL treat one iweb installation as one personal-node tenancy boundary. It MUST NOT claim to sandbox mutually untrusted tenants or code within that installation.

#### Scenario: Operator evaluates isolation scope
- **WHEN** an operator deploys one iweb image for a household or personal node
- **THEN** the node documents the installation as the ownership boundary rather than a hostile multi-tenant execution environment

### Requirement: Caddy is the only published ingress
The system SHALL publish Caddy as the only container network ingress. MinIO, Kernel, celld public Worker, and celld internal/operator listeners MUST remain un-published Docker services.

#### Scenario: External connection reaches node services
- **WHEN** a client connects through the node's published container port
- **THEN** the request first reaches Caddy and no direct Docker mapping exists for MinIO, Kernel, or either celld listener

### Requirement: Internal operator listener remains isolated
The system SHALL bind celld's operator/peer listener to loopback only. Caddy MUST NOT route a public hostname or path to that listener.

#### Scenario: External caller attempts operator access
- **WHEN** a caller uses a public iweb hostname
- **THEN** the caller cannot reach celld's internal/operator listener through Caddy or a published Docker port

### Requirement: Node services have distinct responsibilities
The system SHALL use Caddy for ingress, MinIO for persistent objects, celld for Worker execution, and Kernel for node control and recovery. A failure in an application route MUST NOT remove the Kernel recovery capability.

#### Scenario: Administration application is unavailable
- **WHEN** the Admin application cannot serve a request
- **THEN** the reserved Kernel API hostname remains independently reachable with a valid owner key
