<!-- 用户原始需求（2026-08-13）：Kernel 必须在应用沙箱之外掌握编排和恢复权，应用永远拿不到 owner key。 -->
<!-- 正交意图：强化凭证边界；活动版本权威；生命周期编排；恢复路径。 -->

## MODIFIED Requirements

### Requirement: Owner credential protects control operations
The system SHALL require `Authorization: Bearer <owner-key>` for Kernel control operations. The bootstrap owner key SHALL originate from node configuration as `IWEB_API_TOKEN` and MUST NOT be copied into application packages, sandbox environments, application storage, URLs, logs, or public responses.

#### Scenario: Unauthenticated control request
- **WHEN** a caller requests an authenticated Kernel endpoint without a valid owner key
- **THEN** the Kernel returns HTTP 401 and performs no control-plane mutation

#### Scenario: Authorized publication creates a sandbox
- **WHEN** a valid owner-authorized publication causes Kernel to prepare an application sandbox
- **THEN** the sandbox receives only explicitly assigned application-scoped credentials and never receives the owner key

### Requirement: Kernel retains an administration recovery action
The system SHALL provide an owner-authorized recovery action through `api.<base>` that restores image-seeded control-plane applications, reconciles sandbox records without executing mutable workspace packages, and restarts the required node processes. This action MUST remain available even if Admin, MCP, application routes, or application sandboxes are broken.

#### Scenario: Administrator recovers the seeded Dispatcher
- **WHEN** an administrator calls the recovery action with a valid owner key before sandboxed application routes exist
- **THEN** the Kernel republishes the image-seeded Worker and initiates the node restart sequence

#### Scenario: Administrator recovers the node control plane
- **WHEN** an administrator calls the recovery action with a valid owner key
- **THEN** the Kernel restores the trusted image-seeded control surfaces and reconciles application state without routing unadmitted workspace code

## ADDED Requirements

### Requirement: Kernel owns application versions and active routing state
The system SHALL be the authority for admitted application version identities, their lifecycle states, resource and network policies, and the single active version pointer for each application. Application code and workspace mutation MUST NOT directly change these records.

#### Scenario: Application attempts to activate itself
- **WHEN** application-controlled code attempts to change its active version or policy outside an owner-authorized Kernel operation
- **THEN** the system denies the mutation and retains the authoritative records

#### Scenario: Kernel activates a ready version
- **WHEN** an owner-authorized operation selects an admitted version that has passed readiness
- **THEN** Kernel atomically updates the active version used for new application requests

### Requirement: Kernel controls sandbox lifecycle without joining the sandbox
The system SHALL provide owner-authorized operations to validate, prepare, start, stop, inspect, update, roll back, and delete application sandboxes while remaining outside their execution, credential, storage, and network boundary. A failed lifecycle operation MUST return a bounded failure result and preserve unrelated applications.

#### Scenario: Sandbox start fails
- **WHEN** Kernel cannot start or ready a requested application version
- **THEN** it reports the affected version and failure category, preserves any previous active version, and leaves unrelated applications operational

#### Scenario: Application sandbox is deleted
- **WHEN** an owner-authorized caller deletes a non-active sandbox version
- **THEN** Kernel removes that version's executable lifecycle resources without deleting application persistent data unless separately requested
