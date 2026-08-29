<!-- 用户原始需求（2026-08-13）：保留不可动摇的 api 控制面，以便 Admin 损坏后仍能恢复节点。 -->

## Purpose

定义独立于 celld 应用生命周期的 Kernel 控制面，以及其所有权鉴权、保留命名空间和恢复边界。

## Requirements

### Requirement: API hostname is permanently Kernel-owned
The system SHALL reserve `api.<base>` for the Kernel API. No celld route registration, application manifest, or system application replacement MAY override that hostname.

#### Scenario: Caller attempts to register the API hostname
- **WHEN** an authorized caller attempts to register host ID `api` or `api.app`
- **THEN** the system rejects the registration because the `api` prefix is reserved

### Requirement: Owner credential protects control operations
The system SHALL require `Authorization: Bearer <owner-key>` for Kernel control operations. The bootstrap owner key SHALL originate from node configuration as `IWEB_API_TOKEN` and MUST NOT be copied into application packages, sandbox environments, application storage, URLs, logs, or public responses.

#### Scenario: Unauthenticated control request
- **WHEN** a caller requests an authenticated Kernel endpoint without a valid owner key
- **THEN** the Kernel returns HTTP 401 and performs no control-plane mutation

#### Scenario: Authorized publication creates a sandbox
- **WHEN** a valid owner-authorized publication causes Kernel to prepare an application sandbox
- **THEN** the sandbox receives only explicitly assigned application-scoped credentials and never receives the owner key

### Requirement: System routes are protected
The system SHALL seed and preserve protected routes for `admin`, `admin.app`, `mcp`, and `mcp.app`. A caller MUST NOT overwrite or delete a protected system route through the route API.

#### Scenario: Caller attempts to delete a system route
- **WHEN** an authorized caller deletes `admin.app`
- **THEN** the Kernel returns a conflict response and retains the system route

### Requirement: Kernel supports bounded workspace control
The system SHALL provide owner-authorized workspace listing, text-file read, text-file write, and file deletion. Text-file writes MUST reject content larger than 1 MiB.

#### Scenario: Caller writes a permitted text file
- **WHEN** an authorized caller writes valid text content at a valid workspace path within 1 MiB
- **THEN** the Kernel persists the object and returns a successful creation response

#### Scenario: Caller writes an oversized text file
- **WHEN** an authorized caller submits workspace text content larger than 1 MiB
- **THEN** the Kernel rejects the request without storing the content

### Requirement: Kernel retains an administration recovery action
The system SHALL provide an owner-authorized recovery action through `api.<base>` that restores image-seeded control-plane applications, reconciles sandbox records without executing mutable workspace packages, and restarts the required node processes. This action MUST remain available even if Admin, MCP, application routes, or application sandboxes are broken.

#### Scenario: Administrator recovers the seeded Dispatcher
- **WHEN** an administrator calls the recovery action with a valid owner key before sandboxed application routes exist
- **THEN** the Kernel republishes the image-seeded Worker and initiates the node restart sequence

#### Scenario: Administrator recovers the node control plane
- **WHEN** an administrator calls the recovery action with a valid owner key
- **THEN** the Kernel restores the trusted image-seeded control surfaces and reconciles application state without routing unadmitted workspace code

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

### Requirement: Control plane ships as a self-contained static binary
The system SHALL deliver the Kernel as a single self-contained binary. The node image MUST NOT carry a general-purpose scripting runtime dedicated to the control plane, and the Kernel MUST keep the permanent `api.<base>` recovery authority independent of celld.

#### Scenario: Image inspection finds no control-plane scripting runtime
- WHEN an operator inspects the node image
- THEN the Kernel is a single static binary and no node/JS runtime is present for control-plane purposes

#### Scenario: Kernel binary reports its identity
- WHEN the Kernel binary is invoked with its version flag
- THEN it reports the version and the recovery authority remains reachable through `api.<base>` with a valid owner key

### Requirement: Kernel implementations are pinned by shared contract vectors
The system SHALL pin Kernel observable behavior with golden contract vectors shared across implementations, covering control request/response shapes, rejection cases, and the canonical package digest; any implementation MUST produce byte-identical digests for the same canonical package content.

#### Scenario: Canonical digest parity across implementations
- WHEN the same canonical package content is digested by any Kernel implementation under test
- THEN the resulting digest equals the golden vector value byte-for-byte
