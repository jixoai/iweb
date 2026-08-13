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
The system SHALL require `Authorization: Bearer <owner-key>` for Kernel control operations. The bootstrap owner key SHALL originate from node configuration as `IWEB_API_TOKEN`.

#### Scenario: Unauthenticated control request
- **WHEN** a caller requests an authenticated Kernel endpoint without a valid owner key
- **THEN** the Kernel returns HTTP 401 and performs no control-plane mutation

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
The system SHALL provide an owner-authorized recovery action that republishes the image-seeded Dispatcher and restarts the node process. This action MUST remain available through `api.<base>` even if the Admin route is broken.

#### Scenario: Administrator recovers the seeded Dispatcher
- **WHEN** an administrator calls the recovery action with a valid owner key
- **THEN** the Kernel republishes the image-seeded Worker and initiates the node restart sequence
