## MODIFIED Requirements

### Requirement: Owner credential protects control operations
The system SHALL require `Authorization: Bearer <owner-key>` for Kernel control operations. The bootstrap owner key SHALL originate from node configuration as `IWEB_API_TOKEN` and MUST NOT be copied into application packages, sandbox environments, application storage, URLs, logs, or public responses. In addition, Kernel SHALL accept an active delegated owner key issued by the owner-key-management capability; delegated keys have the same unsplit owner authority but can expire or be banned. The Kernel SHALL attribute every accepted operation to `bootstrap` or the delegated `keyId` derived from the received bearer and SHALL never trust a caller-supplied actor header.

#### Scenario: Unauthenticated control request
- **WHEN** a caller requests an authenticated Kernel endpoint without a valid bootstrap or delegated owner key
- **THEN** the Kernel returns HTTP 401 and performs no control-plane mutation

#### Scenario: Authorized publication creates a sandbox
- **WHEN** a valid owner-authorized publication causes Kernel to prepare an application sandbox
- **THEN** the sandbox receives only explicitly assigned application-scoped credentials and never receives the bootstrap or delegated owner key

#### Scenario: Delegated owner key performs control work
- **WHEN** a non-expired, non-banned delegated owner key calls a control operation
- **THEN** Kernel applies the same owner capability set as bootstrap, records the delegated `keyId`, and does not require a separate role or scope

#### Scenario: Banned delegated key is used
- **WHEN** a caller presents a delegated key after its ban is durably recorded
- **THEN** Kernel returns the standard HTTP 401 invalid-owner-key response and does not mutate control state

### Requirement: Kernel retains an administration recovery action
The system SHALL provide an owner-authorized recovery action through `api.<base>` that restores image-seeded control-plane applications, reconciles sandbox records without executing mutable workspace packages, and restarts the required node processes. This action MUST remain available even if Admin, MCP, application routes, application sandboxes, or the delegated owner-key snapshot are broken; `IWEB_API_TOKEN` remains the independent recovery credential.

#### Scenario: Administrator recovers the seeded Dispatcher
- **WHEN** an administrator calls the recovery action with a valid bootstrap or delegated owner key before sandboxed application routes exist
- **THEN** the Kernel republishes the image-seeded Worker and initiates the node restart sequence

#### Scenario: Administrator recovers the node control plane
- **WHEN** an administrator calls the recovery action with a valid bootstrap key while Admin, MCP, or `/data/kernel/keys.json` is unavailable
- **THEN** the Kernel restores the trusted image-seeded control surfaces and reconciles application state without routing unadmitted workspace code

#### Scenario: Delegated key cannot replace bootstrap recovery
- **WHEN** a caller attempts to ban, expire, or overwrite the bootstrap credential
- **THEN** Kernel rejects the operation and keeps `api.<base>` reachable with the configured `IWEB_API_TOKEN`
