# application-sandbox Specification

## Purpose
定义不可信应用从包准入到运行、更新和回滚的强制安全边界，使任一应用都不能越权影响其他应用或节点控制面。

## Requirements

### Requirement: Publication admits an immutable application version
The system SHALL validate an application package and its declared runtime policy before creating an immutable application version. A rejected package MUST NOT create or replace an active version, start executable code, or receive application traffic.

#### Scenario: Package admission succeeds
- **WHEN** an owner-authorized deployment request supplies a package and policy that satisfy the node's admission contract
- **THEN** the system creates an immutable version identity that can be prepared for that application

#### Scenario: Package admission fails
- **WHEN** the package, manifest, or requested policy fails validation
- **THEN** the system returns structured rejection details without executing the package or changing the active version

### Requirement: Every application has an exclusive security boundary
The system SHALL execute each application as a security principal distinct from the node control plane and every other application. An application MUST receive only its own package snapshot, application-scoped credentials, and application-scoped persistent storage; it MUST NOT read or mutate the owner workspace, another application's package or storage, the owner key, or infrastructure credentials.

#### Scenario: Compromised application probes another security principal
- **WHEN** application `alpha` attempts to read application `beta` data, owner workspace objects, or node credentials
- **THEN** the isolation boundary denies access without exposing the target data or credential value

#### Scenario: Application inspects its runtime environment
- **WHEN** an application reads the files, variables, and credentials available inside its boundary
- **THEN** it sees only its admitted package and explicitly assigned application-scoped resources

### Requirement: Application network access is policy-bound
The system SHALL deny direct application access to node control-plane, object-store administration, runtime-operator, host-loopback, and other application-private endpoints. External network access MUST be limited to an explicit owner-authorized application policy and MUST NOT grant reachability to those protected destinations.

#### Scenario: Application targets an internal node service
- **WHEN** an application attempts to connect to Kernel, MinIO administration, a runtime operator listener, host loopback, or another application's private endpoint
- **THEN** the connection is denied by an enforced boundary outside the application process

#### Scenario: Application requests undeclared external access
- **WHEN** an application attempts an external connection that its active policy does not allow
- **THEN** the connection is denied without changing the active policy

### Requirement: Resource and failure effects are contained per application
The system SHALL enforce finite per-application CPU and memory limits and SHALL account usage to the same application boundary. A sandbox crash, forced termination, resource exhaustion, stop, or delete operation MUST NOT terminate another application or the node control plane.

#### Scenario: Application exceeds its memory limit
- **WHEN** an application consumes more memory than its configured sandbox limit
- **THEN** the system contains or terminates that sandbox, records the application-specific failure, and keeps other security principals operational

#### Scenario: Owner stops an application
- **WHEN** an owner-authorized caller stops one application
- **THEN** new traffic no longer reaches that application's sandbox while other applications and the recovery API remain available

### Requirement: Version activation and rollback are atomic
The system SHALL direct new traffic to exactly one active admitted version per application. An update MUST become active only after its sandbox is ready; failed preparation or activation MUST preserve the previous healthy active version. An owner-authorized rollback SHALL reactivate a retained admitted version through the same readiness gate.

#### Scenario: Replacement version becomes ready
- **WHEN** a newly admitted version reaches its required ready state
- **THEN** the system atomically makes it active for new requests and retires the previous version from new traffic

#### Scenario: Replacement version fails before activation
- **WHEN** a newly admitted version fails to become ready
- **THEN** the system reports the failure and continues routing new requests to the previous healthy active version

#### Scenario: Owner rolls back an application
- **WHEN** an owner-authorized caller selects a retained admitted version and that version becomes ready
- **THEN** the system atomically makes the selected version active without rebuilding it from mutable workspace content
