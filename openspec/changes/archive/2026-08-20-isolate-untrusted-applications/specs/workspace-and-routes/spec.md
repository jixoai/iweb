<!-- 用户原始需求（2026-08-13）：统一工作区服务于所有者，但应用必须只拥有自己的存储和显式发布版本。 -->
<!-- 正交意图：工作区权限；路由激活；别名一致；写入与发布分离；应用存储隔离。 -->

## MODIFIED Requirements

### Requirement: One unified workspace
The system SHALL present ordinary files, application manifests, and application assets in one owner-visible `iweb-workspace` root. This logical owner view is available only through owner-authorized control operations; application sandboxes MUST NOT receive workspace-wide credentials or direct workspace-wide access.

#### Scenario: Operator lists workspace content
- **WHEN** an authorized caller lists the workspace
- **THEN** ordinary files and application directories are visible in one logical root

#### Scenario: Application attempts workspace-wide access
- **WHEN** application code attempts to list or read objects outside its admitted package and application-scoped storage
- **THEN** access is denied without exposing workspace-wide credentials

### Requirement: Application hostname registration is explicit
The system SHALL use the Kernel route registry as the source of truth for host IDs, application targets, enabled state, and system-route protection. In v1, user application host IDs MUST end in `.app`. Route registration SHALL NOT create an executable version and SHALL deliver traffic only when the target application has a ready active sandbox version.

#### Scenario: Authorized caller registers a user application route
- **WHEN** an authorized caller registers `notes.app` for application `notes`
- **THEN** the route registry persists the mapping without treating registration as application publication

#### Scenario: Registered application has an active version
- **WHEN** an enabled route targets an application with a ready active sandbox version
- **THEN** the route sends application traffic to that version

#### Scenario: Caller registers a non-app user host
- **WHEN** an authorized caller attempts to register `notes` for application `notes`
- **THEN** the system rejects the request because v1 user routes require the `.app` namespace

### Requirement: Hostname and path aliases preserve application identity
The system SHALL route `<app>.app.<base>` and `<base>/<app>/app` to the same active sandbox version of the registered application. The path alias MUST preserve an application base path so static-resource references resolve within the application.

#### Scenario: Visitor opens an application through its hostname
- **WHEN** a visitor requests `notes.app.<base>/` and Notes has a ready active version
- **THEN** the request is dispatched to that active Notes sandbox version

#### Scenario: Visitor opens an application through its path alias
- **WHEN** a visitor requests `<base>/notes/app` and Notes has a ready active version
- **THEN** the same version serves the response with resource URLs resolving from `/notes/app/`

### Requirement: Workspace writes do not publish code
The system SHALL persist authorized workspace file writes immediately. Such writes MUST NOT alter an admitted version, a running sandbox, or the active version pointer until an explicit publication succeeds.

#### Scenario: Operator edits an application source file
- **WHEN** an authorized caller writes `notes/app/index.js` while a Notes version is active
- **THEN** the object is stored and the active application behavior remains unchanged

#### Scenario: Publication of edited content fails
- **WHEN** edited workspace content fails package admission or sandbox readiness
- **THEN** the previous active version remains unchanged and continues receiving traffic

## ADDED Requirements

### Requirement: Application persistent storage is sandbox-scoped
The system SHALL provide each application a persistent storage namespace inaccessible to other applications. Deleting or replacing a package version MUST NOT implicitly grant another application access to that namespace, and any destructive storage action MUST be explicit and owner-authorized.

#### Scenario: One application probes another application's storage
- **WHEN** application `alpha` attempts to enumerate or mutate application `beta` persistent data
- **THEN** the storage boundary denies the operation

#### Scenario: Owner removes an application version
- **WHEN** an owner-authorized caller removes a non-active application version
- **THEN** the application's persistent data remains unchanged unless a separate authorized storage deletion was requested
