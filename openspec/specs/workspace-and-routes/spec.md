<!-- 用户原始需求（2026-08-13）：让个人开发者在一个统一文件空间中管理应用、资源和域名。 -->

## Purpose

定义 iweb 的单一工作区、应用目录约定与显式路由注册模型，避免将对象存储目录误认为自动部署机制。

## Requirements

### Requirement: One unified workspace
The system SHALL store ordinary files, application manifests, and application assets in one RustFS-backed `iweb-workspace` root. It MUST NOT introduce a product-level public/private bucket split. This logical owner view is available only through owner-authorized control operations; application sandboxes MUST NOT receive workspace-wide credentials or direct workspace-wide access.

#### Scenario: Operator lists workspace content
- WHEN an authorized caller lists the workspace
- THEN ordinary files and application directories are visible in one logical root

#### Scenario: Application attempts workspace-wide access
- WHEN application code attempts to list or read objects outside its admitted package and application-scoped storage
- THEN access is denied without exposing workspace-wide credentials

### Requirement: Application hostname registration is explicit
Every application host SHALL be an explicit route-registry entry. User-managed routes (`system:false`) target the wasm tier: their dispatch resolves the application's wasm v2 active pointer. `celld-app` targets exist only on system/image-seeded routes (`system:true`); the registration surface rejects a user route that names a `celld-app` target with bounded guidance. Route registration never confers admission.

#### Scenario: Owner registers a wasm application route
- **WHEN** an owner creates a user route for an admitted wasm application
- **THEN** dispatch resolves that application's v2 active pointer and nothing else

#### Scenario: User route names a celld target
- **WHEN** a user route registration carries a `celld-app` target
- **THEN** the Kernel rejects it with bounded guidance and the registry is unchanged

#### Scenario: Authorized caller registers a user application route
- **WHEN** an owner-authorized caller registers a valid user route
- **THEN** the registry records exactly the requested host and target and the change is visible to subsequent routing

#### Scenario: Registered application has an active version
- **WHEN** a registered wasm host is requested while its application has an active pointer
- **THEN** the request dispatches to that active execution; without an active pointer it is the generic bounded 502

#### Scenario: Caller registers a non-app user host
- **WHEN** a caller registers a user host without a valid wasm application target
- **THEN** registration is rejected with a bounded error and no route is created

### Requirement: Hostname and path aliases preserve application identity
The system SHALL route `<app>.app.<base>` and `<base>/<app>/app` to the same active sandbox version of the registered application. The path alias MUST preserve an application base path so static-resource references resolve within the application.

#### Scenario: Visitor opens an application through its hostname
- **WHEN** a visitor requests `notes.app.<base>/` and Notes has a ready active version
- **THEN** the request is dispatched to that active Notes sandbox version

#### Scenario: Visitor opens an application through its path alias
- **WHEN** a visitor requests `<base>/notes/app` and Notes has a ready active version
- **THEN** the same version serves the response with resource URLs resolving from `/notes/app/`

### Requirement: Workspace writes do not publish code
Workspace writes SHALL remain real storage writes that never compile, deploy, replace, or retire application code of either tier: no wasm version becomes admitted or routed from a workspace write, and no celld deployment project is created or republished from workspace content. Application code enters the node only through wasm admission or the node image.

#### Scenario: Workspace receives application-looking files
- **WHEN** an owner stores source or package files in the workspace
- **THEN** they remain inert files; no admission, execution, or deployment state changes

#### Scenario: Operator edits an application source file
- **WHEN** an operator edits source files under the workspace
- **THEN** the write succeeds as an ordinary object write and no runtime of either tier observes a code change

#### Scenario: Publication of edited content fails
- **WHEN** edited workspace content is expected to reach a running application without admission or image supply
- **THEN** no publication path exists; the application's code is unchanged

### Requirement: Application persistent storage is sandbox-scoped
The system SHALL provide each application a persistent storage namespace inaccessible to other applications. Deleting or replacing a package version MUST NOT implicitly grant another application access to that namespace, and any destructive storage action MUST be explicit and owner-authorized.

#### Scenario: One application probes another application's storage
- **WHEN** application `alpha` attempts to enumerate or mutate application `beta` persistent data
- **THEN** the storage boundary denies the operation

#### Scenario: Owner removes an application version
- **WHEN** an owner-authorized caller removes a non-active application version
- **THEN** the application's persistent data remains unchanged unless a separate authorized storage deletion was requested
