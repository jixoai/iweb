<!-- 用户原始需求（2026-08-13）：让个人开发者在一个统一文件空间中管理应用、资源和域名。 -->

## Purpose

定义 iweb 的单一工作区、应用目录约定与显式路由注册模型，避免将对象存储目录误认为自动部署机制。

## Requirements

### Requirement: One unified workspace
The system SHALL store ordinary files, application manifests, and application assets in one MinIO-backed `iweb-workspace` root. It MUST NOT introduce a product-level public/private bucket split.

#### Scenario: Operator lists workspace content
- **WHEN** an authorized caller lists the workspace
- **THEN** ordinary files and application directories are visible in one logical root

### Requirement: Application directory convention is explicit
The system SHALL recognize an application directory as `<app>/iweb.json` plus `<app>/app/`. This directory convention MUST NOT by itself create an executable route.

#### Scenario: Manifest exists without a route
- **WHEN** an application manifest and implementation directory exist in the workspace without an enabled route record
- **THEN** the application appears as workspace content but receives no implicit hostname execution route

### Requirement: Application hostname registration is explicit
The system SHALL use the Kernel route registry as the source of truth for host IDs, application targets, enabled state, and system-route protection. In v1, user application host IDs MUST end in `.app`.

#### Scenario: Authorized caller registers a user application route
- **WHEN** an authorized caller registers `notes.app` for application `notes`
- **THEN** the route registry persists that mapping and routes that hostname to the registered application

#### Scenario: Caller registers a non-app user host
- **WHEN** an authorized caller attempts to register `notes` for application `notes`
- **THEN** the system rejects the request because v1 user routes require the `.app` namespace

### Requirement: Hostname and path aliases preserve application identity
The system SHALL route `<app>.app.<base>` to the registered application and SHALL provide `<base>/<app>/app` as an alias for that same application. The alias MUST preserve an application base path so static-resource references resolve within the application.

#### Scenario: Visitor opens an application through its hostname
- **WHEN** a visitor requests `notes.app.<base>/`
- **THEN** the request is dispatched to the registered `notes` application

#### Scenario: Visitor opens an application through its path alias
- **WHEN** a visitor requests `<base>/notes/app`
- **THEN** the response is served by the registered `notes` application with resource URLs resolving from `/notes/app/`

### Requirement: Workspace writes do not publish code
The system SHALL persist authorized workspace file writes immediately. Such writes MUST NOT dynamically compile, deploy, or replace celld Worker code.

#### Scenario: Operator edits an application source file
- **WHEN** an authorized caller writes `notes/app/index.js` into the workspace
- **THEN** the object is stored and the currently deployed application behavior remains unchanged until an explicit publish capability exists
