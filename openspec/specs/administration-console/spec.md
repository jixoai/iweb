<!-- 用户原始需求（2026-08-13）：Admin 要以企业级控制台管理文件、应用路由、密钥登录与实时节点状态。 -->

## Purpose

定义 iweb Admin 作为可替换系统应用的管理员体验、浏览器凭据边界，以及工作区、应用路由和节点观测的职责划分。

## Requirements

### Requirement: Admin console application reachability
The Admin console SHALL remain reachable on its three origins (`admin.<base>`, `admin.app.<base>`, `<base>/admin/app`) with relative-resource behavior preserved. Application lists and detail views label each application's runtime kind (celld image-seeded vs wasm admitted); celld entries present their supervised process state and watchdog soft limits, and no celld version-lifecycle controls exist.

#### Scenario: Administrator opens the system hostname
- **WHEN** an administrator opens `admin.<base>`
- **THEN** the console serves from the celld admin assets with relative resources resolving under that origin

#### Scenario: Administrator opens the path alias
- **WHEN** an administrator opens `<base>/admin/app`
- **THEN** the console serves the same application with assets resolving under the alias base path

#### Scenario: Browser requests an immutable Admin resource
- **WHEN** the browser requests a hashed immutable asset
- **THEN** it is served with its immutable cache semantics and no worker-side asset duplication

#### Scenario: Administrator distinguishes runtime tiers
- **WHEN** an administrator opens the application routes view
- **THEN** each application row and its detail show the runtime kind, and celld entries expose supervision/limit state instead of version lifecycle controls

### Requirement: Admin resource delivery avoids Dispatcher asset duplication
The system SHALL keep Admin static-resource bytes outside the Dispatcher source bundle. The final node image MUST NOT include a generated base64 Admin asset module or a build step that converts the Admin output into JavaScript source.

#### Scenario: Operator inspects the built node image inputs
- **WHEN** an operator reviews the Admin delivery inputs used for a node image build
- **THEN** Admin static resources are supplied as a native static-asset directory and no generated base64 asset module is present

### Requirement: Admin login uses the owner key without browser persistence
The system SHALL require the administrator to enter the bootstrap owner key before showing authenticated administration data. The browser MUST keep that key only in tab-scoped session storage and MUST NOT place it in a URL, browser asset, or durable browser storage.

#### Scenario: New Admin tab opens
- **WHEN** an administrator opens the Admin console without a tab session
- **THEN** the console shows an administrator login view before protected data is fetched

#### Scenario: Administrator completes login
- **WHEN** the administrator supplies a valid owner key
- **THEN** the console creates an authenticated session for that browser tab without persisting the key outside session storage

### Requirement: Workspace and application routing are separate primary views
The system SHALL present workspace file management and application-route management as separate primary Admin views. The workspace view SHALL own file-tree, file-detail, and text-edit operations; the application-route view SHALL own application projections and domain mappings.

#### Scenario: Administrator needs to edit a workspace object
- **WHEN** an authenticated administrator selects a text file in the workspace tree
- **THEN** the Admin console presents the file detail and editing flow without mixing route registration controls into that workspace view

#### Scenario: Administrator needs to inspect routes
- **WHEN** an authenticated administrator opens the application-route view
- **THEN** the Admin console presents applications with their route mappings separately from the file editor

### Requirement: Admin does not gain implicit Kernel authority
The Admin application SHALL call the Kernel only with the owner credential supplied by the administrator. It MUST NOT embed `IWEB_API_TOKEN`, node secrets, or privileged control credentials in the deployed browser assets.

#### Scenario: Browser receives Admin assets
- **WHEN** a visitor downloads the Admin console HTML, JavaScript, CSS, or media
- **THEN** the assets contain no bootstrap owner key or node secret
