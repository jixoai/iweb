## MODIFIED Requirements

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
