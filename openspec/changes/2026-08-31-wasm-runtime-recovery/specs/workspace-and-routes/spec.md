## MODIFIED Requirements

### Requirement: Application hostname registration is explicit
Every application host SHALL be an explicit route-registry entry. User-managed routes (`system:false`) target the wasm tier: their dispatch resolves the application's wasm v2 active pointer. `celld-app` targets exist only on system/image-seeded routes (`system:true`); the registration surface rejects a user route that names a `celld-app` target with bounded guidance. Route registration never confers admission.

The Kernel route registry file on the persistent volume is the single write authority for routes and SHALL survive node restarts and container recreation. Node startup MUST NOT overwrite it wholesale: when the registry file exists, the image seed is applied only as a system-route upsert keyed by `hostId` (seed rows with `system:true` may add or update their own host IDs), user routes (`system:false`) are never deleted or overwritten, and a seed row colliding with an existing user route is dropped with an owner-visible log line. Only when the registry file does not exist (first boot) is the seed loaded wholesale. When the registry file already exists, an unparseable seed is skipped with an owner-visible log (never a panic, never a partial apply). A missing registry file with no seed, or a missing registry file whose seed exists but is unparseable, is a fail-closed startup error, because a node booting without any valid system route is not a legal steady state. A user route registered through the control surface remains registered across restarts with no re-registration.

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

#### Scenario: Node restarts after a user route was registered
- **WHEN** the container is recreated after `iweb_domain_register` created a user route
- **THEN** the user route is still registered and serving after boot, without re-registration

#### Scenario: Image upgrade adds a new system route
- **WHEN** a newer node image seeds a system route for a host ID that no existing route uses
- **THEN** startup upserts exactly that system route and leaves every user route untouched

#### Scenario: Seed system route collides with a user route
- **WHEN** the image seed contains a `system:true` row whose `hostId` is already a user route
- **THEN** the seed row is dropped with an owner-visible log line and the user route is preserved unchanged

#### Scenario: First boot finds an unparseable seed
- **WHEN** the registry file does not exist and the seed file exists but cannot be parsed
- **THEN** startup fails closed with an owner-visible error, because booting with no valid system route is not a legal steady state

#### Scenario: Parseable seed carries no system routes
- **WHEN** the registry file does not exist and the seed parses but contains no `system:true` rows
- **THEN** startup fails closed the same way; a parseable-but-systemless seed is not a legal first boot either
