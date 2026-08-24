<!-- 用户原始需求（2026-08-24）：mini 准入法立法（grilling Q1/Q2/Q15–Q17/Q22–Q25 准入相关部分）。 -->
<!-- Codex 审稿 R1：路由顺序矛盾修正（新应用准入需先有注册路由）；委托禁权落为可测试 denylist；亲证诚实条款与 co-trust 披露升为 requirement。 -->

## ADDED Requirements

### Requirement: Admission authority is the bootstrap owner only
The iweb-mini system SHALL make the bootstrap owner key the only authority that can turn workspace content into executable code. Delegated keys MUST NOT obtain admission authority: the scope vocabulary is defined in the shared contracts with one grammar for both products, and the set of scopes issuable on an iweb-mini node is exactly `{workspace}`. Requests to admission authority without credentials SHALL receive 401; delegated keys SHALL receive 403. The mini MCP server SHALL expose only workspace and read-only projection tools in its tool list regardless of the caller's identity; application lifecycle tools SHALL NOT appear.

#### Scenario: Delegated key attempts admission
- **WHEN** an `iwb_*` delegated key calls the admission confirmation operation
- **THEN** the operation returns 403 and no version is created, and the entry is absent from delegated Admin and MCP views rather than rendered-then-rejected

#### Scenario: Owner automates via MCP
- **WHEN** the bootstrap owner connects to the mini MCP server
- **THEN** the tool list contains workspace and read-only projection tools only, because executable-ization through MCP does not exist in this product; owner automation uses the `api.<base>` API directly

### Requirement: Delegated keys are workspace-only by testable denial
On an iweb-mini node, a valid delegated key SHALL succeed only at workspace create, read, update, and delete and at read-only projections (routes, version ledger, composition, node status). For every other control operation — route creation, modification, deletion, or enablement; receipt issuance and confirmation; admission; composition submit, activate, or rollback; snapshot creation or restore; key management; and audit export — a delegated key SHALL receive 403 and an unauthenticated caller SHALL receive 401, verified per operation class in the mode matrix. Bootstrap-owner-only entries SHALL NOT be rendered for delegated identities in Admin or MCP surfaces.

#### Scenario: Delegated key attempts audit export
- **WHEN** a valid `iwb_*` key calls the audit export operation
- **THEN** the response is 403, and the operation requires the bootstrap owner key

#### Scenario: Delegated key attempts route mutation
- **WHEN** a valid `iwb_*` key calls route registration, deletion, or enable state changes
- **THEN** the response is 403 and no route registry record changes

### Requirement: Frozen receipt two-phase admission
Admission SHALL proceed through the shared version-ledger contract: the Kernel freezes the package and issues the receipt, the Admin displays it, and the bootstrap owner confirms the receipt ID, after which the Kernel executes admission only against that frozen snapshot. The mini differences from iweb-full are exactly the mode-matrix closed list: authorization (bootstrap attestation), execution topology (shared fleet), and the first-admission route-registration precondition — never a forked protocol.

#### Scenario: Workspace changes after receipt
- **WHEN** staging files change after receipt issuance but before confirmation
- **THEN** admission still executes against the frozen snapshot and the later workspace writes have no effect on the admitted version

#### Scenario: Owner confirms an expired receipt
- **WHEN** the bootstrap owner submits a receipt ID past its expiry
- **THEN** the confirmation fails closed and instructs re-staging

### Requirement: Attestation semantics are honest
Admission confirmation SHALL be specified as proof of bootstrap-key possession only: the API MUST NOT be described as proving a human click or human review. The Admin attestation checkbox is a UX confirmation ritual, not a security claim, and this distinction SHALL be carried in the requirement text, the Admin interface copy, and the product documentation.

#### Scenario: Documentation overstates attestation
- **WHEN** mini documentation or Admin copy claims the API proves human approval
- **THEN** the text is corrected to key-possession semantics before release

### Requirement: Co-trust and compromise disclosures
The mini admission interface and product documentation SHALL disclose, before confirmation: that admitted applications join the shared fleet and share execution, state, and availability fate with the control-plane applications (co-trust); that a compromised fleet can tamper with fleet-served Admin assets and capture credentials entered into them, while `api.<base>` guarantees recovery availability, not credential secrecy in that scenario; and that this product does not host untrusted applications — the answer for untrusted code is the full product.

#### Scenario: Admission summary shows disclosures
- **WHEN** the owner opens the attestation confirmation step
- **THEN** the co-trust, credential-capture, and use-full-instead disclosures are visible alongside the package summary before the confirmation control is enabled

### Requirement: Strict identity binding
The admission request's application identity SHALL equal the package manifest name exactly; any mismatch SHALL reject without creating a version. Protected system applications (admin, mcp) SHALL NOT be replaceable through attested admission — their update authority is the iweb-mini image release itself. Running the same code as another application SHALL require re-staging and re-admission under the new identity.

#### Scenario: Package targets a protected application
- **WHEN** an attested admission targets application `admin`
- **THEN** it is rejected and the control-plane application continues to track the image release

### Requirement: Hosts derive from the route registry with registration preceding first admission
The admission manifest SHALL NOT carry host identifiers. The admission summary SHALL present two clearly separated sections: package content (manifest fields) and the application's registered hosts, derived live from the Kernel route registry and labeled as such. Admission MUST NOT create, modify, or implicitly enable any route. The fixed sequence for a new application is: explicit owner route registration, then owner-attested admission, then composition inclusion; a receipt for an application with no registered route SHALL be refused. For an already-routed application, later version admissions do not touch routes. Domain registration alone never serves traffic. A package author's hostname intent MAY live in ordinary workspace documentation files and carries no authority.

#### Scenario: New application skips route registration
- **WHEN** the owner requests a receipt for an application identity with no registered route
- **THEN** receipt issuance is refused with guidance to register the route first

#### Scenario: Owner registers the route before first admission
- **WHEN** the bootstrap owner registers a user application route for a not-yet-admitted application and then requests the receipt
- **THEN** the registry persists the mapping without any publication occurring, MCP offers no registration tool for the step, and receipt issuance proceeds for the owner's attestation

#### Scenario: Version update for a routed application
- **WHEN** the owner admits a new version of an application that already has registered routes
- **THEN** admission proceeds without any route registry change, and traffic moves only when a composition including the new version activates

### Requirement: Self-contained package shape
An admitted package SHALL be a celld-project-shaped, fully self-contained bundle (ESM/TS sources, static assets, declarative binding configuration) deployable by the image-pinned celld runtime with fixed parameters. The node MUST NOT execute package-carried build or install instructions: no package scripts, package-manager installs, build tools, shell commands, compiler plugins, package-specified images or commands, and no deploy-time network dependency resolution. All runtime dependencies MUST be inside the frozen package; bare modules, remote imports, runtime code downloads, and arbitrary Worker Loader entrypoints are unsupported. The only permitted transformation is the image-pinned celld pipeline; unsupported package shapes SHALL be rejected at freeze or admission, never deployed to discover failure.

#### Scenario: Package declares an install step
- **WHEN** a staged package requires an install or build command to become runnable
- **THEN** receipt issuance rejects it as an unsupported shape, and no code executes

### Requirement: Egress declarations are rejected
Admission SHALL reject any non-empty `manifest.egress.allow` with a structured `unsupported-policy` error that identifies external egress as an iweb-full capability. Factory forms of built-in applications SHALL obey the same limitation. Kernel-driven operations for updates, snapshots, and object storage are not application egress.

#### Scenario: App declares third-party API access
- **WHEN** a staged package declares egress to a third-party API
- **THEN** admission rejects it with `unsupported-policy`, and the error names the full product as the supported path

### Requirement: Resource and storage fields are review metadata
Manifest resource and storage fields SHALL enter the frozen receipt, admission ledger, and Admin summary as owner-review metadata labeled as declared-but-not-enforced in this product. The system MUST NOT present them as per-application limits, reservations, or quotas; MUST NOT derive per-application usage from them; and MUST NOT promise terminating only that application on overrun. The only enforceable resource boundaries are composition/fleet-level: deployment resources, the whole-node memory envelope, and whole-fleet restart. An optional container-level memory cap MAY be configured as deployment hardening with fleet-wide kill semantics and is not a product contract.

#### Scenario: Admin displays declared memory
- **WHEN** the admission summary shows a declared memory value
- **THEN** it is labeled as a package declaration that mini does not enforce, beside fleet-level resource facts

### Requirement: Workspace staging remains ordinary files
Workspace-scope delegated keys SHALL be able to list, read, write, and delete workspace objects. Workspace writes MUST NOT execute code or change any admitted version, composition, or route. The delegation's inherent risks (including file deletion by a rogue agent) are accepted and mitigated by revocation and audit, without secondary permission theater.

#### Scenario: Agent stages a candidate package
- **WHEN** a delegated key writes a candidate package into workspace staging
- **THEN** the files persist as ordinary objects and nothing becomes executable until the bootstrap owner confirms a frozen receipt
