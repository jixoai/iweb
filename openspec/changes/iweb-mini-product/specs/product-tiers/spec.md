<!-- 用户原始需求（2026-08-24）：iweb-mini 独立产品线立法（grilling Q7/Q8/Q10–Q14/Q22 拓扑与治理部分）。 -->
<!-- Codex 审稿 R1：阅读规则改为「双产品适用 + 显式替换清单」；latest 全禁；迁移补 ledger 驱动预暂存与 DNS 切换；无出口拓扑升为发布阻断。 -->

## ADDED Requirements

### Requirement: Two product builds from one source
The system SHALL be built from one source tree into two mutually exclusive product kernels, `iweb-full` and `iweb-mini`, selected by compile-time product features where enabling neither or both fails the build. Product mode SHALL be established by the image build artifact, remain immutable for the container lifetime, and MUST NOT be switchable by environment variable or any runtime control. The Kernel SHALL fail closed at startup when the product mode is missing or inconsistent with the image's product descriptor, and SHALL project the mode read-only through the owner status API.

#### Scenario: Mini binary lacks full-only routes
- **WHEN** any caller requests a full-only application runtime endpoint (per-application prepare/readiness/activate/rollback/start/stop, sandbox inspect or delete, sandbox recovery) on an iweb-mini node
- **THEN** the response is the Kernel's generic unknown-route 404 regardless of caller identity or credentials

#### Scenario: Mode descriptor mismatch
- **WHEN** a Kernel binary starts with a product descriptor that does not match its compiled product mode
- **THEN** startup fails closed with a deployment error instead of serving any route

### Requirement: Spec capabilities apply to both products with an explicit requirement-level replacement map
Every OpenSpec requirement SHALL apply to both products as written, except where the `mini-*` capabilities explicitly replace it for iweb-mini. The authoritative replacement map SHALL be stated at requirement granularity in this capability — mixed capabilities MUST NOT be classified wholesale — and the mode matrix SHALL verify the map against running binaries. Full-product specifications MUST NOT gain mini-exception clauses. This `product-tiers` capability and the `version-ledger` capability are shared law. The map below is stated against the spec baseline after the `typescript-monorepo` change archives; requirement renames there are tracked by that change:

- `kernel-control-plane`: `API hostname is permanently Kernel-owned`, `Owner credential protects control operations`, `System routes are protected`, and `Kernel supports bounded workspace control` are shared; `Kernel retains an administration recovery action` is shared with its sandbox-record reconciliation clause replaced for mini by composition and ledger reconciliation per `mini-recovery`; `Kernel owns application versions and active routing state` is shared except that the per-application active-version pointer clause is replaced for mini by the composition pointer per `mini-fleet-composition`; `Kernel controls sandbox lifecycle without joining the sandbox` is full-only, replaced for mini by the composition deploy transaction and snapshot recovery law in `mini-fleet-composition` and `mini-recovery`.
- `owner-key-management` (in-flight when this change was drafted; archived before this change applies): key identity, lifecycle, revocation, expiry, persistence, audit attribution, and secret-handling requirements are shared; its delegated-keys-carry-the-same-unsplit-owner-authority requirement is full-only, replaced for mini by the workspace-only delegation law in `mini-admission` — a mini delegated key holds exactly the `workspace` scope and never admission, route, composition, snapshot, key-management, or audit-export authority.
- `workspace-and-routes`: the unified-workspace, alias-identity, and writes-do-not-publish requirements are shared; `Application hostname registration is explicit` is shared with its ready-active-sandbox-version delivery clause replaced for mini by composition-inclusion delivery per `mini-fleet-composition`, and mini restricts registration authority to the bootstrap owner per `mini-admission`; `Application persistent storage is sandbox-scoped` is full-only, replaced for mini by the fleet-bucket storage and review-metadata law in `mini-admission` and `mini-fleet-composition`.
- `node-boundary`: `Internal operator listener remains isolated` is shared; `Application sandboxes cannot reach internal node authority` is full-only, replaced for mini by `Fleet shares fate, not credentials` in `mini-fleet-composition`; `Caddy is the only published ingress` and `Node services have distinct responsibilities` describe the full topology and are replaced for mini by the mini listener-boundary and topology requirements in `mini-fleet-composition`; `Transitional runtime does not execute arbitrary packages` is replaced for mini by the owner-attested admission law in `mini-admission`.
- `mcp-control`: `MCP endpoint requires owner authorization` and `MCP forwards no stored credential` are shared; `MCP exposes bounded workspace tools` is shared; `MCP exposes route inspection and registration tools` is replaced for mini by an inspection-only projection with no registration tool, per `mini-admission`; `MCP exposes application validation and publication tools` and `MCP exposes sandbox lifecycle and rollback tools` are full-only and absent from mini.
- `runtime-observability`: `Owner status reports node memory envelope`, `Overview uses a ticketed WebSocket session`, and `Observability is process-lifecycle scoped` are shared; `Monitor snapshot includes node and application projections` is shared except that sandbox-lifecycle and per-application CPU/memory projection fields are replaced for mini by `Monitoring without per-application attribution` in `mini-fleet-composition`; `Per-application resources use sandbox accounting` and `Sandbox failures are visible only to authorized monitoring` are full-only, replaced the same way; `Admin presents node and application memory as different resource scopes` is shared in principle with its application-row presentation replaced by the mini monitoring and Admin requirements in `mini-fleet-composition`.
- `managed-applications`: `Application availability does not expose runtime internals`, `Unknown application host is rejected`, and `System surfaces remain visible in current projections` are shared; `Notes demonstrates a normal application response` and `Dispatcher is the image-seeded prototype entrypoint` are full-only, replaced for mini by the composition membership and factory composition law in `mini-fleet-composition`.
- `administration-console`: `Admin console application reachability`, `Admin resource delivery avoids Dispatcher asset duplication`, and `Admin does not gain implicit Kernel authority` are shared; `Admin login uses the owner key without browser persistence` is shared, with mini delegated logins rendering only workspace and read-only surfaces per `mini-admission`; `Workspace and application routing are separate primary views` is full-only, replaced for mini by `Mini Admin information architecture` in `mini-fleet-composition`.
- `developer-ingress`: all requirements are shared development-tooling law.
- `application-sandbox` and the sandbox lifecycle requirements of `managed-applications` are full-only and replaced wholesale for mini by the `mini-*` capabilities; mini has no application sandboxes.

#### Scenario: Reader resolves a lifecycle requirement for mini
- **WHEN** a reader needs the MCP toolset contract for an iweb-mini node
- **THEN** `mcp-control` authentication requirements apply unchanged, route inspection remains with registration absent, lifecycle and publication tools are absent per the map, and the mode matrix lists each replacement

#### Scenario: Shared ingress law binds mini
- **WHEN** an iweb-mini node receives a request for an unknown host, or a request for `api.<base>` influenced by any manifest or composition entry
- **THEN** the shared `developer-ingress` and `kernel-control-plane` behavior applies: unknown hosts are 404, and `api.<base>` remains Kernel-owned regardless of composition content

### Requirement: Shared-core behavioral identity beyond the ledger
The shared control core — authentication and actor attribution, workspace gateway, route registry, system-route protection, owner status projection, and audit attribution — SHALL behave identically across both product binaries for identical authorized inputs. The common black-box contract suite SHALL exercise these surfaces on both product images, not only the version-ledger family, and any divergence outside the mode matrix SHALL block release.

#### Scenario: Workspace gateway behaves identically
- **WHEN** the same authorized workspace read and write fixture runs against an iweb-full and an iweb-mini image
- **THEN** both return the same results, errors, and audit attribution, with no product-specific divergence outside the mode matrix

### Requirement: Mode matrix is a release-blocking artifact
The system SHALL maintain a mode matrix derived from the shared contracts enumerating, for every Kernel API endpoint, MCP tool, and Admin operation: availability per product, required authorization identity, 401/403 semantics for existing-but-protected operations, 404-absent semantics for operations not compiled into the product, the audit event emitted, and the requirement-replacement map between full law and mini law. Continuous integration SHALL verify the mini absent cells and the replacement map against running binaries and SHALL block release on any mismatch between matrix and behavior.

#### Scenario: Matrix claims an absent endpoint that exists
- **WHEN** the mode matrix marks an endpoint 404-absent for mini but the mini binary answers anything other than the generic unknown-route 404
- **THEN** the release pipeline fails

### Requirement: Separate release identities per product
The system SHALL publish iweb-full and iweb-mini as separate OCI repositories that each accept only their own `vX.Y.Z` tags and digests, with independent git tag lines `full-v*` and `mini-v*`, no shared incrementing version, and no `latest` or other moving alias published or moved in either repository in v1; any future alias requires an owner-approved spec change. Every release manifest and the owner status API SHALL record the product slug, product version, Kernel digest, Admin bundle digest, celld digest, and contracts revision. The historical `iweb` image name and tags SHALL NOT be redirected to iweb-full.

#### Scenario: Product-aware upgrade entrypoint refuses a wrong-product image
- **WHEN** an operator's deployment or upgrade entrypoint for an iweb-mini node is given an iweb-full image reference
- **THEN** the entrypoint refuses to replace the running container before any change, because it validates the expected product slug and repository; the dual repositories eliminate reference ambiguity in tooling and documentation, and this is stated honestly — a raw `docker pull` of any public image is not and cannot be prevented at the registry layer

#### Scenario: Release pipeline attempts to move a latest tag
- **WHEN** any automated stage of the release pipeline would publish or move a `latest` alias in either repository
- **THEN** the pipeline rejects the operation as a policy violation

### Requirement: Two-phase release approval
The release pipeline SHALL publish immutable candidate digests with evidence (shared contract suite results, product mode matrix results, dual-architecture builds, identity collection, SBOM and provenance) and SHALL NOT mark any official product version — including patch versions — without explicit owner approval. The whole-node RssAnon release gate SHALL execute on real arm64 and amd64 nodes (self-hosted runners or owner-executed acceptance producing the same evidence artifact format), never mocked or single-architecture substituted.

#### Scenario: Candidate promoted without approval
- **WHEN** a candidate digest passes all CI checks
- **THEN** it remains an unlabeled candidate until an explicit owner approval marks the version tag

### Requirement: Mini baseline memory envelope
An iweb-mini release SHALL pass a memory gate measured on the factory composition — the fixed built-in application set at a fixed image digest, after cold start and a settled idle window — where the sum of per-process RssAnon for the whole node is at or below 160 MiB on both arm64 and amd64. A missing measurement SHALL fail the gate and MUST NOT be substituted with zero. If the measured floor on either architecture exceeds the target, the gate number MAY only change after explicit owner re-approval; it MUST NOT be silently loosened, and features MUST NOT be cut to pass the gate. Owner-attested applications added after factory are outside this gate; the Admin node totals SHALL reflect their growth honestly. Full-product comparisons are descriptive deltas recorded under identical method only.

#### Scenario: Architecture measurement missing
- **WHEN** a mini release candidate has an arm64 but no amd64 RssAnon measurement
- **THEN** the release gate fails

### Requirement: Mini external egress is physically absent
The iweb-mini deployment topology SHALL default to a network with no external egress for the node container (internal services on loopback only), making the absence of application egress an enforced fact rather than an undeclared permission. A mini release whose default topology lacks this property SHALL NOT ship: the no-egress default is a release blocker, established before any admission or fleet execution capability is enabled on the node. Image-level updates occur host-side and are not application egress. When an operator overrides this topology, the admission summary and product documentation SHALL state the degradation honestly: admitted applications then share the fleet process's raw network capability, which the manifest never controls.

#### Scenario: Factory topology
- **WHEN** an iweb-mini node runs the default compose topology
- **THEN** no process inside the node container can reach the public internet, while loopback object storage and Kernel control remain reachable

#### Scenario: Topology missing at release
- **WHEN** a mini image's default compose topology permits external egress
- **THEN** the release is blocked before any application can be admitted on shipped nodes

### Requirement: Mini to full is a parallel-node migration
The system SHALL define upgrading from iweb-mini to iweb-full as standing up a separate full node alongside the mini node, not an in-place image swap. The migration SHALL require: full-node sandbox preflight; workspace copied as ordinary owner files; a migration archive containing the mini admission ledger, composition history as read-only audit evidence, and verifiable immutable package snapshots for every ledger entry; a full-side migration wizard that processes only owner-attested non-control-plane applications — the `admin` and `mcp` control-plane applications are never re-admitted and are restored by the full image itself — verifies each archived package snapshot against the ledger's recorded package digest before pre-staging it into the full node's workspace, refusing missing or digest-mismatched packages with guidance for the owner to supply fresh packages, and never imports mini control state or activates anything automatically; rotation of the bootstrap token and revocation of all delegated keys; and state transfer only through application-specific verifiable export/import adapters (none shipped in v1). The migration completes only when the owner verifies application readiness on the full node and switches DNS or hostname routing to it; the mini node remains available as an archive until the owner decommissions it. Downgrading full to mini in place SHALL NOT be offered.

#### Scenario: Migration archive package no longer matches the ledger
- **WHEN** the wizard finds a package snapshot whose digest differs from the ledger's recorded package digest, or a ledger entry with no archived snapshot
- **THEN** that application is refused from pre-staging with a clear reason, other applications continue, and the owner is guided to supply a fresh package

#### Scenario: Migration does not carry control state
- **WHEN** an owner completes the mini-to-full migration
- **THEN** the full node's active control state consists of the `admin` and `mcp` control-plane applications restored by the full image itself plus owner-re-admitted non-control-plane applications and freshly issued credentials, with no mini control state imported, while the mini archive remains readable

#### Scenario: Wizard pre-stages but does not activate
- **WHEN** the full-side migration wizard processes the mini ledger
- **THEN** every listed owner-attested non-control-plane application appears as a workspace-staged candidate requiring explicit owner re-admission, `admin` and `mcp` are absent from the candidate list because they come with the full image, and none receives routes or traffic automatically

### Requirement: No preview or canary in v1 products
Neither product SHALL offer real-traffic preview, canary, or per-application traffic splitting in v1. Candidate validation in mini SHALL be named and presented as a pre-check (code-level readiness on a zero-state candidate) and MUST NOT be described as a preview. Historical versions SHALL be selectable into the next composition but not individually previewed or hot-switched.

#### Scenario: Terminology drift in user-facing text
- **WHEN** Admin UI, MCP tool descriptions, or documentation describe mini candidate validation
- **THEN** they use pre-check wording and do not promise real-state preview availability
