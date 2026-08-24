<!-- 用户原始需求（2026-08-24）：共享版本账本族契约（Codex 审稿 R1 阻塞项 2：mini 宣称与 full 同族但无双方可验证契约实体，本 capability 补齐）。 -->

## ADDED Requirements

### Requirement: Shared admission receipt contract
Both products SHALL implement the same two-phase frozen-receipt admission contract over workspace staging: atomic collection, validation, and freezing of the package into an immutable candidate snapshot; a receipt containing the application identity, package digest, manifest digest, precomputed version identity, and the route-registry generation as audit context; and a confirmation step that binds the submitter's receipt ID to that frozen snapshot only. Receipt expiry, snapshot tampering, identity mismatch, or a changed precomputed version SHALL fail closed identically in both products. Product differences are limited to a closed list recorded in the mode matrix: (1) the authority permitted to confirm (full: the owner-authorized publication flow; mini: the bootstrap owner only), (2) the execution topology an admitted version enters (full: an application sandbox; mini: the shared fleet composition flow), and (3) mini's first-admission route-registration precondition, where a receipt for an application with no registered route is refused. Outside this closed list, the wire schema, field semantics, and failure semantics MUST NOT diverge.

#### Scenario: Same receipt flow on both products
- **WHEN** the shared black-box receipt fixture exercises collect-freeze-confirm against an iweb-full and an iweb-mini image
- **THEN** both produce the same receipt fields and the same fail-closed behaviors for expired and tampered receipts, differing only by the mode-matrix closed list: the confirmation authority, the execution topology, and mini's route-registration precondition

#### Scenario: Route precondition differs by product
- **WHEN** the fixture requests a receipt for a new application with no registered route on each product
- **THEN** the iweb-mini image refuses receipt issuance, the iweb-full image proceeds per its own flow, and both behaviors are asserted in the shared suite and recorded in the mode matrix

### Requirement: Version identity is content-addressed per application
Both products SHALL derive version identities content-addressed within the namespace of the application identity: identical content and manifest under different applications yields distinct version records, and an admitted version is immutable after creation.

#### Scenario: Same package admitted under two applications
- **WHEN** the same package digest is admitted under application `alpha` and later under application `beta`
- **THEN** two distinct version records exist, each namespaced to its application

### Requirement: Rejection shapes are shared
Both products SHALL return structured rejection details with the same schema for version-ledger failures: validation errors, unsupported package shapes, unsupported policies, identity mismatches, and stale or expired receipts. A product MAY add product-specific rejection reasons only through the shared contracts vocabulary and the mode matrix.

#### Scenario: Unsupported policy rejection on mini
- **WHEN** an iweb-mini admission rejects a non-empty egress declaration
- **THEN** the rejection uses the shared schema with a product-specific reason code documented in the mode matrix

### Requirement: Shared contract suite runs on both products
A common black-box contract suite SHALL exercise the version-ledger family on both product images in continuous integration, permitting only the authorization and topology differences listed in the mode matrix. Any behavioral divergence in shared fields, failure semantics, or rejection shapes SHALL block release of the affected product.

#### Scenario: Shared field diverges
- **WHEN** the receipt schema or a fail-closed behavior differs between products outside the mode matrix
- **THEN** the release pipeline fails for the diverging product
