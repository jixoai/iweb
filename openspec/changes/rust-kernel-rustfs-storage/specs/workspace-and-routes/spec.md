<!-- 用户原始需求（2026-08-15）：统一工作区不变，存储后端由 MinIO 换 RustFS。 -->

## MODIFIED Requirements

### Requirement: One unified workspace
The system SHALL store ordinary files, application manifests, and application assets in one RustFS-backed `iweb-workspace` root. It MUST NOT introduce a product-level public/private bucket split. This logical owner view is available only through owner-authorized control operations; application sandboxes MUST NOT receive workspace-wide credentials or direct workspace-wide access.

#### Scenario: Operator lists workspace content
- WHEN an authorized caller lists the workspace
- THEN ordinary files and application directories are visible in one logical root

#### Scenario: Application attempts workspace-wide access
- WHEN application code attempts to list or read objects outside its admitted package and application-scoped storage
- THEN access is denied without exposing workspace-wide credentials
