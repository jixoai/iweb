<!-- 用户原始需求（2026-08-15）：控制面为自包含静态二进制；行为由跨实现契约向量钉死。 -->

## ADDED Requirements

### Requirement: Control plane ships as a self-contained static binary
The system SHALL deliver the Kernel as a single self-contained binary. The node image MUST NOT carry a general-purpose scripting runtime dedicated to the control plane, and the Kernel MUST keep the permanent `api.<base>` recovery authority independent of celld.

#### Scenario: Image inspection finds no control-plane scripting runtime
- WHEN an operator inspects the node image
- THEN the Kernel is a single static binary and no node/JS runtime is present for control-plane purposes

#### Scenario: Kernel binary reports its identity
- WHEN the Kernel binary is invoked with its version flag
- THEN it reports the version and the recovery authority remains reachable through `api.<base>` with a valid owner key

### Requirement: Kernel implementations are pinned by shared contract vectors
The system SHALL pin Kernel observable behavior with golden contract vectors shared across implementations, covering control request/response shapes, rejection cases, and the canonical package digest; any implementation MUST produce byte-identical digests for the same canonical package content.

#### Scenario: Canonical digest parity across implementations
- WHEN the same canonical package content is digested by any Kernel implementation under test
- THEN the resulting digest equals the golden vector value byte-for-byte
