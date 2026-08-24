<!-- 用户原始需求（2026-08-20，Codex R4）：归档合并后主 specs 仍写"Caddy and Kernel accept"，与 Kernel-only ingress 冲突；本 delta 收敛入口为 Kernel。 -->

## MODIFIED Requirements

### Requirement: Dispatcher is the image-seeded prototype entrypoint
The system SHALL restrict the shared celld Dispatcher to trusted image-seeded control-plane handlers retained during migration. It MUST NOT load, execute, or route a user application package; registered user application traffic SHALL target that application's active sandbox version. Ingress hostnames are accepted by the Kernel ingress directly; Caddy is retired from the node image.

#### Scenario: Registered image-seeded handler reaches Dispatcher
- **WHEN** the Kernel ingress accepts a registered hostname for an image-seeded handler
- **THEN** celld receives the request through the transitional node Dispatcher

#### Scenario: Registered user application receives traffic
- **WHEN** the Kernel ingress accepts a request for a registered user application with an active sandbox version
- **THEN** the request reaches that application's sandbox without executing in the shared Dispatcher
