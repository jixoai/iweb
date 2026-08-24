<!-- 用户原始需求（2026-08-20，Codex R4）：Portless 远端场景仍指向"remote node's Caddy port"；Caddy 已废除，转发目标是 Kernel 发布端口。 -->

## MODIFIED Requirements

### Requirement: Remote node remains the execution target
The development workflow SHALL support building and running iweb on a configured remote iMac Docker context while the developer machine supplies only local HTTPS ingress and an SSH loopback forward.

#### Scenario: Developer starts remote Portless workflow
- **WHEN** the developer runs the remote ingress helper with a configured remote node
- **THEN** the helper targets the remote Docker context and forwards a local loopback port to the remote node's published Kernel ingress port

### Requirement: Portless registers known nested iweb hosts
The development workflow SHALL register the base host and known nested hosts, including Admin, API, MCP, Admin app, and demonstration app hostnames, to the local forward. Wildcard mode SHALL remain available for future nested app hosts.

#### Scenario: Developer opens a nested Admin hostname
- **WHEN** the local Portless ingress is ready for `test.iweb.localhost`
- **THEN** `admin.test.iweb.localhost` resolves to the same local forward and reaches the remote Kernel ingress
