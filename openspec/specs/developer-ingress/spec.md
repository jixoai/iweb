<!-- 用户原始需求（2026-08-13）：本机通过 Portless 测试远程 iMac 上的 iweb，而不在开发机误跑节点。 -->

## Purpose

定义本地开发机如何通过 Portless 与 SSH loopback 转发验收远程 iMac 节点，同时保持远程节点和本地测试入口的职责清晰。

## Requirements

### Requirement: Remote node remains the execution target
The development workflow SHALL support building and running iweb on a configured remote iMac Docker context while the developer machine supplies only local HTTPS ingress and an SSH loopback forward.

#### Scenario: Developer starts remote Portless workflow
- **WHEN** the developer runs the remote ingress helper with a configured remote node
- **THEN** the helper targets the remote Docker context and forwards a local loopback port to the remote node's Caddy port

### Requirement: Portless registers known nested iweb hosts
The development workflow SHALL register the base host and known nested hosts, including Admin, API, MCP, Admin app, and demonstration app hostnames, to the local forward. Wildcard mode SHALL remain available for future nested app hosts.

#### Scenario: Developer opens a nested Admin hostname
- **WHEN** the local Portless ingress is ready for `test.iweb.localhost`
- **THEN** `admin.test.iweb.localhost` resolves to the same local forward and reaches the remote Caddy instance

### Requirement: Local development ingress verifies nested routing
The helper SHALL not report success until it verifies the base node and required nested application/control hostnames through the local HTTPS ingress.

#### Scenario: Nested ingress is incomplete
- **WHEN** only the base hostname resolves but an Admin or app nested hostname does not reach iweb
- **THEN** the helper reports ingress failure rather than declaring the development environment ready
