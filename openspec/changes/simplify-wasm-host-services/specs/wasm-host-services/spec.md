## Purpose

定义 wasm 宿主服务（KV/SQL/Logging）的单版本形态。

## ADDED Requirements

### Requirement: Host services are single-version
The system SHALL provide host services (KV, SQL, Logging) only on the `iweb-wasmd-abi@1.1.0` runtime. Applications targeting the ABI 1.0.0 runtime SHALL NOT receive host services. All wire types SHALL have exactly one form—no version unions.

#### Scenario: V1 application requests host services
- **WHEN** an application on ABI 1.0.0 imports iweb:kv, iweb:sql, or iweb:logging
- **THEN** admission rejects the imports as outside the capability matrix

#### Scenario: V2 application uses all three services
- **WHEN** an application on ABI 1.1.0 imports all three host services
- **THEN** the services are available with policy-enforced quotas and identity binding
