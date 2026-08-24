## Purpose

为个人节点提供 GitHub PAT 风格的多把 owner key，使部署 Agent 可以被独立分发、吊销和审计，同时保留不依赖 Admin/MCP 的 bootstrap 恢复凭据。

## ADDED Requirements

### Requirement: Owner keys have a bounded, non-secret wire format
The system SHALL issue delegated owner keys in the form `iwb_<keyId>_<secret>`, where `keyId` is exactly eight lowercase hexadecimal characters generated from a cryptographically secure random source and `secret` is exactly 32 random bytes encoded as unpadded base64url. The persisted `secretHash` SHALL be the lowercase hexadecimal SHA-256 digest of the secret. The bootstrap credential from `IWEB_API_TOKEN` is an opaque configuration value and is not required to use this format.

#### Scenario: Kernel creates a delegated key
- **WHEN** an authenticated owner submits `POST /v1/keys` with a valid label and optional absolute UTC `expiresAt`
- **THEN** Kernel returns HTTP 201 with the complete key exactly once, returns no secret hash, and does not include the key in a URL, log, workspace object, application package, or browser asset

#### Scenario: Invalid key creation input is rejected
- **WHEN** a caller submits a control character, a label larger than 128 UTF-8 bytes, a non-UTC or non-RFC3339 `expiresAt`, or a past `expiresAt`
- **THEN** Kernel returns HTTP 400 without writing a key record or an audit success event

#### Scenario: Key identifiers collide during creation
- **WHEN** random generation produces an already-recorded `keyId`
- **THEN** Kernel retries under the key-store writer lock and never overwrites the existing record

### Requirement: Bootstrap and delegated keys share owner authority with independent state
The system SHALL authorize the bootstrap `IWEB_API_TOKEN` and every delegated key with the same owner capability set. A delegated key SHALL authorize a request only while its record is neither banned nor expired at the Kernel's current UTC time. Bootstrap SHALL always authorize and SHALL NOT be represented by a revocable secret record.

#### Scenario: Bootstrap remains available when the delegated key store is damaged
- **WHEN** `/data/kernel/keys.json` is missing or fails schema, permission, or integrity validation and a caller presents `IWEB_API_TOKEN`
- **THEN** the caller can still reach authenticated Kernel recovery and status operations, delegated credentials are rejected, and Kernel does not reset or replace the damaged file automatically

#### Scenario: An expired or banned key is used
- **WHEN** a caller presents a delegated key whose `expiresAt` is at or before now, or whose `bannedAt` is set
- **THEN** Kernel returns the same HTTP 401 invalid-owner-key response used for an unknown key and performs no control-plane mutation

#### Scenario: Authorization comparison is not secret-length dependent
- **WHEN** Kernel evaluates a bearer value
- **THEN** it compares fixed-length digests in constant-time, does not short-circuit on a secret mismatch, and never reveals whether a key identifier exists through the error body

### Requirement: Kernel exposes owner-key lifecycle and audit APIs
The system SHALL expose owner-authorized `GET /v1/keys`, `POST /v1/keys`, `DELETE /v1/keys/{keyId}`, and `GET /v1/audit`. `GET /v1/keys` SHALL return `{ "keys": [...] }` containing metadata only, including a synthetic `bootstrap` entry marked non-revocable; delegated status is one of `active`, `expired`, or `banned`. `POST /v1/keys` SHALL accept `{ "label": string, "expiresAt": string|null }` and return HTTP 201 with `{ "token": string, "key": metadata }`; the token is returned once and never from a later read. `DELETE` SHALL be irreversible for delegated keys; and `GET /v1/audit` SHALL support an optional `keyId` filter and a bounded `limit` whose default is 50 and maximum is 200, returning `{ "events": [...], "dropped": <count> }` newest-first, where `dropped` counts corrupt lines skipped during the read (corruption signaling).

#### Scenario: Owner lists key metadata
- **WHEN** an authenticated owner requests `GET /v1/keys`
- **THEN** the response lists bootstrap and delegated key metadata (`keyId`, `label`, `createdAt`, `expiresAt`, `bannedAt`, status, and revocability) without any secret or hash

#### Scenario: Owner bans a delegated key
- **WHEN** an authenticated owner sends `DELETE /v1/keys/{keyId}` for a known delegated key
- **THEN** Kernel serializes the ban, records `bannedAt`, makes subsequent requests with that key fail with HTTP 401, and returns HTTP 204; repeating the delete is idempotent

#### Scenario: Bootstrap cannot be banned
- **WHEN** an authenticated owner sends `DELETE /v1/keys/bootstrap`
- **THEN** Kernel returns HTTP 409 with a stable immutable-bootstrap error and leaves the bootstrap credential valid

#### Scenario: Owner reads recent audit events
- **WHEN** an authenticated owner requests `GET /v1/audit?keyId=<id>&limit=20`
- **THEN** Kernel returns at most 20 newest events for that actor, with no bearer value, secret hash, query value, or workspace content

### Requirement: Owner-key state and audit evidence are durable, bounded, and fail-closed
The system SHALL keep the versioned key snapshot at `/data/kernel/keys.json` and the append-only audit stream at `/data/kernel/audit.log` (with rotated siblings) outside application lifecycle state. Key records SHALL contain only `keyId`, `secretHash`, `label`, `createdAt`, optional `expiresAt`, and optional `bannedAt`; the snapshot and audit directory SHALL be owner-readable only. The audit stream SHALL retain no more than 4 MiB across the active file and three 1 MiB rotated segments, and SHALL discard the oldest segment only at rotation. Key mutations SHALL not be reported successful unless the key snapshot and their durable audit commit complete; a storage failure SHALL return a bounded 503 and SHALL not silently reset or partially apply state.

#### Scenario: Concurrent key mutations are serialized
- **WHEN** two authenticated callers create or ban keys concurrently
- **THEN** Kernel produces one ordered, valid snapshot with no lost update, duplicate identifier, or partial JSON file, and audit events preserve that order

#### Scenario: Kernel restarts after an interrupted key mutation
- **WHEN** the process stops between an audit intent and a snapshot write, or between a snapshot write and its audit commit
- **THEN** startup reconciliation leaves either the prior state or the fully committed state, marks any incomplete audit intent as aborted, and never authorizes a half-written record

#### Scenario: Audit storage reaches its bound
- **WHEN** appending an event would exceed the active segment or the four-segment total
- **THEN** Kernel rotates complete append-only segments, removes only the oldest segment, and continues serving `GET /v1/audit` over the retained newest events

#### Scenario: Key storage cannot be durably written
- **WHEN** a key create or ban cannot atomically persist the snapshot and its audit commit
- **THEN** Kernel returns HTTP 503, leaves the durable key state unchanged, and keeps the bootstrap recovery route available

### Requirement: Audit events identify the authenticated actor without carrying credentials
The system SHALL emit bounded audit events for authenticated Kernel control operations, key lifecycle operations, monitor ticket/connection lifecycle, and rejected bearer attempts. Each event SHALL contain UTC `ts`, `keyId` (`bootstrap`, a delegated identifier, or null for an unattributed attempt), `action`, HTTP `method`, normalized path without query values, and HTTP `status`. Audit recording SHALL not include the `Authorization` header, monitor ticket, request body, label, or arbitrary client-supplied actor identity.

#### Scenario: A delegated MCP request is audited
- **WHEN** a valid delegated key invokes an MCP JSON-RPC operation that calls Kernel
- **THEN** the resulting Kernel control operation is attributed to that delegated `keyId` using the bearer credential actually received by Kernel

#### Scenario: A malformed or revoked bearer is rejected
- **WHEN** a caller sends a malformed, unknown, expired, or banned bearer to an authenticated endpoint
- **THEN** Kernel returns HTTP 401 and records a bounded unattributed or known-key rejection event without storing the bearer value

### Requirement: Revocation applies to new work and long-lived monitor sessions
The system SHALL re-evaluate delegated-key state for every HTTP control request and every MCP JSON-RPC request. A ban SHALL close monitor WebSocket sessions and invalidate unconsumed monitor tickets that were issued for that key; an already-running ordinary HTTP or MCP operation MAY finish, but no later operation using the key may begin.

#### Scenario: Ban closes a delegated monitor stream
- **WHEN** an owner bans a key that owns an active monitor WebSocket
- **THEN** Kernel closes that stream with a policy-revocation close and rejects any later ticket or control request for the key

#### Scenario: Ban races an in-flight request
- **WHEN** a delegated request has passed authorization before another owner bans its key
- **THEN** the in-flight request either completes with its already-selected result or fails boundedly, while the next request is rejected with HTTP 401

### Requirement: Node backup and recovery preserve delegated-key state without copying bootstrap secrets
The system SHALL include `keys.json` and all retained audit segments in a quiesced node backup and restore them as one Kernel-state set. Backups, restore logs, tests, and handoff material MUST NOT contain the plaintext `IWEB_API_TOKEN` or any newly-issued delegated key.

#### Scenario: Owner restores a node from a quiesced backup
- **WHEN** the node is stopped or quiesced before restoring Kernel state
- **THEN** delegated key metadata, bans, expirations, and retained audit events are restored consistently while the bootstrap credential continues to come only from node configuration
