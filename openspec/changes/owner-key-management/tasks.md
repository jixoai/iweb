## 1. Contract and fixtures

- [x] 1.1 wire schemas/golden vectors → Admin strict contracts（keyMetadata/issuance/auditEvent 语义校验）+ 黑盒 31 断言 —Add owner-key wire schemas and golden vectors for token parsing, metadata redaction, status derivation, absolute expiry, uniform 401, audit event shape, and bounded query validation.
- [ ] 1.2 Add crash-point fixtures for `keys.pending` before/after audit intent, snapshot rename, audit commit, and startup reconciliation; include corrupt, missing, symlink, wrong-permission, and unknown-version files.
- [ ] 1.3 Add credential-scan fixtures proving bootstrap/delegated plaintext, bearer headers, hashes, tickets, and prompt text never enter logs, workspace objects, packages, browser assets, or test output.

## 2. Rust Kernel owner-key store

- [x] 2.1 keys.rs：CSPRNG/SHA-256/常数时间/UTC 过期/统一 401（单测 6 项） —Add a dedicated owner-key module with strict serde validation, CSPRNG key generation, SHA-256 digesting, constant-time comparison, UTC expiry checks, and uniform public rejection errors.
- [x] 2.2 keys.json 加载（0600/symlink/完整性 fail-closed；bootstrap digest 仅内存） —Load `/data/kernel/keys.json` plus pending journal at startup with 0700/0600 permission and symlink/ownership checks; keep bootstrap digest from `IWEB_API_TOKEN` in memory only and preserve bootstrap access when delegated state is unavailable.
- [x] 2.3 单写者 WAL 四段提交 + 崩溃对账 + 碰撞重试 + 幂等 ban + 503（phase1_failure/snapshot_write_failure 注入测试） —Implement a single-writer mutation queue with same-directory temp-file fsync+rename, pending transaction phases, startup recovery, collision retry, idempotent ban, and bounded 503 on durable failure.
- [x] 2.4 audit.log 4×1MiB 轮转 + fsync + dropped 信号 + 无凭据字段 —Implement append-only audit segments (`audit.log`, `.1`-`.3`) with strict line bounds, newest-first reads, 4 MiB total cap, rotation, corruption/unavailable signaling, and no secret-bearing fields.

## 3. Rust HTTP and monitor integration

- [x] 3.1 audit_middleware：/v1/* 归因 + 401 拒绝事件 + 路径去 query —Refactor Kernel authentication into one request guard that returns actor identity (`bootstrap` or delegated `keyId`) to handlers and emits bounded audit events for accepted/rejected control requests.
- [x] 3.2 GET/POST /v1/keys + DELETE /v1/keys/{keyId} + GET /v1/audit（409/404/400 精确契约） —Add `GET/POST /v1/keys`, `DELETE /v1/keys/{keyId}`, and `GET /v1/audit` with exact status/error contracts, metadata-only responses, limit/filter validation, and bootstrap protection.
- [x] 3.3 monitor 票据绑定 actor + ban 即时关闭（revision 广播+5s 重验） —Bind monitor tickets and WebSocket sessions to actor identity; invalidate delegated tickets and close active delegated streams on ban without placing owner keys in URLs or subprotocols.
- [x] 3.4 /v1/recover/* 独立 + bootstrap 恢复语义（损坏快照 fail-closed 单测） —Keep `/v1/recover/*` on the independent api hostname and verify bootstrap recovery while keys snapshot, Admin, MCP, and application routes are unavailable; do not widen `control_journal.rs` with credentials.
- [x] 3.5 Rust 单测 10 项（鉴权/持久化/过期/审计轮转/故障注入） —Add Rust unit/integration tests for auth parity, concurrent mutation ordering, crash recovery, audit rotation, ban races, monitor close, and bootstrap fallback.

## 4. MCP propagation

- [ ] 4.1 Add MCP contract tests proving initialize, tools/list, notifications reaching the server, and tools/call authenticate every request with bootstrap or delegated keys.
- [ ] 4.2 Prove the Worker forwards the exact current Authorization header, does not accept actor/key-id overrides, stores no credential, and surfaces Kernel 401 after ban; do not add a JS authorization implementation.
- [ ] 4.3 Add an end-to-end fixture that calls an MCP tool with a delegated key and asserts the Kernel audit event carries the matching keyId without bearer material.

## 5. Admin console

- [x] 5.1 Admin strict schemas + keysList/Create/Ban/audit 客户端 —Extend strict API contracts/client methods for key metadata, one-time issuance response, ban, audit filters, bounded errors, and bootstrap revocability.
- [ ] 5.2 Update tab-scoped session behavior to accept any valid owner key, clear stale sessions on 401, and preserve the no-URL/no-localStorage/no-build-secret boundary.
- [x] 5.3 Keys 视图：创建/一次性 token/提示词复制/吊销确认/禁用 bootstrap 吊销（浏览器全流程实证） —Build Keys view with explicit create/ban confirmation, absolute-expiry presets, one-time secret display, clipboard-only prompt construction, loading/error/empty states, and a disabled bootstrap revoke action.
- [x] 5.4 Audit 视图：keyId 过滤/limit/newest-first/dropped 提示 —Build Audit view with key/limit filtering, newest-first rendering, unavailable/corrupt-range state, and no raw credential display; add component and browser contract tests.

## 6. Backup, operations, and verification

- [ ] 6.1 Update quiesced node backup/restore tooling to include keys snapshot, pending journal, and rotated audit segments as one Kernel-state set without accepting or printing owner secrets in argv/logs.
- [ ] 6.2 Add Linux/container acceptance for permissions, restart recovery, keys-store corruption, bootstrap recovery, audit cap/rotation, and concurrent requests; keep publication disabled unless existing sandbox gates pass.
- [ ] 6.3 Run `openspec validate owner-key-management --strict`, Rust tests, MCP tests, Admin check/tests, focused credential scans, and direct API/MCP/WS smoke tests; record missing host-dependent evidence without marking it complete.
- [ ] 6.4 Perform one whole-change security/spec review against committed and uncommitted diffs; leave Apply, acceptance-record creation, spec sync/archive, commit, and release to the owner.
