<!-- 冻结（2026-08-15）：owner 决定直接转向 rust-kernel-rustfs-storage（Kernel Rust 重写 + RustFS + 废 Caddy）。本 change 保持 open 作为 sandbox 能力规范权威；剩余 kernel 侧工作（11.2–11.4 / 12.3 / 6.5 / 2.7）移至新 change 第 9 节执行，其完成后解锁本 change 归档。 -->
<!-- 用户原始需求（2026-08-13）：普通人交给 AI 部署的应用默认不可信，每一个应用必须隔离。 -->
<!-- 独立复审输入（2026-08-14）：所谓“全部本地可执行实现完成”不成立；把生产链断点转成 correction gate 后再继续整项实现。 -->
<!-- 第三轮整项复审（2026-08-14）：83/97 含错误勾选；共享 slirp 网络、CONNECT 二次解析、非事务生命周期写入、synthetic Notes adapter 与失败测试必须先修复。 -->
<!-- 第四轮独立复审（2026-08-15）：99/107 仍含错误勾选；Admin 主表未展示逐应用内存，持久状态验证/生产 celld deploy/恢复与凭据扫描证据不成立，生命周期 HTTP 编排未 await。 -->
<!-- 第五轮独立复审（2026-08-15）：83→94 汇报大部分本地修复成立；但 celld 实证文件未落盘，supervisor 的 snapshot alias/endpoint 仍无 unit 接线，故 2.33/2.34/2.48/4.2 保持未完成。 -->
<!-- 第六轮独立复审（2026-08-15）：部署指针未校验请求 digest/identity，desired/quarantine/Kernel secret 的损坏记录仍可能被静默当作缺失，rollback 生产响应缺少 retired，版本策略过宽且 monitor sanitizer 不递归数组；2.22/2.28/2.37/2.47/7.3/7.4/10.4 重新打开。 -->
<!-- 正交意图：建立可验收实施序列；保持发布关闭；迁移示例应用；以独立安全验收作为开放门槛。 -->

## 1. Establish the implementation baseline

- [x] 1.1 Add an automated preflight that verifies Linux cgroup v2, user namespaces, rootless OCI support, local Unix sockets, and required filesystem ownership; fail installation with bounded diagnostics when a mandatory isolation primitive is absent.
- [x] 1.2 Add a feature gate that keeps arbitrary application validation, publication, and execution disabled until the sandbox acceptance gate is explicitly satisfied.
- [x] 1.3 Split the current node packaging into a trusted control-plane service and a dedicated unprivileged sandbox-supervisor service without publishing a new host port or mounting the host Docker socket into Kernel.
- [x] 1.4 Add upgrade preflight and backup tooling for the persistent volume, Kernel route state, and the new control database, including a tested restore command for the previous node image.

## 2. Define the application and supervisor contracts

- [x] 2.1 Define and validate the versioned `iweb.json` application package schema, including entrypoint, static assets, finite resource policy, storage request, and deny-by-default egress policy.
- [x] 2.2 Define stable typed records for application identity, immutable version identity, lifecycle state, active version, normalized policy, readiness lease, failure category, and resource sample without unchecked external input.
- [x] 2.3 Define the narrow versioned Kernel-to-supervisor protocol for prepare, start, stop, inspect, metrics, and delete operations over a permission-restricted Unix socket.
- [x] 2.4 Add contract tests proving that the supervisor rejects unknown fields and unsafe requests for arbitrary images, commands, host paths, devices, capabilities, network modes, sockets, or identifiers.

## 2A. Preserve the resolved review corrections and deferred host acceptance

- [x] 2.5 Validate backup source labels and canonical containment before any root-owned write; reject duplicate labels, traversal, absolute labels, and symlink source roots, and create backup directories/files with fixed `0700`/`0600` permissions independent of umask.
- [x] 2.6 Create a consistent backup snapshot before calculating source records, reject unsafe archive members, restore into same-filesystem staging, verify the complete staged tree, and atomically replace the intended node-data paths without retaining stale target files or partially modifying the live target on failure.
- [ ] 2.7 Preserve each source's real restore destination, add an executable previous-image restore command that stops the current node before replacement and never runs old and new celld processes concurrently, and test `backup -> mutate -> restore -> previous image -> api.<base>` against a disposable node volume.
- [x] 2.8 Add and runtime-validate the missing active-version pointer record, including application identity, selected immutable version, route generation, and nullable/unavailable state required before first activation.
- [x] 2.9 Validate every supervisor adapter response before serialization; require the response operation, sandbox identity, status variant, and metrics version identity to match the request, and return fixed bounded failure categories without reflecting adapter exception text.
- [x] 2.10 Replace the unsupported package-digest inequality rule with a deterministic sandbox/application/version identity contract, add mismatch and duplicate-identity negative tests, and make real Unix-socket oversized requests return a stable JSON `413` instead of resetting the connection.
- [x] 2.11 Audit direct edits under `openspec/specs/` against checked-in current behavior; keep future sandbox behavior in this change's delta specs until implementation is accepted and the change is explicitly synced or archived.

## 2B. Resolve the whole-change implementation review

- [x] 2.12 Make the celld runtime invocation unambiguous: use exactly one image entrypoint or command, require an immutable image digest, install the referenced restrictive seccomp profile with the supervisor package, and add tests that exercise the assembled runtime command rather than only matching argument strings.
- [x] 2.13 Replace the unusable `network none` plus sandbox-loopback object endpoint with an enforceable topology that gives Kernel exactly one private application ingress, gives celld only its version-scoped deployment-object path, and routes authorized outbound traffic only through the policy gateway; prove actual connectivity and denials before claiming runtime integration.
- [x] 2.14 Require every lifecycle operation to verify the complete trusted sandbox identity and managed labels before acting; make create/start/stop/inspect/delete idempotent only for explicitly recognized runtime states, preserve infrastructure failures, persist enough desired state for supervisor restart, and quarantine unknown resources without adopting or executing them.
- [x] 2.15 Preserve unavailable resource measurements and limits through the supervisor protocol, Kernel status, monitor snapshots, and Admin projections; wire cgroup ownership, termination, sample time, and limits into the runtime adapter without substituting zero or in-memory defaults.
- [x] 2.16 Make readiness use a fixed health contract, accepted success statuses, per-attempt deadlines, bounded total attempts, and candidate identity/generation correlation so authorization failures, missing routes, throttling, hangs, or stale responses cannot activate a version.
- [x] 2.17 Harden canonical package collection to runtime-validate the manifest and filesystem/object metadata, reject duplicate canonical paths, symlinks, non-regular files, TOCTOU changes, missing declared entrypoints/assets, and non-canonical manifest serialization before persisting a digest.
- [x] 2.18 Harden storage capabilities with bounded application identity, secret, TTL, timestamp, nonce, and token validation; use durable replay prevention and stable machine-readable rejection, and ensure no invalid input path throws an internal exception or reflects a credential.
- [x] 2.19 Replace ad hoc egress address parsing with a proven normalized IP/DNS classification path that rejects all non-global, alternate-family, embedded, rebinding, redirect, internal-name, and peer targets; test hostname case and trailing-dot equivalence while keeping enforcement outside application code.
- [x] 2.20 Expand the hostile fixture to perform every attack named by 12.1, sanitize credential-scan locations as well as values, and provide an executable sandbox matrix rather than treating pure predicates or fabricated specs as denial evidence.
- [x] 2.21 Connect each security module to its production authority and add integration evidence before marking its owning 3.x-12.x task complete; a pure function, mock adapter, generated argument list, cross-compile, Compose render, or strict OpenSpec validation alone is not implementation evidence.

## 2C. Resolve the second whole-change code, spec, and security review

- [x] 2.22 Persist the complete canonical admitted package snapshot atomically under its verified digest, create the private version deployment objects from that exact snapshot with fixed platform commands, and make prepare, restart recovery, and rollback fail closed when the snapshot or deployment object is absent, partial, stale, or mismatched. `deploy/current.json` and every deployment record MUST be field-validated against the requested applicationId, versionId, and digest before `deployed()` can return true; a stale pointer MUST trigger redeploy or a bounded failure. Prove that later workspace mutation cannot alter the admitted or active version.
- [x] 2.23 Replace the wildcard `iweb-app-*` object policy with authority scoped to exactly one immutable application version, create and retire that authority with the version lifecycle, and separate celld's private deployment-object transport from every Worker-callable path so hostile application code cannot list, sign, write, or delete version objects.
- [x] 2.24 Connect application outbound HTTP and HTTPS to the policy gateway through an enforceable runtime transport, prove an explicitly admitted destination succeeds, and prove direct, undeclared, redirected-private, host-loopback, control-plane, object-store, supervisor, and peer access cannot bypass that gateway.
- [x] 2.25 Remove the shared Dispatcher fallback for every user application route; return a bounded generic HTTP 502 whenever no ready active sandbox can serve the route, while preserving 404 for unknown hosts and the trusted image-seeded control-plane routes only.
- [x] 2.26 Reconcile the complete desired pod and child-container topology on create and restart: verify pod, gateway, and app role/version identities, recreate a missing desired child without accepting a partial sandbox as prepared, and quarantine any known-name resource whose immutable identity conflicts with the trusted record.
- [x] 2.27 Connect application-storage capabilities to a production Kernel/gateway/Worker data path, enforce one stable application namespace without listing or cross-application access, and implement a separate owner-authorized persistent-data deletion operation that version deletion cannot invoke implicitly.
- [x] 2.28 Move security-critical Kernel lifecycle and persisted-state boundaries behind strongly typed modules and complete runtime validation, reject unknown or malformed persisted records and RPC results without assertions, and make control/secrets state replacement durable with file and parent-directory synchronization or narrow the durability contract explicitly. Malformed top-level files and malformed nested `GatewaySecret.data` MUST take the documented quarantine/failure path; they MUST NOT become an empty or silently dropped state.
- [x] 2.29 Bound and stream gateway request and response bodies before allocation, remove raw exception and signing-detail logging, return well-formed bounded JSON for every gateway failure, inject clock dependencies for deterministic capability validation, and make the full test suite plus the real TCP/Unix-socket gateway tests pass repeatedly with zero failures.
- [x] 2.30 Replace synthetic-only Notes migration claims with a production Durable Object export/import adapter and a non-destructive dry-run verifier for count, digest, repeatability, and rollback inputs; keep execution against real Notes data behind explicit owner authorization.

## 2D. Production wiring and node acceptance correction gate

- [x] 2.31 Make the GatewaySecret complete and bootable: provide and validate `ingressTarget`, `socketDirectory`, object/data endpoints, and gateway listen addresses from one production configuration; reject self-loop and unreachable endpoint combinations before pod creation.
- [x] 2.32 Replace `network none` plus loopback self-reference with a concrete private topology. Add deterministic contributor tests for the assembled wiring and ship an operator acceptance that proves Gateway reachability to MinIO/admitted egress while the Worker cannot reach Kernel, MinIO, supervisor, host loopback, peers, or the OCI socket.
- [x] 2.33 Materialize the admitted snapshot into the exact supervisor-owned read-only mount, run the real pinned `celld deploy`/deployment-object flow from that snapshot, and fail closed on missing, partial, stale, or digest-mismatched objects. The production Kernel and supervisor call sites plus a persisted real-node evidence record are required; injected deploy hooks alone are insufficient.
- [x] 2.34 Enforce exact-one-version object authority and remove all Worker-callable signing or mutation paths; the version credential policy itself MUST not grant broad `ListBucket`/arbitrary `PutObject` authority, and Gateway restrictions are not a substitute for least-privilege policy. Verify the real celld process can read only its own deployment objects and cannot list, write, delete, sign, or access another version. Record the exact bucket/prefix denial matrix in evidence.
- [x] 2.35 Connect HTTP/HTTPS egress in the assembled runtime, bind DNS validation to the verified destination IP, handle the real HTTP `connect` event, stream bounded request/response bodies, and prove redirect/rebinding/private-target denials with real TCP tests.
- [x] 2.36 Connect the storage gateway and owner-authorized data-delete operation to production Kernel, Gateway, and Worker consumers; prove data survives version deletion and rollback while cross-application access and listing remain denied.
- [x] 2.37 Replace persisted-record assertions with field-by-field runtime validation and make all lifecycle writes single-writer transactional under concurrent admission/reconcile; preserve infrastructure errors and quarantine malformed state. Validate endpoint, bucket, credential, application identity, policy, limits, timestamps, unknown fields, and quarantine records through one shared authority; `ENOENT` is the only missing-state result, while permission/I/O and corrupt quarantine files remain explicit failures with durable reasons.
- [x] 2.38 Inject a durable nonce store into the production Gateway, remove all credential-bearing argv paths, and verify credentials are absent from argv, URLs, logs, assets, workspace objects, monitor frames, and test evidence.
- [x] 2.39 Connect a real Notes Durable Object export/import adapter behind explicit owner authorization; dry-run must be non-destructive and evidence must include count, digest, repeatability, and rollback inputs.
- [x] 2.40 Fix rootless installation so gateway and celld images are built/pulled in the `iweb-sandbox` user image store or explicitly transferred there; cover user/image-store command construction locally and ship the clean-install systemd proof as an operator acceptance.
- [x] 2.41 Run the local Docker-to-iMac control-plane smoke flow using `scripts/portless-imac.bun.ts up`, verify base/admin/api/path-alias routes over HTTPS, collect remote Compose status/log evidence, and verify `connect` reuses an already-running node without rebuilding.
- [x] 2.42 Ship and document `tests/sandbox-supervisor.acceptance.sh.ts` as an operator/release gate for a Linux host with systemd and rootless Podman, including `IWEB_ACCEPTANCE_RUN_LIFECYCLE=1`; keep contributor verification runnable without Linux and record the exact host evidence contract.
- [x] 2.43 Ship and document `tests/node-backup.acceptance.sh.ts` plus hostile, resource, rollback, and cross-architecture matrices with explicit image digests; the node operator runs these before publication, while contributors verify command construction, secret handling, and dry/local substitutes without claiming host acceptance.

## 2E. Resolve the third whole-change review without requiring contributor-owned Linux

- [x] 2.44 Replace the shared Worker/Gateway slirp namespace with an enforced network boundary outside application code. The Gateway MUST retain the only path to host MinIO and admitted external destinations; Worker direct sockets to the slirp host, public Internet, Kernel, MinIO, supervisor, peer sandboxes, host loopback, and OCI sockets MUST be structurally denied. Proxy environment variables and object-store authorization are not network isolation.
- [x] 2.45 Carry the verified destination IP through both ordinary HTTP forwarding and HTTPS `CONNECT`, preserve the original Host header and TLS SNI, revalidate every redirect/request, and add real TCP tests proving the connected peer is the verified address for IPv4 and IPv6 rather than a second DNS result.
- [x] 2.46 Serialize every Kernel lifecycle mutation through one production writer across asynchronous package, supervisor, readiness, activation, reconcile, rollback, delete, and recovery operations. Add deterministic concurrent admission/reconcile/activation tests that fail on lost updates, duplicate sequence allocation, or split active pointers.
- [x] 2.47 Runtime-validate every persisted control, desired, quarantine, gateway-secret, and Kernel-secret field without whole-record assertions; distinguish missing files from permission/I/O failure, quarantine malformed state, and ensure invalid policy, identity, limit, endpoint, or credential records cannot reach runtime consumers. Include production `loadSecrets` and supervisor desired-state consumers, malformed-file quarantine evidence, and negative tests proving no malformed credential or endpoint reaches a gateway or celld adapter.
- [x] 2.48 Complete the production snapshot-to-celld chain: inject the materializer in `supervisor/main.ts`, materialize the admitted digest into the exact read-only mount, execute the real pinned `celld deploy` flow, and prove exact-one-version read authority with no Worker-callable list/write/delete/sign path. The systemd unit/install flow must configure the same alias, endpoint, identity and read-only mount used by the running supervisor.
- [x] 2.49 Replace the arbitrary Notes `readState()` module seam and temporary JSON target with a concrete adapter for the pinned celld operator/export contract and the application-storage import target. Keep real-data execution disabled by default; contributor tests use a protocol-faithful fixture, while owner authorization remains required only to touch actual Notes data.
- [x] 2.50 Make clean rootless installation executable before systemd starts: create and own the service home/data/runtime directories, run all Podman commands with the same `HOME`, `XDG_DATA_HOME`, and `XDG_RUNTIME_DIR` used by the unit, and test the constructed environment plus failure propagation. Keep clean-host execution as operator evidence.
- [x] 2.51 Repair and expand the 3.5 isolation suite so each sandbox returns its own immutable identity and stop, crash, delete, and resource-exhaustion cases prove the survivor sandbox plus Kernel control path remain usable. The full test suite MUST pass repeatedly with zero failures.
- [x] 2.52 Wire Kernel startup reconciliation automatically, complete the local lifecycle matrix for activation-commit failure, node restart, supervisor restart, rollback, previous-image orchestration, and old/new fleet mutual exclusion, and leave only explicitly host-dependent observations to the operator scripts.
- [x] 2.53 Reconcile all downstream checkboxes after 2.44-2.52: a task may be rechecked only with its production owning call site and focused evidence recorded in the handoff. Re-run full tests, focused real-socket tests, builds, Admin checks, Compose validation, and strict OpenSpec validation before the next whole-change review.

## 3. Build the rootless sandbox supervisor

- [x] 3.1 Implement supervisor startup under a dedicated unprivileged host identity with no public listener, owner key, workspace credential, MinIO administration credential, or authority over unrelated host workloads.
- [x] 3.2 Implement deterministic per-version sandbox creation with separate user, mount, PID, IPC, network, and cgroup boundaries; a read-only runtime root; bounded writable scratch space; no host devices; dropped capabilities; `no-new-privileges`; and a restrictive seccomp profile.
- [x] 3.3 Enforce finite CPU, memory, PID, and storage limits at sandbox creation and reject a sandbox whose host cannot enforce every requested limit.
- [x] 3.4 Implement idempotent start, stop, inspect, and delete operations plus restart reconciliation that quarantines unknown iweb-labeled resources instead of adopting or executing them.
- [x] 3.5 Add supervisor integration tests proving that stopping, crashing, deleting, or exhausting one sandbox leaves another sandbox and the trusted control plane operational.

## 4. Isolate package and persistent storage

- [x] 4.1 Implement canonical workspace package collection with path, file-count, size, manifest, and symlink validation, and produce a content-addressed immutable version digest without executing package-provided code.
- [x] 4.2 Store admitted package snapshots and runtime deployment objects outside anonymously readable workspace paths with credentials scoped to exactly one application version. The supervisor service must have a reproducible, documented snapshot endpoint/alias and credential path, not only a developer shell configuration.
- [x] 4.3 Implement an application-scoped persistent-storage gateway using short-lived capabilities that map to one stable opaque application identity and cannot list the owner workspace or another application namespace.
- [x] 4.4 Separate version deletion from application-data deletion and require a distinct owner-authorized destructive operation for persistent-data removal.
- [x] 4.5 Add storage security tests for workspace-wide reads, cross-application reads and writes, version-bucket mutation, expired capabilities, credential reuse, and data preservation across update and rollback.

## 5. Enforce application networking

- [x] 5.1 Place every sandbox outside the control-plane network and expose only one supervisor-managed private ingress endpoint for a ready application version.
- [x] 5.2 Implement the deny-by-default egress gateway and compile only owner-authorized DNS-name and port rules from the admitted application policy.
- [x] 5.3 Deny loopback, link-local, metadata, node-private ranges, internal service names, Unix sockets, supervisor access, Kernel, MinIO, celld operator listeners, and peer sandboxes after DNS resolution and every redirect.
- [x] 5.4 Add network security tests covering direct IP probes, DNS rebinding, redirect-to-private targets, undeclared destinations, alternate address families, and attempts to mutate policy from application code.

## 6. Integrate one celld runtime per application version

- [x] 6.1 Build a pinned celld application-runtime image that contains no owner, workspace, system-bucket, control-plane-fleet, supervisor, or host OCI credentials.
- [x] 6.2 Implement the supervisor's celld adapter so each version gets a unique node identity and private deployment bucket and no two applications or versions share celld fleet authority.
- [x] 6.3 Deploy admitted Worker bundles with fixed platform-controlled commands only, reject unsupported package shapes, and prove that package scripts, compiler plugins, and arbitrary shell commands never execute.
- [x] 6.4 Implement bounded readiness probing and generic public failure shaping without exposing celld, Durable Object, supervisor, or infrastructure diagnostics.
- [ ] 6.5 Benchmark cold RSS, ready RSS, request-loaded RSS, CPU, and startup time for the pinned celld image on supported arm64 and amd64 nodes; record evidence and select finite default limits from those measurements rather than resident-cell benchmarks.

## 7. Add transactional Kernel application control

- [x] 7.1 Add a single-writer transactional control database for application identities, immutable versions, policies, lifecycle observations, readiness leases, route generations, and active-version pointers, with secrets stored outside inspectable records.
- [x] 7.2 Implement owner-authorized validation and admission that snapshots a package, normalizes policy, creates an immutable version once, and returns stable machine-readable rejection stages without starting rejected code.
- [x] 7.3 Implement prepare, start, stop, inspect, update, rollback, version deletion, and explicit application-data deletion through the narrow supervisor protocol while preserving unrelated applications on failure. Production responses MUST satisfy the declared operation-specific union, including rollback's committed `generation` and `retired` result.
- [x] 7.4 Implement atomic activation that verifies candidate generation and readiness, switches exactly one active pointer for new requests, drains the previous version, and preserves it for rollback. Exercise the production control object through the Kernel endpoint; stubbed dispatcher results alone do not prove commit/drain ordering.
- [x] 7.5 Implement Kernel restart reconciliation from admitted versions only, including missing active sandboxes, stale readiness leases, failed starts, and quarantined unknown supervisor resources.
- [ ] 7.6 Extend `api.<base>` recovery to restore trusted control-plane applications and reconcile sandbox state without executing mutable workspace packages; verify it while Admin, MCP, and all sandboxes are stopped.

## 8. Route traffic and close workspace exposure

- [x] 8.1 Update Kernel's application proxy so an enabled route resolves to one ready active sandbox version and otherwise returns generic HTTP 502 while unknown hosts remain HTTP 404.
- [x] 8.2 Preserve `<app>.app.<base>` and `<base>/<app>/app` identity and base-path asset resolution against the same active version, including atomic behavior during activation and rollback.
- [x] 8.3 Implement a narrow public-object gateway for the base hostname that serves explicitly public owner objects without bucket listing, workspace credentials, or direct MinIO proxy authority.
- [x] 8.4 Verify public-root compatibility through the gateway, remove Caddy's direct arbitrary workspace-object proxy, and atomically revoke anonymous download access from `iweb-workspace`.
- [x] 8.5 Add routing tests proving that workspace writes and route registration never publish code, failed updates retain the prior active version, and no user route can replace `api`, `admin`, or `mcp`.

## 9. Expose deployment-agent and owner interfaces

- [x] 9.1 Add MCP tools for package validation and publication with stable admission, preparation, readiness, and activation results and no owner credential in packages, stored records, sandbox environments, logs, or URLs.
- [x] 9.2 Add MCP tools for application inspection, start, stop, retained-version listing, rollback, version deletion, and separate persistent-data deletion with active-version safety checks.
- [x] 9.3 Extend Admin application projections to show source-folder path on the second line, control-plane versus sandbox identity, active version, lifecycle state, policy, domains, and unavailable states without merging workspace editing into the application view.
- [x] 9.4 Add loading locks, failure recovery, and real-time refresh to every Admin publication and lifecycle action, and preserve the tab-scoped owner-key boundary.
- [x] 9.5 Add MCP contract tests and Admin unit/component tests for successful publication, rejected packages, failed readiness, stop/start, rollback, protected routes, credential absence, and stale monitor recovery.

## 10. Report real per-application resources

- [x] 10.1 Read CPU, memory, PID, limit, termination, availability, and sample-time data from each sandbox cgroup through the supervisor protocol.
- [x] 10.2 Extend Kernel status and ticketed monitor snapshots with sandbox lifecycle and per-application resource data while retaining a separately labeled node cgroup total and Kernel-lifecycle request metrics.
- [x] 10.3 Update the Admin application-monitoring primary table so every visible application row shows its measured current memory and enforced memory limit beside its request and lifecycle state. Keep node/container memory as a separately labeled node total; label trusted control-plane applications as node overhead rather than attributing a fabricated per-application value; and keep unavailable or not-yet-sandboxed applications visible with an explicit unavailable state instead of hiding the resource surface.
- [x] 10.4 Add monitor protocol and Admin component tests for changing per-application usage, enforced limits, limit termination, unavailable and not-yet-sandboxed rows, control-plane node-overhead labeling, Kernel restart with surviving sandboxes, WebSocket reconnect, and exclusion of protected diagnostics from public responses. The monitor sanitizer MUST recurse through arrays as well as objects; prove array-contained credentials/diagnostics are removed, the UI never copies the node total into an application row, and the UI never hides per-application resource columns merely because no sandbox sample is currently available.

## 11. Migrate Notes without weakening rollback

- [x] 11.1 Implement a one-time Notes Durable Object export and application-storage import path with backup, record-count, content, and repeatability verification while leaving original data untouched.
- [ ] 11.2 Admit and prepare Notes as an immutable sandboxed version, verify its HTML and API through both hostname and path alias, and prove that it cannot access control-plane or other application authority.
- [ ] 11.3 Atomically activate sandboxed Notes, verify data equality and new writes, then exercise rollback to the image-seeded Notes handler and forward activation without data loss.
- [ ] 11.4 After acceptance, remove user-code handling for Notes from the shared Dispatcher while retaining trusted image-seeded Admin and MCP and the independent Kernel recovery route.

## 12. Pass the security and release gates

- [x] 12.1 Add an automated hostile-application fixture that attempts credential discovery, workspace and cross-application access, internal-service probes, undeclared egress, filesystem escape, supervisor access, process escape, and resource exhaustion.
- [ ] 12.2 Run the hostile fixture and lifecycle matrix on supported arm64 and amd64 Linux nodes and record evidence that every denial is enforced outside application code while other applications and `api.<base>` remain available.
- [ ] 12.3 Scan packages, sandbox filesystems, environment projections, object stores, built Admin assets, logs, monitor frames, test output, and node-image layers for owner and infrastructure credentials without recording the credential values. Every one of the nine declared location kinds needs a non-empty scan and a persisted sanitized evidence record; missing kinds remain open.
- [x] 12.4 Exercise failed admission, failed readiness, activation commit failure, sandbox crash, node restart, supervisor restart, rollback, previous-image restore, and the rule that old and new celld processes never share one fleet bucket concurrently.
- [ ] 12.5 Enable generic application publication only after all isolation, routing, recovery, credential, resource, and cross-architecture acceptance checks pass; otherwise leave the feature gate closed.
- [x] 12.6 Update README, AGENTS, `i18n.zh.md`, installation guidance, and current OpenSpec truth with the accepted node-bundle topology, measured resource semantics, security limits, recovery procedure, and evidence paths.
- [ ] 12.7 Re-run all focused tests, full project tests, image acceptance, and strict OpenSpec validation; archive this change only after every implementation task and owner-visible acceptance requirement is complete.
