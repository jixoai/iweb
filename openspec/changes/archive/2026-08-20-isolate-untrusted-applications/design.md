<!-- 用户原始需求（2026-08-13）：普通人会让 AI 部署来源不明的代码，每一个应用必须隔离。 -->
<!-- 架构诊断（2026-08-14）：共享 slirp 网络加代理环境变量不能约束恶意应用；Worker 与 Gateway 必须由应用进程外的强制网络边界隔开。 -->
<!-- 正交意图：选择沙箱边界；确定发布与路由状态机；隔离数据和网络；建立计量；定义迁移回滚。 -->

## Context

See [proposal.md](./proposal.md) for motivation and [specs](./specs/) for the required behavior.

The current node is one Docker container containing Caddy, Kernel, MinIO, and one celld v0.2 Dispatcher. All processes share one network namespace and cgroup; celld also receives fleet-wide S3 credentials. `iweb-workspace` is currently anonymous-readable so Caddy can proxy arbitrary root objects. These properties are acceptable only for the image-seeded prototype and cannot host untrusted application packages.

The deployment target is a low-cost Linux personal node managed through 1Panel or an equivalent installer. Caddy remains the only host-published ingress, `api.<base>` remains recoverable without any application runtime, and the owner must not learn container or network operations.

celld's resident-cell density and an independent celld process are different resource units. A measured cell benchmark near 0.5 MB does not describe the RSS or cgroup usage of a celld process. The current node cgroup value also aggregates Caddy, MinIO, Kernel, celld, and charged caches; it cannot be assigned to an application.

## Goals / Non-Goals

**Goals:**

- Make a compromised application unable to read another application, the owner workspace, or node-control credentials through ordinary process, filesystem, network, or resource interfaces.
- Preserve the simple product model: the owner sees one personal node and applications, while the deployment agent handles package, policy, lifecycle, and rollback operations.
- Keep celld v0.2 as the first Worker runtime without treating celld itself as the hostile-code security boundary.
- Make application versions immutable and activation transactional, so a rejected or unready update cannot replace a healthy version.
- Produce actual per-application CPU and memory measurements from the same boundary that enforces limits.

**Non-Goals:**

- Defend against a Linux-kernel or OCI-runtime zero-day. The first release uses a hardened shared-kernel boundary; microVM isolation remains a future runtime backend.
- Execute arbitrary package-provided install or build scripts on the node. The first release accepts the platform's declarative manifest and deterministic Worker bundle inputs only.
- Provide arbitrary databases, arbitrary inbound ports, GPU access, or unrestricted outbound networking in the first release.
- Make Admin and MCP untrusted user applications. They remain trusted, protected control-plane applications during this migration.
- Optimize idle density before isolation and negative security tests pass.

## Decisions

### 1. Split the personal node into a trusted control plane and rootless OCI application sandboxes

```text
host ingress
    |
 Caddy                         only published listener
    |
 Kernel -------------------- control DB / package store
    |  narrow local RPC
    v
Sandbox Supervisor            dedicated unprivileged host identity
    |
    +-- sandbox app-a/version-7 -> celld -> Worker A
    +-- sandbox app-b/version-2 -> celld -> Worker B
    `-- candidate app-a/v8      -> celld -> Worker A'
```

The node installer SHALL provision a dedicated rootless OCI supervisor outside the current all-in-one container namespace. Kernel talks to it through a local Unix socket carrying a small typed lifecycle protocol. The supervisor owns only iweb-labeled sandbox resources under its dedicated host identity; it has no public listener and receives no owner key.

The production baseline is Linux with cgroup v2 and user-namespace support. Each application sandbox receives its own user, mount, PID, IPC, network, and cgroup boundary; a read-only runtime root; a writable ephemeral area; dropped capabilities; `no-new-privileges`; a restrictive seccomp profile; finite PID, CPU, memory, and storage limits; and no host devices.

The supervisor API accepts semantic operations such as prepare, start, stop, inspect, metrics, and delete. It does not accept arbitrary images, commands, host paths, devices, capabilities, or network settings. Kernel MUST NOT mount the host Docker socket. The application container MUST NOT receive either the supervisor socket or an OCI daemon socket.

Every lifecycle operation re-establishes the full managed-resource identity before acting. A syntactically valid opaque name or an `iweb` label alone does not grant authority over a rootless OCI resource. Idempotency applies only to explicitly recognized already-achieved or not-found states; permission failures, runtime corruption, and unavailable OCI infrastructure remain failures. Desired sandbox identity, limits, and admitted-version mapping survive supervisor restart so reconciliation never reconstructs authority from mutable container labels alone.

### 2A. Rejected supervisor topologies and accepted network invariant

Two locally reproducible shapes have failed and MUST NOT be restored:

```text
REJECTED A: network none
Worker + Gateway share netns -> neither can reach MinIO or admitted egress

REJECTED B: shared slirp4netns, allow_host_loopback=true
Worker + Gateway share netns -> both can reach 10.0.2.2 and public Internet
HTTP_PROXY/HTTPS_PROXY       -> cooperative hint, not hostile-code enforcement
MinIO authorization         -> storage authorization, not network isolation
```

The accepted topology is defined by reachability rather than one mandatory OCI
mechanism. The supervisor may use separate network namespaces, a supervisor-
owned router namespace, nftables, cgroup BPF, or another rootless-compatible
facility, but the resulting graph MUST be equivalent to:

```text
Kernel ---- private ingress ----> Gateway ---- pod-private ----> celld/Worker
                                      |
                                      +---- exact version objects ----> MinIO
                                      `---- policy-checked egress ----> Internet

Worker --X--> host/slirp gateway | Kernel | MinIO | supervisor | OCI socket
Worker --X--> public Internet directly | host loopback | peer sandbox
Worker -----> Gateway object/data/egress endpoints only as explicitly assigned
```

The denial must be enforced outside application-controlled code. Removing proxy
variables, opening a raw socket, choosing another DNS resolver, or constructing a
direct IP connection MUST NOT weaken it. Contributor evidence proves the
assembled rules and production call sites; operator acceptance executes the same
matrix on the target host. The absence of a contributor-owned Linux machine does
not permit a cooperative-proxy topology to be marked complete.

- The celld image ENTRYPOINT is the single executable authority; the supervisor appends only fixed arguments (never a second `celld`).
- Both images must be immutable digest references; the installer builds and pins the gateway image and pulls the pinned celld image.
- The restrictive seccomp profile (default ERRNO with an allowlist, x86_64 + aarch64) ships with the supervisor package at `/usr/local/libexec/iweb-sandbox/seccomp.json` and preflight verifies it.
- Per-sandbox version-object credentials live only in a supervisor 0600 secrets file mounted read-only into the gateway container; the gateway signs S3 requests itself, so no credential reaches the application container.
- The readiness contract is `GET /iweb-health?versionId=..&generation=..` on the ingress socket: exactly HTTP 200 with a payload matching the candidate versionId and generation is ready; 4xx/5xx, hangs, timeouts, and stale identities never activate a version. Route generation correlates to the version sequence.
- Resource measurements carry per-component availability: cpu/memory/pids/termination/limits are each provable or unavailable, never zero-substituted; sample time comes from the read, limits from the enforcing cgroup files and the storage driver option.
- The Kernel control database is a single-writer transactional JSON file (atomic tmp+rename, 0600, corrupt files quarantined) wrapping the pure control-state transitions; readiness leases are recorded on versions and activation requires an unexpired lease.

### 2B. Kernel consumption

`kernel/contracts-bundle.cjs` is generated from the contracts modules by `scripts/build-kernel-contracts.bun.ts`; Kernel (CommonJS) consumes admission, activation, routing, readiness, metrics, package collection, and public-object resolution from that single authority. `kernel/application-control.js` owns the supervisor protocol flow (prepare/start/stop/inspect/metrics/delete, readiness leases, drain, reconcile, recovery) and persists sandbox secrets outside inspectable records.

Alternative considered: one celld process per application inside the existing container. Rejected because separate processes still share its filesystem, loopback services, credentials, network namespace, and node cgroup.

Alternative considered: mount the host Docker socket directly into Kernel. Rejected because a control API bug would become unrestricted authority over the owner host and unrelated 1Panel workloads.

Alternative considered: one microVM per application. It provides a stronger kernel boundary but requires KVM, raises memory and cold-start cost, and is not consistently available on current 1Panel and Docker Desktop targets. The supervisor protocol intentionally permits a later microVM backend without changing application or MCP contracts.

### 2. Run one celld deployment per active application sandbox

For the initial runtime adapter, one active application maps to one sandbox containing one celld process and one admitted Worker deployment. celld is responsible for Worker semantics inside that sandbox; the outer OCI boundary is responsible for hostile-code isolation. A replacement version runs in a temporary candidate sandbox, so an update can briefly create two celld processes for one application.

Every sandbox uses an opaque application/version identity, a unique celld node identity, and credentials scoped to only that version's private deployment objects. It does not join the trusted celld fleet bucket used by Admin and MCP. Different versions or applications never run celld concurrently against the same fleet bucket.

The runtime image is selected by an immutable digest and its process contract has exactly one executable authority: the image entrypoint or the supervisor-supplied command, never both. The installed supervisor package includes every referenced seccomp or runtime-policy artifact. A generated OCI argument array is preparation evidence only; acceptance must start the assembled image and prove that the intended celld process reaches only its version-scoped deployment objects.

```text
trusted fleet bucket                 application version buckets
  admin + mcp only              app-a/v7     app-a/v8     app-b/v2
       |                            |            |            |
 control-plane celld              celld        celld        celld
```

This intentionally pays process overhead for isolation. The 0.5 MB resident-cell figure is not used for capacity planning. Before choosing default limits, acceptance records cold RSS, ready RSS, request-loaded RSS, CPU, and startup time for the pinned celld image on arm64 and amd64.

Alternative considered: one shared celld Dispatcher, Worker Loader, V8 isolate, or Durable Object cell per application. Rejected because celld v0.2 does not claim that these are hostile multi-tenant boundaries and they do not enforce the required credential, storage, network, and cgroup isolation.

### 3. Snapshot workspace input into immutable content-addressed versions

Kernel remains the only authority that reads the owner workspace for publication. It validates `iweb.json`, resolves the declared application directory, canonicalizes the accepted file set, and creates a content-addressed snapshot. The version ID is derived from the snapshot digest plus the normalized runtime and policy manifest.

```text
mutable workspace
      |
 validate names, sizes, manifest, policy
      |
 immutable version digest ----> private package object
      |
 prepare disposable sandbox --> readiness result
```

The node does not run package-provided lifecycle scripts, compiler plugins, or shell commands. The celld adapter invokes only pinned platform tooling with fixed arguments over the admitted snapshot. Dependencies must already be represented in the admitted bundle; unsupported package shapes fail admission with machine-readable reasons.

Package objects and version deployment objects are private. They are never written beneath an anonymously readable workspace path, and their object credentials never enter Worker bindings.

Alternative considered: let celld compile directly from the mutable workspace. Rejected because a concurrent edit would make a version non-reproducible and would require workspace-wide credentials inside the runtime boundary.

### 4. Separate package versions from stable application data

An immutable version contains executable code and static assets only. Persistent data belongs to a stable opaque application identity and survives version replacement or rollback. The first release exposes persistence through an application-scoped storage gateway and short-lived capability credential; the gateway maps the credential to exactly one application namespace.

Application sandboxes cannot call MinIO administration and never receive MinIO root, workspace, system, or celld-fleet credentials. A version-scoped celld credential is visible only to the celld process environment and grants access only to that version's deployment bucket. A Worker receives only its application-scoped storage capability.

The current Notes Durable Object data cannot simply be shared by two independent celld fleets. Its migration requires an explicit export/import adapter with record count and content verification. The old data remains untouched until the sandboxed Notes version is active and accepted.

Alternative considered: one MinIO credential or one application bucket shared by all versions and processes. Rejected because it makes cross-version concurrency unsafe and lets a runtime compromise mutate its own executable authority.

Alternative considered: copy application data into each version bucket. Rejected because rollback would also roll data backward and could silently lose writes.

### 5. Enforce ingress and egress outside application code

Sandboxes do not join the control-plane network. The supervisor exposes one private ingress endpoint per ready sandbox to Kernel's reverse proxy; the application sees no control endpoint on that path. Kernel resolves an enabled route to an active version and forwards only ordinary application traffic.

`--network none` paired with a sandbox-local `127.0.0.1` endpoint is not an implementation of this topology: container loopback names the sandbox itself and cannot provide trusted object storage, Kernel ingress, or controlled egress. The selected backend must expose concrete, non-public endpoints and prove bidirectional reachability for the allowed Kernel-to-application path while proving that application-to-Kernel, control-plane, host-loopback, and peer paths remain unreachable.

Outbound access is deny-by-default. A declared, owner-authorized policy is compiled into the sandbox network boundary and an egress gateway. Allowed DNS names and ports are resolved by the gateway; loopback, link-local, private node ranges, metadata endpoints, internal service names, Unix sockets, and other sandbox addresses remain denied after DNS resolution and redirects. Application code cannot edit this policy. `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` may configure compatible clients, but they are never the enforcement boundary. HTTP forwarding and HTTPS `CONNECT` MUST connect to the already-validated address while preserving the original Host header and TLS SNI; neither path may trigger an unvalidated second DNS resolution.

The entire `iweb-workspace` bucket will no longer be anonymous-readable. Caddy stops proxying arbitrary MinIO objects directly. Public root resources are served through a narrow gateway that selects explicit owner-visible public objects without exposing bucket listing or credentials.

```text
Internet -> Caddy -> Kernel -> selected sandbox ingress
                                   |
                                   `-> egress policy gateway -> allowed Internet target

denied from sandbox: Kernel | MinIO | supervisor | celld operator | host loopback | app peers
```

Alternative considered: rely on loopback binding and application cooperation. Rejected because the sandboxed process controls its own requests and loopback protection in the current shared namespace is not a security boundary.

### 6. Persist lifecycle state transactionally and route through one active pointer

Kernel stores application identities, immutable versions, normalized policies, lifecycle observations, and active pointers in a single-writer transactional control database on the node data volume. Secrets are stored separately from inspectable records. The database is backed up before node-image migration; MinIO remains the durable object service, not the transaction coordinator for activation.

```text
          +----------> failed
          |
draft -> admitted -> preparing -> ready -> active -> retired
                                \          |
                                 `-> stopped <---+
```

Activation is a short Kernel transaction that verifies the candidate's generation and ready lease, changes the application's active version pointer, and increments the route generation. New requests use exactly that generation. The old sandbox drains after commit and remains retained for rollback. If candidate preparation or readiness fails, no pointer changes. If activation cannot commit, the candidate is stopped and the old version remains active.

On restart, Kernel loads its database, asks the supervisor for observed sandbox state, and reconciles desired versus observed state without executing mutable workspace content. Unknown supervisor resources are quarantined; missing active resources are reported unavailable and restarted only from their admitted version.

Alternative considered: use route registration as deployment state. Rejected because a hostname mapping cannot express immutable versions, readiness, rollback, policy, or observed lifecycle.

### 7. Keep the supervisor protocol smaller than the Kernel and MCP APIs

Kernel owns authorization, application names, version records, policy validation, route activation, and public error shaping. The supervisor owns mechanical sandbox enforcement and measurement only. MCP maps owner-authorized tools onto Kernel operations and never talks to the supervisor directly.

The supervisor protocol uses opaque IDs and fixed request variants. It returns bounded lifecycle state, failure category, timestamps, and measurements; raw runtime logs require a separate owner-authorized bounded read and are never included in public 502 responses or monitor tickets.

Admin and MCP remain on the trusted image-seeded celld deployment during this change. User applications can neither replace their routes nor reach their runtime. `api.<base>` continues to terminate directly at Kernel even if every celld process is stopped.

Alternative considered: expose an OCI or celld management API through MCP. Rejected because it leaks implementation authority into the deployment-agent contract and permits unsafe combinations that bypass Kernel invariants.

### 8. Measure resources at the application cgroup, not from process guesses

The supervisor reads CPU, memory, PID, and termination data from the sandbox's cgroup and returns the value, limit, sample time, and availability. Kernel joins those measurements to the opaque application/version record and streams them through the existing ticketed monitor channel.

Node memory remains the outer node cgroup measurement. Control-plane processes remain labeled as node overhead. If the supervisor cannot prove which cgroup owns a sample, the per-application value is `unavailable`; Kernel never divides node memory, sums process names, or substitutes celld resident-cell counts.

Availability is part of the end-to-end data contract, not an adapter-local hint. Missing measurements, limits, retained runtime state, or cgroup ownership remain `unavailable` across supervisor serialization, Kernel projection, monitor delivery, and Admin rendering; zero is emitted only when the measured value is provably zero.

## 9. Acceptance environments and executable evidence

The change has two different acceptance environments. They are complementary and
must not be conflated:

```text
developer Mac
    | Docker CLI + remote Docker context
    v
iMac Docker node ----------------------> control-plane smoke only
    |                                    Caddy :9010 / Portless HTTPS
    `-- no systemd, no rootless Podman evidence

disposable Linux host
    | systemd + iweb-sandbox user + rootless Podman + cgroup v2
    v
real supervisor / pod / gateway / celld lifecycle ------------> security acceptance
```

### 9.1 Docker-to-iMac control-plane smoke

The repository already contains `scripts/portless-imac.bun.ts` and
`.env.portless-imac.example`. The developer machine owns the Docker CLI and
uses the `remote-mini` context to build and start the node on the iMac; the
script then creates an SSH local forward and registers Portless aliases. The
owner key remains in `.env` and is never placed in command arguments or evidence.

```bash
cp .env.example .env
cp .env.portless-imac.example .env.portless-imac
# Set unique secrets in .env; set the iMac address/context in .env.portless-imac.
docker context inspect remote-mini
bun scripts/portless-imac.bun.ts up
```

`up` is the deployment path. It must build/start through the remote Docker
context, wait for `/_iweb/health`, establish the private SSH forward, enable
Portless wildcard mode, and probe base, `admin`, `api`, `mcp`, `notes.app`, and
the `/notes/app` path alias. When the node is already running, use:

```bash
bun scripts/portless-imac.bun.ts connect
docker --context remote-mini compose -f docker-compose.yml -f docker-compose.portless.yml ps
docker --context remote-mini compose -f docker-compose.yml -f docker-compose.portless.yml logs --tail=200 iweb
```

This smoke proves Docker build/deploy, Caddy routing, Admin asset delivery,
Kernel recovery reachability, and path aliases. It does **not** prove rootless
Podman, systemd, cgroup, namespace, seccomp, or hostile application isolation.
The sandbox compose override must not be used on a macOS Docker Desktop node as
evidence; its `/run/iweb-sandbox` bind and systemd supervisor require Linux.

Keep the Portless process alive while testing. Stop only the disposable remote
node after evidence collection:

```bash
docker --context remote-mini compose -f docker-compose.yml -f docker-compose.portless.yml down
```

### 9.2 Contributor verification versus operator acceptance

Contributors are not required to own a Linux machine. The implementation gate is
the typed protocol, deterministic local tests, assembled-image checks, and
reproducible acceptance tooling. A Linux host is an operator/release environment
requirement, not a prerequisite for ordinary development or code review.

The supervisor acceptance is intentionally shipped as a command that an
operator, CI runner, or release maintainer can execute on a Linux host with
systemd, cgroup v2, user namespaces, and rootless Podman under `iweb-sandbox`.
It performs installation, service identity, preflight, socket ownership/mode,
no-TCP-listener, image digest, Compose topology, and (when explicitly enabled)
real prepare/start/metrics/stop/delete pod lifecycle checks:

```bash
bun tests/sandbox-supervisor.acceptance.sh.ts
IWEB_ACCEPTANCE_RUN_LIFECYCLE=1 bun tests/sandbox-supervisor.acceptance.sh.ts
```

The node operator runs `tests/node-backup.acceptance.sh.ts` separately with
explicit image digests for backup, volume mutation, previous-image restore,
`api.<base>` recovery, workspace object recovery, and route-count equality:

```bash
IWEB_CURRENT_IMAGE=... \\
IWEB_PREVIOUS_IMAGE=... \\
  bun tests/node-backup.acceptance.sh.ts
```

The scripts emit machine-readable evidence but never accept owner keys in argv;
the backup script passes the key to `curl --config` through stdin. Save redacted
JSON evidence under `.agents/evidence/` and record host architecture, kernel,
Podman version, image digests, and the exact command. A dry run, mock adapter,
cross-build, Compose rendering, or empty-directory round trip is not runtime
acceptance evidence; it is still valid contributor-level preparation evidence
when labelled honestly.

Contributor completion still requires production wiring to be internally
enforceable. PLAN output, proxy environment variables, mock sockets, generated
Podman arguments, or a statement that a future host firewall may deny traffic do
not satisfy a task whose implementation currently allows the forbidden path.

### 9.3 Review gate

The next Agent must first close correction tasks `2.44-2.52`, then reconcile the
owning `2.13-2.40` and `3.x-12.x` checkboxes through `2.53`. A task may be checked
when it has a production call site and focused contributor-level evidence; tasks
that explicitly require a host remain operator/release gates and must not be
falsely marked as executed. The handoff must list each command, result,
environment, and unrun host gate. Generic publication remains disabled until the operator runs the Linux
hostile/lifecycle/resource matrices and the independent whole-change review
passes; absence of that host must not block local implementation.

## Risks / Trade-offs

- [One celld process per active application may consume materially more memory than one resident cell] -> benchmark the exact pinned runtime on both architectures, expose real limits, reject unsafe overcommit, and consider idle stopping only after correctness acceptance.
- [Rootless OCI still shares the host kernel] -> use namespaces, seccomp, capability removal, read-only roots, no devices, current runtime patches, and a narrow supervisor; keep a microVM backend possible for higher-assurance deployments.
- [The supervisor is trusted and lifecycle bugs could affect multiple sandboxes] -> minimize its protocol and code surface, forbid arbitrary OCI options, isolate its host identity, and security-test every rejected mount, network, capability, and identifier path.
- [Default-deny egress can break applications that expect unrestricted Internet access] -> make required destinations explicit in `iweb.json`, return actionable admission errors, and let the deployment agent request owner-authorized policy changes.
- [Application rollback cannot automatically roll back incompatible data migrations] -> keep code activation and data migration separate, require explicit backup/migration steps, and report when a retained version is data-incompatible rather than pretending rollback is safe.
- [Changing from one container to a node bundle complicates 1Panel delivery] -> ship one installer/application package that creates the control plane, supervisor identity, local socket, persistent directories, and health checks as one personal-node unit.
- [Removing anonymous workspace access changes root-file delivery] -> introduce and test the public-object gateway before revoking anonymous MinIO policy; never leave both paths as permanent authorities.
- [celld version deployment and Durable Object layout may not support the required code/data split] -> keep the celld adapter behind the sandbox protocol and block generic publication until its isolated package and storage fixtures pass; do not weaken the sandbox contract to fit celld internals.

## Migration Plan

1. Add the transactional application/version model and supervisor protocol while generic publication remains disabled. Back up the existing Kernel route state and persistent volume.
2. Package the dedicated rootless supervisor and prove on arm64 and amd64 that it can enforce user, mount, PID, network, cgroup, seccomp, and credential boundaries without a host Docker socket in Kernel.
3. Add private package/version storage and the application storage gateway. Route public root objects through the narrow gateway, verify equivalent public behavior, and only then revoke anonymous access to `iweb-workspace`.
4. Add the celld sandbox adapter using distinct per-version deployment buckets and pinned runtime images. Run resource benchmarks and cross-boundary negative tests before selecting finite defaults.
5. Add Kernel publication, reconciliation, proxy activation, rollback, MCP tools, Admin projections, and sandbox-backed monitor measurements. Keep user publication feature-gated off.
6. Export the image-seeded Notes data, import it into its application namespace, prepare a sandboxed Notes version, and verify hostname/path-alias behavior and data equality. Atomically activate it while Admin and MCP remain on the trusted Dispatcher.
7. Run independent acceptance for credential theft, workspace and cross-app reads, internal-network probes, undeclared egress, resource exhaustion, crash recovery, failed update, rollback, node restart, and secret scanning. Enable generic publication only after every denial is enforced outside application code.
8. Remove Notes from user-code handling in the shared Dispatcher. Keep the trusted control-plane deployment and `api.<base>` recovery path until a separate change migrates Admin or MCP.

Rollback is stage-aware:

- Before any sandboxed route is activated, restore the previous node image and control database backup on the existing data volume.
- After Notes activation but before generic publication, switch its active route back to the image-seeded Notes handler, stop its sandbox, and retain both old Durable Object data and new application data for inspection.
- After generic publication is enabled, rollback MUST first disable user routes and stop their sandboxes. Reinstalling the prior image MUST NOT execute those packages through the shared Dispatcher. Per-application package and data objects remain quarantined for a forward recovery.
- A failed node-image rollout restores the previous trusted image and control database snapshot. It never runs old and new celld processes against the same fleet bucket; every application-version bucket is unique, and the original control-plane fleet bucket remains separate.

## Open Questions

- Exact default memory, CPU, PID, storage, startup-time, and retained-version limits will be selected from the required arm64/amd64 benchmark evidence; the contract already requires all limits to be finite.
- Whether higher-assurance installations default to a gVisor or microVM supervisor backend can be decided after compatibility testing without changing the Kernel, MCP, package, or application lifecycle contracts.
