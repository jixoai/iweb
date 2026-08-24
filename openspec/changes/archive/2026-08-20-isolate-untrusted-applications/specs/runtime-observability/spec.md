<!-- 用户原始需求（2026-08-13）：应用监控要显示每个应用真实占用的内存，不能拿容器总内存冒充。 -->
<!-- 正交意图：扩展监控快照；定义逐沙箱计量；保持生命周期语义。 -->

## MODIFIED Requirements

### Requirement: Monitor snapshot includes node and application projections
The system SHALL stream snapshots containing node uptime, route count, workspace file count and bytes, node cgroup memory, and per-application request, error, in-flight, latency, sandbox lifecycle, CPU, memory, and configured limit projections. Node-wide memory MUST NOT be labeled or duplicated as an individual application's usage.

#### Scenario: Application receives requests while overview is open
- **WHEN** routed application traffic is handled while an authorized monitor client remains connected
- **THEN** subsequent monitor snapshots reflect that application's updated request and error projections

#### Scenario: Application consumes memory
- **WHEN** an active application sandbox changes its accounted memory usage
- **THEN** subsequent snapshots report the change for that application while retaining a separately labeled node cgroup total

### Requirement: Observability is process-lifecycle scoped
The system SHALL label in-memory request and latency metrics as Kernel-process-lifecycle data and MUST NOT present them as durable history after a Kernel or node restart. Current sandbox lifecycle and resource values SHALL be reacquired from the sandbox authority after monitoring starts or reconnects rather than inferred from the prior Kernel lifecycle.

#### Scenario: Node restarts
- **WHEN** the Kernel process or node restarts
- **THEN** the next monitor session begins a new in-memory metric lifecycle

#### Scenario: Kernel restarts while sandboxes persist
- **WHEN** the Kernel process restarts and an authorized monitor session reconnects
- **THEN** request-history counters begin a new lifecycle while current sandbox state and resource values are reacquired and labeled as current measurements

## ADDED Requirements

### Requirement: Per-application resources use sandbox accounting
The system SHALL derive an application's CPU and memory usage from that application's enforced sandbox boundary. It MUST NOT substitute node cgroup totals, aggregate runtime-process usage, route counters, resident-cell estimates, or benchmark values for sandbox accounting. If trustworthy accounting is unavailable, the value SHALL be unavailable rather than estimated.

#### Scenario: Sandbox accounting is available
- **WHEN** the monitoring authority reads resource data for an application sandbox
- **THEN** it reports measured CPU and memory together with the applicable limit and measurement time

#### Scenario: Sandbox accounting is unavailable
- **WHEN** the node cannot obtain trustworthy resource data for an application
- **THEN** the application projection marks that resource measurement unavailable and does not display node-wide usage as a fallback

### Requirement: Sandbox failures are visible only to authorized monitoring
The system SHALL expose sandbox lifecycle and failure categories to owner-authorized status and monitor clients while keeping protected runtime diagnostics out of public application responses.

#### Scenario: Sandbox is terminated by a resource limit
- **WHEN** the sandbox authority terminates an application for exceeding an enforced limit
- **THEN** the authorized monitor projection identifies the affected application, lifecycle state, and resource-limit failure category

### Requirement: Admin presents node and application memory as different resource scopes
The Admin application-monitoring primary table SHALL keep every visible application as one stable row and SHALL present that application's measured current memory together with its enforced memory limit beside its request and lifecycle state. Node or container memory SHALL remain a separately labeled node-wide total and MUST NOT be presented as any application's usage. A trusted control-plane application SHALL be labeled as node overhead, and an application without a trustworthy sandbox sample SHALL remain visible with an explicit unavailable state; the resource columns or application row MUST NOT disappear merely because the measurement is unavailable.

#### Scenario: Active sandbox has a trustworthy memory sample
- **WHEN** an authorized Admin monitor snapshot contains measured memory and an enforced limit for an active application sandbox
- **THEN** that application's primary monitoring row displays the current memory and limit without requiring a separate resource table

#### Scenario: Application has no trustworthy sandbox sample
- **WHEN** a visible application is not yet sandboxed or its sandbox accounting cannot be proven
- **THEN** its primary monitoring row remains visible and displays memory as unavailable rather than displaying the node total, zero, an estimate, or no resource field

#### Scenario: Trusted control-plane application shares node overhead
- **WHEN** Admin displays a trusted control-plane application that has no independent application sandbox
- **THEN** its primary monitoring row labels memory as node overhead and does not claim an independently measured application value

#### Scenario: Node and application totals are viewed together
- **WHEN** Admin displays both the node summary and application monitoring
- **THEN** the node-wide memory total is visibly distinct from each application row's current usage and enforced limit
