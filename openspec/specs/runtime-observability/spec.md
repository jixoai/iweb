<!-- 用户原始需求（2026-08-13）：总览要基于 WebSocket 展示应用监控与必要统计，并反映内存占用。 -->

## Purpose

定义当前单节点、短生命周期的运行态观测契约，让管理员能够查看节点内存、工作区与应用请求统计而不误解其持久性。

## Requirements

### Requirement: Owner status reports node memory envelope
The system SHALL expose owner-authorized node status containing cgroup-v2 memory usage, memory limit when configured, memory utilization percentage when computable, and Kernel heap usage. A null memory limit SHALL mean Docker has not configured a memory cap.

#### Scenario: Node has no Docker memory cap
- **WHEN** the status endpoint reads a cgroup memory limit of `max`
- **THEN** it reports `limitBytes` as null and does not represent that value as an error

### Requirement: Overview uses a ticketed WebSocket session
The system SHALL require an owner-authorized short-lived monitor ticket before accepting a WebSocket connection to the monitor stream. The owner key MUST NOT be placed in a monitor URL, URL fragment, or WebSocket subprotocol.

#### Scenario: Authorized administrator starts monitoring
- **WHEN** an authenticated administrator creates a monitor session and connects with the resulting valid ticket
- **THEN** the monitor stream accepts the connection and sends a current snapshot

#### Scenario: Caller connects without a valid ticket
- **WHEN** a caller attempts to open the monitor WebSocket without a valid unexpired ticket
- **THEN** the Kernel rejects the connection

### Requirement: Monitor snapshot includes node and application projections
Monitor snapshots SHALL carry the node memory envelope and per-application projections with each application's runtime kind, lifecycle availability, measured resources, and configured limits. Sources are tier-defined: celld applications report process-sampled values and watchdog soft limits; wasm applications report engine metrics and engine-enforced limits. The `sandboxes` array of celld control-state records is removed; wasm execution state is reported by the wasm status projection.

#### Scenario: Snapshot distinguishes tiers
- **WHEN** a snapshot includes a celld fleet app and a wasm app
- **THEN** each entry names its runtime kind and carries only its tier's honestly measured resources

#### Scenario: Application receives requests while overview is open
- **WHEN** a monitored application serves requests while the overview WebSocket is connected
- **THEN** per-application request counters and latencies update in subsequent snapshots from the Kernel routing layer

#### Scenario: Application consumes memory
- **WHEN** a monitored application's memory usage changes across sampling windows
- **THEN** its projected memory value follows its tier's source (process VmRSS sample or engine metric) and its limit label follows its enforcement kind

### Requirement: Observability is process-lifecycle scoped
Metrics SHALL be scoped to the current Kernel process lifecycle and re-acquired from their authorities after restart: celld samples from pidfiles, wasm metrics from the engine/executions, supervisor health from the in-container execution socket. No cross-lifecycle aggregation is implied.

#### Scenario: Kernel restart resets sampled series
- **WHEN** the Kernel process restarts
- **THEN** sampled series start fresh and availability flags reflect the new process's acquisitions

#### Scenario: Node restarts
- **WHEN** the whole node container restarts
- **THEN** every projected series restarts from the new process lifecycle and persistent business state (routes, wasm control state) is re-read, never extrapolated from the previous series

#### Scenario: Kernel restarts while sandboxes persist
- **WHEN** the Kernel process restarts while application processes keep running
- **THEN** the new Kernel re-acquires samples from the still-running processes by pidfile and execution identity, and no stale pre-restart values are presented as current

### Requirement: Per-application resources use sandbox accounting
Per-application resources SHALL use tier-honest measurement with one law: a value is reported only from its tier's defined source — celld memoryBytes from `/proc/<pid>/status VmRSS` sampling, celld cpuMillis from `/proc/<pid>/stat` utime+stime deltas, wasm values from the engine metrics contract — and an unavailable measurement is `unavailable`, never zero or estimated from another scope (no node-cgroup totals, no aggregate runtime usage). `limits` report the tier's configured limits: engine limits for wasm, watchdog soft limits for celld, labeled as such.

#### Scenario: Sample is missing
- **WHEN** a pidfile is absent or a sample window failed
- **THEN** the corresponding resources entry reports `unavailable` with its bounded reason and no substituted value

#### Scenario: Soft limit is displayed as soft
- **WHEN** a celld application has a watchdog soft limit configured
- **THEN** projections label it a soft limit with the sampling interval, never as an enforced ceiling

#### Scenario: Sandbox accounting is available
- **WHEN** an application's tier source yields a valid measurement
- **THEN** its projection reports the measured value with `available:true` and the tier-appropriate limit projection

#### Scenario: Sandbox accounting is unavailable
- **WHEN** a tier source cannot produce a trustworthy measurement
- **THEN** the projection reports `unavailable` with the bounded reason and the zero-value law holds: zero appears only for a proven zero measurement or limit

### Requirement: Sandbox failures are visible only to authorized monitoring
Application failures — engine limit terminations, watchdog kills with sampled RSS and configured limit, supervised restarts — SHALL be recorded as bounded events visible to owner-authorized monitoring and status only, never in visitor responses.

#### Scenario: Watchdog kill is auditable
- **WHEN** the watchdog terminates an application process
- **THEN** an authorized monitor sees the bounded event naming the application, sampled RSS, configured soft limit, and timestamp

#### Scenario: Sandbox is terminated by a resource limit
- **WHEN** an application is terminated for exceeding its tier limit (engine limit or watchdog soft limit)
- **THEN** the bounded termination event is visible to authorized monitoring only and visitor traffic receives the generic availability behavior

### Requirement: Admin presents node and application memory as different resource scopes
Admin SHALL keep node container memory (cgroup-v2 `memory.current` scope) and per-application memory (tier-measured) visually and semantically distinct, label limits by enforcement kind (engine-enforced vs watchdog soft), and keep the rule that an unavailable row never silently disappears and zero is never substituted for missing data.

#### Scenario: Overview shows both scopes
- **WHEN** an administrator opens the overview
- **THEN** node envelope and per-application rows are separate scopes with distinct labels and no cross-substitution

#### Scenario: Active sandbox has a trustworthy memory sample
- **WHEN** an application row shows a measured memory value
- **THEN** it comes from that tier's defined source (celld process VmRSS sample or wasm engine metric) with its limit labeled by enforcement kind

#### Scenario: Application has no trustworthy sandbox sample
- **WHEN** an application has no valid sample in the current window
- **THEN** its row reports `unavailable` with the bounded reason and never zero or an estimated value

#### Scenario: Trusted control-plane application shares node overhead
- **WHEN** a control-plane celld application's memory is displayed
- **THEN** its row shows its own process measurement and node-level overhead stays attributed to the node scope, not hidden in the application row

#### Scenario: Node and application totals are viewed together
- **WHEN** both scopes are visible at once
- **THEN** the UI labels each scope separately and never presents their sum or one as the other
