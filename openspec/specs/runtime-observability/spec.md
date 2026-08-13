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
The system SHALL stream snapshots containing node uptime, route count, workspace file count and bytes, node memory, and per-application request/error/in-flight/latency projections.

#### Scenario: Application receives requests while overview is open
- **WHEN** routed application traffic is handled while an authorized monitor client remains connected
- **THEN** subsequent monitor snapshots reflect the application's updated request and error projections

### Requirement: Observability is process-lifecycle scoped
The system SHALL label current monitor and metric values as in-memory, Kernel-process-lifecycle data. It MUST NOT present them as durable historical observability after a Kernel or node restart.

#### Scenario: Node restarts
- **WHEN** the Kernel process or node restarts
- **THEN** the next monitor session begins a new in-memory metric lifecycle
