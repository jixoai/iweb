<!-- 用户原始需求（2026-08-24）：mini 快照与审计账本立法（grilling Q4/Q5/Q20/Q21 恢复与审计部分）。 -->

## ADDED Requirements

### Requirement: Snapshot scope and exclusions
Every composition update SHALL be preceded by a verifiable snapshot of the steady fleet bucket and the composition registry, taken after the fleet is quiesced and in-flight work has drained — uniformly for all updates, with no stateless shortcut. Snapshot creation failure SHALL refuse the update. The workspace, the version-object zone, and the Kernel audit ledger are explicitly outside snapshot and restore scope: the registry may roll back as part of recovery semantics, the audit ledger never does.

#### Scenario: Snapshot cannot be created
- **WHEN** the pre-update snapshot fails verification or creation
- **THEN** the update is refused, the current composition keeps serving, and no restart occurs

### Requirement: Retention is a fixed product constant
The system SHALL retain the last three successful pre-update snapshots as a v1 product constant with no configuration option and no manual deletion API. The in-flight update's snapshot is pinned until the transaction succeeds or automatic recovery completes; after a failed update and completed automatic recovery, the pinned snapshot is retained as a normal member of the rotation set, because it is a valid snapshot of the last healthy pre-update state. Rotation deletes the oldest snapshot beyond three, automatically and predictably, shown in the Admin snapshot list with timestamps and storage usage. When no recoverable snapshot would remain, the update SHALL be refused rather than proceeding unprotected or silently lowering retention. Snapshots live in a Kernel-managed bucket outside the fleet credential domain, and all snapshot operations are driven by Kernel credentials.

#### Scenario: Failed update then rotation
- **WHEN** an update fails readiness, automatic recovery completes, and two further successful updates run
- **THEN** the failed update's pre-state snapshot participates in normal rotation and the retained set holds the three most recent valid pre-update snapshots

#### Scenario: Fourth update rotates the oldest snapshot
- **WHEN** a fourth successful update completes with three prior snapshots retained
- **THEN** the oldest snapshot is deleted automatically and the Admin list shows exactly three with current usage

### Requirement: Explicit destructive restore
Restoring a designated snapshot SHALL be a bootstrap-owner-only operation offered from the retained snapshots, never delegable, presented with an explicit data-loss warning naming the discarded-write cutoff, and recorded in the audit ledger with that cutoff timestamp. Restore discards all state written after the snapshot.

#### Scenario: Owner restores an older snapshot
- **WHEN** the bootstrap owner confirms a destructive restore of a retained snapshot
- **THEN** the fleet returns to that snapshot's state, writes after the cutoff are discarded, and the action appears in the audit log with its cutoff

### Requirement: Kernel is the recovery authority
The `api.<base>` Kernel API SHALL be the only recovery authority for iweb-mini: composition redeployment, automatic-rollback verification, and snapshot restore are Kernel-level capabilities that remain available when the fleet — including the Admin application — is broken or absent. Admin recovery interfaces are conveniences layered on the same API, never an alternate authority.

#### Scenario: Fleet is broken by a bad update
- **WHEN** the shared fleet cannot serve the Admin application
- **THEN** the owner can still roll back to a recorded composition or restore a snapshot through `api.<base>` with the bootstrap key

### Requirement: Audit ledger is independent and commit-preceding
The Kernel SHALL keep an operational audit ledger as Kernel-owned state outside the fleet bucket — recording the current carrier as a fact: the existing Kernel-owned JSONL ledger with 4 × 1 MiB rotation, whose capacity acceptance belongs to implementation evidence — and successful audit append SHALL be a commit precondition for high-risk control operations — admission, receipt confirmation, composition submit, activation, and rollback, snapshot creation and restore, automatic recovery, and recorded rejections including stale 409s. On append failure the operation SHALL return 503 without flipping the composition pointer or claiming success; this applies to automatic recovery uniformly, without exceptions. Events SHALL include at least event id, timestamp, actor, action, result, composition id and generation, application and version ids, package digest, snapshot id, and transaction id — with entity fields nullable and present when applicable to the event's action — and MUST NOT contain credentials, package bodies, or workspace content. Snapshot restore SHALL never roll back the audit ledger; recovery appends new events. The v1 ledger keeps finite rotation, offers no deletion API, provides bootstrap-owner-only export of the retained segment, is an operational (not tamper-proof) log, and does not defend against an actor with host disk access.

#### Scenario: Audit write fails during activation
- **WHEN** the audit append fails while a composition update transaction is committing
- **THEN** the transaction aborts with 503, the previous composition remains authoritative, and no success is reported

#### Scenario: Snapshot restore completes
- **WHEN** a destructive restore finishes and the fleet resumes
- **THEN** the audit ledger still contains the full pre-restore history followed by a new restore event
