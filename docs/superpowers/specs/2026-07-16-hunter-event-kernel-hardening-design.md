# Hunter Task 8 Event Kernel Hardening Design

**Date:** 2026-07-16
**Status:** Ready for implementation
**Repository:** `C:\Users\Administrator\.agents\skills\hunter`
**Required baseline:** `932b601 fix: stabilize workflow lock identity`
**Scope:** Task 8 event-kernel ownership, correctness, compatibility, recovery, concurrency, and performance only

## 1. Supersession and authority

This design is the authoritative specification for Hunter Task 8.

It replaces:

- all of **Task 8** in
  `docs/superpowers/plans/2026-07-15-hunter-unified-proof-engine.md`;
- the event-sink, arbitrary event-recording, action-attempt persistence, and
  event-idempotency portions of that plan's **Task 9**;
- the event-kernel ownership and production-entry cutover prerequisites for
  that plan's **Task 10**;
- the `WorkflowKernel` handoff-ingestion, attempt-number, checkpoint binding,
  event-log recovery, and resume-idempotency portions of that plan's
  **Task 11**.

The remaining Tool Broker work in Task 9, production entry-point routing in
Task 10, and high-level orchestrator/MCP handoff work in Task 11 are not
implemented by this design. Task 8 does not connect `EventKernel` to any
production entry point. Task 9/10 integration may claim a production workflow
only after the Task 8 acceptance suite passes and the integration has gated
all legacy mutation, legacy checkpoint creation, and legacy resume/handoff
paths for that workflow. Task 11 inherits the same gate.

No implementation under this design may modify:

- `core/workflow/models.py`;
- `core/workflow/kernel.py`;
- `core/workflow/locking.py`;
- `core/workflow/__init__.py`;
- existing high-level MCP entry points;
- Tool Broker code;
- SQLite memory dispatchers;
- Process Supervisor code.

The Windows lock-identity fix in commit `932b601` is a hard prerequisite. The
new event kernel imports and uses the existing `WorkflowFileLock` without
altering it.

## 2. Goal

Build an independent, typed, event-sourced command kernel that can explicitly
claim writer ownership and safely append namespaced schema 2.0 domain events
to existing Hunter workflow logs while:

1. making the first schema 2.0 event a typed ownership claim and rejecting
   legacy writes after that claim;
2. separating a logical action from every execution attempt;
3. enforcing command idempotency and two-part compare-and-swap;
4. using one reducer for strict materialization and semantic-prefix replay;
5. preserving all existing schema 1.0 bytes through lazy upcasting;
6. requiring typed evidence attestation before a verified finding;
7. preventing invalid process projections and memory side effects;
8. binding recovery to cryptographically verified checkpoint metadata and
   committing recovery with one atomic event-log replacement;
9. remaining correct under 32 threads and 8 independent processes;
10. replaying both compact and 4,096-byte-excerpt 10,000-event fixtures in one
    linear pass and replaying at most once per command.

Task 8 is complete only when the independent acceptance suite proves these
properties without changing the legacy kernel files.

## 3. Scope boundaries

### 3.1 Included

- schema 2.0 event and command envelopes whose event names all begin with
  `event_kernel.`;
- typed workflow ownership claim and mixed-writer detection;
- the Task 9/10 production-integration gate contract, tested without wiring
  any production entry point;
- canonical JSON, command digests, event hashes, and generation-scoped IDs;
- typed domain command methods;
- logical-action and execution-attempt reducers;
- typed evidence attestation and verifier-policy binding;
- verdict supersession and finding activation rules;
- process-state projection with bounded redacted output;
- memory outbox projection;
- schema 1.0 lazy upcasting;
- strict replay and semantic replayable-prefix inspection;
- duplicate-event, duplicate-command, command-conflict, and transition checks;
- revision plus head-hash CAS;
- checkpoint v2 creation, binding validation, single-replace authorized
  recovery, and recovery crash-injection tests;
- derived event-kernel cache;
- thread/process concurrency acceptance tests;
- separate compact-event and 4,096-byte-excerpt 10,000-event performance
  gates, including peak RSS and lock-queue measurements;
- compatibility tests against the frozen legacy acceptance corpus.

### 3.2 Excluded

- executing a Hunter tool;
- selecting or routing a tool;
- Tool Broker integration;
- MCP schemas, registration, or high-level entry points;
- claiming any production workflow during Task 8;
- installing the Task 9/10 legacy mutation/checkpoint/resume gate in production;
- ingesting external MCP handoff results;
- writing TargetMemory or TechniqueMemory SQLite databases;
- dispatching memory outbox entries;
- starting, supervising, cancelling, or killing operating-system processes;
- changing the old `WorkflowKernel` materializer;
- rewriting or migrating existing event-log files in place;
- replacing `workflow.json` as the legacy high-level projection.

## 4. Component architecture

The implementation is a new subpackage:

```text
core/workflow/event_kernel/
    __init__.py
    contracts.py
    errors.py
    envelope.py
    upcast.py
    reducer.py
    replay.py
    checkpoint.py
    store.py
    service.py
```

Responsibilities are fixed:

| File | Responsibility |
|---|---|
| `contracts.py` | Frozen dataclasses, enums, command inputs, projection state, replay and command results |
| `errors.py` | Stable typed exceptions and error codes |
| `envelope.py` | Canonical JSON, validation, command digest, entity IDs, event hash, schema 2.0 serialization |
| `upcast.py` | In-memory schema 1.0 to semantic-event conversion without file mutation |
| `reducer.py` | The sole domain transition function for legacy semantic events and schema 2.0 events |
| `replay.py` | One-pass byte reader, ownership and chain validation, compact command/event indexes, semantic prefix |
| `checkpoint.py` | Compact checkpoint serialization, binding verification, and recovery authorization |
| `store.py` | Paths, existing workflow lock, append-command commit, checkpoint sidecar protocol, single-replace recovery, atomic cache writes |
| `service.py` | Public `EventKernel` typed command API; no arbitrary event append method |
| `__init__.py` | Explicit exports for the new subpackage only |

The parent `core/workflow/__init__.py` and the other three legacy workflow
files remain unchanged. Consumers and tests import the new component directly:

```python
from core.workflow.event_kernel import EventKernel
```

### 4.1 Persistent paths

For a workflow slug `alpha`, rooted at a workspace containing `cases/`:

| Artifact | Relative path |
|---|---|
| Authoritative event log | `cases/alpha/workflow.events.jsonl` |
| Existing shared lock | `cases/alpha/.workflow.lock` |
| New derived cache | `cases/alpha/workflow.event-kernel.json` |
| Checkpoint v2 sidecar | `cases/alpha/checkpoints/event-kernel/<checkpoint_id>.json` |
| Recovery backup | `cases/alpha/recovery/event-kernel/<checkpoint_id>-<source_sha256>.jsonl` |

Checkpoint metadata stores POSIX-style relative paths such as
`checkpoints/event-kernel/cp-abc.json`. Absolute checkpoint paths and paths
that resolve outside the workflow directory are rejected.

### 4.2 Single-writer cutover

`workflow.events.jsonl` remains shared only for read compatibility. Writer
ownership is not shared:

```text
UNCLAIMED_LEGACY
    -- event_kernel.ownership.claimed --> EVENT_KERNEL_OWNED
```

The typed claim input is:

```python
@dataclass(frozen=True)
class WorkflowOwnershipClaim:
    cutover_id: str
    owner_version: str
    legacy_gate_digest: str
```

The owner ID is fixed by the method to `event_kernel` and cannot be supplied or
overridden by the caller. The event also records lock-generated pre-claim head
revision/hash mode/hash, complete pre-claim byte length and file SHA-256, and
the three typed claim fields. `legacy_gate_digest` is the canonical digest of
the acceptance gate in Task 8 tests and of the actual disabled/redirected
legacy routes in Task 9/10 production integration.

Rules:

1. `claim_workflow` is the only command permitted to append the first schema
   2.0 event. That event is `event_kernel.ownership.claimed`.
2. Every schema 2.0 event type, including the ownership claim, is in the
   `event_kernel.` namespace.
3. Before the claim, `EventKernel` may strictly read and lazily upcast the
   schema 1.0 prefix. No other schema 2.0 event is legal.
4. After the claim, only `EventKernel` may write the log. A new replay that
   encounters any schema 1.0 event after
   `event_kernel.ownership.claimed` raises `MixedWriterError`; the later bytes
   are preserved and never silently ignored or truncated.
5. Legacy materialization is read-only compatibility only. It may ignore
   `event_kernel.*` events while reconstructing its legacy projection, but it
   must not mutate, checkpoint, or resume a claimed workflow.
6. Task 8 does not alter production callers to enforce rule 5. Before Task
   9/10 integration claims a workflow, that integration must atomically gate
   or redirect every legacy mutation, checkpoint, and resume/handoff path.
   The gate is a release prerequisite, not a best-effort operational step.
7. A repeated `claim_workflow` with the original command ID and digest returns
   the original event. A different ownership claim after ownership is
   established raises `WorkflowAlreadyClaimedError`.

Acceptance proves that the unchanged legacy materializer can ignore
namespaced events for reads and that the new replay detects an injected
post-claim schema 1.0 write.

## 5. Public typed API

`EventKernel` exposes read methods and typed commands. It does not expose
`record_event`, `append_event`, a generic event type parameter, or a generic
payload parameter.

```python
class EventKernel:
    def head(self, slug: str) -> Head:
        ...

    def materialize(self, slug: str) -> EventKernelState:
        ...

    def inspect_prefix(self, slug: str) -> ReplayResult:
        ...

    def claim_workflow(
        self, slug: str, meta: CommandMeta, claim: WorkflowOwnershipClaim
    ) -> CommandResult:
        ...

    def propose_action(
        self, slug: str, meta: CommandMeta, action: ActionProposal
    ) -> CommandResult:
        ...

    def merge_action(
        self, slug: str, meta: CommandMeta, merge: ActionMerge
    ) -> CommandResult:
        ...

    def defer_action(
        self, slug: str, meta: CommandMeta, decision: ActionDecision
    ) -> CommandResult:
        ...

    def block_action(
        self, slug: str, meta: CommandMeta, decision: ActionDecision
    ) -> CommandResult:
        ...

    def start_attempt(
        self, slug: str, meta: CommandMeta, start: AttemptStart
    ) -> CommandResult:
        ...

    def complete_attempt(
        self, slug: str, meta: CommandMeta, terminal: AttemptComplete
    ) -> CommandResult:
        ...

    def block_attempt(
        self, slug: str, meta: CommandMeta, terminal: AttemptBlock
    ) -> CommandResult:
        ...

    def cancel_attempt(
        self, slug: str, meta: CommandMeta, terminal: AttemptCancel
    ) -> CommandResult:
        ...

    def attest_evidence(
        self, slug: str, meta: CommandMeta, attestation: EvidenceAttestation
    ) -> CommandResult:
        ...

    def record_verdict(
        self, slug: str, meta: CommandMeta, verdict: VerdictRecord
    ) -> CommandResult:
        ...

    def start_process(
        self, slug: str, meta: CommandMeta, process: ProcessStart
    ) -> CommandResult:
        ...

    def record_process_output(
        self, slug: str, meta: CommandMeta, output: ProcessOutput
    ) -> CommandResult:
        ...

    def terminate_process(
        self, slug: str, meta: CommandMeta, terminal: ProcessTerminal
    ) -> CommandResult:
        ...

    def enqueue_memory(
        self, slug: str, meta: CommandMeta, item: MemoryEnqueue
    ) -> CommandResult:
        ...

    def mark_memory_applied(
        self, slug: str, meta: CommandMeta, result: MemoryApplied
    ) -> CommandResult:
        ...

    def mark_memory_failed(
        self, slug: str, meta: CommandMeta, failure: MemoryFailed
    ) -> CommandResult:
        ...

    def create_checkpoint(
        self, slug: str, meta: CommandMeta, source_session: str = ""
    ) -> CommandResult:
        ...

    def recover_checkpoint(
        self, slug: str, meta: CommandMeta, recovery: RecoveryRequest
    ) -> CommandResult:
        ...
```

The displayed ellipses denote Python signature notation in this design, not
unspecified behavior. Every method's transition contract is defined in this
document.

### 5.1 Command metadata

Every mutating call requires:

```python
@dataclass(frozen=True)
class CommandMeta:
    command_id: str
    expected_revision: int
    expected_event_hash: str
    generation: int
    correlation_id: str
    causation_id: str | None = None
    actor: str = "hunter_tools"
```

Rules:

- `command_id` is supplied by the caller and is the durable idempotency key.
- `expected_revision` and `expected_event_hash` must match the current head
  for a new command.
- `generation` must equal the materialized workflow generation.
- `correlation_id` is required and groups a logical operation.
- `causation_id` is explicit and may be `null` only for a root command.
- `actor` is bounded and persisted.
- command type is selected by the typed method and cannot be overridden by the
  caller.
- command digest is generated by the kernel.
- except for `claim_workflow`, every mutating command requires the replayed
  ownership state to be `EVENT_KERNEL_OWNED`.

## 6. LogicalAction and ExecutionAttempt

### 6.1 Logical action identity

A logical action represents one generation-scoped proof goal. Its identity is
derived from immutable execution identity fields:

```text
action_identity = canonical_json({
  "generation": generation,
  "tool": tool,
  "target": target,
  "arguments": normalized_arguments,
  "kind": kind
})
action_key = sha256(action_identity)
action_id = "act-g" + generation_as_6_digits + "-" + action_key[0:16]
```

Example:

```text
act-g000003-7fe42d7dfcbb2a10
```

The generation is therefore visible in and cryptographically included in the
action ID. A generation mismatch is rejected before append.

`merge_action` may update only:

- `sources`;
- `strategy_ids`;
- `labels`;
- `expected_evidence`;
- priority, and only toward a higher priority.

It cannot change tool, target, arguments, kind, action key, action ID, or
generation. A changed execution identity requires a new logical action.

### 6.2 Logical action states

```text
absent -> proposed
proposed -> deferred | blocked | running
deferred -> blocked | running
running -> completed | retryable
retryable -> blocked | running
blocked -> terminal
completed -> terminal
```

`merge_action` is allowed while the effective state is `proposed`, `deferred`,
or `retryable` and does not change the effective state.

### 6.3 Execution attempts

An execution attempt is a separate entity:

```text
event_kernel.attempt.started -> event_kernel.attempt.completed
event_kernel.attempt.started -> event_kernel.attempt.blocked
event_kernel.attempt.started -> event_kernel.attempt.cancelled
```

All terminal attempt states are immutable. An attempt terminal command is
legal only when every process bound to that attempt is already terminal. The
fixed persisted ordering is:

```text
event_kernel.process.terminated
    -> event_kernel.attempt.completed
    |  event_kernel.attempt.blocked
    |  event_kernel.attempt.cancelled
```

If multiple processes belong to the attempt, all corresponding
`event_kernel.process.terminated` events must precede the one attempt-terminal
event. The reducer rejects an attempt-terminal candidate while any bound
process remains started.

`start_attempt` does not accept `attempt_no` or `attempt_id`. While holding
`.workflow.lock`, the store calculates:

```text
attempt_no = max(existing attempt_no for action_id, default 0) + 1
attempt_id = "att-" + action_id_without_act_prefix + "-" + attempt_no_as_6_digits
```

Only one started attempt may exist for a logical action. A blocked or cancelled
attempt makes the logical action `retryable`; the next `start_attempt` receives
the next number under the same lock.

### 6.4 Budget charging

Budget metrics are event-derived:

- `event_kernel.action.proposed` increments `actions_proposed`;
- `event_kernel.action.deferred` increments `actions_deferred`;
- `event_kernel.action.blocked` increments `actions_blocked`;
- `event_kernel.attempt.started` increments `attempts_started` and
  `budget_charges`;
- terminal attempt events update terminal counters;
- `event_kernel.action.deferred` never increments `attempts_started` or
  `budget_charges`.

Retries are new attempts and each successful
`event_kernel.attempt.started` event charges once.

## 7. Schema 2.0 event envelope

Each new event is one UTF-8 JSON object followed by `\n`:

```json
{
  "event_id": "evt-8a81f2f1e63c4cdf",
  "schema_version": "2.0",
  "workflow_id": "wf-9b10b81f8803",
  "actor": "hunter_tools",
  "type": "event_kernel.attempt.started",
  "timestamp": "2026-07-16T08:00:00.000000+00:00",
  "revision": 42,
  "previous_event_hash": "6d8f4a8fb5c9b3f1f91d8f193a6670db83863c4dd2fd27f3a2eac9f7c01988c1",
  "generation": 3,
  "correlation_id": "corr-proof-17",
  "causation_id": "evt-55f3153f7e0b42c7",
  "command": {
    "command_id": "cmd-start-act-17-attempt",
    "type": "start_attempt",
    "digest": "4c5bdd2d6d09bb1748c1857948c0830d9b1356bbb33e614d2f71f2399381ee72",
    "expected_revision": 41,
    "expected_event_hash": "6d8f4a8fb5c9b3f1f91d8f193a6670db83863c4dd2fd27f3a2eac9f7c01988c1"
  },
  "payload": {
    "attempt": {
      "attempt_id": "att-g000003-7fe42d7dfcbb2a10-000001",
      "action_id": "act-g000003-7fe42d7dfcbb2a10",
      "attempt_no": 1,
      "executor": "hunter_auto_sqli",
      "budget_class": "active-proof"
    }
  },
  "event_hash": "a928fc4a3754c617c5882129d32f68b81071a7384a904ad73774cde35bc63457"
}
```

### 7.1 Canonical JSON

All digests and hashes use:

```python
json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

Non-finite floats, non-string mapping keys, non-JSON values, and payloads over
256 KiB are rejected before lock acquisition.

### 7.2 Command digest

The digest is SHA-256 over the normalized caller intent:

```json
{
  "workflow_id": "wf-...",
  "generation": 3,
  "type": "start_attempt",
  "correlation_id": "corr-proof-17",
  "causation_id": "evt-...",
  "payload": {}
}
```

The digest excludes:

- `command_id`;
- `expected_revision`;
- `expected_event_hash`;
- fields generated under the workflow lock, including attempt number, attempt
  ID, process output sequence, outbox ID, memory delivery attempt, checkpoint
  ID, and checkpoint sidecar metadata;
- event ID;
- event timestamp.

This permits the same command to be retried with a refreshed CAS head after a
conflict while still detecting reuse of a command ID with different semantic
content.

### 7.3 Event hash

`event_hash` is SHA-256 over the canonical event object with only the
`event_hash` key removed. Schema 1.0 hashed events retain their original hash
algorithm. Existing bytes are never reserialized.

### 7.4 One command, one event

Every first-time successful typed command commits exactly one event.
Append-style commands append that event. A verdict and its optional finding
are carried in the same `event_kernel.verdict.recorded` event so finding
validation is atomic and one command never needs a multi-event partial commit.

This invariant includes checkpoint and recovery commands:

- `create_checkpoint` may first write and fsync a sidecar temporary file, then
  finalize that sidecar through the protocol in section 15 before appending
  exactly one `event_kernel.checkpoint.created` event;
- `recover_checkpoint` does not truncate and then append. It constructs
  exactly one `event_kernel.recovery.performed` event and atomically replaces
  the log once with `maximum_semantic_prefix + recovery_event`.

An idempotent retry or semantic outbox dedupe that returns an already committed
result performs no new commit and therefore appends no duplicate event.

## 8. Event and command types

| Typed method | Command type | Event type |
|---|---|---|
| `claim_workflow` | `claim_workflow` | `event_kernel.ownership.claimed` |
| `propose_action` | `propose_action` | `event_kernel.action.proposed` |
| `merge_action` | `merge_action` | `event_kernel.action.merged` |
| `defer_action` | `defer_action` | `event_kernel.action.deferred` |
| `block_action` | `block_action` | `event_kernel.action.blocked` |
| `start_attempt` | `start_attempt` | `event_kernel.attempt.started` |
| `complete_attempt` | `complete_attempt` | `event_kernel.attempt.completed` |
| `block_attempt` | `block_attempt` | `event_kernel.attempt.blocked` |
| `cancel_attempt` | `cancel_attempt` | `event_kernel.attempt.cancelled` |
| `attest_evidence` | `attest_evidence` | `event_kernel.evidence.attested` |
| `record_verdict` | `record_verdict` | `event_kernel.verdict.recorded` |
| `start_process` | `start_process` | `event_kernel.process.started` |
| `record_process_output` | `record_process_output` | `event_kernel.process.output_recorded` |
| `terminate_process` | `terminate_process` | `event_kernel.process.terminated` |
| `enqueue_memory` | `enqueue_memory` | `event_kernel.memory.enqueued` |
| `mark_memory_applied` | `mark_memory_applied` | `event_kernel.memory.applied` |
| `mark_memory_failed` | `mark_memory_failed` | `event_kernel.memory.failed` |
| `create_checkpoint` | `create_checkpoint` | `event_kernel.checkpoint.created` |
| `recover_checkpoint` | `recover_checkpoint` | `event_kernel.recovery.performed` |

No other schema 2.0 event type is accepted by Task 8. The first schema 2.0
event must be `event_kernel.ownership.claimed`.

## 9. `_commit_command` atomic order

Every append-style typed method, including `claim_workflow`,
`attest_evidence`, and `create_checkpoint`, delegates to the private
`EventStore._commit_command`. Its order is fixed:

```text
validate and canonicalize caller input
acquire cases/<slug>/.workflow.lock
replay the event file exactly once
check same command_id
    same digest -> return original committed result
    different digest -> raise CommandConflictError
for claim_workflow:
    require no prior schema 2.0 event and ownership == UNCLAIMED_LEGACY
for every other append command:
    require ownership == EVENT_KERNEL_OWNED
check expected_revision and expected_event_hash together
validate generation
generate lock-owned fields such as attempt_no and attempt_id
construct the candidate schema 2.0 event
apply the sole reducer to a copy of replayed state
append one JSON line
flush and fsync the event file
atomically replace the derived cache
release the lock
return CommandResult
```

The same-command check occurs before CAS. Therefore a retry of an already
committed command returns its original event even when the retry carries a
stale expected head.

For a new command, both CAS values must match:

```text
expected_revision == replay.head.revision
expected_event_hash == replay.head.event_hash
```

Matching revision with a different head hash is an ABA conflict and is
rejected.

The reducer runs before the authoritative append. An illegal transition never
writes a byte. The cache runs only after the fsynced append. Cache replacement
failure does not roll back or hide the committed event; the returned result
sets `cache_updated=false`, and a later materialization may rebuild the cache.

Checkpoint creation follows the sidecar fsync/rename protocol in section 15
while holding the same lock. The final sidecar is durable before the one event
append. A crash before the append can leave only an unreferenced sidecar,
which replay ignores and deterministic cleanup may remove. A committed
checkpoint event never refers to a sidecar that was only present in an
un-fsynced temporary file.

`recover_checkpoint` uses `EventStore._recover_command`, not the append path.
It reuses the same command digest, same-command-before-CAS ordering, ownership
check, generation check, sole reducer, and `CommandResult` contract, but its
only authoritative event-log mutation is the single atomic replacement
defined in section 15.5.

## 10. Replay, upcasting, and reducer

### 10.1 One reducer

`reduce_event(state, semantic_event)` is the only domain transition
implementation. It is used by:

- strict `materialize`;
- `inspect_prefix`;
- `_commit_command` candidate validation;
- cache reconstruction;
- checkpoint state-digest verification;
- recovery verification.

No command method directly mutates materialized state.

### 10.2 One-pass replay

Replay reads the event file in binary mode exactly once and updates:

- rolling event-file SHA-256;
- byte offset after each complete line;
- revision and head hash;
- ownership state and ownership-claim offset;
- compact event index;
- compact command index;
- workflow ID and generation;
- reducer state;
- replay statistics;
- first semantic or structural issue.

It does not first parse the whole file and then replay it again. Complexity is
`O(event count)` in time and
`O(event count + compact command/event indexes + live state)` in space. Index
entries retain only byte offset, byte length, and metadata required for chain,
idempotency, binding, and result reconstruction. They never retain full raw
event objects, arbitrary payload mappings, process excerpts, or decoded JSON
trees.

### 10.3 Replay result

`ReplayResult` contains:

- compact `state`;
- `head` with revision, event hash, event ID, and hash mode;
- `event_count`;
- `semantic_event_count`;
- `valid_prefix_bytes`;
- `event_file_prefix_sha256`;
- complete `event_file_bytes` and `event_file_sha256`, computed over all raw
  bytes even when semantic replay stops at an issue;
- compact `event_index`;
- `command_index`;
- ownership mode and ownership-claim position;
- `issue`, when replay cannot continue semantically;
- `stats.lines_read`, `stats.json_decodes`, and `stats.reducer_calls`.

`materialize` requires `issue is None`. `inspect_prefix` returns the same
state and issue without changing the file.

### 10.4 Issue classification

The following are distinct:

| Issue | Meaning | Automatic truncation |
|---|---|---|
| `CorruptEventLogError` | invalid UTF-8/JSON, revision gap, bad previous hash, missing required hash field, or hash mismatch | Never during materialize |
| `UnknownEventTypeError` | schema version is known but event type is not implemented | Never |
| `UnsupportedFutureSchemaError` | schema version is newer than 2.0 | Never |
| `DuplicateEventIdError` | an event ID occurs more than once | Never |
| `DuplicateCommittedCommandError` | a command ID was appended more than once with the same digest | Never |
| `CommandConflictError` | a command ID occurs with different digests | Never |
| `OwnershipClaimRequiredError` | the first schema 2.0 event is not `event_kernel.ownership.claimed` | Never |
| `MixedWriterError` | a schema 1.0 event occurs after `event_kernel.ownership.claimed` | Never |
| `IllegalTransitionError` | a structurally valid event violates reducer state | Never |

Unknown known-schema events, future-schema events, and mixed-writer events are
not treated as corrupt tails. They remain intact for operator diagnosis or a
newer implementation. A recovery command cannot authorize their removal.

### 10.5 Schema 1.0 lazy upcasting

Schema 1.0 lines before the ownership claim are converted to internal semantic
events in memory. Replay never writes, normalizes, reorders, or rehashes them.
Schema 1.0 after the claim is not upcast; it is a `MixedWriterError`.

The upcaster recognizes the legacy kernel event vocabulary:

- `workflow.created`;
- `phase.transitioned`;
- `hypothesis.added`;
- `policy.changed`;
- `dead_end.recorded`;
- `evidence.registered`;
- `finding.promoted`;
- `checkpoint.created`;
- `orchestrator.initialized`;
- `orchestrator.observations.updated`;
- `orchestrator.approval.recorded`;
- `orchestrator.approval.consumed`;
- `orchestrator.generation.started`;
- `orchestrator.stage.started`;
- `orchestrator.stage.completed`;
- `orchestrator.stage.blocked`;
- `orchestrator.interrupted`;
- `orchestrator.completed`.

The compact event-kernel projection extracts only information needed by Task
8:

- workflow ID;
- current generation;
- known evidence records and their legacy/schema 2.0 origin;
- legacy finding records, marked inactive and unverified;
- phase and stage-status summaries;
- digests of reconstructable stage results;
- legacy checkpoint hints.

It does not copy full `history` or full orchestrator stage-result payloads into
the event-kernel state.

## 11. Legacy hash modes

### 11.1 Hashed schema 1.0

Hashed schema 1.0 lines are verified using their original canonical hash,
revision, and previous-event hash. The only schema 2.0 event that may directly
follow the verified schema 1.0 head is
`event_kernel.ownership.claimed`; it uses the last schema 1.0 event hash as its
`previous_event_hash`.

### 11.2 Unbound schema 1.0

`LEGACY_UNBOUND` is a closed, manifest-pinned compatibility exception, not a
shape-based mode. The manifest describes the exact pre-claim legacy prefix.
On an unclaimed log that prefix is the complete file; on a claimed log it ends
immediately before `event_kernel.ownership.claimed`. The only accepted entry
is:

```json
{
  "slug": "mixed-smoke",
  "workflow_id": "wf-82e6092ac0b3",
  "byte_length": 2045,
  "line_count": 4,
  "file_sha256": "C89FFD15629D293D5B3BC026E361433B074D41725E8AA4EF10B8BE96CDE16BC7"
}
```

Replay classifies a candidate schema 1.0 prefix as `LEGACY_UNBOUND` only when
all five manifest fields match exactly:

1. the directory slug is `mixed-smoke`;
2. the workflow ID extracted from the `workflow.created` state is
   `wf-82e6092ac0b3`;
3. the exact candidate-prefix byte length is `2045`;
4. the candidate-prefix JSONL line count is `4`, counted as complete
   LF-terminated JSON object lines;
5. SHA-256 over the complete exact candidate-prefix bytes is
   `C89FFD15629D293D5B3BC026E361433B074D41725E8AA4EF10B8BE96CDE16BC7`.

The pinned file is a contiguous schema 1.0 prefix without:

- `event_hash`;
- `previous_event_hash`;
- `revision`.

The absence of chain fields and a recognized schema 1.0 shape are necessary
but not sufficient. After the exact manifest match, replay assigns virtual
revisions by file order and computes:

```text
legacy_head = "legacy-sha256:" + sha256(exact_prefix_bytes)
```

The first schema 2.0 append is `event_kernel.ownership.claimed` and uses this
synthetic value as `previous_event_hash`, thereby binding the exact legacy
bytes without rewriting them.

`LEGACY_UNBOUND` provides no cryptographic proof that its four pre-claim events
are authentic or untampered. The manifest is a frozen-fixture identity check,
not an integrity chain. Once present, the ownership claim binds that exact
manifest-matched prefix and protects only forward from the claim.

### 11.3 Removed hashes cannot masquerade as legacy

Any of these conditions are corruption:

- schema 2.0 event missing `event_hash`, `revision`, or
  `previous_event_hash`;
- schema 1.0 event with one or two chain fields present but another required
  chain field missing;
- a missing hash after the log has entered hashed mode;
- a hash mismatch.

Removing `event_hash` from a current hashed event therefore cannot cause the
line to be accepted as unbound legacy. Removing all chain fields from every
line of a formerly hashed log is also rejected: a fully de-chained log cannot
enter `LEGACY_UNBOUND` unless its slug, workflow ID, byte length, line count,
and exact candidate-prefix SHA-256 equal the pinned `mixed-smoke` manifest.
A fully de-chained formerly hashed log that does not match that one manifest
is rejected as corruption.

### 11.4 Frozen acceptance corpus

The 2026-07-16 acceptance baseline freezes these 17 fixture slugs:

1. `auto-pentest-14300db75251b4c0`
2. `auto-pentest-14300db75251b4c0-g2-b26f4c0e`
3. `auto-pentest-3f6bdcb1b355fc08`
4. `auto-pentest-57dc294aa4e12121`
5. `auto-pentest-57dc294aa4e12121-g2-178a2e4a`
6. `auto-pentest-7495cfdc433065ba`
7. `auto-pentest-9dc0e32640374db3`
8. `auto-pentest-f1e2c7da767e6e0f`
9. `crypto-platforms`
10. `gnnu-edu`
11. `gnnu-security`
12. `hejun-security`
13. `hzxy-security`
14. `jxnee-cors-validation-20260715`
15. `mcp-case`
16. `mixed-smoke`
17. `sjtu-src-20260714`

These 17 names are frozen baseline fixtures only. They are not a complete
inventory or allowlist of all workflow logs that exist now or may exist later.
The acceptance suite hashes each fixture before and after materialization. All
17 must remain byte-identical. `mixed-smoke` must match the exact manifest and
be classified as unbound; the other 16 must verify as hashed schema 1.0.
Every non-fixture log is classified by the same strict hashed rules, and no
additional unbound log is accepted without a future explicit design revision.

## 12. Evidence, verdict, and finding rules

### 12.1 Typed evidence attestation

`attest_evidence` appends one `event_kernel.evidence.attested` event. It is the
only schema 2.0 path by which evidence becomes eligible for a `VERIFIED`
verdict.

The typed input contains:

```python
@dataclass(frozen=True)
class EvidenceAttestation:
    evidence_id: str
    evidence_sha256: str
    source_ref_digest: str
    action_id: str
    attempt_id: str
    generation: int
    verifier_id: str
    verifier_version: str
    verification_policy_digest: str
    baseline: VerificationObservation
    control: VerificationObservation
    reproduction: ReproductionObservation
```

`VerificationObservation` contains a bounded result code, a canonical
procedure digest, and an observation digest. `ReproductionObservation`
additionally contains positive `run_count` and `success_count`, with
`success_count <= run_count`. Baseline, control, and reproduction are all
required and must have non-empty digests. `verifier_id`, `verifier_version`,
and `verification_policy_digest` are required, bounded, and persisted.

The event contains no raw artifact or unbounded verifier transcript. It
records the evidence content hash, source-reference digest, the three
verification records, and their shared generation/action/attempt context.

Rules:

1. `action_id` must exist in the same generation.
2. `attempt_id` must exist, belong to `action_id`, and be terminal.
3. A new schema 2.0 evidence ID is established by its first attestation. If
   the evidence ID already came from schema 1.0, the event attaches the typed
   attestation to that legacy record.
4. An evidence ID has one immutable generation/action/attempt binding. A
   non-idempotent second attestation that changes any identity, artifact,
   verifier, policy, baseline, control, or reproduction field is rejected.
   Corrections use a new evidence ID.
5. Legacy evidence is known for audit display but remains ineligible for
   `VERIFIED` until a schema 2.0
   `event_kernel.evidence.attested` event binds it.

### 12.2 Verdict state

Each verdict has:

- `verdict_id`;
- `subject_id`;
- `action_id`;
- optional `attempt_id` for non-verified statuses and required `attempt_id`
  for `VERIFIED`;
- status `LIKELY`, `VERIFIED`, `REFUTED`, or `INCONCLUSIVE`;
- exact ordered `evidence_ids`;
- `active`;
- optional `supersedes_verdict_id`;
- timestamp and generation.

There is at most one active verdict per `subject_id`.

Rules:

1. Evidence IDs in every verdict are ordered and duplicate-free.
2. A `VERIFIED` verdict has a non-empty evidence list.
3. Every evidence ID on a `VERIFIED` verdict has a typed attestation whose
   generation, `action_id`, and `attempt_id` exactly match the verdict.
4. A legacy evidence record without a schema 2.0 attestation cannot support a
   `VERIFIED` verdict.
5. If no active verdict exists, `supersedes_verdict_id` must be absent.
6. If an active verdict exists, a new verdict must explicitly name it.
7. The superseded verdict must be active and have the same `subject_id`.
8. Supersession marks the old verdict inactive.
9. A repeated `verdict_id` from a different command is rejected.
10. The command's generation must match the action's generation.

### 12.3 Finding creation

There is no standalone finding command in Task 8. `record_verdict` may carry
zero or one `finding` object in the same
`event_kernel.verdict.recorded` event.

A finding is created only when:

- the new verdict status is `VERIFIED`;
- the new verdict is active after applying supersession;
- all evidence requirements in section 12.2 pass;
- `finding.evidence_ids` is exactly equal to the verdict's ordered
  `evidence_ids`;
- finding and verdict reference the same `subject_id`, action, attempt, and
  generation;
- `finding_id` has never appeared anywhere in replay history;
- no finding has previously been attached to this `verdict_id`.

`finding_id` is globally unique within the workflow across active, inactive,
legacy, and superseded findings. Each verdict can create at most one finding.
`LIKELY`, `REFUTED`, and `INCONCLUSIVE` cannot create a finding.

When an active verified verdict is superseded, its finding remains in audit
history but becomes:

```json
{
  "active": false,
  "superseded_by_verdict_id": "verdict-new"
}
```

Only findings whose backing verdict is currently active and `VERIFIED` appear
in `state.active_findings`.

Legacy schema 1.0 findings are imported as inactive
`legacy_unverified=true`; they do not satisfy the active verified-finding
rule until a schema 2.0 verdict creates a new, globally unique finding backed
by fully attested evidence.

## 13. Process projection

Task 8 records process facts but does not launch or supervise processes.

### 13.1 Identity and transitions

Every process is indexed by both `attempt_id` and `process_id`.

```text
event_kernel.process.started -> event_kernel.process.output_recorded
event_kernel.process.started -> event_kernel.process.terminated
event_kernel.process.output_recorded -> event_kernel.process.output_recorded
event_kernel.process.output_recorded -> event_kernel.process.terminated
event_kernel.process.terminated -> terminal
```

`event_kernel.process.started` requires an existing started attempt. A process
event with a different attempt ID from the process's original attempt is
rejected. No process event may follow `event_kernel.process.terminated`, and
no new process may start after its attempt becomes terminal.

### 13.2 Output sequencing and counters

Each process has one sequence across stdout and stderr:

- first output sequence is `1`;
- each next sequence is exactly previous sequence plus one;
- sequence is generated by the kernel while holding `.workflow.lock` and is
  not supplied by the caller;
- `stdout_bytes_total`, `stderr_bytes_total`, and
  `combined_bytes_total` are absolute totals;
- totals never decrease;
- `combined_bytes_total == stdout_bytes_total + stderr_bytes_total`;
- `stdout_omitted_bytes_total`, `stderr_omitted_bytes_total`, and
  `combined_omitted_bytes_total` are absolute cumulative totals, never
  per-event deltas;
- omitted totals never decrease and
  `combined_omitted_bytes_total == stdout_omitted_bytes_total +
  stderr_omitted_bytes_total`;
- terminal byte totals and terminal omitted-byte totals are at least the last
  corresponding output totals.

Absolute byte and omitted-byte totals allow bounded output retention without
losing accounting.

### 13.3 Sensitive output prohibition

Raw process material is forbidden at the contract boundary. No process command
type contains raw byte, raw stdout, raw stderr, base64, unredacted chunk, or an
arbitrary output mapping field. The typed `ProcessOutput` contract accepts
only:

- an excerpt redacted by the upstream producer before the command is called;
- `redaction_applied=true`;
- the absolute counters;
- truncation state and absolute cumulative omitted-byte totals.

The upstream producer is responsible for redaction; `EventKernel` never
accepts raw output and is not a redaction service. As a second rejection layer,
the kernel rejects an already-redacted excerpt that still matches the bounded
known-marker set, including authorization bearer values, cookies, passwords,
API keys, private-key headers, and common token fields. This marker scan is an
additional deny check, not proof that arbitrary secrets were redacted.

The excerpt is limited to 4,096 UTF-8 bytes. The kernel calculates the
persisted digest from the accepted redacted excerpt; the caller cannot provide
or substitute that digest.

The projection retains only bounded redacted head/tail excerpts and the latest
absolute counters. It never reconstructs or stores raw sensitive output.

## 14. Memory outbox

Task 8 uses an event-derived outbox:

```text
event_kernel.memory.enqueued -> event_kernel.memory.applied
event_kernel.memory.enqueued -> event_kernel.memory.failed
event_kernel.memory.failed(retryable=true) -> event_kernel.memory.failed
event_kernel.memory.failed(retryable=true) -> event_kernel.memory.applied
event_kernel.memory.applied -> terminal
event_kernel.memory.failed(retryable=false) -> terminal
```

Each outbox entry contains:

- `outbox_id`;
- generation;
- projector name;
- dedupe key;
- bounded redacted payload;
- payload digest;
- status;
- absolute `delivery_attempt`;
- applied receipt digest or bounded failure metadata.

`delivery_attempt` is generated under the workflow lock.

Materialization and replay perform no SQLite imports, connections, writes, or
callbacks. They only update the in-memory projection.

Delivery semantics are explicitly **at least once**. A future dispatcher may
send the same entry more than once before
`event_kernel.memory.applied` is durably recorded. Therefore the sink contract
requires a unique constraint on `outbox_id` and idempotent application:
reapplying an existing `outbox_id` returns the original receipt and performs no
second sink mutation.

The kernel generates the ID under the workflow lock:

```text
outbox_identity = canonical_json({
  "workflow_id": workflow_id,
  "generation": generation,
  "projector": projector,
  "dedupe_key": dedupe_key,
  "payload_digest": sha256(canonical_payload)
})
outbox_id = "out-" + sha256(outbox_identity)
```

The dedupe scope is `(workflow_id, generation, projector, dedupe_key)`.
`enqueue_memory` checks that scope after same-command handling and before
append:

- same dedupe scope and same payload digest returns the original outbox item
  and original enqueue event without appending another event;
- same dedupe scope and a different payload digest raises
  `OutboxConflictError`;
- a new scope appends one `event_kernel.memory.enqueued` event.

The equal-payload dedupe result sets `deduplicated=true` and identifies the
original committed command/event. Because no new event is committed, the
incoming alias `command_id` is not reserved; retrying it with the same enqueue
intent deterministically dedupes again.

The future reconciler is deterministic. Given the same event log and explicit
reconciliation cutoff, it derives the same queue ordered by
`(enqueued_revision, outbox_id)`, submits one sink operation per selected item,
and records the next absolute `delivery_attempt` through a typed
`mark_memory_applied` or `mark_memory_failed` command. It uses no random queue
ordering and never mutates replay state outside events. Task 8 defines and
tests this projection/reconciliation contract but does not dispatch entries.

## 15. Checkpoint v2 and recovery

### 15.1 Checkpoint contents

A checkpoint v2 sidecar contains:

```json
{
  "schema_version": "2.0",
  "checkpoint_id": "cp-...",
  "workflow_id": "wf-...",
  "generation": 3,
  "bound_revision": 41,
  "bound_event_hash": "...",
  "bound_event_id": "evt-...",
  "binding_mode": "hashed",
  "state_digest": "...",
  "event_file_prefix_sha256": "...",
  "bound_prefix_bytes": 123456,
  "relative_path": "checkpoints/event-kernel/cp-....json",
  "created_at": "...",
  "state": {}
}
```

The `event_kernel.checkpoint.created` event additionally records the SHA-256
of the exact sidecar bytes as `checkpoint_file_sha256`, the sidecar relative
path, and the same binding fields.

The checkpoint state is the compact event-kernel projection. It excludes:

- event history;
- raw event envelopes;
- reconstructable orchestrator stage payloads;
- raw process output;
- SQLite state.

### 15.2 Checkpoint one-event commit protocol

Under `.workflow.lock`, `create_checkpoint`:

1. replays once and performs same-command, ownership, CAS, and generation
   validation;
2. reduces the compact state at the current pre-checkpoint head and constructs
   the final sidecar bytes;
3. writes those bytes to a sidecar temporary file in the checkpoint directory,
   flushes, and fsyncs the temporary file;
4. atomically renames the temporary file to the final relative path and fsyncs
   the checkpoint directory;
5. constructs and validates one
   `event_kernel.checkpoint.created` event referencing the already durable
   sidecar;
6. appends, flushes, and fsyncs that one event;
7. updates the derived cache.

This ordering permits only a harmless unreferenced final sidecar after a crash
between steps 4 and 6. Replay recognizes a checkpoint only through its event,
so an orphan sidecar is never authoritative and deterministic cleanup may
remove it. A committed checkpoint event cannot point only to an un-fsynced
temporary file. Checkpoint creation never appends a prepare event or a second
commit event.

### 15.3 State and file binding

Recovery verifies all of:

1. normalized relative path remains under the workflow directory;
2. checkpoint sidecar SHA-256 matches `checkpoint_file_sha256`;
3. a matching `event_kernel.checkpoint.created` event exists in the maximum
   semantic prefix and references the same checkpoint ID, sidecar hash, and
   binding fields;
4. workflow ID and generation match;
5. replay reaches `bound_revision`;
6. event ID and event hash at that revision match;
7. exact event bytes through `bound_prefix_bytes` match
   `event_file_prefix_sha256`;
8. reduced compact state matches `state_digest`;
9. the checkpoint event's end offset is at or before the maximum semantic
   prefix boundary;
10. the first issue begins strictly after the checkpoint event and is an
    authorized truncatable corruption.

The checkpoint authorizes removal of an invalid tail; it does not request a
rollback to the checkpoint. Valid semantic events after the checkpoint are
retained.

### 15.4 Recovery authorization

Only these tail conditions may be explicitly recovered when their first issue
offset is strictly after the checkpoint event:

- incomplete final line;
- invalid UTF-8;
- invalid JSON;
- revision/hash-chain corruption.

Recovery is denied for:

- unknown event type;
- future schema version;
- duplicate event ID;
- duplicate or conflicting command ID;
- an ownership claim error or `MixedWriterError`;
- illegal domain transition;
- corruption at or before the checkpoint event's end offset;
- a checkpoint whose current binding mode is `legacy_unbound`;
- any legacy schema 1.0 checkpoint lacking checkpoint-v2 binding fields.

Unknown future events are never automatically truncated.

### 15.5 Single-replace recovery transaction

The typed recovery request is:

```python
@dataclass(frozen=True)
class RecoveryRequest:
    checkpoint_id: str
    expected_source_file_bytes: int
    expected_source_file_sha256: str
```

The source byte length and SHA-256 come from `inspect_prefix`. They are part of
the command digest and prevent a changed corrupt tail from passing CAS merely
because the maximum semantic head revision/hash stayed unchanged.

Under `.workflow.lock`:

1. load the selected checkpoint sidecar, then replay the event file exactly
   once to the **maximum semantic prefix** while capturing the checkpoint-bound
   state digest and the first issue;
2. apply same-command idempotency/conflict handling, ownership validation,
   two-part head CAS, full-source byte-length/SHA-256 CAS, and generation
   validation;
3. verify every checkpoint binding rule in section 15.3 and verify that the
   issue begins after the checkpoint event;
4. identify the exact retained prefix as all valid semantic event bytes before
   the issue, including every valid event after the checkpoint;
5. create an idempotent, complete backup of the original event file at the
   source-hash-derived recovery path. The backup contains every original byte.
   A new backup is written through a temporary file, flushed, fsynced,
   atomically renamed, and followed by a recovery-directory fsync. If the
   final backup already exists, its byte length and SHA-256 must equal the
   current source file or recovery fails; the existing file is fsynced and
   reused;
6. construct and reduce one `event_kernel.recovery.performed` event whose
   revision and `previous_event_hash` continue from the head of the maximum
   semantic prefix, not from the checkpoint head;
7. write `exact_retained_prefix_bytes + canonical_recovery_event_line` to an
   event-log temporary file in the same directory, flush it, and fsync it;
8. perform exactly one atomic replace of `workflow.events.jsonl` with that
   temporary file, then fsync the workflow directory;
9. rebuild the derived cache from the already reduced maximum-prefix state
   plus the recovery event, without a second replay.

There is no visible prefix-only state and no append after replacement. The
single replacement contains the one recovery event.

The recovery event records:

- `checkpoint_id`, checkpoint-event ID, and
  `checkpoint_event_end_offset`;
- issue type and `issue_offset`;
- `source_file_bytes` and `source_file_sha256`;
- `retained_prefix_bytes` and `retained_prefix_sha256`;
- `discarded_tail_bytes` and `discarded_tail_sha256`;
- backup relative path, byte length, and SHA-256;
- the recovered head revision/hash and recovery command metadata.

Offsets and byte counts are measured against the exact original event-file
bytes. Hashes are SHA-256 over the exact corresponding byte ranges.

Crash-injection acceptance points are fixed:

1. after backup file fsync and before backup rename;
2. after durable backup rename and before event-log temp creation;
3. after event-log temp fsync and before the one replace;
4. immediately after replace and before workflow-directory fsync;
5. after workflow-directory fsync and before cache replacement.

After restart, each point yields either the byte-identical original log or the
complete recovered log ending in exactly one
`event_kernel.recovery.performed` event. Retrying the same command never
duplicates the event or backup. Temporary files and unreferenced artifacts are
cleaned deterministically only after their hashes are checked.

A legacy-unbound checkpoint may provide a resume hint but cannot authorize any
destructive recovery. Once a schema 2.0 event has cryptographically anchored
the exact unbound prefix through `event_kernel.ownership.claimed`, a later
`event_kernel.checkpoint.created` checkpoint from the hashed head may be
recovery-authoritative.

## 16. Derived cache and performance

### 16.1 Cache format

`workflow.event-kernel.json` contains:

- schema version;
- workflow ID and generation;
- source revision, event hash, event ID, file size, and file modification time;
- compact state digest;
- compact state.

It excludes event history and full reconstructable stage payloads.

The cache is not authoritative:

- commands always replay the event log;
- recovery never trusts the cache;
- strict materialization verifies the event log;
- cache failure never invalidates a committed event.

### 16.2 Complexity limits

Replay time is `O(event count)`. Peak replay space is
`O(event count + compact command/event indexes + live state)`. The event and
command indexes store only offsets, lengths, hashes/digests, IDs, revision,
event/command type, and the minimal bounded metadata needed to reconstruct a
committed result. Full decoded events and payloads are released after each
line is reduced.

Acceptance benchmarks two separate deterministic fixtures:

1. **compact fixture:** exactly 10,000 total events, beginning with
   `event_kernel.ownership.claimed`, with small bounded payloads;
2. **excerpt fixture:** minimal claim/action/attempt/process setup plus exactly
   10,000 `event_kernel.process.output_recorded` events, each containing an
   accepted redacted excerpt of exactly 4,096 UTF-8 bytes.

For each fixture, the report records:

- Windows version/build, Python version and architecture, CPU model and logical
  core count, installed RAM, filesystem type, repository volume, and commit;
- fixture byte length, event count, and SHA-256;
- three untimed warmup runs followed by ten measured runs in fresh processes;
- replay and append median and p95 wall time;
- absolute peak RSS/Windows peak working set and delta from the post-startup
  pre-replay baseline;
- JSON decodes, reducer calls, bytes read, and replay-call count.

Acceptance gates on the required Windows test environment are:

- compact replay: median at most 5.0 seconds, p95 at most 6.5 seconds, and peak
  RSS delta at most 64 MiB;
- append after the compact fixture: one replay pass, median at most 6.0
  seconds, p95 at most 8.0 seconds;
- excerpt replay: median at most 15.0 seconds, p95 at most 20.0 seconds, and
  peak RSS delta at most 128 MiB;
- append after the excerpt fixture: one replay pass, median at most 16.0
  seconds, p95 at most 22.0 seconds;
- strict replay JSON-decode and reducer-call counts equal the exact line/event
  counts for each fixture; append decodes each existing line exactly once and
  performs exactly one additional reducer call for its candidate event;
- `_commit_command` and `_recover_command` never invoke replay twice;
- cache and checkpoint output contain no `history`, raw `events`, full
  `stage_results`, raw process output, or per-event process excerpts;
- for the excerpt fixture, both cache and checkpoint remain below 512 KiB.

Concurrency benchmarks also record lock acquisition count, maximum observed
queue depth, and lock-wait median/p95/maximum for the 32-thread and 8-process
runs. Every contender must acquire or receive its deterministic idempotent
result, the queue must drain, and each run must complete within 60 seconds.
These thresholds are acceptance gates, not production telemetry.

## 17. Concurrency model

All mutation uses the existing `WorkflowFileLock` on `.workflow.lock`. The
baseline fix `932b601` guarantees stable Windows path identity for thread and
process contenders.

Acceptance covers:

1. one ownership claim before mutation races begin;
2. 32 threads committing unique commands with CAS retry loops;
3. 8 processes committing unique commands with CAS retry loops;
4. 32 threads submitting the same command ID and digest;
5. 8 processes submitting the same command ID and digest;
6. one appended event and one budget charge for the same command;
7. command-ID conflict when the same ID carries a different digest;
8. ABA rejection when revision is unchanged but head hash differs;
9. an injected schema 1.0 append after the claim producing
   `MixedWriterError`;
10. lock queue depth and wait-time reporting without starvation.

CAS retries reuse the original command ID and semantic payload. Only the
expected revision and head hash are refreshed, so the command digest remains
stable.

## 18. Error contract

The public exception hierarchy is:

```text
EventKernelError
├── WorkflowNotFoundError
├── InvalidCommandError
├── ConcurrencyConflictError
├── CommandConflictError
├── DuplicateCommittedCommandError
├── WorkflowAlreadyClaimedError
├── OwnershipClaimRequiredError
├── MixedWriterError
├── CorruptEventLogError
├── UnknownEventTypeError
├── UnsupportedFutureSchemaError
├── DuplicateEventIdError
├── IllegalTransitionError
├── EvidenceAttestationError
├── OutboxConflictError
├── SensitiveOutputRejectedError
├── CheckpointBindingError
└── RecoveryNotAuthorizedError
```

Each exception exposes:

- stable `code`;
- bounded `message`;
- slug;
- revision and event ID when known;
- no raw sensitive process output.

## 19. Independent acceptance suite

All new tests live under:

```text
tests/acceptance/event_kernel/
```

They do not modify or extend `tests/test_workflow_kernel.py` or orchestrator
tests.

Required test modules:

| Module | Required coverage |
|---|---|
| `test_contracts_envelope.py` | canonical JSON, digest exclusions, schema 2.0 fields, required `event_kernel.` namespace, generation IDs, invalid payloads |
| `test_ownership_cutover.py` | typed claim as first schema 2.0 event, claim idempotency, legacy read-only ignore behavior, post-claim `MixedWriterError`, Task 9/10 gate contract |
| `test_replay_upcast_reducer.py` | one reducer, pre-claim schema 1.0 upcast, known/unknown/future distinction, compact indexes, duplicate IDs and commands |
| `test_command_commit.py` | commit order, same-command priority, two-part CAS, cache-after-fsync, ABA, one event per command |
| `test_action_attempt_lifecycle.py` | action/attempt separation, locked numbering, transitions, deferred budget, all processes terminal before attempt terminal |
| `test_evidence_verdict_finding.py` | typed attestation fields, legacy-attestation requirement, non-empty duplicate-free verified evidence, exact generation/action/attempt, finding uniqueness and one-per-verdict |
| `test_process_projection.py` | attempt/process binding, sequence, absolute byte and omitted-byte totals, upstream-redaction contract, known-marker rejection |
| `test_memory_outbox.py` | at-least-once contract, canonical outbox ID, dedupe equality/conflict, sink idempotency, deterministic reconciliation, no SQLite side effects |
| `test_checkpoint_recovery.py` | checkpoint one-event sidecar protocol, checkpoint-v2 binding, full-source hash/byte CAS, maximum-prefix preservation, single-replace recovery, offset/hash/byte metadata, crash injection, unknown future preservation |
| `test_performance.py` | separate compact and 4,096-byte-excerpt 10,000-event benchmarks, one replay per command, peak RSS, environment/warmup/median/p95/lock queue report, bounded cache/checkpoint |
| `test_compatibility_gates.py` | 17 frozen fixtures unchanged, exact mixed-smoke pre-claim-prefix manifest/hash before and after a claim on a copy, full de-chain rejection, thread/process races, unchanged legacy four-file hashes |

## 20. Acceptance criteria

Task 8 is accepted only when:

- existing `models.py`, `kernel.py`, `locking.py`, and
  `core/workflow/__init__.py` are unchanged from the required baseline;
- Task 8 imports are direct from the independent
  `core.workflow.event_kernel` subpackage and no production entry point is
  connected;
- no arbitrary event-recording API exists;
- `claim_workflow` writes the first schema 2.0 event as
  `event_kernel.ownership.claimed`;
- every schema 2.0 event type begins with `event_kernel.`, and checkpoint
  creation uses exactly `event_kernel.checkpoint.created`;
- after the claim, schema 1.0 input raises `MixedWriterError`;
- unchanged legacy materialization can ignore namespaced events for read-only
  projection;
- Task 9/10 integration is blocked until legacy mutation, checkpoint, and
  resume/handoff routes are gated for the workflow;
- action IDs visibly include generation;
- attempt numbers are generated under lock;
- deferred actions spend zero attempt budget;
- every process is terminal before its attempt-terminal event, with
  `event_kernel.process.terminated` persisted first;
- same-command replay precedes CAS and a first-time command commits exactly one
  event;
- revision and head hash both participate in CAS;
- ABA is rejected;
- the sole reducer powers materialization and semantic-prefix replay;
- unknown event types and future schemas are reported distinctly;
- duplicate event IDs, duplicate committed commands, command conflicts, and
  illegal transitions are rejected;
- typed evidence attestation persists verifier ID/version, policy digest, and
  baseline/control/reproduction records;
- a `VERIFIED` verdict has non-empty duplicate-free evidence whose generation,
  action, and attempt exactly match the verdict;
- legacy evidence cannot support `VERIFIED` without a schema 2.0 attestation;
- only an active `VERIFIED` verdict can create an active finding;
- finding evidence exactly matches verdict evidence;
- finding IDs are globally unique and each verdict creates at most one finding;
- process output uses exact sequence, absolute byte totals, and absolute
  cumulative omitted-byte totals;
- raw process fields are absent, upstream redaction is required, and known
  secret markers are rejected as a second layer;
- raw sensitive output is absent from events, cache, checkpoints, and errors;
- memory materialization performs no SQLite write;
- outbox delivery is at least once, the sink is idempotent on unique
  `outbox_id`, canonical IDs are deterministic, equal dedupe/payload returns
  the original item, different payload conflicts, and reconciliation order is
  deterministic;
- checkpoint creation makes its sidecar durable and appends exactly one event;
- checkpoint v2 verifies revision, event hash, event ID, state digest, event
  file hash, sidecar hash, and relative path;
- legacy-unbound checkpoints are hints only;
- unknown future events are never automatically truncated;
- recovery retains the maximum semantic prefix, including valid events after
  the authorizing checkpoint;
- recovery rejects a changed source byte length or full-file SHA-256 even when
  the semantic head revision/hash is unchanged;
- recovery creates a complete idempotent fsynced backup, records exact
  offsets/hashes/byte counts, and performs one replace containing exactly one
  `event_kernel.recovery.performed` event;
- every recovery crash-injection point leaves either the original log or the
  complete recovered log, never a prefix-only log;
- all 17 frozen schema 1.0 fixture logs remain byte-identical, without
  implying that they enumerate all current logs;
- `mixed-smoke` matches workflow ID `wf-82e6092ac0b3`, 2045 bytes, 4 lines,
  and SHA-256
  `C89FFD15629D293D5B3BC026E361433B074D41725E8AA4EF10B8BE96CDE16BC7`;
- after a claim is appended to a copy of `mixed-smoke`, replay still matches
  those exact first 2045 bytes as the pinned unbound prefix;
- `LEGACY_UNBOUND` is acknowledged to provide no integrity proof;
- removing some or all hashes from a current hashed log cannot classify it as
  legacy unbound;
- replay is `O(event count)` time and
  `O(event count + compact command/event indexes + live state)` space;
- compact indexes contain only offsets, lengths, and necessary metadata;
- separate compact and 4,096-byte-excerpt 10,000-event time/peak-RSS gates
  pass with recorded environment, warmups, median/p95, and lock-queue metrics;
- append and recovery replay at most once;
- 32-thread and 8-process tests pass;
- the legacy workflow-kernel tests and the full Hunter suite pass.

## 21. Expected result

After Task 8, Hunter has a standalone event-kernel foundation that can be
integrated by later tasks without inheriting the old plan's ambiguous action,
attempt, ownership, idempotency, replay, evidence, finding, memory, process, or
recovery semantics. Task 8 itself leaves production entry points and the four
legacy workflow files untouched. Once a workflow is explicitly claimed, every
new mutation is typed, namespaced, generation-aware, CAS-protected,
hash-chained, replayable, and acceptance-tested, and no legacy writer may
resume mutation.
