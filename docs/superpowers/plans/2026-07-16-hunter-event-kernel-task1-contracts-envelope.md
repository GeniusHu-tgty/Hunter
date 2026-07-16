# Hunter Event Kernel Stage 1 Contracts and Envelope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze and verify the independent event-kernel public contracts, exact command/event vocabulary, typed error surface, strict canonical JSON primitives, deterministic digests and IDs, schema 2.0 envelope construction/validation, and explicit package exports required by Stage 1.

**Architecture:** Stage 1 is an isolated foundation under `core/workflow/event_kernel/`; it does not connect a production entry point or mutate legacy workflow code. Two workers may execute disjoint TDD streams for contracts and envelope/errors, after which one integrator creates the explicit package facade, runs all gates, and resolves two independent reviews.

**Tech Stack:** Python 3, frozen/slotted `dataclasses`, `Enum`, `hashlib.sha256`, strict standard-library `json`, `pytest`, PowerShell, Git.

---

## 1. Authority, Evidence Rule, and Current State

This plan implements only Stage 1 of:

- authoritative design: `docs/superpowers/specs/2026-07-16-hunter-event-kernel-hardening-design.md` at `d56f2d8`;
- sequencing roadmap: `docs/superpowers/plans/2026-07-16-hunter-event-kernel-roadmap.md` at `7ec9479`.

The worktree already contains in-progress, untracked Stage 1 candidates. At plan-writing time they include:

```text
core/workflow/event_kernel/contracts.py
core/workflow/event_kernel/envelope.py
core/workflow/event_kernel/errors.py
tests/acceptance/event_kernel/__init__.py
tests/acceptance/event_kernel/test_contracts_envelope.py
tests/acceptance/event_kernel/test_contracts_models.py
tests/acceptance/event_kernel/test_public_api.py
```

`core/workflow/event_kernel/__init__.py` may still be absent when execution begins. Re-inventory the worktree before acting because concurrent workers may have progressed.

Existing source, existing tests, worker statements, historical counts such as `63 passed`, `19 passed`, or `770 passed`, and a test that was not observed RED for its intended defect are **not Stage 1 validation evidence**. Preserve useful work, but put every requirement through a fresh focused RED, implementation, GREEN, integration, and review cycle. Do not delete and rewrite another worker's file merely to manufacture RED.

## 2. Hard Boundaries

### Allowed Stage 1 implementation paths

```text
core/workflow/event_kernel/__init__.py
core/workflow/event_kernel/contracts.py
core/workflow/event_kernel/envelope.py
core/workflow/event_kernel/errors.py
tests/acceptance/event_kernel/__init__.py
tests/acceptance/event_kernel/test_contracts_envelope.py
tests/acceptance/event_kernel/test_contracts_models.py
tests/acceptance/event_kernel/test_public_api.py
```

### Forbidden paths and behavior

Do not modify:

```text
core/workflow/models.py
core/workflow/kernel.py
core/workflow/locking.py
core/workflow/__init__.py
sessions/
```

Also do not:

- modify a production entry point;
- import the new package from legacy workflow code;
- expose `record_event`, `append_event`, `write_event`, `commit_event`, a generic event type argument, or a generic event payload API;
- implement replay, store/CAS, reducer transitions, process launching, SQLite delivery, checkpoint I/O, or recovery I/O in Stage 1;
- stage with `git add -A` or `git add .`;
- delete or stage pre-existing runtime artifacts under `sessions/browser/` or `sessions/scans/`.

Stateful invariants that require replay, lock ownership, or reducer state are represented by typed contracts now and enforced in their owning later stage. Stage 1 enforces all local shape, identity, bounds, serialization, and cross-field invariants that do not require workflow history.

## 3. Exact File Map and Parallel Ownership

| Owner | Path | Responsibility |
|---|---|---|
| Worker A | `core/workflow/event_kernel/errors.py` | Exact base error plus 18 direct public leaf errors, codes, bounded UTF-8-safe messages, location metadata, issue conversion |
| Worker A | `core/workflow/event_kernel/envelope.py` | Canonical JSON, command/event digests, generated IDs, 19 event names, schema 2.0 construction and validation |
| Worker A | `tests/acceptance/event_kernel/test_contracts_envelope.py` | RED/GREEN tests for errors, serialization, digests, IDs, envelope, adversarial inputs |
| Worker B | `core/workflow/event_kernel/contracts.py` | Exact enums, command DTOs, projection DTOs, replay/result DTOs, local validation and snapshots |
| Worker B | `tests/acceptance/event_kernel/test_contracts_models.py` | RED/GREEN tests for exact fields, enum values, type hints, DTO invariants, process/outbox boundaries |
| Integrator | `core/workflow/event_kernel/__init__.py` | Explicit re-exports only after Workers A and B are green |
| Integrator | `tests/acceptance/event_kernel/test_public_api.py` | Exact export identity and forbidden generic-write API tests |
| Integrator | `tests/acceptance/event_kernel/__init__.py` | Acceptance package marker only; no fixtures or side effects |

Workers A and B may run concurrently because their write sets are disjoint. The integrator must wait for both, re-read their current files, and never overwrite either worker's edits. Reviewers are read-only until the owning worker receives a concrete finding.

## 4. Frozen Public Surface

The authoritative design fixes the semantics, required typed concepts, error
classes, event names, and safety invariants. It intentionally does **not** fix
three literal implementation details: error-code strings/message length,
projection/index class names and fields, or the package export tuple. Sections
4.3, 4.5, and 4.8 therefore record explicit **Stage 1 design decisions**. They
are normative decisions made here so tests and later stages have one stable
surface; they must not be cited as text dictated by the authoritative design.

### 4.1 Exact command/event vocabulary

`CommandType` and `EventType` are ordered `str, Enum` classes. Their zip is the authoritative one-to-one mapping; no 20th value, alias, or alternate spelling is accepted.

| `CommandType` member | Value | `EventType` member | Value |
|---|---|---|---|
| `CLAIM_WORKFLOW` | `claim_workflow` | `OWNERSHIP_CLAIMED` | `event_kernel.ownership.claimed` |
| `PROPOSE_ACTION` | `propose_action` | `ACTION_PROPOSED` | `event_kernel.action.proposed` |
| `MERGE_ACTION` | `merge_action` | `ACTION_MERGED` | `event_kernel.action.merged` |
| `DEFER_ACTION` | `defer_action` | `ACTION_DEFERRED` | `event_kernel.action.deferred` |
| `BLOCK_ACTION` | `block_action` | `ACTION_BLOCKED` | `event_kernel.action.blocked` |
| `START_ATTEMPT` | `start_attempt` | `ATTEMPT_STARTED` | `event_kernel.attempt.started` |
| `COMPLETE_ATTEMPT` | `complete_attempt` | `ATTEMPT_COMPLETED` | `event_kernel.attempt.completed` |
| `BLOCK_ATTEMPT` | `block_attempt` | `ATTEMPT_BLOCKED` | `event_kernel.attempt.blocked` |
| `CANCEL_ATTEMPT` | `cancel_attempt` | `ATTEMPT_CANCELLED` | `event_kernel.attempt.cancelled` |
| `ATTEST_EVIDENCE` | `attest_evidence` | `EVIDENCE_ATTESTED` | `event_kernel.evidence.attested` |
| `RECORD_VERDICT` | `record_verdict` | `VERDICT_RECORDED` | `event_kernel.verdict.recorded` |
| `START_PROCESS` | `start_process` | `PROCESS_STARTED` | `event_kernel.process.started` |
| `RECORD_PROCESS_OUTPUT` | `record_process_output` | `PROCESS_OUTPUT_RECORDED` | `event_kernel.process.output_recorded` |
| `TERMINATE_PROCESS` | `terminate_process` | `PROCESS_TERMINATED` | `event_kernel.process.terminated` |
| `ENQUEUE_MEMORY` | `enqueue_memory` | `MEMORY_ENQUEUED` | `event_kernel.memory.enqueued` |
| `MARK_MEMORY_APPLIED` | `mark_memory_applied` | `MEMORY_APPLIED` | `event_kernel.memory.applied` |
| `MARK_MEMORY_FAILED` | `mark_memory_failed` | `MEMORY_FAILED` | `event_kernel.memory.failed` |
| `CREATE_CHECKPOINT` | `create_checkpoint` | `CHECKPOINT_CREATED` | `event_kernel.checkpoint.created` |
| `RECOVER_CHECKPOINT` | `recover_checkpoint` | `RECOVERY_PERFORMED` | `event_kernel.recovery.performed` |

`SCHEMA2_EVENT_TYPES` is exactly the set of the 19 `EventType` values. Every value starts with `event_kernel.`. The ownership claim is the only legal first schema 2.0 event, although replay enforcement belongs to Stage 2/3.

### 4.2 Exact state enums

```text
OwnershipState: UNCLAIMED_LEGACY=unclaimed_legacy, EVENT_KERNEL_OWNED=event_kernel_owned
ActionState: PROPOSED=proposed, DEFERRED=deferred, BLOCKED=blocked,
             RUNNING=running, RETRYABLE=retryable, COMPLETED=completed
AttemptState: STARTED=started, COMPLETED=completed, BLOCKED=blocked, CANCELLED=cancelled
VerdictStatus: LIKELY=likely, VERIFIED=verified, REFUTED=refuted, INCONCLUSIVE=inconclusive
ProcessState: STARTED=started, TERMINATED=terminated
ProcessStream: STDOUT=stdout, STDERR=stderr
OutboxState: ENQUEUED=enqueued, APPLIED=applied, FAILED=failed
EvidenceOrigin: LEGACY=legacy, SCHEMA_2=schema_2
HashMode: EMPTY=empty, HASHED=hashed, LEGACY_UNBOUND=legacy_unbound
ReplayIssueKind: INCOMPLETE_FINAL_LINE=incomplete_final_line, INVALID_UTF8=invalid_utf8,
                 INVALID_JSON=invalid_json, CORRUPT_CHAIN=corrupt_chain,
                 UNKNOWN_EVENT=unknown_event, FUTURE_SCHEMA=future_schema,
                 DUPLICATE_EVENT=duplicate_event, DUPLICATE_COMMAND=duplicate_command,
                 COMMAND_CONFLICT=command_conflict,
                 OWNERSHIP_CLAIM_REQUIRED=ownership_claim_required,
                 MIXED_WRITER=mixed_writer, ILLEGAL_TRANSITION=illegal_transition
```

`ProcessStream` is a Stage 1 contract decision used by `ProcessOutput.stream`;
the boundary accepts only that enum or its exact `stdout`/`stderr` values.
Arbitrary stream names are rejected.

### 4.3 Stage 1 design decision: exact public error codes and message bound

The design requires the base and these 18 direct leaf classes but does not
prescribe their literal code strings or a numeric message limit. Stage 1
chooses the following current snake_case codes and a 512-character message
limit, then freezes both in exact tests. All 18 classes are direct subclasses
of `EventKernelError`; none subclasses another leaf.

| Class | Stable `code` |
|---|---|
| `EventKernelError` | `event_kernel_error` |
| `WorkflowNotFoundError` | `workflow_not_found` |
| `InvalidCommandError` | `invalid_command` |
| `ConcurrencyConflictError` | `concurrency_conflict` |
| `CommandConflictError` | `command_conflict` |
| `DuplicateCommittedCommandError` | `duplicate_committed_command` |
| `WorkflowAlreadyClaimedError` | `workflow_already_claimed` |
| `OwnershipClaimRequiredError` | `ownership_claim_required` |
| `MixedWriterError` | `mixed_writer` |
| `CorruptEventLogError` | `corrupt_event_log` |
| `UnknownEventTypeError` | `unknown_event_type` |
| `UnsupportedFutureSchemaError` | `unsupported_future_schema` |
| `DuplicateEventIdError` | `duplicate_event_id` |
| `IllegalTransitionError` | `illegal_transition` |
| `EvidenceAttestationError` | `evidence_attestation` |
| `OutboxConflictError` | `outbox_conflict` |
| `SensitiveOutputRejectedError` | `sensitive_output_rejected` |
| `CheckpointBindingError` | `checkpoint_binding` |
| `RecoveryNotAuthorizedError` | `recovery_not_authorized` |

Every error exposes `code`, a maximum-512-character UTF-8-encodable `message`, `slug`, optional `revision`, and optional `event_id`. Invalid surrogates must be escaped before storage; messages and exceptions must never include raw process output.

`issue_to_error` maps incomplete line, invalid UTF-8, invalid JSON, chain corruption, and unknown issue kinds to `CorruptEventLogError`; all other `ReplayIssueKind` values map to their exact corresponding leaf class.

### 4.4 Exact command-input and result contracts

All data contracts are `@dataclass(frozen=True, slots=True)`. Mutable caller input is validated as strict native JSON and recursively snapshotted before storage. Tuple fields use immutable independent defaults. Cross-workflow history checks remain reducer responsibilities.

| Contract | Exact fields in order |
|---|---|
| `CommandMeta` | `command_id`, `expected_revision`, `expected_event_hash`, `generation`, `correlation_id`, `causation_id=None`, `actor="hunter_tools"` |
| `WorkflowOwnershipClaim` | `cutover_id`, `owner_version`, `legacy_gate_digest` |
| `ActionProposal` | `tool`, `target`, `kind`, `arguments`, `sources`, `strategy_ids`, `labels`, `expected_evidence`, `priority="P2"` |
| `ActionMerge` | `action_id`, `sources`, `strategy_ids`, `labels`, `expected_evidence`, `priority=None` |
| `ActionDecision` | `action_id`, `reason` |
| `AttemptStart` | `action_id`, `executor`, `budget_class` |
| `AttemptComplete` | `attempt_id`, `result_code`, `result_digest` |
| `AttemptBlock` | `attempt_id`, `reason` |
| `AttemptCancel` | `attempt_id`, `reason` |
| `VerificationObservation` | `result_code`, `procedure_digest`, `observation_digest` |
| `ReproductionObservation` | `result_code`, `procedure_digest`, `observation_digest`, `run_count`, `success_count` |
| `EvidenceAttestation` | `evidence_id`, `evidence_sha256`, `source_ref_digest`, `action_id`, `attempt_id`, `generation`, `verifier_id`, `verifier_version`, `verification_policy_digest`, `baseline`, `control`, `reproduction` |
| `FindingCandidate` | `finding_id`, `subject_id`, `action_id`, `attempt_id`, `generation`, `evidence_ids` |
| `VerdictRecord` | `verdict_id`, `subject_id`, `action_id`, `status`, `generation`, `evidence_ids`, `attempt_id=None`, `supersedes_verdict_id=None`, `finding=None` |
| `ProcessStart` | `attempt_id`, `process_name=""` |
| `ProcessOutput` | `process_id`, `attempt_id`, `stream`, `redacted_excerpt`, `redaction_applied`, `truncated`, `stdout_bytes_total`, `stderr_bytes_total`, `combined_bytes_total`, `stdout_omitted_bytes_total`, `stderr_omitted_bytes_total`, `combined_omitted_bytes_total` |
| `ProcessTerminal` | `process_id`, `attempt_id`, `exit_code`, `termination_reason`, `stdout_bytes_total`, `stderr_bytes_total`, `combined_bytes_total`, `stdout_omitted_bytes_total`, `stderr_omitted_bytes_total`, `combined_omitted_bytes_total` |
| `MemoryEnqueue` | `projector`, `dedupe_key`, `payload` |
| `MemoryApplied` | `outbox_id`, `receipt_digest` |
| `MemoryFailed` | `outbox_id`, `error_code`, `failure_digest`, `retryable` |
| `RecoveryRequest` | `checkpoint_id`, `expected_source_file_bytes`, `expected_source_file_sha256` |
| `Head` | `revision`, `event_hash`, `event_id`, `hash_mode` |
| `ReplayIssue` | `kind`, `message`, `offset`, `revision=None`, `event_id=None`, `line_number=None` |
| `ReplayStats` | `lines_read=0`, `json_decodes=0`, `reducer_calls=0` |
| `ReplayResult` | `state`, `head`, `event_count`, `semantic_event_count`, `valid_prefix_bytes`, `event_file_prefix_sha256`, `event_file_bytes`, `event_file_sha256`, `ownership`, `event_index`, `command_index`, `ownership_claim_offset=None`, `issue=None`, `stats` |
| `CommandResult` | `command_id`, `event_id`, `event_type`, `revision`, `event_hash`, `generation`, `cache_updated=True`, `idempotent=False`, `deduplicated=False`, `original_command_id=None`, `original_event_id=None`, `payload` |

Required local invariants include:

- `ReproductionObservation.run_count > 0`, `success_count > 0`, and `success_count <= run_count`;
- `VERIFIED` requires `attempt_id` and non-empty, ordered, duplicate-free evidence;
- non-`VERIFIED` cannot carry a finding;
- a finding exactly matches verdict subject/action/attempt/generation/evidence;
- `ProcessOutput.stream` is `stdout` or `stderr`, excerpt length is at most 4,096 UTF-8 bytes, `redaction_applied is True`, counters are non-negative absolutes, and combined totals equal component totals;
- process models expose no raw/base64/arbitrary output field and reject known secret markers;
- `MemoryEnqueue.payload` is bounded, strict native JSON and detached from caller mutation;
- `RecoveryRequest` uses a non-negative source byte count and a canonical lowercase SHA-256;
- `CommandResult` idempotent/deduplicated/original identity combinations are internally consistent.

### 4.5 Stage 1 design decision: exact projection and index contracts

The design requires typed compact projection and index contracts but does not
name their concrete Python classes or fields. Stage 1 chooses the models below
after Worker B's final GREEN implementation and freezes their literal field
order. These are plan decisions, not quotations from the design. They make
`EventKernelState` and `ReplayResult` fully typed before Stage 2; `typing.Any`
is forbidden from every public type hint in `ReplayResult` and its direct
index/state graph.

| Contract | Exact fields in order |
|---|---|
| `FrozenJsonArray` | `values` |
| `FrozenJsonObject` | `items` |
| `LogicalActionRecord` | `action_id`, `action_key`, `generation`, `tool`, `target`, `arguments`, `kind`, `sources`, `strategy_ids`, `labels`, `expected_evidence`, `priority`, `state`, `attempt_ids`, `active_attempt_id` |
| `ExecutionAttemptRecord` | `attempt_id`, `action_id`, `generation`, `attempt_no`, `executor`, `budget_class`, `state`, `process_ids`, `result_code`, `result_digest`, `terminal_reason` |
| `EvidenceRecord` | `evidence_id`, `origin`, `attestation` |
| `VerdictStateRecord` | `verdict_id`, `subject_id`, `action_id`, `attempt_id`, `status`, `generation`, `evidence_ids`, `active`, `supersedes_verdict_id`, `superseded_by_verdict_id`, `recorded_at` |
| `FindingRecord` | `finding_id`, `verdict_id`, `subject_id`, `action_id`, `attempt_id`, `generation`, `evidence_ids`, `active`, `superseded_by_verdict_id`, `legacy_unverified` |
| `ProcessRecord` | `process_id`, `attempt_id`, `process_name`, `state`, `last_sequence`, `stdout_bytes_total`, `stderr_bytes_total`, `combined_bytes_total`, `stdout_omitted_bytes_total`, `stderr_omitted_bytes_total`, `combined_omitted_bytes_total`, `redacted_head_excerpt`, `redacted_tail_excerpt`, `exit_code`, `termination_reason` |
| `OutboxEntry` | `outbox_id`, `workflow_id`, `generation`, `projector`, `dedupe_key`, `payload`, `payload_digest`, `status`, `delivery_attempt`, `enqueued_revision`, `receipt_digest`, `error_code`, `failure_digest`, `retryable` |
| `StageStatusRecord` | `stage_id`, `status` |
| `StageResultDigest` | `stage_id`, `result_digest` |
| `LegacyCheckpointHint` | `checkpoint_id`, `revision`, `relative_path` |
| `BudgetMetrics` | `actions_proposed`, `actions_deferred`, `actions_blocked`, `attempts_started`, `attempts_completed`, `attempts_blocked`, `attempts_cancelled`, `budget_charges` |
| `CheckpointRecord` | `checkpoint_id`, `workflow_id`, `generation`, `bound_revision`, `bound_event_hash`, `bound_event_id`, `binding_mode`, `state_digest`, `event_file_prefix_sha256`, `bound_prefix_bytes`, `relative_path`, `created_at`, `checkpoint_file_sha256`, `event_id`, `event_end_offset` |
| `EventKernelState` | `workflow_id`, `generation`, `ownership`, `phase`, `stage_statuses`, `stage_result_digests`, `legacy_checkpoint_hints`, `actions`, `attempts`, `evidence`, `verdicts`, `findings`, `active_findings`, `processes`, `outbox`, `checkpoints`, `budget` |
| `EventIndexEntry` | `revision`, `event_id`, `event_type`, `event_hash`, `previous_event_hash`, `schema_version`, `generation`, `byte_offset`, `byte_length`, `hash_mode` |
| `CommandIndexEntry` | `command_id`, `command_type`, `command_digest`, `event_id`, `event_type`, `revision`, `event_hash`, `generation`, `byte_offset`, `byte_length` |

`FrozenJsonArray` and `FrozenJsonObject` recursively hold canonical immutable
JSON snapshots. `LogicalActionRecord.arguments` and `OutboxEntry.payload` use
`FrozenJsonObject`. `EventKernelState.workflow_id` is `str | None` so a
pre-`workflow.created` legacy prefix remains representable, and
`active_findings` is exactly `tuple[str, ...]` listing active finding IDs in
the same order as active records in `findings`. Index records contain only
compact metadata, never decoded event payloads, process excerpts, or raw event
objects.

### 4.6 Exact canonical JSON and digest behavior

Canonical bytes are produced with exactly:

```python
json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

Before serialization, recursively accept only exact native JSON types (`dict` with string keys, `list`, `str`, `int`, finite `float`, `bool`, and `None`). Reject tuples, enums, dataclasses, objects, non-string keys, surrogate code points, non-finite numbers, cycles, excessive nesting, and oversized mapping keys as `InvalidCommandError`. Convert `RecursionError`, `UnicodeError`, `ValueError`, and JSON encoder failures to the typed error; none may leak.

The 256 KiB limit applies to the canonical payload/intent being bounded, not to the entire event envelope. A payload of exactly 256 KiB is accepted; one byte over is rejected. Envelope metadata is independently bounded.

`command_digest` must first validate the complete caller intent, including fields later excluded from the digest. It then removes only these structural retry/generated locations:

```text
top-level actor, event_id, timestamp
top-level command.command_id
top-level command.expected_revision
top-level command.expected_event_hash
payload.attempt.attempt_no
payload.attempt.attempt_id
payload.process_output.sequence
payload.outbox.outbox_id
payload.outbox.delivery_attempt
payload.checkpoint.checkpoint_id
payload.checkpoint.checkpoint_file_sha256
payload.checkpoint.checkpoint_relative_path
```

This explicit path table is closed for Stage 1. Adding another generated path
requires a new Stage 1 design decision, a semantic-collision RED test, and both
reviews. Never recursively drop a key merely because its leaf name matches:
`payload.arguments.sequence`, `payload.arguments.attempt_no`, and
`payload.arguments.checkpoint_id` are semantic and must change the digest.
SHA-256 is lowercase hexadecimal.

`event_hash` hashes the canonical event with only top-level `event_hash` removed. Existing caller `command` and `payload` objects are deep-snapshotted before event construction so later mutation cannot change the event or invalidate its hash.

### 4.7 Exact ID and envelope contracts

```text
action_id     = act-g<generation:06d>-<first 16 lowercase hex of action identity SHA-256>
attempt_id    = att-<action_id without "act-">-<attempt_no:06d>
event_id      = evt-<16 lowercase hex>
checkpoint_id = cp-<16 lowercase hex>
process_id    = proc-<16 lowercase hex>
outbox_id     = out-<64 lowercase hex of canonical outbox identity>
```

Action identity contains exactly generation, tool, target, normalized arguments, and kind. Outbox identity contains exactly workflow ID, generation, projector, dedupe key, and the canonical payload SHA-256.

Every schema 2.0 event has exactly these fields:

```text
event_id, schema_version, workflow_id, actor, type, timestamp, revision,
previous_event_hash, generation, correlation_id, causation_id, command,
payload, event_hash
```

`schema_version` is exactly the string `2.0`; variants such as `2.00` and `02.0` are corrupt, while a syntactically valid version greater than 2.0 is `UnsupportedFutureSchemaError`. Huge or malformed schema strings remain `CorruptEventLogError` and cannot leak integer-conversion errors.

The nested command has exactly:

```text
command_id, type, digest, expected_revision, expected_event_hash
```

Validate `expected_revision == revision - 1`, `expected_event_hash == previous_event_hash`, exact command/event pairing, bounded UTC timestamp format, exact IDs and hashes, payload object shape and size, unknown known-schema event distinction, and final hash equality. Error messages for invalid Unicode event types remain UTF-8 encodable and bounded.

The design explicitly requires each persisted event to be one canonical UTF-8
JSON object followed by one LF. Stage 1 exposes:

```python
def canonical_event_line(event: dict[str, Any]) -> bytes:
    validate_event(event)
    return _canonical_json_bytes(event, maximum=None) + b"\n"
```

It validates the complete event, serializes the entire envelope without
reapplying the payload-only 256 KiB limit, and returns exactly
`canonical_event_bytes + b"\n"`. The output contains no BOM, no `\r`, no
pretty-print whitespace, and exactly one terminal LF. Repeated serialization
of the same event is byte-identical, `json.loads(line[:-1])` reconstructs the
event, and the embedded `event_hash` remains the hash of the event object, not
of the newline-terminated line.

### 4.8 Stage 1 design decision: literal module and package exports

The design requires explicit exports but does not prescribe a literal export
tuple. Stage 1 chooses the following lists. Tests compare literal order and
object identity; later stages must return to Stage 1 review before changing
them.

`envelope.__all__` is exactly:

```python
[
    "MAX_CANONICAL_JSON_BYTES",
    "SCHEMA2_EVENT_TYPES",
    "SCHEMA_VERSION",
    "build_event",
    "canonical_event_line",
    "canonical_json_bytes",
    "command_digest",
    "event_hash",
    "make_action_id",
    "make_attempt_id",
    "make_checkpoint_id",
    "make_event_id",
    "make_outbox_id",
    "make_process_id",
    "validate_event",
]
```

`issue_to_error` is intentionally **public** from both `errors` and the package
facade because Stage 2 strict materialization converts data-only replay issues
through it. `errors.__all__` contains the base, all 18 leaves, and
`issue_to_error`, with no internal tables. `contracts.__all__` contains every
enum and dataclass named in sections 4.1-4.5 plus exactly
`EvidenceAttestationError`, `InvalidCommandError`, and
`SensitiveOutputRejectedError` as identity-preserving convenience exports.

After Worker B finished its assigned write cycle, the actual `contracts.py`
shape was read and is frozen as this literal list. This records the chosen
surface only; it does not assert that the existing implementation or tests
validate Stage 1:

```python
[
    "ActionDecision",
    "ActionMerge",
    "ActionProposal",
    "ActionState",
    "AttemptBlock",
    "AttemptCancel",
    "AttemptComplete",
    "AttemptStart",
    "AttemptState",
    "BudgetMetrics",
    "CheckpointRecord",
    "CommandIndexEntry",
    "CommandType",
    "CommandMeta",
    "CommandResult",
    "EvidenceAttestation",
    "EvidenceAttestationError",
    "EvidenceOrigin",
    "EvidenceRecord",
    "EventIndexEntry",
    "EventKernelState",
    "EventType",
    "ExecutionAttemptRecord",
    "FindingRecord",
    "FrozenJsonArray",
    "FrozenJsonObject",
    "ReproductionObservation",
    "FindingCandidate",
    "HashMode",
    "Head",
    "InvalidCommandError",
    "LegacyCheckpointHint",
    "LogicalActionRecord",
    "MemoryApplied",
    "MemoryEnqueue",
    "MemoryFailed",
    "OutboxState",
    "OutboxEntry",
    "OwnershipState",
    "ProcessOutput",
    "ProcessStart",
    "ProcessState",
    "ProcessStream",
    "ProcessTerminal",
    "ProcessRecord",
    "RecoveryRequest",
    "ReplayIssue",
    "ReplayIssueKind",
    "ReplayResult",
    "ReplayStats",
    "SensitiveOutputRejectedError",
    "StageResultDigest",
    "StageStatusRecord",
    "VerdictRecord",
    "VerdictStateRecord",
    "VerdictStatus",
    "VerificationObservation",
    "WorkflowOwnershipClaim",
]
```

`core.workflow.event_kernel.__all__` is a literal tuple in the order recorded
below after Worker B's final `contracts.__all__`, followed by previously unseen
names from `errors.__all__` and `envelope.__all__`. Every object is the
identical object from its owning module. The implementation uses explicit
imports and a literal `__all__`; no runtime concatenation, wildcard import, or
`import *` appears in source.

```python
(
    "ActionDecision",
    "ActionMerge",
    "ActionProposal",
    "ActionState",
    "AttemptBlock",
    "AttemptCancel",
    "AttemptComplete",
    "AttemptStart",
    "AttemptState",
    "BudgetMetrics",
    "CheckpointRecord",
    "CommandIndexEntry",
    "CommandType",
    "CommandMeta",
    "CommandResult",
    "EvidenceAttestation",
    "EvidenceAttestationError",
    "EvidenceOrigin",
    "EvidenceRecord",
    "EventIndexEntry",
    "EventKernelState",
    "EventType",
    "ExecutionAttemptRecord",
    "FindingRecord",
    "FrozenJsonArray",
    "FrozenJsonObject",
    "ReproductionObservation",
    "FindingCandidate",
    "HashMode",
    "Head",
    "InvalidCommandError",
    "LegacyCheckpointHint",
    "LogicalActionRecord",
    "MemoryApplied",
    "MemoryEnqueue",
    "MemoryFailed",
    "OutboxState",
    "OutboxEntry",
    "OwnershipState",
    "ProcessOutput",
    "ProcessStart",
    "ProcessState",
    "ProcessStream",
    "ProcessTerminal",
    "ProcessRecord",
    "RecoveryRequest",
    "ReplayIssue",
    "ReplayIssueKind",
    "ReplayResult",
    "ReplayStats",
    "SensitiveOutputRejectedError",
    "StageResultDigest",
    "StageStatusRecord",
    "VerdictRecord",
    "VerdictStateRecord",
    "VerdictStatus",
    "VerificationObservation",
    "WorkflowOwnershipClaim",
    "CheckpointBindingError",
    "CommandConflictError",
    "ConcurrencyConflictError",
    "CorruptEventLogError",
    "DuplicateCommittedCommandError",
    "DuplicateEventIdError",
    "EventKernelError",
    "IllegalTransitionError",
    "MixedWriterError",
    "OutboxConflictError",
    "OwnershipClaimRequiredError",
    "RecoveryNotAuthorizedError",
    "UnknownEventTypeError",
    "UnsupportedFutureSchemaError",
    "WorkflowAlreadyClaimedError",
    "WorkflowNotFoundError",
    "issue_to_error",
    "MAX_CANONICAL_JSON_BYTES",
    "SCHEMA2_EVENT_TYPES",
    "SCHEMA_VERSION",
    "build_event",
    "canonical_event_line",
    "canonical_json_bytes",
    "command_digest",
    "event_hash",
    "make_action_id",
    "make_attempt_id",
    "make_checkpoint_id",
    "make_event_id",
    "make_outbox_id",
    "make_process_id",
    "validate_event",
)
```

## 5. Required Test Inventory

The final files may group parameterized cases, but every bullet below must have a named assertion and must be observed RED for the intended reason before its implementation change.

### `test_contracts_envelope.py`

- exact direct error hierarchy and exact code map;
- UTF-8-safe 512-character messages and location preservation;
- complete `ReplayIssueKind` to leaf-error conversion for objects and mappings;
- sorted compact UTF-8 canonical bytes;
- rejection of every non-native/non-finite/non-Unicode value;
- cycle, depth, and oversized-key rejection without leaked built-in exceptions;
- exact 256 KiB boundary;
- generation-visible deterministic action/attempt IDs and invalid ID boundaries;
- random generated ID formats and deterministic outbox ID vector;
- complete-intent validation before command-digest projection;
- lock-generated path exclusion and nested semantic same-name collision regression;
- all 19 schema 2.0 event names and exact envelope exports;
- exact envelope and nested command fields, command/event pair validation, CAS-link fields, and hash;
- canonical event-line serialization, exact one-LF termination, no BOM/CR,
  round-trip, deterministic bytes, and payload-limit independence;
- deep snapshot of caller command/payload;
- payload-only size accounting;
- explicit vs generated ID/timestamp handling;
- exact schema spelling, future schema distinction, huge schema handling, invalid Unicode type handling;
- tamper, unknown event, invalid identity, invalid chain, and invalid payload leaf errors.

### `test_contracts_models.py`

- exact public contract/enums inventory and exact 19 enum pairs;
- exact projection field order from section 4.5;
- fully typed `EventKernelState`, indexes, and `ReplayResult`, with no `Any`;
- projection identity and state consistency and compact-index constraints;
- exact `CommandMeta` fields and invalid scalar boundaries;
- independent immutable defaults and detached JSON snapshots;
- action/attempt DTO shape and IDs;
- distinct verification/reproduction records and strictly positive reproduction counts;
- evidence/verdict/finding local identity, evidence equality, and status constraints;
- process stream enum/validation, 4,096 UTF-8-byte boundary including multibyte input, absolute counter equations, omitted-byte equations, no raw fields, and known-marker rejection;
- process terminal counters and field boundaries;
- bounded detached memory payload, deterministic payload digest/ID compatibility, outbox absolute delivery state and invalid combinations;
- recovery full-source fields, head/hash-mode combinations, data-only replay issue, replay consistency;
- deduplicated/idempotent `CommandResult` invariants and detached payload.

### `test_public_api.py`

- package `__all__` equality against the independently hard-coded literal
  tuple in section 4.8 and object identity;
- public `issue_to_error` identity from `errors` through the package facade;
- no wildcard imports in package source;
- no arbitrary event write API;
- imports are direct from `core.workflow.event_kernel`, with no production entry point connection.

## 6. Task 0: Capture Fresh Baseline Without Editing

**Files:** Read only.

- [ ] **Step 1: Confirm branch, authority, and current candidates**

```powershell
git branch --show-current
git log -5 --oneline
git status --short --untracked-files=all
Get-ChildItem core\workflow\event_kernel,tests\acceptance\event_kernel -File |
  Select-Object FullName,Length,LastWriteTime
```

Expected: branch `feat/hunter-unified-proof-engine`; authority commits `d56f2d8` and `7ec9479` are reachable; pre-existing runtime artifacts are recorded but untouched.

- [ ] **Step 2: Prove the forbidden legacy baseline is currently clean**

```powershell
git diff --exit-code HEAD -- `
  core/workflow/models.py `
  core/workflow/kernel.py `
  core/workflow/locking.py `
  core/workflow/__init__.py
```

Expected: exit 0 and no output. Stop Stage 1 and escalate if this command shows a concurrent edit; do not revert it.

- [ ] **Step 3: Record current focused behavior as diagnostic evidence only**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q tests/acceptance/event_kernel
```

Expected: either focused failures that identify incomplete candidates or a diagnostic green. Even a green result does not replace the requirement-by-requirement RED cycles below.

## 7. Task 1A: Freeze Errors and Envelope Vocabulary

**Files:**

- Modify/Create: `tests/acceptance/event_kernel/test_contracts_envelope.py`
- Modify/Create: `core/workflow/event_kernel/errors.py`
- Modify/Create: `core/workflow/event_kernel/envelope.py`

- [ ] **Step 1: Add only the error-code, UTF-8 message, issue-map, event-name, and export tests**

Use the exact inventories in sections 4.1, 4.3, and 4.8. Include equality against the complete maps; uniqueness-only assertions are insufficient.

- [ ] **Step 2: Run the focused slice and capture expected RED**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py `
  -k "error_contract or issue_to_error or event_type_vocabulary or envelope_public_exports"
```

Expected RED: a missing exact code, unsafe surrogate message, incomplete mapping, vocabulary mismatch, or missing `__all__`. A collection/import failure unrelated to the tested contract is not an acceptable RED; repair the test setup first.

- [ ] **Step 3: Implement the minimum exact error and vocabulary surface**

Implement the base plus 18 direct leaves, exact codes, bounded surrogate-safe messages, typed issue conversion, `SCHEMA_VERSION`, the exact 19 event values, and exact envelope exports. Do not add replay or store behavior.

- [ ] **Step 4: Run GREEN for this slice**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py `
  -k "error_contract or issue_to_error or event_type_vocabulary or envelope_public_exports"
```

Expected: all selected tests pass, zero failures.

## 8. Task 1B: Freeze Typed Contracts and Projections

**Files:**

- Modify/Create: `tests/acceptance/event_kernel/test_contracts_models.py`
- Modify/Create: `core/workflow/event_kernel/contracts.py`

- [ ] **Step 1: Add exact enum, field-order, projection, and no-`Any` tests**

Lock every name/value/field from sections 4.1, 4.2, 4.4, and 4.5. The test must instantiate a minimal internally consistent empty `EventKernelState`, `Head`, and `ReplayResult` and reject mismatched ownership or `state=None`.

- [ ] **Step 2: Run expected RED**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q tests/acceptance/event_kernel/test_contracts_models.py `
  -k "exports_all or command_and_event_type or projection_contracts or fully_typed or compact_indexes"
```

Expected RED: missing projection type, wrong field order, enum mismatch, `Any` in `ReplayResult`, or invalid consistency accepted.

- [ ] **Step 3: Implement the minimum typed enum/projection graph**

Use frozen/slotted dataclasses, exact enum values, tuple defaults, strict scalar/hash/ID validators, and compact index records. Keep decoded events and raw payloads out of index entries.

- [ ] **Step 4: Run GREEN for the projection slice**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_models.py `
  -k "exports_all or command_and_event_type or projection_contracts or fully_typed or compact_indexes"
```

Expected: all selected tests pass, zero failures.

- [ ] **Step 5: Add command DTO and immutable snapshot tests**

Test exact fields, falsey/boolean integer confusion, lowercase canonical hashes, tuple independence, recursive mutation of `ActionProposal.arguments`, `MemoryEnqueue.payload`, `OutboxEntry.payload`, and `CommandResult.payload`, and strict JSON bounds.

- [ ] **Step 6: Run expected RED**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_models.py `
  -k "command_meta or claim_and_action or attempt_contracts or memory or command_result or snapshot"
```

Expected RED: at least one mutable alias, invalid field acceptance, or inconsistent result accepted.

- [ ] **Step 7: Implement only local DTO validation and detached snapshots**

Do not implement history-dependent transitions. Canonicalize hashes to lowercase only after validating exact 64-hex form. Reject `bool` wherever an integer counter is required.

- [ ] **Step 8: Run GREEN for the DTO slice**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_models.py `
  -k "command_meta or claim_and_action or attempt_contracts or memory or command_result or snapshot"
```

Expected: all selected tests pass, zero failures.

- [ ] **Step 9: Add evidence, verdict, finding, process, and outbox negative tests**

Include every local invariant in section 4.4, especially distinct observation types, positive reproduction counts, non-verified finding rejection, exact finding/verdict identity, UTF-8 byte length, stream restriction, absolute omitted counters, known markers, no raw fields, outbox payload bounds, and invalid delivery/result combinations.

- [ ] **Step 10: Run expected RED**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_models.py `
  -k "evidence or verdict or finding or process or outbox"
```

Expected RED: the new focused adversarial case is accepted, has the wrong leaf error, or leaks mutable payload state.

- [ ] **Step 11: Implement the minimum local invariants**

Use `EvidenceAttestationError` for proof-shape failures, `SensitiveOutputRejectedError` for known marker/redaction failures, and `InvalidCommandError` for general malformed contracts. Count excerpt size using UTF-8 bytes, not Python characters.

- [ ] **Step 12: Run the complete contracts file GREEN**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_models.py
```

Expected: all tests pass, zero failures.

## 9. Task 1C: Harden Canonical JSON and Command Digest

**Files:**

- Modify: `tests/acceptance/event_kernel/test_contracts_envelope.py`
- Modify: `core/workflow/event_kernel/envelope.py`

- [ ] **Step 1: Add strict serializer boundary tests**

Cover exact native types, non-string keys, non-finite floats, surrogates, tuples/enums/dataclasses/objects, cyclic list/dict, 65-level nesting, a 4,097-character key, exact 256 KiB acceptance, and one-byte-over rejection. Assert exact `InvalidCommandError`, not only a generic exception.

- [ ] **Step 2: Run expected RED**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py `
  -k "canonical_json"
```

Expected RED: a built-in `RecursionError`/`UnicodeError`/`ValueError` leaks, a non-native object is accepted, or a byte/depth boundary is wrong.

- [ ] **Step 3: Implement strict validation before canonical encoding**

Track container identities to reject cycles, enforce a documented maximum nesting depth of 64, measure UTF-8 bytes, and convert encoder failures to `InvalidCommandError`. Keep the canonical JSON call byte-for-byte identical to section 4.6.

- [ ] **Step 4: Run serializer GREEN**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py `
  -k "canonical_json"
```

Expected: all selected tests pass, zero failures.

- [ ] **Step 5: Add path-sensitive command-digest tests**

Create two intents that differ only at `payload.arguments.sequence` and prove different hashes. Create retries that differ only at the exact generated paths in section 4.6 and prove equal hashes. Put invalid objects and oversized strings in excluded paths and prove validation happens before projection.

- [ ] **Step 6: Run expected RED**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py `
  -k "command_digest"
```

Expected RED: semantic collision, generated retry mismatch, or invalid excluded value bypass.

- [ ] **Step 7: Replace recursive key-name filtering with explicit path projection**

Validate the complete input first, copy only through the explicit structural path table, preserve same-named semantic argument keys, and hash the canonical normalized intent with SHA-256.

- [ ] **Step 8: Run digest GREEN**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py `
  -k "command_digest"
```

Expected: all selected tests pass, zero failures.

## 10. Task 1D: Harden IDs and Schema 2.0 Envelope

**Files:**

- Modify: `tests/acceptance/event_kernel/test_contracts_envelope.py`
- Modify: `core/workflow/event_kernel/envelope.py`

- [ ] **Step 1: Add ID, snapshot, size, pairing, schema, Unicode, tamper, and canonical event-line tests**

Use fixed digest vectors for action/outbox identity; exact regexes for random IDs; invalid generation/attempt boundaries; caller mutation after `build_event`; payload exactly 256 KiB; mismatched command/event type; huge schema; invalid Unicode type; exact envelope keys; chain/CAS mismatch; tampered event hash; and `canonical_event_line(event) == canonical_unbounded_event_bytes + b"\n"` with one LF, no CR/BOM, deterministic round-trip, and a maximum-size payload whose full envelope exceeds 256 KiB.

- [ ] **Step 2: Run expected RED**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py `
  -k "id_ or outbox_id or build_event or validate_event or schema2_event or event_line"
```

Expected RED: mutable alias, whole-envelope size rejection, accepted mismatched pair, leaked built-in exception, wrong leaf error, or wrong digest/ID.

- [ ] **Step 3: Implement the minimum exact envelope behavior**

Deep-snapshot strict JSON inputs before constructing the envelope. Validate exact shape and command/event pairing. `build_event` raises `InvalidCommandError`; persisted-event validation raises `CorruptEventLogError`, `UnknownEventTypeError`, or `UnsupportedFutureSchemaError` exactly as classified. Hash only after all fields are finalized. Implement `canonical_event_line` with the private unbounded canonical serializer after event validation, then append exactly `b"\n"`.

- [ ] **Step 4: Run the complete envelope file GREEN**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_contracts_envelope.py
```

Expected: all tests pass, zero failures.

## 11. Task 1E: Integrate Explicit Package Exports

**Files:**

- Create/Modify: `tests/acceptance/event_kernel/test_public_api.py`
- Create: `core/workflow/event_kernel/__init__.py`
- Create/Verify: `tests/acceptance/event_kernel/__init__.py`

- [ ] **Step 1: Wait for Workers A and B and re-run both file-level suites**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q `
  tests/acceptance/event_kernel/test_contracts_envelope.py `
  tests/acceptance/event_kernel/test_contracts_models.py
```

Expected: zero failures. Do not integrate against a worker's still-running write.

- [ ] **Step 2: Add package export and forbidden API tests before creating the facade**

The test imports `core.workflow.event_kernel`, compares `api.__all__` to an
independently hard-coded copy of the literal tuple in section 4.8, checks every
object's identity with its owning module, explicitly proves
`api.issue_to_error is errors.issue_to_error`, scans package source for
`import *` and runtime `__all__` concatenation, and rejects the generic-write
names in section 2. Do not derive the expected tuple from the modules under
test; that would let mutually wrong exports self-confirm.

- [ ] **Step 3: Run expected RED**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_public_api.py
```

Expected RED: missing package module or missing explicit exports. A failure caused by a Worker A/B test regression is not the intended RED.

- [ ] **Step 4: Create the explicit facade**

Import every public object by name from `contracts`, `errors`, and `envelope`;
assign the literal tuple from section 4.8 directly; expose no
kernel/store/event-write object.

- [ ] **Step 5: Run public API GREEN**

```powershell
python -m pytest -q tests/acceptance/event_kernel/test_public_api.py
```

Expected: all tests pass, zero failures.

- [ ] **Step 6: Run complete focused Stage 1 GREEN**

```powershell
python -m pytest -q tests/acceptance/event_kernel
```

Expected: all focused tests pass, zero failures. Record the fresh count and duration; do not copy a historical count.

## 12. Task 1F: Boundary, Compile, Collection, Full, and Real-Root Gates

Run these only after focused GREEN and after concurrent Stage 1 writers have stopped.

- [ ] **Step 1: Compile the complete Stage 1 source and tests**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m compileall -q core/workflow/event_kernel tests/acceptance/event_kernel
```

Expected: exit 0, no output.

- [ ] **Step 2: Prove forbidden legacy files are unchanged**

```powershell
git diff --exit-code HEAD -- `
  core/workflow/models.py `
  core/workflow/kernel.py `
  core/workflow/locking.py `
  core/workflow/__init__.py
```

Expected: exit 0, no output.

- [ ] **Step 3: Inspect all changes and prove there is no production connection**

```powershell
git status --short --untracked-files=all
git diff --check
git diff --name-only HEAD
git ls-files --others --exclude-standard `
  core/workflow/event_kernel tests/acceptance/event_kernel
rg -n "core\.workflow\.event_kernel|from \.event_kernel|import event_kernel" `
  core mcp_server.py hunter_tools_mcp.py `
  -g "!core/workflow/event_kernel/**"
```

Expected: Stage 1 source/tests are confined to the allowed paths; the final `rg` reports no new production entry-point connection. Pre-existing `sessions/` artifacts remain unmodified and unstaged.

- [ ] **Step 4: Run full test collection**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest --collect-only -q
```

Expected: exit 0 with no collection/import errors. Record the fresh collected count; do not require the old 770 count.

- [ ] **Step 5: Run the full suite in a clean environment process**

```powershell
powershell -NoProfile -Command `
  '$env:PYTHONDONTWRITEBYTECODE="1"; Remove-Item Env:OPEN_TGTYLAB_ROOT -ErrorAction SilentlyContinue; python -m pytest -q'
```

Expected: exit 0, zero failures. Record count and duration.

- [ ] **Step 6: Run the full suite with the real workspace root**

```powershell
powershell -NoProfile -Command `
  '$env:PYTHONDONTWRITEBYTECODE="1"; $env:OPEN_TGTYLAB_ROOT="D:\Open-tgtylab"; python -m pytest -q'
```

Expected: exit 0, zero failures, no workspace-root skip or fallback. This is a separate required run; the clean-environment run cannot substitute for it.

- [ ] **Step 7: Run a final focused rerun after the broad gates**

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q tests/acceptance/event_kernel
```

Expected: exit 0, zero failures. This detects concurrent edits that landed during the long full-suite runs.

## 13. Task 1G: Two-Stage Review and Finding Closure

Reviews are sequential and independent. The code-quality reviewer does not replace the specification reviewer. Any finding returns to its owning file, receives a new focused RED where applicable, then repeats GREEN and all affected gates.

- [ ] **Step 1: Run the specification-compliance review with this exact prompt**

```text
Read docs/superpowers/specs/2026-07-16-hunter-event-kernel-hardening-design.md,
docs/superpowers/plans/2026-07-16-hunter-event-kernel-roadmap.md, and
docs/superpowers/plans/2026-07-16-hunter-event-kernel-task1-contracts-envelope.md.
Review only the Stage 1 diff under core/workflow/event_kernel/ and
tests/acceptance/event_kernel/. Verify requirement by requirement: exact public
contracts and field order; all enum values; all 18 leaf errors; the explicitly
recorded Stage 1 decisions for snake_case codes, 512-character messages,
projection/index shape, and literal exports without misattributing them to the
design; public issue_to_error identity; canonical LF-terminated event lines;
all 19 command/event pairs; strict native canonical JSON; full-input validation
before path-sensitive digest projection; no semantic key collisions; deterministic
IDs; exact schema 2.0 envelope and error classification; immutable caller snapshots;
payload-only 256 KiB bound; fully typed ReplayResult/EventKernelState/indexes;
process/output/outbox local safety contracts; exact exports; no generic event API;
and all forbidden path/production-entry boundaries. Treat current passing tests as
evidence only where their assertions directly prove the requirement. Report each
finding with severity, file, line, violated requirement, and a concrete missing test.
If no finding remains, state SPEC REVIEW PASS and enumerate the evidence commands
you inspected.
```

Expected: `SPEC REVIEW PASS`, or concrete findings are resolved and the review is repeated until it passes.

- [ ] **Step 2: Run the code-quality/adversarial review with this exact prompt**

```text
Review the Stage 1 event-kernel source and tests for defects independent of the
specification-compliance review. Attack canonicalization with cycles, deep nesting,
surrogates, huge schema strings, bool/int confusion, mapping subclasses, mutable
aliases, semantic digest collisions, generated-path over-exclusion, command/event
pair mismatches, hash confusion, BOM/CR/double-LF or missing-LF event lines,
oversized multibyte excerpts, secret-marker bypass,
outbox payload mutation, inconsistent idempotent/deduplicated results, and Any or
unbounded payload retention in public projection/index contracts. Inspect API and
type consistency, maintainability, exact error leaves, test false positives, and the
fresh focused/compile/collection/full/OPEN_TGTYLAB_ROOT outputs. Confirm no forbidden
legacy or runtime artifact diff. Report findings first with severity, file, line,
reproducer, and required regression test. If no finding remains, state QUALITY
REVIEW PASS and list residual risks deferred to the owning later roadmap stages.
```

Expected: `QUALITY REVIEW PASS`, or concrete findings are resolved and the review is repeated until it passes.

- [ ] **Step 3: Re-run all affected and final gates after review fixes**

At minimum rerun:

```powershell
python -m pytest -q tests/acceptance/event_kernel
python -m compileall -q core/workflow/event_kernel tests/acceptance/event_kernel
python -m pytest --collect-only -q
powershell -NoProfile -Command `
  '$env:PYTHONDONTWRITEBYTECODE="1"; $env:OPEN_TGTYLAB_ROOT="D:\Open-tgtylab"; python -m pytest -q'
git diff --exit-code HEAD -- `
  core/workflow/models.py core/workflow/kernel.py `
  core/workflow/locking.py core/workflow/__init__.py
```

Expected: every command exits 0. If a review fix can affect environment-independent tests, also repeat the clean-environment full suite.

## 14. Explicit Staging and Commit Commands

The worker executing this plan does not use these commands until every gate and both reviews pass. Never include `sessions/`.

### Publish this detailed plan, if it is not already committed

```powershell
git add -- docs/superpowers/plans/2026-07-16-hunter-event-kernel-task1-contracts-envelope.md
git diff --cached --check
git diff --cached --name-only
git commit -m "docs: detail event kernel stage 1"
```

Expected staged path: exactly the plan document.

### Commit Stage 1 implementation

```powershell
git add -- `
  core/workflow/event_kernel/__init__.py `
  core/workflow/event_kernel/contracts.py `
  core/workflow/event_kernel/envelope.py `
  core/workflow/event_kernel/errors.py `
  tests/acceptance/event_kernel/__init__.py `
  tests/acceptance/event_kernel/test_contracts_envelope.py `
  tests/acceptance/event_kernel/test_contracts_models.py `
  tests/acceptance/event_kernel/test_public_api.py

git diff --cached --check
git diff --cached --name-only
git diff --cached --stat
git commit -m "feat: freeze event kernel contracts and envelope"
```

Before commit, compare `git diff --cached --name-only` to the exact eight implementation/test paths above. Abort the commit if any runtime artifact, forbidden legacy file, production entry point, or unrelated path is staged. Do not amend another agent's commit.

After commit:

```powershell
git status --short --branch
git show --stat --oneline --summary HEAD
```

Expected: Stage 1 files are committed; pre-existing untracked runtime artifacts may remain and are not evidence of a Stage 1 diff.

## 15. Stage 1 Exit-Gate Self-Review Matrix

| Roadmap exit gate | Direct evidence required |
|---|---|
| Frozen public contracts | Exact export and dataclass field-order tests; no `Any` in replay/state/index graph |
| Stable command/event enums | Exact ordered 19-pair equality test and exact namespace test |
| Typed errors | Exact direct hierarchy/code map, bounded UTF-8-safe message test, complete issue conversion test |
| Strict canonical JSON | Native-type, ordering, UTF-8, finite-number, key, cycle, depth, and byte-boundary tests |
| Correct command digest | Complete-input validation, exact generated paths, semantic same-name collision tests |
| Deterministic IDs | Fixed action/outbox vectors and exact generated-ID regex/boundary tests |
| Schema 2.0 construction/validation | Exact fields, pair mapping, CAS links, payload bound, snapshot, hash, schema/type leaf tests |
| Canonical event line | Unbounded full-envelope canonical serialization, UTF-8 round-trip, one terminal LF, no BOM/CR, deterministic bytes |
| Explicit exports/no arbitrary API | Independently hard-coded literal package tuple, object and public `issue_to_error` identity, no wildcard/runtime concatenation, forbidden generic-write API test |
| Focused tests | Fresh `python -m pytest -q tests/acceptance/event_kernel`, zero failures |
| Compile gate | Fresh `compileall`, exit 0 |
| Legacy forbidden diff | Fresh `git diff --exit-code HEAD --` four forbidden files, no output |
| Full collection | Fresh `pytest --collect-only -q`, exit 0 |
| Full regression | Fresh clean-environment full suite, zero failures |
| Real workspace root | Fresh full suite with `OPEN_TGTYLAB_ROOT=D:\Open-tgtylab`, zero failures and no skip/fallback |
| Two-stage review | Recorded `SPEC REVIEW PASS` and `QUALITY REVIEW PASS` after all findings are resolved |
| Commit hygiene | Exact staged path list; no `sessions/`, legacy, entry-point, or unrelated file |

Stage 1 is not complete while any matrix cell lacks fresh direct evidence. A passing narrow test cannot prove a broad gate, and a review statement cannot replace command output. Stage 2 may begin only after every cell passes and the Stage 1 commit is inspectable.
