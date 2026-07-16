from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .contracts import (
    ActionState,
    AttemptState,
    BudgetMetrics,
    CheckpointRecord,
    EvidenceAttestation,
    EvidenceOrigin,
    EvidenceRecord,
    EventKernelState,
    ExecutionAttemptRecord,
    FindingRecord,
    FindingCandidate,
    LegacyCheckpointHint,
    LogicalActionRecord,
    OwnershipState,
    ProcessOutput,
    ProcessRecord,
    ProcessState,
    ProcessTerminal,
    StageResultDigest,
    StageStatusRecord,
    VerdictRecord,
    VerdictStateRecord,
    VerdictStatus,
    VerificationObservation,
    ReproductionObservation,
    OutboxEntry,
    OutboxState,
)
from .errors import (
    CorruptEventLogError,
    EvidenceAttestationError,
    IllegalTransitionError,
    MixedWriterError,
    OwnershipClaimRequiredError,
)
from .upcast import SemanticEvent
from .envelope import canonical_json_bytes


def _payload(event: SemanticEvent) -> Mapping[str, Any]:
    return event.payload


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _replace_record(records: tuple[Any, ...], record: Any, identifier: str) -> tuple[Any, ...]:
    for index, existing in enumerate(records):
        if getattr(existing, identifier) == getattr(record, identifier):
            if existing == record:
                return records
            return records[:index] + (record,) + records[index + 1 :]
    return records + (record,)


def _find_record(records: tuple[Any, ...], identifier: str, value: str) -> Any | None:
    return next((record for record in records if getattr(record, identifier) == value), None)


def _tuple_union(existing: tuple[str, ...], additions: Any) -> tuple[str, ...]:
    values = additions if isinstance(additions, (list, tuple)) else ()
    return existing + tuple(value for value in values if value not in existing)


def _ordered_ids(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise EvidenceAttestationError(f"{name} must be an ordered collection")
    return tuple(value)


def _action_key(*, generation: int, tool: str, target: str, arguments: Any, kind: str) -> str:
    identity = {
        "generation": generation,
        "tool": tool,
        "target": target,
        "arguments": _thaw(arguments),
        "kind": kind,
    }
    return hashlib.sha256(canonical_json_bytes(identity)).hexdigest()


def _budget(state: EventKernelState, **changes: int) -> BudgetMetrics:
    values = {
        name: getattr(state.budget, name)
        for name in (
            "actions_proposed",
            "actions_deferred",
            "actions_blocked",
            "attempts_started",
            "attempts_completed",
            "attempts_blocked",
            "attempts_cancelled",
            "budget_charges",
        )
    }
    values.update(changes)
    return BudgetMetrics(**values)


def _action_decision(
    state: EventKernelState,
    event: SemanticEvent,
    *,
    target: ActionState,
) -> EventKernelState:
    item = _mapping(_payload(event).get("decision"))
    action_id = _first(item, "action_id")
    action = _find_record(state.actions, "action_id", action_id)
    allowed = {
        ActionState.DEFERRED: {ActionState.PROPOSED},
        ActionState.BLOCKED: {ActionState.PROPOSED, ActionState.DEFERRED, ActionState.RETRYABLE},
    }[target]
    if action is None or action.state not in allowed:
        raise IllegalTransitionError(f"action cannot transition to {target.value}")
    updated = replace(action, state=target)
    budget = state.budget
    if target is ActionState.DEFERRED:
        budget = _budget(state, actions_deferred=state.budget.actions_deferred + 1)
    else:
        budget = _budget(state, actions_blocked=state.budget.actions_blocked + 1)
    return replace(state, actions=_replace_record(state.actions, updated, "action_id"), budget=budget)


def _reduce_action(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    payload = _payload(event)
    if event.event_type == "event_kernel.action.proposed":
        item = _mapping(payload.get("action"))
        generation = _first(item, "generation", default=event.generation)
        tool = _first(item, "tool")
        target = _first(item, "target")
        arguments = _first(item, "arguments", default={})
        kind = _first(item, "kind")
        action_key = _action_key(
            generation=generation, tool=tool, target=target, arguments=arguments, kind=kind
        )
        action_id = _first(item, "action_id")
        if _find_record(state.actions, "action_id", action_id) is not None:
            raise IllegalTransitionError("action_id was already proposed")
        if not isinstance(action_id, str) or action_id != f"act-g{generation:06d}-{action_key[:16]}":
            raise IllegalTransitionError("action_id does not match the action identity")
        action = LogicalActionRecord(
            action_id=action_id,
            action_key=action_key,
            generation=generation,
            tool=tool,
            target=target,
            arguments=_thaw(arguments),
            kind=kind,
            sources=tuple(_first(item, "sources", default=())),
            strategy_ids=tuple(_first(item, "strategy_ids", default=())),
            labels=tuple(_first(item, "labels", default=())),
            expected_evidence=tuple(_first(item, "expected_evidence", default=())),
            priority=_first(item, "priority", default="P2"),
        )
        return replace(
            state,
            actions=state.actions + (action,),
            budget=_budget(state, actions_proposed=state.budget.actions_proposed + 1),
        )

    if event.event_type == "event_kernel.action.merged":
        item = _mapping(payload.get("merge"))
        action_id = _first(item, "action_id")
        action = _find_record(state.actions, "action_id", action_id)
        if action is None or action.state not in {
            ActionState.PROPOSED,
            ActionState.DEFERRED,
            ActionState.RETRYABLE,
        }:
            raise IllegalTransitionError("action cannot be merged in its current state")
        priority = _first(item, "priority")
        rank = {"P0": 0, "P1": 1, "P2": 2}
        if priority is not None and rank[priority] > rank[action.priority]:
            raise IllegalTransitionError("action priority may only improve")
        updated = replace(
            action,
            sources=_tuple_union(action.sources, _first(item, "sources", default=())),
            strategy_ids=_tuple_union(action.strategy_ids, _first(item, "strategy_ids", default=())),
            labels=_tuple_union(action.labels, _first(item, "labels", default=())),
            expected_evidence=_tuple_union(
                action.expected_evidence, _first(item, "expected_evidence", default=())
            ),
            priority=priority if priority is not None and rank[priority] < rank[action.priority] else action.priority,
        )
        return replace(state, actions=_replace_record(state.actions, updated, "action_id"))

    if event.event_type == "event_kernel.action.deferred":
        return _action_decision(state, event, target=ActionState.DEFERRED)
    if event.event_type == "event_kernel.action.blocked":
        return _action_decision(state, event, target=ActionState.BLOCKED)
    return state


def _process_terminal(state: EventKernelState, attempt: ExecutionAttemptRecord) -> bool:
    processes = {process.process_id: process for process in state.processes}
    return all(
        process_id in processes and processes[process_id].state is ProcessState.TERMINATED
        for process_id in attempt.process_ids
    )


def _reduce_attempt(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    payload = _payload(event)
    item = _mapping(payload.get("attempt"))
    attempt_id = _first(item, "attempt_id", "id")
    action_id = _first(item, "action_id")
    if event.event_type == "event_kernel.attempt.started":
        action = _find_record(state.actions, "action_id", action_id)
        if action is None or action.state not in {
            ActionState.PROPOSED,
            ActionState.DEFERRED,
            ActionState.RETRYABLE,
        }:
            raise IllegalTransitionError("action cannot start an attempt in its current state")
        if any(
            attempt.action_id == action_id and attempt.state is AttemptState.STARTED
            for attempt in state.attempts
        ):
            raise IllegalTransitionError("only one attempt may be started for an action")
        if _find_record(state.attempts, "attempt_id", attempt_id) is not None:
            raise IllegalTransitionError("attempt_id was already used")
        attempt = ExecutionAttemptRecord(
            attempt_id=attempt_id,
            action_id=action_id,
            generation=_first(item, "generation", default=event.generation),
            attempt_no=_first(item, "attempt_no"),
            executor=_first(item, "executor"),
            budget_class=_first(item, "budget_class"),
            state=AttemptState.STARTED,
        )
        updated_action = replace(
            action,
            state=ActionState.RUNNING,
            attempt_ids=action.attempt_ids + (attempt_id,),
            active_attempt_id=attempt_id,
        )
        return replace(
            state,
            actions=_replace_record(state.actions, updated_action, "action_id"),
            attempts=state.attempts + (attempt,),
            budget=_budget(
                state,
                attempts_started=state.budget.attempts_started + 1,
                budget_charges=state.budget.budget_charges + 1,
            ),
        )

    attempt = _find_record(state.attempts, "attempt_id", attempt_id)
    if attempt is None or attempt.state is not AttemptState.STARTED:
        raise IllegalTransitionError("terminal attempt command requires a started attempt")
    if not _process_terminal(state, attempt):
        raise IllegalTransitionError("all processes bound to an attempt must be terminal")
    action = _find_record(state.actions, "action_id", attempt.action_id)
    assert action is not None
    if event.event_type == "event_kernel.attempt.completed":
        updated_attempt = replace(
            attempt,
            state=AttemptState.COMPLETED,
            result_code=_first(item, "result_code"),
            result_digest=_first(item, "result_digest"),
        )
        updated_action = replace(
            action, state=ActionState.COMPLETED, active_attempt_id=None
        )
        budget = _budget(state, attempts_completed=state.budget.attempts_completed + 1)
    else:
        target = (
            AttemptState.BLOCKED
            if event.event_type == "event_kernel.attempt.blocked"
            else AttemptState.CANCELLED
        )
        updated_attempt = replace(attempt, state=target, terminal_reason=_first(item, "reason"))
        updated_action = replace(action, state=ActionState.RETRYABLE, active_attempt_id=None)
        counter = "attempts_blocked" if target is AttemptState.BLOCKED else "attempts_cancelled"
        budget = _budget(state, **{counter: getattr(state.budget, counter) + 1})
    return replace(
        state,
        actions=_replace_record(state.actions, updated_action, "action_id"),
        attempts=_replace_record(state.attempts, updated_attempt, "attempt_id"),
        budget=budget,
    )


def _reduce_process(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    if event.event_type == "event_kernel.process.started":
        item = _mapping(_payload(event).get("process"))
        process_id = _first(item, "process_id")
        attempt_id = _first(item, "attempt_id")
        attempt = _find_record(state.attempts, "attempt_id", attempt_id)
        if attempt is None:
            raise IllegalTransitionError("process must bind to an existing attempt")
        if attempt.state is not AttemptState.STARTED or _find_record(state.processes, "process_id", process_id):
            raise IllegalTransitionError("process cannot be started for this attempt")
        process = ProcessRecord(
            process_id=process_id,
            attempt_id=attempt_id,
            process_name=_first(item, "process_name", default=""),
            state=ProcessState.STARTED,
            last_sequence=0,
            stdout_bytes_total=0,
            stderr_bytes_total=0,
            combined_bytes_total=0,
            stdout_omitted_bytes_total=0,
            stderr_omitted_bytes_total=0,
            combined_omitted_bytes_total=0,
            redacted_head_excerpt="",
            redacted_tail_excerpt="",
            exit_code=None,
            termination_reason=None,
        )
        updated_attempt = replace(attempt, process_ids=attempt.process_ids + (process_id,))
        return replace(
            state,
            attempts=_replace_record(state.attempts, updated_attempt, "attempt_id"),
            processes=state.processes + (process,),
        )

    if event.event_type == "event_kernel.process.output_recorded":
        item = _mapping(_payload(event).get("process_output"))
        allowed = {
            "process_id",
            "attempt_id",
            "stream",
            "redacted_excerpt",
            "redaction_applied",
            "truncated",
            "stdout_bytes_total",
            "stderr_bytes_total",
            "combined_bytes_total",
            "stdout_omitted_bytes_total",
            "stderr_omitted_bytes_total",
            "combined_omitted_bytes_total",
            "sequence",
            "excerpt_digest",
        }
        if set(item).difference(allowed):
            raise IllegalTransitionError("process output contains unsupported fields")
        process_id = _first(item, "process_id")
        attempt_id = _first(item, "attempt_id")
        process = _find_record(state.processes, "process_id", process_id)
        if process is None or process.attempt_id != attempt_id:
            raise IllegalTransitionError("process output has an invalid attempt binding")
        if process.state is ProcessState.TERMINATED:
            raise IllegalTransitionError("process output cannot follow process termination")
        output = ProcessOutput(
            process_id=process_id,
            attempt_id=attempt_id,
            stream=_first(item, "stream"),
            redacted_excerpt=_first(item, "redacted_excerpt"),
            redaction_applied=_first(item, "redaction_applied"),
            truncated=_first(item, "truncated"),
            stdout_bytes_total=_first(item, "stdout_bytes_total"),
            stderr_bytes_total=_first(item, "stderr_bytes_total"),
            combined_bytes_total=_first(item, "combined_bytes_total"),
            stdout_omitted_bytes_total=_first(item, "stdout_omitted_bytes_total"),
            stderr_omitted_bytes_total=_first(item, "stderr_omitted_bytes_total"),
            combined_omitted_bytes_total=_first(item, "combined_omitted_bytes_total"),
        )
        sequence = _first(item, "sequence")
        if sequence != process.last_sequence + 1:
            raise IllegalTransitionError("process output sequence is not contiguous")
        if _first(item, "excerpt_digest") != hashlib.sha256(
            output.redacted_excerpt.encode("utf-8")
        ).hexdigest():
            raise IllegalTransitionError("process output excerpt digest is invalid")
        counters = (
            "stdout_bytes_total",
            "stderr_bytes_total",
            "combined_bytes_total",
            "stdout_omitted_bytes_total",
            "stderr_omitted_bytes_total",
            "combined_omitted_bytes_total",
        )
        if any(getattr(output, name) < getattr(process, name) for name in counters):
            raise IllegalTransitionError("process output counters must be monotonic")
        updated = replace(
            process,
            last_sequence=sequence,
            stdout_bytes_total=output.stdout_bytes_total,
            stderr_bytes_total=output.stderr_bytes_total,
            combined_bytes_total=output.combined_bytes_total,
            stdout_omitted_bytes_total=output.stdout_omitted_bytes_total,
            stderr_omitted_bytes_total=output.stderr_omitted_bytes_total,
            combined_omitted_bytes_total=output.combined_omitted_bytes_total,
            redacted_head_excerpt=(
                process.redacted_head_excerpt or output.redacted_excerpt
            ),
            redacted_tail_excerpt=output.redacted_excerpt,
        )
        return replace(state, processes=_replace_record(state.processes, updated, "process_id"))

    item = _mapping(_payload(event).get("process_terminal"))
    process_id = _first(item, "process_id")
    attempt_id = _first(item, "attempt_id")
    process = _find_record(state.processes, "process_id", process_id)
    if process is None or process.attempt_id != attempt_id or process.state is ProcessState.TERMINATED:
        raise IllegalTransitionError("process cannot be terminated in its current state")
    terminal = ProcessTerminal(
        process_id=process_id,
        attempt_id=attempt_id,
        exit_code=_first(item, "exit_code"),
        termination_reason=_first(item, "termination_reason"),
        stdout_bytes_total=_first(item, "stdout_bytes_total"),
        stderr_bytes_total=_first(item, "stderr_bytes_total"),
        combined_bytes_total=_first(item, "combined_bytes_total"),
        stdout_omitted_bytes_total=_first(item, "stdout_omitted_bytes_total"),
        stderr_omitted_bytes_total=_first(item, "stderr_omitted_bytes_total"),
        combined_omitted_bytes_total=_first(item, "combined_omitted_bytes_total"),
    )
    counters = (
        "stdout_bytes_total",
        "stderr_bytes_total",
        "combined_bytes_total",
        "stdout_omitted_bytes_total",
        "stderr_omitted_bytes_total",
        "combined_omitted_bytes_total",
    )
    if any(getattr(terminal, name) < getattr(process, name) for name in counters):
        raise IllegalTransitionError("process terminal counters cannot shrink")
    updated = replace(
        process,
        state=ProcessState.TERMINATED,
        exit_code=terminal.exit_code,
        termination_reason=terminal.termination_reason,
        stdout_bytes_total=terminal.stdout_bytes_total,
        stderr_bytes_total=terminal.stderr_bytes_total,
        combined_bytes_total=terminal.combined_bytes_total,
        stdout_omitted_bytes_total=terminal.stdout_omitted_bytes_total,
        stderr_omitted_bytes_total=terminal.stderr_omitted_bytes_total,
        combined_omitted_bytes_total=terminal.combined_omitted_bytes_total,
    )
    return replace(state, processes=_replace_record(state.processes, updated, "process_id"))


def _workflow_id(state: EventKernelState, event: SemanticEvent) -> str | None:
    return event.workflow_id or state.workflow_id


def _generation_from_created(state: EventKernelState, event: SemanticEvent, created: Mapping[str, Any]) -> int:
    orchestrator = _mapping(created.get("orchestrator"))
    generation = _mapping(orchestrator.get("generation"))
    number = _first(generation, "number", "generation")
    return number if type(number) is int and number >= 1 else state.generation


def _legacy_evidence(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    item = _mapping(_payload(event).get("evidence"))
    evidence_id = _first(item, "evidence_id", "id")
    if not isinstance(evidence_id, str) or not evidence_id:
        return state
    record = EvidenceRecord(evidence_id=evidence_id, origin=EvidenceOrigin.LEGACY)
    return replace(state, evidence=_replace_record(state.evidence, record, "evidence_id"))


def _legacy_finding(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    item = _mapping(_payload(event).get("finding"))
    finding_id = _first(item, "finding_id", "id")
    if not isinstance(finding_id, str) or not finding_id:
        return state
    evidence_ids = _first(item, "evidence_ids", default=())
    if not isinstance(evidence_ids, (list, tuple)):
        evidence_ids = ()
    evidence_ids = tuple(value for value in evidence_ids if isinstance(value, str) and value)
    if not evidence_ids:
        evidence_ids = (f"legacy-finding:{finding_id}",)
    subject_id = _first(item, "subject_id", "type", "title", default=finding_id)
    if not isinstance(subject_id, str) or not subject_id:
        subject_id = finding_id
    verdict_id = _first(item, "verdict_id", default=f"legacy-verdict:{finding_id}")
    if not isinstance(verdict_id, str) or not verdict_id:
        verdict_id = f"legacy-verdict:{finding_id}"
    record = FindingRecord(
        finding_id=finding_id,
        verdict_id=verdict_id,
        subject_id=subject_id,
        action_id=None,
        attempt_id=None,
        generation=state.generation,
        evidence_ids=evidence_ids,
        active=False,
        superseded_by_verdict_id=None,
        legacy_unverified=True,
    )
    return replace(state, findings=_replace_record(state.findings, record, "finding_id"))


def _legacy_stage(state: EventKernelState, event: SemanticEvent, status: str) -> EventKernelState:
    item = _payload(event)
    stage_id = item.get("stage")
    if not isinstance(stage_id, str) or not stage_id:
        return state
    statuses = _replace_record(
        state.stage_statuses,
        StageStatusRecord(stage_id=stage_id, status=status),
        "stage_id",
    )
    result_digests = state.stage_result_digests
    if status == "completed":
        result = _mapping(item.get("result"))
        supplied = _first(result, "result_digest", "digest")
        if not isinstance(supplied, str) or not supplied:
            canonical = json.dumps(
                _thaw(result),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            supplied = hashlib.sha256(canonical).hexdigest()
        result_digests = _replace_record(
            result_digests,
            StageResultDigest(stage_id=stage_id, result_digest=supplied),
            "stage_id",
        )
    return replace(state, stage_statuses=statuses, stage_result_digests=result_digests)


def _legacy_checkpoint(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    item = _mapping(_payload(event).get("checkpoint"))
    checkpoint_id = _first(item, "checkpoint_id", "id")
    path = _first(item, "relative_path", "path")
    if not isinstance(checkpoint_id, str) or not isinstance(path, str):
        return state
    revision = _first(item, "revision", default=event.revision or 1)
    if type(revision) is not int:
        raise CorruptEventLogError("legacy checkpoint revision must be an integer")
    hint = LegacyCheckpointHint(
        checkpoint_id=checkpoint_id,
        revision=revision,
        relative_path=path,
    )
    return replace(
        state,
        legacy_checkpoint_hints=_replace_record(
            state.legacy_checkpoint_hints,
            hint,
            "checkpoint_id",
        ),
    )


def _schema2_evidence(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    payload = _payload(event)
    attestation_data = _mapping(payload.get("attestation"))
    if not attestation_data:
        return state
    evidence_id = attestation_data.get("evidence_id")
    if not isinstance(evidence_id, str):
        raise EvidenceAttestationError("schema 2 evidence attestation requires evidence_id")

    def observation(data: Any) -> VerificationObservation:
        value = _mapping(data)
        return VerificationObservation(
            result_code=value.get("result_code", "unknown"),
            procedure_digest=value.get("procedure_digest", ""),
            observation_digest=value.get("observation_digest", ""),
        )

    reproduction = _mapping(attestation_data.get("reproduction"))
    attestation = EvidenceAttestation(
        evidence_id=evidence_id,
        evidence_sha256=attestation_data.get("evidence_sha256", ""),
        source_ref_digest=attestation_data.get("source_ref_digest", ""),
        action_id=attestation_data.get("action_id", ""),
        attempt_id=attestation_data.get("attempt_id", ""),
        generation=attestation_data.get("generation", event.generation),
        verifier_id=attestation_data.get("verifier_id", ""),
        verifier_version=attestation_data.get("verifier_version", ""),
        verification_policy_digest=attestation_data.get("verification_policy_digest", ""),
        baseline=observation(attestation_data.get("baseline")),
        control=observation(attestation_data.get("control")),
        reproduction=ReproductionObservation(
            result_code=reproduction.get("result_code", "unknown"),
            procedure_digest=reproduction.get("procedure_digest", ""),
            observation_digest=reproduction.get("observation_digest", ""),
            run_count=reproduction.get("run_count", 1),
            success_count=reproduction.get("success_count", 1),
        ),
    )
    record = EvidenceRecord(
        evidence_id=evidence_id,
        origin=EvidenceOrigin.SCHEMA_2,
        attestation=attestation,
    )
    if attestation.generation != event.generation:
        raise EvidenceAttestationError("evidence generation must match the event generation")
    action = _find_record(state.actions, "action_id", attestation.action_id)
    attempt = _find_record(state.attempts, "attempt_id", attestation.attempt_id)
    if (
        action is None
        or attempt is None
        or action.generation != attestation.generation
        or attempt.action_id != attestation.action_id
        or attempt.generation != attestation.generation
        or attempt.state is AttemptState.STARTED
    ):
        raise IllegalTransitionError(
            "evidence must bind to a matching action and terminal attempt"
        )
    existing = _find_record(state.evidence, "evidence_id", evidence_id)
    if existing is not None:
        if existing.attestation is not None and existing.attestation != attestation:
            raise EvidenceAttestationError("evidence identity and attestation are immutable")
        record = replace(existing, attestation=attestation)
    return replace(state, evidence=_replace_record(state.evidence, record, "evidence_id"))


def _schema2_verdict(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    raw_verdict = _payload(event).get("verdict")
    if raw_verdict is None:
        return state
    if not isinstance(raw_verdict, Mapping):
        raise EvidenceAttestationError("verdict must be an object")
    item = raw_verdict
    verdict_id = _first(item, "verdict_id", "id")
    if _find_record(state.verdicts, "verdict_id", verdict_id) is not None:
        raise IllegalTransitionError("verdict_id was already recorded")

    raw_finding = item.get("finding")
    if raw_finding is not None and not isinstance(raw_finding, Mapping):
        raise EvidenceAttestationError("finding must be an object")
    finding_data = raw_finding if raw_finding is not None else None
    finding = None
    if finding_data:
        finding = FindingCandidate(
            finding_id=_first(finding_data, "finding_id", "id"),
            subject_id=_first(finding_data, "subject_id"),
            action_id=_first(finding_data, "action_id"),
            attempt_id=_first(finding_data, "attempt_id"),
            generation=_first(finding_data, "generation"),
            evidence_ids=_ordered_ids(_first(finding_data, "evidence_ids", default=()), "finding evidence_ids"),
        )
    verdict = VerdictRecord(
        verdict_id=verdict_id,
        subject_id=_first(item, "subject_id"),
        action_id=_first(item, "action_id"),
        attempt_id=_first(item, "attempt_id"),
        status=_first(item, "status"),
        generation=_first(item, "generation", default=event.generation),
        evidence_ids=_ordered_ids(_first(item, "evidence_ids", default=()), "evidence_ids"),
        supersedes_verdict_id=_first(item, "supersedes_verdict_id"),
        finding=finding,
    )
    if verdict.generation != event.generation:
        raise IllegalTransitionError("verdict generation must match the event generation")
    action = _find_record(state.actions, "action_id", verdict.action_id)
    attempt = _find_record(state.attempts, "attempt_id", verdict.attempt_id) if verdict.attempt_id else None
    if action is None or action.generation != verdict.generation:
        raise IllegalTransitionError("verdict must bind to an action in its generation")
    if verdict.attempt_id is not None and (
        attempt is None
        or attempt.action_id != verdict.action_id
        or attempt.generation != verdict.generation
    ):
        raise IllegalTransitionError("verdict attempt must bind to its action")
    if verdict.status is VerdictStatus.VERIFIED:
        for evidence_id in verdict.evidence_ids:
            evidence = _find_record(state.evidence, "evidence_id", evidence_id)
            attestation = evidence.attestation if evidence is not None else None
            if (
                attestation is None
                or attestation.generation != verdict.generation
                or attestation.action_id != verdict.action_id
                or attestation.attempt_id != verdict.attempt_id
            ):
                raise EvidenceAttestationError(
                    "VERIFIED verdict evidence must exactly match generation, action, and attempt"
                )

    active = next((record for record in state.verdicts if record.subject_id == verdict.subject_id and record.active), None)
    if active is None and verdict.supersedes_verdict_id is not None:
        raise IllegalTransitionError("a verdict may supersede only an active verdict")
    if active is not None and verdict.supersedes_verdict_id != active.verdict_id:
        raise IllegalTransitionError("active subject verdict must be explicitly superseded")
    if verdict.supersedes_verdict_id is not None:
        previous = _find_record(state.verdicts, "verdict_id", verdict.supersedes_verdict_id)
        if previous is None or not previous.active or previous.subject_id != verdict.subject_id:
            raise IllegalTransitionError("verdict supersession must name the active subject verdict")
    if finding is not None:
        if verdict.status is not VerdictStatus.VERIFIED:
            raise EvidenceAttestationError("only VERIFIED verdicts may create findings")
        if _find_record(state.findings, "finding_id", finding.finding_id) is not None:
            raise IllegalTransitionError("finding_id was already recorded")
        if any(record.verdict_id == verdict.verdict_id for record in state.findings):
            raise EvidenceAttestationError("each verdict may create at most one finding")

    previous_verdicts = list(state.verdicts)
    previous_findings = list(state.findings)
    if active is not None:
        previous_verdicts = [
            replace(record, active=False, superseded_by_verdict_id=verdict.verdict_id)
            if record.verdict_id == active.verdict_id else record
            for record in previous_verdicts
        ]
        previous_findings = [
            replace(finding_record, active=False, superseded_by_verdict_id=verdict.verdict_id)
            if finding_record.verdict_id == active.verdict_id and finding_record.active else finding_record
            for finding_record in previous_findings
        ]
    recorded = VerdictStateRecord(
        verdict_id=verdict.verdict_id,
        subject_id=verdict.subject_id,
        action_id=verdict.action_id,
        attempt_id=verdict.attempt_id,
        status=verdict.status,
        generation=verdict.generation,
        evidence_ids=verdict.evidence_ids,
        active=True,
        supersedes_verdict_id=verdict.supersedes_verdict_id,
        superseded_by_verdict_id=None,
        recorded_at=event.timestamp or "event",
    )
    if finding is not None:
        previous_findings.append(
            FindingRecord(
                finding_id=finding.finding_id,
                verdict_id=verdict.verdict_id,
                subject_id=finding.subject_id,
                action_id=finding.action_id,
                attempt_id=finding.attempt_id,
                generation=finding.generation,
                evidence_ids=finding.evidence_ids,
                active=True,
                superseded_by_verdict_id=None,
                legacy_unverified=False,
            )
        )
    active_findings = tuple(record.finding_id for record in previous_findings if record.active)
    return replace(
        state,
        verdicts=tuple(previous_verdicts) + (recorded,),
        findings=tuple(previous_findings),
        active_findings=active_findings,
    )


def _reduce_outbox(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    item = _mapping(_payload(event).get("outbox"))
    event_type = event.event_type
    if event_type == "event_kernel.memory.enqueued":
        payload = _thaw(item.get("payload", {}))
        digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        from .envelope import make_outbox_id
        outbox_id = make_outbox_id(workflow_id=state.workflow_id or event.workflow_id, generation=event.generation, projector=item.get("projector"), dedupe_key=item.get("dedupe_key"), payload=payload)
        entry = OutboxEntry(outbox_id, state.workflow_id or event.workflow_id, event.generation, item.get("projector"), item.get("dedupe_key"), payload, digest, OutboxState.ENQUEUED, 0, event.revision)
        return replace(state, outbox=_replace_record(state.outbox, entry, "outbox_id"))
    existing = _find_record(state.outbox, "outbox_id", item.get("outbox_id"))
    if existing is None or (
        existing.status is not OutboxState.ENQUEUED
        and not (existing.status is OutboxState.FAILED and existing.retryable is True)
    ):
        raise IllegalTransitionError("memory delivery requires an enqueued outbox entry")
    if event_type == "event_kernel.memory.applied":
        entry = replace(
            existing,
            status=OutboxState.APPLIED,
            delivery_attempt=existing.delivery_attempt + 1,
            receipt_digest=item.get("receipt_digest"),
            error_code=None,
            failure_digest=None,
            retryable=None,
        )
    else:
        entry = replace(
            existing,
            status=OutboxState.FAILED,
            delivery_attempt=existing.delivery_attempt + 1,
            error_code=item.get("error_code"),
            failure_digest=item.get("failure_digest"),
            retryable=item.get("retryable"),
        )
    return replace(state, outbox=_replace_record(state.outbox, entry, "outbox_id"))


def _reduce_checkpoint(state: EventKernelState, event: SemanticEvent) -> EventKernelState:
    item = _mapping(_payload(event).get("checkpoint"))
    record = CheckpointRecord(
        checkpoint_id=item.get("checkpoint_id"),
        workflow_id=item.get("workflow_id"),
        generation=item.get("generation"),
        bound_revision=item.get("bound_revision"),
        bound_event_hash=item.get("bound_event_hash"),
        bound_event_id=item.get("bound_event_id"),
        binding_mode=item.get("binding_mode"),
        state_digest=item.get("state_digest"),
        event_file_prefix_sha256=item.get("event_file_prefix_sha256"),
        bound_prefix_bytes=item.get("bound_prefix_bytes"),
        relative_path=item.get("relative_path"),
        created_at=item.get("created_at"),
        checkpoint_file_sha256=item.get("checkpoint_file_sha256"),
        event_id=event.event_id,
        event_end_offset=item.get("event_end_offset"),
    )
    return replace(state, checkpoints=_replace_record(state.checkpoints, record, "checkpoint_id"))


def reduce_event(state: EventKernelState, semantic_event: SemanticEvent) -> EventKernelState:
    """Apply one immutable semantic event and return a new projection state."""

    if not isinstance(state, EventKernelState):
        raise TypeError("state must be EventKernelState")
    if not isinstance(semantic_event, SemanticEvent):
        raise TypeError("semantic_event must be SemanticEvent")
    if semantic_event.workflow_id and state.workflow_id and semantic_event.workflow_id != state.workflow_id:
        raise IllegalTransitionError("event workflow_id does not match materialized state")

    if semantic_event.schema_version == "1.0":
        if state.ownership is OwnershipState.EVENT_KERNEL_OWNED:
            raise MixedWriterError("schema 1.0 event occurred after ownership claim")
        event_type = semantic_event.event_type
        if event_type == "workflow.created":
            created = _mapping(_payload(semantic_event).get("state"))
            return replace(
                state,
                workflow_id=_workflow_id(state, semantic_event) or created.get("workflow_id"),
                generation=_generation_from_created(state, semantic_event, created),
            )
        if event_type == "phase.transitioned":
            phase = _payload(semantic_event).get("phase")
            return replace(state, phase=phase if isinstance(phase, str) else state.phase)
        if event_type == "evidence.registered":
            return _legacy_evidence(state, semantic_event)
        if event_type == "finding.promoted":
            return _legacy_finding(state, semantic_event)
        if event_type == "checkpoint.created":
            return _legacy_checkpoint(state, semantic_event)
        if event_type == "orchestrator.generation.started":
            generation = _mapping(_payload(semantic_event).get("generation"))
            number = _first(generation, "number", "generation")
            return replace(state, generation=number if type(number) is int else state.generation)
        if event_type == "orchestrator.stage.started":
            return _legacy_stage(state, semantic_event, "running")
        if event_type == "orchestrator.stage.completed":
            return _legacy_stage(state, semantic_event, "completed")
        if event_type == "orchestrator.stage.blocked":
            status = _payload(semantic_event).get("status", "blocked")
            return _legacy_stage(
                state,
                semantic_event,
                status if isinstance(status, str) and status else "blocked",
            )
        if event_type == "orchestrator.interrupted":
            return _legacy_stage(state, semantic_event, "interrupted")
        return state

    if semantic_event.event_type == "event_kernel.ownership.claimed":
        return replace(
            state,
            workflow_id=_workflow_id(state, semantic_event),
            generation=semantic_event.generation,
            ownership=OwnershipState.EVENT_KERNEL_OWNED,
        )
    if state.ownership is not OwnershipState.EVENT_KERNEL_OWNED:
        raise OwnershipClaimRequiredError("schema 2.0 event requires an ownership claim")
    if semantic_event.event_type in {
        "event_kernel.action.proposed",
        "event_kernel.action.merged",
        "event_kernel.action.deferred",
        "event_kernel.action.blocked",
    }:
        return _reduce_action(state, semantic_event)
    if semantic_event.event_type in {
        "event_kernel.attempt.started",
        "event_kernel.attempt.completed",
        "event_kernel.attempt.blocked",
        "event_kernel.attempt.cancelled",
    }:
        return _reduce_attempt(state, semantic_event)
    if semantic_event.event_type in {
        "event_kernel.process.started",
        "event_kernel.process.output_recorded",
        "event_kernel.process.terminated",
    }:
        return _reduce_process(state, semantic_event)
    if semantic_event.event_type == "event_kernel.evidence.attested":
        return _schema2_evidence(state, semantic_event)
    if semantic_event.event_type == "event_kernel.verdict.recorded":
        return _schema2_verdict(state, semantic_event)
    if semantic_event.event_type in {"event_kernel.memory.enqueued", "event_kernel.memory.applied", "event_kernel.memory.failed"}:
        return _reduce_outbox(state, semantic_event)
    if semantic_event.event_type == "event_kernel.checkpoint.created":
        return _reduce_checkpoint(state, semantic_event)
    return state


__all__ = ["reduce_event"]
