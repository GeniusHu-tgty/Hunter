from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .contracts import (
    EvidenceAttestation,
    EvidenceOrigin,
    EvidenceRecord,
    EventKernelState,
    FindingRecord,
    LegacyCheckpointHint,
    OwnershipState,
    StageResultDigest,
    StageStatusRecord,
    VerificationObservation,
    ReproductionObservation,
)
from .errors import (
    CorruptEventLogError,
    EvidenceAttestationError,
    IllegalTransitionError,
    MixedWriterError,
    OwnershipClaimRequiredError,
)
from .upcast import SemanticEvent


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
    return replace(state, evidence=_replace_record(state.evidence, record, "evidence_id"))


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
    if semantic_event.event_type == "event_kernel.evidence.attested":
        return _schema2_evidence(state, semantic_event)
    return state


__all__ = ["reduce_event"]
