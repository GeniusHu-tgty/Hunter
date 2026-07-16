from __future__ import annotations

from copy import deepcopy

import pytest

from core.workflow.event_kernel.contracts import (
    EventKernelState,
    EvidenceOrigin,
    OwnershipState,
)
from core.workflow.event_kernel.errors import (
    UnknownEventTypeError,
    UnsupportedFutureSchemaError,
)
from core.workflow.event_kernel.reducer import reduce_event
from core.workflow.event_kernel.upcast import (
    LEGACY_EVENT_TYPES,
    SemanticEvent,
    upcast_event,
)


LEGACY_TYPES = (
    "workflow.created",
    "phase.transitioned",
    "hypothesis.added",
    "policy.changed",
    "dead_end.recorded",
    "evidence.registered",
    "finding.promoted",
    "checkpoint.created",
    "orchestrator.initialized",
    "orchestrator.observations.updated",
    "orchestrator.approval.recorded",
    "orchestrator.approval.consumed",
    "orchestrator.generation.started",
    "orchestrator.stage.started",
    "orchestrator.stage.completed",
    "orchestrator.stage.blocked",
    "orchestrator.interrupted",
    "orchestrator.completed",
)


def _legacy_event(event_type: str, payload: dict | None = None) -> dict:
    return {
        "schema_version": "1.0",
        "workflow_id": "wf-0123456789ab",
        "event_id": "evt-0123456789abcdef",
        "revision": 3,
        "generation": 1,
        "timestamp": "2026-07-16T08:00:00.000000+00:00",
        "type": event_type,
        "payload": payload or {},
    }


def test_schema_one_vocabulary_is_exactly_the_specified_eighteen_types() -> None:
    assert LEGACY_EVENT_TYPES == frozenset(LEGACY_TYPES)


@pytest.mark.parametrize("event_type", LEGACY_TYPES)
def test_upcast_recognizes_legacy_event_without_mutating_input(event_type: str) -> None:
    event = _legacy_event(event_type, {"nested": {"items": [1, 2]}})
    original = deepcopy(event)
    raw = b'{"schema_version":"1.0","type":"' + event_type.encode() + b'"}\n'

    semantic = upcast_event(event)

    assert isinstance(semantic, SemanticEvent)
    assert semantic.event_type == event_type
    assert semantic.schema_version == "1.0"
    assert semantic.payload["nested"]["items"] == (1, 2)
    with pytest.raises(TypeError):
        semantic.payload["new"] = "value"  # type: ignore[index]
    assert event == original
    assert raw == b'{"schema_version":"1.0","type":"' + event_type.encode() + b'"}\n'


def test_upcast_rejects_unknown_and_future_types_as_typed_replay_errors() -> None:
    unknown = _legacy_event("workflow.renamed")
    with pytest.raises(UnknownEventTypeError):
        upcast_event(unknown)

    future = {**unknown, "schema_version": "3.0", "type": "workflow.created"}
    with pytest.raises(UnsupportedFutureSchemaError):
        upcast_event(future)


def test_reducer_projects_legacy_state_without_history_or_raw_payload() -> None:
    state = EventKernelState(
        workflow_id=None,
        generation=1,
        ownership=OwnershipState.UNCLAIMED_LEGACY,
    )
    created = upcast_event(
        _legacy_event(
            "workflow.created",
            {
                "state": {
                    "workflow_id": "wf-0123456789ab",
                    "history": [{"secret": "must-not-project"}],
                    "orchestrator": {"generation": {"number": 4}},
                }
            },
        )
    )
    evidence = upcast_event(
        _legacy_event("evidence.registered", {"evidence": {"id": "ev-1"}})
    )
    finding = upcast_event(
        _legacy_event(
            "finding.promoted",
            {
                "finding": {
                    "id": "finding-1",
                    "title": "legacy finding",
                    "evidence_ids": ["ev-1"],
                }
            },
        )
    )
    stage = upcast_event(
        _legacy_event(
            "orchestrator.stage.completed",
            {"stage": "recon", "result": {"hosts": ["example.test"]}},
        )
    )

    after_created = reduce_event(state, created)
    after_evidence = reduce_event(after_created, evidence)
    after_finding = reduce_event(after_evidence, finding)
    projected = reduce_event(after_finding, stage)

    assert projected.workflow_id == "wf-0123456789ab"
    assert projected.generation == 4
    assert projected.evidence[0].origin is EvidenceOrigin.LEGACY
    assert projected.findings[0].active is False
    assert projected.findings[0].legacy_unverified is True
    assert projected.stage_statuses[0].status == "completed"
    assert projected.stage_result_digests[0].stage_id == "recon"
    assert not hasattr(projected, "history")
    assert "must-not-project" not in repr(projected)


def test_schema_two_ownership_reduction_is_pure() -> None:
    state = EventKernelState(
        workflow_id="wf-0123456789ab",
        generation=1,
        ownership=OwnershipState.UNCLAIMED_LEGACY,
    )
    semantic = SemanticEvent(
        schema_version="2.0",
        event_type="event_kernel.ownership.claimed",
        workflow_id="wf-0123456789ab",
        generation=2,
        revision=1,
        event_id="evt-0123456789abcdef",
        timestamp="2026-07-16T08:00:00.000000+00:00",
        payload={"claim": {"cutover_id": "cutover-1"}},
    )

    reduced = reduce_event(state, semantic)

    assert reduced is not state
    assert reduced.ownership is OwnershipState.EVENT_KERNEL_OWNED
    assert reduced.generation == 2
    assert state.ownership is OwnershipState.UNCLAIMED_LEGACY
