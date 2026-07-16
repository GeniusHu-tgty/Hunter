from __future__ import annotations

from core import auto_race
from core.request_broker.artifacts import ArtifactStore
from core.workflow.event_kernel import (
    ActionProposal,
    AttemptComplete,
    AttemptStart,
    CommandMeta,
    WorkflowOwnershipClaim,
)
from core.workflow.event_kernel.service import EventKernel


def _meta(kernel: EventKernel, slug: str, command_id: str) -> CommandMeta:
    head = kernel.head(slug)
    return CommandMeta(command_id, head.revision, head.event_hash, 1, "race-test", command_id)


def _completed_attempt(tmp_path):
    kernel = EventKernel(tmp_path / "kernel")
    slug = "race-proof"
    kernel.claim_workflow(slug, _meta(kernel, slug, "claim"), WorkflowOwnershipClaim("race", "1", "a" * 64))
    action = kernel.propose_action(
        slug, _meta(kernel, slug, "action"),
        ActionProposal("hunter_auto_race", "https://target.test/redeem", "race"),
    )
    attempt = kernel.start_attempt(slug, _meta(kernel, slug, "attempt"), AttemptStart(action.action_id, "race", "verify"))
    kernel.complete_attempt(slug, _meta(kernel, slug, "complete"), AttemptComplete(attempt.attempt_id, "completed", "b" * 64))
    return kernel, slug, action.action_id, attempt.attempt_id


def test_verified_race_result_creates_one_attested_manifest_and_verdict(tmp_path):
    kernel, slug, action_id, attempt_id = _completed_attempt(tmp_path)
    result = {
        "classification": "verified",
        "rounds": [{"control_normal": True, "invariant_violated": True}],
        "evidence": {"metadata": {"control_normal": True, "oracle_stable": True, "gate_verified": True}},
    }

    evidence_id = auto_race.persist_race_evidence(
        result,
        workflow_id="wf-race",
        action_id=action_id,
        attempt_id=attempt_id,
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        event_kernel=kernel,
        slug=slug,
        meta_factory=lambda command_id: _meta(kernel, slug, command_id),
    )

    assert evidence_id == f"wf-race:1:{action_id}:{attempt_id}:race"
    state = kernel.materialize(slug)
    assert [item.attestation.evidence_id for item in state.evidence] == [evidence_id]
    assert state.verdicts[0].status.value == "verified"


def test_race_attestation_uses_actual_successful_round_count(tmp_path):
    kernel, slug, action_id, attempt_id = _completed_attempt(tmp_path)
    result = {
        "classification": "verified",
        "rounds": [
            {"control_normal": True, "invariant_violated": True},
            {"control_normal": True, "invariant_violated": True},
            {"control_normal": True, "invariant_violated": True},
        ],
        "evidence": {"metadata": {"control_normal": True, "oracle_stable": True}},
    }

    auto_race.persist_race_evidence(
        result, workflow_id="wf-race", action_id=action_id, attempt_id=attempt_id,
        artifacts=ArtifactStore(tmp_path / "artifacts"), event_kernel=kernel, slug=slug,
        meta_factory=lambda command_id: _meta(kernel, slug, command_id),
    )

    assert kernel.materialize(slug).evidence[0].attestation.reproduction.run_count == 3
    assert kernel.materialize(slug).evidence[0].attestation.reproduction.success_count == 3
