from __future__ import annotations

from core.request_broker.artifacts import ArtifactStore
from core.request_broker.oast import OastCallback, OastVerifier
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
    return CommandMeta(command_id, head.revision, head.event_hash, 1, "oast-test", command_id)


def _completed_attempt(tmp_path):
    kernel = EventKernel(tmp_path / "kernel")
    slug = "oast-proof"
    kernel.claim_workflow(
        slug,
        _meta(kernel, slug, "claim"),
        WorkflowOwnershipClaim("oast", "1", "a" * 64),
    )
    action = kernel.propose_action(
        slug,
        _meta(kernel, slug, "action"),
        ActionProposal("hunter_auto_ssrf", "https://target.test/fetch", "ssrf"),
    )
    attempt = kernel.start_attempt(
        slug,
        _meta(kernel, slug, "attempt"),
        AttemptStart(action.action_id, "oast", "verify"),
    )
    kernel.complete_attempt(
        slug,
        _meta(kernel, slug, "complete"),
        AttemptComplete(attempt.attempt_id, "completed", "b" * 64),
    )
    return kernel, slug, action.action_id, attempt.attempt_id


def test_matching_callback_without_negative_control_persists_verified_oast_evidence(tmp_path):
    kernel, slug, action_id, attempt_id = _completed_attempt(tmp_path)
    verifier = OastVerifier(ArtifactStore(tmp_path / "artifacts"), nonce_factory=lambda: "positive-nonce")
    scheduled = verifier.schedule("https://oast.test", workflow_id="wf-test", action_id=action_id, attempt_id=attempt_id)

    result = verifier.finalize(
        scheduled,
        [OastCallback("dns", "positive-nonce.oast.test", "oast.test")],
        [],
        event_kernel=kernel,
        slug=slug,
        meta_factory=lambda command_id: _meta(kernel, slug, command_id),
    )

    assert result.status == "verified"
    assert result.evidence_id == f"wf-test:1:{action_id}:{attempt_id}:oast"
    state = kernel.materialize(slug)
    assert state.evidence[0].attestation.evidence_id == result.evidence_id
    assert state.verdicts[0].status.value == "verified"


def test_negative_control_callback_refutes_oast_without_attesting_evidence(tmp_path):
    kernel, slug, action_id, attempt_id = _completed_attempt(tmp_path)
    verifier = OastVerifier(ArtifactStore(tmp_path / "artifacts"), nonce_factory=lambda: "positive-nonce")
    scheduled = verifier.schedule("https://oast.test", workflow_id="wf-test", action_id=action_id, attempt_id=attempt_id)

    result = verifier.finalize(
        scheduled,
        [OastCallback("http", "positive-nonce.oast.test", "oast.test")],
        [OastCallback("http", "control.oast.test", "oast.test")],
        event_kernel=kernel,
        slug=slug,
        meta_factory=lambda command_id: _meta(kernel, slug, command_id),
    )

    assert result.status == "refuted"
    state = kernel.materialize(slug)
    assert state.evidence == ()
    assert state.verdicts[0].status.value == "refuted"
