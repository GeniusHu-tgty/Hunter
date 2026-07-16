from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from core.workflow.event_kernel import (
    ActionProposal,
    AttemptComplete,
    AttemptStart,
    CommandMeta,
    EvidenceAttestation,
    EvidenceAttestationError,
    FindingCandidate,
    IllegalTransitionError,
    OwnershipState,
    ReproductionObservation,
    VerdictRecord,
    VerdictStatus,
    VerificationObservation,
    WorkflowOwnershipClaim,
)
from core.workflow.event_kernel.reducer import reduce_event
from core.workflow.event_kernel.service import EventKernel
from core.workflow.event_kernel.upcast import SemanticEvent


def _meta(kernel: EventKernel, slug: str, command_id: str) -> CommandMeta:
    head = kernel.head(slug)
    return CommandMeta(
        command_id=command_id,
        expected_revision=head.revision,
        expected_event_hash=head.event_hash,
        generation=1,
        correlation_id="corr-proof",
    )


def _setup(tmp_path: Path) -> tuple[EventKernel, str, str]:
    kernel = EventKernel(tmp_path)
    slug = "proof"
    kernel.claim_workflow(
        slug,
        _meta(kernel, slug, "claim"),
        WorkflowOwnershipClaim("cutover", "stage5", "a" * 64),
    )
    result = kernel.propose_action(
        slug,
        _meta(kernel, slug, "propose"),
        ActionProposal(
            tool="hunter_auto_sqli",
            target="https://example.test/login",
            kind="sqli",
            arguments={"param": "username"},
        ),
    )
    assert result.action_id is not None
    attempt = kernel.start_attempt(
        slug,
        _meta(kernel, slug, "start"),
        AttemptStart(result.action_id, "executor", "proof"),
    )
    assert attempt.attempt_id is not None
    kernel.complete_attempt(
        slug,
        _meta(kernel, slug, "complete"),
        AttemptComplete(attempt.attempt_id, "ok", "b" * 64),
    )
    return kernel, slug, result.action_id


def _attestation(action_id: str, attempt_id: str, evidence_id: str = "evidence-1") -> EvidenceAttestation:
    observation = VerificationObservation("ok", "c" * 64, "d" * 64)
    return EvidenceAttestation(
        evidence_id=evidence_id,
        evidence_sha256="e" * 64,
        source_ref_digest="f" * 64,
        action_id=action_id,
        attempt_id=attempt_id,
        generation=1,
        verifier_id="verifier",
        verifier_version="1",
        verification_policy_digest="1" * 64,
        baseline=observation,
        control=observation,
        reproduction=ReproductionObservation("ok", "2" * 64, "3" * 64, 2, 2),
    )


def _attest(kernel: EventKernel, slug: str, action_id: str, attempt_id: str, command_id: str, evidence_id: str = "evidence-1") -> None:
    kernel.attest_evidence(
        slug,
        _meta(kernel, slug, command_id),
        _attestation(action_id, attempt_id, evidence_id),
    )


def test_attestation_and_verified_verdict_persist_typed_proof_and_finding(tmp_path: Path) -> None:
    kernel, slug, action_id = _setup(tmp_path)
    attempt_id = kernel.materialize(slug).attempts[0].attempt_id
    _attest(kernel, slug, action_id, attempt_id, "attest")

    finding = FindingCandidate(
        finding_id="finding-1",
        subject_id="subject-1",
        action_id=action_id,
        attempt_id=attempt_id,
        generation=1,
        evidence_ids=("evidence-1",),
    )
    kernel.record_verdict(
        slug,
        _meta(kernel, slug, "verdict"),
        VerdictRecord(
            verdict_id="verdict-1",
            subject_id="subject-1",
            action_id=action_id,
            attempt_id=attempt_id,
            status=VerdictStatus.VERIFIED,
            generation=1,
            evidence_ids=("evidence-1",),
            finding=finding,
        ),
    )

    state = kernel.materialize(slug)
    assert state.evidence[0].attestation is not None
    assert state.evidence[0].attestation.baseline.result_code == "ok"
    assert state.evidence[0].attestation.verification_policy_digest == "1" * 64
    assert state.verdicts[0].active is True
    assert state.findings[0].finding_id == "finding-1"
    assert state.active_findings == ("finding-1",)


def test_legacy_evidence_can_only_become_verified_after_schema2_attestation(tmp_path: Path) -> None:
    kernel, slug, action_id = _setup(tmp_path)
    state = kernel.materialize(slug)
    attempt_id = state.attempts[0].attempt_id
    state = replace(state, ownership=OwnershipState.UNCLAIMED_LEGACY)
    legacy = reduce_event(
        state,
        SemanticEvent(
            "1.0", "evidence.registered", state.workflow_id, 1, None, None, None,
            {"evidence": {"evidence_id": "legacy-evidence"}},
        ),
    )
    legacy = replace(legacy, ownership=OwnershipState.EVENT_KERNEL_OWNED)
    with pytest.raises(EvidenceAttestationError):
        reduce_event(
            legacy,
            SemanticEvent(
                "2.0", "event_kernel.verdict.recorded", state.workflow_id, 1, None, None, "now",
                {"verdict": {"verdict_id": "v", "subject_id": "s", "action_id": action_id,
                              "attempt_id": attempt_id, "status": "verified", "generation": 1,
                              "evidence_ids": ["legacy-evidence"]}},
            ),
        )
    _attest(kernel, slug, action_id, attempt_id, "attest-legacy", "legacy-evidence")


def test_reducer_rejects_unbound_or_duplicate_proof_and_immutable_attestation(tmp_path: Path) -> None:
    kernel, slug, action_id = _setup(tmp_path)
    attempt_id = kernel.materialize(slug).attempts[0].attempt_id
    with pytest.raises(IllegalTransitionError):
        kernel.attest_evidence(
            slug,
            _meta(kernel, slug, "attest-before-terminal"),
            replace(_attestation(action_id, attempt_id), attempt_id="missing-attempt"),
        )

    _attest(kernel, slug, action_id, attempt_id, "attest")
    with pytest.raises(EvidenceAttestationError):
        kernel.attest_evidence(
            slug,
            _meta(kernel, slug, "attest-correction"),
            replace(_attestation(action_id, attempt_id), evidence_sha256="9" * 64),
        )

    state = kernel.materialize(slug)
    with pytest.raises(EvidenceAttestationError):
        reduce_event(
            state,
            SemanticEvent(
                "2.0", "event_kernel.verdict.recorded", state.workflow_id, 1, None, None, "now",
                {"verdict": {"verdict_id": "duplicate-evidence", "subject_id": "s",
                              "action_id": action_id, "attempt_id": attempt_id, "status": "verified",
                              "generation": 1, "evidence_ids": ["evidence-1", "evidence-1"]}},
            ),
        )


def test_verdict_supersession_is_bidirectional_and_deactivates_old_finding(tmp_path: Path) -> None:
    kernel, slug, action_id = _setup(tmp_path)
    attempt_id = kernel.materialize(slug).attempts[0].attempt_id
    _attest(kernel, slug, action_id, attempt_id, "attest")
    first = VerdictRecord(
        "verdict-1", "subject-1", action_id, VerdictStatus.VERIFIED, 1,
        ("evidence-1",), attempt_id, finding=FindingCandidate(
            "finding-1", "subject-1", action_id, attempt_id, 1, ("evidence-1",)
        ),
    )
    kernel.record_verdict(slug, _meta(kernel, slug, "verdict-1"), first)
    kernel.record_verdict(
        slug,
        _meta(kernel, slug, "verdict-2"),
        VerdictRecord("verdict-2", "subject-1", action_id, VerdictStatus.VERIFIED, 1,
                      ("evidence-1",), attempt_id, "verdict-1"),
    )
    state = kernel.materialize(slug)
    assert [(v.verdict_id, v.active, v.superseded_by_verdict_id) for v in state.verdicts] == [
        ("verdict-1", False, "verdict-2"), ("verdict-2", True, None)
    ]
    assert state.findings[0].active is False
    assert state.findings[0].superseded_by_verdict_id == "verdict-2"
    assert state.active_findings == ()


def test_verdict_requires_explicit_supersession_and_rejects_reused_ids_or_findings(tmp_path: Path) -> None:
    kernel, slug, action_id = _setup(tmp_path)
    attempt_id = kernel.materialize(slug).attempts[0].attempt_id
    _attest(kernel, slug, action_id, attempt_id, "attest")
    verdict = VerdictRecord("verdict-1", "subject-1", action_id, VerdictStatus.LIKELY, 1, (), attempt_id)
    kernel.record_verdict(slug, _meta(kernel, slug, "verdict-1"), verdict)

    with pytest.raises(IllegalTransitionError):
        kernel.record_verdict(
            slug, _meta(kernel, slug, "verdict-2"),
            VerdictRecord("verdict-2", "subject-1", action_id, VerdictStatus.REFUTED, 1, (), attempt_id),
        )
    with pytest.raises(IllegalTransitionError):
        kernel.record_verdict(slug, _meta(kernel, slug, "verdict-duplicate"), verdict)
    with pytest.raises(EvidenceAttestationError):
        VerdictRecord("bad-finding", "subject-1", action_id, VerdictStatus.LIKELY, 1, (), attempt_id,
                      finding=FindingCandidate("finding-2", "subject-1", action_id, attempt_id, 1, ("evidence-1",)))
