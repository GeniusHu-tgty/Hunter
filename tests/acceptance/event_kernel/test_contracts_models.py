from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict, fields, is_dataclass, replace
from enum import Enum
import hashlib
import importlib
import json
from typing import get_type_hints

import pytest


def _contracts():
    return importlib.import_module("core.workflow.event_kernel.contracts")


def _sha(character: str = "a") -> str:
    return character * 64


def _verification_observation():
    contracts = _contracts()
    return contracts.VerificationObservation(
        result_code="matched",
        procedure_digest=_sha("b"),
        observation_digest=_sha("c"),
    )


def _reproduction_observation(*, runs: int = 1, successes: int = 1):
    contracts = _contracts()
    return contracts.ReproductionObservation(
        result_code="matched",
        procedure_digest=_sha("b"),
        observation_digest=_sha("c"),
        run_count=runs,
        success_count=successes,
    )


def test_contract_module_exports_all_required_models_and_state_enums() -> None:
    contracts = _contracts()
    required = {
        "CommandMeta",
        "WorkflowOwnershipClaim",
        "ActionProposal",
        "ActionMerge",
        "ActionDecision",
        "AttemptStart",
        "AttemptComplete",
        "AttemptBlock",
        "AttemptCancel",
        "VerificationObservation",
        "ReproductionObservation",
        "EvidenceAttestation",
        "FindingCandidate",
        "VerdictRecord",
        "ProcessStart",
        "ProcessOutput",
        "ProcessTerminal",
        "MemoryEnqueue",
        "MemoryApplied",
        "MemoryFailed",
        "RecoveryRequest",
        "Head",
        "ReplayIssueKind",
        "ReplayIssue",
        "ReplayResult",
        "ReplayStats",
        "CommandResult",
        "OwnershipState",
        "ActionState",
        "AttemptState",
        "VerdictStatus",
        "ProcessState",
        "ProcessStream",
        "OutboxState",
        "HashMode",
        "CommandType",
        "EventType",
        "EvidenceOrigin",
        "LogicalActionRecord",
        "ExecutionAttemptRecord",
        "EvidenceRecord",
        "VerdictStateRecord",
        "FindingRecord",
        "ProcessRecord",
        "OutboxEntry",
        "StageStatusRecord",
        "StageResultDigest",
        "LegacyCheckpointHint",
        "BudgetMetrics",
        "CheckpointRecord",
        "EventKernelState",
        "EventIndexEntry",
        "CommandIndexEntry",
        "FrozenJsonArray",
        "FrozenJsonObject",
    }

    assert set(contracts.__all__) == required | {
        "EvidenceAttestationError",
        "InvalidCommandError",
        "SensitiveOutputRejectedError",
    }
    assert all(is_dataclass(getattr(contracts, name)) for name in required if name not in {
        "ReplayIssueKind",
        "OwnershipState",
        "ActionState",
        "AttemptState",
        "VerdictStatus",
        "ProcessState",
        "ProcessStream",
        "OutboxState",
        "HashMode",
        "CommandType",
        "EventType",
        "EvidenceOrigin",
    })
    assert all(
        issubclass(getattr(contracts, name), Enum)
        for name in {
            "ReplayIssueKind",
            "OwnershipState",
            "ActionState",
            "AttemptState",
            "VerdictStatus",
            "ProcessState",
            "ProcessStream",
            "OutboxState",
            "HashMode",
            "CommandType",
            "EventType",
            "EvidenceOrigin",
        }
    )
    assert all(
        "Any" not in repr(hint)
        for name in required
        if is_dataclass(getattr(contracts, name))
        for hint in get_type_hints(getattr(contracts, name)).values()
    )


def test_command_and_event_type_enums_lock_all_exact_stage1_pairs() -> None:
    contracts = _contracts()
    expected_pairs = (
        ("claim_workflow", "event_kernel.ownership.claimed"),
        ("propose_action", "event_kernel.action.proposed"),
        ("merge_action", "event_kernel.action.merged"),
        ("defer_action", "event_kernel.action.deferred"),
        ("block_action", "event_kernel.action.blocked"),
        ("start_attempt", "event_kernel.attempt.started"),
        ("complete_attempt", "event_kernel.attempt.completed"),
        ("block_attempt", "event_kernel.attempt.blocked"),
        ("cancel_attempt", "event_kernel.attempt.cancelled"),
        ("attest_evidence", "event_kernel.evidence.attested"),
        ("record_verdict", "event_kernel.verdict.recorded"),
        ("start_process", "event_kernel.process.started"),
        ("record_process_output", "event_kernel.process.output_recorded"),
        ("terminate_process", "event_kernel.process.terminated"),
        ("enqueue_memory", "event_kernel.memory.enqueued"),
        ("mark_memory_applied", "event_kernel.memory.applied"),
        ("mark_memory_failed", "event_kernel.memory.failed"),
        ("create_checkpoint", "event_kernel.checkpoint.created"),
        ("recover_checkpoint", "event_kernel.recovery.performed"),
    )

    assert tuple(item.value for item in contracts.CommandType) == tuple(
        command for command, _event in expected_pairs
    )
    assert tuple(item.value for item in contracts.EventType) == tuple(
        event for _command, event in expected_pairs
    )
    assert tuple(zip(contracts.CommandType, contracts.EventType, strict=True)) == tuple(
        (contracts.CommandType(command), contracts.EventType(event))
        for command, event in expected_pairs
    )


def test_state_and_issue_enums_lock_exact_values() -> None:
    contracts = _contracts()
    expected = {
        "OwnershipState": ("unclaimed_legacy", "event_kernel_owned"),
        "ActionState": (
            "proposed", "deferred", "blocked", "running", "retryable", "completed",
        ),
        "AttemptState": ("started", "completed", "blocked", "cancelled"),
        "VerdictStatus": ("likely", "verified", "refuted", "inconclusive"),
        "ProcessState": ("started", "terminated"),
        "ProcessStream": ("stdout", "stderr"),
        "OutboxState": ("enqueued", "applied", "failed"),
        "HashMode": ("empty", "hashed", "legacy_unbound"),
        "EvidenceOrigin": ("legacy", "schema_2"),
        "ReplayIssueKind": (
            "incomplete_final_line", "invalid_utf8", "invalid_json", "corrupt_chain",
            "unknown_event", "future_schema", "duplicate_event", "duplicate_command",
            "command_conflict", "ownership_claim_required", "mixed_writer",
            "illegal_transition",
        ),
    }

    for name, values in expected.items():
        assert tuple(item.value for item in getattr(contracts, name)) == values


def test_command_input_and_replay_contracts_lock_exact_public_field_names() -> None:
    contracts = _contracts()
    expected = {
        "CommandMeta": (
            "command_id", "expected_revision", "expected_event_hash", "generation",
            "correlation_id", "causation_id", "actor",
        ),
        "WorkflowOwnershipClaim": ("cutover_id", "owner_version", "legacy_gate_digest"),
        "ActionProposal": (
            "tool", "target", "kind", "arguments", "sources", "strategy_ids",
            "labels", "expected_evidence", "priority",
        ),
        "ActionMerge": (
            "action_id", "sources", "strategy_ids", "labels", "expected_evidence",
            "priority",
        ),
        "ActionDecision": ("action_id", "reason"),
        "AttemptStart": ("action_id", "executor", "budget_class"),
        "AttemptComplete": ("attempt_id", "result_code", "result_digest"),
        "AttemptBlock": ("attempt_id", "reason"),
        "AttemptCancel": ("attempt_id", "reason"),
        "VerificationObservation": (
            "result_code", "procedure_digest", "observation_digest",
        ),
        "ReproductionObservation": (
            "result_code", "procedure_digest", "observation_digest", "run_count",
            "success_count",
        ),
        "EvidenceAttestation": (
            "evidence_id", "evidence_sha256", "source_ref_digest", "action_id",
            "attempt_id", "generation", "verifier_id", "verifier_version",
            "verification_policy_digest", "baseline", "control", "reproduction",
        ),
        "FindingCandidate": (
            "finding_id", "subject_id", "action_id", "attempt_id", "generation",
            "evidence_ids",
        ),
        "VerdictRecord": (
            "verdict_id", "subject_id", "action_id", "status", "generation",
            "evidence_ids", "attempt_id", "supersedes_verdict_id", "finding",
        ),
        "ProcessStart": ("attempt_id", "process_name"),
        "ProcessOutput": (
            "process_id", "attempt_id", "stream", "redacted_excerpt",
            "redaction_applied", "truncated", "stdout_bytes_total",
            "stderr_bytes_total", "combined_bytes_total", "stdout_omitted_bytes_total",
            "stderr_omitted_bytes_total", "combined_omitted_bytes_total",
        ),
        "ProcessTerminal": (
            "process_id", "attempt_id", "exit_code", "termination_reason",
            "stdout_bytes_total", "stderr_bytes_total", "combined_bytes_total",
            "stdout_omitted_bytes_total", "stderr_omitted_bytes_total",
            "combined_omitted_bytes_total",
        ),
        "MemoryEnqueue": ("projector", "dedupe_key", "payload"),
        "MemoryApplied": ("outbox_id", "receipt_digest"),
        "MemoryFailed": (
            "outbox_id", "error_code", "failure_digest", "retryable",
        ),
        "RecoveryRequest": (
            "checkpoint_id", "expected_source_file_bytes", "expected_source_file_sha256",
        ),
        "Head": ("revision", "event_hash", "event_id", "hash_mode"),
        "ReplayIssue": ("kind", "message", "offset", "revision", "event_id", "line_number"),
        "ReplayStats": ("lines_read", "json_decodes", "reducer_calls"),
        "ReplayResult": (
            "state", "head", "event_count", "semantic_event_count",
            "valid_prefix_bytes", "event_file_prefix_sha256", "event_file_bytes",
            "event_file_sha256", "ownership", "event_index", "command_index",
            "ownership_claim_offset", "issue", "stats",
        ),
    }

    for name, expected_fields in expected.items():
        assert tuple(field.name for field in fields(getattr(contracts, name))) == expected_fields

def test_projection_contracts_lock_exact_public_field_names() -> None:
    contracts = _contracts()
    expected = {
        "LogicalActionRecord": (
            "action_id", "action_key", "generation", "tool", "target", "arguments",
            "kind", "sources", "strategy_ids", "labels", "expected_evidence",
            "priority", "state", "attempt_ids", "active_attempt_id",
        ),
        "ExecutionAttemptRecord": (
            "attempt_id", "action_id", "generation", "attempt_no", "executor",
            "budget_class", "state", "process_ids", "result_code", "result_digest",
            "terminal_reason",
        ),
        "EvidenceRecord": ("evidence_id", "origin", "attestation"),
        "VerdictStateRecord": (
            "verdict_id", "subject_id", "action_id", "attempt_id", "status",
            "generation", "evidence_ids", "active", "supersedes_verdict_id",
            "superseded_by_verdict_id", "recorded_at",
        ),
        "FindingRecord": (
            "finding_id", "verdict_id", "subject_id", "action_id", "attempt_id",
            "generation", "evidence_ids", "active", "superseded_by_verdict_id",
            "legacy_unverified",
        ),
        "ProcessRecord": (
            "process_id", "attempt_id", "process_name", "state", "last_sequence",
            "stdout_bytes_total", "stderr_bytes_total", "combined_bytes_total",
            "stdout_omitted_bytes_total", "stderr_omitted_bytes_total",
            "combined_omitted_bytes_total", "redacted_head_excerpt",
            "redacted_tail_excerpt", "exit_code", "termination_reason",
        ),
        "OutboxEntry": (
            "outbox_id", "workflow_id", "generation", "projector", "dedupe_key",
            "payload", "payload_digest", "status", "delivery_attempt",
            "enqueued_revision", "receipt_digest", "error_code", "failure_digest",
            "retryable",
        ),
        "StageStatusRecord": ("stage_id", "status"),
        "StageResultDigest": ("stage_id", "result_digest"),
        "LegacyCheckpointHint": ("checkpoint_id", "revision", "relative_path"),
        "BudgetMetrics": (
            "actions_proposed", "actions_deferred", "actions_blocked",
            "attempts_started", "attempts_completed", "attempts_blocked",
            "attempts_cancelled", "budget_charges",
        ),
        "CheckpointRecord": (
            "checkpoint_id", "workflow_id", "generation", "bound_revision",
            "bound_event_hash", "bound_event_id", "binding_mode", "state_digest",
            "event_file_prefix_sha256", "bound_prefix_bytes", "relative_path",
            "created_at", "checkpoint_file_sha256", "event_id", "event_end_offset",
        ),
        "EventKernelState": (
            "workflow_id", "generation", "ownership", "phase", "stage_statuses",
            "stage_result_digests", "legacy_checkpoint_hints", "actions", "attempts",
            "evidence", "verdicts", "findings", "active_findings", "processes",
            "outbox", "checkpoints", "budget",
        ),
        "EventIndexEntry": (
            "revision", "event_id", "event_type", "event_hash",
            "previous_event_hash", "schema_version", "generation", "byte_offset",
            "byte_length", "hash_mode",
        ),
        "CommandIndexEntry": (
            "command_id", "command_type", "command_digest", "event_id", "event_type",
            "revision", "event_hash", "generation", "byte_offset", "byte_length",
            "action_id", "attempt_id", "process_id", "outbox_id", "checkpoint_id",
        ),
        "FrozenJsonArray": ("values",),
        "FrozenJsonObject": ("items",),
    }

    for name, expected_fields in expected.items():
        assert tuple(field.name for field in fields(getattr(contracts, name))) == expected_fields


def test_event_kernel_state_and_replay_result_are_fully_typed_and_consistent() -> None:
    contracts = _contracts()
    state = contracts.EventKernelState(
        workflow_id="wf-0123456789ab",
        generation=1,
        ownership=contracts.OwnershipState.UNCLAIMED_LEGACY,
    )
    head = contracts.Head(
        revision=0,
        event_hash="",
        event_id=None,
        hash_mode=contracts.HashMode.EMPTY,
    )
    result = contracts.ReplayResult(
        state=state,
        head=head,
        event_count=0,
        semantic_event_count=0,
        valid_prefix_bytes=0,
        event_file_prefix_sha256=_sha("e"),
        event_file_bytes=0,
        event_file_sha256=_sha("e"),
        ownership=contracts.OwnershipState.UNCLAIMED_LEGACY,
    )

    replay_hints = get_type_hints(contracts.ReplayResult)
    assert all("Any" not in repr(hint) for hint in replay_hints.values())
    assert replay_hints["state"] is contracts.EventKernelState
    assert result.state == state
    assert result.event_index == result.command_index == ()
    assert state.actions == state.processes == state.outbox == ()

    with pytest.raises(contracts.InvalidCommandError):
        contracts.ReplayResult(
            state=None,
            head=head,
            event_count=0,
            semantic_event_count=0,
            valid_prefix_bytes=0,
            event_file_prefix_sha256=_sha("e"),
            event_file_bytes=0,
            event_file_sha256=_sha("e"),
            ownership=contracts.OwnershipState.UNCLAIMED_LEGACY,
        )
    with pytest.raises(contracts.InvalidCommandError):
        contracts.ReplayResult(
            state=state,
            head=head,
            event_count=0,
            semantic_event_count=0,
            valid_prefix_bytes=0,
            event_file_prefix_sha256=_sha("e"),
            event_file_bytes=0,
            event_file_sha256=_sha("e"),
            ownership=contracts.OwnershipState.EVENT_KERNEL_OWNED,
        )


def test_projection_records_validate_identity_state_and_compact_indexes() -> None:
    contracts = _contracts()
    action_id = "act-g000001-0123456789abcdef"
    attempt_id = "att-g000001-0123456789abcdef-000001"
    attestation = contracts.EvidenceAttestation(
        evidence_id="evidence-1",
        evidence_sha256=_sha("d"),
        source_ref_digest=_sha("e"),
        action_id=action_id,
        attempt_id=attempt_id,
        generation=1,
        verifier_id="verifier",
        verifier_version="1.0",
        verification_policy_digest=_sha("f"),
        baseline=_verification_observation(),
        control=_verification_observation(),
        reproduction=_reproduction_observation(),
    )
    action = contracts.LogicalActionRecord(
        action_id=action_id,
        action_key="0123456789abcdef" + "0" * 48,
        generation=1,
        tool="http_probe",
        target="https://example.test",
        arguments=contracts.FrozenJsonObject(),
        kind="recon",
        priority="P2",
        state=contracts.ActionState.RUNNING,
        attempt_ids=(attempt_id,),
        active_attempt_id=attempt_id,
    )
    attempt = contracts.ExecutionAttemptRecord(
        attempt_id=attempt_id,
        action_id=action_id,
        generation=1,
        attempt_no=1,
        executor="hunter_auto_sqli",
        budget_class="active-proof",
        state=contracts.AttemptState.STARTED,
    )
    evidence = contracts.EvidenceRecord(
        evidence_id="evidence-1",
        origin=contracts.EvidenceOrigin.SCHEMA_2,
        attestation=attestation,
    )
    event_entry = contracts.EventIndexEntry(
        revision=1,
        event_id="evt-0123456789abcdef",
        event_type=contracts.EventType.OWNERSHIP_CLAIMED.value,
        event_hash=_sha("a"),
        previous_event_hash="",
        schema_version="2.0",
        generation=1,
        byte_offset=0,
        byte_length=512,
        hash_mode=contracts.HashMode.HASHED,
    )
    command_entry = contracts.CommandIndexEntry(
        command_id="cmd-1",
        command_type=contracts.CommandType.CLAIM_WORKFLOW,
        command_digest=_sha("b"),
        event_id=event_entry.event_id,
        event_type=contracts.EventType.OWNERSHIP_CLAIMED,
        revision=1,
        event_hash=event_entry.event_hash,
        generation=1,
        byte_offset=0,
        byte_length=512,
    )

    assert evidence.attestation == attestation
    assert action.arguments == contracts.FrozenJsonObject()
    assert command_entry.event_id == event_entry.event_id

    with pytest.raises(contracts.InvalidCommandError):
        contracts.LogicalActionRecord(
            action_id=action_id,
            action_key="0123456789abcdef" + "0" * 48,
            generation=1,
            tool="http_probe",
            target="https://example.test",
            arguments=contracts.FrozenJsonObject(),
            kind="recon",
            priority="P2",
            state=contracts.ActionState.RUNNING,
            active_attempt_id=attempt_id,
        )
    with pytest.raises(contracts.InvalidCommandError):
        contracts.EvidenceRecord(
            evidence_id="other-evidence",
            origin=contracts.EvidenceOrigin.SCHEMA_2,
            attestation=attestation,
        )
    with pytest.raises(contracts.InvalidCommandError):
        contracts.EventIndexEntry(
            revision=1,
            event_id="evt-0123456789abcdef",
            event_type=contracts.EventType.OWNERSHIP_CLAIMED.value,
            event_hash=_sha("a"),
            previous_event_hash="",
            schema_version="2.0",
            generation=1,
            byte_offset=0,
            byte_length=0,
            hash_mode=contracts.HashMode.HASHED,
        )


def test_command_meta_has_exact_cas_generation_and_correlation_contract() -> None:
    contracts = _contracts()
    assert [field.name for field in fields(contracts.CommandMeta)] == [
        "command_id",
        "expected_revision",
        "expected_event_hash",
        "generation",
        "correlation_id",
        "causation_id",
        "actor",
    ]

    meta = contracts.CommandMeta(
        command_id="cmd-claim-alpha",
        expected_revision=0,
        expected_event_hash="",
        generation=1,
        correlation_id="corr-alpha",
    )

    assert asdict(meta) == {
        "command_id": "cmd-claim-alpha",
        "expected_revision": 0,
        "expected_event_hash": "",
        "generation": 1,
        "correlation_id": "corr-alpha",
        "causation_id": None,
        "actor": "hunter_tools",
    }
    with pytest.raises(FrozenInstanceError):
        meta.generation = 2


@pytest.mark.parametrize(
    "changes",
    [
        {"command_id": ""},
        {"expected_revision": -1},
        {"expected_revision": True},
        {"expected_event_hash": 7},
        {"expected_event_hash": "not-a-hash"},
        {"generation": 0},
        {"generation": True},
        {"correlation_id": ""},
        {"causation_id": ""},
        {"actor": ""},
    ],
)
def test_command_meta_rejects_invalid_local_fields(changes: dict[str, object]) -> None:
    contracts = _contracts()
    values = {
        "command_id": "cmd-1",
        "expected_revision": 0,
        "expected_event_hash": "",
        "generation": 1,
        "correlation_id": "corr-1",
        "causation_id": None,
        "actor": "hunter_tools",
    }
    values.update(changes)

    with pytest.raises(contracts.InvalidCommandError):
        contracts.CommandMeta(**values)


def test_claim_and_action_contracts_use_immutable_collection_defaults() -> None:
    contracts = _contracts()
    claim = contracts.WorkflowOwnershipClaim(
        cutover_id="cutover-1",
        owner_version="8.2",
        legacy_gate_digest=_sha(),
    )
    first = contracts.ActionProposal(
        tool="http_probe",
        target="https://example.test",
        arguments={"method": "GET"},
        kind="recon",
    )
    second = contracts.ActionProposal(
        tool="http_probe",
        target="https://example.test",
        kind="recon",
    )
    merge = contracts.ActionMerge(action_id="act-g000001-0123456789abcdef")

    assert asdict(claim)["cutover_id"] == "cutover-1"
    assert first.sources == second.sources == ()
    assert first.strategy_ids == second.strategy_ids == ()
    assert first.labels == second.labels == ()
    assert first.expected_evidence == second.expected_evidence == ()
    assert isinstance(first.arguments, contracts.FrozenJsonObject)
    assert second.arguments == contracts.FrozenJsonObject()
    assert first.arguments != second.arguments
    assert merge.priority is None
    with pytest.raises(FrozenInstanceError):
        merge.action_id = "changed"
    with pytest.raises(contracts.InvalidCommandError):
        contracts.ActionProposal(
            tool="http_probe",
            target="https://example.test",
            kind="recon",
            sources=frozenset({"source-a", "source-b"}),
        )


def test_attempt_contracts_are_serializable_and_locally_validated() -> None:
    contracts = _contracts()
    models = (
        contracts.AttemptStart(
            action_id="act-g000001-0123456789abcdef",
            executor="hunter_auto_sqli",
            budget_class="active-proof",
        ),
        contracts.AttemptComplete(
            attempt_id="att-g000001-0123456789abcdef-000001",
            result_code="completed",
            result_digest=_sha(),
        ),
        contracts.AttemptBlock(
            attempt_id="att-g000001-0123456789abcdef-000001",
            reason="executor_unavailable",
        ),
        contracts.AttemptCancel(
            attempt_id="att-g000001-0123456789abcdef-000001",
            reason="operator_cancelled",
        ),
    )

    assert all(asdict(model) for model in models)
    with pytest.raises(contracts.InvalidCommandError):
        contracts.AttemptStart(
            action_id="",
            executor="hunter_auto_sqli",
            budget_class="active-proof",
        )


def test_evidence_observations_are_distinct_and_require_exact_fields() -> None:
    contracts = _contracts()
    verification = _verification_observation()
    reproduction = _reproduction_observation(runs=3, successes=2)

    assert [field.name for field in fields(contracts.VerificationObservation)] == [
        "result_code",
        "procedure_digest",
        "observation_digest",
    ]
    assert [field.name for field in fields(contracts.ReproductionObservation)] == [
        "result_code",
        "procedure_digest",
        "observation_digest",
        "run_count",
        "success_count",
    ]
    assert asdict(verification)["result_code"] == "matched"
    assert asdict(reproduction)["success_count"] == 2

    for values in (
        {
            "result_code": "",
            "procedure_digest": _sha("b"),
            "observation_digest": _sha("c"),
        },
        {
            "result_code": "x" * 129,
            "procedure_digest": _sha("b"),
            "observation_digest": _sha("c"),
        },
        {
            "result_code": "matched",
            "procedure_digest": "",
            "observation_digest": _sha("c"),
        },
    ):
        with pytest.raises(contracts.EvidenceAttestationError):
            contracts.VerificationObservation(**values)

    for run_count, success_count in ((0, 0), (1, 0), (1, 2)):
        with pytest.raises(contracts.EvidenceAttestationError):
            contracts.ReproductionObservation(
                result_code="matched",
                procedure_digest=_sha("b"),
                observation_digest=_sha("c"),
                run_count=run_count,
                success_count=success_count,
            )


def test_evidence_attestation_and_verified_verdict_enforce_local_proof_shape() -> None:
    contracts = _contracts()
    observation = _reproduction_observation(runs=3, successes=3)
    attestation = contracts.EvidenceAttestation(
        evidence_id="evidence-1",
        evidence_sha256=_sha("d"),
        source_ref_digest=_sha("e"),
        action_id="act-g000001-0123456789abcdef",
        attempt_id="att-g000001-0123456789abcdef-000001",
        generation=1,
        verifier_id="verifier",
        verifier_version="1.0",
        verification_policy_digest=_sha("f"),
        baseline=_verification_observation(),
        control=_verification_observation(),
        reproduction=observation,
    )
    finding = contracts.FindingCandidate(
        finding_id="finding-1",
        subject_id="subject-1",
        action_id=attestation.action_id,
        attempt_id=attestation.attempt_id,
        generation=1,
        evidence_ids=("evidence-1",),
    )
    verdict = contracts.VerdictRecord(
        verdict_id="verdict-1",
        subject_id="subject-1",
        action_id=attestation.action_id,
        attempt_id=attestation.attempt_id,
        status=contracts.VerdictStatus.VERIFIED,
        generation=1,
        evidence_ids=("evidence-1",),
        finding=finding,
    )

    assert asdict(attestation)["reproduction"]["run_count"] == 3
    assert verdict.finding == finding

    with pytest.raises(contracts.EvidenceAttestationError):
        contracts.VerdictRecord(
            verdict_id="verdict-2",
            subject_id="subject-1",
            action_id=attestation.action_id,
            attempt_id=attestation.attempt_id,
            status=contracts.VerdictStatus.VERIFIED,
            generation=1,
            evidence_ids=(),
        )
    with pytest.raises(contracts.EvidenceAttestationError):
        contracts.VerdictRecord(
            verdict_id="verdict-3",
            subject_id="subject-1",
            action_id=attestation.action_id,
            attempt_id=attestation.attempt_id,
            status=contracts.VerdictStatus.VERIFIED,
            generation=1,
            evidence_ids=("evidence-1", "evidence-1"),
        )
    with pytest.raises(contracts.EvidenceAttestationError):
        contracts.VerdictRecord(
            verdict_id="verdict-4",
            subject_id="subject-1",
            action_id=attestation.action_id,
            attempt_id=attestation.attempt_id,
            status=contracts.VerdictStatus.LIKELY,
            generation=1,
            evidence_ids=("evidence-1",),
            finding=finding,
        )
    with pytest.raises(contracts.InvalidCommandError):
        contracts.VerdictRecord(
            verdict_id="verdict-self",
            subject_id="subject-1",
            action_id=attestation.action_id,
            attempt_id=attestation.attempt_id,
            status=contracts.VerdictStatus.VERIFIED,
            generation=1,
            evidence_ids=("evidence-1",),
            supersedes_verdict_id="verdict-self",
        )


def test_event_kernel_state_enforces_verdict_evidence_finding_and_supersession_graph() -> None:
    contracts = _contracts()
    action_id = "act-g000001-0123456789abcdef"
    attempt_id = "att-g000001-0123456789abcdef-000001"
    action = contracts.LogicalActionRecord(
        action_id=action_id,
        action_key="0123456789abcdef" + "0" * 48,
        generation=1,
        tool="http_probe",
        target="https://example.test",
        arguments=contracts.FrozenJsonObject(),
        kind="proof",
        priority="P1",
        state=contracts.ActionState.COMPLETED,
        attempt_ids=(attempt_id,),
    )
    attempt = contracts.ExecutionAttemptRecord(
        attempt_id=attempt_id,
        action_id=action_id,
        generation=1,
        attempt_no=1,
        executor="hunter_auto_sqli",
        budget_class="active-proof",
        state=contracts.AttemptState.COMPLETED,
        result_code="verified",
        result_digest=_sha("9"),
    )
    attestation = contracts.EvidenceAttestation(
        evidence_id="evidence-1",
        evidence_sha256=_sha("d"),
        source_ref_digest=_sha("e"),
        action_id=action_id,
        attempt_id=attempt_id,
        generation=1,
        verifier_id="verifier",
        verifier_version="1.0",
        verification_policy_digest=_sha("f"),
        baseline=_verification_observation(),
        control=_verification_observation(),
        reproduction=_reproduction_observation(),
    )
    evidence = contracts.EvidenceRecord(
        evidence_id="evidence-1",
        origin=contracts.EvidenceOrigin.SCHEMA_2,
        attestation=attestation,
    )
    verdict = contracts.VerdictStateRecord(
        verdict_id="verdict-1",
        subject_id="subject-1",
        action_id=action_id,
        attempt_id=attempt_id,
        status=contracts.VerdictStatus.VERIFIED,
        generation=1,
        evidence_ids=("evidence-1",),
        active=True,
        supersedes_verdict_id=None,
        superseded_by_verdict_id=None,
        recorded_at="2026-07-16T00:00:00.000000+00:00",
    )
    finding = contracts.FindingRecord(
        finding_id="finding-1",
        verdict_id="verdict-1",
        subject_id="subject-1",
        action_id=action_id,
        attempt_id=attempt_id,
        generation=1,
        evidence_ids=("evidence-1",),
        active=True,
        superseded_by_verdict_id=None,
        legacy_unverified=False,
    )
    values = {
        "workflow_id": "wf-0123456789ab",
        "generation": 1,
        "ownership": contracts.OwnershipState.EVENT_KERNEL_OWNED,
        "actions": (action,),
        "attempts": (attempt,),
        "evidence": (evidence,),
        "verdicts": (verdict,),
        "findings": (finding,),
        "active_findings": ("finding-1",),
        "budget": contracts.BudgetMetrics(
            actions_proposed=1,
            attempts_started=1,
            attempts_completed=1,
            budget_charges=1,
        ),
    }

    assert contracts.EventKernelState(**values).active_findings == ("finding-1",)

    invalid_verdicts = (
        replace(verdict, evidence_ids=("missing-evidence",)),
        replace(verdict, action_id="act-g000001-fedcba9876543210"),
        replace(verdict, attempt_id="att-g000001-0123456789abcdef-000002"),
        replace(verdict, generation=2),
    )
    for invalid_verdict in invalid_verdicts:
        with pytest.raises(contracts.EvidenceAttestationError):
            contracts.EventKernelState(**(values | {"verdicts": (invalid_verdict,)}))

    second_active = replace(verdict, verdict_id="verdict-2")
    with pytest.raises(contracts.InvalidCommandError):
        contracts.EventKernelState(**(values | {"verdicts": (verdict, second_active)}))

    duplicate_finding = replace(finding, finding_id="finding-2")
    with pytest.raises(contracts.EvidenceAttestationError):
        contracts.EventKernelState(
            **(
                values
                | {
                    "findings": (finding, duplicate_finding),
                    "active_findings": ("finding-1", "finding-2"),
                }
            )
        )

    for invalid_finding in (
        replace(finding, subject_id="other-subject"),
        replace(finding, evidence_ids=("missing-evidence",)),
    ):
        with pytest.raises(contracts.EvidenceAttestationError):
            contracts.EventKernelState(
                **(
                    values
                    | {
                        "findings": (invalid_finding,),
                        "active_findings": (invalid_finding.finding_id,),
                    }
                )
            )

    likely = replace(verdict, status=contracts.VerdictStatus.LIKELY)
    with pytest.raises(contracts.EvidenceAttestationError):
        contracts.EventKernelState(**(values | {"verdicts": (likely,)}))

    old = replace(
        verdict,
        active=False,
        superseded_by_verdict_id="verdict-2",
    )
    new = replace(
        verdict,
        verdict_id="verdict-2",
        supersedes_verdict_id="verdict-1",
    )
    superseded_finding = replace(
        finding,
        active=False,
        superseded_by_verdict_id="verdict-2",
    )
    assert contracts.EventKernelState(
        **(
            values
            | {
                "verdicts": (old, new),
                "findings": (superseded_finding,),
                "active_findings": (),
            }
        )
    ).verdicts == (old, new)

    malformed_new = replace(new, subject_id="other-subject")
    with pytest.raises(contracts.InvalidCommandError):
        contracts.EventKernelState(
            **(
                values
                | {
                    "verdicts": (old, malformed_new),
                    "findings": (superseded_finding,),
                    "active_findings": (),
                }
            )
        )


def test_process_output_has_no_raw_fields_and_checks_absolute_counters() -> None:
    contracts = _contracts()
    names = {field.name for field in fields(contracts.ProcessOutput)}
    forbidden = {"raw", "raw_bytes", "raw_stdout", "raw_stderr", "base64", "output"}
    assert not names & forbidden
    assert "sequence" not in names

    output = contracts.ProcessOutput(
        process_id="proc-0123456789abcdef",
        attempt_id="att-g000001-0123456789abcdef-000001",
        stream=contracts.ProcessStream.STDOUT,
        redacted_excerpt="request completed",
        redaction_applied=True,
        truncated=True,
        stdout_bytes_total=120,
        stderr_bytes_total=30,
        combined_bytes_total=150,
        stdout_omitted_bytes_total=20,
        stderr_omitted_bytes_total=5,
        combined_omitted_bytes_total=25,
    )
    assert asdict(output)["combined_bytes_total"] == 150
    assert output.stream is contracts.ProcessStream.STDOUT

    with pytest.raises(contracts.InvalidCommandError):
        contracts.ProcessOutput(
            process_id="proc-0123456789abcdef",
            attempt_id="att-g000001-0123456789abcdef-000001",
            stream="stdout",
            redacted_excerpt="request completed",
            redaction_applied=True,
            truncated=False,
            stdout_bytes_total=2,
            stderr_bytes_total=3,
            combined_bytes_total=4,
            stdout_omitted_bytes_total=0,
            stderr_omitted_bytes_total=0,
            combined_omitted_bytes_total=0,
        )
    with pytest.raises(contracts.SensitiveOutputRejectedError):
        contracts.ProcessOutput(
            process_id="proc-0123456789abcdef",
            attempt_id="att-g000001-0123456789abcdef-000001",
            stream="stderr",
            redacted_excerpt="password=secret",
            redaction_applied=True,
            truncated=False,
            stdout_bytes_total=0,
            stderr_bytes_total=15,
            combined_bytes_total=15,
            stdout_omitted_bytes_total=0,
            stderr_omitted_bytes_total=0,
            combined_omitted_bytes_total=0,
        )


def test_process_stream_excerpt_and_omitted_counter_contract_is_strict() -> None:
    contracts = _contracts()
    assert tuple(item.value for item in contracts.ProcessStream) == ("stdout", "stderr")
    assert get_type_hints(contracts.ProcessOutput)["stream"] is contracts.ProcessStream

    accepted = contracts.ProcessOutput(
        process_id="proc-0123456789abcdef",
        attempt_id="att-g000001-0123456789abcdef-000001",
        stream="stdout",
        redacted_excerpt="é" * 2048,
        redaction_applied=True,
        truncated=False,
        stdout_bytes_total=4096,
        stderr_bytes_total=0,
        combined_bytes_total=4096,
        stdout_omitted_bytes_total=0,
        stderr_omitted_bytes_total=0,
        combined_omitted_bytes_total=0,
    )
    assert accepted.stream is contracts.ProcessStream.STDOUT

    with pytest.raises(contracts.SensitiveOutputRejectedError):
        contracts.ProcessOutput(
            process_id="proc-0123456789abcdef",
            attempt_id="att-g000001-0123456789abcdef-000001",
            stream="stdout",
            redacted_excerpt="é" * 2049,
            redaction_applied=True,
            truncated=False,
            stdout_bytes_total=4098,
            stderr_bytes_total=0,
            combined_bytes_total=4098,
            stdout_omitted_bytes_total=0,
            stderr_omitted_bytes_total=0,
            combined_omitted_bytes_total=0,
        )
    with pytest.raises(contracts.SensitiveOutputRejectedError):
        contracts.ProcessOutput(
            process_id="proc-0123456789abcdef",
            attempt_id="att-g000001-0123456789abcdef-000001",
            stream="stdout",
            redacted_excerpt="x" * 4097,
            redaction_applied=True,
            truncated=False,
            stdout_bytes_total=4097,
            stderr_bytes_total=0,
            combined_bytes_total=4097,
            stdout_omitted_bytes_total=0,
            stderr_omitted_bytes_total=0,
            combined_omitted_bytes_total=0,
        )

    invalid_counters = (
        (False, 11, 0, 11, 1, 0, 1),
        (True, 10, 0, 10, 11, 0, 11),
        (True, 10, 5, 15, 1, 1, 3),
        (True, 10, 5, 15, 0, 0, 0),
    )
    for truncated, stdout, stderr, combined, stdout_omitted, stderr_omitted, combined_omitted in invalid_counters:
        with pytest.raises(contracts.InvalidCommandError):
            contracts.ProcessOutput(
                process_id="proc-0123456789abcdef",
                attempt_id="att-g000001-0123456789abcdef-000001",
                stream="stderr",
                redacted_excerpt="redacted",
                redaction_applied=True,
                truncated=truncated,
                stdout_bytes_total=stdout,
                stderr_bytes_total=stderr,
                combined_bytes_total=combined,
                stdout_omitted_bytes_total=stdout_omitted,
                stderr_omitted_bytes_total=stderr_omitted,
                combined_omitted_bytes_total=combined_omitted,
            )


@pytest.mark.parametrize(
    "excerpt",
    [
        "Authorization: Bearer abc.def",
        "Cookie: session=abc",
        "password=hunter2",
        "api_key=abc123",
        "refresh_token=abc123",
        "token=abc123",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_process_output_rejects_known_secret_markers(excerpt: str) -> None:
    contracts = _contracts()
    with pytest.raises(contracts.SensitiveOutputRejectedError):
        contracts.ProcessOutput(
            process_id="proc-0123456789abcdef",
            attempt_id="att-g000001-0123456789abcdef-000001",
            stream="stderr",
            redacted_excerpt=excerpt,
            redaction_applied=True,
            truncated=False,
            stdout_bytes_total=0,
            stderr_bytes_total=len(excerpt.encode("utf-8")),
            combined_bytes_total=len(excerpt.encode("utf-8")),
            stdout_omitted_bytes_total=0,
            stderr_omitted_bytes_total=0,
            combined_omitted_bytes_total=0,
        )


def test_process_terminal_and_memory_models_use_absolute_delivery_contracts() -> None:
    contracts = _contracts()
    terminal = contracts.ProcessTerminal(
        process_id="proc-0123456789abcdef",
        attempt_id="att-g000001-0123456789abcdef-000001",
        exit_code=0,
        termination_reason="exited",
        stdout_bytes_total=10,
        stderr_bytes_total=2,
        combined_bytes_total=12,
        stdout_omitted_bytes_total=0,
        stderr_omitted_bytes_total=0,
        combined_omitted_bytes_total=0,
    )
    enqueue_a = contracts.MemoryEnqueue(projector="target_memory", dedupe_key="finding:1")
    enqueue_b = contracts.MemoryEnqueue(projector="target_memory", dedupe_key="finding:2")
    applied = contracts.MemoryApplied(outbox_id="out-" + _sha(), receipt_digest=_sha("b"))
    failed = contracts.MemoryFailed(
        outbox_id="out-" + _sha(),
        error_code="sink_unavailable",
        failure_digest=_sha("c"),
        retryable=True,
    )

    assert asdict(terminal)["combined_bytes_total"] == 12
    assert enqueue_a.payload == enqueue_b.payload == contracts.FrozenJsonObject()
    assert applied.receipt_digest == _sha("b")
    assert failed.retryable is True


def test_action_and_memory_json_are_native_bounded_canonical_snapshots() -> None:
    contracts = _contracts()
    source = {
        "z": [1, True, None, {"nested": "value"}],
        "a": 1.5,
    }
    first = contracts.MemoryEnqueue(
        projector="target_memory",
        dedupe_key="finding:1",
        payload=source,
    )
    second = contracts.MemoryEnqueue(
        projector="target_memory",
        dedupe_key="finding:1",
        payload={"a": 1.5, "z": [1, True, None, {"nested": "value"}]},
    )
    action = contracts.ActionProposal(
        tool="http_probe",
        target="https://example.test",
        kind="recon",
        arguments=source,
    )

    source["z"][3]["nested"] = "mutated"
    assert first.payload == second.payload
    assert isinstance(first.payload, contracts.FrozenJsonObject)
    assert isinstance(action.arguments, contracts.FrozenJsonObject)
    assert "mutated" not in repr(first.payload)
    assert "mutated" not in repr(action.arguments)
    for model in (contracts.ActionProposal, contracts.MemoryEnqueue, contracts.OutboxEntry):
        assert all("Any" not in repr(hint) for hint in get_type_hints(model).values())

    large_action = contracts.ActionProposal(
        tool="http_probe",
        target="https://example.test",
        kind="recon",
        arguments={"value": "x" * 20_000},
    )
    assert isinstance(large_action.arguments, contracts.FrozenJsonObject)


def test_native_json_boundary_rejects_nonfinite_cycles_depth_and_oversize() -> None:
    contracts = _contracts()
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    too_deep: object = "leaf"
    for _ in range(40):
        too_deep = [too_deep]

    invalid_payloads = (
        {"value": b"raw"},
        {"value": {1, 2}},
        {1: "non-string key"},
        {"valid": 1, 2: "mixed key types"},
        {"value": float("nan")},
        {"value": float("inf")},
        cyclic,
        {"value": too_deep},
        {"value": "x" * 20_000},
    )
    for payload in invalid_payloads:
        with pytest.raises(contracts.InvalidCommandError):
            contracts.MemoryEnqueue(
                projector="target_memory",
                dedupe_key="finding:1",
                payload=payload,
            )

    frozen_value: object = "leaf"
    for _ in range(40):
        frozen_value = contracts.FrozenJsonArray((frozen_value,))
    with pytest.raises(contracts.InvalidCommandError):
        contracts.MemoryEnqueue(
            projector="target_memory",
            dedupe_key="finding:1",
            payload=contracts.FrozenJsonObject((("value", frozen_value),)),
        )
    with pytest.raises(contracts.InvalidCommandError):
        contracts.FrozenJsonObject((("x" * 257, 1),))


def test_head_hash_mode_contract_rejects_ambiguous_shapes() -> None:
    contracts = _contracts()
    assert contracts.Head(
        revision=1,
        event_hash=_sha("a"),
        event_id="evt-0123456789abcdef",
        hash_mode=contracts.HashMode.HASHED,
    ).hash_mode is contracts.HashMode.HASHED
    assert contracts.Head(
        revision=1,
        event_hash="",
        event_id="evt-0123456789ab",
        hash_mode=contracts.HashMode.LEGACY_UNBOUND,
    ).hash_mode is contracts.HashMode.LEGACY_UNBOUND
    legacy_entry = contracts.EventIndexEntry(
        revision=1,
        event_id="evt-0123456789ab",
        event_type="workflow.created",
        event_hash="",
        previous_event_hash="",
        schema_version="1.0",
        generation=1,
        byte_offset=0,
        byte_length=128,
        hash_mode=contracts.HashMode.LEGACY_UNBOUND,
    )
    claim_entry = contracts.EventIndexEntry(
        revision=5,
        event_id="evt-0123456789abcdef",
        event_type="event_kernel.ownership.claimed",
        event_hash=_sha("b"),
        previous_event_hash="legacy-sha256:" + _sha("a"),
        schema_version="2.0",
        generation=1,
        byte_offset=2045,
        byte_length=512,
        hash_mode=contracts.HashMode.HASHED,
    )
    assert legacy_entry.event_id == "evt-0123456789ab"
    assert claim_entry.previous_event_hash.startswith("legacy-sha256:")

    for values in (
        {
            "revision": 1,
            "event_hash": "bad-hash",
            "event_id": "evt-0123456789abcdef",
            "hash_mode": contracts.HashMode.HASHED,
        },
        {
            "revision": 1,
            "event_hash": _sha("a"),
            "event_id": "evt-0123456789abcdef",
            "hash_mode": contracts.HashMode.LEGACY_UNBOUND,
        },
        {
            "revision": 0,
            "event_hash": "",
            "event_id": None,
            "hash_mode": contracts.HashMode.HASHED,
        },
    ):
        with pytest.raises(contracts.InvalidCommandError):
            contracts.Head(**values)

    with pytest.raises(contracts.InvalidCommandError):
        contracts.EventIndexEntry(
            revision=1,
            event_id="evt-0123456789abcdef",
            event_type="workflow.created",
            event_hash=_sha("a"),
            previous_event_hash="",
            schema_version="1.0",
            generation=1,
            byte_offset=0,
            byte_length=128,
            hash_mode=contracts.HashMode.LEGACY_UNBOUND,
        )


def test_outbox_entry_validates_canonical_payload_digest_and_deterministic_id() -> None:
    contracts = _contracts()
    payload = {"finding_id": "finding-1", "scores": [1, 2]}
    canonical_payload = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    payload_digest = hashlib.sha256(canonical_payload).hexdigest()
    identity = {
        "workflow_id": "wf-0123456789ab",
        "generation": 1,
        "projector": "target_memory",
        "dedupe_key": "finding:1",
        "payload_digest": payload_digest,
    }
    canonical_identity = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    outbox_id = "out-" + hashlib.sha256(canonical_identity).hexdigest()
    entry = contracts.OutboxEntry(
        outbox_id=outbox_id,
        workflow_id=identity["workflow_id"],
        generation=1,
        projector="target_memory",
        dedupe_key="finding:1",
        payload=payload,
        payload_digest=payload_digest.upper(),
        status=contracts.OutboxState.ENQUEUED,
        delivery_attempt=0,
        enqueued_revision=7,
    )

    assert entry.payload_digest == payload_digest
    assert isinstance(entry.payload, contracts.FrozenJsonObject)
    for changes in (
        {"payload_digest": _sha("f")},
        {"outbox_id": "out-" + _sha("f")},
    ):
        values = {
            "outbox_id": outbox_id,
            "workflow_id": identity["workflow_id"],
            "generation": 1,
            "projector": "target_memory",
            "dedupe_key": "finding:1",
            "payload": payload,
            "payload_digest": payload_digest,
            "status": contracts.OutboxState.ENQUEUED,
            "delivery_attempt": 0,
            "enqueued_revision": 7,
        }
        values.update(changes)
        with pytest.raises(contracts.InvalidCommandError):
            contracts.OutboxEntry(**values)


def test_recovery_head_replay_issue_and_result_are_data_contracts() -> None:
    contracts = _contracts()
    recovery = contracts.RecoveryRequest(
        checkpoint_id="cp-0123456789abcdef",
        expected_source_file_bytes=4096,
        expected_source_file_sha256=_sha().upper(),
    )
    head = contracts.Head(
        revision=1,
        event_hash=_sha("b"),
        event_id="evt-0123456789abcdef",
        hash_mode=contracts.HashMode.HASHED,
    )
    state = contracts.EventKernelState(
        workflow_id="wf-0123456789ab",
        generation=1,
        ownership=contracts.OwnershipState.EVENT_KERNEL_OWNED,
    )
    event_entry = contracts.EventIndexEntry(
        revision=1,
        event_id=head.event_id,
        event_type=contracts.EventType.OWNERSHIP_CLAIMED.value,
        event_hash=head.event_hash,
        previous_event_hash="",
        schema_version="2.0",
        generation=1,
        byte_offset=0,
        byte_length=512,
        hash_mode=contracts.HashMode.HASHED,
    )
    command_entry = contracts.CommandIndexEntry(
        command_id="cmd-1",
        command_type=contracts.CommandType.CLAIM_WORKFLOW,
        command_digest=_sha("a"),
        event_id=head.event_id,
        event_type=contracts.EventType.OWNERSHIP_CLAIMED,
        revision=1,
        event_hash=head.event_hash,
        generation=1,
        byte_offset=0,
        byte_length=512,
    )
    result = contracts.ReplayResult(
        state=state,
        head=head,
        event_count=1,
        semantic_event_count=1,
        valid_prefix_bytes=512,
        event_file_prefix_sha256=_sha("c"),
        event_file_bytes=512,
        event_file_sha256=_sha("c"),
        ownership=contracts.OwnershipState.EVENT_KERNEL_OWNED,
        event_index=(event_entry,),
        command_index=(command_entry,),
        ownership_claim_offset=0,
        stats=contracts.ReplayStats(lines_read=1, json_decodes=1, reducer_calls=1),
    )
    issue = contracts.ReplayIssue(
        kind=contracts.ReplayIssueKind.INVALID_JSON,
        message="invalid JSON",
        offset=512,
        revision=2,
    )
    prefix = contracts.ReplayResult(
        state=state,
        head=head,
        event_count=1,
        semantic_event_count=1,
        valid_prefix_bytes=512,
        event_file_prefix_sha256=_sha("c"),
        event_file_bytes=600,
        event_file_sha256=_sha("d"),
        ownership=contracts.OwnershipState.EVENT_KERNEL_OWNED,
        event_index=(event_entry,),
        command_index=(command_entry,),
        ownership_claim_offset=0,
        issue=issue,
        stats=contracts.ReplayStats(lines_read=2, json_decodes=2, reducer_calls=1),
    )

    assert asdict(recovery)["expected_source_file_bytes"] == 4096
    assert recovery.expected_source_file_sha256 == _sha()
    assert not isinstance(issue, BaseException)
    assert prefix.issue == issue
    assert result.event_index == (event_entry,)
    assert result.command_index == (command_entry,)

    for changes in (
        {"checkpoint_id": "checkpoint-1"},
        {"expected_source_file_bytes": 0},
        {"expected_source_file_sha256": "not-a-hash"},
    ):
        values = {
            "checkpoint_id": "cp-0123456789abcdef",
            "expected_source_file_bytes": 4096,
            "expected_source_file_sha256": _sha(),
        }
        values.update(changes)
        with pytest.raises(contracts.InvalidCommandError):
            contracts.RecoveryRequest(**values)

    mismatched_command = replace(command_entry, event_hash=_sha("e"))
    inconsistent_results = (
        {"event_count": 2},
        {"event_file_bytes": 600},
        {"head": replace(head, event_hash=_sha("e"))},
        {"ownership_claim_offset": None},
        {"stats": contracts.ReplayStats(lines_read=1, json_decodes=1, reducer_calls=0)},
        {"command_index": (mismatched_command,)},
    )
    for changes in inconsistent_results:
        with pytest.raises(contracts.InvalidCommandError):
            replace(result, **changes)


def test_command_result_is_frozen_typed_and_enforces_generated_identity_shape() -> None:
    contracts = _contracts()
    assert tuple(field.name for field in fields(contracts.CommandResult)) == (
        "command_id",
        "event_id",
        "event_type",
        "revision",
        "event_hash",
        "generation",
        "cache_updated",
        "idempotent",
        "deduplicated",
        "original_command_id",
        "original_event_id",
        "action_id",
        "attempt_id",
        "process_id",
        "outbox_id",
        "checkpoint_id",
    )
    assert all("Any" not in repr(hint) for hint in get_type_hints(contracts.CommandResult).values())
    first = contracts.CommandResult(
        command_id="cmd-1",
        event_id="evt-0123456789abcdef",
        event_type="event_kernel.ownership.claimed",
        revision=1,
        event_hash=_sha(),
        generation=1,
    )
    idempotent = replace(first, idempotent=True)
    action_result = contracts.CommandResult(
        command_id="cmd-action",
        event_id="evt-1111111111111111",
        event_type=contracts.EventType.ACTION_PROPOSED,
        revision=2,
        event_hash=_sha("1"),
        generation=1,
        action_id="act-g000001-0123456789abcdef",
    )
    deduplicated = contracts.CommandResult(
        command_id="cmd-alias",
        event_id="evt-fedcba9876543210",
        event_type=contracts.EventType.MEMORY_ENQUEUED,
        revision=7,
        event_hash=_sha("b"),
        generation=1,
        deduplicated=True,
        original_command_id="cmd-original",
        original_event_id="evt-fedcba9876543210",
        outbox_id="out-" + _sha("c"),
    )

    assert asdict(first)["cache_updated"] is True
    assert first.event_type is contracts.EventType.OWNERSHIP_CLAIMED
    assert idempotent.idempotent is True
    assert action_result.action_id == "act-g000001-0123456789abcdef"
    assert deduplicated.original_event_id == deduplicated.event_id
    assert deduplicated.outbox_id == "out-" + _sha("c")
    with pytest.raises(FrozenInstanceError):
        first.revision = 3

    invalid_deduplicated = (
        {"idempotent": True},
        {"original_command_id": None},
        {"original_command_id": "cmd-alias"},
        {"original_event_id": "evt-0123456789abcdef"},
        {"event_type": contracts.EventType.ACTION_PROPOSED},
        {"outbox_id": None},
    )
    for changes in invalid_deduplicated:
        with pytest.raises(contracts.InvalidCommandError):
            replace(deduplicated, **changes)
    with pytest.raises(contracts.InvalidCommandError):
        replace(
            first,
            original_command_id="cmd-other",
            original_event_id=first.event_id,
        )
    with pytest.raises(contracts.InvalidCommandError):
        replace(action_result, action_id=None)
    with pytest.raises(contracts.InvalidCommandError):
        replace(first, action_id="act-g000001-0123456789abcdef")
