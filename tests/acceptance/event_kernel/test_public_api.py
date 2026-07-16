from __future__ import annotations

import importlib
from pathlib import Path


EXPECTED_STAGE1_EXPORTS = (
    "ActionDecision", "ActionMerge", "ActionProposal", "ActionState",
    "AttemptBlock", "AttemptCancel", "AttemptComplete", "AttemptStart",
    "AttemptState", "BudgetMetrics", "CheckpointRecord", "CommandIndexEntry",
    "CommandType", "CommandMeta", "CommandResult", "EvidenceAttestation",
    "EvidenceAttestationError", "EvidenceOrigin", "EvidenceRecord",
    "EventIndexEntry", "EventKernelState", "EventType", "ExecutionAttemptRecord",
    "FindingRecord", "FrozenJsonArray", "FrozenJsonObject",
    "ReproductionObservation", "FindingCandidate", "HashMode", "Head",
    "InvalidCommandError", "LegacyCheckpointHint", "LogicalActionRecord",
    "MemoryApplied", "MemoryEnqueue", "MemoryFailed", "OutboxState",
    "OutboxEntry", "OwnershipState", "ProcessOutput", "ProcessStart",
    "ProcessState", "ProcessStream", "ProcessTerminal", "ProcessRecord",
    "RecoveryRequest", "ReplayIssue", "ReplayIssueKind", "ReplayResult",
    "ReplayStats", "SensitiveOutputRejectedError", "StageResultDigest",
    "StageStatusRecord", "VerdictRecord", "VerdictStateRecord", "VerdictStatus",
    "VerificationObservation", "WorkflowOwnershipClaim", "CheckpointBindingError",
    "CommandConflictError", "ConcurrencyConflictError", "CorruptEventLogError",
    "DuplicateCommittedCommandError", "DuplicateEventIdError", "EventKernelError",
    "IllegalTransitionError", "MixedWriterError", "OutboxConflictError",
    "OwnershipClaimRequiredError", "RecoveryNotAuthorizedError",
    "UnknownEventTypeError", "UnsupportedFutureSchemaError",
    "WorkflowAlreadyClaimedError", "WorkflowNotFoundError", "issue_to_error",
    "MAX_CANONICAL_JSON_BYTES", "SCHEMA2_EVENT_TYPES", "SCHEMA_VERSION",
    "build_event", "canonical_event_line", "canonical_json_bytes",
    "command_digest", "event_hash", "make_action_id", "make_attempt_id",
    "make_checkpoint_id", "make_event_id", "make_outbox_id", "make_process_id",
    "validate_event",
)


def test_event_kernel_package_explicitly_reexports_stage1_surface() -> None:
    api = importlib.import_module("core.workflow.event_kernel")
    contracts = importlib.import_module("core.workflow.event_kernel.contracts")
    envelope = importlib.import_module("core.workflow.event_kernel.envelope")
    errors = importlib.import_module("core.workflow.event_kernel.errors")

    assert api.__all__ == EXPECTED_STAGE1_EXPORTS
    for name in EXPECTED_STAGE1_EXPORTS:
        source = next(
            module
            for module in (contracts, errors, envelope)
            if name in module.__all__
        )
        assert getattr(api, name) is getattr(source, name)

    source_text = Path(api.__file__).read_text(encoding="utf-8")
    assert "import *" not in source_text


def test_event_kernel_package_has_no_arbitrary_event_write_api() -> None:
    api = importlib.import_module("core.workflow.event_kernel")

    forbidden = {
        "append_event",
        "record_event",
        "write_event",
        "commit_event",
    }

    assert forbidden.isdisjoint(api.__all__)
    assert all(not hasattr(api, name) for name in forbidden)
