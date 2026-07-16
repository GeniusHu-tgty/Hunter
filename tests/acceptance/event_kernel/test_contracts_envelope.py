from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
import re

import pytest

from core.workflow.event_kernel.errors import (
    CheckpointBindingError,
    CommandConflictError,
    ConcurrencyConflictError,
    CorruptEventLogError,
    DuplicateCommittedCommandError,
    DuplicateEventIdError,
    EventKernelError,
    EvidenceAttestationError,
    IllegalTransitionError,
    InvalidCommandError,
    MixedWriterError,
    OutboxConflictError,
    OwnershipClaimRequiredError,
    RecoveryNotAuthorizedError,
    SensitiveOutputRejectedError,
    UnknownEventTypeError,
    UnsupportedFutureSchemaError,
    WorkflowAlreadyClaimedError,
    WorkflowNotFoundError,
    issue_to_error,
)


PUBLIC_LEAF_ERRORS = (
    WorkflowNotFoundError,
    InvalidCommandError,
    ConcurrencyConflictError,
    CommandConflictError,
    DuplicateCommittedCommandError,
    WorkflowAlreadyClaimedError,
    OwnershipClaimRequiredError,
    MixedWriterError,
    CorruptEventLogError,
    UnknownEventTypeError,
    UnsupportedFutureSchemaError,
    DuplicateEventIdError,
    IllegalTransitionError,
    EvidenceAttestationError,
    OutboxConflictError,
    SensitiveOutputRejectedError,
    CheckpointBindingError,
    RecoveryNotAuthorizedError,
)


def test_error_contract_has_exact_direct_leaf_hierarchy_and_unique_codes() -> None:
    assert len(PUBLIC_LEAF_ERRORS) == 18
    assert EventKernelError.__subclasses__() == list(PUBLIC_LEAF_ERRORS)
    assert all(error_type.__bases__ == (EventKernelError,) for error_type in PUBLIC_LEAF_ERRORS)
    assert {error_type: error_type.code for error_type in PUBLIC_LEAF_ERRORS} == {
        WorkflowNotFoundError: "workflow_not_found",
        InvalidCommandError: "invalid_command",
        ConcurrencyConflictError: "concurrency_conflict",
        CommandConflictError: "command_conflict",
        DuplicateCommittedCommandError: "duplicate_committed_command",
        WorkflowAlreadyClaimedError: "workflow_already_claimed",
        OwnershipClaimRequiredError: "ownership_claim_required",
        MixedWriterError: "mixed_writer",
        CorruptEventLogError: "corrupt_event_log",
        UnknownEventTypeError: "unknown_event_type",
        UnsupportedFutureSchemaError: "unsupported_future_schema",
        DuplicateEventIdError: "duplicate_event_id",
        IllegalTransitionError: "illegal_transition",
        EvidenceAttestationError: "evidence_attestation",
        OutboxConflictError: "outbox_conflict",
        SensitiveOutputRejectedError: "sensitive_output_rejected",
        CheckpointBindingError: "checkpoint_binding",
        RecoveryNotAuthorizedError: "recovery_not_authorized",
    }


def test_error_contract_bounds_message_and_preserves_location() -> None:
    error = InvalidCommandError(
        "x" * 700,
        slug="alpha",
        revision=42,
        event_id="evt-0123456789abcdef",
    )

    assert len(error.message) == 512
    assert str(error) == error.message
    assert error.slug == "alpha"
    assert error.revision == 42
    assert error.event_id == "evt-0123456789abcdef"


def test_error_contract_escapes_invalid_unicode_in_messages() -> None:
    error = UnknownEventTypeError("unknown type: event_kernel.\ud800")

    assert error.message.encode("utf-8")
    assert "\\ud800" in error.message


@pytest.mark.parametrize(
    ("raw_message", "secrets"),
    [
        (
            "process failed; Authorization: Bearer hunter-bearer-secret",
            ("hunter-bearer-secret",),
        ),
        (
            "process failed; Cookie: session=hunter-cookie-secret; "
            "csrftoken=hunter-csrf-secret",
            ("hunter-cookie-secret", "hunter-csrf-secret"),
        ),
        ("process failed; password=hunter-password-secret", ("hunter-password-secret",)),
        ("process failed; X-API-Key: hunter-api-secret", ("hunter-api-secret",)),
        (
            'process failed; "access_token":"hunter-token-secret"',
            ("hunter-token-secret",),
        ),
        (
            "process failed\n-----BEGIN PRIVATE KEY-----\n"
            "hunter-private-key-secret\n-----END PRIVATE KEY-----",
            ("hunter-private-key-secret",),
        ),
    ],
)
def test_error_contract_redacts_sensitive_markers_without_losing_location(
    raw_message: str,
    secrets: tuple[str, ...],
) -> None:
    direct = InvalidCommandError(
        raw_message,
        slug="alpha",
        revision=42,
        event_id="evt-0123456789abcdef",
    )
    converted = issue_to_error(
        {
            "kind": "invalid_json",
            "message": raw_message,
            "revision": 42,
            "event_id": "evt-0123456789abcdef",
        },
        slug="alpha",
    )

    for error in (direct, converted):
        rendered = f"{error.message} {error!s} {error!r}"
        assert "process failed" in error.message
        assert "REDACTED" in error.message
        assert all(secret not in rendered for secret in secrets)
        assert error.slug == "alpha"
        assert error.revision == 42
        assert error.event_id == "evt-0123456789abcdef"


@dataclass(frozen=True)
class _Issue:
    kind: str
    message: str
    revision: int
    event_id: str


@pytest.mark.parametrize(
    ("kind", "error_type"),
    [
        ("incomplete_final_line", CorruptEventLogError),
        ("invalid_utf8", CorruptEventLogError),
        ("invalid_json", CorruptEventLogError),
        ("unknown_event", UnknownEventTypeError),
        ("future_schema", UnsupportedFutureSchemaError),
        ("corrupt_chain", CorruptEventLogError),
        ("duplicate_event", DuplicateEventIdError),
        ("duplicate_command", DuplicateCommittedCommandError),
        ("command_conflict", CommandConflictError),
        ("ownership_claim_required", OwnershipClaimRequiredError),
        ("illegal_transition", IllegalTransitionError),
        ("mixed_writer", MixedWriterError),
        ("anything_else", CorruptEventLogError),
    ],
)
def test_issue_to_error_maps_objects_and_mappings(kind: str, error_type: type[EventKernelError]) -> None:
    issue = _Issue(kind, "broken", 7, "evt-0123456789abcdef")
    from_object = issue_to_error(issue, slug="alpha")
    from_mapping = issue_to_error(
        {
            "kind": kind,
            "message": "broken",
            "revision": 7,
            "event_id": "evt-0123456789abcdef",
        },
        slug="alpha",
    )

    assert isinstance(from_object, error_type)
    assert isinstance(from_mapping, error_type)
    assert from_object.message == from_mapping.message == "broken"
    assert from_object.slug == from_mapping.slug == "alpha"
    assert from_object.revision == from_mapping.revision == 7
    assert from_object.event_id == from_mapping.event_id == "evt-0123456789abcdef"


def test_canonical_json_bytes_is_sorted_compact_utf8() -> None:
    from core.workflow.event_kernel.envelope import canonical_json_bytes

    assert canonical_json_bytes({"z": [True, None, 1, 1.5], "a": "雪"}) == (
        '{"a":"雪","z":[true,null,1,1.5]}'.encode()
    )


class _Colour(Enum):
    RED = "red"


@pytest.mark.parametrize(
    "value",
    [
        (1, 2),
        _Issue("x", "y", 1, "evt-0123456789abcdef"),
        _Colour.RED,
        {1: "not a string key"},
        math.nan,
        math.inf,
        -math.inf,
        "\ud800",
        ["ok", {"nested": object()}],
    ],
)
def test_canonical_json_bytes_rejects_non_native_or_non_unicode_values(value: object) -> None:
    from core.workflow.event_kernel.envelope import canonical_json_bytes

    with pytest.raises(InvalidCommandError):
        canonical_json_bytes(value)


def test_canonical_json_bytes_rejects_values_over_256_kib() -> None:
    from core.workflow.event_kernel.envelope import canonical_json_bytes

    with pytest.raises(InvalidCommandError):
        canonical_json_bytes("x" * (256 * 1024))


def test_canonical_json_bytes_rejects_cycles_and_excessive_depth_as_invalid_command() -> None:
    from core.workflow.event_kernel.envelope import canonical_json_bytes

    cyclic: list[object] = []
    cyclic.append(cyclic)
    too_deep: object = None
    for _ in range(65):
        too_deep = [too_deep]

    for value in (cyclic, too_deep):
        with pytest.raises(InvalidCommandError) as caught:
            canonical_json_bytes(value)
        assert type(caught.value) is InvalidCommandError


def test_canonical_json_bytes_rejects_oversized_mapping_keys() -> None:
    from core.workflow.event_kernel.envelope import canonical_json_bytes

    with pytest.raises(InvalidCommandError, match="mapping key"):
        canonical_json_bytes({"k" * 4097: 1})


def test_action_and_attempt_ids_follow_generation_visible_contract() -> None:
    from core.workflow.event_kernel.envelope import make_action_id, make_attempt_id

    action_id = make_action_id(
        generation=1,
        tool="http_probe",
        target="https://example.test",
        arguments={"method": "GET", "headers": []},
        kind="recon",
    )

    assert action_id == "act-g000001-98b17fa495e9e7d4"
    assert make_attempt_id(action_id, 1) == "att-g000001-98b17fa495e9e7d4-000001"
    assert make_attempt_id(action_id, 999_999).endswith("-999999")


@pytest.mark.parametrize("generation", [0, -1, 1_000_000, True, 1.0])
def test_action_id_rejects_invalid_generation(generation: object) -> None:
    from core.workflow.event_kernel.envelope import make_action_id

    with pytest.raises(InvalidCommandError):
        make_action_id(
            generation=generation,
            tool="http_probe",
            target="https://example.test",
            arguments={},
            kind="recon",
        )


@pytest.mark.parametrize(
    ("action_id", "attempt_no"),
    [
        ("act-g000001-ABCDEF0123456789", 1),
        ("act-g000001-0123456789abcde", 1),
        ("act-g000000-0123456789abcdef", 1),
        ("act-g000001-0123456789abcdef", 0),
        ("act-g000001-0123456789abcdef", 1_000_000),
        ("act-g000001-0123456789abcdef", True),
    ],
)
def test_attempt_id_requires_legal_action_id_and_number(action_id: str, attempt_no: object) -> None:
    from core.workflow.event_kernel.envelope import make_attempt_id

    with pytest.raises(InvalidCommandError):
        make_attempt_id(action_id, attempt_no)


def test_generated_id_helpers_have_stable_formats() -> None:
    from core.workflow.event_kernel.envelope import (
        make_checkpoint_id,
        make_event_id,
        make_process_id,
    )

    assert re.fullmatch(r"evt-[0-9a-f]{16}", make_event_id())
    assert re.fullmatch(r"cp-[0-9a-f]{16}", make_checkpoint_id())
    assert re.fullmatch(r"proc-[0-9a-f]{16}", make_process_id())


def test_outbox_id_uses_canonical_identity_and_payload_digest() -> None:
    from core.workflow.event_kernel.envelope import make_outbox_id

    assert make_outbox_id(
        workflow_id="wf-0123456789ab",
        generation=1,
        projector="memory",
        dedupe_key="finding:7",
        payload={"value": "x"},
    ) == (
        "out-53b0e92d6d8776257a6373a617adadd302c245f019fe487fb37442e895c80c6a"
    )


def test_outbox_id_requires_a_json_object_payload() -> None:
    from core.workflow.event_kernel.envelope import make_outbox_id

    with pytest.raises(InvalidCommandError, match="payload must be a JSON object"):
        make_outbox_id(
            workflow_id="wf-0123456789ab",
            generation=1,
            projector="memory",
            dedupe_key="finding:7",
            payload=["not", "an", "object"],
        )


def _complete_digest_intent() -> dict[str, object]:
    return {
        "workflow_id": "wf-0123456789ab",
        "generation": 3,
        "actor": "hunter_tools",
        "correlation_id": "corr-proof-17",
        "causation_id": "evt-1111111111111111",
        "command": {
            "command_id": "cmd-start-17",
            "type": "start_attempt",
            "expected_revision": 40,
            "expected_event_hash": "1" * 64,
        },
        "payload": {
            "attempt_id": "semantic-payload-attempt-id",
            "attempt": {
                "attempt_no": 1,
                "attempt_id": "att-g000003-7fe42d7dfcbb2a10-000001",
                "action_id": "act-g000003-7fe42d7dfcbb2a10",
            },
            "process_output": {"sequence": 1, "stream": "stdout"},
            "outbox": {
                "outbox_id": "out-" + "2" * 64,
                "delivery_attempt": 1,
                "projector": "memory",
            },
            "checkpoint": {
                "checkpoint_id": "cp-1111111111111111",
                "checkpoint_file_sha256": "3" * 64,
                "checkpoint_relative_path": "checkpoints/event-kernel/old.json",
                "state_digest": "4" * 64,
            },
            "arguments": {
                "actor": "semantic-actor",
                "event_id": "semantic-event-id",
                "timestamp": "semantic-timestamp",
                "command_id": "semantic-command-id",
                "expected_revision": 7,
                "expected_event_hash": "semantic-expected-hash",
                "attempt_no": 8,
                "sequence": 9,
                "outbox_id": "semantic-outbox-id",
                "delivery_attempt": 10,
                "checkpoint_id": "semantic-checkpoint-id",
                "checkpoint_file_sha256": "semantic-checkpoint-sha",
                "checkpoint_relative_path": "semantic-checkpoint-path",
            },
        },
        "event_id": "evt-2222222222222222",
        "timestamp": "2026-07-16T08:00:00.000000+00:00",
    }


def _replace_path(document: dict[str, object], path: tuple[str, ...], value: object) -> None:
    current: dict[str, object] = document
    for component in path[:-1]:
        nested = current[component]
        assert isinstance(nested, dict)
        current = nested
    current[path[-1]] = value


def _changed_value(value: object) -> object:
    if type(value) is int:
        return value + 1
    if isinstance(value, str) and len(value) == 64:
        return "a" * 64 if value != "a" * 64 else "b" * 64
    if isinstance(value, str) and value.startswith("evt-"):
        return "evt-3333333333333333"
    if isinstance(value, str) and value.startswith("att-"):
        return "att-g000003-7fe42d7dfcbb2a10-000009"
    if isinstance(value, str) and value.startswith("out-"):
        return "out-" + "5" * 64
    if isinstance(value, str) and value.startswith("cp-"):
        return "cp-9999999999999999"
    return f"changed-{value}"


@pytest.mark.parametrize(
    ("generated_path", "semantic_path"),
    [
        (("actor",), ("payload", "arguments", "actor")),
        (("event_id",), ("payload", "arguments", "event_id")),
        (("timestamp",), ("payload", "arguments", "timestamp")),
        (("command", "command_id"), ("payload", "arguments", "command_id")),
        (
            ("command", "expected_revision"),
            ("payload", "arguments", "expected_revision"),
        ),
        (
            ("command", "expected_event_hash"),
            ("payload", "arguments", "expected_event_hash"),
        ),
        (("payload", "attempt", "attempt_no"), ("payload", "arguments", "attempt_no")),
        (("payload", "attempt", "attempt_id"), ("payload", "attempt_id")),
        (
            ("payload", "process_output", "sequence"),
            ("payload", "arguments", "sequence"),
        ),
        (("payload", "outbox", "outbox_id"), ("payload", "arguments", "outbox_id")),
        (
            ("payload", "outbox", "delivery_attempt"),
            ("payload", "arguments", "delivery_attempt"),
        ),
        (
            ("payload", "checkpoint", "checkpoint_id"),
            ("payload", "arguments", "checkpoint_id"),
        ),
        (
            ("payload", "checkpoint", "checkpoint_file_sha256"),
            ("payload", "arguments", "checkpoint_file_sha256"),
        ),
        (
            ("payload", "checkpoint", "checkpoint_relative_path"),
            ("payload", "arguments", "checkpoint_relative_path"),
        ),
    ],
)
def test_command_digest_excludes_generated_path_but_preserves_semantic_same_name(
    generated_path: tuple[str, ...],
    semantic_path: tuple[str, ...],
) -> None:
    from core.workflow.event_kernel.envelope import command_digest

    intent = _complete_digest_intent()
    generated_retry = copy.deepcopy(intent)
    generated_value = generated_retry
    for component in generated_path:
        generated_value = generated_value[component]
    _replace_path(generated_retry, generated_path, _changed_value(generated_value))
    assert command_digest(intent) == command_digest(generated_retry)

    semantic_change = copy.deepcopy(intent)
    semantic_value = semantic_change
    for component in semantic_path:
        semantic_value = semantic_value[component]
    _replace_path(semantic_change, semantic_path, _changed_value(semantic_value))
    assert command_digest(intent) != command_digest(semantic_change)


def test_command_digest_builds_exact_six_field_semantic_intent() -> None:
    from core.workflow.event_kernel.envelope import canonical_json_bytes, command_digest

    intent = _complete_digest_intent()
    payload = copy.deepcopy(intent["payload"])
    del payload["attempt"]["attempt_no"]
    del payload["attempt"]["attempt_id"]
    del payload["process_output"]["sequence"]
    del payload["outbox"]["outbox_id"]
    del payload["outbox"]["delivery_attempt"]
    del payload["checkpoint"]["checkpoint_id"]
    del payload["checkpoint"]["checkpoint_file_sha256"]
    del payload["checkpoint"]["checkpoint_relative_path"]
    normalized = {
        "workflow_id": intent["workflow_id"],
        "generation": intent["generation"],
        "type": intent["command"]["type"],
        "correlation_id": intent["correlation_id"],
        "causation_id": intent["causation_id"],
        "payload": payload,
    }
    expected = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()

    assert command_digest(intent) == expected


def test_command_digest_changes_for_command_type_and_checkpoint_state_digest() -> None:
    from core.workflow.event_kernel.envelope import command_digest

    intent = _complete_digest_intent()
    changed_type = copy.deepcopy(intent)
    changed_type["command"]["type"] = "complete_attempt"
    changed_state = copy.deepcopy(intent)
    changed_state["payload"]["checkpoint"]["state_digest"] = "a" * 64

    assert command_digest(intent) != command_digest(changed_type)
    assert command_digest(intent) != command_digest(changed_state)


def test_command_digest_rejects_unmodeled_semantic_root_fields() -> None:
    from core.workflow.event_kernel.envelope import command_digest

    intent = _complete_digest_intent()
    intent["unmodeled_semantic_field"] = "must not be silently dropped"

    with pytest.raises(InvalidCommandError):
        command_digest(intent)


def test_command_digest_ignores_only_exact_retry_and_lock_generated_paths() -> None:
    from core.workflow.event_kernel.envelope import command_digest

    intent = {
        "workflow_id": "wf-0123456789ab",
        "generation": 3,
        "type": "start_attempt",
        "actor": "caller-supplied-but-not-semantic",
        "correlation_id": "corr-proof-17",
        "causation_id": "evt-1111111111111111",
        "command": {
            "command_id": "cmd-original",
            "expected_revision": 40,
            "expected_event_hash": "1" * 64,
        },
        "payload": {
            "attempt": {
                "action_id": "act-g000003-7fe42d7dfcbb2a10",
                "executor": "hunter_auto_sqli",
                "attempt_no": 1,
                "attempt_id": "att-g000003-7fe42d7dfcbb2a10-000001",
            },
            "process_output": {
                "sequence": 1,
                "stream": "stdout",
            },
            "outbox": {
                "outbox_id": "out-" + "2" * 64,
                "delivery_attempt": 1,
                "projector": "memory",
            },
            "checkpoint": {
                "checkpoint_id": "cp-1111111111111111",
                "checkpoint_file_sha256": "3" * 64,
                "checkpoint_relative_path": "checkpoints/event-kernel/old.json",
            },
            "arguments": {
                "sequence": 1,
                "attempt_no": 1,
                "checkpoint_id": "semantic-user-value",
            },
        },
        "event_id": "evt-2222222222222222",
        "timestamp": "2026-07-16T08:00:00.000000+00:00",
    }
    retried = {
        **intent,
        "actor": "different-actor",
        "command": {
            "command_id": "cmd-retry",
            "expected_revision": 99,
            "expected_event_hash": "4" * 64,
        },
        "payload": {
            **intent["payload"],
            "attempt": {
                **intent["payload"]["attempt"],
                "attempt_no": 9,
                "attempt_id": "att-g000003-7fe42d7dfcbb2a10-000009",
            },
            "process_output": {
                **intent["payload"]["process_output"],
                "sequence": 19,
            },
            "outbox": {
                **intent["payload"]["outbox"],
                "outbox_id": "out-" + "5" * 64,
                "delivery_attempt": 7,
            },
            "checkpoint": {
                "checkpoint_id": "cp-9999999999999999",
                "checkpoint_file_sha256": "6" * 64,
                "checkpoint_relative_path": "checkpoints/event-kernel/new.json",
            },
        },
        "event_id": "evt-3333333333333333",
        "timestamp": "2026-07-16T09:00:00.000000+00:00",
    }

    assert command_digest(intent) == command_digest(retried)

    semantic_change = copy.deepcopy(retried)
    semantic_change["payload"]["arguments"]["sequence"] = 2
    assert command_digest(intent) != command_digest(semantic_change)


@pytest.mark.parametrize(
    "excluded_but_invalid",
    [
        {"command": {"expected_revision": object()}, "payload": {}},
        {"payload": {"attempt": {"attempt_id": object()}}},
        {"payload": {"attempt": {"attempt_id": "x" * (256 * 1024)}}},
    ],
)
def test_command_digest_validates_complete_intent_before_projection(
    excluded_but_invalid: dict[str, object],
) -> None:
    from core.workflow.event_kernel.envelope import command_digest

    with pytest.raises(InvalidCommandError) as caught:
        command_digest(excluded_but_invalid)
    assert type(caught.value) is InvalidCommandError


def test_command_digest_changes_when_semantic_intent_changes() -> None:
    from core.workflow.event_kernel.envelope import command_digest

    intent = {
        "workflow_id": "wf-0123456789ab",
        "generation": 3,
        "type": "start_attempt",
        "correlation_id": "corr-proof-17",
        "causation_id": None,
        "payload": {"executor": "hunter_auto_sqli"},
    }
    changed = {
        **intent,
        "payload": {"executor": "hunter_auto_xss"},
    }

    assert command_digest(intent) != command_digest(changed)


EXPECTED_SCHEMA2_EVENT_TYPES = frozenset(
    {
        "event_kernel.ownership.claimed",
        "event_kernel.action.proposed",
        "event_kernel.action.merged",
        "event_kernel.action.deferred",
        "event_kernel.action.blocked",
        "event_kernel.attempt.started",
        "event_kernel.attempt.completed",
        "event_kernel.attempt.blocked",
        "event_kernel.attempt.cancelled",
        "event_kernel.evidence.attested",
        "event_kernel.verdict.recorded",
        "event_kernel.process.started",
        "event_kernel.process.output_recorded",
        "event_kernel.process.terminated",
        "event_kernel.memory.enqueued",
        "event_kernel.memory.applied",
        "event_kernel.memory.failed",
        "event_kernel.checkpoint.created",
        "event_kernel.recovery.performed",
    }
)

EXPECTED_COMMAND_EVENT_PAIRS = (
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


def test_schema2_event_type_vocabulary_is_complete_and_namespaced() -> None:
    from core.workflow.event_kernel.envelope import SCHEMA2_EVENT_TYPES

    assert SCHEMA2_EVENT_TYPES == EXPECTED_SCHEMA2_EVENT_TYPES
    assert all(event_type.startswith("event_kernel.") for event_type in SCHEMA2_EVENT_TYPES)


def test_envelope_public_exports_are_exact_and_stable() -> None:
    from core.workflow.event_kernel import envelope

    assert envelope.__all__ == [
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


def _build_valid_event(**overrides: object) -> dict[str, object]:
    from core.workflow.event_kernel.envelope import build_event

    arguments: dict[str, object] = {
        "workflow_id": "wf-0123456789ab",
        "actor": "hunter_tools",
        "event_type": "event_kernel.action.proposed",
        "revision": 1,
        "previous_event_hash": "",
        "generation": 1,
        "correlation_id": "corr-proof-17",
        "causation_id": None,
        "command": {
            "command_id": "cmd-propose-17",
            "type": "propose_action",
            "digest": "1" * 64,
            "expected_revision": 0,
            "expected_event_hash": "",
        },
        "payload": {"action": {"kind": "recon", "target": "https://example.test"}},
        "event_id": "evt-0123456789abcdef",
        "timestamp": "2026-07-16T08:00:00.000000+00:00",
    }
    arguments.update(overrides)
    return build_event(**arguments)


@pytest.mark.parametrize(("command_type", "event_type"), EXPECTED_COMMAND_EVENT_PAIRS)
def test_build_event_and_validate_event_accept_all_exact_command_event_pairs(
    command_type: str,
    event_type: str,
) -> None:
    from core.workflow.event_kernel.envelope import validate_event

    event = _build_valid_event(
        event_type=event_type,
        command={
            "command_id": f"cmd-{command_type}",
            "type": command_type,
            "digest": "1" * 64,
            "expected_revision": 0,
            "expected_event_hash": "",
        },
    )

    assert validate_event(event) is None


@pytest.mark.parametrize(
    ("command_type", "event_type"),
    [
        (command_type, EXPECTED_COMMAND_EVENT_PAIRS[(index + 1) % 19][1])
        for index, (command_type, _) in enumerate(EXPECTED_COMMAND_EVENT_PAIRS)
    ],
)
def test_build_event_rejects_all_mismatched_command_event_pairs(
    command_type: str,
    event_type: str,
) -> None:
    with pytest.raises(InvalidCommandError, match="command/event type pair"):
        _build_valid_event(
            event_type=event_type,
            command={
                "command_id": f"cmd-{command_type}",
                "type": command_type,
                "digest": "1" * 64,
                "expected_revision": 0,
                "expected_event_hash": "",
            },
        )


@pytest.mark.parametrize(
    ("command_type", "event_type", "wrong_command_type"),
    [
        (
            command_type,
            event_type,
            EXPECTED_COMMAND_EVENT_PAIRS[(index + 1) % 19][0],
        )
        for index, (command_type, event_type) in enumerate(EXPECTED_COMMAND_EVENT_PAIRS)
    ],
)
def test_validate_event_rejects_all_persisted_command_event_pair_mismatches(
    command_type: str,
    event_type: str,
    wrong_command_type: str,
) -> None:
    from core.workflow.event_kernel.envelope import event_hash, validate_event

    event = _build_valid_event(
        event_type=event_type,
        command={
            "command_id": f"cmd-{command_type}",
            "type": command_type,
            "digest": "1" * 64,
            "expected_revision": 0,
            "expected_event_hash": "",
        },
    )
    event["command"]["type"] = wrong_command_type
    event["event_hash"] = event_hash(event)

    with pytest.raises(CorruptEventLogError, match="command/event type pair"):
        validate_event(event)


def test_build_event_constructs_exact_schema2_envelope_and_hash() -> None:
    from core.workflow.event_kernel.envelope import event_hash, validate_event

    event = _build_valid_event()

    assert set(event) == {
        "event_id",
        "schema_version",
        "workflow_id",
        "actor",
        "type",
        "timestamp",
        "revision",
        "previous_event_hash",
        "generation",
        "correlation_id",
        "causation_id",
        "command",
        "payload",
        "event_hash",
    }
    assert event["schema_version"] == "2.0"
    assert event["event_hash"] == event_hash(event)
    assert validate_event(event) is None


def test_build_event_deep_snapshots_mutable_command_and_payload() -> None:
    from core.workflow.event_kernel.envelope import validate_event

    command = {
        "command_id": "cmd-propose-17",
        "type": "propose_action",
        "digest": "1" * 64,
        "expected_revision": 0,
        "expected_event_hash": "",
    }
    payload = {"action": {"tags": ["recon"]}}

    event = _build_valid_event(command=command, payload=payload)
    command["command_id"] = "cmd-mutated"
    payload["action"]["tags"].append("mutated")

    assert event["command"]["command_id"] == "cmd-propose-17"
    assert event["payload"] == {"action": {"tags": ["recon"]}}
    assert validate_event(event) is None


def test_build_event_payload_limit_is_measured_on_payload_not_whole_envelope() -> None:
    from core.workflow.event_kernel.envelope import (
        MAX_CANONICAL_JSON_BYTES,
        canonical_json_bytes,
    )

    empty_size = len(canonical_json_bytes({"data": ""}))
    payload = {"data": "x" * (MAX_CANONICAL_JSON_BYTES - empty_size)}
    assert len(canonical_json_bytes(payload)) == MAX_CANONICAL_JSON_BYTES

    event = _build_valid_event(payload=payload)
    assert len(canonical_json_bytes(event["payload"])) == MAX_CANONICAL_JSON_BYTES

    with pytest.raises(InvalidCommandError):
        _build_valid_event(payload={"data": payload["data"] + "x"})


def test_canonical_event_line_is_unbounded_canonical_utf8_with_exactly_one_lf() -> None:
    from core.workflow.event_kernel.envelope import (
        MAX_CANONICAL_JSON_BYTES,
        canonical_event_line,
        canonical_json_bytes,
    )

    empty_size = len(canonical_json_bytes({"data": ""}))
    payload = {
        "data": "x" * (MAX_CANONICAL_JSON_BYTES - empty_size),
        "label": "",  # Removed below so the payload remains exactly at the limit.
    }
    del payload["label"]
    event = _build_valid_event(payload=payload)
    expected = json.dumps(
        event,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8") + b"\n"

    line = canonical_event_line(event)

    assert line == expected
    assert line == canonical_event_line(event)
    assert len(line[:-1]) > MAX_CANONICAL_JSON_BYTES
    assert line.endswith(b"\n")
    assert not line.endswith(b"\n\n")
    assert line.count(b"\n") == 1
    assert b"\r" not in line
    assert not line.startswith(b"\xef\xbb\xbf")
    assert json.loads(line[:-1]) == event


def test_canonical_event_line_validates_before_serializing() -> None:
    from core.workflow.event_kernel.envelope import canonical_event_line

    event = _build_valid_event()
    event["event_hash"] = "0" * 64

    with pytest.raises(CorruptEventLogError):
        canonical_event_line(event)


def test_build_event_generates_event_id_and_timestamp_only_for_none() -> None:
    event = _build_valid_event(event_id=None, timestamp=None)

    assert re.fullmatch(r"evt-[0-9a-f]{16}", str(event["event_id"]))
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00",
        str(event["timestamp"]),
    )


def test_build_event_accepts_bounded_explicit_causation_id() -> None:
    event = _build_valid_event(causation_id="cause-proof-16")

    assert event["causation_id"] == "cause-proof-16"


def test_ownership_claim_accepts_manifest_bound_legacy_head() -> None:
    legacy_head = "legacy-sha256:" + "a" * 64

    event = _build_valid_event(
        event_type="event_kernel.ownership.claimed",
        revision=5,
        previous_event_hash=legacy_head,
        command={
            "command_id": "cmd-claim-17",
            "type": "claim_workflow",
            "digest": "1" * 64,
            "expected_revision": 4,
            "expected_event_hash": legacy_head,
        },
    )

    assert event["previous_event_hash"] == legacy_head


def test_non_claim_event_rejects_manifest_bound_legacy_head() -> None:
    legacy_head = "legacy-sha256:" + "a" * 64

    with pytest.raises(InvalidCommandError):
        _build_valid_event(
            revision=5,
            previous_event_hash=legacy_head,
            command={
                "command_id": "cmd-propose-17",
                "type": "propose_action",
                "digest": "1" * 64,
                "expected_revision": 4,
                "expected_event_hash": legacy_head,
            },
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", ""),
        ("timestamp", ""),
    ],
)
def test_build_event_rejects_explicit_empty_generated_fields(field: str, value: str) -> None:
    with pytest.raises(InvalidCommandError):
        _build_valid_event(**{field: value})


@pytest.mark.parametrize("schema_version", ["2.00", "02.0"])
def test_validate_event_rejects_non_exact_schema2_spellings(schema_version: str) -> None:
    from core.workflow.event_kernel.envelope import validate_event

    event = _build_valid_event()
    event["schema_version"] = schema_version

    with pytest.raises(CorruptEventLogError) as caught:
        validate_event(event)
    assert type(caught.value) is CorruptEventLogError


def test_validate_event_rejects_huge_schema_as_corrupt_without_integer_conversion_error() -> None:
    from core.workflow.event_kernel.envelope import validate_event

    event = _build_valid_event()
    event["schema_version"] = "9" * 5000 + ".0"

    with pytest.raises(CorruptEventLogError) as caught:
        validate_event(event)
    assert type(caught.value) is CorruptEventLogError


def test_validate_event_rejects_invalid_unicode_type_with_usable_error() -> None:
    from core.workflow.event_kernel.envelope import validate_event

    event = _build_valid_event()
    event["type"] = "event_kernel.\ud800"

    with pytest.raises(CorruptEventLogError) as caught:
        validate_event(event)
    assert caught.value.message.encode("utf-8")


def test_build_event_rejects_surrogate_in_nested_payload() -> None:
    with pytest.raises(InvalidCommandError):
        _build_valid_event(payload={"nested": ["ok", "\udfff"]})


def test_validate_event_rejects_tampered_event_hash() -> None:
    from core.workflow.event_kernel.envelope import validate_event

    event = _build_valid_event()
    event["payload"] = {"action": {"kind": "exploit"}}

    with pytest.raises(CorruptEventLogError) as caught:
        validate_event(event)
    assert type(caught.value) is CorruptEventLogError


def test_validate_event_reports_unknown_type_with_exact_leaf_error() -> None:
    from core.workflow.event_kernel.envelope import validate_event

    event = _build_valid_event()
    event["type"] = "event_kernel.future.unimplemented"

    with pytest.raises(UnknownEventTypeError) as caught:
        validate_event(event)
    assert type(caught.value) is UnknownEventTypeError


def test_validate_event_reports_future_schema_with_exact_leaf_error() -> None:
    from core.workflow.event_kernel.envelope import validate_event

    event = _build_valid_event()
    event["schema_version"] = "3.0"
    event["type"] = "event_kernel.future.unimplemented"

    with pytest.raises(UnsupportedFutureSchemaError) as caught:
        validate_event(event)
    assert type(caught.value) is UnsupportedFutureSchemaError


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_id", "wf-ABCDEF012345"),
        ("event_id", "evt-0123456789abcde"),
        ("correlation_id", ""),
        ("causation_id", ""),
        ("generation", 0),
        ("generation", True),
        ("revision", 0),
        ("revision", 1.0),
        ("previous_event_hash", "A" * 64),
    ],
)
def test_build_event_rejects_invalid_identity_and_chain_fields(field: str, value: object) -> None:
    with pytest.raises(InvalidCommandError):
        _build_valid_event(**{field: value})


@pytest.mark.parametrize(
    ("revision", "previous_event_hash", "expected_revision", "expected_event_hash"),
    [
        (1, "a" * 64, 0, "a" * 64),
        (2, "", 1, ""),
    ],
)
def test_build_event_requires_chain_anchor_consistent_with_revision(
    revision: int,
    previous_event_hash: str,
    expected_revision: int,
    expected_event_hash: str,
) -> None:
    with pytest.raises(InvalidCommandError):
        _build_valid_event(
            revision=revision,
            previous_event_hash=previous_event_hash,
            command={
                "command_id": "cmd-propose-17",
                "type": "propose_action",
                "digest": "1" * 64,
                "expected_revision": expected_revision,
                "expected_event_hash": expected_event_hash,
            },
        )
