from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from core.workflow.event_kernel import contracts
from core.workflow.event_kernel import envelope
from core.workflow.event_kernel import replay
from core.workflow.event_kernel.errors import (
    CorruptEventLogError,
    DuplicateCommittedCommandError,
    DuplicateEventIdError,
    UnsupportedFutureSchemaError,
    UnknownEventTypeError,
    WorkflowNotFoundError,
)


WORKFLOW_ID = "wf-0123456789ab"
TIMESTAMP = "2026-07-16T08:00:00.000000+00:00"


def _legacy_event(
    event_type: str,
    revision: int,
    previous_event_hash: str,
    *,
    event_id: str = "evt-0123456789abcdef",
    payload: dict | None = None,
    chained: bool = True,
) -> dict:
    event = {
        "event_id": event_id,
        "schema_version": "1.0",
        "workflow_id": WORKFLOW_ID,
        "actor": "hunter_tools",
        "type": event_type,
        "timestamp": TIMESTAMP,
        "revision": revision,
        "previous_event_hash": previous_event_hash,
        "payload": payload or {},
    }
    if chained:
        event["event_hash"] = "0" * 64
        event["event_hash"] = envelope.event_hash(event)
    else:
        event.pop("revision")
        event.pop("previous_event_hash")
    return event


def _line(event: dict) -> bytes:
    return json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _write(path: Path, *events: dict, suffix: bytes = b"") -> bytes:
    data = b"".join(_line(event) for event in events) + suffix
    path.write_bytes(data)
    return data


def _schema2_event(
    event_type: str,
    command_type: str,
    command_id: str,
    digest: str,
    revision: int,
    previous_event_hash: str,
    *,
    event_id: str,
    payload: dict,
) -> dict:
    return envelope.build_event(
        workflow_id=WORKFLOW_ID,
        actor="hunter_tools",
        event_type=event_type,
        revision=revision,
        previous_event_hash=previous_event_hash,
        generation=1,
        correlation_id="corr-replay",
        causation_id=None,
        command={
            "command_id": command_id,
            "type": command_type,
            "digest": digest,
            "expected_revision": revision - 1,
            "expected_event_hash": previous_event_hash,
        },
        payload=payload,
        event_id=event_id,
        timestamp=TIMESTAMP,
    )


def test_missing_and_empty_logs_have_typed_empty_results(tmp_path: Path) -> None:
    missing = tmp_path / "missing.events.jsonl"
    with pytest.raises(WorkflowNotFoundError):
        replay.inspect_event_log(missing, slug="missing")

    empty = tmp_path / "empty.events.jsonl"
    empty.write_bytes(b"")
    result = replay.inspect_event_log(empty, slug="empty")

    assert result.state.workflow_id is None
    assert result.head.revision == 0
    assert result.event_count == result.semantic_event_count == 0
    assert result.valid_prefix_bytes == result.event_file_bytes == 0
    assert result.event_file_sha256 == hashlib.sha256(b"").hexdigest()
    assert result.stats.lines_read == result.stats.json_decodes == result.stats.reducer_calls == 0


def test_hashed_legacy_replay_builds_compact_indexes_and_projection(tmp_path: Path) -> None:
    first = _legacy_event(
        "workflow.created",
        1,
        "",
        payload={
            "state": {
                "workflow_id": WORKFLOW_ID,
                "orchestrator": {"generation": {"number": 2}},
                "history": [{"raw": "must not enter state"}],
            }
        },
    )
    second = _legacy_event(
        "phase.transitioned",
        2,
        first["event_hash"],
        event_id="evt-1111111111111111",
        payload={"phase": "triage"},
    )
    path = tmp_path / "workflow.events.jsonl"
    raw = _write(path, first, second)

    result = replay.inspect_event_log(path, slug="hashed")

    assert result.issue is None
    assert result.state.workflow_id == WORKFLOW_ID
    assert result.state.generation == 2
    assert result.state.phase == "triage"
    assert result.event_count == result.semantic_event_count == 2
    assert result.valid_prefix_bytes == result.event_file_bytes == len(raw)
    assert result.event_file_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.event_index[0].hash_mode is contracts.HashMode.HASHED
    assert result.event_index[1].previous_event_hash == first["event_hash"]
    assert result.stats.reducer_calls == 2


def test_materialize_converts_replay_issue_strictly(tmp_path: Path) -> None:
    path = tmp_path / "bad.events.jsonl"
    path.write_bytes(b"not-json\n")

    with pytest.raises(CorruptEventLogError) as exc_info:
        replay.materialize_event_log(path, slug="bad")

    assert exc_info.value.slug == "bad"


@pytest.mark.parametrize(
    ("suffix", "kind"),
    ((b"{\"broken\"", contracts.ReplayIssueKind.INCOMPLETE_FINAL_LINE),
     (b"\xff\xfe\n", contracts.ReplayIssueKind.INVALID_UTF8),
     (b"not-json\n", contracts.ReplayIssueKind.INVALID_JSON)),
)
def test_first_structural_issue_stops_semantic_work_but_hashes_remaining_bytes(
    tmp_path: Path,
    suffix: bytes,
    kind: contracts.ReplayIssueKind,
) -> None:
    first = _legacy_event(
        "workflow.created",
        1,
        "",
        payload={"state": {"workflow_id": WORKFLOW_ID}},
    )
    path = tmp_path / "broken.events.jsonl"
    raw = _write(path, first, suffix=suffix)

    result = replay.inspect_event_log(path, slug="broken")

    assert result.issue is not None
    assert result.issue.kind is kind
    assert result.semantic_event_count == result.stats.reducer_calls == 1
    assert result.valid_prefix_bytes == len(_line(first))
    assert result.event_file_bytes == len(raw)
    assert result.event_file_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.stats.lines_read == 2
    assert result.stats.json_decodes == (
        1
        if kind
        in {
            contracts.ReplayIssueKind.INCOMPLETE_FINAL_LINE,
            contracts.ReplayIssueKind.INVALID_UTF8,
        }
        else 2
    )


def test_tampered_hash_and_revision_are_corrupt_chain_issues(tmp_path: Path) -> None:
    first = _legacy_event(
        "workflow.created",
        1,
        "",
        payload={"state": {"workflow_id": WORKFLOW_ID}},
    )
    tampered = dict(first)
    tampered["event_hash"] = "f" * 64
    path = tmp_path / "tampered.events.jsonl"
    _write(path, tampered)
    assert replay.inspect_event_log(path, slug="tampered").issue.kind is contracts.ReplayIssueKind.CORRUPT_CHAIN

    gap = _legacy_event(
        "phase.transitioned",
        3,
        first["event_hash"],
        payload={"phase": "triage"},
    )
    _write(path, first, gap)
    assert replay.inspect_event_log(path, slug="gap").issue.kind is contracts.ReplayIssueKind.CORRUPT_CHAIN


def test_unknown_and_future_schema_are_distinct_and_preserve_full_hash(tmp_path: Path) -> None:
    unknown = _legacy_event("workflow.unknown", 1, "", payload={})
    path = tmp_path / "unknown.events.jsonl"
    raw = _write(path, unknown)
    result = replay.inspect_event_log(path, slug="unknown")
    assert result.issue.kind is contracts.ReplayIssueKind.UNKNOWN_EVENT
    assert result.event_file_sha256 == hashlib.sha256(raw).hexdigest()

    future = {
        "schema_version": "3.0",
        "type": "event_kernel.ownership.claimed",
        "event_id": "evt-1111111111111111",
        "revision": 1,
    }
    raw = _write(path, future)
    result = replay.inspect_event_log(path, slug="future")
    assert result.issue.kind is contracts.ReplayIssueKind.FUTURE_SCHEMA
    with pytest.raises(UnsupportedFutureSchemaError):
        replay.materialize_event_log(path, slug="future")


def test_duplicate_event_ids_are_reported(tmp_path: Path) -> None:
    first = _legacy_event("workflow.created", 1, "", payload={"state": {"workflow_id": WORKFLOW_ID}})
    duplicate = _legacy_event(
        "phase.transitioned",
        2,
        first["event_hash"],
        event_id=first["event_id"],
        payload={"phase": "triage"},
    )
    path = tmp_path / "duplicate.events.jsonl"
    _write(path, first, duplicate)

    result = replay.inspect_event_log(path, slug="duplicate")

    assert result.issue.kind is contracts.ReplayIssueKind.DUPLICATE_EVENT
    assert result.semantic_event_count == result.stats.reducer_calls == 1


def test_duplicate_commands_distinguish_same_and_different_digest(tmp_path: Path) -> None:
    claim = _schema2_event(
        "event_kernel.ownership.claimed",
        "claim_workflow",
        "cmd-same",
        "1" * 64,
        1,
        "",
        event_id="evt-1111111111111111",
        payload={"claim": {"cutover_id": "cutover-1"}},
    )
    duplicate = _schema2_event(
        "event_kernel.action.proposed",
        "propose_action",
        "cmd-same",
        "1" * 64,
        2,
        claim["event_hash"],
        event_id="evt-2222222222222222",
        payload={"action": {"kind": "recon", "target": "https://example.test"}},
    )
    path = tmp_path / "commands.events.jsonl"
    _write(path, claim, duplicate)
    result = replay.inspect_event_log(path, slug="same")
    assert result.issue.kind is contracts.ReplayIssueKind.DUPLICATE_COMMAND
    assert len(result.command_index) == 1

    conflict = dict(duplicate)
    conflict["command"] = dict(duplicate["command"], digest="2" * 64)
    conflict["event_hash"] = envelope.event_hash(conflict)
    _write(path, claim, conflict)
    result = replay.inspect_event_log(path, slug="conflict")
    assert result.issue.kind is contracts.ReplayIssueKind.COMMAND_CONFLICT


def test_first_schema_two_event_must_be_claim_and_claim_can_follow_legacy(tmp_path: Path) -> None:
    not_claim = _schema2_event(
        "event_kernel.action.proposed",
        "propose_action",
        "cmd-not-claim",
        "1" * 64,
        1,
        "",
        event_id="evt-3333333333333333",
        payload={"action": {"kind": "recon", "target": "https://example.test"}},
    )
    path = tmp_path / "ownership.events.jsonl"
    _write(path, not_claim)
    result = replay.inspect_event_log(path, slug="ownership")
    assert result.issue.kind is contracts.ReplayIssueKind.OWNERSHIP_CLAIM_REQUIRED

    legacy = _legacy_event("workflow.created", 1, "", payload={"state": {"workflow_id": WORKFLOW_ID}})
    claim = _schema2_event(
        "event_kernel.ownership.claimed",
        "claim_workflow",
        "cmd-claim",
        "3" * 64,
        2,
        legacy["event_hash"],
        event_id="evt-4444444444444444",
        payload={"claim": {"cutover_id": "cutover-1"}},
    )
    _write(path, legacy, claim)
    result = replay.inspect_event_log(path, slug="cutover")
    assert result.issue is None
    assert result.ownership is contracts.OwnershipState.EVENT_KERNEL_OWNED
    assert result.ownership_claim_offset == len(_line(legacy))
