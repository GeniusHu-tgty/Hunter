from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.workflow.event_kernel import CommandMeta, CommandType
from core.workflow.event_kernel.errors import CommandConflictError, ConcurrencyConflictError, InvalidCommandError
from core.workflow.event_kernel.replay import inspect_event_log
from core.workflow.event_kernel.store import EventStore


WORKFLOW_ID = "wf-0123456789ab"


def _meta(command_id: str, revision: int, event_hash: str, *, generation: int = 1) -> CommandMeta:
    return CommandMeta(
        command_id=command_id,
        expected_revision=revision,
        expected_event_hash=event_hash,
        generation=generation,
        correlation_id="corr-1",
    )


def _claim(store: EventStore, command_id: str = "cmd-claim"):
    return store.append_command(
        "alpha",
        _meta(command_id, 0, ""),
        CommandType.CLAIM_WORKFLOW,
        {"claim": {"cutover_id": "cutover-1", "owner_version": "3", "legacy_gate_digest": "a" * 64}},
        workflow_id=WORKFLOW_ID,
    )


def _next_head(root: Path) -> tuple[int, str]:
    result = inspect_event_log(root / "cases" / "alpha" / "workflow.events.jsonl", slug="alpha")
    assert result.issue is None
    return result.head.revision, result.head.event_hash


def test_idempotency_is_checked_before_cas_and_does_not_append(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    original = _claim(store)

    retry = store.append_command(
        "alpha",
        _meta("cmd-claim", 999, "f" * 64),
        CommandType.CLAIM_WORKFLOW,
        {"claim": {"cutover_id": "cutover-1", "owner_version": "3", "legacy_gate_digest": "a" * 64}},
        workflow_id=WORKFLOW_ID,
    )

    assert retry.idempotent is True
    assert retry.revision == original.revision
    assert retry.event_id == original.event_id
    assert (tmp_path / "cases" / "alpha" / "workflow.events.jsonl").read_bytes().count(b"\n") == 1


def test_revision_and_event_hash_are_independent_cas_values(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    original = _claim(store)

    with pytest.raises(ConcurrencyConflictError, match="expected revision"):
        store.append_command(
            "alpha",
            _meta("cmd-revision", original.revision - 1, original.event_hash),
            CommandType.RECORD_VERDICT,
            {},
            workflow_id=WORKFLOW_ID,
        )

    with pytest.raises(ConcurrencyConflictError, match="expected event hash"):
        store.append_command(
            "alpha",
            _meta("cmd-hash", original.revision, "0" * 64),
            CommandType.RECORD_VERDICT,
            {},
            workflow_id=WORKFLOW_ID,
        )


def test_concurrent_commands_are_serialized_with_cas_retries(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    _claim(store)

    def commit(index: int):
        while True:
            revision, event_hash = _next_head(tmp_path)
            try:
                return store.append_command(
                    "alpha",
                    _meta(f"cmd-{index}", revision, event_hash),
                    CommandType.RECORD_VERDICT,
                    {},
                    workflow_id=WORKFLOW_ID,
                )
            except ConcurrencyConflictError:
                continue

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(commit, range(6)))

    assert {result.command_id for result in results} == {f"cmd-{i}" for i in range(6)}
    assert (tmp_path / "cases" / "alpha" / "workflow.events.jsonl").read_bytes().count(b"\n") == 7


def test_append_replays_once_and_cache_failure_does_not_rollback(tmp_path: Path, monkeypatch) -> None:
    import core.workflow.event_kernel.store as store_module

    store = EventStore(tmp_path)
    replay_calls = 0
    fsync_calls = 0
    real_replay = inspect_event_log
    real_fsync = store_module.os.fsync

    def counted_replay(*args, **kwargs):
        nonlocal replay_calls
        replay_calls += 1
        return real_replay(*args, **kwargs)

    def counted_fsync(fd):
        nonlocal fsync_calls
        fsync_calls += 1
        return real_fsync(fd)

    def failed_cache(payload, **kwargs):
        assert fsync_calls == 1
        raise OSError("cache")

    monkeypatch.setattr("core.workflow.event_kernel.store.inspect_event_log", counted_replay)
    monkeypatch.setattr(store_module.os, "fsync", counted_fsync)
    monkeypatch.setattr(store, "_write_cache", failed_cache)

    result = _claim(store)

    assert replay_calls == 1
    assert result.cache_updated is False
    assert (tmp_path / "cases" / "alpha" / "workflow.events.jsonl").read_bytes().count(b"\n") == 1


def test_each_commit_writes_exactly_one_canonical_event_line(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    first = _claim(store)
    revision, event_hash = _next_head(tmp_path)

    store.append_command(
        "alpha",
        _meta("cmd-one", revision, event_hash),
        CommandType.RECORD_VERDICT,
        {},
        workflow_id=WORKFLOW_ID,
    )

    lines = (tmp_path / "cases" / "alpha" / "workflow.events.jsonl").read_bytes().splitlines(keepends=True)
    assert len(lines) == 2
    assert all(line.endswith(b"\n") and not line.endswith(b"\r\n") for line in lines)
    assert first.event_id.encode() in lines[0]


def test_same_id_with_different_digest_is_a_command_conflict(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    _claim(store)

    with pytest.raises(CommandConflictError):
        store.append_command(
            "alpha",
            _meta("cmd-claim", 999, "f" * 64),
            CommandType.CLAIM_WORKFLOW,
            {"claim": {"cutover_id": "different", "owner_version": "3", "legacy_gate_digest": "b" * 64}},
            workflow_id=WORKFLOW_ID,
        )


def test_slug_resolution_rejects_path_traversal(tmp_path: Path) -> None:
    store = EventStore(tmp_path)

    with pytest.raises(InvalidCommandError):
        store.event_log_path("../escape")
