import hashlib
import json
from dataclasses import replace

import pytest

from core.workflow.event_kernel.contracts import CommandMeta, RecoveryRequest, WorkflowOwnershipClaim
from core.workflow.event_kernel.replay import inspect_event_log
from core.workflow.event_kernel.service import EventKernel
from core.workflow.event_kernel.errors import CommandConflictError
from core.workflow.event_kernel.errors import CheckpointBindingError
from core.workflow.event_kernel.errors import RecoveryNotAuthorizedError
from core.workflow.event_kernel.envelope import canonical_json_bytes
from core.workflow.event_kernel.store import EventStore


def meta(kernel, slug, command_id):
    head = kernel.head(slug)
    return CommandMeta(command_id, head.revision, head.event_hash, 1, "test", command_id)


def test_create_checkpoint_persists_a_bound_sidecar_and_one_checkpoint_event(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "checkpoint"
    kernel.claim_workflow(
        slug,
        meta(kernel, slug, "claim"),
        WorkflowOwnershipClaim("cut", "1", "a" * 64),
    )

    created = kernel.create_checkpoint(slug, meta(kernel, slug, "checkpoint"))

    state = kernel.materialize(slug)
    assert created.checkpoint_id is not None
    assert len(state.checkpoints) == 1
    record = state.checkpoints[0]
    path = tmp_path / "cases" / slug / record.relative_path
    contents = path.read_bytes()
    sidecar = json.loads(contents)
    assert hashlib.sha256(contents).hexdigest() == record.checkpoint_file_sha256
    assert sidecar["checkpoint_id"] == created.checkpoint_id
    assert sidecar["bound_revision"] == 1
    assert record.bound_revision == 1
    assert record.event_end_offset == (tmp_path / "cases" / slug / "workflow.events.jsonl").stat().st_size


def test_create_checkpoint_replays_the_original_checkpoint_id_for_the_same_command(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "checkpoint-idempotent"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    command = meta(kernel, slug, "checkpoint")

    first = kernel.create_checkpoint(slug, command)
    repeated = kernel.create_checkpoint(slug, command)

    assert repeated.idempotent is True
    assert repeated.checkpoint_id == first.checkpoint_id
    assert len(kernel.materialize(slug).checkpoints) == 1


def test_recover_checkpoint_replaces_an_invalid_tail_and_preserves_a_complete_backup(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "recovery"
    kernel.claim_workflow(
        slug,
        meta(kernel, slug, "claim"),
        WorkflowOwnershipClaim("cut", "1", "a" * 64),
    )
    kernel.create_checkpoint(slug, meta(kernel, slug, "checkpoint"))
    path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    original = path.read_bytes() + b'{"broken"\n'
    path.write_bytes(original)
    prefix = inspect_event_log(path, slug=slug)

    recovered = kernel.recover_checkpoint(
        slug,
        CommandMeta("recover", prefix.head.revision, prefix.head.event_hash, 1, "test", "recover"),
        RecoveryRequest(prefix.state.checkpoints[0].checkpoint_id, len(original), hashlib.sha256(original).hexdigest()),
    )

    assert recovered.event_type.value == "event_kernel.recovery.performed"
    repaired = inspect_event_log(path, slug=slug)
    assert repaired.issue is None
    assert repaired.event_count == 3
    backup = next((tmp_path / "cases" / slug / "recovery" / "event-kernel").glob("*.jsonl"))
    assert backup.read_bytes() == original


def test_recover_checkpoint_rejects_a_changed_request_for_an_existing_command(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "recovery-command-conflict"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    kernel.create_checkpoint(slug, meta(kernel, slug, "checkpoint"))
    path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    original = path.read_bytes() + b'{"broken"\n'
    path.write_bytes(original)
    prefix = inspect_event_log(path, slug=slug)
    command = CommandMeta("recover", prefix.head.revision, prefix.head.event_hash, 1, "test", "recover")
    checkpoint_id = prefix.state.checkpoints[0].checkpoint_id
    kernel.recover_checkpoint(
        slug,
        command,
        RecoveryRequest(checkpoint_id, len(original), hashlib.sha256(original).hexdigest()),
    )

    with pytest.raises(CommandConflictError):
        kernel.recover_checkpoint(slug, command, RecoveryRequest(checkpoint_id, 1, "b" * 64))


@pytest.mark.parametrize(
    ("crash_point", "recovered"),
    [
        ("backup_after_fsync_before_rename", False),
        ("backup_after_rename_before_recovery_temp", False),
        ("recovery_temp_after_fsync_before_replace", False),
        ("recovery_after_replace_before_dirsync", True),
        ("recovery_after_dirsync_before_cache", True),
    ],
)
def test_recovery_crash_points_leave_only_original_or_complete_recovered_log(tmp_path, crash_point, recovered):
    class InjectedCrash(RuntimeError):
        pass

    def crash_hook(point):
        if point == crash_point:
            raise InjectedCrash(point)

    kernel = EventKernel(tmp_path, crash_hook=crash_hook)
    slug = f"recovery-crash-{crash_point}"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    kernel.create_checkpoint(slug, meta(kernel, slug, "checkpoint"))
    path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    original = path.read_bytes() + b'{"broken"\n'
    path.write_bytes(original)
    prefix = inspect_event_log(path, slug=slug)

    with pytest.raises(InjectedCrash):
        kernel.recover_checkpoint(
            slug,
            CommandMeta("recover", prefix.head.revision, prefix.head.event_hash, 1, "test", "recover"),
            RecoveryRequest(prefix.state.checkpoints[0].checkpoint_id, len(original), hashlib.sha256(original).hexdigest()),
        )

    replay = inspect_event_log(path, slug=slug)
    assert (replay.issue is None) is recovered
    assert replay.event_count == (3 if recovered else 2)
    if not recovered:
        assert path.read_bytes() == original


def test_next_checkpoint_cleans_a_verified_orphan_sidecar_after_pre_append_crash(tmp_path):
    class InjectedCrash(RuntimeError):
        pass

    def crash_hook(point):
        if point == "checkpoint_after_rename_before_event_append":
            raise InjectedCrash(point)

    slug = "checkpoint-orphan"
    crashing = EventKernel(tmp_path, crash_hook=crash_hook)
    crashing.claim_workflow(slug, meta(crashing, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    with pytest.raises(InjectedCrash):
        crashing.create_checkpoint(slug, meta(crashing, slug, "crashed-checkpoint"))
    checkpoint_dir = tmp_path / "cases" / slug / "checkpoints" / "event-kernel"
    orphan = next(checkpoint_dir.glob("cp-*.json"))

    restarted = EventKernel(tmp_path)
    created = restarted.create_checkpoint(slug, meta(restarted, slug, "checkpoint"))

    assert not orphan.exists()
    assert restarted.materialize(slug).checkpoints[0].checkpoint_id == created.checkpoint_id


def test_checkpoint_binding_rejects_a_sidecar_with_a_wrong_event_prefix_digest(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "checkpoint-prefix-binding"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    kernel.create_checkpoint(slug, meta(kernel, slug, "checkpoint"))
    workflow_dir = tmp_path / "cases" / slug
    replay = inspect_event_log(workflow_dir / "workflow.events.jsonl", slug=slug)
    record = replay.state.checkpoints[0]
    path = workflow_dir / record.relative_path
    sidecar = json.loads(path.read_bytes())
    sidecar["event_file_prefix_sha256"] = "b" * 64
    contents = canonical_json_bytes(sidecar) + b"\n"
    path.write_bytes(contents)
    forged = replace(
        record,
        event_file_prefix_sha256="b" * 64,
        checkpoint_file_sha256=hashlib.sha256(contents).hexdigest(),
    )

    with pytest.raises(CheckpointBindingError):
        EventStore._validate_checkpoint_binding(workflow_dir, replay, forged)


def test_checkpoint_binding_rejects_a_sidecar_with_a_wrong_compact_state_digest(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "checkpoint-state-binding"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    kernel.create_checkpoint(slug, meta(kernel, slug, "checkpoint"))
    workflow_dir = tmp_path / "cases" / slug
    replay = inspect_event_log(workflow_dir / "workflow.events.jsonl", slug=slug)
    record = replay.state.checkpoints[0]
    path = workflow_dir / record.relative_path
    sidecar = json.loads(path.read_bytes())
    sidecar["state"]["generation"] = 2
    contents = canonical_json_bytes(sidecar) + b"\n"
    path.write_bytes(contents)
    forged = replace(record, checkpoint_file_sha256=hashlib.sha256(contents).hexdigest())

    with pytest.raises(CheckpointBindingError):
        EventStore._validate_checkpoint_binding(workflow_dir, replay, forged)


@pytest.mark.parametrize(
    "invalid_tail",
    [
        b'{"schema_version":"3.0","type":"future.event"}\n',
        b'{"schema_version":"1.0","type":"future.event"}\n',
        b'{"schema_version":"1.0","type":"workflow.created","payload":{}}\n',
    ],
)
def test_recovery_rejects_non_truncatable_replay_issue_kinds(tmp_path, invalid_tail):
    kernel = EventKernel(tmp_path)
    slug = "recovery-non-truncatable"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    kernel.create_checkpoint(slug, meta(kernel, slug, "checkpoint"))
    path = tmp_path / "cases" / slug / "workflow.events.jsonl"
    source = path.read_bytes() + invalid_tail
    path.write_bytes(source)
    replay = inspect_event_log(path, slug=slug)
    assert replay.issue is not None

    with pytest.raises(RecoveryNotAuthorizedError):
        kernel.recover_checkpoint(
            slug,
            CommandMeta("recover", replay.head.revision, replay.head.event_hash, 1, "test", "recover"),
            RecoveryRequest(replay.state.checkpoints[0].checkpoint_id, len(source), hashlib.sha256(source).hexdigest()),
        )

    assert path.read_bytes() == source
    assert not (tmp_path / "cases" / slug / "recovery").exists()
