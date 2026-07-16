import pytest

from core.workflow.event_kernel.contracts import (
    CommandMeta,
    MemoryApplied,
    MemoryEnqueue,
    MemoryFailed,
    WorkflowOwnershipClaim,
)
from core.workflow.event_kernel.errors import IllegalTransitionError, OutboxConflictError
from core.workflow.event_kernel.service import EventKernel


def meta(kernel, slug, command_id):
    head = kernel.head(slug)
    return CommandMeta(command_id, head.revision, head.event_hash, 1, "test", command_id)


def test_enqueue_memory_replays_a_single_canonical_outbox_entry(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "memory"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    command = meta(kernel, slug, "enqueue")
    first = kernel.enqueue_memory(slug, command, MemoryEnqueue("memory", "idor", {"verdict": "verified"}))
    replay = kernel.enqueue_memory(slug, command, MemoryEnqueue("memory", "idor", {"verdict": "verified"}))
    state = kernel.materialize(slug)
    assert first.outbox_id == replay.outbox_id
    assert replay.idempotent is True
    assert len(state.outbox) == 1
    assert state.outbox[0].status.value == "enqueued"


def test_enqueue_memory_deduplicates_an_equivalent_new_command_without_reserving_it(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "memory-dedupe"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))

    first = kernel.enqueue_memory(slug, meta(kernel, slug, "first"), MemoryEnqueue("memory", "idor", {"verdict": "verified"}))
    duplicate = kernel.enqueue_memory(slug, meta(kernel, slug, "duplicate"), MemoryEnqueue("memory", "idor", {"verdict": "verified"}))

    assert duplicate.deduplicated is True
    assert duplicate.command_id == "duplicate"
    assert duplicate.original_command_id == first.command_id
    assert duplicate.outbox_id == first.outbox_id
    assert kernel.head(slug).revision == first.revision


def test_enqueue_memory_rejects_a_changed_payload_for_an_existing_dedupe_scope(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "memory-conflict"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    kernel.enqueue_memory(slug, meta(kernel, slug, "first"), MemoryEnqueue("memory", "idor", {"verdict": "verified"}))

    with pytest.raises(OutboxConflictError):
        kernel.enqueue_memory(slug, meta(kernel, slug, "conflict"), MemoryEnqueue("memory", "idor", {"verdict": "refuted"}))


def test_applied_outbox_cannot_transition_again(tmp_path):
    kernel = EventKernel(tmp_path); slug = "memory-terminal"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    queued = kernel.enqueue_memory(slug, meta(kernel, slug, "enqueue"), MemoryEnqueue("memory", "idor", {}))
    kernel.mark_memory_applied(slug, meta(kernel, slug, "applied"), MemoryApplied(queued.outbox_id, "receipt"))
    with pytest.raises(IllegalTransitionError):
        kernel.mark_memory_applied(slug, meta(kernel, slug, "repeat"), MemoryApplied(queued.outbox_id, "receipt"))


def test_restart_recovers_only_dispatchable_memory_outbox_entries(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "memory-recovery"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    enqueued = kernel.enqueue_memory(slug, meta(kernel, slug, "enqueue"), MemoryEnqueue("memory", "enqueued", {}))
    retryable = kernel.enqueue_memory(slug, meta(kernel, slug, "retryable"), MemoryEnqueue("memory", "retryable", {}))
    nonretryable = kernel.enqueue_memory(slug, meta(kernel, slug, "nonretryable"), MemoryEnqueue("memory", "nonretryable", {}))
    applied = kernel.enqueue_memory(slug, meta(kernel, slug, "applied"), MemoryEnqueue("memory", "applied", {}))
    kernel.mark_memory_failed(slug, meta(kernel, slug, "retryable-failed"), MemoryFailed(retryable.outbox_id, "timeout", "b" * 64, True))
    kernel.mark_memory_failed(slug, meta(kernel, slug, "nonretryable-failed"), MemoryFailed(nonretryable.outbox_id, "invalid", "c" * 64, False))
    kernel.mark_memory_applied(slug, meta(kernel, slug, "applied-ok"), MemoryApplied(applied.outbox_id, "receipt"))

    recovered = EventKernel(tmp_path).recover_memory_outbox(slug)

    assert [entry.outbox_id for entry in recovered] == [enqueued.outbox_id, retryable.outbox_id]


def test_retryable_memory_failure_advances_the_absolute_delivery_attempt(tmp_path):
    kernel = EventKernel(tmp_path)
    slug = "memory-retry"
    kernel.claim_workflow(slug, meta(kernel, slug, "claim"), WorkflowOwnershipClaim("cut", "1", "a" * 64))
    queued = kernel.enqueue_memory(slug, meta(kernel, slug, "enqueue"), MemoryEnqueue("memory", "idor", {}))

    kernel.mark_memory_failed(slug, meta(kernel, slug, "failed-one"), MemoryFailed(queued.outbox_id, "timeout", "b" * 64, True))
    kernel.mark_memory_failed(slug, meta(kernel, slug, "failed-two"), MemoryFailed(queued.outbox_id, "timeout", "c" * 64, True))

    state = kernel.materialize(slug)
    assert state.outbox[0].status.value == "failed"
    assert state.outbox[0].delivery_attempt == 2
