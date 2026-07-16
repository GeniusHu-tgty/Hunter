from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.workflow.event_kernel import (
    ActionDecision,
    ActionMerge,
    ActionProposal,
    AttemptBlock,
    AttemptComplete,
    AttemptStart,
    CommandMeta,
    ConcurrencyConflictError,
    IllegalTransitionError,
    make_action_id,
)
from core.workflow.event_kernel.service import EventKernel
from core.workflow.event_kernel.upcast import SemanticEvent
from core.workflow.event_kernel.reducer import reduce_event


WORKFLOW_ID = "wf-0123456789ab"


def _meta(kernel: EventKernel, slug: str, command_id: str) -> CommandMeta:
    head = kernel.head(slug)
    return CommandMeta(
        command_id=command_id,
        expected_revision=head.revision,
        expected_event_hash=head.event_hash,
        generation=1,
        correlation_id="corr-lifecycle",
    )


def _claim(kernel: EventKernel, slug: str = "alpha") -> None:
    from core.workflow.event_kernel import WorkflowOwnershipClaim

    kernel.claim_workflow(
        slug,
        _meta(kernel, slug, "claim"),
        WorkflowOwnershipClaim("cutover", "stage4", "a" * 64),
    )


def _propose(kernel: EventKernel, slug: str = "alpha") -> str:
    result = kernel.propose_action(
        slug,
        _meta(kernel, slug, "propose"),
        ActionProposal(
            tool="hunter_auto_sqli",
            target="https://example.test/login",
            kind="sqli",
            arguments={"param": "username"},
            sources=("finding-1",),
            strategy_ids=("strategy-1",),
            priority="P2",
        ),
    )
    assert result.action_id is not None
    return result.action_id


def test_action_identity_merge_and_priority_only_improves(tmp_path: Path) -> None:
    kernel = EventKernel(tmp_path)
    _claim(kernel)
    action_id = _propose(kernel)

    assert action_id == make_action_id(
        generation=1,
        tool="hunter_auto_sqli",
        target="https://example.test/login",
        arguments={"param": "username"},
        kind="sqli",
    )

    kernel.merge_action(
        "alpha",
        _meta(kernel, "alpha", "merge-good"),
        ActionMerge(
            action_id=action_id,
            sources=("finding-2",),
            strategy_ids=("strategy-2",),
            labels=("auth-required",),
            expected_evidence=("evidence-1",),
            priority="P0",
        ),
    )
    action = kernel.materialize("alpha").actions[0]
    assert action.sources == ("finding-1", "finding-2")
    assert action.strategy_ids == ("strategy-1", "strategy-2")
    assert action.priority == "P0"

    with pytest.raises(IllegalTransitionError):
        kernel.merge_action(
            "alpha",
            _meta(kernel, "alpha", "merge-worse"),
            ActionMerge(action_id=action_id, priority="P2"),
        )


def test_attempt_retry_numbering_terminal_immutability_and_budget(tmp_path: Path) -> None:
    kernel = EventKernel(tmp_path)
    _claim(kernel)
    action_id = _propose(kernel)

    kernel.defer_action(
        "alpha", _meta(kernel, "alpha", "defer"), ActionDecision(action_id, "later")
    )
    first = kernel.start_attempt(
        "alpha", _meta(kernel, "alpha", "start-1"), AttemptStart(action_id, "executor", "proof")
    )
    assert first.attempt_id is not None and first.attempt_id.endswith("-000001")
    kernel.block_attempt(
        "alpha", _meta(kernel, "alpha", "block-1"), AttemptBlock(first.attempt_id, "blocked")
    )
    second = kernel.start_attempt(
        "alpha", _meta(kernel, "alpha", "start-2"), AttemptStart(action_id, "executor", "proof")
    )
    assert second.attempt_id is not None and second.attempt_id.endswith("-000002")
    kernel.complete_attempt(
        "alpha",
        _meta(kernel, "alpha", "complete-2"),
        AttemptComplete(second.attempt_id, "ok", "b" * 64),
    )

    state = kernel.materialize("alpha")
    assert state.actions[0].state.value == "completed"
    assert state.budget.actions_proposed == 1
    assert state.budget.actions_deferred == 1
    assert state.budget.attempts_started == 2
    assert state.budget.attempts_blocked == 1
    assert state.budget.attempts_completed == 1
    assert state.budget.budget_charges == 2

    with pytest.raises(IllegalTransitionError):
        kernel.block_attempt(
            "alpha",
            _meta(kernel, "alpha", "block-terminal"),
            AttemptBlock(second.attempt_id, "late"),
        )


def test_terminal_attempt_requires_all_bound_processes_terminal(tmp_path: Path) -> None:
    kernel = EventKernel(tmp_path)
    _claim(kernel)
    action_id = _propose(kernel)
    started = kernel.start_attempt(
        "alpha", _meta(kernel, "alpha", "start"), AttemptStart(action_id, "executor", "proof")
    )
    state = kernel.materialize("alpha")
    process_id = "proc-0123456789abcdef"
    started_process = SemanticEvent(
        schema_version="2.0",
        event_type="event_kernel.process.started",
        workflow_id=state.workflow_id,
        generation=1,
        revision=None,
        event_id=None,
        timestamp=None,
        payload={
            "process": {
                "process_id": process_id,
                "attempt_id": started.attempt_id,
                "process_name": "worker",
            }
        },
    )
    state = reduce_event(state, started_process)

    with pytest.raises(IllegalTransitionError):
        reduce_event(
            state,
            SemanticEvent(
                schema_version="2.0",
                event_type="event_kernel.attempt.completed",
                workflow_id=state.workflow_id,
                generation=1,
                revision=None,
                event_id=None,
                timestamp=None,
                payload={
                    "attempt": {
                        "attempt_id": started.attempt_id,
                        "result_code": "ok",
                        "result_digest": "c" * 64,
                    }
                },
            ),
        )


def test_concurrent_attempt_commands_do_not_duplicate_a_started_attempt(tmp_path: Path) -> None:
    kernel = EventKernel(tmp_path)
    _claim(kernel)
    action_id = _propose(kernel)

    def start(command_id: str):
        try:
            return kernel.start_attempt(
                "alpha",
                _meta(kernel, "alpha", command_id),
                AttemptStart(action_id, "executor", "proof"),
            )
        except (ConcurrencyConflictError, IllegalTransitionError) as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(start, ("concurrent-1", "concurrent-2")))

    assert sum(result.attempt_id is not None for result in results if not isinstance(result, Exception)) == 1
    assert len(kernel.materialize("alpha").attempts) == 1
