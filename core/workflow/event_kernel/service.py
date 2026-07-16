from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .contracts import (
    ActionDecision,
    ActionMerge,
    ActionProposal,
    AttemptBlock,
    AttemptCancel,
    AttemptComplete,
    AttemptStart,
    CommandMeta,
    CommandResult,
    CommandType,
    EventKernelState,
    HashMode,
    Head,
    OwnershipState,
    WorkflowOwnershipClaim,
)
from .envelope import canonical_json_bytes, make_action_id
from .errors import InvalidCommandError, issue_to_error
from .replay import inspect_event_log
from .store import EventStore


def _thaw(value: Any) -> Any:
    if hasattr(value, "items") and not isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items}
    if hasattr(value, "values") and not isinstance(value, (str, bytes, bytearray)):
        return [_thaw(item) for item in value.values]
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


class EventKernel:
    """Typed action/attempt facade over the authoritative event store."""

    def __init__(self, workspace_root: str | Path, *, lock_timeout: float = 10.0) -> None:
        self._store = EventStore(workspace_root, lock_timeout=lock_timeout)

    def inspect_prefix(self, slug: str):
        replay = inspect_event_log(self._store.event_log_path(slug), slug=slug)
        if replay.issue is not None:
            raise issue_to_error(replay.issue, slug=slug)
        return replay

    def head(self, slug: str) -> Head:
        if not self._store.event_log_path(slug).exists():
            return Head(0, "", None, HashMode.EMPTY)
        return self.inspect_prefix(slug).head

    def materialize(self, slug: str) -> EventKernelState:
        if not self._store.event_log_path(slug).exists():
            return EventKernelState(None, 1, OwnershipState.UNCLAIMED_LEGACY)
        return self.inspect_prefix(slug).state

    def _workflow_id(self, slug: str) -> str:
        workflow_id = self.materialize(slug).workflow_id
        if workflow_id:
            return workflow_id
        return "wf-" + hashlib.sha256(slug.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _require(value: Any, expected: type[Any], name: str) -> None:
        if not isinstance(value, expected):
            raise InvalidCommandError(f"{name} must be {expected.__name__}")

    def claim_workflow(
        self, slug: str, meta: CommandMeta, claim: WorkflowOwnershipClaim
    ) -> CommandResult:
        self._require(meta, CommandMeta, "meta")
        self._require(claim, WorkflowOwnershipClaim, "claim")
        return self._store._commit_command(
            slug,
            meta,
            CommandType.CLAIM_WORKFLOW,
            {"claim": {"cutover_id": claim.cutover_id, "owner_version": claim.owner_version, "legacy_gate_digest": claim.legacy_gate_digest}},
            workflow_id=self._workflow_id(slug),
        )

    def propose_action(
        self, slug: str, meta: CommandMeta, action: ActionProposal
    ) -> CommandResult:
        self._require(meta, CommandMeta, "meta")
        self._require(action, ActionProposal, "action")
        arguments = _thaw(action.arguments)
        action_id = make_action_id(
            generation=meta.generation,
            tool=action.tool,
            target=action.target,
            arguments=arguments,
            kind=action.kind,
        )
        action_key = hashlib.sha256(
            canonical_json_bytes(
                {"generation": meta.generation, "tool": action.tool, "target": action.target, "arguments": arguments, "kind": action.kind}
            )
        ).hexdigest()
        payload = {
            "action": {
                "action_id": action_id,
                "action_key": action_key,
                "generation": meta.generation,
                "tool": action.tool,
                "target": action.target,
                "arguments": arguments,
                "kind": action.kind,
                "sources": list(action.sources),
                "strategy_ids": list(action.strategy_ids),
                "labels": list(action.labels),
                "expected_evidence": list(action.expected_evidence),
                "priority": action.priority,
            }
        }
        return self._store._commit_command(slug, meta, CommandType.PROPOSE_ACTION, payload)

    def merge_action(
        self, slug: str, meta: CommandMeta, merge: ActionMerge
    ) -> CommandResult:
        self._require(meta, CommandMeta, "meta")
        self._require(merge, ActionMerge, "merge")
        return self._store._commit_command(
            slug,
            meta,
            CommandType.MERGE_ACTION,
            {"merge": {"action_id": merge.action_id, "sources": list(merge.sources), "strategy_ids": list(merge.strategy_ids), "labels": list(merge.labels), "expected_evidence": list(merge.expected_evidence), "priority": merge.priority}},
        )

    def defer_action(
        self, slug: str, meta: CommandMeta, decision: ActionDecision
    ) -> CommandResult:
        return self._decision(slug, meta, decision, CommandType.DEFER_ACTION)

    def block_action(
        self, slug: str, meta: CommandMeta, decision: ActionDecision
    ) -> CommandResult:
        return self._decision(slug, meta, decision, CommandType.BLOCK_ACTION)

    def _decision(
        self, slug: str, meta: CommandMeta, decision: ActionDecision, command: CommandType
    ) -> CommandResult:
        self._require(meta, CommandMeta, "meta")
        self._require(decision, ActionDecision, "decision")
        return self._store._commit_command(
            slug,
            meta,
            command,
            {"decision": {"action_id": decision.action_id, "reason": decision.reason}},
        )

    def start_attempt(
        self, slug: str, meta: CommandMeta, start: AttemptStart
    ) -> CommandResult:
        self._require(meta, CommandMeta, "meta")
        self._require(start, AttemptStart, "start")
        return self._store._commit_command(
            slug,
            meta,
            CommandType.START_ATTEMPT,
            {"attempt": {"action_id": start.action_id, "executor": start.executor, "budget_class": start.budget_class}},
        )

    def complete_attempt(
        self, slug: str, meta: CommandMeta, terminal: AttemptComplete
    ) -> CommandResult:
        return self._terminal(slug, meta, terminal, CommandType.COMPLETE_ATTEMPT)

    def block_attempt(
        self, slug: str, meta: CommandMeta, terminal: AttemptBlock
    ) -> CommandResult:
        return self._terminal(slug, meta, terminal, CommandType.BLOCK_ATTEMPT)

    def cancel_attempt(
        self, slug: str, meta: CommandMeta, terminal: AttemptCancel
    ) -> CommandResult:
        return self._terminal(slug, meta, terminal, CommandType.CANCEL_ATTEMPT)

    def _terminal(self, slug: str, meta: CommandMeta, terminal: Any, command: CommandType) -> CommandResult:
        self._require(meta, CommandMeta, "meta")
        expected = {
            CommandType.COMPLETE_ATTEMPT: AttemptComplete,
            CommandType.BLOCK_ATTEMPT: AttemptBlock,
            CommandType.CANCEL_ATTEMPT: AttemptCancel,
        }[command]
        self._require(terminal, expected, "terminal")
        data = {"id": terminal.attempt_id}
        if command is CommandType.COMPLETE_ATTEMPT:
            data.update(result_code=terminal.result_code, result_digest=terminal.result_digest)
        else:
            data["reason"] = terminal.reason
        return self._store._commit_command(slug, meta, command, {"attempt": data})


__all__ = ["EventKernel"]
