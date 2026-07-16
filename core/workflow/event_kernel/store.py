from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
import re
from typing import Any

from core.workflow.locking import WorkflowFileLock

from .contracts import (
    CommandMeta,
    CommandResult,
    CommandType,
    EventKernelState,
    EventType,
    HashMode,
)
from .envelope import build_event, canonical_event_line, command_digest
from .envelope import make_attempt_id
from .errors import (
    CommandConflictError,
    ConcurrencyConflictError,
    InvalidCommandError,
    OwnershipClaimRequiredError,
    WorkflowAlreadyClaimedError,
    issue_to_error,
)
from .replay import inspect_event_log
from .upcast import upcast_event
from .reducer import reduce_event


_SAFE_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

_EVENT_FOR_COMMAND = {
    command_type: event_type
    for command_type, event_type in zip(CommandType, EventType)
}


def _cache_state(value: Any) -> Any:
    """Keep cache output derived and free of event-history-shaped fields."""
    if isinstance(value, Mapping):
        return {
            str(key): _cache_state(item)
            for key, item in value.items()
            if str(key) not in {"history", "events", "stage_results", "process_output", "excerpts"}
        }
    if is_dataclass(value):
        return {
            field.name: _cache_state(getattr(value, field.name))
            for field in fields(value)
            if field.name not in {"history", "events", "stage_results", "process_output", "excerpts"}
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (tuple, list)):
        return [_cache_state(item) for item in value]
    return value


class EventStore:
    """Authoritative event-log writer with lock-scoped two-part CAS."""

    def __init__(self, workspace_root: str | Path, *, lock_timeout: float = 10.0) -> None:
        if workspace_root is None:
            raise InvalidCommandError("workspace_root is required")
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.cases_root = (self.workspace_root / "cases").resolve()
        self.lock_timeout = float(lock_timeout)

    def _workflow_dir(self, slug: str) -> Path:
        if type(slug) is not str or _SAFE_SLUG.fullmatch(slug) is None or slug in {".", ".."}:
            raise InvalidCommandError("workflow slug is not a safe path component")
        workflow_dir = (self.cases_root / slug).resolve()
        try:
            workflow_dir.relative_to(self.cases_root)
        except ValueError as exc:
            raise InvalidCommandError("workflow slug resolves outside cases") from exc
        return workflow_dir

    def event_log_path(self, slug: str) -> Path:
        return self._workflow_dir(slug) / "workflow.events.jsonl"

    def cache_path(self, slug: str) -> Path:
        return self._workflow_dir(slug) / "workflow.event-kernel.json"

    def _commit_command(
        self,
        slug: str,
        meta: CommandMeta,
        command_type: CommandType | str,
        payload: dict[str, Any],
        workflow_id: str | None = None,
    ) -> CommandResult:
        if not isinstance(meta, CommandMeta):
            raise InvalidCommandError("meta must be CommandMeta")
        try:
            command_type = CommandType(command_type)
        except (TypeError, ValueError) as exc:
            raise InvalidCommandError("command_type is unsupported") from exc
        if type(payload) is not dict:
            raise InvalidCommandError("payload must be a JSON object")
        event_type = _EVENT_FOR_COMMAND[command_type]
        workflow_dir = self._workflow_dir(slug)
        event_path = workflow_dir / "workflow.events.jsonl"

        with WorkflowFileLock(workflow_dir / ".workflow.lock", timeout=self.lock_timeout):
            workflow_dir.mkdir(parents=True, exist_ok=True)
            event_path.touch(exist_ok=True)
            replay = inspect_event_log(event_path, slug=slug)
            if replay.issue is not None:
                raise issue_to_error(replay.issue, slug=slug)

            existing = next(
                (entry for entry in replay.command_index if entry.command_id == meta.command_id),
                None,
            )
            resolved_workflow_id = workflow_id or replay.state.workflow_id
            if not isinstance(resolved_workflow_id, str) or not resolved_workflow_id:
                raise InvalidCommandError("workflow_id is required for a new event", slug=slug)

            digest = command_digest(
                {
                    "workflow_id": resolved_workflow_id,
                    "generation": meta.generation,
                    "type": command_type.value,
                    "correlation_id": meta.correlation_id,
                    "causation_id": meta.causation_id,
                    "payload": payload,
                }
            )
            if existing is not None:
                if existing.command_digest == digest:
                    return self._result_from_index(existing, idempotent=True)
                raise CommandConflictError(
                    "command_id was already committed with a different digest",
                    slug=slug,
                    revision=existing.revision,
                    event_id=existing.event_id,
                )

            if meta.expected_revision != replay.head.revision:
                raise ConcurrencyConflictError(
                    f"expected revision {meta.expected_revision} does not match current revision "
                    f"{replay.head.revision}",
                    slug=slug,
                    revision=replay.head.revision,
                    event_id=replay.head.event_id,
                )
            if meta.expected_event_hash != replay.head.event_hash:
                raise ConcurrencyConflictError(
                    f"expected event hash {meta.expected_event_hash or '<empty>'} does not match "
                    f"current event hash {replay.head.event_hash or '<empty>'}",
                    slug=slug,
                    revision=replay.head.revision,
                    event_id=replay.head.event_id,
                )
            if meta.generation != replay.state.generation:
                raise ConcurrencyConflictError(
                    f"expected generation {meta.generation} does not match current generation "
                    f"{replay.state.generation}",
                    slug=slug,
                    revision=replay.head.revision,
                    event_id=replay.head.event_id,
                )

            if command_type is CommandType.START_ATTEMPT:
                attempt_data = payload.get("attempt")
                if not isinstance(attempt_data, dict):
                    raise InvalidCommandError("start_attempt payload requires an attempt object", slug=slug)
                action_id = attempt_data.get("action_id")
                action = next(
                    (record for record in replay.state.actions if record.action_id == action_id),
                    None,
                )
                if action is None:
                    raise InvalidCommandError("start_attempt action does not exist", slug=slug)
                attempt_no = max(
                    (
                        attempt.attempt_no
                        for attempt in replay.state.attempts
                        if attempt.action_id == action_id
                    ),
                    default=0,
                ) + 1
                generated_attempt = dict(attempt_data)
                generated_attempt["attempt_no"] = attempt_no
                generated_attempt["attempt_id"] = make_attempt_id(action_id, attempt_no)
                payload = dict(payload)
                payload["attempt"] = generated_attempt

            if command_type is CommandType.CLAIM_WORKFLOW:
                if replay.command_index or replay.ownership.value != "unclaimed_legacy":
                    raise WorkflowAlreadyClaimedError("workflow ownership was already claimed", slug=slug)
            elif replay.ownership.value != "event_kernel_owned":
                raise OwnershipClaimRequiredError("schema 2.0 event requires an ownership claim", slug=slug)

            previous_hash = replay.head.event_hash
            if replay.head.hash_mode is HashMode.LEGACY_UNBOUND:
                previous_hash = "legacy-sha256:" + replay.event_file_prefix_sha256
            command = {
                "command_id": meta.command_id,
                "type": command_type.value,
                "digest": digest,
                "expected_revision": meta.expected_revision,
                "expected_event_hash": meta.expected_event_hash,
            }
            candidate = build_event(
                workflow_id=resolved_workflow_id,
                actor=meta.actor,
                event_type=event_type.value,
                revision=replay.head.revision + 1,
                previous_event_hash=previous_hash,
                generation=meta.generation,
                correlation_id=meta.correlation_id,
                causation_id=meta.causation_id,
                command=command,
                payload=payload,
            )
            next_state = reduce_event(replay.state, upcast_event(candidate))
            line = canonical_event_line(candidate)
            with event_path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())

            cache_updated = True
            try:
                self._update_cache(
                    slug,
                    state=next_state,
                    event=candidate,
                    event_path=event_path,
                )
            except Exception:
                cache_updated = False
            return self._result_from_event(
                candidate,
                cache_updated=cache_updated,
            )

    def append_command(
        self,
        slug: str,
        meta: CommandMeta,
        command_type: CommandType | str,
        payload: dict[str, Any],
        workflow_id: str | None = None,
    ) -> CommandResult:
        """Compatibility entry point retained for Stage 3 callers."""
        return self._commit_command(slug, meta, command_type, payload, workflow_id)

    def _result_from_index(self, entry, *, idempotent: bool) -> CommandResult:
        generated = {
            "event_kernel.action.proposed": (entry.action_id, None, None, None, None),
            "event_kernel.attempt.started": (None, entry.attempt_id, None, None, None),
            "event_kernel.process.started": (None, None, entry.process_id, None, None),
        }.get(entry.event_type, (None, None, None, None, None))
        return CommandResult(
            command_id=entry.command_id,
            event_id=entry.event_id,
            event_type=entry.event_type,
            revision=entry.revision,
            event_hash=entry.event_hash,
            generation=entry.generation,
            idempotent=idempotent,
            action_id=generated[0],
            attempt_id=generated[1],
            process_id=generated[2],
            outbox_id=generated[3],
            checkpoint_id=generated[4],
        )

    def _result_from_event(self, event: dict[str, Any], *, cache_updated: bool) -> CommandResult:
        payload = event["payload"]
        ids = {
            "action_id": None,
            "attempt_id": None,
            "process_id": None,
            "outbox_id": None,
            "checkpoint_id": None,
        }
        allowed = {
            "event_kernel.action.proposed": {"action"},
            "event_kernel.attempt.started": {"attempt"},
            "event_kernel.process.started": {"process"},
            "event_kernel.memory.enqueued": {"outbox"},
            "event_kernel.checkpoint.created": {"checkpoint"},
        }.get(event["type"], set())
        for container, identifier in (
            ("action", "action_id"),
            ("attempt", "attempt_id"),
            ("process", "process_id"),
            ("outbox", "outbox_id"),
            ("checkpoint", "checkpoint_id"),
        ):
            value = payload.get(container) if container in allowed else None
            if isinstance(value, Mapping) and isinstance(value.get(identifier), str):
                ids[identifier] = value[identifier]
        return CommandResult(
            command_id=event["command"]["command_id"],
            event_id=event["event_id"],
            event_type=event["type"],
            revision=event["revision"],
            event_hash=event["event_hash"],
            generation=event["generation"],
            cache_updated=cache_updated,
            **ids,
        )

    def _update_cache(
        self,
        slug: str,
        *,
        state: EventKernelState,
        event: dict[str, Any],
        event_path: Path,
    ) -> None:
        stat = event_path.stat()
        compact_state = _cache_state(state)
        state_bytes = json.dumps(
            compact_state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        cache = {
            "schema_version": "1.0",
            "workflow_id": event["workflow_id"],
            "generation": event["generation"],
            "source_revision": event["revision"],
            "source_event_hash": event["event_hash"],
            "source_event_id": event["event_id"],
            "source_file_size": stat.st_size,
            "source_file_mtime": stat.st_mtime_ns,
            "state_digest": hashlib.sha256(state_bytes).hexdigest(),
            "state": compact_state,
        }
        self._write_cache(cache, path=self.cache_path(slug))

    def _write_cache(self, payload: dict[str, Any], *, path: Path | None = None) -> None:
        target = path or self.cache_path(payload["workflow_id"])
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        data = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        try:
            with temporary.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


__all__ = ["EventStore"]
