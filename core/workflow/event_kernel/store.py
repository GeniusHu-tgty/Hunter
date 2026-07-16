from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from collections.abc import Callable, Mapping
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
    RecoveryRequest,
    ReplayIssueKind,
)
from .envelope import build_event, canonical_event_line, canonical_json_bytes, command_digest
from .envelope import make_attempt_id, make_checkpoint_id, make_process_id, make_outbox_id
from .errors import (
    CommandConflictError,
    ConcurrencyConflictError,
    CheckpointBindingError,
    InvalidCommandError,
    OutboxConflictError,
    OwnershipClaimRequiredError,
    RecoveryNotAuthorizedError,
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

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        lock_timeout: float = 10.0,
        crash_hook: Callable[[str], None] | None = None,
    ) -> None:
        if workspace_root is None:
            raise InvalidCommandError("workspace_root is required")
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.cases_root = (self.workspace_root / "cases").resolve()
        self.lock_timeout = float(lock_timeout)
        self._crash_hook = crash_hook

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

    def create_checkpoint(self, slug: str, meta: CommandMeta) -> CommandResult:
        """Persist a checkpoint-v2 sidecar and bind it with one event-log entry."""
        if not isinstance(meta, CommandMeta):
            raise InvalidCommandError("meta must be CommandMeta")
        workflow_dir = self._workflow_dir(slug)
        event_path = self.event_log_path(slug)
        with WorkflowFileLock(workflow_dir / ".workflow.lock", timeout=self.lock_timeout):
            workflow_dir.mkdir(parents=True, exist_ok=True)
            event_path.touch(exist_ok=True)
            replay = inspect_event_log(event_path, slug=slug)
            if replay.issue is not None:
                raise issue_to_error(replay.issue, slug=slug)
            self._cleanup_orphan_checkpoints(workflow_dir, replay)
            existing = next(
                (entry for entry in replay.command_index if entry.command_id == meta.command_id),
                None,
            )
            if existing is not None:
                if existing.command_type is not CommandType.CREATE_CHECKPOINT:
                    raise CommandConflictError("command_id was already committed with a different digest", slug=slug)
                return self._result_from_index(existing, idempotent=True)
            if replay.ownership.value != "event_kernel_owned":
                raise OwnershipClaimRequiredError("schema 2.0 event requires an ownership claim", slug=slug)
            if meta.expected_revision != replay.head.revision or meta.expected_event_hash != replay.head.event_hash:
                raise ConcurrencyConflictError("checkpoint command head does not match current event log", slug=slug)
            if meta.generation != replay.state.generation:
                raise ConcurrencyConflictError("checkpoint command generation does not match current event log", slug=slug)

            checkpoint_id = make_checkpoint_id()
            relative_path = f"checkpoints/event-kernel/{checkpoint_id}.json"
            state = _cache_state(replay.state)
            state_digest = hashlib.sha256(canonical_json_bytes(state)).hexdigest()
            sidecar = {
                "schema_version": "2.0",
                "checkpoint_id": checkpoint_id,
                "workflow_id": replay.state.workflow_id,
                "generation": replay.state.generation,
                "bound_revision": replay.head.revision,
                "bound_event_hash": replay.head.event_hash,
                "bound_event_id": replay.head.event_id,
                "binding_mode": replay.head.hash_mode.value,
                "state_digest": state_digest,
                "event_file_prefix_sha256": replay.event_file_prefix_sha256,
                "bound_prefix_bytes": replay.valid_prefix_bytes,
                "relative_path": relative_path,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
                "state": state,
            }
            sidecar_bytes = canonical_json_bytes(sidecar) + b"\n"
            sidecar_hash = hashlib.sha256(sidecar_bytes).hexdigest()
            sidecar_path = workflow_dir / relative_path
            self._write_sidecar(
                sidecar_path,
                sidecar_bytes,
                after_rename="checkpoint_after_rename_before_event_append",
            )

            checkpoint = {
                **{key: value for key, value in sidecar.items() if key != "state"},
                "checkpoint_file_sha256": sidecar_hash,
                "event_end_offset": 0,
            }
            payload = {"checkpoint": checkpoint}
            digest = command_digest({
                "workflow_id": replay.state.workflow_id,
                "generation": meta.generation,
                "type": CommandType.CREATE_CHECKPOINT.value,
                "correlation_id": meta.correlation_id,
                "causation_id": meta.causation_id,
                "payload": payload,
            })
            command = {
                "command_id": meta.command_id,
                "type": CommandType.CREATE_CHECKPOINT.value,
                "digest": digest,
                "expected_revision": meta.expected_revision,
                "expected_event_hash": meta.expected_event_hash,
            }
            previous_hash = replay.head.event_hash
            for _ in range(3):
                candidate = build_event(
                    workflow_id=replay.state.workflow_id,
                    actor=meta.actor,
                    event_type=EventType.CHECKPOINT_CREATED.value,
                    revision=replay.head.revision + 1,
                    previous_event_hash=previous_hash,
                    generation=meta.generation,
                    correlation_id=meta.correlation_id,
                    causation_id=meta.causation_id,
                    command=command,
                    payload=payload,
                )
                line = canonical_event_line(candidate)
                event_end_offset = replay.valid_prefix_bytes + len(line)
                if checkpoint["event_end_offset"] == event_end_offset:
                    break
                checkpoint["event_end_offset"] = event_end_offset
            else:
                raise InvalidCommandError("checkpoint event offset did not converge", slug=slug)
            next_state = reduce_event(replay.state, upcast_event(candidate))
            with event_path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            cache_updated = True
            try:
                self._update_cache(slug, state=next_state, event=candidate, event_path=event_path)
            except Exception:
                cache_updated = False
            return self._result_from_event(candidate, cache_updated=cache_updated)

    def recover_checkpoint(
        self, slug: str, meta: CommandMeta, recovery: RecoveryRequest
    ) -> CommandResult:
        """Replace a checkpoint-authorized corrupt tail with one recovery event."""
        if not isinstance(meta, CommandMeta):
            raise InvalidCommandError("meta must be CommandMeta")
        if not isinstance(recovery, RecoveryRequest):
            raise InvalidCommandError("recovery must be RecoveryRequest")
        workflow_dir = self._workflow_dir(slug)
        event_path = self.event_log_path(slug)
        with WorkflowFileLock(workflow_dir / ".workflow.lock", timeout=self.lock_timeout):
            replay = inspect_event_log(event_path, slug=slug)
            request_digest = command_digest({
                "workflow_id": replay.state.workflow_id,
                "generation": meta.generation,
                "type": CommandType.RECOVER_CHECKPOINT.value,
                "correlation_id": meta.correlation_id,
                "causation_id": meta.causation_id,
                "payload": {"recovery_request": {
                    "checkpoint_id": recovery.checkpoint_id,
                    "expected_source_file_bytes": recovery.expected_source_file_bytes,
                    "expected_source_file_sha256": recovery.expected_source_file_sha256,
                }},
            })
            existing = next(
                (entry for entry in replay.command_index if entry.command_id == meta.command_id),
                None,
            )
            if existing is not None:
                if (
                    existing.command_type is not CommandType.RECOVER_CHECKPOINT
                    or existing.command_digest != request_digest
                ):
                    raise CommandConflictError("command_id was already committed with a different digest", slug=slug)
                return self._result_from_index(existing, idempotent=True)
            if replay.issue is None:
                raise RecoveryNotAuthorizedError("recovery requires a corrupt event-log tail", slug=slug)
            if replay.ownership.value != "event_kernel_owned":
                raise OwnershipClaimRequiredError("schema 2.0 event requires an ownership claim", slug=slug)
            if meta.expected_revision != replay.head.revision or meta.expected_event_hash != replay.head.event_hash:
                raise ConcurrencyConflictError("recovery command head does not match valid prefix", slug=slug)
            if meta.generation != replay.state.generation:
                raise ConcurrencyConflictError("recovery command generation does not match valid prefix", slug=slug)
            source = event_path.read_bytes()
            if len(source) != recovery.expected_source_file_bytes or hashlib.sha256(source).hexdigest() != recovery.expected_source_file_sha256:
                raise ConcurrencyConflictError("recovery source bytes do not match the supplied CAS binding", slug=slug)
            if replay.event_file_bytes != len(source) or replay.event_file_sha256 != recovery.expected_source_file_sha256:
                raise ConcurrencyConflictError("replay source does not match the supplied CAS binding", slug=slug)

            checkpoint = next(
                (record for record in replay.state.checkpoints if record.checkpoint_id == recovery.checkpoint_id),
                None,
            )
            if checkpoint is None:
                raise CheckpointBindingError("checkpoint is not present in the valid event-log prefix", slug=slug)
            self._validate_checkpoint_binding(workflow_dir, replay, checkpoint)
            allowed_issues = {
                ReplayIssueKind.INCOMPLETE_FINAL_LINE,
                ReplayIssueKind.INVALID_UTF8,
                ReplayIssueKind.INVALID_JSON,
                ReplayIssueKind.CORRUPT_CHAIN,
            }
            if replay.issue.kind not in allowed_issues or replay.issue.offset < checkpoint.event_end_offset:
                raise RecoveryNotAuthorizedError("checkpoint does not authorize this recovery tail", slug=slug)

            retained = source[:replay.valid_prefix_bytes]
            discarded = source[replay.valid_prefix_bytes:]
            backup_relative = f"recovery/event-kernel/{checkpoint.checkpoint_id}-{recovery.expected_source_file_sha256}.jsonl"
            backup_path = workflow_dir / backup_relative
            if backup_path.exists():
                if backup_path.read_bytes() != source:
                    raise CheckpointBindingError("existing recovery backup does not match the source event log", slug=slug)
            else:
                self._write_sidecar(
                    backup_path,
                    source,
                    before_rename="backup_after_fsync_before_rename",
                )
            self._crash("backup_after_rename_before_recovery_temp")
            payload = {"recovery": {
                "checkpoint_id": checkpoint.checkpoint_id,
                "checkpoint_event_id": checkpoint.event_id,
                "checkpoint_event_end_offset": checkpoint.event_end_offset,
                "issue_kind": replay.issue.kind.value,
                "issue_offset": replay.issue.offset,
                "source_file_bytes": len(source),
                "source_file_sha256": recovery.expected_source_file_sha256,
                "retained_prefix_bytes": len(retained),
                "retained_prefix_sha256": hashlib.sha256(retained).hexdigest(),
                "discarded_tail_bytes": len(discarded),
                "discarded_tail_sha256": hashlib.sha256(discarded).hexdigest(),
                "backup_relative_path": backup_relative,
                "backup_file_bytes": len(source),
                "backup_file_sha256": recovery.expected_source_file_sha256,
            }}
            candidate = build_event(
                workflow_id=replay.state.workflow_id,
                actor=meta.actor,
                event_type=EventType.RECOVERY_PERFORMED.value,
                revision=replay.head.revision + 1,
                previous_event_hash=replay.head.event_hash,
                generation=meta.generation,
                correlation_id=meta.correlation_id,
                causation_id=meta.causation_id,
                command={
                    "command_id": meta.command_id,
                    "type": CommandType.RECOVER_CHECKPOINT.value,
                    "digest": request_digest,
                    "expected_revision": meta.expected_revision,
                    "expected_event_hash": meta.expected_event_hash,
                },
                payload=payload,
            )
            line = canonical_event_line(candidate)
            temporary = event_path.with_name(f".{event_path.name}.{os.getpid()}.recovery.tmp")
            try:
                with temporary.open("wb") as handle:
                    handle.write(retained)
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
                self._crash("recovery_temp_after_fsync_before_replace")
                os.replace(temporary, event_path)
                self._crash("recovery_after_replace_before_dirsync")
                self._fsync_directory(workflow_dir)
                self._crash("recovery_after_dirsync_before_cache")
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            next_state = reduce_event(replay.state, upcast_event(candidate))
            cache_updated = True
            try:
                self._update_cache(slug, state=next_state, event=candidate, event_path=event_path)
            except Exception:
                cache_updated = False
            return self._result_from_event(candidate, cache_updated=cache_updated)

    @staticmethod
    def _validate_checkpoint_binding(workflow_dir: Path, replay, checkpoint) -> None:
        path = (workflow_dir / checkpoint.relative_path).resolve()
        try:
            path.relative_to(workflow_dir)
        except ValueError as exc:
            raise CheckpointBindingError("checkpoint sidecar path escapes the workflow directory") from exc
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != checkpoint.checkpoint_file_sha256:
            raise CheckpointBindingError("checkpoint sidecar SHA-256 does not match its event binding")
        try:
            sidecar = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CheckpointBindingError("checkpoint sidecar is not valid JSON") from exc
        expected = {
            "checkpoint_id": checkpoint.checkpoint_id,
            "workflow_id": checkpoint.workflow_id,
            "generation": checkpoint.generation,
            "bound_revision": checkpoint.bound_revision,
            "bound_event_hash": checkpoint.bound_event_hash,
            "bound_event_id": checkpoint.bound_event_id,
            "state_digest": checkpoint.state_digest,
            "event_file_prefix_sha256": checkpoint.event_file_prefix_sha256,
            "bound_prefix_bytes": checkpoint.bound_prefix_bytes,
            "relative_path": checkpoint.relative_path,
        }
        if any(sidecar.get(key) != value for key, value in expected.items()):
            raise CheckpointBindingError("checkpoint sidecar fields do not match its event binding")
        state = sidecar.get("state")
        if not isinstance(state, dict) or hashlib.sha256(canonical_json_bytes(state)).hexdigest() != checkpoint.state_digest:
            raise CheckpointBindingError("checkpoint sidecar state digest does not match its compact state")
        event_log = workflow_dir / "workflow.events.jsonl"
        source = event_log.read_bytes()
        if (
            checkpoint.bound_prefix_bytes > len(source)
            or hashlib.sha256(source[:checkpoint.bound_prefix_bytes]).hexdigest()
            != checkpoint.event_file_prefix_sha256
        ):
            raise CheckpointBindingError("checkpoint event prefix digest does not match the event log")
        if checkpoint.bound_revision > replay.head.revision:
            raise CheckpointBindingError("checkpoint bound revision is outside the valid prefix")
        bound = replay.event_index[checkpoint.bound_revision - 1]
        if bound.event_id != checkpoint.bound_event_id or bound.event_hash != checkpoint.bound_event_hash:
            raise CheckpointBindingError("checkpoint head binding does not match the event log")
        if checkpoint.event_end_offset > replay.valid_prefix_bytes:
            raise CheckpointBindingError("checkpoint event is outside the valid prefix")

    def _crash(self, point: str) -> None:
        if self._crash_hook is not None:
            self._crash_hook(point)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            create_file = ctypes.windll.kernel32.CreateFileW
            create_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                str(path),
                0x80000000,
                0x00000001 | 0x00000002 | 0x00000004,
                None,
                3,
                0x02000000,
                None,
            )
            invalid_handle = ctypes.c_void_p(-1).value
            if handle == invalid_handle:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                if not ctypes.windll.kernel32.FlushFileBuffers(handle):
                    # NTFS commonly rejects FlushFileBuffers for directory
                    # handles; the durable file writes and atomic replace are
                    # still mandatory and have already completed.
                    return
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_sidecar(
        self,
        path: Path,
        data: bytes,
        *,
        before_rename: str | None = None,
        after_rename: str | None = None,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if before_rename is not None:
                self._crash(before_rename)
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
            if after_rename is not None:
                self._crash(after_rename)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _cleanup_orphan_checkpoints(workflow_dir: Path, replay) -> None:
        directory = workflow_dir / "checkpoints" / "event-kernel"
        if not directory.exists():
            return
        referenced = {record.relative_path for record in replay.state.checkpoints}
        for path in sorted(directory.glob("cp-*.json")):
            relative_path = path.relative_to(workflow_dir).as_posix()
            if relative_path in referenced:
                continue
            try:
                data = path.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                sidecar = json.loads(data)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                not digest
                or sidecar.get("schema_version") != "2.0"
                or sidecar.get("checkpoint_id") != path.stem
                or sidecar.get("relative_path") != relative_path
            ):
                continue
            path.unlink()

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

            if command_type is CommandType.START_PROCESS:
                process_data = payload.get("process")
                if not isinstance(process_data, dict):
                    raise InvalidCommandError(
                        "start_process payload requires a process object", slug=slug
                    )
                generated_process = dict(process_data)
                generated_process["process_id"] = make_process_id()
                payload = dict(payload)
                payload["process"] = generated_process

            if command_type is CommandType.ENQUEUE_MEMORY:
                outbox_data = payload.get("outbox")
                if not isinstance(outbox_data, dict):
                    raise InvalidCommandError("enqueue_memory payload requires an outbox object", slug=slug)
                generated_outbox = dict(outbox_data)
                generated_outbox["outbox_id"] = make_outbox_id(
                    workflow_id=resolved_workflow_id,
                    generation=meta.generation,
                    projector=generated_outbox.get("projector"),
                    dedupe_key=generated_outbox.get("dedupe_key"),
                    payload=generated_outbox.get("payload"),
                )
                existing_outbox = next(
                    (
                        entry
                        for entry in replay.state.outbox
                        if entry.generation == meta.generation
                        and entry.projector == generated_outbox["projector"]
                        and entry.dedupe_key == generated_outbox["dedupe_key"]
                    ),
                    None,
                )
                if existing_outbox is not None:
                    if existing_outbox.outbox_id != generated_outbox["outbox_id"]:
                        raise OutboxConflictError(
                            "memory enqueue dedupe scope already exists with a different payload",
                            slug=slug,
                        )
                    original = next(
                        entry
                        for entry in replay.command_index
                        if entry.outbox_id == existing_outbox.outbox_id
                    )
                    return CommandResult(
                        command_id=meta.command_id,
                        event_id=original.event_id,
                        event_type=original.event_type,
                        revision=original.revision,
                        event_hash=original.event_hash,
                        generation=original.generation,
                        deduplicated=True,
                        original_command_id=original.command_id,
                        original_event_id=original.event_id,
                        outbox_id=existing_outbox.outbox_id,
                    )
                payload = dict(payload)
                payload["outbox"] = generated_outbox

            if command_type is CommandType.RECORD_PROCESS_OUTPUT:
                output_data = payload.get("process_output")
                if not isinstance(output_data, dict):
                    raise InvalidCommandError(
                        "record_process_output payload requires a process_output object",
                        slug=slug,
                    )
                process_id = output_data.get("process_id")
                process = next(
                    (
                        record
                        for record in replay.state.processes
                        if record.process_id == process_id
                    ),
                    None,
                )
                generated_output = dict(output_data)
                generated_output["sequence"] = (
                    process.last_sequence + 1 if process is not None else 1
                )
                excerpt = generated_output.get("redacted_excerpt")
                if isinstance(excerpt, str):
                    generated_output["excerpt_digest"] = hashlib.sha256(
                        excerpt.encode("utf-8")
                    ).hexdigest()
                payload = dict(payload)
                payload["process_output"] = generated_output

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
            "event_kernel.memory.enqueued": (None, None, None, entry.outbox_id, None),
            "event_kernel.memory.applied": (None, None, None, entry.outbox_id, None),
            "event_kernel.memory.failed": (None, None, None, entry.outbox_id, None),
            "event_kernel.checkpoint.created": (None, None, None, None, entry.checkpoint_id),
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
            "event_kernel.memory.applied": {"outbox"},
            "event_kernel.memory.failed": {"outbox"},
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
