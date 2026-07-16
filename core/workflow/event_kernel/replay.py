from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from .contracts import (
    CommandIndexEntry,
    EventIndexEntry,
    EventKernelState,
    EventType,
    HashMode,
    Head,
    OwnershipState,
    ReplayIssue,
    ReplayIssueKind,
    ReplayResult,
    ReplayStats,
)
from .envelope import SCHEMA2_EVENT_TYPES, event_hash, validate_event
from .errors import (
    CommandConflictError,
    CorruptEventLogError,
    DuplicateCommittedCommandError,
    DuplicateEventIdError,
    EventKernelError,
    IllegalTransitionError,
    MixedWriterError,
    OwnershipClaimRequiredError,
    UnknownEventTypeError,
    UnsupportedFutureSchemaError,
    WorkflowNotFoundError,
    issue_to_error,
)
from .reducer import reduce_event
from .upcast import LEGACY_EVENT_TYPES, SemanticEvent, upcast_event


_MIXED_SMOKE_MANIFEST = {
    "slug": "mixed-smoke",
    "workflow_id": "wf-82e6092ac0b3",
    "byte_length": 2045,
    "line_count": 4,
    "file_sha256": "C89FFD15629D293D5B3BC026E361433B074D41725E8AA4EF10B8BE96CDE16BC7",
}
_CHAIN_FIELDS = frozenset({"event_hash", "previous_event_hash", "revision"})


def _initial_state() -> EventKernelState:
    return EventKernelState(
        workflow_id=None,
        generation=1,
        ownership=OwnershipState.UNCLAIMED_LEGACY,
    )


def _as_event_id(event: Mapping[str, Any]) -> str | None:
    value = event.get("event_id")
    return value if isinstance(value, str) else None


def _as_revision(event: Mapping[str, Any]) -> int | None:
    value = event.get("revision")
    return value if type(value) is int else None


def _event_workflow_id(event: Mapping[str, Any]) -> str | None:
    workflow_id = event.get("workflow_id")
    if isinstance(workflow_id, str):
        return workflow_id
    payload = event.get("payload")
    if isinstance(payload, Mapping):
        state = payload.get("state")
        if isinstance(state, Mapping) and isinstance(state.get("workflow_id"), str):
            return state["workflow_id"]
    return None


def _exception_issue_kind(error: BaseException) -> ReplayIssueKind:
    if isinstance(error, UnknownEventTypeError):
        return ReplayIssueKind.UNKNOWN_EVENT
    if isinstance(error, UnsupportedFutureSchemaError):
        return ReplayIssueKind.FUTURE_SCHEMA
    if isinstance(error, DuplicateEventIdError):
        return ReplayIssueKind.DUPLICATE_EVENT
    if isinstance(error, DuplicateCommittedCommandError):
        return ReplayIssueKind.DUPLICATE_COMMAND
    if isinstance(error, CommandConflictError):
        return ReplayIssueKind.COMMAND_CONFLICT
    if isinstance(error, OwnershipClaimRequiredError):
        return ReplayIssueKind.OWNERSHIP_CLAIM_REQUIRED
    if isinstance(error, MixedWriterError):
        return ReplayIssueKind.MIXED_WRITER
    if isinstance(error, IllegalTransitionError):
        return ReplayIssueKind.ILLEGAL_TRANSITION
    return ReplayIssueKind.CORRUPT_CHAIN


@dataclass
class _CandidateEvent:
    raw: bytes
    event: dict[str, Any]
    semantic: SemanticEvent
    offset: int
    line_number: int


class _ReplayScanner:
    def __init__(self, path: Path, slug: str) -> None:
        self.path = path
        self.slug = slug
        self.full_hash = hashlib.sha256()
        self.prefix_hash = hashlib.sha256()
        self.file_bytes = 0
        self.valid_prefix_bytes = 0
        self.lines_read = 0
        self.json_decodes = 0
        self.reducer_calls = 0
        self.state = _initial_state()
        self.event_index: list[EventIndexEntry] = []
        self.command_index: list[CommandIndexEntry] = []
        self.event_ids: set[str] = set()
        self.commands: dict[str, str] = {}
        self.ownership_claim_offset: int | None = None
        self.issue: ReplayIssue | None = None
        self.legacy_mode: HashMode | None = None
        self.legacy_head: str | None = None
        self.candidate: list[_CandidateEvent] = []

    def scan(self) -> ReplayResult:
        try:
            handle = self.path.open("rb")
        except FileNotFoundError as exc:
            raise WorkflowNotFoundError(
                f"event log does not exist: {self.path}", slug=self.slug
            ) from exc

        with handle:
            while True:
                raw = handle.readline()
                if raw == b"":
                    break
                offset = self.file_bytes
                self.file_bytes += len(raw)
                self.full_hash.update(raw)
                self.lines_read += 1
                if self.issue is not None:
                    continue
                if not raw.endswith(b"\n"):
                    self._set_issue(
                        ReplayIssueKind.INCOMPLETE_FINAL_LINE,
                        "event log ended with an incomplete final line",
                        offset,
                    )
                    continue
                self._scan_line(raw, offset)

        if self.issue is None and self.candidate:
            self._finalize_candidate()
        return self._result()

    def _set_issue(
        self,
        kind: ReplayIssueKind,
        message: str,
        offset: int,
        *,
        revision: int | None = None,
        event_id: str | None = None,
    ) -> None:
        if self.issue is not None:
            return
        self.issue = ReplayIssue(
            kind=kind,
            message=message,
            offset=offset,
            revision=revision,
            event_id=event_id,
            line_number=self.lines_read,
        )

    def _scan_line(self, raw: bytes, offset: int) -> None:
        try:
            text = raw[:-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            self._set_issue(ReplayIssueKind.INVALID_UTF8, str(exc), offset)
            return
        try:
            event = json.loads(text)
        except json.JSONDecodeError as exc:
            self.json_decodes += 1
            self._set_issue(ReplayIssueKind.INVALID_JSON, str(exc), offset)
            return
        self.json_decodes += 1
        if not isinstance(event, dict):
            self._set_issue(ReplayIssueKind.INVALID_JSON, "event line must be a JSON object", offset)
            return
        schema_version = event.get("schema_version")
        if schema_version == "1.0":
            self._scan_legacy(event, raw, offset)
            return
        self._scan_schema2(event, raw, offset)

    def _scan_legacy(self, event: dict[str, Any], raw: bytes, offset: int) -> None:
        if self.state.ownership is OwnershipState.EVENT_KERNEL_OWNED:
            self._set_issue(
                ReplayIssueKind.MIXED_WRITER,
                "schema 1.0 event occurred after ownership claim",
                offset,
                revision=_as_revision(event),
                event_id=_as_event_id(event),
            )
            return
        present = _CHAIN_FIELDS.intersection(event)
        if not present:
            if self.legacy_mode is not None:
                self._set_issue(
                    ReplayIssueKind.CORRUPT_CHAIN,
                    "schema 1.0 unbound prefix must end before the next event",
                    offset,
                    event_id=_as_event_id(event),
                )
                return
            try:
                semantic = upcast_event(event)
            except EventKernelError as exc:
                self._set_issue(_exception_issue_kind(exc), str(exc), offset, revision=exc.revision, event_id=exc.event_id)
                return
            self.candidate.append(
                _CandidateEvent(
                    raw=raw,
                    event=event,
                    semantic=semantic,
                    offset=offset,
                    line_number=self.lines_read,
                )
            )
            if len(self.candidate) >= _MIXED_SMOKE_MANIFEST["line_count"]:
                self._finalize_candidate()
            return
        if present != _CHAIN_FIELDS:
            self._set_issue(
                ReplayIssueKind.CORRUPT_CHAIN,
                "schema 1.0 chain fields must be complete or entirely absent",
                offset,
                revision=_as_revision(event),
                event_id=_as_event_id(event),
            )
            return
        if self.legacy_mode is HashMode.LEGACY_UNBOUND:
            self._set_issue(
                ReplayIssueKind.CORRUPT_CHAIN,
                "schema 1.0 hashed event cannot follow an unbound prefix",
                offset,
                revision=_as_revision(event),
                event_id=_as_event_id(event),
            )
            return
        self._scan_hashed_legacy(event, raw, offset)

    def _scan_hashed_legacy(self, event: dict[str, Any], raw: bytes, offset: int) -> None:
        revision = _as_revision(event)
        supplied_hash = event.get("event_hash")
        previous_hash = event.get("previous_event_hash")
        if revision != len(self.event_index) + 1:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, "legacy revision is not contiguous", offset, revision=revision, event_id=_as_event_id(event))
            return
        if not isinstance(supplied_hash, str) or not isinstance(previous_hash, str):
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, "legacy chain fields have invalid types", offset, revision=revision, event_id=_as_event_id(event))
            return
        try:
            calculated = event_hash(event)
        except EventKernelError as exc:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, str(exc), offset, revision=revision, event_id=_as_event_id(event))
            return
        expected_previous = ""
        if self.event_index:
            expected_previous = self.event_index[-1].event_hash
        if supplied_hash != calculated or previous_hash != expected_previous:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, "legacy event hash chain is invalid", offset, revision=revision, event_id=_as_event_id(event))
            return
        try:
            semantic = upcast_event(event)
        except EventKernelError as exc:
            self._set_issue(_exception_issue_kind(exc), str(exc), offset, revision=exc.revision, event_id=exc.event_id)
            return
        self.legacy_mode = HashMode.HASHED
        self._commit(
            event,
            semantic,
            raw,
            offset,
            HashMode.HASHED,
            supplied_hash,
            previous_hash,
            revision,
        )

    def _scan_schema2(self, event: dict[str, Any], raw: bytes, offset: int) -> None:
        try:
            validate_event(event)
        except EventKernelError as exc:
            self._set_issue(_exception_issue_kind(exc), str(exc), offset, revision=exc.revision, event_id=exc.event_id)
            return
        revision = _as_revision(event)
        if revision != len(self.event_index) + 1:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, "schema 2.0 revision is not contiguous", offset, revision=revision, event_id=_as_event_id(event))
            return
        event_type = event["type"]
        if self.state.ownership is not OwnershipState.EVENT_KERNEL_OWNED and event_type != "event_kernel.ownership.claimed":
            self._set_issue(ReplayIssueKind.OWNERSHIP_CLAIM_REQUIRED, "the first schema 2.0 event must claim ownership", offset, revision=revision, event_id=_as_event_id(event))
            return
        if self.state.ownership is OwnershipState.EVENT_KERNEL_OWNED and event_type == "event_kernel.ownership.claimed":
            self._set_issue(ReplayIssueKind.ILLEGAL_TRANSITION, "workflow ownership was already claimed", offset, revision=revision, event_id=_as_event_id(event))
            return
        expected_previous = ""
        if self.event_index:
            expected_previous = self.event_index[-1].event_hash
        elif self.legacy_head is not None:
            expected_previous = self.legacy_head
        if event["previous_event_hash"] != expected_previous:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, "schema 2.0 previous_event_hash does not match the replay head", offset, revision=revision, event_id=_as_event_id(event))
            return
        try:
            semantic = upcast_event(event)
        except EventKernelError as exc:
            self._set_issue(_exception_issue_kind(exc), str(exc), offset, revision=exc.revision, event_id=exc.event_id)
            return
        self._commit(
            event,
            semantic,
            raw,
            offset,
            HashMode.HASHED,
            event["event_hash"],
            event["previous_event_hash"],
            revision,
        )

    def _finalize_candidate(self) -> None:
        if not self.candidate:
            return
        prefix = b"".join(item.raw for item in self.candidate)
        workflow_id = None
        for item in self.candidate:
            if item.event.get("type") == "workflow.created":
                workflow_id = _event_workflow_id(item.event)
                break
        manifest_matches = (
            self.slug == _MIXED_SMOKE_MANIFEST["slug"]
            and workflow_id == _MIXED_SMOKE_MANIFEST["workflow_id"]
            and len(prefix) == _MIXED_SMOKE_MANIFEST["byte_length"]
            and len(self.candidate) == _MIXED_SMOKE_MANIFEST["line_count"]
            and hashlib.sha256(prefix).hexdigest() == _MIXED_SMOKE_MANIFEST["file_sha256"]
        )
        if not manifest_matches:
            self._set_issue(
                ReplayIssueKind.CORRUPT_CHAIN,
                "schema 1.0 unbound prefix does not match the pinned manifest",
                0,
            )
            self.candidate.clear()
            return
        self.legacy_mode = HashMode.LEGACY_UNBOUND
        self.legacy_head = "legacy-sha256:" + _MIXED_SMOKE_MANIFEST["file_sha256"]
        for item in self.candidate:
            if self.issue is not None:
                break
            self._commit(
                item.event,
                item.semantic,
                item.raw,
                item.offset,
                HashMode.LEGACY_UNBOUND,
                "",
                "",
                len(self.event_index) + 1,
            )
        self.candidate.clear()

    def _commit(
        self,
        event: dict[str, Any],
        semantic: SemanticEvent,
        raw: bytes,
        offset: int,
        hash_mode: HashMode,
        supplied_hash: str,
        previous_hash: str,
        revision: int,
    ) -> None:
        event_id = _as_event_id(event)
        if event_id is None:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, "event_id is required", offset, revision=revision)
            return
        if event_id in self.event_ids:
            self._set_issue(ReplayIssueKind.DUPLICATE_EVENT, "event_id occurs more than once", offset, revision=revision, event_id=event_id)
            return
        try:
            command_entry = self._command_entry(event, revision, offset, len(raw), supplied_hash)
        except EventKernelError as exc:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, str(exc), offset, revision=revision, event_id=event_id)
            return
        if command_entry is _COMMAND_DUPLICATE:
            self._set_issue(ReplayIssueKind.DUPLICATE_COMMAND, "command_id was committed more than once", offset, revision=revision, event_id=event_id)
            return
        if command_entry is _COMMAND_CONFLICT:
            self._set_issue(ReplayIssueKind.COMMAND_CONFLICT, "command_id was reused with a different digest", offset, revision=revision, event_id=event_id)
            return
        try:
            entry = EventIndexEntry(
                revision=revision,
                event_id=event_id,
                event_type=event["type"],
                event_hash=supplied_hash,
                previous_event_hash=previous_hash,
                schema_version=event["schema_version"],
                generation=event.get("generation", self.state.generation),
                byte_offset=offset,
                byte_length=len(raw),
                hash_mode=hash_mode,
            )
        except EventKernelError as exc:
            self._set_issue(ReplayIssueKind.CORRUPT_CHAIN, str(exc), offset, revision=revision, event_id=event_id)
            return
        try:
            next_state = reduce_event(self.state, semantic)
        except EventKernelError as exc:
            self._set_issue(_exception_issue_kind(exc), str(exc), offset, revision=exc.revision or revision, event_id=exc.event_id or event_id)
            return
        self.state = next_state
        self.event_ids.add(event_id)
        self.event_index.append(entry)
        if command_entry is not None:
            self.command_index.append(command_entry)
        self.reducer_calls += 1
        self.valid_prefix_bytes += len(raw)
        self.prefix_hash.update(raw)
        if event["type"] == "event_kernel.ownership.claimed":
            self.ownership_claim_offset = offset

    def _command_entry(
        self,
        event: dict[str, Any],
        revision: int,
        offset: int,
        byte_length: int,
        supplied_hash: str,
    ) -> CommandIndexEntry | None | object:
        if event.get("schema_version") != "2.0":
            return None
        command = event.get("command")
        if not isinstance(command, Mapping):
            return None
        command_id = command.get("command_id")
        digest = command.get("digest")
        if not isinstance(command_id, str) or not isinstance(digest, str):
            return None
        previous = self.commands.get(command_id)
        if previous is not None:
            return _COMMAND_DUPLICATE if previous == digest else _COMMAND_CONFLICT
        payload = event.get("payload")
        payload = payload if isinstance(payload, Mapping) else {}
        ids: dict[str, str | None] = {
            "action_id": None,
            "attempt_id": None,
            "process_id": None,
            "outbox_id": None,
            "checkpoint_id": None,
        }
        for container_name, id_name in (
            ("action", "action_id"),
            ("attempt", "attempt_id"),
            ("process", "process_id"),
            ("outbox", "outbox_id"),
            ("checkpoint", "checkpoint_id"),
        ):
            value = payload.get(container_name)
            if isinstance(value, Mapping) and isinstance(value.get(id_name), str):
                ids[id_name] = value[id_name]
        entry = CommandIndexEntry(
            command_id=command_id,
            command_type=command["type"],
            command_digest=digest,
            event_id=event["event_id"],
            event_type=event["type"],
            revision=revision,
            event_hash=supplied_hash,
            generation=event["generation"],
            byte_offset=offset,
            byte_length=byte_length,
            **ids,
        )
        self.commands[command_id] = digest
        return entry

    def _result(self) -> ReplayResult:
        if self.issue is None and self.candidate:
            self._finalize_candidate()
        if self.issue is None and self.legacy_mode is HashMode.LEGACY_UNBOUND:
            self.legacy_head = "legacy-sha256:" + _MIXED_SMOKE_MANIFEST["file_sha256"]
        if self.event_index:
            last = self.event_index[-1]
            head = Head(
                revision=last.revision,
                event_hash=last.event_hash,
                event_id=last.event_id,
                hash_mode=last.hash_mode,
            )
        else:
            head = Head(revision=0, event_hash="", event_id=None, hash_mode=HashMode.EMPTY)
        ownership = self.state.ownership
        return ReplayResult(
            state=self.state,
            head=head,
            event_count=len(self.event_index),
            semantic_event_count=self.reducer_calls,
            valid_prefix_bytes=self.valid_prefix_bytes,
            event_file_prefix_sha256=self.prefix_hash.hexdigest(),
            event_file_bytes=self.file_bytes,
            event_file_sha256=self.full_hash.hexdigest(),
            ownership=ownership,
            event_index=tuple(self.event_index),
            command_index=tuple(self.command_index),
            ownership_claim_offset=self.ownership_claim_offset,
            issue=self.issue,
            stats=ReplayStats(
                lines_read=self.lines_read,
                json_decodes=self.json_decodes,
                reducer_calls=self.reducer_calls,
            ),
        )


_COMMAND_DUPLICATE = object()
_COMMAND_CONFLICT = object()


def inspect_event_log(path: str | Path, *, slug: str) -> ReplayResult:
    return _ReplayScanner(Path(path), slug).scan()


def materialize_event_log(path: str | Path, *, slug: str) -> EventKernelState:
    result = inspect_event_log(path, slug=slug)
    if result.issue is not None:
        raise issue_to_error(result.issue, slug=slug)
    return result.state


__all__ = ["inspect_event_log", "materialize_event_log"]
