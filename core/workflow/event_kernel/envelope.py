from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any
import uuid

from .errors import (
    CorruptEventLogError,
    InvalidCommandError,
    UnknownEventTypeError,
    UnsupportedFutureSchemaError,
)


SCHEMA_VERSION = "2.0"
MAX_CANONICAL_JSON_BYTES = 256 * 1024
_COMMAND_EVENT_TYPES = {
    "claim_workflow": "event_kernel.ownership.claimed",
    "propose_action": "event_kernel.action.proposed",
    "merge_action": "event_kernel.action.merged",
    "defer_action": "event_kernel.action.deferred",
    "block_action": "event_kernel.action.blocked",
    "start_attempt": "event_kernel.attempt.started",
    "complete_attempt": "event_kernel.attempt.completed",
    "block_attempt": "event_kernel.attempt.blocked",
    "cancel_attempt": "event_kernel.attempt.cancelled",
    "attest_evidence": "event_kernel.evidence.attested",
    "record_verdict": "event_kernel.verdict.recorded",
    "start_process": "event_kernel.process.started",
    "record_process_output": "event_kernel.process.output_recorded",
    "terminate_process": "event_kernel.process.terminated",
    "enqueue_memory": "event_kernel.memory.enqueued",
    "mark_memory_applied": "event_kernel.memory.applied",
    "mark_memory_failed": "event_kernel.memory.failed",
    "create_checkpoint": "event_kernel.checkpoint.created",
    "recover_checkpoint": "event_kernel.recovery.performed",
}
SCHEMA2_EVENT_TYPES = frozenset(_COMMAND_EVENT_TYPES.values())
_GENERATION_MAX = 999_999
_ACTION_ID_PATTERN = re.compile(r"act-g([0-9]{6})-([0-9a-f]{16})")
_WORKFLOW_ID_PATTERN = re.compile(r"wf-[0-9a-f]{12}")
_EVENT_ID_PATTERN = re.compile(r"evt-[0-9a-f]{16}")
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_LEGACY_HEAD_PATTERN = re.compile(r"legacy-sha256:[0-9a-f]{64}")
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00"
)
_SCHEMA_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_MAX_JSON_DEPTH = 64
_MAX_JSON_KEY_BYTES = 4096
_MAX_JSON_STRING_BYTES = MAX_CANONICAL_JSON_BYTES
_MAX_SCHEMA_VERSION_LENGTH = 32
_EVENT_FIELDS = frozenset(
    {
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
)
_COMMAND_FIELDS = frozenset(
    {
        "command_id",
        "type",
        "digest",
        "expected_revision",
        "expected_event_hash",
    }
)
_DIGEST_GENERATED_PAYLOAD_PATHS = frozenset(
    {
        ("attempt", "attempt_id"),
        ("attempt", "attempt_no"),
        ("process_output", "sequence"),
        ("outbox", "outbox_id"),
        ("outbox", "delivery_attempt"),
        ("checkpoint", "checkpoint_id"),
        ("checkpoint", "checkpoint_file_sha256"),
        ("checkpoint", "checkpoint_relative_path"),
    }
)
_DIGEST_INTENT_FIELDS = frozenset(
    {
        "workflow_id",
        "generation",
        "type",
        "actor",
        "correlation_id",
        "causation_id",
        "command",
        "payload",
        "event_id",
        "timestamp",
    }
)
_DIGEST_COMMAND_FIELDS = frozenset(
    {
        "command_id",
        "type",
        "digest",
        "expected_revision",
        "expected_event_hash",
    }
)


def _utf8_length(value: str, path: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise InvalidCommandError(f"{path} contains an invalid Unicode surrogate") from exc


def _validate_json_native(value: Any, path: str = "$") -> None:
    stack: list[tuple[Any, str, int, bool]] = [(value, path, 0, False)]
    active_containers: set[int] = set()

    while stack:
        item, item_path, depth, leaving = stack.pop()
        item_type = type(item)
        if leaving:
            active_containers.remove(id(item))
            continue
        if depth > _MAX_JSON_DEPTH:
            raise InvalidCommandError(
                f"{item_path} exceeds maximum JSON nesting depth {_MAX_JSON_DEPTH}"
            )
        if item is None or item_type is bool or item_type is int:
            continue
        if item_type is float:
            if not math.isfinite(item):
                raise InvalidCommandError(f"{item_path} contains a non-finite float")
            continue
        if item_type is str:
            if _utf8_length(item, item_path) > _MAX_JSON_STRING_BYTES:
                raise InvalidCommandError(f"{item_path} contains an oversized JSON string")
            continue
        if item_type not in {list, dict}:
            raise InvalidCommandError(f"{item_path} contains a non-JSON-native value")

        identity = id(item)
        if identity in active_containers:
            raise InvalidCommandError(f"{item_path} contains a cyclic JSON container")
        active_containers.add(identity)
        stack.append((item, item_path, depth, True))

        if item_type is list:
            for index in range(len(item) - 1, -1, -1):
                stack.append((item[index], f"{item_path}[{index}]", depth + 1, False))
            continue

        for key, nested in reversed(tuple(item.items())):
            if type(key) is not str:
                raise InvalidCommandError(f"{item_path} contains a non-string mapping key")
            if _utf8_length(key, f"{item_path}.<key>") > _MAX_JSON_KEY_BYTES:
                raise InvalidCommandError(
                    f"{item_path} contains a mapping key exceeding {_MAX_JSON_KEY_BYTES} UTF-8 bytes"
                )
            stack.append((nested, f"{item_path}.<value>", depth + 1, False))


def _canonical_json_bytes(value: Any, *, maximum: int | None) -> bytes:
    _validate_json_native(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise InvalidCommandError("value cannot be encoded as canonical JSON") from exc
    if maximum is not None and len(encoded) > maximum:
        raise InvalidCommandError("canonical JSON exceeds 256 KiB")
    return encoded


def canonical_json_bytes(value: Any) -> bytes:
    return _canonical_json_bytes(value, maximum=MAX_CANONICAL_JSON_BYTES)


def _json_snapshot(value: Any, *, maximum: int | None) -> Any:
    encoded = _canonical_json_bytes(value, maximum=maximum)
    try:
        return json.loads(encoded)
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise InvalidCommandError("value cannot be copied as canonical JSON") from exc


def _without_generated_payload_fields(value: Any, path: tuple[str, ...] = ()) -> Any:
    if type(value) is list:
        return [
            _without_generated_payload_fields(item, path + (str(index),))
            for index, item in enumerate(value)
        ]
    if type(value) is dict:
        return {
            key: _without_generated_payload_fields(item, path + (key,))
            for key, item in value.items()
            if path + (key,) not in _DIGEST_GENERATED_PAYLOAD_PATHS
        }
    return value


def command_digest(intent: dict[str, Any]) -> str:
    if type(intent) is not dict:
        raise InvalidCommandError("command intent must be a JSON object")
    _validate_json_native(intent)
    unexpected = set(intent).difference(_DIGEST_INTENT_FIELDS)
    if unexpected:
        raise InvalidCommandError(
            "command intent contains unsupported fields: " + ", ".join(sorted(unexpected))
        )
    required = {"workflow_id", "generation", "correlation_id", "causation_id", "payload"}
    missing = required.difference(intent)
    if missing:
        raise InvalidCommandError(
            "command intent is missing required fields: " + ", ".join(sorted(missing))
        )
    payload = intent["payload"]
    if type(payload) is not dict:
        raise InvalidCommandError("command intent payload must be a JSON object")
    _canonical_json_bytes(payload, maximum=MAX_CANONICAL_JSON_BYTES)

    command = intent.get("command")
    if command is not None:
        if type(command) is not dict:
            raise InvalidCommandError("command intent command must be a JSON object")
        unexpected_command = set(command).difference(_DIGEST_COMMAND_FIELDS)
        if unexpected_command:
            raise InvalidCommandError(
                "command intent command contains unsupported fields: "
                + ", ".join(sorted(unexpected_command))
            )
    nested_type = command.get("type") if type(command) is dict else None
    top_level_type = intent.get("type")
    if nested_type is not None and top_level_type is not None and nested_type != top_level_type:
        raise InvalidCommandError("command intent type fields must match")
    command_type = nested_type if nested_type is not None else top_level_type
    if type(command_type) is not str or command_type not in _COMMAND_EVENT_TYPES:
        raise InvalidCommandError("command intent type is unsupported")
    if type(intent["workflow_id"]) is not str or _WORKFLOW_ID_PATTERN.fullmatch(
        intent["workflow_id"]
    ) is None:
        raise InvalidCommandError("command intent workflow_id is invalid")
    if type(intent["generation"]) is not int or not 1 <= intent["generation"] <= _GENERATION_MAX:
        raise InvalidCommandError("command intent generation is invalid")
    if type(intent["correlation_id"]) is not str or not intent["correlation_id"]:
        raise InvalidCommandError("command intent correlation_id is invalid")
    if intent["causation_id"] is not None and (
        type(intent["causation_id"]) is not str or not intent["causation_id"]
    ):
        raise InvalidCommandError("command intent causation_id is invalid")

    payload_snapshot = _json_snapshot(payload, maximum=MAX_CANONICAL_JSON_BYTES)
    normalized = {
        "workflow_id": intent["workflow_id"],
        "generation": intent["generation"],
        "type": command_type,
        "correlation_id": intent["correlation_id"],
        "causation_id": intent["causation_id"],
        "payload": _without_generated_payload_fields(payload_snapshot),
    }
    return hashlib.sha256(_canonical_json_bytes(normalized, maximum=None)).hexdigest()


def event_hash(event: dict[str, Any]) -> str:
    if type(event) is not dict:
        raise InvalidCommandError("event must be a JSON object")
    unsigned = {key: value for key, value in event.items() if key != "event_hash"}
    payload = unsigned.get("payload")
    if payload is not None:
        if type(payload) is not dict:
            raise InvalidCommandError("payload must be a JSON object")
        _canonical_json_bytes(payload, maximum=MAX_CANONICAL_JSON_BYTES)
    return hashlib.sha256(_canonical_json_bytes(unsigned, maximum=None)).hexdigest()


def _location(event: Any) -> tuple[int | None, str | None]:
    if type(event) is not dict:
        return None, None
    revision = event.get("revision")
    event_id = event.get("event_id")
    return (
        revision if type(revision) is int else None,
        event_id
        if type(event_id) is str and _EVENT_ID_PATTERN.fullmatch(event_id) is not None
        else None,
    )


def _raise_event_error(
    error_type: type[InvalidCommandError] | type[CorruptEventLogError],
    event: Any,
    message: str,
) -> None:
    revision, event_id = _location(event)
    raise error_type(message, revision=revision, event_id=event_id)


def _require_event_text(
    event: dict[str, Any],
    field: str,
    *,
    maximum: int,
    error_type: type[InvalidCommandError] | type[CorruptEventLogError],
) -> str:
    value = event.get(field)
    if type(value) is not str or not value:
        _raise_event_error(
            error_type,
            event,
            f"{field} must be a non-empty string of at most {maximum} UTF-8 bytes",
        )
    try:
        _validate_json_native(value, field)
    except InvalidCommandError as exc:
        _raise_event_error(error_type, event, exc.message)
    if _utf8_length(value, field) > maximum:
        _raise_event_error(
            error_type,
            event,
            f"{field} must be a non-empty string of at most {maximum} UTF-8 bytes",
        )
    return value


def _valid_hash(value: Any, *, allow_empty: bool, allow_legacy_head: bool = False) -> bool:
    return (allow_empty and value == "") or (
        type(value) is str
        and (
            _HASH_PATTERN.fullmatch(value) is not None
            or (allow_legacy_head and _LEGACY_HEAD_PATTERN.fullmatch(value) is not None)
        )
    )


def _validate_timestamp(
    event: dict[str, Any],
    error_type: type[InvalidCommandError] | type[CorruptEventLogError],
) -> None:
    value = event.get("timestamp")
    if type(value) is not str or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        _raise_event_error(
            error_type,
            event,
            "timestamp must be UTC ISO-8601 with six fractional digits and +00:00",
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _raise_event_error(error_type, event, "timestamp is not a valid date-time")
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _raise_event_error(error_type, event, "timestamp must use UTC offset +00:00")


def _validate_event_shape(
    event: Any,
    *,
    error_type: type[InvalidCommandError] | type[CorruptEventLogError],
    check_hash: bool,
) -> None:
    if type(event) is not dict:
        _raise_event_error(error_type, event, "event must be a JSON object")
    try:
        _validate_json_native(event)
    except InvalidCommandError as exc:
        _raise_event_error(error_type, event, exc.message)
    if set(event) != _EVENT_FIELDS:
        missing = sorted(_EVENT_FIELDS.difference(event))
        extra = sorted(str(key) for key in set(event).difference(_EVENT_FIELDS))
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        _raise_event_error(error_type, event, "event fields are invalid: " + "; ".join(details))

    if event.get("schema_version") != SCHEMA_VERSION:
        _raise_event_error(error_type, event, "schema_version must be exactly '2.0'")

    event_id = event.get("event_id")
    if type(event_id) is not str or _EVENT_ID_PATTERN.fullmatch(event_id) is None:
        _raise_event_error(
            error_type,
            event,
            "event_id must match evt-<16 lowercase hex characters>",
        )
    workflow_id = event.get("workflow_id")
    if type(workflow_id) is not str or _WORKFLOW_ID_PATTERN.fullmatch(workflow_id) is None:
        _raise_event_error(
            error_type,
            event,
            "workflow_id must match wf-<12 lowercase hex characters>",
        )

    _require_event_text(event, "actor", maximum=128, error_type=error_type)
    event_type = _require_event_text(event, "type", maximum=128, error_type=error_type)
    if not event_type.startswith("event_kernel.") or event_type not in SCHEMA2_EVENT_TYPES:
        _raise_event_error(error_type, event, f"unknown schema 2.0 event type: {event_type}")
    _validate_timestamp(event, error_type)

    revision = event.get("revision")
    if type(revision) is not int or revision < 1:
        _raise_event_error(error_type, event, "revision must be a positive integer")
    generation = event.get("generation")
    if type(generation) is not int or not 1 <= generation <= _GENERATION_MAX:
        _raise_event_error(
            error_type,
            event,
            "generation must be an integer from 1 to 999999",
        )
    _require_event_text(event, "correlation_id", maximum=256, error_type=error_type)

    causation_id = event.get("causation_id")
    if causation_id is not None:
        if type(causation_id) is not str or not causation_id:
            _raise_event_error(
                error_type,
                event,
                "causation_id must be null or a non-empty string of at most 256 UTF-8 bytes",
            )
        try:
            _validate_json_native(causation_id, "causation_id")
        except InvalidCommandError as exc:
            _raise_event_error(error_type, event, exc.message)
        if _utf8_length(causation_id, "causation_id") > 256:
            _raise_event_error(
                error_type,
                event,
                "causation_id must be null or a non-empty string of at most 256 UTF-8 bytes",
            )

    previous_event_hash = event.get("previous_event_hash")
    allow_legacy_head = event_type == "event_kernel.ownership.claimed"
    if not _valid_hash(
        previous_event_hash,
        allow_empty=True,
        allow_legacy_head=allow_legacy_head,
    ):
        _raise_event_error(
            error_type,
            event,
            "previous_event_hash is not a valid schema 2.0 chain head",
        )
    if revision == 1 and previous_event_hash != "":
        _raise_event_error(error_type, event, "revision 1 must have an empty previous_event_hash")
    if revision > 1 and previous_event_hash == "":
        _raise_event_error(error_type, event, "revision after 1 must have a previous_event_hash")

    command = event.get("command")
    if type(command) is not dict or set(command) != _COMMAND_FIELDS:
        _raise_event_error(error_type, event, "command must contain the exact schema 2.0 fields")
    for field, maximum in (("command_id", 256), ("type", 128)):
        value = command.get(field)
        if type(value) is not str or not value:
            _raise_event_error(
                error_type,
                event,
                f"command.{field} must be a non-empty string of at most {maximum} UTF-8 bytes",
            )
        try:
            _validate_json_native(value, f"command.{field}")
        except InvalidCommandError as exc:
            _raise_event_error(error_type, event, exc.message)
        if _utf8_length(value, f"command.{field}") > maximum:
            _raise_event_error(
                error_type,
                event,
                f"command.{field} must be a non-empty string of at most {maximum} UTF-8 bytes",
            )
    if _COMMAND_EVENT_TYPES.get(command.get("type")) != event_type:
        _raise_event_error(
            error_type,
            event,
            "command/event type pair is invalid",
        )
    if not _valid_hash(command.get("digest"), allow_empty=False):
        _raise_event_error(
            error_type,
            event,
            "command.digest must be 64 lowercase hex characters",
        )
    expected_revision = command.get("expected_revision")
    if type(expected_revision) is not int or expected_revision < 0:
        _raise_event_error(
            error_type,
            event,
            "command.expected_revision must be a non-negative integer",
        )
    if expected_revision != revision - 1:
        _raise_event_error(
            error_type,
            event,
            "command.expected_revision must equal event revision minus one",
        )
    expected_event_hash = command.get("expected_event_hash")
    if not _valid_hash(
        expected_event_hash,
        allow_empty=True,
        allow_legacy_head=allow_legacy_head,
    ):
        _raise_event_error(
            error_type,
            event,
            "command.expected_event_hash is not a valid schema 2.0 chain head",
        )
    if expected_event_hash != previous_event_hash:
        _raise_event_error(
            error_type,
            event,
            "command.expected_event_hash must equal previous_event_hash",
        )

    if type(event.get("payload")) is not dict:
        _raise_event_error(error_type, event, "payload must be a JSON object")
    try:
        _canonical_json_bytes(event["payload"], maximum=MAX_CANONICAL_JSON_BYTES)
    except InvalidCommandError as exc:
        _raise_event_error(error_type, event, exc.message)

    supplied_hash = event.get("event_hash")
    if not _valid_hash(supplied_hash, allow_empty=False):
        _raise_event_error(
            error_type,
            event,
            "event_hash must be 64 lowercase hex characters",
        )
    if check_hash:
        try:
            calculated_hash = event_hash(event)
        except InvalidCommandError as exc:
            _raise_event_error(error_type, event, exc.message)
        if supplied_hash != calculated_hash:
            _raise_event_error(error_type, event, "event_hash does not match event content")


def build_event(
    *,
    workflow_id: str,
    actor: str,
    event_type: str,
    revision: int,
    previous_event_hash: str,
    generation: int,
    correlation_id: str,
    causation_id: str | None,
    command: dict[str, Any],
    payload: dict[str, Any],
    event_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    command_snapshot = _json_snapshot(command, maximum=MAX_CANONICAL_JSON_BYTES)
    payload_snapshot = _json_snapshot(payload, maximum=MAX_CANONICAL_JSON_BYTES)
    if event_id is None:
        event_id = make_event_id()
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    event = {
        "event_id": event_id,
        "schema_version": SCHEMA_VERSION,
        "workflow_id": workflow_id,
        "actor": actor,
        "type": event_type,
        "timestamp": timestamp,
        "revision": revision,
        "previous_event_hash": previous_event_hash,
        "generation": generation,
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "command": command_snapshot,
        "payload": payload_snapshot,
        "event_hash": "0" * 64,
    }
    _validate_event_shape(event, error_type=InvalidCommandError, check_hash=False)
    event["event_hash"] = event_hash(event)
    return event


def _is_future_schema(match: re.Match[str]) -> bool:
    major, minor = match.groups()
    if len(major) > 1 or major > "2":
        return True
    return major == "2" and minor != "0"


def validate_event(event: Any) -> None:
    if type(event) is not dict:
        _raise_event_error(CorruptEventLogError, event, "event must be a JSON object")
    try:
        _validate_json_native(event)
    except InvalidCommandError as exc:
        _raise_event_error(CorruptEventLogError, event, exc.message)
    schema_version = event.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        if type(schema_version) is str and len(schema_version) <= _MAX_SCHEMA_VERSION_LENGTH:
            match = _SCHEMA_PATTERN.fullmatch(schema_version)
            if match is not None and _is_future_schema(match):
                revision, event_id = _location(event)
                raise UnsupportedFutureSchemaError(
                    f"unsupported future schema version: {schema_version}",
                    revision=revision,
                    event_id=event_id,
                )
        _raise_event_error(
            CorruptEventLogError,
            event,
            "schema_version must be exactly '2.0'",
        )

    event_type = event.get("type")
    if type(event_type) is str and event_type not in SCHEMA2_EVENT_TYPES:
        revision, event_id = _location(event)
        raise UnknownEventTypeError(
            f"unknown schema 2.0 event type: {event_type}",
            revision=revision,
            event_id=event_id,
        )
    _validate_event_shape(event, error_type=CorruptEventLogError, check_hash=True)


def canonical_event_line(event: dict[str, Any]) -> bytes:
    validate_event(event)
    return _canonical_json_bytes(event, maximum=None) + b"\n"


def _require_counter(name: str, value: Any) -> int:
    if type(value) is not int or not 1 <= value <= _GENERATION_MAX:
        raise InvalidCommandError(f"{name} must be an integer from 1 to 999999")
    return value


def _require_text(name: str, value: Any, *, maximum: int) -> str:
    if type(value) is not str or not value:
        raise InvalidCommandError(
            f"{name} must be a non-empty string of at most {maximum} UTF-8 bytes"
        )
    _validate_json_native(value, name)
    if _utf8_length(value, name) > maximum:
        raise InvalidCommandError(
            f"{name} must be a non-empty string of at most {maximum} UTF-8 bytes"
        )
    return value


def make_action_id(
    *,
    generation: int,
    tool: str,
    target: str,
    arguments: dict[str, Any],
    kind: str,
) -> str:
    generation = _require_counter("generation", generation)
    _require_text("tool", tool, maximum=128)
    _require_text("target", target, maximum=4096)
    _require_text("kind", kind, maximum=128)
    if type(arguments) is not dict:
        raise InvalidCommandError("arguments must be a JSON object")
    identity = {
        "generation": generation,
        "tool": tool,
        "target": target,
        "arguments": arguments,
        "kind": kind,
    }
    action_key = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    return f"act-g{generation:06d}-{action_key[:16]}"


def make_attempt_id(action_id: str, attempt_no: int) -> str:
    if type(action_id) is not str:
        raise InvalidCommandError("action_id must be a valid action identifier")
    match = _ACTION_ID_PATTERN.fullmatch(action_id)
    if match is None or int(match.group(1)) < 1:
        raise InvalidCommandError("action_id must be a valid action identifier")
    attempt_no = _require_counter("attempt_no", attempt_no)
    return f"att-{action_id[4:]}-{attempt_no:06d}"


def _random_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def make_event_id() -> str:
    return _random_id("evt")


def make_checkpoint_id() -> str:
    return _random_id("cp")


def make_process_id() -> str:
    return _random_id("proc")


def make_outbox_id(
    *,
    workflow_id: str,
    generation: int,
    projector: str,
    dedupe_key: str,
    payload: dict[str, Any],
) -> str:
    if type(workflow_id) is not str or _WORKFLOW_ID_PATTERN.fullmatch(workflow_id) is None:
        raise InvalidCommandError("workflow_id must match wf-<12 lowercase hex characters>")
    generation = _require_counter("generation", generation)
    _require_text("projector", projector, maximum=128)
    _require_text("dedupe_key", dedupe_key, maximum=512)
    if type(payload) is not dict:
        raise InvalidCommandError("payload must be a JSON object")
    payload_digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    identity = {
        "workflow_id": workflow_id,
        "generation": generation,
        "projector": projector,
        "dedupe_key": dedupe_key,
        "payload_digest": payload_digest,
    }
    return "out-" + hashlib.sha256(canonical_json_bytes(identity)).hexdigest()


__all__ = [
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
