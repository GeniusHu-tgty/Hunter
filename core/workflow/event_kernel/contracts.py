from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import math
import re
from typing import TypeAlias, TypeVar, cast

from .errors import (
    EvidenceAttestationError,
    InvalidCommandError,
    SensitiveOutputRejectedError,
)


_MAX_ID = 256
_MAX_SHORT_TEXT = 128
_MAX_REASON = 512
_MAX_TARGET = 4096
_MAX_EXCERPT_BYTES = 4096
_MAX_COMMAND_JSON_BYTES = 256 * 1024
_MAX_OUTBOX_JSON_BYTES = 16 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_KEY_BYTES = 256
_MAX_JSON_STRING_BYTES = 256 * 1024
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_ACTION_ID_RE = re.compile(r"act-g([0-9]{6})-([0-9a-f]{16})")
_ATTEMPT_ID_RE = re.compile(r"att-g([0-9]{6})-([0-9a-f]{16})-([0-9]{6})")
_WORKFLOW_ID_RE = re.compile(r"wf-[0-9a-f]{12}")
_EVENT_ID_RE = re.compile(r"evt-(?:[0-9a-f]{12}|[0-9a-f]{16})")
_LEGACY_HEAD_RE = re.compile(r"legacy-sha256:[0-9a-f]{64}")
_PROCESS_ID_RE = re.compile(r"proc-[0-9a-f]{16}")
_OUTBOX_ID_RE = re.compile(r"out-[0-9a-f]{64}")
_CHECKPOINT_ID_RE = re.compile(r"cp-[0-9a-f]{16,64}")
_KNOWN_SENSITIVE_MARKERS = (
    re.compile(r"authorization\s*:\s*bearer\s+\S+", re.IGNORECASE),
    re.compile(r"cookie\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"password\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(
        r"(?:api[_-]?key|secret[_-]?key|(?:(?:access|refresh|auth|id)[_-]?)?token)"
        r"\s*[=:]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
)


JsonScalar: TypeAlias = None | bool | int | float | str


@dataclass(frozen=True, slots=True)
class FrozenJsonArray:
    values: tuple[FrozenJsonValue, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self.values) is not tuple:
            raise InvalidCommandError("FrozenJsonArray values must be a tuple")
        if any(not _is_frozen_json_value(value) for value in self.values):
            raise InvalidCommandError("FrozenJsonArray contains an invalid value")


@dataclass(frozen=True, slots=True)
class FrozenJsonObject:
    items: tuple[tuple[str, FrozenJsonValue], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self.items) is not tuple:
            raise InvalidCommandError("FrozenJsonObject items must be a tuple")
        keys: list[str] = []
        for item in self.items:
            if type(item) is not tuple or len(item) != 2 or type(item[0]) is not str:
                raise InvalidCommandError("FrozenJsonObject items must be string/value pairs")
            if not _is_frozen_json_value(item[1]):
                raise InvalidCommandError("FrozenJsonObject contains an invalid value")
            if _utf8_size("FrozenJsonObject key", item[0]) > _MAX_JSON_KEY_BYTES:
                raise InvalidCommandError("FrozenJsonObject contains an oversized key")
            keys.append(item[0])
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise InvalidCommandError("FrozenJsonObject keys must be sorted and unique")


FrozenJsonValue: TypeAlias = JsonScalar | FrozenJsonArray | FrozenJsonObject
EnumT = TypeVar("EnumT", bound=Enum)
RecordT = TypeVar("RecordT")


class OwnershipState(str, Enum):
    UNCLAIMED_LEGACY = "unclaimed_legacy"
    EVENT_KERNEL_OWNED = "event_kernel_owned"


class ActionState(str, Enum):
    PROPOSED = "proposed"
    DEFERRED = "deferred"
    BLOCKED = "blocked"
    RUNNING = "running"
    RETRYABLE = "retryable"
    COMPLETED = "completed"


class AttemptState(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class VerdictStatus(str, Enum):
    LIKELY = "likely"
    VERIFIED = "verified"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class ProcessState(str, Enum):
    STARTED = "started"
    TERMINATED = "terminated"


class ProcessStream(str, Enum):
    STDOUT = "stdout"
    STDERR = "stderr"


class OutboxState(str, Enum):
    ENQUEUED = "enqueued"
    APPLIED = "applied"
    FAILED = "failed"


class EvidenceOrigin(str, Enum):
    LEGACY = "legacy"
    SCHEMA_2 = "schema_2"


class HashMode(str, Enum):
    EMPTY = "empty"
    HASHED = "hashed"
    LEGACY_UNBOUND = "legacy_unbound"


class ReplayIssueKind(str, Enum):
    INCOMPLETE_FINAL_LINE = "incomplete_final_line"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_JSON = "invalid_json"
    CORRUPT_CHAIN = "corrupt_chain"
    UNKNOWN_EVENT = "unknown_event"
    FUTURE_SCHEMA = "future_schema"
    DUPLICATE_EVENT = "duplicate_event"
    DUPLICATE_COMMAND = "duplicate_command"
    COMMAND_CONFLICT = "command_conflict"
    OWNERSHIP_CLAIM_REQUIRED = "ownership_claim_required"
    MIXED_WRITER = "mixed_writer"
    ILLEGAL_TRANSITION = "illegal_transition"


class CommandType(str, Enum):
    CLAIM_WORKFLOW = "claim_workflow"
    PROPOSE_ACTION = "propose_action"
    MERGE_ACTION = "merge_action"
    DEFER_ACTION = "defer_action"
    BLOCK_ACTION = "block_action"
    START_ATTEMPT = "start_attempt"
    COMPLETE_ATTEMPT = "complete_attempt"
    BLOCK_ATTEMPT = "block_attempt"
    CANCEL_ATTEMPT = "cancel_attempt"
    ATTEST_EVIDENCE = "attest_evidence"
    RECORD_VERDICT = "record_verdict"
    START_PROCESS = "start_process"
    RECORD_PROCESS_OUTPUT = "record_process_output"
    TERMINATE_PROCESS = "terminate_process"
    ENQUEUE_MEMORY = "enqueue_memory"
    MARK_MEMORY_APPLIED = "mark_memory_applied"
    MARK_MEMORY_FAILED = "mark_memory_failed"
    CREATE_CHECKPOINT = "create_checkpoint"
    RECOVER_CHECKPOINT = "recover_checkpoint"


class EventType(str, Enum):
    OWNERSHIP_CLAIMED = "event_kernel.ownership.claimed"
    ACTION_PROPOSED = "event_kernel.action.proposed"
    ACTION_MERGED = "event_kernel.action.merged"
    ACTION_DEFERRED = "event_kernel.action.deferred"
    ACTION_BLOCKED = "event_kernel.action.blocked"
    ATTEMPT_STARTED = "event_kernel.attempt.started"
    ATTEMPT_COMPLETED = "event_kernel.attempt.completed"
    ATTEMPT_BLOCKED = "event_kernel.attempt.blocked"
    ATTEMPT_CANCELLED = "event_kernel.attempt.cancelled"
    EVIDENCE_ATTESTED = "event_kernel.evidence.attested"
    VERDICT_RECORDED = "event_kernel.verdict.recorded"
    PROCESS_STARTED = "event_kernel.process.started"
    PROCESS_OUTPUT_RECORDED = "event_kernel.process.output_recorded"
    PROCESS_TERMINATED = "event_kernel.process.terminated"
    MEMORY_ENQUEUED = "event_kernel.memory.enqueued"
    MEMORY_APPLIED = "event_kernel.memory.applied"
    MEMORY_FAILED = "event_kernel.memory.failed"
    CHECKPOINT_CREATED = "event_kernel.checkpoint.created"
    RECOVERY_PERFORMED = "event_kernel.recovery.performed"


def _utf8_size(name: str, value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise InvalidCommandError(f"{name} contains invalid Unicode") from exc


def _is_frozen_json_value(value: object) -> bool:
    if value is None or type(value) in {bool, int, str}:
        return type(value) is not str or _utf8_size("JSON string", value) <= _MAX_JSON_STRING_BYTES
    if type(value) is float:
        return math.isfinite(value)
    return isinstance(value, (FrozenJsonArray, FrozenJsonObject))


def _freeze_json_value(
    name: str,
    value: object,
    *,
    depth: int,
    active_containers: set[int],
) -> FrozenJsonValue:
    if depth > _MAX_JSON_DEPTH:
        raise InvalidCommandError(f"{name} exceeds maximum JSON nesting depth")
    if isinstance(value, (FrozenJsonArray, FrozenJsonObject)):
        return value
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise InvalidCommandError(f"{name} contains a non-finite float")
        return value
    if type(value) is str:
        if _utf8_size(name, value) > _MAX_JSON_STRING_BYTES:
            raise InvalidCommandError(f"{name} contains an oversized JSON string")
        return value
    if type(value) not in {dict, list}:
        raise InvalidCommandError(f"{name} contains a non-JSON-native value")

    identity = id(value)
    if identity in active_containers:
        raise InvalidCommandError(f"{name} contains a cyclic JSON container")
    active_containers.add(identity)
    try:
        if type(value) is list:
            return FrozenJsonArray(
                tuple(
                    _freeze_json_value(
                        f"{name}[{index}]",
                        nested,
                        depth=depth + 1,
                        active_containers=active_containers,
                    )
                    for index, nested in enumerate(value)
                )
            )

        if any(type(key) is not str for key in value):
            raise InvalidCommandError(f"{name} contains a non-string mapping key")
        pairs: list[tuple[str, FrozenJsonValue]] = []
        for key in sorted(value):
            if _utf8_size(f"{name} key", key) > _MAX_JSON_KEY_BYTES:
                raise InvalidCommandError(f"{name} contains an oversized mapping key")
            pairs.append(
                (
                    key,
                    _freeze_json_value(
                        f"{name}.{key}",
                        value[key],
                        depth=depth + 1,
                        active_containers=active_containers,
                    ),
                )
            )
        return FrozenJsonObject(tuple(pairs))
    finally:
        active_containers.remove(identity)


def _thaw_json_value(value: FrozenJsonValue) -> object:
    if isinstance(value, FrozenJsonArray):
        return [_thaw_json_value(item) for item in value.values]
    if isinstance(value, FrozenJsonObject):
        return {key: _thaw_json_value(item) for key, item in value.items}
    return value


def _validate_frozen_json_depth(value: FrozenJsonValue, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise InvalidCommandError("frozen JSON exceeds maximum nesting depth")
    if isinstance(value, FrozenJsonArray):
        for nested in value.values:
            _validate_frozen_json_depth(nested, depth=depth + 1)
    elif isinstance(value, FrozenJsonObject):
        for _key, nested in value.items:
            _validate_frozen_json_depth(nested, depth=depth + 1)


def _canonical_frozen_json_bytes(
    value: FrozenJsonObject,
    *,
    maximum_bytes: int = _MAX_OUTBOX_JSON_BYTES,
) -> bytes:
    _validate_frozen_json_depth(value)
    try:
        encoded = json.dumps(
            _thaw_json_value(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise InvalidCommandError("payload cannot be encoded as canonical JSON") from exc
    if len(encoded) > maximum_bytes:
        raise InvalidCommandError(
            f"canonical JSON payload exceeds {maximum_bytes} UTF-8 bytes"
        )
    return encoded


def _freeze_json_object(
    name: str,
    value: object,
    *,
    maximum_bytes: int = _MAX_OUTBOX_JSON_BYTES,
) -> FrozenJsonObject:
    if isinstance(value, FrozenJsonObject):
        frozen = value
    else:
        if type(value) is not dict:
            raise InvalidCommandError(f"{name} must be a JSON object")
        frozen_value = _freeze_json_value(
            name,
            value,
            depth=0,
            active_containers=set(),
        )
        if not isinstance(frozen_value, FrozenJsonObject):
            raise InvalidCommandError(f"{name} must be a JSON object")
        frozen = frozen_value
    _canonical_frozen_json_bytes(frozen, maximum_bytes=maximum_bytes)
    return frozen


def _require_text(
    name: str,
    value: object,
    *,
    maximum: int,
    allow_empty: bool = False,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> str:
    if type(value) is not str:
        raise error_type(f"{name} must be a string")
    if not allow_empty and not value:
        raise error_type(f"{name} must not be empty")
    if len(value) > maximum:
        raise error_type(f"{name} must be at most {maximum} characters")
    return value


def _require_optional_text(
    name: str,
    value: object,
    *,
    maximum: int,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> str | None:
    if value is None:
        return None
    return _require_text(name, value, maximum=maximum, error_type=error_type)


def _require_int(
    name: str,
    value: object,
    *,
    minimum: int = 0,
    maximum: int | None = None,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        boundary = f" from {minimum}" if maximum is None else f" from {minimum} to {maximum}"
        raise error_type(f"{name} must be an integer{boundary}")
    return value


def _require_bool(
    name: str,
    value: object,
    *,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> bool:
    if type(value) is not bool:
        raise error_type(f"{name} must be a boolean")
    return value


def _require_sha256(
    name: str,
    value: object,
    *,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> str:
    value = _require_text(name, value, maximum=64, error_type=error_type)
    if _SHA256_RE.fullmatch(value) is None:
        raise error_type(f"{name} must be a 64-character SHA-256 hex digest")
    return value.lower()


def _require_digest(
    name: str,
    value: object,
    *,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> str:
    return _require_text(name, value, maximum=256, error_type=error_type)


def _require_string_tuple(
    name: str,
    value: object,
    *,
    duplicate_free: bool = False,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise error_type(f"{name} must be an ordered collection of strings")
    normalized = tuple(value)
    for item in normalized:
        _require_text(f"{name} item", item, maximum=_MAX_ID, error_type=error_type)
    if duplicate_free and len(set(normalized)) != len(normalized):
        raise error_type(f"{name} must not contain duplicates")
    return normalized


def _coerce_enum(
    name: str,
    value: object,
    enum_type: type[EnumT],
    *,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> EnumT:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise error_type(f"{name} has an unsupported value") from exc


def _require_pattern(
    name: str,
    value: object,
    pattern: re.Pattern[str],
    *,
    error_type: type[InvalidCommandError] = InvalidCommandError,
) -> str:
    normalized = _require_text(name, value, maximum=_MAX_ID, error_type=error_type)
    if pattern.fullmatch(normalized) is None:
        raise error_type(f"{name} has an invalid canonical form")
    return normalized


def _require_optional_pattern(
    name: str,
    value: object,
    pattern: re.Pattern[str],
) -> str | None:
    if value is None:
        return None
    return _require_pattern(name, value, pattern)


def _validate_generated_result_ids(
    event_type: EventType,
    *,
    action_id: str | None,
    attempt_id: str | None,
    process_id: str | None,
    outbox_id: str | None,
    checkpoint_id: str | None,
) -> None:
    values = {
        "action_id": action_id,
        "attempt_id": attempt_id,
        "process_id": process_id,
        "outbox_id": outbox_id,
        "checkpoint_id": checkpoint_id,
    }
    expected_by_event = {
        EventType.ACTION_PROPOSED: "action_id",
        EventType.ATTEMPT_STARTED: "attempt_id",
        EventType.PROCESS_STARTED: "process_id",
        EventType.MEMORY_ENQUEUED: "outbox_id",
        EventType.CHECKPOINT_CREATED: "checkpoint_id",
    }
    expected = expected_by_event.get(event_type)
    present = {name for name, value in values.items() if value is not None}
    if present != ({expected} if expected is not None else set()):
        raise InvalidCommandError("generated result identity does not match event_type")


def _require_record_tuple(
    name: str,
    value: object,
    record_type: type[RecordT],
) -> tuple[RecordT, ...]:
    if not isinstance(value, (tuple, list)):
        raise InvalidCommandError(f"{name} must be an ordered collection")
    normalized = tuple(value)
    if any(not isinstance(item, record_type) for item in normalized):
        raise InvalidCommandError(f"{name} contains an invalid record")
    return cast(tuple[RecordT, ...], normalized)


def _require_unique_record_ids(
    name: str,
    records: tuple[object, ...],
    attribute: str,
) -> None:
    identifiers = tuple(getattr(record, attribute) for record in records)
    if len(set(identifiers)) != len(identifiers):
        raise InvalidCommandError(f"{name} must not contain duplicate identifiers")


def _validate_absolute_counters(
    *,
    stdout_bytes_total: int,
    stderr_bytes_total: int,
    combined_bytes_total: int,
    stdout_omitted_bytes_total: int,
    stderr_omitted_bytes_total: int,
    combined_omitted_bytes_total: int,
    truncated: bool | None = None,
) -> None:
    for name, value in (
        ("stdout_bytes_total", stdout_bytes_total),
        ("stderr_bytes_total", stderr_bytes_total),
        ("combined_bytes_total", combined_bytes_total),
        ("stdout_omitted_bytes_total", stdout_omitted_bytes_total),
        ("stderr_omitted_bytes_total", stderr_omitted_bytes_total),
        ("combined_omitted_bytes_total", combined_omitted_bytes_total),
    ):
        _require_int(name, value)
    if combined_bytes_total != stdout_bytes_total + stderr_bytes_total:
        raise InvalidCommandError(
            "combined_bytes_total must equal stdout_bytes_total plus stderr_bytes_total"
        )
    if combined_omitted_bytes_total != (
        stdout_omitted_bytes_total + stderr_omitted_bytes_total
    ):
        raise InvalidCommandError(
            "combined_omitted_bytes_total must equal the stdout and stderr omitted totals"
        )
    if (
        stdout_omitted_bytes_total > stdout_bytes_total
        or stderr_omitted_bytes_total > stderr_bytes_total
        or combined_omitted_bytes_total > combined_bytes_total
    ):
        raise InvalidCommandError("omitted byte totals cannot exceed byte totals")
    if truncated is not None:
        _require_bool("truncated", truncated)
        if truncated != (combined_omitted_bytes_total > 0):
            raise InvalidCommandError("truncated must exactly reflect omitted bytes")


@dataclass(frozen=True, slots=True)
class CommandMeta:
    command_id: str
    expected_revision: int
    expected_event_hash: str
    generation: int
    correlation_id: str
    causation_id: str | None = None
    actor: str = "hunter_tools"

    def __post_init__(self) -> None:
        _require_text("command_id", self.command_id, maximum=_MAX_ID)
        _require_int("expected_revision", self.expected_revision)
        _require_text(
            "expected_event_hash",
            self.expected_event_hash,
            maximum=128,
            allow_empty=True,
        )
        if self.expected_event_hash:
            object.__setattr__(
                self,
                "expected_event_hash",
                _require_sha256("expected_event_hash", self.expected_event_hash),
            )
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_text("correlation_id", self.correlation_id, maximum=_MAX_ID)
        _require_optional_text("causation_id", self.causation_id, maximum=_MAX_ID)
        _require_text("actor", self.actor, maximum=_MAX_SHORT_TEXT)


@dataclass(frozen=True, slots=True)
class WorkflowOwnershipClaim:
    cutover_id: str
    owner_version: str
    legacy_gate_digest: str

    def __post_init__(self) -> None:
        _require_text("cutover_id", self.cutover_id, maximum=_MAX_ID)
        _require_text("owner_version", self.owner_version, maximum=_MAX_SHORT_TEXT)
        _require_digest("legacy_gate_digest", self.legacy_gate_digest)


@dataclass(frozen=True, slots=True)
class ActionProposal:
    tool: str
    target: str
    kind: str
    arguments: FrozenJsonObject = field(default_factory=FrozenJsonObject)
    sources: tuple[str, ...] = field(default_factory=tuple)
    strategy_ids: tuple[str, ...] = field(default_factory=tuple)
    labels: tuple[str, ...] = field(default_factory=tuple)
    expected_evidence: tuple[str, ...] = field(default_factory=tuple)
    priority: str = "P2"

    def __post_init__(self) -> None:
        _require_text("tool", self.tool, maximum=_MAX_SHORT_TEXT)
        _require_text("target", self.target, maximum=_MAX_TARGET)
        _require_text("kind", self.kind, maximum=_MAX_SHORT_TEXT)
        object.__setattr__(
            self,
            "arguments",
            _freeze_json_object(
                "arguments",
                self.arguments,
                maximum_bytes=_MAX_COMMAND_JSON_BYTES,
            ),
        )
        object.__setattr__(self, "sources", _require_string_tuple("sources", self.sources))
        object.__setattr__(
            self,
            "strategy_ids",
            _require_string_tuple("strategy_ids", self.strategy_ids),
        )
        object.__setattr__(self, "labels", _require_string_tuple("labels", self.labels))
        object.__setattr__(
            self,
            "expected_evidence",
            _require_string_tuple("expected_evidence", self.expected_evidence),
        )
        if self.priority not in {"P0", "P1", "P2"}:
            raise InvalidCommandError("priority must be P0, P1, or P2")


@dataclass(frozen=True, slots=True)
class ActionMerge:
    action_id: str
    sources: tuple[str, ...] = field(default_factory=tuple)
    strategy_ids: tuple[str, ...] = field(default_factory=tuple)
    labels: tuple[str, ...] = field(default_factory=tuple)
    expected_evidence: tuple[str, ...] = field(default_factory=tuple)
    priority: str | None = None

    def __post_init__(self) -> None:
        _require_text("action_id", self.action_id, maximum=_MAX_ID)
        object.__setattr__(self, "sources", _require_string_tuple("sources", self.sources))
        object.__setattr__(
            self,
            "strategy_ids",
            _require_string_tuple("strategy_ids", self.strategy_ids),
        )
        object.__setattr__(self, "labels", _require_string_tuple("labels", self.labels))
        object.__setattr__(
            self,
            "expected_evidence",
            _require_string_tuple("expected_evidence", self.expected_evidence),
        )
        if self.priority is not None and self.priority not in {"P0", "P1", "P2"}:
            raise InvalidCommandError("priority must be P0, P1, P2, or None")


@dataclass(frozen=True, slots=True)
class ActionDecision:
    action_id: str
    reason: str

    def __post_init__(self) -> None:
        _require_text("action_id", self.action_id, maximum=_MAX_ID)
        _require_text("reason", self.reason, maximum=_MAX_REASON)


@dataclass(frozen=True, slots=True)
class AttemptStart:
    action_id: str
    executor: str
    budget_class: str

    def __post_init__(self) -> None:
        _require_text("action_id", self.action_id, maximum=_MAX_ID)
        _require_text("executor", self.executor, maximum=_MAX_SHORT_TEXT)
        _require_text("budget_class", self.budget_class, maximum=_MAX_SHORT_TEXT)


@dataclass(frozen=True, slots=True)
class AttemptComplete:
    attempt_id: str
    result_code: str
    result_digest: str

    def __post_init__(self) -> None:
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        _require_text("result_code", self.result_code, maximum=_MAX_SHORT_TEXT)
        _require_digest("result_digest", self.result_digest)


@dataclass(frozen=True, slots=True)
class AttemptBlock:
    attempt_id: str
    reason: str

    def __post_init__(self) -> None:
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        _require_text("reason", self.reason, maximum=_MAX_REASON)


@dataclass(frozen=True, slots=True)
class AttemptCancel:
    attempt_id: str
    reason: str

    def __post_init__(self) -> None:
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        _require_text("reason", self.reason, maximum=_MAX_REASON)


@dataclass(frozen=True, slots=True)
class LogicalActionRecord:
    action_id: str
    action_key: str
    generation: int
    tool: str
    target: str
    arguments: FrozenJsonObject
    kind: str
    sources: tuple[str, ...] = field(default_factory=tuple)
    strategy_ids: tuple[str, ...] = field(default_factory=tuple)
    labels: tuple[str, ...] = field(default_factory=tuple)
    expected_evidence: tuple[str, ...] = field(default_factory=tuple)
    priority: str = "P2"
    state: ActionState = ActionState.PROPOSED
    attempt_ids: tuple[str, ...] = field(default_factory=tuple)
    active_attempt_id: str | None = None

    def __post_init__(self) -> None:
        match = _ACTION_ID_RE.fullmatch(self.action_id)
        if match is None:
            raise InvalidCommandError("action_id has an invalid canonical form")
        _require_sha256("action_key", self.action_key)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        if int(match.group(1)) != self.generation or match.group(2) != self.action_key[:16]:
            raise InvalidCommandError("action_id must bind generation and action_key")
        _require_text("tool", self.tool, maximum=_MAX_SHORT_TEXT)
        _require_text("target", self.target, maximum=_MAX_TARGET)
        _require_text("kind", self.kind, maximum=_MAX_SHORT_TEXT)
        object.__setattr__(
            self,
            "arguments",
            _freeze_json_object(
                "arguments",
                self.arguments,
                maximum_bytes=_MAX_COMMAND_JSON_BYTES,
            ),
        )
        for name in ("sources", "strategy_ids", "labels", "expected_evidence"):
            object.__setattr__(self, name, _require_string_tuple(name, getattr(self, name)))
        if self.priority not in {"P0", "P1", "P2"}:
            raise InvalidCommandError("priority must be P0, P1, or P2")
        object.__setattr__(self, "state", _coerce_enum("state", self.state, ActionState))
        attempts = _require_string_tuple(
            "attempt_ids", self.attempt_ids, duplicate_free=True
        )
        for attempt_id in attempts:
            if _ATTEMPT_ID_RE.fullmatch(attempt_id) is None:
                raise InvalidCommandError("attempt_ids contains an invalid canonical ID")
        object.__setattr__(self, "attempt_ids", attempts)
        _require_optional_text("active_attempt_id", self.active_attempt_id, maximum=_MAX_ID)
        if self.active_attempt_id is not None and self.active_attempt_id not in attempts:
            raise InvalidCommandError("active_attempt_id must appear in attempt_ids")
        if self.state is ActionState.RUNNING and self.active_attempt_id is None:
            raise InvalidCommandError("running action requires active_attempt_id")
        if self.state is not ActionState.RUNNING and self.active_attempt_id is not None:
            raise InvalidCommandError("only a running action may have active_attempt_id")


@dataclass(frozen=True, slots=True)
class ExecutionAttemptRecord:
    attempt_id: str
    action_id: str
    generation: int
    attempt_no: int
    executor: str
    budget_class: str
    state: AttemptState
    process_ids: tuple[str, ...] = field(default_factory=tuple)
    result_code: str | None = None
    result_digest: str | None = None
    terminal_reason: str | None = None

    def __post_init__(self) -> None:
        attempt_match = _ATTEMPT_ID_RE.fullmatch(self.attempt_id)
        action_match = _ACTION_ID_RE.fullmatch(self.action_id)
        if attempt_match is None or action_match is None:
            raise InvalidCommandError("attempt_id or action_id has an invalid canonical form")
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_int("attempt_no", self.attempt_no, minimum=1)
        if (
            attempt_match.group(1) != action_match.group(1)
            or attempt_match.group(2) != action_match.group(2)
            or int(attempt_match.group(1)) != self.generation
            or int(attempt_match.group(3)) != self.attempt_no
        ):
            raise InvalidCommandError("attempt_id must bind action_id, generation, and attempt_no")
        _require_text("executor", self.executor, maximum=_MAX_SHORT_TEXT)
        _require_text("budget_class", self.budget_class, maximum=_MAX_SHORT_TEXT)
        state = _coerce_enum("state", self.state, AttemptState)
        object.__setattr__(self, "state", state)
        object.__setattr__(
            self,
            "process_ids",
            _require_string_tuple("process_ids", self.process_ids, duplicate_free=True),
        )
        _require_optional_text("result_code", self.result_code, maximum=_MAX_SHORT_TEXT)
        if self.result_digest is not None:
            _require_digest("result_digest", self.result_digest)
        _require_optional_text("terminal_reason", self.terminal_reason, maximum=_MAX_REASON)
        if state is AttemptState.STARTED and any(
            value is not None for value in (self.result_code, self.result_digest, self.terminal_reason)
        ):
            raise InvalidCommandError("started attempt cannot contain terminal metadata")
        if state is AttemptState.COMPLETED and (
            self.result_code is None or self.result_digest is None or self.terminal_reason is not None
        ):
            raise InvalidCommandError("completed attempt requires result metadata only")
        if state in {AttemptState.BLOCKED, AttemptState.CANCELLED} and (
            self.terminal_reason is None
            or self.result_code is not None
            or self.result_digest is not None
        ):
            raise InvalidCommandError("blocked or cancelled attempt requires terminal_reason only")


@dataclass(frozen=True, slots=True)
class VerificationObservation:
    result_code: str
    procedure_digest: str
    observation_digest: str

    def __post_init__(self) -> None:
        _require_text(
            "result_code",
            self.result_code,
            maximum=_MAX_SHORT_TEXT,
            error_type=EvidenceAttestationError,
        )
        _require_digest(
            "procedure_digest",
            self.procedure_digest,
            error_type=EvidenceAttestationError,
        )
        _require_digest(
            "observation_digest",
            self.observation_digest,
            error_type=EvidenceAttestationError,
        )


@dataclass(frozen=True, slots=True)
class ReproductionObservation:
    result_code: str
    procedure_digest: str
    observation_digest: str
    run_count: int
    success_count: int

    def __post_init__(self) -> None:
        error = EvidenceAttestationError
        _require_text("result_code", self.result_code, maximum=_MAX_SHORT_TEXT, error_type=error)
        _require_digest("procedure_digest", self.procedure_digest, error_type=error)
        _require_digest("observation_digest", self.observation_digest, error_type=error)
        _require_int("run_count", self.run_count, minimum=1, error_type=error)
        _require_int("success_count", self.success_count, minimum=1, error_type=error)
        if self.success_count > self.run_count:
            raise error("success_count must not exceed run_count")


@dataclass(frozen=True, slots=True)
class EvidenceAttestation:
    evidence_id: str
    evidence_sha256: str
    source_ref_digest: str
    action_id: str
    attempt_id: str
    generation: int
    verifier_id: str
    verifier_version: str
    verification_policy_digest: str
    baseline: VerificationObservation
    control: VerificationObservation
    reproduction: ReproductionObservation

    def __post_init__(self) -> None:
        error = EvidenceAttestationError
        _require_text("evidence_id", self.evidence_id, maximum=_MAX_ID, error_type=error)
        normalized_hash = _require_sha256(
            "evidence_sha256",
            self.evidence_sha256,
            error_type=error,
        )
        object.__setattr__(self, "evidence_sha256", normalized_hash)
        _require_digest("source_ref_digest", self.source_ref_digest, error_type=error)
        _require_text("action_id", self.action_id, maximum=_MAX_ID, error_type=error)
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID, error_type=error)
        _require_int(
            "generation",
            self.generation,
            minimum=1,
            maximum=999_999,
            error_type=error,
        )
        _require_text("verifier_id", self.verifier_id, maximum=_MAX_SHORT_TEXT, error_type=error)
        _require_text(
            "verifier_version",
            self.verifier_version,
            maximum=_MAX_SHORT_TEXT,
            error_type=error,
        )
        _require_digest(
            "verification_policy_digest",
            self.verification_policy_digest,
            error_type=error,
        )
        for name, observation in (("baseline", self.baseline), ("control", self.control)):
            if not isinstance(observation, VerificationObservation):
                raise error(f"{name} must be a VerificationObservation")
        if not isinstance(self.reproduction, ReproductionObservation):
            raise error("reproduction must be a ReproductionObservation")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    origin: EvidenceOrigin
    attestation: EvidenceAttestation | None = None

    def __post_init__(self) -> None:
        _require_text("evidence_id", self.evidence_id, maximum=_MAX_ID)
        origin = _coerce_enum("origin", self.origin, EvidenceOrigin)
        object.__setattr__(self, "origin", origin)
        if self.attestation is not None:
            if not isinstance(self.attestation, EvidenceAttestation):
                raise InvalidCommandError("attestation must be an EvidenceAttestation or None")
            if self.attestation.evidence_id != self.evidence_id:
                raise InvalidCommandError("attestation evidence_id must match the record")
        if origin is EvidenceOrigin.SCHEMA_2 and self.attestation is None:
            raise InvalidCommandError("schema_2 evidence requires a typed attestation")


@dataclass(frozen=True, slots=True)
class FindingCandidate:
    finding_id: str
    subject_id: str
    action_id: str
    attempt_id: str
    generation: int
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _require_text("finding_id", self.finding_id, maximum=_MAX_ID)
        _require_text("subject_id", self.subject_id, maximum=_MAX_ID)
        _require_text("action_id", self.action_id, maximum=_MAX_ID)
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        normalized = _require_string_tuple(
            "evidence_ids",
            self.evidence_ids,
            duplicate_free=True,
            error_type=EvidenceAttestationError,
        )
        if not normalized:
            raise EvidenceAttestationError("finding evidence_ids must not be empty")
        object.__setattr__(self, "evidence_ids", normalized)


@dataclass(frozen=True, slots=True)
class VerdictRecord:
    verdict_id: str
    subject_id: str
    action_id: str
    status: VerdictStatus
    generation: int
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    attempt_id: str | None = None
    supersedes_verdict_id: str | None = None
    finding: FindingCandidate | None = None

    def __post_init__(self) -> None:
        _require_text("verdict_id", self.verdict_id, maximum=_MAX_ID)
        _require_text("subject_id", self.subject_id, maximum=_MAX_ID)
        _require_text("action_id", self.action_id, maximum=_MAX_ID)
        status = _coerce_enum("status", self.status, VerdictStatus)
        object.__setattr__(self, "status", status)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_optional_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        _require_optional_text(
            "supersedes_verdict_id",
            self.supersedes_verdict_id,
            maximum=_MAX_ID,
        )
        if self.supersedes_verdict_id == self.verdict_id:
            raise InvalidCommandError("verdict cannot supersede itself")
        normalized = _require_string_tuple(
            "evidence_ids",
            self.evidence_ids,
            duplicate_free=True,
            error_type=EvidenceAttestationError,
        )
        object.__setattr__(self, "evidence_ids", normalized)
        if status is VerdictStatus.VERIFIED:
            if self.attempt_id is None:
                raise EvidenceAttestationError("VERIFIED verdict requires attempt_id")
            if not normalized:
                raise EvidenceAttestationError("VERIFIED verdict requires evidence_ids")
        if self.finding is not None:
            if not isinstance(self.finding, FindingCandidate):
                raise InvalidCommandError("finding must be a FindingCandidate")
            if status is not VerdictStatus.VERIFIED:
                raise EvidenceAttestationError("only VERIFIED verdicts may create findings")
            if (
                self.finding.subject_id != self.subject_id
                or self.finding.action_id != self.action_id
                or self.finding.attempt_id != self.attempt_id
                or self.finding.generation != self.generation
                or self.finding.evidence_ids != normalized
            ):
                raise EvidenceAttestationError(
                    "finding identity and evidence must exactly match the verdict"
                )


@dataclass(frozen=True, slots=True)
class VerdictStateRecord:
    verdict_id: str
    subject_id: str
    action_id: str
    attempt_id: str | None
    status: VerdictStatus
    generation: int
    evidence_ids: tuple[str, ...]
    active: bool
    supersedes_verdict_id: str | None
    superseded_by_verdict_id: str | None
    recorded_at: str

    def __post_init__(self) -> None:
        _require_text("verdict_id", self.verdict_id, maximum=_MAX_ID)
        _require_text("subject_id", self.subject_id, maximum=_MAX_ID)
        _require_text("action_id", self.action_id, maximum=_MAX_ID)
        _require_optional_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        status = _coerce_enum("status", self.status, VerdictStatus)
        object.__setattr__(self, "status", status)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        evidence_ids = _require_string_tuple(
            "evidence_ids",
            self.evidence_ids,
            duplicate_free=True,
            error_type=EvidenceAttestationError,
        )
        object.__setattr__(self, "evidence_ids", evidence_ids)
        _require_bool("active", self.active)
        _require_optional_text(
            "supersedes_verdict_id", self.supersedes_verdict_id, maximum=_MAX_ID
        )
        _require_optional_text(
            "superseded_by_verdict_id", self.superseded_by_verdict_id, maximum=_MAX_ID
        )
        _require_text("recorded_at", self.recorded_at, maximum=_MAX_SHORT_TEXT)
        if status is VerdictStatus.VERIFIED and (
            self.attempt_id is None or not evidence_ids
        ):
            raise EvidenceAttestationError(
                "VERIFIED verdict state requires attempt_id and evidence_ids"
            )
        if self.active and self.superseded_by_verdict_id is not None:
            raise InvalidCommandError("active verdict cannot be superseded")
        if not self.active and self.superseded_by_verdict_id is None:
            raise InvalidCommandError("inactive verdict requires superseded_by_verdict_id")
        if self.verdict_id in {
            self.supersedes_verdict_id,
            self.superseded_by_verdict_id,
        }:
            raise InvalidCommandError("verdict cannot supersede itself")


@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    verdict_id: str
    subject_id: str
    action_id: str | None
    attempt_id: str | None
    generation: int
    evidence_ids: tuple[str, ...]
    active: bool
    superseded_by_verdict_id: str | None
    legacy_unverified: bool

    def __post_init__(self) -> None:
        _require_text("finding_id", self.finding_id, maximum=_MAX_ID)
        _require_text("verdict_id", self.verdict_id, maximum=_MAX_ID)
        _require_text("subject_id", self.subject_id, maximum=_MAX_ID)
        _require_optional_text("action_id", self.action_id, maximum=_MAX_ID)
        _require_optional_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        evidence_ids = _require_string_tuple(
            "evidence_ids",
            self.evidence_ids,
            duplicate_free=True,
            error_type=EvidenceAttestationError,
        )
        if not evidence_ids:
            raise EvidenceAttestationError("finding record requires evidence_ids")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        _require_bool("active", self.active)
        _require_optional_text(
            "superseded_by_verdict_id", self.superseded_by_verdict_id, maximum=_MAX_ID
        )
        _require_bool("legacy_unverified", self.legacy_unverified)
        if self.legacy_unverified:
            if self.active:
                raise EvidenceAttestationError("legacy-unverified finding cannot be active")
        elif self.action_id is None or self.attempt_id is None:
            raise EvidenceAttestationError("schema 2 finding requires action and attempt")
        if self.active and self.superseded_by_verdict_id is not None:
            raise InvalidCommandError("active finding cannot be superseded")


@dataclass(frozen=True, slots=True)
class ProcessStart:
    attempt_id: str
    process_name: str = ""

    def __post_init__(self) -> None:
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        _require_text(
            "process_name",
            self.process_name,
            maximum=_MAX_SHORT_TEXT,
            allow_empty=True,
        )


@dataclass(frozen=True, slots=True)
class ProcessOutput:
    process_id: str
    attempt_id: str
    stream: ProcessStream
    redacted_excerpt: str
    redaction_applied: bool
    truncated: bool
    stdout_bytes_total: int
    stderr_bytes_total: int
    combined_bytes_total: int
    stdout_omitted_bytes_total: int
    stderr_omitted_bytes_total: int
    combined_omitted_bytes_total: int

    def __post_init__(self) -> None:
        _require_text("process_id", self.process_id, maximum=_MAX_ID)
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        stream = _coerce_enum("stream", self.stream, ProcessStream)
        object.__setattr__(self, "stream", stream)
        _require_text(
            "redacted_excerpt",
            self.redacted_excerpt,
            maximum=_MAX_EXCERPT_BYTES,
            allow_empty=True,
            error_type=SensitiveOutputRejectedError,
        )
        try:
            excerpt_bytes = self.redacted_excerpt.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SensitiveOutputRejectedError(
                "redacted_excerpt must be valid UTF-8 text"
            ) from exc
        if len(excerpt_bytes) > _MAX_EXCERPT_BYTES:
            raise SensitiveOutputRejectedError(
                "redacted_excerpt exceeds 4096 UTF-8 bytes"
            )
        _require_bool("redaction_applied", self.redaction_applied)
        if self.redaction_applied is not True:
            raise SensitiveOutputRejectedError("redaction_applied must be true")
        _require_bool("truncated", self.truncated)
        if any(pattern.search(self.redacted_excerpt) for pattern in _KNOWN_SENSITIVE_MARKERS):
            raise SensitiveOutputRejectedError(
                "redacted_excerpt contains a known sensitive marker"
            )
        _validate_absolute_counters(
            stdout_bytes_total=self.stdout_bytes_total,
            stderr_bytes_total=self.stderr_bytes_total,
            combined_bytes_total=self.combined_bytes_total,
            stdout_omitted_bytes_total=self.stdout_omitted_bytes_total,
            stderr_omitted_bytes_total=self.stderr_omitted_bytes_total,
            combined_omitted_bytes_total=self.combined_omitted_bytes_total,
            truncated=self.truncated,
        )


@dataclass(frozen=True, slots=True)
class ProcessTerminal:
    process_id: str
    attempt_id: str
    exit_code: int | None
    termination_reason: str
    stdout_bytes_total: int
    stderr_bytes_total: int
    combined_bytes_total: int
    stdout_omitted_bytes_total: int
    stderr_omitted_bytes_total: int
    combined_omitted_bytes_total: int

    def __post_init__(self) -> None:
        _require_text("process_id", self.process_id, maximum=_MAX_ID)
        _require_text("attempt_id", self.attempt_id, maximum=_MAX_ID)
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise InvalidCommandError("exit_code must be an integer or None")
        _require_text("termination_reason", self.termination_reason, maximum=_MAX_REASON)
        _validate_absolute_counters(
            stdout_bytes_total=self.stdout_bytes_total,
            stderr_bytes_total=self.stderr_bytes_total,
            combined_bytes_total=self.combined_bytes_total,
            stdout_omitted_bytes_total=self.stdout_omitted_bytes_total,
            stderr_omitted_bytes_total=self.stderr_omitted_bytes_total,
            combined_omitted_bytes_total=self.combined_omitted_bytes_total,
        )


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    process_id: str
    attempt_id: str
    process_name: str
    state: ProcessState
    last_sequence: int
    stdout_bytes_total: int
    stderr_bytes_total: int
    combined_bytes_total: int
    stdout_omitted_bytes_total: int
    stderr_omitted_bytes_total: int
    combined_omitted_bytes_total: int
    redacted_head_excerpt: str
    redacted_tail_excerpt: str
    exit_code: int | None
    termination_reason: str | None

    def __post_init__(self) -> None:
        _require_pattern("process_id", self.process_id, _PROCESS_ID_RE)
        _require_pattern("attempt_id", self.attempt_id, _ATTEMPT_ID_RE)
        _require_text(
            "process_name", self.process_name, maximum=_MAX_SHORT_TEXT, allow_empty=True
        )
        state = _coerce_enum("state", self.state, ProcessState)
        object.__setattr__(self, "state", state)
        _require_int("last_sequence", self.last_sequence)
        _validate_absolute_counters(
            stdout_bytes_total=self.stdout_bytes_total,
            stderr_bytes_total=self.stderr_bytes_total,
            combined_bytes_total=self.combined_bytes_total,
            stdout_omitted_bytes_total=self.stdout_omitted_bytes_total,
            stderr_omitted_bytes_total=self.stderr_omitted_bytes_total,
            combined_omitted_bytes_total=self.combined_omitted_bytes_total,
        )
        for name, excerpt in (
            ("redacted_head_excerpt", self.redacted_head_excerpt),
            ("redacted_tail_excerpt", self.redacted_tail_excerpt),
        ):
            _require_text(
                name,
                excerpt,
                maximum=_MAX_EXCERPT_BYTES,
                allow_empty=True,
                error_type=SensitiveOutputRejectedError,
            )
            try:
                encoded = excerpt.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise SensitiveOutputRejectedError(f"{name} must be valid UTF-8 text") from exc
            if len(encoded) > _MAX_EXCERPT_BYTES:
                raise SensitiveOutputRejectedError(f"{name} exceeds 4096 UTF-8 bytes")
            if any(pattern.search(excerpt) for pattern in _KNOWN_SENSITIVE_MARKERS):
                raise SensitiveOutputRejectedError(f"{name} contains a known sensitive marker")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise InvalidCommandError("exit_code must be an integer or None")
        _require_optional_text(
            "termination_reason", self.termination_reason, maximum=_MAX_REASON
        )
        if state is ProcessState.STARTED and (
            self.exit_code is not None or self.termination_reason is not None
        ):
            raise InvalidCommandError("started process cannot contain terminal metadata")
        if state is ProcessState.TERMINATED and self.termination_reason is None:
            raise InvalidCommandError("terminated process requires termination_reason")


@dataclass(frozen=True, slots=True)
class MemoryEnqueue:
    projector: str
    dedupe_key: str
    payload: FrozenJsonObject = field(default_factory=FrozenJsonObject)

    def __post_init__(self) -> None:
        _require_text("projector", self.projector, maximum=_MAX_SHORT_TEXT)
        _require_text("dedupe_key", self.dedupe_key, maximum=_MAX_REASON)
        object.__setattr__(self, "payload", _freeze_json_object("payload", self.payload))


@dataclass(frozen=True, slots=True)
class MemoryApplied:
    outbox_id: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_text("outbox_id", self.outbox_id, maximum=_MAX_ID)
        _require_digest("receipt_digest", self.receipt_digest)


@dataclass(frozen=True, slots=True)
class MemoryFailed:
    outbox_id: str
    error_code: str
    failure_digest: str
    retryable: bool

    def __post_init__(self) -> None:
        _require_text("outbox_id", self.outbox_id, maximum=_MAX_ID)
        _require_text("error_code", self.error_code, maximum=_MAX_SHORT_TEXT)
        _require_digest("failure_digest", self.failure_digest)
        _require_bool("retryable", self.retryable)


@dataclass(frozen=True, slots=True)
class OutboxEntry:
    outbox_id: str
    workflow_id: str
    generation: int
    projector: str
    dedupe_key: str
    payload: FrozenJsonObject
    payload_digest: str
    status: OutboxState
    delivery_attempt: int
    enqueued_revision: int
    receipt_digest: str | None = None
    error_code: str | None = None
    failure_digest: str | None = None
    retryable: bool | None = None

    def __post_init__(self) -> None:
        _require_pattern("outbox_id", self.outbox_id, _OUTBOX_ID_RE)
        _require_pattern("workflow_id", self.workflow_id, _WORKFLOW_ID_RE)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_text("projector", self.projector, maximum=_MAX_SHORT_TEXT)
        _require_text("dedupe_key", self.dedupe_key, maximum=_MAX_REASON)
        payload = _freeze_json_object("payload", self.payload)
        object.__setattr__(self, "payload", payload)
        normalized_digest = _require_sha256("payload_digest", self.payload_digest)
        object.__setattr__(self, "payload_digest", normalized_digest)
        expected_payload_digest = hashlib.sha256(
            _canonical_frozen_json_bytes(payload)
        ).hexdigest()
        if normalized_digest != expected_payload_digest:
            raise InvalidCommandError("payload_digest must match canonical payload bytes")
        identity = {
            "workflow_id": self.workflow_id,
            "generation": self.generation,
            "projector": self.projector,
            "dedupe_key": self.dedupe_key,
            "payload_digest": normalized_digest,
        }
        canonical_identity = json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        expected_outbox_id = "out-" + hashlib.sha256(canonical_identity).hexdigest()
        if self.outbox_id != expected_outbox_id:
            raise InvalidCommandError("outbox_id must match the canonical outbox identity")
        status = _coerce_enum("status", self.status, OutboxState)
        object.__setattr__(self, "status", status)
        _require_int("delivery_attempt", self.delivery_attempt)
        _require_int("enqueued_revision", self.enqueued_revision, minimum=1)
        if self.receipt_digest is not None:
            _require_digest("receipt_digest", self.receipt_digest)
        _require_optional_text("error_code", self.error_code, maximum=_MAX_SHORT_TEXT)
        if self.failure_digest is not None:
            _require_digest("failure_digest", self.failure_digest)
        if self.retryable is not None:
            _require_bool("retryable", self.retryable)
        if status is OutboxState.ENQUEUED and (
            self.delivery_attempt != 0
            or any(
                value is not None
                for value in (
                    self.receipt_digest,
                    self.error_code,
                    self.failure_digest,
                    self.retryable,
                )
            )
        ):
            raise InvalidCommandError("enqueued outbox entry cannot contain delivery metadata")
        if status is OutboxState.APPLIED and (
            self.delivery_attempt < 1
            or self.receipt_digest is None
            or any(
                value is not None
                for value in (self.error_code, self.failure_digest, self.retryable)
            )
        ):
            raise InvalidCommandError("applied outbox entry requires receipt metadata only")
        if status is OutboxState.FAILED and (
            self.delivery_attempt < 1
            or self.error_code is None
            or self.failure_digest is None
            or self.retryable is None
            or self.receipt_digest is not None
        ):
            raise InvalidCommandError("failed outbox entry requires failure metadata only")


@dataclass(frozen=True, slots=True)
class RecoveryRequest:
    checkpoint_id: str
    expected_source_file_bytes: int
    expected_source_file_sha256: str

    def __post_init__(self) -> None:
        _require_pattern("checkpoint_id", self.checkpoint_id, _CHECKPOINT_ID_RE)
        _require_int("expected_source_file_bytes", self.expected_source_file_bytes, minimum=1)
        normalized_hash = _require_sha256(
            "expected_source_file_sha256",
            self.expected_source_file_sha256,
        )
        object.__setattr__(self, "expected_source_file_sha256", normalized_hash)


@dataclass(frozen=True, slots=True)
class StageStatusRecord:
    stage_id: str
    status: str

    def __post_init__(self) -> None:
        _require_text("stage_id", self.stage_id, maximum=_MAX_ID)
        _require_text("status", self.status, maximum=_MAX_SHORT_TEXT)


@dataclass(frozen=True, slots=True)
class StageResultDigest:
    stage_id: str
    result_digest: str

    def __post_init__(self) -> None:
        _require_text("stage_id", self.stage_id, maximum=_MAX_ID)
        _require_digest("result_digest", self.result_digest)


@dataclass(frozen=True, slots=True)
class LegacyCheckpointHint:
    checkpoint_id: str
    revision: int
    relative_path: str

    def __post_init__(self) -> None:
        _require_text("checkpoint_id", self.checkpoint_id, maximum=_MAX_ID)
        _require_int("revision", self.revision)
        _require_text("relative_path", self.relative_path, maximum=_MAX_TARGET)


@dataclass(frozen=True, slots=True)
class BudgetMetrics:
    actions_proposed: int = 0
    actions_deferred: int = 0
    actions_blocked: int = 0
    attempts_started: int = 0
    attempts_completed: int = 0
    attempts_blocked: int = 0
    attempts_cancelled: int = 0
    budget_charges: int = 0

    def __post_init__(self) -> None:
        for name in (
            "actions_proposed",
            "actions_deferred",
            "actions_blocked",
            "attempts_started",
            "attempts_completed",
            "attempts_blocked",
            "attempts_cancelled",
            "budget_charges",
        ):
            _require_int(name, getattr(self, name))
        if self.budget_charges != self.attempts_started:
            raise InvalidCommandError("budget_charges must equal attempts_started")
        terminal_attempts = (
            self.attempts_completed + self.attempts_blocked + self.attempts_cancelled
        )
        if terminal_attempts > self.attempts_started:
            raise InvalidCommandError("terminal attempts cannot exceed attempts_started")


@dataclass(frozen=True, slots=True)
class CheckpointRecord:
    checkpoint_id: str
    workflow_id: str
    generation: int
    bound_revision: int
    bound_event_hash: str
    bound_event_id: str
    binding_mode: HashMode
    state_digest: str
    event_file_prefix_sha256: str
    bound_prefix_bytes: int
    relative_path: str
    created_at: str
    checkpoint_file_sha256: str
    event_id: str
    event_end_offset: int

    def __post_init__(self) -> None:
        _require_pattern("checkpoint_id", self.checkpoint_id, _CHECKPOINT_ID_RE)
        _require_pattern("workflow_id", self.workflow_id, _WORKFLOW_ID_RE)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_int("bound_revision", self.bound_revision, minimum=1)
        object.__setattr__(
            self, "bound_event_hash", _require_sha256("bound_event_hash", self.bound_event_hash)
        )
        _require_pattern("bound_event_id", self.bound_event_id, _EVENT_ID_RE)
        mode = _coerce_enum("binding_mode", self.binding_mode, HashMode)
        if mode is HashMode.EMPTY:
            raise InvalidCommandError("checkpoint binding_mode cannot be empty")
        object.__setattr__(self, "binding_mode", mode)
        _require_digest("state_digest", self.state_digest)
        object.__setattr__(
            self,
            "event_file_prefix_sha256",
            _require_sha256("event_file_prefix_sha256", self.event_file_prefix_sha256),
        )
        _require_int("bound_prefix_bytes", self.bound_prefix_bytes, minimum=1)
        _require_text("relative_path", self.relative_path, maximum=_MAX_TARGET)
        _require_text("created_at", self.created_at, maximum=_MAX_SHORT_TEXT)
        object.__setattr__(
            self,
            "checkpoint_file_sha256",
            _require_sha256("checkpoint_file_sha256", self.checkpoint_file_sha256),
        )
        _require_pattern("event_id", self.event_id, _EVENT_ID_RE)
        _require_int("event_end_offset", self.event_end_offset, minimum=1)
        if self.event_end_offset < self.bound_prefix_bytes:
            raise InvalidCommandError("checkpoint event offset cannot precede bound prefix")


@dataclass(frozen=True, slots=True)
class EventKernelState:
    workflow_id: str | None
    generation: int
    ownership: OwnershipState
    phase: str | None = None
    stage_statuses: tuple[StageStatusRecord, ...] = field(default_factory=tuple)
    stage_result_digests: tuple[StageResultDigest, ...] = field(default_factory=tuple)
    legacy_checkpoint_hints: tuple[LegacyCheckpointHint, ...] = field(default_factory=tuple)
    actions: tuple[LogicalActionRecord, ...] = field(default_factory=tuple)
    attempts: tuple[ExecutionAttemptRecord, ...] = field(default_factory=tuple)
    evidence: tuple[EvidenceRecord, ...] = field(default_factory=tuple)
    verdicts: tuple[VerdictStateRecord, ...] = field(default_factory=tuple)
    findings: tuple[FindingRecord, ...] = field(default_factory=tuple)
    active_findings: tuple[str, ...] = field(default_factory=tuple)
    processes: tuple[ProcessRecord, ...] = field(default_factory=tuple)
    outbox: tuple[OutboxEntry, ...] = field(default_factory=tuple)
    checkpoints: tuple[CheckpointRecord, ...] = field(default_factory=tuple)
    budget: BudgetMetrics = field(default_factory=BudgetMetrics)

    def __post_init__(self) -> None:
        if self.workflow_id is not None:
            _require_pattern("workflow_id", self.workflow_id, _WORKFLOW_ID_RE)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        ownership = _coerce_enum("ownership", self.ownership, OwnershipState)
        object.__setattr__(self, "ownership", ownership)
        _require_optional_text("phase", self.phase, maximum=_MAX_SHORT_TEXT)
        record_fields = (
            ("stage_statuses", StageStatusRecord, "stage_id"),
            ("stage_result_digests", StageResultDigest, "stage_id"),
            ("legacy_checkpoint_hints", LegacyCheckpointHint, "checkpoint_id"),
            ("actions", LogicalActionRecord, "action_id"),
            ("attempts", ExecutionAttemptRecord, "attempt_id"),
            ("evidence", EvidenceRecord, "evidence_id"),
            ("verdicts", VerdictStateRecord, "verdict_id"),
            ("findings", FindingRecord, "finding_id"),
            ("processes", ProcessRecord, "process_id"),
            ("outbox", OutboxEntry, "outbox_id"),
            ("checkpoints", CheckpointRecord, "checkpoint_id"),
        )
        for name, record_type, identifier in record_fields:
            records = _require_record_tuple(name, getattr(self, name), record_type)
            _require_unique_record_ids(name, records, identifier)
            object.__setattr__(self, name, records)
        active_findings = _require_string_tuple(
            "active_findings", self.active_findings, duplicate_free=True
        )
        object.__setattr__(self, "active_findings", active_findings)
        actual_active = tuple(finding.finding_id for finding in self.findings if finding.active)
        if active_findings != actual_active:
            raise InvalidCommandError("active_findings must exactly list active finding IDs")
        if not isinstance(self.budget, BudgetMetrics):
            raise InvalidCommandError("budget must be BudgetMetrics")
        self._validate_record_graph()

    def _validate_record_graph(self) -> None:
        actions = {record.action_id: record for record in self.actions}
        attempts = {record.attempt_id: record for record in self.attempts}
        evidence = {record.evidence_id: record for record in self.evidence}
        verdicts = {record.verdict_id: record for record in self.verdicts}

        for attempt in self.attempts:
            action = actions.get(attempt.action_id)
            if (
                action is None
                or attempt.generation != action.generation
                or attempt.attempt_id not in action.attempt_ids
            ):
                raise InvalidCommandError("attempt projection must bind to its action")

        for record in self.evidence:
            attestation = record.attestation
            if attestation is None:
                continue
            action = actions.get(attestation.action_id)
            attempt = attempts.get(attestation.attempt_id)
            if (
                action is None
                or attempt is None
                or attempt.action_id != attestation.action_id
                or action.generation != attestation.generation
                or attempt.generation != attestation.generation
                or attempt.state is AttemptState.STARTED
            ):
                raise EvidenceAttestationError(
                    "typed evidence must bind to a terminal attempt and matching action"
                )

        active_subjects: set[str] = set()
        for verdict in self.verdicts:
            action = actions.get(verdict.action_id)
            attempt = attempts.get(verdict.attempt_id) if verdict.attempt_id is not None else None
            if action is None or action.generation != verdict.generation:
                raise EvidenceAttestationError("verdict must bind to its generation action")
            if verdict.attempt_id is not None and (
                attempt is None
                or attempt.action_id != verdict.action_id
                or attempt.generation != verdict.generation
            ):
                raise EvidenceAttestationError("verdict attempt must exactly bind to its action")
            if verdict.status is VerdictStatus.VERIFIED:
                for evidence_id in verdict.evidence_ids:
                    record = evidence.get(evidence_id)
                    attestation = record.attestation if record is not None else None
                    if (
                        attestation is None
                        or attestation.generation != verdict.generation
                        or attestation.action_id != verdict.action_id
                        or attestation.attempt_id != verdict.attempt_id
                    ):
                        raise EvidenceAttestationError(
                            "VERIFIED verdict evidence must exactly match generation, action, and attempt"
                        )
            if verdict.active:
                if verdict.subject_id in active_subjects:
                    raise InvalidCommandError("only one active verdict is allowed per subject")
                active_subjects.add(verdict.subject_id)

        for verdict in self.verdicts:
            if verdict.supersedes_verdict_id is not None:
                previous = verdicts.get(verdict.supersedes_verdict_id)
                if (
                    previous is None
                    or previous.active
                    or previous.subject_id != verdict.subject_id
                    or previous.superseded_by_verdict_id != verdict.verdict_id
                ):
                    raise InvalidCommandError("verdict supersession must be explicit and bidirectional")
            if verdict.superseded_by_verdict_id is not None:
                successor = verdicts.get(verdict.superseded_by_verdict_id)
                if (
                    successor is None
                    or not successor.active
                    or successor.subject_id != verdict.subject_id
                    or successor.supersedes_verdict_id != verdict.verdict_id
                ):
                    raise InvalidCommandError("superseded verdict must bind to its active successor")

        finding_verdict_ids: set[str] = set()
        for finding in self.findings:
            if finding.verdict_id in finding_verdict_ids:
                raise EvidenceAttestationError("each verdict may create at most one finding")
            finding_verdict_ids.add(finding.verdict_id)
            if finding.legacy_unverified:
                continue
            verdict = verdicts.get(finding.verdict_id)
            if (
                verdict is None
                or verdict.status is not VerdictStatus.VERIFIED
                or verdict.subject_id != finding.subject_id
                or verdict.action_id != finding.action_id
                or verdict.attempt_id != finding.attempt_id
                or verdict.generation != finding.generation
                or verdict.evidence_ids != finding.evidence_ids
                or verdict.active != finding.active
                or verdict.superseded_by_verdict_id != finding.superseded_by_verdict_id
            ):
                raise EvidenceAttestationError(
                    "finding must exactly bind to one active or superseded VERIFIED verdict"
                )


@dataclass(frozen=True, slots=True)
class Head:
    revision: int
    event_hash: str
    event_id: str | None
    hash_mode: HashMode

    def __post_init__(self) -> None:
        _require_int("revision", self.revision)
        hash_mode = _coerce_enum("hash_mode", self.hash_mode, HashMode)
        object.__setattr__(self, "hash_mode", hash_mode)
        if self.revision == 0:
            if self.event_id is not None or self.event_hash != "" or hash_mode is not HashMode.EMPTY:
                raise InvalidCommandError("revision zero requires an empty head")
            return
        if self.event_id is None:
            raise InvalidCommandError("a non-empty head requires an event_id")
        _require_pattern("event_id", self.event_id, _EVENT_ID_RE)
        if hash_mode is HashMode.HASHED:
            object.__setattr__(self, "event_hash", _require_sha256("event_hash", self.event_hash))
        elif hash_mode is HashMode.LEGACY_UNBOUND:
            if self.event_hash != "":
                raise InvalidCommandError("legacy-unbound head cannot carry an event hash")
        else:
            raise InvalidCommandError("non-empty head cannot use empty hash mode")


@dataclass(frozen=True, slots=True)
class EventIndexEntry:
    revision: int
    event_id: str
    event_type: str
    event_hash: str
    previous_event_hash: str
    schema_version: str
    generation: int
    byte_offset: int
    byte_length: int
    hash_mode: HashMode

    def __post_init__(self) -> None:
        _require_int("revision", self.revision, minimum=1)
        _require_pattern("event_id", self.event_id, _EVENT_ID_RE)
        _require_text("event_type", self.event_type, maximum=_MAX_ID)
        mode = _coerce_enum("hash_mode", self.hash_mode, HashMode)
        if mode is HashMode.EMPTY:
            raise InvalidCommandError("indexed event cannot use empty hash mode")
        object.__setattr__(self, "hash_mode", mode)
        if mode is HashMode.HASHED:
            object.__setattr__(
                self, "event_hash", _require_sha256("event_hash", self.event_hash)
            )
            if self.revision == 1:
                _require_text(
                    "previous_event_hash",
                    self.previous_event_hash,
                    maximum=64,
                    allow_empty=True,
                )
                if self.previous_event_hash:
                    raise InvalidCommandError("first event previous_event_hash must be empty")
            elif (
                self.event_type == EventType.OWNERSHIP_CLAIMED.value
                and _LEGACY_HEAD_RE.fullmatch(self.previous_event_hash) is not None
            ):
                pass
            else:
                object.__setattr__(
                    self,
                    "previous_event_hash",
                    _require_sha256("previous_event_hash", self.previous_event_hash),
                )
        else:
            _require_text("event_hash", self.event_hash, maximum=64, allow_empty=True)
            _require_text(
                "previous_event_hash", self.previous_event_hash, maximum=64, allow_empty=True
            )
            if self.event_hash or self.previous_event_hash:
                raise InvalidCommandError("legacy-unbound event index cannot carry hashes")
        _require_text("schema_version", self.schema_version, maximum=16)
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_int("byte_offset", self.byte_offset)
        _require_int("byte_length", self.byte_length, minimum=1)


@dataclass(frozen=True, slots=True)
class CommandIndexEntry:
    command_id: str
    command_type: CommandType
    command_digest: str
    event_id: str
    event_type: EventType
    revision: int
    event_hash: str
    generation: int
    byte_offset: int
    byte_length: int
    action_id: str | None = None
    attempt_id: str | None = None
    process_id: str | None = None
    outbox_id: str | None = None
    checkpoint_id: str | None = None

    def __post_init__(self) -> None:
        _require_text("command_id", self.command_id, maximum=_MAX_ID)
        command_type = _coerce_enum("command_type", self.command_type, CommandType)
        event_type = _coerce_enum("event_type", self.event_type, EventType)
        object.__setattr__(self, "command_type", command_type)
        object.__setattr__(self, "event_type", event_type)
        expected_event_type = tuple(EventType)[tuple(CommandType).index(command_type)]
        if event_type is not expected_event_type:
            raise InvalidCommandError("command_type and event_type must be the defined pair")
        object.__setattr__(
            self, "command_digest", _require_sha256("command_digest", self.command_digest)
        )
        _require_pattern("event_id", self.event_id, _EVENT_ID_RE)
        _require_int("revision", self.revision, minimum=1)
        object.__setattr__(self, "event_hash", _require_sha256("event_hash", self.event_hash))
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_int("byte_offset", self.byte_offset)
        _require_int("byte_length", self.byte_length, minimum=1)
        _require_optional_pattern("action_id", self.action_id, _ACTION_ID_RE)
        _require_optional_pattern("attempt_id", self.attempt_id, _ATTEMPT_ID_RE)
        _require_optional_pattern("process_id", self.process_id, _PROCESS_ID_RE)
        _require_optional_pattern("outbox_id", self.outbox_id, _OUTBOX_ID_RE)
        _require_optional_pattern("checkpoint_id", self.checkpoint_id, _CHECKPOINT_ID_RE)
        _validate_generated_result_ids(
            event_type,
            action_id=self.action_id,
            attempt_id=self.attempt_id,
            process_id=self.process_id,
            outbox_id=self.outbox_id,
            checkpoint_id=self.checkpoint_id,
        )


@dataclass(frozen=True, slots=True)
class ReplayIssue:
    kind: ReplayIssueKind
    message: str
    offset: int
    revision: int | None = None
    event_id: str | None = None
    line_number: int | None = None

    def __post_init__(self) -> None:
        kind = _coerce_enum("kind", self.kind, ReplayIssueKind)
        object.__setattr__(self, "kind", kind)
        _require_text("message", self.message, maximum=_MAX_REASON)
        _require_int("offset", self.offset)
        if self.revision is not None:
            _require_int("revision", self.revision)
        _require_optional_text("event_id", self.event_id, maximum=_MAX_ID)
        if self.line_number is not None:
            _require_int("line_number", self.line_number, minimum=1)


@dataclass(frozen=True, slots=True)
class ReplayStats:
    lines_read: int = 0
    json_decodes: int = 0
    reducer_calls: int = 0

    def __post_init__(self) -> None:
        _require_int("lines_read", self.lines_read)
        _require_int("json_decodes", self.json_decodes)
        _require_int("reducer_calls", self.reducer_calls)


@dataclass(frozen=True, slots=True)
class ReplayResult:
    state: EventKernelState
    head: Head
    event_count: int
    semantic_event_count: int
    valid_prefix_bytes: int
    event_file_prefix_sha256: str
    event_file_bytes: int
    event_file_sha256: str
    ownership: OwnershipState
    event_index: tuple[EventIndexEntry, ...] = field(default_factory=tuple)
    command_index: tuple[CommandIndexEntry, ...] = field(default_factory=tuple)
    ownership_claim_offset: int | None = None
    issue: ReplayIssue | None = None
    stats: ReplayStats = field(default_factory=ReplayStats)

    def __post_init__(self) -> None:
        if not isinstance(self.state, EventKernelState):
            raise InvalidCommandError("state must be EventKernelState")
        if not isinstance(self.head, Head):
            raise InvalidCommandError("head must be a Head")
        for name, value in (
            ("event_count", self.event_count),
            ("semantic_event_count", self.semantic_event_count),
            ("valid_prefix_bytes", self.valid_prefix_bytes),
            ("event_file_bytes", self.event_file_bytes),
        ):
            _require_int(name, value)
        _require_sha256("event_file_prefix_sha256", self.event_file_prefix_sha256)
        _require_sha256("event_file_sha256", self.event_file_sha256)
        ownership = _coerce_enum("ownership", self.ownership, OwnershipState)
        object.__setattr__(self, "ownership", ownership)
        event_index = _require_record_tuple(
            "event_index", self.event_index, EventIndexEntry
        )
        command_index = _require_record_tuple(
            "command_index", self.command_index, CommandIndexEntry
        )
        _require_unique_record_ids("event_index", event_index, "event_id")
        _require_unique_record_ids("command_index", command_index, "command_id")
        object.__setattr__(self, "event_index", event_index)
        object.__setattr__(self, "command_index", command_index)
        if self.ownership_claim_offset is not None:
            _require_int("ownership_claim_offset", self.ownership_claim_offset)
        if self.issue is not None and not isinstance(self.issue, ReplayIssue):
            raise InvalidCommandError("issue must be a ReplayIssue or None")
        if not isinstance(self.stats, ReplayStats):
            raise InvalidCommandError("stats must be ReplayStats")
        if self.semantic_event_count > self.event_count:
            raise InvalidCommandError("semantic_event_count cannot exceed event_count")
        if self.valid_prefix_bytes > self.event_file_bytes:
            raise InvalidCommandError("valid_prefix_bytes cannot exceed event_file_bytes")
        if self.state.ownership is not ownership:
            raise InvalidCommandError("state ownership must match replay ownership")
        self._validate_replay_consistency()

    def _validate_replay_consistency(self) -> None:
        if len(self.event_index) != self.event_count:
            raise InvalidCommandError("event_count must equal compact event index length")
        if self.semantic_event_count > len(self.event_index):
            raise InvalidCommandError("semantic_event_count exceeds compact event index")

        expected_offset = 0
        previous: EventIndexEntry | None = None
        for expected_revision, entry in enumerate(self.event_index, start=1):
            if entry.revision != expected_revision:
                raise InvalidCommandError("event index revisions must be contiguous")
            if entry.byte_offset != expected_offset:
                raise InvalidCommandError("event index byte ranges must be contiguous")
            if (
                previous is not None
                and previous.hash_mode is HashMode.HASHED
                and entry.hash_mode is HashMode.HASHED
                and entry.previous_event_hash != previous.event_hash
            ):
                raise InvalidCommandError("event index hash chain is inconsistent")
            expected_offset += entry.byte_length
            previous = entry
        if expected_offset > self.event_file_bytes:
            raise InvalidCommandError("event index extends beyond the event file")

        semantic_prefix_bytes = 0
        if self.semantic_event_count:
            semantic_head = self.event_index[self.semantic_event_count - 1]
            semantic_prefix_bytes = semantic_head.byte_offset + semantic_head.byte_length
            if (
                self.head.revision != semantic_head.revision
                or self.head.event_id != semantic_head.event_id
                or self.head.event_hash != semantic_head.event_hash
                or self.head.hash_mode is not semantic_head.hash_mode
            ):
                raise InvalidCommandError("head must match the final semantic event index entry")
        elif (
            self.head.revision != 0
            or self.head.event_id is not None
            or self.head.event_hash != ""
            or self.head.hash_mode is not HashMode.EMPTY
        ):
            raise InvalidCommandError("empty semantic replay requires an empty head")
        if self.valid_prefix_bytes != semantic_prefix_bytes:
            raise InvalidCommandError("valid_prefix_bytes must end at the semantic head")

        event_by_revision = {entry.revision: entry for entry in self.event_index}
        for command in self.command_index:
            event = event_by_revision.get(command.revision)
            if event is None or command.revision > self.semantic_event_count:
                raise InvalidCommandError("command index must reference a semantic event")
            if (
                command.event_id != event.event_id
                or command.event_type.value != event.event_type
                or command.event_hash != event.event_hash
                or command.generation != event.generation
                or command.byte_offset != event.byte_offset
                or command.byte_length != event.byte_length
            ):
                raise InvalidCommandError("command index must exactly bind to its event entry")

        ownership_claims = tuple(
            entry
            for entry in self.event_index[: self.semantic_event_count]
            if entry.event_type == EventType.OWNERSHIP_CLAIMED.value
        )
        if self.ownership is OwnershipState.EVENT_KERNEL_OWNED:
            if (
                len(ownership_claims) != 1
                or self.ownership_claim_offset != ownership_claims[0].byte_offset
            ):
                raise InvalidCommandError("owned replay requires one exact ownership claim offset")
        elif self.ownership_claim_offset is not None or ownership_claims:
            raise InvalidCommandError("unclaimed replay cannot contain an ownership claim")

        if self.issue is None:
            if self.event_count != self.semantic_event_count:
                raise InvalidCommandError("issue-free replay must reduce every indexed event")
            if self.valid_prefix_bytes != self.event_file_bytes:
                raise InvalidCommandError("issue-free replay prefix must cover the complete file")
            if self.event_file_prefix_sha256 != self.event_file_sha256:
                raise InvalidCommandError("issue-free prefix and full-file hashes must match")
        elif self.issue.offset != self.valid_prefix_bytes:
            raise InvalidCommandError("replay issue must begin at the semantic prefix boundary")

        if self.stats.reducer_calls != self.semantic_event_count:
            raise InvalidCommandError("reducer_calls must equal semantic_event_count")
        if self.stats.lines_read < self.event_count or self.stats.lines_read < self.stats.json_decodes:
            raise InvalidCommandError("replay statistics are internally inconsistent")


@dataclass(frozen=True, slots=True)
class CommandResult:
    command_id: str
    event_id: str
    event_type: EventType
    revision: int
    event_hash: str
    generation: int
    cache_updated: bool = True
    idempotent: bool = False
    deduplicated: bool = False
    original_command_id: str | None = None
    original_event_id: str | None = None
    action_id: str | None = None
    attempt_id: str | None = None
    process_id: str | None = None
    outbox_id: str | None = None
    checkpoint_id: str | None = None

    def __post_init__(self) -> None:
        _require_text("command_id", self.command_id, maximum=_MAX_ID)
        _require_pattern("event_id", self.event_id, _EVENT_ID_RE)
        event_type = _coerce_enum("event_type", self.event_type, EventType)
        object.__setattr__(self, "event_type", event_type)
        _require_int("revision", self.revision, minimum=1)
        object.__setattr__(self, "event_hash", _require_sha256("event_hash", self.event_hash))
        _require_int("generation", self.generation, minimum=1, maximum=999_999)
        _require_bool("cache_updated", self.cache_updated)
        _require_bool("idempotent", self.idempotent)
        _require_bool("deduplicated", self.deduplicated)
        _require_optional_text(
            "original_command_id",
            self.original_command_id,
            maximum=_MAX_ID,
        )
        _require_optional_text("original_event_id", self.original_event_id, maximum=_MAX_ID)
        _require_optional_pattern("action_id", self.action_id, _ACTION_ID_RE)
        _require_optional_pattern("attempt_id", self.attempt_id, _ATTEMPT_ID_RE)
        _require_optional_pattern("process_id", self.process_id, _PROCESS_ID_RE)
        _require_optional_pattern("outbox_id", self.outbox_id, _OUTBOX_ID_RE)
        _require_optional_pattern("checkpoint_id", self.checkpoint_id, _CHECKPOINT_ID_RE)
        _validate_generated_result_ids(
            event_type,
            action_id=self.action_id,
            attempt_id=self.attempt_id,
            process_id=self.process_id,
            outbox_id=self.outbox_id,
            checkpoint_id=self.checkpoint_id,
        )
        if self.idempotent and self.deduplicated:
            raise InvalidCommandError("result cannot be both idempotent and deduplicated")
        if self.deduplicated:
            if (
                self.event_type is not EventType.MEMORY_ENQUEUED
                or self.original_command_id is None
                or self.original_event_id is None
                or self.original_command_id == self.command_id
                or self.original_event_id != self.event_id
                or self.outbox_id is None
            ):
                raise InvalidCommandError(
                    "deduplicated result must identify a distinct original memory enqueue"
                )
        elif self.original_command_id is not None or self.original_event_id is not None:
            raise InvalidCommandError("original command metadata is only valid for dedupe results")


__all__ = [
    "ActionDecision",
    "ActionMerge",
    "ActionProposal",
    "ActionState",
    "AttemptBlock",
    "AttemptCancel",
    "AttemptComplete",
    "AttemptStart",
    "AttemptState",
    "BudgetMetrics",
    "CheckpointRecord",
    "CommandIndexEntry",
    "CommandType",
    "CommandMeta",
    "CommandResult",
    "EvidenceAttestation",
    "EvidenceAttestationError",
    "EvidenceOrigin",
    "EvidenceRecord",
    "EventIndexEntry",
    "EventKernelState",
    "EventType",
    "ExecutionAttemptRecord",
    "FindingRecord",
    "FrozenJsonArray",
    "FrozenJsonObject",
    "ReproductionObservation",
    "FindingCandidate",
    "HashMode",
    "Head",
    "InvalidCommandError",
    "LegacyCheckpointHint",
    "LogicalActionRecord",
    "MemoryApplied",
    "MemoryEnqueue",
    "MemoryFailed",
    "OutboxState",
    "OutboxEntry",
    "OwnershipState",
    "ProcessOutput",
    "ProcessStart",
    "ProcessState",
    "ProcessStream",
    "ProcessTerminal",
    "ProcessRecord",
    "RecoveryRequest",
    "ReplayIssue",
    "ReplayIssueKind",
    "ReplayResult",
    "ReplayStats",
    "SensitiveOutputRejectedError",
    "StageResultDigest",
    "StageStatusRecord",
    "VerdictRecord",
    "VerdictStateRecord",
    "VerdictStatus",
    "VerificationObservation",
    "WorkflowOwnershipClaim",
]
