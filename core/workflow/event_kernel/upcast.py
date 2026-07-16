from __future__ import annotations

from dataclasses import dataclass
import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .envelope import SCHEMA2_EVENT_TYPES
from .errors import (
    CorruptEventLogError,
    UnknownEventTypeError,
    UnsupportedFutureSchemaError,
)


LEGACY_EVENT_TYPES = frozenset(
    {
        "workflow.created",
        "phase.transitioned",
        "hypothesis.added",
        "policy.changed",
        "dead_end.recorded",
        "evidence.registered",
        "finding.promoted",
        "checkpoint.created",
        "orchestrator.initialized",
        "orchestrator.observations.updated",
        "orchestrator.approval.recorded",
        "orchestrator.approval.consumed",
        "orchestrator.generation.started",
        "orchestrator.stage.started",
        "orchestrator.stage.completed",
        "orchestrator.stage.blocked",
        "orchestrator.interrupted",
        "orchestrator.completed",
    }
)

_KNOWN_SCHEMA_VERSIONS = frozenset({"1.0", "2.0"})


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if type(value) in {type(None), bool, int, float, str}:
        return value
    raise TypeError("semantic event payload must contain JSON-native values")


@dataclass(frozen=True, slots=True)
class SemanticEvent:
    """Immutable, in-memory input to the event-kernel reducer."""

    schema_version: str
    event_type: str
    workflow_id: str | None
    generation: int
    revision: int | None
    event_id: str | None
    timestamp: str | None
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        frozen_payload = _freeze(self.payload)
        if not isinstance(frozen_payload, Mapping):
            raise TypeError("semantic event payload must be a mapping")
        object.__setattr__(self, "payload", frozen_payload)

    @property
    def type(self) -> str:
        return self.event_type


def _location(event: Mapping[str, Any]) -> tuple[int | None, str | None]:
    revision = event.get("revision")
    event_id = event.get("event_id")
    return revision if type(revision) is int else None, event_id if isinstance(event_id, str) else None


def _decode_event(event: Mapping[str, Any] | bytes | bytearray | memoryview) -> Mapping[str, Any]:
    if isinstance(event, (bytes, bytearray, memoryview)):
        try:
            event = json.loads(bytes(event).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise CorruptEventLogError("schema event is not valid UTF-8 JSON") from exc
    if not isinstance(event, Mapping):
        raise CorruptEventLogError("schema event must be a JSON object")
    return event


def _future_schema(schema_version: Any) -> bool:
    if not isinstance(schema_version, str):
        return False
    try:
        major, minor = (int(part) for part in schema_version.split(".", 1))
    except (ValueError, TypeError):
        return False
    return major > 2 or (major == 2 and minor > 0)


def upcast_event(event: Mapping[str, Any] | bytes | bytearray | memoryview) -> SemanticEvent:
    """Convert one legacy or schema 2.0 event without rewriting its source."""

    source = _decode_event(event)
    schema_version = source.get("schema_version")
    revision, event_id = _location(source)
    if _future_schema(schema_version):
        raise UnsupportedFutureSchemaError(
            f"unsupported future schema version: {schema_version}",
            revision=revision,
            event_id=event_id,
        )
    if schema_version not in _KNOWN_SCHEMA_VERSIONS:
        raise CorruptEventLogError(
            "schema_version must be exactly '1.0' or '2.0'",
            revision=revision,
            event_id=event_id,
        )

    event_type = source.get("type")
    known_types = LEGACY_EVENT_TYPES if schema_version == "1.0" else SCHEMA2_EVENT_TYPES
    if not isinstance(event_type, str) or event_type not in known_types:
        raise UnknownEventTypeError(
            f"unknown schema {schema_version} event type: {event_type}",
            revision=revision,
            event_id=event_id,
        )

    payload = source.get("payload", {})
    if not isinstance(payload, Mapping):
        raise CorruptEventLogError(
            "event payload must be a JSON object",
            revision=revision,
            event_id=event_id,
        )
    generation = source.get("generation", 1)
    if type(generation) is not int:
        raise CorruptEventLogError(
            "event generation must be an integer",
            revision=revision,
            event_id=event_id,
        )
    workflow_id = source.get("workflow_id")
    if workflow_id is not None and not isinstance(workflow_id, str):
        raise CorruptEventLogError(
            "event workflow_id must be a string or null",
            revision=revision,
            event_id=event_id,
        )
    try:
        frozen_payload = _freeze(payload)
    except TypeError as exc:
        raise CorruptEventLogError(
            "event payload must contain JSON-native values",
            revision=revision,
            event_id=event_id,
        ) from exc
    return SemanticEvent(
        schema_version=schema_version,
        event_type=event_type,
        workflow_id=workflow_id,
        generation=generation,
        revision=revision,
        event_id=event_id,
        timestamp=source.get("timestamp") if isinstance(source.get("timestamp"), str) else None,
        payload=frozen_payload,
    )


def upcast_legacy_event(event: Mapping[str, Any] | bytes | bytearray | memoryview) -> SemanticEvent:
    return upcast_event(event)


__all__ = ["LEGACY_EVENT_TYPES", "SemanticEvent", "upcast_event", "upcast_legacy_event"]
