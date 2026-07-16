from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_MAX_MESSAGE_LENGTH = 512
_REDACTED = "[REDACTED]"
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?P<prefix>[\"']?(?:password|passphrase|api[_-]?key|x-api-key|"
    r"access[_-]?token|refresh[_-]?token|secret[_-]?key|auth[_-]?token)"
    r"[\"']?\s*[:=]\s*[\"']?)(?P<value>[^\"'\s;,}]+)",
    re.IGNORECASE,
)
_AUTHORIZATION_BEARER = re.compile(
    r"(?P<prefix>authorization\s*:\s*bearer\s+)(?P<value>[^\s;,]+)",
    re.IGNORECASE,
)
_COOKIE_HEADER = re.compile(
    r"(?P<prefix>cookie\s*:\s*)(?P<value>[^\r\n]+)",
    re.IGNORECASE,
)


def _redact_sensitive_text(text: str) -> str:
    text = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", text)
    text = _AUTHORIZATION_BEARER.sub(
        lambda match: match.group("prefix") + _REDACTED,
        text,
    )
    text = _COOKIE_HEADER.sub(
        lambda match: match.group("prefix") + _REDACTED,
        text,
    )
    return _SENSITIVE_ASSIGNMENT.sub(
        lambda match: match.group("prefix") + _REDACTED,
        text,
    )


def _safe_message(message: Any) -> str:
    try:
        text = str(message)
    except Exception:
        text = "event kernel error"
    text = text.encode("utf-8", errors="backslashreplace").decode("utf-8")
    return _redact_sensitive_text(text)[:_MAX_MESSAGE_LENGTH]


class EventKernelError(Exception):
    code = "event_kernel_error"

    def __init__(
        self,
        message: str,
        *,
        slug: str = "",
        revision: int | None = None,
        event_id: str | None = None,
    ) -> None:
        self.message = _safe_message(message)
        self.slug = slug
        self.revision = revision
        self.event_id = event_id
        super().__init__(self.message)


class WorkflowNotFoundError(EventKernelError):
    code = "workflow_not_found"


class InvalidCommandError(EventKernelError):
    code = "invalid_command"


class ConcurrencyConflictError(EventKernelError):
    code = "concurrency_conflict"


class CommandConflictError(EventKernelError):
    code = "command_conflict"


class DuplicateCommittedCommandError(EventKernelError):
    code = "duplicate_committed_command"


class WorkflowAlreadyClaimedError(EventKernelError):
    code = "workflow_already_claimed"


class OwnershipClaimRequiredError(EventKernelError):
    code = "ownership_claim_required"


class MixedWriterError(EventKernelError):
    code = "mixed_writer"


class CorruptEventLogError(EventKernelError):
    code = "corrupt_event_log"


class UnknownEventTypeError(EventKernelError):
    code = "unknown_event_type"


class UnsupportedFutureSchemaError(EventKernelError):
    code = "unsupported_future_schema"


class DuplicateEventIdError(EventKernelError):
    code = "duplicate_event_id"


class IllegalTransitionError(EventKernelError):
    code = "illegal_transition"


class EvidenceAttestationError(EventKernelError):
    code = "evidence_attestation"


class OutboxConflictError(EventKernelError):
    code = "outbox_conflict"


class SensitiveOutputRejectedError(EventKernelError):
    code = "sensitive_output_rejected"


class CheckpointBindingError(EventKernelError):
    code = "checkpoint_binding"


class RecoveryNotAuthorizedError(EventKernelError):
    code = "recovery_not_authorized"


_ISSUE_ERRORS = {
    "unknown_event": UnknownEventTypeError,
    "future_schema": UnsupportedFutureSchemaError,
    "corrupt_chain": CorruptEventLogError,
    "duplicate_event": DuplicateEventIdError,
    "duplicate_command": DuplicateCommittedCommandError,
    "command_conflict": CommandConflictError,
    "ownership_claim_required": OwnershipClaimRequiredError,
    "illegal_transition": IllegalTransitionError,
    "mixed_writer": MixedWriterError,
}


def issue_to_error(issue: Any, *, slug: str = "") -> EventKernelError:
    def field(name: str, default: Any = None) -> Any:
        if isinstance(issue, Mapping):
            return issue.get(name, default)
        return getattr(issue, name, default)

    error_type = _ISSUE_ERRORS.get(field("kind"), CorruptEventLogError)
    return error_type(
        field("message", ""),
        slug=slug,
        revision=field("revision"),
        event_id=field("event_id"),
    )


__all__ = [
    "CheckpointBindingError",
    "CommandConflictError",
    "ConcurrencyConflictError",
    "CorruptEventLogError",
    "DuplicateCommittedCommandError",
    "DuplicateEventIdError",
    "EventKernelError",
    "EvidenceAttestationError",
    "IllegalTransitionError",
    "InvalidCommandError",
    "MixedWriterError",
    "OutboxConflictError",
    "OwnershipClaimRequiredError",
    "RecoveryNotAuthorizedError",
    "SensitiveOutputRejectedError",
    "UnknownEventTypeError",
    "UnsupportedFutureSchemaError",
    "WorkflowAlreadyClaimedError",
    "WorkflowNotFoundError",
    "issue_to_error",
]
