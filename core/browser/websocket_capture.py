"""Pure-data helpers for captured WebSocket traffic and deferred replay plans."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit


MAX_CAPTURE_BYTES = 256 * 1024
MAX_REPLAY_BYTES = 1024 * 1024
MAX_DIFF_DEPTH = 64
TEXT_PREVIEW_BYTES = 4096

_DIRECTION_ALIASES = {
    "in": "received",
    "incoming": "received",
    "recv": "received",
    "received": "received",
    "out": "sent",
    "outgoing": "sent",
    "send": "sent",
    "sent": "sent",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _payload_bytes(payload: Any) -> tuple[bytes, str, Any]:
    if isinstance(payload, str):
        parsed: Any = None
        try:
            parsed = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            pass
        return payload.encode("utf-8"), "text", parsed
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return bytes(payload), "binary", None
    if isinstance(payload, (Mapping, list, tuple, bool, int, float)) or payload is None:
        normalized = dict(payload) if isinstance(payload, Mapping) else payload
        text = _json_text(normalized)
        return text.encode("utf-8"), "text", normalized
    text = str(payload)
    return text.encode("utf-8"), "text", None


def _normalized_ws_url(url: str) -> str:
    parsed = urlsplit(str(url).strip())
    if parsed.scheme.lower() not in {"ws", "wss"} or not parsed.hostname:
        raise ValueError("WebSocket URL must be an absolute ws:// or wss:// URL")
    if parsed.username or parsed.password:
        raise ValueError("WebSocket URL must not contain user information")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parsed.port
    default_port = 443 if scheme == "wss" else 80
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def _web_origin(url: str) -> str:
    parsed = urlsplit(url)
    scheme = "https" if parsed.scheme == "wss" else "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def _path_for_key(parent: str, key: Any) -> str:
    if isinstance(key, str) and key.isidentifier():
        return f"{parent}.{key}"
    return f"{parent}[{json.dumps(key, ensure_ascii=False)}]"


class WebSocketCapture:
    """Normalize frames, retain bounded sequences, diff data, and gate replay."""

    def __init__(
        self,
        approval_verifier: Callable[..., Any] | Any | None = None,
        *,
        max_messages: int = 2000,
    ) -> None:
        self._approval_verifier = approval_verifier
        self.max_messages = max(1, int(max_messages))
        self.messages: list[dict[str, Any]] = []
        self.connections: list[dict[str, Any]] = []
        self._sequences: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def infer_binary_format(payload: bytes | bytearray | memoryview) -> dict[str, Any]:
        """Infer conservative framing and content hints without decoding a schema."""
        raw = bytes(payload)
        result: dict[str, Any] = {
            "encoding": "binary",
            "byte_length": len(raw),
            "length_prefix": None,
        }
        body = raw

        for width in (4, 2, 1, 8):
            if len(raw) <= width:
                continue
            for byteorder in ("big", "little"):
                declared = int.from_bytes(raw[:width], byteorder=byteorder, signed=False)
                if declared == len(raw) - width:
                    result.update(
                        {
                            "length_prefix": declared,
                            "length_prefix_bytes": width,
                            "length_prefix_endianness": byteorder,
                            "body_offset": width,
                        }
                    )
                    body = raw[width:]
                    break
            if result["length_prefix"] is not None:
                break

        signatures = (
            (b"\x1f\x8b", "gzip"),
            (b"PK\x03\x04", "zip"),
            (b"\x89PNG\r\n\x1a\n", "png"),
            (b"\xff\xd8\xff", "jpeg"),
            (b"%PDF-", "pdf"),
        )
        for signature, name in signatures:
            if body.startswith(signature):
                result["content_hint"] = name
                return result

        try:
            decoded = body.decode("utf-8")
        except UnicodeDecodeError:
            result["content_hint"] = "opaque-binary"
            result["hex_preview"] = body[:64].hex()
            return result

        result["text_preview"] = decoded[:TEXT_PREVIEW_BYTES]
        try:
            result["parsed_body"] = json.loads(decoded)
            result["content_hint"] = "json"
        except json.JSONDecodeError:
            printable = sum(character.isprintable() or character.isspace() for character in decoded)
            result["content_hint"] = (
                "utf-8-text" if not decoded or printable / len(decoded) >= 0.9 else "utf-8-binary"
            )
        return result

    def normalize_message(
        self,
        *,
        direction: str,
        payload: Any,
        timestamp: float | int | str | None = None,
        connection_url: str | None = None,
    ) -> dict[str, Any]:
        """Return a JSON-safe, size-bounded representation of one frame."""
        normalized_direction = _DIRECTION_ALIASES.get(str(direction).strip().lower())
        if normalized_direction is None:
            raise ValueError("direction must describe a sent or received message")

        raw, message_type, parsed = _payload_bytes(payload)
        captured = raw[:MAX_CAPTURE_BYTES]
        result: dict[str, Any] = {
            "direction": normalized_direction,
            "timestamp": _utc_now() if timestamp is None else timestamp,
            "message_type": message_type,
            "byte_length": len(raw),
            "truncated": len(raw) > len(captured),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        if connection_url is not None:
            result["url"] = _normalized_ws_url(connection_url)

        if message_type == "text":
            text = captured.decode("utf-8", errors="replace")
            result["content"] = text
            result["parsed"] = parsed
            result["format"] = {
                "encoding": "utf-8",
                "content_hint": "json" if parsed is not None else "text",
            }
        else:
            result["content_base64"] = base64.b64encode(captured).decode("ascii")
            result["parsed"] = None
            result["format"] = self.infer_binary_format(raw)
        return result

    def record_message(self, **message: Any) -> dict[str, Any]:
        normalized = self.normalize_message(**message)
        self.messages.append(normalized)
        if len(self.messages) > self.max_messages:
            del self.messages[: len(self.messages) - self.max_messages]
        return deepcopy(normalized)

    def record_connection(
        self,
        url: str,
        *,
        subprotocol: str | None = None,
        timestamp: float | int | str | None = None,
    ) -> dict[str, Any]:
        connection = {
            "url": _normalized_ws_url(url),
            "subprotocol": str(subprotocol or ""),
            "timestamp": _utc_now() if timestamp is None else timestamp,
        }
        self.connections.append(connection)
        return deepcopy(connection)

    def save_sequence(
        self,
        name: str,
        messages: Sequence[Mapping[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        normalized_name = str(name).strip()
        if not normalized_name:
            raise ValueError("sequence name is required")
        source = self.messages if messages is None else messages
        sequence = [deepcopy(dict(item)) for item in source]
        self._sequences[normalized_name] = sequence
        return deepcopy(sequence)

    def get_sequence(self, name: str) -> list[dict[str, Any]]:
        normalized_name = str(name).strip()
        if normalized_name not in self._sequences:
            raise KeyError(f"unknown WebSocket sequence: {normalized_name}")
        return deepcopy(self._sequences[normalized_name])

    @staticmethod
    def compare(before: Any, after: Any) -> dict[str, Any]:
        """Return a deterministic structural diff suitable for evidence records."""
        before = WebSocketCapture._structured_value(before)
        after = WebSocketCapture._structured_value(after)
        added: set[str] = set()
        removed: set[str] = set()
        changed: set[str] = set()
        changes: list[dict[str, Any]] = []

        def walk(left: Any, right: Any, path: str, depth: int) -> None:
            if depth > MAX_DIFF_DEPTH:
                changed.add(path)
                changes.append({"path": path, "kind": "depth-limit"})
                return
            if type(left) is not type(right):
                changed.add(path)
                changes.append(
                    {
                        "path": path,
                        "kind": "type-changed",
                        "before_type": type(left).__name__,
                        "after_type": type(right).__name__,
                    }
                )
                return
            if isinstance(left, Mapping):
                left_keys = set(left)
                right_keys = set(right)
                for key in sorted(right_keys - left_keys, key=str):
                    child = _path_for_key(path, key)
                    added.add(child)
                    changes.append({"path": child, "kind": "added", "after": right[key]})
                for key in sorted(left_keys - right_keys, key=str):
                    child = _path_for_key(path, key)
                    removed.add(child)
                    changes.append({"path": child, "kind": "removed", "before": left[key]})
                for key in sorted(left_keys & right_keys, key=str):
                    walk(left[key], right[key], _path_for_key(path, key), depth + 1)
                return
            if isinstance(left, list):
                if len(left) != len(right):
                    changed.add(path)
                    changes.append(
                        {
                            "path": path,
                            "kind": "length-changed",
                            "before_length": len(left),
                            "after_length": len(right),
                        }
                    )
                for index, (left_item, right_item) in enumerate(zip(left, right)):
                    walk(left_item, right_item, f"{path}[{index}]", depth + 1)
                return
            if left != right:
                changed.add(path)
                changes.append({"path": path, "kind": "changed", "before": left, "after": right})

        walk(before, after, "$", 0)
        return {
            "changed": bool(added or removed or changed),
            "added_paths": sorted(added),
            "removed_paths": sorted(removed),
            "changed_paths": sorted(changed),
            "changes": changes,
        }

    def replay_plan(
        self,
        url: str,
        payload: Any,
        *,
        approved: bool = False,
        allowed_origins: Sequence[str] | None = None,
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        """Build a deferred replay descriptor only after independent verification."""
        normalized_url = _normalized_ws_url(url)
        raw, message_type, _ = _payload_bytes(payload)
        if len(raw) > MAX_REPLAY_BYTES:
            raise ValueError(f"WebSocket replay payload exceeds {MAX_REPLAY_BYTES} bytes")

        digest = hashlib.sha256(raw).hexdigest()
        context = {
            "action": "websocket-replay",
            "url": normalized_url,
            "origin": _web_origin(normalized_url),
            "payload_sha256": digest,
            "payload_size": len(raw),
            "message_type": message_type,
        }
        blocked = {
            "backend": "playwright-mcp",
            "mode": "external-mcp-handoff",
            "operation": "websocket_replay",
            "status": "approval-required",
            "execution": "deferred",
            "requires_confirmation": True,
            "reason": "independent-approval-required",
            "approval_context": context,
            "caller_approval_ignored": bool(approved),
            "caller_allowed_origins_ignored": bool(allowed_origins),
        }
        if self._approval_verifier is None or not approval_token:
            return blocked

        verification = self._verify_approval(approval_token, context)
        if not self._verification_allows(verification, context):
            blocked["reason"] = "independent-approval-rejected"
            return blocked

        if message_type == "binary":
            replay_payload: dict[str, Any] = {
                "type": "binary",
                "base64": base64.b64encode(raw).decode("ascii"),
            }
        else:
            replay_payload = {
                "type": "text",
                "text": raw.decode("utf-8"),
            }

        function = (
            "({url, payload}) => {"
            "const sockets = Array.from(window.__hunterWebSockets || []);"
            "const socket = sockets.find((item) => item && item.url === url && item.readyState === 1);"
            "if (!socket) throw new Error('No open approved WebSocket matches the URL');"
            "const data = payload.type === 'binary'"
            " ? Uint8Array.from(atob(payload.base64), (char) => char.charCodeAt(0))"
            " : payload.text;"
            "socket.send(data);"
            "return {sent: true, url, byteLength: payload.type === 'binary' ? data.byteLength : data.length};"
            "}"
        )
        return {
            "backend": "playwright-mcp",
            "mode": "external-mcp-handoff",
            "operation": "websocket_replay",
            "status": "ready",
            "execution": "deferred",
            "requires_confirmation": False,
            "approval_context": context,
            "approval": self._approval_summary(verification),
            "calls": [
                {
                    "tool": "browser_evaluate",
                    "arguments": {
                        "function": function,
                        "argument": {
                            "url": normalized_url,
                            "payload": replay_payload,
                        },
                    },
                }
            ],
        }

    def _verify_approval(self, token: str, context: Mapping[str, Any]) -> Any:
        verifier = self._approval_verifier
        target = verifier.verify if hasattr(verifier, "verify") else verifier
        if not callable(target):
            return False
        try:
            return target(token=token, context=dict(context))
        except TypeError:
            try:
                return target(token, dict(context))
            except Exception:
                return False
        except Exception:
            return False

    @staticmethod
    def _verification_allows(verification: Any, context: Mapping[str, Any]) -> bool:
        if verification is True:
            return True
        if not isinstance(verification, Mapping):
            return False
        if not bool(verification.get("approved", verification.get("valid", False))):
            return False
        for field in ("action", "url", "origin", "payload_sha256"):
            asserted = verification.get(field)
            if asserted is not None and asserted != context[field]:
                return False
        origins = verification.get("allowed_origins")
        if origins is not None and context["origin"] not in {str(item) for item in origins}:
            return False
        expires_at = verification.get("expires_at")
        if expires_at is not None and WebSocketCapture._is_expired(expires_at):
            return False
        return True

    @staticmethod
    def _is_expired(expires_at: Any) -> bool:
        try:
            if isinstance(expires_at, (int, float)):
                expiry = datetime.fromtimestamp(float(expires_at), tz=timezone.utc)
            else:
                text = str(expires_at).replace("Z", "+00:00")
                expiry = datetime.fromisoformat(text)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
            return expiry <= datetime.now(timezone.utc)
        except (TypeError, ValueError, OSError):
            return True

    @staticmethod
    def _approval_summary(verification: Any) -> dict[str, Any]:
        if verification is True:
            return {"approved": True, "verifier": "trusted"}
        allowed = {
            "approval_id",
            "approved",
            "valid",
            "action",
            "url",
            "origin",
            "payload_sha256",
            "expires_at",
        }
        return {
            str(key): value
            for key, value in dict(verification).items()
            if str(key) in allowed
        }

    @staticmethod
    def _structured_value(value: Any) -> Any:
        if isinstance(value, Mapping):
            if "message_type" in value and "parsed" in value and value.get("parsed") is not None:
                return value["parsed"]
            return dict(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            try:
                value = bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                return {"base64": base64.b64encode(bytes(value)).decode("ascii")}
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        if isinstance(value, tuple):
            return list(value)
        return value
