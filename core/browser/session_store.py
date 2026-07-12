"""Persistent, encrypted storage for deferred browser observations."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable
from urllib.parse import urlparse

from core.session.secret_store import SecretStore


HOOK_PREFIX = "__HUNTER_HOOK__"
MAX_RECORDS = 2000
MAX_STRING = 8192
SENSITIVE_KEYS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(marker in lowered for marker in SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value[:200]]
    if isinstance(value, str):
        return value[:MAX_STRING]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:MAX_STRING]


class BrowserSessionStore:
    """Store public browser state and encrypted hook records on disk."""

    def __init__(self, storage_dir: str | Path) -> None:
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.secret_store = SecretStore(self.storage_dir)

    def _path(self, session_id: str) -> Path:
        normalized = str(session_id).strip()
        if not normalized or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in normalized):
            raise ValueError("invalid browser session id")
        path = (self.storage_dir / f"{normalized}.json").resolve()
        if path.parent != self.storage_dir:
            raise ValueError("browser session path escaped storage directory")
        return path

    @staticmethod
    def _validate_target(target: str) -> str:
        parsed = urlparse(str(target).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("browser target must be an absolute http(s) URL")
        return parsed.geturl()

    def create(self, target: str) -> Dict[str, Any]:
        now = _now()
        session = {
            "session_id": f"browser-{uuid.uuid4().hex}",
            "target": self._validate_target(target),
            "current_url": str(target),
            "title": "",
            "forms": [],
            "links": [],
            "network_requests": [],
            "hook_results": [],
            "created_at": now,
            "updated_at": now,
        }
        self._write(session)
        return session

    def get(self, session_id: str) -> Dict[str, Any]:
        path = self._path(session_id)
        if not path.is_file():
            raise KeyError(f"unknown browser session: {session_id}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        sealed = payload.pop("hook_results_secret", "")
        payload["hook_results"] = self.secret_store.open(sealed) if sealed else []
        return payload

    def update(self, session_id: str, **changes: Any) -> Dict[str, Any]:
        session = self.get(session_id)
        allowed = {
            "current_url",
            "title",
            "forms",
            "links",
            "network_requests",
            "last_plan",
        }
        for key, value in changes.items():
            if key in allowed:
                session[key] = _redact(value, key)
        session["updated_at"] = _now()
        self._write(session)
        return session

    def ingest_console(
        self,
        session_id: str,
        console_messages: Iterable[str],
    ) -> Dict[str, Any]:
        session = self.get(session_id)
        accepted = 0
        rejected = 0
        records = list(session.get("hook_results", []))
        for message in console_messages:
            text = str(message)
            if not text.startswith(HOOK_PREFIX):
                continue
            try:
                parsed = json.loads(text[len(HOOK_PREFIX):])
                if not isinstance(parsed, dict):
                    raise ValueError("hook record must be an object")
                records.append(_redact(parsed))
                accepted += 1
            except (json.JSONDecodeError, ValueError, TypeError):
                rejected += 1
        session["hook_results"] = records[-MAX_RECORDS:]
        session["updated_at"] = _now()
        self._write(session)
        return {
            "browser_session_id": session_id,
            "accepted": accepted,
            "rejected": rejected,
            "total": len(session["hook_results"]),
            "hook_results": session["hook_results"],
        }

    def _write(self, session: Dict[str, Any]) -> None:
        public = dict(session)
        hook_results = public.pop("hook_results", [])
        public["hook_results_secret"] = self.secret_store.seal(hook_results)
        path = self._path(str(public["session_id"]))
        temporary = path.with_suffix(f".{uuid.uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(public, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
