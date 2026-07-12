"""Authenticated encryption for persisted attack-session secrets."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError as exc:  # pragma: no cover - enforced by CI dependency
    raise RuntimeError(
        "cryptography is required for encrypted AttackSession persistence"
    ) from exc


class SecretStore:
    def __init__(self, storage_dir: str | Path) -> None:
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.storage_dir / ".attack-session.key"
        self._fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        temporary = self.key_path.with_suffix(f".{uuid.uuid4().hex}.tmp")
        temporary.write_bytes(key + b"\n")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.key_path)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return key

    def seal(self, value: Any) -> str:
        payload = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return self._fernet.encrypt(payload).decode("ascii")

    def open(self, token: str) -> Any:
        try:
            payload = self._fernet.decrypt(token.encode("ascii"))
        except (InvalidToken, ValueError) as exc:
            raise ValueError("attack-session secret payload failed authentication") from exc
        return json.loads(payload.decode("utf-8"))
