"""Persistent target-specific facts shared across assessment sessions."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_STORAGE_DIR = Path(r"D:\Open-tgtylab\data\blackboards")


class Blackboard:
    def __init__(self, target: str, storage_dir: str | Path | None = None) -> None:
        self.target = target
        self.storage_dir = Path(storage_dir) if storage_dir is not None else DEFAULT_STORAGE_DIR
        target_hash = hashlib.sha1(target.encode("utf-8")).hexdigest()
        self.path = self.storage_dir / f"{target_hash}.json"
        self.facts: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.is_file():
            return {}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"invalid blackboard data in {self.path}")
        return data

    def _save(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(self.facts, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self.path)

    def upsert(self, key: str, value: Any) -> None:
        self.facts[key] = {"value": value, "timestamp": time.time()}
        self._save()

    def get(self, key: str) -> Any | None:
        fact = self.facts.get(key)
        return fact.get("value") if fact is not None else None

    def list(self) -> list[tuple[str, Any, float]]:
        ordered = sorted(
            self.facts.items(),
            key=lambda item: (item[1].get("timestamp", 0), item[0]),
        )
        return [
            (key, fact.get("value"), fact.get("timestamp", 0))
            for key, fact in ordered
        ]

    def as_context(self) -> str:
        if not self.facts:
            return ""
        lines = [f"[FACTS \u2014 {self._target_name()}]"]
        lines.extend(f"{key}: {value}" for key, value, _ in self.list())
        return "\n".join(lines)

    def _target_name(self) -> str:
        parsed = urlparse(self.target if "://" in self.target else f"//{self.target}")
        return parsed.hostname or self.target


class BoardRegistry:
    _instance: BoardRegistry | None = None
    _boards: dict[tuple[str, str], Blackboard] = {}

    def __new__(cls) -> BoardRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get(
        cls, target: str, storage_dir: str | Path | None = None
    ) -> Blackboard:
        directory = Path(storage_dir) if storage_dir is not None else DEFAULT_STORAGE_DIR
        registry_key = (target, str(directory.resolve()))
        if registry_key not in cls._boards:
            cls._boards[registry_key] = Blackboard(target, storage_dir=directory)
        return cls._boards[registry_key]
