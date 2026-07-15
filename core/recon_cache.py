"""Persistent target/profile cache for adaptive scans."""
from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_LOCKS_GUARD = threading.Lock()
_KEY_LOCKS: dict[str, threading.RLock] = {}


class ReconCache:
    def __init__(self, root: str | Path, default_ttl_s: int = 1800):
        self.root = Path(root)
        self.default_ttl_s = int(default_ttl_s)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def normalize_target(target: str) -> str:
        raw = target.strip()
        if "://" not in raw:
            raw = "https://" + raw
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        port = f":{parts.port}" if parts.port else ""
        path = parts.path.rstrip("/") or "/"
        return urlunsplit((parts.scheme.lower(), host + port, path, parts.query, ""))

    def key(self, target: str, profile: str, plan_signature: str = "") -> str:
        value = f"{self.normalize_target(target)}\n{profile.lower()}\n{plan_signature}"
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def _lock(self, key: str) -> threading.RLock:
        lock_key = f"{self.root.resolve()}::{key}"
        with _LOCKS_GUARD:
            return _KEY_LOCKS.setdefault(lock_key, threading.RLock())

    def get(self, target: str, profile: str, plan_signature: str = "", ttl_s: int | None = None) -> dict[str, Any] | None:
        key = self.key(target, profile, plan_signature)
        path = self._path(key)
        with self._lock(key):
            if not path.exists():
                return None
            try:
                record = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                return None
            ttl = self.default_ttl_s if ttl_s is None else int(ttl_s)
            if ttl >= 0 and time.time() - float(record.get("created_at", 0)) > ttl:
                path.unlink(missing_ok=True)
                return None
            record["cache_path"] = str(path)
            return record

    def put(self, target: str, profile: str, data: dict[str, Any], plan_signature: str = "") -> Path:
        key = self.key(target, profile, plan_signature)
        path = self._path(key)
        record = {"key": key, "target": self.normalize_target(target), "profile": profile, "created_at": time.time(), "data": data}
        temp = self.root / f"{key}.{uuid.uuid4().hex}.tmp"
        with self._lock(key):
            try:
                temp.write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
                temp.replace(path)
            finally:
                temp.unlink(missing_ok=True)
        return path

    def status(self) -> dict[str, Any]:
        entries = []
        total = 0
        for path in sorted(self.root.glob("*.json")):
            size = path.stat().st_size
            total += size
            try:
                record = json.loads(path.read_text(encoding="utf-8-sig"))
                entries.append({"key": record.get("key", path.stem), "target": record.get("target"), "profile": record.get("profile"), "age_s": round(time.time() - float(record.get("created_at", 0)), 3), "bytes": size})
            except Exception:
                entries.append({"key": path.stem, "invalid": True, "bytes": size})
        return {"root": str(self.root), "entries": entries, "count": len(entries), "bytes": total, "default_ttl_s": self.default_ttl_s}

    def clear(self, target: str = "", profile: str = "") -> dict[str, Any]:
        removed = []
        normalized = self.normalize_target(target) if target else ""
        for path in self.root.glob("*.json"):
            remove = not target and not profile
            if not remove:
                try:
                    record = json.loads(path.read_text(encoding="utf-8-sig"))
                    remove = (not normalized or record.get("target") == normalized) and (not profile or record.get("profile") == profile)
                except Exception:
                    remove = not target and not profile
            if remove:
                removed.append(str(path))
                path.unlink(missing_ok=True)
        return {"removed": len(removed), "paths": removed, "remaining": self.status()["count"]}
