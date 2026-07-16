from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


_MODE_LIMITS = {"discover": 1024, "probe": 8192, "verify": 262144, "race": 262144, "oast": 262144}
_RETENTION_SECONDS = {"telemetry": 7 * 86400, "inconclusive": 30 * 86400, "refuted": 30 * 86400, "verified": 180 * 86400}


@dataclass(frozen=True)
class ArtifactWrite:
    digest: str
    path: str
    stored: bool
    sample_bytes: int
    reason: str = ""


class ArtifactStore:
    """Content-addressed, quota-aware storage for Broker observations."""

    def __init__(
        self,
        root: str | Path,
        *,
        quota_bytes: int = 500 * 1024 * 1024,
        target_quota_bytes: int = 100 * 1024 * 1024,
        telemetry_retention_seconds: int = _RETENTION_SECONDS["telemetry"],
        now: Callable[[], float] = time.time,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.quota_bytes = int(quota_bytes)
        self.target_quota_bytes = int(target_quota_bytes)
        self.telemetry_retention_seconds = int(telemetry_retention_seconds)
        self.now = now
        self.db = sqlite3.connect(self.root / "artifacts.sqlite")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS artifacts (digest TEXT PRIMARY KEY, path TEXT NOT NULL, bytes INTEGER NOT NULL, mode TEXT NOT NULL, created_at REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS artifact_policy (digest TEXT PRIMARY KEY, target_id TEXT NOT NULL, retention TEXT NOT NULL, protected INTEGER NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS artifact_references (digest TEXT NOT NULL, reference_type TEXT NOT NULL, reference_id TEXT NOT NULL, PRIMARY KEY(digest, reference_type, reference_id))"
        )
        self.db.commit()

    def used_bytes(self) -> int:
        row = self.db.execute("SELECT COALESCE(SUM(bytes), 0) FROM artifacts").fetchone()
        return int(row[0] or 0)

    def target_used_bytes(self, target_id: str) -> int:
        row = self.db.execute(
            "SELECT COALESCE(SUM(a.bytes), 0) FROM artifacts a JOIN artifact_policy p ON p.digest=a.digest WHERE p.target_id=?",
            (target_id,),
        ).fetchone()
        return int(row[0] or 0)

    def add_reference(self, digest: str, reference_type: str, reference_id: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO artifact_references(digest,reference_type,reference_id) VALUES(?,?,?)",
            (digest, reference_type, reference_id),
        )
        self.db.commit()

    def register_event_kernel_manifest(self, digest: str, manifest_id: str) -> None:
        """Pin an artifact referenced by a finalized Event Kernel attempt manifest."""
        self.add_reference(digest, "event_kernel_manifest", manifest_id)

    def collect_garbage(self) -> list[str]:
        now = self.now()
        rows = self.db.execute(
            """SELECT a.digest,a.path,a.created_at,p.retention,p.protected,
            EXISTS(SELECT 1 FROM artifact_references r WHERE r.digest=a.digest)
            FROM artifacts a JOIN artifact_policy p ON p.digest=a.digest"""
        ).fetchall()
        removed: list[str] = []
        for digest, path, created_at, retention, protected, referenced in rows:
            limit = self.telemetry_retention_seconds if retention == "telemetry" else _RETENTION_SECONDS.get(retention, _RETENTION_SECONDS["telemetry"])
            if protected or referenced or now - float(created_at) < limit:
                continue
            Path(path).unlink(missing_ok=True)
            self.db.execute("DELETE FROM artifacts WHERE digest=?", (digest,))
            self.db.execute("DELETE FROM artifact_policy WHERE digest=?", (digest,))
            self.db.execute("DELETE FROM artifact_references WHERE digest=?", (digest,))
            removed.append(digest)
        self.db.commit()
        return removed

    def write(
        self,
        observation: dict[str, Any],
        *,
        mode: str,
        target_id: str = "global",
        retention: str | None = None,
        protected: bool = False,
    ) -> ArtifactWrite:
        if mode not in _MODE_LIMITS:
            raise ValueError("unknown artifact mode")
        retention = retention or ("telemetry" if mode == "discover" else "verified" if mode in {"verify", "race", "oast"} else "inconclusive")
        if retention not in _RETENTION_SECONDS:
            raise ValueError("unknown retention class")
        value = dict(observation)
        body = str(value.get("body", ""))
        value["body"] = body[: _MODE_LIMITS[mode]]
        value["body_truncated"] = len(body) > len(value["body"])
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        existing = self.db.execute("SELECT path FROM artifacts WHERE digest=?", (digest,)).fetchone()
        if existing:
            return ArtifactWrite(digest, existing[0], True, len(value["body"]))
        compressed = gzip.compress(encoded, compresslevel=6)
        if self.used_bytes() >= int(self.quota_bytes * 0.8):
            self.collect_garbage()
        if mode == "discover" and self.target_used_bytes(target_id) + len(compressed) > self.target_quota_bytes:
            return ArtifactWrite(digest, "", False, len(value["body"]), "target_quota_exhausted")
        if mode == "discover" and self.used_bytes() + len(compressed) > self.quota_bytes:
            return ArtifactWrite(digest, "", False, len(value["body"]), "quota_exhausted")
        path = self.root / f"{digest}.json.gz"
        path.write_bytes(compressed)
        self.db.execute(
            "INSERT INTO artifacts(digest,path,bytes,mode,created_at) VALUES(?,?,?,?,?)",
            (digest, str(path), len(compressed), mode, self.now()),
        )
        self.db.execute(
            "INSERT INTO artifact_policy(digest,target_id,retention,protected) VALUES(?,?,?,?)",
            (digest, target_id, retention, int(protected)),
        )
        self.db.commit()
        return ArtifactWrite(digest, str(path), True, len(value["body"]))
