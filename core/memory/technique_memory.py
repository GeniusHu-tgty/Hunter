"""SQLite-backed attack technique effectiveness tracking."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


DEFAULT_DB_PATH = Path(r"D:\Open-tgtylab\data\targets.db")
ALL_WAF_TYPES = "*"


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _json_load(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    declaration: str,
) -> None:
    existing = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in existing:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        )


class TechniqueMemory:
    """Record attack attempts and rank techniques by observed effectiveness."""

    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB_PATH,
        *,
        initialize: bool = True,
        read_only: bool = False,
    ):
        self.db_path = Path(db_path).expanduser().resolve()
        self.read_only = bool(read_only)
        if initialize and not self.read_only:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        if self.read_only:
            connection = sqlite3.connect(
                f"{self.db_path.as_uri()}?mode=ro",
                timeout=30,
                factory=_ClosingConnection,
                uri=True,
            )
        else:
            connection = sqlite3.connect(
                self.db_path,
                timeout=30,
                factory=_ClosingConnection,
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialize_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS techniques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_techniques_type
            ON techniques(type, active);

        CREATE TABLE IF NOT EXISTS technique_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            technique_id INTEGER NOT NULL,
            waf_type TEXT NOT NULL DEFAULT '',
            success INTEGER NOT NULL,
            attempted_at TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}',
            notes TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(technique_id) REFERENCES techniques(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_technique_attempts_lookup
            ON technique_attempts(technique_id, waf_type, attempted_at);

        CREATE TABLE IF NOT EXISTS technique_stats (
            technique_id INTEGER NOT NULL,
            waf_type TEXT NOT NULL,
            total_attempts INTEGER NOT NULL DEFAULT 0,
            successful_attempts INTEGER NOT NULL DEFAULT 0,
            success_rate REAL NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(technique_id, waf_type),
            FOREIGN KEY(technique_id) REFERENCES techniques(id) ON DELETE CASCADE
        );
        """
        with self._connect() as connection:
            connection.executescript(schema)
            _ensure_column(
                connection,
                "technique_attempts",
                "transport_success",
                "INTEGER NOT NULL DEFAULT 0",
            )
            _ensure_column(
                connection,
                "technique_attempts",
                "probe_executed",
                "INTEGER NOT NULL DEFAULT 0",
            )
            _ensure_column(
                connection,
                "technique_attempts",
                "signal_detected",
                "INTEGER NOT NULL DEFAULT 0",
            )
            _ensure_column(
                connection,
                "technique_attempts",
                "vulnerability_confirmed",
                "INTEGER NOT NULL DEFAULT 0",
            )
            _ensure_column(
                connection,
                "technique_attempts",
                "verdict",
                "TEXT NOT NULL DEFAULT 'inconclusive'",
            )
            _ensure_column(
                connection,
                "technique_attempts",
                "outcome",
                "TEXT NOT NULL DEFAULT 'unknown'",
            )

    def register_technique(
        self,
        name: str,
        technique_type: str,
        description: str = "",
    ) -> dict[str, Any]:
        normalized_name = str(name).strip()
        if not normalized_name:
            raise ValueError("technique name must not be empty")
        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO techniques(
                    name, type, description, active, created_at, updated_at
                )
                VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    type = excluded.type,
                    description = CASE
                        WHEN excluded.description = '' THEN techniques.description
                        ELSE excluded.description
                    END,
                    active = 1,
                    updated_at = excluded.updated_at
                """,
                (
                    normalized_name,
                    str(technique_type).strip().lower() or "unknown",
                    str(description or ""),
                    now,
                    now,
                ),
            )
        technique = self.query_technique(normalized_name)
        if technique is None:
            raise RuntimeError("failed to register technique")
        return technique

    def _technique_id(
        self,
        connection: sqlite3.Connection,
        name: str,
    ) -> int:
        row = connection.execute(
            "SELECT id FROM techniques WHERE name = ?",
            (name,),
        ).fetchone()
        if row is not None:
            return int(row["id"])
        now = _utc_now()
        cursor = connection.execute(
            """
            INSERT INTO techniques(
                name, type, description, active, created_at, updated_at
            )
            VALUES (?, 'unknown', 'Automatically learned from an attempt.', 1, ?, ?)
            """,
            (name, now, now),
        )
        return int(cursor.lastrowid)

    def record_attempt(
        self,
        *,
        target_url: str,
        technique_name: str,
        waf_type: str | None = None,
        success: bool | None = None,
        transport_success: bool = False,
        probe_executed: bool = False,
        signal_detected: bool = False,
        vulnerability_confirmed: bool | None = None,
        verdict: str = "inconclusive",
        outcome: str = "unknown",
        attempted_at: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        notes: str = "",
    ) -> dict[str, Any]:
        normalized_name = str(technique_name).strip()
        if not normalized_name:
            raise ValueError("technique_name must not be empty")
        normalized_target = str(target_url).strip()
        if not normalized_target:
            raise ValueError("target_url must not be empty")
        normalized_waf = str(waf_type or "").strip()
        confirmed = (
            bool(success)
            if vulnerability_confirmed is None
            else bool(vulnerability_confirmed)
        )
        normalized_verdict = str(verdict or "inconclusive").strip().lower()
        if (
            normalized_verdict == "inconclusive"
            and vulnerability_confirmed is None
            and success is not None
        ):
            normalized_verdict = "verified" if confirmed else "refuted"
        timestamp = attempted_at or _utc_now()
        with self._connect() as connection:
            technique_id = self._technique_id(connection, normalized_name)
            cursor = connection.execute(
                """
                INSERT INTO technique_attempts(
                    target_url, technique_id, waf_type, success,
                    attempted_at, metadata, notes,
                    transport_success, probe_executed, signal_detected,
                    vulnerability_confirmed, verdict, outcome
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_target,
                    technique_id,
                    normalized_waf,
                    int(confirmed),
                    timestamp,
                    _json_dump(dict(metadata or {})),
                    str(notes or ""),
                    int(bool(transport_success)),
                    int(bool(probe_executed)),
                    int(bool(signal_detected)),
                    int(confirmed),
                    normalized_verdict,
                    str(outcome or "unknown").strip().lower(),
                ),
            )
            self._refresh_stat(connection, technique_id, ALL_WAF_TYPES)
            if normalized_waf:
                self._refresh_stat(connection, technique_id, normalized_waf)
            attempt_id = int(cursor.lastrowid)
            row = connection.execute(
                """
                SELECT a.*, t.name AS technique_name, t.type AS technique_type
                FROM technique_attempts AS a
                JOIN techniques AS t ON t.id = a.technique_id
                WHERE a.id = ?
                """,
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("failed to record technique attempt")
        return self._decode_attempt(row)

    @staticmethod
    def _refresh_stat(
        connection: sqlite3.Connection,
        technique_id: int,
        waf_type: str,
    ) -> None:
        if waf_type == ALL_WAF_TYPES:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(vulnerability_confirmed), 0) AS successful
                FROM technique_attempts
                WHERE technique_id = ?
                """,
                (technique_id,),
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(vulnerability_confirmed), 0) AS successful
                FROM technique_attempts
                WHERE technique_id = ? AND lower(waf_type) = lower(?)
                """,
                (technique_id, waf_type),
            ).fetchone()
        total = int(row["total"])
        successful = int(row["successful"])
        rate = successful / total if total else 0.0
        connection.execute(
            """
            INSERT INTO technique_stats(
                technique_id, waf_type, total_attempts, successful_attempts,
                success_rate, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(technique_id, waf_type) DO UPDATE SET
                total_attempts = excluded.total_attempts,
                successful_attempts = excluded.successful_attempts,
                success_rate = excluded.success_rate,
                updated_at = excluded.updated_at
            """,
            (technique_id, waf_type, total, successful, rate, _utc_now()),
        )

    def query_technique(self, name: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT t.*, s.total_attempts, s.successful_attempts,
                       s.success_rate
                FROM techniques AS t
                LEFT JOIN technique_stats AS s
                  ON s.technique_id = t.id AND s.waf_type = ?
                WHERE t.name = ?
                """,
                (ALL_WAF_TYPES, str(name).strip()),
            ).fetchone()
        return self._decode_technique(row) if row is not None else None

    def best_for_waf(
        self,
        waf_type: str,
        *,
        limit: int = 10,
        include_retired: bool = False,
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT t.*, s.waf_type, s.total_attempts,
                       s.successful_attempts, s.success_rate
                FROM technique_stats AS s
                JOIN techniques AS t ON t.id = s.technique_id
                WHERE lower(s.waf_type) = lower(?)
                  AND (? = 1 OR t.active = 1)
                ORDER BY s.success_rate DESC,
                         s.successful_attempts DESC,
                         s.total_attempts DESC,
                         t.name ASC
                LIMIT ?
                """,
                (
                    str(waf_type or "").strip(),
                    int(bool(include_retired)),
                    max(0, int(limit)),
                ),
            ).fetchall()
        return [self._decode_ranked(row) for row in rows]

    def retire_low_success(
        self,
        *,
        threshold: float = 0.10,
        minimum_attempts: int = 10,
    ) -> list[str]:
        if not 0 <= threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")
        if minimum_attempts < 1:
            raise ValueError("minimum_attempts must be at least 1")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT t.id, t.name
                FROM techniques AS t
                JOIN technique_stats AS s ON s.technique_id = t.id
                WHERE s.waf_type = ?
                  AND s.total_attempts >= ?
                  AND s.success_rate < ?
                  AND t.active = 1
                ORDER BY t.name
                """,
                (ALL_WAF_TYPES, int(minimum_attempts), float(threshold)),
            ).fetchall()
            ids = [int(row["id"]) for row in rows]
            if ids:
                placeholders = ", ".join("?" for _ in ids)
                connection.execute(
                    f"""
                    UPDATE techniques
                    SET active = 0, updated_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    (_utc_now(), *ids),
                )
        return [row["name"] for row in rows]

    def recommend_combinations(
        self,
        waf_type: str,
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        ranked = self.best_for_waf(waf_type, limit=max(2, limit * 2))
        if len(ranked) < 2:
            return []
        combinations = []
        for index, first in enumerate(ranked):
            for second in ranked[index + 1 :]:
                combined_probability = 1 - (
                    (1 - first["success_rate"]) * (1 - second["success_rate"])
                )
                combinations.append(
                    {
                        "techniques": [first["name"], second["name"]],
                        "waf_type": waf_type,
                        "estimated_success_rate": combined_probability,
                        "evidence_attempts": (
                            first["total_attempts"] + second["total_attempts"]
                        ),
                    }
                )
        combinations.sort(
            key=lambda item: (
                item["estimated_success_rate"],
                item["evidence_attempts"],
            ),
            reverse=True,
        )
        return combinations[: max(0, int(limit))]

    def attempts(
        self,
        *,
        technique_name: str | None = None,
        target_url: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses = []
        parameters: list[Any] = []
        if technique_name:
            clauses.append("t.name = ?")
            parameters.append(str(technique_name).strip())
        if target_url:
            clauses.append("a.target_url = ?")
            parameters.append(str(target_url).strip())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(0, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT a.*, t.name AS technique_name, t.type AS technique_type
                FROM technique_attempts AS a
                JOIN techniques AS t ON t.id = a.technique_id
                {where}
                ORDER BY a.attempted_at DESC, a.id DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [self._decode_attempt(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            technique_count = int(
                connection.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
            )
            active_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM techniques WHERE active = 1"
                ).fetchone()[0]
            )
            attempt_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM technique_attempts"
                ).fetchone()[0]
            )
            successful_attempts = int(
                connection.execute(
                    """
                    SELECT COALESCE(SUM(success), 0)
                    FROM technique_attempts
                    """
                ).fetchone()[0]
            )
        return {
            "database_path": str(self.db_path),
            "techniques": technique_count,
            "active_techniques": active_count,
            "retired_techniques": technique_count - active_count,
            "attempts": attempt_count,
            "successful_attempts": successful_attempts,
            "success_rate": (
                successful_attempts / attempt_count if attempt_count else 0.0
            ),
        }

    def reset(self) -> dict[str, Any]:
        """Clear learned techniques while preserving the initialized schema."""

        if self.read_only:
            raise RuntimeError("cannot reset read-only technique memory")
        with self._connect() as connection:
            for table in (
                "technique_stats",
                "technique_attempts",
                "techniques",
            ):
                connection.execute(f"DELETE FROM {table}")
        return self.stats()

    @staticmethod
    def _decode_technique(row: sqlite3.Row) -> dict[str, Any]:
        total = int(row["total_attempts"] or 0)
        successful = int(row["successful_attempts"] or 0)
        return {
            "id": int(row["id"]),
            "name": row["name"],
            "type": row["type"],
            "description": row["description"],
            "active": bool(row["active"]),
            "retired": not bool(row["active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "total_attempts": total,
            "successful_attempts": successful,
            "success_rate": float(row["success_rate"] or 0.0),
        }

    @staticmethod
    def _decode_ranked(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "name": row["name"],
            "type": row["type"],
            "description": row["description"],
            "active": bool(row["active"]),
            "retired": not bool(row["active"]),
            "waf_type": row["waf_type"],
            "total_attempts": int(row["total_attempts"]),
            "successful_attempts": int(row["successful_attempts"]),
            "success_rate": float(row["success_rate"]),
        }

    @staticmethod
    def _decode_attempt(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "target_url": row["target_url"],
            "technique_name": row["technique_name"],
            "technique_type": row["technique_type"],
            "waf_type": row["waf_type"],
            "success": bool(row["success"]),
            "transport_success": bool(row["transport_success"]),
            "probe_executed": bool(row["probe_executed"]),
            "signal_detected": bool(row["signal_detected"]),
            "vulnerability_confirmed": bool(
                row["vulnerability_confirmed"]
            ),
            "verdict": row["verdict"],
            "outcome": row["outcome"],
            "attempted_at": row["attempted_at"],
            "metadata": _json_load(row["metadata"], {}),
            "notes": row["notes"],
        }
