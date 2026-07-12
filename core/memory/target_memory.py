"""SQLite-backed target observations and regression snapshots."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


DEFAULT_DB_PATH = Path(r"D:\Open-tgtylab\data\targets.db")


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


def _domain_for(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or parsed.path.split("/", 1)[0]).lower()


class TargetMemory:
    """Store target-scoped observations in a local SQLite database."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
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
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            technology_stack TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_targets_domain
            ON targets(domain);

        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            observed_at TEXT NOT NULL,
            waf_type TEXT,
            cdn_type TEXT,
            cms_type TEXT,
            web_server TEXT,
            programming_language TEXT,
            framework TEXT,
            database_type TEXT,
            details TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_fingerprints_target
            ON fingerprints(target_id, observed_at);

        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            method TEXT NOT NULL,
            parameters TEXT NOT NULL DEFAULT '[]',
            injection_points TEXT NOT NULL DEFAULT '[]',
            unauthorized_risk INTEGER NOT NULL DEFAULT 0,
            details TEXT NOT NULL DEFAULT '{}',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(target_id, url, method),
            FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_endpoints_target
            ON endpoints(target_id);

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            poc_path TEXT NOT NULL DEFAULT '',
            report_path TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '{}',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(target_id, type, poc_path),
            FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target
            ON vulnerabilities(target_id, status);

        CREATE TABLE IF NOT EXISTS attack_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            attempted_at TEXT NOT NULL,
            tool TEXT NOT NULL,
            payload_metadata TEXT NOT NULL DEFAULT '{}',
            success INTEGER NOT NULL,
            bypass_strategy TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_attack_history_target
            ON attack_history(target_id, attempted_at);
        """
        with self._connect() as connection:
            connection.executescript(schema)

    def _ensure_target(
        self,
        connection: sqlite3.Connection,
        target_url: str,
        technology_stack: Mapping[str, Any] | None = None,
    ) -> int:
        url = str(target_url).strip()
        if not url:
            raise ValueError("target_url must not be empty")
        now = _utc_now()
        stack = dict(technology_stack or {})
        existing = connection.execute(
            "SELECT id, technology_stack FROM targets WHERE url = ?",
            (url,),
        ).fetchone()
        if existing is not None and stack:
            merged_stack = _json_load(existing["technology_stack"], {})
            if not isinstance(merged_stack, dict):
                merged_stack = {}
            merged_stack.update(stack)
            stack = merged_stack
        connection.execute(
            """
            INSERT INTO targets(url, domain, first_seen, last_seen, technology_stack)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                domain = excluded.domain,
                last_seen = excluded.last_seen,
                technology_stack = CASE
                    WHEN excluded.technology_stack = '{}' THEN targets.technology_stack
                    ELSE excluded.technology_stack
                END
            """,
            (url, _domain_for(url), now, now, _json_dump(stack)),
        )
        row = connection.execute(
            "SELECT id FROM targets WHERE url = ?",
            (url,),
        ).fetchone()
        if row is None:
            raise RuntimeError("failed to create target record")
        return int(row["id"])

    def record_target(
        self,
        target_url: str,
        fingerprints: Mapping[str, Any] | None = None,
        technology_stack: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        fingerprint_data = dict(fingerprints or {})
        stack = dict(technology_stack or fingerprint_data)
        with self._connect() as connection:
            target_id = self._ensure_target(connection, target_url, stack)
            if fingerprint_data:
                self._insert_fingerprint(connection, target_id, fingerprint_data)
        return self.query_target(target_url)["target"]

    def _insert_fingerprint(
        self,
        connection: sqlite3.Connection,
        target_id: int,
        values: Mapping[str, Any],
    ) -> None:
        known = {
            "waf",
            "waf_type",
            "cdn",
            "cdn_type",
            "cms",
            "cms_type",
            "server",
            "web_server",
            "language",
            "programming_language",
            "framework",
            "database",
            "database_type",
        }
        details = {key: value for key, value in values.items() if key not in known}
        connection.execute(
            """
            INSERT INTO fingerprints(
                target_id, observed_at, waf_type, cdn_type, cms_type,
                web_server, programming_language, framework, database_type,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_id,
                _utc_now(),
                values.get("waf") or values.get("waf_type"),
                values.get("cdn") or values.get("cdn_type"),
                values.get("cms") or values.get("cms_type"),
                values.get("server") or values.get("web_server"),
                values.get("language") or values.get("programming_language"),
                values.get("framework"),
                values.get("database") or values.get("database_type"),
                _json_dump(details),
            ),
        )

    def record_fingerprint(
        self,
        target_url: str,
        fingerprints: Mapping[str, Any] | str,
        value: Any = None,
        *,
        confidence: float = 0.0,
        evidence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if isinstance(fingerprints, Mapping):
            values = dict(fingerprints)
        else:
            fingerprint_type = str(fingerprints).strip().lower()
            if not fingerprint_type:
                raise ValueError("fingerprint type must not be empty")
            values = {
                fingerprint_type: value,
                "confidence": float(confidence),
                "evidence": dict(evidence or {}),
            }
        stack_values = {
            key: item
            for key, item in values.items()
            if key not in {"confidence", "evidence", "details"}
        }
        with self._connect() as connection:
            target_id = self._ensure_target(connection, target_url, stack_values)
            self._insert_fingerprint(connection, target_id, values)
        return self.query_target(target_url)["fingerprint_history"][-1]

    def record_endpoint(
        self,
        target_url: str,
        endpoint_url: str,
        *,
        method: str = "GET",
        parameters: Iterable[Any] | Mapping[str, Any] | None = None,
        injection_points: Iterable[Any] | None = None,
        unauthorized_risk: bool = False,
        authorization_risk: bool | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        endpoint = str(endpoint_url).strip()
        if not endpoint:
            raise ValueError("endpoint_url must not be empty")
        normalized_method = str(method or "GET").strip().upper()
        risk = unauthorized_risk if authorization_risk is None else authorization_risk
        now = _utc_now()
        with self._connect() as connection:
            target_id = self._ensure_target(connection, target_url)
            connection.execute(
                """
                INSERT INTO endpoints(
                    target_id, url, method, parameters, injection_points,
                    unauthorized_risk, details, first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id, url, method) DO UPDATE SET
                    parameters = excluded.parameters,
                    injection_points = excluded.injection_points,
                    unauthorized_risk = excluded.unauthorized_risk,
                    details = excluded.details,
                    last_seen = excluded.last_seen
                """,
                (
                    target_id,
                    endpoint,
                    normalized_method,
                    _json_dump(parameters or []),
                    _json_dump(list(injection_points or [])),
                    int(bool(risk)),
                    _json_dump(dict(details or {})),
                    now,
                    now,
                ),
            )
        return self._find_endpoint(target_url, endpoint, normalized_method)

    def _find_endpoint(
        self,
        target_url: str,
        endpoint_url: str,
        method: str,
    ) -> dict[str, Any]:
        history = self.query_target(target_url)
        for endpoint in history["endpoints"]:
            if endpoint["url"] == endpoint_url and endpoint["method"] == method:
                return endpoint
        raise RuntimeError("failed to create endpoint record")

    def record_vulnerability(
        self,
        target_url: str,
        *,
        vuln_type: str,
        severity: str,
        status: str,
        poc_path: str | Path | None = None,
        report_path: str | Path | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_type = str(vuln_type).strip().lower()
        if not normalized_type:
            raise ValueError("vuln_type must not be empty")
        normalized_poc = str(poc_path or "")
        now = _utc_now()
        with self._connect() as connection:
            target_id = self._ensure_target(connection, target_url)
            connection.execute(
                """
                INSERT INTO vulnerabilities(
                    target_id, type, severity, status, poc_path, report_path,
                    details, first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id, type, poc_path) DO UPDATE SET
                    severity = excluded.severity,
                    status = excluded.status,
                    report_path = excluded.report_path,
                    details = excluded.details,
                    last_seen = excluded.last_seen
                """,
                (
                    target_id,
                    normalized_type,
                    str(severity).strip().lower(),
                    str(status).strip().lower(),
                    normalized_poc,
                    str(report_path or ""),
                    _json_dump(dict(details or {})),
                    now,
                    now,
                ),
            )
        history = self.query_target(target_url)
        for vulnerability in history["vulnerabilities"]:
            if (
                vulnerability["type"] == normalized_type
                and vulnerability["poc_path"] == normalized_poc
            ):
                return vulnerability
        raise RuntimeError("failed to create vulnerability record")

    def record_attack(
        self,
        target_url: str,
        *,
        tool: str,
        payload_metadata: Mapping[str, Any] | None = None,
        success: bool,
        bypass_strategy: str = "",
        notes: str = "",
        attempted_at: str | None = None,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            target_id = self._ensure_target(connection, target_url)
            cursor = connection.execute(
                """
                INSERT INTO attack_history(
                    target_id, attempted_at, tool, payload_metadata, success,
                    bypass_strategy, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_id,
                    attempted_at or _utc_now(),
                    str(tool).strip(),
                    _json_dump(dict(payload_metadata or {})),
                    int(bool(success)),
                    str(bypass_strategy or ""),
                    str(notes or ""),
                ),
            )
            attack_id = int(cursor.lastrowid)
        history = self.query_target(target_url)
        for attack in history["attack_history"]:
            if attack["id"] == attack_id:
                return attack
        raise RuntimeError("failed to create attack history record")

    def _target_row(self, query: str) -> sqlite3.Row | None:
        needle = str(query).strip()
        domain = _domain_for(needle)
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT * FROM targets
                WHERE url = ?
                   OR lower(domain) = lower(?)
                   OR lower(url) LIKE lower(?)
                ORDER BY
                    CASE WHEN url = ? THEN 0 ELSE 1 END,
                    last_seen DESC
                LIMIT 1
                """,
                (needle, domain, f"%{needle}%", needle),
            ).fetchone()

    def query_target(self, query: str) -> dict[str, Any]:
        target = self._target_row(query)
        if target is None:
            return {
                "target": None,
                "fingerprints": {},
                "fingerprint_history": [],
                "endpoints": [],
                "vulnerabilities": [],
                "attack_history": [],
            }
        target_id = int(target["id"])
        with self._connect() as connection:
            fingerprints = connection.execute(
                """
                SELECT * FROM fingerprints
                WHERE target_id = ?
                ORDER BY observed_at, id
                """,
                (target_id,),
            ).fetchall()
            endpoints = connection.execute(
                """
                SELECT * FROM endpoints
                WHERE target_id = ?
                ORDER BY url, method
                """,
                (target_id,),
            ).fetchall()
            vulnerabilities = connection.execute(
                """
                SELECT * FROM vulnerabilities
                WHERE target_id = ?
                ORDER BY type, id
                """,
                (target_id,),
            ).fetchall()
            attacks = connection.execute(
                """
                SELECT * FROM attack_history
                WHERE target_id = ?
                ORDER BY attempted_at, id
                """,
                (target_id,),
            ).fetchall()
        fingerprint_history = [
            self._decode_fingerprint(row) for row in fingerprints
        ]
        return {
            "target": self._decode_target(target),
            "fingerprints": self._merge_fingerprints(fingerprint_history),
            "fingerprint_history": fingerprint_history,
            "endpoints": [self._decode_endpoint(row) for row in endpoints],
            "vulnerabilities": [
                self._decode_vulnerability(row) for row in vulnerabilities
            ],
            "attack_history": [self._decode_attack(row) for row in attacks],
        }

    @staticmethod
    def _merge_fingerprints(
        history: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for item in history:
            for key in (
                "waf",
                "cdn",
                "cms",
                "server",
                "language",
                "framework",
                "database",
            ):
                if item.get(key) not in (None, ""):
                    merged[key] = item[key]
            details = item.get("details")
            if isinstance(details, Mapping):
                merged.update(details)
        return merged

    @staticmethod
    def _decode_target(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "url": row["url"],
            "domain": row["domain"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "technology_stack": _json_load(row["technology_stack"], {}),
        }

    @staticmethod
    def _decode_fingerprint(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "observed_at": row["observed_at"],
            "waf": row["waf_type"],
            "cdn": row["cdn_type"],
            "cms": row["cms_type"],
            "server": row["web_server"],
            "language": row["programming_language"],
            "framework": row["framework"],
            "database": row["database_type"],
            "details": _json_load(row["details"], {}),
        }

    @staticmethod
    def _decode_endpoint(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "url": row["url"],
            "method": row["method"],
            "parameters": _json_load(row["parameters"], []),
            "injection_points": _json_load(row["injection_points"], []),
            "unauthorized_risk": bool(row["unauthorized_risk"]),
            "details": _json_load(row["details"], {}),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    @staticmethod
    def _decode_vulnerability(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "type": row["type"],
            "severity": row["severity"],
            "status": row["status"],
            "poc_path": row["poc_path"],
            "report_path": row["report_path"],
            "details": _json_load(row["details"], {}),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    @staticmethod
    def _decode_attack(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "attempted_at": row["attempted_at"],
            "tool": row["tool"],
            "payload_metadata": _json_load(row["payload_metadata"], {}),
            "success": bool(row["success"]),
            "bypass_strategy": row["bypass_strategy"],
            "notes": row["notes"],
        }

    def snapshot(self, target_url: str) -> dict[str, Any]:
        history = self.query_target(target_url)
        return {
            "target_url": (
                history["target"]["url"] if history["target"] is not None else target_url
            ),
            "captured_at": _utc_now(),
            "endpoints": sorted(
                {
                    endpoint["url"]
                    for endpoint in history["endpoints"]
                }
            ),
            "vulnerabilities": sorted(
                {
                    vulnerability["type"]
                    for vulnerability in history["vulnerabilities"]
                    if vulnerability["status"] not in {"fixed", "resolved"}
                }
            ),
        }

    def compare_regression(
        self,
        target_url: str,
        baseline: Mapping[str, Any],
    ) -> dict[str, Any]:
        current = self.snapshot(target_url)
        baseline_endpoints = set(baseline.get("endpoints", []))
        current_endpoints = set(current["endpoints"])
        baseline_vulnerabilities = set(baseline.get("vulnerabilities", []))
        current_vulnerabilities = set(current["vulnerabilities"])
        return {
            "baseline_at": baseline.get("captured_at"),
            "current_at": current["captured_at"],
            "new": {
                "endpoints": sorted(current_endpoints - baseline_endpoints),
                "vulnerabilities": sorted(
                    current_vulnerabilities - baseline_vulnerabilities
                ),
            },
            "fixed": {
                "endpoints": sorted(baseline_endpoints - current_endpoints),
                "vulnerabilities": sorted(
                    baseline_vulnerabilities - current_vulnerabilities
                ),
            },
            "reproduced": {
                "endpoints": sorted(current_endpoints & baseline_endpoints),
                "vulnerabilities": sorted(
                    current_vulnerabilities & baseline_vulnerabilities
                ),
            },
        }

    def similar_targets(
        self,
        target_url: str,
        *,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        history = self.query_target(target_url)
        if history["target"] is None:
            return []
        stack = history["target"]["technology_stack"]
        if not stack:
            return []
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM targets
                WHERE id <> ?
                ORDER BY last_seen DESC
                """,
                (history["target"]["id"],),
            ).fetchall()
        requested = {str(key).lower(): str(value).lower() for key, value in stack.items()}
        matches = []
        for row in rows:
            candidate = self._decode_target(row)
            candidate_stack = {
                str(key).lower(): str(value).lower()
                for key, value in candidate["technology_stack"].items()
            }
            shared = sorted(
                key
                for key, value in requested.items()
                if candidate_stack.get(key) == value
            )
            if shared:
                candidate["shared_fingerprints"] = shared
                candidate["similarity"] = len(shared) / max(len(requested), 1)
                matches.append(candidate)
        matches.sort(
            key=lambda item: (item["similarity"], item["last_seen"]),
            reverse=True,
        )
        return matches[: max(0, int(limit))]

    def stats(self) -> dict[str, Any]:
        table_names = (
            "targets",
            "fingerprints",
            "endpoints",
            "vulnerabilities",
            "attack_history",
        )
        with self._connect() as connection:
            counts = {
                table: int(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
                for table in table_names
            }
        return {"database_path": str(self.db_path), **counts}
