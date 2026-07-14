"""Lightweight SQL injection detection over Hunter's stealth HTTP path."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from core.memory.technique_memory import TechniqueMemory
from core.stealth.stealth_http_client import StealthHTTPClient


ERROR_PATTERNS = {
    "mysql": (r"SQL syntax.*MySQL", r"mysql_fetch", r"\b1064\b", r"You have an error"),
    "postgresql": (r"PostgreSQL", r"pg_query", r"\bpsql\b"),
    "mssql": (r"Microsoft SQL Server", r"ODBC SQL Server Driver"),
    "oracle": (r"ORA-[0-9]{5}",),
    "sqlite": (r"SQLite", r"sqlite_"),
}
KEYWORDS = (
    "welcome", "result", "product", "found", "not found", "no results",
    "error", "invalid", "success",
)


class SqliDetector:
    """Run bounded error-based and boolean-blind SQLi checks."""

    ERROR_PROBES = ("'", '"', "\\")
    TRUE_PAYLOAD = " AND 1=1"
    FALSE_PAYLOAD = " AND 1=2"
    CONFIRMATION_RUNS = 3

    def __init__(
        self,
        target_url: str,
        param: str = "category",
        method: str = "GET",
        *,
        session: Any = None,
        session_id: str | None = None,
        stealth_client: StealthHTTPClient | None = None,
        headers: Mapping[str, str] | None = None,
        technique_memory: Any = None,
        waf_type: str = "",
        case_slug: str = "",
        workspace_root: str | Path | None = None,
    ) -> None:
        self.target_url = str(target_url)
        self.param = str(param or "")
        self.method = str(method or "GET").upper()
        self.headers = dict(headers or {})
        self.session_id = str(session_id or getattr(session, "session_id", "") or "")
        self.case_slug = str(case_slug or "")
        self.workspace_root = Path(
            workspace_root or os.getenv("OPEN_TGTYLAB_ROOT", r"D:\Open-tgtylab")
        ).resolve()
        self.technique_memory = technique_memory or TechniqueMemory()
        self.waf_type = str(waf_type or "")
        self._temporary_directory = None
        self.stealth_client = stealth_client
        self.session = session or self._session_from_id() or self._create_ephemeral_session()
        self.attempts: list[dict[str, Any]] = []

    def _session_from_id(self):
        if not self.session_id:
            return None
        client = self.stealth_client or StealthHTTPClient(
            state_dir=Path(__file__).resolve().parents[1] / "sessions" / "stealth"
        )
        return client.detection_session(self.session_id)

    def _create_ephemeral_session(self):
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="hunter-sqli-")
        client = StealthHTTPClient(state_dir=self._temporary_directory.name)
        created = client.session_create(self.target_url, resume=False)
        self.session_id = str(created["session_id"])
        return client.detection_session(self.session_id)

    def _parameters(self) -> list[tuple[str, str]]:
        query = parse_qsl(urlsplit(self.target_url).query, keep_blank_values=True)
        names = list(dict.fromkeys(name for name, _ in query))
        if self.param and self.param not in names:
            names.append(self.param)
        if not names:
            names.append(self.param or "category")
        values = dict(query)
        return [(name, values.get(name, "")) for name in names]

    def _request_url(self) -> str:
        parsed = urlsplit(self.target_url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", parsed.fragment))

    def _request(self, parameter: str, value: str):
        values = dict(parse_qsl(urlsplit(self.target_url).query, keep_blank_values=True))
        values[parameter] = value
        kwargs = {"headers": self.headers, "timeout": 15, "allow_redirects": True}
        kwargs["params" if self.method == "GET" else "data"] = values
        return self.session.request(self.method, self._request_url(), **kwargs)

    @staticmethod
    def _response(response: Any) -> dict[str, Any]:
        elapsed = getattr(response, "elapsed", None)
        body = str(getattr(response, "text", "") or "")
        return {
            "status": int(getattr(response, "status_code", 0) or 0),
            "headers": dict(getattr(response, "headers", {}) or {}),
            "body": body,
            "length": len(body),
            "time": float(elapsed.total_seconds() if elapsed else 0.0),
        }

    def _current_waf(self) -> str:
        if self.waf_type:
            return self.waf_type
        client = getattr(self.session, "client", None)
        session_id = getattr(self.session, "session_id", self.session_id)
        runtime = (
            client._runtime_for_session_id(session_id)
            if client is not None and session_id
            else None
        )
        for row in reversed(runtime["state"].get("timeline", [])) if runtime else []:
            waf = row.get("waf", {}) if isinstance(row, dict) else {}
            if isinstance(waf, dict) and waf.get("waf_type"):
                return str(waf["waf_type"])
        return ""

    def _record_attempt(
        self,
        parameter: str,
        payload: str,
        phase: str,
        success: bool,
        response: Mapping[str, Any],
    ) -> None:
        attempt = self.technique_memory.record_attempt(
            target_url=self.target_url,
            technique_name=f"sqli:{phase}",
            waf_type=self._current_waf(),
            success=bool(success),
            metadata={
                "payload": payload,
                "parameter": parameter,
                "phase": phase,
                "method": self.method,
                "status_code": response.get("status", 0),
                "response_length": response.get("length", 0),
                "response_time": response.get("time", 0),
                "session_id": self.session_id,
            },
            notes=f"SQLi {phase} probe for parameter {parameter}",
        )
        self.attempts.append(attempt)

    @staticmethod
    def _database_error(body: str) -> tuple[str, str]:
        for db_type, patterns in ERROR_PATTERNS.items():
            for expression in patterns:
                match = re.search(expression, body, re.I | re.S)
                if match:
                    return db_type, match.group(0)
        return "", ""

    @staticmethod
    def _keywords(body: str) -> set[str]:
        lowered = body.casefold()
        return {keyword for keyword in KEYWORDS if keyword in lowered}

    def _boolean_analysis(
        self,
        true_response: Mapping[str, Any],
        false_response: Mapping[str, Any],
    ) -> dict[str, Any]:
        true_body = str(true_response.get("body", ""))
        false_body = str(false_response.get("body", ""))
        length_delta = abs(len(true_body) - len(false_body)) / max(
            len(true_body), len(false_body), 1
        )
        keyword_delta = sorted(self._keywords(true_body) ^ self._keywords(false_body))
        return {
            "significant": length_delta > 0.05 or bool(keyword_delta),
            "length_delta_ratio": round(length_delta, 4),
            "content_similarity": round(
                SequenceMatcher(None, true_body, false_body).ratio(), 4
            ),
            "keyword_delta": keyword_delta,
        }

    def _redacted_headers(self) -> dict[str, str]:
        sensitive = {"authorization", "cookie", "proxy-authorization", "x-csrf-token", "x-xsrf-token"}
        return {
            name: "<redacted>" if name.casefold() in sensitive else value
            for name, value in self.headers.items()
        }

    def _evidence(
        self,
        *,
        parameter: str,
        payload: str,
        response: Mapping[str, Any],
        baseline: Mapping[str, Any],
        detection_type: str,
        reproduction_count: int,
        db_type: str = "",
        boolean_analysis: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request_data = (
            {"params": {parameter: payload}}
            if self.method == "GET"
            else {"body": {parameter: payload}}
        )
        return {
            "request": {
                "method": self.method,
                "url": self._request_url(),
                "headers": self._redacted_headers(),
                **request_data,
            },
            "response": {
                "status_code": response.get("status", 0),
                "headers": response.get("headers", {}),
                "body": response.get("body", ""),
            },
            "baseline_response": {
                "status_code": baseline.get("status", 0),
                "headers": baseline.get("headers", {}),
                "body": baseline.get("body", ""),
            },
            "payload": payload,
            "reproduction_count": reproduction_count,
            "metadata": {
                "parameter": parameter,
                "detection_type": detection_type,
                "db_type": db_type,
                "boolean_blind": detection_type == "boolean-based",
                "boolean_analysis": dict(boolean_analysis or {}),
                "response_time": response.get("time", 0),
                "baseline_response_time": baseline.get("time", 0),
                "session_id": self.session_id,
                "waf_type": self._current_waf(),
            },
        }

    def _save_evidence(self, evidence: Mapping[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(evidence, sort_keys=True, ensure_ascii=False).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        directory = self.workspace_root / "exports" / "evidence" / "sqli"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"sqli-{digest[:16]}.json"
        path.write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        registration: dict[str, Any] = {
            "path": str(path),
            "sha256": digest,
            "workflow_registered": False,
        }
        if self.case_slug:
            from core.workflow import WorkflowKernel

            registered = WorkflowKernel(self.workspace_root).register_evidence(
                self.case_slug,
                summary=(
                    f"Confirmed SQL injection at {self.target_url} "
                    f"parameter {evidence['metadata']['parameter']}"
                ),
                source="hunter_auto_sqli",
                path_or_url=str(path),
                evidence_type="sqli-proof",
                confidence="high",
                sha256=digest,
                dedupe_key=f"sqli:{digest}",
            )
            registration.update(
                {
                    "workflow_registered": True,
                    "evidence_id": registered["evidence"]["id"],
                    "case_slug": self.case_slug,
                }
            )
        return registration

    def _confirm_error(
        self,
        parameter: str,
        payload: str,
        db_type: str,
        first_response: Mapping[str, Any],
    ) -> tuple[int, Mapping[str, Any]]:
        matches = 1
        last_response = first_response
        for _ in range(self.CONFIRMATION_RUNS - 1):
            response = self._response(self._request(parameter, payload))
            confirmed_db, _ = self._database_error(response["body"])
            success = confirmed_db == db_type
            self._record_attempt(parameter, payload, "error-based", success, response)
            matches += int(success)
            last_response = response
        return matches, last_response

    def _confirm_boolean(
        self,
        parameter: str,
        true_payload: str,
        false_payload: str,
        first_analysis: Mapping[str, Any],
        first_true: Mapping[str, Any],
        first_false: Mapping[str, Any],
    ) -> tuple[int, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
        matches = int(bool(first_analysis.get("significant")))
        last_analysis = first_analysis
        last_true = first_true
        last_false = first_false
        for _ in range(self.CONFIRMATION_RUNS - 1):
            true_response = self._response(self._request(parameter, true_payload))
            false_response = self._response(self._request(parameter, false_payload))
            analysis = self._boolean_analysis(true_response, false_response)
            success = bool(analysis["significant"])
            self._record_attempt(parameter, true_payload, "boolean-based", success, true_response)
            self._record_attempt(parameter, false_payload, "boolean-based", success, false_response)
            matches += int(success)
            last_analysis, last_true, last_false = analysis, true_response, false_response
        return matches, last_analysis, last_true, last_false

    def detect(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "scanner": "sqli",
            "engine": "lightweight",
            "target": self.target_url,
            "method": self.method,
            "session_id": self.session_id,
            "vulnerable": False,
            "workflow_state": "completed",
            "attempts": self.attempts,
        }
        for parameter, original_value in self._parameters():
            baseline = self._response(self._request(parameter, original_value))
            baseline_db, _ = self._database_error(baseline["body"])
            matched = None
            for probe in self.ERROR_PROBES:
                payload = f"{original_value}{probe}"
                response = self._response(self._request(parameter, payload))
                db_type, error = self._database_error(response["body"])
                success = bool(db_type and db_type != baseline_db)
                self._record_attempt(parameter, payload, "error-based", success, response)
                if success and matched is None:
                    matched = (payload, response, db_type, error)
            if matched is not None:
                payload, response, db_type, error = matched
                reproductions, response = self._confirm_error(
                    parameter, payload, db_type, response
                )
                if reproductions >= self.CONFIRMATION_RUNS:
                    evidence = self._evidence(
                        parameter=parameter,
                        payload=payload,
                        response=response,
                        baseline=baseline,
                        detection_type="error-based",
                        reproduction_count=reproductions,
                        db_type=db_type,
                    )
                    result.update(
                        {
                            "vulnerable": True,
                            "detection_type": "error-based",
                            "injection_point": parameter,
                            "db_type": db_type,
                            "matched_error": error,
                            "evidence": evidence,
                            "evidence_registration": self._save_evidence(evidence),
                        }
                    )
                    return result

            true_payload = f"{original_value}{self.TRUE_PAYLOAD}"
            false_payload = f"{original_value}{self.FALSE_PAYLOAD}"
            true_response = self._response(self._request(parameter, true_payload))
            false_response = self._response(self._request(parameter, false_payload))
            analysis = self._boolean_analysis(true_response, false_response)
            success = bool(analysis["significant"])
            self._record_attempt(parameter, true_payload, "boolean-based", success, true_response)
            self._record_attempt(parameter, false_payload, "boolean-based", success, false_response)
            reproductions, analysis, true_response, false_response = self._confirm_boolean(
                parameter,
                true_payload,
                false_payload,
                analysis,
                true_response,
                false_response,
            )
            if reproductions >= self.CONFIRMATION_RUNS:
                evidence = self._evidence(
                    parameter=parameter,
                    payload=false_payload,
                    response=false_response,
                    baseline=true_response,
                    detection_type="boolean-based",
                    reproduction_count=reproductions,
                    boolean_analysis=analysis,
                )
                result.update(
                    {
                        "vulnerable": True,
                        "detection_type": "boolean-based",
                        "injection_point": parameter,
                        "boolean_analysis": analysis,
                        "evidence": evidence,
                        "evidence_registration": self._save_evidence(evidence),
                    }
                )
                return result
        return result
