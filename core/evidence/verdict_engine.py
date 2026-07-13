from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping
from urllib.parse import urlparse


class Verdict(Enum):
    VERIFIED = "verified"
    LIKELY = "likely"
    INCONCLUSIVE = "inconclusive"
    REFUTED = "refuted"


class VulnType(Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    XXE = "xxe"
    SSTI = "ssti"
    UPLOAD = "upload"
    INFO_DISCLOSURE = "info_disclosure"


@dataclass(frozen=True)
class Evidence:
    request: Dict[str, Any]
    response: Dict[str, Any]
    baseline_response: Dict[str, Any]
    payload: str
    reproduction_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Evidence":
        if not isinstance(value, Mapping):
            value = {}

        def mapping_field(name: str) -> Dict[str, Any]:
            field_value = value.get(name)
            return dict(field_value) if isinstance(field_value, Mapping) else {}

        try:
            reproduction_count = max(0, int(value.get("reproduction_count") or 0))
        except (TypeError, ValueError):
            reproduction_count = 0
        return cls(
            request=mapping_field("request"),
            response=mapping_field("response"),
            baseline_response=mapping_field("baseline_response"),
            payload=str(value.get("payload") or ""),
            reproduction_count=reproduction_count,
            metadata=mapping_field("metadata"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": self.request,
            "response": self.response,
            "baseline_response": self.baseline_response,
            "payload": self.payload,
            "reproduction_count": self.reproduction_count,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class VerdictResult:
    vuln_type: VulnType
    verdict: Verdict
    reason: str
    matched_signals: tuple[str, ...] = ()
    reproduction_count: int = 0

    @property
    def verified(self) -> bool:
        return self.verdict is Verdict.VERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_type": self.vuln_type.value,
            "verdict": self.verdict.value,
            "verified": self.verified,
            "reason": self.reason,
            "matched_signals": list(self.matched_signals),
            "reproduction_count": self.reproduction_count,
        }


class VerdictEngine:
    MIN_REPRODUCTIONS = 3

    SQL_ERRORS = (
        re.compile(r"SQL syntax", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"\b1064\b"),
        re.compile(r"pg_query", re.I),
        re.compile(r"psql", re.I),
        re.compile(r"Microsoft SQL Server", re.I),
        re.compile(r"ODBC SQL Server Driver", re.I),
        re.compile(r"ORA-[0-9]{5}", re.I),
    )
    LFI_MARKERS = (
        "root:x:0:0:", "[boot loader]", "daemon:x:1:1:",
        "[drivers]", "[fonts]", "Volume Serial Number",
    )
    PHP_MARKERS = ("<?php", "define(", "$db_")
    INFO_MARKERS = (
        "-----BEGIN PRIVATE KEY-----", "aws_secret_access_key", "client_secret",
        "database_url=", "authorization: bearer ", "password=",
    )

    def assess(self, vuln_type: VulnType, evidence: Evidence | Mapping[str, Any]) -> VerdictResult:
        if not isinstance(vuln_type, VulnType):
            vuln_type = VulnType(str(vuln_type).lower())
        if not isinstance(evidence, Evidence):
            evidence = Evidence.from_mapping(evidence)
        handler = getattr(self, f"_assess_{vuln_type.value}")
        signals, refuted_reason = handler(evidence)
        if signals:
            verdict = Verdict.VERIFIED if evidence.reproduction_count >= self.MIN_REPRODUCTIONS else Verdict.LIKELY
            reason = "Strong evidence reproduced at least three times" if verdict is Verdict.VERIFIED else "Strong evidence found but reproduced fewer than three times"
            return VerdictResult(vuln_type, verdict, reason, tuple(signals), evidence.reproduction_count)
        if refuted_reason:
            return VerdictResult(vuln_type, Verdict.REFUTED, refuted_reason, (), evidence.reproduction_count)
        return VerdictResult(vuln_type, Verdict.INCONCLUSIVE, "No programmatic verification signal was present", (), evidence.reproduction_count)

    @staticmethod
    def _body(evidence: Evidence) -> str:
        return str(evidence.response.get("body") or "")

    @staticmethod
    def _baseline_body(evidence: Evidence) -> str:
        return str(evidence.baseline_response.get("body") or "")

    @staticmethod
    def _status(evidence: Evidence) -> int:
        return int(evidence.response.get("status_code") or evidence.response.get("status") or 0)

    @staticmethod
    def _structured_kinds(body: str) -> set[str]:
        kinds: set[str] = set()
        stripped = body.strip()
        if not stripped:
            return kinds
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, (dict, list)) and parsed:
                return {"json"}
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        if re.search(r"<table\b[^>]*>.*?<tr\b", body, re.I | re.S):
            kinds.add("html_table")
        if re.search(r"(?:^|[\r\n])[^,\r\n]+,[^,\r\n]+(?:,[^,\r\n]+)+(?:[\r\n]|$)", body):
            kinds.add("csv")
        if re.search(r"\b(?:id|username|email|password|token)\s*[:=]\s*[^<\s]+", body, re.I):
            kinds.add("record_fields")
        return kinds

    @classmethod
    def _structured_data(cls, body: str) -> bool:
        return bool(cls._structured_kinds(body))

    def _assess_sqli(self, evidence: Evidence):
        body = self._body(evidence)
        baseline = self._baseline_body(evidence)
        signals = []
        response_matches = {pattern.pattern for pattern in self.SQL_ERRORS if pattern.search(body)}
        baseline_matches = {pattern.pattern for pattern in self.SQL_ERRORS if pattern.search(baseline)}
        if response_matches - baseline_matches:
            signals.append("database_error")
        baseline_len = max(1, len(baseline))
        response_structures = self._structured_kinds(body)
        baseline_structures = self._structured_kinds(baseline)
        if len(body) > baseline_len * 1.5 and response_structures - baseline_structures:
            signals.append("union_structured_data")
        response_time = float(evidence.metadata.get("response_time") or evidence.response.get("elapsed") or evidence.response.get("time") or 0)
        baseline_time = float(evidence.metadata.get("baseline_response_time") or evidence.baseline_response.get("elapsed") or evidence.baseline_response.get("time") or 0)
        if response_time > 5.0 and 0 <= baseline_time < 1.0:
            signals.append("timing_delta")
        baseline_collision = response_matches and response_matches <= baseline_matches
        same_structured_shape = (
            len(body) > baseline_len * 1.5
            and bool(response_structures)
            and response_structures <= baseline_structures
        )
        refuted = "SQLi signal was already present in the baseline response" if (baseline_collision or same_structured_shape) and not signals else ""
        return signals, refuted

    @staticmethod
    def _inside_ranges(index: int, ranges: list[tuple[int, int]]) -> bool:
        return any(start <= index < end for start, end in ranges)

    @staticmethod
    def _tag_range(body: str, index: int):
        start = body.rfind("<", 0, index + 1)
        end = body.find(">", index)
        if start >= 0 and end >= index and body.rfind(">", 0, index + 1) < start:
            return start, end + 1
        return None

    @staticmethod
    def _payload_breaks_attribute(payload: str) -> bool:
        return bool(re.search(r"['\"]\s*>\s*<", payload, re.I | re.S))

    def _assess_xss(self, evidence: Evidence):
        body = self._body(evidence)
        payload = evidence.payload
        if not payload:
            return [], ""
        comments = [(m.start(), m.end()) for m in re.finditer(r"<!--.*?-->", body, re.S)]
        inert = [(m.start(), m.end()) for m in re.finditer(r"<(textarea|xmp)\b[^>]*>.*?</\1\s*>", body, re.I | re.S)]
        start = 0
        raw_seen = False
        isolated_seen = False
        while True:
            index = body.find(payload, start)
            if index < 0:
                break
            raw_seen = True
            start = index + max(1, len(payload))
            if self._inside_ranges(index, comments) or self._inside_ranges(index, inert):
                isolated_seen = True
                continue
            tag_range = None if payload.startswith("<") else self._tag_range(body, index)
            if tag_range and not self._payload_breaks_attribute(payload):
                isolated_seen = True
                continue
            if not payload.startswith("<") and not self._payload_breaks_attribute(payload):
                isolated_seen = True
                continue
            return ["raw_executable_reflection"], ""
        normalized_payload = re.sub(r"</?script", lambda m: m.group(0).lower(), payload, flags=re.I)
        for match in re.finditer(r"<script\b[^>]*>.*?</script\s*>", body, re.I | re.S):
            normalized_variant = re.sub(r"</?script", lambda m: m.group(0).lower(), match.group(0), flags=re.I)
            if normalized_variant.lower() == normalized_payload.lower() and match.group(0) != payload:
                if self._inside_ranges(match.start(), comments) or self._inside_ranges(match.start(), inert):
                    isolated_seen = True
                    continue
                return ["browser_executable_variant"], ""
        decoded = html.unescape(body)
        if payload in decoded and payload not in body:
            return [], "Payload was HTML encoded and is not browser-executable in this response context"
        if isolated_seen:
            return [], "Payload reflection was isolated in a non-executable HTML context"
        return [], ""

    def _assess_ssrf(self, evidence: Evidence):
        body = self._body(evidence)
        lower = body.lower()
        signals = []
        callbacks = evidence.metadata.get("collaborator_callbacks") or evidence.metadata.get("callbacks") or []
        if callbacks or evidence.metadata.get("collaborator_callback"):
            signals.append("collaborator_callback")
        baseline = self._baseline_body(evidence).lower()
        metadata_markers = ("ami-id", "security-credentials", "computemetadata")
        metadata_fingerprint = any(marker in lower for marker in metadata_markers)
        baseline_metadata_fingerprint = any(marker in baseline for marker in metadata_markers)
        if "169.254.169.254" in evidence.payload and metadata_fingerprint and not baseline_metadata_fingerprint:
            signals.append("cloud_metadata_fingerprint")
        fingerprint = "noauth" in lower or "cluster_name" in lower or bool(re.search(r"(?:^|\r?\n)STAT\s", body))
        baseline_fingerprint = "noauth" in baseline or "cluster_name" in baseline or bool(re.search(r"(?:^|\r?\n)STAT\s", self._baseline_body(evidence)))
        if fingerprint and not baseline_fingerprint:
            signals.append("internal_service_fingerprint")
        baseline_collision = (fingerprint and baseline_fingerprint) or (
            "169.254.169.254" in evidence.payload and metadata_fingerprint and baseline_metadata_fingerprint
        )
        refuted = "SSRF fingerprint was already present in the baseline response" if baseline_collision and not signals else ""
        return signals, refuted

    def _assess_lfi(self, evidence: Evidence):
        body = self._body(evidence)
        baseline = self._baseline_body(evidence)
        signals = []
        if any(marker in body and marker not in baseline for marker in self.LFI_MARKERS):
            signals.append("os_file_signature")
        if any(marker in body and marker not in baseline for marker in self.PHP_MARKERS):
            signals.append("php_source_signature")
        return signals, ""

    def _assess_rce(self, evidence: Evidence):
        body = self._body(evidence)
        lower = body.lower()
        baseline = self._baseline_body(evidence).lower()
        command = str(evidence.metadata.get("command") or evidence.payload).lower()
        signals = []
        if any(name in command for name in ("id", "whoami")) and any(marker in lower and marker not in baseline for marker in ("uid=", "gid=", "root", "nt authority")):
            signals.append("identity_command_output")
        marker = str(evidence.metadata.get("unique_marker") or "")
        if marker and "echo" in command and marker in body and marker not in self._baseline_body(evidence):
            signals.append("unique_echo_marker")
        structured = bool(
            re.search(r"\bLinux\s+\S+\s+\d+\.\d+", body)
            or re.search(r"Windows IP Configuration", body, re.I)
            or re.search(r"(?:^|\n)(?:eth|en|wlan)\w*:\s", body)
        )
        structured_command = any(name in command for name in ("uname", "ipconfig", "ifconfig"))
        if structured and structured_command and body not in self._baseline_body(evidence):
            signals.append("structured_command_output")
        refuted = "Command-output signature was already present or was not bound to the tested command" if structured and not signals else ""
        return signals, refuted

    def _assess_idor(self, evidence: Evidence):
        meta = evidence.metadata
        cross_user = meta.get("request_user") and meta.get("resource_owner") and meta.get("request_user") != meta.get("resource_owner")
        if cross_user and meta.get("owner_data_returned"):
            return ["cross_user_resource_data"], ""
        if meta.get("owner_data_returned") is False:
            return [], "The response did not return the other user's resource data"
        return [], ""

    def _assess_auth_bypass(self, evidence: Evidence):
        body = self._body(evidence).lower()
        location = str(evidence.metadata.get("redirect_location") or evidence.response.get("headers", {}).get("Location") or "")
        signals = []
        if self._status(evidence) == 302 and location and not re.search(r"login|signin|auth|error|denied|forbidden|fail", location, re.I):
            signals.append("authenticated_redirect")
        if any(marker in body for marker in ("logout", "dashboard", "welcome")) and not any(marker in self._baseline_body(evidence).lower() for marker in ("logout", "dashboard", "welcome")):
            signals.append("authenticated_page_marker")
        refuted = "Redirect target is an error, denial, or authentication page" if self._status(evidence) == 302 and location and not signals else ""
        return signals, refuted

    def _assess_open_redirect(self, evidence: Evidence):
        location = str(evidence.metadata.get("redirect_location") or evidence.response.get("headers", {}).get("Location") or "")
        payload_host = str(evidence.metadata.get("payload_host") or urlparse(evidence.payload).hostname or "").lower()
        location_host = str(urlparse(location).hostname or "").lower()
        target_host = str(urlparse(str(evidence.request.get("url") or "")).hostname or "").lower()
        if self._status(evidence) in {301, 302, 303, 307, 308} and payload_host and location_host == payload_host and location_host != target_host:
            return ["external_redirect_control"], ""
        if location_host and target_host and location_host == target_host:
            return [], "Redirect remained on the target origin"
        return [], ""

    def _assess_csrf(self, evidence: Evidence):
        meta = evidence.metadata
        if meta.get("state_changed") and (meta.get("csrf_protection_missing") or meta.get("cross_site_request_succeeded")):
            return ["cross_site_state_change"], ""
        return [], ""

    def _assess_xxe(self, evidence: Evidence):
        body = self._body(evidence)
        callbacks = evidence.metadata.get("collaborator_callbacks") or evidence.metadata.get("callbacks") or []
        signals = []
        if callbacks:
            signals.append("xxe_oob_callback")
        if any(marker in body and marker not in self._baseline_body(evidence) for marker in self.LFI_MARKERS):
            signals.append("xxe_file_disclosure")
        return signals, ""

    def _assess_ssti(self, evidence: Evidence):
        body = self._body(evidence)
        expected = str(evidence.metadata.get("expected_template_result") or "")
        if expected and expected in body and expected not in self._baseline_body(evidence):
            return ["template_expression_evaluated"], ""
        marker = str(evidence.metadata.get("unique_marker") or "")
        if marker and marker in body and marker not in self._baseline_body(evidence):
            return ["template_command_marker"], ""
        return [], ""

    def _assess_upload(self, evidence: Evidence):
        meta = evidence.metadata
        status = int(meta.get("uploaded_file_status") or 0)
        if meta.get("uploaded_executable") and meta.get("uploaded_file_url") and 200 <= status < 400:
            return ["executable_upload_reachable"], ""
        if status < 200 or status >= 400:
            return [], "Uploaded file was not successfully reachable"
        return [], ""

    def _assess_info_disclosure(self, evidence: Evidence):
        body = self._body(evidence).lower()
        baseline = self._baseline_body(evidence).lower()
        if any(marker.lower() in body and marker.lower() not in baseline for marker in self.INFO_MARKERS):
            return ["sensitive_information_signature"], ""
        return [], ""
