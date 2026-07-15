from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .verdict_engine import Evidence, VulnType


class EvidenceNormalizer:
    KIND_TO_VULN = {
        "sqli": VulnType.SQLI,
        "sqli_xss": VulnType.SQLI,
        "xss": VulnType.XSS,
        "ssrf": VulnType.SSRF,
        "ssrf_open_redirect": VulnType.SSRF,
        "lfi": VulnType.LFI,
        "rce": VulnType.RCE,
        "command_injection": VulnType.RCE,
        "cmdi": VulnType.RCE,
        "idor": VulnType.IDOR,
        "api_access_control": VulnType.IDOR,
        "auth_bypass": VulnType.AUTH_BYPASS,
        "authentication": VulnType.AUTH_BYPASS,
        "authentication_bypass": VulnType.AUTH_BYPASS,
        "open_redirect": VulnType.OPEN_REDIRECT,
        "csrf": VulnType.CSRF,
        "registration": VulnType.CSRF,
        "xxe": VulnType.XXE,
        "ssti": VulnType.SSTI,
        "upload": VulnType.UPLOAD,
        "file_upload": VulnType.UPLOAD,
        "information_disclosure": VulnType.INFO_DISCLOSURE,
        "info_disclosure": VulnType.INFO_DISCLOSURE,
    }

    def normalize_attempt(
        self,
        attempt: Mapping[str, Any],
    ) -> tuple[VulnType | None, Evidence]:
        current = dict(attempt or {})
        result = (
            dict(current.get("response"))
            if isinstance(current.get("response"), Mapping)
            else {}
        )
        payload = (
            dict(result.get("data"))
            if isinstance(result.get("data"), Mapping)
            else result
        )
        raw = (
            dict(payload.get("evidence"))
            if isinstance(payload.get("evidence"), Mapping)
            else dict(result.get("evidence"))
            if isinstance(result.get("evidence"), Mapping)
            else {}
        )
        metadata = (
            dict(raw.get("metadata"))
            if isinstance(raw.get("metadata"), Mapping)
            else {}
        )
        metadata.update(
            {
                "action_id": str(current.get("action_id") or ""),
                "tool": str(current.get("tool") or ""),
                "target": str(current.get("target") or ""),
            }
        )
        evidence = Evidence.from_mapping(
            {
                "request": raw.get("request", {}),
                "response": raw.get("response", {}),
                "baseline_response": (
                    raw.get("baseline_response")
                    or raw.get("baseline")
                    or {}
                ),
                "payload": raw.get("payload", ""),
                "reproduction_count": raw.get(
                    "reproduction_count",
                    0,
                ),
                "metadata": metadata,
            }
        )
        kind = str(
            current.get("attack_surface")
            or current.get("vulnerability_type")
            or current.get("type")
            or payload.get("vulnerability_type")
            or ""
        ).strip().casefold()
        return self.KIND_TO_VULN.get(kind), evidence
