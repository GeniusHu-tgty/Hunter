"""
Hunter Unified Scan Engine 鈥?First Principles Design

Core idea: ONE entry point that orchestrates ALL tools.
Recon 鈫?Detect 鈫?Exploit 鈫?Report 鈥?fully automated.

Architecture:
1. Recon Phase: probe() 鈫?find params/forms/endpoints
2. Detect Phase: auto_sqli + auto_xss + auto_ssti + auto_ssrf + auto_xxe + auto_cmd + auto_idor
3. Exploit Phase: Burp MCP to verify and exploit
4. Report Phase: aggregate findings

Key innovations:
- Tools share state (recon results feed into detection)
- Burp Collaborator integration for blind vulns
- Adaptive testing (fail 鈫?try different approach)
- Session management (remember findings across tests)
"""

import asyncio
import hashlib
import inspect
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence
from urllib.parse import parse_qs, urljoin, urlparse

from core.reasoning.attack_reasoning import AttackReasoner


SPA_SCRIPT_THRESHOLD = 64 * 1024
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_SCRIPT_COUNT = 32
ATTACK_PRIORITY = {
    "authentication_bypass": 0,
    "authentication": 0,
    "sqli": 1,
    "sqli_xss": 1,
    "xss": 2,
    "information_disclosure": 3,
    "api_access_control": 4,
    "ssrf_open_redirect": 5,
    "file_upload": 6,
    "registration": 7,
    "baseline": 8,
}
SEVERITY_PRIORITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
WEAK_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("test", "test"),
    ("guest", "guest"),
)
_SCRIPT_RE = re.compile(
    r"<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_ATTRIBUTE_RE = re.compile(
    r"""(?P<name>[\w:-]+)\s*=\s*(?P<quote>["'])(?P<value>.*?)(?P=quote)""",
    re.IGNORECASE | re.DOTALL,
)


def _unique(items: Sequence[Any]) -> list[Any]:
    seen = set()
    output = []
    for item in items:
        marker = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(item)
    return output


def _fingerprint_name(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(
            value.get("name")
            or value.get("waf_type")
            or value.get("value")
            or ""
        ).strip()
    return str(value or "").strip()


def _parameter_names(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [str(key) for key in value if str(key).strip()]
    if not isinstance(value, (list, tuple, set)):
        return [str(value)] if str(value or "").strip() else []
    names = []
    for item in value:
        if isinstance(item, Mapping):
            name = item.get("name") or item.get("parameter") or item.get("key")
        else:
            name = item
        if str(name or "").strip():
            names.append(str(name).strip())
    return list(dict.fromkeys(names))


def _response_body(result: Mapping[str, Any], limit: int = MAX_SCRIPT_BYTES) -> str:
    body = str(result.get("body") or "")
    artifact = str(result.get("body_artifact") or "")
    if result.get("body_truncated") and artifact:
        path = Path(artifact)
        try:
            if path.is_file() and path.stat().st_size <= limit:
                return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    return body


def _attributes(raw: str) -> dict[str, str]:
    return {
        match.group("name").casefold(): match.group("value")
        for match in _ATTRIBUTE_RE.finditer(raw or "")
    }


_BROWSER_SENSITIVE_MARKERS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "csrf",
    "api_key",
    "apikey",
)
_BROWSER_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (
        ["']?
        (?:authorization|cookie|password|passwd|secret|token|csrf|api[_-]?key)
        ["']?
        \s*[:=]\s*
        ["']?
    )
    ([^"'&,\s}\]]+)
    """
)


def _redact_browser_observation(value: Any, key: str = "") -> Any:
    lowered = str(key).casefold().replace("-", "_")
    if any(marker in lowered for marker in _BROWSER_SENSITIVE_MARKERS):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact_browser_observation(item, str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _redact_browser_observation(item)
            for item in list(value)[:200]
        ]
    if isinstance(value, str):
        text = value[:8192]
        stripped = text.strip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
            else:
                if isinstance(parsed, (Mapping, list)):
                    return json.dumps(
                        _redact_browser_observation(parsed),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
        return _BROWSER_SECRET_ASSIGNMENT_RE.sub(
            r"\1[REDACTED]",
            text,
        )
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:8192]


def _browser_execution_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    direct_keys = {
        "installed",
        "pattern",
        "url",
        "targetState",
        "target_state",
    }
    if direct_keys.intersection(value):
        return dict(value)
    for key in (
        "structuredContent",
        "data",
        "result",
        "value",
        "content",
    ):
        nested = value.get(key)
        if nested is not None and nested is not value:
            payload = _browser_execution_payload(nested)
            if payload:
                return payload
    return {}


def _json_result(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {"status": "error", "error": value}
    if isinstance(value, Mapping):
        return dict(value)
    return {
        "status": "error",
        "error": f"tool returned {type(value).__name__}, expected an object",
    }


class UnifiedOrchestrationBridge:
    """Connect the workflow orchestrator to Hunter's native subsystems."""

    def __init__(
        self,
        services: Mapping[str, Any] | None = None,
        *,
        js_threshold: int = SPA_SCRIPT_THRESHOLD,
        call_mcp_tool=None,
    ) -> None:
        self.services = dict(services or {})
        self.js_threshold = max(1, int(js_threshold))
        self.call_mcp_tool = (
            call_mcp_tool
            if call_mcp_tool is not None
            else self.services.get("call_mcp_tool")
        )
        self._instances: dict[str, Any] = {}

    def _service(self, name: str, factory) -> Any:
        if name in self.services:
            return self.services[name]
        if name not in self._instances:
            self._instances[name] = factory()
        return self._instances[name]

    def _stealth_client(self):
        from core.stealth import StealthHTTPClient

        return self._service("stealth_http_client", StealthHTTPClient)

    def _browser_controller(self):
        from core.browser import BrowserController

        return self._service(
            "browser_controller",
            lambda: BrowserController(call_mcp_tool=self.call_mcp_tool),
        )

    def _browser_execution_enabled(self, browser: Any) -> bool:
        if self.call_mcp_tool is None:
            return False
        if hasattr(browser, "execution_adapter"):
            return browser.execution_adapter is not None
        return True

    def _resolve_browser_operation(self, value: Any) -> Any:
        if not inspect.isawaitable(value):
            return value
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(value)
        if inspect.iscoroutine(value):
            value.close()
        return {
            "status": "error",
            "execution": "failed",
            "error": (
                "browser execution cannot be synchronously resolved inside "
                "an active event loop"
            ),
        }

    @staticmethod
    def _browser_result_summary(
        operation: str,
        result: Any,
    ) -> dict[str, Any]:
        if not isinstance(result, Mapping):
            return {
                "operation": operation,
                "status": "error",
                "execution": "failed",
                "error": (
                    "browser operation returned "
                    f"{type(result).__name__}, expected an object"
                ),
            }
        summary = {
            "operation": str(result.get("operation") or operation),
            "status": str(result.get("status") or "unknown"),
            "execution": str(result.get("execution") or "unknown"),
        }
        for key in (
            "error",
            "url",
            "title",
            "html_length",
            "has_form",
            "has_login",
            "has_websocket",
            "url_pattern",
            "target_url",
            "target_state",
            "expected_url",
            "current_url",
            "hook_statuses",
            "accepted",
            "rejected",
            "hook_results",
            "network_requests",
            "crypto_operations",
            "storage_operations",
            "websocket_messages",
        ):
            if key in result:
                summary[key] = _redact_browser_observation(
                    result[key],
                    key,
                )
        if isinstance(result.get("execution_results"), list):
            execution_payloads = [
                _browser_execution_payload(item.get("result"))
                for item in result["execution_results"]
                if isinstance(item, Mapping)
            ]
            for payload in execution_payloads:
                for source_key, target_key in (
                    ("installed", "installed"),
                    ("pattern", "pattern"),
                    ("url", "url"),
                    ("targetState", "target_state"),
                    ("target_state", "target_state"),
                ):
                    if source_key in payload:
                        summary[target_key] = _redact_browser_observation(
                            payload[source_key],
                            target_key,
                        )
            summary["execution_results"] = [
                {
                    "tool": str(item.get("tool") or ""),
                    "error": (
                        str((item.get("result") or {}).get("error") or "")
                        if isinstance(item, Mapping)
                        and isinstance(item.get("result"), Mapping)
                        else ""
                    ),
                }
                for item in result["execution_results"]
                if isinstance(item, Mapping)
            ]
        if summary.get("installed") is False:
            summary.update(
                {
                    "status": "error",
                    "execution": "failed",
                    "error": "browser instrumentation was not installed",
                }
            )
        return summary

    def _run_browser_operation(
        self,
        operation: str,
        invoke,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        try:
            raw_result = self._resolve_browser_operation(invoke())
        except Exception as exc:
            raw_result = {
                "status": "error",
                "execution": "failed",
                "error": str(exc).strip() or type(exc).__name__,
            }
        summary = self._browser_result_summary(operation, raw_result)
        status = str(summary.get("status") or "").casefold()
        failed = (
            status in {"error", "timeout"}
            or summary.get("execution") == "failed"
        )
        navigation_changed = status == "navigation_changed"
        if not failed and not navigation_changed:
            return summary, []
        error = str(summary.get("error") or status or "unknown browser error")
        evidence_type = (
            "browser_navigation_changed"
            if navigation_changed and not failed
            else "browser_error"
        )
        return summary, [
            {
                "summary": f"Browser operation {operation} failed: {error}",
                "source": "browser-controller",
                "type": evidence_type,
                "confidence": "observed",
                "operation": operation,
                "status": status or "error",
                "error": error,
            }
        ]

    def _fingerprint_database(self):
        from core.memory import FingerprintDatabase

        return self._service("fingerprint_database", FingerprintDatabase)

    def _pattern_engine(self):
        from core.memory import PatternEngine

        return self._service("pattern_engine", PatternEngine)

    def _target_memory(self):
        from core.memory import TargetMemory

        return self._service("target_memory", TargetMemory)

    def _technique_memory(self):
        from core.memory import TechniqueMemory

        return self._service("technique_memory", TechniqueMemory)

    @staticmethod
    def _resolve_operation(value: Any) -> Any:
        if not inspect.isawaitable(value):
            return value
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(value)
        if inspect.iscoroutine(value):
            value.close()
        return {
            "status": "error",
            "error": "async tool execution requires the orchestrator worker thread",
        }

    @staticmethod
    def _call_with_supported_arguments(operation, arguments: Mapping[str, Any]):
        try:
            signature = inspect.signature(operation)
        except (TypeError, ValueError):
            return operation(**dict(arguments))
        if any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            return operation(**dict(arguments))
        supported = {
            name: value
            for name, value in arguments.items()
            if name in signature.parameters
        }
        return operation(**supported)

    def _invoke_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        operation = self.services.get(tool_name)
        if operation is not None:
            return _json_result(
                self._resolve_operation(
                    self._call_with_supported_arguments(
                        operation,
                        arguments,
                    )
                )
            )

        runner = self.services.get("auto_tool_runner")
        if runner is not None:
            try:
                signature = inspect.signature(runner)
            except (TypeError, ValueError):
                value = runner(tool_name, dict(arguments))
            else:
                parameters = signature.parameters
                if "tool_name" in parameters or "arguments" in parameters:
                    value = runner(
                        **{
                            name: item
                            for name, item in {
                                "tool_name": tool_name,
                                "arguments": dict(arguments),
                            }.items()
                            if name in parameters
                        }
                    )
                else:
                    positional = [
                        parameter
                        for parameter in parameters.values()
                        if parameter.kind
                        in {
                            inspect.Parameter.POSITIONAL_ONLY,
                            inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        }
                    ]
                    value = (
                        runner(tool_name, dict(arguments))
                        if len(positional) >= 2
                        else runner(
                            {
                                "tool": tool_name,
                                "arguments": dict(arguments),
                            }
                        )
                    )
            if value is not NotImplemented:
                return _json_result(self._resolve_operation(value))

        try:
            import mcp_server

            operation = getattr(mcp_server, tool_name)
        except (AttributeError, ImportError) as exc:
            return {
                "status": "error",
                "tool": tool_name,
                "error": str(exc),
            }
        return _json_result(
            self._resolve_operation(
                self._call_with_supported_arguments(
                    operation,
                    arguments,
                )
            )
        )

    @staticmethod
    def _result_payload(result: Mapping[str, Any]) -> dict[str, Any]:
        data = result.get("data")
        return dict(data) if isinstance(data, Mapping) else dict(result)

    @classmethod
    def _result_success(cls, result: Mapping[str, Any]) -> bool:
        payload = cls._result_payload(result)
        status = str(
            payload.get("status")
            or result.get("status")
            or ""
        ).casefold()
        if status in {
            "error",
            "failed",
            "timeout",
            "blocked",
            "rejected",
            "approval-required",
            "recovery-required",
        }:
            return False
        if isinstance(payload.get("vulnerable"), bool):
            return bool(payload["vulnerable"])
        if isinstance(result.get("vulnerable"), bool):
            return bool(result["vulnerable"])
        return bool(payload.get("findings") or result.get("findings"))

    @staticmethod
    def _header_observations(
        headers: Mapping[str, Any],
        target_url: str,
    ) -> dict[str, Any]:
        normalized = {
            str(key).casefold(): str(value)
            for key, value in headers.items()
        }
        selected = {
            name: normalized.get(name.casefold(), "")
            for name in (
                "Content-Security-Policy",
                "Location",
                "Server",
                "Set-Cookie",
                "X-Powered-By",
            )
            if normalized.get(name.casefold())
        }
        subdomains = []
        csp = normalized.get("content-security-policy", "")
        cookie = normalized.get("set-cookie", "")
        location = normalized.get("location", "")
        candidates = re.findall(
            r"(?i)(?<![a-z0-9_-])(?:https?://|wss?://)?"
            r"(?:\*\.)?(\.?[a-z0-9-]+(?:\.[a-z0-9-]+)+)",
            f"{csp} {cookie} {location}",
        )
        target_host = (urlparse(target_url).hostname or "").casefold()
        for candidate in candidates:
            host = str(candidate).strip().lstrip("*.").lstrip(".").casefold()
            if (
                host
                and host != target_host
                and "." in host
                and host not in subdomains
            ):
                subdomains.append(host)
        cookie_names = re.findall(
            r"(?i)(?:^|,\s*(?=[^;,\s]+=))\s*([^=;,\s]+)=",
            cookie,
        )
        server = normalized.get("server", "").strip()
        if server == "*****":
            server = ""
        powered_by = normalized.get("x-powered-by", "").strip()
        platform = ""
        normalized_cookie_names = {
            name.casefold(): name for name in cookie_names
        }
        if "jsessionid" in normalized_cookie_names:
            platform = "Java/JSP"
        elif "phpsessid" in normalized_cookie_names:
            platform = "PHP"
        elif "asp.net_sessionid" in normalized_cookie_names:
            platform = "ASP.NET"
        return {
            "headers": selected,
            "subdomains": subdomains,
            "features": {
                "server": server,
                "powered_by": powered_by,
                "platform": platform,
                "cookie_names": list(dict.fromkeys(cookie_names)),
                "csp": csp,
                "location": location,
            },
        }

    @staticmethod
    def _baseline_headers(baseline: Mapping[str, Any]) -> dict[str, Any]:
        headers = {}
        timeline = baseline.get("timeline") or []
        if isinstance(timeline, Sequence) and not isinstance(timeline, str):
            for item in timeline:
                if isinstance(item, Mapping) and isinstance(
                    item.get("headers"),
                    Mapping,
                ):
                    headers.update(dict(item["headers"]))
        if isinstance(baseline.get("headers"), Mapping):
            headers.update(dict(baseline["headers"]))
        return headers

    def _record_fingerprint_observation(
        self,
        target_url: str,
        *,
        fingerprints: Mapping[str, Any],
        matches: Mapping[str, Any],
        headers: Mapping[str, Any],
        subdomains: Sequence[str],
    ) -> None:
        database = self._fingerprint_database()
        observation = {
            "target_url": target_url,
            "fingerprints": dict(fingerprints),
            "matches": dict(matches),
            "headers": dict(headers),
            "subdomains": list(subdomains),
        }
        for name in ("record_observation", "record", "upsert"):
            operation = getattr(database, name, None)
            if not callable(operation):
                continue
            try:
                self._call_with_supported_arguments(
                    operation,
                    {
                        "target_url": target_url,
                        "target": target_url,
                        "fingerprints": dict(fingerprints),
                        "observation": observation,
                    },
                )
            except (TypeError, ValueError):
                continue
            return
        runtime_observations = getattr(
            database,
            "runtime_observations",
            None,
        )
        if not isinstance(runtime_observations, dict):
            runtime_observations = {}
            setattr(database, "runtime_observations", runtime_observations)
        runtime_observations[target_url] = observation

    @staticmethod
    def _identify_target_type(
        target_url: str,
        *,
        detected: Mapping[str, Any],
        headers: Mapping[str, Any],
        body: str,
        paths: Sequence[str],
    ) -> str:
        product_names = " ".join(
            _fingerprint_name(detected.get(kind))
            for kind in ("edu", "cms", "framework")
        )
        corpus = " ".join(
            (
                target_url,
                product_names,
                " ".join(f"{key}: {value}" for key, value in headers.items()),
                body[:262144],
                " ".join(paths),
            )
        ).casefold()
        if any(
            signal in corpus
            for signal in (
                "鍗氳揪 cms/vsb",
                "vsb portal",
                "/system/resource/js/vsb",
                "vsbcontent",
                "_vsb",
            )
        ):
            return "vsb_cms"
        if any(
            signal in corpus
            for signal in (
                "瓒呮槦鏅烘収闂ㄦ埛",
                "chaoxing.com",
                "passport2.chaoxing",
                "mooc1.chaoxing",
            )
        ):
            return "chaoxing_portal"
        if any(
            signal in corpus
            for signal in (
                "閲戞櫤 cas",
                "鑹惧崱 cas",
                "apereo cas",
                "central authentication service",
                "/cas/login",
                "/zfcas/",
                "castgc",
            )
        ):
            return "cas_authentication"
        return "generic_web"

    @staticmethod
    def _scan_options(profile: Mapping[str, Any]) -> dict[str, Any]:
        name = str(profile.get("name", "standard")).casefold()
        rates = {
            "fast": [1],
            "standard": [1, 2],
            "deep": [1, 2, 5],
        }.get(name, [1, 2])
        return {
            "active_waf": True,
            "rate_probe_rates": rates,
            "requests_per_rate": 1,
            "timeout": 5 if name == "fast" else 10,
        }

    @staticmethod
    def _waf_from_scan(scan: Mapping[str, Any]) -> str:
        waf = scan.get("waf") or {}
        if isinstance(waf, Mapping):
            candidate = _fingerprint_name(waf)
            if candidate:
                return candidate
            passive = waf.get("passive") or {}
            candidate = _fingerprint_name(passive)
            if candidate:
                return candidate
        timeline = (scan.get("baseline") or {}).get("timeline") or []
        for item in reversed(timeline):
            if isinstance(item, Mapping):
                candidate = _fingerprint_name(item.get("waf"))
                if candidate:
                    return candidate
        return ""

    def _record_stealth_strategy_attempts(
        self,
        result: Mapping[str, Any],
        *,
        target_url: str,
        waf_type: str,
        learning_run_id: str = "",
    ) -> list[dict[str, Any]]:
        timeline = result.get("timeline") or []
        if not isinstance(timeline, Sequence) or isinstance(timeline, str):
            return []
        from core.stealth.waf_detector import BLOCK_WORDS

        response_body = _response_body(result).casefold()
        final_body_has_block_keyword = any(
            str(keyword).casefold() in response_body for keyword in BLOCK_WORDS
        )
        updates = []
        technique_memory = None
        timeline_items = [item for item in timeline if isinstance(item, Mapping)]
        for index, item in enumerate(timeline_items):
            strategy = str(item.get("strategy") or "").strip()
            if (
                not strategy
                or str(item.get("strategy_status") or "") != "applied"
            ):
                continue
            try:
                status_code = int(item.get("status_code") or 0)
            except (TypeError, ValueError):
                continue
            rate_limited = bool(item.get("rate_limited"))
            if status_code in {429, 503} and rate_limited:
                continue
            waf_details = item.get("waf") or {}
            if not isinstance(waf_details, Mapping):
                waf_details = {}
            blocked = bool(waf_details.get("blocked"))
            block_keyword = bool(waf_details.get("block_keyword"))
            body_has_block_keyword = bool(
                index == len(timeline_items) - 1
                and final_body_has_block_keyword
            )
            if status_code == 403:
                if blocked or block_keyword or body_has_block_keyword:
                    success = False
                else:
                    continue
            elif status_code == 429:
                continue
            elif blocked:
                success = False
            elif status_code > 0:
                success = True
            else:
                continue
            effective_waf = (
                str(waf_type or "").strip()
                or _fingerprint_name(waf_details)
                or "custom/unknown"
            )
            if technique_memory is None:
                technique_memory = self._technique_memory()
            learning_key = hashlib.sha256(
                json.dumps(
                    {
                        "learning_run_id": str(learning_run_id or ""),
                        "target_url": str(target_url),
                        "strategy": strategy,
                        "attempt": item.get("attempt"),
                    },
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            attempts_query = getattr(technique_memory, "attempts", None)
            if learning_run_id and callable(attempts_query):
                existing = attempts_query(
                    technique_name=strategy,
                    target_url=str(target_url),
                    limit=100,
                )
                if any(
                    attempt.get("metadata", {}).get("learning_key")
                    == learning_key
                    for attempt in existing
                    if isinstance(attempt, Mapping)
                ):
                    continue
            technique_memory.record_attempt(
                technique_name=strategy,
                target_url=str(target_url),
                waf_type=effective_waf,
                success=success,
                metadata={
                    "source": "unified-recon",
                    "attempt": item.get("attempt"),
                    "status_code": status_code,
                    "strategy_status": item.get("strategy_status"),
                    "rate_limited": rate_limited,
                    "learning_run_id": str(learning_run_id or ""),
                    "learning_key": learning_key,
                },
            )
            updates.append(
                {
                    "technique": strategy,
                    "target_url": str(target_url),
                    "waf_type": effective_waf,
                    "success": success,
                    "status_code": status_code,
                }
            )
        return updates

    @staticmethod
    def _page_inventory(html: str) -> dict[str, Any]:
        forms = []
        params = re.findall(
            r"<input\b[^>]*\bname=[\"']([^\"']+)",
            html,
            re.IGNORECASE,
        )
        for form_match in re.finditer(
            r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>",
            html,
            re.IGNORECASE | re.DOTALL,
        ):
            attrs = _attributes(form_match.group("attrs"))
            forms.append(
                {
                    "action": attrs.get("action", ""),
                    "method": attrs.get("method", "GET").upper(),
                    "inputs": re.findall(
                        r"<input\b[^>]*\bname=[\"']([^\"']+)",
                        form_match.group("body"),
                        re.IGNORECASE,
                    ),
                }
            )
        links = re.findall(
            r"\bhref=[\"']([^\"']+)",
            html,
            re.IGNORECASE,
        )
        endpoints = []
        for link in links:
            if link.startswith("/") and not link.startswith("//"):
                endpoints.append(link)
            parsed = urlparse(link)
            params.extend(parse_qs(parsed.query).keys())
        csrf_token = ""
        for match in re.finditer(
            r"<input\b(?P<attrs>[^>]*)>",
            html,
            re.IGNORECASE,
        ):
            attrs = _attributes(match.group("attrs"))
            name = attrs.get("name", "")
            if (
                attrs.get("type", "").casefold() == "hidden"
                and ("csrf" in name.casefold() or "token" in name.casefold())
            ):
                csrf_token = attrs.get("value", "")
                break
        return {
            "forms": forms,
            "params": list(dict.fromkeys(params)),
            "endpoints": list(dict.fromkeys(endpoints)),
            "csrf_token": csrf_token,
        }

    @staticmethod
    def _spa_signals(html: str) -> dict[str, Any]:
        checks = (
            ("react-root", r"<div\b[^>]*\bid=[\"']root[\"']"),
            ("vue-app", r"<div\b[^>]*\bid=[\"']app[\"']"),
            ("angular", r"\bng-app\b|angular(?:\.module|\W)"),
            ("webpack-require", r"__webpack_require__"),
            ("module-script", r"<script\b[^>]*\btype=[\"']module[\"']"),
            ("webpack-jsonp", r"\bwebpackJsonp\b"),
        )
        signals = [
            name
            for name, expression in checks
            if re.search(expression, html, re.IGNORECASE)
        ]
        frameworks = []
        if "react-root" in signals:
            frameworks.append("React")
        if "vue-app" in signals:
            frameworks.append("Vue")
        if "angular" in signals:
            frameworks.append("Angular")
        if {"webpack-require", "webpack-jsonp"} & set(signals):
            frameworks.append("Webpack")
        return {
            "detected": bool(signals),
            "signals": signals,
            "frameworks": frameworks,
        }

    @staticmethod
    def _script_tags(html: str) -> tuple[list[str], list[dict[str, str]]]:
        external = []
        inline = []
        for index, match in enumerate(_SCRIPT_RE.finditer(html)):
            attrs = _attributes(match.group("attrs"))
            if attrs.get("src"):
                external.append(attrs["src"])
                continue
            body = match.group("body").strip()
            if body:
                inline.append(
                    {
                        "name": f"inline-{index}.js",
                        "code": body,
                    }
                )
        return list(dict.fromkeys(external)), inline

    @staticmethod
    def _websocket_urls(source: str, target: str) -> list[str]:
        candidates = re.findall(
            r"""(?:new\s+WebSocket\s*\(\s*)?["'](wss?://[^"' )]+|/[^"' )]*ws[^"' )]*)["']""",
            source,
            re.IGNORECASE,
        )
        parsed_target = urlparse(target)
        urls = []
        for candidate in candidates:
            if candidate.startswith(("ws://", "wss://")):
                urls.append(candidate)
                continue
            scheme = "wss" if parsed_target.scheme == "https" else "ws"
            urls.append(
                urljoin(
                    f"{scheme}://{parsed_target.netloc}/",
                    candidate.lstrip("/"),
                )
            )
        return list(dict.fromkeys(urls))

    @staticmethod
    def _normalise_js_result(result: Any) -> dict[str, Any]:
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except ValueError:
                return {"error": result}
        if not isinstance(result, Mapping):
            return {"error": f"invalid JS analysis result: {type(result).__name__}"}
        if isinstance(result.get("data"), Mapping):
            return dict(result["data"])
        return dict(result)

    def _run_js_full_analysis(
        self,
        sources: Sequence[Mapping[str, Any]],
        *,
        target_url: str,
    ) -> dict[str, Any]:
        operation = self.services.get("js_full_analysis")
        if operation is not None:
            return self._normalise_js_result(
                operation(list(sources), target_url=target_url)
            )

        from core.js_analysis import (
            deobfuscate,
            extract_api,
            extract_signature,
            unpack_bundle,
        )

        digest = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:12]
        destination = (
            Path("evidence")
            / "js_analysis"
            / f"orchestrator-{digest}-{int(time.time())}"
        ).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        unpacked = []
        transformed = []
        api = {
            "endpoints": [],
            "websockets": [],
            "routes": [],
            "authentication": [],
            "confirmed": [],
            "inferred": [],
            "unresolved": [],
        }
        for index, source in enumerate(sources):
            name = str(source.get("name") or f"source-{index}.js")
            code = str(source.get("code") or "")
            unpacked.append(
                unpack_bundle(
                    code,
                    destination / f"source-{index}" / "unpacked",
                    source_name=name,
                )
            )
            deobfuscated = deobfuscate(code)
            transformed.append(deobfuscated["code"])
            extracted = extract_api(deobfuscated["code"], source_name=name)
            for key in api:
                api[key].extend(extracted.get(key, []))
        signature = extract_signature(
            "\n".join(transformed),
            target_url=target_url,
        )
        safe_signature = {
            key: value
            for key, value in signature.items()
            if key not in {"replay_code", "candidates"}
        }
        return {
            "pipeline": {
                "input_sources": len(sources),
                "unpacked_sources": len(unpacked),
                "deobfuscated_sources": len(transformed),
                "downstream_input": "deobfuscated",
            },
            "unpack": unpacked,
            "api": api,
            "signature": safe_signature,
            "evidence": {"artifact_dir": str(destination)},
        }

    @staticmethod
    def _merge_fingerprints(
        detected: Mapping[str, Any],
        *,
        waf_name: str,
        spa: Mapping[str, Any],
        header_features: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        fingerprints = {}
        for kind in (
            "waf",
            "cdn",
            "cms",
            "edu",
            "framework",
            "api",
            "language",
            "database",
        ):
            name = _fingerprint_name(detected.get(kind))
            if name:
                fingerprints[kind] = name
        if waf_name:
            fingerprints["waf"] = waf_name
        if spa.get("frameworks"):
            fingerprints["frontend_frameworks"] = list(spa["frameworks"])
            if "framework" not in fingerprints:
                fingerprints["framework"] = spa["frameworks"][0]
        features = dict(header_features or {})
        if features.get("server"):
            fingerprints["server"] = str(features["server"])
        if features.get("powered_by"):
            fingerprints["powered_by"] = str(features["powered_by"])
            fingerprints.setdefault("language", str(features["powered_by"]))
        if features.get("platform"):
            fingerprints["platform"] = str(features["platform"])
        if features.get("cookie_names"):
            fingerprints["cookie_names"] = list(features["cookie_names"])
        return fingerprints

    @staticmethod
    def _normalise_endpoints(
        endpoints: Sequence[Any],
        *,
        limit: int,
    ) -> list[dict[str, Any]]:
        normalized = []
        for item in endpoints:
            if isinstance(item, Mapping):
                endpoint = dict(item)
                url = endpoint.get("url") or endpoint.get("path")
            else:
                endpoint = {}
                url = item
            if not str(url or "").strip():
                continue
            endpoint["url"] = str(url)
            endpoint["method"] = str(endpoint.get("method") or "GET").upper()
            endpoint["parameters"] = _parameter_names(
                endpoint.get("parameters", [])
            )
            endpoint["parameters"] = list(
                dict.fromkeys(
                    endpoint["parameters"]
                    + list(parse_qs(urlparse(endpoint["url"]).query).keys())
                )
            )
            normalized.append(endpoint)
        return _unique(normalized)[: max(0, int(limit))]

    def stage_memory(self, context: Mapping[str, Any]) -> dict[str, Any]:
        target_memory = self._target_memory()
        technique_memory = self._technique_memory()
        history = target_memory.query_target(context["target_url"])
        fingerprints = history.get("fingerprints", {})
        waf = _fingerprint_name(fingerprints.get("waf"))
        return {
            "memo": {
                "target_seen": history.get("target") is not None,
                "history": history,
                "best_techniques": technique_memory.best_for_waf(
                    waf or "*",
                    limit=5,
                ),
                "stack_strategy": self._pattern_engine().recommend_stack(
                    fingerprints
                ),
                "fingerprint_catalog": self._fingerprint_database().counts(),
                "http_transport": "stealth_http_client",
            }
        }

    def stage_recon(self, context: Mapping[str, Any]) -> dict[str, Any]:
        target = str(context["target_url"])
        profile = dict(context.get("profile", {}))
        client = self._stealth_client()
        session = {}
        create_session = getattr(client, "session_create", None)
        if callable(create_session):
            try:
                session = dict(
                    self._call_with_supported_arguments(
                        create_session,
                        {
                            "target": target,
                            "target_url": target,
                            "resume": False,
                        },
                    )
                    or {}
                )
            except Exception as exc:
                session = {"status": "error", "error": str(exc)}
        try:
            scan = client.stealth_scan(
                target,
                options=self._scan_options(profile),
            )
        except Exception as exc:
            scan = {
                "target": target,
                "baseline": {
                    "status": "error",
                    "status_code": 0,
                    "headers": {},
                    "body": "",
                    "timeline": [],
                    "error": str(exc),
                },
                "waf": {},
                "rate_limit": {},
                "captcha": {},
            }
        scan_session = scan.get("session")
        if isinstance(scan_session, Mapping):
            session = {**session, **dict(scan_session)}
        baseline = dict(scan.get("baseline") or {})
        baseline["headers"] = self._baseline_headers(baseline)
        session_id = str(session.get("session_id") or "")
        if isinstance(context, dict):
            context["session_id"] = session_id
        waf_name = self._waf_from_scan(scan)
        rate_limit = dict(scan.get("rate_limit") or {})
        safe_rps = rate_limit.get("safe_rps", 0)
        learning_updates = self._record_stealth_strategy_attempts(
            baseline,
            target_url=target,
            waf_type=waf_name,
            learning_run_id=str(context.get("workflow_id") or ""),
        )
        html = _response_body(baseline)
        inventory = self._page_inventory(html)
        spa = self._spa_signals(html)
        script_urls, script_sources = self._script_tags(html)
        script_errors = []
        max_scripts = min(
            MAX_SCRIPT_COUNT,
            max(1, int(profile.get("max_endpoints", MAX_SCRIPT_COUNT))),
        )
        for script_url in script_urls[:max_scripts]:
            absolute = urljoin(target, script_url)
            result = client.stealth_request(
                "GET",
                absolute,
                options={
                    "max_retries": 3 if self._waf_from_scan(scan) else 1,
                    "max_body_chars": MAX_SCRIPT_BYTES,
                    "timeout": self._scan_options(profile)["timeout"],
                },
            )
            learning_updates.extend(
                self._record_stealth_strategy_attempts(
                    result,
                    target_url=absolute,
                    waf_type=waf_name,
                    learning_run_id=str(context.get("workflow_id") or ""),
                )
            )
            if result.get("status") == "ok":
                script_sources.append(
                    {
                        "name": str(result.get("url") or absolute),
                        "code": _response_body(result),
                    }
                )
            else:
                script_errors.append(
                    {
                        "url": absolute,
                        "status": result.get("status", "error"),
                        "error": result.get("error", ""),
                    }
                )
        combined_scripts = "\n".join(
            str(item.get("code") or "") for item in script_sources
        )
        spa_from_scripts = self._spa_signals(combined_scripts)
        spa["signals"] = list(
            dict.fromkeys(spa["signals"] + spa_from_scripts["signals"])
        )
        spa["frameworks"] = list(
            dict.fromkeys(
                spa["frameworks"] + spa_from_scripts["frameworks"]
            )
        )
        spa["detected"] = bool(spa["signals"])
        script_bytes = sum(
            len(str(item.get("code") or "").encode("utf-8"))
            for item in script_sources
        )
        js_result = {}
        js_triggered = bool(
            spa["detected"]
            and script_sources
            and script_bytes > self.js_threshold
        )
        if js_triggered:
            js_result = self._run_js_full_analysis(
                script_sources,
                target_url=target,
            )
        js_api = js_result.get("api", {}) if isinstance(js_result, Mapping) else {}
        js_endpoints = (
            js_api.get("endpoints", [])
            if isinstance(js_api, Mapping)
            else []
        )
        endpoints = self._normalise_endpoints(
            list(inventory["endpoints"]) + list(js_endpoints),
            limit=int(profile.get("max_endpoints", 100)),
        )
        paths = [endpoint["url"] for endpoint in endpoints]
        header_observations = self._header_observations(
            baseline.get("headers", {}),
            target,
        )
        detected = self._fingerprint_database().detect(
            {
                "url": target,
                "headers": baseline.get("headers", {}),
                "cookies": header_observations["features"].get(
                    "cookie_names",
                    [],
                ),
                "body": html + "\n" + combined_scripts[:262144],
                "paths": paths + script_urls,
            }
        )
        fingerprints = self._merge_fingerprints(
            detected,
            waf_name=waf_name,
            spa=spa,
            header_features=header_observations["features"],
        )
        target_type = self._identify_target_type(
            target,
            detected=detected,
            headers=baseline.get("headers", {}),
            body=html + "\n" + combined_scripts[:262144],
            paths=paths + script_urls,
        )
        fingerprints["target_type"] = target_type
        auth_redirects = []
        for candidate in (
            *(session.get("oauth_chain") or []),
            baseline.get("url", ""),
        ):
            value = str(candidate or "").strip()
            lowered = value.casefold()
            if (
                value
                and value != target
                and any(
                    signal in lowered
                    for signal in (
                        "/login",
                        "/signin",
                        "/auth",
                        "/cas/",
                        "passport",
                    )
                )
            ):
                auth_redirects.append(value)
        auth_redirects = list(dict.fromkeys(auth_redirects))
        self._record_fingerprint_observation(
            target,
            fingerprints=fingerprints,
            matches=detected,
            headers=header_observations["headers"],
            subdomains=header_observations["subdomains"],
        )
        websocket_inventory = (
            list(js_api.get("websockets", []))
            if isinstance(js_api, Mapping)
            else []
        )
        websocket_urls = self._websocket_urls(
            html + "\n" + combined_scripts,
            target,
        )
        for item in websocket_inventory:
            if isinstance(item, Mapping) and item.get("url"):
                websocket_urls.append(str(item["url"]))
        websocket_urls = list(dict.fromkeys(websocket_urls))
        browser = self._browser_controller()
        browser_enabled = self._browser_execution_enabled(browser)
        browser_evidence: list[dict[str, Any]] = []
        capture_plans = []
        browser_analysis: dict[str, Any] = {
            "enabled": browser_enabled,
            "execution": "deferred",
            "navigation": {},
            "spa_routes": [],
            "hook_injection": {},
            "hook_results": {},
            "errors": [],
        }
        spa_expected_url = ""
        if not browser_enabled:
            capture_plans = [
                browser.intercept_websocket(url)
                for url in websocket_urls
            ]
        else:
            for url in websocket_urls:
                capture, evidence = self._run_browser_operation(
                    "intercept_websocket",
                    lambda url=url: browser.intercept_websocket(
                        url,
                        execute=True,
                    ),
                )
                capture_plans.append(capture)
                browser_evidence.extend(evidence)

            if spa["detected"] or websocket_urls:
                navigation, evidence = self._run_browser_operation(
                    "navigate_and_wait",
                    lambda: browser.navigate_and_wait(
                        target,
                        {
                            "network_idle": True,
                            "timeout_ms": (
                                self._scan_options(profile)["timeout"] * 1000
                            ),
                        },
                        execute=True,
                    ),
                )
                browser_analysis["navigation"] = navigation
                browser_evidence.extend(evidence)

            if spa["detected"]:
                parsed_target = urlparse(target)
                route_candidates = []
                for endpoint in endpoints:
                    if str(endpoint.get("method") or "GET").upper() != "GET":
                        continue
                    raw_url = str(endpoint.get("url") or "").strip()
                    parsed = urlparse(raw_url)
                    if parsed.scheme and parsed.netloc != parsed_target.netloc:
                        continue
                    route = (
                        f"{parsed.path or '/'}"
                        f"{'?' + parsed.query if parsed.query else ''}"
                    )
                    if route:
                        route_candidates.append(route)
                route_limit = (
                    3
                    if str(profile.get("name") or "").casefold() == "deep"
                    else 1
                )
                for route in list(dict.fromkeys(route_candidates))[:route_limit]:
                    spa_expected_url = urljoin(target, route)
                    route_result, evidence = self._run_browser_operation(
                        "auto_navigate_spa",
                        lambda route=route: browser.auto_navigate_spa(
                            target,
                            route,
                            execute=True,
                        ),
                    )
                    browser_analysis["spa_routes"].append(route_result)
                    browser_evidence.extend(evidence)

            if spa["detected"] or websocket_urls:
                try:
                    from core.browser import DynamicHookInjector

                    injector = DynamicHookInjector()
                    hook_sources = {
                        hook: injector.read_template(hook)
                        for hook in (
                            "xhr",
                            "fetch",
                            "crypto",
                            "storage",
                            "cookie",
                            "websocket",
                        )
                    }
                    expected_url = str(
                        spa_expected_url
                        or browser_analysis["navigation"].get("url")
                        or target
                    )
                    hook_injection, evidence = self._run_browser_operation(
                        "inject_hooks",
                        lambda: browser.inject_hooks(
                            hook_sources,
                            expected_url=expected_url,
                            execute=True,
                        ),
                    )
                    browser_analysis["hook_injection"] = hook_injection
                    browser_evidence.extend(evidence)
                    hook_results, evidence = self._run_browser_operation(
                        "get_hook_results",
                        lambda: browser.get_hook_results(execute=True),
                    )
                    browser_analysis["hook_results"] = hook_results
                    browser_evidence.extend(evidence)
                except Exception as exc:
                    _, evidence = self._run_browser_operation(
                        "inject_hooks",
                        lambda: {
                            "status": "error",
                            "execution": "failed",
                            "error": str(exc).strip() or type(exc).__name__,
                        },
                    )
                    browser_evidence.extend(evidence)

            browser_analysis["errors"] = [
                item
                for item in browser_evidence
                if item.get("type") == "browser_error"
            ]
            browser_results = [
                *capture_plans,
                browser_analysis["navigation"],
                *browser_analysis["spa_routes"],
                browser_analysis["hook_injection"],
                browser_analysis["hook_results"],
            ]
            browser_deferred = any(
                isinstance(item, Mapping)
                and (
                    item.get("status") == "proposed"
                    or item.get("execution") == "deferred"
                )
                for item in browser_results
            )
            browser_analysis["execution"] = (
                "failed"
                if browser_analysis["errors"]
                else "deferred"
                if browser_deferred
                else "completed"
            )
        return {
            "target_profile": {
                "target_url": target,
                "session_id": session_id,
                "session": session,
                "http_status": baseline.get("status_code", 0),
                "waf_type": waf_name,
                "safe_rps": safe_rps,
                "http_transport": "stealth_http_client",
                "stealth_required": bool(waf_name),
                "stealth_scan": {
                    "status": baseline.get("status", "error"),
                    "waf": scan.get("waf", {}),
                    "rate_limit": scan.get("rate_limit", {}),
                    "captcha": scan.get("captcha", {}),
                    "error": baseline.get("error", ""),
                    "learning_updates": learning_updates,
                },
                "fingerprints": fingerprints,
                "fingerprint_matches": detected,
                "target_type": target_type,
                "response_headers": header_observations["headers"],
                "header_fingerprints": header_observations["features"],
                "subdomains": header_observations["subdomains"],
                "auth_redirects": auth_redirects,
                "forms": inventory["forms"],
                "params": inventory["params"],
                "csrf_token": inventory["csrf_token"],
                "api_endpoints": endpoints,
                "js_bundles": [
                    {
                        "name": source.get("name", ""),
                        "bytes": len(
                            str(source.get("code") or "").encode("utf-8")
                        ),
                    }
                    for source in script_sources
                ],
                "spa": {
                    **spa,
                    "script_bytes": script_bytes,
                    "analysis_threshold": self.js_threshold,
                },
                "js_analysis": {
                    "triggered": js_triggered,
                    "result": js_result,
                    "script_errors": script_errors,
                },
                "browser_analysis": browser_analysis,
                "browser_evidence": browser_evidence,
                "websocket_capture": {
                    "triggered": bool(capture_plans),
                    "urls": websocket_urls,
                    "plans": capture_plans,
                    "message_formats": [
                        message
                        for item in websocket_inventory
                        if isinstance(item, Mapping)
                        for message in item.get("message_formats", [])
                    ],
                },
            }
        }

    def _auto_attack_strategy(self, fingerprints: dict) -> list[dict]:
        """Compile passive stack intelligence into deferred attack actions."""
        fingerprints = dict(fingerprints or {})

        def names(value: Any) -> list[str]:
            if isinstance(value, Mapping):
                value = value.get("name") or value.get("value") or value.get("waf_type") or ""
            if isinstance(value, (list, tuple, set)):
                return [str(item).strip() for item in value if str(item or "").strip()]
            return [str(value).strip()] if str(value or "").strip() else []

        observed = []
        for key in ("edu", "edu_system", "cms", "framework", "frontend_frameworks", "api", "server", "language", "runtime", "database"):
            observed.extend(names(fingerprints.get(key)))
        observed_text = " | ".join(observed).casefold()
        waf = _fingerprint_name(fingerprints.get("waf"))

        # Local clues keep strategy generation available with an empty memory DB.
        clue_catalog = (
            (("金智 cas", "lyuapserver"), "金智 CAS / lyuapServer", ("弱口令枚举", "service 参数开放重定向检测", "SSO Cookie 篡改", "/lyuapServer/login 路径认证绕过")),
            (("apereo cas", "authserver", "艾卡 cas"), "Apereo CAS / authserver", ("/cas/login 弱口令", "TGT 票据伪造", "/cas/status 信息泄露")),
            (("正方教务", "正方教务管理系统"), "正方教务", ("/jwglxt/xtgl/login_slogin.html 弱口令", "JSESSIONID 会话固定", "学生信息API未授权")),
            (("超星智慧门户", "chaoxing"), "超星智慧门户", ("passport2.chaoxing.com 认证绕过", "/entry/ 路径遍历", "API 接口越权")),
            (("vsb portal", "webberrasp", "博达 cms"), "VSB Portal / WebberRASP", ("/system/ 后台弱口令", "文件上传绕过", "搜索接口 SQL 注入")),
            (("wordpress",), "WordPress", ("/wp-admin 弱口令", "xmlrpc.php 用户枚举", "插件/主题已知漏洞", "wp-config.php.bak 备份文件")),
            (("django",), "Django", ("/admin 弱口令", "Debug 模式检测(?debug=1)", "CSRF token 重用", "SECRET_KEY 泄露检测")),
            (("spring boot",), "Spring Boot", ("/actuator 信息泄露", "Spring4Shell CVE-2022-22965", "SpEL 注入", "/env 属性泄露")),
            (("laravel",), "Laravel", ("APP_KEY 泄露", ".env 文件访问", "Debug 模式信息泄露", "反序列化 RCE")),
            (("struts2", "struts"), "Struts2", ("S2-系列漏洞检测", "OGNL 表达式注入", "devMode 远程执行")),
            (("nginx",), "Nginx", ("路径穿越(off-by-slash)", "CRLF 注入", "配置错误检测", "反向代理 SSRF")),
            (("apache", "httpd"), "Apache", ("目录列表", ".htaccess 访问", "CVE-2021-41773 路径穿越", "mod_status 泄露")),
            (("redis",), "Redis", ("未授权访问", "主从复制 RCE", "CONFIG SET 写文件", "SSRF gopher 利用")),
            (("joomla",), "Joomla", ("/administrator 弱口令", "扩展已知漏洞", "configuration.php 备份泄露")),
            (("drupal",), "Drupal", ("Drupalgeddon 已知漏洞", "/user/login 弱口令", "模块版本枚举")),
            (("magento",), "Magento", ("/admin 后台枚举", "REST API 越权", "历史反序列化漏洞")),
            (("gitlab",), "GitLab", ("用户枚举", "导入功能 SSRF", "项目与 Runner 越权")),
            (("jenkins",), "Jenkins", ("/script 控制台暴露", "匿名读取", "CLI 与插件已知漏洞")),
            (("nextcloud",), "Nextcloud", ("WebDAV 越权", "共享链接枚举", "应用插件已知漏洞")),
            (("odoo",), "Odoo", ("数据库管理器暴露", "记录规则越权", "QWeb 模板注入")),
            (("fastapi",), "FastAPI", ("/docs OpenAPI 泄露", "对象级授权缺失", "Pydantic 参数边界绕过")),
            (("flask",), "Flask", ("Werkzeug Debug PIN", "SECRET_KEY 泄露", "Jinja2 SSTI")),
            (("express", "node.js", "nodejs"), "Express / Node.js", ("原型污染", "NoSQL 注入", "调试端点与 source map 泄露")),
            (("tomcat",), "Apache Tomcat", ("/manager 弱口令", "AJP Ghostcat", "示例应用与版本泄露")),
            (("iis", "asp.net", "aspnet"), "IIS / ASP.NET", ("ViewState 篡改", "短文件名枚举", "web.config 备份泄露")),
            (("liferay",), "Liferay", ("Portlet 权限绕过", "JSON Web Service 暴露", "文档导入 XXE")),
            (("moodle",), "Moodle", ("/login/index.php 弱口令", "课程与用户 API 越权", "插件已知漏洞")),
            (("open edx", "edx"), "Open edX", ("课程 API 越权", "OAuth 配置错误", "调试与静态资源泄露")),
            (("blackboard",), "Blackboard Learn", ("JSESSIONID 会话固定", "课程内容越权", "WebDAV 与历史插件漏洞")),
            (("sakai",), "Sakai", ("/portal 登录枚举", "/direct API 越权", "工具插件已知漏洞")),
            (("phpmyadmin",), "phpMyAdmin", ("弱口令", "setup 页面暴露", "版本相关 RCE/文件读取")),
            (("grafana",), "Grafana", ("匿名面板访问", "数据源代理 SSRF", "插件与路径穿越漏洞")),
            (("kibana",), "Kibana", ("未授权访问", "Dev Tools 暴露", "Saved Objects 越权")),
            (("elasticsearch",), "Elasticsearch", ("未授权 REST API", "索引数据泄露", "脚本执行配置审计")),
            (("docker registry",), "Docker Registry", ("/v2/_catalog 未授权", "镜像清单泄露", "敏感层文件提取")),
        )

        try:
            stack_result = self._pattern_engine().recommend_stack(fingerprints)
        except Exception:
            stack_result = {}
        try:
            waf_techniques = list(self._technique_memory().best_for_waf(waf, limit=5)) if waf else []
        except Exception:
            waf_techniques = []
        try:
            fingerprint_records = list(self._fingerprint_database().list())
        except Exception:
            fingerprint_records = []

        matched_records = []
        for record in fingerprint_records:
            record_name = str(record.get("name") or "").strip()
            if record_name and record_name.casefold() in observed_text:
                matched_records.append(record)
        metadata_endpoints = list(dict.fromkeys(str(endpoint) for record in matched_records for endpoint in record.get("default_endpoints", []) if str(endpoint or "").strip()))
        metadata_cves = list(dict.fromkeys(str(cve) for record in matched_records for cve in record.get("cves", []) if str(cve or "").strip()))

        def slug(value: str) -> str:
            return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")

        def classify(clue: str) -> tuple[str, str, dict[str, Any], str, str]:
            lowered = clue.casefold()
            match = re.search(r"(?:https?://[^\s]+|/[A-Za-z0-9_./?=-]+)", clue)
            endpoint = match.group(0) if match else ""
            if "弱口令" in clue:
                return "weak_password_bruteforce", "authentication", {"chain_name": "login_to_admin", "endpoint": endpoint}, "hunter_session_execute_chain", "P0"
            if any(term in clue for term in ("认证绕过", "未授权", "越权", "会话固定", "Cookie 篡改", "票据伪造")):
                return "access_control_bypass", "authentication_bypass", {"endpoint": endpoint}, "hunter_auto_access_control", "P0"
            if "SQL 注入" in clue or "nosql" in lowered:
                return "sql_injection_probe", "sqli", {"endpoint": endpoint}, "hunter_auto_sqli", "P0"
            if "SSRF" in clue or "开放重定向" in clue or "gopher" in lowered:
                return "ssrf_redirect_probe", "ssrf_open_redirect", {"endpoint": endpoint}, "hunter_auto_ssrf", "P1"
            if any(term in clue for term in ("文件上传", "写文件", "RCE", "远程执行", "命令执行", "表达式注入", "OGNL", "SpEL", "SSTI", "反序列化")):
                return "code_execution_chain", "file_upload", {"chain_name": "file_upload_to_shell", "endpoint": endpoint}, "hunter_session_execute_chain", "P1"
            if "XSS" in clue:
                return "xss_probe", "xss", {"endpoint": endpoint}, "hunter_auto_xss", "P1"
            if any(term in clue for term in ("泄露", "暴露", "目录列表", "备份", "枚举", "配置错误", "路径穿越", "CRLF", "已知漏洞", "CVE-")):
                return "information_disclosure_probe", "information_disclosure", {"mode": "standard", "endpoint": endpoint}, "hunter_scan_plan", "P1"
            return "targeted_stack_probe", "baseline", {"mode": "standard", "endpoint": endpoint}, "hunter_scan_plan", "P2"

        strategies = []
        used_strategy_ids: dict[str, int] = {}
        for aliases, product, clues in clue_catalog:
            if not any(alias.casefold() in observed_text for alias in aliases):
                continue
            for clue in clues:
                strategy_id, kind, tool_args, tool, priority = classify(clue)
                duplicate_index = used_strategy_ids.get(strategy_id, 0)
                used_strategy_ids[strategy_id] = duplicate_index + 1
                clue_id = (
                    strategy_id
                    if duplicate_index == 0
                    else f"{strategy_id}_{slug(product)}_{slug(clue)}"
                )
                metadata = []
                if metadata_endpoints:
                    metadata.append("fingerprint endpoints: " + ", ".join(metadata_endpoints[:4]))
                if metadata_cves:
                    metadata.append("fingerprint CVEs: " + ", ".join(metadata_cves[:4]))
                reason = f"已识别 {product}；攻击线索：{clue}"
                if metadata:
                    reason += "；" + "；".join(metadata)
                strategies.append({"strategy_id": clue_id, "title": f"{product} {clue}", "tool": tool, "tool_args": {key: value for key, value in tool_args.items() if value not in (None, "")}, "priority": priority, "reason": reason, "kind": kind, "source": "fingerprint_clue"})

        for record in matched_records:
            record_name = str(record.get("name") or "").strip()
            record_slug = slug(record_name) or "technology"
            for endpoint in record.get("default_endpoints", []) or []:
                endpoint = str(endpoint or "").strip()
                if not endpoint:
                    continue
                strategies.append({"strategy_id": f"fingerprint_endpoint_{record_slug}_{slug(endpoint) or 'root'}", "title": f"{record_name} 默认端点验证：{endpoint}", "tool": "hunter_scan_plan", "tool_args": {"mode": "standard", "endpoint": endpoint}, "priority": "P1", "reason": f"FingerprintDatabase 为已识别的 {record_name} 提供默认端点 {endpoint}。", "kind": "information_disclosure", "source": "fingerprint_database"})
            for cve in record.get("cves", []) or []:
                cve = str(cve or "").strip()
                if not cve:
                    continue
                strategies.append({"strategy_id": f"fingerprint_cve_{record_slug}_{slug(cve)}", "title": f"{record_name} {cve} 适用性验证", "tool": "hunter_scan_plan", "tool_args": {"mode": "standard"}, "priority": "P1", "reason": f"FingerprintDatabase 将 {cve} 与已识别的 {record_name} 关联；先验证版本和暴露面。", "kind": "information_disclosure", "source": "fingerprint_database"})

        primary = stack_result.get("primary") if isinstance(stack_result, Mapping) else None
        if isinstance(primary, Mapping) and primary.get("name"):
            stack_name = str(primary["name"])
            follow_ups = [str(item) for item in (primary.get("follow_ups") or [])]
            reason = str(primary.get("description") or "PatternEngine 根据已识别技术栈推荐后续验证。")
            if follow_ups:
                reason += "；建议关注：" + ", ".join(follow_ups)
            strategies.append({"strategy_id": "stack_" + (slug(stack_name) or "recommendation"), "title": f"技术栈策略：{stack_name}", "tool": "hunter_scan_plan", "tool_args": {"mode": "standard"}, "priority": "P1", "reason": reason, "kind": "baseline", "source": "pattern_engine"})
        for technique in waf_techniques:
            if not isinstance(technique, Mapping):
                continue
            technique_name = str(technique.get("name") or "").strip()
            if not technique_name:
                continue
            try:
                success_rate = float(technique.get("success_rate") or 0.0)
            except (TypeError, ValueError):
                success_rate = 0.0
            strategies.append({"strategy_id": "waf_" + (slug(technique_name) or "bypass"), "title": f"{waf} WAF 绕过策略：{technique_name}", "tool": "hunter_scan_plan", "tool_args": {"mode": "standard"}, "priority": "P1" if success_rate > 0 else "P2", "reason": f"TechniqueMemory 对 {waf} 的历史成功率为 {success_rate:.0%}；建议策略：{technique_name}。", "kind": "baseline", "source": "technique_memory"})
        if not strategies:
            strategies.append({"strategy_id": "baseline_stack_scan", "title": "通用技术栈攻击面扫描", "tool": "hunter_scan_plan", "tool_args": {"mode": "standard"}, "priority": "P2", "reason": "未找到专用栈或 WAF 策略，继续使用通用攻击面分析。", "kind": "baseline", "source": "fallback"})

        priority_order = {"P0": 0, "P1": 1, "P2": 2}
        unique = {str(item["strategy_id"]): item for item in strategies}
        return sorted(unique.values(), key=lambda item: (priority_order.get(str(item.get("priority", "P2")), 2), str(item.get("strategy_id", ""))))
    def stage_attack_surface(
        self,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        profile = context.get("target_profile", {})
        endpoints = list(profile.get("api_endpoints", []))
        if not endpoints:
            endpoints = [
                {
                    "url": context["target_url"],
                    "parameters": profile.get("params", []),
                }
            ]
        fingerprints = dict(profile.get("fingerprints", {}))
        target_type = str(
            profile.get("target_type")
            or fingerprints.get("target_type")
            or "generic_web"
        )
        try:
            stack_strategy = self._pattern_engine().recommend_stack(
                fingerprints
            )
        except Exception:
            stack_strategy = {
                "primary": None,
                "alternatives": [],
                "confidence": 0.0,
                "evidence": [],
            }
        form_endpoints = []
        for form in profile.get("forms", []):
            if not isinstance(form, Mapping):
                continue
            form_endpoints.append(
                {
                    "url": form.get("action") or context["target_url"],
                    "method": form.get("method") or "POST",
                    "parameters": form.get("inputs") or [],
                    "source": "form",
                }
            )
        for redirect in profile.get("auth_redirects", []):
            form_endpoints.append(
                {
                    "url": redirect,
                    "method": "GET",
                    "parameters": [],
                    "source": "authentication_redirect",
                }
            )
        endpoints = self._normalise_endpoints(
            [*endpoints, *form_endpoints],
            limit=max(
                int(context["profile"].get("max_endpoints", 100)),
                len(endpoints) + len(form_endpoints),
            ),
        )
        queue = []
        for raw_endpoint in endpoints:
            endpoint = (
                dict(raw_endpoint)
                if isinstance(raw_endpoint, Mapping)
                else {"url": str(raw_endpoint)}
            )
            target = urljoin(
                str(context["target_url"]).rstrip("/") + "/",
                str(endpoint.get("url") or context["target_url"]),
            )
            parameters = _parameter_names(endpoint.get("parameters", []))
            lowered = target.casefold()
            parameter_patterns = [
                self._pattern_engine().match_parameter(
                    parameter,
                    context=target,
                )
                for parameter in parameters
            ]
            password_parameters = [
                parameter
                for parameter in parameters
                if any(
                    signal in parameter.casefold()
                    for signal in ("password", "passwd", "pwd")
                )
            ]
            authentication = bool(
                password_parameters
                or endpoint.get("source") == "authentication_redirect"
                or target_type
                in {"cas_authentication", "chaoxing_portal"}
                or any(
                    signal in lowered
                    for signal in (
                        "/login",
                        "/signin",
                        "/auth",
                        "/cas/",
                        "passport",
                    )
                )
            )
            injection_candidate = bool(
                parameters
                or any(
                    signal in lowered
                    for signal in ("search", "query", "keyword", "filter")
                )
            )
            matched_kinds = []
            if authentication:
                matched_kinds.append("authentication_bypass")
            if injection_candidate:
                matched_kinds.extend(("sqli", "xss"))
            if any(
                signal in lowered
                for signal in (
                    "/.git",
                    "/.env",
                    "swagger",
                    "openapi",
                    "actuator",
                    "server-status",
                    "backup",
                    ".bak",
                )
            ):
                matched_kinds.append("information_disclosure")
            if any(
                signal in lowered
                for signal in ("upload", "file", "avatar", "import")
            ):
                matched_kinds.append("file_upload")
            if any(
                signal in lowered
                for signal in ("/api/", "graphql", "swagger")
            ):
                matched_kinds.append("api_access_control")
            if any(
                signal in lowered
                for signal in ("redirect", "callback", "return", "url=")
            ):
                matched_kinds.append("ssrf_open_redirect")
            if any(
                signal in lowered
                for signal in ("register", "signup", "captcha")
            ):
                matched_kinds.append("registration")
            if not matched_kinds:
                matched_kinds.append("baseline")
            for kind in dict.fromkeys(matched_kinds):
                queue.append(
                    {
                        "kind": kind,
                        "priority": (
                            "P0"
                            if ATTACK_PRIORITY.get(kind, 99) == 0
                            else "P1"
                            if ATTACK_PRIORITY.get(kind, 99) <= 2
                            else "P2"
                        ),
                        "target": target,
                        "method": str(endpoint.get("method") or "GET").upper(),
                        "parameters": parameters,
                        "parameter_patterns": parameter_patterns,
                        "target_type": target_type,
                        "stack_strategy": stack_strategy,
                    }
                )
        if not any(
            item.get("kind") == "information_disclosure"
            for item in queue
        ):
            queue.append(
                {
                    "kind": "information_disclosure",
                    "priority": "P2",
                    "target": str(context["target_url"]),
                    "method": "GET",
                    "parameters": [],
                    "parameter_patterns": [],
                    "target_type": target_type,
                    "stack_strategy": stack_strategy,
                }
            )
        base_target = str(context["target_url"])
        for item in self._auto_attack_strategy(fingerprints):
            strategy = dict(item)
            args = dict(strategy.get("tool_args") or {})
            endpoint = str(args.get("endpoint") or "").strip()
            strategy["target"] = urljoin(
                base_target.rstrip("/") + "/",
                endpoint or base_target,
            )
            strategy.setdefault("method", "GET")
            strategy.setdefault("parameters", [])
            strategy.setdefault("parameter_patterns", [])
            strategy.setdefault("target_type", target_type)
            strategy.setdefault("stack_strategy", stack_strategy)
            queue.append(strategy)
        priority_order = {"P0": 0, "P1": 1, "P2": 2}

        def queue_priority(item: Mapping[str, Any]) -> int:
            value = item.get("priority", 99)
            if isinstance(value, int):
                if value == 0:
                    return 0
                if value <= 2:
                    return 1
                return 2
            return priority_order.get(str(value), 2)

        queue = sorted(
            _unique(queue),
            key=lambda item: (
                queue_priority(item),
                1 if item.get("strategy_id") else 0,
                str(item.get("target", "")),
                str(item.get("kind", "")),
            ),
        )[: int(context["profile"]["max_attack_surfaces"])]
        return {
            "attack_surface": {
                "target_type": target_type,
                "stack_strategy": stack_strategy,
                "identified": queue,
            },
            "attack_queue": queue,
        }

    def _technique_recommendations(
        self,
        context: Mapping[str, Any],
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        fingerprints = context.get("target_profile", {}).get(
            "fingerprints",
            {},
        )
        waf = _fingerprint_name(fingerprints.get("waf")) or "*"
        ranked = list(
            self._technique_memory().best_for_waf(waf, limit=limit)
        )
        target_memory = self._target_memory()
        if hasattr(target_memory, "query_target"):
            history = target_memory.query_target(context["target_url"])
            successful = [
                {
                    "name": item.get("tool", ""),
                    "success_rate": 1.0,
                    "source": "target_history",
                }
                for item in reversed(history.get("attack_history", []))
                if item.get("success") and item.get("tool")
            ]
            ranked = successful + ranked
        if hasattr(target_memory, "similar_targets"):
            for similar in target_memory.similar_targets(
                context["target_url"],
                limit=5,
            ):
                if not hasattr(target_memory, "query_target"):
                    break
                similar_history = target_memory.query_target(
                    similar.get("url", "")
                )
                ranked.extend(
                    {
                        "name": item.get("tool", ""),
                        "success_rate": float(
                            similar.get("similarity", 0)
                        ),
                        "source": "similar_stack_history",
                        "similar_target": similar.get("url", ""),
                    }
                    for item in reversed(
                        similar_history.get("attack_history", [])
                    )
                    if item.get("success") and item.get("tool")
                )
        unique_ranked = []
        seen_names = set()
        for item in ranked:
            name = str(item.get("name") or "").strip()
            if not name or name in seen_names:
                continue
            seen_names.add(name)
            unique_ranked.append(item)
        return unique_ranked[:limit]

    @staticmethod
    def _reasoning_technologies(fingerprints: Mapping[str, Any]) -> list[str]:
        technologies = []
        for value in fingerprints.values():
            if isinstance(value, Mapping):
                value = value.get("name") or value.get("value") or value.get("type")
            values = value if isinstance(value, (list, tuple, set)) else [value]
            for item in values:
                name = str(item or "").strip()
                if name and name not in technologies:
                    technologies.append(name)
        return technologies

    @staticmethod
    def _reasoning_cookies(profile: Mapping[str, Any]) -> dict[str, str]:
        cookies = dict(profile.get("cookies") or {})
        raw_cookie = str(
            profile.get("session", {}).get("cookie", "")
            or profile.get("session_cookie", "")
        )
        for part in raw_cookie.split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name and value:
                cookies.setdefault(name, value)
        return cookies

    def _reasoning_facts(self, context: Mapping[str, Any]) -> dict[str, Any]:
        profile = dict(context.get("target_profile") or {})
        fingerprints = dict(profile.get("fingerprints") or {})
        cookies = self._reasoning_cookies(profile)
        target_type = str(profile.get("target_type") or "general_web")
        authentication = str(profile.get("authentication") or "")
        if not authentication:
            if target_type == "cas_authentication":
                authentication = "cas_sso"
            elif cookies:
                authentication = "session_cookie"
            else:
                authentication = "none"
        endpoints = list(profile.get("api_endpoints") or [])
        endpoints.extend(
            item.get("target")
            for item in context.get("attack_queue", [])
            if isinstance(item, Mapping) and item.get("target")
        )
        waf = (
            profile.get("waf")
            or fingerprints.get("waf")
            or profile.get("stealth_scan", {}).get("waf")
        )
        if waf and not isinstance(waf, Mapping):
            waf = {"type": str(waf), "confidence": 1.0}
        captcha = profile.get("captcha") or profile.get("stealth_scan", {}).get("captcha")
        forms = []
        for raw_form in profile.get("forms") or []:
            form = dict(raw_form) if isinstance(raw_form, Mapping) else {}
            form.setdefault("fields", list(form.get("inputs") or []))
            forms.append(form)
        return {
            "target_url": str(context.get("target_url") or profile.get("target_url") or ""),
            "target_type": target_type,
            "authentication": authentication,
            "captcha": captcha or None,
            "waf": waf or None,
            "endpoints": endpoints,
            "params": list(profile.get("params") or []),
            "forms": forms,
            "cookies": cookies,
            "technologies": self._reasoning_technologies(fingerprints),
        }

    @staticmethod
    def _merge_reasoned_queue(existing: Sequence[dict], reasoned: Sequence[dict]) -> list[dict]:
        replacements = {
            str(item.get("strategy_id")): dict(item)
            for item in reasoned
            if item.get("strategy_id")
        }
        merged = []
        seen = set()
        for raw_item in existing:
            item = dict(raw_item)
            strategy_id = str(item.get("strategy_id") or "")
            if strategy_id and strategy_id in seen:
                continue
            if strategy_id in replacements:
                replacement = replacements.pop(strategy_id)
                if str(item.get("status") or "") != "completed":
                    item = {**item, **replacement}
            if strategy_id:
                seen.add(strategy_id)
            merged.append(item)
        for strategy_id, item in replacements.items():
            if strategy_id not in seen:
                merged.append(item)
        return merged

    @staticmethod
    def _expand_reasoned_queue(queue: Sequence[dict]) -> list[dict]:
        tool_kinds = {
            "hunter_session_execute_chain": "authentication",
            "hunter_auto_sqli": "sqli",
            "hunter_auto_xss": "xss",
            "hunter_auto_ssrf": "ssrf_open_redirect",
            "hunter_auto_access_control": "api_access_control",
            "hunter_auto_idor": "api_access_control",
            "hunter_auto_csrf": "registration",
            "hunter_auto_jwt": "api_access_control",
            "hunter_browser_navigate": "authentication",
            "hunter_scan_plan": "baseline",
        }
        expanded = []
        for item in queue:
            actions = item.get("actions") if isinstance(item, Mapping) else None
            if not actions:
                expanded.append(dict(item))
                continue
            for action_index, raw_action in enumerate(actions, start=1):
                action = dict(raw_action)
                tool = str(action.get("tool") or "hunter_scan_plan")
                params = dict(action.get("params") or {})
                target = str(
                    params.get("target")
                    or params.get("target_url")
                    or item.get("target")
                    or ""
                )
                parameter = str(action.get("param") or params.get("param") or "")
                tool_args = dict(params)
                tool_args.pop("target", None)
                tool_args.pop("target_url", None)
                allowed_args = {
                    "hunter_auto_access_control": {"cookie"},
                    "hunter_auto_idor": {"cookie", "endpoint"},
                    "hunter_auto_sqli": {"param", "method", "case_slug", "deep_action"},
                    "hunter_auto_xss": {"param", "method", "verify_with_browser"},
                    "hunter_auto_ssrf": {"param", "method", "collaborator"},
                    "hunter_auto_csrf": {"cookie"},
                    "hunter_auto_jwt": {"cookie", "token"},
                    "hunter_browser_navigate": {"wait_for"},
                    "hunter_scan_plan": {"mode", "phases"},
                }
                if tool == "hunter_session_execute_chain":
                    tool_args = {
                        "chain_name": str(action.get("chain") or "login_to_admin"),
                        "params": params,
                    }
                    login_path = str(params.get("login_path") or "")
                    if login_path:
                        tool_args["endpoint"] = login_path
                elif tool in allowed_args:
                    tool_args = {
                        key: value
                        for key, value in tool_args.items()
                        if key in allowed_args[tool]
                    }
                expanded.append({
                    "kind": str(action.get("kind") or tool_kinds.get(tool, "baseline")),
                    "priority": str(action.get("priority") or "P2"),
                    "target": target,
                    "method": str(action.get("method") or params.get("method") or "GET").upper(),
                    "parameters": [parameter] if parameter else [],
                    "strategy_id": item.get("strategy_id"),
                    "reasoning_action_id": f"{item.get('strategy_id', 'reasoned')}:{action_index}",
                    "strategy_title": item.get("title", ""),
                    "condition": item.get("condition", ""),
                    "status": item.get("status", ""),
                    "tool": tool,
                    "tool_args": tool_args,
                })
        return expanded

    def stage_attack_execution(
        self,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        facts = self._reasoning_facts(context)
        evidence = list(context.get("evidence") or [])
        observations = context.get("observations") or {}

        def collect_observations(value: Any) -> None:
            if isinstance(value, Mapping):
                if any(key in value for key in ("type", "summary", "status_code")):
                    evidence.append(dict(value))
                for nested in value.values():
                    collect_observations(nested)
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                for nested in value:
                    collect_observations(nested)

        collect_observations(observations)
        evidence.extend(
            item
            for item in context.get("target_profile", {}).get("browser_evidence", [])
            if isinstance(item, Mapping)
        )
        try:
            recommendations = self._technique_recommendations(context)
        except Exception:
            recommendations = []
        technique_memory = {"recommendations": recommendations}
        provided_strategies = context.get("strategies")
        if provided_strategies is not None:
            reasoned_strategies = [
                dict(item)
                for item in provided_strategies
                if isinstance(item, Mapping)
            ]
        else:
            reasoner = self._service("attack_reasoner", AttackReasoner)
            reasoned_strategies = reasoner.reason(
                facts,
                evidence,
                technique_memory,
            )
        attack_queue = self._merge_reasoned_queue(
            list(context.get("attack_queue") or []),
            reasoned_strategies,
        )
        if isinstance(context, dict):
            context["attack_queue"] = attack_queue
        execution_queue = self._expand_reasoned_queue(attack_queue)
        tools = {
            "authentication_bypass": "hunter_auto_access_control",
            "authentication": "hunter_auto_access_control",
            "sqli": "hunter_auto_sqli",
            "sqli_xss": "hunter_auto_sqli",
            "xss": "hunter_auto_xss",
            "information_disclosure": "hunter_auto_access_control",
            "file_upload": "hunter_auto_access_control",
            "api_access_control": "hunter_auto_access_control",
            "ssrf_open_redirect": "hunter_auto_ssrf",
            "registration": "hunter_auto_csrf",
            "baseline": "hunter_scan_plan",
        }
        chains = {
            "authentication_bypass": "login_to_admin",
            "authentication": "login_to_admin",
            "sqli": "sqli_to_data_dump",
            "sqli_xss": "sqli_to_data_dump",
            "file_upload": "file_upload_to_shell",
            "api_access_control": "jwt_to_account_takeover",
            "ssrf_open_redirect": "ssrf_to_internal_access",
        }
        profile = context.get("target_profile", {})
        session_id = str(
            context.get("session_id")
            or profile.get("session_id")
            or profile.get("session", {}).get("session_id")
            or ""
        )
        cookie = str(
            profile.get("session", {}).get("cookie", "")
            or profile.get("session_cookie", "")
            or ""
        )
        attempts: list[dict[str, Any]] = []
        handoffs: list[dict[str, Any]] = []
        browser = None
        browser_operations: list[dict[str, Any]] = []
        browser_evidence: list[dict[str, Any]] = []
        has_injected_executor = bool(
            self.services.get("auto_tool_runner")
            or any(
                str(name).startswith("hunter_auto_")
                for name in self.services
            )
        )
        executable_session = False
        if session_id and not has_injected_executor:
            executable_session = callable(
                getattr(self._stealth_client(), "detection_session", None)
            )
        execution_mode = str(
            context.get("profile", {}).get("mode") or "interactive"
        ).casefold()
        executed = bool(
            has_injected_executor
            or (
                session_id
                and execution_mode == "autopilot"
                and executable_session
            )
        )
        explicit_tools = {
            "hunter_auto_access_control",
            "hunter_auto_idor",
            "hunter_auto_sqli",
            "hunter_auto_ssrf",
            "hunter_auto_xss",
            "hunter_auto_csrf",
            "hunter_auto_jwt",
            "hunter_browser_navigate",
            "hunter_scan_plan",
            "hunter_session_execute_chain",
        }
        base_target = str(context["target_url"])
        completed_attacks = context.get("completed_attacks", set())
        if not isinstance(completed_attacks, set):
            completed_attacks = set(completed_attacks or [])
        if isinstance(context, dict):
            context["completed_attacks"] = completed_attacks
        waf_type = _fingerprint_name(
            profile.get("fingerprints", {}).get("waf")
        )

        def attack_key(kind: str, tool: str, target: str) -> str:
            normalized_kind = (
                "authentication"
                if kind in {"authentication_bypass", "authentication"}
                else kind
            )
            return f"{normalized_kind}|{tool}|{target}"

        def response_details(result: Mapping[str, Any]) -> dict[str, Any]:
            payload = self._result_payload(result)
            evidence = payload.get("evidence") or result.get("evidence") or {}
            response = (
                evidence.get("response", {})
                if isinstance(evidence, Mapping)
                else {}
            )
            headers = (
                payload.get("headers")
                or result.get("headers")
                or response.get("headers")
                or {}
            )
            status_code = (
                payload.get("status_code")
                or result.get("status_code")
                or response.get("status_code")
                or 0
            )
            try:
                status_code = int(status_code)
            except (TypeError, ValueError):
                status_code = 0
            used_payload = (
                payload.get("payload")
                or result.get("payload")
                or (
                    evidence.get("payload")
                    if isinstance(evidence, Mapping)
                    else ""
                )
                or ""
            )
            return {
                "payload": used_payload,
                "status_code": status_code,
                "headers": dict(headers) if isinstance(headers, Mapping) else {},
            }

        def record_auto_attempt(
            tool_name: str,
            target_url: str,
            result: Mapping[str, Any],
        ) -> dict[str, Any]:
            details = response_details(result)
            success = (
                details["status_code"] not in {403, 429, 503}
                if details["status_code"]
                else self._result_success(result)
            )
            memory = self._technique_memory()
            record_attempt = getattr(memory, "record_attempt", None)
            if callable(record_attempt):
                record_attempt(
                    technique_name=tool_name,
                    target_url=target_url,
                    waf_type=waf_type,
                    success=success,
                    metadata={
                        "payload": details["payload"],
                        "status_code": details["status_code"],
                    },
                )
            return {**details, "success": success}

        def redirected_to_login(details: Mapping[str, Any]) -> bool:
            if details.get("status_code") != 302:
                return False
            location = next(
                (
                    str(value)
                    for name, value in details.get("headers", {}).items()
                    if str(name).casefold() == "location"
                ),
                "",
            ).casefold()
            return any(
                marker in location
                for marker in ("/login", "/signin", "/auth", "/cas/")
            )

        for index, item in enumerate(execution_queue, start=1):
            kind = str(item.get("kind") or "baseline")
            target = str(item.get("target") or context["target_url"])
            parameters = _parameter_names(item.get("parameters", []))
            parameter = parameters[0] if parameters else (
                "url" if kind == "ssrf_open_redirect" else "category"
            )
            parameter_patterns = [
                self._pattern_engine().match_parameter(
                    name,
                    context=target,
                )
                for name in parameters
            ]
            recommendations = self._technique_recommendations(context)
            preflight = {
                "parameter_patterns": parameter_patterns,
                "recommended_techniques": recommendations,
                "technology_stack": profile.get("fingerprints", {}),
                "target_type": profile.get("target_type", "generic_web"),
            }
            requested_tool = str(item.get("tool") or "").strip()
            explicit_tool = (
                requested_tool
                if requested_tool in explicit_tools
                else "hunter_scan_plan"
                if requested_tool
                else ""
            )
            tool = explicit_tool or tools.get(kind, "hunter_scan_plan")
            current_attack = attack_key(kind, tool, target)
            if (
                current_attack in completed_attacks
                or str(item.get("status") or "") == "completed"
                or (
                    kind in {"authentication_bypass", "authentication"}
                    and bool(context.get("authentication_required"))
                )
            ):
                continue
            arguments = {
                "target": target,
                "param": parameter,
                "method": str(item.get("method") or "GET").upper(),
                "cookie": cookie,
            }
            if tool == "hunter_auto_xss":
                arguments["param"] = parameters[0] if parameters else "q"
            elif tool == "hunter_auto_ssrf":
                arguments["param"] = parameters[0] if parameters else "url"
            elif tool in {
                "hunter_auto_access_control",
                "hunter_auto_idor",
                "hunter_auto_csrf",
            }:
                arguments = {"target": target, "cookie": cookie}
            elif tool == "hunter_auto_jwt":
                arguments = {"target": target, "cookie": cookie}
            elif tool == "hunter_browser_navigate":
                arguments = {"target_url": target}
            elif tool == "hunter_scan_plan":
                arguments = {
                    "target": target,
                    "mode": context.get("profile", {}).get("name", "standard"),
                }
            if explicit_tool:
                supplied = dict(item.get("tool_args") or {})
                if tool == "hunter_session_execute_chain":
                    endpoint = str(supplied.get("endpoint") or "").strip()
                    chain_name = str(
                        supplied.get("chain_name") or "login_to_admin"
                    )
                    chain_params = dict(supplied.get("params") or {})
                    chain_params.setdefault("target_url", base_target)
                    if endpoint:
                        chain_params.setdefault("login_path", endpoint)
                    if chain_name == "login_to_admin":
                        chain_params.setdefault(
                            "username",
                            "${credentials.username}",
                        )
                        chain_params.setdefault(
                            "password",
                            "${credentials.password}",
                        )
                    arguments = {
                        "session_id": session_id
                        or "${stealth_session.session_id}",
                        "chain_name": chain_name,
                        "params": chain_params,
                    }
                else:
                    supplied.pop("endpoint", None)
                    if tool == "hunter_scan_plan":
                        supplied = {
                            key: value
                            for key, value in supplied.items()
                            if key in {"mode", "phases"}
                        }
                    arguments.update(supplied)
            elif session_id:
                arguments["session_id"] = session_id
            attempt = {
                "tool": tool,
                "technique": tool,
                "target": target,
                "parameter": parameter,
                "method": arguments.get("method", "GET"),
                "attack_surface": kind,
                "preflight": preflight,
                "arguments": dict(arguments),
            }
            if executed and not explicit_tool:
                result = self._invoke_tool(tool, arguments)
                payload = self._result_payload(result)
                auto_details = (
                    record_auto_attempt(tool, target, result)
                    if tool.startswith("hunter_auto_")
                    else {
                        **response_details(result),
                        "success": self._result_success(result),
                    }
                )
                attempt.update({
                    "response": result,
                    "status": result.get("status", payload.get("status", "")),
                    "success": auto_details["success"],
                    "vulnerable": bool(
                        payload.get("vulnerable")
                        or result.get("vulnerable")
                    ),
                    "confidence": float(
                        payload.get("confidence")
                        or result.get("confidence")
                        or 0.0
                    ),
                    "session_id": session_id,
                    "technique_recorded": tool.startswith("hunter_auto_"),
                })
                if redirected_to_login(auto_details):
                    if isinstance(context, dict):
                        context["authentication_required"] = True
                        context["authentication_status"] = "需要认证"
                    attempt["authentication_required"] = True
                if payload.get("findings"):
                    attempt["findings"] = payload["findings"]
                if (
                    kind in {"authentication_bypass", "authentication"}
                    and not attempt.get("authentication_required")
                ):
                    response_url = str(
                        payload.get("url")
                        or payload.get("final_url")
                        or ""
                    )
                    redirected = response_url and response_url != target
                    if redirected or str(payload.get("status_code", "")) in {
                        "301", "302", "303", "307", "308"
                    }:
                        for username, password in WEAK_CREDENTIALS:
                            weak_args = {
                                "target": response_url or target,
                                "param": "username",
                                "method": "POST",
                                "session_id": session_id,
                                "username": username,
                                "password": password,
                            }
                            weak_result = self._invoke_tool(
                                "hunter_auto_access_control",
                                weak_args,
                            )
                            weak_payload = self._result_payload(weak_result)
                            weak_details = record_auto_attempt(
                                "hunter_auto_access_control",
                                response_url or target,
                                weak_result,
                            )
                            attempts.append({
                                "tool": "hunter_auto_access_control",
                                "technique": "weak-credential-probe",
                                "target": response_url or target,
                                "parameter": "username",
                                "arguments": {
                                    **weak_args,
                                    "password": "REDACTED",
                                },
                                "response": weak_result,
                                "success": weak_details["success"],
                                "vulnerable": bool(
                                    weak_payload.get("vulnerable")
                                    or weak_result.get("vulnerable")
                                ),
                                "confidence": float(
                                    weak_payload.get("confidence")
                                    or weak_result.get("confidence")
                                    or 0.0
                                ),
                                "session_id": session_id,
                                "technique_recorded": True,
                            })
                            if attempts[-1]["success"]:
                                break
                attempts.append(attempt)
                if isinstance(item, dict):
                    item["status"] = "completed"
                completed_attacks.add(current_attack)
            else:
                handoffs.append({
                    "tool": tool,
                    "execution": "deferred",
                    "status": "proposed",
                    "target": target,
                    "attack_surface": kind,
                    "http_transport": "stealth_http_client",
                    "preflight": preflight,
                    "arguments": arguments,
                })
            if (
                session_id
                and not explicit_tool
                and kind in chains
                and attempt.get("success")
                and not attempt.get("vulnerable")
                and not attempt.get("authentication_required")
            ):
                chain_arguments = {
                    "session_id": session_id,
                    "chain_name": chains[kind],
                    "params": {
                        "target_url": target,
                        "probe_path": urlparse(target).path or "/",
                        "parameter_name": parameter,
                        "request_method": str(
                            item.get("method") or "GET"
                        ).upper(),
                        "session_cookie": cookie,
                        "preferred_techniques": [
                            row.get("name")
                            for row in recommendations
                            if row.get("name")
                        ],
                    },
                }
                chain_result = self._invoke_tool(
                    "hunter_session_execute_chain",
                    chain_arguments,
                )
                attempts.append({
                    "tool": "hunter_session_execute_chain",
                    "technique": chains[kind],
                    "target": target,
                    "parameter": parameter,
                    "arguments": chain_arguments,
                    "response": chain_result,
                    "success": self._result_success(chain_result),
                    "vulnerable": False,
                    "confidence": 0.0,
                    "session_id": session_id,
                })
            if kind in {
                "authentication_bypass",
                "authentication",
                "file_upload",
                "registration",
            }:
                if self.call_mcp_tool is None:
                    handoffs.append({
                        "tool": "hunter_browser_navigate",
                        "execution": "deferred",
                        "status": "proposed",
                        "arguments": {"target_url": target},
                    })
                else:
                    if browser is None:
                        browser = self._browser_controller()
                    if not self._browser_execution_enabled(browser):
                        handoffs.append({
                            "tool": "hunter_browser_navigate",
                            "execution": "deferred",
                            "status": "proposed",
                            "arguments": {"target_url": target},
                        })
                    else:
                        operation, evidence = self._run_browser_operation(
                            "dynamic_form_navigate",
                            lambda target=target: browser.navigate_and_wait(
                                target,
                                {
                                    "network_idle": True,
                                    "timeout_ms": (
                                        self._scan_options(
                                            context.get("profile", {})
                                        )["timeout"]
                                        * 1000
                                    ),
                                },
                                execute=True,
                            ),
                        )
                        browser_operations.append(operation)
                        browser_evidence.extend(evidence)
                        if (
                            operation.get("status") != "ok"
                            or operation.get("execution") != "completed"
                        ):
                            handoffs.append({
                                "tool": "hunter_browser_navigate",
                                "execution": "deferred",
                                "status": "proposed",
                                "arguments": {"target_url": target},
                            })
            elif not executed and kind in chains:
                handoffs.append({
                    "tool": "hunter_session_execute_chain",
                    "execution": "deferred",
                    "status": "proposed",
                    "target": target,
                    "attack_surface": kind,
                    "http_transport": "stealth_http_client",
                    "arguments": {
                        "session_id": "${stealth_session.session_id}",
                        "chain_name": chains[kind],
                        "params": {
                            "target_url": target,
                            "probe_path": urlparse(target).path or "/",
                            "parameter_name": parameter,
                        },
                    },
                })
        if handoffs:
            return {
                "status": "deferred",
                "handoffs": handoffs,
                "attempts": attempts,
                "browser_operations": browser_operations,
                "browser_evidence": browser_evidence,
                "http_transport": "stealth_http_client",
                "attack_queue": attack_queue,
                "completed_attacks": sorted(completed_attacks),
            }
        return {
            "status": "completed",
            "handoffs": handoffs,
            "attempts": attempts,
            "browser_operations": browser_operations,
            "browser_evidence": browser_evidence,
            "http_transport": "stealth_http_client",
            "session_id": session_id,
            "attack_queue": attack_queue,
            "completed_attacks": sorted(completed_attacks),
        }

    @staticmethod
    def _response_records(context: Mapping[str, Any]) -> list[Any]:
        records = list(context.get("observations", {}).get("responses", []))
        attempts = context.get("stage_results", {}).get(
            "attack_execution",
            {},
        ).get("attempts", [])
        for attempt in attempts:
            if isinstance(attempt, Mapping) and any(
                key in attempt
                for key in ("response", "body", "text", "content")
            ):
                records.append(attempt)
        return records

    def stage_confirmation(
        self,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        findings = []
        false_positives = []
        for raw_response in self._response_records(context):
            record = (
                dict(raw_response)
                if isinstance(raw_response, Mapping)
                else {"body": raw_response}
            )
            for key in ("body", "text", "content", "response"):
                if key in record and record[key] is not None:
                    record[key] = str(record[key]).casefold()
            match = self._pattern_engine().match_response(record)
            claimed = str(
                record.get("vulnerability_type")
                or record.get("type")
                or ""
            ).strip().casefold()
            if claimed == "cmdi":
                claimed = "command_injection"
            matched = str(match.get("vulnerability_type") or "").casefold()
            reported = bool(
                record.get("vulnerable")
                or record.get("reported_vulnerable")
                or claimed
            )
            explicitly_confirmed = bool(
                record.get("confirmed")
                or str(record.get("status", "")).casefold() == "confirmed"
            )
            if matched and (not claimed or matched == claimed):
                findings.append(
                    {
                        "title": f"{matched} response pattern",
                        "type": matched,
                        "severity": (
                            "high"
                            if float(match.get("confidence", 0)) >= 0.9
                            else "medium"
                        ),
                        "status": "confirmed",
                        "confidence": match.get("confidence", 0),
                        "evidence": match.get("evidence", []),
                        "session_id": record.get("session_id", ""),
                    }
                )
                continue
            if explicitly_confirmed and claimed:
                findings.append(
                    {
                        "title": str(
                            record.get("title")
                            or f"{claimed} confirmed finding"
                        ),
                        "type": claimed,
                        "severity": str(record.get("severity") or "high"),
                        "status": "confirmed",
                        "confidence": float(record.get("confidence") or 1.0),
                        "evidence": list(record.get("evidence") or []),
                        "session_id": record.get("session_id", ""),
                    }
                )
                continue
            if reported:
                false_positives.append(
                    {
                        "title": str(
                            record.get("title")
                            or f"{claimed or 'reported finding'} lacks response confirmation"
                        ),
                        "type": claimed or matched or "unknown",
                        "status": "probable_false_positive",
                        "reason": (
                            "response fingerprint did not match the reported vulnerability"
                            if not matched
                            else f"response matched {matched}, not {claimed}"
                        ),
                        "response_fingerprint": match,
                    }
                )
        findings = _unique(findings)
        post_exploitation_handoffs = [
            {
                "tool": "hunter_post_exploit",
                "execution": "deferred",
                "requires_confirmation": finding.get("type")
                in {"command_injection", "rce"},
                "arguments": {
                    "session_id": finding.get("session_id")
                    or "${confirmed_finding.session_id}",
                    "vuln_type": finding.get("type", "unknown"),
                    "vuln_details": {
                        **finding,
                        "verification_depth": "deep",
                    },
                },
            }
            for finding in findings
        ]
        high_impact = [
            handoff
            for handoff in post_exploitation_handoffs
            if handoff["requires_confirmation"]
        ]
        result = {
            "findings": findings,
            "false_positives": false_positives,
            "post_exploitation_handoffs": post_exploitation_handoffs,
        }
        if high_impact:
            result.update(
                {
                    "confirmation_required": high_impact,
                    "reason": "post-exploitation requires analyst confirmation",
                }
            )
        return result

    def stage_evidence_learning(
        self,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        target = str(context["target_url"])
        target_memory = self._target_memory()
        technique_memory = self._technique_memory()
        profile = context.get("target_profile", {})
        fingerprints = dict(profile.get("fingerprints", {}))
        technology_stack = {
            key: value
            for key, value in fingerprints.items()
            if value not in (None, "", [], {})
        }
        previous = {}
        if hasattr(target_memory, "query_target"):
            try:
                previous = target_memory.query_target(target).get(
                    "fingerprints",
                    {},
                )
            except Exception:
                previous = {}
        target_memory.record_target(
            target,
            technology_stack=technology_stack,
        )
        new_fingerprints = {
            key: value
            for key, value in fingerprints.items()
            if value not in (None, "", [], {}) and previous.get(key) != value
        }
        if new_fingerprints and hasattr(target_memory, "record_fingerprint"):
            target_memory.record_fingerprint(target, new_fingerprints)
        for endpoint in profile.get("api_endpoints", []):
            if not hasattr(target_memory, "record_endpoint"):
                break
            item = (
                dict(endpoint)
                if isinstance(endpoint, Mapping)
                else {"url": str(endpoint)}
            )
            if item.get("url"):
                target_memory.record_endpoint(
                    target,
                    urljoin(
                        target.rstrip("/") + "/",
                        str(item["url"]),
                    ),
                    method=str(item.get("method") or "GET"),
                    parameters=_parameter_names(
                        item.get("parameters", [])
                    ),
                    injection_points=_parameter_names(
                        item.get("parameters", [])
                    ),
                    details={
                        "source": "unified-orchestrator",
                        "confidence": item.get("confidence", ""),
                    },
                )
        updates = []
        attempts = context.get("stage_results", {}).get(
            "attack_execution",
            {},
        ).get("attempts", [])
        waf = _fingerprint_name(fingerprints.get("waf"))
        for attempt in attempts:
            if (
                not isinstance(attempt, Mapping)
                or attempt.get("success") is None
                or attempt.get("technique_recorded")
            ):
                continue
            technique = attempt.get("technique") or attempt.get("tool")
            if not technique:
                continue
            success = bool(attempt["success"])
            technique_memory.record_attempt(
                target_url=str(attempt.get("target") or target),
                technique_name=str(technique),
                waf_type=waf,
                success=success,
                metadata={
                    key: value
                    for key, value in attempt.items()
                    if key not in {"response", "body", "text", "content"}
                },
            )
            if hasattr(target_memory, "record_attack"):
                target_memory.record_attack(
                    target,
                    tool=str(technique),
                    payload_metadata={
                        "target": attempt.get("target", target),
                        "parameter": attempt.get("parameter", ""),
                        "response_fingerprint": self._pattern_engine().match_response(
                            attempt
                        ),
                    },
                    success=success,
                    bypass_strategy=str(
                        attempt.get("bypass_strategy")
                        or attempt.get("technique")
                        or ""
                    ),
                )
            updates.append(
                {"technique": str(technique), "success": success}
            )
        findings = context.get("stage_results", {}).get(
            "vulnerability_confirmation",
            {},
        ).get("findings", [])
        for finding in findings:
            if (
                isinstance(finding, Mapping)
                and finding.get("status") == "confirmed"
                and hasattr(target_memory, "record_vulnerability")
            ):
                target_memory.record_vulnerability(
                    target,
                    vuln_type=str(finding.get("type") or "unknown"),
                    severity=str(finding.get("severity") or "info"),
                    status="confirmed",
                    details=dict(finding),
                )
        evidence = [
            {
                "summary": (
                    f"Deferred attack handoff: "
                    f"{handoff.get('tool', 'unknown')}"
                ),
                "source": "unified-orchestrator",
                "type": "handoff",
                "confidence": "pending",
            }
            for handoff in context.get("stage_results", {}).get(
                "attack_execution",
                {},
            ).get("handoffs", [])
        ]
        evidence.extend(
            dict(item)
            for item in profile.get("browser_evidence", [])
            if isinstance(item, Mapping)
        )
        evidence.extend(
            dict(item)
            for item in context.get("stage_results", {}).get(
                "attack_execution",
                {},
            ).get("browser_evidence", [])
            if isinstance(item, Mapping)
        )
        return {
            "evidence": evidence,
            "learning_updates": updates,
            "fingerprint_updates": [
                {
                    "kind": key,
                    "value": value,
                    "source": "target_profile",
                }
                for key, value in new_fingerprints.items()
            ],
            "post_exploitation_handoffs": context.get(
                "stage_results",
                {},
            ).get(
                "vulnerability_confirmation",
                {},
            ).get(
                "post_exploitation_handoffs",
                [],
            ),
        }


class OrchestratorRunner:
    """Execute the six native orchestration bridge stages end to end."""

    _PRIORITY = {"P0": 0, "P1": 1, "P2": 2}

    def __init__(
        self,
        bridge: UnifiedOrchestrationBridge,
        stealth_client: "StealthHTTPClient",
        reasoner: AttackReasoner,
    ) -> None:
        self.bridge = bridge
        self.stealth_client = stealth_client
        self.reasoner = reasoner
        services = getattr(self.bridge, "services", None)
        if isinstance(services, dict):
            services.setdefault("stealth_http_client", stealth_client)
            services.setdefault("attack_reasoner", reasoner)

    def run(self, target: str, options: dict | None = None) -> dict:
        """Run memory, recon, reasoning, execution, confirmation, and learning."""
        config = dict(options or {})
        profile = dict(config.get("profile") or {})
        for key in (
            "policy",
            "mode",
            "modules",
            "max_endpoints",
            "timeout",
            "session_id",
        ):
            if key in config:
                profile.setdefault(key, config[key])
        target_info: dict[str, Any] = {
            "url": target,
            "target_url": target,
            "profile": profile,
            "options": config,
            "phases_completed": [],
            "stage_results": {},
            "errors": [],
        }
        if config.get("session_id"):
            target_info["session_id"] = config["session_id"]
        if config.get("session_cookie") or config.get("cookie"):
            target_info["session_cookie"] = str(
                config.get("session_cookie") or config.get("cookie")
            )

        memory = self._run_stage("memory", self.bridge.stage_memory, target_info)
        self._apply_stage(target_info, "memory", memory)

        recon = self._run_stage("recon", self.bridge.stage_recon, target_info)
        self._apply_stage(target_info, "recon", recon)

        attack_surface = self._run_stage(
            "attack_surface",
            self.bridge.stage_attack_surface,
            target_info,
        )
        self._apply_stage(target_info, "attack_surface", attack_surface)

        facts = self._build_facts(target_info)
        evidence = self._evidence_items(recon.get("observations", []))
        memory_data = {
            "recommendations": list(
                memory.get("memo", {}).get("best_techniques", [])
            )
        }
        try:
            strategies = self.reasoner.reason(facts, evidence, memory_data)
        except Exception as exc:
            target_info["errors"].append(self._error("attack_surface", exc))
            strategies = []
        target_info["strategies"] = list(strategies or [])

        attack_results = [
            self._execute_strategy(strategy, target_info)
            for strategy in sorted(target_info["strategies"], key=self._priority)
        ]
        target_info["attack_results"] = attack_results
        execution = self._merge_attack_results(attack_results)
        target_info["stage_results"]["attack_execution"] = execution
        target_info.update(execution)
        target_info["phases_completed"].append("attack_execution")

        confirmation = self._run_stage(
            "confirmation",
            self.bridge.stage_confirmation,
            target_info,
        )
        target_info["stage_results"]["vulnerability_confirmation"] = confirmation
        target_info.update(confirmation)
        target_info["phases_completed"].append("confirmation")

        learning = self._run_stage(
            "evidence_learning",
            self.bridge.stage_evidence_learning,
            target_info,
        )
        self._apply_stage(target_info, "evidence_learning", learning)
        return target_info

    def _run_stage(self, name: str, operation, info: dict) -> dict:
        try:
            result = operation(info)
            return dict(result) if isinstance(result, Mapping) else {"result": result}
        except Exception as exc:
            info["errors"].append(self._error(name, exc))
            return {
                "status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

    @staticmethod
    def _error(stage: str, exc: Exception) -> dict[str, str]:
        return {
            "stage": stage,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    @staticmethod
    def _apply_stage(info: dict, name: str, result: Mapping[str, Any]) -> None:
        value = dict(result)
        info["stage_results"][name] = value
        info.update(value)
        info["phases_completed"].append(name)

    @staticmethod
    def _evidence_items(value: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        def collect(current: Any) -> None:
            if isinstance(current, Mapping):
                if any(key in current for key in ("type", "summary", "status_code")):
                    items.append(dict(current))
                else:
                    for nested in current.values():
                        collect(nested)
            elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
                for nested in current:
                    collect(nested)

        collect(value)
        return items

    def _build_facts(self, info: dict) -> dict:
        """Build the normalized fact dictionary consumed by AttackReasoner."""
        profile = dict(info.get("target_profile") or {})
        endpoints = list(
            profile.get("api_endpoints")
            or profile.get("endpoints")
            or info.get("endpoints")
            or []
        )
        params = _parameter_names(
            profile.get("params")
            or info.get("params")
            or []
        )
        forms = []
        for raw_form in profile.get("forms") or info.get("forms") or []:
            form = dict(raw_form) if isinstance(raw_form, Mapping) else {}
            form.setdefault("fields", list(form.get("inputs") or []))
            forms.append(form)

        cookies = dict(profile.get("cookies") or {})
        raw_cookie = str(
            profile.get("session", {}).get("cookie", "")
            or profile.get("session_cookie", "")
            or info.get("session_cookie", "")
        )
        for part in raw_cookie.split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name:
                cookies.setdefault(name, value)

        fingerprints = dict(profile.get("fingerprints") or {})
        technologies = []
        raw_technologies = list(profile.get("technologies") or [])
        raw_technologies.extend(fingerprints.values())
        for raw_value in raw_technologies:
            if isinstance(raw_value, Mapping):
                raw_value = (
                    raw_value.get("name")
                    or raw_value.get("value")
                    or raw_value.get("type")
                )
            values = raw_value if isinstance(raw_value, (list, tuple, set)) else [raw_value]
            for value in values:
                name = str(value or "").strip()
                if name and name not in technologies:
                    technologies.append(name)

        waf = (
            profile.get("waf")
            or fingerprints.get("waf")
            or profile.get("stealth_scan", {}).get("waf")
        )
        if waf and not isinstance(waf, Mapping):
            waf = {"type": str(waf), "confidence": 1.0}
        captcha = (
            profile.get("captcha")
            or profile.get("stealth_scan", {}).get("captcha")
        )
        target_type = str(profile.get("target_type") or "general_web")
        authentication = str(profile.get("authentication") or "")
        if not authentication:
            if target_type == "cas_authentication":
                authentication = "cas_sso"
            elif cookies:
                authentication = "session_cookie"
            else:
                authentication = "none"
        return {
            "target_url": str(info.get("target_url") or info.get("url") or ""),
            "target_type": target_type,
            "authentication": authentication,
            "captcha": captcha or None,
            "waf": dict(waf) if isinstance(waf, Mapping) else None,
            "endpoints": endpoints,
            "params": params,
            "forms": forms,
            "cookies": cookies,
            "technologies": technologies,
        }

    def _execute_strategy(self, strategy: dict, info: dict) -> dict:
        """Execute one reasoned strategy through the bridge's auto-tool dispatcher."""
        execution_context = dict(info)
        execution_context["stage_results"] = dict(info.get("stage_results") or {})
        execution_context["attack_queue"] = []
        execution_context["strategies"] = [dict(strategy)]
        result = self._run_stage(
            "attack_execution",
            self.bridge.stage_attack_execution,
            execution_context,
        )
        return {"strategy_id": strategy.get("strategy_id", ""), **result}

    @classmethod
    def _priority(cls, strategy: Mapping[str, Any]) -> tuple[int, str]:
        action_priorities = [
            cls._PRIORITY.get(str(action.get("priority") or "P2"), 2)
            for action in strategy.get("actions", [])
            if isinstance(action, Mapping)
        ]
        priority = min(
            action_priorities,
            default=cls._PRIORITY.get(str(strategy.get("priority") or "P2"), 2),
        )
        return priority, str(strategy.get("strategy_id") or "")

    @staticmethod
    def _merge_attack_results(results: Sequence[Mapping[str, Any]]) -> dict:
        attempts = []
        handoffs = []
        browser_operations = []
        browser_evidence = []
        statuses = []
        for result in results:
            attempts.extend(result.get("attempts") or [])
            handoffs.extend(result.get("handoffs") or [])
            browser_operations.extend(result.get("browser_operations") or [])
            browser_evidence.extend(result.get("browser_evidence") or [])
            statuses.append(str(result.get("status") or ""))
        return {
            "status": "deferred" if handoffs or "deferred" in statuses else "completed",
            "attempts": attempts,
            "handoffs": handoffs,
            "browser_operations": browser_operations,
            "browser_evidence": browser_evidence,
        }


@dataclass
class ScanContext:
    """Shared state across all tools during a scan."""
    target: str
    session_cookie: str = ""
    csrf_token: str = ""
    forms: List[dict] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    tested_payloads: List[str] = field(default_factory=list)
    collaborator_domain: str = ""
    burp_session: Any = None

    def add_finding(self, vuln_type: str, payload: str, evidence: str, severity: str = "medium"):
        self.findings.append({
            "type": vuln_type,
            "payload": payload,
            "evidence": evidence[:500],
            "severity": severity,
            "timestamp": time.time(),
        })

    def has_finding(self, vuln_type: str) -> bool:
        return any(f["type"] == vuln_type for f in self.findings)

    def get_findings(self, vuln_type: str = "") -> List[dict]:
        if vuln_type:
            return [f for f in self.findings if f["type"] == vuln_type]
        return self.findings


class UnifiedScanner:
    """Unified scan engine that orchestrates all Hunter tools."""

    def __init__(self, target: str, session_cookie: str = "",
                 collaborator_domain: str = "",
                 services: Mapping[str, Any] | None = None,
                 call_mcp_tool=None):
        self.ctx = ScanContext(
            target=target,
            session_cookie=session_cookie,
            collaborator_domain=collaborator_domain,
        )
        self.call_mcp_tool = call_mcp_tool
        self.integration = UnifiedOrchestrationBridge(
            services,
            call_mcp_tool=call_mcp_tool,
        )
        self.phases_completed = []
        self.errors = []

    def run_full_scan(self, phases: List[str] = None) -> dict:
        """Run complete scan pipeline.

        Args:
            phases: List of phases to run. Default: all.
                    Options: ['recon', 'sqli', 'xss', 'ssti', 'ssrf', 'xxe', 'cmd', 'idor']
        """
        if phases is None:
            phases = ["recon", "sqli", "xss", "ssti", "ssrf", "xxe", "cmd", "idor", "csrf", "graphql", "websocket"]

        results = {
            "target": self.ctx.target,
            "phases": {},
            "findings": [],
            "summary": {},
        }

        start = time.time()

        for phase in phases:
            try:
                phase_result = self._run_phase(phase)
                results["phases"][phase] = phase_result
                self.phases_completed.append(phase)
            except Exception as e:
                self.errors.append({"phase": phase, "error": str(e)})
                results["phases"][phase] = {"error": str(e)}

        results["findings"] = self.ctx.get_findings()
        results["summary"] = self._generate_summary()
        results["elapsed_ms"] = int((time.time() - start) * 1000)
        results["errors"] = self.errors

        return results

    def _run_phase(self, phase: str) -> dict:
        """Run a single scan phase."""
        if phase == "recon":
            return self._phase_recon()
        elif phase == "sqli":
            return self._phase_sqli()
        elif phase == "xss":
            return self._phase_xss()
        elif phase == "ssti":
            return self._phase_ssti()
        elif phase == "ssrf":
            return self._phase_ssrf()
        elif phase == "xxe":
            return self._phase_xxe()
        elif phase == "cmd":
            return self._phase_cmd()
        elif phase == "idor":
            return self._phase_idor()
        elif phase == "csrf":
            return self._phase_csrf()
        elif phase == "graphql":
            return self._phase_graphql()
        elif phase == "websocket":
            return self._phase_websocket()
        else:
            return {"error": f"Unknown phase: {phase}"}

    def _phase_recon(self) -> dict:
        """Phase 1: Reconnaissance 鈥?discover attack surface."""
        result = self.integration.stage_recon(
            {
                "target_url": self.ctx.target,
                "modules": ["all"],
                "profile": {
                    "name": "standard",
                    "max_endpoints": 100,
                    "max_attack_surfaces": 12,
                    "depth": "standard",
                },
                "observations": {},
            }
        )
        profile = result["target_profile"]
        self.ctx.forms = list(profile.get("forms", []))
        self.ctx.params = list(profile.get("params", []))
        self.ctx.endpoints = [
            str(item.get("url") if isinstance(item, Mapping) else item)
            for item in profile.get("api_endpoints", [])
        ]
        self.ctx.csrf_token = str(profile.get("csrf_token", ""))
        return {
            "forms_found": len(self.ctx.forms),
            "params_found": len(self.ctx.params),
            "endpoints_found": len(self.ctx.endpoints),
            "csrf_token": self.ctx.csrf_token,
            "params": self.ctx.params[:20],
            "endpoints": self.ctx.endpoints[:20],
            "http_status": profile.get("http_status", 0),
            "fingerprints": profile.get("fingerprints", {}),
            "spa": profile.get("spa", {}),
            "js_analysis": profile.get("js_analysis", {}),
            "websocket_capture": profile.get("websocket_capture", {}),
            "http_transport": "stealth_http_client",
        }
    def _phase_sqli(self) -> dict:
        """Phase 2: SQL Injection detection."""
        try:
            from core.auto_sqli import AutoSQLi
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_sqli not available", "suggestion": "install the selected auto module dependencies"}

        results = []

        # Test each parameter discovered in recon
        for param in self.ctx.params:
            sqli = AutoSQLi(
                base_url=self.ctx.target,
                param=param,
                cookie_param="session" if self.ctx.session_cookie else "",
                csrf_url=self.ctx.target + "/login" if self.ctx.csrf_token else "",
            )

            # Quick boolean test first
            bool_result = sqli.test_boolean_blind()
            if bool_result.get("vulnerable"):
                self.ctx.add_finding("sqli", f"' AND 1=1-- on param={param}",
                                     f"Boolean blind: {bool_result}", "high")
                results.append({"param": param, "type": "boolean_blind", "vulnerable": True})
                continue

            # Time-based test
            time_result = sqli.test_time_blind()
            if time_result.get("vulnerable"):
                self.ctx.add_finding("sqli", f"Time-based on param={param}",
                                     f"Time blind: {time_result}", "high")
                results.append({"param": param, "type": "time_blind", "vulnerable": True})
                continue

            # Conditional response test
            cond_result = sqli.test_conditional_response()
            if cond_result.get("vulnerable"):
                self.ctx.add_finding("sqli", f"Conditional response on param={param}",
                                     f"Conditional: {cond_result}", "high")
                results.append({"param": param, "type": "conditional", "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_xss(self) -> dict:
        """Phase 3: XSS detection."""
        try:
            from core.auto_xss import AutoXSS
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_xss not available", "suggestion": "install the selected auto module dependencies"}
        results = []

        for param in self.ctx.params:
            xss = AutoXSS(
                base_url=self.ctx.target,
                param=param,
                csrf_url=self.ctx.target + "/comment" if self.ctx.forms else "",
            )

            # Detect context
            context = xss.detect_context()
            if context == "not_reflected":
                continue

            # Test payloads for detected context
            scan_result = xss.run_full_scan(dom_check=True)
            if scan_result.get("vulnerable"):
                self.ctx.add_finding("xss", scan_result.get("working_payload", ""),
                                     f"Context: {context}, Type: {scan_result.get('xss_type')}", "high")
                results.append({"param": param, "context": context, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_ssti(self) -> dict:
        """Phase 4: SSTI detection."""
        try:
            from core.auto_ssti import AutoSSTI
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_ssti not available", "suggestion": "install the selected auto module dependencies"}
        results = []

        for param in self.ctx.params:
            ssti = AutoSSTI(base_url=self.ctx.target, param=param)
            scan_result = ssti.run_full_scan()

            if scan_result.get("vulnerable"):
                engine = scan_result.get("engine", "unknown")
                self.ctx.add_finding("ssti", scan_result.get("working_payload", ""),
                                     f"Engine: {engine}", "critical")
                results.append({"param": param, "engine": engine, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_ssrf(self) -> dict:
        """Phase 5: SSRF detection."""
        try:
            from core.auto_ssrf import AutoSSRF
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_ssrf not available", "suggestion": "install the selected auto module dependencies"}
        results = []

        for param in self.ctx.params:
            if any(kw in param.lower() for kw in ["url", "uri", "link", "src", "href", "redirect", "path"]):
                ssrf = AutoSSRF(base_url=self.ctx.target, param=param)

                # Test internal access
                internal = ssrf.test_internal_access()
                if internal.get("vulnerable"):
                    self.ctx.add_finding("ssrf", f"Internal access via {param}",
                                         f"Internal: {internal}", "high")
                    results.append({"param": param, "type": "internal_access", "vulnerable": True})

                # Test bypass
                bypass = ssrf.test_bypass()
                if bypass.get("bypasses_found", 0) > 0:
                    self.ctx.add_finding("ssrf", f"Bypass via {param}",
                                         f"Bypass: {bypass}", "high")
                    results.append({"param": param, "type": "bypass", "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_xxe(self) -> dict:
        """Phase 6: XXE detection."""
        try:
            from core.auto_xxe import AutoXXE
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_xxe not available", "suggestion": "install the selected auto module dependencies"}
        results = []

        for param in self.ctx.params:
            xxe = AutoXXE(base_url=self.ctx.target, param=param)
            scan_result = xxe.run_full_scan()

            if scan_result.get("vulnerable"):
                self.ctx.add_finding("xxe", scan_result.get("working_payload", ""),
                                     f"XXE: {scan_result}", "critical")
                results.append({"param": param, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_cmd(self) -> dict:
        """Phase 7: Command Injection detection."""
        try:
            from core.auto_cmd import AutoCMD
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_cmd not available", "suggestion": "install the selected auto module dependencies"}
        results = []

        for param in self.ctx.params:
            if any(kw in param.lower() for kw in ["cmd", "command", "exec", "ping", "ip", "host", "domain"]):
                cmd = AutoCMD(base_url=self.ctx.target, param=param)
                scan_result = cmd.run_full_scan()

                if scan_result.get("vulnerable"):
                    self.ctx.add_finding("cmdi", scan_result.get("working_payload", ""),
                                         f"CMDi: {scan_result}", "critical")
                    results.append({"param": param, "vulnerable": True})

        return {"params_tested": len(self.ctx.params), "findings": results}

    def _phase_idor(self) -> dict:
        """Phase 8: IDOR detection."""
        try:
            from core.auto_idor import AutoIDOR
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_idor not available", "suggestion": "install the selected auto module dependencies"}
        results = []

        for endpoint in self.ctx.endpoints:
            if any(kw in endpoint.lower() for kw in ["/api/", "/user/", "/profile/", "/account/"]):
                idor = AutoIDOR(base_url=self.ctx.target, endpoint=endpoint)
                scan_result = idor.run_full_scan()

                if scan_result.get("vulnerable"):
                    self.ctx.add_finding("idor", f"IDOR on {endpoint}",
                                         f"IDOR: {scan_result}", "high")
                    results.append({"endpoint": endpoint, "vulnerable": True})

        return {"endpoints_tested": len(self.ctx.endpoints), "findings": results}

    def _phase_csrf(self) -> dict:
        """Phase 9: CSRF detection."""
        try:
            from core.auto_csrf import scan as csrf_scan
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_csrf not available"}

        result = csrf_scan(self.ctx.target, self.ctx.session_cookie)

        if result.get("findings"):
            for finding in result["findings"]:
                self.ctx.add_finding("csrf", finding.get("type", "csrf"),
                                     f"{finding.get('details', '')}", finding.get("severity", "medium"))

        return {
            "forms_found": len(result.get("forms", [])),
            "findings": result.get("findings", []),
            "exploit_html": result.get("exploit_html", "")[:500]
        }

    def _phase_graphql(self) -> dict:
        """Phase 10: GraphQL detection."""
        try:
            from core.auto_graphql import full_scan as graphql_scan
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_graphql not available"}

        result = graphql_scan(self.ctx.target)

        if result.get("findings_count", 0) > 0:
            self.ctx.add_finding("graphql", "GraphQL vulnerabilities found",
                                 f"Findings: {result.get('findings_count')}", result.get("severity", "medium"))

        return {
            "endpoint_found": result.get("endpoint_discovery", {}).get("found", False),
            "findings_count": result.get("findings_count", 0),
            "severity": result.get("severity", "info")
        }

    def _phase_websocket(self) -> dict:
        """Phase 11: WebSocket detection."""
        try:
            from core.auto_websocket import full_scan as ws_scan
        except (ImportError, ModuleNotFoundError):
            return {"error": "auto_websocket not available"}

        result = ws_scan(self.ctx.target)

        if result.get("findings"):
            for finding in result["findings"]:
                self.ctx.add_finding("websocket", finding.get("type", "websocket"),
                                     f"{finding.get('details', '')}", finding.get("severity", "medium"))

        return {
            "endpoints_found": len(result.get("discovery", {}).get("endpoints", [])),
            "findings_count": result.get("findings_count", 0),
            "severity": result.get("severity", "info")
        }

    def _generate_summary(self) -> dict:
        """Generate scan summary."""
        findings = self.ctx.get_findings()
        by_type = {}
        for f in findings:
            t = f["type"]
            if t not in by_type:
                by_type[t] = 0
            by_type[t] += 1

        return {
            "total_findings": len(findings),
            "by_type": by_type,
            "phases_completed": len(self.phases_completed),
            "errors": len(self.errors),
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
        }

    def aggregate_burp_results(self) -> dict:
        """Aggregate results from Burp Scanner, Collaborator, and Proxy.

        This enhances findings with Burp's own analysis:
        - Scanner issues: passive/active scan findings
        - Collaborator: OOB callbacks (blind vulns)
        - Proxy history: interesting patterns in traffic
        """
        burp_findings = []

        # This would integrate with Burp MCP tools
        # For now, return the aggregation structure
        return {
            "scanner_issues": "Use burp(action='scanner_issues') to get",
            "collaborator": "Use burp(action='collaborator_check') to get OOB callbacks",
            "proxy_patterns": "Use burp(action='proxy_search', regex='token|key|password') to find",
            "burp_findings": burp_findings,
        }

    def aggregate_burp_scanner(self) -> dict:
        """Aggregate Burp Scanner issues into Hunter findings.

        This calls Burp MCP to get scanner issues and converts them
        to Hunter's finding format.
        """
        # This would call burp(action="scanner_issues")
        # For now, return placeholder
        return {
            "note": "Use burp(action='scanner_issues') to get Burp Scanner findings",
            "integration": "Scanner issues will be merged into Hunter findings",
        }

    def get_recommendations(self) -> List[str]:
        """Get next-step recommendations based on findings."""
        recs = []

        if not self.ctx.findings:
            recs.append("No vulnerabilities found. Try manual testing or different parameters.")

        if self.ctx.has_finding("sqli"):
            recs.append("SQLi found! Try extracting data: tables 鈫?columns 鈫?credentials")
            recs.append("Use Burp Collaborator for blind OOB exfiltration")

        if self.ctx.has_finding("xss"):
            recs.append("XSS found! Try stealing cookies or escalating to account takeover")
            recs.append("Use exploit server for DOM/Stored XSS delivery")

        if self.ctx.has_finding("ssrf"):
            recs.append("SSRF found! Try accessing internal services, cloud metadata, or admin panels")
            recs.append("Chain with open redirect if host filter exists")

        if self.ctx.has_finding("ssti"):
            recs.append("SSTI found! Try RCE payload for the identified template engine")

        return recs


def unified_scan_impl(target: str, session_cookie: str = "",
                       collaborator_domain: str = "",
                       phases: List[str] = None) -> dict:
    """MCP entry point for unified scan."""
    scanner = UnifiedScanner(
        target=target,
        session_cookie=session_cookie,
        collaborator_domain=collaborator_domain,
    )
    return scanner.run_full_scan(phases=phases)
