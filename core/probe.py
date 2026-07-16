"""
Hunter v4 — HTTP Probe Tool

All HTTP operations go through here.
Returns complete response + auto-detected interesting content.
"""

import re
import threading
import time
from pathlib import Path
from typing import Any, Optional

from core.request_broker import LegacyRequestsAdapter, RequestBroker, RequestSpec

try:
    from core.config import USER_AGENTS
except (ImportError, ModuleNotFoundError):
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

try:
    from core.response_analyzer import analyze_response, is_interesting
except (ImportError, ModuleNotFoundError):
    def analyze_response(resp): return {}
    def is_interesting(resp): return False

# Interesting patterns to detect in responses
INTERESTING_PATTERNS = {
    "form": re.compile(r'<form[^>]*>', re.I),
    "input_hidden": re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.I),
    "csrf_token": re.compile(r'(csrf|_token|authenticity.token)', re.I),
    "comment": re.compile(r'<!--(.{1,200}?)-->', re.S),
    "debug_flag": re.compile(r'(debug\s*[:=]\s*true|DEBUG\s*=\s*True|APP_DEBUG)', re.I),
    "error_disclosure": re.compile(r'(SQL syntax|mysql_|ORA-|PostgreSQL|SQLite|stack trace|Traceback)', re.I),
    "api_key": re.compile(r'(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']?[\w-]{10,}', re.I),
    "internal_ip": re.compile(r'(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)'),
    "directory_listing": re.compile(r'<title>Index of /|Directory listing for', re.I),
    "default_page": re.compile(r'(Apache2? Ubuntu Default Page|Welcome to nginx|IIS Windows Server)', re.I),
}

HEADER_LEAKS = {
    "X-Powered-By": "header_leak",
    "X-AspNet-Version": "header_leak",
    "X-AspNetMvc-Version": "header_leak",
    "Server": "server_leak",
    "X-Debug-Token": "debug_leak",
    "X-Runtime": "runtime_leak",
}

# Global session (reused across calls, UA rotated)
_session: Optional[LegacyRequestsAdapter] = None
_ua_index = 0
_session_lock = threading.Lock()


def _get_session() -> LegacyRequestsAdapter:
    """Get or create HTTP session with anti-detection defaults."""
    global _session, _ua_index
    with _session_lock:
        if _session is None:
            _session = LegacyRequestsAdapter(
                RequestBroker(Path("sessions") / "request_broker")
            )
        # Rotate UA
        _session.headers["User-Agent"] = USER_AGENTS[_ua_index % len(USER_AGENTS)]
        _ua_index += 1
        return _session


def _analyze_body(body: str) -> tuple:
    """Analyze response body for interesting content. Returns (interesting, tags)."""
    interesting = []
    tags = set()

    for name, pattern in INTERESTING_PATTERNS.items():
        matches = pattern.findall(body)
        if matches:
            tags.add(name)
            if name == "form":
                interesting.append(f"found {len(matches)} form(s)")
            elif name == "comment":
                for m in matches[:3]:
                    text = m.strip()[:100]
                    interesting.append(f"comment: {text}")
            elif name == "error_disclosure":
                interesting.append(f"error disclosure: {matches[0][:80]}")
            elif name == "debug_flag":
                interesting.append(f"debug mode detected: {matches[0][:50]}")
            elif name == "api_key":
                interesting.append("potential API key found")
            elif name == "internal_ip":
                interesting.append(f"internal IP: {matches[0]}")
            elif name == "directory_listing":
                interesting.append("directory listing enabled")
            elif name == "default_page":
                interesting.append(f"default page: {matches[0][:50]}")
            elif name == "api_config":
                interesting.append(f"API config leak: {matches[0][:80]}")
            elif name == "sensitive_path":
                interesting.append(f"sensitive path detected")
            elif name == "input_hidden":
                interesting.append(f"hidden input field(s): {len(matches)}")
            elif name == "csrf_token":
                interesting.append("CSRF token found")

    return interesting, list(tags)


def probe_impl(url: str, method: str = "GET", headers: Optional[dict] = None,
               body: Optional[str] = None, follow_redirects: bool = True,
               timeout: int = 10) -> dict:
    """Execute HTTP request and analyze response."""
    session = _get_session()
    start = time.time()

    try:
        resp = session.request(
            method=method,
            url=url,
            headers=headers or {},
            data=body,
            allow_redirects=follow_redirects,
            timeout=timeout,
        )
        elapsed_ms = int((time.time() - start) * 1000)
        broker_outcome = session.broker.classify_response(
            RequestSpec(method=method, url=url, headers=headers or {}), resp
        )

        resp_headers = dict(resp.headers)
        resp_body = resp.text
        resp_cookies = {k: v for k, v in resp.cookies.items()}

        redirect_chain = []
        if resp.history:
            redirect_chain = [r.url for r in resp.history]

        body_interesting, body_tags = _analyze_body(resp_body)

        header_interesting = []
        for header_name, tag in HEADER_LEAKS.items():
            if header_name in resp_headers:
                header_interesting.append(f"header leak: {header_name}: {resp_headers[header_name]}")
                body_tags.append(tag)

        all_interesting = body_interesting + header_interesting

        # Use response analyzer for semantic understanding
        analysis = analyze_response(resp_headers, resp_body, resp.status_code, url)

        # Merge analyzer findings into interesting list
        all_interesting.extend(analysis.interesting)
        tags = list(set(body_tags + analysis.tags))

        return {
            "url": url,
            "status": resp.status_code,
            "headers": resp_headers,
            "body": resp_body,
            "body_length": len(resp_body),
            "cookies": resp_cookies,
            "timing_ms": elapsed_ms,
            "redirect_chain": redirect_chain,
            "interesting": all_interesting,
            "tags": tags,
            "analysis": {
                "error_type": analysis.error_type,
                "waf_detected": analysis.waf_detected,
                "waf_name": analysis.waf_name,
                "page_type": analysis.page_type,
                "auth_state": analysis.auth_state,
                "has_debug_info": analysis.has_debug_info,
                "has_credentials": analysis.has_credentials,
                "detected_tech": analysis.detected_tech,
                "suggested_actions": analysis.suggested_actions,
            },
            "broker": {
                "classification": broker_outcome.classification.value,
                "confidence": broker_outcome.confidence,
                "evidence_ids": broker_outcome.evidence_ids,
                "missing_inputs": broker_outcome.missing_inputs,
                "next_actions": broker_outcome.next_actions,
            },
        }

    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return {
            "url": url,
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "cookies": {},
            "timing_ms": elapsed_ms,
            "redirect_chain": [],
            "interesting": [f"error: {str(e)}"],
            "tags": ["error"],
            "error": str(e),
        }
