# tools/js_analyze.py
"""Hunter v4 — JavaScript Analyzer"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session

SECRET_PATTERNS = {
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "api_key": re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'),
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "password": re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})'),
    "token": re.compile(r'(?i)(token|secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'),
}

ENDPOINT_PATTERNS = [
    re.compile(r'["\']/(api|v[12]|rest|graphql)[^"\']*["\']'),
    re.compile(r'["\']https?://[^"\']*(?:api|v[12]|rest)[^"\']*["\']'),
    re.compile(r'(?:(?:get|post|put|delete|patch)\s*\(\s*["\'])([^"\']+)'),
    re.compile(r'(?:(?:fetch|axios|request)\s*\(\s*["\'])([^"\']+)'),
]

INTERNAL_PATTERNS = [
    re.compile(r'https?://(?:192\.168|10\.|172\.(?:1[6-9]|2\d|3[01]))\.[^\s"\']+'),
    re.compile(r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"\']*'),
    re.compile(r'https?://[a-z0-9-]+\.(?:internal|local|corp|private)[^\s"\']*'),
]

INTERESTING_PATTERNS = {
    "hardcoded_password": re.compile(r'(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*["\'][^"\']{3,}["\']'),
    "debug_flag": re.compile(r'(?i)DEBUG\s*[:=]\s*(?:true|1|yes)'),
    "eval_usage": re.compile(r'\beval\s*\('),
    "innerHTML": re.compile(r'\.innerHTML\s*='),
}


def js_analyze_impl(url: str) -> dict:
    session = _get_session()
    try:
        resp = session.get(url, timeout=15)
        source = resp.text
    except Exception as e:
        return {"url": url, "error": str(e)}

    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(source):
            endpoint = match.group(1) if match.lastindex else match.group(0)
            endpoint = endpoint.strip("\"'")
            if endpoint.startswith("/") or endpoint.startswith("http"):
                endpoints.add(endpoint)

    secrets = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            secrets.append({"type": name, "value": match.group(0)[:80], "line": line_num})

    internal_urls = set()
    for pattern in INTERNAL_PATTERNS:
        for match in pattern.finditer(source):
            internal_urls.add(match.group(0))

    interesting = []
    for name, pattern in INTERESTING_PATTERNS.items():
        for match in pattern.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            context = source[max(0, match.start()-20):min(len(source), match.end()+20)].strip()
            interesting.append({"pattern": name, "context": context[:100], "line": line_num})

    return {"url": url, "size": len(source), "endpoints": sorted(endpoints),
            "secrets": secrets, "internal_urls": sorted(internal_urls),
            "interesting_patterns": interesting, "source_preview": source[:5000]}
