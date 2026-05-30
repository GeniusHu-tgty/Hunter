# tools/inject.py
"""Hunter v4 — Injection Tester

Claude provides payloads, tool sends them and compares responses.
"""

import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.probe import _get_session


def inject_impl(url: str, method: str = "POST", param: str = "",
                payloads: list[str] = None, base_payload: str = "test",
                compare_field: str = "body_length", headers: dict = None,
                body_template: str = "", timeout: int = 10) -> dict:
    """Test injection vulnerabilities by sending payloads and comparing responses."""
    if not payloads:
        return {"error": "No payloads provided"}

    session = _get_session()
    start = time.time()

    base_result = _send_injection(session, url, method, param, base_payload,
                                  headers, body_template, timeout)

    results = []
    for payload in payloads:
        result = _send_injection(session, url, method, param, payload,
                                 headers, body_template, timeout)
        diff = _compute_diff(base_result, result, compare_field)
        result["diff_from_base"] = diff
        result["interesting"] = _is_injection_interesting(diff, result, base_result)
        results.append(result)

    analysis = _analyze_injection(results, base_result, compare_field)
    elapsed_ms = int((time.time() - start) * 1000)

    return {
        "url": url,
        "param": param,
        "base_response": {
            "status": base_result["status"],
            "body_length": base_result["body_length"],
            "body_preview": base_result["body"][:200],
        },
        "results": results,
        "analysis": analysis,
        "elapsed_ms": elapsed_ms,
    }


def _send_injection(session, url: str, method: str, param: str, payload: str,
                    headers: dict, body_template: str, timeout: int) -> dict:
    try:
        if method.upper() == "GET":
            separator = "&" if "?" in url else "?"
            target_url = f"{url}{separator}{param}={payload}"
            resp = session.get(target_url, headers=headers or {}, timeout=timeout, allow_redirects=False)
        else:
            if body_template:
                body = body_template.replace("{payload}", payload)
            else:
                body = f"{param}={payload}"
            resp = session.post(url, data=body, headers=headers or {"Content-Type": "application/x-www-form-urlencoded"},
                               timeout=timeout, allow_redirects=False)

        return {
            "payload": payload,
            "status": resp.status_code,
            "body": resp.text,
            "body_length": len(resp.text),
            "body_hash": hashlib.md5(resp.text.encode()).hexdigest()[:8],
            "redirect": resp.headers.get("Location"),
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {"payload": payload, "status": 0, "body": "", "body_length": 0,
                "body_hash": "", "redirect": None, "headers": {}, "error": str(e)}


def _compute_diff(base: dict, result: dict, compare_field: str) -> str:
    if compare_field == "body_length":
        diff = result["body_length"] - base["body_length"]
        return f"+{diff} bytes" if diff > 0 else f"{diff} bytes" if diff < 0 else "0 bytes"
    elif compare_field == "body_hash":
        return "different content" if result["body_hash"] != base["body_hash"] else "same content"
    elif compare_field == "status_code":
        return f"status changed: {base['status']} -> {result['status']}" if result["status"] != base["status"] else "same status"
    return "unknown"


def _is_injection_interesting(diff: str, result: dict, base: dict) -> bool:
    if "bytes" in diff and diff != "0 bytes":
        return True
    if diff == "different content":
        return True
    if "status changed" in diff:
        return True
    if result.get("redirect") and not base.get("redirect"):
        return True
    error_patterns = ["sql", "syntax", "mysql", "postgresql", "ora-", "sqlite", "template", "jinja", "mako", "twig"]
    body_lower = result.get("body", "").lower()
    if any(p in body_lower for p in error_patterns):
        return True
    return False


def _analyze_injection(results: list, base: dict, compare_field: str) -> dict:
    interesting_count = sum(1 for r in results if r["interesting"])
    if interesting_count == 0:
        return {"likely_vuln": False, "type": None, "confidence": 0.0, "evidence": "No differential responses detected"}

    has_longer = any(r["body_length"] > base["body_length"] for r in results if r["interesting"])
    has_shorter = any(r["body_length"] < base["body_length"] for r in results if r["interesting"])

    if has_longer and has_shorter:
        return {"likely_vuln": True, "type": "boolean-based blind", "confidence": 0.8,
                "evidence": f"Differential responses: {interesting_count}/{len(results)} payloads show differences"}

    error_payloads = [r for r in results if any(p in r.get("body", "").lower() for p in ["sql", "syntax", "mysql", "template"])]
    if error_payloads:
        return {"likely_vuln": True, "type": "error-based", "confidence": 0.7,
                "evidence": f"Error messages found in {len(error_payloads)} responses"}

    return {"likely_vuln": True, "type": "unknown", "confidence": 0.5,
            "evidence": f"{interesting_count}/{len(results)} payloads show differential responses"}
