"""
auto_websocket.py - Automated WebSocket vulnerability detection and exploitation
"""

import re
import json
import time
from typing import Optional


def discover_websockets(url: str) -> dict:
    """Discover WebSocket endpoints on target by analyzing HTML and JS."""
    session = _get_session()
    ws_endpoints = []

    try:
        resp = session.get(url, timeout=15)
        html = resp.text
    except Exception as e:
        return {"error": str(e), "endpoints": [], "found": False}

    # Pattern 1: new WebSocket('ws://...')
    ws_patterns = [
        r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
        r'wss?://[^\s"\'<>]+',
        r'["\'](/wss?/[^\s"\'<>]+)["\']',
        r'ws_url\s*[=:]\s*["\']([^"\']+)["\']',
        r'websocketUrl["\']?\s*[=:]\s*["\']([^"\']+)["\']',
    ]

    for pattern in ws_patterns:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            ws_url = m.group(1) if m.lastindex else m.group(0)
            if ws_url and not any(e["url"] == ws_url for e in ws_endpoints):
                ws_endpoints.append({
                    "url": ws_url,
                    "source": "html",
                    "type": _classify_ws_url(ws_url)
                })

    # Pattern 2: Check JS files for WebSocket connections
    js_urls = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
    for js_url in js_urls[:5]:  # Limit to 5 JS files
        if not js_url.startswith('http'):
            js_url = url.rstrip('/') + '/' + js_url.lstrip('/')
        try:
            js_resp = session.get(js_url, timeout=8)
            for pattern in ws_patterns:
                for m in re.finditer(pattern, js_resp.text, re.IGNORECASE):
                    ws_url = m.group(1) if m.lastindex else m.group(0)
                    if ws_url and not any(e["url"] == ws_url for e in ws_endpoints):
                        ws_endpoints.append({
                            "url": ws_url,
                            "source": f"js:{js_url}",
                            "type": _classify_ws_url(ws_url)
                        })
        except Exception:
            continue

    # Convert relative URLs to absolute
    for ep in ws_endpoints:
        if ep["url"].startswith('/'):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            ws_proto = 'wss' if parsed.scheme == 'https' else 'ws'
            ep["url"] = f"{ws_proto}://{parsed.netloc}{ep['url']}"

    return {
        "base_url": url,
        "endpoints": ws_endpoints,
        "found": len(ws_endpoints) > 0
    }


def _classify_ws_url(url: str) -> str:
    """Classify WebSocket URL type."""
    if 'chat' in url.lower():
        return 'chat'
    elif 'live' in url.lower() or 'stream' in url.lower():
        return 'live_data'
    elif 'api' in url.lower():
        return 'api'
    elif 'ws' in url.lower() or 'websocket' in url.lower():
        return 'generic'
    return 'unknown'


def _get_session():
    """Get HTTP session with fallback."""
    try:
        from tools.probe import _get_session as _gs
        return _gs()
    except (ImportError, ModuleNotFoundError):
        import requests
        s = requests.Session()
        s.verify = False
        s.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        return s


def test_xss_injection(ws_url: str, origin: str = "") -> dict:
    """Test if WebSocket reflects messages without sanitization (XSS via WebSocket)."""
    try:
        import websocket
    except ImportError:
        return {"error": "websocket-client not installed", "xss_possible": False}

    results = {
        "ws_url": ws_url,
        "xss_possible": False,
        "payloads_tested": [],
        "reflected": []
    }

    # XSS payloads to test
    xss_payloads = [
        '<img src=x onerror=alert(1)>',
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "<img src=x onerror='alert(1)'>",
        'javascript:alert(1)',
    ]

    headers = {}
    if origin:
        headers['Origin'] = origin

    try:
        ws = websocket.create_connection(ws_url, timeout=5, header=headers)

        for payload in xss_payloads:
            try:
                ws.send(payload)
                results["payloads_tested"].append(payload)

                # Check for reflection
                try:
                    ws.settimeout(2)
                    response = ws.recv()
                    if payload in response or 'onerror' in response.lower():
                        results["reflected"].append({
                            "payload": payload,
                            "response": response[:200]
                        })
                        results["xss_possible"] = True
                except Exception:
                    pass  # Timeout is expected if no reflection

            except Exception:
                continue

        ws.close()
    except Exception as e:
        results["connection_error"] = str(e)

    return results


def test_origin_policy(ws_url: str) -> dict:
    """Test WebSocket Origin header validation."""
    results = {
        "ws_url": ws_url,
        "tests": []
    }

    origins_to_test = [
        ("null", "null_origin"),
        ("https://evil.com", "arbitrary_origin"),
        ("https://attacker.com", "attacker_origin"),
        ("", "no_origin"),
    ]

    for origin, test_name in origins_to_test:
        try:
            import websocket
            headers = {}
            if origin:
                headers['Origin'] = origin

            ws = websocket.create_connection(ws_url, timeout=5, header=headers)
            ws.close()

            results["tests"].append({
                "test": test_name,
                "origin": origin,
                "connected": True,
                "vulnerable": True,
                "severity": "medium",
                "details": f"Accepted connection with Origin: {origin or 'none'}"
            })
        except Exception as e:
            results["tests"].append({
                "test": test_name,
                "origin": origin,
                "connected": False,
                "vulnerable": False,
                "error": str(e)[:100]
            })

    results["origin_bypassed"] = any(t.get("vulnerable") for t in results["tests"])
    return results


def test_cross_site_websocket_hijacking(ws_url: str, session_cookie: str = "") -> dict:
    """Test for Cross-Site WebSocket Hijacking (CSWSH)."""
    results = {
        "ws_url": ws_url,
        "cswsh_possible": False,
        "tests": []
    }

    # CSWSH: attacker site can open WebSocket to target with victim's cookies
    try:
        import websocket

        # Test with null origin (typical CSWSH attack vector)
        headers = {'Origin': 'null'}
        if session_cookie:
            headers['Cookie'] = session_cookie

        ws = websocket.create_connection(ws_url, timeout=5, header=headers)
        ws.close()

        results["cswsh_possible"] = True
        results["tests"].append({
            "test": "null_origin_with_cookies",
            "vulnerable": True,
            "severity": "high",
            "details": "WebSocket accepts connections from null origin with session cookies"
        })
    except Exception as e:
        results["tests"].append({
            "test": "null_origin_with_cookies",
            "vulnerable": False,
            "error": str(e)[:100]
        })

    return results


def test_message_manipulation(ws_url: str, origin: str = "") -> dict:
    """Test for message manipulation vulnerabilities."""
    try:
        import websocket
    except ImportError:
        return {"error": "websocket-client not installed"}

    results = {
        "ws_url": ws_url,
        "manipulation_tests": []
    }

    headers = {}
    if origin:
        headers['Origin'] = origin

    try:
        ws = websocket.create_connection(ws_url, timeout=5, header=headers)

        # Test 1: Send JSON with manipulated fields
        json_payloads = [
            '{"message":"hello","role":"admin"}',
            '{"message":"hello","isAdmin":true}',
            '{"message":"hello","userId":1}',
            '{"action":"delete","target":"all"}',
            '{"type":"admin","data":"test"}',
        ]

        for payload in json_payloads:
            try:
                ws.send(payload)
                try:
                    ws.settimeout(2)
                    response = ws.recv()
                    results["manipulation_tests"].append({
                        "payload": payload,
                        "response": response[:200],
                        "has_response": True
                    })
                except Exception:
                    results["manipulation_tests"].append({
                        "payload": payload,
                        "has_response": False
                    })
            except Exception:
                continue

        ws.close()
    except Exception as e:
        results["connection_error"] = str(e)

    return results


def full_scan(url: str) -> dict:
    """Full WebSocket security scan."""
    results = {
        "url": url,
        "discovery": None,
        "findings": [],
        "severity": "info"
    }

    # 1. Discover WebSocket endpoints
    discovery = discover_websockets(url)
    results["discovery"] = discovery

    if not discovery["found"]:
        results["error"] = "No WebSocket endpoints found"
        return results

    # 2. Test each endpoint
    for ep in discovery["endpoints"]:
        ws_url = ep["url"]

        # Origin policy test
        origin_result = test_origin_policy(ws_url)
        if origin_result.get("origin_bypassed"):
            results["findings"].append({
                "type": "origin_bypass",
                "endpoint": ws_url,
                "severity": "medium",
                "details": origin_result
            })

        # XSS injection test
        xss_result = test_xss_injection(ws_url)
        if xss_result.get("xss_possible"):
            results["findings"].append({
                "type": "websocket_xss",
                "endpoint": ws_url,
                "severity": "high",
                "details": xss_result
            })

        # CSWSH test
        cswsh_result = test_cross_site_websocket_hijacking(ws_url)
        if cswsh_result.get("cswsh_possible"):
            results["findings"].append({
                "type": "cswsh",
                "endpoint": ws_url,
                "severity": "high",
                "details": cswsh_result
            })

    results["findings_count"] = len(results["findings"])
    if any(f["severity"] == "high" for f in results["findings"]):
        results["severity"] = "high"
    elif results["findings"]:
        results["severity"] = "medium"

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_websocket.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    result = full_scan(target)
    print(json.dumps(result, indent=2, default=str))
